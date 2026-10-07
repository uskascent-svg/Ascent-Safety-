from datetime import datetime, timedelta, UTC

import pytest

from app.detection.network.detectors import norm_issuer
from app.detection.network.engine import evaluate
from app.detection.network.types import BaselineSnapshot, Context
from app.schemas.network import NetworkBatch

NOW = datetime.now(UTC)
HOST = "bank.example.com"


def iso(sec=0, base=None):
    return ((base or NOW - timedelta(minutes=45)) + timedelta(seconds=sec)).isoformat()


def run(*observations, ctx=None):
    batch = NetworkBatch.model_validate({"observations": list(observations)})
    return evaluate(batch.observations, ctx)


def codes(findings):
    return {f.code for f in findings}


def known(issuer="Example CA", max_tls="TLSv1.3", n=5, name=HOST):
    return Context(tls={name: BaselineSnapshot(norm_issuer(issuer), None, max_tls, n, issuer)})


def cert(issuer="Example CA", **over):
    base = {
        "issuer": issuer,
        "not_before": iso(base=NOW - timedelta(days=300)),
        "not_after": iso(base=NOW + timedelta(days=60)),
        "chain_valid": True,
        "hostname_match": True,
        "sha256": "a" * 64,
    }
    return {**base, **over}


def tls(version="TLSv1.3", certificate=None, name=HOST):
    return {
        "type": "tls_connection",
        "occurred_at": iso(),
        "server_ip": "93.184.216.34",
        "server_name": name,
        "tls_version": version,
        "certificate": certificate if certificate is not None else cert(),
    }


def conn(src="10.0.0.5", dst="93.184.216.34", port=443, sec=0, **over):
    return {
        "type": "connection",
        "occurred_at": iso(sec),
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        **over,
    }


# ---------- TLS ----------
def test_stable_host_produces_nothing():
    assert run(tls(), ctx=known()) == []


def test_issuer_change_with_valid_chain_is_medium():
    [f] = run(tls(certificate=cert("Other CA")), ctx=known())
    assert (f.code, f.severity, f.threat_type) == ("TLS_ISSUER_CHANGED", "medium", "mitm")


def test_issuer_change_plus_untrusted_chain_is_possible_interception_with_hedged_wording():
    [f] = run(tls(certificate=cert("Evil CA", chain_valid=False)), ctx=known())
    assert (f.code, f.severity) == ("POSSIBLE_TLS_INTERCEPTION", "high")
    assert (
        "inspection proxy" in f.description and "previously seen issuer: Example CA" in f.evidence
    )


def test_problems_on_known_host_without_issuer_change():
    [f] = run(tls(certificate=cert(self_signed=True)), ctx=known())
    assert f.code == "TLS_CERT_INVALID_FOR_KNOWN_HOST"


def test_no_history_means_only_a_low_severity_validation_failure():
    [f] = run(tls(certificate=cert(chain_valid=False, hostname_match=False)))
    assert (f.code, f.severity, f.threat_type) == (
        "TLS_CERT_VALIDATION_FAILURE",
        "low",
        "unsafe_network",
    )
    assert run(tls(certificate=cert("Other CA"))) == []  # new host: nothing to compare against


def test_baseline_must_be_established_before_issuer_changes_count():
    assert run(tls(certificate=cert("Other CA")), ctx=known(n=2)) == []


def test_expired_certificate():
    expired = cert(not_after=iso(base=NOW - timedelta(days=2)))
    assert "TLS_CERT_EXPIRED" in codes(run(tls(certificate=expired)))


def test_version_downgrade_and_deprecated_versions():
    [down] = run(tls("TLSv1.2"), ctx=known(max_tls="TLSv1.3"))
    assert down.code == "TLS_VERSION_DOWNGRADE" and down.severity == "medium"
    [old] = run(tls("TLSv1.0"))
    assert (old.code, old.severity) == ("TLS_DEPRECATED_VERSION", "low")
    assert run(tls("TLSv1.2")) == []


# ---------- cleartext ----------
def test_cleartext_credentials_and_protocols():
    [cred] = run(conn(port=21, service="ftp", credentials_in_cleartext=True))
    assert (cred.code, cred.severity, cred.threat_type) == (
        "UNENCRYPTED_CREDENTIALS",
        "high",
        "unsafe_network",
    )
    [public] = run(conn(port=23, service="telnet"))
    [private] = run(conn(dst="10.0.0.9", port=23, service="telnet"))
    assert (public.severity, private.severity) == ("medium", "low")


@pytest.mark.parametrize(
    "over",
    [
        {"service": "ssh"},
        {"service": "https"},
        {"service": "ftp", "encrypted": True},
        {"service": "telnet", "state": "rejected"},
    ],
)
def test_secure_or_failed_connections_are_not_cleartext_findings(over):
    assert run(conn(port=22, **over)) == []


# ---------- scanning ----------
def scan(n, state="rejected", spread=1):
    return [conn(dst="10.0.0.9", port=1000 + i, sec=i * spread, state=state) for i in range(n)]


def test_port_scan_thresholds_and_severity():
    [medium] = run(*scan(25))
    assert (medium.code, medium.severity) == ("PORT_SCAN_ACTIVITY", "medium")
    [high] = run(*scan(110))
    assert high.severity == "high"
    assert run(*scan(19)) == []  # below the target threshold


def test_normal_browsing_or_slow_scans_do_not_look_like_a_scan():
    assert run(*scan(40, state="established")) == []  # many successful connections
    mixed = scan(15, "established") + scan(15, "rejected")
    assert run(*mixed) == []  # only half failed
    assert run(*scan(25, spread=60)) == []  # spread over 24 minutes


# ---------- beaconing ----------
def beacons(n, gap=60, dst="93.184.216.34", jitter=0):
    return [
        conn(dst=dst, port=8443, sec=i * gap + (jitter * (i % 2)), bytes_out=200) for i in range(n)
    ]


def test_beaconing_requires_regular_intervals_to_a_public_host():
    [f] = run(*beacons(10))
    assert (f.code, f.severity) == ("PERIODIC_BEACONING", "medium")
    assert "monitoring agents" in f.description
    assert run(*beacons(10, jitter=40)) == []  # irregular
    assert run(*beacons(10, dst="10.1.1.1")) == []  # internal destination
    assert run(*beacons(5)) == []  # too few connections
    assert run(*beacons(10, gap=2)) == []  # sub-5-second chatter


# ---------- ARP / Wi-Fi ----------
def test_arp_gateway_change_only():
    base = {
        "type": "arp_change",
        "occurred_at": iso(),
        "ip": "192.168.1.1",
        "old_mac": "aa:bb:cc:dd:ee:01",
        "new_mac": "aa:bb:cc:dd:ee:02",
    }
    [f] = run({**base, "is_gateway": True})
    assert (f.code, f.severity, f.threat_type) == ("POSSIBLE_ARP_SPOOFING_GATEWAY", "high", "mitm")
    assert run({**base, "is_gateway": False}) == [] and run(base) == []


def wifi(bssid, security, ssid="CoffeeShop", connected=False):
    return {
        "type": "wifi_network",
        "occurred_at": iso(),
        "ssid": ssid,
        "bssid": bssid,
        "security": security,
        "connected": connected,
    }


def test_wifi_rules():
    [open_net] = run(wifi("aa:aa:aa:aa:aa:01", "open", connected=True))
    assert (open_net.code, open_net.severity) == ("UNSAFE_WIFI_OPEN", "medium")
    assert run(wifi("aa:aa:aa:aa:aa:01", "open")) == []  # merely visible
    twin = run(wifi("aa:aa:aa:aa:aa:01", "wpa2"), wifi("aa:aa:aa:aa:aa:02", "open"))
    assert [(f.code, f.severity) for f in twin] == [("POSSIBLE_EVIL_TWIN", "high")]
    assert run(wifi("aa:aa:aa:aa:aa:01", "wpa2"), wifi("aa:aa:aa:aa:aa:02", "wpa2")) == []


def test_evidence_is_sanitised():
    [f] = run(wifi("aa:aa:aa:aa:aa:01", "open", ssid="Cafe\x1b[31m\nX", connected=True))
    assert all("\x1b" not in e and "\n" not in e for e in f.evidence)
