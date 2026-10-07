import uuid
from datetime import datetime, timedelta, UTC

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.models import Alert, NetworkSensor, SecurityEvent, TlsBaseline
from tests.test_events import analyst  # noqa: F401
from tests.test_malware_api import SITE as ENDPOINT_SITE
from tests.test_malware_api import admin, headers  # noqa: F401
from tests.test_threat_intel import intel  # noqa: F401

NOW = datetime.now(UTC)
SITE = {
    "name": "hq-sensor",
    "kind": "zeek",
    "region": "EMEA",
    "country": "Germany",
    "latitude": 52.52,
    "longitude": 13.405,
}
HOST = "bank.example.com"


def iso(minutes_ago=3, base=None):
    return ((base or NOW) - timedelta(minutes=minutes_ago)).isoformat()


def cert(issuer="Example CA", **over):
    base = {
        "issuer": issuer,
        "not_before": iso(base=NOW - timedelta(days=300)),
        "not_after": iso(-60 * 24),
        "chain_valid": True,
        "hostname_match": True,
    }
    return {**base, **over}


def tls(certificate=None, version="TLSv1.3", name=HOST, minutes_ago=3):
    return {
        "type": "tls_connection",
        "occurred_at": iso(minutes_ago),
        "server_ip": "93.184.216.34",
        "server_name": name,
        "tls_version": version,
        "certificate": certificate if certificate is not None else cert(),
    }


CLEARTEXT = {
    "type": "connection",
    "occurred_at": iso(),
    "src_ip": "10.0.0.5",
    "dst_ip": "93.184.216.34",
    "dst_port": 21,
    "service": "ftp",
    "credentials_in_cleartext": True,
}


@pytest.fixture()
def sensor(client, admin):  # noqa: F811
    r = client.post("/api/sensors", json=SITE, headers=admin)
    assert r.status_code == 201, r.text
    return r.json()["sensor"], r.json()["api_key"]


def send(client, key, *observations):
    return client.post(
        "/api/network-telemetry",
        json={"observations": list(observations)},
        headers={"X-Sensor-Key": key},
    )


def events(client, analyst):  # noqa: F811
    return client.get("/api/security-events?limit=100", headers=analyst).json()["items"]


# ---------- sensor management ----------
def test_sensor_management_is_admin_only_and_key_shown_once(
    client, make_user, analyst, admin
):  # noqa: F811
    make_user("plain@example.com")
    plain = headers(client, "plain@example.com")
    assert client.post("/api/sensors", json=SITE).status_code == 401
    assert client.post("/api/sensors", json=SITE, headers=plain).status_code == 403
    assert client.post("/api/sensors", json=SITE, headers=analyst).status_code == 403
    created = client.post("/api/sensors", json=SITE, headers=admin).json()
    key = created["api_key"]
    assert key.startswith("ascent_sn_") and created["sensor"]["key_prefix"] == key[:14]
    listing = client.get("/api/sensors", headers=analyst)
    assert listing.status_code == 200 and key not in listing.text and "key_hash" not in listing.text
    assert client.get("/api/sensors", headers=plain).status_code == 403


def test_sensor_validation_and_lifecycle(client, admin, sensor):
    def post(body):
        return client.post("/api/sensors", json=body, headers=admin).status_code

    assert post(SITE) == 409
    assert post({**SITE, "name": "a/b"}) == 422
    assert post({**SITE, "name": "x", "kind": "router"}) == 422
    assert post({**SITE, "name": "x", "longitude": None}) == 422
    meta, old = sensor
    new = client.post(f"/api/sensors/{meta['id']}/rotate-key", headers=admin).json()["api_key"]
    assert send(client, old, CLEARTEXT).status_code == 401
    assert send(client, new, CLEARTEXT).status_code == 200
    assert client.delete(f"/api/sensors/{meta['id']}", headers=admin).status_code == 204
    assert send(client, new, CLEARTEXT).status_code == 401


def test_keys_are_not_interchangeable_between_endpoints_and_sensors(client, admin, sensor):
    ep_key = client.post("/api/endpoints", json=ENDPOINT_SITE, headers=admin).json()["api_key"]
    assert send(client, ep_key, CLEARTEXT).status_code == 401
    r = client.post(
        "/api/endpoint-telemetry", json={"observations": []}, headers={"X-Endpoint-Key": sensor[1]}
    )
    assert r.status_code == 401


# ---------- telemetry validation ----------
@pytest.mark.parametrize(
    "bad",
    [
        {"observations": []},
        {"observations": [CLEARTEXT] * 1001},
        {"observations": [{**CLEARTEXT, "surprise": 1}]},
        {"observations": [{**CLEARTEXT, "occurred_at": "2024-01-01T00:00:00"}]},
        {"observations": [{**CLEARTEXT, "occurred_at": iso(-120)}]},
        {"observations": [{**CLEARTEXT, "dst_port": 0}]},
        {"observations": [{**CLEARTEXT, "dst_ip": "300.1.1.1"}]},
        {"observations": [tls(version="TLSv9")]},
        {"observations": [tls(certificate=cert(not_after="2030-01-01T00:00:00"))]},
        {
            "observations": [
                {
                    "type": "arp_change",
                    "occurred_at": iso(),
                    "ip": "192.168.1.1",
                    "old_mac": "nope",
                    "new_mac": "aa:bb:cc:dd:ee:02",
                }
            ]
        },
        {"observations": [{"type": "dns_query", "occurred_at": iso()}]},
    ],
)
def test_telemetry_validation(client, sensor, bad):
    r = client.post("/api/network-telemetry", json=bad, headers={"X-Sensor-Key": sensor[1]})
    assert r.status_code == 422


def test_telemetry_requires_a_key(client, sensor):
    assert (
        client.post("/api/network-telemetry", json={"observations": [CLEARTEXT]}).status_code == 401
    )


# ---------- end to end ----------
def test_cleartext_credentials_become_an_event_inheriting_site_location_and_an_alert(
    client, sensor, analyst, session_factory  # noqa: F811
):
    r = send(client, sensor[1], CLEARTEXT)
    assert r.json() == {"received": 1, "findings": 1, "events_created": 1, "duplicates_skipped": 0}
    [ev] = events(client, analyst)
    assert ev["source"] == "sensor:hq-sensor" and ev["threat_type"] == "unsafe_network"
    assert (ev["severity"], ev["region"], ev["latitude"]) == ("high", "EMEA", 52.52)
    again = send(client, sensor[1], CLEARTEXT).json()
    assert (again["events_created"], again["duplicates_skipped"]) == (0, 1)
    with session_factory() as db:
        assert db.query(SecurityEvent).count() == 1 and db.query(Alert).count() == 1
        assert db.get(NetworkSensor, uuid.UUID(sensor[0]["id"])).last_seen_at is not None


def test_benign_batch_stores_no_events(client, sensor, session_factory):
    r = send(
        client,
        sensor[1],
        tls(),
        {**CLEARTEXT, "dst_port": 443, "service": "https", "credentials_in_cleartext": False},
    )
    assert r.json()["findings"] == 0
    with session_factory() as db:
        assert db.query(SecurityEvent).count() == 0


def baseline(session_factory):
    with session_factory() as db:
        return db.scalar(select(TlsBaseline))


def test_tls_baseline_lifecycle_learn_flag_resist_poisoning_adapt(
    client, sensor, analyst, session_factory
):  # noqa: F811
    key = sensor[1]
    # 1) Learn: three valid sightings establish the baseline; nothing is reported.
    for n in (30, 20, 10):
        assert send(client, key, tls(minutes_ago=n)).json()["findings"] == 0
    row = baseline(session_factory)
    assert (row.server_name, row.issuer, row.observations) == (HOST, "Example CA", 3)

    # 2) Flag: a different issuer with an untrusted chain is a possible interception.
    bad = tls(certificate=cert("Evil CA", chain_valid=False), minutes_ago=5)
    assert send(client, key, bad).json()["events_created"] == 1
    [ev] = events(client, analyst)
    assert ev["threat_type"] == "mitm" and ev["severity"] == "high"
    assert "Possible TLS interception" in ev["title"]

    # 3) No poisoning: the bad certificate did not become the new normal.
    row = baseline(session_factory)
    assert (row.issuer, row.observations) == ("Example CA", 3)
    retry = send(client, key, tls(certificate=cert("Evil CA", chain_valid=False), minutes_ago=4))
    assert retry.json()["duplicates_skipped"] == 1  # still flagged (deduplicated, not accepted)

    # 4) Adapt: a validly-issued certificate from another CA is flagged once (medium), then learned.
    other = tls(certificate=cert("Other CA"), minutes_ago=2)
    assert send(client, key, other).json()["events_created"] == 1
    assert baseline(session_factory).issuer == "Other CA"
    later = tls(certificate=cert("Other CA"), minutes_ago=1)
    assert send(client, key, later).json()["findings"] == 0
    titles = {e["title"] for e in events(client, analyst)}
    assert "Certificate issuer changed for a known host" in titles


def test_one_batch_can_establish_a_baseline_and_findings_use_the_pre_batch_state(client, sensor):
    key = sensor[1]
    first = send(client, key, *(tls(minutes_ago=30 - i) for i in range(5)))
    assert first.json()["findings"] == 0  # a batch never judges itself against what it teaches
    assert (
        send(client, key, tls(certificate=cert("Other CA"), minutes_ago=1)).json()["findings"] == 1
    )


def test_baselines_are_isolated_per_sensor(client, admin, sensor, analyst):  # noqa: F811
    for n in (30, 20, 10):
        send(client, sensor[1], tls(minutes_ago=n))
    second = client.post(
        "/api/sensors", json={**SITE, "name": "branch-sensor"}, headers=admin
    ).json()
    r = send(client, second["api_key"], tls(certificate=cert("Other CA", chain_valid=False)))
    codes = [e["title"] for e in events(client, analyst)]
    assert r.json()["findings"] == 1 and "Certificate failed validation" in codes
    assert not any("interception" in c.lower() for c in codes)  # no history on this sensor


def test_medium_findings_do_not_alert_but_high_do(client, sensor, session_factory):
    send(
        client,
        sensor[1],
        {**CLEARTEXT, "credentials_in_cleartext": False, "service": "telnet", "dst_port": 23},
    )  # medium: public cleartext protocol
    with session_factory() as db:
        assert db.query(SecurityEvent).count() == 1 and db.query(Alert).count() == 0
    send(
        client,
        sensor[1],
        {
            "type": "arp_change",
            "occurred_at": iso(),
            "ip": "192.168.1.1",
            "old_mac": "aa:bb:cc:dd:ee:01",
            "new_mac": "aa:bb:cc:dd:ee:02",
            "is_gateway": True,
        },
    )
    with session_factory() as db:
        assert db.query(Alert).count() == 1


# ---------- optional IP enrichment ----------
PUBLIC = {
    "type": "connection",
    "occurred_at": iso(),
    "src_ip": "10.0.0.5",
    "dst_ip": "8.8.4.4",
    "dst_port": 443,
}


def test_ip_enrichment_is_off_by_default(client, sensor, intel):  # noqa: F811
    assert send(client, sensor[1], PUBLIC).json()["findings"] == 0 and intel["calls"] == []


def test_known_malicious_destination_ip(client, sensor, intel, monkeypatch, analyst):  # noqa: F811
    monkeypatch.setattr(get_settings(), "network_ip_enrichment", True)
    private = {**PUBLIC, "dst_ip": "10.9.9.9"}
    r = send(client, sensor[1], PUBLIC, private)
    assert r.json()["events_created"] == 1
    assert {c.url.params.get("ipAddress") for c in intel["calls"] if "abuseipdb" in c.url.host} == {
        "8.8.4.4"
    }
    [ev] = events(client, analyst)
    assert ev["severity"] == "high" and "abuseipdb" in ev["description"]


def test_enrichment_outage_does_not_block_detection(
    client, sensor, intel, monkeypatch
):  # noqa: F811
    import httpx

    monkeypatch.setattr(get_settings(), "network_ip_enrichment", True)
    for host in list(intel["responders"]):
        intel["responders"][host] = lambda req: (_ for _ in ()).throw(httpx.ConnectError("down"))
    r = send(client, sensor[1], PUBLIC, CLEARTEXT)
    assert r.status_code == 200 and r.json()["events_created"] == 1
