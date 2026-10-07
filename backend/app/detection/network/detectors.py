"""Network-telemetry detectors. They judge only what sensors report; they cannot see traffic
themselves. Wording is deliberately cautious ("possible"): several indicators have benign causes
(e.g. corporate TLS-inspection proxies, certificate rotation, monitoring agents)."""

import re
import statistics
from collections import defaultdict
from ipaddress import ip_address

from app.core.config import get_settings
from app.detection.network.types import Context, Finding
from app.schemas.network import (
    ArpChangeObs,
    ConnectionObs,
    NetworkObservation,
    TlsObs,
    WifiObs,
)

_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_RANK = {"SSLv2": 0, "SSLv3": 1, "TLSv1.0": 2, "TLSv1.1": 3, "TLSv1.2": 4, "TLSv1.3": 5}
_DEPRECATED = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
_CLEARTEXT_SERVICES = {"telnet", "ftp", "rlogin", "rsh", "pop3", "imap"}


def clip(text: str, n: int = 200) -> str:
    return _CTRL.sub(" ", text)[:n]


def norm_issuer(issuer: str) -> str:
    return " ".join(issuer.lower().split())


def tls_name(o: TlsObs) -> str:
    return (o.server_name or str(o.server_ip)).lower()


def _is_public(ip) -> bool:
    return ip_address(str(ip)).is_global


def _f(o_time, code, sev, title, desc, evidence, fp, ttype, detector):
    return Finding(detector, code, sev, title, desc, o_time, evidence, fp, ttype)


def detect_tls(obs: list[NetworkObservation], ctx: Context) -> list[Finding]:
    settings = get_settings()
    out: list[Finding] = []
    for o in (x for x in obs if isinstance(x, TlsObs)):
        name, cert = tls_name(o), o.certificate
        base = ctx.tls.get(name)
        established = (
            base is not None and base.observations >= settings.tls_baseline_min_observations
        )
        problems: list[str] = []
        if cert:
            if cert.self_signed:
                problems.append("self-signed certificate")
            if cert.chain_valid is False:
                problems.append("untrusted certificate chain")
            if cert.hostname_match is False:
                problems.append("certificate does not match the hostname")
        issuer_changed = bool(established and cert and norm_issuer(cert.issuer) != base.issuer)
        downgraded = bool(established and _RANK[o.tls_version] < _RANK[base.max_tls_version])
        evidence = [f"host: {clip(name)}", f"tls: {o.tls_version}"]
        if cert:
            evidence.append(f"issuer: {clip(cert.issuer)}")
        if established and cert:
            evidence.append(f"previously seen issuer: {clip(base.issuer_raw or base.issuer)}")
        if problems:
            evidence.append("; ".join(problems))
        fp = f"{name}|{cert.issuer if cert else ''}|{cert.sha256 if cert else ''}"

        def add(code, sev, title, desc, ttype="mitm", o=o, evidence=evidence, fp=fp):
            out.append(
                _f(o.occurred_at, code, sev, title, desc, evidence, f"{code}|{fp}", ttype, "tls")
            )

        if issuer_changed and problems:
            add(
                "POSSIBLE_TLS_INTERCEPTION",
                "high",
                "Possible TLS interception for a known host",
                f"{name} previously presented a valid certificate from a different issuer; the "
                f"certificate now seen has problems ({'; '.join(problems)}). This can indicate a "
                "man-in-the-middle, but a TLS-inspection proxy or misconfiguration can look the same.",
            )
        elif issuer_changed:
            add(
                "TLS_ISSUER_CHANGED",
                "medium",
                "Certificate issuer changed for a known host",
                f"{name} now presents a valid certificate from a different issuer than before. "
                "Legitimate CA changes cause this; so can interception by a trusted CA.",
            )
        elif problems and established:
            add(
                "TLS_CERT_INVALID_FOR_KNOWN_HOST",
                "medium",
                "Certificate problems for a previously valid host",
                f"{name} had valid certificates before but now shows: {'; '.join(problems)}.",
            )
        elif problems:
            add(
                "TLS_CERT_VALIDATION_FAILURE",
                "low",
                "Certificate failed validation",
                f"The certificate for {name} has problems: {'; '.join(problems)}. There is no "
                "history for this host, so this may just be a misconfigured server.",
                "unsafe_network",
            )
        if cert and cert.not_after < o.occurred_at:
            add(
                "TLS_CERT_EXPIRED",
                "low",
                "Expired certificate presented",
                f"{name} presented a certificate that had already expired.",
                "unsafe_network",
            )
        if downgraded:
            add(
                "TLS_VERSION_DOWNGRADE",
                "medium",
                "TLS version lower than previously seen",
                f"{name} previously negotiated {base.max_tls_version} but now {o.tls_version}. "
                "Downgrades are a technique used to weaken encryption.",
            )
        elif o.tls_version in _DEPRECATED:
            add(
                "TLS_DEPRECATED_VERSION",
                "low",
                "Deprecated TLS/SSL version in use",
                f"{name} negotiated {o.tls_version}, which is considered insecure.",
                "unsafe_network",
            )
    return out


def detect_cleartext(obs: list[NetworkObservation], ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for o in (x for x in obs if isinstance(x, ConnectionObs) and x.state == "established"):
        svc = (o.service or "").lower()
        target = f"{o.src_ip} -> {o.dst_ip}:{o.dst_port}"
        if o.credentials_in_cleartext:
            out.append(
                _f(
                    o.occurred_at,
                    "UNENCRYPTED_CREDENTIALS",
                    "high",
                    "Credentials sent without encryption",
                    f"The sensor observed login credentials in cleartext ({svc or 'unknown service'}).",
                    [target, f"service: {svc or 'unknown'}"],
                    f"CLEARCRED|{svc}|{o.src_ip}|{o.dst_ip}|{o.dst_port}",
                    "unsafe_network",
                    "cleartext",
                )
            )
        elif svc in _CLEARTEXT_SERVICES and o.encrypted is not True:
            sev = "medium" if _is_public(o.dst_ip) else "low"
            out.append(
                _f(
                    o.occurred_at,
                    "CLEARTEXT_PROTOCOL",
                    sev,
                    f"Unencrypted {svc} traffic",
                    f"{svc} is an unencrypted protocol and was used"
                    + (" across the internet." if sev == "medium" else " on the local network."),
                    [target],
                    f"CLEAR|{svc}|{o.src_ip}|{o.dst_ip}|{o.dst_port}",
                    "unsafe_network",
                    "cleartext",
                )
            )
    return out


def detect_scanning(obs: list[NetworkObservation], ctx: Context) -> list[Finding]:
    settings = get_settings()
    by_src: dict[str, list[ConnectionObs]] = defaultdict(list)
    for o in obs:
        if isinstance(o, ConnectionObs):
            by_src[str(o.src_ip)].append(o)
    out: list[Finding] = []
    for src, conns in by_src.items():
        targets = {(str(c.dst_ip), c.dst_port) for c in conns}
        hosts = {t[0] for t in targets}
        failed = sum(1 for c in conns if c.state != "established") / len(conns)
        span = (
            max(c.occurred_at for c in conns) - min(c.occurred_at for c in conns)
        ).total_seconds()
        if len(targets) < settings.portscan_min_targets or failed < 0.7 or span > 600:
            continue
        kind = "hosts" if len(hosts) >= len(targets) / 2 else "ports"
        sev = "high" if len(targets) >= 5 * settings.portscan_min_targets else "medium"
        out.append(
            _f(
                max(c.occurred_at for c in conns),
                "PORT_SCAN_ACTIVITY",
                sev,
                "Probable port or host scan",
                f"{src} attempted {len(targets)} distinct destination {kind} in {int(span)}s with "
                f"{failed:.0%} of attempts not completing. Vulnerability scanners do this too.",
                [f"source: {src}", f"targets: {len(targets)} ({len(hosts)} hosts)"],
                f"SCAN|{src}",
                "other",
                "scan",
            )
        )
    return out


def detect_beaconing(obs: list[NetworkObservation], ctx: Context) -> list[Finding]:
    settings = get_settings()
    groups: dict[tuple, list[ConnectionObs]] = defaultdict(list)
    for o in obs:
        if isinstance(o, ConnectionObs) and o.state == "established" and _is_public(o.dst_ip):
            groups[(str(o.src_ip), str(o.dst_ip), o.dst_port)].append(o)
    out: list[Finding] = []
    for (src, dst, port), conns in groups.items():
        if len(conns) < settings.beacon_min_connections:
            continue
        times = sorted(c.occurred_at.timestamp() for c in conns)
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        mean = statistics.fmean(gaps)
        if mean < 5 or statistics.pstdev(gaps) / mean > settings.beacon_max_jitter:
            continue
        out.append(
            _f(
                max(c.occurred_at for c in conns),
                "PERIODIC_BEACONING",
                "medium",
                "Regular, machine-like connections to an external host",
                f"{src} connected to {dst}:{port} {len(conns)} times at near-constant "
                f"{mean:.0f}s intervals. Malware command-and-control often looks like this; so do "
                "monitoring agents and update checks.",
                [f"{src} -> {dst}:{port}", f"connections: {len(conns)}, interval ~{mean:.0f}s"],
                f"BEACON|{src}|{dst}|{port}",
                "other",
                "beacon",
            )
        )
    return out


def detect_arp(obs: list[NetworkObservation], ctx: Context) -> list[Finding]:
    return [
        _f(
            o.occurred_at,
            "POSSIBLE_ARP_SPOOFING_GATEWAY",
            "high",
            "Gateway hardware address changed",
            f"The MAC address for gateway {o.ip} changed from {o.old_mac} to {o.new_mac}. This is "
            "how ARP-spoofing man-in-the-middle attacks look; failover or replacement hardware can too.",
            [f"{o.ip}: {o.old_mac} -> {o.new_mac}"],
            f"ARP|{o.ip}|{o.new_mac}",
            "mitm",
            "arp",
        )
        for o in obs
        if isinstance(o, ArpChangeObs) and o.is_gateway
    ]


def detect_wifi(obs: list[NetworkObservation], ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    by_ssid: dict[str, list[WifiObs]] = defaultdict(list)
    for o in obs:
        if isinstance(o, WifiObs):
            by_ssid[o.ssid.lower()].append(o)
            if o.connected and o.security in {"open", "wep"}:
                out.append(
                    _f(
                        o.occurred_at,
                        f"UNSAFE_WIFI_{o.security.upper()}",
                        "medium",
                        f"Connected to {o.security} Wi-Fi network",
                        f"Network '{clip(o.ssid, 32)}' is {o.security}"
                        + (
                            ", so traffic is not encrypted over the air."
                            if o.security == "open"
                            else ", whose encryption is broken."
                        ),
                        [f"ssid: {clip(o.ssid, 32)}", f"bssid: {o.bssid}"],
                        f"WIFI|{o.security}|{o.ssid.lower()}|{o.bssid}",
                        "unsafe_network",
                        "wifi",
                    )
                )
    for ssid, aps in by_ssid.items():
        secs = {a.security for a in aps}
        if len({a.bssid for a in aps}) >= 2 and "open" in secs and secs - {"open", "unknown"}:
            out.append(
                _f(
                    max(a.occurred_at for a in aps),
                    "POSSIBLE_EVIL_TWIN",
                    "high",
                    "Same Wi-Fi name offered with different security",
                    f"'{clip(ssid, 32)}' is advertised by multiple access points, one of them "
                    "open while others are secured. Rogue 'evil twin' access points do this.",
                    [f"ssid: {clip(ssid, 32)}"] + [f"{a.bssid}: {a.security}" for a in aps[:4]],
                    f"TWIN|{ssid}",
                    "mitm",
                    "wifi",
                )
            )
    return out
