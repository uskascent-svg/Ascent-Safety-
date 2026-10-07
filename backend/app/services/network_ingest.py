"""Turn a network-telemetry batch into findings, events and alerts, maintaining TLS baselines."""

import hashlib
import logging
from datetime import UTC, datetime
from ipaddress import ip_address

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.detection.network.detectors import _RANK, norm_issuer, tls_name
from app.detection.network.engine import evaluate
from app.detection.network.types import BaselineSnapshot, Context, Finding
from app.models import EventStatus, NetworkFinding, NetworkSensor, Severity, ThreatType, TlsBaseline
from app.schemas.endpoint import BatchResult
from app.schemas.network import ConnectionObs, NetworkObservation, TlsObs
from app.schemas.security import SecurityEventCreate
from app.services import event_ingest
from app.services.threat_intel import aggregator

log = logging.getLogger("ascent.network")
DEDUPE_BUCKET_SECONDS = 600
MAX_IP_LOOKUPS = 5


def _load_context(db: Session, sensor: NetworkSensor, obs: list[NetworkObservation]) -> Context:
    names = {tls_name(o) for o in obs if isinstance(o, TlsObs)}
    ctx = Context()
    if names:
        for row in db.scalars(
            select(TlsBaseline).where(
                TlsBaseline.sensor_id == sensor.id, TlsBaseline.server_name.in_(names)
            )
        ):
            ctx.tls[row.server_name] = BaselineSnapshot(
                norm_issuer(row.issuer),
                row.cert_sha256,
                row.max_tls_version,
                row.observations,
                row.issuer,
            )
    return ctx


def _is_good(o: TlsObs) -> bool:
    c = o.certificate
    return bool(
        c
        and c.chain_valid is True
        and c.hostname_match is not False
        and not c.self_signed
        and c.not_after >= o.occurred_at
    )


def update_baselines(db: Session, sensor: NetworkSensor, obs: list[NetworkObservation]) -> None:
    """Learn only from certificates that passed validation, so attacks never become 'normal'."""
    for o in sorted(
        (x for x in obs if isinstance(x, TlsObs) and _is_good(x)), key=lambda x: x.occurred_at
    ):
        name = tls_name(o)
        row = db.scalar(
            select(TlsBaseline).where(
                TlsBaseline.sensor_id == sensor.id, TlsBaseline.server_name == name
            )
        )
        if row is None:
            db.add(
                TlsBaseline(
                    sensor_id=sensor.id,
                    server_name=name,
                    issuer=o.certificate.issuer,
                    cert_sha256=o.certificate.sha256,
                    max_tls_version=o.tls_version,
                    observations=1,
                    first_seen=o.occurred_at,
                    last_seen=o.occurred_at,
                )
            )
            db.flush()
            continue
        row.issuer, row.cert_sha256 = o.certificate.issuer, o.certificate.sha256
        if _RANK[o.tls_version] > _RANK[row.max_tls_version]:
            row.max_tls_version = o.tls_version
        row.observations += 1
        row.last_seen = max(
            (row.last_seen.replace(tzinfo=UTC) if row.last_seen.tzinfo is None else row.last_seen),
            o.occurred_at,
        )


def ip_findings(db: Session, obs: list[NetworkObservation]) -> list[Finding]:
    """Optional: ask threat-intel providers about public destination IPs contacted."""
    if not any("ip" in p.types for p in aggregator.configured_providers()):
        return []
    seen: dict[str, tuple[str, datetime]] = {}
    for o in obs:
        if isinstance(o, ConnectionObs) and o.state == "established":
            ip = ip_address(str(o.dst_ip))
            if ip.is_global and str(ip) not in seen and len(seen) < MAX_IP_LOOKUPS:
                seen[str(ip)] = (f"{o.src_ip} -> {ip}:{o.dst_port}", o.occurred_at)
    out: list[Finding] = []
    for lk in aggregator.lookup_many(db, [(ip, "ip") for ip in seen]) if seen else []:
        if lk.verdict != "malicious":
            continue
        label, when = seen[lk.indicator]
        flagged = [r.provider for r in lk.results if r.status == "ok" and r.verdict == "malicious"]
        out.append(
            Finding(
                "threat_intel",
                "KNOWN_MALICIOUS_IP",
                "high",
                "Connection to an IP flagged as malicious",
                "A host on the network connected to a public IP address that threat-intelligence "
                "services flag as malicious.",
                when,
                [label, f"flagged by: {', '.join(flagged)}"],
                f"BADIP|{lk.indicator}",
                "other",
            )
        )
    return out


def _dedupe_key(sensor: NetworkSensor, f: Finding) -> str:
    bucket = int(f.occurred_at.timestamp()) // DEDUPE_BUCKET_SECONDS
    return hashlib.sha256(f"{sensor.id}|{f.code}|{f.fingerprint}|{bucket}".encode()).hexdigest()


def process_batch(
    db: Session, sensor: NetworkSensor, obs: list[NetworkObservation], request: Request | None
) -> BatchResult:
    findings = evaluate(obs, _load_context(db, sensor, obs))  # judged against PRE-batch baselines
    if get_settings().network_ip_enrichment:
        try:
            findings += ip_findings(db, obs)
        except Exception:  # enrichment is best-effort
            log.exception("IP enrichment failed")
    update_baselines(db, sensor, obs)
    db.commit()

    created = duplicates = 0
    for f in findings:
        payload = SecurityEventCreate(
            source=f"sensor:{sensor.name}",
            external_id=_dedupe_key(sensor, f),
            threat_type=ThreatType(f.threat_type),
            severity=Severity(f.severity),
            status=EventStatus.OPEN,
            title=f.title[:200],
            description=(f.description + "\nEvidence: " + "; ".join(f.evidence))[:4000],
            country=sensor.country,
            region=sensor.region,
            latitude=sensor.latitude,
            longitude=sensor.longitude,
            occurred_at=f.occurred_at,
        )
        try:
            event = event_ingest.store_event(
                db, payload, request, {"sensor_id": str(sensor.id), "code": f.code}
            )
        except event_ingest.DuplicateEvent:
            duplicates += 1
            continue
        db.add(
            NetworkFinding(
                sensor_id=sensor.id,
                event_id=event.id,
                detector=f.detector,
                code=f.code,
                severity=f.severity,
                title=f.title,
                description=f.description,
                evidence=f.evidence,
                occurred_at=f.occurred_at,
            )
        )
        db.commit()
        event_ingest.publish(event)
        created += 1

    sensor.last_seen_at = datetime.now(UTC)
    db.commit()
    return BatchResult(
        received=len(obs),
        findings=len(findings),
        events_created=created,
        duplicates_skipped=duplicates,
    )
