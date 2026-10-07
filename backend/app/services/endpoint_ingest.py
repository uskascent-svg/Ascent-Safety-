"""Turn a telemetry batch into findings, events and (via the shared ingest service) alerts."""

import hashlib
import logging
from datetime import UTC, datetime

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.detection.malware.engine import evaluate
from app.detection.malware.types import Finding
from app.models import Endpoint, EndpointFinding, EventStatus, Severity, ThreatType
from app.schemas.endpoint import BatchResult, FileObs, Observation, ProcessObs
from app.schemas.security import SecurityEventCreate
from app.services import event_ingest
from app.services.threat_intel import aggregator
from app.services.threat_intel.indicators import IndicatorError, normalize

log = logging.getLogger("ascent.endpoint")
DEDUPE_BUCKET_SECONDS = 600  # repeats of the same finding within 10 minutes are collapsed
MAX_HASH_LOOKUPS = 5


def hash_findings(db: Session, observations: list[Observation]) -> list[Finding]:
    """Optional enrichment: ask threat-intel providers about file hashes seen on the endpoint."""
    if not any("hash" in p.types for p in aggregator.configured_providers()):
        return []
    seen: dict[str, tuple[str, datetime]] = {}
    for o in observations:
        digest, label = None, None
        if isinstance(o, ProcessObs) and o.sha256:
            digest, label = o.sha256, o.image
        elif isinstance(o, FileObs) and o.sha256 and o.action in {"created", "executed"}:
            digest, label = o.sha256, o.path
        if digest and digest not in seen and len(seen) < MAX_HASH_LOOKUPS:
            try:
                seen[normalize(digest, "hash")] = (label or "", o.occurred_at)
            except IndicatorError:
                continue
    if not seen:
        return []
    out: list[Finding] = []
    for lookup in aggregator.lookup_many(db, [(h, "hash") for h in seen]):
        if lookup.verdict != "malicious":
            continue
        label, when = seen[lookup.indicator]
        flagged = [
            r.provider for r in lookup.results if r.status == "ok" and r.verdict == "malicious"
        ]
        out.append(
            Finding(
                "threat_intel",
                "KNOWN_MALICIOUS_FILE_HASH",
                "critical",
                "File matches a known-malicious hash",
                "A file seen on this endpoint has a SHA-256 hash that threat-intelligence services "
                "flag as malicious.",
                when,
                [
                    f"file: {label[:200]}",
                    f"sha256: {lookup.indicator}",
                    f"flagged by: {', '.join(flagged)}",
                ],
                f"HASH|{lookup.indicator}",
            )
        )
    return out


def _dedupe_key(endpoint: Endpoint, f: Finding) -> str:
    bucket = int(f.occurred_at.timestamp()) // DEDUPE_BUCKET_SECONDS
    raw = f"{endpoint.id}|{f.code}|{f.fingerprint}|{bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()


def process_batch(
    db: Session, endpoint: Endpoint, observations: list[Observation], request: Request | None
) -> BatchResult:
    findings = evaluate(observations)
    if get_settings().endpoint_hash_enrichment:
        try:
            findings += hash_findings(db, observations)
        except Exception:  # enrichment is best-effort; behavioural detection must still be stored
            log.exception("Hash enrichment failed")

    created = duplicates = 0
    for f in findings:
        description = f.description + "\nEvidence: " + "; ".join(f.evidence)
        payload = SecurityEventCreate(
            source=f"endpoint:{endpoint.name}",
            external_id=_dedupe_key(endpoint, f),
            threat_type=ThreatType.MALWARE_RANSOMWARE,
            severity=Severity(f.severity),
            status=EventStatus.OPEN,
            title=f.title[:200],
            description=description[:4000],
            country=endpoint.country,
            region=endpoint.region,
            latitude=endpoint.latitude,
            longitude=endpoint.longitude,
            occurred_at=f.occurred_at,
        )
        try:
            event = event_ingest.store_event(
                db, payload, request, {"endpoint_id": str(endpoint.id), "code": f.code}
            )
        except event_ingest.DuplicateEvent:
            duplicates += 1
            continue
        db.add(
            EndpointFinding(
                endpoint_id=endpoint.id,
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
        db.commit()  # one transaction per event so a duplicate race cannot undo earlier ones
        event_ingest.publish(event)
        created += 1

    endpoint.last_seen_at = datetime.now(UTC)
    db.commit()
    return BatchResult(
        received=len(observations),
        findings=len(findings),
        events_created=created,
        duplicates_skipped=duplicates,
    )
