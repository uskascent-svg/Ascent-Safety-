"""Safe adapters from persisted events and authenticated endpoint telemetry to core rules."""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import PureWindowsPath
from typing import Any

from app.detection.core_rules import Rule, evaluate_catalog, load_catalog
from app.detection.malware.types import Finding
from app.schemas.endpoint import Observation, PersistenceObs, ProcessObs

@lru_cache(maxsize=1)
def _catalog() -> dict[str, Rule]:
    return load_catalog()


def security_event_to_normalized(event: Any) -> dict[str, Any]:
    """Map known persisted event fields without fabricating action, user, or asset context."""
    source = getattr(event, "source", None)
    occurred_at = getattr(event, "occurred_at", None)
    threat_type = getattr(event, "threat_type", None)
    severity = getattr(event, "severity", None)
    status = getattr(event, "status", None)
    title = getattr(event, "title", None)
    if not isinstance(source, str) or not source:
        raise ValueError("security event source is required")
    return {
        "source": source,
        "timestamp": occurred_at.isoformat() if occurred_at is not None else None,
        "event": {
            "kind": "alert",
            "category": [threat_type] if isinstance(threat_type, str) and threat_type else [],
            "type": [status] if isinstance(status, str) and status else [],
            "severity": severity if isinstance(severity, str) else None,
        },
        "security_event": {
            "title": title if isinstance(title, str) else None,
            "threat_type": threat_type if isinstance(threat_type, str) else None,
            "status": status if isinstance(status, str) else None,
        },
    }


def endpoint_observation_to_normalized(observation: Observation) -> dict[str, Any]:
    """Map only fields explicitly supplied by the authenticated endpoint agent.

    This is a normalized rule-evaluation view, not a persisted raw-telemetry record.
    In particular, persistence targets are not treated as Windows event IDs or task XML.
    """
    data = observation.model_dump(mode="json")
    normalized: dict[str, Any] = {
        "source": "endpoint",
        "timestamp": data.get("occurred_at"),
        "event": {"kind": "event"},
    }
    if isinstance(observation, ProcessObs):
        normalized["process"] = {
            "name": PureWindowsPath(observation.image).name.lower(),
            "image": observation.image,
            "command_line": observation.command_line or "",
            "parent_image": observation.parent_image,
            "user": observation.user,
            "sha256": observation.sha256,
        }
    elif isinstance(observation, PersistenceObs):
        normalized["persistence"] = {
            "mechanism": observation.mechanism,
            "target": observation.target,
            "name": observation.name,
            "process_image": observation.process_image,
            "signed": observation.signed,
        }
    else:
        # Unsupported observation kinds deliberately have no process/persistence fields.
        normalized["observation"] = {"type": data.get("type")}
    return normalized


def evaluate_endpoint_observations(observations: list[Observation]) -> list[Finding]:
    """Convert matches from enabled production rules into existing endpoint findings.

    Draft candidates remain inert. Raw command lines and persistence targets are not copied
    into the resulting finding; a digest is used only for deduplication.
    """
    findings: list[Finding] = []
    catalog = _catalog()
    for observation in observations:
        normalized = endpoint_observation_to_normalized(observation)
        for match in evaluate_catalog(catalog, normalized):
            rule_id = match["rule_id"]
            technique_ids = match.get("mitre_techniques", [])
            digest = hashlib.sha256(
                json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            findings.append(
                Finding(
                    detector="core_rules",
                    code=rule_id,
                    severity=match["severity"],
                    title=match["title"][:200],
                    description=(
                        f"Enabled core detection rule {rule_id} matched authenticated endpoint "
                        "telemetry. Review the rule conditions and source event."
                    ),
                    occurred_at=observation.occurred_at,
                    evidence=[
                        f"rule_id: {rule_id}",
                        f"mitre_techniques: {', '.join(technique_ids) or 'not mapped'}",
                    ],
                    fingerprint=f"{rule_id}:{digest}",
                )
            )
    return findings


def evaluate_security_event(event: Any) -> dict[str, Any]:
    """Run catalog in shadow mode; fail closed without disrupting event ingestion."""
    try:
        normalized = security_event_to_normalized(event)
        catalog = _catalog()
    except (OSError, ValueError, TypeError) as exc:
        return {"status": "unavailable", "match_count": 0, "matches": [], "reason": type(exc).__name__}
    matches = evaluate_catalog(catalog, normalized)
    return {
        "status": "evaluated",
        "match_count": len(matches),
        "matches": [
            {
                "rule_id": match["rule_id"],
                "title": match["title"],
                "severity": match["severity"],
                "confidence": match["confidence"],
            }
            for match in matches
        ],
    }
