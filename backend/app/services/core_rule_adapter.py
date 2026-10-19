"""Safe shadow adapter from persisted security events to the core rule evaluator.

Only fields present in the existing event model are mapped. In particular, title and
description are never treated as an event.action, and source names are not guessed into
source families. Matches are audit metadata only until alert persistence and promotion
controls are explicitly implemented.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any

from app.detection.core_rules import Rule, evaluate_catalog, load_catalog


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


def evaluate_security_event(event: Any) -> dict[str, Any]:
    """Run catalog in shadow mode; fail closed without disrupting event ingestion."""
    try:
        normalized = security_event_to_normalized(event)
        catalog = _catalog()
    except (OSError, ValueError, TypeError) as exc:
        return {
            "status": "unavailable",
            "match_count": 0,
            "matches": [],
            "reason": type(exc).__name__,
        }

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
