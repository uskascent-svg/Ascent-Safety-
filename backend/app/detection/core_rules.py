"""Small, dependency-free core rule engine for normalized security events.

This is an additive foundation. It does not replace the existing phishing/file analyzer.
Rules are explicit data, draft by default, and must be validated before production use.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SEVERITIES = {"low", "medium", "high", "critical"}
LIFECYCLE = {"draft", "test", "shadow", "production", "review", "retired"}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    source: str
    severity: str
    confidence: float
    conditions: tuple[dict[str, Any], ...]
    mitre_techniques: tuple[str, ...] = ()
    fp_notes: str = "Validate against representative benign telemetry."
    owner: str = "ascent-detection"
    last_tested: str | None = None
    playbook: str | None = None
    lifecycle: str = "draft"
    enabled: bool = False

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("rule id is required")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.lifecycle not in LIFECYCLE:
            raise ValueError(f"unsupported lifecycle: {self.lifecycle}")
        if self.lifecycle != "production" and self.enabled:
            raise ValueError("only production rules may be enabled")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Rule":
        required = ("id", "title", "source", "severity", "confidence", "conditions")
        missing = [key for key in required if key not in raw]
        if missing:
            raise ValueError("missing required rule fields: " + ", ".join(missing))
        conditions = raw["conditions"]
        if not isinstance(conditions, list) or not conditions:
            raise ValueError("conditions must be a non-empty list")
        allowed_ops = {"eq", "ne", "contains", "in", "gte", "gt", "lte", "lt", "exists"}
        for condition in conditions:
            if not isinstance(condition, dict) or not condition.get("field"):
                raise ValueError("each condition needs a field")
            if condition.get("op") not in allowed_ops:
                raise ValueError(f"unsupported operator: {condition.get('op')}")
            if condition["op"] != "exists" and "value" not in condition:
                raise ValueError("condition value is required")
        return cls(
            id=str(raw["id"]), title=str(raw["title"]), source=str(raw["source"]),
            severity=str(raw["severity"]), confidence=float(raw["confidence"]),
            conditions=tuple(conditions),
            mitre_techniques=tuple(raw.get("mitre_techniques", ())),
            fp_notes=str(raw.get("fp_notes", "Validate against representative benign telemetry.")),
            owner=str(raw.get("owner", "ascent-detection")),
            last_tested=raw.get("last_tested"), playbook=raw.get("playbook"),
            lifecycle=str(raw.get("lifecycle", "draft")), enabled=bool(raw.get("enabled", False)),
        )


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow, predictable ECS-inspired event without inventing fields."""
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    normalized = dict(event)
    if "event" in normalized and not isinstance(normalized["event"], dict):
        raise ValueError("event.event must be an object")
    if "source" in normalized and not isinstance(normalized["source"], str):
        raise ValueError("event.source must be a string")
    if "timestamp" not in normalized and "@timestamp" in normalized:
        normalized["timestamp"] = normalized["@timestamp"]
    if "event" not in normalized:
        normalized["event"] = {}
    return normalized


def _get_path(value: dict[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _matches_condition(event: dict[str, Any], condition: dict[str, Any]) -> bool:
    found, actual = _get_path(event, str(condition["field"]))
    op, expected = condition["op"], condition.get("value")
    if op == "exists":
        return found is bool(expected)
    if not found:
        return False
    try:
        if op == "eq":
            return actual == expected
        if op == "ne":
            return actual != expected
        if op == "contains":
            return expected in actual
        if op == "in":
            return actual in expected
        if op == "gte":
            return actual >= expected
        if op == "gt":
            return actual > expected
        if op == "lte":
            return actual <= expected
        if op == "lt":
            return actual < expected
    except (TypeError, ValueError):
        return False
    return False


def evaluate_rule(rule: Rule, event: dict[str, Any]) -> dict[str, Any] | None:
    """Match an event against an enabled production rule; all conditions are ANDed."""
    event = normalize_event(event)
    if not rule.enabled or rule.lifecycle != "production":
        return None
    if rule.source != "*" and event.get("source") != rule.source:
        return None
    if not all(_matches_condition(event, condition) for condition in rule.conditions):
        return None
    return {
        "rule_id": rule.id,
        "title": rule.title,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "mitre_techniques": list(rule.mitre_techniques),
        "event": event,
    }


def load_rules(rows: list[dict[str, Any]]) -> dict[str, Rule]:
    """Validate a catalog and reject duplicate IDs rather than silently overriding."""
    result: dict[str, Rule] = {}
    for row in rows:
        rule = Rule.from_dict(row)
        if rule.id in result:
            raise ValueError(f"duplicate rule id: {rule.id}")
        result[rule.id] = rule
    return result
