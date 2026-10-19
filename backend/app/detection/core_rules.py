"""Dependency-free, fail-closed evaluator for normalized security events.

Rules are data, never executable expressions. Catalog entries default to draft and disabled.
This module is additive; it does not replace existing phishing/file analysis routes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SEVERITIES = {"low", "medium", "high", "critical"}
LIFECYCLE = {"draft", "test", "shadow", "production", "review", "retired"}
OPERATORS = {"eq", "ne", "contains", "in", "gte", "gt", "lte", "lt", "exists"}


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
        if not self.id.strip() or not self.title.strip() or not self.source.strip():
            raise ValueError("rule id, title and source are required")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.lifecycle not in LIFECYCLE:
            raise ValueError(f"unsupported lifecycle: {self.lifecycle}")
        if self.lifecycle != "production" and self.enabled:
            raise ValueError("only production rules may be enabled")
        if not self.conditions:
            raise ValueError("conditions must not be empty")
        for condition in self.conditions:
            if not isinstance(condition, dict) or not isinstance(condition.get("field"), str):
                raise ValueError("each condition needs a field")
            if not condition["field"].strip() or any(not p for p in condition["field"].split(".")):
                raise ValueError("condition field path is invalid")
            if condition.get("op") not in OPERATORS:
                raise ValueError(f"unsupported operator: {condition.get('op')}")
            if condition["op"] == "exists":
                if not isinstance(condition.get("value"), bool):
                    raise ValueError("exists operator requires a boolean value")
            elif "value" not in condition:
                raise ValueError("condition value is required")
            if condition["op"] == "in" and not isinstance(condition["value"], (list, tuple, set, str)):
                raise ValueError("in operator value must be a list, tuple, set or string")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Rule:
        if not isinstance(raw, dict):
            raise ValueError("each rule must be an object")
        required = ("id", "title", "source", "severity", "confidence", "conditions")
        missing = [key for key in required if key not in raw]
        if missing:
            raise ValueError("missing required rule fields: " + ", ".join(missing))
        conditions = raw["conditions"]
        if not isinstance(conditions, list) or not conditions:
            raise ValueError("conditions must be a non-empty list")
        techniques = raw.get("mitre_techniques", [])
        if not isinstance(techniques, list) or not all(isinstance(t, str) for t in techniques):
            raise ValueError("mitre_techniques must be a list of strings")
        enabled = raw.get("enabled", False)
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a boolean")
        return cls(
            id=str(raw["id"]), title=str(raw["title"]), source=str(raw["source"]),
            severity=str(raw["severity"]), confidence=float(raw["confidence"]),
            conditions=tuple(conditions), mitre_techniques=tuple(techniques),
            fp_notes=str(raw.get("fp_notes", "Validate against representative benign telemetry.")),
            owner=str(raw.get("owner", "ascent-detection")), last_tested=raw.get("last_tested"),
            playbook=raw.get("playbook"), lifecycle=str(raw.get("lifecycle", "draft")),
            enabled=enabled,
        )


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow ECS-inspired event without fabricating asset or identity fields."""
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
    found, actual = _get_path(event, condition["field"])
    op, expected = condition["op"], condition.get("value")
    if op == "exists":
        return found is expected
    if not found:
        return False
    try:
        if op == "eq":
            return actual == expected
        if op == "ne":
            return actual != expected
        if op == "contains":
            return isinstance(actual, (str, list, tuple, set, dict)) and expected in actual
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
    """Match only explicitly enabled production rules; conditions are ANDed."""
    event = normalize_event(event)
    if not rule.enabled or rule.lifecycle != "production":
        return None
    if rule.source != "*" and event.get("source") != rule.source:
        return None
    if not all(_matches_condition(event, condition) for condition in rule.conditions):
        return None
    return {
        "rule_id": rule.id, "title": rule.title, "severity": rule.severity,
        "confidence": rule.confidence, "mitre_techniques": list(rule.mitre_techniques),
        "event": event,
    }


def load_rules(rows: list[dict[str, Any]]) -> dict[str, Rule]:
    """Validate a catalog and reject duplicate IDs rather than silently overriding."""
    if not isinstance(rows, list):
        raise ValueError("rule catalog must be a list")
    result: dict[str, Rule] = {}
    for row in rows:
        rule = Rule.from_dict(row)
        if rule.id in result:
            raise ValueError(f"duplicate rule id: {rule.id}")
        result[rule.id] = rule
    return result


def load_catalog(path: str | Path | None = None) -> dict[str, Rule]:
    """Load the repository's JSON catalog, failing closed on malformed or duplicate data."""
    catalog_path = Path(path) if path else (
        Path(__file__).resolve().parents[2] / "rules" / "core" / "core_rules.json"
    )
    try:
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read rule catalog: {catalog_path}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("unsupported or invalid rule catalog schema")
    return load_rules(payload.get("rules"))
