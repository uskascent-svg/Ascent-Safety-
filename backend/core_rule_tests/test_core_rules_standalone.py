import json
from dataclasses import replace
from pathlib import Path

import pytest

from app.detection.core_rules import Rule, evaluate_rule, load_catalog

CATALOG_PATH = Path(__file__).resolve().parents[1] / "rules" / "core" / "core_rules.json"


def test_catalog_has_303_unique_disabled_draft_candidates():
    rules = load_catalog()
    assert len(rules) == 303
    assert len(set(rules)) == 303
    assert all(rule.lifecycle == "draft" and not rule.enabled for rule in rules.values())
    assert {rule.source for rule in rules.values()} == {
        "auth", "endpoint", "network", "web", "cloud", "dns"
    }


def test_only_explicit_production_rule_can_fire():
    rule = Rule.from_dict({
        "id": "AS-TEST-1", "title": "Failed login", "source": "auth",
        "severity": "high", "confidence": 0.8,
        "conditions": [{"field": "event.action", "op": "eq", "value": "login_failed"}],
        "lifecycle": "production", "enabled": True,
    })
    assert evaluate_rule(rule, {"source": "auth", "event": {"action": "login_failed"}})
    assert evaluate_rule(rule, {"source": "web", "event": {"action": "login_failed"}}) is None


def test_invalid_operator_is_rejected():
    with pytest.raises(ValueError, match="unsupported operator"):
        Rule.from_dict({
            "id": "AS-TEST-2", "title": "Invalid", "source": "*",
            "severity": "low", "confidence": 0.5,
            "conditions": [{"field": "event.action", "op": "eval", "value": "x"}],
        })


def test_every_catalog_candidate_has_a_matching_and_nonmatching_fixture():
    """Schema/dispatch smoke test only; not proof of detection quality."""
    payload = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    raw_by_id = {row["id"]: row for row in payload["rules"]}

    for draft in load_catalog().values():
        rule = replace(draft, lifecycle="production", enabled=True)
        raw = raw_by_id[rule.id]
        if raw.get("positive_fixtures") and raw.get("negative_fixtures"):
            matching = raw["positive_fixtures"][0]
            nonmatching = raw["negative_fixtures"][0]
        else:
            action = rule.conditions[0]["value"]
            matching = {"source": rule.source, "event": {"action": action}}
            nonmatching = {
                "source": rule.source,
                "event": {"action": "__benign_control_event__"},
            }
        assert evaluate_rule(rule, matching) is not None, rule.id
        assert evaluate_rule(rule, nonmatching) is None, rule.id
