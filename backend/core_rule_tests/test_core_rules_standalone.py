import pytest

from app.detection.core_rules import Rule, evaluate_rule, load_catalog


def test_catalog_has_300_unique_disabled_draft_candidates():
    rules = load_catalog()
    assert len(rules) == 300
    assert len(set(rules)) == 300
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
