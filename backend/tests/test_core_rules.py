import pytest

from app.detection.core_rules import Rule, evaluate_rule, load_rules, normalize_event


def production_rule(**overrides):
    row = {
        "id": "AS-CORE-0001",
        "title": "Repeated failed authentication",
        "source": "auth",
        "severity": "high",
        "confidence": 0.8,
        "conditions": [
            {"field": "event.action", "op": "eq", "value": "login_failed"},
            {"field": "event.count", "op": "gte", "value": 5},
        ],
        "mitre_techniques": ["T1110"],
        "lifecycle": "production",
        "enabled": True,
    }
    row.update(overrides)
    return Rule.from_dict(row)


def test_normalizer_maps_ecs_timestamp_without_inventing_values():
    result = normalize_event({"@timestamp": "2026-10-20T10:00:00Z", "source": "auth"})
    assert result["timestamp"] == "2026-10-20T10:00:00Z"
    assert result["event"] == {}
    assert "host" not in result


def test_rule_matches_expected_event():
    hit = evaluate_rule(
        production_rule(),
        {"source": "auth", "event": {"action": "login_failed", "count": 7}},
    )
    assert hit is not None
    assert hit["rule_id"] == "AS-CORE-0001"
    assert hit["mitre_techniques"] == ["T1110"]


def test_rule_does_not_match_other_source_or_low_count():
    rule = production_rule()
    assert evaluate_rule(rule, {"source": "web", "event": {"action": "login_failed", "count": 8}}) is None
    assert evaluate_rule(rule, {"source": "auth", "event": {"action": "login_failed", "count": 2}}) is None


def test_draft_rules_never_fire():
    row = {
        "id": "AS-CORE-0002", "title": "Draft", "source": "*", "severity": "low",
        "confidence": 0.5, "conditions": [{"field": "event.action", "op": "eq", "value": "x"}],
    }
    assert evaluate_rule(Rule.from_dict(row), {"event": {"action": "x"}}) is None


def test_enabled_non_production_rule_is_rejected():
    with pytest.raises(ValueError, match="only production"):
        production_rule(lifecycle="draft", enabled=True)


def test_unknown_operator_is_rejected():
    row = {
        "id": "AS-CORE-0003", "title": "Bad", "source": "*", "severity": "low",
        "confidence": 0.5, "conditions": [{"field": "event.action", "op": "regex", "value": "x"}],
    }
    with pytest.raises(ValueError, match="unsupported operator"):
        Rule.from_dict(row)


def test_duplicate_rule_ids_are_rejected():
    row = {
        "id": "AS-CORE-0004", "title": "Test", "source": "*", "severity": "low",
        "confidence": 0.5, "conditions": [{"field": "event.action", "op": "eq", "value": "x"}],
    }
    with pytest.raises(ValueError, match="duplicate rule id"):
        load_rules([row, row])


def test_missing_fields_fail_closed():
    with pytest.raises(ValueError, match="missing required"):
        Rule.from_dict({"id": "broken"})


def test_missing_event_fields_do_not_match():
    rule = production_rule()
    assert evaluate_rule(rule, {"source": "auth", "event": {}}) is None
