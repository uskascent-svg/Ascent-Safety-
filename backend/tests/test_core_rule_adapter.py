from datetime import UTC, datetime
from types import SimpleNamespace

from app.services.core_rule_adapter import evaluate_security_event, security_event_to_normalized


def sample_event(**overrides):
    values = {
        "source": "test-ingestor",
        "occurred_at": datetime(2026, 10, 19, 12, tzinfo=UTC),
        "threat_type": "phishing",
        "severity": "high",
        "status": "open",
        "title": "Suspicious login detected",
        "description": "Untrusted source details must not become executable rule context.",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_adapter_maps_only_known_fields_and_does_not_infer_action():
    normalized = security_event_to_normalized(sample_event())

    assert normalized["source"] == "test-ingestor"
    assert normalized["timestamp"] == "2026-10-19T12:00:00+00:00"
    assert normalized["event"]["category"] == ["phishing"]
    assert normalized["event"]["severity"] == "high"
    assert "action" not in normalized["event"]
    assert "description" not in normalized
    assert normalized["security_event"]["title"] == "Suspicious login detected"


def test_shadow_evaluation_runs_catalog_and_draft_rules_do_not_fire():
    result = evaluate_security_event(sample_event())

    assert result["status"] == "evaluated"
    assert result["match_count"] == len(result["matches"]) == 0


def test_missing_source_fails_closed():
    result = evaluate_security_event(sample_event(source=""))

    assert result["status"] == "unavailable"
    assert result["match_count"] == 0
    assert result["matches"] == []


def test_event_title_cannot_trigger_action_rules():
    event = sample_event(title="dns_zone_transfer_attempt")
    normalized = security_event_to_normalized(event)

    assert "action" not in normalized["event"]
    result = evaluate_security_event(event)
    assert result["match_count"] == 0
