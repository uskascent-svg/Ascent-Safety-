import pytest

from app.detection.promotion_gates import evaluate_promotion_candidate


def candidate(**overrides):
    row = {
        "id": "AS-TEST-PROMOTE-0001",
        "title": "Repeated failed authentication",
        "source": "auth",
        "severity": "high",
        "confidence": 0.8,
        "conditions": [
            {"field": "event.action", "op": "eq", "value": "login_failed"},
            {"field": "event.count", "op": "gte", "value": 5},
        ],
        "mitre_techniques": ["T1110"],
        "last_tested": "2026-10-20",
        "provenance": {
            "source": "ASCENT SAFETY analyst-authored",
            "reference": "internal-detection-spec-v1",
        },
        "lifecycle": "draft",
        "enabled": False,
    }
    row.update(overrides)
    return row


def test_candidate_passes_with_positive_and_benign_negative_fixtures():
    row = candidate()
    positive = [{"source": "auth", "event": {"action": "login_failed", "count": 8}}]
    negative = [{"source": "auth", "event": {"action": "login_success", "count": 8}}]

    result = evaluate_promotion_candidate(row, positive, negative)

    assert result["passed"] is True
    assert result["human_approval_required"] is True
    assert result["automatic_promotion"] is False
    assert result["failed_checks"] == []
    assert row["lifecycle"] == "draft"
    assert row["enabled"] is False


def test_candidate_fails_if_benign_fixture_matches():
    result = evaluate_promotion_candidate(
        candidate(),
        [{"source": "auth", "event": {"action": "login_failed", "count": 8}}],
        [{"source": "auth", "event": {"action": "login_failed", "count": 6}}],
    )

    assert result["passed"] is False
    assert "negative_fixtures_rejected" in result["failed_checks"]
    assert result["negative_fixture_matches"] == 1


def test_candidate_fails_without_provenance_or_attack_mapping():
    row = candidate(provenance={}, mitre_techniques=[])
    result = evaluate_promotion_candidate(
        row,
        [{"source": "auth", "event": {"action": "login_failed", "count": 8}}],
        [{"source": "auth", "event": {"action": "login_success", "count": 8}}],
    )

    assert result["passed"] is False
    assert "provenance" in result["failed_checks"]
    assert "mitre_mapping" in result["failed_checks"]


def test_candidate_requires_both_fixture_classes():
    result = evaluate_promotion_candidate(candidate(), [], [])

    assert result["passed"] is False
    assert "positive_fixtures_present" in result["failed_checks"]
    assert "negative_fixtures_present" in result["failed_checks"]


def test_malformed_fixture_fails_explicitly():
    with pytest.raises(ValueError, match="positive fixture"):
        evaluate_promotion_candidate(candidate(), ["not-an-event"], [{"source": "auth"}])
