import json
from pathlib import Path

from app.detection.promotion_gates import evaluate_promotion_candidate

CATALOG_PATH = (
    Path(__file__).resolve().parents[1] / "rules" / "core" / "core_rules.json"
)
CANDIDATE_IDS = {"AS-CORE-0301", "AS-CORE-0302", "AS-CORE-0303"}
PINNED_SIGMA_COMMIT = "f083329893e4f44869bf7d283c7aa001ad86a0cd"


def test_pinned_sigma_endpoint_candidates_pass_their_regression_fixtures():
    payload = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    candidates = [
        row for row in payload["rules"] if row["id"] in CANDIDATE_IDS
    ]

    assert {row["id"] for row in candidates} == CANDIDATE_IDS
    for candidate in candidates:
        result = evaluate_promotion_candidate(
            candidate,
            candidate["positive_fixtures"],
            candidate["negative_fixtures"],
        )
        assert result["passed"], (candidate["id"], result["failed_checks"])
        assert result["positive_fixture_matches"] == len(candidate["positive_fixtures"])
        assert result["negative_fixture_matches"] == 0
        assert result["human_approval_required"] is True
        assert result["automatic_promotion"] is False


def test_candidates_are_source_scoped_draft_rules_with_pinned_provenance():
    payload = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    candidates = [
        row for row in payload["rules"] if row["id"] in CANDIDATE_IDS
    ]

    for candidate in candidates:
        assert candidate["source"] == "endpoint"
        assert candidate["lifecycle"] == "draft"
        assert candidate["enabled"] is False
        assert candidate["provenance"]["source"].startswith("SigmaHQ/sigma")
        assert PINNED_SIGMA_COMMIT in candidate["provenance"]["reference"]
        assert candidate["mitre_techniques"]
        assert candidate["positive_fixtures"]
        assert candidate["negative_fixtures"]


def test_candidate_events_from_another_source_never_match():
    payload = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    candidates = [
        row for row in payload["rules"] if row["id"] in CANDIDATE_IDS
    ]

    for candidate in candidates:
        wrong_source_fixtures = [
            dict(candidate["positive_fixtures"][0], source="web")
        ]
        result = evaluate_promotion_candidate(
            candidate, wrong_source_fixtures, candidate["negative_fixtures"]
        )
        assert result["passed"] is False
        assert "positive_fixture_match" in result["failed_checks"]
