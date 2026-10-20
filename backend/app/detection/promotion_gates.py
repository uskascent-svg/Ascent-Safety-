"""Evidence-based rule promotion gates.

This module evaluates evidence for a human-controlled promotion decision. It never
changes a catalog rule or enables a rule by itself.
"""
from __future__ import annotations

from datetime import date
from typing import Any

from app.detection.core_rules import Rule, evaluate_rule


def evaluate_promotion_candidate(
    raw_rule: dict[str, Any],
    positive_fixtures: list[dict[str, Any]],
    negative_fixtures: list[dict[str, Any]],
) -> dict[str, Any]:
    """Check provenance and positive/negative fixtures without mutating the input.

    A candidate passes only if it has a source reference, an explicit test date,
    ATT&CK technique references, at least one positive fixture that matches, and
    at least one benign negative fixture that does not match. Human review remains
    mandatory; a passing report is not an automatic promotion.
    """
    if not isinstance(raw_rule, dict):
        raise ValueError("rule candidate must be an object")
    if not isinstance(positive_fixtures, list) or not isinstance(negative_fixtures, list):
        raise ValueError("positive and negative fixtures must be lists")

    checks: dict[str, bool] = {}
    provenance = raw_rule.get("provenance")
    checks["provenance"] = isinstance(provenance, dict) and bool(
        str(provenance.get("source", "")).strip()
    ) and bool(str(provenance.get("reference", "")).strip())

    tested = raw_rule.get("last_tested")
    try:
        date.fromisoformat(tested) if isinstance(tested, str) else None
        checks["last_tested"] = isinstance(tested, str) and bool(tested)
    except ValueError:
        checks["last_tested"] = False

    techniques = raw_rule.get("mitre_techniques")
    checks["mitre_mapping"] = isinstance(techniques, list) and bool(techniques) and all(
        isinstance(item, str) and item.strip() for item in techniques
    )
    checks["positive_fixtures_present"] = bool(positive_fixtures)
    checks["negative_fixtures_present"] = bool(negative_fixtures)

    # Evaluate the rule as an isolated candidate, without changing the catalog.
    candidate_data = dict(raw_rule)
    candidate_data["lifecycle"] = "production"
    candidate_data["enabled"] = True
    candidate = Rule.from_dict(candidate_data)

    positive_matches = 0
    for fixture in positive_fixtures:
        if not isinstance(fixture, dict):
            raise ValueError("each positive fixture must be an event object")
        if evaluate_rule(candidate, fixture) is not None:
            positive_matches += 1

    negative_matches = 0
    for fixture in negative_fixtures:
        if not isinstance(fixture, dict):
            raise ValueError("each negative fixture must be an event object")
        if evaluate_rule(candidate, fixture) is not None:
            negative_matches += 1

    checks["positive_fixture_match"] = positive_matches > 0 and positive_matches == len(
        positive_fixtures
    )
    checks["negative_fixtures_rejected"] = negative_matches == 0

    failed = [name for name, passed in checks.items() if not passed]
    return {
        "candidate_rule_id": candidate.id,
        "passed": not failed,
        "human_approval_required": True,
        "automatic_promotion": False,
        "checks": checks,
        "failed_checks": failed,
        "positive_fixture_count": len(positive_fixtures),
        "positive_fixture_matches": positive_matches,
        "negative_fixture_count": len(negative_fixtures),
        "negative_fixture_matches": negative_matches,
    }
