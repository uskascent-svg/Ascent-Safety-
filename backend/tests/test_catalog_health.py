import json

import pytest

from app.detection.catalog_health import build_catalog_report


def _write_catalog(tmp_path, rows):
    path = tmp_path / "catalog.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "catalog_name": "test",
                "catalog_version": "test",
                "count": len(rows),
                "rules": rows,
            }
        ),
        encoding="utf-8",
    )
    return path


def _rule(**overrides):
    row = {
        "id": "AS-TEST-0001",
        "title": "Test candidate",
        "source": "auth",
        "severity": "medium",
        "confidence": 0.5,
        "conditions": [{"field": "event.action", "op": "eq", "value": "test"}],
        "mitre_techniques": [],
        "last_tested": None,
        "lifecycle": "draft",
        "enabled": False,
    }
    row.update(overrides)
    return row


def test_report_counts_catalog_without_claiming_capacity_is_coverage(tmp_path):
    path = _write_catalog(tmp_path, [_rule()])
    report = build_catalog_report(path)

    assert report["catalog_count"] == 1
    assert report["capacity_limit"] == 10_000
    assert report["capacity_remaining"] == 9_999
    assert report["enabled_production_rule_count"] == 0
    assert report["counts_by_lifecycle"] == {"draft": 1}
    assert report["source_family_counts"] == {"auth": 1}
    assert report["promotion_ready_by_catalog_evidence_count"] == 0
    assert report["automatic_promotion"] is False


def test_report_counts_only_complete_stored_promotion_evidence(tmp_path):
    row = _rule(
        provenance={"source": "vendor advisory", "reference": "https://example.test/advisory"},
        last_tested="2026-10-19",
        mitre_techniques=["T1110"],
        positive_fixtures=[{"source": "auth", "event": {"action": "test"}}],
        negative_fixtures=[{"source": "auth", "event": {"action": "benign"}}],
    )
    report = build_catalog_report(_write_catalog(tmp_path, [row]))

    assert report["promotion_evidence_counts"] == {
        "with_mitre_mapping": 1,
        "with_negative_fixtures": 1,
        "with_positive_fixtures": 1,
        "with_provenance": 1,
        "with_valid_test_date": 1,
    }
    assert report["promotion_ready_by_catalog_evidence_count"] == 1
    assert report["human_review_required"] is True


def test_report_rejects_count_mismatch(tmp_path):
    path = _write_catalog(tmp_path, [_rule()])
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["count"] = 2
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="count mismatch"):
        build_catalog_report(path)


def test_repository_catalog_report_reflects_actual_catalog():
    report = build_catalog_report()

    assert report["catalog_count"] == 303
    assert report["declared_count"] == 303
    assert report["counts_by_lifecycle"] == {"draft": 303}
    assert report["enabled_production_rule_count"] == 0
    assert report["source_family_counts"] == {
        "auth": 50,
        "cloud": 50,
        "dns": 50,
        "endpoint": 53,
        "network": 50,
        "web": 50,
    }
    assert report["promotion_ready_by_catalog_evidence_count"] == 3
    assert report["promotion_evidence_counts"] == {
        "with_mitre_mapping": 3,
        "with_negative_fixtures": 3,
        "with_positive_fixtures": 3,
        "with_provenance": 3,
        "with_valid_test_date": 3,
    }
