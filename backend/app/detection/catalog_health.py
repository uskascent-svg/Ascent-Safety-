"""Machine-readable readiness report for the declarative detection catalog.

This reports catalog facts and missing promotion evidence; it does not certify detection
quality or change any rule lifecycle state.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

from app.detection.core_rules import MAX_RULES, load_catalog


def _valid_iso_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def build_catalog_report(path: str | Path | None = None) -> dict[str, Any]:
    """Validate the catalog and summarize scale, lifecycle, source and evidence gaps."""
    catalog_path = Path(path) if path else (
        Path(__file__).resolve().parents[2] / "rules" / "core" / "core_rules.json"
    )
    try:
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read rule catalog: {catalog_path}") from exc

    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("unsupported or invalid rule catalog schema")
    rows = payload.get("rules")
    if not isinstance(rows, list):
        raise ValueError("rule catalog rules must be a list")

    # Reuse the production loader so duplicate IDs, malformed rules and count mismatches
    # are treated identically by diagnostics and the runtime evaluator.
    loaded = load_catalog(catalog_path)
    lifecycle_counts = Counter(rule.lifecycle for rule in loaded.values())
    source_counts = Counter(rule.source for rule in loaded.values())

    evidence = Counter()
    promotion_ready = 0
    for row in rows:
        provenance = row.get("provenance") if isinstance(row, dict) else None
        has_provenance = isinstance(provenance, dict) and bool(
            str(provenance.get("source", "")).strip()
        ) and bool(str(provenance.get("reference", "")).strip())
        has_test_date = _valid_iso_date(row.get("last_tested")) if isinstance(row, dict) else False
        techniques = row.get("mitre_techniques") if isinstance(row, dict) else None
        has_mitre = isinstance(techniques, list) and bool(techniques) and all(
            isinstance(item, str) and item.strip() for item in techniques
        )
        has_positive_fixtures = isinstance(row.get("positive_fixtures"), list) and bool(
            row["positive_fixtures"]
        ) if isinstance(row, dict) else False
        has_negative_fixtures = isinstance(row.get("negative_fixtures"), list) and bool(
            row["negative_fixtures"]
        ) if isinstance(row, dict) else False

        evidence["with_provenance"] += int(has_provenance)
        evidence["with_valid_test_date"] += int(has_test_date)
        evidence["with_mitre_mapping"] += int(has_mitre)
        evidence["with_positive_fixtures"] += int(has_positive_fixtures)
        evidence["with_negative_fixtures"] += int(has_negative_fixtures)
        promotion_ready += int(
            has_provenance and has_test_date and has_mitre
            and has_positive_fixtures and has_negative_fixtures
        )

    enabled_production = sum(
        rule.enabled and rule.lifecycle == "production" for rule in loaded.values()
    )
    return {
        "catalog_name": payload.get("catalog_name"),
        "catalog_version": payload.get("catalog_version"),
        "catalog_count": len(loaded),
        "declared_count": payload.get("count"),
        "capacity_limit": MAX_RULES,
        "capacity_remaining": MAX_RULES - len(loaded),
        "capacity_limit_reached": len(loaded) == MAX_RULES,
        "counts_by_lifecycle": dict(sorted(lifecycle_counts.items())),
        "source_family_counts": dict(sorted(source_counts.items())),
        "enabled_production_rule_count": enabled_production,
        "promotion_evidence_counts": dict(sorted(evidence.items())),
        "promotion_ready_by_catalog_evidence_count": promotion_ready,
        "human_review_required": True,
        "automatic_promotion": False,
        "limitations": [
            "Capacity is not the same as validated detection coverage.",
            "Evidence counts only inspect fields stored in the catalog; fixture quality and representativeness require independent review.",
            "A rule can fire only when explicitly enabled and in production lifecycle.",
        ],
    }


def main() -> None:
    print(json.dumps(build_catalog_report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
