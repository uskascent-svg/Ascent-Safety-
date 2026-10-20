from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

from app.detection.core_rules import Rule, evaluate_rule, load_catalog
from app.schemas.endpoint import PersistenceObs, ProcessObs
from app.services import core_rule_adapter

CATALOG_PATH = Path(__file__).resolve().parents[1] / "rules" / "core" / "core_rules.json"


def _catalog_rows():
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))["rules"]


def _production_candidate(rule_id):
    raw = next(row for row in _catalog_rows() if row["id"] == rule_id)
    raw = dict(raw, lifecycle="production", enabled=True)
    return Rule.from_dict(raw)


def _process(image, command_line):
    return ProcessObs(
        type="process",
        occurred_at=datetime.now(UTC) - timedelta(minutes=1),
        image=image,
        command_line=command_line,
    )


def _persistence(target, mechanism="scheduled_task"):
    return PersistenceObs(
        type="persistence",
        occurred_at=datetime.now(UTC) - timedelta(minutes=1),
        mechanism=mechanism,
        target=target,
    )


def test_process_observation_maps_windows_image_and_command_line():
    event = core_rule_adapter.endpoint_observation_to_normalized(
        _process(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoProfile -enc SQBFAFgA",
        )
    )
    assert event["source"] == "endpoint"
    assert event["process"]["name"] == "powershell.exe"
    assert event["process"]["command_line"].endswith("-enc SQBFAFgA")
    assert event["event"]["kind"] == "event"


def test_persistence_observation_maps_only_explicit_fields():
    event = core_rule_adapter.endpoint_observation_to_normalized(
        _persistence(r"C:\Users\user\AppData\Local\Temp\powershell-update.ps1")
    )
    assert event["source"] == "endpoint"
    assert event["persistence"]["mechanism"] == "scheduled_task"
    assert event["persistence"]["target"].endswith("powershell-update.ps1")
    assert "event.code" not in event
    assert "task.content" not in event


def test_candidates_match_normalized_real_schema_observations():
    cases = [
        (
            "AS-CORE-0301",
            _process(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "powershell.exe -NoProfile -enc SQBFAFgA",
            ),
        ),
        (
            "AS-CORE-0302",
            _persistence(r"C:\Users\user\AppData\Local\Temp\powershell-update.ps1"),
        ),
        (
            "AS-CORE-0303",
            _process(
                r"C:\Windows\System32\rundll32.exe",
                r"rundll32.exe C:\Users\Public\photo.png,EntryPoint",
            ),
        ),
    ]
    for rule_id, observation in cases:
        normalized = core_rule_adapter.endpoint_observation_to_normalized(observation)
        assert evaluate_rule(_production_candidate(rule_id), normalized) is not None, rule_id


def test_candidate_controls_do_not_match_benign_observations():
    cases = [
        (
            "AS-CORE-0301",
            _process(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     "powershell.exe -NoProfile -File maintenance.ps1"),
        ),
        (
            "AS-CORE-0302",
            _persistence(r"C:\Windows\System32\cleanmgr.exe"),
        ),
        (
            "AS-CORE-0303",
            _process(r"C:\Windows\System32\rundll32.exe",
                     r"rundll32.exe C:\Windows\System32\example.dll,EntryPoint"),
        ),
    ]
    for rule_id, observation in cases:
        normalized = core_rule_adapter.endpoint_observation_to_normalized(observation)
        assert evaluate_rule(_production_candidate(rule_id), normalized) is None, rule_id


def test_only_enabled_production_rules_create_endpoint_findings(monkeypatch):
    candidate = _production_candidate("AS-CORE-0301")
    monkeypatch.setattr(core_rule_adapter, "_catalog", lambda: {candidate.id: candidate})
    observation = _process(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe -NoProfile -enc SQBFAFgA",
    )
    findings = core_rule_adapter.evaluate_endpoint_observations([observation])
    assert len(findings) == 1
    assert findings[0].detector == "core_rules"
    assert findings[0].code == "AS-CORE-0301"
    assert "SQBFAFgA" not in findings[0].description
    assert all("command_line" not in item for item in findings[0].evidence)


def test_checked_in_draft_candidates_remain_inert_for_endpoint_telemetry():
    catalog = load_catalog()
    assert all(
        rule.lifecycle == "draft" and not rule.enabled
        for rule_id, rule in catalog.items()
        if rule_id in {"AS-CORE-0301", "AS-CORE-0302", "AS-CORE-0303"}
    )
    observations = [
        _process(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                 "powershell.exe -NoProfile -enc SQBFAFgA"),
        _persistence(r"C:\Users\user\AppData\Local\Temp\powershell-update.ps1"),
        _process(r"C:\Windows\System32\rundll32.exe",
                 r"rundll32.exe C:\Users\Public\photo.png,EntryPoint"),
    ]
    assert core_rule_adapter.evaluate_endpoint_observations(observations) == []
