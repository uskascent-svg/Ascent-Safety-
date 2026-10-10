import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app.models import (
    AuditLog,
    RoleName,
    ThreatAnalysis,
    ThreatFeedback,
    ThreatModelVersion,
    ThreatTrainingJob,
    User,
)
from app.services import threat_training
from tests.test_phishing_api import auth


def test_model_artifact_must_remain_inside_store_and_match_hmac(tmp_path, monkeypatch):
    key = "verification-key-for-test-only-32chars"
    monkeypatch.setattr(
        threat_training,
        "get_settings",
        lambda: SimpleNamespace(
            threat_analysis_model_dir=str(tmp_path), threat_analysis_model_hmac_key=key
        ),
    )
    artifact = tmp_path / "candidate.joblib"
    contents = b"signed model bytes"
    artifact.write_bytes(contents)
    version = "candidate-test-v1"
    digest = hashlib.sha256(contents).hexdigest()
    signature = hmac.new(key.encode(), f"{version}:{digest}".encode(), hashlib.sha256).hexdigest()
    row = SimpleNamespace(
        artifact_path=str(artifact), sha256=digest, signature=signature, version=version
    )
    assert threat_training._verified_path(row) == artifact

    artifact.write_bytes(b"tampered model bytes")
    with pytest.raises(threat_training.TrainingUnavailable, match="signature verification"):
        threat_training._verified_path(row)

    outside = tmp_path.parent / "outside-model.joblib"
    outside.write_bytes(contents)
    row.artifact_path = str(outside)
    with pytest.raises(threat_training.TrainingUnavailable, match="path is invalid"):
        threat_training._verified_path(row)


def test_approved_consent_samples_train_and_promote_only_after_held_out_evaluation(
    client, session_factory, promote, monkeypatch, tmp_path
):
    from app.api import threat_analysis

    key = Fernet.generate_key().decode()
    signing_key = "model-signing-test-key-with-at-least-32-characters"
    test_set = tmp_path / "independent.jsonl"
    rows = [
        {
            "text": f"Team agenda and project schedule for colleagues, routine benign note {i}",
            "label": "benign",
        }
        for i in range(10)
    ] + [
        {
            "text": (
                f"Urgent verify your account password credentials sign in now malicious report {i}"
            ),
            "label": "malicious",
        }
        for i in range(10)
    ]
    test_set.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    settings = SimpleNamespace(
        threat_analysis_data_key=key,
        threat_analysis_model_hmac_key=signing_key,
        threat_analysis_independent_test_set=str(test_set),
        threat_analysis_model_dir=str(tmp_path / "models"),
    )
    monkeypatch.setattr(threat_training, "get_settings", lambda: settings)
    monkeypatch.setattr(threat_training, "SessionLocal", session_factory)
    monkeypatch.setattr(
        threat_analysis, "evaluate_for_promotion", threat_training.evaluate_for_promotion
    )

    operator_headers = auth(client, "real-model-operator@example.com")
    promote("real-model-operator@example.com", RoleName.THREAT_MODEL_OPERATOR)
    auth(client, "approved-benign@example.com")
    auth(client, "approved-malicious@example.com")
    with session_factory() as db:
        operator = db.scalar(select(User).where(User.email == "real-model-operator@example.com"))
        benign_user = db.scalar(select(User).where(User.email == "approved-benign@example.com"))
        malicious_user = db.scalar(
            select(User).where(User.email == "approved-malicious@example.com")
        )
        job = ThreatTrainingJob(
            requested_by_id=operator.id,
            status="queued",
            message="Waiting for trainer.",
        )
        db.add(job)
        for i in range(3):
            for user, label, content in (
                (
                    benign_user,
                    "benign",
                    f"Routine team agenda schedule for project colleagues note {i}",
                ),
                (
                    malicious_user,
                    "malicious",
                    f"Urgent verify account password credentials sign in immediately case {i}",
                ),
            ):
                analysis = ThreatAnalysis(
                    user_id=user.id,
                    content_sha256=hashlib.sha256(content.encode()).hexdigest(),
                    input_kind="message",
                    verdict="unknown",
                    severity="unknown",
                    heuristic_score=0,
                    completeness="complete",
                    findings=[],
                    explanation="test record",
                    remediation="test record",
                )
                db.add(analysis)
                db.flush()
                db.add(
                    ThreatFeedback(
                        analysis_id=analysis.id,
                        user_id=user.id,
                        candidate_label=label,
                        reason="Independently checked training sample.",
                        training_sample_encrypted=Fernet(key.encode())
                        .encrypt(content.encode())
                        .decode(),
                        status="approved",
                    )
                )
        db.commit()
        job_id = job.id

    threat_training.run_training_job(job_id)
    with session_factory() as db:
        completed = db.get(ThreatTrainingJob, job_id)
        assert completed.status == "candidate"
        assert completed.sample_count == 6, completed.message
        assert completed.metrics["f1"] >= 0.65
        model = db.get(ThreatModelVersion, completed.model_version_id)
        model_id = model.id
        assert threat_training._verified_path(model).is_file()

    promoted = client.post(
        f"/api/threat-analysis/admin/models/{model_id}/promote", headers=operator_headers
    )
    assert promoted.status_code == 200, promoted.text
    assert promoted.json()["state"] == "active"
    assert promoted.json()["metrics"]["sample_count"] == 20
    with session_factory() as db:
        active = db.get(ThreatModelVersion, model_id)
        assert active.state == "active"
        assert "threat_analysis.model_promote" in {row.action for row in db.query(AuditLog).all()}
        active_path = threat_training._verified_path(active)
        active_bundle = threat_training.joblib.load(active_path)
        operator_id = active.created_by_id

    rollback_version = "threat-rollback-test-v1"
    rollback_artifact = (tmp_path / "models") / f"{rollback_version}.joblib"
    active_bundle["version"] = rollback_version
    threat_training.joblib.dump(active_bundle, rollback_artifact)
    rollback_digest = hashlib.sha256(rollback_artifact.read_bytes()).hexdigest()
    rollback_signature = threat_training._signature(rollback_version, rollback_digest)
    with session_factory() as db:
        rollback_model = ThreatModelVersion(
            version=rollback_version,
            state="superseded",
            artifact_path=str(rollback_artifact),
            sha256=rollback_digest,
            signature=rollback_signature,
            metrics=promoted.json()["metrics"],
            created_by_id=operator_id,
        )
        db.add(rollback_model)
        db.commit()
        rollback_id = rollback_model.id

    rolled_back = client.post(
        f"/api/threat-analysis/admin/models/{rollback_id}/rollback", headers=operator_headers
    )
    assert rolled_back.status_code == 200, rolled_back.text
    assert rolled_back.json()["state"] == "active"
    with session_factory() as db:
        assert db.get(ThreatModelVersion, rollback_id).state == "active"
        assert db.get(ThreatModelVersion, model_id).state == "superseded"
        assert db.scalar(
            select(AuditLog).where(AuditLog.action == "threat_analysis.model_rollback")
        )
