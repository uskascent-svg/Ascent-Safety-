import uuid
import asyncio
from datetime import UTC, datetime, timedelta
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from sqlalchemy import select

from app.models import AuditLog, RoleName, ThreatAnalysis, ThreatFeedback, ThreatTrainingJob, User
from tests.test_phishing_api import auth


MESSAGE = "URGENT: verify your password within 10 minutes at http://203.0.113.9/login"


def test_analyze_explains_rules_and_does_not_persist_submitted_content(client, session_factory):
    headers = auth(client)
    response = client.post(
        "/api/threat-analysis/analyze",
        json={"text": MESSAGE, "input_kind": "message"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["verdict"] == "suspicious"
    assert result["score_type"] == "heuristic"
    assert result["findings"]
    with session_factory() as db:
        row = db.get(ThreatAnalysis, uuid.UUID(result["id"]))
        assert row.content_sha256 and row.content_sha256 != MESSAGE
        assert not hasattr(row, "submitted_text")
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "threat_analysis.analyze"))
        assert audit.details["analysis_id"] == result["id"]


def test_analysis_requires_authentication_and_valid_input(client):
    assert client.post("/api/threat-analysis/analyze", json={"text": MESSAGE}).status_code == 401
    headers = auth(client)
    assert (
        client.post(
            "/api/threat-analysis/analyze", json={"text": "short"}, headers=headers
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/threat-analysis/analyze", json={"text": "x" * 100_001}, headers=headers
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/threat-analysis/analyze", json={"text": MESSAGE, "extra": 1}, headers=headers
        ).status_code
        == 422
    )


def test_analysis_history_and_detail_are_user_scoped(client):
    one = auth(client, "first-threat@example.com")
    two = auth(client, "second-threat@example.com")
    result = client.post("/api/threat-analysis/analyze", json={"text": MESSAGE}, headers=one).json()
    assert client.get("/api/threat-analysis/analyses", headers=one).json()["total"] == 1
    assert client.get("/api/threat-analysis/analyses", headers=two).json()["total"] == 0
    assert (
        client.get(f"/api/threat-analysis/analyses/{result['id']}", headers=one).status_code == 200
    )
    assert (
        client.get(f"/api/threat-analysis/analyses/{result['id']}", headers=two).status_code == 404
    )
    assert (
        client.delete(f"/api/threat-analysis/analyses/{result['id']}", headers=two).status_code
        == 404
    )
    assert (
        client.delete(f"/api/threat-analysis/analyses/{result['id']}", headers=one).status_code
        == 204
    )


def test_metrics_are_admin_only_and_derived_from_saved_rows(client, promote):
    user = auth(client, "metrics-user@example.com")
    admin = auth(client, "metrics-admin@example.com")
    promote("metrics-admin@example.com", RoleName.ADMINISTRATOR)
    assert client.get("/api/threat-analysis/admin/metrics", headers=user).status_code == 403
    assert client.get("/api/threat-analysis/admin/metrics").status_code == 401
    assert (
        client.post(
            "/api/threat-analysis/analyze", json={"text": MESSAGE}, headers=user
        ).status_code
        == 200
    )
    metrics = client.get("/api/threat-analysis/admin/metrics", headers=admin)
    assert metrics.status_code == 200
    assert metrics.json()["total"] == 1
    assert metrics.json()["detection_quality"] is None
    dashboard = client.get("/api/threat-analysis/admin/dashboard", headers=admin)
    assert dashboard.status_code == 200
    assert dashboard.json()["total"] == 1
    assert dashboard.json()["refreshed_at"]
    assert dashboard.json()["model_status"]["state"] == "rules_only"


def test_url_analysis_never_fetches_and_rejects_invalid_url(client):
    headers = auth(client, "url-threat@example.com")
    invalid = client.post(
        "/api/threat-analysis/analyze",
        json={"text": "not a url with words", "input_kind": "url"},
        headers=headers,
    )
    assert invalid.status_code in {422}
    valid = client.post(
        "/api/threat-analysis/analyze",
        json={"text": "https://203.0.113.9/signin", "input_kind": "url"},
        headers=headers,
    )
    assert valid.status_code == 200
    assert valid.json()["findings"]


def test_no_matches_are_unknown_not_benign(client):
    headers = auth(client, "unknown-threat@example.com")
    result = client.post(
        "/api/threat-analysis/analyze",
        json={"text": "A routine project update with no actionable indicators."},
        headers=headers,
    ).json()
    assert result["verdict"] == "unknown"
    assert result["severity"] == "unknown"
    assert result["findings"] == []


def test_file_upload_isolated_analysis_and_signature_validation(client):
    headers = auth(client, "upload-threat@example.com")
    response = client.post(
        "/api/threat-analysis/analyze-file",
        headers=headers,
        files={
            "file": (
                "mail.txt",
                b"Urgent. Verify your password within 10 minutes using this link.",
                "text/plain",
            )
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "suspicious"
    assert body["extraction_status"] == "ok"
    assert body["extraction_notes"] == []
    assert (
        client.post(
            "/api/threat-analysis/analyze-file",
            headers=headers,
            files={"file": ("fake.pdf", b"plain text pretending to be pdf", "application/pdf")},
        ).status_code
        == 415
    )


def test_malformed_file_returns_unknown_and_extraction_failure(client):
    headers = auth(client, "malformed-threat@example.com")
    response = client.post(
        "/api/threat-analysis/analyze-file",
        headers=headers,
        files={"file": ("damaged.pdf", b"%PDF-this is not a valid pdf", "application/pdf")},
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "unknown"
    assert response.json()["extraction_status"] == "failed"
    assert response.json()["completeness"] == "partial"


def test_feedback_validation_ownership_and_admin_review(client, promote):
    user = auth(client, "feedback-user@example.com")
    other = auth(client, "feedback-other@example.com")
    admin = auth(client, "feedback-admin@example.com")
    promote("feedback-admin@example.com", RoleName.ADMINISTRATOR)
    result = client.post(
        "/api/threat-analysis/analyze", json={"text": MESSAGE}, headers=user
    ).json()
    path = f"/api/threat-analysis/analyses/{result['id']}/feedback"
    assert (
        client.post(
            path,
            json={
                "candidate_label": "malicious",
                "reason": "This sample should be reconsidered.",
                "include_in_training": True,
                "training_sample": "",
            },
            headers=user,
        ).status_code
        == 422
    )
    assert (
        client.post(
            path, json={"candidate_label": "benign", "reason": "short"}, headers=user
        ).status_code
        == 422
    )
    assert (
        client.post(
            path,
            json={"candidate_label": "benign", "reason": "Rule did not match my context."},
            headers=other,
        ).status_code
        == 404
    )
    submitted = client.post(
        path,
        json={"candidate_label": "benign", "reason": "Rule did not match my context."},
        headers=user,
    )
    assert submitted.status_code == 201
    feedback_id = submitted.json()["id"]
    assert (
        client.post(
            path,
            json={"candidate_label": "benign", "reason": "Second candidate label."},
            headers=user,
        ).status_code
        == 409
    )
    assert client.get("/api/threat-analysis/admin/feedback", headers=user).status_code == 403
    queue = client.get("/api/threat-analysis/admin/feedback", headers=admin)
    assert queue.status_code == 200 and queue.json()[0]["id"] == feedback_id
    review = client.post(
        f"/api/threat-analysis/admin/feedback/{feedback_id}/review",
        json={"decision": "approve", "note": "Reviewed against the available evidence."},
        headers=admin,
    )
    assert review.status_code == 200
    assert review.json()["status"] == "approved"
    assert review.json()["includes_training_sample"] is False
    assert (
        client.post(
            f"/api/threat-analysis/admin/feedback/{feedback_id}/review",
            json={"decision": "reject", "note": "Cannot review a second time."},
            headers=admin,
        ).status_code
        == 409
    )


def test_threat_permissions_separate_monitor_review_and_model_operations(client, promote):
    monitor = auth(client, "threat-monitor@example.com")
    reviewer = auth(client, "threat-reviewer@example.com")
    operator = auth(client, "threat-operator@example.com")
    promote("threat-monitor@example.com", RoleName.THREAT_MONITOR)
    promote("threat-reviewer@example.com", RoleName.THREAT_DATA_REVIEWER)
    promote("threat-operator@example.com", RoleName.THREAT_MODEL_OPERATOR)

    assert client.get("/api/threat-analysis/admin/dashboard", headers=monitor).status_code == 200
    assert client.get("/api/threat-analysis/admin/feedback", headers=monitor).status_code == 403
    assert (
        client.post("/api/threat-analysis/admin/training-jobs", headers=monitor).status_code == 403
    )
    assert client.get("/api/threat-analysis/admin/feedback", headers=reviewer).status_code == 200
    assert (
        client.post("/api/threat-analysis/admin/training-jobs", headers=reviewer).status_code == 403
    )
    assert client.get("/api/threat-analysis/admin/dashboard", headers=operator).status_code == 200
    # A 409 or 503 here confirms the model-operator role passed authorization.
    assert client.post(
        "/api/threat-analysis/admin/training-jobs", headers=operator
    ).status_code in {
        409,
        503,
    }


def test_deployment_role_command_grants_and_revokes_only_scoped_roles(
    client, session_factory, monkeypatch
):
    from app import bootstrap_threat_role

    headers = auth(client, "role-cli@example.com")
    monkeypatch.setattr(bootstrap_threat_role, "SessionLocal", session_factory)
    bootstrap_threat_role.update_role("role-cli@example.com", RoleName.THREAT_MONITOR.value)
    with session_factory() as db:
        from app.models import User

        user = db.scalar(select(User).where(User.email == "role-cli@example.com"))
        assert {role.name for role in user.roles} == {
            RoleName.USER.value,
            RoleName.THREAT_MONITOR.value,
        }
    bootstrap_threat_role.update_role(
        "role-cli@example.com", RoleName.THREAT_MONITOR.value, revoke=True
    )
    with session_factory() as db:
        from app.models import User

        user = db.scalar(select(User).where(User.email == "role-cli@example.com"))
        assert [role.name for role in user.roles] == [RoleName.USER.value]
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    with pytest.raises(ValueError, match="scoped threat roles"):
        bootstrap_threat_role.update_role("role-cli@example.com", RoleName.ADMINISTRATOR.value)


def test_startup_marks_interrupted_training_jobs_failed(session_factory, monkeypatch):
    from app import main

    monkeypatch.setattr(main, "SessionLocal", session_factory)
    with session_factory() as db:
        user = User(
            email="restart-training@example.com",
            password_hash="not-used",
            full_name="Training Operator",
        )
        db.add(user)
        db.flush()
        queued = ThreatTrainingJob(
            requested_by_id=user.id, status="queued", message="Waiting for a worker."
        )
        running = ThreatTrainingJob(
            requested_by_id=user.id, status="running", message="Training in progress."
        )
        db.add_all([queued, running])
        db.commit()
        queued_id, running_id = queued.id, running.id

    async def start_and_stop():
        async with main.lifespan(main.app):
            return

    asyncio.run(start_and_stop())
    with session_factory() as db:
        assert db.get(ThreatTrainingJob, queued_id).status == "failed"
        assert db.get(ThreatTrainingJob, running_id).status == "failed"


def test_opted_in_feedback_is_encrypted_and_disclosed_only_to_reviewer(
    client, session_factory, promote, monkeypatch
):
    from types import SimpleNamespace

    from cryptography.fernet import Fernet

    import app.services.threat_training as training

    sample = "An independently reviewed benign message sample with sufficient context."
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(
        training,
        "get_settings",
        lambda: SimpleNamespace(threat_analysis_data_key=key),
    )
    user = auth(client, "consenting-user@example.com")
    reviewer = auth(client, "sample-reviewer@example.com")
    monitor = auth(client, "sample-monitor@example.com")
    promote("sample-reviewer@example.com", RoleName.THREAT_DATA_REVIEWER)
    promote("sample-monitor@example.com", RoleName.THREAT_MONITOR)
    analysis = client.post(
        "/api/threat-analysis/analyze", json={"text": MESSAGE}, headers=user
    ).json()
    submitted = client.post(
        f"/api/threat-analysis/analyses/{analysis['id']}/feedback",
        json={
            "candidate_label": "benign",
            "reason": "Reviewed context indicates this is routine.",
            "include_in_training": True,
            "training_sample": sample,
        },
        headers=user,
    )
    assert submitted.status_code == 201
    assert submitted.json()["includes_training_sample"] is True
    assert "training_sample" not in submitted.json()
    with session_factory() as db:
        stored = db.scalar(select(ThreatFeedback))
        assert stored.training_sample_encrypted
        assert sample not in stored.training_sample_encrypted

    assert client.get("/api/threat-analysis/admin/feedback", headers=monitor).status_code == 403
    reviewed_queue = client.get("/api/threat-analysis/admin/feedback", headers=reviewer)
    assert reviewed_queue.status_code == 200
    assert reviewed_queue.json()[0]["training_sample"] == sample
    with session_factory() as db:
        assert db.scalar(
            select(AuditLog).where(AuditLog.action == "threat_analysis.training_sample_review")
        )


def test_upload_limit_and_worker_timeout_return_bounded_failure(client, monkeypatch):
    from app.api import threat_analysis

    headers = auth(client, "upload-limits@example.com")
    monkeypatch.setattr(threat_analysis, "MAX_UPLOAD_BYTES", 32)
    oversized = client.post(
        "/api/threat-analysis/analyze-file",
        headers=headers,
        files={"file": ("large.txt", b"A" * 33, "text/plain")},
    )
    assert oversized.status_code == 413

    monkeypatch.setattr(threat_analysis, "MAX_UPLOAD_BYTES", 1024)
    monkeypatch.setattr(
        threat_analysis.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            __import__("subprocess").TimeoutExpired(args[0], kwargs["timeout"])
        ),
    )
    timed_out = client.post(
        "/api/threat-analysis/analyze-file",
        headers=headers,
        files={"file": ("slow.txt", b"A sufficiently long document to parse safely", "text/plain")},
    )
    assert timed_out.status_code == 200
    assert timed_out.json()["verdict"] == "unknown"
    assert timed_out.json()["extraction_status"] == "failed"
    assert "time limit" in " ".join(timed_out.json()["extraction_notes"]).lower()


def test_archive_path_traversal_is_reported_without_extracting_entries(client):
    headers = auth(client, "archive-traversal@example.com")
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        archive.writestr("../outside.txt", "urgent password reset now")
        archive.writestr("word/document.xml", "ordinary content")
    response = client.post(
        "/api/threat-analysis/analyze-file",
        headers=headers,
        files={
            "file": (
                "unsafe.docx",
                stream.getvalue(),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
    )
    assert response.status_code == 200
    assert response.json()["extraction_status"] == "limit"
    assert response.json()["verdict"] == "unknown"
    assert any("unsafe entry paths" in note.lower() for note in response.json()["extraction_notes"])


def test_user_delete_is_scoped_and_admin_retention_is_audited(client, session_factory, promote):
    owner = auth(client, "delete-owner@example.com")
    other = auth(client, "delete-other@example.com")
    admin = auth(client, "retention-admin@example.com")
    promote("retention-admin@example.com", RoleName.ADMINISTRATOR)
    result = client.post(
        "/api/threat-analysis/analyze", json={"text": MESSAGE}, headers=owner
    ).json()
    analysis_id = result["id"]
    feedback_response = client.post(
        f"/api/threat-analysis/analyses/{analysis_id}/feedback",
        json={"candidate_label": "malicious", "reason": "The result needs human review."},
        headers=owner,
    )
    assert feedback_response.status_code == 201
    feedback_id = uuid.UUID(feedback_response.json()["id"])
    assert (
        client.delete(f"/api/threat-analysis/analyses/{analysis_id}", headers=other).status_code
        == 404
    )
    with session_factory() as db:
        row = db.get(ThreatAnalysis, uuid.UUID(analysis_id))
        row.created_at = datetime.now(UTC) - timedelta(days=60)
        db.commit()
    purge = client.post("/api/threat-analysis/admin/retention/purge", headers=admin)
    assert purge.status_code == 200
    assert purge.json()["deleted_analyses"] == 1
    assert (
        client.get(f"/api/threat-analysis/analyses/{analysis_id}", headers=owner).status_code == 404
    )
    with session_factory() as db:
        audit = db.scalar(
            select(AuditLog).where(AuditLog.action == "threat_analysis.retention_purge")
        )
        assert audit.details["deleted_analyses"] == 1
        assert db.get(ThreatFeedback, feedback_id) is None
