from datetime import UTC, datetime, timedelta
import uuid

from sqlalchemy import select

from app.models import (
    AuditLog,
    CyberAlertActivity,
    EventStatus,
    RoleName,
    SecurityEvent,
)
from tests.test_reports import auth_headers


def alert_payload(**override):
    payload = {
        "title": "Regional credential phishing advisory",
        "severity": "critical",
        "threat_type": "phishing",
        "affected_region": "Pune, India",
        "summary": "Verified credential phishing activity is affecting users in this region.",
        "recommended_actions": ["Avoid the reported sign-in page", "Report suspicious messages"],
        "related_event_ids": [],
        "expires_at": (datetime.now(UTC) + timedelta(hours=12)).isoformat(),
    }
    payload.update(override)
    return payload


def test_critical_cyber_alert_requires_admin_approval_and_publication(
    client, make_user, promote, session_factory
):
    analyst = auth_headers(client, make_user, "alert-analyst@example.com")
    promote("alert-analyst@example.com", RoleName.SECURITY_ANALYST)
    admin = auth_headers(client, make_user, "alert-admin@example.com")
    promote("alert-admin@example.com", RoleName.ADMINISTRATOR)
    member = auth_headers(client, make_user, "alert-member@example.com")

    created = client.post("/api/cyber-alerts", json=alert_payload(), headers=analyst)
    assert created.status_code == 201, created.text
    alert_id = created.json()["id"]
    assert created.json()["status"] == "draft"
    assert client.post(f"/api/cyber-alerts/{alert_id}/publish", headers=analyst).status_code == 409

    approved = client.post(f"/api/cyber-alerts/{alert_id}/approve", headers=admin)
    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    assert client.post(f"/api/cyber-alerts/{alert_id}/publish", headers=analyst).status_code == 403

    published = client.post(f"/api/cyber-alerts/{alert_id}/publish", headers=admin)
    assert published.status_code == 200, published.text
    assert published.json()["status"] == "active"
    assert published.json()["published_event_id"]
    notifications = client.get("/api/notifications", headers=member)
    assert notifications.status_code == 200
    assert notifications.json()["unread"] == 1
    assert notifications.json()["items"][0]["event_id"] == published.json()["published_event_id"]
    with session_factory() as db:
        event = db.get(SecurityEvent, uuid.UUID(published.json()["published_event_id"]))
        assert event is not None
        assert event.source == "cyber_alert_declaration"
        assert event.severity == "critical"
        assert event.latitude is None  # unresolved place name never gets invented coordinates
        history = db.scalars(
            select(CyberAlertActivity).where(
                CyberAlertActivity.declaration_id == uuid.UUID(alert_id)
            )
        ).all()
        assert [item.action for item in history] == ["created", "approved", "published"]
        assert db.scalar(select(AuditLog).where(AuditLog.action == "cyber_alert.publish"))

    revoked = client.post(f"/api/cyber-alerts/{alert_id}/revoke", headers=admin)
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    with session_factory() as db:
        event = db.get(SecurityEvent, uuid.UUID(published.json()["published_event_id"]))
        assert event and event.status == EventStatus.RESOLVED.value
        assert event.latitude is None and event.longitude is None


def test_cyber_alert_validation_and_user_visibility(client, make_user, promote):
    user_headers = auth_headers(client, make_user, "alert-user@example.com")
    assert (
        client.post("/api/cyber-alerts", json=alert_payload(), headers=user_headers).status_code
        == 403
    )
    assert (
        client.post(
            "/api/cyber-alerts", json=alert_payload(severity="catastrophic"), headers=user_headers
        ).status_code
        == 403
    )

    analyst = auth_headers(client, make_user, "alert-editor@example.com")
    promote("alert-editor@example.com", RoleName.SECURITY_ANALYST)
    assert (
        client.post(
            "/api/cyber-alerts", json=alert_payload(severity="catastrophic"), headers=analyst
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/cyber-alerts",
            json=alert_payload(expires_at="2020-01-01T00:00:00Z"),
            headers=analyst,
        ).status_code
        == 422
    )
