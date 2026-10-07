from datetime import UTC, datetime, timedelta
import uuid

import pytest
from sqlalchemy import select

from app.models import AuditLog, RoleName, SecurityEvent
from tests.conftest import PASSWORD


def report_payload(**override):
    payload = {
        "issue_type": "phishing_website",
        "title": "Suspicious banking login page",
        "description": "A message directed me to a page imitating my bank.",
        "suspicious_url": "https://example.invalid/login",
        "source_location": "Pune, India",
        "reported_at": datetime.now(UTC).isoformat(),
        "severity": "high",
        "additional_notes": "Received by email.",
    }
    payload.update(override)
    return payload


def auth_headers(client, make_user, email="reporter@example.com"):
    make_user(email)
    token = client.post("/api/auth/login", json={"email": email, "password": PASSWORD}).json()
    return {"Authorization": f"Bearer {token['access_token']}"}


@pytest.fixture()
def reporter(client, make_user):
    return auth_headers(client, make_user)


@pytest.fixture()
def admin(client, make_user, promote):
    headers = auth_headers(client, make_user, "admin@example.com")
    promote("admin@example.com", RoleName.ADMINISTRATOR)
    # The backend resolves roles from the database on every request.
    return headers


def test_report_submission_supports_anonymous_tracking_and_authenticated_reports(client, reporter):
    anonymous = client.post("/api/reports", json=report_payload())
    assert anonymous.status_code == 201, anonymous.text
    anonymous_record = anonymous.json()
    assert anonymous_record["tracking_token"]
    assert "reporter_id" not in anonymous_record
    tracked = client.post(
        f"/api/reports/track/{anonymous_record['report_code']}",
        json={"token": anonymous_record["tracking_token"]},
    )
    assert tracked.status_code == 200
    assert tracked.json()["report_code"] == anonymous_record["report_code"]
    assert (
        client.post(
            f"/api/reports/track/{anonymous_record['report_code']}", json={"token": "x" * 40}
        ).status_code
        == 404
    )

    response = client.post("/api/reports", json=report_payload(), headers=reporter)
    assert response.status_code == 201, response.text
    record = response.json()
    assert record["report_code"].startswith("ASR-")
    assert record["status"] == "submitted"
    assert "reporter_id" not in record
    assert "internal_notes" not in record
    assert record["tracking_token"] is None

    listing = client.get("/api/reports/mine", headers=reporter)
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["report_code"] == record["report_code"]
    assert listing.json()["items"][0]["timeline"][0]["summary"] == "Report submitted"
    detail = client.get(f"/api/reports/mine/{record['report_code']}", headers=reporter)
    assert detail.status_code == 200


def test_report_ownership_and_internal_notes_are_enforced(
    client, reporter, admin, make_user, promote, session_factory
):
    response = client.post("/api/reports", json=report_payload(), headers=reporter)
    code = response.json()["report_code"]
    stranger = auth_headers(client, make_user, "stranger@example.com")
    analyst = auth_headers(client, make_user, "analyst@example.com")
    promote("analyst@example.com", RoleName.SECURITY_ANALYST)

    assert client.get(f"/api/reports/mine/{code}", headers=stranger).status_code == 404
    assert client.get("/api/reports/admin", headers=stranger).status_code == 403
    assert client.get("/api/reports/admin", headers=analyst).status_code == 403
    assert (
        client.patch(
            f"/api/reports/admin/{code}",
            json={"internal_note": "Review sender headers"},
            headers=stranger,
        ).status_code
        == 403
    )
    assert (
        client.patch(
            f"/api/reports/admin/{code}",
            json={"internal_note": "Review sender headers"},
            headers=analyst,
        ).status_code
        == 403
    )

    managed = client.patch(
        f"/api/reports/admin/{code}", json={"internal_note": "Review sender headers"}, headers=admin
    )
    assert managed.status_code == 200, managed.text
    assert managed.json()["internal_notes"][0]["content"] == "Review sender headers"
    private_view = client.get(f"/api/reports/mine/{code}", headers=reporter)
    assert private_view.status_code == 200
    assert "internal_notes" not in private_view.json()
    assert all(item["action"] != "internal_note" for item in private_view.json()["timeline"])
    with session_factory() as db:
        log = db.scalar(select(AuditLog).where(AuditLog.action == "security_report.manage"))
        assert log and log.details["report_code"] == code
        assert "Review sender headers" not in str(log.details)


def test_report_admin_can_filter_assign_transition_and_reopen(
    client, reporter, admin, make_user, promote
):
    analyst_headers = auth_headers(client, make_user, "analyst@example.com")
    promote("analyst@example.com", RoleName.SECURITY_ANALYST)
    analyst_id = client.get("/api/auth/me", headers=analyst_headers).json()["id"]
    report = client.post("/api/reports", json=report_payload(), headers=reporter).json()
    code = report["report_code"]

    filtered = client.get(
        "/api/reports/admin?severity=high&issue_type=phishing_website", headers=admin
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
    assigned = client.patch(
        f"/api/reports/admin/{code}", json={"assigned_to_id": analyst_id}, headers=admin
    )
    assert assigned.status_code == 200 and assigned.json()["assigned_to_id"] == analyst_id

    assert (
        client.patch(
            f"/api/reports/admin/{code}", json={"status": "investigating"}, headers=admin
        ).status_code
        == 409
    )
    reviewed = client.patch(
        f"/api/reports/admin/{code}", json={"status": "under_review"}, headers=admin
    )
    assert reviewed.status_code == 200 and reviewed.json()["status"] == "under_review"
    resolved = client.patch(
        f"/api/reports/admin/{code}", json={"status": "resolved"}, headers=admin
    )
    assert resolved.status_code == 200 and resolved.json()["status"] == "resolved"
    reopened = client.patch(
        f"/api/reports/admin/{code}", json={"status": "reopened"}, headers=admin
    )
    assert reopened.status_code == 200 and reopened.json()["status"] == "reopened"


@pytest.mark.parametrize(
    "override",
    [
        {"title": "  "},
        {"description": "short"},
        {"suspicious_url": "javascript:alert(1)"},
        {"reported_at": "2026-10-07T10:00:00"},
        {"reported_at": (datetime.now(UTC) + timedelta(days=2)).isoformat()},
        {"severity": "catastrophic"},
        {"unexpected": "field"},
    ],
)
def test_report_submission_rejects_invalid_fields(client, reporter, override):
    response = client.post("/api/reports", json=report_payload(**override), headers=reporter)
    assert response.status_code == 422


def test_assignment_requires_active_analyst_or_admin(client, reporter, admin, make_user):
    auth_headers(client, make_user, "plain-assignee@example.com")
    token = client.post(
        "/api/auth/login",
        json={"email": "plain-assignee@example.com", "password": PASSWORD},
    ).json()
    plain = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token['access_token']}"})
    assert plain.status_code == 200
    report = client.post("/api/reports", json=report_payload(), headers=reporter).json()
    response = client.patch(
        f"/api/reports/admin/{report['report_code']}",
        json={"assigned_to_id": plain.json()["id"]},
        headers=admin,
    )
    assert response.status_code == 422


def test_report_promotion_requires_admin_review_and_publishes_sanitized_event(
    client, reporter, admin, make_user, promote, session_factory
):
    report = client.post("/api/reports", json=report_payload(), headers=reporter).json()
    code = report["report_code"]
    payload = {
        "content_reviewed": True,
        "location_verified": True,
        "threat_type": "phishing",
        "title": "Verified phishing site targeting bank customers",
        "description": "Analyst verified the domain and removed reporter details.",
        "country": "India",
        "region": "Maharashtra",
        "latitude": 18.52,
        "longitude": 73.86,
    }
    assert (
        client.post(
            f"/api/reports/admin/{code}/promote", json=payload, headers=reporter
        ).status_code
        == 403
    )
    assert (
        client.post(f"/api/reports/admin/{code}/promote", json=payload, headers=admin).status_code
        == 409
    )

    reviewed = client.patch(
        f"/api/reports/admin/{code}", json={"status": "under_review"}, headers=admin
    )
    assert reviewed.status_code == 200
    too_precise = {**payload, "latitude": 18.521}
    assert (
        client.post(
            f"/api/reports/admin/{code}/promote", json=too_precise, headers=admin
        ).status_code
        == 422
    )
    missing_ack = {**payload, "location_verified": False}
    assert (
        client.post(
            f"/api/reports/admin/{code}/promote", json=missing_ack, headers=admin
        ).status_code
        == 422
    )

    response = client.post(f"/api/reports/admin/{code}/promote", json=payload, headers=admin)
    assert response.status_code == 201, response.text
    event_id = response.json()["promoted_event_id"]
    assert event_id
    assert (
        client.post(f"/api/reports/admin/{code}/promote", json=payload, headers=admin).status_code
        == 409
    )
    with session_factory() as db:
        event = db.get(SecurityEvent, uuid.UUID(event_id))
        assert event and event.source == "reviewed_user_report"
        assert event.external_id == code and event.latitude == 18.52
        assert event.title == payload["title"] and event.description == payload["description"]
        audit_log = db.scalar(select(AuditLog).where(AuditLog.action == "security_report.promote"))
        assert audit_log and audit_log.details["event_id"] == event_id


def test_admin_can_resolve_report_place_name_only_during_review(
    client, reporter, admin, monkeypatch
):
    report = client.post("/api/reports", json=report_payload(), headers=reporter).json()
    code = report["report_code"]
    endpoint = f"/api/reports/admin/{code}/location-options"

    denied = client.get(endpoint, headers=reporter)
    assert denied.status_code == 403
    not_in_review = client.get(endpoint, headers=admin)
    assert not_in_review.status_code == 409

    reviewed = client.patch(
        f"/api/reports/admin/{code}", json={"status": "under_review"}, headers=admin
    )
    assert reviewed.status_code == 200

    def fake_resolve(db, place_name):
        assert place_name == "Pune, India"
        return (
            [
                {
                    "label": "Pune, Maharashtra, India",
                    "locality": "Pune",
                    "region": "Maharashtra",
                    "country": "India",
                    "latitude": 18.52,
                    "longitude": 73.86,
                }
            ],
            False,
        )

    monkeypatch.setattr("app.api.reports.resolve_place_name", fake_resolve)
    response = client.get(endpoint, headers=admin)
    assert response.status_code == 200, response.text
    assert response.json()["items"][0]["latitude"] == 18.52
    assert response.json()["items"][0]["longitude"] == 73.86
    assert "OpenStreetMap" in response.json()["attribution"]


def test_geocoder_rejects_address_like_report_place_names():
    from app.services.geocoding import _normalize_query

    with pytest.raises(ValueError):
        _normalize_query("42 Main Street, Pune")
    with pytest.raises(ValueError):
        _normalize_query("person@example.com")


def test_place_name_matches_are_cached_without_persisting_search_text(session_factory, monkeypatch):
    from app.models import GeocodeCache
    from app.services import geocoding

    candidates = [
        {
            "label": "Pune, Maharashtra, India",
            "locality": "Pune",
            "region": "Maharashtra",
            "country": "India",
            "latitude": 18.52,
            "longitude": 73.86,
        }
    ]
    calls = 0

    def fake_fetch(query):
        nonlocal calls
        calls += 1
        assert query == "Pune, India"
        return candidates

    monkeypatch.setattr(geocoding, "_fetch_candidates", fake_fetch)
    with session_factory() as db:
        first, first_cached = geocoding.resolve_place_name(db, "Pune, India")
        second, second_cached = geocoding.resolve_place_name(db, "Pune, India")
        row = db.scalar(select(GeocodeCache))
        assert row.query_hash != "Pune, India"
        assert "Pune, India" not in str(row.results)

    assert first == second == candidates
    assert not first_cached and second_cached
    assert calls == 1
