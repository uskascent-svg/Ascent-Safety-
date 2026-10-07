from datetime import datetime, timedelta, UTC

import pytest

from app.core.config import get_settings
from app.models import RoleName
from tests.conftest import PASSWORD

KEY = {"X-Ingest-Key": "ingest-key-ingest-key-ingest-key-123"}
NOW = datetime.now(UTC)


def iso(dt):
    return dt.isoformat()


def event(**over):
    base = {
        "source": "test-sensor",
        "threat_type": "phishing",
        "severity": "high",
        "title": "Test event",
        "occurred_at": iso(NOW - timedelta(minutes=10)),
    }
    base.update(over)
    return base


@pytest.fixture()
def ingest(client):
    def _ingest(**over):
        r = client.post("/api/security-events", json=event(**over), headers=KEY)
        assert r.status_code == 201, r.text
        return r.json()

    return _ingest


@pytest.fixture()
def analyst(client, make_user, promote):
    make_user("analyst@example.com")
    promote("analyst@example.com", RoleName.SECURITY_ANALYST)
    r = client.post("/api/auth/login", json={"email": "analyst@example.com", "password": PASSWORD})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ---------- ingestion ----------
def test_ingest_requires_valid_key(client):
    assert client.post("/api/security-events", json=event()).status_code == 401
    bad = client.post("/api/security-events", json=event(), headers={"X-Ingest-Key": "x" * 40})
    assert bad.status_code == 401


def test_ingest_disabled_without_configured_key(client):
    settings = get_settings()
    original, settings.ingest_api_key = settings.ingest_api_key, None
    try:
        assert client.post("/api/security-events", json=event(), headers=KEY).status_code == 503
    finally:
        settings.ingest_api_key = original


def test_alert_notifications_are_user_scoped_and_readable(
    client, analyst, ingest, make_user, promote
):
    created = ingest(severity="critical", external_id="notification-event-1")
    page = client.get("/api/notifications", headers=analyst)
    assert page.status_code == 200
    assert page.json()["unread"] == 1
    notification = page.json()["items"][0]
    assert notification["event_id"] == created["id"] and notification["read_at"] is None
    assert client.get("/api/notifications").status_code == 401

    make_user("second-analyst@example.com")
    promote("second-analyst@example.com", RoleName.SECURITY_ANALYST)
    token = client.post(
        "/api/auth/login",
        json={"email": "second-analyst@example.com", "password": PASSWORD},
    ).json()["access_token"]
    other_page = client.get("/api/notifications", headers={"Authorization": f"Bearer {token}"})
    assert other_page.status_code == 200 and other_page.json()["total"] == 0
    assert (
        client.post(
            f"/api/notifications/{notification['id']}/read",
            headers={"Authorization": f"Bearer {token}"},
        ).status_code
        == 404
    )

    read = client.post(f"/api/notifications/{notification['id']}/read", headers=analyst)
    assert read.status_code == 200 and read.json()["read_at"]
    assert client.get("/api/notifications", headers=analyst).json()["unread"] == 0


@pytest.mark.parametrize(
    "override",
    [
        {"latitude": 10.0},  # unpaired coordinates
        {"origin_latitude": 10.0},  # origin needs a complete coordinate pair
        {"destination_longitude": 10.0},  # destination needs a complete coordinate pair
        {"latitude": 91, "longitude": 0},  # out of range
        {"longitude": 181, "latitude": 0},
        {"origin_latitude": 91, "origin_longitude": 0},
        {"destination_latitude": 0, "destination_longitude": 181},
        {"occurred_at": "2024-01-01T00:00:00"},  # naive timestamp
        {"occurred_at": iso(NOW + timedelta(hours=1))},  # future
        {"severity": "catastrophic"},
        {"threat_type": "alien"},
        {"source_ip": "999.1.1.1"},
        {"unexpected": "field"},
        {"title": ""},
    ],
)
def test_ingest_rejects_invalid_payloads(client, override):
    r = client.post("/api/security-events", json=event(**override), headers=KEY)
    assert r.status_code == 422


def test_ingest_is_idempotent_per_source_external_id(client, ingest):
    ingest(external_id="abc-1")
    r = client.post("/api/security-events", json=event(external_id="abc-1"), headers=KEY)
    assert r.status_code == 409
    # same external id from a different source is a different event
    ingest(external_id="abc-1", source="other-sensor")


# ---------- authorization ----------
def test_read_endpoints_require_analyst_or_admin(client, make_user, ingest):
    ev = ingest()
    paths = [
        "/api/security-events",
        "/api/security-events/locations",
        f"/api/security-events/{ev['id']}",
        "/api/dashboard/summary",
        "/api/dashboard/timeline",
        "/api/dashboard/severity",
        "/api/dashboard/threat-types",
        "/api/dashboard/regions",
    ]
    assert all(client.get(p).status_code == 401 for p in paths)
    make_user("plain@example.com")
    tok = client.post(
        "/api/auth/login", json={"email": "plain@example.com", "password": PASSWORD}
    ).json()
    h = {"Authorization": f"Bearer {tok['access_token']}"}
    assert all(client.get(p, headers=h).status_code == 403 for p in paths)


# ---------- empty state: no fabricated data ----------
def test_empty_database_returns_zeros_and_empty_lists(client, analyst):
    assert client.get("/api/security-events", headers=analyst).json() == {
        "items": [],
        "total": 0,
        "limit": 25,
        "offset": 0,
    }
    assert client.get("/api/security-events/locations", headers=analyst).json() == {
        "items": [],
        "total": 0,
        "truncated": False,
    }
    assert client.get("/api/dashboard/summary", headers=analyst).json() == {
        "total_events": 0,
        "active_threats": 0,
        "blocked_threats": 0,
        "critical_events": 0,
        "affected_regions": 0,
    }
    for p in ("timeline", "severity", "threat-types", "regions"):
        assert client.get(f"/api/dashboard/{p}", headers=analyst).json() == []


# ---------- listing / filtering ----------
def test_list_filter_search_and_pagination(client, analyst, ingest):
    ingest(
        title="Credential harvest page",
        threat_type="phishing",
        severity="critical",
        region="EMEA",
        country="Germany",
    )
    ingest(
        title="Ransomware note found",
        threat_type="malware_ransomware",
        severity="high",
        region="APAC",
        country="Japan",
    )
    ingest(title="Odd login", threat_type="suspicious_login", severity="low", region="EMEA")

    def get(q=""):
        return client.get(f"/api/security-events?{q}", headers=analyst).json()

    assert get()["total"] == 3
    assert get("severity=critical&severity=high")["total"] == 2
    assert get("threat_type=suspicious_login")["items"][0]["title"] == "Odd login"
    assert get("region=EMEA")["total"] == 2
    assert get("country=Japan")["total"] == 1
    assert get("q=ransom")["total"] == 1
    assert get("q=%25")["total"] == 0  # wildcard is escaped, not a match-all
    page = get("limit=2&offset=2")
    assert len(page["items"]) == 1 and page["total"] == 3
    assert client.get("/api/security-events?limit=1000", headers=analyst).status_code == 422
    assert client.get("/api/security-events?severity=bogus", headers=analyst).status_code == 422


def test_time_filters_and_ordering(client, analyst, ingest):
    old = ingest(title="old", occurred_at=iso(NOW - timedelta(days=10)))
    new = ingest(title="new", occurred_at=iso(NOW - timedelta(hours=1)))
    all_ = client.get("/api/security-events", headers=analyst).json()["items"]
    assert [e["id"] for e in all_] == [new["id"], old["id"]]  # newest first
    since = iso(NOW - timedelta(days=1)).replace("+00:00", "Z")
    recent = client.get("/api/security-events", params={"since": since}, headers=analyst).json()
    assert [e["id"] for e in recent["items"]] == [new["id"]]


def test_event_detail_and_404(client, analyst, ingest):
    ev = ingest(source_ip="203.0.113.7")
    r = client.get(f"/api/security-events/{ev['id']}", headers=analyst)
    assert r.status_code == 200 and r.json()["source_ip"] == "203.0.113.7"
    missing = client.get(
        "/api/security-events/00000000-0000-0000-0000-000000000000", headers=analyst
    )
    assert missing.status_code == 404


def test_locations_only_include_events_with_coordinates(client, analyst, ingest):
    ingest(title="no coords")
    ingest(title="with coords", latitude=48.85, longitude=2.35, country="France")
    r = client.get("/api/security-events/locations", headers=analyst).json()
    assert r["total"] == 1 and r["items"][0]["title"] == "with coords"
    assert (r["items"][0]["latitude"], r["items"][0]["longitude"]) == (48.85, 2.35)
    capped = client.get("/api/security-events/locations?limit=1", headers=analyst).json()
    assert capped["truncated"] is False
    ingest(title="second", latitude=1.0, longitude=1.0)
    capped = client.get("/api/security-events/locations?limit=1", headers=analyst).json()
    assert capped["truncated"] is True and capped["total"] == 2


def test_locations_include_explicit_routes_without_inventing_event_point(client, analyst, ingest):
    ingest(
        title="route event",
        origin_latitude=40.71,
        origin_longitude=-74.0,
        destination_latitude=51.51,
        destination_longitude=-0.13,
    )

    response = client.get("/api/security-events/locations", headers=analyst)

    assert response.status_code == 200
    [route] = response.json()["items"]
    assert route["latitude"] is None and route["longitude"] is None
    assert (route["origin_latitude"], route["origin_longitude"]) == (40.71, -74.0)
    assert (route["destination_latitude"], route["destination_longitude"]) == (51.51, -0.13)


# ---------- dashboard aggregation ----------
def test_dashboard_numbers_are_derived_from_events(client, analyst, ingest):
    ingest(severity="critical", status="open", region="EMEA", threat_type="phishing")
    ingest(severity="critical", status="blocked", region="EMEA", threat_type="phishing")
    ingest(severity="high", status="investigating", region="APAC", threat_type="mitm")
    ingest(severity="low", status="resolved", threat_type="other")  # no region
    ingest(severity="info", status="false_positive", region="AMER", threat_type="phishing")

    def get(path, q=""):
        return client.get(f"/api/dashboard/{path}?{q}", headers=analyst).json()

    assert get("summary") == {
        "total_events": 5,
        "active_threats": 2,
        "blocked_threats": 1,
        "critical_events": 2,
        "affected_regions": 3,
    }
    assert get("severity") == [
        {"key": "critical", "count": 2},
        {"key": "high", "count": 1},
        {"key": "low", "count": 1},
        {"key": "info", "count": 1},
    ]
    assert get("threat-types")[0] == {"key": "phishing", "count": 3}
    assert get("regions") == [
        {"region": "EMEA", "count": 2},
        {"region": "AMER", "count": 1},
        {"region": "APAC", "count": 1},
    ]
    # filters apply to the dashboard the same way they apply to the list
    assert get("summary", "region=EMEA")["total_events"] == 2


def test_timeline_buckets_by_hour_and_day(client, analyst, ingest):
    base = NOW.replace(minute=30, second=0, microsecond=0) - timedelta(hours=3)
    ingest(occurred_at=iso(base))
    ingest(occurred_at=iso(base + timedelta(minutes=5)))
    ingest(occurred_at=iso(base - timedelta(hours=2)))
    pts = client.get("/api/dashboard/timeline?bucket=hour", headers=analyst).json()
    assert [p["count"] for p in pts] == [1, 2]
    assert pts[1]["bucket"].startswith(base.strftime("%Y-%m-%dT%H:00:00"))
    daily = client.get("/api/dashboard/timeline?bucket=day", headers=analyst).json()
    assert sum(p["count"] for p in daily) == 3
    assert client.get("/api/dashboard/timeline?bucket=week", headers=analyst).status_code == 422


def test_ingest_is_audited(client, ingest, session_factory):
    from sqlalchemy import select

    from app.models import AuditLog

    ev = ingest()
    with session_factory() as db:
        rows = list(db.scalars(select(AuditLog).where(AuditLog.action == "security_event.ingest")))
    assert len(rows) == 1 and rows[0].details["event_id"] == ev["id"]
