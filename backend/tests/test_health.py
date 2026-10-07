from sqlalchemy.exc import SQLAlchemyError

from app import main as main_module


def test_liveness_reports_running_api(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_checks_database(client):
    response = client.get("/api/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": "available"}


def test_readiness_is_unavailable_when_database_is_down(client, monkeypatch):
    class UnavailableEngine:
        def connect(self):
            raise SQLAlchemyError("database unavailable")

    monkeypatch.setattr(main_module, "engine", UnavailableEngine())

    response = client.get("/api/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}


def test_cors_allows_alert_updates_and_telemetry_headers(client):
    response = client.options(
        "/api/alerts/00000000-0000-0000-0000-000000000000",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "PATCH",
            "Access-Control-Request-Headers": (
                "authorization,content-type,x-endpoint-key,x-sensor-key"
            ),
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "PATCH" in response.headers["access-control-allow-methods"]
    allowed_headers = response.headers["access-control-allow-headers"].lower()
    assert "x-endpoint-key" in allowed_headers
    assert "x-sensor-key" in allowed_headers
