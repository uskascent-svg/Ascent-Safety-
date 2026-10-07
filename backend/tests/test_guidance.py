from tests.conftest import PASSWORD
from unittest.mock import AsyncMock, patch


def login(client, make_user, email="guide@example.com"):
    make_user(email)
    token = client.post("/api/auth/login", json={"email": email, "password": PASSWORD}).json()
    return {"Authorization": f"Bearer {token['access_token']}"}


def test_guidance_requires_auth_and_uses_rules_fallback(client, make_user):
    assert client.get("/api/guidance/status").status_code == 401
    headers = login(client, make_user)
    status = client.get("/api/guidance/status", headers=headers)
    assert status.status_code == 200
    assert status.json() == {"provider": "rules", "model": None}

    response = client.post(
        "/api/guidance/chat",
        headers=headers,
        json={"messages": [{"role": "user", "text": "How do I check a suspicious email?"}]},
    )
    assert response.status_code == 200
    assert response.json()["provider"] == "rules"
    assert "Do not open" in response.json()["answer"]


def test_guidance_limits_message_size(client, make_user):
    headers = login(client, make_user)
    response = client.post(
        "/api/guidance/chat",
        headers=headers,
        json={"messages": [{"role": "user", "text": "x" * 1501}]},
    )
    assert response.status_code == 422


def test_guidance_uses_one_adk_agent_call_when_configured(client, make_user, monkeypatch):
    from app.core.config import get_settings

    headers = login(client, make_user)
    monkeypatch.setenv("GOOGLE_API_KEY", "test-google-api-key-not-a-real-secret")
    get_settings.cache_clear()
    try:
        with patch(
            "app.services.guidance._ask_agent",
            new=AsyncMock(return_value="Use your approved incident response process."),
        ) as ask:
            response = client.post(
                "/api/guidance/chat",
                headers=headers,
                json={"messages": [{"role": "user", "text": "What should I do after malware?"}]},
            )

        assert response.status_code == 200
        assert response.json() == {
            "answer": "Use your approved incident response process.",
            "provider": "gemini",
            "model": "gemini-3.5-flash-lite",
        }
        ask.assert_awaited_once()
    finally:
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        get_settings.cache_clear()


def test_guidance_provider_failure_falls_back_without_exposing_error(
    client, make_user, monkeypatch
):
    from app.core.config import get_settings

    headers = login(client, make_user)
    monkeypatch.setenv("GOOGLE_API_KEY", "test-google-api-key-not-a-real-secret")
    get_settings.cache_clear()
    try:
        with patch(
            "app.services.guidance._ask_agent", new=AsyncMock(side_effect=TimeoutError("private"))
        ) as ask:
            response = client.post(
                "/api/guidance/chat",
                headers=headers,
                json={"messages": [{"role": "user", "text": "What should I do after ransomware?"}]},
            )

        assert response.status_code == 200
        assert response.json()["provider"] == "rules"
        assert "preserve logs" in response.json()["answer"]
        assert "private" not in response.text
        ask.assert_awaited_once()
    finally:
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        get_settings.cache_clear()
