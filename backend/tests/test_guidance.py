from tests.conftest import PASSWORD


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
