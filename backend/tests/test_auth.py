from sqlalchemy import select

from app.models import AuditLog, RoleName
from tests.conftest import PASSWORD


def login(client, email="a@example.com", password=PASSWORD):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def test_register_assigns_user_role_and_hides_hash(client):
    r = client.post(
        "/api/auth/register",
        json={"email": "A@Example.com", "password": PASSWORD, "full_name": "A"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["roles"] == ["USER"] and body["email"] == "a@example.com"
    assert "password" not in str(body).lower()


def test_register_rejects_weak_password_and_duplicates(client, make_user):
    weak = client.post(
        "/api/auth/register",
        json={"email": "b@example.com", "password": "short", "full_name": "B"},
    )
    assert weak.status_code == 422
    make_user()
    dup = client.post(
        "/api/auth/register",
        json={"email": "a@example.com", "password": PASSWORD, "full_name": "A"},
    )
    assert dup.status_code == 409


def test_login_and_me(client, make_user):
    make_user()
    r = login(client)
    assert r.status_code == 200
    token = r.json()["access_token"]
    assert "refresh_token" in r.cookies
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200 and me.json()["email"] == "a@example.com"


def test_bad_credentials_are_generic_and_audited(client, make_user, session_factory):
    make_user()
    assert login(client, password="wrong-password-123").status_code == 401
    assert login(client, email="nobody@example.com").status_code == 401
    with session_factory() as db:
        actions = [a.action for a in db.scalars(select(AuditLog))]
    assert actions.count("auth.login_failed") == 2


def test_me_requires_valid_token(client):
    assert client.get("/api/auth/me").status_code == 401
    bad = client.get("/api/auth/me", headers={"Authorization": "Bearer nope"})
    assert bad.status_code == 401


def test_refresh_rotates_and_reuse_revokes_all(client, make_user):
    make_user()
    login(client)
    old = client.cookies.get("refresh_token")
    assert client.post("/api/auth/refresh").status_code == 200
    new = client.cookies.get("refresh_token")
    assert new != old
    # replay the rotated token
    client.cookies.set("refresh_token", old, path="/api/auth")
    assert client.post("/api/auth/refresh").status_code == 401
    # the legitimate new token is now revoked too
    client.cookies.set("refresh_token", new, path="/api/auth")
    assert client.post("/api/auth/refresh").status_code == 401


def test_logout_revokes_refresh_token(client, make_user):
    make_user()
    login(client)
    raw = client.cookies.get("refresh_token")
    assert client.post("/api/auth/logout").status_code == 204
    client.cookies.set("refresh_token", raw, path="/api/auth")
    assert client.post("/api/auth/refresh").status_code == 401


def test_rbac_blocks_regular_users_and_allows_admins(client, make_user, promote):
    make_user()
    token = login(client).json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/users", headers=h).status_code == 403
    promote("a@example.com", RoleName.ADMINISTRATOR)
    assert client.get("/api/users", headers=h).status_code == 200


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
