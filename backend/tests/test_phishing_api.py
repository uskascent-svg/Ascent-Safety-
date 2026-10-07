from sqlalchemy import select

from app.models import AuditLog, PhishingAnalysis, PhishingIndicator
from tests.conftest import PASSWORD

PHISH = {
    "sender": "PayPal Support <support@secure-mail.example.xyz>",
    "subject": "URGENT: verify your account within 24 hours",
    "body_html": "<p>Your account will be suspended. Verify your password:</p>"
    '<a href="http://203.0.113.9/login">www.paypal.com/signin</a>',
}


def auth(client, email="u@example.com"):
    client.post("/api/auth/register", json={"email": email, "password": PASSWORD, "full_name": "U"})
    token = client.post("/api/auth/login", json={"email": email, "password": PASSWORD}).json()
    return {"Authorization": f"Bearer {token['access_token']}"}


def test_requires_authentication(client):
    assert client.post("/api/phishing/analyze", json=PHISH).status_code == 401
    assert client.get("/api/phishing/analyses").status_code == 401


def test_analyze_returns_explained_result_and_persists(client, session_factory):
    h = auth(client)
    r = client.post("/api/phishing/analyze", json=PHISH, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["classification"] == "likely_phishing" and body["risk_score"] >= 55
    assert body["reasons"] and body["recommended_action"]
    assert {i["code"] for i in body["indicators"]} >= {"URL_IP_HOST", "TEXT_URGENCY"}
    assert body["ml"] == {
        "available": False,
        "probability": None,
        "model_version": None,
        "top_terms": [],
    }
    with session_factory() as db:
        analysis = db.scalar(select(PhishingAnalysis))
        assert analysis.content_sha256 and not hasattr(analysis, "body")  # body is not stored
        assert db.query(PhishingIndicator).count() == len(body["indicators"])
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "phishing.analyze"))
        assert audit.details["analysis_id"] == body["id"]


def test_raw_email_input(client):
    h = auth(client)
    raw = "From: a@example.com\nSubject: Hi\n\nSee you at lunch."
    r = client.post("/api/phishing/analyze", json={"raw_email": raw}, headers=h)
    assert r.status_code == 200 and r.json()["classification"] == "low_risk"
    assert r.json()["subject"] == "Hi"


def test_input_validation(client):
    h = auth(client)

    def post(payload):
        return client.post("/api/phishing/analyze", json=payload, headers=h)

    assert post({}).status_code == 422
    assert post({"raw_email": "x", "body_text": "y"}).status_code == 422
    assert post({"raw_email": "x", "subject": "y"}).status_code == 422
    assert post({"body_text": "x" * 500_001}).status_code == 422
    assert post({"body_text": "ok", "unknown": 1}).status_code == 422


def test_history_is_private_to_each_user(client):
    h1, h2 = auth(client, "one@example.com"), auth(client, "two@example.com")
    mine = client.post("/api/phishing/analyze", json=PHISH, headers=h1).json()
    page = client.get("/api/phishing/analyses", headers=h1).json()
    assert page["total"] == 1 and page["items"][0]["id"] == mine["id"]
    assert client.get("/api/phishing/analyses", headers=h2).json()["total"] == 0
    assert client.get(f"/api/phishing/analyses/{mine['id']}", headers=h1).status_code == 200
    assert client.get(f"/api/phishing/analyses/{mine['id']}", headers=h2).status_code == 404


def test_evidence_is_defanged_in_api_output(client):
    h = auth(client)
    body = client.post("/api/phishing/analyze", json=PHISH, headers=h).json()
    evidence = [e for i in body["indicators"] for e in i["evidence"]]
    assert not any(e.startswith("http") for e in evidence)
