from app.models import RoleName, TrainingScenario
from tests.conftest import PASSWORD


def login(client, make_user, email="learner@example.com"):
    make_user(email)
    token = client.post("/api/auth/login", json={"email": email, "password": PASSWORD}).json()
    return {"Authorization": f"Bearer {token['access_token']}"}


def make_scenario(db):
    row = TrainingScenario(
        slug="test-credential-simulation",
        title="Simulated account review",
        category="credential_phishing",
        difficulty="beginner",
        artifact_type="email",
        sender="Service <alerts@account-check.example>",
        reply_to="reply@external-mail.example",
        subject="Review your account",
        received_at="2026-10-06 · simulated",
        headers={"Authentication-Results": "spf=fail (SIMULATED)"},
        body="This is fictional training content; no real service is involved.",
        links=[{"label": "Training destination", "url": "https://account-check.example/login"}],
        attachments=[],
        indicators=[
            {
                "id": "sender_mismatch",
                "label": "Sender mismatch",
                "severity": "high",
                "explanation": "The reply address uses a separate domain.",
            },
            {
                "id": "credential_request",
                "label": "Credential request",
                "severity": "critical",
                "explanation": "Unsolicited login prompts can steal credentials.",
            },
        ],
        correct_decision="report",
        attack_technique="Simulated credential phishing",
        explanation="This is a simulation.",
        prevention="Verify requests using a trusted route.",
        correct_actions=["report_message", "avoid_clicking"],
        action_rationales={"report_message": "Report it.", "avoid_clicking": "Do not click."},
        objective="Inspect the sender and requested action.",
        is_active=True,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_scenario_is_safe_preview_and_attempt_persists_progress(client, make_user, session_factory):
    headers = login(client, make_user)
    with session_factory() as db:
        scenario = make_scenario(db)
        scenario_id = scenario.id

    listing = client.get("/api/phishing-training/scenarios", headers=headers)
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    preview = listing.json()["items"][0]
    assert preview["artifact_type"] == "email"
    assert "correct_decision" not in preview and "indicators" not in preview
    assert preview["links"][0]["url"].endswith(".example/login")

    attempted = client.post(
        "/api/phishing-training/attempts",
        headers=headers,
        json={
            "scenario_id": str(scenario_id),
            "decision": "report",
            "discovered_indicators": ["sender_mismatch"],
            "response_actions": ["report_message"],
            "elapsed_seconds": 60,
        },
    )
    assert attempted.status_code == 201, attempted.text
    result = attempted.json()
    assert result["decision_correct"] is True
    assert [item["id"] for item in result["indicators_missed"]] == ["credential_request"]
    assert result["security_score"] < 100
    progress = client.get("/api/phishing-training/progress", headers=headers).json()
    assert progress["scenarios_completed"] == 1
    assert progress["weakest_category"] == "credential_phishing"
    assert progress["recommended_next"]["id"] == str(scenario_id)
    assert progress["badges"]


def test_admin_can_create_only_reserved_training_links(client, make_user, promote):
    headers = login(client, make_user, "training-admin@example.com")
    promote("training-admin@example.com", RoleName.ADMINISTRATOR)
    payload = {
        "slug": "auth-example",
        "title": "Fictional sign-in prompt",
        "category": "credential_phishing",
        "difficulty": "beginner",
        "artifact_type": "login_page",
        "sender": "Service <help@accounts.example>",
        "reply_to": None,
        "subject": "Sign in",
        "received_at": "Training only",
        "headers": {},
        "body": "This fictional scenario does not collect credentials.",
        "links": [{"label": "Simulated", "url": "https://accounts.example/login"}],
        "attachments": [],
        "indicators": [
            {
                "id": "credential_request",
                "label": "Credential request",
                "severity": "high",
                "explanation": "The page is untrusted.",
            }
        ],
        "correct_decision": "report",
        "attack_technique": "Credential phishing simulation",
        "explanation": "The sender is unverified.",
        "prevention": "Use the known organization portal.",
        "correct_actions": ["report_message"],
        "action_rationales": {"report_message": "Report through the approved process."},
        "objective": "Check the hostname carefully.",
        "is_active": True,
    }
    rejected = client.post(
        "/api/phishing-training/admin/scenarios",
        headers=headers,
        json={**payload, "links": [{"label": "Real", "url": "https://example.com/login"}]},
    )
    assert rejected.status_code == 422
    created = client.post("/api/phishing-training/admin/scenarios", headers=headers, json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["created_by"]
