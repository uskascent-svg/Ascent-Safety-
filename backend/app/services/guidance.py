"""Role-aware product and defensive cyber guidance with an optional Gemini provider."""

import logging

import httpx

from app.core.config import get_settings
from app.schemas.guidance import ChatTurn

log = logging.getLogger("ascent.guidance")

_SYSTEM = """You are Ascent Safety's defensive cybersecurity guidance assistant.
Give concise, practical, non-destructive security guidance. Adapt product instructions to the
user's server-verified application role. Never claim access to Ascent Safety records; no private
records are provided. Do not request passwords, OTPs, tokens, or sensitive evidence. Never provide
instructions to break into systems, evade detection, deploy malware, or exploit a real target.
For incidents, prioritize containment, evidence preservation, and the organization's security
team. Clarify uncertainty. Keep all phishing-lab guidance strictly simulated and safe."""


def _rules_answer(question: str, role_names: set[str]) -> str:
    q = question.casefold()
    analyst = bool(role_names & {"ADMINISTRATOR", "SECURITY_ANALYST"})
    if any(word in q for word in ("phish", "email", "sms", "text message", "qr code")):
        return (
            "Treat unexpected links and attachments as untrusted. Do not open them. Check the full "
            "sender address and reply-to, hover or copy a URL without visiting it, and verify "
            "urgent "
            "requests through a known channel. Use the Phishing Lab to practice with simulations; "
            "report suspected messages to your security team."
        )
    if any(word in q for word in ("incident", "attack", "ransomware", "compromised")):
        return (
            "If an incident may be active, disconnect the affected device from networks when safe, "
            "preserve logs and timestamps, and contact your security response team. Do not delete "
            "evidence or pay an attacker based on an unverified message."
        )
    if any(word in q for word in ("map", "location", "globe", "coordinates")):
        return (
            "The map shows only coordinates attached to stored security events. A city-name lookup "
            "can provide an approximate point during report review; an analyst must confirm and "
            "publish it. Missing or ambiguous locations remain unmapped."
        )
    if any(word in q for word in ("endpoint", "sensor", "telemetry", "agent")):
        return (
            "Ascent Safety analyzes telemetry from sources your organization registers. It does "
            "not install endpoint agents or capture traffic itself. Administrators can register "
            "sources and use the documented ingest APIs; detections depend on submitted telemetry."
        )
    if any(word in q for word in ("report", "submit", "issue")):
        if analyst:
            return (
                "In Reports, move a submission into active review, verify a city-level location if "
                "one was provided, sanitize the public summary, then publish only after confirming "
                "the evidence. Internal notes remain analyst-only."
            )
        return (
            "Use Report issue to send the response team a concise description and city/region "
            "only. Your report stays private while it is reviewed. Do not include passwords, OTPs, "
            "private "
            "addresses, or other people's personal data."
        )
    if analyst and any(word in q for word in ("alert", "triage", "analyst")):
        return (
            "Use the Security panel to filter stored events, inspect evidence, acknowledge alerts, "
            "and add internal notes through the report queue. Severity and location should reflect "
            "validated source evidence, not assumptions."
        )
    return (
        "I can help with phishing safety, incident response, report review, threat-map locations, "
        "and connected telemetry. Share only a short description; do not include credentials, "
        "personal data, or confidential incident evidence."
    )


def answer(messages: list[ChatTurn], role_names: set[str]) -> tuple[str, str, str | None]:
    settings = get_settings()
    if not settings.gemini_api_key:
        return _rules_answer(messages[-1].text, role_names), "rules", None

    contents = [
        {
            "role": "model" if turn.role == "assistant" else "user",
            "parts": [{"text": turn.text}],
        }
        for turn in messages
    ]
    system_instruction = _SYSTEM + "\nVerified role names: " + ", ".join(sorted(role_names))
    try:
        response = httpx.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}:generateContent",
            params={"key": settings.gemini_api_key},
            json={
                "systemInstruction": {"parts": [{"text": system_instruction}]},
                "contents": contents,
                "generationConfig": {"temperature": 0.25, "maxOutputTokens": 700},
            },
            timeout=15.0,
        )
        response.raise_for_status()
        candidates = response.json().get("candidates", [])
        parts = candidates[0].get("content", {}).get("parts", []) if candidates else []
        generated = "\n".join(str(part.get("text", "")) for part in parts).strip()
        if generated:
            return generated[:6000], "gemini", settings.gemini_model
    except (httpx.HTTPError, ValueError, KeyError, TypeError, IndexError):
        log.warning("Gemini guidance unavailable; using the rules-based response", exc_info=True)
    return _rules_answer(messages[-1].text, role_names), "rules", None
