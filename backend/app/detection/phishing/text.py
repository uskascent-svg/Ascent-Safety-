"""Phrase-category matching for language commonly used in phishing."""

import re

_P = lambda *pats: [re.compile(p, re.I) for p in pats]  # noqa: E731

PATTERNS: dict[str, list[re.Pattern]] = {
    "urgency": _P(
        r"\burgent(?:ly)?\b",
        r"\bimmediate(?:ly)?\b",
        r"\bwithin 24 hours\b",
        r"\bact now\b",
        r"\bfinal (?:notice|warning)\b",
        r"\blast warning\b",
        r"\bexpires? (?:today|soon|in)\b",
        r"\baccount (?:will be |has been )?(?:suspended|closed|locked|disabled)\b",
    ),
    "credential_request": _P(
        r"\bverify your (?:account|identity|password|credentials|email)\b",
        r"\bconfirm your (?:password|login|account|identity|details)\b",
        r"\bupdate your (?:payment|billing|account|login) (?:information|details)\b",
        r"\blog ?in to (?:verify|confirm|restore|unlock)\b",
        r"\benter your (?:password|pin|ssn|social security)\b",
        r"\b(?:security|verification) code\b",
    ),
    "financial": _P(
        r"\bwire transfer\b",
        r"\bgift cards?\b",
        r"\bbitcoin\b",
        r"\bpayment (?:failed|declined)\b",
        r"\boutstanding (?:invoice|balance)\b",
        r"\bunpaid (?:invoice|balance)\b",
    ),
    "threat": _P(
        r"\bunauthori[sz]ed (?:access|login|activity|transaction)\b",
        r"\bsuspicious (?:activity|sign-?in|login)\b",
        r"\blegal action\b",
        r"\byour account has been (?:compromised|hacked|limited)\b",
    ),
}


def find_phrases(text: str) -> dict[str, list[str]]:
    """Return {category: distinct matched phrases (max 5)} for categories with any match."""
    found: dict[str, list[str]] = {}
    for category, patterns in PATTERNS.items():
        seen: list[str] = []
        for pattern in patterns:
            m = pattern.search(text)
            if m and m.group(0).lower() not in seen:
                seen.append(m.group(0).lower())
        if seen:
            found[category] = seen[:5]
    return found


def model_text(subject: str, body: str) -> str:
    """Text fed to the ML classifier. Training must build text the same way (see ml/README.md)."""
    return f"{subject}\n{body}"[:20_000]
