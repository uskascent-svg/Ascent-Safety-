"""Combine rule indicators and the optional ML probability into one explainable risk score."""

from app.detection.phishing.ml import MlResult
from app.detection.phishing.rules import Indicator

RULE_WEIGHT = 0.7
ML_WEIGHT = 0.3
PHISHING_THRESHOLD = 55
SUSPICIOUS_THRESHOLD = 25
MIN_INDICATORS_FOR_PHISHING = 2  # never classify as phishing on a single signal

ACTIONS = {
    "likely_phishing": (
        "Do not click links, open attachments or reply. Report the message to your security team "
        "and delete it. If you already interacted with it, change the affected passwords and "
        "enable multi-factor authentication."
    ),
    "suspicious": (
        "Treat with caution. Verify the sender through a separate, trusted channel before clicking "
        "links or opening attachments."
    ),
    "low_risk": (
        "No significant indicators were found. This is not a guarantee of safety — stay alert for "
        "unexpected requests."
    ),
}


def rule_score(indicators: list[Indicator]) -> int:
    """Probabilistic OR: each indicator independently adds risk with diminishing returns."""
    remaining = 1.0
    for i in indicators:
        remaining *= 1.0 - i.weight
    return round((1.0 - remaining) * 100)


def combine(rules: int, ml: MlResult | None) -> int:
    if ml is None:
        return rules
    return round(RULE_WEIGHT * rules + ML_WEIGHT * ml.probability * 100)


def classify(score: int, indicator_count: int, strong_signal: bool = False) -> str:
    """`strong_signal`: an authoritative threat-intelligence verdict (not a heuristic keyword)."""
    if score >= PHISHING_THRESHOLD and (
        indicator_count >= MIN_INDICATORS_FOR_PHISHING or strong_signal
    ):
        return "likely_phishing"
    if score >= SUSPICIOUS_THRESHOLD or score >= PHISHING_THRESHOLD:
        return "suspicious"
    return "low_risk"


def build_reasons(
    indicators: list[Indicator], ml: MlResult | None, classification: str
) -> list[str]:
    reasons = [i.description for i in indicators]
    if ml and ml.probability >= 0.5:
        terms = ", ".join(ml.top_terms[:3])
        suffix = f" Influential terms: {terms}." if terms else ""
        reasons.append(
            f"The machine-learning classifier rated the text as {ml.probability:.0%} likely to be "
            f"phishing.{suffix}"
        )
    if not reasons:
        reasons.append("No phishing indicators were detected by the rules or classifier.")
    return reasons
