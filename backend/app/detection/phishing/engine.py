import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache

from app.core.config import get_settings
from app.detection.phishing import scoring
from app.detection.phishing.ml import MlClassifier, MlResult
from app.detection.phishing.parser import ParsedEmail
from app.detection.phishing.rules import Indicator, run_rules
from app.detection.phishing.text import find_phrases, model_text
from app.detection.phishing.urls import Link, extract_links


@dataclass
class AnalysisResult:
    risk_score: int
    rule_score: int
    classification: str
    indicators: list[Indicator]
    reasons: list[str]
    ml: MlResult | None
    ml_available: bool
    recommended_action: str
    link_count: int
    attachment_count: int
    content_sha256: str


@lru_cache
def _get_classifier(path: str | None, version_key: str | None = None) -> MlClassifier:
    return MlClassifier(path)


def get_classifier() -> MlClassifier:
    configured = get_settings().ml_model_path
    if configured:
        return _get_classifier(configured)
    try:
        from app.services.threat_training import verified_active_model_path

        active = verified_active_model_path()
    except Exception:
        active = None
    return _get_classifier(*active) if active else _get_classifier(None)


def analyze(
    parsed: ParsedEmail,
    classifier: MlClassifier | None = None,
    intel: Callable[[list[Link]], list[Indicator]] | None = None,
) -> AnalysisResult:
    classifier = classifier if classifier is not None else get_classifier()
    links = extract_links(parsed.text, parsed.html)
    phrases = find_phrases(f"{parsed.subject}\n{parsed.text}")
    indicators = run_rules(parsed, links, phrases)
    if intel is not None:
        indicators = sorted(indicators + intel(links), key=lambda i: -i.weight)

    ml = (
        classifier.predict(model_text(parsed.subject, parsed.text))
        if classifier.available
        else None
    )
    rules = scoring.rule_score(indicators)
    score = scoring.combine(rules, ml)
    strong = any(i.code == "TI_MALICIOUS_INDICATOR" for i in indicators)
    classification = scoring.classify(score, len(indicators), strong)

    return AnalysisResult(
        risk_score=score,
        rule_score=rules,
        classification=classification,
        indicators=indicators,
        reasons=scoring.build_reasons(indicators, ml, classification),
        ml=ml,
        ml_available=classifier.available,
        recommended_action=scoring.ACTIONS[classification],
        link_count=len(links),
        attachment_count=len(parsed.attachments),
        content_sha256=hashlib.sha256(f"{parsed.subject}\n{parsed.text}".encode()).hexdigest(),
    )
