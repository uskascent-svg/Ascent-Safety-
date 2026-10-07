from email.message import EmailMessage

import pytest

from app.detection.phishing import scoring
from app.detection.phishing.engine import analyze
from app.detection.phishing.ml import MlClassifier, MlResult
from app.detection.phishing.parser import parse_fields, parse_raw
from app.detection.phishing.urls import (
    brand_lookalike,
    extract_links,
    registered_domain,
    text_domain_mismatch,
)

NO_ML = MlClassifier(None)


def codes(result):
    return {i.code for i in result.indicators}


# ---------- URL helpers ----------
def test_registered_domain():
    assert registered_domain("login.mail.example.com") == "example.com"
    assert registered_domain("shop.example.co.uk") == "example.co.uk"
    assert registered_domain("192.168.1.5") == "192.168.1.5"


def test_link_extraction_from_text_and_html_without_duplicates():
    html = '<a href="https://paypal.com/x">paypal.com</a><a href="mailto:a@b.c">mail</a>'
    links = extract_links("see www.example.org/page. and https://paypal.com/x", html)
    assert {link.host for link in links} == {"paypal.com", "www.example.org"}


def test_brand_lookalike_uses_whole_tokens():
    [bad] = extract_links("http://paypal-secure-login.example.xyz/a", None)
    [real] = extract_links("https://www.paypal.com/signin", None)
    [fp] = extract_links("https://pineapple-recipes.com", None)  # 'apple' is not a token
    assert brand_lookalike(bad) == "paypal"
    assert brand_lookalike(real) is None
    assert brand_lookalike(fp) is None


def test_link_text_mismatch():
    html = '<a href="http://evil.example.net/login">www.paypal.com/account</a>'
    [link] = extract_links("", html)
    assert text_domain_mismatch(link) == "www.paypal.com"


# ---------- engine behaviour ----------
def test_benign_message_has_no_indicators():
    parsed = parse_fields(
        "Alex <alex@example.com>",
        "Lunch on Friday",
        "Hi team, are we still on for lunch Friday? See the agenda: " "https://example.com/agenda",
        None,
    )
    r = analyze(parsed, NO_ML)
    assert r.indicators == [] and r.risk_score == 0 and r.classification == "low_risk"
    assert "No phishing indicators" in r.reasons[0]


def test_single_keyword_never_classifies_as_phishing():
    r = analyze(parse_fields(None, "Quick note", "This is urgent, call me.", None), NO_ML)
    assert codes(r) == {"TEXT_URGENCY"}
    assert r.classification == "low_risk"


def test_multiple_signals_classify_as_phishing_with_explanations():
    raw = (
        "From: PayPal Support <support@secure-mail.example.xyz>\r\n"
        "Reply-To: help@other-domain.example.net\r\n"
        "Subject: URGENT: verify your account within 24 hours\r\n"
        "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=example.xyz; dkim=none\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        "<p>Your account will be suspended. Verify your password now:</p>"
        '<a href="http://203.0.113.9/login">www.paypal.com/signin</a>'
    )
    r = analyze(parse_raw(raw), NO_ML)
    assert r.classification == "likely_phishing" and r.risk_score >= scoring.PHISHING_THRESHOLD
    expected = {
        "AUTH_SPF_FAIL",
        "SENDER_DISPLAY_NAME_BRAND_MISMATCH",
        "SENDER_REPLYTO_MISMATCH",
        "URL_IP_HOST",
        "URL_LINK_TEXT_MISMATCH",
        "TEXT_URGENCY",
        "TEXT_CREDENTIAL_REQUEST",
        "COMBO_CREDENTIAL_REQUEST_WITH_LINK",
    }
    assert expected <= codes(r)
    assert len(r.reasons) == len(r.indicators)
    assert all(e.startswith(("hxxp", "text '")) or e for i in r.indicators for e in i.evidence)
    ip_evidence = next(i for i in r.indicators if i.code == "URL_IP_HOST").evidence[0]
    assert ip_evidence.startswith("hxxp") and "http" not in ip_evidence.split("hxxp", 1)[1]


def test_attachments_are_inspected_by_name_only():
    msg = EmailMessage()
    msg["From"] = "Billing <billing@example.com>"
    msg["Subject"] = "Invoice"
    msg.set_content("Please see attached.")
    msg.add_attachment(
        b"MZ\x90\x00", maintype="application", subtype="octet-stream", filename="invoice.pdf.exe"
    )
    msg.add_attachment(b"PK", maintype="application", subtype="zip", filename="files.zip")
    parsed = parse_raw(msg.as_string())
    assert [(a.filename, a.size) for a in parsed.attachments] == [
        ("invoice.pdf.exe", 4),
        ("files.zip", 2),
    ]
    r = analyze(parsed, NO_ML)
    assert {"ATTACH_EXECUTABLE", "ATTACH_DOUBLE_EXTENSION", "ATTACH_ARCHIVE"} <= codes(r)
    assert r.attachment_count == 2 and r.classification == "likely_phishing"


def test_password_form_in_html_is_flagged():
    html = '<form action="http://x.example.net"><input type="password" name="p"></form>'
    r = analyze(parse_fields(None, "Sign in", None, html), NO_ML)
    assert "HTML_PASSWORD_FORM" in codes(r)


def test_malformed_input_does_not_crash():
    for raw in [
        "",
        "\x00\x01 garbage",
        "From: <<<>>>\nSubject:\n\n",
        "no headers at all, just text",
    ]:
        analyze(parse_raw(raw or " "), NO_ML)


# ---------- ML integration ----------
class StubClassifier(MlClassifier):
    def __init__(self, probability):
        super().__init__(None)
        self._p = probability

    @property
    def available(self):
        return True

    def predict(self, text):
        return MlResult(self._p, "stub", ["login", "verify"])


def test_ml_alone_cannot_classify_as_phishing():
    r = analyze(
        parse_fields(None, "Hello", "Nothing suspicious in here.", None), StubClassifier(1.0)
    )
    assert r.ml is not None and r.risk_score == 30  # 30% weight only
    assert r.classification == "suspicious"
    assert any("machine-learning classifier" in reason for reason in r.reasons)


def test_ml_unavailable_is_reported_and_score_is_rules_only():
    r = analyze(parse_fields(None, "x", "This is urgent", None), NO_ML)
    assert r.ml is None and r.ml_available is False and r.risk_score == r.rule_score


def test_training_pipeline_and_model_loading(tmp_path):
    """Exercises the code path with a tiny throwaway dataset; says nothing about real accuracy."""
    import pandas as pd

    from ml.training.train import train

    rows = (
        [("verify your account password now click link", 1)] * 12
        + [("urgent login suspended confirm credentials", 1)] * 12
        + [("meeting agenda attached see you tomorrow", 0)] * 12
        + [("lunch menu for friday team", 0)] * 12
    )
    csv = tmp_path / "toy.csv"
    pd.DataFrame(rows, columns=["body", "label"]).to_csv(csv, index=False)
    model, metrics_path = tmp_path / "m.joblib", tmp_path / "metrics.json"

    metrics = train(csv, "body", "label", model, metrics_path, min_df=1)
    assert {"accuracy", "precision", "recall", "f1", "confusion_matrix"} <= metrics.keys()
    assert metrics["rows_test"] == 10 and len(metrics["confusion_matrix"]) == 2
    assert metrics_path.exists()

    clf = MlClassifier(str(model))
    assert clf.available
    hit = clf.predict("please verify your password and confirm credentials")
    miss = clf.predict("agenda for the lunch meeting")
    assert 0 <= miss.probability < hit.probability <= 1
    assert hit.top_terms and all(isinstance(t, str) for t in hit.top_terms)


def test_missing_model_file_degrades_gracefully(tmp_path):
    assert MlClassifier(str(tmp_path / "nope.joblib")).available is False


@pytest.mark.parametrize(
    "score,count,expected",
    [
        (10, 0, "low_risk"),
        (30, 1, "suspicious"),
        (80, 1, "suspicious"),
        (80, 2, "likely_phishing"),
    ],
)
def test_classification_thresholds(score, count, expected):
    assert scoring.classify(score, count) == expected
