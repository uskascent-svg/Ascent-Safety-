"""Rule-based detection. Each rule emits an Indicator with a weight and the evidence that triggered it."""

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

from app.detection.phishing.brands import (
    ARCHIVE_EXTENSIONS,
    BRAND_DOMAINS,
    DANGEROUS_EXTENSIONS,
    MACRO_EXTENSIONS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)
from app.detection.phishing.parser import ParsedEmail
from app.detection.phishing.urls import (
    Link,
    brand_lookalike,
    defang,
    is_ip_host,
    registered_domain,
    text_domain_mismatch,
)


@dataclass
class Indicator:
    code: str
    category: (
        str  # authentication | sender | url | text | content | attachment | threat_intelligence
    )
    severity: str  # low | medium | high
    weight: float  # 0..1, combined probabilistically in scoring
    description: str
    evidence: list[str] = field(default_factory=list)


def _ev(items: list[str], n: int = 3) -> list[str]:
    return [s[:120] for s in items[:n]]


def _link_rules(links: list[Link]) -> list[Indicator]:
    out: list[Indicator] = []

    def add(code, sev, weight, desc, hits: list[str]):
        if hits:
            out.append(Indicator(code, "url", sev, weight, desc, _ev(hits)))

    add(
        "URL_IP_HOST",
        "high",
        0.35,
        "A link points to a raw IP address instead of a domain name.",
        [defang(link.url) for link in links if is_ip_host(link.host)],
    )
    add(
        "URL_USERINFO",
        "high",
        0.35,
        "A link contains embedded credentials ('@'), a trick used to disguise the real destination.",
        [defang(link.url) for link in links if link.has_userinfo],
    )
    add(
        "URL_BRAND_LOOKALIKE",
        "high",
        0.40,
        "A link's domain contains a well-known brand name but is not that brand's domain.",
        [f"{brand}: {defang(link.host)}" for link in links if (brand := brand_lookalike(link))],
    )
    add(
        "URL_LINK_TEXT_MISMATCH",
        "high",
        0.35,
        "The visible link text shows a different domain than the link's real destination.",
        [
            f"text '{shown}' -> {defang(link.host)}"
            for link in links
            if (shown := text_domain_mismatch(link))
        ],
    )
    add(
        "URL_PUNYCODE",
        "medium",
        0.25,
        "A link uses an internationalised (punycode) domain, which can imitate familiar names.",
        [defang(link.host) for link in links if "xn--" in link.host],
    )
    add(
        "URL_SUSPICIOUS_TLD",
        "low",
        0.15,
        "A link uses a top-level domain frequently abused for throwaway sites.",
        [defang(link.host) for link in links if link.host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS],
    )
    add(
        "URL_EXCESS_SUBDOMAINS",
        "low",
        0.15,
        "A link has an unusually deep subdomain chain.",
        [
            defang(link.host)
            for link in links
            if len(link.host.split(".")) - len(link.domain.split(".")) >= 3
        ],
    )
    add(
        "URL_SHORTENER",
        "low",
        0.10,
        "A link uses a URL-shortening service that hides its destination.",
        [defang(link.host) for link in links if link.domain in URL_SHORTENERS],
    )
    add(
        "URL_NON_HTTPS",
        "low",
        0.08,
        "A link uses unencrypted HTTP.",
        [defang(link.url) for link in links if link.scheme == "http"],
    )
    return out


def _text_rules(phrases: dict[str, list[str]], has_links: bool) -> list[Indicator]:
    out: list[Indicator] = []
    urgency = phrases.get("urgency", [])
    if urgency:
        out.append(
            Indicator(
                "TEXT_URGENCY",
                "text",
                "medium" if len(urgency) > 1 else "low",
                0.20 if len(urgency) > 1 else 0.08,
                "The message uses urgent or pressuring language.",
                _ev(urgency),
            )
        )
    if cred := phrases.get("credential_request"):
        out.append(
            Indicator(
                "TEXT_CREDENTIAL_REQUEST",
                "text",
                "medium",
                0.25,
                "The message asks the reader to verify or enter account credentials.",
                _ev(cred),
            )
        )
        if has_links:
            out.append(
                Indicator(
                    "COMBO_CREDENTIAL_REQUEST_WITH_LINK",
                    "content",
                    "high",
                    0.25,
                    "A credential request is combined with a clickable link.",
                    _ev(cred, 1),
                )
            )
    if fin := phrases.get("financial"):
        out.append(
            Indicator(
                "TEXT_FINANCIAL",
                "text",
                "low",
                0.12,
                "The message references payments, transfers or gift cards.",
                _ev(fin),
            )
        )
    if threat := phrases.get("threat"):
        out.append(
            Indicator(
                "TEXT_THREAT",
                "text",
                "medium",
                0.15,
                "The message claims suspicious activity or threatens consequences.",
                _ev(threat),
            )
        )
    return out


def _sender_rules(parsed: ParsedEmail) -> list[Indicator]:
    out: list[Indicator] = []
    for mech, weight in (("spf", 0.30), ("dkim", 0.30), ("dmarc", 0.35)):
        result = parsed.auth.get(mech)
        if result in {"fail", "softfail"}:
            w = weight / 2 if result == "softfail" else weight
            out.append(
                Indicator(
                    f"AUTH_{mech.upper()}_{result.upper()}",
                    "authentication",
                    "high" if w >= 0.3 else "medium",
                    w,
                    f"{mech.upper()} reported '{result}' in the message's Authentication-Results header.",
                    [f"{mech}={result}"],
                )
            )

    sender_dom = parsed.sender_domain
    if sender_dom and parsed.reply_to_domain:
        if registered_domain(parsed.reply_to_domain) != registered_domain(sender_dom):
            out.append(
                Indicator(
                    "SENDER_REPLYTO_MISMATCH",
                    "sender",
                    "medium",
                    0.20,
                    "Replies would go to a different domain than the sender's.",
                    [f"from {sender_dom}, reply-to {parsed.reply_to_domain}"],
                )
            )

    if parsed.display_name and sender_dom:
        tokens = set(re.split(r"[^a-z0-9]+", parsed.display_name.lower()))
        for brand, legit in BRAND_DOMAINS.items():
            if brand in tokens and registered_domain(sender_dom) not in legit:
                out.append(
                    Indicator(
                        "SENDER_DISPLAY_NAME_BRAND_MISMATCH",
                        "sender",
                        "high",
                        0.30,
                        "The sender's display name uses a known brand but the address is from another domain.",
                        [f"'{parsed.display_name[:60]}' <{parsed.sender_address}>"],
                    )
                )
                break
    return out


def _html_rules(html: str | None) -> list[Indicator]:
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        if form.find("input", attrs={"type": re.compile("^password$", re.I)}):
            return [
                Indicator(
                    "HTML_PASSWORD_FORM",
                    "content",
                    "high",
                    0.45,
                    "The email body embeds a form that collects a password.",
                    ["<form> with password input"],
                )
            ]
    return []


def _attachment_rules(parsed: ParsedEmail) -> list[Indicator]:
    dangerous, macro, archive, double = [], [], [], []
    for att in parsed.attachments:
        name = (att.filename or "").lower()
        parts = name.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if ext in DANGEROUS_EXTENSIONS:
            dangerous.append(name)
            if len(parts) > 2:
                double.append(name)
        elif ext in MACRO_EXTENSIONS:
            macro.append(name)
        elif ext in ARCHIVE_EXTENSIONS:
            archive.append(name)
    out: list[Indicator] = []
    if dangerous:
        out.append(
            Indicator(
                "ATTACH_EXECUTABLE",
                "attachment",
                "high",
                0.45,
                "An attachment has an executable or script file type.",
                _ev(dangerous),
            )
        )
    if double:
        out.append(
            Indicator(
                "ATTACH_DOUBLE_EXTENSION",
                "attachment",
                "high",
                0.30,
                "An attachment uses a double extension to disguise its type.",
                _ev(double),
            )
        )
    if macro:
        out.append(
            Indicator(
                "ATTACH_MACRO_DOCUMENT",
                "attachment",
                "medium",
                0.25,
                "An attachment is a macro-enabled Office document.",
                _ev(macro),
            )
        )
    if archive:
        out.append(
            Indicator(
                "ATTACH_ARCHIVE",
                "attachment",
                "low",
                0.10,
                "An attachment is a compressed archive that can hide its contents.",
                _ev(archive),
            )
        )
    return out


def run_rules(
    parsed: ParsedEmail, links: list[Link], phrases: dict[str, list[str]]
) -> list[Indicator]:
    indicators = (
        _sender_rules(parsed)
        + _link_rules(links)
        + _text_rules(phrases, has_links=bool(links))
        + _html_rules(parsed.html)
        + _attachment_rules(parsed)
    )
    return sorted(indicators, key=lambda i: -i.weight)
