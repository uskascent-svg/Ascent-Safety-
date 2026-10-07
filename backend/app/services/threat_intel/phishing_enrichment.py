"""Turn threat-intel verdicts for an email's links into phishing-engine indicators."""

import logging
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.detection.phishing.rules import Indicator
from app.detection.phishing.urls import Link, defang, is_ip_host
from app.services.threat_intel import aggregator
from app.services.threat_intel.indicators import IndicatorError, normalize

log = logging.getLogger("ascent.intel")
MAX_URLS = 3
MAX_HOSTS = 3  # bounds third-party calls (and provider quota use) per analysis


@dataclass
class IntelSummary:
    providers: list[str] = field(default_factory=list)
    indicators_checked: int = 0
    unavailable: int = 0  # provider answers that were errors or rate limits
    note: str | None = None


def _select_items(links: list[Link]) -> list[tuple[str, str]]:
    """Pick a bounded set of public URLs, then public hosts (domains or IPs) to look up."""
    items: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def collect(candidates: list[tuple[str, str]], cap: int) -> None:
        taken = 0
        for value, itype in candidates:
            if taken >= cap:
                return
            try:
                norm = normalize(value, itype)
            except IndicatorError:  # private/internal/malformed: never sent out
                continue
            if (norm, itype) not in seen:
                seen.add((norm, itype))
                items.append((norm, itype))
                taken += 1

    collect([(link.url, "url") for link in links], MAX_URLS)
    collect([(link.host, "ip" if is_ip_host(link.host) else "domain") for link in links], MAX_HOSTS)
    return items


def link_indicators(db: Session, links: list[Link]) -> tuple[list[Indicator], IntelSummary]:
    summary = IntelSummary()
    providers = aggregator.configured_providers()
    if not providers:
        summary.note = (
            "No threat-intelligence providers are configured, so link reputation was not checked."
        )
        return [], summary
    items = _select_items(links)
    if not items:
        summary.note = "No public links were available to check."
        return [], summary

    lookups = aggregator.lookup_many(db, items)
    summary.providers = sorted({r.provider for lk in lookups for r in lk.results})
    summary.indicators_checked = len(items)
    summary.unavailable = sum(
        1 for lk in lookups for r in lk.results if r.status in {"error", "rate_limited"}
    )

    evidence: dict[str, list[str]] = {"malicious": [], "suspicious": []}
    for lk in lookups:
        for r in lk.results:
            if r.status == "ok" and r.verdict in evidence:
                evidence[r.verdict].append(f"{r.provider}: {r.verdict} — {defang(lk.indicator)}")

    out: list[Indicator] = []
    if evidence["malicious"]:
        out.append(
            Indicator(
                "TI_MALICIOUS_INDICATOR",
                "threat_intelligence",
                "high",
                0.60,
                "A link or domain in this message is flagged as malicious by threat-intelligence services.",
                [e[:160] for e in evidence["malicious"][:3]],
            )
        )
    if evidence["suspicious"]:
        out.append(
            Indicator(
                "TI_SUSPICIOUS_INDICATOR",
                "threat_intelligence",
                "medium",
                0.25,
                "A link or domain in this message is flagged as suspicious by threat-intelligence services.",
                [e[:160] for e in evidence["suspicious"][:3]],
            )
        )
    if summary.unavailable:
        summary.note = "Some threat-intelligence providers were unavailable or rate-limited."
    return out, summary
