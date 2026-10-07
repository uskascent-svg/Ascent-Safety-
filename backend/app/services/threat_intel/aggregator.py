import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import ThreatIntelCache
from app.services.threat_intel.base import IntelResult, Provider, failure
from app.services.threat_intel.providers import ALL_PROVIDERS

log = logging.getLogger("ascent.intel")
_ORDER = ["malicious", "suspicious", "clean", "unknown"]


@dataclass
class LookupResult:
    indicator: str
    indicator_type: str
    verdict: str
    results: list[IntelResult]


def make_client() -> httpx.Client:
    s = get_settings()
    return httpx.Client(
        timeout=s.intel_timeout_seconds,
        follow_redirects=False,
        headers={"User-Agent": "AscentSafety/0.5"},
    )


def configured_providers() -> list[Provider]:
    return [p for p in ALL_PROVIDERS if p.enabled()]


def provider_status() -> list[dict]:
    """Which providers are configured. Never includes key material."""
    return [
        {"name": p.name, "configured": p.enabled(), "types": list(p.types)} for p in ALL_PROVIDERS
    ]


def overall_verdict(results: list[IntelResult]) -> str:
    verdicts = {r.verdict for r in results if r.status in {"ok", "not_found"}}
    return next((v for v in _ORDER if v in verdicts), "unknown")


def _key(indicator: str) -> str:
    return hashlib.sha256(indicator.encode()).hexdigest()


def _safe_lookup(
    provider: Provider, client: httpx.Client, indicator: str, itype: str
) -> IntelResult:
    try:
        return provider.lookup(client, indicator, itype)
    except httpx.HTTPError:
        return failure(provider.name, indicator, itype, "error", "Provider unreachable")
    except Exception:  # malformed provider response etc. must not break the caller
        log.exception("Unexpected failure from provider %s", provider.name)
        return failure(provider.name, indicator, itype, "error", "Unexpected provider error")


def _to_cache(r: IntelResult) -> dict:
    return {"status": r.status, "verdict": r.verdict, "detail": r.detail}


def lookup_many(db: Session, items: list[tuple[str, str]]) -> list[LookupResult]:
    """Look up already-validated (indicator, type) pairs across every configured provider.

    Cache reads/writes happen on the calling thread (a Session is not thread-safe); only the HTTP
    calls for cache misses run concurrently.
    """
    s = get_settings()
    now = datetime.now(UTC)
    providers = configured_providers()
    per_item: dict[tuple[str, str], list[IntelResult]] = {item: [] for item in items}
    misses: list[tuple[Provider, str, str]] = []

    for indicator, itype in items:
        for p in providers:
            if itype not in p.types:
                continue
            row = db.scalar(
                select(ThreatIntelCache).where(
                    ThreatIntelCache.provider == p.name,
                    ThreatIntelCache.indicator_type == itype,
                    ThreatIntelCache.indicator_hash == _key(indicator),
                    ThreatIntelCache.expires_at > now,
                )
            )
            if row:
                per_item[(indicator, itype)].append(
                    IntelResult(
                        p.name,
                        indicator,
                        itype,
                        row.result["status"],
                        row.result["verdict"],
                        row.result.get("detail", {}),
                        cached=True,
                        checked_at=row.fetched_at,
                    )
                )
            else:
                misses.append((p, indicator, itype))

    if misses:
        with make_client() as client, ThreadPoolExecutor(max_workers=min(8, len(misses))) as pool:
            futures = [(pool.submit(_safe_lookup, p, client, i, t), p, i, t) for p, i, t in misses]
            fetched = [(f.result(), p, i, t) for f, p, i, t in futures]
        for result, p, indicator, itype in fetched:
            result.checked_at = now
            ttl = (
                s.intel_cache_ttl_seconds
                if result.status in {"ok", "not_found"}
                else s.intel_negative_ttl_seconds
            )
            db.query(ThreatIntelCache).filter_by(
                provider=p.name, indicator_type=itype, indicator_hash=_key(indicator)
            ).delete()
            db.add(
                ThreatIntelCache(
                    provider=p.name,
                    indicator_type=itype,
                    indicator_hash=_key(indicator),
                    indicator=indicator,
                    result=_to_cache(result),
                    fetched_at=now,
                    expires_at=now + timedelta(seconds=ttl),
                )
            )
            per_item[(indicator, itype)].append(result)
        db.flush()

    return [
        LookupResult(i, t, overall_verdict(per_item[(i, t)]), per_item[(i, t)]) for i, t in items
    ]
