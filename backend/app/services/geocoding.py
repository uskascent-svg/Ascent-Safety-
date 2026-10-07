"""Administrator-triggered, city-level place-name lookup for reviewed reports."""

import hashlib
import re
import threading
import time
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import GeocodeCache

_TTL = timedelta(days=30)
_MIN_REQUEST_INTERVAL = 1.0
_request_lock = threading.Lock()
_resolve_lock = threading.Lock()
_last_request_at = 0.0


class GeocodingUnavailable(Exception):
    """The configured place-name provider did not return a usable response."""


def _normalize_query(value: str) -> str:
    query = " ".join(value.split())
    if not query or len(query) > 120:
        raise ValueError("Enter a city, region, or country name (up to 120 characters).")
    street_detail = re.compile(
        r"\b(street|st\.?|road|rd\.?|avenue|ave\.?|apartment|apt\.?|flat|suite|unit|floor|house|lane|ln\.?)\b",
        re.I,
    )
    has_private_detail = (
        "@" in query
        or "://" in query
        or re.search(r"\b\d{5,}\b", query)
        or street_detail.search(query)
    )
    if has_private_detail:
        raise ValueError(
            "Only a place name is allowed; remove URLs, email addresses, or street details."
        )
    return query


def _cache_key(query: str) -> str:
    return hashlib.sha256(query.casefold().encode("utf-8")).hexdigest()


def _read_cache(db: Session, key: str) -> list[dict] | None:
    row = db.scalar(select(GeocodeCache).where(GeocodeCache.query_hash == key))
    if row is None:
        return None
    expires = row.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if expires <= datetime.now(UTC):
        return None
    return row.results


def _fetch_candidates(query: str) -> list[dict]:
    global _last_request_at
    settings = get_settings()
    # Public Nominatim requires no more than one request per second per application.
    with _request_lock:
        wait_for = _MIN_REQUEST_INTERVAL - (time.monotonic() - _last_request_at)
        if wait_for > 0:
            time.sleep(wait_for)
        try:
            _last_request_at = time.monotonic()
            response = httpx.get(
                f"{settings.geocoding_base_url.rstrip('/')}/search",
                params={
                    "q": query,
                    "format": "jsonv2",
                    "addressdetails": 1,
                    "limit": 5,
                    "featureType": "settlement",
                },
                headers={"User-Agent": settings.geocoding_user_agent},
                timeout=8.0,
            )
            response.raise_for_status()
            places = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise GeocodingUnavailable from exc

    if not isinstance(places, list):
        raise GeocodingUnavailable

    candidates: list[dict] = []
    seen: set[tuple[float, float]] = set()
    for place in places:
        try:
            latitude = round(float(place["lat"]), 2)
            longitude = round(float(place["lon"]), 2)
        except (KeyError, TypeError, ValueError):
            continue
        if not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
            continue
        if (latitude, longitude) in seen:
            continue
        seen.add((latitude, longitude))
        address = place.get("address") or {}
        locality = (
            address.get("city")
            or address.get("town")
            or address.get("village")
            or address.get("municipality")
            or address.get("county")
            or place.get("name")
            or query
        )
        region = address.get("state") or address.get("region") or address.get("state_district")
        country = address.get("country")
        label = ", ".join(part for part in (locality, region, country) if part)
        candidates.append(
            {
                "label": label or query,
                "locality": str(locality)[:64],
                "region": str(region)[:64] if region else None,
                "country": str(country)[:64] if country else None,
                "latitude": latitude,
                "longitude": longitude,
            }
        )
    return candidates


def resolve_place_name(db: Session, value: str, *, commit: bool = True) -> tuple[list[dict], bool]:
    query = _normalize_query(value)
    key = _cache_key(query)
    with _resolve_lock:
        cached = _read_cache(db, key)
        if cached is not None:
            return cached, True

        candidates = _fetch_candidates(query)
        now = datetime.now(UTC)
        row = db.scalar(select(GeocodeCache).where(GeocodeCache.query_hash == key))
        if row is None:
            row = GeocodeCache(query_hash=key, results=candidates, expires_at=now + _TTL)
            db.add(row)
        else:
            row.results = candidates
            row.fetched_at = now
            row.expires_at = now + _TTL
        if commit:
            db.commit()
        else:
            db.flush()
        return candidates, False
