from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Query
from sqlalchemy import Select

from app.models import EventStatus, SecurityEvent, Severity, ThreatType


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


@dataclass
class EventFilters:
    severity: list[Severity]
    threat_type: list[ThreatType]
    status: list[EventStatus]
    region: str | None
    country: str | None
    since: datetime | None
    until: datetime | None
    q: str | None


def event_filters(
    severity: list[Severity] = Query(default=[]),
    threat_type: list[ThreatType] = Query(default=[]),
    status: list[EventStatus] = Query(default=[]),
    region: str | None = Query(default=None, max_length=64),
    country: str | None = Query(default=None, max_length=64),
    since: datetime | None = None,
    until: datetime | None = None,
    q: str | None = Query(default=None, max_length=100),
) -> EventFilters:
    """FastAPI dependency shared by list, map and dashboard endpoints so they always agree."""
    return EventFilters(severity, threat_type, status, region, country, _utc(since), _utc(until), q)


def apply_filters(stmt: Select, f: EventFilters) -> Select:
    E = SecurityEvent
    if f.severity:
        stmt = stmt.where(E.severity.in_([s.value for s in f.severity]))
    if f.threat_type:
        stmt = stmt.where(E.threat_type.in_([t.value for t in f.threat_type]))
    if f.status:
        stmt = stmt.where(E.status.in_([s.value for s in f.status]))
    if f.region:
        stmt = stmt.where(E.region == f.region)
    if f.country:
        stmt = stmt.where(E.country == f.country)
    if f.since:
        stmt = stmt.where(E.occurred_at >= f.since)
    if f.until:
        stmt = stmt.where(E.occurred_at <= f.until)
    if f.q:
        stmt = stmt.where(
            E.title.icontains(f.q, autoescape=True) | E.description.icontains(f.q, autoescape=True)
        )
    return stmt
