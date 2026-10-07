from datetime import UTC, datetime

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models import ACTIVE_STATUSES, EventStatus, SecurityEvent, Severity
from app.schemas.security import (
    DashboardSummary,
    DistributionItem,
    RegionItem,
    TimelinePoint,
)
from app.services.events import EventFilters, apply_filters

E = SecurityEvent
_SEVERITY_ORDER = {s.value: i for i, s in enumerate(Severity)}


def summary(db: Session, f: EventFilters) -> DashboardSummary:
    stmt = select(
        func.count(E.id),
        func.count(case((E.status.in_(ACTIVE_STATUSES), 1))),
        func.count(case((E.status == EventStatus.BLOCKED.value, 1))),
        func.count(case((E.severity == Severity.CRITICAL.value, 1))),
        func.count(E.region.distinct()),
    )
    total, active, blocked, critical, regions = db.execute(apply_filters(stmt, f)).one()
    return DashboardSummary(
        total_events=total,
        active_threats=active,
        blocked_threats=blocked,
        critical_events=critical,
        affected_regions=regions,
    )


def _grouped(db: Session, f: EventFilters, column) -> list[tuple[str, int]]:
    stmt = select(column, func.count(E.id)).where(column.is_not(None)).group_by(column)
    return [(k, c) for k, c in db.execute(apply_filters(stmt, f)).all()]


def by_severity(db: Session, f: EventFilters) -> list[DistributionItem]:
    rows = sorted(_grouped(db, f, E.severity), key=lambda r: _SEVERITY_ORDER[r[0]])
    return [DistributionItem(key=k, count=c) for k, c in rows]


def by_threat_type(db: Session, f: EventFilters) -> list[DistributionItem]:
    rows = sorted(_grouped(db, f, E.threat_type), key=lambda r: (-r[1], r[0]))
    return [DistributionItem(key=k, count=c) for k, c in rows]


def by_region(db: Session, f: EventFilters, limit: int = 50) -> list[RegionItem]:
    rows = sorted(_grouped(db, f, E.region), key=lambda r: (-r[1], r[0]))[:limit]
    return [RegionItem(region=k, count=c) for k, c in rows]


def _bucket_expr(db: Session, unit: str):
    if db.get_bind().dialect.name == "postgresql":
        return func.date_trunc(unit, func.timezone("UTC", E.occurred_at))
    fmt = "%Y-%m-%dT%H:00:00" if unit == "hour" else "%Y-%m-%dT00:00:00"
    return func.strftime(fmt, E.occurred_at)


def timeline(db: Session, f: EventFilters, unit: str) -> list[TimelinePoint]:
    bucket = _bucket_expr(db, unit)
    stmt = select(bucket.label("b"), func.count(E.id)).group_by("b").order_by("b")
    points = []
    for b, count in db.execute(apply_filters(stmt, f)).all():
        dt = datetime.fromisoformat(b) if isinstance(b, str) else b
        points.append(TimelinePoint(bucket=dt.replace(tzinfo=UTC), count=count))
    return points  # sparse: only buckets that contain real events
