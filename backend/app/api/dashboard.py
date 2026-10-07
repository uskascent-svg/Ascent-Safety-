from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import User
from app.schemas.security import (
    DashboardSummary,
    DistributionItem,
    RegionItem,
    TimelinePoint,
)
from app.security.deps import analyst_or_admin
from app.services import dashboard
from app.services.events import EventFilters, event_filters

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def get_summary(
    f: EventFilters = Depends(event_filters),
    db: Session = Depends(get_db),
    _: User = Depends(analyst_or_admin),
):
    return dashboard.summary(db, f)


@router.get("/timeline", response_model=list[TimelinePoint])
def get_timeline(
    bucket: Literal["hour", "day"] = Query(default="hour"),
    f: EventFilters = Depends(event_filters),
    db: Session = Depends(get_db),
    _: User = Depends(analyst_or_admin),
):
    if f.since is None:  # default window: 24h of hourly buckets, or 30 days of daily buckets
        f.since = datetime.now(UTC) - (
            timedelta(hours=24) if bucket == "hour" else timedelta(days=30)
        )
    return dashboard.timeline(db, f, bucket)


@router.get("/severity", response_model=list[DistributionItem])
def get_severity(
    f: EventFilters = Depends(event_filters),
    db: Session = Depends(get_db),
    _: User = Depends(analyst_or_admin),
):
    return dashboard.by_severity(db, f)


@router.get("/threat-types", response_model=list[DistributionItem])
def get_threat_types(
    f: EventFilters = Depends(event_filters),
    db: Session = Depends(get_db),
    _: User = Depends(analyst_or_admin),
):
    return dashboard.by_threat_type(db, f)


@router.get("/regions", response_model=list[RegionItem])
def get_regions(
    f: EventFilters = Depends(event_filters),
    db: Session = Depends(get_db),
    _: User = Depends(analyst_or_admin),
):
    return dashboard.by_region(db, f)
