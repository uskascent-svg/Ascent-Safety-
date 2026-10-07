import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Alert, EventStatus, Severity, User
from app.schemas.alerts import AlertOut, AlertPage, AlertUpdate
from app.security.deps import analyst_or_admin
from app.services import audit

router = APIRouter(prefix="/api/alerts", tags=["alerts"])
_STATUSES = ("open", "acknowledged", "resolved")


@router.get("", response_model=AlertPage)
def list_alerts(
    alert_status: list[str] = Query(default=[], alias="status"),
    severity: list[Severity] = Query(default=[]),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(analyst_or_admin),
):
    if any(s not in _STATUSES for s in alert_status):
        raise HTTPException(422, f"status must be one of {', '.join(_STATUSES)}")
    where = []
    if alert_status:
        where.append(Alert.status.in_(alert_status))
    if severity:
        where.append(Alert.severity.in_([s.value for s in severity]))
    total = db.scalar(select(func.count(Alert.id)).where(*where)) or 0
    rows = db.scalars(
        select(Alert)
        .where(*where)
        .order_by(Alert.created_at.desc(), Alert.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return AlertPage(
        items=[AlertOut.from_alert(a) for a in rows], total=total, limit=limit, offset=offset
    )


def _get(db: Session, alert_id: uuid.UUID) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alert


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: uuid.UUID, db: Session = Depends(get_db), _: User = Depends(analyst_or_admin)
):
    return AlertOut.from_alert(_get(db, alert_id))


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(
    request: Request,
    alert_id: uuid.UUID,
    payload: AlertUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    alert = _get(db, alert_id)
    if alert.status == "resolved":
        raise HTTPException(status.HTTP_409_CONFLICT, "Alert is already resolved")
    if alert.status == payload.status:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Alert is already {payload.status}")

    now = datetime.now(UTC)
    alert.status = payload.status
    if payload.status == "acknowledged":
        alert.acknowledged_by, alert.acknowledged_at = user.id, now
        if alert.event.status == EventStatus.OPEN.value:
            alert.event.status = EventStatus.INVESTIGATING.value
    else:
        alert.resolved_by, alert.resolved_at, alert.resolution_note = user.id, now, payload.note
        alert.event.status = EventStatus.RESOLVED.value
    audit.record(
        db,
        f"alert.{'acknowledge' if payload.status == 'acknowledged' else 'resolve'}",
        request,
        user.id,
        {"alert_id": str(alert.id), "event_id": str(alert.event_id)},
    )
    db.commit()
    return AlertOut.from_alert(alert)
