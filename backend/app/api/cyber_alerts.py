import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.limiter import limiter
from app.database.session import get_db
from app.models import (
    CyberAlertActivity,
    CyberAlertDeclaration,
    EventStatus,
    RoleName,
    SecurityEvent,
    Severity,
    ThreatType,
    User,
    UserNotification,
)
from app.schemas.cyber_alerts import (
    CyberAlertActivityOut,
    CyberAlertCreate,
    CyberAlertDetail,
    CyberAlertOut,
    CyberAlertPage,
)
from app.schemas.security import SecurityEventCreate
from app.security.deps import analyst_or_admin, get_current_user, require_roles
from app.services import audit
from app.services.event_ingest import publish, store_event
from app.services.geocoding import GeocodingUnavailable, resolve_place_name

router = APIRouter(prefix="/api/cyber-alerts", tags=["cyber alerts"])
admin_only = require_roles(RoleName.ADMINISTRATOR)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _activity(db: Session, alert: CyberAlertDeclaration, actor: User, action: str, changes: dict):
    db.add(
        CyberAlertActivity(
            declaration_id=alert.id, actor_id=actor.id, action=action, changes=changes
        )
    )


def _get(db: Session, alert_id: uuid.UUID) -> CyberAlertDeclaration:
    alert = db.get(CyberAlertDeclaration, alert_id)
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cyber alert not found")
    return alert


def _detail(db: Session, alert: CyberAlertDeclaration) -> CyberAlertDetail:
    history = db.scalars(
        select(CyberAlertActivity)
        .where(CyberAlertActivity.declaration_id == alert.id)
        .order_by(CyberAlertActivity.created_at, CyberAlertActivity.id)
    ).all()
    return CyberAlertDetail(
        **CyberAlertOut.model_validate(alert).model_dump(exclude={"history"}),
        history=[CyberAlertActivityOut.model_validate(item) for item in history],
    )


def _expire_due(db: Session, alerts: list[CyberAlertDeclaration]) -> list[SecurityEvent]:
    now = datetime.now(UTC)
    changed_events = []
    for alert in alerts:
        if alert.status in {"active", "approved"} and _utc(alert.expires_at) <= now:
            alert.status = "expired"
            _add_system_activity(db, alert)
            if alert.published_event_id:
                event = db.get(SecurityEvent, alert.published_event_id)
                if event and event.status != EventStatus.RESOLVED.value:
                    event.status = EventStatus.RESOLVED.value
                    event.latitude = event.longitude = None
                    event.region = "Alert expired"
                    changed_events.append(event)
    return changed_events


def _add_system_activity(db: Session, alert: CyberAlertDeclaration) -> None:
    db.add(
        CyberAlertActivity(
            declaration_id=alert.id, actor_id=None, action="expired", changes={"status": "expired"}
        )
    )


@router.get("", response_model=CyberAlertPage)
def list_cyber_alerts(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    now = datetime.now(UTC)
    due = db.scalars(
        select(CyberAlertDeclaration).where(
            CyberAlertDeclaration.status.in_(["active", "approved"]),
            CyberAlertDeclaration.expires_at <= now,
        )
    ).all()
    changed_events = _expire_due(db, due)
    if due:
        db.commit()
        for event in changed_events:
            publish(event)
    stmt = select(CyberAlertDeclaration)
    if RoleName.ADMINISTRATOR.value not in {
        role.name for role in user.roles
    } and RoleName.SECURITY_ANALYST.value not in {role.name for role in user.roles}:
        stmt = stmt.where(
            CyberAlertDeclaration.status == "active", CyberAlertDeclaration.expires_at > now
        )
    rows = db.scalars(stmt.order_by(CyberAlertDeclaration.created_at.desc()).limit(100)).all()
    return CyberAlertPage(items=[_detail(db, row) for row in rows], total=len(rows))


@router.post("", response_model=CyberAlertDetail, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/hour")
def create_cyber_alert(
    request: Request,
    payload: CyberAlertCreate,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    for event_id in payload.related_event_ids:
        if not db.get(SecurityEvent, event_id):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Related event not found")
    data = payload.model_dump()
    data["related_event_ids"] = [str(value) for value in payload.related_event_ids]
    alert = CyberAlertDeclaration(**data, status="draft", created_by_id=user.id)
    db.add(alert)
    db.flush()
    _activity(db, alert, user, "created", {"status": "draft"})
    audit.record(db, "cyber_alert.create", request, user.id, {"alert_id": str(alert.id)})
    db.commit()
    db.refresh(alert)
    return _detail(db, alert)


@router.get("/{alert_id}", response_model=CyberAlertDetail)
def get_cyber_alert(
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    alert = _get(db, alert_id)
    changed_events = _expire_due(db, [alert])
    if alert.status == "expired":
        db.commit()
        for event in changed_events:
            publish(event)
        db.refresh(alert)
    return _detail(db, alert)


@router.put("/{alert_id}", response_model=CyberAlertDetail)
def update_cyber_alert(
    request: Request,
    alert_id: uuid.UUID,
    payload: CyberAlertCreate,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    alert = _get(db, alert_id)
    is_admin = RoleName.ADMINISTRATOR.value in {role.name for role in user.roles}
    if alert.status != "draft" or (not is_admin and alert.created_by_id != user.id):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Only the draft creator or an administrator can edit this draft",
        )
    for event_id in payload.related_event_ids:
        if not db.get(SecurityEvent, event_id):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Related event not found")
    data = payload.model_dump()
    data["related_event_ids"] = [str(value) for value in payload.related_event_ids]
    before = {key: getattr(alert, key) for key in data}
    for key, value in data.items():
        setattr(alert, key, value)
    changes = {
        key: {
            "from": before[key].isoformat() if isinstance(before[key], datetime) else before[key],
            "to": value.isoformat() if isinstance(value, datetime) else value,
        }
        for key, value in data.items()
        if before[key] != value
    }
    _activity(db, alert, user, "updated", changes)
    audit.record(
        db,
        "cyber_alert.update",
        request,
        user.id,
        {"alert_id": str(alert.id), "fields": sorted(changes)},
    )
    db.commit()
    db.refresh(alert)
    return _detail(db, alert)


@router.post("/{alert_id}/approve", response_model=CyberAlertDetail)
def approve_cyber_alert(
    request: Request,
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(admin_only),
):
    alert = _get(db, alert_id)
    if alert.status != "draft":
        raise HTTPException(status.HTTP_409_CONFLICT, "Only a draft alert can be approved")
    alert.status = "approved"
    alert.approved_by_id = user.id
    alert.approved_at = datetime.now(UTC)
    _activity(db, alert, user, "approved", {"status": "approved"})
    audit.record(db, "cyber_alert.approve", request, user.id, {"alert_id": str(alert.id)})
    db.commit()
    db.refresh(alert)
    return _detail(db, alert)


@router.post("/{alert_id}/publish", response_model=CyberAlertDetail)
def publish_cyber_alert(
    request: Request,
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    alert = _get(db, alert_id)
    is_admin = RoleName.ADMINISTRATOR.value in {role.name for role in user.roles}
    if alert.status != "approved":
        raise HTTPException(status.HTTP_409_CONFLICT, "Alert must be approved before publication")
    if alert.severity == Severity.CRITICAL.value and not is_admin:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only an administrator can publish Critical alerts"
        )
    if _utc(alert.expires_at) <= datetime.now(UTC):
        raise HTTPException(status.HTTP_409_CONFLICT, "Alert has expired")

    location = None
    try:
        candidates, _ = resolve_place_name(db, alert.affected_region, commit=False)
        if len(candidates) == 1:
            location = candidates[0]
    except (ValueError, GeocodingUnavailable):
        pass
    alert.latitude = location["latitude"] if location else None
    alert.longitude = location["longitude"] if location else None
    alert.location_status = "resolved" if location else "unavailable"
    threat_type = ThreatType(alert.threat_type)
    severity = Severity(alert.severity)
    event = store_event(
        db,
        SecurityEventCreate(
            source="cyber_alert_declaration",
            external_id=str(alert.id),
            threat_type=threat_type,
            severity=severity,
            status=EventStatus.OPEN,
            title=alert.title,
            description=f"{alert.summary}\n\nRecommended actions: "
            + " ".join(alert.recommended_actions),
            occurred_at=datetime.now(UTC),
            country=location["country"] if location else None,
            region=location["region"] or location["locality"]
            if location
            else alert.affected_region,
            latitude=location["latitude"] if location else None,
            longitude=location["longitude"] if location else None,
        ),
        request,
        {"cyber_alert_id": str(alert.id)},
    )
    alert.status = "active"
    alert.published_by_id = user.id
    alert.published_at = datetime.now(UTC)
    alert.published_event_id = event.id
    _activity(db, alert, user, "published", {"status": "active", "event_id": str(event.id)})
    recipients = db.scalars(
        select(User).where(User.is_active.is_(True), User.deleted_at.is_(None))
    ).all()
    db.add_all(
        [
            UserNotification(user_id=recipient.id, event_id=event.id, title=alert.title)
            for recipient in recipients
        ]
    )
    audit.record(
        db,
        "cyber_alert.publish",
        request,
        user.id,
        {"alert_id": str(alert.id), "event_id": str(event.id)},
    )
    db.commit()
    db.refresh(alert)
    publish(event)
    return _detail(db, alert)


@router.post("/{alert_id}/revoke", response_model=CyberAlertDetail)
def revoke_cyber_alert(
    request: Request,
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(admin_only),
):
    alert = _get(db, alert_id)
    if alert.status not in {"active", "approved"}:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Only active or approved alerts can be revoked"
        )
    alert.status = "revoked"
    alert.revoked_at = datetime.now(UTC)
    if alert.published_event_id:
        event = db.get(SecurityEvent, alert.published_event_id)
        if event:
            event.status = EventStatus.RESOLVED.value
            event.latitude = event.longitude = None
            event.region = "Alert revoked"
            publish_after_commit = event
        else:
            publish_after_commit = None
    else:
        publish_after_commit = None
    _activity(db, alert, user, "revoked", {"status": "revoked"})
    audit.record(db, "cyber_alert.revoke", request, user.id, {"alert_id": str(alert.id)})
    db.commit()
    db.refresh(alert)
    if publish_after_commit:
        publish(publish_after_commit)
    return _detail(db, alert)
