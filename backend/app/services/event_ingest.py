"""The one place security events are stored, so every source gets the same side effects:
validation (by the schema), persistence, audit logging, alert creation and live-stream publish."""

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import ACTIVE_STATUSES, Alert, Role, SecurityEvent, User, UserNotification
from app.schemas.security import SecurityEventCreate, SecurityEventOut
from app.services import audit
from app.services.broker import broker

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class DuplicateEvent(Exception):
    pass


def store_event(
    db: Session,
    payload: SecurityEventCreate,
    request: Request | None = None,
    audit_details: dict | None = None,
) -> SecurityEvent:
    """Add the event (and an alert if warranted) to the session and flush. The caller commits,
    then calls `publish`. Raises DuplicateEvent for a repeated (source, external_id)."""
    if payload.external_id and db.scalar(
        select(SecurityEvent.id).where(
            SecurityEvent.source == payload.source,
            SecurityEvent.external_id == payload.external_id,
        )
    ):
        raise DuplicateEvent
    data = payload.model_dump()
    data["source_ip"] = str(payload.source_ip) if payload.source_ip else None
    event = SecurityEvent(**{k: (v.value if hasattr(v, "value") else v) for k, v in data.items()})
    db.add(event)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise DuplicateEvent from None
    audit.record(
        db,
        "security_event.ingest",
        request,
        details={"event_id": str(event.id), "source": event.source, **(audit_details or {})},
    )
    _maybe_alert(db, event, request)
    return event


def _maybe_alert(db: Session, event: SecurityEvent, request: Request | None) -> None:
    threshold = SEVERITY_RANK.get(get_settings().alert_min_severity, SEVERITY_RANK["high"])
    if event.status not in ACTIVE_STATUSES or SEVERITY_RANK[event.severity] < threshold:
        return
    alert = Alert(event_id=event.id, severity=event.severity, title=event.title)
    db.add(alert)
    db.flush()
    if event.source != "cyber_alert_declaration":
        recipients = db.scalars(
            select(User)
            .join(User.roles)
            .where(
                Role.name.in_(["SECURITY_ANALYST", "ADMINISTRATOR"]),
                User.is_active.is_(True),
                User.deleted_at.is_(None),
            )
        ).unique()
        db.add_all(
            [
                UserNotification(user_id=recipient.id, event_id=event.id, title=event.title)
                for recipient in recipients
            ]
        )
    audit.record(
        db,
        "alert.create",
        request,
        details={"alert_id": str(alert.id), "event_id": str(event.id), "severity": event.severity},
    )


def publish(event: SecurityEvent) -> None:
    """Notify live-stream subscribers. Call only after the transaction has been committed."""
    broker.publish(SecurityEventOut.model_validate(event).model_dump(mode="json"))
