import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import User, UserNotification
from app.schemas.notifications import NotificationOut, NotificationPage
from app.security.deps import analyst_or_admin
from app.services import audit

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("", response_model=NotificationPage)
def list_notifications(
    limit: int = 20,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    limit = max(1, min(limit, 50))
    total = (
        db.scalar(
            select(func.count(UserNotification.id)).where(UserNotification.user_id == user.id)
        )
        or 0
    )
    unread = (
        db.scalar(
            select(func.count(UserNotification.id)).where(
                UserNotification.user_id == user.id, UserNotification.read_at.is_(None)
            )
        )
        or 0
    )
    items = db.scalars(
        select(UserNotification)
        .where(UserNotification.user_id == user.id)
        .order_by(UserNotification.created_at.desc(), UserNotification.id)
        .limit(limit)
    ).all()
    return NotificationPage(items=items, total=total, unread=unread)


@router.post("/{notification_id}/read", response_model=NotificationOut)
def mark_notification_read(
    request: Request,
    notification_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    item = db.scalar(
        select(UserNotification).where(
            UserNotification.id == notification_id, UserNotification.user_id == user.id
        )
    )
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Notification not found")
    if item.read_at is None:
        item.read_at = datetime.now(UTC)
        audit.record(db, "notification.read", request, user.id, {"notification_id": str(item.id)})
        db.commit()
        db.refresh(item)
    return item


@router.post("/read-all", status_code=status.HTTP_204_NO_CONTENT)
def mark_all_notifications_read(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    now = datetime.now(UTC)
    changed = (
        db.execute(
            update(UserNotification)
            .where(UserNotification.user_id == user.id, UserNotification.read_at.is_(None))
            .values(read_at=now)
        ).rowcount
        or 0
    )
    if changed:
        audit.record(db, "notification.read_all", request, user.id, {"count": changed})
    db.commit()
