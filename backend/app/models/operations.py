import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class ReportActivity(Base):
    """Append-only report lifecycle entry; public entries are safe for the reporter to see."""

    __tablename__ = "security_report_activities"
    __table_args__ = (Index("ix_report_activity_report_created", "report_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("security_reports.id", ondelete="CASCADE"), index=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(40))
    summary: Mapped[str] = mapped_column(String(240))
    is_public: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    actor = relationship("User", lazy="joined")


class UserNotification(Base):
    """User-scoped durable alert notification with an individual read state."""

    __tablename__ = "user_notifications"
    __table_args__ = (
        UniqueConstraint("user_id", "event_id", name="uq_user_notifications_user_event"),
        Index("ix_user_notifications_user_read_created", "user_id", "read_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("security_events.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(200))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


def record_report_activity(
    db,
    report_id: uuid.UUID,
    action: str,
    summary: str,
    actor_id: uuid.UUID | None,
    is_public: bool = False,
) -> ReportActivity:
    activity = ReportActivity(
        report_id=report_id,
        actor_id=actor_id,
        action=action,
        summary=summary,
        is_public=is_public,
    )
    db.add(activity)
    return activity
