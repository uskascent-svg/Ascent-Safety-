import enum
import secrets
import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.security_event import Severity


class ReportType(str, enum.Enum):
    PHISHING_WEBSITE = "phishing_website"
    SUSPICIOUS_URL = "suspicious_url"
    MALICIOUS_EMAIL = "malicious_email"
    SCAM_MESSAGE = "scam_message"
    MALWARE = "malware"
    CREDENTIAL_THEFT = "credential_theft"
    IMPERSONATION = "impersonation"
    SUSPICIOUS_ATTACHMENT = "suspicious_attachment"
    OTHER = "other"


class ReportStatus(str, enum.Enum):
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    REOPENED = "reopened"


def _in(column: str, enum_cls: type[enum.Enum]) -> str:
    return f"{column} IN ({', '.join(repr(e.value) for e in enum_cls)})"


def _report_code() -> str:
    return f"ASR-{secrets.token_hex(5).upper()}"


class SecurityReport(Base):
    """Private report with an optional separately consented, sanitized map event."""

    __tablename__ = "security_reports"
    __table_args__ = (
        CheckConstraint(_in("issue_type", ReportType), name="ck_security_reports_type"),
        CheckConstraint(_in("severity", Severity), name="ck_security_reports_severity"),
        CheckConstraint(_in("status", ReportStatus), name="ck_security_reports_status"),
        Index("ix_security_reports_status_created", "status", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    report_code: Mapped[str] = mapped_column(
        String(16), unique=True, index=True, default=_report_code
    )
    reporter_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=True
    )
    anonymous_token_hash: Mapped[str | None] = mapped_column(String(64))
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    issue_type: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text)
    suspicious_url: Mapped[str | None] = mapped_column(String(2048))
    source_location: Mapped[str | None] = mapped_column(String(120))
    reported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    additional_notes: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        String(24), index=True, default=ReportStatus.SUBMITTED.value
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    promoted_event_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("security_events.id", ondelete="SET NULL"), unique=True, index=True
    )
    published_event_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("security_events.id", ondelete="SET NULL"), unique=True, index=True
    )

    reporter = relationship("User", foreign_keys=[reporter_id], lazy="joined")
    assigned_to = relationship("User", foreign_keys=[assigned_to_id], lazy="joined")
    promoted_event = relationship("SecurityEvent", foreign_keys=[promoted_event_id], lazy="joined")
    notes = relationship(
        "SecurityReportNote", back_populates="report", lazy="selectin", cascade="all, delete-orphan"
    )
    activities = relationship(
        "ReportActivity",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="ReportActivity.created_at",
    )


class SecurityReportNote(Base):
    __tablename__ = "security_report_notes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("security_reports.id", ondelete="CASCADE"), index=True
    )
    author_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    content: Mapped[str] = mapped_column(String(2000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    report = relationship("SecurityReport", back_populates="notes")
    author = relationship("User", lazy="joined")
