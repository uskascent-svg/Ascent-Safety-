import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ThreatType(str, enum.Enum):
    PHISHING = "phishing"
    MALWARE_RANSOMWARE = "malware_ransomware"
    MITM = "mitm"
    UNSAFE_NETWORK = "unsafe_network"
    VULNERABILITY = "vulnerability"
    SUSPICIOUS_LOGIN = "suspicious_login"
    OTHER = "other"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    BLOCKED = "blocked"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# "Active" threats are those still requiring attention.
ACTIVE_STATUSES = (EventStatus.OPEN.value, EventStatus.INVESTIGATING.value)


def _in(column: str, enum_cls: type[enum.Enum]) -> str:
    return f"{column} IN ({', '.join(repr(e.value) for e in enum_cls)})"


class SecurityEvent(Base):
    """A single event reported by a real telemetry source or detector."""

    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_security_events_source_external"),
        CheckConstraint(_in("threat_type", ThreatType), name="ck_security_events_threat_type"),
        CheckConstraint(_in("severity", Severity), name="ck_security_events_severity"),
        CheckConstraint(_in("status", EventStatus), name="ck_security_events_status"),
        CheckConstraint("latitude BETWEEN -90 AND 90", name="ck_security_events_lat"),
        CheckConstraint("longitude BETWEEN -180 AND 180", name="ck_security_events_lng"),
        CheckConstraint(
            "(origin_latitude IS NULL) = (origin_longitude IS NULL)",
            name="ck_security_events_origin_pair",
        ),
        CheckConstraint(
            "origin_latitude BETWEEN -90 AND 90", name="ck_security_events_origin_lat"
        ),
        CheckConstraint(
            "origin_longitude BETWEEN -180 AND 180", name="ck_security_events_origin_lng"
        ),
        CheckConstraint(
            "(destination_latitude IS NULL) = (destination_longitude IS NULL)",
            name="ck_security_events_destination_pair",
        ),
        CheckConstraint(
            "destination_latitude BETWEEN -90 AND 90",
            name="ck_security_events_destination_lat",
        ),
        CheckConstraint(
            "destination_longitude BETWEEN -180 AND 180",
            name="ck_security_events_destination_lng",
        ),
        CheckConstraint(
            "(latitude IS NULL) = (longitude IS NULL)",
            name="ck_security_events_latlng_pair",
        ),
        Index("ix_security_events_severity_occurred", "severity", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(64), index=True)
    external_id: Mapped[str | None] = mapped_column(String(128))
    threat_type: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(20), index=True, default=EventStatus.OPEN.value)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    country: Mapped[str | None] = mapped_column(String(64), index=True)
    region: Mapped[str | None] = mapped_column(String(64), index=True)
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    # A reported event/site point is distinct from a verified route between two geolocated ends.
    origin_latitude: Mapped[float | None] = mapped_column(Float)
    origin_longitude: Mapped[float | None] = mapped_column(Float)
    destination_latitude: Mapped[float | None] = mapped_column(Float)
    destination_longitude: Mapped[float | None] = mapped_column(Float)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
