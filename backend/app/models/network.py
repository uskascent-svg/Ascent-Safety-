import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class NetworkSensor(Base):
    """A registered source of network telemetry (Zeek/Suricata export, proxy, client agent…).
    Ascent Safety ships no sensor: the operator connects their own with this sensor's API key."""

    __tablename__ = "network_sensors"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('zeek', 'suricata', 'proxy', 'agent', 'other')", name="ck_sensors_kind"
        ),
        CheckConstraint("(latitude IS NULL) = (longitude IS NULL)", name="ck_sensors_latlng_pair"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(48), unique=True)
    kind: Mapped[str] = mapped_column(String(16))
    region: Mapped[str | None] = mapped_column(String(64))
    country: Mapped[str | None] = mapped_column(String(64))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    key_prefix: Mapped[str] = mapped_column(String(20))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TlsBaseline(Base):
    """What a sensor has *validly* observed for a host: the basis for interception indicators.
    Built only from certificates that passed validation, so bad certificates never become normal."""

    __tablename__ = "tls_baselines"
    __table_args__ = (UniqueConstraint("sensor_id", "server_name", name="uq_tls_baseline_host"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    sensor_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("network_sensors.id", ondelete="CASCADE"), index=True
    )
    server_name: Mapped[str] = mapped_column(String(255))
    issuer: Mapped[str] = mapped_column(String(512))
    cert_sha256: Mapped[str | None] = mapped_column(String(64))
    max_tls_version: Mapped[str] = mapped_column(String(8))
    observations: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class NetworkFinding(Base):
    __tablename__ = "network_findings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    sensor_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("network_sensors.id", ondelete="CASCADE"), index=True
    )
    event_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("security_events.id", ondelete="SET NULL"), index=True
    )
    detector: Mapped[str] = mapped_column(String(32))
    code: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
