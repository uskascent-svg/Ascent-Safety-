import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Endpoint(Base):
    """A registered source of endpoint telemetry. Ascent Safety ships no agent: the operator
    connects their own, which authenticates with this endpoint's API key (only its hash is stored).
    """

    __tablename__ = "endpoints"
    __table_args__ = (
        CheckConstraint("os IN ('windows', 'linux', 'macos')", name="ck_endpoints_os"),
        CheckConstraint(
            "(latitude IS NULL) = (longitude IS NULL)", name="ck_endpoints_latlng_pair"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(48), unique=True)
    os: Mapped[str] = mapped_column(String(16))
    hostname: Mapped[str | None] = mapped_column(String(255))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    # Site location supplied by the administrator; events from this endpoint inherit it.
    region: Mapped[str | None] = mapped_column(String(64))
    country: Mapped[str | None] = mapped_column(String(64))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    key_prefix: Mapped[str] = mapped_column(String(16))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EndpointFinding(Base):
    """Why a detector fired. Only findings are stored — not the raw endpoint telemetry."""

    __tablename__ = "endpoint_findings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("endpoints.id", ondelete="CASCADE"), index=True
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
