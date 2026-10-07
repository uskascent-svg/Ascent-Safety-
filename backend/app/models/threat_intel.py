import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, String, Text, UniqueConstraint, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ThreatIntelCache(Base):
    """Cached third-party reputation answers (protects API quotas; short TTL for failures)."""

    __tablename__ = "threat_intel_cache"
    __table_args__ = (
        UniqueConstraint("provider", "indicator_type", "indicator_hash", name="uq_intel_cache_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    provider: Mapped[str] = mapped_column(String(32))
    indicator_type: Mapped[str] = mapped_column(String(10))
    indicator_hash: Mapped[str] = mapped_column(String(64))  # sha256; keeps the unique key small
    indicator: Mapped[str] = mapped_column(Text)
    result: Mapped[dict] = mapped_column(JSON)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class GeocodeCache(Base):
    """Cached city-level place-name matches; raw report location text is not retained."""

    __tablename__ = "geocode_cache"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    query_hash: Mapped[str] = mapped_column(String(64), unique=True)
    results: Mapped[list] = mapped_column(JSON)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
