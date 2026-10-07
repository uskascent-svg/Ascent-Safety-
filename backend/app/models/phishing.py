import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class PhishingAnalysis(Base):
    """Result of one analysis. The email body is NOT stored — only a hash and derived results."""

    __tablename__ = "phishing_analysis"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    sender: Mapped[str | None] = mapped_column(String(320))
    subject: Mapped[str | None] = mapped_column(String(200))
    content_sha256: Mapped[str] = mapped_column(String(64))
    risk_score: Mapped[int] = mapped_column(Integer)
    rule_score: Mapped[int] = mapped_column(Integer)
    classification: Mapped[str] = mapped_column(String(20), index=True)
    ml_probability: Mapped[float | None] = mapped_column(Float)
    ml_model_version: Mapped[str | None] = mapped_column(String(64))
    ml_top_terms: Mapped[list | None] = mapped_column(JSON)
    reasons: Mapped[list] = mapped_column(JSON)
    recommended_action: Mapped[str] = mapped_column(Text)
    link_count: Mapped[int] = mapped_column(Integer)
    attachment_count: Mapped[int] = mapped_column(Integer)

    indicators: Mapped[list["PhishingIndicator"]] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
        order_by="PhishingIndicator.weight.desc()",
        lazy="selectin",
    )


class PhishingIndicator(Base):
    __tablename__ = "phishing_indicators"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("phishing_analysis.id", ondelete="CASCADE"), index=True
    )
    code: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(20))
    severity: Mapped[str] = mapped_column(String(10))
    weight: Mapped[float] = mapped_column(Float)
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON)

    analysis: Mapped[PhishingAnalysis] = relationship(back_populates="indicators")
