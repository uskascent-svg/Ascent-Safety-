import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class TrainingScenario(Base):
    """Fictional, non-executable training material authored and stored by the application."""

    __tablename__ = "phishing_training_scenarios"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(160))
    category: Mapped[str] = mapped_column(String(48), index=True)
    difficulty: Mapped[str] = mapped_column(String(16))
    artifact_type: Mapped[str] = mapped_column(String(16))
    sender: Mapped[str] = mapped_column(String(320))
    reply_to: Mapped[str | None] = mapped_column(String(320))
    subject: Mapped[str] = mapped_column(String(240))
    received_at: Mapped[str] = mapped_column(String(80))
    headers: Mapped[dict] = mapped_column(JSON)
    body: Mapped[str] = mapped_column(Text)
    links: Mapped[list] = mapped_column(JSON)
    attachments: Mapped[list] = mapped_column(JSON)
    indicators: Mapped[list] = mapped_column(JSON)
    correct_decision: Mapped[str] = mapped_column(String(16))
    attack_technique: Mapped[str] = mapped_column(String(240))
    explanation: Mapped[str] = mapped_column(Text)
    prevention: Mapped[str] = mapped_column(Text)
    correct_actions: Mapped[list] = mapped_column(JSON)
    action_rationales: Mapped[dict] = mapped_column(JSON)
    objective: Mapped[str] = mapped_column(String(500))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    attempts: Mapped[list["TrainingAttempt"]] = relationship(back_populates="scenario")


class TrainingAttempt(Base):
    """Stores a learner's choices and derived score, never pasted message content."""

    __tablename__ = "phishing_training_attempts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    scenario_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("phishing_training_scenarios.id", ondelete="CASCADE"), index=True
    )
    decision: Mapped[str] = mapped_column(String(16))
    discovered_indicators: Mapped[list] = mapped_column(JSON)
    response_actions: Mapped[list] = mapped_column(JSON)
    elapsed_seconds: Mapped[int] = mapped_column(Integer)
    security_score: Mapped[int] = mapped_column(Integer)
    detection_accuracy: Mapped[float] = mapped_column(Float)
    indicator_score: Mapped[float] = mapped_column(Float)
    action_score: Mapped[float] = mapped_column(Float)
    indicators_missed: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scenario: Mapped[TrainingScenario] = relationship(back_populates="attempts", lazy="joined")
