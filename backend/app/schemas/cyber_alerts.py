import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CyberAlertCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=5, max_length=200)
    severity: str
    threat_type: str
    affected_region: str = Field(min_length=2, max_length=120)
    summary: str = Field(min_length=20, max_length=3000)
    recommended_actions: list[str] = Field(min_length=1, max_length=8)
    related_event_ids: list[uuid.UUID] = Field(default_factory=list, max_length=20)
    expires_at: datetime

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, value: str) -> str:
        if value not in {"low", "medium", "high", "critical"}:
            raise ValueError("Invalid severity")
        return value

    @field_validator("threat_type")
    @classmethod
    def valid_threat_type(cls, value: str) -> str:
        from app.models import ThreatType

        allowed = {v.value for v in ThreatType}
        if value not in allowed:
            raise ValueError("Invalid threat type")
        return value

    @field_validator("title", "affected_region", "summary")
    @classmethod
    def trim_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value must not be blank")
        return value

    @field_validator("recommended_actions")
    @classmethod
    def clean_actions(cls, value: list[str]) -> list[str]:
        actions = [item.strip() for item in value]
        if any(not item or len(item) > 300 for item in actions):
            raise ValueError("Actions must be non-empty and at most 300 characters")
        return actions

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value <= datetime.now(UTC):
            raise ValueError("Expiry must be a future timezone-aware timestamp")
        return value.astimezone(UTC)


class CyberAlertActivityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    actor_id: uuid.UUID | None
    action: str
    changes: dict
    created_at: datetime


class CyberAlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    severity: str
    threat_type: str
    affected_region: str
    summary: str
    recommended_actions: list[str]
    related_event_ids: list[uuid.UUID]
    status: str
    created_by_id: uuid.UUID
    approved_by_id: uuid.UUID | None
    published_by_id: uuid.UUID | None
    published_event_id: uuid.UUID | None
    location_status: str
    approved_at: datetime | None
    published_at: datetime | None
    expires_at: datetime
    revoked_at: datetime | None
    created_at: datetime
    updated_at: datetime
    history: list[CyberAlertActivityOut] = Field(default_factory=list)


class CyberAlertDetail(CyberAlertOut):
    history: list[CyberAlertActivityOut]


class CyberAlertPage(BaseModel):
    items: list[CyberAlertOut]
    total: int
