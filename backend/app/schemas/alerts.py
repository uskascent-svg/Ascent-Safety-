import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.models import Alert


class AlertOut(BaseModel):
    id: uuid.UUID
    event_id: uuid.UUID
    severity: str
    title: str
    status: str
    created_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    resolution_note: str | None
    threat_type: str
    source: str
    region: str | None
    occurred_at: datetime

    @classmethod
    def from_alert(cls, a: Alert) -> "AlertOut":
        return cls(
            id=a.id,
            event_id=a.event_id,
            severity=a.severity,
            title=a.title,
            status=a.status,
            created_at=a.created_at,
            acknowledged_at=a.acknowledged_at,
            resolved_at=a.resolved_at,
            resolution_note=a.resolution_note,
            threat_type=a.event.threat_type,
            source=a.event.source,
            region=a.event.region,
            occurred_at=a.event.occurred_at,
        )


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    limit: int
    offset: int


class AlertUpdate(BaseModel):
    status: Literal["acknowledged", "resolved"]
    note: str | None = Field(default=None, max_length=1000)
