import uuid
from datetime import UTC, datetime, timedelta

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
    model_validator,
)

from app.models import EventStatus, Severity, ThreatType


class SecurityEventCreate(BaseModel):
    """Payload a telemetry source / detector sends. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=64)
    external_id: str | None = Field(default=None, min_length=1, max_length=128)
    threat_type: ThreatType
    severity: Severity
    status: EventStatus = EventStatus.OPEN
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    source_ip: IPvAnyAddress | None = None
    country: str | None = Field(default=None, min_length=1, max_length=64)
    region: str | None = Field(default=None, min_length=1, max_length=64)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    origin_latitude: float | None = Field(default=None, ge=-90, le=90)
    origin_longitude: float | None = Field(default=None, ge=-180, le=180)
    destination_latitude: float | None = Field(default=None, ge=-90, le=90)
    destination_longitude: float | None = Field(default=None, ge=-180, le=180)
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def _valid_time(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("occurred_at must include a timezone offset")
        if v > datetime.now(UTC) + timedelta(minutes=5):
            raise ValueError("occurred_at cannot be in the future")
        return v.astimezone(UTC)

    @model_validator(mode="after")
    def _coords_paired(self):
        pairs = (
            ("reported location", self.latitude, self.longitude),
            ("origin", self.origin_latitude, self.origin_longitude),
            ("destination", self.destination_latitude, self.destination_longitude),
        )
        for name, latitude, longitude in pairs:
            if (latitude is None) != (longitude is None):
                raise ValueError(f"{name} latitude and longitude must be provided together")
        return self


class SecurityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str
    external_id: str | None
    threat_type: ThreatType
    severity: Severity
    status: EventStatus
    title: str
    description: str | None
    source_ip: str | None
    country: str | None
    region: str | None
    latitude: float | None
    longitude: float | None
    origin_latitude: float | None
    origin_longitude: float | None
    destination_latitude: float | None
    destination_longitude: float | None
    occurred_at: datetime


class SecurityEventPage(BaseModel):
    items: list[SecurityEventOut]
    total: int
    limit: int
    offset: int


class EventLocation(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    latitude: float | None
    longitude: float | None
    origin_latitude: float | None
    origin_longitude: float | None
    destination_latitude: float | None
    destination_longitude: float | None
    country: str | None
    region: str | None
    threat_type: ThreatType
    severity: Severity
    status: EventStatus
    source: str
    title: str
    occurred_at: datetime


class EventLocationList(BaseModel):
    items: list[EventLocation]
    total: int
    truncated: bool


class DashboardSummary(BaseModel):
    total_events: int
    active_threats: int
    blocked_threats: int
    critical_events: int
    affected_regions: int


class DistributionItem(BaseModel):
    key: str
    count: int


class RegionItem(BaseModel):
    region: str
    count: int


class TimelinePoint(BaseModel):
    bucket: datetime
    count: int
