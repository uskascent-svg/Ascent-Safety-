import uuid
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

from app.models import ReportStatus, ReportType, Severity, ThreatType


class ReportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issue_type: ReportType
    title: str = Field(min_length=3, max_length=160)
    description: str = Field(min_length=10, max_length=5000)
    suspicious_url: HttpUrl | None = Field(default=None, max_length=2048)
    source_location: str | None = Field(default=None, max_length=120)
    reported_at: datetime
    severity: Severity
    additional_notes: str | None = Field(default=None, max_length=3000)
    anonymous: bool = False
    publish_to_map: bool = False

    @field_validator("title", "description", "source_location", "additional_notes")
    @classmethod
    def _normalize_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be empty")
        return normalized

    @field_validator("reported_at")
    @classmethod
    def _valid_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("reported_at must include a timezone offset")
        if value > datetime.now(UTC) + timedelta(minutes=5):
            raise ValueError("reported_at cannot be in the future")
        return value.astimezone(UTC)


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_code: str
    issue_type: ReportType
    title: str
    description: str
    suspicious_url: str | None
    source_location: str | None
    reported_at: datetime
    severity: Severity
    additional_notes: str | None
    status: ReportStatus
    created_at: datetime
    updated_at: datetime
    timeline: list["ReportActivityOut"] = Field(default_factory=list)


class ReportActivityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    action: str
    summary: str
    created_at: datetime
    actor_name: str | None = None


class ReportNoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    content: str
    created_at: datetime
    author: str


class AdminReportOut(ReportOut):
    reporter_id: uuid.UUID | None
    reporter_name: str
    reporter_email: str
    assigned_to_id: uuid.UUID | None
    assigned_to_name: str | None
    internal_notes: list[ReportNoteOut]
    promoted_event_id: uuid.UUID | None
    published_event_id: uuid.UUID | None


class ReportSubmissionOut(ReportOut):
    tracking_token: str | None = None
    location_status: str
    published_event_id: uuid.UUID | None = None


class AnonymousReportTrack(BaseModel):
    token: str = Field(min_length=32, max_length=128)


class ReportPromotion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content_reviewed: bool
    location_verified: bool
    threat_type: ThreatType
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=10, max_length=4000)
    country: str | None = Field(default=None, min_length=1, max_length=64)
    region: str | None = Field(default=None, min_length=1, max_length=64)
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)

    @field_validator("title", "description", "country", "region")
    @classmethod
    def _normalize_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        return value

    @model_validator(mode="after")
    def _verified_coarse_location(self):
        if not self.content_reviewed or not self.location_verified:
            raise ValueError("Content and location review must be explicitly confirmed")
        if round(self.latitude, 2) != self.latitude or round(self.longitude, 2) != self.longitude:
            raise ValueError("Use coarse coordinates rounded to at most two decimal places")
        return self


class GeocodeOption(BaseModel):
    label: str
    locality: str
    region: str | None
    country: str | None
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)


class GeocodeOptionPage(BaseModel):
    items: list[GeocodeOption]
    cached: bool
    attribution: str = "© OpenStreetMap contributors"


class ReportPage(BaseModel):
    items: list[ReportOut]
    total: int
    limit: int
    offset: int


class AdminReportPage(BaseModel):
    items: list[AdminReportOut]
    total: int
    limit: int
    offset: int


class AdminReportUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: ReportStatus | None = None
    assigned_to_id: uuid.UUID | None = None
    internal_note: str | None = Field(default=None, min_length=1, max_length=2000)

    @field_validator("internal_note")
    @classmethod
    def _nonblank_note(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("internal_note must not be empty")
        return value.strip() if value is not None else None

    @field_validator("status")
    @classmethod
    def _no_resubmission(cls, value: ReportStatus | None) -> ReportStatus | None:
        if value == ReportStatus.SUBMITTED:
            raise ValueError("A report cannot be moved back to submitted")
        return value
