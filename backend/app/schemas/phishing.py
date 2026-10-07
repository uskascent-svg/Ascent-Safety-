import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PhishingAnalyzeRequest(BaseModel):
    """Submit either a full raw email (headers + body) or the message fields."""

    model_config = ConfigDict(extra="forbid")

    raw_email: str | None = Field(default=None, max_length=1_000_000)
    sender: str | None = Field(default=None, max_length=320)
    subject: str | None = Field(default=None, max_length=998)
    body_text: str | None = Field(default=None, max_length=500_000)
    body_html: str | None = Field(default=None, max_length=500_000)
    # Opt-in: sends the message's link addresses to third-party reputation services.
    check_threat_intel: bool = False

    @model_validator(mode="after")
    def _exactly_one_input(self):
        has_raw = bool(self.raw_email and self.raw_email.strip())
        has_body = bool(
            (self.body_text and self.body_text.strip())
            or (self.body_html and self.body_html.strip())
        )
        if has_raw == has_body:
            raise ValueError(
                "Provide either raw_email, or body_text/body_html — not both, not neither"
            )
        if has_raw and (self.sender or self.subject):
            raise ValueError("sender and subject apply only when raw_email is not used")
        return self


class IndicatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    code: str
    category: str
    severity: str
    description: str
    evidence: list[str]


class MlOut(BaseModel):
    available: bool
    probability: float | None = None
    model_version: str | None = None
    top_terms: list[str] = []


class IntelSummaryOut(BaseModel):
    providers: list[str]
    indicators_checked: int
    unavailable: int
    note: str | None = None


class PhishingAnalysisOut(BaseModel):
    id: uuid.UUID
    created_at: datetime
    sender: str | None
    subject: str | None
    risk_score: int
    classification: str
    reasons: list[str]
    indicators: list[IndicatorOut]
    ml: MlOut
    recommended_action: str
    link_count: int
    attachment_count: int
    intel: IntelSummaryOut | None = None  # only present on the analyze response


class PhishingAnalysisSummary(BaseModel):
    id: uuid.UUID
    created_at: datetime
    sender: str | None
    subject: str | None
    risk_score: int
    classification: str


class PhishingAnalysisPage(BaseModel):
    items: list[PhishingAnalysisSummary]
    total: int
    limit: int
    offset: int
