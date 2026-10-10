import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ThreatAnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=100_000)
    input_kind: Literal["message", "url", "document_text"] = "message"

    @model_validator(mode="after")
    def validate_url(self):
        if self.input_kind in {"message", "url"} and len(self.text.strip()) < 20:
            raise ValueError("Provide at least 20 characters for message or URL analysis")
        if self.input_kind == "url" and any(char.isspace() for char in self.text.strip()):
            raise ValueError("URL analysis accepts one URL only")
        return self


class ThreatFinding(BaseModel):
    detector: str
    code: str
    severity: str
    title: str
    explanation: str
    evidence: list[str]


class ThreatAnalysisOut(BaseModel):
    id: uuid.UUID
    created_at: datetime
    verdict: Literal["malicious", "suspicious", "benign", "unknown"]
    severity: Literal["critical", "high", "medium", "low", "unknown"]
    heuristic_score: int = Field(ge=0, le=100)
    score_type: Literal["heuristic", "hybrid"] = "heuristic"
    detector_mode: Literal["rules_only", "hybrid"] = "rules_only"
    model_version: str | None = None
    model_family: str | None = None
    model_confidence: float | None = Field(default=None, ge=0, le=1)
    combined_score: int | None = Field(default=None, ge=0, le=100)
    completeness: Literal["complete", "partial"]
    input_kind: str
    findings: list[ThreatFinding]
    explanation: str
    remediation: str
    extraction_status: str = "not_applicable"
    extraction_notes: list[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class ThreatAnalysisSummary(BaseModel):
    id: uuid.UUID
    created_at: datetime
    verdict: str
    severity: str
    input_kind: str


class ThreatAnalysisPage(BaseModel):
    items: list[ThreatAnalysisSummary]
    total: int


class ThreatMetrics(BaseModel):
    window_days: int
    total: int
    by_verdict: dict[str, int]
    by_severity: dict[str, int]
    heuristic_only: bool = True
    detector_modes: dict[str, int] = Field(default_factory=dict)
    detection_quality: None = None
    source: Literal["persisted user threat analyses"] = "persisted user threat analyses"


class ThreatFeedbackCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_label: Literal["malicious", "suspicious", "benign", "unknown"]
    reason: str = Field(min_length=10, max_length=2000)
    include_in_training: bool = False
    training_sample: str | None = Field(default=None, min_length=20, max_length=100_000)

    @model_validator(mode="after")
    def validate_training_sample(self):
        if self.include_in_training and (
            self.candidate_label not in {"malicious", "benign"} or not self.training_sample
        ):
            raise ValueError(
                "Training opt-in requires a benign/malicious label and the exact sample text"
            )
        if not self.include_in_training and self.training_sample is not None:
            raise ValueError("A training sample requires explicit training opt-in")
        return self


class ThreatFeedbackOut(BaseModel):
    id: uuid.UUID
    analysis_id: uuid.UUID
    candidate_label: str
    status: str
    reason: str
    includes_training_sample: bool = False
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode="before")
    @classmethod
    def hide_encrypted_sample(cls, value):
        if isinstance(value, dict):
            value.pop("training_sample_encrypted", None)
        else:
            try:
                value.includes_training_sample = bool(value.training_sample_encrypted)
            except AttributeError:
                pass
        return value


class ThreatFeedbackReviewItem(ThreatFeedbackOut):
    """Sensitive sample disclosure for the server-authorized dataset-review role only."""

    training_sample: str | None = None


class ThreatFeedbackReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject"]
    note: str = Field(min_length=10, max_length=2000)


class ThreatModelReject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str = Field(min_length=10, max_length=500)
