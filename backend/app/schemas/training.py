import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TrainingIndicator(BaseModel):
    id: str = Field(min_length=2, max_length=48, pattern=r"^[a-z0-9_]+$")
    label: str = Field(min_length=3, max_length=120)
    severity: Literal["low", "medium", "high", "critical"]
    explanation: str = Field(min_length=8, max_length=1000)


class TrainingScenarioCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slug: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9-]+$")
    title: str = Field(min_length=3, max_length=160)
    category: str = Field(min_length=2, max_length=48)
    difficulty: Literal["beginner", "intermediate", "advanced"]
    artifact_type: Literal["email", "sms", "url", "login_page"]
    sender: str = Field(min_length=2, max_length=320)
    reply_to: str | None = Field(default=None, max_length=320)
    subject: str = Field(min_length=2, max_length=240)
    received_at: str = Field(min_length=2, max_length=80)
    headers: dict[str, str] = Field(default_factory=dict, max_length=20)
    body: str = Field(min_length=10, max_length=8000)
    links: list[dict[str, str]] = Field(default_factory=list, max_length=10)
    attachments: list[dict[str, str]] = Field(default_factory=list, max_length=10)
    indicators: list[TrainingIndicator] = Field(min_length=1, max_length=20)
    correct_decision: Literal["report", "safe"]
    attack_technique: str = Field(min_length=3, max_length=240)
    explanation: str = Field(min_length=10, max_length=3000)
    prevention: str = Field(min_length=10, max_length=2000)
    correct_actions: list[str] = Field(min_length=1, max_length=7)
    action_rationales: dict[str, str] = Field(default_factory=dict, max_length=7)
    objective: str = Field(min_length=10, max_length=500)
    is_active: bool = True

    @field_validator(
        "title",
        "category",
        "sender",
        "subject",
        "attack_technique",
        "explanation",
        "prevention",
        "objective",
    )
    @classmethod
    def _trim_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("This field cannot be blank")
        return value

    @model_validator(mode="after")
    def _safe_simulation_links(self):
        for link in self.links:
            url = link.get("url", "")
            if url and not (
                url.startswith("https://") and (url.endswith(".example") or ".example/" in url)
            ):
                raise ValueError("Training links must use reserved .example domains")
        return self


class TrainingScenarioPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: TrainingScenarioCreate


class TrainingScenarioPlay(BaseModel):
    id: uuid.UUID
    slug: str
    title: str
    category: str
    difficulty: str
    artifact_type: str
    sender: str
    reply_to: str | None
    subject: str
    received_at: str
    headers: dict[str, str]
    body: str
    links: list[dict[str, str]]
    attachments: list[dict[str, str]]
    objective: str


class TrainingScenarioAdmin(TrainingScenarioCreate):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class TrainingScenarioPage(BaseModel):
    items: list[TrainingScenarioPlay]
    total: int


class TrainingAttemptCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: uuid.UUID
    decision: Literal["report", "safe"]
    discovered_indicators: list[str] = Field(max_length=20)
    response_actions: list[str] = Field(max_length=7)
    elapsed_seconds: int = Field(ge=0, le=3600)


class TrainingAttemptOut(BaseModel):
    id: uuid.UUID
    scenario_id: uuid.UUID
    security_score: int
    detection_accuracy: float
    indicator_score: float
    action_score: float
    indicators_found: list[TrainingIndicator]
    indicators_missed: list[TrainingIndicator]
    actions_feedback: list[dict[str, str | bool]]
    decision_correct: bool
    attack_technique: str
    explanation: str
    prevention: str
    recommended_improvement: str
    created_at: datetime


class TrainingProgress(BaseModel):
    scenarios_completed: int
    average_score: float
    detection_accuracy: float
    training_level: str
    weakest_category: str | None
    current_streak: int
    badges: list[str]
    certificate_eligible: bool
    recommended_next: TrainingScenarioPlay | None
