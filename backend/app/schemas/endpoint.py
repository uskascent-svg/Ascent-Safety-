import uuid
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StringConstraints,
    model_validator,
)


def _valid_time(v: datetime) -> datetime:
    if v.tzinfo is None:
        raise ValueError("timestamps must include a timezone offset")
    if v > datetime.now(UTC) + timedelta(minutes=5):
        raise ValueError("timestamps cannot be in the future")
    return v.astimezone(UTC)


UtcTime = Annotated[datetime, AfterValidator(_valid_time)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[A-Fa-f0-9]{64}$", to_lower=True)]
Path = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class _Obs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    occurred_at: UtcTime


class ProcessObs(_Obs):
    type: Literal["process"]
    image: Path
    command_line: str | None = Field(default=None, max_length=4096)
    parent_image: Path | None = None
    user: str | None = Field(default=None, max_length=128)
    sha256: Sha256 | None = None


class FileObs(_Obs):
    type: Literal["file"]
    path: Path
    action: Literal["created", "modified", "renamed", "deleted", "executed"]
    process_image: Path | None = None
    sha256: Sha256 | None = None


class FileActivityObs(_Obs):
    """Aggregated file-system behaviour of one process over a window (computed by the agent)."""

    type: Literal["file_activity"]
    window_seconds: int = Field(ge=1, le=3600)
    files_modified: int = Field(ge=0, le=10_000_000)
    files_renamed: int = Field(ge=0, le=10_000_000)
    files_deleted: int = Field(ge=0, le=10_000_000)
    distinct_directories: int = Field(ge=0, le=10_000_000)
    new_extensions: list[Annotated[str, StringConstraints(max_length=16)]] = Field(
        default_factory=list, max_length=20
    )
    mean_write_entropy: float | None = Field(default=None, ge=0, le=8)  # Shannon bits/byte
    process_image: Path | None = None


class PersistenceObs(_Obs):
    type: Literal["persistence"]
    mechanism: Literal[
        "run_key",
        "scheduled_task",
        "service",
        "startup_folder",
        "launch_agent",
        "cron",
        "wmi_subscription",
        "other",
    ]
    target: str = Field(min_length=1, max_length=1024)
    name: str | None = Field(default=None, max_length=256)
    process_image: Path | None = None
    signed: bool | None = None


class NetworkObs(_Obs):
    type: Literal["network"]
    process_image: Path
    remote_ip: IPvAnyAddress
    remote_port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    direction: Literal["outbound", "inbound"] = "outbound"


Observation = Annotated[
    ProcessObs | FileObs | FileActivityObs | PersistenceObs | NetworkObs,
    Field(discriminator="type"),
]


class TelemetryBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observations: list[Observation] = Field(min_length=1, max_length=500)


class BatchResult(BaseModel):
    received: int
    findings: int
    events_created: int
    duplicates_skipped: int


class EndpointOS(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class EndpointCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}$")
    os: EndpointOS
    hostname: str | None = Field(default=None, max_length=255)
    agent_version: str | None = Field(default=None, max_length=32)
    region: str | None = Field(default=None, min_length=1, max_length=64)
    country: str | None = Field(default=None, min_length=1, max_length=64)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)

    @model_validator(mode="after")
    def _coords_paired(self):
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("latitude and longitude must be provided together")
        return self


class EndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    os: str
    hostname: str | None
    agent_version: str | None
    region: str | None
    country: str | None
    latitude: float | None
    longitude: float | None
    key_prefix: str
    is_active: bool
    created_at: datetime
    last_seen_at: datetime | None


class EndpointCreated(BaseModel):
    endpoint: EndpointOut
    api_key: str  # shown exactly once; only a hash is stored
