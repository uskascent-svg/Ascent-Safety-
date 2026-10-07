import uuid
from datetime import UTC, datetime
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

from app.schemas.endpoint import Sha256, UtcTime

Mac = Annotated[
    str, StringConstraints(pattern=r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$", to_lower=True)
]


def _aware(v: datetime) -> datetime:
    if v.tzinfo is None:
        raise ValueError("timestamps must include a timezone offset")
    return v.astimezone(UTC)


AwareTime = Annotated[datetime, AfterValidator(_aware)]  # certificate dates may be past or future
TlsVersion = Literal["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


class _Obs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    occurred_at: UtcTime


class Certificate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_cn: str | None = Field(default=None, max_length=255)
    issuer: str = Field(min_length=1, max_length=512)
    not_before: AwareTime
    not_after: AwareTime
    self_signed: bool = False
    chain_valid: bool | None = None  # as validated by the sensor against its trust store
    hostname_match: bool | None = None
    sha256: Sha256 | None = None


class TlsObs(_Obs):
    type: Literal["tls_connection"]
    server_ip: IPvAnyAddress
    server_port: int = Field(default=443, ge=1, le=65535)
    server_name: str | None = Field(default=None, max_length=253)
    tls_version: TlsVersion
    client_ip: IPvAnyAddress | None = None
    certificate: Certificate | None = None


class ConnectionObs(_Obs):
    type: Literal["connection"]
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    dst_port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    state: Literal["established", "rejected", "no_response", "reset"] = "established"
    service: str | None = Field(default=None, max_length=32)
    encrypted: bool | None = None
    credentials_in_cleartext: bool = False
    bytes_out: int = Field(default=0, ge=0)
    bytes_in: int = Field(default=0, ge=0)


class ArpChangeObs(_Obs):
    type: Literal["arp_change"]
    ip: IPvAnyAddress
    old_mac: Mac
    new_mac: Mac
    is_gateway: bool | None = None


class WifiObs(_Obs):
    type: Literal["wifi_network"]
    ssid: str = Field(min_length=1, max_length=32)
    bssid: Mac
    security: Literal["open", "wep", "wpa", "wpa2", "wpa3", "unknown"]
    connected: bool = False
    captive_portal: bool | None = None


NetworkObservation = Annotated[
    TlsObs | ConnectionObs | ArpChangeObs | WifiObs, Field(discriminator="type")
]


class NetworkBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observations: list[NetworkObservation] = Field(min_length=1, max_length=1000)


class SensorKind(str, Enum):
    ZEEK = "zeek"
    SURICATA = "suricata"
    PROXY = "proxy"
    AGENT = "agent"
    OTHER = "other"


class SensorCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}$")
    kind: SensorKind
    region: str | None = Field(default=None, min_length=1, max_length=64)
    country: str | None = Field(default=None, min_length=1, max_length=64)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)

    @model_validator(mode="after")
    def _coords_paired(self):
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("latitude and longitude must be provided together")
        return self


class SensorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: str
    region: str | None
    country: str | None
    latitude: float | None
    longitude: float | None
    key_prefix: str
    is_active: bool
    created_at: datetime
    last_seen_at: datetime | None


class SensorCreated(BaseModel):
    sensor: SensorOut
    api_key: str  # shown exactly once
