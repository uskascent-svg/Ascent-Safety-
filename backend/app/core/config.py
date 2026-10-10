from functools import lru_cache

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    jwt_secret: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    cors_origins: list[str] = ["http://localhost:3000"]
    cookie_secure: bool = True
    # Path to a joblib artifact produced by ml/training/train.py. Unset = rules-only detection.
    ml_model_path: str | None = None
    threat_analysis_data_key: str | None = None
    threat_analysis_independent_test_set: str | None = None
    threat_analysis_model_hmac_key: str | None = None
    threat_analysis_model_dir: str = "./threat_analysis_models"
    sse_max_seconds: int = 600  # streams end after this so clients re-authenticate on reconnect
    sse_heartbeat_seconds: int = 15
    # Optional threat-intel keys (used in later phases)
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    otx_api_key: str | None = None
    # abuse.ch Auth-Key (URLhaus now requires one; free at auth.abuse.ch)
    urlhaus_auth_key: str | None = None
    intel_timeout_seconds: float = 5.0
    google_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GOOGLE_API_KEY", "GEMINI_API_KEY"),
    )
    gemini_model: str = "gemini-3.5-flash-lite"
    # Public Nominatim is used only when an administrator explicitly resolves a report place name.
    geocoding_base_url: str = "https://nominatim.openstreetmap.org"
    geocoding_user_agent: str = "AscentSafety/0.3 (https://github.com/uskascent-svg/Ascent-Safety-)"
    # Alerts are created for new events at or above this severity.
    alert_min_severity: str = "high"
    # Ransomware-behaviour thresholds (tune per environment)
    ransomware_min_file_changes: int = 100
    ransomware_entropy_threshold: float = 7.2
    # Opt-in: send file hashes seen on endpoints to threat-intel providers (uses API quota).
    endpoint_hash_enrichment: bool = False
    # Network-detection thresholds (tune per environment)
    portscan_min_targets: int = 20
    beacon_min_connections: int = 8
    beacon_max_jitter: float = 0.1  # max coefficient of variation of inter-connection intervals
    tls_baseline_min_observations: int = 3  # valid sightings before a host's cert is "established"
    # Opt-in: send public destination IPs seen by sensors to threat-intel providers.
    network_ip_enrichment: bool = False
    intel_cache_ttl_seconds: int = 21600  # 6h for definitive answers
    intel_negative_ttl_seconds: int = 300  # 5m for errors / rate limits
    # Shared secret that telemetry sources present in the X-Ingest-Key header.
    # If unset, event ingestion is disabled.
    ingest_api_key: str | None = Field(default=None, min_length=32)

    @field_validator("database_url", mode="before")
    @classmethod
    def _use_psycopg3_driver(cls, value):
        # Render and several managed Postgres providers supply a generic postgres URL.
        # This project pins psycopg 3, so make SQLAlchemy select that driver explicitly.
        if isinstance(value, str):
            if value.startswith("postgres://"):
                return "postgresql+psycopg://" + value.removeprefix("postgres://")
            if value.startswith("postgresql://"):
                return "postgresql+psycopg://" + value.removeprefix("postgresql://")
        return value

    @field_validator(
        "virustotal_api_key",
        "abuseipdb_api_key",
        "otx_api_key",
        "urlhaus_auth_key",
        "google_api_key",
        "ingest_api_key",
        "ml_model_path",
        "threat_analysis_data_key",
        "threat_analysis_independent_test_set",
        "threat_analysis_model_hmac_key",
        mode="before",
    )
    @classmethod
    def _blank_to_none(cls, v):
        return v or None


@lru_cache
def get_settings() -> Settings:
    return Settings()
