from collections.abc import Callable
from dataclasses import dataclass, field

from app.detection.malware.types import Finding
from app.schemas.network import NetworkObservation


@dataclass
class BaselineSnapshot:
    issuer: str  # normalised
    cert_sha256: str | None
    max_tls_version: str
    observations: int
    issuer_raw: str = ""  # original text, for display in evidence


@dataclass
class Context:
    """State from BEFORE this batch (per sensor), so detection never learns from its own input."""

    tls: dict[str, BaselineSnapshot] = field(default_factory=dict)


NetDetector = Callable[[list[NetworkObservation], Context], list[Finding]]
__all__ = ["BaselineSnapshot", "Context", "Finding", "NetDetector"]
