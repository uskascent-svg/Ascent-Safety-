from app.detection.network.detectors import (
    detect_arp,
    detect_beaconing,
    detect_cleartext,
    detect_scanning,
    detect_tls,
    detect_wifi,
)
from app.detection.network.types import Context, Finding, NetDetector
from app.schemas.network import NetworkObservation

# Modular: append a detector `(observations, context) -> findings` to extend.
DETECTORS: list[NetDetector] = [
    detect_tls,
    detect_cleartext,
    detect_scanning,
    detect_beaconing,
    detect_arp,
    detect_wifi,
]
_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def evaluate(observations: list[NetworkObservation], ctx: Context | None = None) -> list[Finding]:
    ctx = ctx or Context()
    findings = [f for d in DETECTORS for f in d(observations, ctx)]
    return sorted(findings, key=lambda f: _RANK[f.severity])
