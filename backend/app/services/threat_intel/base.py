from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

import httpx

# status:  ok | not_found | rate_limited | error
# verdict: malicious | suspicious | clean | unknown   ("clean" = not flagged, never a guarantee)


@dataclass
class IntelResult:
    provider: str
    indicator: str
    indicator_type: str
    status: str
    verdict: str
    detail: dict = field(default_factory=dict)
    cached: bool = False
    checked_at: datetime | None = None


def failure(provider: str, indicator: str, itype: str, status: str, message: str) -> IntelResult:
    return IntelResult(provider, indicator, itype, status, "unknown", {"error": message})


def check_http(
    provider: str, indicator: str, itype: str, resp: httpx.Response
) -> IntelResult | None:
    """Map common HTTP failures to a result; return None when the response is usable."""
    if resp.status_code == 404:
        return IntelResult(provider, indicator, itype, "not_found", "unknown")
    if resp.status_code == 429:
        return failure(provider, indicator, itype, "rate_limited", "Provider rate limit reached")
    if resp.status_code in (401, 403):
        return failure(
            provider, indicator, itype, "error", "Authentication failed — check the API key"
        )
    if resp.status_code >= 400:
        return failure(
            provider, indicator, itype, "error", f"Provider returned HTTP {resp.status_code}"
        )
    return None


class Provider(ABC):
    name: str
    types: tuple[str, ...]

    @abstractmethod
    def enabled(self) -> bool: ...

    @abstractmethod
    def lookup(self, client: httpx.Client, indicator: str, itype: str) -> IntelResult: ...
