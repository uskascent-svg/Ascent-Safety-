from datetime import datetime

from pydantic import BaseModel


class ProviderStatusOut(BaseModel):
    name: str
    configured: bool
    types: list[str]


class ProviderResultOut(BaseModel):
    provider: str
    status: str
    verdict: str
    detail: dict
    cached: bool
    checked_at: datetime | None


class LookupOut(BaseModel):
    indicator: str
    indicator_type: str
    verdict: str
    results: list[ProviderResultOut]
    note: str = (
        "'clean' means not flagged by the queried services. It is not a guarantee of safety."
    )
