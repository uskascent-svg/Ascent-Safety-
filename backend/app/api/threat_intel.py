import hashlib
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.limiter import limiter
from app.database.session import get_db
from app.models import User
from app.schemas.threat_intel import LookupOut, ProviderResultOut, ProviderStatusOut
from app.security.deps import analyst_or_admin
from app.services import audit
from app.services.threat_intel import aggregator
from app.services.threat_intel.aggregator import LookupResult
from app.services.threat_intel.indicators import IndicatorError, normalize

router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])


def to_out(lk: LookupResult) -> LookupOut:
    return LookupOut(
        indicator=lk.indicator,
        indicator_type=lk.indicator_type,
        verdict=lk.verdict,
        results=[
            ProviderResultOut(**{k: getattr(r, k) for k in ProviderResultOut.model_fields})
            for r in lk.results
        ],
    )


def run_lookup(db: Session, request: Request, user: User, indicator: str, itype: str) -> LookupOut:
    """Validate, look up, audit. Shared with the security-event enrichment endpoint."""
    try:
        norm = normalize(indicator, itype)
    except IndicatorError as exc:
        raise HTTPException(422, str(exc)) from None
    if not any(itype in p.types for p in aggregator.configured_providers()):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "No threat-intelligence provider is configured for this indicator type",
        )
    [lookup] = aggregator.lookup_many(db, [(norm, itype)])
    audit.record(
        db,
        "threat_intel.lookup",
        request,
        user.id,
        {
            "type": itype,
            "indicator_sha256": hashlib.sha256(norm.encode()).hexdigest(),
            "verdict": lookup.verdict,
        },
    )
    db.commit()
    return to_out(lookup)


@router.get("/providers", response_model=list[ProviderStatusOut])
def providers(_: User = Depends(analyst_or_admin)):
    return aggregator.provider_status()


@router.get("/lookup", response_model=LookupOut)
@limiter.limit("30/minute")
def lookup(
    request: Request,
    indicator: str = Query(min_length=1, max_length=2000),
    type: Literal[
        "ip", "domain", "url", "hash"
    ] = Query(),  # noqa: A002 - public query parameter name
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    return run_lookup(db, request, user, indicator, type)
