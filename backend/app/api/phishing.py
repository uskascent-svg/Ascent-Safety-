import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.limiter import limiter
from app.database.session import get_db
from app.detection.phishing import engine
from app.detection.phishing.parser import parse_fields, parse_raw
from app.models import PhishingAnalysis, PhishingIndicator, User
from app.schemas.phishing import (
    IndicatorOut,
    IntelSummaryOut,
    MlOut,
    PhishingAnalysisOut,
    PhishingAnalysisPage,
    PhishingAnalysisSummary,
    PhishingAnalyzeRequest,
)
from app.security.deps import get_current_user
from app.services import audit
from app.services.threat_intel.phishing_enrichment import IntelSummary, link_indicators

router = APIRouter(prefix="/api/phishing", tags=["phishing"])


def _to_out(a: PhishingAnalysis, intel: IntelSummary | None = None) -> PhishingAnalysisOut:
    return PhishingAnalysisOut(
        id=a.id,
        created_at=a.created_at,
        sender=a.sender,
        subject=a.subject,
        risk_score=a.risk_score,
        classification=a.classification,
        reasons=a.reasons,
        indicators=[IndicatorOut.model_validate(i) for i in a.indicators],
        ml=MlOut(
            available=a.ml_probability is not None,
            probability=a.ml_probability,
            model_version=a.ml_model_version,
            top_terms=a.ml_top_terms or [],
        ),
        recommended_action=a.recommended_action,
        link_count=a.link_count,
        attachment_count=a.attachment_count,
        intel=IntelSummaryOut(**vars(intel)) if intel else None,
    )


@router.post("/analyze", response_model=PhishingAnalysisOut)
@limiter.limit("20/minute")
def analyze_email(
    request: Request,
    payload: PhishingAnalyzeRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    parsed = (
        parse_raw(payload.raw_email)
        if payload.raw_email and payload.raw_email.strip()
        else parse_fields(payload.sender, payload.subject, payload.body_text, payload.body_html)
    )
    intel_summary: list[IntelSummary] = []

    def enrich(links):
        try:
            indicators, summary = link_indicators(db, links)
        except Exception:  # reputation lookups are best-effort and must never block analysis
            logging.getLogger("ascent.intel").exception("Threat-intel enrichment failed")
            indicators, summary = [], IntelSummary(note="Threat-intelligence lookup failed.")
        intel_summary.append(summary)
        return indicators

    result = engine.analyze(parsed, intel=enrich if payload.check_threat_intel else None)

    analysis = PhishingAnalysis(
        user_id=user.id,
        sender=(parsed.sender_raw or None) and parsed.sender_raw[:320],
        subject=parsed.subject[:200] or None,
        content_sha256=result.content_sha256,
        risk_score=result.risk_score,
        rule_score=result.rule_score,
        classification=result.classification,
        ml_probability=result.ml.probability if result.ml else None,
        ml_model_version=result.ml.model_version if result.ml else None,
        ml_top_terms=result.ml.top_terms if result.ml else None,
        reasons=result.reasons,
        recommended_action=result.recommended_action,
        link_count=result.link_count,
        attachment_count=result.attachment_count,
        indicators=[
            PhishingIndicator(
                code=i.code,
                category=i.category,
                severity=i.severity,
                weight=i.weight,
                description=i.description,
                evidence=i.evidence,
            )
            for i in result.indicators
        ],
    )
    db.add(analysis)
    db.flush()
    audit.record(
        db,
        "phishing.analyze",
        request,
        user.id,
        {
            "analysis_id": str(analysis.id),
            "classification": result.classification,
            "risk_score": result.risk_score,
        },
    )
    db.commit()
    db.refresh(analysis)
    return _to_out(analysis, intel_summary[0] if intel_summary else None)


@router.get("/analyses", response_model=PhishingAnalysisPage)
def list_analyses(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    mine = PhishingAnalysis.user_id == user.id
    total = db.scalar(select(func.count(PhishingAnalysis.id)).where(mine)) or 0
    rows = db.scalars(
        select(PhishingAnalysis)
        .where(mine)
        .order_by(PhishingAnalysis.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return PhishingAnalysisPage(
        items=[PhishingAnalysisSummary.model_validate(r, from_attributes=True) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/analyses/{analysis_id}", response_model=PhishingAnalysisOut)
def get_analysis(
    analysis_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    analysis = db.get(PhishingAnalysis, analysis_id)
    if analysis is None or analysis.user_id != user.id:  # same response: don't reveal others' ids
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    return _to_out(analysis)
