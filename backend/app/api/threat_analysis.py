import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.limiter import limiter
from app.database.session import get_db
from app.detection.phishing.engine import get_classifier
from app.detection.phishing.ml import ML_DECISION_THRESHOLD
from app.detection.phishing.parser import parse_fields
from app.detection.phishing.rules import run_rules
from app.detection.phishing.text import find_phrases, model_text
from app.detection.phishing.urls import extract_links
from app.models import (
    RoleName,
    ThreatAnalysis,
    ThreatFeedback,
    ThreatModelVersion,
    ThreatTrainingJob,
    User,
)
from app.schemas.threat_analysis import (
    ThreatAnalysisOut,
    ThreatAnalysisPage,
    ThreatAnalyzeRequest,
    ThreatFeedbackCreate,
    ThreatFeedbackOut,
    ThreatFeedbackReview,
    ThreatFeedbackReviewItem,
    ThreatFinding,
    ThreatMetrics,
    ThreatModelReject,
)
from app.security.deps import get_current_user, require_roles
from app.services import audit
from app.services.threat_training import (
    TrainingUnavailable,
    _decrypt_sample,
    encrypt_sample,
    evaluate_for_promotion,
    run_training_job,
)

router = APIRouter(prefix="/api/threat-analysis", tags=["threat-analysis"])
reviewer_only = require_roles(RoleName.ADMINISTRATOR, RoleName.THREAT_DATA_REVIEWER)
model_operator_only = require_roles(RoleName.ADMINISTRATOR, RoleName.THREAT_MODEL_OPERATOR)
threat_dashboard_access = require_roles(
    RoleName.ADMINISTRATOR,
    RoleName.THREAT_MONITOR,
    RoleName.THREAT_DATA_REVIEWER,
    RoleName.THREAT_MODEL_OPERATOR,
)
_URGENCY = re.compile(
    r"\b(urgent|immediately|within \d+ (?:minutes?|hours?)|"
    r"account (?:will be|has been) (?:closed|suspended|locked))\b",
    re.I,
)
_CREDENTIAL = re.compile(
    r"\b(password|passcode|one.time code|verification code|sign in|log in|credentials)\b", re.I
)
_PAYMENT = re.compile(
    r"\b(wire transfer|gift cards?|crypto(?:currency)?|bank details|payment)\b", re.I
)
_EXEC = re.compile(
    r"\b(powershell|cmd\.exe|wscript|cscript|rundll32|regsvr32|mshta|certutil|downloadstring|invoke-expression)\b",
    re.I,
)
MAX_UPLOAD_BYTES = min(
    50 * 1024 * 1024, int(os.getenv("THREAT_ANALYSIS_MAX_BYTES", str(12 * 1024 * 1024)))
)
PARSE_TIMEOUT_SECONDS = min(120, max(1, int(os.getenv("THREAT_ANALYSIS_PARSE_TIMEOUT", "20"))))
MAX_CONCURRENT_PARSES = min(64, max(1, int(os.getenv("THREAT_ANALYSIS_MAX_CONCURRENT", "4"))))
_PARSE_LOCK = threading.Lock()
_ACTIVE_PARSES = 0
_WORKER_PATH = Path(__file__).parents[1] / "workers" / "threat_extract_worker.py"
log = logging.getLogger("ascent.threat_analysis")


def _extract_file(filename: str, raw: bytes) -> dict:
    global _ACTIVE_PARSES
    from app.workers import threat_extract_worker

    ext = Path(filename).suffix.lower()
    problem = threat_extract_worker.validate_content(ext, raw)
    if problem:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, problem[1])
    with _PARSE_LOCK:
        if _ACTIVE_PARSES >= MAX_CONCURRENT_PARSES:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Analysis capacity reached; retry shortly.",
                headers={"Retry-After": "5"},
            )
        _ACTIVE_PARSES += 1
    env = {
        key: os.environ[key]
        for key in ("PATH", "LANG", "SYSTEMROOT", "TESSDATA_PREFIX")
        if key in os.environ
    }
    env.update(
        {
            "ASCENT_WORKER_MEM_BYTES": str(768 * 1024 * 1024),
            "ASCENT_WORKER_CPU_SECONDS": str(PARSE_TIMEOUT_SECONDS + 5),
            "ASCENT_WORKER_OCR_TIMEOUT": str(max(1, PARSE_TIMEOUT_SECONDS - 2)),
            "OMP_THREAD_LIMIT": "1",
        }
    )
    try:
        # Static interpreter/worker paths only; uploaded bytes go over stdin, never a shell.
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-I", str(_WORKER_PATH), ext],
            input=raw,
            capture_output=True,
            timeout=PARSE_TIMEOUT_SECONDS,
            env=env,
            cwd=tempfile.gettempdir(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "failed",
            "text": "",
            "indicators": [],
            "error_code": "timeout",
            "notes": ["Parsing exceeded the time limit and was terminated."],
        }
    except OSError:
        return {
            "status": "failed",
            "text": "",
            "indicators": [],
            "error_code": "worker_unavailable",
            "notes": ["The isolated parser could not be started."],
        }
    finally:
        with _PARSE_LOCK:
            _ACTIVE_PARSES -= 1
    if proc.returncode != 0 or not 0 < len(proc.stdout) <= 4 * 1024 * 1024:
        return {
            "status": "failed",
            "text": "",
            "indicators": [],
            "error_code": "worker_failed",
            "notes": ["The parser failed or exceeded a resource limit."],
        }
    try:
        result = json.loads(proc.stdout)
    except (ValueError, UnicodeDecodeError):
        result = None
    if not isinstance(result, dict) or result.get("status") not in {
        "ok",
        "no_text",
        "failed",
        "limit",
    }:
        return {
            "status": "failed",
            "text": "",
            "indicators": [],
            "error_code": "worker_failed",
            "notes": ["The parser returned an invalid result."],
        }
    return result


def _analyze(
    payload: ThreatAnalyzeRequest,
) -> tuple[
    str,
    str,
    int,
    list[ThreatFinding],
    str,
    str,
    str,
    str | None,
    float | None,
    int,
    str,
    str | None,
]:
    text = payload.text.strip()
    hits: list[ThreatFinding] = []
    if payload.input_kind == "url":
        parsed = urlparse(text)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "Provide a valid HTTP or HTTPS URL"
            )
    parsed = parse_fields(None, None, text, None)
    links = extract_links(parsed.text, parsed.html)
    indicators = run_rules(parsed, links, find_phrases(parsed.subject + "\n" + parsed.text))
    for indicator in indicators:
        hits.append(
            ThreatFinding(
                detector="phishing_rules",
                code=indicator.code,
                severity=indicator.severity,
                title=indicator.description,
                explanation=indicator.description,
                evidence=indicator.evidence
                or ["Rule indicator matched; submitted content is not retained"],
            )
        )

    for code, pattern, severity, title, explanation in (
        (
            "TEXT_URGENCY",
            _URGENCY,
            "medium",
            "Urgent or coercive language",
            "Urgency can pressure a recipient to skip independent verification.",
        ),
        (
            "TEXT_CREDENTIAL_REQUEST",
            _CREDENTIAL,
            "medium",
            "Credential-related language",
            "The content refers to credentials or sign-in; verify requests through "
            "a trusted channel.",
        ),
        (
            "TEXT_PAYMENT_REQUEST",
            _PAYMENT,
            "high",
            "Payment or value-transfer language",
            "The content mentions payment or transferable value; verify unusual "
            "requests independently.",
        ),
        (
            "TEXT_EXECUTABLE_COMMAND",
            _EXEC,
            "high",
            "Executable or scripting command indicator",
            "The content mentions a command interpreter or script utility; do not "
            "run untrusted commands.",
        ),
    ):
        if pattern.search(text):
            hits.append(
                ThreatFinding(
                    detector="text_rules",
                    code=code,
                    severity=severity,
                    title=title,
                    explanation=explanation,
                    evidence=["Matching phrase detected; submitted content is not retained"],
                )
            )

    score = min(
        100,
        sum({"critical": 35, "high": 24, "medium": 13, "low": 5}.get(h.severity, 0) for h in hits),
    )
    rule_indicator_count = len(hits)
    model_result = None
    try:
        classifier = get_classifier()
        if classifier.available:
            model_result = classifier.predict(model_text(parsed.subject, parsed.text))
    except Exception:
        # Detector loading/inference must fail closed to the existing rules.
        log.exception("Optional threat model unavailable; completing analysis with rules only")
    combined_score = (
        round(0.7 * score + 0.3 * model_result.probability * 100)
        if model_result is not None
        else score
    )
    if model_result is not None and model_result.probability >= ML_DECISION_THRESHOLD:
        hits.append(
            ThreatFinding(
                detector=model_result.model_family,
                code="MODEL_MALICIOUS_SCORE",
                severity="medium",
                title="Text classifier flagged malicious-content patterns",
                explanation=(
                    "The active text classifier crossed its evaluated malicious-class cutoff. "
                    "This confidence is not calibrated and is not proof of compromise."
                ),
                evidence=[
                    f"Model score {model_result.probability:.3f} · "
                    f"version {model_result.model_version}"
                ],
            )
        )
    if hits:
        verdict = "suspicious"
        severity = "high" if combined_score >= 50 else "medium" if combined_score >= 20 else "low"
    else:
        verdict, severity = "unknown", "unknown"
    completeness = "partial" if payload.input_kind == "document_text" else "complete"
    explanation = (
        f"{rule_indicator_count} "
        "rule indicator(s) matched. "
        + (
            f"The {model_result.model_family} model returned an uncalibrated malicious-class "
            f"score of {model_result.probability:.3f} (version {model_result.model_version}). "
            if model_result
            else "No active machine-learning model was available; rules-only fallback was used. "
        )
        + "This triage is not a malware scan or guarantee."
        if hits
        else "No configured indicators matched. The result is unknown and does not "
        "establish that the content is safe."
    )
    remediation = (
        "Do not interact with suspicious content; verify requests through an "
        "independent trusted channel and report concerns to your security team."
    )
    return (
        verdict,
        severity,
        score,
        hits,
        explanation,
        remediation,
        completeness,
        model_result.model_version if model_result else None,
        model_result.probability if model_result else None,
        combined_score,
        "hybrid" if model_result else "rules_only",
        model_result.model_family if model_result else None,
    )


def _out(row: ThreatAnalysis) -> ThreatAnalysisOut:
    return ThreatAnalysisOut(
        id=row.id,
        created_at=row.created_at,
        verdict=row.verdict,
        severity=row.severity,
        heuristic_score=row.heuristic_score,
        score_type="hybrid" if row.detector_mode == "hybrid" else "heuristic",
        detector_mode=row.detector_mode,
        model_version=row.model_version,
        model_family=row.model_family,
        model_confidence=row.model_confidence,
        combined_score=row.combined_score,
        completeness=row.completeness,
        input_kind=row.input_kind,
        findings=row.findings,
        explanation=row.explanation,
        remediation=row.remediation,
        extraction_status=row.extraction_status,
        extraction_notes=row.extraction_notes,
    )


@router.post("/analyze", response_model=ThreatAnalysisOut)
@limiter.limit("20/minute")
def analyze(
    request: Request,
    payload: ThreatAnalyzeRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    (
        verdict, severity, score, hits, explanation, remediation, completeness,
        model_version, model_confidence, combined_score, detector_mode, model_family,
    ) = _analyze(payload)
    row = ThreatAnalysis(
        user_id=user.id,
        content_sha256=hashlib.sha256(payload.text.encode()).hexdigest(),
        input_kind=payload.input_kind,
        verdict=verdict,
        severity=severity,
        heuristic_score=score,
        combined_score=combined_score,
        detector_mode=detector_mode,
        model_version=model_version,
        model_confidence=model_confidence,
        model_family=model_family,
        completeness=completeness,
        findings=[hit.model_dump() for hit in hits],
        explanation=explanation,
        remediation=remediation,
        extraction_status="not_applicable",
        extraction_notes=[],
    )
    db.add(row)
    db.flush()
    audit.record(
        db,
        "threat_analysis.analyze",
        request,
        user.id,
        {"analysis_id": str(row.id), "verdict": verdict, "finding_count": len(hits)},
    )
    db.commit()
    db.refresh(row)
    return _out(row)


@router.post("/analyze-file", response_model=ThreatAnalysisOut)
@limiter.limit("10/minute")
async def analyze_file(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    filename = (file.filename or "upload").replace("\\", "/").rsplit("/", 1)[-1][:180]
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if not raw:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "The uploaded file is empty")
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Upload exceeds the configured size limit"
        )
    extracted = _extract_file(filename, raw)
    text = extracted.get("text", "")
    if len(text) > 100_000:
        text = text[:100_000]
        extracted.setdefault("notes", []).append(
            "Extracted text was truncated to the analysis limit."
        )
    if len(text.strip()) >= 20:
        payload = ThreatAnalyzeRequest(text=text, input_kind="document_text")
        (
            verdict, severity, score, hits, explanation, remediation, _,
            model_version, model_confidence, combined_score, detector_mode, model_family,
        ) = _analyze(payload)
    else:
        verdict, severity, score, hits = "unknown", "unknown", 0, []
        model_version = model_confidence = model_family = None
        combined_score, detector_mode = 0, "rules_only"
        explanation = "No usable text was extracted. The file remains unclassified."
        remediation = (
            "Use a supported format with extractable content or submit it to your security team."
        )
    for code in extracted.get("indicators", []):
        hits.append(
            ThreatFinding(
                detector="document_structure",
                code=code,
                severity="high",
                title="Potentially active or embedded document content",
                explanation=(
                    "The document contains a structure commonly associated with active "
                    "content or embedded objects."
                ),
                evidence=["Structural indicator; document content is not executed"],
            )
        )
    if extracted.get("indicators"):
        verdict, severity = "suspicious", "high"
        score = min(100, max(score, 50))
        combined_score = min(100, max(combined_score, 50))
    if extracted["status"] not in {"ok", "no_text"} and not extracted.get("indicators"):
        verdict, severity = "unknown", "unknown"
        explanation = "Extraction was incomplete; this result does not classify the file as safe."
    row = ThreatAnalysis(
        user_id=user.id,
        content_sha256=hashlib.sha256(raw).hexdigest(),
        input_kind="document_text",
        verdict=verdict,
        severity=severity,
        heuristic_score=score,
        combined_score=combined_score,
        detector_mode=detector_mode,
        model_version=model_version,
        model_confidence=model_confidence,
        model_family=model_family,
        completeness="complete" if extracted["status"] == "ok" else "partial",
        findings=[hit.model_dump() for hit in hits],
        explanation=explanation,
        remediation=remediation,
        extraction_status=extracted["status"],
        extraction_notes=extracted.get("notes", []),
    )
    db.add(row)
    db.flush()
    audit.record(
        db,
        "threat_analysis.upload",
        request,
        user.id,
        {
            "analysis_id": str(row.id),
            "verdict": verdict,
            "extraction_status": extracted["status"],
            "file_size": len(raw),
        },
    )
    db.commit()
    db.refresh(row)
    return _out(row)


@router.get("/analyses", response_model=ThreatAnalysisPage)
def list_analyses(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    scope = ThreatAnalysis.user_id == user.id
    total = db.scalar(select(func.count(ThreatAnalysis.id)).where(scope)) or 0
    rows = db.scalars(
        select(ThreatAnalysis)
        .where(scope)
        .order_by(ThreatAnalysis.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    from app.schemas.threat_analysis import ThreatAnalysisPage, ThreatAnalysisSummary

    return ThreatAnalysisPage(
        items=[ThreatAnalysisSummary.model_validate(row, from_attributes=True) for row in rows],
        total=total,
    )


@router.get("/analyses/{analysis_id}", response_model=ThreatAnalysisOut)
def get_analysis(
    analysis_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    row = db.get(ThreatAnalysis, analysis_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    return _out(row)


@router.delete("/analyses/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_analysis(
    analysis_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    row = db.scalar(
        select(ThreatAnalysis).where(
            ThreatAnalysis.id == analysis_id, ThreatAnalysis.user_id == user.id
        )
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    audit.record(db, "threat_analysis.delete", request, user.id, {"analysis_id": str(analysis_id)})
    db.delete(row)
    db.commit()
    return None


@router.get("/admin/metrics", response_model=ThreatMetrics)
def metrics(
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db),
    _: User = Depends(threat_dashboard_access),
):
    start = datetime.now(UTC) - timedelta(days=days)
    rows = db.execute(
        select(ThreatAnalysis.verdict, ThreatAnalysis.severity, func.count(ThreatAnalysis.id))
        .where(ThreatAnalysis.created_at >= start)
        .group_by(ThreatAnalysis.verdict, ThreatAnalysis.severity)
    ).all()
    by_verdict = {key: 0 for key in ("malicious", "suspicious", "benign", "unknown")}
    by_severity = {key: 0 for key in ("critical", "high", "medium", "low", "unknown")}
    for verdict, severity, count in rows:
        by_verdict[verdict] = by_verdict.get(verdict, 0) + count
        by_severity[severity] = by_severity.get(severity, 0) + count
    mode_rows = db.execute(
        select(ThreatAnalysis.detector_mode, func.count(ThreatAnalysis.id))
        .where(ThreatAnalysis.created_at >= start)
        .group_by(ThreatAnalysis.detector_mode)
    ).all()
    detector_modes = {mode: count for mode, count in mode_rows}
    return ThreatMetrics(
        window_days=days,
        total=sum(by_verdict.values()),
        by_verdict=by_verdict,
        by_severity=by_severity,
        heuristic_only=detector_modes.get("hybrid", 0) == 0,
        detector_modes=detector_modes,
    )


@router.get("/admin/dashboard")
def admin_dashboard(
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db),
    _: User = Depends(threat_dashboard_access),
):
    summary = metrics(days=days, db=db, _=None)
    active = _active_model_status(db)
    classifier = get_classifier()
    return {
        "refreshed_at": datetime.now(UTC),
        "window_days": summary.window_days,
        "total": summary.total,
        "by_verdict": summary.by_verdict,
        "by_severity": summary.by_severity,
        "detection_quality": (
            active.get("metrics", {}).get("promotion_evaluation")
            if active["state"] == "active" and classifier.version == active.get("version")
            else None
        ),
        "source": "persisted user threat analyses",
        "note": (
            "Analysis counts are persisted hybrid-analyzer records. Detection-quality metrics "
            "come only from an active artifact's independent promotion evaluation; they do not "
            "measure rule behavior. Runtime model availability and identity are reported "
            "separately."
        ),
        "model_status": active,
        "detector_runtime": {
            "state": "model_ready" if classifier.available else "rules_only",
            "model_family": classifier.model_family,
            "model_version": classifier.version,
        },
    }


def _active_model_status(db: Session) -> dict:
    row = db.scalar(select(ThreatModelVersion).where(ThreatModelVersion.state == "active"))
    if row is None:
        return {"state": "rules_only", "version": None}
    return {
        "state": "active",
        "version": row.version,
        "model_family": row.model_family or "legacy_classifier",
        "metrics": row.metrics,
    }


@router.post(
    "/analyses/{analysis_id}/feedback",
    response_model=ThreatFeedbackOut,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("10/minute")
def submit_feedback(
    analysis_id: uuid.UUID,
    payload: ThreatFeedbackCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    analysis = db.scalar(
        select(ThreatAnalysis).where(
            ThreatAnalysis.id == analysis_id, ThreatAnalysis.user_id == user.id
        )
    )
    if analysis is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    exists = db.scalar(
        select(ThreatFeedback.id).where(
            ThreatFeedback.analysis_id == analysis_id,
            ThreatFeedback.user_id == user.id,
        )
    )
    if exists:
        raise HTTPException(status.HTTP_409_CONFLICT, "Feedback was already submitted")
    encrypted_sample = None
    if payload.include_in_training:
        try:
            encrypted_sample = encrypt_sample(payload.training_sample)
        except TrainingUnavailable as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None
    row = ThreatFeedback(
        analysis_id=analysis_id,
        user_id=user.id,
        candidate_label=payload.candidate_label,
        reason=payload.reason.strip(),
        training_sample_encrypted=encrypted_sample,
        status="pending",
    )
    db.add(row)
    db.flush()
    audit.record(
        db,
        "threat_analysis.feedback_submit",
        request,
        user.id,
        {"analysis_id": str(analysis_id), "candidate_label": payload.candidate_label},
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/admin/feedback", response_model=list[ThreatFeedbackReviewItem])
def list_feedback(
    request: Request,
    status_filter: str = Query(
        default="pending", alias="status", pattern="^(pending|approved|rejected)$"
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    reviewer: User = Depends(reviewer_only),
):
    rows = db.scalars(
        select(ThreatFeedback)
        .where(ThreatFeedback.status == status_filter)
        .order_by(ThreatFeedback.created_at.asc())
        .limit(limit)
        .offset(offset)
    ).all()
    output = []
    for row in rows:
        sample = None
        if row.training_sample_encrypted:
            try:
                sample = _decrypt_sample(row.training_sample_encrypted)
            except TrainingUnavailable as exc:
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None
        output.append(
            ThreatFeedbackReviewItem.model_validate(
                {
                    **row.__dict__,
                    "includes_training_sample": row.training_sample_encrypted is not None,
                    "training_sample": sample,
                },
                from_attributes=True,
            )
        )
    if any(item.training_sample is not None for item in output):
        audit.record(
            db,
            "threat_analysis.training_sample_review",
            request,
            reviewer.id,
            {"sample_count": sum(item.training_sample is not None for item in output)},
        )
        db.commit()
    return output


@router.post("/admin/feedback/{feedback_id}/review", response_model=ThreatFeedbackOut)
def review_feedback(
    feedback_id: uuid.UUID,
    payload: ThreatFeedbackReview,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(reviewer_only),
):
    row = db.get(ThreatFeedback, feedback_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Feedback not found")
    if row.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, "Feedback has already been reviewed")
    if row.user_id == admin.id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "A reviewer cannot approve their own feedback"
        )
    row.status = "approved" if payload.decision == "approve" else "rejected"
    row.reviewed_by_id = admin.id
    row.review_note = payload.note.strip()
    row.reviewed_at = datetime.now(UTC)
    audit.record(
        db,
        "threat_analysis.feedback_review",
        request,
        admin.id,
        {"feedback_id": str(row.id), "decision": payload.decision},
    )
    db.commit()
    db.refresh(row)
    return row


@router.post("/admin/training-jobs", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("2/hour")
def start_training(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    admin: User = Depends(model_operator_only),
):
    settings = get_settings()
    if not settings.threat_analysis_data_key or not settings.threat_analysis_model_hmac_key:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Encrypted samples and model signing must be configured before training.",
        )
    if not settings.threat_analysis_independent_test_set:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Training is blocked until an independent labeled evaluation set is configured.",
        )
    running = db.scalar(
        select(ThreatTrainingJob.id).where(ThreatTrainingJob.status.in_(("queued", "running")))
    )
    if running:
        raise HTTPException(status.HTTP_409_CONFLICT, "A training job is already active")
    job = ThreatTrainingJob(
        requested_by_id=admin.id,
        status="queued",
        message="Waiting for the candidate trainer.",
    )
    db.add(job)
    db.flush()
    audit.record(db, "threat_analysis.training_start", request, admin.id, {"job_id": str(job.id)})
    db.commit()
    background_tasks.add_task(run_training_job, job.id)
    return {"id": str(job.id), "status": job.status, "message": job.message}


@router.get("/admin/training-jobs/{job_id}")
def get_training_job(
    job_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(model_operator_only),
):
    job = db.get(ThreatTrainingJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Training job not found")
    return {
        "id": str(job.id),
        "status": job.status,
        "message": job.message,
        "sample_count": job.sample_count,
        "metrics": job.metrics,
        "model_version_id": str(job.model_version_id) if job.model_version_id else None,
        "created_at": job.created_at,
        "finished_at": job.finished_at,
    }


@router.get("/admin/models")
def list_models(
    db: Session = Depends(get_db),
    _: User = Depends(threat_dashboard_access),
):
    rows = db.scalars(
        select(ThreatModelVersion).order_by(ThreatModelVersion.created_at.desc())
    ).all()
    return [
        {
            "id": str(row.id),
            "version": row.version,
            "model_family": row.model_family or "legacy_classifier",
            "state": row.state,
            "metrics": row.metrics,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@router.post("/admin/models/{version_id}/reject")
def reject_model(
    version_id: uuid.UUID,
    payload: ThreatModelReject,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(model_operator_only),
):
    row = db.get(ThreatModelVersion, version_id)
    if row is None or row.state != "candidate":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Candidate model not found")
    row.state = "rejected"
    audit.record(
        db,
        "threat_analysis.model_reject",
        request,
        admin.id,
        {"model_version": row.version, "note": payload.note.strip()},
    )
    db.commit()
    return {"version": row.version, "state": row.state}


@router.post("/admin/models/{version_id}/promote")
def promote_model(
    version_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(model_operator_only),
):
    row = db.get(ThreatModelVersion, version_id)
    if row is None or row.state not in {"candidate", "superseded"}:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Promotable model version not found")
    try:
        metrics = evaluate_for_promotion(row)
    except TrainingUnavailable as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    active = db.scalars(
        select(ThreatModelVersion).where(ThreatModelVersion.state == "active")
    ).all()
    for current in active:
        current.state = "superseded"
    row.state = "active"
    row.metrics = {**row.metrics, "promotion_evaluation": metrics}
    audit.record(
        db,
        "threat_analysis.model_promote",
        request,
        admin.id,
        {"model_version": row.version, "metrics": metrics},
    )
    db.commit()
    return {"version": row.version, "state": row.state, "metrics": metrics}


@router.post("/admin/models/{version_id}/rollback")
def rollback_model(
    version_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(model_operator_only),
):
    row = db.get(ThreatModelVersion, version_id)
    if row is None or row.state != "superseded":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rollback target not found")
    try:
        metrics = evaluate_for_promotion(row)
    except TrainingUnavailable as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    active = db.scalars(
        select(ThreatModelVersion).where(ThreatModelVersion.state == "active")
    ).all()
    for current in active:
        current.state = "superseded"
    row.state = "active"
    audit.record(
        db,
        "threat_analysis.model_rollback",
        request,
        admin.id,
        {"model_version": row.version, "metrics": metrics},
    )
    db.commit()
    return {"version": row.version, "state": row.state, "metrics": metrics}


@router.post("/admin/retention/purge")
def purge_expired_analyses(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(model_operator_only),
):
    retention_days = min(3650, max(1, int(os.getenv("THREAT_ANALYSIS_RETENTION_DAYS", "30"))))
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    expired = (
        db.scalar(select(func.count(ThreatAnalysis.id)).where(ThreatAnalysis.created_at < cutoff))
        or 0
    )
    expired_ids = select(ThreatAnalysis.id).where(ThreatAnalysis.created_at < cutoff)
    # Delete linked feedback explicitly; SQLite test databases may not enable FK cascades.
    db.execute(delete(ThreatFeedback).where(ThreatFeedback.analysis_id.in_(expired_ids)))
    db.execute(delete(ThreatAnalysis).where(ThreatAnalysis.created_at < cutoff))
    audit.record(
        db,
        "threat_analysis.retention_purge",
        request,
        admin.id,
        {"deleted_analyses": expired, "retention_days": retention_days},
    )
    db.commit()
    return {"deleted_analyses": expired, "retention_days": retention_days}
