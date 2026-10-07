from datetime import UTC

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.limiter import limiter
from app.database.session import get_db
from app.models import (
    ReportStatus,
    ReportType,
    RoleName,
    SecurityReport,
    SecurityReportNote,
    Severity,
    User,
)
from app.models.operations import record_report_activity
from app.schemas.reports import (
    AdminReportOut,
    AdminReportPage,
    AdminReportUpdate,
    ReportActivityOut,
    ReportCreate,
    ReportOut,
    ReportPage,
    ReportPromotion,
)
from app.schemas.security import SecurityEventCreate
from app.security.deps import get_current_user, require_roles
from app.services import audit
from app.services.event_ingest import DuplicateEvent, publish, store_event

router = APIRouter(prefix="/api/reports", tags=["reports"])

_TRANSITIONS = {
    ReportStatus.SUBMITTED.value: {ReportStatus.UNDER_REVIEW.value},
    ReportStatus.UNDER_REVIEW.value: {
        ReportStatus.INVESTIGATING.value,
        ReportStatus.RESOLVED.value,
        ReportStatus.FALSE_POSITIVE.value,
    },
    ReportStatus.INVESTIGATING.value: {
        ReportStatus.UNDER_REVIEW.value,
        ReportStatus.RESOLVED.value,
        ReportStatus.FALSE_POSITIVE.value,
    },
    ReportStatus.RESOLVED.value: {ReportStatus.REOPENED.value},
    ReportStatus.FALSE_POSITIVE.value: {ReportStatus.REOPENED.value},
    ReportStatus.REOPENED.value: {
        ReportStatus.UNDER_REVIEW.value,
        ReportStatus.INVESTIGATING.value,
        ReportStatus.RESOLVED.value,
        ReportStatus.FALSE_POSITIVE.value,
    },
}


def _admin_out(report: SecurityReport) -> AdminReportOut:
    return AdminReportOut(
        **{
            **ReportOut.model_validate(report).model_dump(),
            "timeline": [
                ReportActivityOut(
                    action=item.action,
                    summary=item.summary,
                    created_at=item.created_at,
                    actor_name=item.actor.full_name if item.actor else None,
                )
                for item in report.activities
            ],
        },
        reporter_id=report.reporter_id,
        reporter_name=report.reporter.full_name,
        reporter_email=report.reporter.email,
        assigned_to_id=report.assigned_to_id,
        assigned_to_name=report.assigned_to.full_name if report.assigned_to else None,
        internal_notes=[
            {
                "content": note.content,
                "created_at": note.created_at,
                "author": note.author.full_name,
            }
            for note in sorted(report.notes, key=lambda item: (item.created_at, str(item.id)))
        ],
        promoted_event_id=report.promoted_event_id,
    )


def _reporter_out(report: SecurityReport) -> ReportOut:
    result = ReportOut.model_validate(report)
    result.timeline = [
        ReportActivityOut(
            action=item.action,
            summary=item.summary,
            created_at=item.created_at,
            actor_name=None,
        )
        for item in report.activities
        if item.is_public
    ]
    return result


@router.post("", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/hour")
def create_report(
    request: Request,
    payload: ReportCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    report = SecurityReport(
        reporter_id=user.id,
        issue_type=payload.issue_type.value,
        title=payload.title,
        description=payload.description,
        suspicious_url=str(payload.suspicious_url) if payload.suspicious_url else None,
        source_location=payload.source_location,
        reported_at=payload.reported_at,
        severity=payload.severity.value,
        additional_notes=payload.additional_notes,
        status=ReportStatus.SUBMITTED.value,
    )
    db.add(report)
    db.flush()
    record_report_activity(db, report.id, "submitted", "Report submitted", user.id, is_public=True)
    audit.record(
        db,
        "security_report.submit",
        request,
        user.id,
        {"report_code": report.report_code, "issue_type": report.issue_type},
    )
    db.commit()
    db.refresh(report)
    return _reporter_out(report)


@router.get("/mine", response_model=ReportPage)
def list_my_reports(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    base = select(SecurityReport).where(SecurityReport.reporter_id == user.id)
    total = (
        db.scalar(
            select(func.count(SecurityReport.id)).where(SecurityReport.reporter_id == user.id)
        )
        or 0
    )
    reports = db.scalars(
        base.order_by(SecurityReport.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return ReportPage(
        items=[_reporter_out(item) for item in reports], total=total, limit=limit, offset=offset
    )


@router.get("/mine/{report_code}", response_model=ReportOut)
def get_my_report(
    report_code: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    report = db.scalar(
        select(SecurityReport).where(
            SecurityReport.report_code == report_code,
            SecurityReport.reporter_id == user.id,
        )
    )
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    return _reporter_out(report)


@router.get("/admin", response_model=AdminReportPage)
def list_reports(
    report_status: list[ReportStatus] = Query(default=[], alias="status"),
    severity: list[Severity] = Query(default=[]),
    issue_type: list[ReportType] = Query(default=[]),
    q: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(RoleName.ADMINISTRATOR)),
):
    where = []
    if report_status:
        where.append(SecurityReport.status.in_([item.value for item in report_status]))
    if severity:
        where.append(SecurityReport.severity.in_([item.value for item in severity]))
    if issue_type:
        where.append(SecurityReport.issue_type.in_([item.value for item in issue_type]))
    if q:
        needle = q.strip()
        if needle:
            where.append(
                or_(
                    SecurityReport.report_code.icontains(needle, autoescape=True),
                    SecurityReport.title.icontains(needle, autoescape=True),
                    SecurityReport.description.icontains(needle, autoescape=True),
                    SecurityReport.suspicious_url.icontains(needle, autoescape=True),
                )
            )
    total = db.scalar(select(func.count(SecurityReport.id)).where(*where)) or 0
    reports = db.scalars(
        select(SecurityReport)
        .where(*where)
        .order_by(SecurityReport.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return AdminReportPage(
        items=[_admin_out(report) for report in reports],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.patch("/admin/{report_code}", response_model=AdminReportOut)
def update_report(
    request: Request,
    report_code: str,
    payload: AdminReportUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(RoleName.ADMINISTRATOR)),
):
    if not payload.model_fields_set:
        raise HTTPException(422, "At least one update is required")
    report = db.scalar(select(SecurityReport).where(SecurityReport.report_code == report_code))
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")

    changed: list[str] = []
    audit_changes: dict[str, object] = {}
    if "status" in payload.model_fields_set and payload.status is not None:
        new_status = payload.status.value
        if new_status not in _TRANSITIONS[report.status]:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Cannot transition report from {report.status} to {new_status}",
            )
        old_status = report.status
        report.status = new_status
        record_report_activity(
            db,
            report.id,
            "status_changed",
            f"Status updated to {new_status.replace('_', ' ')}",
            user.id,
            is_public=True,
        )
        audit_changes["status"] = {"from": old_status, "to": new_status}
        changed.append("status")

    if "assigned_to_id" in payload.model_fields_set:
        assigned_id = payload.assigned_to_id
        if assigned_id is not None:
            assignee = db.get(User, assigned_id)
            if assignee is None or not assignee.is_active or assignee.deleted_at is not None:
                raise HTTPException(422, "Assignee is not active")
            if not {RoleName.ADMINISTRATOR.value, RoleName.SECURITY_ANALYST.value} & {
                role.name for role in assignee.roles
            }:
                raise HTTPException(422, "Assignee must be an analyst or administrator")
        old_assignee_id = report.assigned_to_id
        report.assigned_to_id = assigned_id
        record_report_activity(
            db, report.id, "assignment_changed", "Analyst assignment updated", user.id
        )
        audit_changes["assigned_to_id"] = {
            "from": str(old_assignee_id) if old_assignee_id else None,
            "to": str(assigned_id) if assigned_id else None,
        }
        changed.append("assignment")

    if payload.internal_note:
        note = SecurityReportNote(
            report_id=report.id, author_id=user.id, content=payload.internal_note
        )
        db.add(note)
        report.notes.append(note)
        record_report_activity(db, report.id, "internal_note", "Internal note added", user.id)
        audit_changes["internal_note_added"] = True
        changed.append("internal_note")

    audit.record(
        db,
        "security_report.manage",
        request,
        user.id,
        {"report_code": report.report_code, "changed": changed, "changes": audit_changes},
    )
    db.commit()
    db.refresh(report)
    return _admin_out(report)


@router.post(
    "/admin/{report_code}/promote",
    response_model=AdminReportOut,
    status_code=status.HTTP_201_CREATED,
)
def promote_report(
    request: Request,
    report_code: str,
    payload: ReportPromotion,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(RoleName.ADMINISTRATOR)),
):
    report = db.scalar(select(SecurityReport).where(SecurityReport.report_code == report_code))
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    if report.promoted_event_id is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Report has already been promoted")
    if report.status not in {ReportStatus.UNDER_REVIEW.value, ReportStatus.INVESTIGATING.value}:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Only reports under active review can be promoted"
        )

    event_payload = SecurityEventCreate(
        source="reviewed_user_report",
        external_id=report.report_code,
        threat_type=payload.threat_type,
        severity=report.severity,
        status="open",
        title=payload.title,
        description=payload.description,
        country=payload.country,
        region=payload.region,
        latitude=payload.latitude,
        longitude=payload.longitude,
        occurred_at=(
            report.reported_at
            if report.reported_at.tzinfo is not None
            else report.reported_at.replace(tzinfo=UTC)
        ),
    )
    try:
        event = store_event(
            db,
            event_payload,
            request,
            {"report_code": report.report_code, "promoted_by": str(user.id)},
        )
    except DuplicateEvent:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Report already has a promoted event"
        ) from None
    report.promoted_event_id = event.id
    record_report_activity(
        db,
        report.id,
        "promoted",
        "A reviewed security event was published",
        user.id,
        is_public=True,
    )
    audit.record(
        db,
        "security_report.promote",
        request,
        user.id,
        {
            "report_code": report.report_code,
            "event_id": str(event.id),
            "content_reviewed": payload.content_reviewed,
            "location_verified": payload.location_verified,
            "coordinates_precision": 2,
        },
    )
    db.commit()
    db.refresh(report)
    publish(event)
    return _admin_out(report)
