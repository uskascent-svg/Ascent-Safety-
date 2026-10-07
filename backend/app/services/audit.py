import uuid

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog


def record(
    db: Session,
    action: str,
    request: Request | None = None,
    user_id: uuid.UUID | None = None,
    details: dict | None = None,
) -> None:
    """Add an audit row to the session. The caller commits."""
    db.add(
        AuditLog(
            user_id=user_id,
            action=action,
            ip_address=request.client.host if request and request.client else None,
            user_agent=(request.headers.get("user-agent", "")[:255] if request else None),
            details=details,
        )
    )
