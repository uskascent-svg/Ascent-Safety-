import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.limiter import limiter
from app.database.session import get_db
from app.models import Endpoint, RoleName, User
from app.schemas.endpoint import (
    BatchResult,
    EndpointCreate,
    EndpointCreated,
    EndpointOut,
    TelemetryBatch,
)
from app.security.api_keys import hash_api_key, new_api_key
from app.security.deps import analyst_or_admin, require_roles
from app.services import audit
from app.services.endpoint_ingest import process_batch

router = APIRouter(tags=["endpoints"])
admin_only = require_roles(RoleName.ADMINISTRATOR)


def _get(db: Session, endpoint_id: uuid.UUID) -> Endpoint:
    ep = db.get(Endpoint, endpoint_id)
    if ep is None or ep.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Endpoint not found")
    return ep


# ---------------- management (administrators) ----------------
@router.post("/api/endpoints", response_model=EndpointCreated, status_code=status.HTTP_201_CREATED)
def register_endpoint(
    request: Request,
    payload: EndpointCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_only),
):
    if db.scalar(select(Endpoint.id).where(Endpoint.name == payload.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "An endpoint with this name already exists")
    key, prefix, key_hash = new_api_key("ascent_ep")
    data = payload.model_dump()
    data["os"] = payload.os.value
    ep = Endpoint(**data, key_prefix=prefix, key_hash=key_hash, created_by=admin.id)
    db.add(ep)
    db.flush()
    audit.record(
        db, "endpoint.create", request, admin.id, {"endpoint_id": str(ep.id), "name": ep.name}
    )
    db.commit()
    return EndpointCreated(endpoint=EndpointOut.model_validate(ep), api_key=key)


@router.post("/api/endpoints/{endpoint_id}/rotate-key", response_model=EndpointCreated)
def rotate_key(
    request: Request,
    endpoint_id: uuid.UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_only),
):
    ep = _get(db, endpoint_id)
    key, ep.key_prefix, ep.key_hash = new_api_key("ascent_ep")
    audit.record(db, "endpoint.rotate_key", request, admin.id, {"endpoint_id": str(ep.id)})
    db.commit()
    return EndpointCreated(endpoint=EndpointOut.model_validate(ep), api_key=key)


@router.delete("/api/endpoints/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_endpoint(
    request: Request,
    endpoint_id: uuid.UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_only),
):
    ep = _get(db, endpoint_id)
    ep.is_active, ep.deleted_at = False, datetime.now(UTC)  # soft delete
    audit.record(db, "endpoint.deactivate", request, admin.id, {"endpoint_id": str(ep.id)})
    db.commit()


@router.get("/api/endpoints", response_model=list[EndpointOut])
def list_endpoints(db: Session = Depends(get_db), _: User = Depends(analyst_or_admin)):
    return db.scalars(
        select(Endpoint).where(Endpoint.deleted_at.is_(None)).order_by(Endpoint.name)
    ).all()


# ---------------- telemetry ingestion (agents) ----------------
def authenticate_endpoint(
    x_endpoint_key: str | None = Header(default=None), db: Session = Depends(get_db)
) -> Endpoint:
    ep = None
    if x_endpoint_key:
        ep = db.scalar(select(Endpoint).where(Endpoint.key_hash == hash_api_key(x_endpoint_key)))
    if ep is None or not ep.is_active or ep.deleted_at is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid endpoint key")
    return ep


@router.post("/api/endpoint-telemetry", response_model=BatchResult)
@limiter.limit("120/minute")
def ingest_telemetry(
    request: Request,
    batch: TelemetryBatch,
    db: Session = Depends(get_db),
    endpoint: Endpoint = Depends(authenticate_endpoint),
):
    """Agents report observed behaviour. Only detector findings are stored, never raw telemetry."""
    return process_batch(db, endpoint, batch.observations, request)
