import asyncio
import hmac
import json
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.limiter import limiter
from app.database.session import get_db
from app.models import SecurityEvent, User
from app.schemas.security import (
    EventLocationList,
    SecurityEventCreate,
    SecurityEventOut,
    SecurityEventPage,
)
from app.schemas.threat_intel import LookupOut
from app.security.deps import analyst_for_stream, analyst_or_admin
from app.services.broker import RESYNC, broker
from app.services.event_ingest import DuplicateEvent, publish, store_event
from app.services.events import EventFilters, apply_filters, event_filters

router = APIRouter(prefix="/api/security-events", tags=["security-events"])


def require_ingest_key(x_ingest_key: str | None = Header(default=None)) -> None:
    expected = get_settings().ingest_api_key
    if not expected:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Event ingestion is not enabled")
    if not x_ingest_key or not hmac.compare_digest(x_ingest_key, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid ingest key")


@router.post(
    "",
    response_model=SecurityEventOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_ingest_key)],
)
@limiter.limit("600/minute")
def ingest_event(request: Request, payload: SecurityEventCreate, db: Session = Depends(get_db)):
    """Telemetry sources and detectors report real events here (machine-to-machine)."""
    try:
        event = store_event(db, payload, request)
    except DuplicateEvent:
        raise HTTPException(status.HTTP_409_CONFLICT, "Event already ingested") from None
    db.commit()
    publish(event)
    return event


@router.get("", response_model=SecurityEventPage)
def list_events(
    f: EventFilters = Depends(event_filters),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(analyst_or_admin),
):
    total = db.scalar(apply_filters(select(func.count(SecurityEvent.id)), f)) or 0
    items = db.scalars(
        apply_filters(select(SecurityEvent), f)
        .order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return SecurityEventPage(items=items, total=total, limit=limit, offset=offset)


async def _sse_frames(request: Request, queue: asyncio.Queue):
    settings = get_settings()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + settings.sse_max_seconds
    try:
        yield ": connected\n\n"
        while (remaining := deadline - loop.time()) > 0:
            try:
                item = await asyncio.wait_for(
                    queue.get(), timeout=min(settings.sse_heartbeat_seconds, remaining)
                )
            except TimeoutError:
                if await request.is_disconnected():
                    break
                yield ": ping\n\n"
                continue
            if item is RESYNC:
                yield "event: resync\ndata: {}\n\n"
            else:
                yield f"id: {item['id']}\nevent: security_event\ndata: {json.dumps(item)}\n\n"
    finally:
        broker.unsubscribe(queue)


@router.get("/stream", dependencies=[Depends(analyst_for_stream)])
async def stream_events(request: Request):
    """Server-Sent Events: one `security_event` frame per newly stored event.

    Authenticated with the Bearer header (use fetch streaming, not EventSource). The stream ends
    after SSE_MAX_SECONDS so clients reconnect with a fresh token.
    """
    queue = broker.subscribe()  # subscribe before responding so no event is missed
    return StreamingResponse(
        _sse_frames(request, queue),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# Declared before /{event_id} so "locations" is not parsed as an id.
@router.get("/locations", response_model=EventLocationList)
def event_locations(
    f: EventFilters = Depends(event_filters),
    limit: int = Query(default=1000, ge=1, le=5000),
    db: Session = Depends(get_db),
    _: User = Depends(analyst_or_admin),
):
    located = apply_filters(select(SecurityEvent), f).where(
        or_(
            SecurityEvent.latitude.is_not(None),
            SecurityEvent.origin_latitude.is_not(None),
            SecurityEvent.destination_latitude.is_not(None),
        )
    )
    total = db.scalar(select(func.count()).select_from(located.subquery())) or 0
    items = db.scalars(located.order_by(SecurityEvent.occurred_at.desc()).limit(limit)).all()
    return EventLocationList(items=items, total=total, truncated=total > len(items))


@router.get("/{event_id}/intel", response_model=LookupOut)
@limiter.limit("30/minute")
def event_intel(
    request: Request,
    event_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    """Reputation of the event's source IP across the configured threat-intel providers."""
    from app.api.threat_intel import run_lookup

    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found")
    if not event.source_ip:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This event has no source IP")
    return run_lookup(db, request, user, event.source_ip, "ip")


@router.get("/{event_id}", response_model=SecurityEventOut)
def get_event(
    event_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(analyst_or_admin),
):
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found")
    return event
