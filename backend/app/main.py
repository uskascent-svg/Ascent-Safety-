import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

from app.api import (
    alerts,
    auth,
    cyber_alerts,
    dashboard,
    endpoints,
    guidance,
    notifications,
    phishing,
    phishing_training,
    reports,
    security_events,
    sensors,
    threat_intel,
    users,
)
from app.core.config import get_settings
from app.core.limiter import limiter
from app.database.session import SessionLocal, engine
from app.models import Role, RoleName

log = logging.getLogger("ascent")


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Roles are reference data (not security telemetry); ensure they exist.
    with SessionLocal() as db:
        existing = set(db.scalars(select(Role.name)))
        for name in RoleName:
            if name.value not in existing:
                db.add(Role(name=name.value))
        db.commit()
    yield


app = FastAPI(
    title="Ascent Safety API",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None if get_settings().cookie_secure else "/docs",
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Ingest-Key",
        "X-Endpoint-Key",
        "X-Sensor-Key",
    ],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update(
        {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            "Cache-Control": "no-store",
        }
    )
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("Unhandled error on %s", request.url.path)  # stack trace stays server-side
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(security_events.router)
app.include_router(dashboard.router)
app.include_router(phishing.router)
app.include_router(guidance.router)
app.include_router(phishing_training.router)
app.include_router(cyber_alerts.router)
app.include_router(reports.router)
app.include_router(notifications.router)
app.include_router(threat_intel.router)
app.include_router(endpoints.router)
app.include_router(alerts.router)
app.include_router(sensors.router)


@app.get("/api/health", tags=["meta"])
def health():
    """Liveness probe: the API process is running."""
    return {"status": "ok"}


@app.get("/api/health/ready", tags=["meta"])
def readiness():
    """Readiness probe: the API can reach its configured database."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        log.warning("Database readiness check failed")
        return JSONResponse({"status": "not_ready"}, status_code=503)
    return {"status": "ready", "database": "available"}
