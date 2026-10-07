import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.limiter import limiter
from app.database.session import get_db
from app.models import NetworkSensor, RoleName, User
from app.schemas.endpoint import BatchResult
from app.schemas.network import NetworkBatch, SensorCreate, SensorCreated, SensorOut
from app.security.api_keys import hash_api_key, new_api_key
from app.security.deps import analyst_or_admin, require_roles
from app.services import audit
from app.services.network_ingest import process_batch

router = APIRouter(tags=["network"])
admin_only = require_roles(RoleName.ADMINISTRATOR)
KEY_PREFIX = "ascent_sn"


def _get(db: Session, sensor_id: uuid.UUID) -> NetworkSensor:
    sensor = db.get(NetworkSensor, sensor_id)
    if sensor is None or sensor.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sensor not found")
    return sensor


@router.post("/api/sensors", response_model=SensorCreated, status_code=status.HTTP_201_CREATED)
def register_sensor(
    request: Request,
    payload: SensorCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_only),
):
    if db.scalar(select(NetworkSensor.id).where(NetworkSensor.name == payload.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A sensor with this name already exists")
    key, prefix, key_hash = new_api_key(KEY_PREFIX)
    data = payload.model_dump()
    data["kind"] = payload.kind.value
    sensor = NetworkSensor(**data, key_prefix=prefix, key_hash=key_hash, created_by=admin.id)
    db.add(sensor)
    db.flush()
    audit.record(
        db, "sensor.create", request, admin.id, {"sensor_id": str(sensor.id), "name": sensor.name}
    )
    db.commit()
    return SensorCreated(sensor=SensorOut.model_validate(sensor), api_key=key)


@router.post("/api/sensors/{sensor_id}/rotate-key", response_model=SensorCreated)
def rotate_sensor_key(
    request: Request,
    sensor_id: uuid.UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_only),
):
    sensor = _get(db, sensor_id)
    key, sensor.key_prefix, sensor.key_hash = new_api_key(KEY_PREFIX)
    audit.record(db, "sensor.rotate_key", request, admin.id, {"sensor_id": str(sensor.id)})
    db.commit()
    return SensorCreated(sensor=SensorOut.model_validate(sensor), api_key=key)


@router.delete("/api/sensors/{sensor_id}", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_sensor(
    request: Request,
    sensor_id: uuid.UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_only),
):
    sensor = _get(db, sensor_id)
    sensor.is_active, sensor.deleted_at = False, datetime.now(UTC)
    audit.record(db, "sensor.deactivate", request, admin.id, {"sensor_id": str(sensor.id)})
    db.commit()


@router.get("/api/sensors", response_model=list[SensorOut])
def list_sensors(db: Session = Depends(get_db), _: User = Depends(analyst_or_admin)):
    return db.scalars(
        select(NetworkSensor).where(NetworkSensor.deleted_at.is_(None)).order_by(NetworkSensor.name)
    ).all()


def authenticate_sensor(
    x_sensor_key: str | None = Header(default=None), db: Session = Depends(get_db)
) -> NetworkSensor:
    sensor = None
    if x_sensor_key:
        sensor = db.scalar(
            select(NetworkSensor).where(NetworkSensor.key_hash == hash_api_key(x_sensor_key))
        )
    if sensor is None or not sensor.is_active or sensor.deleted_at is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid sensor key")
    return sensor


@router.post("/api/network-telemetry", response_model=BatchResult)
@limiter.limit("120/minute")
def ingest_network_telemetry(
    request: Request,
    batch: NetworkBatch,
    db: Session = Depends(get_db),
    sensor: NetworkSensor = Depends(authenticate_sensor),
):
    """Sensors report observed network behaviour. Only findings and TLS baselines are stored."""
    return process_batch(db, sensor, batch.observations, request)
