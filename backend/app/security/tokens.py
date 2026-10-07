import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt

from app.core.config import get_settings


def create_access_token(user_id: uuid.UUID, roles: list[str]) -> str:
    s = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "roles": roles,
        "type": "access",
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + timedelta(minutes=s.access_token_minutes),
    }
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    s = get_settings()
    payload = jwt.decode(
        token,
        s.jwt_secret,
        algorithms=[s.jwt_algorithm],
        options={"require": ["exp", "sub"]},
    )
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return payload


def new_refresh_token() -> tuple[str, str]:
    """Return (raw_token, sha256_hash). Only the hash is stored."""
    raw = secrets.token_urlsafe(48)
    return raw, hash_refresh_token(raw)


def hash_refresh_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()
