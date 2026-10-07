import uuid

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database.session import get_db, get_session_factory
from app.models import RoleName, User
from app.security.tokens import decode_access_token

_bearer = HTTPBearer(auto_error=False)


def _unauth() -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _user_from_creds(creds: HTTPAuthorizationCredentials | None, db: Session) -> User:
    if creds is None:
        raise _unauth()
    try:
        user_id = uuid.UUID(decode_access_token(creds.credentials)["sub"])
    except (jwt.PyJWTError, ValueError):
        raise _unauth() from None
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.deleted_at is not None:
        raise _unauth()
    return user


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    return _user_from_creds(creds, db)


def require_roles(*allowed: RoleName):
    """Authorize against roles stored in the DB (not token claims) so changes apply immediately."""
    allowed_names = {r.value for r in allowed}

    def checker(user: User = Depends(get_current_user)) -> User:
        if not allowed_names & {r.name for r in user.roles}:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user

    return checker


# Security Panel data is restricted to analysts and administrators.
analyst_or_admin = require_roles(RoleName.SECURITY_ANALYST, RoleName.ADMINISTRATOR)


def analyst_for_stream(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    factory=Depends(get_session_factory),
) -> None:
    """Same checks as analyst_or_admin, but the DB session is closed before streaming starts."""
    with factory() as db:
        user = _user_from_creds(creds, db)
        if not {RoleName.SECURITY_ANALYST.value, RoleName.ADMINISTRATOR.value} & {
            r.name for r in user.roles
        }:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
