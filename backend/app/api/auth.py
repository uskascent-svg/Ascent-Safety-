from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.limiter import limiter
from app.database.session import get_db
from app.models import RefreshToken, Role, RoleName, User
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserOut
from app.security.deps import get_current_user
from app.security.passwords import hash_password, verify_password
from app.security.tokens import (
    create_access_token,
    hash_refresh_token,
    new_refresh_token,
)
from app.services import audit

router = APIRouter(prefix="/api/auth", tags=["auth"])
COOKIE = "refresh_token"


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        roles=[r.name for r in user.roles],
    )


def _issue_tokens(db: Session, user: User, response: Response) -> TokenResponse:
    s = get_settings()
    raw, token_hash = new_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.now(UTC) + timedelta(days=s.refresh_token_days),
        )
    )
    response.set_cookie(
        COOKIE,
        raw,
        max_age=s.refresh_token_days * 86400,
        httponly=True,
        secure=s.cookie_secure,
        samesite="strict",
        path="/api/auth",
    )
    access = create_access_token(user.id, [r.name for r in user.roles])
    return TokenResponse(access_token=access, expires_in=s.access_token_minutes * 60)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def register(request: Request, payload: RegisterRequest, db: Session = Depends(get_db)):
    email = payload.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    role = db.scalar(select(Role).where(Role.name == RoleName.USER.value))
    if role is None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Service misconfigured")
    # Self-registration only ever grants USER. Elevated roles are assigned by an administrator.
    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name.strip(),
        roles=[role],
    )
    db.add(user)
    db.flush()
    audit.record(db, "auth.register", request, user.id)
    db.commit()
    return _user_out(user)


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    valid = verify_password(payload.password, user.password_hash if user else None)
    if not (user and valid and user.is_active and user.deleted_at is None):
        audit.record(
            db,
            "auth.login_failed",
            request,
            user.id if user else None,
            {"email": payload.email.lower()},
        )
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    tokens = _issue_tokens(db, user, response)
    audit.record(db, "auth.login", request, user.id)
    db.commit()
    return tokens


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("30/minute")
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    raw = request.cookies.get(COOKIE)
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")
    if not raw:
        raise invalid
    token = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(raw))
    )
    if token is None:
        raise invalid
    now = datetime.now(UTC)
    if token.revoked_at is not None:
        # Reuse of a rotated token: assume theft and revoke every session for this user.
        db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == token.user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        audit.record(db, "auth.refresh_reuse_detected", request, token.user_id)
        db.commit()
        raise invalid
    user = db.get(User, token.user_id)
    if _aware(token.expires_at) < now or not user or not user.is_active or user.deleted_at:
        raise invalid
    token.revoked_at = now  # rotation
    tokens = _issue_tokens(db, user, response)
    audit.record(db, "auth.refresh", request, user.id)
    db.commit()
    return tokens


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, db: Session = Depends(get_db)):
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    raw = request.cookies.get(COOKIE)
    if raw:
        token = db.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(raw))
        )
        if token and token.revoked_at is None:
            token.revoked_at = datetime.now(UTC)
            audit.record(db, "auth.logout", request, token.user_id)
            db.commit()
    response.delete_cookie(COOKIE, path="/api/auth")
    return response


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return _user_out(user)
