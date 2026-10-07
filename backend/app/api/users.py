from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import RoleName, User
from app.schemas.auth import UserOut
from app.security.deps import require_roles

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(RoleName.ADMINISTRATOR)),
):
    users = db.scalars(select(User).where(User.deleted_at.is_(None))).all()
    return [
        UserOut(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            roles=[r.name for r in u.roles],
        )
        for u in users
    ]
