"""Promote an existing account to administrator from the deployment shell."""

import argparse
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import SessionLocal
from app.models import Role, RoleName, User


def promote_admin(db: Session, email: str) -> bool:
    normalized_email = email.strip().lower()
    user = db.scalar(select(User).where(User.email == normalized_email))
    if user is None or not user.is_active or user.deleted_at is not None:
        return False

    role = db.scalar(select(Role).where(Role.name == RoleName.ADMINISTRATOR.value))
    if role is None:
        role = Role(name=RoleName.ADMINISTRATOR.value)
        db.add(role)
        db.flush()
    if role not in user.roles:
        user.roles.append(role)
    db.commit()
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Promote an existing Ascent Safety user to admin")
    parser.add_argument("email", help="Email address of the existing account")
    args = parser.parse_args()

    with SessionLocal() as db:
        if not promote_admin(db, args.email):
            print("No active, non-deleted account found for that email.", file=sys.stderr)
            return 1
    print("Administrator role granted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
