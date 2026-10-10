"""Grant or revoke a scoped threat role from the trusted deployment shell."""

import argparse

from sqlalchemy import select

from app.database.session import SessionLocal
from app.models import Role, RoleName, User

THREAT_ROLES = {
    RoleName.THREAT_MONITOR.value,
    RoleName.THREAT_DATA_REVIEWER.value,
    RoleName.THREAT_MODEL_OPERATOR.value,
}


def update_role(email: str, role_name: str, revoke: bool = False) -> None:
    if role_name not in THREAT_ROLES:
        raise ValueError("Role must be one of the scoped threat roles")
    with SessionLocal.begin() as db:
        user = db.scalar(select(User).where(User.email == email.lower(), User.deleted_at.is_(None)))
        role = db.scalar(select(Role).where(Role.name == role_name))
        if user is None or not user.is_active:
            raise ValueError("Active account not found")
        if role is None:
            raise ValueError("Role is not initialized; run database migrations first")
        if revoke:
            user.roles = [assigned for assigned in user.roles if assigned.id != role.id]
        elif role not in user.roles:
            user.roles.append(role)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("email")
    parser.add_argument("role", choices=sorted(THREAT_ROLES))
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args()
    update_role(args.email, args.role, args.revoke)
    print(f"{args.role} {'revoked from' if args.revoke else 'granted to'} {args.email.lower()}")


if __name__ == "__main__":
    main()
