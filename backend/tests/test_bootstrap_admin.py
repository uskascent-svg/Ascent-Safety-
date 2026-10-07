from app.bootstrap_admin import promote_admin
from app.models import RoleName, User


def test_promote_admin_adds_administrator_role(session_factory, make_user):
    make_user("owner@example.com")

    with session_factory() as db:
        assert promote_admin(db, " OWNER@example.com ")
        user = db.query(User).filter_by(email="owner@example.com").one()
        assert RoleName.ADMINISTRATOR.value in {role.name for role in user.roles}


def test_promote_admin_returns_false_for_unknown_user(session_factory):
    with session_factory() as db:
        assert not promote_admin(db, "missing@example.com")
