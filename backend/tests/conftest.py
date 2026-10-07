import os

os.environ.update(
    DATABASE_URL="sqlite+pysqlite:///:memory:",
    JWT_SECRET="test-secret-test-secret-test-secret-1234",
    COOKIE_SECURE="false",
    INGEST_API_KEY="ingest-key-ingest-key-ingest-key-123",
)

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.limiter import limiter
from app.database.session import get_db, get_session_factory
from app.main import app
from app.models import Base, Role, RoleName, User

limiter.enabled = False


@pytest.fixture()
def session_factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as db:
        db.add_all([Role(name=r.value) for r in RoleName])
        db.commit()
    return factory


@pytest.fixture()
def client(session_factory):
    def _get_db():
        with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    yield TestClient(app)  # no `with`: skip lifespan; roles are seeded by session_factory
    app.dependency_overrides.clear()


PASSWORD = "correct-horse-battery"


@pytest.fixture()
def make_user(client):
    def _make(email="a@example.com"):
        r = client.post(
            "/api/auth/register",
            json={"email": email, "password": PASSWORD, "full_name": "Test User"},
        )
        assert r.status_code == 201
        return r.json()

    return _make


@pytest.fixture()
def promote(session_factory):
    def _promote(email, role: RoleName):
        from sqlalchemy import select

        with session_factory() as db:
            user = db.scalar(select(User).where(User.email == email))
            user.roles = [db.scalar(select(Role).where(Role.name == role.value))]
            db.commit()

    return _promote
