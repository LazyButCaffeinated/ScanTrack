import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-chars-long")
os.environ.setdefault("DATABASE_URL", "sqlite://")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.api.deps import get_db
from app.core.security import hash_password
from app.db.base import Base
from app.main import app
from app.models.user import User

PASSWORD = "correct-horse-battery"


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def client(engine):
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture()
def make_user(engine):
    Session = sessionmaker(bind=engine)

    def _make(username: str, role: str, active: bool = True):
        with Session() as db:
            db.add(User(username=username, hashed_password=hash_password(PASSWORD), role=role, is_active=active))
            db.commit()

    return _make


@pytest.fixture()
def auth(client, make_user):
    """auth('analyst') -> headers dict with a valid bearer token for a user of that role."""

    def _auth(role: str):
        make_user(role, role)
        r = client.post("/api/v1/auth/login", data={"username": role, "password": PASSWORD})
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    return _auth


def sample_payload(n=3, scanner="nessus"):
    sev = ["critical", "high", "medium", "low", "info"]
    return {
        "scanner": scanner,
        "findings": [
            {"asset": f"host-{i}.lab", "plugin_id": f"P-{i}", "title": f"Finding {i}", "severity": sev[i % 5]}
            for i in range(n)
        ],
    }
