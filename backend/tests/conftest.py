"""Shared test fixtures.

The suite runs against a throwaway SQLite database in the system temp directory, with
AI disabled (so no provider call is ever made) and generous rate limits except where a
test deliberately tightens them.
"""

from __future__ import annotations

import os
import sys
import tempfile
import uuid
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

TEST_DB = Path(tempfile.gettempdir()) / "secureconfigai_pytest_v2.db"
if TEST_DB.exists():
    TEST_DB.unlink()

os.environ.update(
    {
        "APP_ENV": "test",
        "DATABASE_URL": f"sqlite:///{TEST_DB.as_posix()}",
        "JWT_SECRET_KEY": "test-secret-key-for-the-suite-0123456789abcdef",
        "RATE_LIMIT_ENABLED": "true",
        "RATE_LIMIT_LOGIN": "100",
        "RATE_LIMIT_REGISTER": "500",
        "RATE_LIMIT_SCAN_START": "500",
        "RATE_LIMIT_UPLOAD": "500",
        "RATE_LIMIT_REPORT": "500",
        "RATE_LIMIT_AI": "500",
        "AI_ENABLED": "false",
        "REPORT_CACHE_ENABLED": "true",
        "SCAN_JOB_WORKERS": "1",
    }
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.database import SessionLocal, engine  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.models import User  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _schema():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    engine.dispose()
    if TEST_DB.exists():
        try:
            TEST_DB.unlink()
        except OSError:
            pass


@pytest.fixture(autouse=True)
def _clean_state(_schema):
    """Reset tables and the in-process rate limiter between tests."""
    from app.core.rate_limit import limiter

    limiter.reset()
    for table in reversed(Base.metadata.sorted_tables):
        with engine.begin() as connection:
            connection.execute(table.delete())
    yield


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# --------------------------------------------------------------------------- auth helpers
def unique_email(prefix: str = "user") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}@example.com"


PASSWORD = "CorrectHorse42"


def register(
    client: TestClient, email: str | None = None, password: str = PASSWORD, prefix: str = "user"
) -> tuple[str, str]:
    email = email or unique_email(prefix)
    response = client.post(
        "/api/v1/auth/register", json={"email": email, "password": password, "full_name": "Test User"}
    )
    assert response.status_code == 201, response.text
    return email, password


def login(client: TestClient, email: str, password: str = PASSWORD) -> dict:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


def auth_headers(tokens: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.fixture
def user(client) -> dict:
    email, password = register(client)
    tokens = login(client, email, password)
    return {"email": email, "password": password, "tokens": tokens, "headers": auth_headers(tokens)}


@pytest.fixture
def admin(client, db) -> dict:
    email, password = register(client, prefix="admin")
    user_row = db.query(User).filter(User.email == email).one()
    user_row.role = "admin"
    db.commit()
    tokens = login(client, email, password)
    return {"email": email, "password": password, "tokens": tokens, "headers": auth_headers(tokens)}


# --------------------------------------------------------------------------- documents
# The evidence documents live in ``tests.documents`` so the PostgreSQL integration test
# can build them in a subprocess without importing this module (which rewrites the
# database environment variables). Re-exported here because existing tests import them
# from ``.conftest``.
from .documents import (  # noqa: E402
    empty_document,
    failing_document,
    legacy_document,
    perfect_document,
    snapshot_from,
)

__all__ = [
    "PASSWORD",
    "empty_document",
    "failing_document",
    "legacy_document",
    "perfect_document",
    "snapshot_from",
]
