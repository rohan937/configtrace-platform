"""Shared pytest fixtures for the ConfigTrace test suite.

DB strategy
-----------
Tests that touch the database use the real Docker PostgreSQL instance.
Each test creates data with globally-unique IDs and cleans up via the fixture
teardown.  The ``test_user`` fixture wraps every test in a user row that
CASCADE-deletes integrations, resources, and sync_runs on teardown.

Encryption
----------
``patch_encryption_key`` is ``autouse=True``, so every test runs with a valid
ENCRYPTION_KEY regardless of what is in ``.env``.

Auth
----
``client`` overrides the ``get_current_user`` FastAPI dependency to return
``test_user`` directly, bypassing the dev-mode DB lookup.  The route handlers
use the standard ``get_db`` dependency (real DB sessions).
"""

from __future__ import annotations

import base64
import secrets
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.auth import get_current_user
from app.database import SessionLocal
from app.main import app
from app.models.user import User

# ── One stable test encryption key per process run ────────────────────────────
# Generated fresh each time pytest starts; never written to disk.
TEST_ENCRYPTION_KEY: str = base64.b64encode(secrets.token_bytes(32)).decode()


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def patch_encryption_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set a valid ENCRYPTION_KEY on the shared settings singleton for every test."""
    from app import config

    monkeypatch.setattr(config.settings, "ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)


@pytest.fixture
def db_session():
    """Yield a real SQLAlchemy session; always closed after the test."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def test_user(db_session):
    """Create a unique user in the DB; cascade-delete everything on teardown."""
    uid = uuid.uuid4().hex[:12]
    user = User(
        clerk_id=f"test_clerk_{uid}",
        email=f"test_{uid}@configtrace.test",
        display_name="Test User",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    yield user

    # Teardown: CASCADE removes integrations → resources → sync_runs
    try:
        db_session.delete(user)
        db_session.commit()
    except Exception:
        db_session.rollback()


@pytest.fixture
def client(test_user: User):
    """TestClient with the current-user dependency replaced by *test_user*.

    Route handlers continue to use the real ``get_db`` dependency so that
    DB writes are visible across sessions (no savepoint isolation).
    """

    def _override_user() -> User:
        return test_user

    app.dependency_overrides[get_current_user] = _override_user
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()
