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


# Hostnames that the deterministic DNS stub treats as *private* — used by
# M59.4 SSRF/DNS-rebinding tests to simulate hostnames resolving to private IPs.
# Tests opt in by adding to this set within a fixture or by patching directly.
_TEST_PRIVATE_HOSTS: dict[str, str] = {}


@pytest.fixture(autouse=True)
def deterministic_dns_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace ``socket.getaddrinfo`` with a deterministic stub.

    M59.4 added DNS-rebinding protection to ``notification_service._validate_url``
    which calls ``socket.getaddrinfo``.  To keep tests independent of real DNS:

    * Hostnames in ``_TEST_PRIVATE_HOSTS`` resolve to the IP recorded there
      (use to exercise the private-IP rejection path).
    * All other hostnames resolve to ``93.184.216.34`` (a known stable public
      IP — example.com's documentation address).

    Tests that need a specific private resolution may mutate
    ``_TEST_PRIVATE_HOSTS`` directly or use ``monkeypatch.setattr`` to install
    their own ``socket.getaddrinfo`` stub.
    """
    import socket as _socket

    def _fake_getaddrinfo(host, port, *args, **kwargs):  # type: ignore[no-untyped-def]
        ip = _TEST_PRIVATE_HOSTS.get(host, "93.184.216.34")
        # Return a single AF_INET tuple matching the real API shape.
        return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (ip, port or 0))]

    monkeypatch.setattr(_socket, "getaddrinfo", _fake_getaddrinfo)


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
