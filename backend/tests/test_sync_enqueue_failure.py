"""Final bug hunt — Celery/Redis enqueue failure must not leave a SyncRun
permanently stuck.

Root cause: ``create_sync_run`` commits a ``pending`` SyncRun row, THEN
``sync_integration.delay(...)`` is called to publish it to the broker. If
the broker (Redis) is unreachable at that moment, ``.delay()`` raises —
but the row was already committed. Without explicit handling, that row
stays 'pending' forever: ``has_in_flight_sync()`` reports the integration
as permanently busy, and the 30-minute stale-run reaper only runs for
integrations with a configured schedule (manual-only integrations would
never self-heal — an operator would have to fix the row directly in the
DB).

This file proves both enqueue call sites (POST /syncs and the scheduled-
sync loop) now mark the SyncRun 'failed' immediately when the broker
publish raises, instead of leaving it stuck 'pending'.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.sync_run import SyncRun
from app.models.user import User
from app.services import sync_service


def _make_user(db_session: Session) -> User:
    uid = uuid.uuid4().hex[:10]
    user = User(
        clerk_id=f"enqueue_fail_{uid}",
        email=f"enqueue_fail_{uid}@configtrace.test",
        display_name="Enqueue Failure Test User",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _make_integration(db_session: Session, user: User, **kwargs) -> Integration:
    ciphertext, iv = encrypt_credentials({"api_token": "tok", "zone_id": "zone_ef"})
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name="Enqueue Failure Integration",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        **kwargs,
    )
    db_session.add(integration)
    db_session.commit()
    db_session.refresh(integration)
    return integration


@pytest.fixture
def broken_broker(monkeypatch: pytest.MonkeyPatch):
    """Make sync_integration.delay() raise, simulating Redis being down."""
    from app.workers import sync_task

    def fake_delay(**kwargs):
        raise ConnectionError("Error 111 connecting to localhost:6379. Connection refused.")

    monkeypatch.setattr(sync_task.sync_integration, "delay", fake_delay)


class TestManualSyncEnqueueFailure:
    def test_broker_failure_marks_sync_run_failed_not_stuck_pending(
        self, db_session: Session, broken_broker
    ) -> None:
        user = _make_user(db_session)
        integration = _make_integration(db_session, user)

        from app.core.auth import get_current_user
        from app.database import get_db
        from app.main import app

        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[get_db] = lambda: db_session
        try:
            client = TestClient(app)
            resp = client.post("/syncs", json={"integration_id": str(integration.id)})
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 503

        run = (
            db_session.query(SyncRun)
            .filter(SyncRun.integration_id == integration.id)
            .one()
        )
        assert run.status == "failed"
        assert "Could not queue sync" in (run.error_message or "")

        # The in-flight guard must be clear — a retry must be possible,
        # not permanently blocked by the row the failed enqueue left behind.
        assert sync_service.has_in_flight_sync(integration.id, db_session) is False

        db_session.expire_all()
        db_session.query(SyncRun).filter(SyncRun.integration_id == integration.id).delete()
        db_session.query(Integration).filter(Integration.id == integration.id).delete()
        db_session.query(User).filter(User.id == user.id).delete()
        db_session.commit()


class TestScheduledSyncEnqueueFailure:
    def test_broker_failure_marks_sync_run_failed_not_stuck_pending(
        self, db_session: Session, broken_broker
    ) -> None:
        user = _make_user(db_session)
        integration = _make_integration(
            db_session, user, scheduled_sync_enabled=True,
        )

        result = sync_service.create_scheduled_syncs_for_active_integrations(db_session)
        assert result["errors"] >= 1

        run = (
            db_session.query(SyncRun)
            .filter(SyncRun.integration_id == integration.id)
            .one()
        )
        assert run.status == "failed"
        assert "Could not queue sync" in (run.error_message or "")
        assert sync_service.has_in_flight_sync(integration.id, db_session) is False

        db_session.expire_all()
        db_session.query(SyncRun).filter(SyncRun.integration_id == integration.id).delete()
        db_session.query(Integration).filter(Integration.id == integration.id).delete()
        db_session.query(User).filter(User.id == user.id).delete()
        db_session.commit()
