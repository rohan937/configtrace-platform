"""Second-wave bug hunt — DB-level in-flight sync guard (mig037).

Root cause: ``has_in_flight_sync()`` is a plain SELECT with no lock.
``POST /syncs`` and the Celery Beat scheduler both call
``has_in_flight_sync()`` then ``create_sync_run()`` as two separate steps.
Two callers racing each other (a manual "Sync Now" against a Beat tick, a
double-click, two Beat workers) can both observe "no in-flight sync" and
both insert a ``pending`` SyncRun for the same integration — the app-level
check alone cannot prevent this.

This proves the actual fix: a partial unique index
(``uq_sync_runs_one_in_flight_per_integration``) on
``sync_runs(integration_id) WHERE status IN ('pending', 'running')`` that
makes the database itself reject a second concurrent insert, and that
``create_sync_run`` surfaces that rejection as
``SyncAlreadyInProgressError`` rather than letting a raw IntegrityError
bubble up.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.database import SessionLocal
from app.models.integration import Integration
from app.models.sync_run import SyncRun
from app.models.user import User
from app.services import sync_service


def _make_user(db_session: Session) -> User:
    uid = uuid.uuid4().hex[:10]
    user = User(
        clerk_id=f"sync_guard_{uid}",
        email=f"sync_guard_{uid}@configtrace.test",
        display_name="Sync Guard Test User",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _make_integration(db_session: Session, user: User) -> Integration:
    ciphertext, iv = encrypt_credentials({"api_token": "tok", "zone_id": "zone_sg"})
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name="Sync Guard Integration",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db_session.add(integration)
    db_session.commit()
    db_session.refresh(integration)
    return integration


@pytest.fixture
def scenario(db_session):
    user = _make_user(db_session)
    integration = _make_integration(db_session, user)
    yield {"user": user, "integration": integration}

    db_session.expire_all()
    db_session.query(SyncRun).filter(SyncRun.integration_id == integration.id).delete()
    db_session.query(Integration).filter(Integration.id == integration.id).delete()
    db_session.query(User).filter(User.id == user.id).delete()
    db_session.commit()


class TestConcurrentSyncRunInsertIsRejectedAtTheDBLayer:
    def test_second_concurrent_create_sync_run_raises(self, db_session, scenario):
        """Simulates the actual race: two independent DB sessions (two
        Celery Beat workers, or a manual trigger racing a Beat tick) both
        pass has_in_flight_sync() and then both call create_sync_run().
        The first commit must win; the second must be rejected by the DB,
        not silently create a duplicate in-flight SyncRun."""
        integration = scenario["integration"]
        user = scenario["user"]

        assert not sync_service.has_in_flight_sync(integration.id, db_session)

        second_session = SessionLocal()
        try:
            assert not sync_service.has_in_flight_sync(integration.id, second_session)

            first_run = sync_service.create_sync_run(
                user_id=user.id, integration_id=integration.id, db=db_session,
                triggered_by="manual",
            )
            assert first_run.status == "pending"

            with pytest.raises(sync_service.SyncAlreadyInProgressError):
                sync_service.create_sync_run(
                    user_id=user.id, integration_id=integration.id, db=second_session,
                    triggered_by="scheduled",
                )

            # Exactly one in-flight SyncRun exists — no duplicate was created.
            in_flight_count = (
                second_session.query(SyncRun)
                .filter(
                    SyncRun.integration_id == integration.id,
                    SyncRun.status.in_(("pending", "running")),
                )
                .count()
            )
            assert in_flight_count == 1
        finally:
            second_session.close()

    def test_new_sync_run_allowed_after_prior_one_completes(self, db_session, scenario):
        """Regression guard: the unique index must not block a legitimate
        NEW sync once the previous one reached a terminal state."""
        integration = scenario["integration"]
        user = scenario["user"]

        first_run = sync_service.create_sync_run(
            user_id=user.id, integration_id=integration.id, db=db_session,
            triggered_by="manual",
        )
        sync_service.mark_sync_completed(
            first_run.id, snapshot_count=0, change_count=0, db=db_session,
        )

        second_run = sync_service.create_sync_run(
            user_id=user.id, integration_id=integration.id, db=db_session,
            triggered_by="manual",
        )
        assert second_run.id != first_run.id
        assert second_run.status == "pending"
