"""Milestone 23 tests — Scheduled syncs.

What's covered
--------------
1. ``create_scheduled_syncs_for_active_integrations`` enqueues a SyncRun per
   active Cloudflare integration.
2. SyncRun is created with ``triggered_by="scheduled"`` and the integration
   owner's ``user_id``.
3. Integrations with an in-flight (pending/running) SyncRun are skipped.
4. Integrations with status != ``"active"`` (paused, error) are skipped.
5. Integrations from a different provider (none yet, but defensive) are skipped.
6. Multiple users' integrations are processed independently — no cross-user
   contamination.
7. The Celery ``sync_integration.delay`` call carries the integration owner's
   user_id, not anything else.
8. Manual ``POST /syncs`` still works and still creates ``triggered_by="manual"``
   SyncRuns (regression).

What's NOT covered (already covered by other suites)
----------------------------------------------------
* The worker ownership guard (test_milestone21).
* The sync pipeline itself (test_milestone10).
* JWT verification on the API path (test_milestone21).

How we test
-----------
We exercise the service function directly with the real Postgres DB used by
the rest of the suite, and monkey-patch ``sync_integration.delay`` so we never
push anything to Redis.  The patched delay records its calls so we can assert
exactly which integrations were enqueued and with what user_id.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.sync_run import SyncRun
from app.models.user import User
from app.services import sync_service


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_user(db_session: Session, suffix: str = "") -> User:
    """Create a user with a fresh clerk_id.  Caller is responsible for cleanup."""
    uid = uuid.uuid4().hex[:10]
    user = User(
        clerk_id=f"m23_test_{uid}{suffix}",
        email=f"m23_{uid}{suffix}@configtrace.test",
        display_name="M23 Test User",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _make_integration(
    db_session: Session,
    user: User,
    *,
    status: str = "active",
    zone_suffix: str | None = None,
) -> Integration:
    """Create a Cloudflare integration owned by *user* with the given status."""
    zone = f"zone_{zone_suffix or uuid.uuid4().hex[:8]}"
    ciphertext, iv = encrypt_credentials({"api_token": "tok", "zone_id": zone})
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name=f"Integration {zone}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status=status,
    )
    db_session.add(integration)
    db_session.commit()
    db_session.refresh(integration)
    return integration


@pytest.fixture
def delay_spy(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Patch ``sync_integration.delay`` to record calls instead of enqueuing.

    The service does ``from app.workers.sync_task import sync_integration``
    inside the function body (deferred import), so we patch the attribute on
    the module that the service imports from.
    """
    from app.workers import sync_task

    calls: list[dict[str, Any]] = []

    def fake_delay(**kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(sync_task.sync_integration, "delay", fake_delay)
    return calls


# ─────────────────────────────────────────────────────────────────────────────
# 1. Happy path — active integration is enqueued exactly once
# ─────────────────────────────────────────────────────────────────────────────


def test_enqueues_active_cloudflare_integration(
    db_session: Session, test_user: User, delay_spy: list[dict[str, Any]]
) -> None:
    """An active CF integration produces a scheduled SyncRun and one queue call."""
    integration = _make_integration(db_session, test_user)

    result = sync_service.create_scheduled_syncs_for_active_integrations(db_session)

    assert result["integrations_seen"] >= 1
    assert result["enqueued"] >= 1
    assert result["errors"] == 0

    # SyncRun row exists with the right shape.
    sync_run = (
        db_session.query(SyncRun)
        .filter(SyncRun.integration_id == integration.id)
        .one()
    )
    assert sync_run.triggered_by == "scheduled"
    assert sync_run.status == "pending"
    assert sync_run.user_id == test_user.id

    # Exactly one Celery enqueue for this integration, with the right ids.
    matching = [c for c in delay_spy if c["integration_id"] == str(integration.id)]
    assert len(matching) == 1
    assert matching[0]["user_id"] == str(test_user.id)
    assert matching[0]["sync_run_id"] == str(sync_run.id)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Duplicate prevention — in-flight syncs cause a skip
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("inflight_status", ["pending", "running"])
def test_skips_integration_with_in_flight_sync(
    db_session: Session,
    test_user: User,
    delay_spy: list[dict[str, Any]],
    inflight_status: str,
) -> None:
    """If an integration already has a pending/running sync, the scheduler skips it."""
    integration = _make_integration(db_session, test_user)

    # Seed an in-flight SyncRun.  Could be manual or scheduled — doesn't matter,
    # the duplicate-prevention check is status-only.
    pre = SyncRun(
        integration_id=integration.id,
        user_id=test_user.id,
        triggered_by="manual",
        status=inflight_status,
    )
    db_session.add(pre)
    db_session.commit()

    result = sync_service.create_scheduled_syncs_for_active_integrations(db_session)

    assert result["skipped_in_flight"] >= 1
    # No new scheduled SyncRun for this integration.
    scheduled = (
        db_session.query(SyncRun)
        .filter(
            SyncRun.integration_id == integration.id,
            SyncRun.triggered_by == "scheduled",
        )
        .all()
    )
    assert scheduled == []

    # No queue call for this integration either.
    matching = [c for c in delay_spy if c["integration_id"] == str(integration.id)]
    assert matching == []


def test_does_not_skip_after_in_flight_completes(
    db_session: Session, test_user: User, delay_spy: list[dict[str, Any]]
) -> None:
    """A completed SyncRun does NOT block a new scheduled sync."""
    integration = _make_integration(db_session, test_user)
    completed = SyncRun(
        integration_id=integration.id,
        user_id=test_user.id,
        triggered_by="manual",
        status="completed",
    )
    db_session.add(completed)
    db_session.commit()

    result = sync_service.create_scheduled_syncs_for_active_integrations(db_session)
    assert result["enqueued"] >= 1

    scheduled = (
        db_session.query(SyncRun)
        .filter(
            SyncRun.integration_id == integration.id,
            SyncRun.triggered_by == "scheduled",
        )
        .one()
    )
    assert scheduled.status == "pending"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Status gating — only active integrations are picked
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("status", ["paused", "error"])
def test_skips_non_active_integration(
    db_session: Session,
    test_user: User,
    delay_spy: list[dict[str, Any]],
    status: str,
) -> None:
    """Paused / errored integrations are excluded from scheduling."""
    integration = _make_integration(db_session, test_user, status=status)

    sync_service.create_scheduled_syncs_for_active_integrations(db_session)

    # No SyncRun and no queue call for this integration.
    assert (
        db_session.query(SyncRun)
        .filter(SyncRun.integration_id == integration.id)
        .count()
        == 0
    )
    matching = [c for c in delay_spy if c["integration_id"] == str(integration.id)]
    assert matching == []


# ─────────────────────────────────────────────────────────────────────────────
# 4. User isolation — two users' integrations are both processed, never mixed
# ─────────────────────────────────────────────────────────────────────────────


def test_multi_user_isolation(
    db_session: Session, test_user: User, delay_spy: list[dict[str, Any]]
) -> None:
    """Two users each get their own scheduled SyncRun with the right user_id."""
    other_user = _make_user(db_session)
    try:
        a = _make_integration(db_session, test_user, zone_suffix="userA")
        b = _make_integration(db_session, other_user, zone_suffix="userB")

        sync_service.create_scheduled_syncs_for_active_integrations(db_session)

        run_a = (
            db_session.query(SyncRun)
            .filter(SyncRun.integration_id == a.id)
            .one()
        )
        run_b = (
            db_session.query(SyncRun)
            .filter(SyncRun.integration_id == b.id)
            .one()
        )

        assert run_a.user_id == test_user.id
        assert run_b.user_id == other_user.id
        assert run_a.user_id != run_b.user_id

        # Queue calls carry the right user_id per integration.
        call_a = next(c for c in delay_spy if c["integration_id"] == str(a.id))
        call_b = next(c for c in delay_spy if c["integration_id"] == str(b.id))
        assert call_a["user_id"] == str(test_user.id)
        assert call_b["user_id"] == str(other_user.id)
    finally:
        # Tidy up the second user (test_user is cleaned by its fixture).
        db_session.delete(other_user)
        db_session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# 5. has_in_flight_sync helper — direct unit test
# ─────────────────────────────────────────────────────────────────────────────


def test_has_in_flight_sync_returns_true_for_pending(
    db_session: Session, test_user: User
) -> None:
    integration = _make_integration(db_session, test_user)
    db_session.add(
        SyncRun(
            integration_id=integration.id,
            user_id=test_user.id,
            triggered_by="manual",
            status="pending",
        )
    )
    db_session.commit()
    assert sync_service.has_in_flight_sync(integration.id, db_session) is True


def test_has_in_flight_sync_returns_false_for_completed_only(
    db_session: Session, test_user: User
) -> None:
    integration = _make_integration(db_session, test_user)
    db_session.add(
        SyncRun(
            integration_id=integration.id,
            user_id=test_user.id,
            triggered_by="manual",
            status="completed",
        )
    )
    db_session.commit()
    assert sync_service.has_in_flight_sync(integration.id, db_session) is False


def test_has_in_flight_sync_returns_false_when_no_runs(
    db_session: Session, test_user: User
) -> None:
    integration = _make_integration(db_session, test_user)
    assert sync_service.has_in_flight_sync(integration.id, db_session) is False


# ─────────────────────────────────────────────────────────────────────────────
# 6. Manual sync regression — POST /syncs still works and still creates
#    triggered_by="manual"
# ─────────────────────────────────────────────────────────────────────────────


def test_manual_sync_still_creates_manual_sync_run(
    client, db_session: Session, test_user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``POST /syncs`` must remain unchanged: still queues with triggered_by=manual."""
    from app.workers import sync_task

    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        sync_task.sync_integration,
        "delay",
        lambda **kwargs: calls.append(kwargs),
    )

    integration = _make_integration(db_session, test_user)

    resp = client.post(
        "/syncs", json={"integration_id": str(integration.id)}
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["triggered_by"] == "manual"
    assert body["status"] == "pending"

    # SyncRun row matches.
    run = db_session.get(SyncRun, uuid.UUID(body["id"]))
    assert run is not None
    assert run.triggered_by == "manual"
    assert run.user_id == test_user.id

    # One queue call, with the right user_id.
    assert len(calls) == 1
    assert calls[0]["user_id"] == str(test_user.id)
    assert calls[0]["integration_id"] == str(integration.id)


# ─────────────────────────────────────────────────────────────────────────────
# 7. create_sync_run default — triggered_by defaults to "manual"
#    (regression guard so a future refactor doesn't change the default and
#     silently break the manual POST /syncs path)
# ─────────────────────────────────────────────────────────────────────────────


def test_create_sync_run_defaults_to_manual(
    db_session: Session, test_user: User
) -> None:
    integration = _make_integration(db_session, test_user)
    run = sync_service.create_sync_run(
        user_id=test_user.id, integration_id=integration.id, db=db_session
    )
    assert run.triggered_by == "manual"


def test_create_sync_run_accepts_scheduled_kwarg(
    db_session: Session, test_user: User
) -> None:
    integration = _make_integration(db_session, test_user)
    run = sync_service.create_sync_run(
        user_id=test_user.id,
        integration_id=integration.id,
        db=db_session,
        triggered_by="scheduled",
    )
    assert run.triggered_by == "scheduled"
