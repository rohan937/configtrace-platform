"""Sync run lifecycle management.

These functions create and update ``SyncRun`` records.  The Celery worker
calls ``mark_sync_running``, ``mark_sync_completed``, and ``mark_sync_failed``
at each stage of task execution so the frontend can poll status accurately.

Two trigger paths land here:

* ``POST /syncs`` calls :func:`create_sync_run` with ``triggered_by="manual"``
  (the default — preserves pre-M23 behaviour).
* Celery Beat fires :func:`create_scheduled_syncs_for_active_integrations`
  every 5 minutes (M29); that function decides which integrations are *due*
  based on their ``sync_interval_minutes`` and ``last_synced_at``, then calls
  :func:`create_sync_run` with ``triggered_by="scheduled"`` for each eligible
  integration.

Both paths produce SyncRun rows that the same ``sync_integration`` worker
task processes — no separate worker pipeline.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.integration import Integration
from app.models.sync_run import SyncRun

logger = logging.getLogger(__name__)

# Status values that count as "still in flight" for duplicate-prevention.
# When a scheduled sync would pick an integration that already has one of
# these queued, we skip it instead of stacking another.
_IN_FLIGHT_STATUSES = ("pending", "running")

# Default sync cadence when sync_interval_minutes is NULL on an integration.
# Matches the old hourly-only behaviour so existing integrations are unchanged.
_DEFAULT_INTERVAL_MINUTES = 60

# Allowed per-integration sync intervals (minutes).  Values outside this set
# are ignored and fall back to the default.  Validated at the PATCH endpoint
# so values in the DB should always be within this set.
_ALLOWED_INTERVALS = frozenset({5, 10, 15, 30, 60})

# Small grace window (seconds) applied when comparing elapsed time to the
# configured interval.  Prevents a sync that completed at 12:00:02 from being
# skipped at the 12:05:00 tick because only 4m58s elapsed.
_INTERVAL_GRACE_SECONDS = 30


def create_sync_run(
    *,
    user_id: uuid.UUID,
    integration_id: uuid.UUID,
    db: Session,
    triggered_by: str = "manual",
) -> SyncRun:
    """Insert a new ``SyncRun`` with ``status='pending'`` and return it.

    The SyncRun is committed immediately so the Celery worker can load it
    by ID as soon as the task is dequeued.

    Args:
        user_id:        Owning user.  Always the integration's user_id —
                        never a header-supplied value.
        integration_id: Integration this sync runs against.
        db:             Active SQLAlchemy session.
        triggered_by:   ``"manual"`` (the default — preserves the M21/M22
                        behaviour of ``POST /syncs``) or ``"scheduled"``
                        (used by the M23 Celery Beat task).
    """
    sync_run = SyncRun(
        integration_id=integration_id,
        user_id=user_id,
        triggered_by=triggered_by,
        status="pending",
    )
    db.add(sync_run)
    db.commit()
    db.refresh(sync_run)  # populates server-default fields (started_at)
    return sync_run


def has_in_flight_sync(integration_id: uuid.UUID, db: Session) -> bool:
    """Return True if *integration_id* has a SyncRun in ``pending`` or ``running``.

    Used by :func:`create_scheduled_syncs_for_active_integrations` to avoid
    stacking duplicate scheduled syncs on top of a sync that hasn't finished
    yet.  This function does **not** filter by user — the integration_id
    is already user-scoped via the caller's earlier query.
    """
    return (
        db.query(SyncRun.id)
        .filter(
            SyncRun.integration_id == integration_id,
            SyncRun.status.in_(_IN_FLIGHT_STATUSES),
        )
        .first()
        is not None
    )


def _is_integration_due(integration: Integration, now: datetime) -> bool:
    """Return True if *integration* is due for a scheduled sync tick.

    An integration is due when:
    - It has never been synced (``last_synced_at`` is None), OR
    - Enough time has elapsed since the last successful sync, accounting for
      the configured ``sync_interval_minutes`` (default: 60).

    A small grace window (``_INTERVAL_GRACE_SECONDS``) prevents a sync that
    completed at 12:00:02 from being skipped at the 12:05:00 tick due to
    sub-minute elapsed-time rounding.
    """
    interval = integration.sync_interval_minutes
    if interval is None or interval not in _ALLOWED_INTERVALS:
        interval = _DEFAULT_INTERVAL_MINUTES

    if integration.last_synced_at is None:
        # Never synced — always due on the first tick.
        return True

    elapsed_seconds = (now - integration.last_synced_at).total_seconds()
    threshold_seconds = interval * 60 - _INTERVAL_GRACE_SECONDS
    return elapsed_seconds >= threshold_seconds


def create_scheduled_syncs_for_active_integrations(db: Session) -> dict:
    """Scan active integrations and enqueue scheduled syncs that are due.

    Called every 5 minutes by the Celery Beat task ``enqueue_scheduled_syncs``
    (M29).  The task decides which integrations are *due* based on their
    ``sync_interval_minutes`` and ``last_synced_at`` — the Beat tick is just
    the scheduling granularity, not the sync cadence.

    Behaviour per integration:

    1. Filter to ``provider in ('cloudflare', 'github')`` and ``status == 'active'``.
       Paused / deleted / errored integrations are silently skipped.
    2. Check whether the integration is due using :func:`_is_integration_due`.
       Skips integrations whose ``sync_interval_minutes`` has not elapsed since
       ``last_synced_at``.
    3. Skip the integration if it already has a SyncRun in ``pending`` or
       ``running`` (duplicate-prevention — existing guard preserved from M23).
    4. Create a SyncRun with ``triggered_by='scheduled'`` and
       ``user_id = integration.user_id``.  User isolation is preserved
       because the user_id is always taken from the integration row, never
       from a request or external source.
    5. Enqueue ``sync_integration`` with the new SyncRun.  Same task, same
       worker, same pipeline as a manual sync.

    The ``sync_integration.delay`` import is deferred so this module stays
    importable in environments without Redis (e.g. unit tests that mock
    the queue).

    Returns:
        Dict with these integer counts:
          - ``integrations_seen``: total active integrations queried
          - ``enqueued``: number of scheduled SyncRuns created and queued
          - ``skipped_not_due``: skipped because interval has not elapsed
          - ``skipped_in_flight``: skipped because a pending/running sync existed
          - ``errors``: non-fatal per-integration failures (logged, counted)
    """
    # Deferred import — keeps the module importable in test environments
    # that mock Celery and avoids a circular import between sync_service and
    # the worker package.
    from app.workers.sync_task import sync_integration

    seen = 0
    enqueued = 0
    skipped_not_due = 0
    skipped_in_flight = 0
    errors = 0

    now = datetime.now(timezone.utc)

    integrations = (
        db.query(Integration)
        .filter(
            Integration.provider.in_(("cloudflare", "github")),
            Integration.status == "active",
        )
        .all()
    )

    for integration in integrations:
        seen += 1
        try:
            # ── Per-integration interval due-check (M29) ───────────────────
            if not _is_integration_due(integration, now):
                skipped_not_due += 1
                logger.debug(
                    "scheduled_sync skipped — interval not elapsed  "
                    "integration_id=%s interval_minutes=%s last_synced_at=%s",
                    integration.id,
                    integration.sync_interval_minutes or _DEFAULT_INTERVAL_MINUTES,
                    integration.last_synced_at,
                )
                continue

            # ── In-flight guard (M23, preserved) ──────────────────────────
            if has_in_flight_sync(integration.id, db):
                skipped_in_flight += 1
                logger.info(
                    "scheduled_sync skipped — in-flight sync exists  "
                    "integration_id=%s user_id=%s",
                    integration.id,
                    integration.user_id,
                )
                continue

            sync_run = create_sync_run(
                user_id=integration.user_id,
                integration_id=integration.id,
                db=db,
                triggered_by="scheduled",
            )
            sync_integration.delay(
                sync_run_id=str(sync_run.id),
                integration_id=str(integration.id),
                user_id=str(integration.user_id),
            )
            enqueued += 1
            logger.info(
                "scheduled_sync enqueued  sync_run_id=%s integration_id=%s "
                "user_id=%s interval_minutes=%s",
                sync_run.id,
                integration.id,
                integration.user_id,
                integration.sync_interval_minutes or _DEFAULT_INTERVAL_MINUTES,
            )
        except Exception:
            # Don't let one integration's failure abort the loop — log it,
            # count it, and continue so the rest of the user base still gets
            # scheduled.
            errors += 1
            logger.exception(
                "scheduled_sync failed to enqueue  integration_id=%s",
                integration.id,
            )

    return {
        "integrations_seen": seen,
        "enqueued": enqueued,
        "skipped_not_due": skipped_not_due,
        "skipped_in_flight": skipped_in_flight,
        "errors": errors,
    }


def get_sync_run(
    *,
    user_id: uuid.UUID,
    sync_run_id: uuid.UUID,
    db: Session,
) -> SyncRun | None:
    """Return the sync run scoped to *user_id*, or ``None`` if not found."""
    return (
        db.query(SyncRun)
        .filter(SyncRun.id == sync_run_id, SyncRun.user_id == user_id)
        .first()
    )


def mark_sync_running(sync_run_id: uuid.UUID, db: Session) -> None:
    """Transition ``status`` from ``'pending'`` to ``'running'``."""
    sync_run = db.get(SyncRun, sync_run_id)
    if sync_run is not None:
        sync_run.status = "running"
        db.commit()


def mark_sync_completed(
    sync_run_id: uuid.UUID,
    *,
    snapshot_count: int,
    change_count: int,
    db: Session,
) -> None:
    """Transition to ``'completed'`` and record snapshot/change counts."""
    sync_run = db.get(SyncRun, sync_run_id)
    if sync_run is not None:
        sync_run.status = "completed"
        sync_run.completed_at = datetime.now(timezone.utc)
        sync_run.snapshot_count = snapshot_count
        sync_run.change_count = change_count
        db.commit()


def mark_sync_failed(
    sync_run_id: uuid.UUID,
    *,
    error_message: str,
    db: Session,
    failure_category: str | None = None,
    error_code: str | None = None,
    recommended_action: str | None = None,
) -> None:
    """Transition to ``'failed'`` and store the error message.

    The optional *failure_category*, *error_code*, and *recommended_action*
    fields (added in M32) are written when provided.  Existing callers that
    omit them continue to work unchanged.
    """
    sync_run = db.get(SyncRun, sync_run_id)
    if sync_run is not None:
        sync_run.status = "failed"
        sync_run.completed_at = datetime.now(timezone.utc)
        sync_run.error_message = error_message
        if failure_category is not None:
            sync_run.failure_category = failure_category
        if error_code is not None:
            sync_run.error_code = error_code
        if recommended_action is not None:
            sync_run.recommended_action = recommended_action
        db.commit()


def increment_consecutive_failures(
    integration_id: uuid.UUID,
    db: Session,
) -> int:
    """Increment ``consecutive_failure_count`` and update ``last_failure_at``.

    Called after a *scheduled* sync fails.  Returns the new count so the
    caller can decide whether to dispatch a failure alert.

    Manual sync failures should NOT call this function — consecutive failure
    tracking is intentionally limited to scheduled syncs so a user manually
    retrying a broken integration doesn't inflate the counter.
    """
    integration = db.get(Integration, integration_id)
    if integration is None:
        logger.warning(
            "increment_consecutive_failures: integration %s not found",
            integration_id,
        )
        return 0
    integration.consecutive_failure_count = (
        (integration.consecutive_failure_count or 0) + 1
    )
    integration.last_failure_at = datetime.now(timezone.utc)
    db.commit()
    return integration.consecutive_failure_count


def reset_consecutive_failures(
    integration_id: uuid.UUID,
    db: Session,
) -> None:
    """Reset ``consecutive_failure_count`` to 0 after a successful sync.

    Called after any successful sync (manual or scheduled) to clear any
    accumulated failure streak.  Safe to call even if the count is already 0.
    """
    integration = db.get(Integration, integration_id)
    if integration is not None and integration.consecutive_failure_count != 0:
        integration.consecutive_failure_count = 0
        db.commit()
