"""Sync run lifecycle management.

These functions create and update ``SyncRun`` records.  The Celery worker
calls ``mark_sync_running``, ``mark_sync_completed``, and ``mark_sync_failed``
at each stage of task execution so the frontend can poll status accurately.

Two trigger paths land here:

* ``POST /syncs`` calls :func:`create_sync_run` with ``triggered_by="manual"``
  (the default — preserves pre-M23 behaviour).
* Celery Beat fires :func:`create_scheduled_syncs_for_active_integrations`
  hourly; that function calls :func:`create_sync_run` with
  ``triggered_by="scheduled"`` for each eligible integration.

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


def create_scheduled_syncs_for_active_integrations(db: Session) -> dict:
    """Scan active Cloudflare integrations and enqueue scheduled syncs.

    Called hourly by the Celery Beat task ``enqueue_scheduled_syncs``.  Pure
    DB / queue side-effects; no return value the worker depends on.  The
    counts dict is returned so the task log line is self-explanatory and so
    tests can assert behaviour without poking at the queue.

    Behaviour per integration:

    1. Filter to ``provider == 'cloudflare'`` and ``status == 'active'``.
       Inactive (paused / error) integrations are silently skipped.
    2. Skip the integration if it already has a SyncRun in ``pending`` or
       ``running`` (duplicate-prevention).
    3. Create a SyncRun with ``triggered_by='scheduled'`` and
       ``user_id = integration.user_id``.  User isolation is preserved
       because the user_id is always taken from the integration row, never
       from a request or external source.
    4. Enqueue ``sync_integration`` with the new SyncRun.  Same task, same
       worker, same pipeline as a manual sync.

    The ``sync_integration.delay`` import is deferred so this module stays
    importable in environments without Redis (e.g. unit tests that mock
    the queue).

    Returns:
        Dict with these integer counts:
          - ``integrations_seen``: total active CF integrations queried
          - ``enqueued``: number of scheduled SyncRuns created and queued
          - ``skipped_in_flight``: skipped because a pending/running sync existed
          - ``errors``: non-fatal per-integration failures (logged, counted)
    """
    # Deferred import — keeps the module importable in test environments
    # that mock Celery and avoids a circular import between sync_service and
    # the worker package.
    from app.workers.sync_task import sync_integration

    seen = 0
    enqueued = 0
    skipped = 0
    errors = 0

    integrations = (
        db.query(Integration)
        .filter(
            Integration.provider == "cloudflare",
            Integration.status == "active",
        )
        .all()
    )

    for integration in integrations:
        seen += 1
        try:
            if has_in_flight_sync(integration.id, db):
                skipped += 1
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
                "user_id=%s",
                sync_run.id,
                integration.id,
                integration.user_id,
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
        "skipped_in_flight": skipped,
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
) -> None:
    """Transition to ``'failed'`` and store the error message."""
    sync_run = db.get(SyncRun, sync_run_id)
    if sync_run is not None:
        sync_run.status = "failed"
        sync_run.completed_at = datetime.now(timezone.utc)
        sync_run.error_message = error_message
        db.commit()
