"""Sync run lifecycle management.

These functions create and update ``SyncRun`` records.  The Celery worker
calls ``mark_sync_running``, ``mark_sync_completed``, and ``mark_sync_failed``
at each stage of task execution so the frontend can poll status accurately.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.sync_run import SyncRun


def create_sync_run(
    *,
    user_id: uuid.UUID,
    integration_id: uuid.UUID,
    db: Session,
) -> SyncRun:
    """Insert a new ``SyncRun`` with ``status='pending'`` and return it.

    The SyncRun is committed immediately so the Celery worker can load it
    by ID as soon as the task is dequeued.
    """
    sync_run = SyncRun(
        integration_id=integration_id,
        user_id=user_id,
        triggered_by="manual",
        status="pending",
    )
    db.add(sync_run)
    db.commit()
    db.refresh(sync_run)  # populates server-default fields (started_at)
    return sync_run


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
