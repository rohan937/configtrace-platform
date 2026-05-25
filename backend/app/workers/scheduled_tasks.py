"""Celery task — periodic scheduled-sync enqueue (Milestone 23).

This module contains a single Celery task, ``enqueue_scheduled_syncs``, that
the Celery Beat scheduler fires on a cron schedule (hourly at minute 0 — see
``app.workers.celery_app.beat_schedule``).

What the task does
------------------
1. Opens a SQLAlchemy session.
2. Calls ``sync_service.create_scheduled_syncs_for_active_integrations(db)``
   which:
     - lists active integrations for all supported providers
       (cloudflare, github, vercel, stripe, aws, firebase, supabase) where scheduled_sync_enabled=True
     - skips any with an in-flight (pending/running) SyncRun
     - creates a SyncRun with ``triggered_by="scheduled"`` per eligible
       integration
     - enqueues the existing ``sync_integration`` worker task
3. Closes the session in ``finally``.

The task itself is intentionally tiny — all logic lives in the service
function so it can be unit-tested without Celery in the loop.

Why a Celery task (rather than running the logic inside Beat)
-------------------------------------------------------------
Celery Beat is meant to dispatch messages, not execute work.  Beat's process
is supposed to stay small and idle most of the time; doing DB queries inside
beat would also serialise behind beat's tick loop.  This task runs on the
existing ``configtrace-worker`` process, which already has a configured DB
connection pool and the M21 ownership guards in place.

Failure handling
----------------
``max_retries=0`` — if this task fails we do not auto-retry.  Beat will fire
again on the next hour anyway; a transient failure heals on its own.  Any
exception is logged via Celery's standard error path.
"""

from __future__ import annotations

import logging

from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="enqueue_scheduled_syncs", max_retries=0)
def enqueue_scheduled_syncs() -> dict:
    """Fire-and-forget periodic task: enqueue scheduled syncs for active integrations.

    Returns the counts dict from
    :func:`sync_service.create_scheduled_syncs_for_active_integrations` so
    Celery's result backend records something meaningful for ops to grep.
    """
    # DB-touching imports are local so Beat itself never imports SessionLocal
    # (beat lives in its own process and shouldn't open DB connections from
    # the task-definition import path).
    from app.database import SessionLocal
    from app.services.sync_service import (
        create_scheduled_syncs_for_active_integrations,
    )

    db = SessionLocal()
    try:
        logger.info("enqueue_scheduled_syncs started")
        result = create_scheduled_syncs_for_active_integrations(db)
        logger.info(
            "enqueue_scheduled_syncs completed  seen=%d enqueued=%d "
            "skipped_not_due=%d skipped_in_flight=%d stale_cleaned=%d errors=%d",
            result["integrations_seen"],
            result["enqueued"],
            result["skipped_not_due"],
            result["skipped_in_flight"],
            result["stale_cleaned"],
            result["errors"],
        )
        return result
    finally:
        db.close()
