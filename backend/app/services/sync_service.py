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
from datetime import datetime, timedelta, timezone

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

# SyncRuns that have been in ``pending`` or ``running`` for longer than this
# threshold are considered stale — the Celery worker was most likely killed
# mid-task (e.g. a Render deploy or OOM restart) and the row was never
# transitioned to a terminal state.  Stale runs are marked ``failed`` before
# the duplicate-prevention in-flight check so they don't permanently block
# future scheduled syncs for the affected integration.
#
# 30 minutes is deliberately conservative: even the heaviest AWS syncs
# (M36–M38, multi-region EC2 + S3 + IAM) complete in under 10 minutes on
# a single worker.  A run still in-flight after 30 minutes is definitively
# stuck, not just slow.
_STALE_SYNC_THRESHOLD_MINUTES = 30


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


def _cleanup_stale_in_flight(
    integration_id: uuid.UUID,
    db: Session,
    now: datetime,
) -> int:
    """Mark stale in-flight SyncRuns as ``failed`` and return the count cleaned.

    A SyncRun in ``pending`` or ``running`` is considered stale when its
    ``started_at`` timestamp is older than ``_STALE_SYNC_THRESHOLD_MINUTES``.
    ``started_at`` is set by ``server_default=now()`` at insert time (when the
    row is created in *pending* state), so it is reliable as a staleness clock
    even if the worker never transitions the row to *running*.

    This handles the common deploy/OOM scenario: Render kills the Celery worker
    mid-task, the SyncRun row stays in ``running`` forever, and every subsequent
    Beat tick finds it via ``has_in_flight_sync()`` and silently skips the
    integration.  Without this cleanup, one bad deploy permanently disables
    scheduled syncs for the affected integration.

    Called *before* ``has_in_flight_sync()`` in the scheduler loop so that
    genuinely stale rows are cleared first and the duplicate-prevention guard
    only fires on legitimately-active syncs.

    Returns:
        The number of SyncRuns that were transitioned to ``failed``.
    """
    cutoff = now - timedelta(minutes=_STALE_SYNC_THRESHOLD_MINUTES)
    stale_runs = (
        db.query(SyncRun)
        .filter(
            SyncRun.integration_id == integration_id,
            SyncRun.status.in_(_IN_FLIGHT_STATUSES),
            SyncRun.started_at < cutoff,
        )
        .all()
    )
    for run in stale_runs:
        run.status = "failed"
        run.completed_at = now
        run.error_message = (
            f"Sync timed out — marked stale after "
            f"{_STALE_SYNC_THRESHOLD_MINUTES}m without completion "
            f"(worker likely restarted during this sync)"
        )
        logger.warning(
            "scheduled_sync: stale SyncRun detected and failed  "
            "sync_run_id=%s integration_id=%s started_at=%s",
            run.id,
            integration_id,
            run.started_at,
        )
    if stale_runs:
        db.commit()
    return len(stale_runs)


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

    1. Filter to all supported providers (cloudflare, github, vercel, stripe, aws, firebase, supabase, shopify, azure, google_cloud, twilio)
       with ``status == 'active'`` AND ``scheduled_sync_enabled == True``.
       Paused / deleted integrations are excluded by status.  Integrations
       whose user explicitly disabled auto-sync (``scheduled_sync_enabled=False``)
       are excluded by the flag — only status is the pause/resume toggle in the
       UI, but ``scheduled_sync_enabled`` is the explicit opt-in gate.
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

    Supported providers (M35–M37 update)
    -------------------------------------
    Originally this function only covered cloudflare + github (M23), then vercel
    (M28).  Stripe (M35) and AWS (M36/M37) were added later but the filter was
    never updated, which silently caused scheduled syncs to never fire for those
    providers.  All five are now included.

    The ``sync_integration.delay`` import is deferred so this module stays
    importable in environments without Redis (e.g. unit tests that mock
    the queue).

    Returns:
        Dict with these integer counts:
          - ``integrations_seen``: total active integrations queried
          - ``enqueued``: number of scheduled SyncRuns created and queued
          - ``skipped_not_due``: skipped because interval has not elapsed
          - ``skipped_in_flight``: skipped because a pending/running sync existed
          - ``stale_cleaned``: in-flight SyncRuns that were stale and marked failed
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
    stale_cleaned = 0
    errors = 0

    now = datetime.now(timezone.utc)

    # All currently-supported providers.  If a new provider is added, extend
    # this tuple so its integrations are automatically included in scheduling.
    _SUPPORTED_PROVIDERS = (
        "cloudflare", "github", "vercel", "stripe", "aws", "firebase", "supabase", "shopify",
        "azure", "google_cloud", "twilio", "sendgrid", "auth0", "datadog", "clerk",
        "pagerduty",
        "linear",
        "jira",
        "gitlab",
        "terraform_cloud",
        "kubernetes",
    )

    # ── Diagnostic pre-scan ────────────────────────────────────────────────
    # Fetch ALL active integrations for this provider set so we can emit a
    # detailed breakdown before applying the eligibility filter.  A single
    # query is used; in-Python counting avoids extra round-trips and keeps
    # the mock interface unchanged for unit tests.
    _all_active = (
        db.query(Integration)
        .filter(
            Integration.provider.in_(_SUPPORTED_PROVIDERS),
            Integration.status == "active",
        )
        .all()
    )

    _total_active   = len(_all_active)
    _enabled_true   = sum(1 for i in _all_active if i.scheduled_sync_enabled is True)
    _enabled_false  = sum(1 for i in _all_active if i.scheduled_sync_enabled is False)
    _enabled_null   = _total_active - _enabled_true - _enabled_false
    _with_interval  = sum(1 for i in _all_active if i.sync_interval_minutes is not None)
    _interval_null  = _total_active - _with_interval

    logger.info(
        "enqueue_scheduled_syncs: diagnostics  "
        "total_active=%d  enabled_true=%d  enabled_false=%d  enabled_null=%d  "
        "with_interval=%d  interval_null=%d  providers=%s",
        _total_active,
        _enabled_true,
        _enabled_false,
        _enabled_null,
        _with_interval,
        _interval_null,
        _SUPPORTED_PROVIDERS,
    )

    # ── Eligibility filter ─────────────────────────────────────────────────
    # An integration is eligible for scheduling when:
    #   (a) scheduled_sync_enabled is explicitly True, OR
    #   (b) sync_interval_minutes is set (backward compatibility).
    #
    # Condition (b) handles integrations created before scheduled_sync_enabled
    # defaulted to True.  Those rows have scheduled_sync_enabled=False (the
    # old server_default) but a configured interval, which is sufficient
    # signal that the user intends scheduled syncs.  This avoids a data
    # migration while restoring correct behaviour for all existing integrations.
    #
    # Integrations with scheduled_sync_enabled=False AND no interval are
    # intentionally excluded — they have neither explicit opt-in nor a
    # configured cadence.
    integrations = [
        i for i in _all_active
        if i.scheduled_sync_enabled is True or i.sync_interval_minutes is not None
    ]

    logger.info(
        "enqueue_scheduled_syncs: scanning providers=%s  "
        "eligible=%d  total_active=%d",
        _SUPPORTED_PROVIDERS,
        len(integrations),
        _total_active,
    )

    for integration in integrations:
        seen += 1
        try:
            # ── Stale in-flight cleanup (reliability fix) ──────────────────
            # Must run BEFORE has_in_flight_sync so stale rows don't
            # permanently block the duplicate-prevention guard.
            stale_cleaned += _cleanup_stale_in_flight(integration.id, db, now)

            # ── Per-integration interval due-check (M29) ───────────────────
            if not _is_integration_due(integration, now):
                skipped_not_due += 1
                # Compute next_due_at for diagnostic observability at INFO
                # level — visible in Render logs without log-level changes.
                _interval = integration.sync_interval_minutes
                if _interval is None or _interval not in _ALLOWED_INTERVALS:
                    _interval = _DEFAULT_INTERVAL_MINUTES
                _next_due = (
                    integration.last_synced_at + timedelta(minutes=_interval)
                    if integration.last_synced_at
                    else now
                )
                logger.info(
                    "scheduled_sync skipped — interval not elapsed  "
                    "integration_id=%s provider=%s interval_minutes=%s "
                    "last_synced_at=%s next_due_at=%s",
                    integration.id,
                    integration.provider,
                    _interval,
                    integration.last_synced_at,
                    _next_due,
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
                "provider=%s user_id=%s interval_minutes=%s",
                sync_run.id,
                integration.id,
                integration.provider,
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
        "stale_cleaned": stale_cleaned,
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
