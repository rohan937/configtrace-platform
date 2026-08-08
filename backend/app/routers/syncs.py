"""Sync run routes.

POST /syncs          — trigger a manual sync for an integration
GET  /syncs/{run_id} — poll sync status (used by the frontend after POST /syncs)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import UUID4
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.sync import SyncCreateRequest, SyncRunResponse
from app.services import integration_service, sync_service

router = APIRouter(prefix="/syncs", tags=["syncs"])


@router.post("", response_model=SyncRunResponse, status_code=201)
def create_sync(
    body: SyncCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SyncRunResponse:
    """Trigger a manual sync for an integration.

    Steps
    -----
    1. Verify the integration exists and belongs to the authenticated user.
    2. Create a ``SyncRun`` with ``status='pending'``.
    3. Enqueue the ``sync_integration`` Celery task.
    4. Return the ``SyncRun`` immediately — poll ``GET /syncs/{id}`` for updates.

    The Celery task runs in the background and updates the sync run status
    through ``pending → running → completed | failed``.
    """
    # Any workspace member may trigger a sync (M51 workspace scoping) —
    # matches GET /integrations/{id}'s viewer-level access; only
    # management actions (update/delete/reconnect) require admin+.
    integration = integration_service.get_integration_for_viewer(
        integration_id=body.integration_id,
        actor_user_id=current_user.id,
        db=db,
    )
    if integration is None:
        # Also covers soft-deleted integrations — both missing and deleted
        # map to 404 so callers cannot distinguish the two cases.
        raise HTTPException(
            status_code=404,
            detail="Integration not found or does not belong to this user.",
        )

    # M29: Block manual Sync Now for paused integrations.
    # Deleted integrations are caught by the 404 above (get_integration_by_id
    # excludes status='deleted').
    if integration.status == "paused":
        raise HTTPException(
            status_code=409,
            detail=(
                "Integration is paused. "
                "Enable it before running a sync."
            ),
        )

    # M59.14: Block manual Sync Now for integrations whose upstream credentials
    # have been revoked (GitHub App uninstalled, token rotated externally,
    # AWS keys deleted, etc.).  Running a sync would just fail again with the
    # same auth error — the only forward path is a reconnect.
    if integration.status == "needs_reconnect":
        raise HTTPException(
            status_code=409,
            detail=(
                "Integration needs to be reconnected — the upstream "
                "credentials or installation are no longer valid. "
                "Use the Reconnect action to provide fresh credentials."
            ),
        )

    # M59.4: Manual sync dedupe.  If a SyncRun is already pending or running
    # for this integration, refuse to enqueue another — Sync Now spam would
    # otherwise stack identical jobs and trigger redundant provider calls.
    # The same helper is used by the scheduler to skip overlapping ticks.
    if sync_service.has_in_flight_sync(body.integration_id, db):
        raise HTTPException(
            status_code=409,
            detail=(
                "A sync is already in progress for this integration. "
                "Wait for it to complete before triggering another."
            ),
        )

    try:
        sync_run = sync_service.create_sync_run(
            user_id=current_user.id,
            integration_id=body.integration_id,
            db=db,
        )
    except sync_service.SyncAlreadyInProgressError:
        # has_in_flight_sync() above raced with another inserter (a Beat
        # tick, or a second concurrent request) and lost — the DB-level
        # guard (mig037) caught it. Same response as the pre-check case.
        raise HTTPException(
            status_code=409,
            detail=(
                "A sync is already in progress for this integration. "
                "Wait for it to complete before triggering another."
            ),
        ) from None

    # Import deferred to avoid circular imports at module load time and to
    # ensure the SyncRun is committed before the task is enqueued.
    from app.workers.sync_task import sync_integration  # noqa: PLC0415

    try:
        sync_integration.delay(
            sync_run_id=str(sync_run.id),
            integration_id=str(body.integration_id),
            user_id=str(current_user.id),
        )
    except Exception as exc:
        # Broker (Redis) unreachable, or any other publish-time failure.
        # The SyncRun row above already committed as 'pending' — if we
        # leave it that way, has_in_flight_sync() will report this
        # integration as permanently busy and reject every future Sync
        # Now until an operator intervenes directly in the DB (the
        # 30-minute stale-run reaper only runs for integrations with
        # scheduled syncs configured, so manual-only integrations would
        # never self-heal). Mark it failed immediately instead so the
        # in-flight guard clears and the user can retry.
        sync_service.mark_sync_failed(
            sync_run.id,
            error_message=f"Could not queue sync: {exc}",
            failure_category="internal_error",
            db=db,
        )
        raise HTTPException(
            status_code=503,
            detail=(
                "Could not start the sync — the background processing "
                "system is temporarily unavailable. Try again shortly."
            ),
        ) from exc

    return sync_run


@router.get("/{run_id}", response_model=SyncRunResponse)
def get_sync_run(
    run_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SyncRunResponse:
    """Return the current state of a sync run.

    Poll this endpoint after calling ``POST /syncs`` until ``status`` is
    ``'completed'`` or ``'failed'``.  A polling interval of 2 seconds is
    recommended for the frontend.
    """
    sync_run = sync_service.get_sync_run(
        user_id=current_user.id,
        sync_run_id=run_id,
        db=db,
    )
    if sync_run is None:
        raise HTTPException(
            status_code=404,
            detail="Sync run not found or does not belong to this user.",
        )
    return sync_run
