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
    integration = integration_service.get_integration_by_id(
        integration_id=body.integration_id,
        user_id=current_user.id,
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

    sync_run = sync_service.create_sync_run(
        user_id=current_user.id,
        integration_id=body.integration_id,
        db=db,
    )

    # Import deferred to avoid circular imports at module load time and to
    # ensure the SyncRun is committed before the task is enqueued.
    from app.workers.sync_task import sync_integration  # noqa: PLC0415

    sync_integration.delay(
        sync_run_id=str(sync_run.id),
        integration_id=str(body.integration_id),
        user_id=str(current_user.id),
    )

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
