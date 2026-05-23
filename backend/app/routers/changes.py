"""Changes router — Milestone 11.

Routes
------
GET /changes              — paginated, filtered change timeline
GET /changes/{change_id}  — single change with full snapshot context

Both routes are scoped to the authenticated user.  A missing change and a
change belonging to another user both return HTTP 404 — the caller cannot
tell whether the change exists for a different user.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import UUID4
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.database import get_db
from app.models.snapshot import Snapshot
from app.models.user import User
from app.schemas.change import ChangeDetailResponse, ChangeListItem, ChangeListResponse
from app.services import changes_service

router = APIRouter(prefix="/changes", tags=["changes"])


@router.get("", response_model=ChangeListResponse)
def list_changes(
    integration_id: Optional[UUID4] = Query(
        None,
        description="Filter to changes from a specific integration.",
    ),
    resource_id: Optional[UUID4] = Query(
        None,
        description="Filter to changes from a specific resource.",
    ),
    risk_level: Optional[str] = Query(
        None,
        description="Filter by risk level: low, medium, high, critical.",
    ),
    change_type: Optional[str] = Query(
        None,
        description="Filter by change type: added, removed, modified.",
    ),
    provider: Optional[str] = Query(
        None,
        description=(
            "Filter by provider: cloudflare, github. "
            "Changes from soft-deleted integrations are still included "
            "so historical data is preserved."
        ),
    ),
    since: Optional[datetime] = Query(
        None,
        description="Return only changes at or after this ISO 8601 datetime.",
    ),
    until: Optional[datetime] = Query(
        None,
        description="Return only changes at or before this ISO 8601 datetime.",
    ),
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(
        50, ge=1, le=100, description="Number of results per page (max 100)."
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChangeListResponse:
    """Return a paginated, filtered list of changes for the authenticated user.

    All filters are optional and combined with AND.  Results are ordered by
    ``created_at DESC`` (most-recent change first).

    The response includes a ``total`` count of matching rows before pagination
    so the frontend can render a "Showing N of M" indicator.
    """
    items, total = changes_service.get_changes(
        user_id=current_user.id,
        db=db,
        integration_id=integration_id,
        resource_id=resource_id,
        risk_level=risk_level,
        change_type=change_type,
        provider=provider,
        since=since,
        until=until,
        page=page,
        page_size=page_size,
    )
    return ChangeListResponse(
        items=[ChangeListItem.model_validate(c) for c in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{change_id}", response_model=ChangeDetailResponse)
def get_change(
    change_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChangeDetailResponse:
    """Return full detail for a single change, including snapshot states.

    In addition to all list-view fields, the response includes:
    - ``prev_snapshot_id`` / ``new_snapshot_id``  — snapshot UUIDs
    - ``prev_snapshot_state`` / ``new_snapshot_state``  — full DNS record lists
    - ``prev_snapshot_created_at`` / ``new_snapshot_created_at``  — timestamps

    This powers the change detail page without requiring a second API request
    to the snapshots endpoint.

    Returns HTTP 404 whether the change does not exist or belongs to a
    different user.
    """
    change = changes_service.get_change_by_id(
        change_id=change_id,
        user_id=current_user.id,
        db=db,
    )
    if change is None:
        raise HTTPException(status_code=404, detail="Change not found.")

    prev_snap: Optional[Snapshot] = db.get(Snapshot, change.prev_snapshot_id)
    new_snap: Optional[Snapshot] = db.get(Snapshot, change.new_snapshot_id)

    return ChangeDetailResponse(
        id=change.id,
        integration_id=change.integration_id,
        resource_id=change.resource_id,
        change_type=change.change_type,
        record_identifier=change.record_identifier,
        field_path=change.field_path,
        prev_value=change.prev_value,
        new_value=change.new_value,
        risk_level=change.risk_level,
        risk_reason=change.risk_reason,
        provider_metadata=change.provider_metadata,
        created_at=change.created_at,
        prev_snapshot_id=change.prev_snapshot_id,
        new_snapshot_id=change.new_snapshot_id,
        prev_snapshot_state=prev_snap.state if prev_snap else None,
        new_snapshot_state=new_snap.state if new_snap else None,
        prev_snapshot_created_at=prev_snap.created_at if prev_snap else None,
        new_snapshot_created_at=new_snap.created_at if new_snap else None,
    )
