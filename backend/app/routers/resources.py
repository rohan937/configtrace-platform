"""Resources router — Milestone 11.

Routes
------
GET /resources                            — paginated list of resources
GET /resources/{resource_id}              — single resource with aggregate counts
GET /resources/{resource_id}/snapshots   — paginated snapshot history for a resource
GET /resources/{resource_id}/changes     — paginated change history for a resource

All routes are scoped to the authenticated user.  A missing resource and a
resource belonging to another user both return HTTP 404.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import UUID4
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.database import get_db
from app.models.change import Change
from app.models.snapshot import Snapshot
from app.models.user import User
from app.schemas.change import ChangeListItem, ChangeListResponse
from app.schemas.resource import (
    ResourceDetailResponse,
    ResourceListItem,
    ResourceListResponse,
    SnapshotListItem,
    SnapshotListResponse,
)
from app.services import resources_service

router = APIRouter(prefix="/resources", tags=["resources"])


@router.get("", response_model=ResourceListResponse)
def list_resources(
    integration_id: Optional[UUID4] = Query(
        None,
        description="Filter to resources under a specific integration.",
    ),
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(
        50, ge=1, le=100, description="Number of results per page (max 100)."
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ResourceListResponse:
    """Return a paginated list of resources owned by the authenticated user.

    Results are ordered by ``created_at DESC``.  Optionally filter by
    ``integration_id`` to list resources under a specific integration.
    """
    items, total = resources_service.get_resources(
        user_id=current_user.id,
        db=db,
        integration_id=integration_id,
        page=page,
        page_size=page_size,
    )
    return ResourceListResponse(
        items=[ResourceListItem.model_validate(r) for r in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{resource_id}", response_model=ResourceDetailResponse)
def get_resource(
    resource_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ResourceDetailResponse:
    """Return detail for a single resource, including snapshot and change counts.

    Returns HTTP 404 whether the resource does not exist or belongs to a
    different user.
    """
    resource = resources_service.get_resource_by_id(
        resource_id=resource_id,
        user_id=current_user.id,
        db=db,
    )
    if resource is None:
        raise HTTPException(status_code=404, detail="Resource not found.")

    snapshot_count: int = (
        db.query(Snapshot).filter(Snapshot.resource_id == resource.id).count()
    )
    change_count: int = (
        db.query(Change).filter(Change.resource_id == resource.id).count()
    )

    return ResourceDetailResponse(
        id=resource.id,
        integration_id=resource.integration_id,
        provider_resource_type=resource.provider_resource_type,
        provider_resource_id=resource.provider_resource_id,
        display_name=resource.display_name,
        metadata=resource.resource_metadata,
        last_snapshot_at=resource.last_snapshot_at,
        is_active=resource.is_active,
        created_at=resource.created_at,
        updated_at=resource.updated_at,
        snapshot_count=snapshot_count,
        change_count=change_count,
    )


@router.get("/{resource_id}/snapshots", response_model=SnapshotListResponse)
def list_resource_snapshots(
    resource_id: UUID4,
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(
        20, ge=1, le=100, description="Number of results per page (max 100)."
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SnapshotListResponse:
    """Return paginated snapshots for a resource, ordered newest-first.

    Each snapshot includes the full ``state`` array so the frontend resource
    history page can render the DNS record table without a second request.

    Returns HTTP 404 if the resource does not exist or belongs to another user.
    """
    items, total = resources_service.get_resource_snapshots(
        resource_id=resource_id,
        user_id=current_user.id,
        db=db,
        page=page,
        page_size=page_size,
    )
    if total == 0:
        # Distinguish "resource not found" from "resource exists, no snapshots".
        resource = resources_service.get_resource_by_id(
            resource_id=resource_id,
            user_id=current_user.id,
            db=db,
        )
        if resource is None:
            raise HTTPException(status_code=404, detail="Resource not found.")

    return SnapshotListResponse(
        items=[SnapshotListItem.model_validate(s) for s in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{resource_id}/changes", response_model=ChangeListResponse)
def list_resource_changes(
    resource_id: UUID4,
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(
        50, ge=1, le=100, description="Number of results per page (max 100)."
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChangeListResponse:
    """Return paginated changes for a resource, ordered newest-first.

    Each change item matches the shape returned by ``GET /changes``.

    Returns HTTP 404 if the resource does not exist or belongs to another user.
    """
    items, total = resources_service.get_resource_changes(
        resource_id=resource_id,
        user_id=current_user.id,
        db=db,
        page=page,
        page_size=page_size,
    )
    if total == 0:
        resource = resources_service.get_resource_by_id(
            resource_id=resource_id,
            user_id=current_user.id,
            db=db,
        )
        if resource is None:
            raise HTTPException(status_code=404, detail="Resource not found.")

    return ChangeListResponse(
        items=[ChangeListItem.model_validate(c) for c in items],
        total=total,
        page=page,
        page_size=page_size,
    )
