"""Pydantic schemas for resource and snapshot endpoints — Milestone 11.

The ``Resource`` ORM model stores the JSONB metadata column under the Python
attribute ``resource_metadata`` (to avoid shadowing SQLAlchemy's ``Base.metadata``),
but the column name in PostgreSQL — and the key exposed in the API — is
``metadata``.  The ``validation_alias`` on ``ResourceListItem.metadata`` handles
this mapping when the schema is populated from ORM objects via
``model_validate()``.  ``populate_by_name=True`` lets callers also pass
``metadata=...`` directly in constructor calls.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import UUID4, BaseModel, ConfigDict, Field


class ResourceListItem(BaseModel):
    """Single resource as returned by GET /resources."""

    id: UUID4
    integration_id: UUID4
    provider_resource_type: str
    provider_resource_id: str
    display_name: str
    # ORM attribute is ``resource_metadata``; JSON key is ``metadata``.
    metadata: Optional[dict[str, Any]] = Field(
        None, validation_alias="resource_metadata"
    )
    last_snapshot_at: Optional[datetime]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class ResourceDetailResponse(BaseModel):
    """Resource detail with aggregate counts — GET /resources/{id}."""

    id: UUID4
    integration_id: UUID4
    provider_resource_type: str
    provider_resource_id: str
    display_name: str
    metadata: Optional[dict[str, Any]]
    last_snapshot_at: Optional[datetime]
    is_active: bool
    created_at: datetime
    updated_at: datetime
    snapshot_count: int
    change_count: int

    model_config = ConfigDict(from_attributes=False)


class ResourceListResponse(BaseModel):
    """Paginated resource list — GET /resources."""

    items: list[ResourceListItem]
    total: int
    page: int
    page_size: int


class SnapshotListItem(BaseModel):
    """Single snapshot as returned by GET /resources/{id}/snapshots.

    ``state`` is included so the frontend resource-history page can render
    the full DNS record table without a separate request.
    """

    id: UUID4
    resource_id: UUID4
    integration_id: UUID4
    content_hash: str
    triggered_by: str
    sync_run_id: Optional[UUID4]
    state: list[dict[str, Any]]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SnapshotListResponse(BaseModel):
    """Paginated snapshot list — GET /resources/{id}/snapshots."""

    items: list[SnapshotListItem]
    total: int
    page: int
    page_size: int
