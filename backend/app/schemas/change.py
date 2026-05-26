"""Pydantic schemas for change endpoints — Milestone 11 / M57.2.

All JSONB fields (prev_value, new_value, provider_metadata) are typed as
``Optional[Any]`` so that Pydantic does not coerce them.  They are stored and
returned verbatim from the database.

M57.2 adds optional ``review`` fields (ChangeReviewInfo) to both list and
detail responses.  When no review row exists for a change the ``review``
field is None; the frontend treats that as ``needs_review``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import UUID4, BaseModel, ConfigDict

from app.schemas.change_review import ChangeReviewInfo  # noqa: F401 (re-exported)


class ChangeListItem(BaseModel):
    """Single change as returned in the paginated timeline (GET /changes)."""

    id: UUID4
    integration_id: UUID4
    resource_id: UUID4
    change_type: str
    record_identifier: str
    field_path: Optional[str]
    prev_value: Optional[Any]
    new_value: Optional[Any]
    risk_level: str
    risk_reason: Optional[str]
    provider_metadata: Optional[dict[str, Any]]
    created_at: datetime

    # M57.2: review state (None = no review row exists → treat as needs_review)
    review: Optional[ChangeReviewInfo] = None

    model_config = ConfigDict(from_attributes=True)


class ChangeDetailResponse(BaseModel):
    """Full change detail including snapshot states — GET /changes/{id}.

    Extends the list item shape with snapshot identifiers and the full state
    arrays so the frontend can render the before/after DNS configuration
    without a second request.
    """

    id: UUID4
    integration_id: UUID4
    resource_id: UUID4
    change_type: str
    record_identifier: str
    field_path: Optional[str]
    prev_value: Optional[Any]
    new_value: Optional[Any]
    risk_level: str
    risk_reason: Optional[str]
    provider_metadata: Optional[dict[str, Any]]
    created_at: datetime

    # M57.2: review state
    review: Optional[ChangeReviewInfo] = None

    # Snapshot identifiers and states — absent from the list view
    prev_snapshot_id: UUID4
    new_snapshot_id: UUID4
    prev_snapshot_state: Optional[list[dict[str, Any]]]
    new_snapshot_state: Optional[list[dict[str, Any]]]
    prev_snapshot_created_at: Optional[datetime]
    new_snapshot_created_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=False)


class ChangeListResponse(BaseModel):
    """Paginated change list — GET /changes."""

    items: list[ChangeListItem]
    total: int
    page: int
    page_size: int
