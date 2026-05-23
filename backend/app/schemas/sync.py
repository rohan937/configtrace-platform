"""Pydantic schemas for sync run endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import UUID4, BaseModel, Field


class SyncCreateRequest(BaseModel):
    """Request body for ``POST /syncs``."""

    integration_id: UUID4 = Field(
        ...,
        description="UUID of the integration to sync.",
    )


class SyncRunResponse(BaseModel):
    """Response shape for a sync run record.

    Poll ``GET /syncs/{id}`` until ``status`` is ``'completed'`` or
    ``'failed'``.  The frontend should treat any non-terminal status as
    'still running' and retry with a short interval (e.g. 2 s).
    """

    id: UUID4
    integration_id: UUID4
    user_id: UUID4
    status: str
    triggered_by: str
    started_at: datetime
    completed_at: Optional[datetime]
    change_count: Optional[int]
    snapshot_count: Optional[int]
    error_message: Optional[str]
    created_at: datetime

    # ── M32: structured failure classification ────────────────────────────────
    # Populated only for failed runs.  Null for completed/pending/running runs.
    # failure_category: broad category (authentication, network, config_error …)
    # error_code:       provider-specific machine-readable code
    # recommended_action: user-facing remediation hint
    failure_category: Optional[str] = None
    error_code: Optional[str] = None
    recommended_action: Optional[str] = None

    model_config = {"from_attributes": True}


class SyncRunListResponse(BaseModel):
    """Response body for ``GET /integrations/{id}/sync-runs``.

    Supports cursor-free offset pagination.  ``sync_runs`` is one page of
    runs ordered newest first.  ``total`` is the all-time SyncRun count for
    this integration (considering any applied filters).
    ``total_pages`` is derived from ``total`` / ``page_size``.
    """

    sync_runs: list[SyncRunResponse]
    total: int
    page: int = 1
    page_size: int = 25
    total_pages: int = 1
