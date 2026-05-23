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

    model_config = {"from_attributes": True}


class SyncRunListResponse(BaseModel):
    """Response body for ``GET /integrations/{id}/sync-runs``.

    ``sync_runs`` is the *limit* most-recent runs ordered newest first.
    ``total`` is the lifetime count of SyncRuns for this integration — lets
    the frontend show "Last 10 of N total runs" without a second query.
    """

    sync_runs: list[SyncRunResponse]
    total: int
