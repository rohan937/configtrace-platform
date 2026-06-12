"""Schemas for AWS CloudTrail management-event ingestion (M67.5)."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class AwsCloudTrailSyncRequest(BaseModel):
    """POST /security/aws-cloudtrail/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_pages: Optional[int] = Field(default=None, ge=1, le=10)


class AwsCloudTrailSyncResponse(BaseModel):
    """CloudTrail ingestion summary — control-plane events into activity events."""

    attempted: bool
    succeeded: bool
    provider: str
    integration_id: Optional[str] = None
    source: str
    events_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None
