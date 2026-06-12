"""Schemas for AWS S3 object-level data-event ingestion (M67.8)."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class AwsS3DataEventSyncRequest(BaseModel):
    """POST /security/aws-s3-data-events/sync request body.

    ``trail_bucket`` is required: CloudTrail S3 data events are only available
    from a configured trail's delivery bucket (LookupEvents cannot return them).
    """

    trail_bucket: str = Field(min_length=1, max_length=255)
    integration_id: Optional[str] = None
    trail_prefix: Optional[str] = Field(default=None, max_length=512)
    max_files: Optional[int] = Field(default=None, ge=1, le=200)
    max_events: Optional[int] = Field(default=None, ge=1, le=20000)


class AwsS3DataEventSyncResponse(BaseModel):
    """S3 data-event ingestion summary."""

    attempted: bool
    succeeded: bool
    provider: str
    integration_id: Optional[str] = None
    source: str
    files_seen: int = 0
    files_read: int = 0
    events_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None
