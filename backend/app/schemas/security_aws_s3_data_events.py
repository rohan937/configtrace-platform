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


class AwsS3AccessSignalGenerateRequest(BaseModel):
    """POST /security/aws-s3-data-events/generate-signals request (optional)."""

    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_signals: Optional[int] = Field(default=None, ge=1, le=1000)
    read_threshold: Optional[int] = Field(default=None, ge=2, le=100000)


class AwsS3AccessSignalGenerateResponse(BaseModel):
    """S3 object-access-spike signal generation summary (M67.9)."""

    provider: str
    events_scanned: int = 0
    buckets_scanned: int = 0
    actors_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
