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


class AwsBehaviorSignalGenerateRequest(BaseModel):
    """POST /security/aws-cloudtrail/generate-behavior-signals request (optional)."""

    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_signals: Optional[int] = Field(default=None, ge=1, le=1000)


class AwsBehaviorSignalGenerateResponse(BaseModel):
    """IAM behavior-timeline signal generation summary (M67.6)."""

    provider: str
    events_scanned: int = 0
    principals_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
