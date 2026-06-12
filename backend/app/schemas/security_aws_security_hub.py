"""Schemas for AWS Security Hub findings ingestion + signal generation (M67.7)."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class AwsSecurityHubSyncRequest(BaseModel):
    """POST /security/aws-security-hub/sync request body (all optional)."""

    integration_id: Optional[str] = None
    max_pages: Optional[int] = Field(default=None, ge=1, le=5)


class AwsSecurityHubSyncResponse(BaseModel):
    """Security Hub ingestion summary — provider-reported findings into events."""

    attempted: bool
    succeeded: bool
    provider: str
    integration_id: Optional[str] = None
    source: str
    findings_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None


class AwsSecurityHubSignalGenerateResponse(BaseModel):
    """Security Hub Incident Signal generation summary."""

    provider: str
    activity_events_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
