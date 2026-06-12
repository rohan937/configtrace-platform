"""Schemas for AWS security-alert ingestion + signal generation (M67.1)."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class AwsAlertSyncRequest(BaseModel):
    """POST /security/aws-alerts/sync request body (all optional)."""

    integration_id: Optional[str] = None


class AwsAlertSyncResponse(BaseModel):
    """Ingestion summary — provider-reported findings into activity events."""

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


class AwsSignalGenerateResponse(BaseModel):
    """AWS Incident Signal generation summary."""

    provider: str
    activity_events_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
