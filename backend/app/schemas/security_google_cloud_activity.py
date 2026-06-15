"""Schemas for Google Cloud Audit Log ingestion (M78D).

Honest about partial/limited results: ``permission_limited`` is True when the
service account lacks the logging.logEntries.list permission on the project,
or when the Cloud Logging API returns 401/403/404/422. ``error_message`` is a
short, safe string — never credentials, bearer tokens, raw audit payloads,
principal emails, or PII.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class GoogleCloudActivitySyncRequest(BaseModel):
    """POST /security/google-cloud-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_events: Optional[int] = Field(default=None, ge=1, le=1000)


class GoogleCloudActivitySyncResponse(BaseModel):
    """Google Cloud Audit Log ingestion summary."""

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
