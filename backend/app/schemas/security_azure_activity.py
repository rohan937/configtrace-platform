"""Schemas for Azure Activity Log ingestion (M77D).

Activity ingestion only — no signals, correlations, or demo for Azure in this
milestone. Honest about partial/limited results: ``permission_limited`` is True
when the service principal lacks the Reader role on the subscription, or when
the Activity Log endpoint returns 401/403/404/422. ``error_message`` is a short,
safe string — never credentials, bearer tokens, raw event payloads, Azure
resource secrets, or PII.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class AzureActivitySyncRequest(BaseModel):
    """POST /security/azure-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_events: Optional[int] = Field(default=None, ge=1, le=1000)


class AzureActivitySyncResponse(BaseModel):
    """Azure Activity Log ingestion summary."""

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
