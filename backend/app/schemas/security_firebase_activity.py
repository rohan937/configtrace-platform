"""Schemas for Firebase activity/audit ingestion (M72B).

Activity ingestion only — no signals, correlations, or demo. Honest about
partial/limited results: ``permission_limited`` is True when the Firebase
service-account credentials do not grant Cloud Audit Log read access (the common
case for a read-only config-sync service account). ``error_message`` is a short,
safe string — never secrets/tokens/URLs.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class FirebaseActivitySyncRequest(BaseModel):
    """POST /security/firebase-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_events: Optional[int] = Field(default=None, ge=1, le=1000)


class FirebaseActivitySyncResponse(BaseModel):
    """Firebase activity/audit ingestion summary."""

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
