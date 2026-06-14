"""Schemas for Vercel activity/audit ingestion (M70B).

Activity ingestion only — no signals, correlations, or demo. Honest about
partial/limited results: ``permission_limited`` is True when the Vercel
token/team does not grant audit-log access (common outside Enterprise plans).
``error_message`` is a short, safe string — never secrets/tokens/URLs.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class VercelActivitySyncRequest(BaseModel):
    """POST /security/vercel-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_events: Optional[int] = Field(default=None, ge=1, le=1000)


class VercelActivitySyncResponse(BaseModel):
    """Vercel activity/audit ingestion summary."""

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


class VercelActivitySignalGenerateRequest(BaseModel):
    """POST /security/vercel-activity/generate-signals body (M70C, all optional)."""

    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_signals: Optional[int] = Field(default=None, ge=1, le=1000)


class VercelActivitySignalGenerateResponse(BaseModel):
    """Vercel activity Incident Signal generation summary (M70C)."""

    provider: str
    source: str
    events_scanned: int = 0
    groups_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
