"""Schemas for Twilio Monitor activity ingestion (M79D).

Honest about partial/limited results: ``permission_limited`` is True when the
credentials lack access to the Twilio Monitor API, or when the Monitor API
returns 401/403/404. ``error_message`` is a short, safe string — never
auth tokens, API secrets, raw phone numbers, message bodies, call logs,
recordings, customer data, or PII.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class TwilioActivitySyncRequest(BaseModel):
    """POST /security/twilio-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_events: int = Field(default=100, ge=1, le=1000)


class TwilioActivitySyncResponse(BaseModel):
    """Twilio Monitor activity ingestion summary."""

    attempted: bool
    succeeded: bool
    provider: str = "twilio"
    source: str = "twilio_activity_event"
    integration_id: Optional[str] = None
    events_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None


class TwilioActivitySignalGenerateRequest(BaseModel):
    """POST /security/twilio-activity/generate-signals request body (all optional)."""

    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_signals: int = Field(default=100, ge=1, le=1000)


class TwilioActivitySignalGenerateResponse(BaseModel):
    """Twilio activity signal generation summary."""

    provider: str = "twilio"
    source: str = "twilio_activity_event"
    events_scanned: int = 0
    groups_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0


class TwilioCorrelationGenerateRequest(BaseModel):
    """POST /security/twilio-correlations/generate request body (all optional)."""

    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_correlations: int = Field(default=100, ge=1, le=1000)


class TwilioCorrelationGenerateResponse(BaseModel):
    """Twilio risk × activity correlation generation summary."""

    provider: str = "twilio"
    findings_scanned: int = 0
    signals_scanned: int = 0
    correlations_created: int = 0
    correlations_skipped: int = 0
