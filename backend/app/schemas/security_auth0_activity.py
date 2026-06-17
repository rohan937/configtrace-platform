"""Schemas for Auth0 configuration activity ingestion (M81D).

Auth0 Management API logs (/api/v2/logs) are highly user-centric — every
entry includes user_id, email, IP address, and device data. ConfigTrace
NEVER ingests from that endpoint. Instead, activity events are synthesized
from the same safe configuration surfaces the drift connector already reads:
tenant settings, applications, connections, resource servers, rules, actions,
MFA/Guardian factors, and custom domains.

Honest about partial/limited results: ``permission_limited`` is True when
the credentials lack Management API read access for a surface, or when the
Auth0 Management API returns 401/403/404. ``error_message`` is a short,
safe string — never client secrets, management tokens, access tokens, JWTs,
raw callback URLs, raw logout URLs, raw allowed origins, audience URIs,
custom domain names, rule/action script content, action secret values,
user emails, user IDs, IP addresses, session data, or PII.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class Auth0ActivitySyncRequest(BaseModel):
    """POST /security/auth0-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_events: int = Field(default=100, ge=1, le=1000)


class Auth0ActivitySyncResponse(BaseModel):
    """Auth0 configuration activity ingestion summary."""

    attempted: bool
    succeeded: bool
    provider: str = "auth0"
    source: str = "auth0_activity_event"
    integration_id: Optional[str] = None
    events_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None


class Auth0ActivitySignalGenerateRequest(BaseModel):
    """POST /security/auth0-activity/generate-signals request body (all optional)."""

    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_signals: int = Field(default=100, ge=1, le=1000)


class Auth0ActivitySignalGenerateResponse(BaseModel):
    """Auth0 configuration activity signal generation summary."""

    provider: str = "auth0"
    source: str = "auth0_activity_event"
    events_scanned: int = 0
    groups_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
