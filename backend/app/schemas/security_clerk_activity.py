"""Schemas for Clerk configuration activity ingestion (M83D).

Clerk's backend audit/event APIs include actor emails, user IDs, session
details, IP addresses, and user agents in every entry — ingesting those would
violate ConfigTrace's privacy contract. Instead, activity events are
synthesized from the same safe configuration surfaces the drift connector
already reads: instance settings, auth strategy, organization settings, session
policy, email/SMS settings, domains, redirect URL configs, JWT templates, and
webhook endpoints.

ConfigTrace stores only safe posture summaries — never Clerk secret key values,
publishable key values, session tokens, JWTs, OAuth tokens, bearer tokens,
webhook secrets, raw webhook URLs, raw redirect URLs, raw domain names,
JWT template body, custom claims, audience URIs, issuer URIs, user emails,
user IDs, phone numbers, names, member identities, session history, login
history, IP addresses, user agents, raw audit payloads, or PII.

Honest about partial/limited results: permission_limited is True when the
credentials lack access to a surface or the Clerk Backend API returns 401/403.
error_message is a short, safe string — never a credential value, token, URL,
or user-identifying data.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class ClerkActivitySyncRequest(BaseModel):
    """POST /security/clerk-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_events: int = Field(default=100, ge=1, le=1000)


class ClerkActivitySyncResponse(BaseModel):
    """Clerk configuration activity ingestion summary."""

    attempted: bool
    succeeded: bool
    provider: str = "clerk"
    source: str = "clerk_activity_event"
    integration_id: Optional[str] = None
    events_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None


class ClerkActivitySignalGenerateRequest(BaseModel):
    """POST /security/clerk-activity/generate-signals request body (all optional)."""

    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_signals: int = Field(default=100, ge=1, le=1000)


class ClerkActivitySignalGenerateResponse(BaseModel):
    """Clerk configuration activity signal generation summary."""

    provider: str = "clerk"
    source: str = "clerk_activity_event"
    events_scanned: int = 0
    groups_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
