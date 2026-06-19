"""Schemas for Linear configuration activity ingestion (M85D).

Linear's API does not expose a safe audit log — its audit endpoints include
actor emails, user IDs, session details, IP addresses, and user agents in
every entry.  Instead, activity events are synthesized from the same safe
configuration surfaces the drift connector already reads (M85A–M85C):
workspace, teams, projects, workflow states, issue labels, webhook
subscriptions, custom views, active cycles, and integrations.

ConfigTrace stores only safe posture summaries — never Linear API keys,
OAuth tokens, webhook secrets, raw webhook URLs, issue titles, issue
descriptions, comment bodies, attachment content, user emails, user names,
member identities, customer names, IP addresses, user agents, raw audit
payloads, or PII of any kind.

Honest about partial/limited results: permission_limited is True when the
credentials lack access to a surface or the Linear API returns 401/403.
error_message is a short, safe string — never a credential value, token, URL,
or user-identifying data.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class LinearActivitySyncRequest(BaseModel):
    """POST /security/linear-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_events: int = Field(default=100, ge=1, le=1000)


class LinearActivitySyncResponse(BaseModel):
    """Linear configuration activity ingestion summary."""

    attempted: bool
    succeeded: bool
    provider: str = "linear"
    source: str = "linear_activity_event"
    integration_id: Optional[str] = None
    events_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None


class LinearActivitySignalGenerateRequest(BaseModel):
    """POST /security/linear-activity/generate-signals request body (all optional)."""

    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_signals: int = Field(default=100, ge=1, le=1000)


class LinearActivitySignalGenerateResponse(BaseModel):
    """Linear configuration activity signal generation summary."""

    provider: str = "linear"
    source: str = "linear_activity_event"
    events_scanned: int = 0
    groups_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
