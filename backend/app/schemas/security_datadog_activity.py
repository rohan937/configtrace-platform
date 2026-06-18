"""Schemas for Datadog configuration activity ingestion (M82D).

Datadog's audit/audit-trail API is identity-heavy — every entry includes
actor email, actor UUID, and IP-level request metadata. ConfigTrace NEVER
ingests from that endpoint. Instead, activity events are synthesized from
the same 10 safe drift surfaces the drift connector already reads:
monitors, SLOs, dashboards, webhook integrations, notification integrations,
API key metadata, application key metadata, roles, teams, and cloud integrations.

Honest about partial/limited results: ``permission_limited`` is True when
the credentials lack read access for one or more surfaces, or when the
Datadog API returns 401/403. ``error_message`` is a short, safe string —
never API key values, application key values, OAuth tokens, bearer tokens,
webhook secrets, raw monitor queries, raw monitor messages, raw dashboard
JSON, webhook URLs, headers, payload templates, notification handles,
email addresses, user IDs, IP addresses, user agents, or raw Datadog
audit payloads.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class DatadogActivitySyncRequest(BaseModel):
    """POST /security/datadog-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_events: int = Field(default=100, ge=1, le=1000)


class DatadogActivitySyncResponse(BaseModel):
    """Datadog configuration activity ingestion summary."""

    attempted: bool
    succeeded: bool
    provider: str = "datadog"
    source: str = "datadog_activity_event"
    integration_id: Optional[str] = None
    events_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None
