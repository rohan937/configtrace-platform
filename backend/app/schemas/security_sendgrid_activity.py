"""Schemas for SendGrid configuration activity ingestion (M80D).

SendGrid does NOT have a native audit/event API for configuration changes.
Therefore these "activity events" are config-state observations synthesized
from the existing safe SendGrid configuration surfaces (account, API keys,
sender identities, domain authentication, mail settings, tracking settings,
event webhook, inbound parse, and suppression settings).

Honest about partial/limited results: ``permission_limited`` is True when the
credentials lack access to the SendGrid configuration surfaces, or when the
SendGrid API returns 401/403/404. ``error_message`` is a short, safe string —
never API key values, bearer tokens, authorization headers, email bodies,
subject lines, recipient emails, sender personal emails, template content,
raw webhook URLs, mail event payloads, customer data, or PII.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class SendGridActivitySyncRequest(BaseModel):
    """POST /security/sendgrid-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_events: int = Field(default=100, ge=1, le=1000)


class SendGridActivitySyncResponse(BaseModel):
    """SendGrid configuration activity ingestion summary."""

    attempted: bool
    succeeded: bool
    provider: str = "sendgrid"
    source: str = "sendgrid_activity_event"
    integration_id: Optional[str] = None
    events_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None
