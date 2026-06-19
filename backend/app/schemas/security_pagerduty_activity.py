"""Schemas for PagerDuty configuration activity ingestion (M84D).

PagerDuty's audit API includes actor emails, user IDs, IP addresses, and
user agents in every entry — ingesting those would violate ConfigTrace's
privacy contract. Instead, activity events are synthesized from the same
safe configuration surfaces the drift connector already reads (M84A–M84C):
services, escalation policies, schedules, service integrations, webhook
subscriptions, event orchestrations, business services, and response plays.

ConfigTrace stores only safe posture summaries — never PagerDuty API tokens,
routing keys, integration keys, webhook secrets, delivery URLs, custom header
values, user emails, user names, phone numbers, contact methods, on-call user
identities, responder identities, subscriber identities, incident payloads,
alert payloads, conference phone numbers, raw routing expressions, IP
addresses, user agents, raw audit payloads, or PII.

Honest about partial/limited results: permission_limited is True when the
credentials lack access to a surface or the PagerDuty API returns 401/403.
error_message is a short, safe string — never a credential value, token, URL,
or user-identifying data.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class PagerDutyActivitySyncRequest(BaseModel):
    """POST /security/pagerduty-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_events: int = Field(default=100, ge=1, le=1000)


class PagerDutyActivitySyncResponse(BaseModel):
    """PagerDuty configuration activity ingestion summary."""

    attempted: bool
    succeeded: bool
    provider: str = "pagerduty"
    source: str = "pagerduty_activity_event"
    integration_id: Optional[str] = None
    events_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None


class PagerDutyActivitySignalGenerateRequest(BaseModel):
    """POST /security/pagerduty-activity/generate-signals request body (all optional)."""

    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_signals: int = Field(default=100, ge=1, le=1000)


class PagerDutyActivitySignalGenerateResponse(BaseModel):
    """PagerDuty configuration activity signal generation summary."""

    provider: str = "pagerduty"
    source: str = "pagerduty_activity_event"
    events_scanned: int = 0
    groups_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0


class PagerDutyCorrelationGenerateRequest(BaseModel):
    """POST /security/pagerduty-correlations/generate request body (all optional)."""

    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_correlations: Optional[int] = Field(default=None, ge=1, le=1000)


class PagerDutyCorrelationGenerateResponse(BaseModel):
    """PagerDuty Risk × Activity correlation generation summary."""

    provider: str = "pagerduty"
    findings_scanned: int = 0
    signals_scanned: int = 0
    candidate_pairs: int = 0
    correlations_created: int = 0
    correlations_skipped: int = 0
