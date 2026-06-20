"""Schemas for Jira configuration activity ingestion (M86D).

Jira's audit log / issue / user activity APIs are identity-heavy: every entry
includes actor account IDs, actor emails, IP addresses, user agents, issue
keys, and issue content.  ConfigTrace NEVER ingests from those endpoints.
Instead, activity events are synthesized from the same safe configuration
posture summaries the drift connector already stores (M86A–M86C): site,
projects, boards, workflows, workflow schemes, permission schemes,
notification schemes, issue type schemes, field configuration schemes, screen
schemes, webhooks, and automation rules.

ConfigTrace stores only safe posture summaries — never Jira API tokens, OAuth
tokens, webhook secrets, raw webhook/delivery URLs, site base URLs, JQL,
filter expressions, issue keys, issue titles, issue descriptions, comment
bodies, attachment content, customer names, user emails, user names, account
IDs, IP addresses, user agents, raw audit payloads, or PII of any kind.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class JiraActivitySyncRequest(BaseModel):
    """POST /security/jira-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_events: int = Field(default=100, ge=1, le=1000)


class JiraActivitySyncResponse(BaseModel):
    """Jira configuration activity ingestion summary."""

    provider: str = "jira"
    source: str = "jira_activity_event"
    events_scanned: int = 0
    events_created: int = 0
    events_skipped: int = 0
    groups_scanned: int = 0
    lookback_hours: int = 24
    max_events: int = 100


class JiraActivitySignalGenerateRequest(BaseModel):
    """POST /security/jira-activity/generate-signals request body (all optional)."""

    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_signals: int = Field(default=100, ge=1, le=1000)


class JiraActivitySignalGenerateResponse(BaseModel):
    """Jira configuration activity signal generation summary."""

    provider: str = "jira"
    source: str = "jira_activity_event"
    events_scanned: int = 0
    groups_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
    lookback_hours: int = 24
    max_signals: int = 100
