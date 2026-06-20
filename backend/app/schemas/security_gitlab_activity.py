"""Schemas for GitLab configuration activity ingestion (M87D).

GitLab's audit log APIs are identity-heavy: every entry includes actor
user IDs, actor emails, IP addresses, and user agents.  ConfigTrace NEVER
ingests from those endpoints.  Instead, activity events are synthesized
from the same safe configuration posture summaries the GitLab drift
connector already stores (M87A–M87C): instance, projects, groups, branch
protection rules, webhooks, CI variable summaries, deploy key summaries,
runner summaries, and MR approval summaries.

ConfigTrace stores only safe posture summaries — never GitLab access
tokens, OAuth tokens, PRIVATE-TOKEN values, webhook secret tokens, raw
webhook URLs, CI/CD variable names or values, deploy key material, SSH
keys, runner tokens, runner IPs, project names, group names, namespace
paths, branch names, commit messages, merge request titles, issue titles,
pipeline logs, job logs, artifacts, user emails, usernames, customer data,
PII, or raw GitLab API payloads of any kind.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class GitLabActivitySyncRequest(BaseModel):
    """POST /security/gitlab-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_events: int = Field(default=100, ge=1, le=1000)


class GitLabActivitySyncResponse(BaseModel):
    """GitLab configuration activity ingestion summary."""

    provider: str = "gitlab"
    source: str = "gitlab_activity_event"
    events_scanned: int = 0
    events_created: int = 0
    events_skipped: int = 0
    groups_scanned: int = 0
    lookback_hours: int = 24
    max_events: int = 100


class GitLabActivitySignalGenerateRequest(BaseModel):
    """POST /security/gitlab-activity/generate-signals request body (all optional)."""

    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_signals: int = Field(default=100, ge=1, le=1000)


class GitLabActivitySignalGenerateResponse(BaseModel):
    """GitLab configuration activity signal generation summary."""

    provider: str = "gitlab"
    source: str = "gitlab_activity_event"
    events_scanned: int = 0
    groups_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
    lookback_hours: int = 24
    max_signals: int = 100
