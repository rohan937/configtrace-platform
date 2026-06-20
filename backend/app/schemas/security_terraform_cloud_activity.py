"""Schemas for Terraform Cloud configuration activity ingestion (M88D).

Terraform Cloud audit-log APIs expose actor user IDs, emails, IP addresses,
and workspace names in every entry.  ConfigTrace NEVER ingests from those
endpoints.  Instead, activity events are synthesized from the same safe
configuration posture records the Terraform Cloud drift connector already
stores (M88A–M88C): organization, workspace, workspace variable summaries,
variable sets, policy sets, notification configurations, run triggers, team
access summaries, and state version summaries.

ConfigTrace stores only safe posture summaries — never Terraform Cloud API
tokens, OAuth tokens, VCS tokens, authorization headers, variable names or
values, Terraform state files, state outputs, resource addresses, plan logs,
apply logs, run logs, webhook URLs, notification tokens, Slack channels,
email recipients, user emails, usernames, team names, organization names,
workspace names, project names, VCS repository names, VCS URLs, branch names,
commit SHAs, customer infrastructure data, PII, or raw API payloads of any
kind.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class TerraformCloudActivitySyncRequest(BaseModel):
    """POST /security/terraform-cloud-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_events: int = Field(default=100, ge=1, le=1000)


class TerraformCloudActivitySyncResponse(BaseModel):
    """Terraform Cloud configuration activity ingestion summary."""

    provider: str = "terraform_cloud"
    source: str = "terraform_cloud_activity_event"
    events_scanned: int = 0
    events_created: int = 0
    events_skipped: int = 0
    groups_scanned: int = 0
    lookback_hours: int = 24
    max_events: int = 100


class TerraformCloudActivitySignalGenerateRequest(BaseModel):
    """POST /security/terraform-cloud-activity/generate-signals request body (all optional)."""

    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_signals: int = Field(default=100, ge=1, le=1000)


class TerraformCloudActivitySignalGenerateResponse(BaseModel):
    """Terraform Cloud configuration activity signal generation summary."""

    provider: str = "terraform_cloud"
    source: str = "terraform_cloud_activity_event"
    events_scanned: int = 0
    groups_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
    lookback_hours: int = 24
    max_signals: int = 100


class TerraformCloudRiskActivityCorrelationGenerateRequest(BaseModel):
    """POST /security/terraform-cloud-activity/generate-correlations request body (all optional)."""

    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_correlations: int = Field(default=100, ge=1, le=1000)


class TerraformCloudRiskActivityCorrelationGenerateResponse(BaseModel):
    """Terraform Cloud Risk × Activity correlation generation summary."""

    provider: str = "terraform_cloud"
    findings_scanned: int = 0
    signals_scanned: int = 0
    events_scanned: int = 0
    correlations_created: int = 0
    correlations_skipped: int = 0
    groups_scanned: int = 0
    lookback_hours: int = 24
    max_correlations: int = 100
