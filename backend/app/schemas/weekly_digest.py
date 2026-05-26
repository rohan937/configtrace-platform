"""Weekly digest schemas — M58.15.

All types are display-safe:
  - No raw credential values, tokens, or secrets.
  - No raw prev_value / new_value.
  - No customer data (order IDs, payment data, email addresses).
  - Language: "detected", "needs review", "policy violation" — never "breach".
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


# ── Digest sub-objects ────────────────────────────────────────────────────────


class WeeklyDigestRiskCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class WeeklyDigestReviewCounts(BaseModel):
    needs_review: int
    acknowledged: int
    expected: int
    snoozed: int


class WeeklyDigestPolicyViolationEntry(BaseModel):
    policy_key: str
    name: str
    count: int
    severity: str


class WeeklyDigestPolicyViolations(BaseModel):
    total: int
    top_policies: list[WeeklyDigestPolicyViolationEntry]


class WeeklyDigestProviderActivity(BaseModel):
    provider: str
    change_count: int
    high_or_critical_count: int


class WeeklyDigestTopRisk(BaseModel):
    """A top-risk change summary.  Never includes raw diff content."""

    change_id: str
    title: str          # provider-safe plain-English title, no raw values
    provider: str
    risk_level: str
    status: str         # review_status or "needs_review"
    url: str            # link to change detail page


class WeeklyDigestStaleIntegration(BaseModel):
    integration_id: str
    provider: str
    name: str
    last_synced_at: Optional[datetime]
    consecutive_failure_count: int


# ── Main digest object ────────────────────────────────────────────────────────


class WeeklyDigest(BaseModel):
    workspace_id: str
    workspace_name: str
    period_start: datetime
    period_end: datetime
    generated_at: datetime

    total_changes: int
    risk_counts: WeeklyDigestRiskCounts
    review_counts: WeeklyDigestReviewCounts
    review_completion_rate: float   # 0.0–1.0; 1.0 when no changes

    policy_violations: WeeklyDigestPolicyViolations
    provider_activity: list[WeeklyDigestProviderActivity]
    top_risks: list[WeeklyDigestTopRisk]
    stale_integrations: list[WeeklyDigestStaleIntegration]
    recommended_actions: list[str]


# ── Settings ──────────────────────────────────────────────────────────────────


class WeeklyDigestSettings(BaseModel):
    """Current digest schedule settings for a workspace."""

    workspace_id: str
    weekly_digest_enabled: bool
    weekly_digest_day: int          # 0 = Monday … 6 = Sunday
    weekly_digest_hour: int         # 0–23 UTC
    weekly_digest_timezone: Optional[str]
    weekly_digest_last_sent_at: Optional[datetime]


class WeeklyDigestSettingsUpdateRequest(BaseModel):
    """PUT body to update digest schedule settings."""

    weekly_digest_enabled: Optional[bool] = None
    weekly_digest_day: Optional[int] = None    # 0–6
    weekly_digest_hour: Optional[int] = None   # 0–23
    weekly_digest_timezone: Optional[str] = None


# ── Test send response ────────────────────────────────────────────────────────


class WeeklyDigestTestResponse(BaseModel):
    """Response from POST /weekly-digest/test."""

    sent: bool
    recipient: Optional[str]          # masked — first 3 chars + "****@..." form
    email_configured: bool
    preview_body: Optional[str]       # rendered email body (always returned)
    error: Optional[str]
