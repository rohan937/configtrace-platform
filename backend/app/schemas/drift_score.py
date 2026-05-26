"""Pydantic schemas for the Drift Control Score endpoint — M58.17.

GET /workspaces/{workspace_id}/drift-score → DriftScoreResponse

The Drift Control Score is a deterministic, advisory measure of how well
a workspace controls risky configuration drift.

Language guidelines (permanent):
  Use:   "drift control", "review and alert hygiene", "configuration drift"
  Avoid: "security rating", "compliance grade", "breach risk score",
         "SOC2 score", "certification"

The score is advisory only.  It does not imply compliance certification.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class DriftScoreFactor(BaseModel):
    """One deduction or concern contributing to the overall score."""

    key: str
    """Machine-readable factor identifier (e.g. 'unreviewed_critical')."""

    label: str
    """Human-readable short name shown in the UI."""

    impact: int
    """Score impact; negative means a penalty (e.g. -12)."""

    status: str
    """'good' | 'needs_attention' | 'critical'"""

    detail: str
    """Plain-English explanation of the factor."""

    action_label: Optional[str] = None
    """Short label for the CTA button, if any."""

    action_href: Optional[str] = None
    """Relative URL for the CTA, if any."""


class DriftScoreMetrics(BaseModel):
    """Raw metrics collected during scoring — no secrets or customer data."""

    providers_connected: int
    """Number of active integrations in this workspace."""

    total_changes_7d: int
    """Total configuration changes detected in the last 7 days."""

    high_critical_changes_7d: int
    """High or critical changes detected in the last 7 days."""

    unreviewed_high_critical: int
    """High/critical changes from the last 7 days with no completed review."""

    policy_violations_7d: int
    """Distinct policy violations found across top-risk changes in last 7 days."""

    stale_integrations: int
    """Integrations that haven't synced in 48h or have repeated failures."""

    review_completion_rate: float
    """Fraction of high/critical changes reviewed (0.0–1.0)."""

    alerts_configured: bool
    """True when at least one proactive alert channel is configured."""


class DriftScoreResponse(BaseModel):
    """Full Drift Control Score response.

    The score is advisory.  It does NOT represent a compliance certification,
    security rating, or breach risk score.  It measures review and alert
    hygiene for configuration drift.
    """

    score: int
    """Drift Control Score, 0–100.  Higher is better."""

    grade: str
    """
    'strong'         — 90–100
    'good'           — 75–89
    'needs_attention'— 55–74
    'weak'           — 0–54
    """

    trend: str
    """
    'up' | 'down' | 'flat' | 'unknown'
    M58.17 MVP: always 'unknown' (no score history table yet).
    """

    summary: str
    """One-sentence plain-English assessment for the workspace."""

    period_days: int
    """Number of days the score covers (7 for the current period)."""

    factors: list[DriftScoreFactor]
    """Ordered list of deductions applied to the score."""

    positive_signals: list[str]
    """Things the workspace is doing well."""

    recommended_actions: list[str]
    """Prioritised list of actions that would improve the score."""

    metrics: DriftScoreMetrics
    """Raw metrics used to compute the score."""
