"""Pydantic schemas for the dashboard summary endpoint — M34.

GET /dashboard/summary → DashboardSummaryResponse

All data is scoped to the authenticated user and computed fresh per request.
No values that could expose credentials, tokens, or secrets are included.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


# ── Sub-schemas ───────────────────────────────────────────────────────────────


class IntegrationHealthCounts(BaseModel):
    """High-level health summary across all integrations."""
    total: int
    active: int
    paused: int
    needs_attention: int
    failed_last_24h: int
    with_consecutive_failures: int


class ResourceCounts(BaseModel):
    """Resource snapshot counts."""
    total: int
    active: int


class ChangeActivityCounts(BaseModel):
    """Change volume over different time windows."""
    total: int
    last_24h: int
    last_7d: int
    high_critical_last_7d: int
    last_change_at: Optional[str]     # ISO 8601 or null


class RiskDistribution(BaseModel):
    """Count of changes at each risk level (all time, user-scoped)."""
    critical: int
    high: int
    medium: int
    low: int


class ProviderStats(BaseModel):
    """Per-provider stats."""
    provider: str
    integration_count: int
    resource_count: int
    change_count_7d: int


class RecentChange(BaseModel):
    """A single high/critical change entry for the dashboard."""
    id: str
    integration_id: str
    resource_id: str
    integration_name: Optional[str]     # display_name from Integration
    provider: Optional[str]             # derived from integration
    record_identifier: str
    change_type: str
    risk_level: str
    field_path: Optional[str]
    created_at: str


class RecentFailedSync(BaseModel):
    """An integration with a recent sync failure."""
    integration_id: str
    integration_name: str
    provider: str
    last_sync_status: Optional[str]
    last_sync_error: Optional[str]
    failure_category: Optional[str]
    error_code: Optional[str]
    recommended_action: Optional[str]
    consecutive_failure_count: int
    needs_attention: bool
    last_failure_at: Optional[str]      # ISO 8601


# ── Top-level response ────────────────────────────────────────────────────────


class DashboardSummaryResponse(BaseModel):
    """Full dashboard summary for the authenticated user."""

    integration_health: IntegrationHealthCounts
    resource_counts: ResourceCounts
    change_activity: ChangeActivityCounts
    risk_distribution: RiskDistribution
    provider_distribution: List[ProviderStats]
    recent_high_critical_changes: List[RecentChange]
    recent_failed_syncs: List[RecentFailedSync]
    last_updated_at: str                # ISO 8601 UTC
