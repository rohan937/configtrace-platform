"""Pydantic schemas for Security Exposure beta usage events (M63.1)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SecurityBetaEventCreate(BaseModel):
    """POST /security/beta-events request body."""

    event_name: str
    page_path: Optional[str] = None
    # Allowlisted + truncated server-side; unknown keys are dropped.
    metadata: Optional[Dict[str, Any]] = Field(default=None)


class SecurityBetaEventResponse(BaseModel):
    """POST /security/beta-events response."""

    id: str
    ok: bool = True


# ── Analytics summary (M63.4) ─────────────────────────────────────────────────


class BetaDayCount(BaseModel):
    day: str
    count: int


class BetaActionCount(BaseModel):
    action: str
    count: int


class BetaRecentEvent(BaseModel):
    event_name: str
    page_path: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    user_id: Optional[str] = None


class SecurityBetaSummaryResponse(BaseModel):
    """GET /security/beta-events/summary — read-only, workspace-scoped."""

    period_start: datetime
    period_end: datetime
    days: int
    total_events: int
    unique_users: int
    events_by_name: Dict[str, int] = Field(default_factory=dict)
    events_by_route_group: Dict[str, int] = Field(default_factory=dict)
    events_by_day: List[BetaDayCount] = Field(default_factory=list)
    top_actions: List[BetaActionCount] = Field(default_factory=list)
    report_exports: int
    demo_seeds: int
    walkthrough_opens: int
    exposure_actions: int
    rule_toggles: int
    page_views: int
    recent_events: List[BetaRecentEvent] = Field(default_factory=list)
