"""Dashboard router — M34.

Routes
------
GET /dashboard/summary  — full operational summary for the authenticated user

The summary includes integration health, resource counts, change activity,
risk distribution, provider distribution, recent high/critical changes,
and recent failed syncs.  All data is scoped to the authenticated user.

No credentials, tokens, or secret values are ever included in any response.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.dashboard import DashboardSummaryResponse
from app.services import dashboard_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DashboardSummaryResponse:
    """Return the full operational dashboard summary for the authenticated user.

    The summary is computed fresh on each request.  At MVP scale (single user,
    tens of integrations) the latency is negligible.

    All sections are scoped to the authenticated user:
    - integration_health: counts by status / attention state
    - resource_counts: total and active resource rows
    - change_activity: totals for all time, 24h, and 7d windows
    - risk_distribution: count of changes at each risk level
    - provider_distribution: per-provider integration and change counts
    - recent_high_critical_changes: last 10 high/critical changes
    - recent_failed_syncs: integrations with failures in the last 7 days
    - last_updated_at: server timestamp when the response was computed

    Returns:
        A :class:`DashboardSummaryResponse` with all dashboard sections.
    """
    return dashboard_service.get_dashboard_summary(
        user_id=current_user.id,
        db=db,
    )
