"""Dashboard summary computation — M34.

Aggregates integration health, resource counts, change activity, risk
distribution, provider distribution, recent high/critical changes, and
recent sync failures for a single user.

All queries are user-scoped via the ``user_id`` parameter.  No data from
other users is ever included.

Performance note: all aggregations use COUNT/GROUP BY SQL so we don't load
large record sets into Python memory.  At MVP scale (single user, tens of
integrations) the latency is negligible.  Add caching when needed.

Security note: this module never returns credential fields, tokens, private
keys, or environment-variable values.  Record-level fields follow the same
exclusion rules as their respective routers.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.failure_classifier import NEEDS_ATTENTION_THRESHOLD
from app.models.change import Change
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.sync_run import SyncRun
from app.schemas.dashboard import (
    ChangeActivityCounts,
    DashboardSummaryResponse,
    IntegrationHealthCounts,
    ProviderStats,
    RecentChange,
    RecentFailedSync,
    ResourceCounts,
    ReviewQueueCounts,
    RiskDistribution,
)
from app.services import changes_service
from app.services.integration_service import get_latest_sync_run_summary


def get_dashboard_summary(user_id: uuid.UUID, db: Session) -> DashboardSummaryResponse:
    """Compute and return the full dashboard summary for *user_id*.

    Args:
        user_id: The authenticated user's UUID.
        db:      Active SQLAlchemy session.

    Returns:
        A :class:`DashboardSummaryResponse` with all dashboard sections.
    """
    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)
    since_7d  = now - timedelta(days=7)

    # ── 1. Integration health ─────────────────────────────────────────────────
    integrations = (
        db.query(Integration)
        .filter(
            Integration.user_id == user_id,
            Integration.status != "deleted",
        )
        .all()
    )

    total_integrations    = len(integrations)
    active_integrations   = sum(1 for i in integrations if i.status == "active")
    paused_integrations   = sum(1 for i in integrations if i.status == "paused")
    needs_attention_count = sum(
        1 for i in integrations
        if (i.consecutive_failure_count or 0) >= NEEDS_ATTENTION_THRESHOLD
    )
    with_consecutive_failures = sum(
        1 for i in integrations if (i.consecutive_failure_count or 0) > 0
    )

    # Count integrations that have at least one failed SyncRun in the last 24h
    failed_integration_ids_24h: set[uuid.UUID] = set()
    failed_runs_24h = (
        db.query(SyncRun.integration_id)
        .filter(
            SyncRun.user_id == user_id,
            SyncRun.status == "failed",
            SyncRun.started_at >= since_24h,
        )
        .distinct()
        .all()
    )
    for (iid,) in failed_runs_24h:
        failed_integration_ids_24h.add(iid)
    failed_last_24h = len(failed_integration_ids_24h)

    integration_health = IntegrationHealthCounts(
        total=total_integrations,
        active=active_integrations,
        paused=paused_integrations,
        needs_attention=needs_attention_count,
        failed_last_24h=failed_last_24h,
        with_consecutive_failures=with_consecutive_failures,
    )

    # ── 2. Resource counts ────────────────────────────────────────────────────
    resource_rows = (
        db.query(Resource.is_active, func.count(Resource.id))
        .filter(Resource.user_id == user_id)
        .group_by(Resource.is_active)
        .all()
    )
    total_resources  = sum(cnt for _, cnt in resource_rows)
    active_resources = next((cnt for is_active, cnt in resource_rows if is_active), 0)

    resource_counts = ResourceCounts(
        total=total_resources,
        active=active_resources,
    )

    # ── 3. Change activity ────────────────────────────────────────────────────
    total_changes = (
        db.query(func.count(Change.id))
        .filter(Change.user_id == user_id)
        .scalar()
    ) or 0

    changes_24h = (
        db.query(func.count(Change.id))
        .filter(Change.user_id == user_id, Change.created_at >= since_24h)
        .scalar()
    ) or 0

    changes_7d = (
        db.query(func.count(Change.id))
        .filter(Change.user_id == user_id, Change.created_at >= since_7d)
        .scalar()
    ) or 0

    high_critical_7d = (
        db.query(func.count(Change.id))
        .filter(
            Change.user_id == user_id,
            Change.created_at >= since_7d,
            Change.risk_level.in_(["high", "critical"]),
        )
        .scalar()
    ) or 0

    last_change_row = (
        db.query(Change.created_at)
        .filter(Change.user_id == user_id)
        .order_by(Change.created_at.desc())
        .first()
    )
    last_change_at: Optional[str] = (
        last_change_row[0].isoformat() if last_change_row else None
    )

    change_activity = ChangeActivityCounts(
        total=total_changes,
        last_24h=changes_24h,
        last_7d=changes_7d,
        high_critical_last_7d=high_critical_7d,
        last_change_at=last_change_at,
    )

    # ── 4. Risk distribution ──────────────────────────────────────────────────
    risk_rows = (
        db.query(Change.risk_level, func.count(Change.id))
        .filter(Change.user_id == user_id)
        .group_by(Change.risk_level)
        .all()
    )
    risk_map: Dict[str, int] = defaultdict(int)
    for level, cnt in risk_rows:
        risk_map[level] += cnt

    risk_distribution = RiskDistribution(
        critical=risk_map.get("critical", 0),
        high=risk_map.get("high", 0),
        medium=risk_map.get("medium", 0),
        low=risk_map.get("low", 0),
    )

    # ── 5. Provider distribution ──────────────────────────────────────────────
    # Count integrations and resources per provider
    provider_integration_map: Dict[str, int] = defaultdict(int)
    provider_resource_map: Dict[str, int] = defaultdict(int)

    for integ in integrations:
        provider_integration_map[integ.provider] += 1
        for res in integ.resources:
            provider_resource_map[integ.provider] += 1

    # Changes in last 7d per provider — join through Integration
    provider_change_rows = (
        db.query(Integration.provider, func.count(Change.id))
        .join(Change, Change.integration_id == Integration.id)
        .filter(
            Integration.user_id == user_id,
            Change.user_id == user_id,
            Change.created_at >= since_7d,
        )
        .group_by(Integration.provider)
        .all()
    )
    provider_change_map: Dict[str, int] = defaultdict(int)
    for provider, cnt in provider_change_rows:
        provider_change_map[provider] += cnt

    all_providers = sorted(
        set(provider_integration_map.keys())
        | set(provider_resource_map.keys())
        | set(provider_change_map.keys())
    )
    provider_distribution: List[ProviderStats] = [
        ProviderStats(
            provider=p,
            integration_count=provider_integration_map.get(p, 0),
            resource_count=provider_resource_map.get(p, 0),
            change_count_7d=provider_change_map.get(p, 0),
        )
        for p in all_providers
    ]

    # ── 6. Recent high/critical changes ───────────────────────────────────────
    recent_hc_rows = (
        db.query(Change)
        .filter(
            Change.user_id == user_id,
            Change.risk_level.in_(["high", "critical"]),
        )
        .order_by(Change.created_at.desc())
        .limit(10)
        .all()
    )

    # Build integration_id → (name, provider) lookup from already-loaded list
    integ_map: Dict[uuid.UUID, Integration] = {i.id: i for i in integrations}

    recent_high_critical_changes: List[RecentChange] = []
    for c in recent_hc_rows:
        integ = integ_map.get(c.integration_id)
        recent_high_critical_changes.append(
            RecentChange(
                id=str(c.id),
                integration_id=str(c.integration_id),
                resource_id=str(c.resource_id),
                integration_name=integ.display_name if integ else None,
                provider=integ.provider if integ else None,
                record_identifier=c.record_identifier,
                change_type=c.change_type,
                risk_level=c.risk_level,
                field_path=c.field_path,
                created_at=c.created_at.isoformat(),
            )
        )

    # ── 7. Recent failed syncs ────────────────────────────────────────────────
    # Integrations with a recent (last 7d) failed sync, ordered by failure recency
    recent_failed_integrations = (
        db.query(Integration)
        .filter(
            Integration.user_id == user_id,
            Integration.status != "deleted",
            Integration.last_failure_at >= since_7d,
        )
        .order_by(Integration.last_failure_at.desc())
        .limit(5)
        .all()
    )

    recent_failed_syncs: List[RecentFailedSync] = []
    for integ in recent_failed_integrations:
        # M59.15: tuple grew to 3-tuple (added failure_category); dashboard
        # already reads classification fields off the SyncRun row directly
        # below so the third value is unused here.
        last_status, last_error, _last_failure_category = (
            get_latest_sync_run_summary(integ.id, db)
        )

        # Get the most recent failed run's classification fields
        failed_run = (
            db.query(SyncRun)
            .filter(
                SyncRun.integration_id == integ.id,
                SyncRun.status == "failed",
            )
            .order_by(SyncRun.started_at.desc())
            .first()
        )
        consecutive = integ.consecutive_failure_count or 0

        recent_failed_syncs.append(
            RecentFailedSync(
                integration_id=str(integ.id),
                integration_name=integ.display_name,
                provider=integ.provider,
                last_sync_status=last_status,
                last_sync_error=last_error,
                failure_category=failed_run.failure_category if failed_run else None,
                error_code=failed_run.error_code if failed_run else None,
                recommended_action=failed_run.recommended_action if failed_run else None,
                consecutive_failure_count=consecutive,
                needs_attention=consecutive >= NEEDS_ATTENTION_THRESHOLD,
                last_failure_at=(
                    integ.last_failure_at.isoformat() if integ.last_failure_at else None
                ),
            )
        )

    # ── 8. Review queue counts (M57.3) ────────────────────────────────────────
    review_queue_total    = changes_service.count_needs_review(user_id, db)
    review_queue_critical = changes_service.count_needs_review_by_risk(user_id, "critical", db)
    review_queue_high     = changes_service.count_needs_review_by_risk(user_id, "high", db)

    review_queue = ReviewQueueCounts(
        total=review_queue_total,
        critical=review_queue_critical,
        high=review_queue_high,
    )

    return DashboardSummaryResponse(
        integration_health=integration_health,
        resource_counts=resource_counts,
        change_activity=change_activity,
        risk_distribution=risk_distribution,
        provider_distribution=provider_distribution,
        recent_high_critical_changes=recent_high_critical_changes,
        recent_failed_syncs=recent_failed_syncs,
        last_updated_at=now.isoformat(),
        review_queue=review_queue,
    )
