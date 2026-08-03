"""Provider-neutral entitlement decisions (Commercial Infrastructure message 1).

Feature gates must read ONLY ``EntitlementDecision`` / ``NormalizedSubscriptionStatus``
— never a raw Stripe status string, and never any other provider's status
vocabulary directly. ``normalize_stripe_status`` is the single place a
Stripe string is translated; a future Paddle status mapping gets its own
equally-narrow function in ``app.billing.adapters.paddle``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.billing.enums import BillingProvider, NormalizedSubscriptionStatus, PlanId
from app.billing.plans import get_plan

# Statuses that confer paid access (message-1 spec item 18-19).
_PAID_ACCESS_STATUSES = frozenset(
    {
        NormalizedSubscriptionStatus.TRIALING,
        NormalizedSubscriptionStatus.ACTIVE,
        NormalizedSubscriptionStatus.PAST_DUE,
        NormalizedSubscriptionStatus.GRACE_PERIOD,
    }
)

# Statuses for which the Stripe-hosted (or future Paddle-hosted)
# billing-management portal remains reachable — mirrors existing
# `create_portal_session` behavior, which only requires a stored customer
# reference, not necessarily an active subscription.
_MANAGEMENT_AVAILABLE_STATUSES = frozenset(
    {
        NormalizedSubscriptionStatus.TRIALING,
        NormalizedSubscriptionStatus.ACTIVE,
        NormalizedSubscriptionStatus.PAST_DUE,
        NormalizedSubscriptionStatus.GRACE_PERIOD,
        NormalizedSubscriptionStatus.PAUSED,
    }
)

# Existing Stripe subscription-status vocabulary (see
# app/models/billing.py's module docstring and
# app/services/billing_service.py's handle_webhook_event) mapped into the
# normalized set. "unpaid" (Stripe's terminal failed-payment state) maps to
# EXPIRED — see the failure/grace-period model in
# backend/tests/reports/commercial_infrastructure_message1.md for why.
_STRIPE_STATUS_MAP: dict[str, NormalizedSubscriptionStatus] = {
    "trialing": NormalizedSubscriptionStatus.TRIALING,
    "active": NormalizedSubscriptionStatus.ACTIVE,
    "past_due": NormalizedSubscriptionStatus.PAST_DUE,
    "canceled": NormalizedSubscriptionStatus.CANCELED,
    "unpaid": NormalizedSubscriptionStatus.EXPIRED,
    "incomplete": NormalizedSubscriptionStatus.INCOMPLETE,
    "incomplete_expired": NormalizedSubscriptionStatus.EXPIRED,
    "paused": NormalizedSubscriptionStatus.PAUSED,
}


def normalize_stripe_status(stripe_status: str) -> NormalizedSubscriptionStatus:
    """Map a raw Stripe subscription-status string to a normalized status.
    Unknown/unexpected strings map to INCOMPLETE rather than raising —
    an unrecognized status must never be silently treated as ACTIVE."""
    return _STRIPE_STATUS_MAP.get(stripe_status, NormalizedSubscriptionStatus.INCOMPLETE)


@dataclass(frozen=True)
class EntitlementDecision:
    """The result of deciding what a workspace is entitled to, right now,
    from its normalized subscription state — never derived by reading a
    provider status string directly in a feature gate."""

    has_paid_access: bool
    plan_id: PlanId
    status: NormalizedSubscriptionStatus
    max_integrations: int
    max_members: int
    min_sync_interval_minutes: int
    history_retention_days: int
    includes_workspace_audit_logs: bool
    grace_period_end: datetime | None
    billing_management_available: bool
    reason: str
    source_provider: BillingProvider | None
    last_synchronized_at: datetime | None = None

    def as_dict(self) -> dict:
        return {
            "has_paid_access": self.has_paid_access,
            "plan_id": self.plan_id.value,
            "status": self.status.value,
            "max_integrations": self.max_integrations,
            "max_members": self.max_members,
            "min_sync_interval_minutes": self.min_sync_interval_minutes,
            "history_retention_days": self.history_retention_days,
            "includes_workspace_audit_logs": self.includes_workspace_audit_logs,
            "grace_period_end": self.grace_period_end.isoformat() if self.grace_period_end else None,
            "billing_management_available": self.billing_management_available,
            "reason": self.reason,
            "source_provider": self.source_provider.value if self.source_provider else None,
            "last_synchronized_at": (
                self.last_synchronized_at.isoformat() if self.last_synchronized_at else None
            ),
        }


def decide_entitlements(
    *,
    plan_id: PlanId,
    status: NormalizedSubscriptionStatus,
    grace_period_end: datetime | None = None,
    source_provider: BillingProvider | None = None,
    last_synchronized_at: datetime | None = None,
) -> EntitlementDecision:
    """Decide what a workspace is entitled to given its normalized
    subscription plan + status. A workspace whose status does not confer
    paid access is enforced under the FREE entitlement bundle immediately
    (mirrors the existing ``_effective_plan`` "fall back to free limits"
    behavior in ``app.services.billing_service``) even though its nominal
    ``plan_id`` may still be TEAM until a webhook confirms the downgrade."""
    has_paid_access = status in _PAID_ACCESS_STATUSES
    effective_plan_id = plan_id if has_paid_access else PlanId.FREE
    plan = get_plan(effective_plan_id)

    reason_map = {
        NormalizedSubscriptionStatus.TRIALING: "trial_active",
        NormalizedSubscriptionStatus.ACTIVE: "subscription_active",
        NormalizedSubscriptionStatus.PAST_DUE: "payment_past_due_grace_active",
        NormalizedSubscriptionStatus.GRACE_PERIOD: "grace_period_active",
        NormalizedSubscriptionStatus.PAUSED: "subscription_paused",
        NormalizedSubscriptionStatus.CANCELED: "subscription_canceled",
        NormalizedSubscriptionStatus.EXPIRED: "subscription_expired",
        NormalizedSubscriptionStatus.INCOMPLETE: "subscription_incomplete",
    }

    return EntitlementDecision(
        has_paid_access=has_paid_access,
        plan_id=effective_plan_id,
        status=status,
        max_integrations=plan.entitlements.max_integrations,
        max_members=plan.entitlements.max_members,
        min_sync_interval_minutes=plan.entitlements.min_sync_interval_minutes,
        history_retention_days=plan.entitlements.history_retention_days,
        includes_workspace_audit_logs=plan.entitlements.includes_workspace_audit_logs,
        grace_period_end=grace_period_end,
        billing_management_available=status in _MANAGEMENT_AVAILABLE_STATUSES,
        reason=reason_map[status],
        source_provider=source_provider,
        last_synchronized_at=last_synchronized_at,
    )
