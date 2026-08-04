"""Provider-neutral plan model (Commercial Infrastructure message 1).

Internal plan identity (``PlanId``) is never a Paddle or Stripe product ID
— those are external references mapped separately (see
``app.billing.adapters.paddle.PaddlePriceMapping`` and
``app.billing.models.BillingProviderReference``).

Entitlement bundles below are copied EXACTLY from the existing,
already-enforced ``app.services.billing_service.PLAN_LIMITS`` values (audit
per message-1 spec item 20) — this message changes ONLY the Team price;
every other limit is preserved unchanged. ``includes_workspace_audit_logs``
mirrors the existing frontend feature-list claim
(``frontend/.../billing/page.tsx`` PLAN_META.team.features) — there is no
separate backend enforcement of this flag today, so it is carried here as
presentational metadata only, not a new enforced limit.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.billing.enums import BillingInterval, PlanId
from app.billing.pricing import (
    PRO_CURRENCY,
    PRO_MONTHLY_CENTS,
    TEAM_ADDITIONAL_SEAT_MONTHLY_CENTS,
    TEAM_BASE_MONTHLY_CENTS,
    TEAM_CURRENCY,
    TEAM_INCLUDED_SEATS,
)


@dataclass(frozen=True)
class EntitlementBundle:
    """Exact existing product limits — copied from
    ``billing_service.PLAN_LIMITS``, never invented or changed here."""

    max_integrations: int
    max_members: int
    min_sync_interval_minutes: int
    history_retention_days: int
    includes_workspace_audit_logs: bool


@dataclass(frozen=True)
class Plan:
    """Provider-neutral plan definition.

    ``pricing_strategy`` is a string tag ("flat" | "seat_based") rather
    than a callable, so the plan definition itself stays a plain,
    serializable dataclass — the actual pricing FUNCTION for a
    seat-based plan lives in ``app.billing.pricing``
    (``calculate_team_monthly_price``), keyed by ``plan_id``.
    """

    plan_id: PlanId
    display_name: str
    billing_available: bool
    entitlements: EntitlementBundle
    supported_intervals: tuple[BillingInterval, ...]
    pricing_strategy: str  # "flat" | "seat_based"
    currency: str


FREE_PLAN = Plan(
    plan_id=PlanId.FREE,
    display_name="Free",
    billing_available=False,
    entitlements=EntitlementBundle(
        max_integrations=3,
        max_members=1,
        min_sync_interval_minutes=60,
        history_retention_days=30,
        includes_workspace_audit_logs=False,
    ),
    supported_intervals=(BillingInterval.MONTH,),
    pricing_strategy="flat",
    currency=TEAM_CURRENCY,
)

PRO_PLAN = Plan(
    plan_id=PlanId.PRO,
    display_name="Pro",
    billing_available=True,
    # Entitlement values copied exactly from the existing, already-enforced
    # ``app.services.billing_service.PLAN_LIMITS["pro"]`` bundle — this is
    # the SAME audit discipline message-1 applied when TEAM_PLAN's
    # entitlements were copied from that legacy table. Only the PRICE is
    # canonicalized here ($10/month flat, via app.billing.pricing); the
    # legacy table's own trial-days concept is not part of this
    # provider-neutral domain and is intentionally not carried over.
    entitlements=EntitlementBundle(
        max_integrations=20,
        max_members=5,
        min_sync_interval_minutes=15,
        history_retention_days=180,
        includes_workspace_audit_logs=False,
    ),
    supported_intervals=(BillingInterval.MONTH,),
    pricing_strategy="flat",
    currency=PRO_CURRENCY,
)

TEAM_PLAN = Plan(
    plan_id=PlanId.TEAM,
    display_name="Team",
    billing_available=True,
    entitlements=EntitlementBundle(
        max_integrations=100,
        max_members=25,
        min_sync_interval_minutes=5,
        history_retention_days=365,
        includes_workspace_audit_logs=True,
    ),
    # Message 1 implements monthly only. YEAR is a real enum member (see
    # app.billing.enums.BillingInterval) precisely so annual pricing can be
    # added to `supported_intervals` later without changing this dataclass
    # shape or any call site's type.
    supported_intervals=(BillingInterval.MONTH,),
    pricing_strategy="seat_based",
    currency=TEAM_CURRENCY,
)

PLANS: dict[PlanId, Plan] = {
    PlanId.FREE: FREE_PLAN,
    PlanId.PRO: PRO_PLAN,
    PlanId.TEAM: TEAM_PLAN,
}


def get_plan(plan_id: PlanId) -> Plan:
    return PLANS[plan_id]


def pro_pricing_summary() -> dict:
    """Static Pro pricing metadata for display — flat, no seat dimension."""
    return {
        "amount_cents": PRO_MONTHLY_CENTS,
        "currency": PRO_CURRENCY,
        "interval": BillingInterval.MONTH.value,
    }


def team_pricing_summary() -> dict:
    """Static (seat-independent) Team pricing metadata for display — the
    per-workspace breakdown with an actual seat count comes from
    ``app.billing.pricing.calculate_team_monthly_price`` via the
    pricing-preview API, never from this function."""
    return {
        "base_amount_cents": TEAM_BASE_MONTHLY_CENTS,
        "included_members": TEAM_INCLUDED_SEATS,
        "additional_seat_amount_cents": TEAM_ADDITIONAL_SEAT_MONTHLY_CENTS,
        "currency": TEAM_CURRENCY,
        "interval": BillingInterval.MONTH.value,
    }
