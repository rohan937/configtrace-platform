"""Desired commercial state calculation (Commercial Infrastructure message 1).

Message 1 calculates DESIRED commercial state only — it never calls
Stripe or Paddle to actually change a subscription. A future message wires
``DesiredSubscriptionState`` into an actual provider ``update_subscription``
call once Paddle checkout exists (message 2+).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from app.billing.enums import BillingInterval, DesiredSubscriptionReason, PlanId
from app.billing.pricing import TEAM_INCLUDED_SEATS, calculate_price_for_plan


@dataclass(frozen=True)
class DesiredSubscriptionState:
    plan_id: PlanId
    billing_interval: BillingInterval
    billable_seats: int
    base_quantity: int
    additional_seat_quantity: int
    calculated_total_cents: int
    effective_at: datetime
    reason: DesiredSubscriptionReason


def calculate_desired_state(
    plan_id: PlanId,
    billable_seats: int,
    reason: DesiredSubscriptionReason,
    effective_at: datetime | None = None,
) -> DesiredSubscriptionState:
    """Generic, provider-neutral desired-state calculation for any
    billable plan (Dodo Payments message 1). ``base_quantity`` is always 1
    (one base recurring item). ``additional_seat_quantity`` is
    ``max(0, seats - 20)`` for TEAM (its only seat-based dimension) and
    always 0 for PRO (flat, no seats) — never re-derived differently
    anywhere else; both dispatch through
    ``app.billing.pricing.calculate_price_for_plan``, the single
    provider-neutral pricing entry point."""
    breakdown = calculate_price_for_plan(plan_id, billable_seats)
    additional_seat_quantity = max(0, billable_seats - TEAM_INCLUDED_SEATS) if plan_id == PlanId.TEAM else 0
    return DesiredSubscriptionState(
        plan_id=plan_id,
        billing_interval=BillingInterval.MONTH,
        billable_seats=billable_seats,
        base_quantity=1,
        additional_seat_quantity=additional_seat_quantity,
        calculated_total_cents=breakdown.total_amount_cents,
        effective_at=effective_at or datetime.now(timezone.utc),
        reason=reason,
    )


def calculate_desired_team_state(
    billable_seats: int,
    reason: DesiredSubscriptionReason,
    effective_at: datetime | None = None,
) -> DesiredSubscriptionState:
    """Preserved, unchanged-behavior wrapper for existing Team call sites
    (message-1 spec item 13) — thin delegation to ``calculate_desired_state``
    so Team's own formula/behavior is byte-for-byte identical to before
    this generalization."""
    return calculate_desired_state(PlanId.TEAM, billable_seats, reason, effective_at)
