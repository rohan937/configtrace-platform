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
from app.billing.pricing import TEAM_INCLUDED_SEATS, calculate_team_monthly_price


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


def calculate_desired_team_state(
    billable_seats: int,
    reason: DesiredSubscriptionReason,
    effective_at: datetime | None = None,
) -> DesiredSubscriptionState:
    """Pure calculation of the desired Team subscription state for a given
    billable-seat count. ``base_quantity`` is always 1 (one Team base
    recurring item, per message-1 spec item 13); ``additional_seat_quantity``
    is ``max(0, seats - 20)`` — never negative, never re-derived
    differently anywhere else."""
    breakdown = calculate_team_monthly_price(billable_seats)
    return DesiredSubscriptionState(
        plan_id=PlanId.TEAM,
        billing_interval=BillingInterval.MONTH,
        billable_seats=billable_seats,
        base_quantity=1,
        additional_seat_quantity=max(0, billable_seats - TEAM_INCLUDED_SEATS),
        calculated_total_cents=breakdown.total_amount_cents,
        effective_at=effective_at or datetime.now(timezone.utc),
        reason=reason,
    )
