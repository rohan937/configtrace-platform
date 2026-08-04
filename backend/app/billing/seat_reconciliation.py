"""Seat reconciliation (Commercial Infrastructure message 2).

Desired vs. observed additional-seat quantity reconciliation for a Team
Paddle subscription (message-2 spec item 18).

    desired_additional_quantity = max(0, current_billable_members - 20)
    observed_additional_quantity = quantity of the configured
                                    additional-seat price on the live
                                    subscription (0 if the item is absent)

When they differ, this module builds an explicit, typed
``SeatReconciliationPlan`` describing exactly what update is needed — it
never calls Paddle itself (that's the adapter's job, given this plan).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.billing.pricing import TEAM_INCLUDED_SEATS

# Paddle "proration_billing_mode" values used for subscription item
# updates (message-2 spec item 19). Chosen policy:
#   * seat ADDED (quantity increases)   -> prorated_immediately
#   * seat REMOVED (quantity decreases) -> prorated_next_billing_period
# This mirrors the message spec's recommended default: additions billed
# immediately (prorated), removals credited against the next invoice
# rather than an immediate refund. Every subscription-item update MUST
# carry one of these two values explicitly — never omitted.
PRORATION_MODE_SEAT_ADDED = "prorated_immediately"
PRORATION_MODE_SEAT_REMOVED = "prorated_next_billing_period"


@dataclass(frozen=True)
class SeatReconciliationPlan:
    needs_update: bool
    desired_additional_quantity: int
    observed_additional_quantity: int
    proration_mode: str | None  # None when no update is needed


def calculate_desired_additional_quantity(current_billable_members: int) -> int:
    return max(0, current_billable_members - TEAM_INCLUDED_SEATS)


def plan_seat_reconciliation(
    *, current_billable_members: int, observed_additional_quantity: int
) -> SeatReconciliationPlan:
    """Compare desired vs. observed additional-seat quantity and produce
    an explicit reconciliation plan. Never mutates anything itself — pure
    calculation only, exactly like ``app.billing.pricing``."""
    desired = calculate_desired_additional_quantity(current_billable_members)
    if desired == observed_additional_quantity:
        return SeatReconciliationPlan(
            needs_update=False,
            desired_additional_quantity=desired,
            observed_additional_quantity=observed_additional_quantity,
            proration_mode=None,
        )

    mode = PRORATION_MODE_SEAT_ADDED if desired > observed_additional_quantity else PRORATION_MODE_SEAT_REMOVED
    return SeatReconciliationPlan(
        needs_update=True,
        desired_additional_quantity=desired,
        observed_additional_quantity=observed_additional_quantity,
        proration_mode=mode,
    )
