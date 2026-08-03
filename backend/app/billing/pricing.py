"""Team pricing calculation (Commercial Infrastructure message 1).

New Team pricing (replaces the old flat monthly price used for display and
manual product decisions — see the message-1 report for the full
before/after comparison):

    monthly_total_cents = 3000 + max(0, billable_member_count - 20) * 500

$30 is the TOTAL base subscription price for up to 20 billable members —
never a per-member price. Only members strictly above 20 incur the $5/month
incremental charge. All amounts are integer minor units (cents); this
module never uses floating point for money.

Zero-member decision (message-1, documented per spec item 10)
---------------------------------------------------------------
A workspace can never actually reach zero billable members in real usage:
every workspace has exactly one owner (``Workspace.created_by_user_id`` is
non-nullable and workspace creation always creates an owner
``WorkspaceMember`` row — see ``app/models/workspace.py`` and
``app/services/workspace_service.py``), so a workspace with zero billable
members is invalid at the workspace domain level, not a real, reachable
commercial state.

Given that, ``calculate_team_monthly_price(0)`` is defined to still return
the $30 base price rather than $0 — an active Team subscription must never
silently become free or negative due to a transient reporting glitch (e.g.
a webhook race that briefly reports a stale, too-low seat count). This
mirrors the explicit rule in the task spec: "an active Team subscription
remains $30 even if a transient state reports zero billable members."
``calculate_billable_member_count`` raises for a workspace with no owner
rather than ever returning 0 in practice; ``calculate_team_monthly_price``
additionally defends the pricing function itself against ever being called
with 0 by treating it identically to any count from 1-20.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.billing.enums import BillingInterval

# ── Team pricing constants (message 1) ──────────────────────────────────────
#
# Never hardcode a Paddle or Stripe price ID here — these are internal,
# provider-neutral amounts. Provider-specific price IDs are mapped
# separately (see app.billing.plans / app.billing.adapters.paddle).

TEAM_BASE_MONTHLY_CENTS = 3000
TEAM_INCLUDED_SEATS = 20
TEAM_ADDITIONAL_SEAT_MONTHLY_CENTS = 500
TEAM_CURRENCY = "USD"

TEAM_BASE_COMPONENT_ID = "team_base_monthly"
TEAM_ADDITIONAL_SEAT_COMPONENT_ID = "team_additional_seat_monthly"


class NegativeMemberCountError(ValueError):
    """Raised when a negative billable-member count is passed to the
    pricing calculation — a negative count can never be a real commercial
    state and must never silently coerce to zero."""


@dataclass(frozen=True)
class PriceComponent:
    """One line item contributing to a total price. Mirrors what a real
    billing provider (Paddle) would charge as one recurring catalog item —
    see message-1 spec item 8. ``quantity`` and ``unit_amount_cents`` are
    kept explicit (rather than folding straight to a subtotal) so a future
    provider adapter can map each component to exactly one external price
    ID + quantity pair without re-deriving the breakdown."""

    component_id: str
    unit_amount_cents: int
    quantity: int
    currency: str = TEAM_CURRENCY
    interval: BillingInterval = BillingInterval.MONTH

    @property
    def subtotal_cents(self) -> int:
        return self.unit_amount_cents * self.quantity


@dataclass(frozen=True)
class PricingBreakdown:
    """Full, itemized result of a Team pricing calculation. The backend
    pricing-preview API returns this shape directly (see
    ``app/routers/billing.py``'s pricing-preview endpoint) — the frontend
    must never re-derive these numbers itself (message-1 spec item 30)."""

    currency: str
    interval: BillingInterval
    billable_members: int
    included_members: int
    additional_members: int
    base_amount_cents: int
    additional_seat_amount_cents: int
    total_amount_cents: int
    components: tuple[PriceComponent, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "currency": self.currency,
            "interval": self.interval.value,
            "billable_members": self.billable_members,
            "included_members": self.included_members,
            "additional_members": self.additional_members,
            "base_amount_cents": self.base_amount_cents,
            "additional_seat_amount_cents": self.additional_seat_amount_cents,
            "total_amount_cents": self.total_amount_cents,
            "components": [
                {
                    "component_id": c.component_id,
                    "unit_amount_cents": c.unit_amount_cents,
                    "quantity": c.quantity,
                    "currency": c.currency,
                    "interval": c.interval.value,
                    "subtotal_cents": c.subtotal_cents,
                }
                for c in self.components
            ],
        }


def calculate_team_monthly_price(billable_member_count: int) -> PricingBreakdown:
    """Pure, deterministic Team monthly pricing calculation.

    Rules (message-1 spec item 9):
      * Negative counts are rejected (``NegativeMemberCountError``) — never
        silently coerced to zero.
      * 0 is treated identically to any count in [0, 20]: the base $30
        applies. See the zero-member decision documented in this module's
        docstring — a real workspace can never actually have 0 billable
        members, but the pricing function itself must never produce a
        free or negative Team price even if called with 0.
      * 1-20 members cost exactly the $30 base — no per-member charge.
      * Every member strictly above 20 adds exactly $5/month.
      * Always returns integer minor units (cents), never a float.
    """
    if billable_member_count < 0:
        raise NegativeMemberCountError(
            f"billable_member_count must be >= 0, got {billable_member_count!r}"
        )

    additional_members = max(0, billable_member_count - TEAM_INCLUDED_SEATS)
    base_amount_cents = TEAM_BASE_MONTHLY_CENTS
    additional_seat_amount_cents = additional_members * TEAM_ADDITIONAL_SEAT_MONTHLY_CENTS
    total_amount_cents = base_amount_cents + additional_seat_amount_cents

    components = (
        PriceComponent(
            component_id=TEAM_BASE_COMPONENT_ID,
            unit_amount_cents=TEAM_BASE_MONTHLY_CENTS,
            quantity=1,
        ),
        PriceComponent(
            component_id=TEAM_ADDITIONAL_SEAT_COMPONENT_ID,
            unit_amount_cents=TEAM_ADDITIONAL_SEAT_MONTHLY_CENTS,
            quantity=additional_members,
        ),
    )

    return PricingBreakdown(
        currency=TEAM_CURRENCY,
        interval=BillingInterval.MONTH,
        billable_members=billable_member_count,
        included_members=TEAM_INCLUDED_SEATS,
        additional_members=additional_members,
        base_amount_cents=base_amount_cents,
        additional_seat_amount_cents=additional_seat_amount_cents,
        total_amount_cents=total_amount_cents,
        components=components,
    )
