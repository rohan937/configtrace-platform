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

from app.billing.enums import BillingInterval, PlanId

# ── Team pricing constants (message 1) ──────────────────────────────────────
#
# Never hardcode a Paddle, Stripe, or Dodo price/product ID here — these are
# internal, provider-neutral amounts. Provider-specific catalog IDs are
# mapped separately (see app.billing.plans / app.billing.adapters.*).
#
# THE canonical Team formula (never duplicate this elsewhere — see the
# "stale legacy pricing" note below):
#
#     monthly_total_cents = 3000 + max(0, billable_member_count - 20) * 500

TEAM_BASE_MONTHLY_CENTS = 3000
TEAM_INCLUDED_SEATS = 20
TEAM_ADDITIONAL_SEAT_MONTHLY_CENTS = 500
TEAM_CURRENCY = "USD"

TEAM_BASE_COMPONENT_ID = "team_base_monthly"
TEAM_ADDITIONAL_SEAT_COMPONENT_ID = "team_additional_seat_monthly"

# ── Pro pricing constants (Dodo Payments message 1) ─────────────────────────
#
# Pro is a flat monthly price — no seat component, no included-member
# concept. $10.00/month = 1000 minor units (cents).
PRO_MONTHLY_CENTS = 1000
PRO_CURRENCY = "USD"
PRO_COMPONENT_ID = "pro_monthly"

# ── Stale legacy pricing warning ─────────────────────────────────────────────
#
# THIS is the canonical, provider-neutral Team price ($30 base). A SEPARATE,
# older, Stripe-only pricing table exists at
# ``app.services.billing_service.PLAN_LIMITS`` with a stale Team price of
# $40/month (no seat-based component) — that table predates this
# provider-neutral domain (Commercial Infrastructure message 1) and must
# NEVER be imported by, or its values copied into, any Dodo-related module.
# ``app.billing.adapters.dodo`` and every other Dodo module in this package
# import ONLY from this file for pricing — never from
# ``app.services.billing_service``. This is enforced by
# ``tests/test_commercial_dodo_no_legacy_billing_service.py``, which greps
# every ``app/billing/*dodo*`` file for a forbidden
# ``billing_service``/``PLAN_LIMITS`` reference.


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


def calculate_pro_monthly_price(billable_member_count: int = 0) -> PricingBreakdown:
    """Pure, deterministic Pro monthly pricing calculation.

    Pro is a FLAT $10.00/month (1000 minor units) — never seat-based.
    ``billable_member_count`` is accepted only so this function has the
    same call signature as ``calculate_team_monthly_price`` (needed for
    ``calculate_price_for_plan`` below to dispatch generically); it never
    affects the returned price. A negative count is still rejected — the
    same "never silently coerce" rule applies regardless of plan.
    """
    if billable_member_count < 0:
        raise NegativeMemberCountError(
            f"billable_member_count must be >= 0, got {billable_member_count!r}"
        )

    components = (
        PriceComponent(
            component_id=PRO_COMPONENT_ID,
            unit_amount_cents=PRO_MONTHLY_CENTS,
            quantity=1,
            currency=PRO_CURRENCY,
        ),
    )
    return PricingBreakdown(
        currency=PRO_CURRENCY,
        interval=BillingInterval.MONTH,
        billable_members=billable_member_count,
        included_members=0,
        additional_members=0,
        base_amount_cents=PRO_MONTHLY_CENTS,
        additional_seat_amount_cents=0,
        total_amount_cents=PRO_MONTHLY_CENTS,
        components=components,
    )


class UnpricedPlanError(ValueError):
    """Raised when ``calculate_price_for_plan`` is asked to price a plan
    with no billing-available pricing function (e.g. FREE, which has no
    external checkout and is never priced through this path)."""


def calculate_price_for_plan(plan_id: PlanId, billable_member_count: int) -> PricingBreakdown:
    """Generic, provider-neutral pricing dispatcher — the single entry
    point checkout code should call regardless of which paid plan is being
    priced. Dispatches to the plan's own pure pricing function; never
    re-implements either formula itself, so ``calculate_team_monthly_price``
    (seat-based) and ``calculate_pro_monthly_price`` (flat) each remain the
    single source of truth for their own plan.
    """
    if plan_id == PlanId.TEAM:
        return calculate_team_monthly_price(billable_member_count)
    if plan_id == PlanId.PRO:
        return calculate_pro_monthly_price(billable_member_count)
    raise UnpricedPlanError(f"{plan_id!r} has no external checkout price (FREE is never priced here).")
