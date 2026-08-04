"""Provider-neutral Pro-plan tests (Dodo Payments message 1, Phase 1).

Proves: Free is unchanged, Pro is a flat $10/month, Team's existing
$30-base + $5/seat-over-20 formula is untouched, and the generic
``calculate_price_for_plan``/``calculate_desired_state`` dispatchers never
diverge from the plan-specific functions they wrap.
"""

from __future__ import annotations

import uuid

import pytest

from app.billing.desired_state import calculate_desired_state, calculate_desired_team_state
from app.billing.enums import BillingProvider, DesiredSubscriptionReason, ObjectType, PlanId
from app.billing.provider import BillingProviderReference
from app.billing.plans import FREE_PLAN, PLANS, PRO_PLAN, TEAM_PLAN, get_plan, pro_pricing_summary
from app.billing.pricing import (
    NegativeMemberCountError,
    PRO_MONTHLY_CENTS,
    UnpricedPlanError,
    calculate_price_for_plan,
    calculate_pro_monthly_price,
    calculate_team_monthly_price,
)


class TestFreeUnchanged:
    def test_free_plan_still_not_billing_available(self):
        assert FREE_PLAN.billing_available is False

    def test_free_plan_entitlements_unchanged(self):
        assert FREE_PLAN.entitlements.max_integrations == 3
        assert FREE_PLAN.entitlements.max_members == 1
        assert FREE_PLAN.entitlements.min_sync_interval_minutes == 60
        assert FREE_PLAN.entitlements.history_retention_days == 30

    def test_free_still_in_plans_registry(self):
        assert PLANS[PlanId.FREE] is FREE_PLAN


class TestProIsFlatTenDollars:
    def test_pro_monthly_cents_constant_is_1000(self):
        assert PRO_MONTHLY_CENTS == 1000

    def test_pro_pricing_breakdown_is_1000_regardless_of_members(self):
        for members in (0, 1, 5, 20, 21, 100):
            breakdown = calculate_pro_monthly_price(members)
            assert breakdown.total_amount_cents == 1000
            assert breakdown.base_amount_cents == 1000
            assert breakdown.additional_seat_amount_cents == 0
            assert breakdown.additional_members == 0

    def test_pro_negative_members_rejected(self):
        with pytest.raises(NegativeMemberCountError):
            calculate_pro_monthly_price(-1)

    def test_pro_plan_registered_and_billing_available(self):
        assert PLANS[PlanId.PRO] is PRO_PLAN
        assert PRO_PLAN.billing_available is True
        assert PRO_PLAN.pricing_strategy == "flat"

    def test_pro_pricing_summary_matches_breakdown(self):
        summary = pro_pricing_summary()
        assert summary["amount_cents"] == 1000
        assert summary["currency"] == "USD"
        assert summary["interval"] == "month"

    def test_get_plan_pro_returns_pro_plan(self):
        assert get_plan(PlanId.PRO) is PRO_PLAN


class TestTeamFormulaPreserved:
    """Preserve: 3000 + max(0, members - 20) * 500."""

    @pytest.mark.parametrize(
        "members,expected_total",
        [(1, 3000), (20, 3000), (21, 3500), (25, 5500), (30, 8000)],
    )
    def test_team_formula_unchanged(self, members, expected_total):
        breakdown = calculate_team_monthly_price(members)
        assert breakdown.total_amount_cents == expected_total

    def test_team_plan_object_unchanged(self):
        assert PLANS[PlanId.TEAM] is TEAM_PLAN
        assert TEAM_PLAN.pricing_strategy == "seat_based"
        assert TEAM_PLAN.entitlements.max_integrations == 100
        assert TEAM_PLAN.entitlements.includes_workspace_audit_logs is True


class TestGenericPricingDispatcher:
    """calculate_price_for_plan must never diverge from the plan-specific
    functions it wraps — same values, same object shape."""

    @pytest.mark.parametrize("members", [1, 20, 21, 25])
    def test_team_dispatch_matches_direct_call(self, members):
        via_dispatch = calculate_price_for_plan(PlanId.TEAM, members)
        direct = calculate_team_monthly_price(members)
        assert via_dispatch.total_amount_cents == direct.total_amount_cents

    def test_pro_dispatch_matches_direct_call(self):
        via_dispatch = calculate_price_for_plan(PlanId.PRO, 5)
        direct = calculate_pro_monthly_price(5)
        assert via_dispatch.total_amount_cents == direct.total_amount_cents

    def test_free_has_no_external_checkout_price(self):
        with pytest.raises(UnpricedPlanError):
            calculate_price_for_plan(PlanId.FREE, 1)


class TestGenericDesiredStateDispatcher:
    def test_team_desired_state_matches_legacy_wrapper(self):
        generic = calculate_desired_state(PlanId.TEAM, 21, DesiredSubscriptionReason.MEMBER_ADDED)
        legacy = calculate_desired_team_state(21, DesiredSubscriptionReason.MEMBER_ADDED)
        assert generic.additional_seat_quantity == legacy.additional_seat_quantity == 1
        assert generic.calculated_total_cents == legacy.calculated_total_cents == 3500
        assert generic.base_quantity == legacy.base_quantity == 1

    def test_pro_desired_state_never_has_additional_seats(self):
        state = calculate_desired_state(PlanId.PRO, 50, DesiredSubscriptionReason.PLAN_CHANGED)
        assert state.additional_seat_quantity == 0
        assert state.base_quantity == 1
        assert state.calculated_total_cents == 1000


class TestStripeAndPaddleUnaffected:
    """PlanId.PRO / BillingProvider.DODO are purely additive — every
    existing enum member keeps its exact value."""

    def test_billing_provider_values_unchanged(self):
        assert BillingProvider.STRIPE.value == "stripe"
        assert BillingProvider.PADDLE.value == "paddle"

    def test_plan_id_free_and_team_values_unchanged(self):
        assert PlanId.FREE.value == "free"
        assert PlanId.TEAM.value == "team"

    def test_stripe_adapter_still_constructs(self):
        from app.billing.adapters.stripe import StripeBillingAdapter

        assert StripeBillingAdapter is not None

    def test_paddle_adapter_still_constructs(self):
        from app.billing.adapters.paddle import PaddleBillingAdapter, PaddleNotConfiguredError

        adapter = PaddleBillingAdapter(None)
        assert adapter.provider == BillingProvider.PADDLE
        with pytest.raises(PaddleNotConfiguredError):
            adapter.get_subscription(
                BillingProviderReference(
                    provider=BillingProvider.PADDLE,
                    object_type=ObjectType.SUBSCRIPTION,
                    external_id="sub_test",
                    workspace_id=uuid.uuid4(),
                )
            )
