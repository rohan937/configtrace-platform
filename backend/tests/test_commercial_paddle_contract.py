"""Paddle adapter contract tests (Commercial Infrastructure message 1).

No live Paddle API call is made anywhere in this file — every assertion
verifies the ADAPTER SHAPE and its typed not-configured /
unsupported-before-M2 states, never real Paddle behavior.
"""

from __future__ import annotations

import uuid

import pytest

from app.billing.adapters.paddle import (
    PaddleBillingAdapter,
    PaddleNotConfiguredError,
    PaddlePriceMapping,
    PaddleUnsupportedBeforeM2Error,
)
from app.billing.enums import BillingInterval, BillingProvider, ObjectType, PlanId
from app.billing.provider import (
    BillingProviderReference,
    CancelSubscriptionRequest,
    CheckoutRequest,
    PortalRequest,
    SubscriptionUpdateRequest,
)


def _checkout_request() -> CheckoutRequest:
    return CheckoutRequest(
        workspace_id=uuid.uuid4(),
        plan_id=PlanId.TEAM,
        billing_interval=BillingInterval.MONTH,
        billable_seat_count=25,
        success_url="https://app.example.test/success",
        cancel_url="https://app.example.test/cancel",
    )


def _reference() -> BillingProviderReference:
    return BillingProviderReference(
        provider=BillingProvider.PADDLE, object_type=ObjectType.SUBSCRIPTION,
        external_id="sub_paddle_1", workspace_id=uuid.uuid4(),
    )


class TestPriceMappingContract:
    def test_unconfigured_mapping_is_not_configured(self):
        mapping = PaddlePriceMapping(environment="sandbox", base_price_id=None, additional_seat_price_id=None)
        assert mapping.is_configured is False

    def test_fully_configured_mapping_is_configured(self):
        mapping = PaddlePriceMapping(
            environment="sandbox", base_price_id="pri_base", additional_seat_price_id="pri_seat"
        )
        assert mapping.is_configured is True

    def test_environment_field_distinguishes_sandbox_and_live(self):
        sandbox = PaddlePriceMapping(environment="sandbox", base_price_id="pri_1", additional_seat_price_id="pri_2")
        live = PaddlePriceMapping(environment="live", base_price_id="pri_1", additional_seat_price_id="pri_2")
        assert sandbox.environment != live.environment


class TestAdapterNotConfigured:
    def test_no_mapping_raises_not_configured(self):
        adapter = PaddleBillingAdapter(None)
        with pytest.raises(PaddleNotConfiguredError):
            adapter.create_checkout(_checkout_request())

    def test_empty_mapping_raises_not_configured(self):
        adapter = PaddleBillingAdapter(
            PaddlePriceMapping(environment="sandbox", base_price_id=None, additional_seat_price_id=None)
        )
        with pytest.raises(PaddleNotConfiguredError):
            adapter.create_portal(
                PortalRequest(
                    workspace_id=uuid.uuid4(),
                    customer_reference=_reference(),
                    return_url="https://app.example.test/billing",
                )
            )

    def test_not_configured_never_silently_returns_none(self):
        adapter = PaddleBillingAdapter(None)
        with pytest.raises(PaddleNotConfiguredError):
            adapter.get_subscription(_reference())


class TestAdapterConfiguredButUnsupported:
    @pytest.fixture
    def configured_adapter(self):
        return PaddleBillingAdapter(
            PaddlePriceMapping(environment="sandbox", base_price_id="pri_base", additional_seat_price_id="pri_seat")
        )

    def test_create_checkout_raises_unsupported(self, configured_adapter):
        with pytest.raises(PaddleUnsupportedBeforeM2Error):
            configured_adapter.create_checkout(_checkout_request())

    def test_create_portal_raises_unsupported(self, configured_adapter):
        with pytest.raises(PaddleUnsupportedBeforeM2Error):
            configured_adapter.create_portal(
                PortalRequest(
                    workspace_id=uuid.uuid4(), customer_reference=_reference(),
                    return_url="https://app.example.test/billing",
                )
            )

    def test_get_customer_raises_unsupported(self, configured_adapter):
        with pytest.raises(PaddleUnsupportedBeforeM2Error):
            configured_adapter.get_customer(_reference())

    def test_get_subscription_raises_unsupported(self, configured_adapter):
        with pytest.raises(PaddleUnsupportedBeforeM2Error):
            configured_adapter.get_subscription(_reference())

    def test_parse_webhook_raises_unsupported(self, configured_adapter):
        with pytest.raises(PaddleUnsupportedBeforeM2Error):
            configured_adapter.parse_webhook({}, b"{}")

    def test_reconcile_raises_unsupported(self, configured_adapter):
        with pytest.raises(PaddleUnsupportedBeforeM2Error):
            configured_adapter.reconcile(_reference())

    def test_update_subscription_returns_typed_result_not_exception(self, configured_adapter):
        result = configured_adapter.update_subscription(
            SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=25, reason="member_added")
        )
        assert result.state == "unsupported_before_m2"

    def test_cancel_subscription_returns_typed_result_not_exception(self, configured_adapter):
        result = configured_adapter.cancel_subscription(CancelSubscriptionRequest(subscription_reference=_reference()))
        assert result.state == "unsupported_before_m2"


class TestNeverFallsBackToStripe:
    def test_paddle_adapter_provider_is_always_paddle(self):
        adapter = PaddleBillingAdapter(None)
        assert adapter.provider == BillingProvider.PADDLE

    def test_paddle_adapter_module_never_imports_stripe(self):
        import app.billing.adapters.paddle as paddle_module

        source = open(paddle_module.__file__).read()
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("import ") or stripped.startswith("from "):
                assert "stripe" not in stripped.lower()


class TestPlannedSeatRepresentation:
    def test_base_quantity_is_always_one_never_combinatorial(self):
        """message-1 spec item 13: ONE base item quantity 1 — never one
        price per team size."""
        from app.billing.desired_state import calculate_desired_team_state
        from app.billing.enums import DesiredSubscriptionReason

        for seats in (1, 20, 21, 50, 100):
            state = calculate_desired_team_state(seats, DesiredSubscriptionReason.RECONCILIATION)
            assert state.base_quantity == 1

    def test_additional_seat_quantity_matches_formula(self):
        from app.billing.desired_state import calculate_desired_team_state
        from app.billing.enums import DesiredSubscriptionReason

        for seats, expected in [(1, 0), (20, 0), (21, 1), (50, 30), (100, 80)]:
            state = calculate_desired_team_state(seats, DesiredSubscriptionReason.RECONCILIATION)
            assert state.additional_seat_quantity == expected
