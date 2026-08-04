"""Paddle checkout creation tests (Commercial Infrastructure message 2)."""

from __future__ import annotations

import uuid

import httpx
import pytest

from app.billing.adapters.paddle import PaddleBillingAdapter, PaddleNotConfiguredError, PaddlePriceMapping
from app.billing.enums import BillingInterval, PlanId
from app.billing.paddle_client import PaddleAPIClient, PaddleClientConfig
from app.billing.provider import CheckoutRequest

_MAPPING = PaddlePriceMapping(environment="sandbox", base_price_id="pri_base_test", additional_seat_price_id="pri_seat_test")


def _adapter(handler) -> PaddleBillingAdapter:
    transport = httpx.MockTransport(handler)
    client = PaddleAPIClient(PaddleClientConfig(environment="sandbox", api_key="test_key"), transport=transport)
    return PaddleBillingAdapter(_MAPPING, client, webhook_secret="whsec_test")


def _request(seats: int, idempotency_reference: str | None = None) -> CheckoutRequest:
    return CheckoutRequest(
        workspace_id=uuid.uuid4(), plan_id=PlanId.TEAM, billing_interval=BillingInterval.MONTH,
        billable_seat_count=seats, success_url="https://app.example.test/success",
        cancel_url="https://app.example.test/cancel", customer_email="owner@example.test",
        idempotency_reference=idempotency_reference,
    )


class TestCheckoutItemsByMemberCount:
    @pytest.mark.parametrize("seats", [1, 10, 19, 20])
    def test_base_only_for_seats_at_or_under_20(self, seats):
        adapter = _adapter(lambda r: httpx.Response(200, json={"data": {"id": "txn_1", "checkout": {"url": "https://sandbox-checkout.paddle.com/x"}}}))
        items = adapter.build_checkout_items(seats)
        assert items == [{"price_id": "pri_base_test", "quantity": 1}]

    @pytest.mark.parametrize("seats,expected_additional", [(21, 1), (25, 5), (50, 30)])
    def test_base_plus_additional_for_seats_over_20(self, seats, expected_additional):
        adapter = _adapter(lambda r: httpx.Response(200, json={"data": {}}))
        items = adapter.build_checkout_items(seats)
        assert items[0] == {"price_id": "pri_base_test", "quantity": 1}
        assert items[1] == {"price_id": "pri_seat_test", "quantity": expected_additional}
        assert len(items) == 2


class TestCustomData:
    def test_custom_data_includes_required_correlation_fields(self):
        seen = {}

        def handler(request):
            import json

            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": {"id": "txn_1", "checkout": {"url": "https://x"}}})

        adapter = _adapter(handler)
        request = _request(25)
        adapter.create_checkout(request)
        custom_data = seen["body"]["custom_data"]
        assert custom_data["workspace_id"] == str(request.workspace_id)
        assert custom_data["plan_id"] == "team"
        assert custom_data["billable_seat_count"] == 25
        assert "pricing_version" in custom_data
        assert "idempotency_reference" in custom_data

    def test_idempotency_reference_generated_if_absent(self):
        seen = {}

        def handler(request):
            import json

            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": {"checkout": {"url": "https://x"}}})

        adapter = _adapter(handler)
        adapter.create_checkout(_request(5, idempotency_reference=None))
        assert seen["body"]["custom_data"]["idempotency_reference"]

    def test_provided_idempotency_reference_is_used(self):
        seen = {}

        def handler(request):
            import json

            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": {"checkout": {"url": "https://x"}}})

        adapter = _adapter(handler)
        adapter.create_checkout(_request(5, idempotency_reference="fixed-ref-1"))
        assert seen["body"]["custom_data"]["idempotency_reference"] == "fixed-ref-1"


class TestCheckoutResponse:
    def test_response_includes_provider_and_url(self):
        adapter = _adapter(
            lambda r: httpx.Response(200, json={"data": {"id": "txn_1", "checkout": {"url": "https://sandbox-checkout.paddle.com/y"}}})
        )
        response = adapter.create_checkout(_request(10))
        assert response.provider.value == "paddle"
        assert response.checkout_url == "https://sandbox-checkout.paddle.com/y"
        assert response.external_reference == "txn_1"


class TestNotConfigured:
    def test_checkout_raises_not_configured_when_no_mapping(self):
        adapter = PaddleBillingAdapter(None)
        with pytest.raises(PaddleNotConfiguredError):
            adapter.create_checkout(_request(10))

    def test_checkout_raises_not_configured_when_client_missing(self):
        adapter = PaddleBillingAdapter(_MAPPING, client=None)
        with pytest.raises(PaddleNotConfiguredError):
            adapter.create_checkout(_request(10))
