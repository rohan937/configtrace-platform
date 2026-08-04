"""Paddle subscription-item update tests (Commercial Infrastructure message 2)."""

from __future__ import annotations

import json
import uuid

import httpx
import pytest

from app.billing.adapters.paddle import (
    PaddleBaseItemMissingError,
    PaddleBillingAdapter,
    PaddleDuplicateBaseItemError,
    PaddlePriceMapping,
)
from app.billing.enums import BillingProvider, ObjectType
from app.billing.paddle_client import PaddleAPIClient, PaddleClientConfig
from app.billing.provider import BillingProviderReference, SubscriptionUpdateRequest

_MAPPING = PaddlePriceMapping(environment="sandbox", base_price_id="pri_base", additional_seat_price_id="pri_seat")


def _adapter(handler) -> PaddleBillingAdapter:
    transport = httpx.MockTransport(handler)
    client = PaddleAPIClient(PaddleClientConfig(environment="sandbox", api_key="k"), transport=transport)
    return PaddleBillingAdapter(_MAPPING, client, webhook_secret="s")


def _reference() -> BillingProviderReference:
    return BillingProviderReference(
        provider=BillingProvider.PADDLE, object_type=ObjectType.SUBSCRIPTION,
        external_id="sub_1", workspace_id=uuid.uuid4(),
    )


def _get_sub_response(items: list[dict]) -> httpx.Response:
    return httpx.Response(200, json={"data": {"id": "sub_1", "items": items}})


class TestBaseOnly:
    def test_update_with_no_additional_members_sends_base_only(self):
        seen = {}

        def handler(request):
            if request.method == "GET":
                return _get_sub_response([{"price": {"id": "pri_base"}, "quantity": 1}])
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": {}})

        adapter = _adapter(handler)
        adapter.update_subscription(SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=10, reason="member_added"))
        assert seen["body"]["items"] == [{"price_id": "pri_base", "quantity": 1}]


class TestBasePlusOneAdditional:
    def test_update_with_21_members_adds_one_seat(self):
        seen = {}

        def handler(request):
            if request.method == "GET":
                return _get_sub_response([{"price": {"id": "pri_base"}, "quantity": 1}])
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": {}})

        adapter = _adapter(handler)
        adapter.update_subscription(SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=21, reason="member_added"))
        assert {"price_id": "pri_seat", "quantity": 1} in seen["body"]["items"]


class TestBasePlusManyAdditional:
    def test_update_with_50_members_sets_30_additional(self):
        seen = {}

        def handler(request):
            if request.method == "GET":
                return _get_sub_response([{"price": {"id": "pri_base"}, "quantity": 1}])
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": {}})

        adapter = _adapter(handler)
        adapter.update_subscription(SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=50, reason="member_added"))
        assert {"price_id": "pri_seat", "quantity": 30} in seen["body"]["items"]


class TestPreserveUnrelatedItem:
    def test_unrelated_recurring_item_preserved_unchanged(self):
        seen = {}

        def handler(request):
            if request.method == "GET":
                return _get_sub_response(
                    [
                        {"price": {"id": "pri_base"}, "quantity": 1},
                        {"price": {"id": "pri_unrelated_addon"}, "quantity": 3},
                    ]
                )
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": {}})

        adapter = _adapter(handler)
        adapter.update_subscription(SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=10, reason="member_added"))
        assert {"price_id": "pri_unrelated_addon", "quantity": 3} in seen["body"]["items"]


class TestMissingBaseItem:
    def test_missing_base_item_raises(self):
        def handler(request):
            return _get_sub_response([{"price": {"id": "pri_seat"}, "quantity": 5}])

        adapter = _adapter(handler)
        with pytest.raises(PaddleBaseItemMissingError):
            adapter.update_subscription(SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=25, reason="member_added"))


class TestDuplicateBaseItem:
    def test_duplicate_base_item_raises(self):
        def handler(request):
            return _get_sub_response(
                [{"price": {"id": "pri_base"}, "quantity": 1}, {"price": {"id": "pri_base"}, "quantity": 1}]
            )

        adapter = _adapter(handler)
        with pytest.raises(PaddleDuplicateBaseItemError):
            adapter.update_subscription(SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=25, reason="member_added"))


class TestWrongPriceId:
    def test_item_with_unknown_price_id_is_preserved_not_dropped(self):
        seen = {}

        def handler(request):
            if request.method == "GET":
                return _get_sub_response(
                    [{"price": {"id": "pri_base"}, "quantity": 1}, {"price": {"id": "pri_totally_unknown"}, "quantity": 2}]
                )
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": {}})

        adapter = _adapter(handler)
        adapter.update_subscription(SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=10, reason="member_added"))
        assert {"price_id": "pri_totally_unknown", "quantity": 2} in seen["body"]["items"]


class TestZeroAdditionalSeatsOmitted:
    @pytest.mark.parametrize(
        "from_seats,to_seats",
        [(21, 20), (25, 20), (30, 25), (50, 10), (10, 50), (20, 21)],
    )
    def test_seat_transitions(self, from_seats, to_seats):
        seen = {}

        def handler(request):
            if request.method == "GET":
                observed_additional = max(0, from_seats - 20)
                items = [{"price": {"id": "pri_base"}, "quantity": 1}]
                if observed_additional > 0:
                    items.append({"price": {"id": "pri_seat"}, "quantity": observed_additional})
                return _get_sub_response(items)
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": {}})

        adapter = _adapter(handler)
        adapter.update_subscription(SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=to_seats, reason="reconciliation"))
        expected_additional = max(0, to_seats - 20)
        seat_items = [i for i in seen["body"]["items"] if i["price_id"] == "pri_seat"]
        if expected_additional > 0:
            assert seat_items == [{"price_id": "pri_seat", "quantity": expected_additional}]
        else:
            assert seat_items == []  # omitted entirely at zero (message-2 spec item 23's chosen behavior)


class TestExplicitProrationMode:
    def test_proration_mode_always_present(self):
        seen = {}

        def handler(request):
            if request.method == "GET":
                return _get_sub_response([{"price": {"id": "pri_base"}, "quantity": 1}])
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": {}})

        adapter = _adapter(handler)
        adapter.update_subscription(SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=25, reason="member_added"))
        assert seen["body"]["proration_billing_mode"] in ("prorated_immediately", "prorated_next_billing_period")

    def test_seat_added_uses_immediate_proration(self):
        seen = {}

        def handler(request):
            if request.method == "GET":
                return _get_sub_response([{"price": {"id": "pri_base"}, "quantity": 1}])
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": {}})

        adapter = _adapter(handler)
        adapter.update_subscription(SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=25, reason="member_added"))
        assert seen["body"]["proration_billing_mode"] == "prorated_immediately"

    def test_seat_removed_uses_next_billing_period_proration(self):
        seen = {}

        def handler(request):
            if request.method == "GET":
                return _get_sub_response([{"price": {"id": "pri_base"}, "quantity": 1}, {"price": {"id": "pri_seat"}, "quantity": 10}])
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": {}})

        adapter = _adapter(handler)
        adapter.update_subscription(SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=25, reason="member_removed"))
        assert seen["body"]["proration_billing_mode"] == "prorated_next_billing_period"


class TestStableIdempotencyKey:
    def test_checkout_idempotency_reference_is_stable_string(self):
        from app.billing.provider import CheckoutRequest
        from app.billing.enums import BillingInterval, PlanId

        request = CheckoutRequest(
            workspace_id=uuid.uuid4(), plan_id=PlanId.TEAM, billing_interval=BillingInterval.MONTH,
            billable_seat_count=25, success_url="https://x/success", cancel_url="https://x/cancel",
            idempotency_reference="stable-key-1",
        )
        assert request.idempotency_reference == "stable-key-1"
