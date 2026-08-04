"""Dodo Team additional-seat add-on update tests (Dodo Payments message 1).

Covers seat increases, decreases, and the transition back to exactly 20
members (add-on removed). Uses the verified ``change-plan`` endpoint.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest

from app.billing.adapters.dodo import (
    DODO_PRORATION_DO_NOT_BILL,
    DODO_PRORATION_PRORATED_IMMEDIATELY,
    DodoBillingAdapter,
    DodoCatalogMapping,
)
from app.billing.enums import BillingProvider, ObjectType
from app.billing.provider import BillingProviderReference, SubscriptionUpdateRequest


def _mapping() -> DodoCatalogMapping:
    return DodoCatalogMapping(
        environment="test", pro_product_id="prod_pro_test",
        team_product_id="prod_team_test", team_seat_addon_id="addon_seat_test",
    )


def _reference() -> BillingProviderReference:
    return BillingProviderReference(
        provider=BillingProvider.DODO, object_type=ObjectType.SUBSCRIPTION,
        external_id="sub_dodo_1", workspace_id=uuid.uuid4(),
    )


def _adapter_with_current_addon_quantity(current_quantity: int, captured: dict) -> DodoBillingAdapter:
    from app.billing.dodo_client import DodoAPIClient, DodoClientConfig

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            addons = [{"addon_id": "addon_seat_test", "quantity": current_quantity}] if current_quantity > 0 else []
            return httpx.Response(200, json={"subscription_id": "sub_dodo_1", "product_id": "prod_team_test", "addons": addons})
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(handler)
    client = DodoAPIClient(DodoClientConfig(environment="test", api_key="apikey_test_dummy"), transport=transport)
    return DodoBillingAdapter(_mapping(), client)


class TestSeatTransitions:
    @pytest.mark.parametrize(
        "current_quantity,new_members,expected_desired",
        [
            (0, 21, 1),   # 20 -> 21: add-on introduced at quantity 1
            (1, 20, 0),   # 21 -> 20: add-on removed entirely (back to 20)
            (5, 10, 0),   # 25 -> 10: add-on removed entirely
            (30, 25, 5),  # 50 -> 25: add-on reduced
            (10, 50, 30), # 30 -> 50: add-on increased
            (0, 20, 0),   # 20 -> 20 (no-op transition, still correct)
        ],
    )
    def test_change_plan_sets_correct_addon_quantity(self, current_quantity, new_members, expected_desired):
        captured = {}
        adapter = _adapter_with_current_addon_quantity(current_quantity, captured)
        adapter.update_subscription(
            SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=new_members, reason="test")
        )
        body = captured["body"]
        assert body["product_id"] == "prod_team_test"
        assert body["quantity"] == 1
        if expected_desired > 0:
            assert body["addons"] == [{"addon_id": "addon_seat_test", "quantity": expected_desired}]
        else:
            assert body["addons"] == []  # documented zero-quantity-omission choice

    def test_seat_increase_uses_prorated_immediately(self):
        captured = {}
        adapter = _adapter_with_current_addon_quantity(0, captured)
        adapter.update_subscription(
            SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=21, reason="member_added")
        )
        assert captured["body"]["proration_billing_mode"] == DODO_PRORATION_PRORATED_IMMEDIATELY

    def test_seat_decrease_uses_do_not_bill(self):
        captured = {}
        adapter = _adapter_with_current_addon_quantity(5, captured)
        adapter.update_subscription(
            SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=20, reason="member_removed")
        )
        assert captured["body"]["proration_billing_mode"] == DODO_PRORATION_DO_NOT_BILL

    def test_proration_mode_always_present(self):
        captured = {}
        adapter = _adapter_with_current_addon_quantity(0, captured)
        adapter.update_subscription(
            SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=25, reason="member_added")
        )
        assert "proration_billing_mode" in captured["body"]

    def test_operation_result_reports_ok(self):
        captured = {}
        adapter = _adapter_with_current_addon_quantity(0, captured)
        result = adapter.update_subscription(
            SubscriptionUpdateRequest(subscription_reference=_reference(), billable_seat_count=21, reason="member_added")
        )
        assert result.state == "ok"
        assert "1" in result.detail


class TestSubscriptionSnapshotNormalization:
    def test_team_snapshot_reports_billable_seats_including_addon(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "subscription_id": "sub_dodo_1",
                    "product_id": "prod_team_test",
                    "status": "active",
                    "addons": [{"addon_id": "addon_seat_test", "quantity": 5}],
                    "customer": {"customer_id": "cus_1"},
                    "cancel_at_next_billing_date": False,
                    "next_billing_date": "2026-09-01T00:00:00Z",
                    "previous_billing_date": "2026-08-01T00:00:00Z",
                },
            )

        transport = httpx.MockTransport(handler)
        from app.billing.dodo_client import DodoAPIClient, DodoClientConfig

        client = DodoAPIClient(DodoClientConfig(environment="test", api_key="apikey_test_dummy"), transport=transport)
        adapter = DodoBillingAdapter(_mapping(), client)
        snapshot = adapter.get_subscription(_reference())
        assert snapshot.billable_seats == 25
        assert snapshot.plan_id.value == "team"
        assert snapshot.status == "active"
        assert snapshot.cancel_at_period_end is False

    def test_pro_snapshot_reports_zero_billable_seats(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "subscription_id": "sub_dodo_2", "product_id": "prod_pro_test", "status": "active",
                    "addons": [], "customer": {"customer_id": "cus_2"},
                },
            )

        transport = httpx.MockTransport(handler)
        from app.billing.dodo_client import DodoAPIClient, DodoClientConfig

        client = DodoAPIClient(DodoClientConfig(environment="test", api_key="apikey_test_dummy"), transport=transport)
        adapter = DodoBillingAdapter(_mapping(), client)
        snapshot = adapter.get_subscription(_reference())
        assert snapshot.plan_id.value == "pro"
        assert snapshot.billable_seats == 0

    def test_get_subscription_returns_none_for_empty_response(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"")

        transport = httpx.MockTransport(handler)
        from app.billing.dodo_client import DodoAPIClient, DodoClientConfig

        client = DodoAPIClient(DodoClientConfig(environment="test", api_key="apikey_test_dummy"), transport=transport)
        adapter = DodoBillingAdapter(_mapping(), client)
        assert adapter.get_subscription(_reference()) is None

    def test_reconcile_delegates_to_get_subscription(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"subscription_id": "sub_dodo_1", "product_id": "prod_team_test", "status": "active", "addons": [], "customer": {"customer_id": "cus_1"}},
            )

        transport = httpx.MockTransport(handler)
        from app.billing.dodo_client import DodoAPIClient, DodoClientConfig

        client = DodoAPIClient(DodoClientConfig(environment="test", api_key="apikey_test_dummy"), transport=transport)
        adapter = DodoBillingAdapter(_mapping(), client)
        snapshot = adapter.reconcile(_reference())
        assert snapshot is not None
        assert snapshot.provider == BillingProvider.DODO
