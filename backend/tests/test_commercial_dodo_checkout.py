"""Dodo checkout payload tests (Dodo Payments message 1).

No live Dodo API call is made anywhere in this file — all HTTP is mocked.
"""

from __future__ import annotations

import uuid

import httpx
import pytest

from app.billing.adapters.dodo import DodoBillingAdapter, DodoCatalogMapping, DodoNotConfiguredError
from app.billing.dodo_client import DodoAPIClient, DodoClientConfig
from app.billing.enums import BillingInterval, BillingProvider, PlanId
from app.billing.provider import CheckoutRequest


def _mapping() -> DodoCatalogMapping:
    return DodoCatalogMapping(
        environment="test", pro_product_id="prod_pro_test",
        team_product_id="prod_team_test", team_seat_addon_id="addon_seat_test",
    )


def _adapter(handler) -> DodoBillingAdapter:
    transport = httpx.MockTransport(handler)
    client = DodoAPIClient(DodoClientConfig(environment="test", api_key="apikey_test_dummy"), transport=transport)
    return DodoBillingAdapter(_mapping(), client)


def _checkout_request(plan_id: PlanId, billable_seat_count: int, **overrides) -> CheckoutRequest:
    defaults = dict(
        workspace_id=uuid.uuid4(),
        plan_id=plan_id,
        billing_interval=BillingInterval.MONTH,
        billable_seat_count=billable_seat_count,
        success_url="https://app.example.test/success",
        cancel_url="https://app.example.test/cancel",
        customer_email="owner@example.test",
        configtrace_user_id=uuid.uuid4(),
    )
    defaults.update(overrides)
    return CheckoutRequest(**defaults)


class TestProCheckoutPayload:
    def test_pro_checkout_sends_single_item_no_addons(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = __import__("json").loads(request.content)
            return httpx.Response(200, json={"session_id": "cks_1", "checkout_url": "https://test.checkout.dodopayments.com/x"})

        adapter = _adapter(handler)
        adapter.create_checkout(_checkout_request(PlanId.PRO, billable_seat_count=1))
        cart = captured["body"]["product_cart"]
        assert cart == [{"product_id": "prod_pro_test", "quantity": 1}]

    def test_pro_metadata_never_includes_seat_count(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = __import__("json").loads(request.content)
            return httpx.Response(200, json={"session_id": "cks_1", "checkout_url": "https://x"})

        adapter = _adapter(handler)
        adapter.create_checkout(_checkout_request(PlanId.PRO, billable_seat_count=1))
        assert captured["body"]["metadata"]["additional_seat_count"] == 0
        assert captured["body"]["metadata"]["included_member_count"] == 0
        assert captured["body"]["metadata"]["plan_id"] == "pro"

    def test_pro_response_shape(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"session_id": "cks_pro1", "checkout_url": "https://test.checkout.dodopayments.com/cks_pro1"})

        adapter = _adapter(handler)
        response = adapter.create_checkout(_checkout_request(PlanId.PRO, billable_seat_count=1))
        assert response.provider == BillingProvider.DODO
        assert response.checkout_url == "https://test.checkout.dodopayments.com/cks_pro1"
        assert response.external_reference == "cks_pro1"


class TestTeamCheckoutPayloadByMemberCount:
    @pytest.mark.parametrize("members", [1, 20])
    def test_base_only_for_seats_at_or_under_20(self, members):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = __import__("json").loads(request.content)
            return httpx.Response(200, json={"session_id": "cks_1", "checkout_url": "https://x"})

        adapter = _adapter(handler)
        adapter.create_checkout(_checkout_request(PlanId.TEAM, billable_seat_count=members))
        item = captured["body"]["product_cart"][0]
        assert item["product_id"] == "prod_team_test"
        assert "addons" not in item

    def test_21_members_adds_addon_quantity_1(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = __import__("json").loads(request.content)
            return httpx.Response(200, json={"session_id": "cks_1", "checkout_url": "https://x"})

        adapter = _adapter(handler)
        adapter.create_checkout(_checkout_request(PlanId.TEAM, billable_seat_count=21))
        item = captured["body"]["product_cart"][0]
        assert item["addons"] == [{"addon_id": "addon_seat_test", "quantity": 1}]

    def test_25_members_adds_addon_quantity_5(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = __import__("json").loads(request.content)
            return httpx.Response(200, json={"session_id": "cks_1", "checkout_url": "https://x"})

        adapter = _adapter(handler)
        adapter.create_checkout(_checkout_request(PlanId.TEAM, billable_seat_count=25))
        item = captured["body"]["product_cart"][0]
        assert item["addons"] == [{"addon_id": "addon_seat_test", "quantity": 5}]

    def test_team_metadata_includes_all_required_fields(self):
        captured = {}
        workspace_id = uuid.uuid4()
        user_id = uuid.uuid4()

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = __import__("json").loads(request.content)
            return httpx.Response(200, json={"session_id": "cks_1", "checkout_url": "https://x"})

        adapter = _adapter(handler)
        adapter.create_checkout(
            _checkout_request(
                PlanId.TEAM, billable_seat_count=25, workspace_id=workspace_id, configtrace_user_id=user_id,
                idempotency_reference="idem-ref-123",
            )
        )
        metadata = captured["body"]["metadata"]
        assert metadata["workspace_id"] == str(workspace_id)
        assert metadata["configtrace_user_id"] == str(user_id)
        assert metadata["plan_id"] == "team"
        assert metadata["included_member_count"] == 20
        assert metadata["additional_seat_count"] == 5
        assert metadata["pricing_version"] == 1
        assert metadata["idempotency_reference"] == "idem-ref-123"

    def test_idempotency_reference_generated_if_absent(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = __import__("json").loads(request.content)
            return httpx.Response(200, json={"session_id": "cks_1", "checkout_url": "https://x"})

        adapter = _adapter(handler)
        adapter.create_checkout(_checkout_request(PlanId.TEAM, billable_seat_count=1, idempotency_reference=None))
        assert captured["body"]["metadata"]["idempotency_reference"]


class TestReturnAndCancelUrls:
    def test_return_and_cancel_url_forwarded(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = __import__("json").loads(request.content)
            return httpx.Response(200, json={"session_id": "cks_1", "checkout_url": "https://x"})

        adapter = _adapter(handler)
        adapter.create_checkout(
            _checkout_request(
                PlanId.PRO, billable_seat_count=1,
                success_url="https://app.example.test/settings/workspace/billing?checkout=success",
                cancel_url="https://app.example.test/settings/workspace/billing?checkout=canceled",
            )
        )
        assert captured["body"]["return_url"].endswith("checkout=success")
        assert captured["body"]["cancel_url"].endswith("checkout=canceled")


class TestNotConfigured:
    def test_checkout_raises_not_configured_when_no_mapping(self):
        adapter = DodoBillingAdapter(None)
        with pytest.raises(DodoNotConfiguredError):
            adapter.create_checkout(_checkout_request(PlanId.PRO, billable_seat_count=1))

    def test_checkout_raises_not_configured_when_client_missing(self):
        adapter = DodoBillingAdapter(_mapping(), client=None)
        with pytest.raises(DodoNotConfiguredError):
            adapter.create_checkout(_checkout_request(PlanId.TEAM, billable_seat_count=1))
