"""Dodo customer-portal and cancellation tests (Dodo Payments message 1)."""

from __future__ import annotations

import json
import uuid

import httpx
import pytest

from app.billing.adapters.dodo import DodoBillingAdapter, DodoCatalogMapping, DodoNotConfiguredError
from app.billing.dodo_client import DodoAPIClient, DodoClientConfig
from app.billing.enums import BillingProvider, ObjectType
from app.billing.provider import BillingProviderReference, CancelSubscriptionRequest, PortalRequest


def _mapping() -> DodoCatalogMapping:
    return DodoCatalogMapping(
        environment="test", pro_product_id="prod_pro_test",
        team_product_id="prod_team_test", team_seat_addon_id="addon_seat_test",
    )


def _adapter(handler) -> DodoBillingAdapter:
    transport = httpx.MockTransport(handler)
    client = DodoAPIClient(DodoClientConfig(environment="test", api_key="apikey_test_dummy"), transport=transport)
    return DodoBillingAdapter(_mapping(), client)


def _customer_reference() -> BillingProviderReference:
    return BillingProviderReference(
        provider=BillingProvider.DODO, object_type=ObjectType.CUSTOMER,
        external_id="cus_dodo_1", workspace_id=uuid.uuid4(),
    )


def _subscription_reference() -> BillingProviderReference:
    return BillingProviderReference(
        provider=BillingProvider.DODO, object_type=ObjectType.SUBSCRIPTION,
        external_id="sub_dodo_1", workspace_id=uuid.uuid4(),
    )


class TestPortalCreation:
    def test_portal_url_returned(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"link": "https://customer.dodopayments.com/unified-session/abc123"})

        adapter = _adapter(handler)
        response = adapter.create_portal(
            PortalRequest(
                workspace_id=uuid.uuid4(), customer_reference=_customer_reference(),
                return_url="https://app.example.test/settings/workspace/billing",
            )
        )
        assert response.provider == BillingProvider.DODO
        assert response.management_url == "https://customer.dodopayments.com/unified-session/abc123"

    def test_supported_actions_present(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"link": "https://customer.dodopayments.com/x"})

        adapter = _adapter(handler)
        response = adapter.create_portal(
            PortalRequest(
                workspace_id=uuid.uuid4(), customer_reference=_customer_reference(),
                return_url="https://app.example.test/billing",
            )
        )
        assert "cancel_subscription" in response.supported_actions

    def test_return_url_forwarded_to_dodo(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content) if request.content else {}
            return httpx.Response(200, json={"link": "https://customer.dodopayments.com/x"})

        adapter = _adapter(handler)
        adapter.create_portal(
            PortalRequest(
                workspace_id=uuid.uuid4(), customer_reference=_customer_reference(),
                return_url="https://app.example.test/settings/workspace/billing",
            )
        )
        assert captured["body"]["return_url"] == "https://app.example.test/settings/workspace/billing"

    def test_missing_link_raises(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={})

        adapter = _adapter(handler)
        with pytest.raises(ValueError):
            adapter.create_portal(
                PortalRequest(
                    workspace_id=uuid.uuid4(), customer_reference=_customer_reference(),
                    return_url="https://app.example.test/billing",
                )
            )

    def test_not_configured_raises(self):
        adapter = DodoBillingAdapter(None)
        with pytest.raises(DodoNotConfiguredError):
            adapter.create_portal(
                PortalRequest(
                    workspace_id=uuid.uuid4(), customer_reference=_customer_reference(),
                    return_url="https://app.example.test/billing",
                )
            )


class TestCancellation:
    def test_cancel_at_period_end_sets_cancel_at_next_billing_date(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={})

        adapter = _adapter(handler)
        result = adapter.cancel_subscription(
            CancelSubscriptionRequest(subscription_reference=_subscription_reference(), cancel_at_period_end=True)
        )
        assert captured["method"] == "PATCH"
        assert captured["body"] == {"cancel_at_next_billing_date": True}
        assert result.state == "ok"

    def test_cancel_immediately_sets_status_cancelled(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={})

        adapter = _adapter(handler)
        adapter.cancel_subscription(
            CancelSubscriptionRequest(subscription_reference=_subscription_reference(), cancel_at_period_end=False)
        )
        assert captured["body"] == {"status": "cancelled"}

    def test_not_configured_raises(self):
        adapter = DodoBillingAdapter(None)
        with pytest.raises(DodoNotConfiguredError):
            adapter.cancel_subscription(
                CancelSubscriptionRequest(subscription_reference=_subscription_reference())
            )


class TestGetCustomer:
    def test_get_customer_returns_reference(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"customer_id": "cus_dodo_1", "email": "owner@example.test"})

        adapter = _adapter(handler)
        result = adapter.get_customer(_customer_reference())
        assert result.provider == BillingProvider.DODO
        assert result.external_id == "cus_dodo_1"
        assert result.metadata["email"] == "owner@example.test"

    def test_not_configured_raises(self):
        adapter = DodoBillingAdapter(None)
        with pytest.raises(DodoNotConfiguredError):
            adapter.get_customer(_customer_reference())
