"""Paddle customer-management URL tests (Commercial Infrastructure message 2)."""

from __future__ import annotations

import uuid

import httpx
import pytest

from app.billing.adapters.paddle import PaddleBillingAdapter, PaddleManagementUrlHostError, PaddlePriceMapping
from app.billing.enums import BillingProvider, ObjectType
from app.billing.paddle_client import PaddleAPIClient, PaddleClientConfig
from app.billing.provider import BillingProviderReference, PortalRequest

_MAPPING = PaddlePriceMapping(environment="sandbox", base_price_id="pri_base", additional_seat_price_id="pri_seat")


def _adapter(handler) -> PaddleBillingAdapter:
    transport = httpx.MockTransport(handler)
    client = PaddleAPIClient(PaddleClientConfig(environment="sandbox", api_key="k"), transport=transport)
    return PaddleBillingAdapter(_MAPPING, client, webhook_secret="s")


def _request() -> PortalRequest:
    return PortalRequest(
        workspace_id=uuid.uuid4(),
        customer_reference=BillingProviderReference(
            provider=BillingProvider.PADDLE, object_type=ObjectType.CUSTOMER,
            external_id="ctm_1", workspace_id=uuid.uuid4(),
        ),
        return_url="https://app.example.test/billing",
    )


class TestManagementUrlReturned:
    def test_valid_sandbox_url_returned(self):
        adapter = _adapter(
            lambda r: httpx.Response(
                200,
                json={"data": {"urls": {"general": {"overview": "https://sandbox-customer-portal.paddle.com/abc"}}}},
            )
        )
        response = adapter.create_portal(_request())
        assert response.provider == BillingProvider.PADDLE
        assert response.management_url == "https://sandbox-customer-portal.paddle.com/abc"

    def test_supported_actions_present(self):
        adapter = _adapter(
            lambda r: httpx.Response(200, json={"data": {"urls": {"general": {"overview": "https://sandbox-customer-portal.paddle.com/x"}}}})
        )
        response = adapter.create_portal(_request())
        assert "cancel_subscription" in response.supported_actions


class TestUrlHostValidation:
    def test_unexpected_host_rejected(self):
        adapter = _adapter(
            lambda r: httpx.Response(200, json={"data": {"urls": {"general": {"overview": "https://evil.example.com/phish"}}}})
        )
        with pytest.raises(PaddleManagementUrlHostError):
            adapter.create_portal(_request())

    def test_production_portal_host_accepted(self):
        adapter = _adapter(
            lambda r: httpx.Response(200, json={"data": {"urls": {"general": {"overview": "https://customer-portal.paddle.com/xyz"}}}})
        )
        response = adapter.create_portal(_request())
        assert response.management_url == "https://customer-portal.paddle.com/xyz"


class TestEmptyUrlNotValidated:
    def test_missing_url_does_not_raise_host_error(self):
        adapter = _adapter(lambda r: httpx.Response(200, json={"data": {"urls": {}}}))
        response = adapter.create_portal(_request())
        assert response.management_url == ""


class TestNotConfigured:
    def test_portal_raises_not_configured_when_no_client(self):
        from app.billing.adapters.paddle import PaddleNotConfiguredError

        adapter = PaddleBillingAdapter(_MAPPING, client=None)
        with pytest.raises(PaddleNotConfiguredError):
            adapter.create_portal(_request())
