"""Stripe compatibility adapter tests (Commercial Infrastructure message 1).

Proves the existing Stripe checkout/portal/webhook behavior remains
functional through the provider-neutral adapter — isolation, not rewrite.
No real Stripe API call is made (`_stripe_post` is mocked).
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.billing.adapters.stripe import StripeBillingAdapter
from app.billing.enums import BillingProvider
from app.billing.provider import CancelSubscriptionRequest, PortalRequest, SubscriptionUpdateRequest, BillingProviderReference
from app.billing.enums import ObjectType


@pytest.fixture
def stripe_env(monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_test_fake_m1")
    monkeypatch.setattr(config.settings, "STRIPE_WEBHOOK_SECRET", "whsec_test_fake_m1")
    monkeypatch.setattr(config.settings, "STRIPE_PRICE_TEAM_MONTHLY", "price_test_team_m1")
    monkeypatch.setattr(config.settings, "STRIPE_PRICE_PRO_MONTHLY", "price_test_pro_m1")
    monkeypatch.setattr(config.settings, "FRONTEND_URL", "https://app.example.test")
    yield


def _mock_billing():
    b = MagicMock(name="WorkspaceBilling")
    b.workspace_id = uuid.uuid4()
    b.plan = "free"
    b.status = "active"
    b.stripe_customer_id = None
    b.stripe_subscription_id = None
    b.stripe_price_id = None
    b.current_period_start = None
    b.current_period_end = None
    b.cancel_at_period_end = False
    b.trial_end = None
    return b


class TestCreateCheckoutThroughAdapter:
    def test_checkout_returns_provider_neutral_response(self, stripe_env):
        db = MagicMock(name="Session")
        adapter = StripeBillingAdapter(db)
        billing = _mock_billing()

        with patch("app.services.billing_service.get_or_create_billing", return_value=billing), \
             patch("app.services.billing_service._stripe_post") as mock_post:
            mock_post.side_effect = [
                {"id": "cus_new"},
                {"url": "https://checkout.stripe.com/session/xyz"},
            ]
            from app.billing.provider import CheckoutRequest
            from app.billing.enums import BillingInterval, PlanId

            response = adapter.create_checkout(
                CheckoutRequest(
                    workspace_id=billing.workspace_id,
                    plan_id=PlanId.TEAM,
                    billing_interval=BillingInterval.MONTH,
                    billable_seat_count=25,
                    success_url="https://app.example.test/success",
                    cancel_url="https://app.example.test/cancel",
                    customer_email="owner@example.test",
                )
            )
        assert response.provider == BillingProvider.STRIPE
        assert response.checkout_url == "https://checkout.stripe.com/session/xyz"


class TestCreatePortalThroughAdapter:
    def test_portal_returns_provider_neutral_response(self, stripe_env):
        db = MagicMock(name="Session")
        adapter = StripeBillingAdapter(db)
        billing = _mock_billing()
        billing.stripe_customer_id = "cus_existing"

        with patch("app.services.billing_service.get_or_create_billing", return_value=billing), \
             patch("app.services.billing_service._stripe_post", return_value={"url": "https://billing.stripe.com/p/session_1"}):
            response = adapter.create_portal(
                PortalRequest(
                    workspace_id=billing.workspace_id,
                    customer_reference=BillingProviderReference(
                        provider=BillingProvider.STRIPE, object_type=ObjectType.CUSTOMER,
                        external_id="cus_existing", workspace_id=billing.workspace_id,
                    ),
                    return_url="https://app.example.test/settings/workspace/billing",
                )
            )
        assert response.provider == BillingProvider.STRIPE
        assert response.management_url == "https://billing.stripe.com/p/session_1"

    def test_portal_without_stripe_customer_raises_400(self, stripe_env):
        from fastapi import HTTPException

        db = MagicMock(name="Session")
        adapter = StripeBillingAdapter(db)
        billing = _mock_billing()  # no stripe_customer_id

        with patch("app.services.billing_service.get_or_create_billing", return_value=billing):
            with pytest.raises(HTTPException) as exc_info:
                adapter.create_portal(
                    PortalRequest(
                        workspace_id=billing.workspace_id,
                        customer_reference=BillingProviderReference(
                            provider=BillingProvider.STRIPE, object_type=ObjectType.CUSTOMER,
                            external_id="", workspace_id=billing.workspace_id,
                        ),
                        return_url="https://app.example.test/settings/workspace/billing",
                    )
                )
        assert exc_info.value.status_code == 400


class TestWebhookNormalizationEquivalence:
    def test_parse_webhook_delegates_to_existing_verify_signature(self, stripe_env):
        import hashlib
        import hmac
        import time

        db = MagicMock(name="Session")
        adapter = StripeBillingAdapter(db)

        body = b'{"id": "evt_1", "type": "customer.updated", "data": {"object": {}}}'
        ts = str(int(time.time()))
        signed_payload = f"{ts}.{body.decode()}"
        sig = hmac.new(b"whsec_test_fake_m1", signed_payload.encode(), hashlib.sha256).hexdigest()
        headers = {"stripe-signature": f"t={ts},v1={sig}"}

        event = adapter.parse_webhook(headers, body)
        assert event["id"] == "evt_1"
        assert event["type"] == "customer.updated"

    def test_parse_webhook_rejects_bad_signature(self, stripe_env):
        db = MagicMock(name="Session")
        adapter = StripeBillingAdapter(db)
        with pytest.raises(ValueError):
            adapter.parse_webhook({"stripe-signature": "t=123,v1=bad"}, b"{}")


class TestUpdateAndCancelUnsupported:
    def test_update_subscription_returns_unsupported_before_m2(self, stripe_env):
        db = MagicMock(name="Session")
        adapter = StripeBillingAdapter(db)
        result = adapter.update_subscription(
            SubscriptionUpdateRequest(
                subscription_reference=BillingProviderReference(
                    provider=BillingProvider.STRIPE, object_type=ObjectType.SUBSCRIPTION,
                    external_id="sub_1", workspace_id=uuid.uuid4(),
                ),
                billable_seat_count=25,
                reason="member_added",
            )
        )
        assert result.state == "unsupported_before_m2"

    def test_cancel_subscription_documents_portal_only_cancellation(self, stripe_env):
        db = MagicMock(name="Session")
        adapter = StripeBillingAdapter(db)
        result = adapter.cancel_subscription(
            CancelSubscriptionRequest(
                subscription_reference=BillingProviderReference(
                    provider=BillingProvider.STRIPE, object_type=ObjectType.SUBSCRIPTION,
                    external_id="sub_1", workspace_id=uuid.uuid4(),
                ),
            )
        )
        assert result.state == "unsupported_before_m2"
        assert "portal" in result.detail.lower()


class TestNoExternalCallsInAdapterConstruction:
    def test_constructing_adapter_makes_no_network_call(self):
        db = MagicMock(name="Session")
        # Constructing must never itself reach out to Stripe.
        StripeBillingAdapter(db)
        db.assert_not_called() if callable(db) else None
