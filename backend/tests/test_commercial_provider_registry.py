"""Provider abstraction tests (Commercial Infrastructure message 1).

Covers Stripe-selected, Paddle-selected-but-not-activated, unknown-provider
rejection, provider-neutral type shape, no Stripe-object leakage, registry
determinism, and no silent provider fallback.
"""

from __future__ import annotations

import dataclasses

import pytest

from app.billing.adapters.paddle import PaddleBillingAdapter, PaddleNotConfiguredError, PaddlePriceMapping
from app.billing.adapters.stripe import StripeBillingAdapter
from app.billing.enums import BillingProvider
from app.billing.provider import CheckoutRequest
from app.billing.registry import UnknownBillingProviderError, get_billing_provider


class TestStripeSelected:
    def test_default_provider_is_stripe(self, db_session, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")
        adapter = get_billing_provider(db_session)
        assert isinstance(adapter, StripeBillingAdapter)
        assert adapter.provider == BillingProvider.STRIPE

    def test_explicit_stripe_override(self, db_session):
        adapter = get_billing_provider(db_session, provider_override=BillingProvider.STRIPE)
        assert isinstance(adapter, StripeBillingAdapter)


class TestPaddleSelectedButNotActivated:
    def test_paddle_without_price_mapping_fails_closed(self, db_session, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "PADDLE_BASE_PRICE_ID", None)
        monkeypatch.setattr(config.settings, "PADDLE_ADDITIONAL_SEAT_PRICE_ID", None)
        with pytest.raises(PaddleNotConfiguredError):
            get_billing_provider(db_session, provider_override=BillingProvider.PADDLE)

    def test_paddle_missing_api_key_fails_closed_even_with_price_mapping(self, db_session, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "PADDLE_TEAM_BASE_PRICE_ID", "pri_test_base")
        monkeypatch.setattr(config.settings, "PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID", "pri_test_seat")
        monkeypatch.setattr(config.settings, "PADDLE_ENVIRONMENT", "sandbox")
        monkeypatch.setattr(config.settings, "PADDLE_API_KEY", None)
        with pytest.raises(PaddleNotConfiguredError):
            get_billing_provider(db_session, provider_override=BillingProvider.PADDLE)

    def test_paddle_fully_configured_returns_a_real_configured_adapter(self, db_session, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "PADDLE_TEAM_BASE_PRICE_ID", "pri_test_base")
        monkeypatch.setattr(config.settings, "PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID", "pri_test_seat")
        monkeypatch.setattr(config.settings, "PADDLE_ENVIRONMENT", "sandbox")
        monkeypatch.setattr(config.settings, "PADDLE_API_KEY", "apikey_sandbox_test")
        monkeypatch.setattr(config.settings, "PADDLE_WEBHOOK_SECRET", "whsec_test")
        adapter = get_billing_provider(db_session, provider_override=BillingProvider.PADDLE)
        assert isinstance(adapter, PaddleBillingAdapter)
        assert adapter.is_configured is True


class TestUnknownProviderRejected:
    def test_unknown_provider_string_raises(self, db_session, monkeypatch):
        from app import config

        # NOTE: "dodo" used to be this test's example of an unhandled
        # provider string — it is now a real, registered BillingProvider
        # (see test_commercial_dodo_* for its own coverage), so this test
        # uses a genuinely unknown string instead.
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "totally_unknown_provider_xyz")
        with pytest.raises(UnknownBillingProviderError):
            get_billing_provider(db_session)


class TestProviderNeutralTypes:
    def test_checkout_request_is_plain_dataclass(self):
        assert dataclasses.is_dataclass(CheckoutRequest)

    def test_checkout_request_fields_are_primitives_or_enums_only(self):
        import uuid as uuid_mod

        from app.billing.enums import BillingInterval, PlanId

        req = CheckoutRequest(
            workspace_id=uuid_mod.uuid4(),
            plan_id=PlanId.TEAM,
            billing_interval=BillingInterval.MONTH,
            billable_seat_count=25,
            success_url="https://app.example.test/success",
            cancel_url="https://app.example.test/cancel",
        )
        for f in dataclasses.fields(req):
            value = getattr(req, f.name)
            assert not type(value).__module__.startswith("stripe"), (
                f"field {f.name} leaked a Stripe SDK type"
            )


class TestNoStripeObjectLeakage:
    def test_stripe_adapter_module_never_imports_stripe_sdk(self):
        import app.billing.adapters.stripe as stripe_adapter_module

        source = open(stripe_adapter_module.__file__).read()
        assert "import stripe" not in source
        assert "from stripe" not in source

    def test_provider_module_has_no_stripe_or_paddle_import_statement(self):
        import app.billing.provider as provider_module

        source = open(provider_module.__file__).read()
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("import ") or stripped.startswith("from "):
                assert "stripe" not in stripped.lower()
                assert "paddle" not in stripped.lower()


class TestRegistryDeterministic:
    def test_same_provider_override_returns_same_adapter_type_every_time(self, db_session):
        a = get_billing_provider(db_session, provider_override=BillingProvider.STRIPE)
        b = get_billing_provider(db_session, provider_override=BillingProvider.STRIPE)
        assert type(a) is type(b)


class TestNoSilentProviderFallback:
    def test_paddle_not_configured_never_returns_a_stripe_adapter(self, db_session, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "PADDLE_BASE_PRICE_ID", None)
        monkeypatch.setattr(config.settings, "PADDLE_ADDITIONAL_SEAT_PRICE_ID", None)
        try:
            get_billing_provider(db_session, provider_override=BillingProvider.PADDLE)
            assert False, "expected PaddleNotConfiguredError"
        except PaddleNotConfiguredError:
            pass  # correct: fails closed, never silently returns Stripe


class TestPaddlePriceMappingConfiguration:
    def test_price_mapping_is_configured_only_with_both_ids(self):
        assert PaddlePriceMapping(environment="sandbox", base_price_id=None, additional_seat_price_id=None).is_configured is False
        assert PaddlePriceMapping(environment="sandbox", base_price_id="pri_1", additional_seat_price_id=None).is_configured is False
        assert PaddlePriceMapping(environment="sandbox", base_price_id="pri_1", additional_seat_price_id="pri_2").is_configured is True
