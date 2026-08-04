"""Provider routing tests (Commercial Infrastructure message 2, spec item 31)."""

from __future__ import annotations

import uuid

import pytest

from app.billing.enums import BillingProvider
from app.billing.models import NormalizedSubscription
from app.billing.provider_routing import (
    configured_checkout_provider,
    get_stored_subscription_provider,
    provider_for_checkout,
    provider_for_management,
    provider_for_reconciliation,
)
from app.models.workspace import Workspace


@pytest.fixture
def workspace(db_session, test_user):
    ws = Workspace(name=f"routing-{uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.delete(ws)
    db_session.commit()


class TestConfiguredCheckoutProvider:
    def test_reads_from_settings_billing_provider(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "paddle")
        assert configured_checkout_provider() == BillingProvider.PADDLE

    def test_defaults_to_stripe(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")
        assert configured_checkout_provider() == BillingProvider.STRIPE


class TestNewCheckoutUsesConfiguredProvider:
    def test_workspace_with_no_subscription_uses_configured_provider(self, db_session, workspace, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "paddle")
        assert provider_for_checkout(workspace.id, db_session) == BillingProvider.PADDLE

    def test_stored_subscription_provider_returns_none_when_absent(self, db_session, workspace):
        assert get_stored_subscription_provider(workspace.id, db_session) is None


class TestExistingSubscriptionUsesStoredProvider:
    def test_stripe_subscription_routes_to_stripe_even_if_global_default_is_paddle(
        self, db_session, workspace, monkeypatch
    ):
        from app import config

        sub = NormalizedSubscription(workspace_id=workspace.id, provider="stripe", plan_id="team", status="active")
        db_session.add(sub)
        db_session.commit()

        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "paddle")
        assert provider_for_management(workspace.id, db_session) == BillingProvider.STRIPE

    def test_paddle_subscription_routes_to_paddle_even_if_global_default_is_stripe(
        self, db_session, workspace, monkeypatch
    ):
        from app import config

        sub = NormalizedSubscription(workspace_id=workspace.id, provider="paddle", plan_id="team", status="active")
        db_session.add(sub)
        db_session.commit()

        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")
        assert provider_for_management(workspace.id, db_session) == BillingProvider.PADDLE

    def test_never_reinterprets_existing_stripe_subscription_as_paddle(self, db_session, workspace, monkeypatch):
        """The core message-2 spec item 31 guarantee, stated as its own
        explicit test: flipping the global BILLING_PROVIDER setting must
        NEVER change what provider an EXISTING subscription is reported
        as belonging to."""
        from app import config

        sub = NormalizedSubscription(workspace_id=workspace.id, provider="stripe", plan_id="team", status="active")
        db_session.add(sub)
        db_session.commit()

        for global_default in ("stripe", "paddle"):
            monkeypatch.setattr(config.settings, "BILLING_PROVIDER", global_default)
            assert provider_for_management(workspace.id, db_session) == BillingProvider.STRIPE


class TestReconciliationUsesStoredProvider:
    def test_reconciliation_provider_is_none_with_no_subscription(self, db_session, workspace):
        assert provider_for_reconciliation(workspace.id, db_session) is None

    def test_reconciliation_provider_matches_stored_paddle_subscription(self, db_session, workspace):
        sub = NormalizedSubscription(workspace_id=workspace.id, provider="paddle", plan_id="team", status="active")
        db_session.add(sub)
        db_session.commit()
        assert provider_for_reconciliation(workspace.id, db_session) == BillingProvider.PADDLE


class TestManagementFallsBackToConfiguredWhenNoSubscription:
    def test_no_subscription_falls_back_to_configured_provider(self, db_session, workspace, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "paddle")
        assert provider_for_management(workspace.id, db_session) == BillingProvider.PADDLE
