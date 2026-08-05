"""One-workspace Dodo pilot override tests (Dodo Payments — live cutover
preparation).

Proves: admin-controlled (env-var only, no code deploy to flip), fails
closed when Dodo isn't configured, never touches BILLING_PROVIDER, never
affects any workspace other than the designated one, and the existing
stored-provider-wins invariant remains completely untouched.
"""

from __future__ import annotations

import uuid

import pytest

from app.billing.enums import BillingAuditEventType, BillingProvider
from app.billing.models import BillingAuditEvent, NormalizedSubscription
from app.billing.provider_routing import (
    configured_checkout_provider,
    dodo_pilot_override_active,
    is_dodo_pilot_workspace,
    provider_for_checkout,
    provider_for_management,
)
from app.models.workspace import Workspace


@pytest.fixture
def workspace(db_session, test_user):
    ws = Workspace(name=f"pilot-{uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(BillingAuditEvent).filter(BillingAuditEvent.workspace_id == ws.id).delete()
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.delete(ws)
    db_session.commit()


def _configure_dodo(monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "DODO_ENVIRONMENT", "test")
    monkeypatch.setattr(config.settings, "DODO_API_KEY", "apikey_test_dummy")
    monkeypatch.setattr(config.settings, "DODO_WEBHOOK_SECRET", "whsec_dGVzdHNlY3JldA==")
    monkeypatch.setattr(config.settings, "DODO_PRO_PRODUCT_ID", "prod_pro_test")
    monkeypatch.setattr(config.settings, "DODO_TEAM_PRODUCT_ID", "prod_team_test")
    monkeypatch.setattr(config.settings, "DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID", "addon_seat_test")


class TestIsDodoPilotWorkspace:
    def test_unset_env_var_matches_nothing(self, monkeypatch, workspace):
        from app import config

        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", None)
        assert is_dodo_pilot_workspace(workspace.id) is False

    def test_matching_workspace_id_returns_true(self, monkeypatch, workspace):
        from app import config

        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(workspace.id))
        assert is_dodo_pilot_workspace(workspace.id) is True

    def test_different_workspace_id_returns_false(self, monkeypatch, workspace):
        from app import config

        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(uuid.uuid4()))
        assert is_dodo_pilot_workspace(workspace.id) is False

    def test_malformed_uuid_fails_closed_never_raises(self, monkeypatch, workspace):
        from app import config

        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", "not-a-uuid")
        assert is_dodo_pilot_workspace(workspace.id) is False

    def test_empty_string_fails_closed(self, monkeypatch, workspace):
        from app import config

        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", "")
        assert is_dodo_pilot_workspace(workspace.id) is False


class TestProviderForCheckoutWithPilotOverride:
    def test_pilot_workspace_routes_to_dodo_when_dodo_configured(self, monkeypatch, workspace, db_session):
        from app import config

        _configure_dodo(monkeypatch)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(workspace.id))
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")

        assert provider_for_checkout(workspace.id, db_session) == BillingProvider.DODO

    def test_pilot_workspace_falls_back_to_configured_provider_when_dodo_not_configured(
        self, monkeypatch, workspace, db_session
    ):
        """Fail-closed: an operator who sets DODO_PILOT_WORKSPACE_ID before
        Dodo is fully configured must never break checkout for that
        workspace — it silently behaves like every other workspace."""
        from app import config

        monkeypatch.setattr(config.settings, "DODO_API_KEY", None)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(workspace.id))
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")

        assert provider_for_checkout(workspace.id, db_session) == BillingProvider.STRIPE

    def test_non_pilot_workspace_completely_unaffected(self, monkeypatch, workspace, db_session):
        """The core isolation guarantee: setting the pilot override for
        SOME OTHER workspace must not change this workspace's routing at
        all."""
        from app import config

        _configure_dodo(monkeypatch)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(uuid.uuid4()))
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")

        assert provider_for_checkout(workspace.id, db_session) == BillingProvider.STRIPE

    def test_no_pilot_configured_behaves_exactly_as_before(self, monkeypatch, workspace, db_session):
        from app import config

        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", None)
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "paddle")

        assert provider_for_checkout(workspace.id, db_session) == BillingProvider.PADDLE


class TestBillingProviderNeverChangedByPilot:
    def test_configured_checkout_provider_ignores_pilot_setting(self, monkeypatch, workspace):
        """The pilot override must never leak into the GLOBAL default —
        configured_checkout_provider() reads ONLY BILLING_PROVIDER."""
        from app import config

        _configure_dodo(monkeypatch)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(workspace.id))
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")

        assert configured_checkout_provider() == BillingProvider.STRIPE


class TestExistingStoredProviderRoutingUntouched:
    def test_existing_stripe_subscription_in_pilot_workspace_still_routes_to_stripe(
        self, monkeypatch, workspace, db_session
    ):
        """The stored-provider-wins invariant is authoritative for
        MANAGEMENT of an existing subscription — even in the designated
        pilot workspace, an already-Stripe subscription is never
        reinterpreted as Dodo."""
        from app import config

        sub = NormalizedSubscription(workspace_id=workspace.id, provider="stripe", plan_id="team", status="active")
        db_session.add(sub)
        db_session.commit()

        _configure_dodo(monkeypatch)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(workspace.id))
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")

        assert provider_for_management(workspace.id, db_session) == BillingProvider.STRIPE

    def test_provider_for_management_has_no_pilot_logic_at_all(self, monkeypatch, workspace, db_session):
        """provider_for_management must behave identically whether or not
        this workspace is the pilot — pilot logic only exists in
        provider_for_checkout (new checkouts)."""
        from app import config

        _configure_dodo(monkeypatch)
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")

        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(workspace.id))
        with_pilot = provider_for_management(workspace.id, db_session)

        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", None)
        without_pilot = provider_for_management(workspace.id, db_session)

        assert with_pilot == without_pilot == BillingProvider.STRIPE


class TestDodoPilotOverrideActive:
    def test_active_when_pilot_and_configured_and_global_default_differs(self, monkeypatch, workspace):
        from app import config

        _configure_dodo(monkeypatch)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(workspace.id))
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")
        assert dodo_pilot_override_active(workspace.id) is True

    def test_inactive_when_global_default_already_dodo(self, monkeypatch, workspace):
        """No override is "applied" if every workspace already uses Dodo
        — nothing is being overridden."""
        from app import config

        _configure_dodo(monkeypatch)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(workspace.id))
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "dodo")
        assert dodo_pilot_override_active(workspace.id) is False

    def test_inactive_when_not_the_pilot_workspace(self, monkeypatch, workspace):
        from app import config

        _configure_dodo(monkeypatch)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(uuid.uuid4()))
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")
        assert dodo_pilot_override_active(workspace.id) is False

    def test_inactive_when_dodo_not_configured(self, monkeypatch, workspace):
        from app import config

        monkeypatch.setattr(config.settings, "DODO_API_KEY", None)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(workspace.id))
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")
        assert dodo_pilot_override_active(workspace.id) is False


class TestPilotOverrideIsAuditable:
    def test_checkout_router_records_audit_event_for_pilot_workspace(
        self, monkeypatch, workspace, db_session, client, test_user
    ):
        """End-to-end: hitting the real checkout/pro route for the pilot
        workspace must leave an auditable trail. Uses a monkeypatched
        adapter so no real Dodo call is made."""
        from app import config
        from app.models.workspace import WorkspaceMember

        db_session.add(WorkspaceMember(workspace_id=workspace.id, user_id=test_user.id, role="owner"))
        db_session.commit()

        _configure_dodo(monkeypatch)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(workspace.id))
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")

        from app.billing.provider import CheckoutResponse

        def _fake_create_checkout(self, request):
            return CheckoutResponse(provider=BillingProvider.DODO, checkout_url="https://test.checkout.dodopayments.com/x", external_reference="cks_test")

        import app.billing.adapters.dodo as dodo_adapter_module

        monkeypatch.setattr(dodo_adapter_module.DodoBillingAdapter, "create_checkout", _fake_create_checkout)

        resp = client.post(f"/workspaces/{workspace.id}/billing/checkout/pro")
        assert resp.status_code == 200
        assert resp.json()["provider"] == "dodo"

        events = (
            db_session.query(BillingAuditEvent)
            .filter(
                BillingAuditEvent.workspace_id == workspace.id,
                BillingAuditEvent.event_type == BillingAuditEventType.PILOT_OVERRIDE_APPLIED.value,
            )
            .all()
        )
        assert len(events) == 1
        assert events[0].details["reason"] == "dodo_pilot_workspace_override"
        assert events[0].details["plan_id"] == "pro"

    def test_non_pilot_workspace_checkout_never_records_pilot_audit_event(
        self, monkeypatch, workspace, db_session, client, test_user
    ):
        from app import config
        from app.models.workspace import WorkspaceMember

        db_session.add(WorkspaceMember(workspace_id=workspace.id, user_id=test_user.id, role="owner"))
        db_session.commit()

        _configure_dodo(monkeypatch)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(uuid.uuid4()))
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")

        # Stripe checkout will fail without real Stripe config — that's
        # fine, we only care that no pilot-override audit event exists.
        try:
            client.post(f"/workspaces/{workspace.id}/billing/checkout/pro")
        except Exception:
            pass

        events = (
            db_session.query(BillingAuditEvent)
            .filter(
                BillingAuditEvent.workspace_id == workspace.id,
                BillingAuditEvent.event_type == BillingAuditEventType.PILOT_OVERRIDE_APPLIED.value,
            )
            .all()
        )
        assert events == []
