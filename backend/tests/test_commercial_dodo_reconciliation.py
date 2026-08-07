"""Dodo read-only reconciliation fallback tests
(``scripts/dodo_live_cutover.py reconcile-from-dodo`` /
``app.billing.dodo_webhook_service.reconcile_workspace_from_dodo_subscription``).

Added while investigating why real Aug 7 Dodo Test Mode subscription
payments never resulted in ConfigTrace subscription activation. Code
audit confirmed the webhook normalizer and first-row creation logic are
already correct against Dodo's official ``subscription.active`` payload
contract (payload["type"], payload["data"]["subscription_id"],
payload["data"]["product_id"], payload["data"]["status"],
payload["data"]["metadata"] — exactly what this module's fixtures already
use). The evidence instead points to Dodo never attempting delivery of
the real events at all (confirmed via the operator's own inspection of
Dodo's webhook Activity log). This reconciliation fallback exists so a
genuinely paid Dodo subscription can be safely recovered without
hand-editing the database whenever a webhook is missed or delayed —
webhook processing remains the sole AUTOMATIC source of truth; this path
is only ever invoked by an explicit operator command.

No live Dodo API call is made anywhere in this file — all HTTP is mocked,
matching the existing test_commercial_dodo_checkout.py pattern.
"""

from __future__ import annotations

import json
import uuid as _uuid

import httpx
import pytest

from app.billing.dodo_client import DodoAPIClient, DodoClientConfig
from app.billing.dodo_webhook_service import (
    DodoReconciliationError,
    reconcile_workspace_from_dodo_subscription,
)
from app.billing.models import BillingAuditEvent, NormalizedSubscription
from app.models.workspace import Workspace, WorkspaceMember


def _configure_dodo(monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "DODO_ENVIRONMENT", "test")
    monkeypatch.setattr(config.settings, "DODO_API_KEY", "apikey_test_dummy")
    monkeypatch.setattr(config.settings, "DODO_WEBHOOK_SECRET", "whsec_dGVzdHNlY3JldA==")
    monkeypatch.setattr(config.settings, "DODO_PRO_PRODUCT_ID", "prod_pro_test")
    monkeypatch.setattr(config.settings, "DODO_TEAM_PRODUCT_ID", "prod_team_test")
    monkeypatch.setattr(config.settings, "DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID", "addon_seat_test")


def _mock_client(handler) -> DodoAPIClient:
    return DodoAPIClient(
        DodoClientConfig(environment="test", api_key="apikey_test_dummy"),
        transport=httpx.MockTransport(handler),
    )


def _subscription_response(
    *, subscription_id="sub_recon_1", customer_id="cus_recon_1", status="active",
    product_id="prod_pro_test", workspace_id=None, plan_id="pro",
) -> dict:
    """Shape mirrors the official Dodo subscription.active `data` object
    (payload["data"]) — same fields a GET /subscriptions/{id} response
    documents: subscription_id, product_id, status, metadata, customer."""
    body = {
        "subscription_id": subscription_id,
        "product_id": product_id,
        "status": status,
        "customer": {"customer_id": customer_id},
    }
    if workspace_id is not None:
        body["metadata"] = {"workspace_id": str(workspace_id), "plan_id": plan_id}
    return body


@pytest.fixture
def workspace(db_session, test_user):
    ws = Workspace(name=f"dodo-recon-{_uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.flush()
    db_session.add(WorkspaceMember(workspace_id=ws.id, user_id=test_user.id, role="owner"))
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(BillingAuditEvent).filter(BillingAuditEvent.workspace_id == ws.id).delete()
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.commit()


class TestSuccessfulReconciliationCreatesTheRow:
    def test_dry_run_does_not_create_a_row(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_subscription_response(workspace_id=workspace.id, plan_id="pro"))

        monkeypatch.setattr(
            "app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler)
        )

        result = reconcile_workspace_from_dodo_subscription(
            workspace_id=workspace.id, dodo_subscription_id="sub_recon_1", db=db_session, apply=False,
        )
        assert result["created"] is False
        assert result["plan_id"] == "pro"
        assert result["status"] == "active"
        assert (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == workspace.id)
            .first()
            is None
        )

    def test_apply_creates_correct_row(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_subscription_response(workspace_id=workspace.id, plan_id="pro"))

        monkeypatch.setattr(
            "app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler)
        )

        result = reconcile_workspace_from_dodo_subscription(
            workspace_id=workspace.id, dodo_subscription_id="sub_recon_1", db=db_session, apply=True,
        )
        db_session.commit()
        assert result["created"] is True

        sub = (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == workspace.id)
            .first()
        )
        assert sub is not None
        assert sub.provider == "dodo"
        assert sub.plan_id == "pro"
        assert sub.status == "active"
        assert sub.provider_subscription_reference == "sub_recon_1"
        assert sub.provider_customer_reference == "cus_recon_1"


class TestWorkspaceOwnershipValidation:
    def test_missing_workspace_fails_closed(self, db_session, monkeypatch):
        _configure_dodo(monkeypatch)
        fake_ws_id = _uuid.uuid4()

        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("must never call Dodo before validating the workspace exists")

        monkeypatch.setattr(
            "app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler)
        )

        with pytest.raises(DodoReconciliationError, match="workspace_not_found"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=fake_ws_id, dodo_subscription_id="sub_x", db=db_session, apply=True,
            )

    def test_dodo_metadata_workspace_mismatch_fails_closed(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)
        other_workspace_id = _uuid.uuid4()

        def handler(request: httpx.Request) -> httpx.Response:
            # Dodo's own record says this subscription belongs to a
            # DIFFERENT workspace than the one the operator supplied.
            return httpx.Response(200, json=_subscription_response(workspace_id=other_workspace_id, plan_id="pro"))

        monkeypatch.setattr(
            "app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler)
        )

        with pytest.raises(DodoReconciliationError, match="workspace_mismatch_with_dodo_metadata"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_recon_1", db=db_session, apply=True,
            )
        assert (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == workspace.id)
            .first()
            is None
        )


class TestExistingSubscriptionNeverOverwritten:
    def test_workspace_with_existing_stripe_subscription_is_refused(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)
        existing = NormalizedSubscription(
            workspace_id=workspace.id, provider="stripe", plan_id="pro", status="active",
        )
        db_session.add(existing)
        db_session.commit()

        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("must never call Dodo when a subscription row already exists")

        monkeypatch.setattr(
            "app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler)
        )

        with pytest.raises(DodoReconciliationError, match="workspace_already_has_subscription"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_recon_1", db=db_session, apply=True,
            )

    def test_workspace_with_existing_dodo_subscription_is_refused(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)
        existing = NormalizedSubscription(
            workspace_id=workspace.id, provider="dodo", plan_id="pro", status="active",
            provider_subscription_reference="sub_already_on_file",
        )
        db_session.add(existing)
        db_session.commit()

        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("must never call Dodo when a subscription row already exists")

        monkeypatch.setattr(
            "app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler)
        )

        with pytest.raises(DodoReconciliationError, match="workspace_already_has_subscription"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_recon_1", db=db_session, apply=True,
            )


class TestUnresolvableDodoSubscriptionFailsClosed:
    def test_not_found_response_fails_closed(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={})

        monkeypatch.setattr(
            "app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler)
        )

        with pytest.raises(DodoReconciliationError, match="dodo_subscription_not_found"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_missing", db=db_session, apply=True,
            )

    def test_unknown_product_id_fails_closed(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_subscription_response(
                    workspace_id=workspace.id, plan_id="pro", product_id="prod_totally_unrecognized"
                ),
            )

        monkeypatch.setattr(
            "app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler)
        )

        with pytest.raises(DodoReconciliationError, match="unknown_product_id"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_recon_1", db=db_session, apply=True,
            )


class TestDodoNotConfiguredFailsClosed:
    def test_refuses_when_dodo_not_configured(self, db_session, workspace, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "DODO_API_KEY", None)

        with pytest.raises(DodoReconciliationError, match="dodo_not_configured"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_x", db=db_session, apply=True,
            )


class TestLiveModeGuard:
    def test_refuses_live_without_explicit_flag(self, db_session, workspace, monkeypatch):
        from app import config

        _configure_dodo(monkeypatch)
        monkeypatch.setattr(config.settings, "DODO_ENVIRONMENT", "live")

        with pytest.raises(DodoReconciliationError, match="refused_live_without_explicit_flag"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_x", db=db_session, apply=True, live=False,
            )

    def test_refuses_live_flag_when_configured_test(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)

        with pytest.raises(DodoReconciliationError, match="refused_live_flag_but_configured_environment_is_test"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_x", db=db_session, apply=True, live=True,
            )


class TestReconciliationIsIdempotent:
    def test_second_reconciliation_attempt_is_refused_not_duplicated(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_subscription_response(workspace_id=workspace.id, plan_id="pro"))

        monkeypatch.setattr(
            "app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler)
        )

        first = reconcile_workspace_from_dodo_subscription(
            workspace_id=workspace.id, dodo_subscription_id="sub_recon_1", db=db_session, apply=True,
        )
        db_session.commit()
        assert first["created"] is True

        with pytest.raises(DodoReconciliationError, match="workspace_already_has_subscription"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_recon_1", db=db_session, apply=True,
            )

        rows = (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == workspace.id)
            .all()
        )
        assert len(rows) == 1


class TestNoAccessFromPaymentAloneByConstruction:
    def test_reconciliation_only_ever_reads_a_subscription_object_never_a_payment(self, db_session, workspace):
        """This function takes a subscription ID, not a payment/transaction
        ID — there is no code path here that could grant access from a
        bare payment.succeeded state. Documented via the function's own
        signature/docstring; this test pins that the only external ID
        parameter is named and used as a subscription reference."""
        import inspect

        sig = inspect.signature(reconcile_workspace_from_dodo_subscription)
        assert "dodo_subscription_id" in sig.parameters
        assert "dodo_payment_id" not in sig.parameters
        assert "payment_id" not in sig.parameters
