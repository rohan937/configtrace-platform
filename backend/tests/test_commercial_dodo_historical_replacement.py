"""Historical-recovery reconciliation tests: replacing an OBSOLETE/CANCELED
Dodo NormalizedSubscription row with a VERIFIED ACTIVE Dodo subscription
for the SAME workspace (``reconcile_workspace_from_dodo_subscription``).

Root cause of the edge case this repairs: the double-billing bug fixed in
an earlier message (checkout creating a second, independent Dodo
subscription instead of changing the existing one in place) left stray
historical state behind — a workspace whose stored NormalizedSubscription
row still points at the OLD, now-canceled Dodo subscription, while the
real, currently-active subscription is a DIFFERENT Dodo subscription ID
that was never captured locally. ``reconcile-from-dodo`` previously
refused unconditionally whenever ANY row already existed
(``workspace_already_has_subscription:provider=dodo``), with no path to
repair this.

This file tests the extended reconciliation logic: it may now REPLACE an
existing row in place, but only when every safety condition holds —
existing row is Dodo and verified (via a fresh, live GET — never the
possibly-stale locally-stored status) to be non-live, target is a
verified active Dodo subscription for the same workspace/customer and a
known plan, and the target isn't already attached to a different
workspace.

No live Dodo API call is made anywhere in this file — all HTTP is mocked,
matching the existing test_commercial_dodo_reconciliation.py pattern.
"""

from __future__ import annotations

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


def _sub_body(
    *, subscription_id, customer_id="cus_shared_1", status="active",
    product_id="prod_team_test", workspace_id=None, plan_id="team",
) -> dict:
    body = {
        "subscription_id": subscription_id,
        "product_id": product_id,
        "status": status,
        "customer": {"customer_id": customer_id},
    }
    if workspace_id is not None:
        body["metadata"] = {"workspace_id": str(workspace_id), "plan_id": plan_id}
    return body


def _router_handler(responses: dict[str, dict]):
    """Routes a GET /subscriptions/{id} to a canned body keyed by
    subscription ID — needed here because a replace-in-place always
    issues TWO GET calls (existing, then target)."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = str(request.url.path)
        for sub_id, body in responses.items():
            if path.endswith(f"/subscriptions/{sub_id}"):
                return httpx.Response(200, json=body)
        return httpx.Response(200, json={})

    return handler


@pytest.fixture
def workspace(db_session, test_user):
    ws = Workspace(name=f"dodo-histrepl-{_uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.flush()
    db_session.add(WorkspaceMember(workspace_id=ws.id, user_id=test_user.id, role="owner"))
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(BillingAuditEvent).filter(BillingAuditEvent.workspace_id == ws.id).delete()
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.commit()


@pytest.fixture
def other_workspace(db_session, test_user):
    ws = Workspace(name=f"dodo-histrepl-other-{_uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.commit()


def _existing_row(db_session, workspace, *, status="canceled", subscription_id="sub_old_pro", customer_id="cus_shared_1", plan_id="pro"):
    sub = NormalizedSubscription(
        workspace_id=workspace.id, provider="dodo", plan_id=plan_id, status=status,
        provider_customer_reference=customer_id, provider_subscription_reference=subscription_id,
        last_provider_event="subscription_canceled", version=1,
    )
    db_session.add(sub)
    db_session.commit()
    db_session.refresh(sub)
    return sub


# 1. canceled Dodo Pro -> active Dodo Team reconciliation succeeds
class TestCanceledProToActiveTeamSucceeds:
    def test_replace_succeeds_and_updates_row_in_place(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)
        existing = _existing_row(db_session, workspace, status="canceled", subscription_id="sub_old_pro")

        handler = _router_handler({
            "sub_old_pro": _sub_body(subscription_id="sub_old_pro", status="cancelled", product_id="prod_pro_test"),
            "sub_new_team": _sub_body(
                subscription_id="sub_new_team", status="active", product_id="prod_team_test",
                workspace_id=workspace.id, plan_id="team",
            ),
        })
        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        result = reconcile_workspace_from_dodo_subscription(
            workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
        )
        db_session.commit()

        assert result["created"] is False
        assert result["replaced"] is True
        assert result["previous_subscription_reference"] == "sub_old_pro"

        rows = db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == workspace.id).all()
        assert len(rows) == 1  # never a second row
        db_session.refresh(existing)
        assert existing.plan_id == "team"
        assert existing.status == "active"
        assert existing.provider_subscription_reference == "sub_new_team"
        assert existing.last_provider_event == "reconciled_from_dodo"
        assert existing.version == 2

    def test_dry_run_does_not_mutate(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)
        existing = _existing_row(db_session, workspace, status="canceled", subscription_id="sub_old_pro")

        handler = _router_handler({
            "sub_old_pro": _sub_body(subscription_id="sub_old_pro", status="cancelled", product_id="prod_pro_test"),
            "sub_new_team": _sub_body(
                subscription_id="sub_new_team", status="active", product_id="prod_team_test",
                workspace_id=workspace.id, plan_id="team",
            ),
        })
        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        result = reconcile_workspace_from_dodo_subscription(
            workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=False,
        )
        assert result["would_replace"] is True
        assert result["replaced"] is False
        db_session.refresh(existing)
        assert existing.plan_id == "pro"  # unchanged
        assert existing.provider_subscription_reference == "sub_old_pro"


# 2. expired/failed Dodo -> active replacement succeeds
class TestExpiredOrFailedExistingRowSucceeds:
    @pytest.mark.parametrize("existing_raw_status,existing_stored_status", [("expired", "expired"), ("failed", "incomplete")])
    def test_replace_succeeds(self, db_session, workspace, monkeypatch, existing_raw_status, existing_stored_status):
        _configure_dodo(monkeypatch)
        _existing_row(db_session, workspace, status=existing_stored_status, subscription_id="sub_old")

        handler = _router_handler({
            "sub_old": _sub_body(subscription_id="sub_old", status=existing_raw_status, product_id="prod_pro_test"),
            "sub_new_team": _sub_body(
                subscription_id="sub_new_team", status="active", product_id="prod_team_test",
                workspace_id=workspace.id, plan_id="team",
            ),
        })
        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        result = reconcile_workspace_from_dodo_subscription(
            workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
        )
        db_session.commit()
        assert result["replaced"] is True


# 3. active Dodo -> another active Dodo replacement refuses
class TestActiveExistingRowRefusesReplacement:
    @pytest.mark.parametrize("live_status", ["active", "on_hold", "pending"])
    def test_refuses_when_existing_still_live(self, db_session, workspace, monkeypatch, live_status):
        _configure_dodo(monkeypatch)
        _existing_row(db_session, workspace, status="active", subscription_id="sub_old")

        def handler(request: httpx.Request) -> httpx.Response:
            assert "sub_old" in str(request.url)  # must never fetch the target once existing is found live
            return httpx.Response(200, json=_sub_body(subscription_id="sub_old", status=live_status))

        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        with pytest.raises(DodoReconciliationError, match="existing_dodo_subscription_still_live"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
            )

        rows = db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == workspace.id).all()
        assert len(rows) == 1
        assert rows[0].provider_subscription_reference == "sub_old"


# 4. Stripe/Paddle existing row refuses
class TestStripeAndPaddleNeverReplaced:
    @pytest.mark.parametrize("provider", ["stripe", "paddle"])
    def test_refuses_without_any_dodo_call(self, db_session, workspace, monkeypatch, provider):
        _configure_dodo(monkeypatch)
        sub = NormalizedSubscription(workspace_id=workspace.id, provider=provider, plan_id="pro", status="active")
        db_session.add(sub)
        db_session.commit()

        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError(f"must never call Dodo when the existing row is {provider}")

        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        with pytest.raises(DodoReconciliationError, match=f"workspace_already_has_subscription:provider={provider}"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
            )


# 5. wrong workspace refuses
class TestWrongWorkspaceMetadataRefuses:
    def test_target_metadata_workspace_mismatch_refuses(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)
        _existing_row(db_session, workspace, status="canceled", subscription_id="sub_old")
        other_ws_id = _uuid.uuid4()

        handler = _router_handler({
            "sub_old": _sub_body(subscription_id="sub_old", status="cancelled", product_id="prod_pro_test"),
            "sub_new_team": _sub_body(
                subscription_id="sub_new_team", status="active", product_id="prod_team_test",
                workspace_id=other_ws_id, plan_id="team",
            ),
        })
        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        with pytest.raises(DodoReconciliationError, match="workspace_mismatch_with_dodo_metadata"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
            )


# 6. target inactive subscription refuses
class TestTargetNotActiveRefuses:
    @pytest.mark.parametrize("target_status", ["cancelled", "expired", "failed", "pending", "on_hold"])
    def test_refuses_when_target_not_active(self, db_session, workspace, monkeypatch, target_status):
        _configure_dodo(monkeypatch)
        _existing_row(db_session, workspace, status="canceled", subscription_id="sub_old")

        handler = _router_handler({
            "sub_old": _sub_body(subscription_id="sub_old", status="cancelled", product_id="prod_pro_test"),
            "sub_new_team": _sub_body(
                subscription_id="sub_new_team", status=target_status, product_id="prod_team_test",
                workspace_id=workspace.id, plan_id="team",
            ),
        })
        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        with pytest.raises(DodoReconciliationError, match="target_subscription_not_active"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
            )


# 7. unknown product refuses
class TestUnknownTargetProductRefuses:
    def test_refuses_for_unrecognized_product(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)
        _existing_row(db_session, workspace, status="canceled", subscription_id="sub_old")

        handler = _router_handler({
            "sub_old": _sub_body(subscription_id="sub_old", status="cancelled", product_id="prod_pro_test"),
            "sub_new_team": _sub_body(
                subscription_id="sub_new_team", status="active", product_id="prod_totally_unrecognized",
                workspace_id=workspace.id, plan_id="team",
            ),
        })
        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        with pytest.raises(DodoReconciliationError, match="unknown_product_id"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
            )


# 8. same customer validation
class TestCustomerOwnershipValidation:
    def test_refuses_when_target_belongs_to_different_customer(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)
        _existing_row(db_session, workspace, status="canceled", subscription_id="sub_old", customer_id="cus_original")

        handler = _router_handler({
            "sub_old": _sub_body(subscription_id="sub_old", status="cancelled", product_id="prod_pro_test", customer_id="cus_original"),
            "sub_new_team": _sub_body(
                subscription_id="sub_new_team", status="active", product_id="prod_team_test",
                workspace_id=workspace.id, plan_id="team", customer_id="cus_totally_different",
            ),
        })
        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        with pytest.raises(DodoReconciliationError, match="customer_mismatch_with_existing_subscription"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
            )

    def test_succeeds_when_same_customer(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)
        _existing_row(db_session, workspace, status="canceled", subscription_id="sub_old", customer_id="cus_shared_1")

        handler = _router_handler({
            "sub_old": _sub_body(subscription_id="sub_old", status="cancelled", product_id="prod_pro_test", customer_id="cus_shared_1"),
            "sub_new_team": _sub_body(
                subscription_id="sub_new_team", status="active", product_id="prod_team_test",
                workspace_id=workspace.id, plan_id="team", customer_id="cus_shared_1",
            ),
        })
        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        result = reconcile_workspace_from_dodo_subscription(
            workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
        )
        db_session.commit()
        assert result["replaced"] is True


# 9. idempotent rerun
class TestIdempotentRerun:
    def test_rerunning_with_same_target_after_replace_is_noop(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)
        _existing_row(db_session, workspace, status="canceled", subscription_id="sub_old")

        handler = _router_handler({
            "sub_old": _sub_body(subscription_id="sub_old", status="cancelled", product_id="prod_pro_test"),
            "sub_new_team": _sub_body(
                subscription_id="sub_new_team", status="active", product_id="prod_team_test",
                workspace_id=workspace.id, plan_id="team",
            ),
        })
        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        first = reconcile_workspace_from_dodo_subscription(
            workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
        )
        db_session.commit()
        assert first["replaced"] is True

        second = reconcile_workspace_from_dodo_subscription(
            workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
        )
        assert second["already_reconciled"] is True
        assert second["replaced"] is False

        rows = db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == workspace.id).all()
        assert len(rows) == 1


# 10. resulting GET /billing returns Team
class TestBillingEndpointReflectsReplacement:
    def test_get_billing_returns_team_after_replacement(self, client, db_session, workspace, monkeypatch, test_user):
        _configure_dodo(monkeypatch)
        _existing_row(db_session, workspace, status="canceled", subscription_id="sub_old")

        handler = _router_handler({
            "sub_old": _sub_body(subscription_id="sub_old", status="cancelled", product_id="prod_pro_test"),
            "sub_new_team": _sub_body(
                subscription_id="sub_new_team", status="active", product_id="prod_team_test",
                workspace_id=workspace.id, plan_id="team",
            ),
        })
        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        result = reconcile_workspace_from_dodo_subscription(
            workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
        )
        db_session.commit()
        assert result["replaced"] is True

        resp = client.get(f"/workspaces/{workspace.id}/billing")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan"] == "team"
        assert body["status"] == "active"


# Target already attached to a different workspace
class TestTargetAlreadyAttachedToAnotherWorkspaceRefuses:
    def test_refuses_when_target_reference_belongs_to_other_workspace(
        self, db_session, workspace, other_workspace, monkeypatch
    ):
        _configure_dodo(monkeypatch)
        _existing_row(db_session, workspace, status="canceled", subscription_id="sub_old")
        conflicting = NormalizedSubscription(
            workspace_id=other_workspace.id, provider="dodo", plan_id="team", status="active",
            provider_subscription_reference="sub_new_team",
        )
        db_session.add(conflicting)
        db_session.commit()

        handler = _router_handler({
            "sub_old": _sub_body(subscription_id="sub_old", status="cancelled", product_id="prod_pro_test"),
            "sub_new_team": _sub_body(
                subscription_id="sub_new_team", status="active", product_id="prod_team_test",
                workspace_id=workspace.id, plan_id="team",
            ),
        })
        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        with pytest.raises(DodoReconciliationError, match="target_subscription_already_attached_to_another_workspace"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
            )


# Existing row with no stored reference at all cannot be safety-verified
class TestExistingRowWithoutReferenceRefuses:
    def test_refuses_when_existing_row_has_no_subscription_reference(self, db_session, workspace, monkeypatch):
        _configure_dodo(monkeypatch)
        sub = NormalizedSubscription(
            workspace_id=workspace.id, provider="dodo", plan_id="pro", status="canceled",
            provider_subscription_reference=None,
        )
        db_session.add(sub)
        db_session.commit()

        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("must never call Dodo without an existing reference to verify")

        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        with pytest.raises(DodoReconciliationError, match="existing_subscription_has_no_reference_to_verify"):
            reconcile_workspace_from_dodo_subscription(
                workspace_id=workspace.id, dodo_subscription_id="sub_new_team", db=db_session, apply=True,
            )
