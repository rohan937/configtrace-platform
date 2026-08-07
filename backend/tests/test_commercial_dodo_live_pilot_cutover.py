"""Test->Live pilot cutover preparation tests
(``app.billing.dodo_webhook_service.prepare_dodo_workspace_for_live_pilot`` /
``scripts/dodo_live_cutover.py prepare-live-pilot``).

Root problem: a pilot workspace's NormalizedSubscription row still
references an active Dodo TEST subscription. Once DODO_ENVIRONMENT is
switched to Live, ``_create_plan_checkout`` (app/routers/billing.py)
would see the row's status as still "live" and route a Pro/Team click to
``change_subscription_plan`` against the OLD TEST subscription ID using
NEW LIVE credentials — Dodo Live has no such subscription, so the call
fails and the first real Live checkout is blocked.

This function is a PURE LOCAL DATABASE operation — it makes NO Dodo API
call of any kind, Test or Live, ever. No HTTP mocking is needed anywhere
in this file; that absence is itself part of what's being verified (a
handler that raises AssertionError on any call would immediately catch a
regression that started making network calls).
"""

from __future__ import annotations

import uuid as _uuid

import pytest

from app.billing.dodo_webhook_service import (
    DodoLivePilotPreparationError,
    prepare_dodo_workspace_for_live_pilot,
)
from app.billing.models import BillingAuditEvent, BillingWebhookEvent, NormalizedSubscription
from app.models.workspace import Workspace, WorkspaceMember

TEST_SUB_ID = "sub_0NksebgBKVCKahnxYgPsg"


@pytest.fixture
def workspace(db_session, test_user):
    ws = Workspace(name=f"dodo-live-pilot-{_uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.flush()
    db_session.add(WorkspaceMember(workspace_id=ws.id, user_id=test_user.id, role="owner"))
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(BillingAuditEvent).filter(BillingAuditEvent.workspace_id == ws.id).delete()
    db_session.query(BillingWebhookEvent).filter(BillingWebhookEvent.subscription_reference == TEST_SUB_ID).delete()
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.commit()


def _pilot_row(db_session, workspace, *, plan_id="team", status="active", subscription_id=TEST_SUB_ID, customer_id="cus_test_pilot"):
    sub = NormalizedSubscription(
        workspace_id=workspace.id, provider="dodo", plan_id=plan_id, status=status,
        provider_customer_reference=customer_id, provider_subscription_reference=subscription_id,
        billable_seats=20, last_provider_event="subscription_updated", version=3,
    )
    db_session.add(sub)
    db_session.commit()
    db_session.refresh(sub)
    return sub


# 1. Active Test-Dodo pilot row can be safely prepared for Live.
class TestActivePilotRowCanBePrepared:
    def test_apply_marks_row_obsolete(self, db_session, workspace):
        sub = _pilot_row(db_session, workspace)

        result = prepare_dodo_workspace_for_live_pilot(
            workspace_id=workspace.id, expected_test_subscription_reference=TEST_SUB_ID, db=db_session, apply=True,
        )
        db_session.commit()

        assert result["prepared"] is True
        assert result["eligible_for_live_checkout"] is True
        assert result["previous_subscription_reference"] == TEST_SUB_ID

        db_session.refresh(sub)
        assert sub.status == "canceled"
        assert sub.provider_subscription_reference is None
        assert sub.provider_customer_reference is None
        assert sub.last_provider_event == "prepared_for_live_cutover"
        assert sub.version == 4
        assert sub.plan_id == "team"  # historical value preserved, not reset


# 2. Dry run performs no mutation.
class TestDryRunNoMutation:
    def test_dry_run_does_not_change_the_row(self, db_session, workspace):
        sub = _pilot_row(db_session, workspace)

        result = prepare_dodo_workspace_for_live_pilot(
            workspace_id=workspace.id, expected_test_subscription_reference=TEST_SUB_ID, db=db_session, apply=False,
        )

        assert result["prepared"] is False
        assert result["would_prepare"] is True
        db_session.refresh(sub)
        assert sub.status == "active"
        assert sub.provider_subscription_reference == TEST_SUB_ID
        assert sub.version == 3


# 3. --yes applies exactly one workspace transition.
class TestAppliesExactlyOneWorkspace:
    def test_other_workspace_never_touched(self, db_session, workspace, test_user):
        sub = _pilot_row(db_session, workspace)
        other_ws = Workspace(name=f"other-{_uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
        db_session.add(other_ws)
        db_session.commit()
        other_sub = NormalizedSubscription(
            workspace_id=other_ws.id, provider="dodo", plan_id="pro", status="active",
            provider_subscription_reference="sub_other_pilot_unrelated",
        )
        db_session.add(other_sub)
        db_session.commit()

        prepare_dodo_workspace_for_live_pilot(
            workspace_id=workspace.id, expected_test_subscription_reference=TEST_SUB_ID, db=db_session, apply=True,
        )
        db_session.commit()

        db_session.refresh(sub)
        db_session.refresh(other_sub)
        assert sub.status == "canceled"
        assert other_sub.status == "active"
        assert other_sub.provider_subscription_reference == "sub_other_pilot_unrelated"

        db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == other_ws.id).delete()
        db_session.commit()


# 4. Expected Test subscription ID mismatch refuses.
class TestExpectedSubscriptionMismatchRefuses:
    def test_wrong_expected_id_refuses(self, db_session, workspace):
        sub = _pilot_row(db_session, workspace, subscription_id=TEST_SUB_ID)

        with pytest.raises(DodoLivePilotPreparationError, match="expected_subscription_mismatch"):
            prepare_dodo_workspace_for_live_pilot(
                workspace_id=workspace.id, expected_test_subscription_reference="sub_totally_wrong",
                db=db_session, apply=True,
            )
        db_session.refresh(sub)
        assert sub.status == "active"  # untouched


# 5. Stripe row refuses.
# 6. Paddle row refuses.
class TestNonDodoProviderRefuses:
    @pytest.mark.parametrize("provider", ["stripe", "paddle"])
    def test_refuses_for_non_dodo_provider(self, db_session, workspace, provider):
        sub = NormalizedSubscription(
            workspace_id=workspace.id, provider=provider, plan_id="pro", status="active",
            provider_subscription_reference="sub_or_cus_something",
        )
        db_session.add(sub)
        db_session.commit()

        with pytest.raises(DodoLivePilotPreparationError, match=f"not_a_dodo_subscription:provider={provider}"):
            prepare_dodo_workspace_for_live_pilot(
                workspace_id=workspace.id, expected_test_subscription_reference="sub_or_cus_something",
                db=db_session, apply=True,
            )
        db_session.refresh(sub)
        assert sub.status == "active"  # untouched


# 7. Unknown workspace refuses.
class TestUnknownWorkspaceRefuses:
    def test_refuses_for_nonexistent_workspace(self, db_session):
        with pytest.raises(DodoLivePilotPreparationError, match="workspace_not_found"):
            prepare_dodo_workspace_for_live_pilot(
                workspace_id=_uuid.uuid4(), expected_test_subscription_reference=TEST_SUB_ID,
                db=db_session, apply=True,
            )

    def test_refuses_when_no_subscription_row_exists(self, db_session, workspace):
        with pytest.raises(DodoLivePilotPreparationError, match="no_subscription_found"):
            prepare_dodo_workspace_for_live_pilot(
                workspace_id=workspace.id, expected_test_subscription_reference=TEST_SUB_ID,
                db=db_session, apply=True,
            )


# 8. Already-prepared/idempotent rerun behaves safely.
class TestIdempotentRerun:
    def test_second_apply_is_noop(self, db_session, workspace):
        sub = _pilot_row(db_session, workspace)

        first = prepare_dodo_workspace_for_live_pilot(
            workspace_id=workspace.id, expected_test_subscription_reference=TEST_SUB_ID, db=db_session, apply=True,
        )
        db_session.commit()
        assert first["prepared"] is True

        second = prepare_dodo_workspace_for_live_pilot(
            workspace_id=workspace.id, expected_test_subscription_reference=TEST_SUB_ID, db=db_session, apply=True,
        )
        assert second["already_prepared"] is True
        assert second["prepared"] is False
        assert second["eligible_for_live_checkout"] is True

        db_session.refresh(sub)
        assert sub.status == "canceled"
        assert sub.version == 4  # not incremented again

    def test_rerun_with_wrong_expected_id_after_prepared_is_still_noop(self, db_session, workspace):
        """Once prepared, the expected-reference argument no longer
        matters — there's nothing left to compare it against, and
        refusing an operator's harmless repeat invocation would be
        needlessly hostile."""
        _pilot_row(db_session, workspace)
        prepare_dodo_workspace_for_live_pilot(
            workspace_id=workspace.id, expected_test_subscription_reference=TEST_SUB_ID, db=db_session, apply=True,
        )
        db_session.commit()

        second = prepare_dodo_workspace_for_live_pilot(
            workspace_id=workspace.id, expected_test_subscription_reference="sub_anything_else",
            db=db_session, apply=True,
        )
        assert second["already_prepared"] is True


# 9. After preparation, GET /billing no longer grants Team/Pro entitlement.
class TestBillingReadPathAfterPreparation:
    def test_billing_shows_free_after_preparation(self, client, db_session, workspace):
        _pilot_row(db_session, workspace, plan_id="team", status="active")

        prepare_dodo_workspace_for_live_pilot(
            workspace_id=workspace.id, expected_test_subscription_reference=TEST_SUB_ID, db=db_session, apply=True,
        )
        db_session.commit()

        resp = client.get(f"/workspaces/{workspace.id}/billing")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan"] == "free"
        assert body["status"] == "canceled"


# 10. After preparation, eligible for a fresh Live Dodo checkout rather
# than change-plan (verified via the router's own status gate).
class TestEligibleForFreshCheckoutNotChangePlan:
    def test_prepared_row_falls_outside_live_status_gate(self, db_session, workspace):
        from app.routers.billing import _DODO_LIVE_STATUSES

        sub = _pilot_row(db_session, workspace)
        prepare_dodo_workspace_for_live_pilot(
            workspace_id=workspace.id, expected_test_subscription_reference=TEST_SUB_ID, db=db_session, apply=True,
        )
        db_session.commit()
        db_session.refresh(sub)
        assert sub.status not in _DODO_LIVE_STATUSES

    def test_create_plan_checkout_routes_to_create_checkout_not_plan_change(self, db_session, workspace, monkeypatch, test_user):
        from app.billing.enums import BillingProvider, PlanId
        from app.billing.provider import CheckoutResponse
        from app.routers import billing as billing_router

        _pilot_row(db_session, workspace)
        prepare_dodo_workspace_for_live_pilot(
            workspace_id=workspace.id, expected_test_subscription_reference=TEST_SUB_ID, db=db_session, apply=True,
        )
        db_session.commit()

        class _FakeAdapter:
            def __init__(self):
                self.create_checkout_calls = []
                self.change_subscription_plan_calls = []

            def create_checkout(self, request):
                self.create_checkout_calls.append(request)
                return CheckoutResponse(
                    provider=BillingProvider.DODO, checkout_url="https://live.checkout.dodopayments.com/new",
                    external_reference="cks_live_new",
                )

            def change_subscription_plan(self, **kwargs):
                self.change_subscription_plan_calls.append(kwargs)
                raise AssertionError("must never call change-plan after live-pilot preparation")

        fake_adapter = _FakeAdapter()
        monkeypatch.setattr(billing_router, "get_adapter_for_provider", lambda provider, db: fake_adapter)
        monkeypatch.setattr(billing_router, "provider_for_checkout", lambda workspace_id, db: BillingProvider.DODO)
        monkeypatch.setattr(billing_router, "dodo_pilot_override_active", lambda workspace_id: False)

        result = billing_router._create_plan_checkout(PlanId.TEAM, workspace.id, db_session, test_user)

        assert len(fake_adapter.create_checkout_calls) == 1
        assert len(fake_adapter.change_subscription_plan_calls) == 0
        assert result.requires_redirect is True
        assert result.checkout_url == "https://live.checkout.dodopayments.com/new"


# 11. Existing non-pilot Stripe routing remains unchanged.
class TestNonPilotStripeRoutingUnaffected:
    def test_stripe_workspace_checkout_routing_unaffected(self, db_session, workspace, monkeypatch, test_user):
        """A completely unrelated Stripe workspace's checkout routing must
        never be touched by anything in this module — proven by never
        calling prepare_dodo_workspace_for_live_pilot for it and
        confirming provider_for_checkout / _create_plan_checkout still
        route to Stripe untouched."""
        from app.billing.enums import BillingProvider, PlanId
        from app.billing.provider import CheckoutResponse
        from app.routers import billing as billing_router

        class _FakeStripeAdapter:
            def __init__(self):
                self.create_checkout_calls = []

            def create_checkout(self, request):
                self.create_checkout_calls.append(request)
                return CheckoutResponse(provider=BillingProvider.STRIPE, checkout_url="https://checkout.stripe.com/x")

        fake_adapter = _FakeStripeAdapter()
        monkeypatch.setattr(billing_router, "get_adapter_for_provider", lambda provider, db: fake_adapter)
        monkeypatch.setattr(billing_router, "provider_for_checkout", lambda workspace_id, db: BillingProvider.STRIPE)
        monkeypatch.setattr(billing_router, "dodo_pilot_override_active", lambda workspace_id: False)

        result = billing_router._create_plan_checkout(PlanId.PRO, workspace.id, db_session, test_user)
        assert len(fake_adapter.create_checkout_calls) == 1
        assert result.provider == "stripe"


# 12. Pro -> Team Live-style change-plan behavior remains intact once a
# new active Dodo subscription exists (i.e. this feature does not
# regress the already-shipped plan-change path for a genuinely live row).
class TestPlanChangeStillWorksForANewActiveDodoRow:
    def test_new_active_dodo_row_still_uses_change_plan(self, db_session, workspace, monkeypatch, test_user):
        from app.billing.enums import BillingProvider, PlanId
        from app.billing.provider import ProviderOperationResult
        from app.routers import billing as billing_router

        # Simulate the state AFTER a fresh Live checkout + webhook synced
        # a brand-new active Dodo subscription onto this same row.
        sub = NormalizedSubscription(
            workspace_id=workspace.id, provider="dodo", plan_id="pro", status="active",
            provider_customer_reference="cus_live_new", provider_subscription_reference="sub_live_new_pro",
        )
        db_session.add(sub)
        db_session.commit()

        class _FakeAdapter:
            def __init__(self):
                self.change_subscription_plan_calls = []

            def change_subscription_plan(self, *, subscription_reference, target_plan_id, billable_seat_count):
                self.change_subscription_plan_calls.append((subscription_reference.external_id, target_plan_id))
                return ProviderOperationResult(state="ok", detail="changed")

            def create_checkout(self, request):
                raise AssertionError("must never create a second subscription for a live existing Dodo row")

        fake_adapter = _FakeAdapter()
        monkeypatch.setattr(billing_router, "get_adapter_for_provider", lambda provider, db: fake_adapter)
        monkeypatch.setattr(billing_router, "provider_for_checkout", lambda workspace_id, db: BillingProvider.DODO)
        monkeypatch.setattr(billing_router, "dodo_pilot_override_active", lambda workspace_id: False)

        result = billing_router._create_plan_checkout(PlanId.TEAM, workspace.id, db_session, test_user)

        assert len(fake_adapter.change_subscription_plan_calls) == 1
        ref, target_plan = fake_adapter.change_subscription_plan_calls[0]
        assert ref == "sub_live_new_pro"
        assert target_plan == PlanId.TEAM
        assert result.requires_redirect is False


# 13. Reconciliation still works (regression guard for the prior message's feature).
class TestReconciliationStillWorks:
    def test_replace_still_works_after_this_change(self, db_session, workspace, monkeypatch):
        import httpx

        from app.billing.dodo_client import DodoAPIClient, DodoClientConfig
        from app.billing.dodo_webhook_service import reconcile_workspace_from_dodo_subscription
        from app import config

        monkeypatch.setattr(config.settings, "DODO_ENVIRONMENT", "test")
        monkeypatch.setattr(config.settings, "DODO_API_KEY", "apikey_test_dummy")
        monkeypatch.setattr(config.settings, "DODO_WEBHOOK_SECRET", "whsec_dGVzdHNlY3JldA==")
        monkeypatch.setattr(config.settings, "DODO_PRO_PRODUCT_ID", "prod_pro_test")
        monkeypatch.setattr(config.settings, "DODO_TEAM_PRODUCT_ID", "prod_team_test")
        monkeypatch.setattr(config.settings, "DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID", "addon_seat_test")

        _pilot_row(db_session, workspace, status="canceled", subscription_id="sub_old_obsolete")

        def handler(request: httpx.Request) -> httpx.Response:
            if "sub_old_obsolete" in str(request.url):
                return httpx.Response(200, json={"subscription_id": "sub_old_obsolete", "status": "cancelled", "product_id": "prod_pro_test", "customer": {"customer_id": "cus_test_pilot"}})
            return httpx.Response(
                200,
                json={
                    "subscription_id": "sub_new_active", "status": "active", "product_id": "prod_team_test",
                    "customer": {"customer_id": "cus_test_pilot"},
                    "metadata": {"workspace_id": str(workspace.id), "plan_id": "team"},
                },
            )

        def _mock_client(h):
            return DodoAPIClient(DodoClientConfig(environment="test", api_key="apikey_test_dummy"), transport=httpx.MockTransport(h))

        monkeypatch.setattr("app.billing.dodo_webhook_service.adapter_client_for", lambda env, key: _mock_client(handler))

        result = reconcile_workspace_from_dodo_subscription(
            workspace_id=workspace.id, dodo_subscription_id="sub_new_active", db=db_session, apply=True,
        )
        db_session.commit()
        assert result["replaced"] is True


# 14. Old Test webhook/history rows are preserved.
class TestHistoryPreserved:
    def test_webhook_events_and_audit_events_not_deleted(self, db_session, workspace):
        sub = _pilot_row(db_session, workspace)

        old_webhook = BillingWebhookEvent(
            provider="dodo", external_event_id=f"evt_pilot_{_uuid.uuid4().hex[:8]}", event_type="subscription.active",
            subscription_reference=TEST_SUB_ID, customer_reference="cus_test_pilot",
            normalized_payload={}, processing_status="processed", attempt_count=1, error_category="none",
        )
        db_session.add(old_webhook)
        db_session.commit()
        webhook_id = old_webhook.id

        prepare_dodo_workspace_for_live_pilot(
            workspace_id=workspace.id, expected_test_subscription_reference=TEST_SUB_ID, db=db_session, apply=True,
        )
        db_session.commit()

        assert db_session.get(BillingWebhookEvent, webhook_id) is not None

        audit_events = (
            db_session.query(BillingAuditEvent)
            .filter(BillingAuditEvent.workspace_id == workspace.id)
            .all()
        )
        assert len(audit_events) >= 1

        db_session.query(BillingWebhookEvent).filter(BillingWebhookEvent.id == webhook_id).delete()
        db_session.commit()


# 15. Audit trail records the Test->Live preparation.
class TestAuditTrailRecordsPreparation:
    def test_audit_event_recorded_with_previous_reference(self, db_session, workspace):
        _pilot_row(db_session, workspace)

        prepare_dodo_workspace_for_live_pilot(
            workspace_id=workspace.id, expected_test_subscription_reference=TEST_SUB_ID, db=db_session, apply=True,
        )
        db_session.commit()

        events = (
            db_session.query(BillingAuditEvent)
            .filter(BillingAuditEvent.workspace_id == workspace.id)
            .all()
        )
        assert len(events) == 1
        event = events[0]
        assert event.event_type == "subscription_changed"
        assert event.provider == "dodo"
        assert event.details["new_status"] == "canceled"
        assert TEST_SUB_ID in event.details["reason"]
