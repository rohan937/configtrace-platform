"""Customer-facing Dodo subscription cancellation tests
(``POST /workspaces/{id}/billing/cancel`` — provider-neutral endpoint,
already implemented; this message hardens it with idempotency + a
fail-closed live-status gate and adds the missing router-level test
coverage).

Audit finding (see final report): a complete backend cancellation flow
already existed — ``cancel_current_subscription`` router endpoint,
``DodoBillingAdapter.cancel_subscription`` (verified
``cancel_at_next_billing_date: true`` semantics), and webhook handling
for the real ``subscription.cancelled``/``subscription.expired``
lifecycle events. What was MISSING was: (1) idempotency — a repeated
click issued a second destructive PATCH to Dodo; (2) a fail-closed gate
for an already-canceled/expired local row; (3) any frontend UI at all
(no button, no confirmation modal, and ``BillingResponse`` didn't expose
which provider the EXISTING subscription actually belongs to, so the
frontend had no way to conditionally show a Dodo cancel affordance).
This file covers the two backend hardening changes; the frontend is
covered by TypeScript compilation (``npx tsc --noEmit``) since there is
no frontend test runner in this repo.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from app.billing.enums import BillingProvider
from app.billing.models import NormalizedSubscription
from app.billing.provider import ProviderOperationResult
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMember


class _FakeAdapter:
    def __init__(self):
        self.cancel_calls = []

    def cancel_subscription(self, request):
        self.cancel_calls.append(request)
        return ProviderOperationResult(state="ok", detail="canceled effective_from=next_billing_date")


@pytest.fixture
def workspace(db_session, test_user):
    ws = Workspace(name=f"dodo-cancel-{uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.flush()
    db_session.add(WorkspaceMember(workspace_id=ws.id, user_id=test_user.id, role="owner"))
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.commit()


def _dodo_row(db_session, workspace, *, plan_id="pro", status="active", cancel_at_period_end=False, subscription_id="sub_pro_1"):
    sub = NormalizedSubscription(
        workspace_id=workspace.id, provider="dodo", plan_id=plan_id, status=status,
        provider_customer_reference="cus_1", provider_subscription_reference=subscription_id,
        cancel_at_period_end=cancel_at_period_end, billable_seats=0,
    )
    db_session.add(sub)
    db_session.commit()
    db_session.refresh(sub)
    return sub


def _call_cancel(monkeypatch, workspace, db_session, test_user, provider=BillingProvider.DODO, fake_adapter=None):
    from app.routers import billing as billing_router

    adapter = fake_adapter if fake_adapter is not None else _FakeAdapter()
    monkeypatch.setattr(billing_router, "get_adapter_for_provider", lambda p, db: adapter)
    monkeypatch.setattr(billing_router, "provider_for_management", lambda workspace_id, db: provider)
    result = billing_router.cancel_current_subscription(workspace.id, db_session, test_user)
    return result, adapter


# 1 & 2. Active Dodo Pro/Team -> schedule end-of-period cancellation.
class TestScheduleCancellationForActiveDodoSubscription:
    @pytest.mark.parametrize("plan_id", ["pro", "team"])
    def test_schedules_cancel_at_period_end(self, monkeypatch, workspace, db_session, test_user, plan_id):
        sub = _dodo_row(db_session, workspace, plan_id=plan_id, status="active")
        result, adapter = _call_cancel(monkeypatch, workspace, db_session, test_user)

        assert len(adapter.cancel_calls) == 1
        call = adapter.cancel_calls[0]
        assert call.cancel_at_period_end is True
        assert call.subscription_reference.external_id == "sub_pro_1"
        assert result.provider == "dodo"

        db_session.refresh(sub)
        # 3. Status remains active immediately after scheduling.
        assert sub.plan_id == plan_id
        assert sub.status == "active"
        # 4. cancel_at_period_end becomes true.
        assert sub.cancel_at_period_end is True


# 5. Current paid entitlement remains available through current_period_end.
class TestEntitlementPreservedAfterScheduling:
    def test_billing_still_reports_paid_plan_and_active_status(self, client, db_session, workspace, monkeypatch, test_user):
        from datetime import datetime, timedelta, timezone

        end = datetime.now(timezone.utc) + timedelta(days=20)
        sub = NormalizedSubscription(
            workspace_id=workspace.id, provider="dodo", plan_id="team", status="active",
            provider_customer_reference="cus_1", provider_subscription_reference="sub_team_1",
            current_period_end=end, billable_seats=20,
        )
        db_session.add(sub)
        db_session.commit()

        _call_cancel(monkeypatch, workspace, db_session, test_user)

        resp = client.get(f"/workspaces/{workspace.id}/billing")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan"] == "team"
        assert body["status"] == "active"
        assert body["cancel_at_period_end"] is True
        assert body["current_period_end"] is not None


# 6. Repeated cancellation is idempotent.
class TestIdempotentRepeatedCancellation:
    def test_second_call_does_not_hit_provider_again(self, monkeypatch, workspace, db_session, test_user):
        sub = _dodo_row(db_session, workspace, status="active", cancel_at_period_end=True)
        result, adapter = _call_cancel(monkeypatch, workspace, db_session, test_user)

        assert len(adapter.cancel_calls) == 0
        assert result.state == "already_scheduled"
        db_session.refresh(sub)
        assert sub.cancel_at_period_end is True
        assert sub.status == "active"


# 7. Missing provider_subscription_reference fails closed.
class TestMissingReferenceFailsClosed:
    def test_no_reference_returns_400(self, monkeypatch, workspace, db_session, test_user):
        sub = NormalizedSubscription(
            workspace_id=workspace.id, provider="dodo", plan_id="pro", status="active",
            provider_subscription_reference=None,
        )
        db_session.add(sub)
        db_session.commit()

        with pytest.raises(HTTPException) as exc_info:
            _call_cancel(monkeypatch, workspace, db_session, test_user)
        assert exc_info.value.status_code == 400


# 8. Canceled/expired subscription does not issue another cancellation request.
class TestNonLiveSubscriptionFailsClosed:
    @pytest.mark.parametrize("status", ["canceled", "expired", "incomplete", "paused"])
    def test_non_live_status_refuses_without_calling_provider(self, monkeypatch, workspace, db_session, test_user, status):
        sub = _dodo_row(db_session, workspace, status=status, cancel_at_period_end=False)

        with pytest.raises(HTTPException) as exc_info:
            _call_cancel(monkeypatch, workspace, db_session, test_user)
        assert exc_info.value.status_code == 400
        db_session.refresh(sub)
        assert sub.cancel_at_period_end is False


# 9. Wrong workspace / unauthorized fails: the ``client`` fixture always
# authenticates as ``test_user``, so "unauthorized" here means a
# workspace ``test_user`` is NOT a member of at all — _require_admin must
# refuse before any cancellation logic runs (proven by the adapter never
# being invoked).
class TestUnauthorizedWorkspaceFails:
    def test_non_member_workspace_cannot_be_canceled(self, client, db_session, test_user, monkeypatch):
        other_owner = User(
            clerk_id=f"test_clerk_other_{uuid.uuid4().hex[:8]}",
            email=f"other-{uuid.uuid4().hex[:8]}@example.test",
            display_name="Other Owner",
        )
        db_session.add(other_owner)
        db_session.flush()
        other_ws = Workspace(name=f"unauthorized-{uuid.uuid4().hex[:8]}", created_by_user_id=other_owner.id)
        db_session.add(other_ws)
        db_session.flush()
        db_session.add(WorkspaceMember(workspace_id=other_ws.id, user_id=other_owner.id, role="owner"))
        sub = NormalizedSubscription(
            workspace_id=other_ws.id, provider="dodo", plan_id="pro", status="active",
            provider_subscription_reference="sub_not_yours",
        )
        db_session.add(sub)
        db_session.commit()

        from app.routers import billing as billing_router

        fake_adapter = _FakeAdapter()
        monkeypatch.setattr(billing_router, "get_adapter_for_provider", lambda p, db: fake_adapter)
        monkeypatch.setattr(billing_router, "provider_for_management", lambda workspace_id, db: BillingProvider.DODO)

        resp = client.post(f"/workspaces/{other_ws.id}/billing/cancel")
        assert resp.status_code in (403, 404)
        assert len(fake_adapter.cancel_calls) == 0

        db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == other_ws.id).delete()
        db_session.delete(other_ws)  # cascades WorkspaceMember
        db_session.commit()
        db_session.delete(other_owner)
        db_session.commit()


# 10. Stripe behavior remains unchanged.
class TestStripeUnaffected:
    def test_stripe_still_rejects_with_portal_message(self, monkeypatch, workspace, db_session, test_user):
        sub = NormalizedSubscription(
            workspace_id=workspace.id, provider="stripe", plan_id="pro", status="active",
            provider_subscription_reference="sub_stripe_1",
        )
        db_session.add(sub)
        db_session.commit()

        with pytest.raises(HTTPException) as exc_info:
            _call_cancel(monkeypatch, workspace, db_session, test_user, provider=BillingProvider.STRIPE)
        assert exc_info.value.status_code == 400
        assert "Billing Portal" in exc_info.value.detail


# 11. Paddle behavior remains unchanged (still dispatches through the
# same provider-neutral path, still schedules cancel_at_period_end).
class TestPaddleUnaffected:
    def test_paddle_active_subscription_still_schedules_cancellation(self, monkeypatch, workspace, db_session, test_user):
        sub = NormalizedSubscription(
            workspace_id=workspace.id, provider="paddle", plan_id="pro", status="active",
            provider_subscription_reference="sub_paddle_1",
        )
        db_session.add(sub)
        db_session.commit()

        result, adapter = _call_cancel(monkeypatch, workspace, db_session, test_user, provider=BillingProvider.PADDLE)
        assert len(adapter.cancel_calls) == 1
        assert result.provider == "paddle"
        db_session.refresh(sub)
        assert sub.cancel_at_period_end is True
        assert sub.status == "active"


# 13. GET /billing exposes cancel_at_period_end correctly, and the new
# `provider` field reflects the actual existing-subscription provider.
class TestBillingExposesProviderAndCancelState:
    def test_provider_field_reflects_dodo(self, client, db_session, workspace):
        _dodo_row(db_session, workspace, status="active")
        resp = client.get(f"/workspaces/{workspace.id}/billing")
        assert resp.status_code == 200
        assert resp.json()["provider"] == "dodo"

    def test_provider_field_none_when_no_subscription(self, client, db_session, workspace):
        resp = client.get(f"/workspaces/{workspace.id}/billing")
        assert resp.status_code == 200
        assert resp.json()["provider"] is None

    def test_no_raw_subscription_or_customer_id_in_response(self, client, db_session, workspace):
        _dodo_row(db_session, workspace, status="active", subscription_id="sub_secret_ref")
        resp = client.get(f"/workspaces/{workspace.id}/billing")
        body_text = resp.text
        assert "sub_secret_ref" not in body_text
        assert "cus_1" not in body_text
