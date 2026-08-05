"""HTTP-level tests for the provider-neutral billing router, Dodo cases
(Dodo Payments — Test Mode verification).

Closes a real gap: prior Dodo test files verified the adapter/service
layer only. This proves the actual endpoint the billing page calls
(`GET /workspaces/{id}/billing/subscription`) correctly reflects a Dodo
subscription — in particular the Phase-1 fix to the stale
``plan_id in ("free", "team")`` fallback tuple (Pro would previously have
silently displayed as Free).
"""

from __future__ import annotations

import uuid

from app.billing.models import NormalizedSubscription
from app.models.workspace import Workspace, WorkspaceMember


def _make_workspace(db_session, test_user):
    ws = Workspace(name=f"dodo-router-ws-{uuid.uuid4().hex[:6]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.flush()
    member = WorkspaceMember(workspace_id=ws.id, user_id=test_user.id, role="owner")
    db_session.add(member)
    db_session.commit()
    return ws


class TestSubscriptionEndpointReflectsDodoPro:
    def test_dodo_pro_subscription_shows_plan_id_pro_not_free(self, client, db_session, test_user):
        """The exact bug this Phase-1 fix prevents: before the fix, a
        Dodo Pro row's plan_id would fall through the stale
        ("free", "team") tuple and silently display as Free."""
        ws = _make_workspace(db_session, test_user)
        sub = NormalizedSubscription(
            workspace_id=ws.id, provider="dodo", provider_customer_reference="cus_dodo_router_1",
            provider_subscription_reference="sub_dodo_router_1", plan_id="pro", status="active",
        )
        db_session.add(sub)
        db_session.commit()

        resp = client.get(f"/workspaces/{ws.id}/billing/subscription")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan_id"] == "pro"
        assert body["provider"] == "dodo"
        assert body["has_paid_access"] is True
        assert body["status"] == "active"

    def test_dodo_team_subscription_shows_additional_seat_quantity(self, client, db_session, test_user):
        ws = _make_workspace(db_session, test_user)
        sub = NormalizedSubscription(
            workspace_id=ws.id, provider="dodo", provider_customer_reference="cus_dodo_router_2",
            provider_subscription_reference="sub_dodo_router_2", plan_id="team", status="active",
            billable_seats=25, additional_seat_quantity=5,
        )
        db_session.add(sub)
        db_session.commit()

        resp = client.get(f"/workspaces/{ws.id}/billing/subscription")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan_id"] == "team"
        assert body["additional_seat_quantity"] == 5
        assert body["billable_seats"] == 25

    def test_dodo_on_hold_subscription_still_has_paid_access(self, client, db_session, test_user):
        """on_hold normalizes to PAST_DUE, which is a grace-period-covered
        paid-access status — the billing page must not prematurely show
        the user as downgraded to Free while Dodo's dunning retries run."""
        ws = _make_workspace(db_session, test_user)
        sub = NormalizedSubscription(
            workspace_id=ws.id, provider="dodo", provider_customer_reference="cus_dodo_router_3",
            provider_subscription_reference="sub_dodo_router_3", plan_id="pro", status="past_due",
        )
        db_session.add(sub)
        db_session.commit()

        resp = client.get(f"/workspaces/{ws.id}/billing/subscription")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "past_due"
        assert body["has_paid_access"] is True

    def test_dodo_cancelled_subscription_falls_back_to_free_display(self, client, db_session, test_user):
        ws = _make_workspace(db_session, test_user)
        sub = NormalizedSubscription(
            workspace_id=ws.id, provider="dodo", provider_customer_reference="cus_dodo_router_4",
            provider_subscription_reference="sub_dodo_router_4", plan_id="team", status="cancelled",
        )
        db_session.add(sub)
        db_session.commit()

        resp = client.get(f"/workspaces/{ws.id}/billing/subscription")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan_id"] == "free"
        assert body["has_paid_access"] is False

    def test_workspace_with_no_subscription_shows_free_regardless_of_dodo_existing(
        self, client, db_session, test_user
    ):
        """A brand-new workspace with no NormalizedSubscription row at
        all must show Free — proves a freshly created workspace is never
        accidentally affected by Dodo being a registered provider."""
        ws = _make_workspace(db_session, test_user)
        resp = client.get(f"/workspaces/{ws.id}/billing/subscription")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan_id"] == "free"
        assert body["provider"] is None
        assert body["has_paid_access"] is False


class TestBillingProviderDefaultUnaffectedByDodoSubscriptions:
    def test_get_billing_checkout_provider_is_stripe_by_default(self, client, db_session, test_user):
        """The top-level GET /billing endpoint's checkout_provider field
        (what the frontend uses to decide the Pro/Team upgrade button's
        behavior) must read the real, unmodified BILLING_PROVIDER
        setting — confirmed still 'stripe' by default even with Dodo
        fully implemented."""
        ws = _make_workspace(db_session, test_user)
        resp = client.get(f"/workspaces/{ws.id}/billing")
        assert resp.status_code == 200
        assert resp.json()["checkout_provider"] == "stripe"
