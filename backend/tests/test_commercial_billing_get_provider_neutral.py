"""GET /workspaces/{id}/billing provider-neutral read-path regression
tests (real production bug fix).

Root cause: this endpoint (the one the frontend billing page actually
calls — ``getWorkspaceBilling`` in ``frontend/src/lib/api.ts``) only ever
read the legacy ``WorkspaceBilling`` row (``billing_service``), which is
written to ONLY by the old Stripe-only checkout/webhook flow. It never
consulted ``NormalizedSubscription`` at all. A workspace with a real,
active Dodo (or Paddle) subscription therefore always read back as
``plan: "free"``, regardless of the actual subscription state — not
because ``checkout_provider``/global ``BILLING_PROVIDER`` was used to
gate anything (it was already correctly informational-only), but because
the endpoint never looked at the provider-neutral system at all.

Fix: when a ``NormalizedSubscription`` row exists for the workspace, it
is now authoritative for plan/status/period dates — exactly the same
normalization/entitlement dispatch ``GET .../billing/subscription``
(``get_current_subscription``) already used correctly, now shared via
``_resolve_normalized_subscription_state``.
"""

from __future__ import annotations

import uuid

from app.billing.models import NormalizedSubscription
from app.models.workspace import Workspace, WorkspaceMember


def _make_workspace(db_session, test_user):
    ws = Workspace(name=f"billing-get-ws-{uuid.uuid4().hex[:6]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.flush()
    db_session.add(WorkspaceMember(workspace_id=ws.id, user_id=test_user.id, role="owner"))
    db_session.commit()
    return ws


class TestDodoActiveSubscriptionOverridesLegacyFreeDefault:
    def test_dodo_pro_subscription_returns_plan_pro(self, client, db_session, test_user, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")  # global default unchanged
        ws = _make_workspace(db_session, test_user)
        sub = NormalizedSubscription(
            workspace_id=ws.id, provider="dodo", plan_id="pro", status="active",
            provider_customer_reference="cus_recon_1", provider_subscription_reference="sub_recon_1",
        )
        db_session.add(sub)
        db_session.commit()

        resp = client.get(f"/workspaces/{ws.id}/billing")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan"] == "pro"
        assert body["status"] == "active"

    def test_dodo_period_dates_are_returned(self, client, db_session, test_user):
        from datetime import datetime, timedelta, timezone

        ws = _make_workspace(db_session, test_user)
        start = datetime.now(timezone.utc)
        end = start + timedelta(days=30)
        sub = NormalizedSubscription(
            workspace_id=ws.id, provider="dodo", plan_id="pro", status="active",
            provider_customer_reference="cus_recon_2", provider_subscription_reference="sub_recon_2",
            current_period_start=start, current_period_end=end,
        )
        db_session.add(sub)
        db_session.commit()

        resp = client.get(f"/workspaces/{ws.id}/billing")
        assert resp.status_code == 200
        body = resp.json()
        assert body["current_period_start"] is not None
        assert body["current_period_end"] is not None
        assert body["current_period_start"].startswith(start.isoformat()[:19])
        assert body["current_period_end"].startswith(end.isoformat()[:19])

    def test_checkout_provider_field_unaffected_still_reflects_global_default(self, client, db_session, test_user, monkeypatch):
        """The response may still expose checkout_provider="stripe"
        globally — that field represents default NEW-checkout routing,
        never the current workspace's existing subscription — but it
        must not force plan back to free."""
        from app import config

        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")
        ws = _make_workspace(db_session, test_user)
        sub = NormalizedSubscription(
            workspace_id=ws.id, provider="dodo", plan_id="pro", status="active",
        )
        db_session.add(sub)
        db_session.commit()

        resp = client.get(f"/workspaces/{ws.id}/billing")
        body = resp.json()
        assert body["checkout_provider"] == "stripe"
        assert body["plan"] == "pro"


class TestPilotOverrideDoesNotCorruptReadSideState:
    def test_pilot_override_workspace_id_set_does_not_affect_billing_read(self, client, db_session, test_user, monkeypatch):
        from app import config

        ws = _make_workspace(db_session, test_user)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(ws.id))
        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")

        sub = NormalizedSubscription(
            workspace_id=ws.id, provider="dodo", plan_id="pro", status="active",
        )
        db_session.add(sub)
        db_session.commit()

        resp = client.get(f"/workspaces/{ws.id}/billing")
        body = resp.json()
        assert body["plan"] == "pro"
        assert body["status"] == "active"

    def test_pilot_override_set_for_a_different_workspace_never_leaks_into_this_one(
        self, client, db_session, test_user, monkeypatch
    ):
        from app import config

        pilot_ws = _make_workspace(db_session, test_user)
        other_ws = _make_workspace(db_session, test_user)
        monkeypatch.setattr(config.settings, "DODO_PILOT_WORKSPACE_ID", str(pilot_ws.id))

        resp = client.get(f"/workspaces/{other_ws.id}/billing")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan"] == "free"  # no NormalizedSubscription row for other_ws


class TestNoSubscriptionStillReturnsFree:
    def test_workspace_with_no_normalized_subscription_shows_free(self, client, db_session, test_user):
        ws = _make_workspace(db_session, test_user)
        resp = client.get(f"/workspaces/{ws.id}/billing")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan"] == "free"
        assert body["stripe_subscription_id"] is None


class TestLegacyStripeFieldsDoNotDetermineEntitlement:
    def test_null_stripe_subscription_id_does_not_force_free_when_dodo_row_exists(
        self, client, db_session, test_user
    ):
        """Pins the exact symptom from the bug report: stripe_subscription_id
        is null (this workspace never used the legacy Stripe checkout
        flow at all) and yet the workspace must still read as its real
        Dodo plan, not fall back to Free because of the null legacy
        field."""
        ws = _make_workspace(db_session, test_user)
        sub = NormalizedSubscription(
            workspace_id=ws.id, provider="dodo", plan_id="pro", status="active",
        )
        db_session.add(sub)
        db_session.commit()

        resp = client.get(f"/workspaces/{ws.id}/billing")
        body = resp.json()
        assert body["stripe_subscription_id"] is None
        assert body["plan"] == "pro"


class TestExistingStripeWorkspaceUnchanged:
    def test_legacy_stripe_billing_row_still_drives_response_when_no_normalized_row(
        self, client, db_session, test_user
    ):
        """No code path creates a NormalizedSubscription row for Stripe
        today, so an existing Stripe customer's billing read must be
        byte-for-byte unchanged by this fix — still driven entirely by
        the legacy WorkspaceBilling row."""
        from app.models.billing import WorkspaceBilling

        ws = _make_workspace(db_session, test_user)
        billing = WorkspaceBilling(
            workspace_id=ws.id, plan="pro", status="active",
            stripe_customer_id="cus_stripe_legacy", stripe_subscription_id="sub_stripe_legacy",
        )
        db_session.add(billing)
        db_session.commit()

        resp = client.get(f"/workspaces/{ws.id}/billing")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan"] == "pro"
        assert body["status"] == "active"
        assert body["stripe_subscription_id"] == "sub_stripe_legacy"


class TestExistingPaddleBehaviorUnchanged:
    def test_paddle_active_subscription_also_correctly_overrides_free_default(
        self, client, db_session, test_user
    ):
        """Paddle rows go through the exact same provider-neutral branch
        as Dodo — proving the fix is provider-agnostic, not a
        Dodo-specific special case, and that Paddle's read-side behavior
        (if/when a real Paddle NormalizedSubscription row exists) is
        correctly reflected too, not broken by this change."""
        ws = _make_workspace(db_session, test_user)
        sub = NormalizedSubscription(
            workspace_id=ws.id, provider="paddle", plan_id="team", status="active",
            billable_seats=25, additional_seat_quantity=5,
        )
        db_session.add(sub)
        db_session.commit()

        resp = client.get(f"/workspaces/{ws.id}/billing")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan"] == "team"
        assert body["status"] == "active"

    def test_workspace_with_no_paddle_row_unaffected(self, client, db_session, test_user):
        ws = _make_workspace(db_session, test_user)
        resp = client.get(f"/workspaces/{ws.id}/billing")
        assert resp.status_code == 200
        assert resp.json()["plan"] == "free"
