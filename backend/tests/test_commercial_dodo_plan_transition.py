"""Dodo same-workspace Pro -> Team plan transition regression tests
(real production bug fix).

Reproduces the exact production failure: a workspace with an existing
active Dodo Pro NormalizedSubscription completed a real Dodo Test Mode
Team checkout. Dodo delivered real, correctly-signed
transaction_completed / subscription_updated / subscription_updated /
subscription_created events, all verified and marked
``processing_status=processed`` — yet the NormalizedSubscription row
never left plan_id="pro". ``last_provider_event`` remained
"transaction_completed" and ``version`` remained 1 despite 4 events being
processed.

Two independent, compounding bugs were found and fixed:

1. ``is_stale_subscription_update`` compared each event's own
   ``occurred_at`` against ``NormalizedSubscription.updated_at`` — a DB
   WRITE-time, not an event TIME. When several events arrive within a
   couple of seconds (typical for a checkout completing), the first
   event's processing/commit latency can easily exceed the gap to the
   next event's ``occurred_at``, so every event after the first gets
   wrongly judged "stale" and silently discarded — explaining why only
   ONE of the four events (transaction_completed, arriving first)
   actually mutated the row.

2. Even for an event that WAS applied, the SUBSCRIPTION_CREATED /
   SUBSCRIPTION_UPDATED branch only ever updated ``status`` — never
   ``plan_id``, seats, ``provider_subscription_reference``, or period
   dates. So even after fixing bug #1, a legitimate Team event still
   would not have transitioned the workspace off Pro.

Fixture event payloads use the official Dodo subscription.active/updated
contract: payload["type"], payload["data"]["subscription_id"],
payload["data"]["product_id"], payload["data"]["status"],
payload["data"]["metadata"].
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.billing.dodo_webhook_service import process_dodo_webhook
from app.billing.enums import NormalizedSubscriptionStatus
from app.billing.models import BillingAuditEvent, BillingWebhookEvent, NormalizedSubscription
from app.models.workspace import Workspace, WorkspaceMember

PRO_PRODUCT_ID = "prod_pro_test"
TEAM_PRODUCT_ID = "prod_team_test"


def _configure_dodo_catalog(monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "DODO_PRO_PRODUCT_ID", PRO_PRODUCT_ID)
    monkeypatch.setattr(config.settings, "DODO_TEAM_PRODUCT_ID", TEAM_PRODUCT_ID)


def _event(event_type: str, data: dict, timestamp: str | None = None) -> dict:
    return {
        "business_id": "biz_test",
        "type": event_type,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "data": data,
    }


def _checkout_metadata(workspace_id, *, plan_id="pro", additional_seat_count=0) -> dict:
    return {
        "workspace_id": str(workspace_id),
        "configtrace_user_id": str(_uuid.uuid4()),
        "plan_id": plan_id,
        "included_member_count": 20 if plan_id == "team" else 0,
        "additional_seat_count": additional_seat_count,
        "pricing_version": 1,
        "idempotency_reference": f"{workspace_id}:{_uuid.uuid4()}",
    }


def _subscription_event(
    event_type: str, workspace_id, *, subscription_id, customer_id="cus_shared_1",
    status="active", plan_id="pro", additional_seat_count=0, product_id=PRO_PRODUCT_ID,
    include_metadata=True, timestamp=None,
) -> dict:
    data = {
        "subscription_id": subscription_id,
        "customer": {"customer_id": customer_id},
        "status": status,
        "product_id": product_id,
    }
    if include_metadata:
        data["metadata"] = _checkout_metadata(workspace_id, plan_id=plan_id, additional_seat_count=additional_seat_count)
    return _event(event_type, data, timestamp=timestamp)


@pytest.fixture
def workspace(db_session, test_user):
    ws = Workspace(name=f"dodo-plan-{_uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.flush()
    db_session.add(WorkspaceMember(workspace_id=ws.id, user_id=test_user.id, role="owner"))
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(BillingAuditEvent).filter(BillingAuditEvent.workspace_id == ws.id).delete()
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.query(BillingWebhookEvent).filter(BillingWebhookEvent.external_event_id.like("evt_plan_%")).delete()
    db_session.commit()


@pytest.fixture
def other_workspace(db_session, test_user):
    ws = Workspace(name=f"dodo-plan-other-{_uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.commit()


def _existing_pro_row(db_session, workspace, *, subscription_id="sub_pro_1", customer_id="cus_shared_1"):
    sub = NormalizedSubscription(
        workspace_id=workspace.id, provider="dodo", plan_id="pro", status="active",
        provider_customer_reference=customer_id, provider_subscription_reference=subscription_id,
        billable_seats=0, additional_seat_quantity=0,
    )
    db_session.add(sub)
    db_session.commit()
    db_session.refresh(sub)
    return sub


class TestSameSubscriptionIdPlanChange:
    """Dodo change-plan on the SAME subscription object — the reference
    stays identical, only status/product/metadata change."""

    def test_pro_to_team_via_subscription_updated_same_sub_id(self, db_session, workspace, monkeypatch):
        _configure_dodo_catalog(monkeypatch)
        sub = _existing_pro_row(db_session, workspace, subscription_id="sub_pro_1")

        event = _subscription_event(
            "subscription.updated", workspace.id, subscription_id="sub_pro_1",
            plan_id="team", additional_seat_count=2, product_id=TEAM_PRODUCT_ID,
        )
        status = process_dodo_webhook(event, "evt_plan_same_sub", db_session)
        db_session.refresh(sub)

        assert status == "processed"
        assert sub.plan_id == "team"
        assert sub.provider_subscription_reference == "sub_pro_1"
        assert sub.billable_seats == 22
        assert sub.additional_seat_quantity == 2


class TestNewSubscriptionIdSameWorkspace:
    """Matches the actual production symptom: checkout produced a NEW
    Dodo subscription ID for the same customer/workspace."""

    def test_existing_pro_plus_team_subscription_updated_new_sub_id(self, db_session, workspace, monkeypatch):
        _configure_dodo_catalog(monkeypatch)
        sub = _existing_pro_row(db_session, workspace, subscription_id="sub_pro_1", customer_id="cus_shared_1")

        event = _subscription_event(
            "subscription.updated", workspace.id, subscription_id="sub_team_2", customer_id="cus_shared_1",
            plan_id="team", additional_seat_count=0, product_id=TEAM_PRODUCT_ID,
        )
        status = process_dodo_webhook(event, "evt_plan_new_sub_updated", db_session)
        db_session.refresh(sub)

        assert status == "processed"
        assert sub.plan_id == "team"
        assert sub.provider_subscription_reference == "sub_team_2"  # migrated to the new reference
        assert sub.status == "active"

    def test_existing_pro_plus_team_subscription_created_new_sub_id(self, db_session, workspace, monkeypatch):
        _configure_dodo_catalog(monkeypatch)
        sub = _existing_pro_row(db_session, workspace, subscription_id="sub_pro_1", customer_id="cus_shared_1")

        event = _subscription_event(
            "subscription.active", workspace.id, subscription_id="sub_team_2", customer_id="cus_shared_1",
            plan_id="team", product_id=TEAM_PRODUCT_ID,
        )
        status = process_dodo_webhook(event, "evt_plan_new_sub_created", db_session)
        db_session.refresh(sub)

        assert status == "processed"
        assert sub.plan_id == "team"
        assert sub.provider_subscription_reference == "sub_team_2"

    def test_reference_change_is_audited_not_silent(self, db_session, workspace, monkeypatch):
        _configure_dodo_catalog(monkeypatch)
        _existing_pro_row(db_session, workspace, subscription_id="sub_pro_1", customer_id="cus_shared_1")

        event = _subscription_event(
            "subscription.updated", workspace.id, subscription_id="sub_team_2", customer_id="cus_shared_1",
            plan_id="team", product_id=TEAM_PRODUCT_ID,
        )
        process_dodo_webhook(event, "evt_plan_audit", db_session)

        rows = (
            db_session.query(BillingAuditEvent)
            .filter(BillingAuditEvent.workspace_id == workspace.id)
            .all()
        )
        details_blobs = [r.details for r in rows]
        assert any(
            d.get("new_plan_id") == "team" and d.get("previous_plan_id") == "pro" for d in details_blobs
        )
        assert any("reference_changed" in (d.get("reason") or "") for d in details_blobs)


class TestProductIdFallbackWhenMetadataAbsent:
    def test_team_product_id_resolves_plan_without_metadata(self, db_session, workspace, monkeypatch):
        _configure_dodo_catalog(monkeypatch)
        sub = _existing_pro_row(db_session, workspace, subscription_id="sub_pro_1")

        event = _subscription_event(
            "subscription.updated", workspace.id, subscription_id="sub_pro_1",
            product_id=TEAM_PRODUCT_ID, include_metadata=False,
        )
        status = process_dodo_webhook(event, "evt_plan_fallback", db_session)
        db_session.refresh(sub)

        assert status == "processed"
        assert sub.plan_id == "team"

    def test_unknown_product_id_never_changes_plan(self, db_session, workspace, monkeypatch):
        _configure_dodo_catalog(monkeypatch)
        sub = _existing_pro_row(db_session, workspace, subscription_id="sub_pro_1")

        event = _subscription_event(
            "subscription.updated", workspace.id, subscription_id="sub_pro_1",
            product_id="prod_totally_unrecognized", include_metadata=False,
        )
        status = process_dodo_webhook(event, "evt_plan_unknown_product", db_session)
        db_session.refresh(sub)

        assert status == "processed"
        assert sub.plan_id == "pro"  # unchanged — fails closed


class TestConflictingSubscriptionSafety:
    def test_event_for_different_customer_and_subscription_never_touches_unrelated_row(
        self, db_session, workspace, other_workspace, monkeypatch
    ):
        _configure_dodo_catalog(monkeypatch)
        pro_sub = _existing_pro_row(db_session, workspace, subscription_id="sub_pro_1", customer_id="cus_shared_1")

        # Genuinely unrelated: different customer AND no workspace metadata
        # matching `workspace` at all — this must create (or fail closed
        # for) a DIFFERENT row, never mutate `workspace`'s Pro row.
        event = _subscription_event(
            "subscription.active", other_workspace.id, subscription_id="sub_unrelated_9",
            customer_id="cus_totally_unrelated", plan_id="pro", product_id=PRO_PRODUCT_ID,
        )
        process_dodo_webhook(event, "evt_plan_conflict", db_session)
        db_session.refresh(pro_sub)

        assert pro_sub.plan_id == "pro"
        assert pro_sub.provider_subscription_reference == "sub_pro_1"


class TestWrongWorkspaceMetadataFailsClosed:
    def test_new_customer_with_mismatched_workspace_metadata_does_not_corrupt_existing_row(
        self, db_session, workspace, monkeypatch
    ):
        _configure_dodo_catalog(monkeypatch)
        pro_sub = _existing_pro_row(db_session, workspace, subscription_id="sub_pro_1", customer_id="cus_shared_1")
        fake_workspace_id = _uuid.uuid4()

        event = _subscription_event(
            "subscription.active", fake_workspace_id, subscription_id="sub_new_99",
            customer_id="cus_new_customer", plan_id="team", product_id=TEAM_PRODUCT_ID,
        )
        status = process_dodo_webhook(event, "evt_plan_wrong_ws", db_session)
        db_session.refresh(pro_sub)

        assert status == "unresolved_workspace"
        assert pro_sub.plan_id == "pro"


class TestStripePaddleOverwriteProtection:
    def test_dodo_event_never_matches_a_stripe_row(self, db_session, workspace, monkeypatch):
        _configure_dodo_catalog(monkeypatch)
        stripe_sub = NormalizedSubscription(
            workspace_id=workspace.id, provider="stripe", plan_id="pro", status="active",
            provider_customer_reference="cus_shared_1", provider_subscription_reference="sub_stripe_1",
        )
        db_session.add(stripe_sub)
        db_session.commit()

        event = _subscription_event(
            "subscription.active", workspace.id, subscription_id="sub_dodo_new",
            customer_id="cus_shared_1", plan_id="team", product_id=TEAM_PRODUCT_ID,
        )
        process_dodo_webhook(event, "evt_plan_stripe_protect", db_session)
        db_session.refresh(stripe_sub)

        # The Stripe row is completely untouched: dodo_webhook_service
        # only ever queries NormalizedSubscription.provider == "dodo".
        assert stripe_sub.provider == "stripe"
        assert stripe_sub.plan_id == "pro"
        # And no NEW dodo row was created either, since a row already
        # exists for this workspace under a different provider.
        dodo_rows = (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == workspace.id, NormalizedSubscription.provider == "dodo")
            .all()
        )
        assert dodo_rows == []


class TestIdempotentDuplicateDelivery:
    def test_duplicate_team_update_does_not_reapply(self, db_session, workspace, monkeypatch):
        _configure_dodo_catalog(monkeypatch)
        sub = _existing_pro_row(db_session, workspace, subscription_id="sub_pro_1")

        event = _subscription_event(
            "subscription.updated", workspace.id, subscription_id="sub_pro_1",
            plan_id="team", product_id=TEAM_PRODUCT_ID,
        )
        first = process_dodo_webhook(event, "evt_plan_dup", db_session)
        version_after_first = sub.version

        second = process_dodo_webhook(event, "evt_plan_dup", db_session)  # same external_event_id
        db_session.refresh(sub)

        assert first == "processed"
        assert second == "duplicate_ignored"
        assert sub.version == version_after_first
        assert sub.plan_id == "team"


class TestBurstOfEventsAllApplyNotJustTheFirst:
    """Direct regression for the exact reported symptom: version=1 and
    last_provider_event=transaction_completed despite 4 events."""

    def test_all_four_events_in_a_tight_burst_are_applied_in_order(self, db_session, workspace, monkeypatch):
        _configure_dodo_catalog(monkeypatch)
        sub = _existing_pro_row(db_session, workspace, subscription_id="sub_pro_1", customer_id="cus_shared_1")

        base = datetime.now(timezone.utc)
        payment_event = _event(
            "payment.succeeded",
            {
                "payment_id": "pay_burst_1", "subscription_id": "sub_team_2",
                "customer": {"customer_id": "cus_shared_1"},
                "metadata": _checkout_metadata(workspace.id, plan_id="team"),
            },
            timestamp=base.isoformat().replace("+00:00", "Z"),
        )
        updated_1 = _subscription_event(
            "subscription.updated", workspace.id, subscription_id="sub_team_2", customer_id="cus_shared_1",
            plan_id="team", product_id=TEAM_PRODUCT_ID,
            timestamp=(base + timedelta(milliseconds=500)).isoformat().replace("+00:00", "Z"),
        )
        updated_2 = _subscription_event(
            "subscription.updated", workspace.id, subscription_id="sub_team_2", customer_id="cus_shared_1",
            plan_id="team", product_id=TEAM_PRODUCT_ID,
            timestamp=(base + timedelta(milliseconds=1000)).isoformat().replace("+00:00", "Z"),
        )
        created = _subscription_event(
            "subscription.active", workspace.id, subscription_id="sub_team_2", customer_id="cus_shared_1",
            plan_id="team", product_id=TEAM_PRODUCT_ID,
            timestamp=(base + timedelta(milliseconds=1600)).isoformat().replace("+00:00", "Z"),
        )

        s1 = process_dodo_webhook(payment_event, "evt_plan_burst_payment", db_session)
        s2 = process_dodo_webhook(updated_1, "evt_plan_burst_updated_1", db_session)
        s3 = process_dodo_webhook(updated_2, "evt_plan_burst_updated_2", db_session)
        s4 = process_dodo_webhook(created, "evt_plan_burst_created", db_session)
        db_session.refresh(sub)

        assert [s1, s2, s3, s4] == ["processed", "processed", "processed", "processed"]
        assert sub.plan_id == "team"
        assert sub.provider_subscription_reference == "sub_team_2"
        # Every event that reached a mutating branch increments version —
        # not just the first one processed.
        assert sub.version >= 3


class TestBillingEndpointReflectsTeamAfterTransition:
    def test_get_billing_returns_team_limits_after_plan_change(self, client, db_session, workspace, monkeypatch):
        _configure_dodo_catalog(monkeypatch)
        _existing_pro_row(db_session, workspace, subscription_id="sub_pro_1", customer_id="cus_shared_1")

        event = _subscription_event(
            "subscription.updated", workspace.id, subscription_id="sub_pro_1",
            plan_id="team", additional_seat_count=0, product_id=TEAM_PRODUCT_ID,
        )
        process_dodo_webhook(event, "evt_plan_billing_endpoint", db_session)
        db_session.commit()

        resp = client.get(f"/workspaces/{workspace.id}/billing")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan"] == "team"
        assert body["limits"]["max_members"] == 25  # team limits, not pro's 5
