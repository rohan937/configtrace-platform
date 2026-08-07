"""Dodo Test Mode subscription-state synchronization regression tests
(production bug fix — Dodo Payments live-cutover pilot verification).

Reproduces and fixes the exact production failure: a real Dodo Test Mode
Pro checkout completed for pilot workspace
ad286e8d-1c59-402e-a7f8-52f490f045f3. Dodo delivered payment.succeeded,
subscription.active, subscription.renewed, subscription.updated — all
verified (HTTP 200) and reported by scripts/dodo_live_cutover.py as
processing_status=processed — yet
``scripts/dodo_live_cutover.py subscription <workspace>`` reported "No
NormalizedSubscription row exists yet", and the billing page kept showing
Free.

Root cause: nothing in this codebase ever INSERTED a ``NormalizedSubscription``
row — every code path (``_apply_normalized_event``,
``reconcile_workspace_subscription``) only ever UPDATES a row located by
matching an existing ``provider_subscription_reference`` /
``provider_customer_reference``. The very FIRST lifecycle event for a
brand-new Dodo subscription can never find an existing row, so the
handler silently no-op'd and ``process_dodo_webhook`` still returned
"processed" regardless of whether anything was actually persisted.

Fix: ``adapters.dodo.DodoBillingAdapter.create_checkout`` already sends an
explicit ``metadata.workspace_id`` (and ``plan_id`` /
``additional_seat_count``) to Dodo at checkout time — this was already
correct and is unchanged. ``dodo_webhooks.normalize_dodo_event`` now
extracts and validates that echoed-back metadata; when no existing row is
found for a subscription-LIFECYCLE event (never a bare payment event),
``dodo_webhook_service._create_subscription_from_hint`` uses it — ONLY
after confirming the UUID parses and names a real, existing workspace —
to create the first row. Anything that can't be safely resolved is now
reported as ``processing_status=failed`` /
``error_category=unknown_reference`` (visible via
``scripts/dodo_live_cutover.py unresolved-events`` /
``webhook-events --status failed``) and ``process_dodo_webhook`` returns
"unresolved_workspace" — never silently "processed".
"""

from __future__ import annotations

import json
import uuid as _uuid
from datetime import datetime, timezone

import httpx
import pytest

from app.billing.adapters.dodo import DodoBillingAdapter, DodoCatalogMapping
from app.billing.dodo_client import DodoAPIClient, DodoClientConfig
from app.billing.dodo_webhook_service import process_dodo_webhook
from app.billing.enums import BillingInterval, NormalizedSubscriptionStatus, PlanId
from app.billing.models import BillingAuditEvent, BillingWebhookEvent, NormalizedSubscription
from app.billing.provider import CheckoutRequest
from app.models.workspace import Workspace, WorkspaceMember


def _event(event_type: str, data: dict, timestamp: str | None = None) -> dict:
    return {
        "business_id": "biz_test",
        "type": event_type,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "data": data,
    }


def _checkout_metadata(workspace_id, *, plan_id="pro", additional_seat_count=0) -> dict:
    """Mirrors adapters.dodo.DodoBillingAdapter.create_checkout's real
    metadata dict exactly — Dodo echoes this back onto the resulting
    subscription/payment object in webhook events."""
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
    event_type: str, workspace_id, *, subscription_id="sub_prod_1", customer_id="cus_prod_1",
    status="active", plan_id="pro", additional_seat_count=0, product_id="prod_pro_test",
    include_metadata=True,
) -> dict:
    data = {
        "subscription_id": subscription_id,
        "customer": {"customer_id": customer_id},
        "status": status,
        "product_id": product_id,
    }
    if include_metadata:
        data["metadata"] = _checkout_metadata(workspace_id, plan_id=plan_id, additional_seat_count=additional_seat_count)
    return _event(event_type, data)


def _payment_event(workspace_id, *, subscription_id="sub_prod_1", customer_id="cus_prod_1", plan_id="pro", payment_id="pay_prod_1") -> dict:
    return _event(
        "payment.succeeded",
        {
            "payment_id": payment_id,
            "subscription_id": subscription_id,
            "customer": {"customer_id": customer_id},
            "metadata": _checkout_metadata(workspace_id, plan_id=plan_id),
        },
    )


@pytest.fixture
def workspace(db_session, test_user):
    ws = Workspace(name=f"dodo-sync-{_uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
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
    ws = Workspace(name=f"dodo-sync-other-{_uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.commit()


# 1. Dodo checkout contains the workspace identifier. ------------------------


class TestCheckoutSendsExplicitWorkspaceIdentifier:
    def test_pro_checkout_metadata_includes_workspace_id(self):
        ws_id = _uuid.uuid4()
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={"session_id": "cks_1", "checkout_url": "https://test.checkout.dodopayments.com/x"})

        client = DodoAPIClient(
            DodoClientConfig(environment="test", api_key="apikey_test_dummy"),
            transport=httpx.MockTransport(handler),
        )
        mapping = DodoCatalogMapping(
            environment="test", pro_product_id="prod_pro_test",
            team_product_id="prod_team_test", team_seat_addon_id="addon_seat_test",
        )
        adapter = DodoBillingAdapter(mapping, client)
        adapter.create_checkout(
            CheckoutRequest(
                workspace_id=ws_id, plan_id=PlanId.PRO, billing_interval=BillingInterval.MONTH,
                billable_seat_count=1, success_url="https://app.example.test/s",
                cancel_url="https://app.example.test/c", customer_email="owner@example.test",
                configtrace_user_id=_uuid.uuid4(),
            )
        )
        assert captured["body"]["metadata"]["workspace_id"] == str(ws_id)


# 2. subscription.active carrying the identifier creates the row. -----------


class TestSubscriptionActiveCreatesNormalizedSubscription:
    def test_creates_pro_subscription_for_the_correct_workspace(self, db_session, workspace):
        event = _subscription_event("subscription.active", workspace.id, plan_id="pro", product_id="prod_pro_test")
        status = process_dodo_webhook(event, "evt_active_1", db_session)
        assert status == "processed"

        sub = (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == workspace.id)
            .first()
        )
        assert sub is not None
        assert sub.provider == "dodo"
        assert sub.plan_id == "pro"
        assert sub.status == NormalizedSubscriptionStatus.ACTIVE.value
        assert sub.workspace_id == workspace.id


# 3. subscription.updated updates the same row. ------------------------------


class TestSubscriptionUpdatedUpdatesSameRowNotADuplicate:
    def test_subsequent_update_mutates_the_created_row(self, db_session, workspace):
        process_dodo_webhook(
            _subscription_event("subscription.active", workspace.id, plan_id="pro"), "evt_active_2", db_session
        )
        status = process_dodo_webhook(
            _subscription_event("subscription.updated", workspace.id, plan_id="pro", status="active"),
            "evt_updated_2", db_session,
        )
        assert status == "processed"

        rows = (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == workspace.id)
            .all()
        )
        assert len(rows) == 1


# 4. Missing workspace metadata never mutates another workspace. -------------


class TestMissingWorkspaceMetadataNeverMutatesAnotherWorkspace:
    def test_event_without_metadata_leaves_unrelated_workspace_untouched(self, db_session, workspace, other_workspace):
        existing = NormalizedSubscription(
            workspace_id=other_workspace.id, provider="dodo", plan_id="pro", status="active",
            provider_customer_reference="cus_other", provider_subscription_reference="sub_other",
        )
        db_session.add(existing)
        db_session.commit()

        event = _subscription_event("subscription.active", workspace.id, include_metadata=False)
        status = process_dodo_webhook(event, "evt_no_meta", db_session)
        assert status == "unresolved_workspace"

        db_session.refresh(existing)
        assert existing.provider_subscription_reference == "sub_other"
        assert (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == workspace.id)
            .first()
            is None
        )


# 5. Malformed workspace UUID fails closed. ----------------------------------


class TestMalformedWorkspaceUuidFailsClosed:
    def test_malformed_workspace_id_creates_nothing(self, db_session, workspace):
        event = _subscription_event("subscription.active", workspace.id, plan_id="pro")
        event["data"]["metadata"]["workspace_id"] = "not-a-uuid"
        status = process_dodo_webhook(event, "evt_malformed", db_session)
        assert status == "unresolved_workspace"
        assert (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == workspace.id)
            .first()
            is None
        )


# 6. Unknown workspace UUID fails closed. ------------------------------------


class TestUnknownWorkspaceUuidFailsClosed:
    def test_well_formed_but_nonexistent_workspace_id_creates_nothing(self, db_session):
        fake_ws_id = _uuid.uuid4()
        event = _subscription_event("subscription.active", fake_ws_id, plan_id="pro")
        status = process_dodo_webhook(event, "evt_unknown_ws", db_session)
        assert status == "unresolved_workspace"
        assert (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == fake_ws_id)
            .first()
            is None
        )

    def test_unresolved_event_row_is_marked_failed_unknown_reference(self, db_session):
        fake_ws_id = _uuid.uuid4()
        event = _subscription_event("subscription.active", fake_ws_id, plan_id="pro")
        process_dodo_webhook(event, "evt_unknown_ws_row", db_session)

        row = (
            db_session.query(BillingWebhookEvent)
            .filter(BillingWebhookEvent.external_event_id == "evt_unknown_ws_row")
            .first()
        )
        assert row is not None
        assert row.processing_status == "failed"
        assert row.error_category == "unknown_reference"


# 7. Duplicate webhook remains idempotent. -----------------------------------


class TestDuplicateWebhookRemainsIdempotentAfterCreation:
    def test_replaying_subscription_active_does_not_duplicate_the_row(self, db_session, workspace):
        event = _subscription_event("subscription.active", workspace.id, plan_id="pro")
        first = process_dodo_webhook(event, "evt_dup_1", db_session)
        second = process_dodo_webhook(event, "evt_dup_1", db_session)
        assert first == "processed"
        assert second == "duplicate_ignored"

        rows = (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == workspace.id)
            .all()
        )
        assert len(rows) == 1


# 8. Payment + subscription event sequence -> exactly one row. --------------


class TestPaymentThenSubscriptionSequenceCreatesExactlyOneRow:
    def test_payment_succeeded_then_active_then_updated(self, db_session, workspace):
        payment_status = process_dodo_webhook(_payment_event(workspace.id, plan_id="pro"), "evt_seq_payment", db_session)
        assert payment_status == "processed"  # safe no-op — payment alone never creates a row
        assert (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == workspace.id)
            .first()
            is None
        )

        active_status = process_dodo_webhook(
            _subscription_event("subscription.active", workspace.id, plan_id="pro"), "evt_seq_active", db_session
        )
        assert active_status == "processed"

        updated_status = process_dodo_webhook(
            _subscription_event("subscription.updated", workspace.id, plan_id="pro"), "evt_seq_updated", db_session
        )
        assert updated_status == "processed"

        rows = (
            db_session.query(NormalizedSubscription)
            .filter(NormalizedSubscription.workspace_id == workspace.id)
            .all()
        )
        assert len(rows) == 1
        assert rows[0].status == NormalizedSubscriptionStatus.ACTIVE.value


# 9. GET /workspaces/{id}/billing reflects Pro after the sequence. ----------


class TestBillingEndpointReflectsProAfterSuccessfulSequence:
    def test_get_billing_subscription_shows_pro(self, client, db_session, workspace):
        process_dodo_webhook(_payment_event(workspace.id, plan_id="pro"), "evt_e2e_payment", db_session)
        process_dodo_webhook(
            _subscription_event("subscription.active", workspace.id, plan_id="pro"), "evt_e2e_active", db_session
        )
        db_session.commit()

        resp = client.get(f"/workspaces/{workspace.id}/billing/subscription")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan_id"] == "pro"
        assert body["provider"] == "dodo"
        assert body["has_paid_access"] is True


# 10. Existing Stripe/Paddle subscription routing remains unchanged. --------
#
# Covered by the existing, unmodified test_commercial_provider_routing.py
# and test_commercial_paddle_webhooks.py — run alongside these tests as
# part of this fix's validation rather than duplicated here, since nothing
# in provider_routing.py or the Paddle webhook service was touched by this
# change (only Dodo's own normalization/service files were).
