"""Paddle webhook event normalization + fixture tests (Commercial Infrastructure message 2).

Fixtures are hand-built, sanitized representative payloads — no real
customer data, no real IDs.
"""

from __future__ import annotations

from app.billing.enums import BillingProvider, WebhookEventType
from app.billing.paddle_webhooks import normalize_paddle_event


def _fixture(event_type: str, data: dict, event_id: str = "ntf_01test", occurred_at: str = "2026-01-01T00:00:00.000000Z") -> dict:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "occurred_at": occurred_at,
        "data": data,
    }


SUBSCRIPTION_CREATED = _fixture(
    "subscription.created",
    {"id": "sub_01test", "customer_id": "ctm_01test", "status": "active", "items": []},
)
SUBSCRIPTION_UPDATED = _fixture(
    "subscription.updated",
    {"id": "sub_01test", "customer_id": "ctm_01test", "status": "active", "items": []},
)
SUBSCRIPTION_CANCELED = _fixture(
    "subscription.canceled",
    {"id": "sub_01test", "customer_id": "ctm_01test", "status": "canceled", "items": []},
)
SUBSCRIPTION_PAUSED = _fixture(
    "subscription.paused",
    {"id": "sub_01test", "customer_id": "ctm_01test", "status": "paused", "items": []},
)
SUBSCRIPTION_RESUMED = _fixture(
    "subscription.resumed",
    {"id": "sub_01test", "customer_id": "ctm_01test", "status": "active", "items": []},
)
TRANSACTION_COMPLETED = _fixture(
    "transaction.completed",
    {"id": "txn_01test", "subscription_id": "sub_01test", "customer_id": "ctm_01test", "status": "completed"},
)
TRANSACTION_PAYMENT_FAILED = _fixture(
    "transaction.payment_failed",
    {"id": "txn_01test", "subscription_id": "sub_01test", "customer_id": "ctm_01test", "status": "past_due"},
)
CUSTOMER_UPDATED = _fixture(
    "customer.updated",
    {"id": "ctm_01test", "email": "billing-contact@example.test"},
)


class TestFixturesNormalizeCorrectly:
    def test_subscription_created(self):
        n = normalize_paddle_event(SUBSCRIPTION_CREATED)
        assert n.event_type == WebhookEventType.SUBSCRIPTION_CREATED
        assert n.provider == BillingProvider.PADDLE
        assert n.subscription_reference == "sub_01test"
        assert n.customer_reference == "ctm_01test"

    def test_subscription_updated(self):
        n = normalize_paddle_event(SUBSCRIPTION_UPDATED)
        assert n.event_type == WebhookEventType.SUBSCRIPTION_UPDATED

    def test_subscription_canceled(self):
        n = normalize_paddle_event(SUBSCRIPTION_CANCELED)
        assert n.event_type == WebhookEventType.SUBSCRIPTION_CANCELED
        assert n.subscription_status == "canceled"

    def test_subscription_paused(self):
        n = normalize_paddle_event(SUBSCRIPTION_PAUSED)
        assert n.event_type == WebhookEventType.SUBSCRIPTION_PAUSED

    def test_subscription_resumed(self):
        n = normalize_paddle_event(SUBSCRIPTION_RESUMED)
        assert n.event_type == WebhookEventType.SUBSCRIPTION_RESUMED

    def test_transaction_completed(self):
        n = normalize_paddle_event(TRANSACTION_COMPLETED)
        assert n.event_type == WebhookEventType.TRANSACTION_COMPLETED
        assert n.transaction_reference == "txn_01test"
        assert n.subscription_reference == "sub_01test"

    def test_transaction_payment_failed(self):
        n = normalize_paddle_event(TRANSACTION_PAYMENT_FAILED)
        assert n.event_type == WebhookEventType.TRANSACTION_FAILED

    def test_customer_updated(self):
        n = normalize_paddle_event(CUSTOMER_UPDATED)
        assert n.event_type == WebhookEventType.CUSTOMER_UPDATED
        assert n.customer_reference is None or n.customer_reference == CUSTOMER_UPDATED["data"].get("customer_id")


class TestSubscriptionPastDue:
    def test_subscription_past_due_maps_to_payment_past_due(self):
        fixture = _fixture(
            "subscription.past_due", {"id": "sub_01test", "customer_id": "ctm_01test", "status": "past_due"}
        )
        n = normalize_paddle_event(fixture)
        assert n.event_type == WebhookEventType.PAYMENT_PAST_DUE


class TestUnknownEventsSafelyAcknowledged:
    def test_unrecognized_event_name_maps_to_unknown(self):
        fixture = _fixture("some.future.paddle.event", {"id": "x"})
        n = normalize_paddle_event(fixture)
        assert n.event_type == WebhookEventType.UNKNOWN

    def test_unknown_event_still_carries_raw_event_name_for_audit(self):
        fixture = _fixture("some.future.paddle.event", {"id": "x"})
        n = normalize_paddle_event(fixture)
        assert n.raw_event_name == "some.future.paddle.event"


class TestNoRealCustomerDataInFixtures:
    def test_fixture_ids_are_obviously_synthetic(self):
        for fixture in (
            SUBSCRIPTION_CREATED, SUBSCRIPTION_UPDATED, SUBSCRIPTION_CANCELED,
            SUBSCRIPTION_PAUSED, SUBSCRIPTION_RESUMED, TRANSACTION_COMPLETED,
            TRANSACTION_PAYMENT_FAILED, CUSTOMER_UPDATED,
        ):
            assert "test" in str(fixture["data"].get("id", "")) or "test" in str(fixture["data"].get("customer_id", ""))


class TestOccurredAtParsing:
    def test_iso_timestamp_parsed(self):
        n = normalize_paddle_event(SUBSCRIPTION_CREATED)
        assert n.occurred_at is not None
        assert n.occurred_at.year == 2026

    def test_missing_occurred_at_yields_none(self):
        fixture = dict(SUBSCRIPTION_CREATED)
        fixture.pop("occurred_at")
        n = normalize_paddle_event(fixture)
        assert n.occurred_at is None

    def test_malformed_occurred_at_yields_none_not_exception(self):
        fixture = dict(SUBSCRIPTION_CREATED)
        fixture["occurred_at"] = "not-a-timestamp"
        n = normalize_paddle_event(fixture)
        assert n.occurred_at is None


class TestNormalizedPayloadIsSmallAndSafe:
    def test_normalized_payload_never_carries_email(self):
        n = normalize_paddle_event(CUSTOMER_UPDATED)
        assert "email" not in n.normalized_payload


# ── End-to-end webhook processing (idempotency + ordering) ──────────────────

import uuid as _uuid

import pytest as _pytest

from app.billing.enums import BillingAuditEventType, NormalizedSubscriptionStatus, WebhookProcessingStatus
from app.billing.models import BillingAuditEvent, BillingWebhookEvent, NormalizedSubscription
from app.billing.paddle_webhook_service import PaddleWebhookProcessingError, process_paddle_webhook
from app.models.workspace import Workspace


@_pytest.fixture
def e2e_workspace(db_session, test_user):
    ws = Workspace(name=f"paddle-webhook-e2e-{_uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(BillingAuditEvent).filter(BillingAuditEvent.workspace_id == ws.id).delete()
    db_session.query(BillingWebhookEvent).delete()
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.delete(ws)
    db_session.commit()


def _fresh(event: dict, **data_overrides: object) -> dict:
    """Return a copy of `event` with `occurred_at` stamped to right now
    and any data fields overridden — avoids the fixed-past-timestamp
    fixtures being treated as stale relative to a subscription row
    created moments ago in the test."""
    from datetime import datetime, timezone

    fresh = dict(event)
    fresh["occurred_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if data_overrides:
        fresh["data"] = {**fresh["data"], **data_overrides}
    return fresh


def _local_sub(db_session, workspace, **overrides):
    kwargs = dict(
        workspace_id=workspace.id, provider="paddle", provider_customer_reference="ctm_01test",
        provider_subscription_reference="sub_01test", plan_id="team", status="active",
    )
    kwargs.update(overrides)
    sub = NormalizedSubscription(**kwargs)
    db_session.add(sub)
    db_session.commit()
    db_session.refresh(sub)
    return sub


class TestFirstDeliveryProcessed:
    def test_subscription_created_updates_local_status(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="incomplete")
        event = _fresh(SUBSCRIPTION_CREATED, status="active")
        status = process_paddle_webhook(event, db_session)
        db_session.refresh(sub)
        assert status == "processed"
        assert sub.status == "active"


class TestDuplicateDeliveryReturnsSuccessNoDuplicateMutation:
    def test_duplicate_delivery_does_not_reapply_or_error(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="incomplete")
        event = _fresh(SUBSCRIPTION_CREATED, status="active")
        process_paddle_webhook(event, db_session)
        version_after_first = sub.version

        status = process_paddle_webhook(event, db_session)
        db_session.refresh(sub)
        assert status == "duplicate_ignored"
        assert sub.version == version_after_first  # no duplicate mutation

    def test_duplicate_delivery_does_not_create_duplicate_audit_entry(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="active")
        event = _fresh(SUBSCRIPTION_CANCELED)
        process_paddle_webhook(event, db_session)
        count_after_first = (
            db_session.query(BillingAuditEvent)
            .filter(BillingAuditEvent.workspace_id == e2e_workspace.id, BillingAuditEvent.event_type == BillingAuditEventType.SUBSCRIPTION_CANCELED.value)
            .count()
        )
        process_paddle_webhook(event, db_session)
        count_after_second = (
            db_session.query(BillingAuditEvent)
            .filter(BillingAuditEvent.workspace_id == e2e_workspace.id, BillingAuditEvent.event_type == BillingAuditEventType.SUBSCRIPTION_CANCELED.value)
            .count()
        )
        assert count_after_first == 1
        assert count_after_second == 1


class TestUnknownEventNeverMutatesState:
    def test_unknown_event_leaves_subscription_untouched(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="active")
        version_before = sub.version
        event = _fixture("some.future.event", {"id": "sub_01test", "customer_id": "ctm_01test"})
        status = process_paddle_webhook(event, db_session)
        db_session.refresh(sub)
        assert status == "unknown_event_acknowledged"
        assert sub.status == "active"
        assert sub.version == version_before


class TestOlderActiveEventAfterCancellation:
    def test_stale_active_event_after_newer_cancellation_is_ignored(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="canceled")
        stale_event = _fixture(
            "subscription.updated",
            {"id": "sub_01test", "customer_id": "ctm_01test", "status": "active"},
            event_id="ntf_stale",
            occurred_at="2020-01-01T00:00:00.000000Z",  # long before sub.updated_at
        )
        process_paddle_webhook(stale_event, db_session)
        db_session.refresh(sub)
        assert sub.status == "canceled"  # unchanged — stale event ignored


class TestWrongWorkspaceCustomData:
    def test_event_for_unknown_subscription_reference_is_a_safe_no_op(self, db_session, e2e_workspace):
        """No local row matches this subscription_reference — processed
        without raising and without fabricating a workspace."""
        event = dict(SUBSCRIPTION_UPDATED)
        event["data"] = {**event["data"], "id": "sub_completely_unknown"}
        status = process_paddle_webhook(event, db_session)
        assert status == "processed"  # acknowledged; no row to mutate


class TestPaymentFailureAndRecovery:
    def test_payment_failed_sets_past_due_and_grace_period(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="active")
        process_paddle_webhook(_fresh(TRANSACTION_PAYMENT_FAILED), db_session)
        db_session.refresh(sub)
        assert sub.status == "past_due"
        assert sub.grace_period_end is not None

    def test_successful_transaction_recovers_from_past_due(self, db_session, e2e_workspace):
        from datetime import datetime, timedelta, timezone

        sub = _local_sub(db_session, e2e_workspace, status="past_due", grace_period_end=datetime.now(timezone.utc) + timedelta(days=3))
        recovery_event = _fresh(TRANSACTION_COMPLETED)
        recovery_event["event_id"] = "ntf_recovery"
        process_paddle_webhook(recovery_event, db_session)
        db_session.refresh(sub)
        assert sub.status == "active"
        assert sub.grace_period_end is None
