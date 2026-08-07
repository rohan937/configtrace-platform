"""Dodo webhook event normalization + end-to-end processing tests
(Dodo Payments message 1).

Fixtures are hand-built, sanitized representative payloads — no real
customer data, no real IDs.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.billing.dodo_webhook_service import (
    DodoWebhookProcessingError,
    normalize_dodo_status,
    process_dodo_webhook,
)
from app.billing.dodo_webhooks import normalize_dodo_event
from app.billing.enums import (
    BillingAuditEventType,
    NormalizedSubscriptionStatus,
    WebhookEventType,
    WebhookProcessingStatus,
)
from app.billing.models import BillingAuditEvent, BillingWebhookEvent, NormalizedSubscription
from app.models.workspace import Workspace


def _fixture(event_type: str, data: dict, timestamp: str = "2026-01-01T00:00:00Z") -> dict:
    return {"business_id": "biz_test", "type": event_type, "timestamp": timestamp, "data": data}


SUBSCRIPTION_ACTIVE = _fixture(
    "subscription.active",
    {"subscription_id": "sub_dodo_1", "customer": {"customer_id": "cus_dodo_1"}, "status": "active", "product_id": "prod_team_test"},
)
SUBSCRIPTION_UPDATED = _fixture(
    "subscription.updated",
    {"subscription_id": "sub_dodo_1", "customer": {"customer_id": "cus_dodo_1"}, "status": "active", "product_id": "prod_team_test"},
)
SUBSCRIPTION_PLAN_CHANGED = _fixture(
    "subscription.plan_changed",
    {"subscription_id": "sub_dodo_1", "customer": {"customer_id": "cus_dodo_1"}, "status": "active", "product_id": "prod_team_test"},
)
SUBSCRIPTION_ON_HOLD = _fixture(
    "subscription.on_hold",
    {"subscription_id": "sub_dodo_1", "customer": {"customer_id": "cus_dodo_1"}, "status": "on_hold"},
)
SUBSCRIPTION_CANCELLED = _fixture(
    "subscription.cancelled",
    {"subscription_id": "sub_dodo_1", "customer": {"customer_id": "cus_dodo_1"}, "status": "cancelled"},
)
SUBSCRIPTION_FAILED = _fixture(
    "subscription.failed",
    {"subscription_id": "sub_dodo_1", "customer": {"customer_id": "cus_dodo_1"}, "status": "failed"},
)
SUBSCRIPTION_EXPIRED = _fixture(
    "subscription.expired",
    {"subscription_id": "sub_dodo_1", "customer": {"customer_id": "cus_dodo_1"}, "status": "expired"},
)
PAYMENT_SUCCEEDED = _fixture(
    "payment.succeeded",
    {"payment_id": "pay_dodo_1", "subscription_id": "sub_dodo_1", "customer": {"customer_id": "cus_dodo_1"}},
)
PAYMENT_FAILED = _fixture(
    "payment.failed",
    {"payment_id": "pay_dodo_1", "subscription_id": "sub_dodo_1", "customer": {"customer_id": "cus_dodo_1"}},
)
DUNNING_STARTED = _fixture(
    "dunning.started",
    {"subscription_id": "sub_dodo_1", "customer": {"customer_id": "cus_dodo_1"}, "status": "on_hold"},
)
DUNNING_RECOVERED = _fixture(
    "dunning.recovered",
    {"subscription_id": "sub_dodo_1", "customer": {"customer_id": "cus_dodo_1"}},
)


class TestFixturesNormalizeCorrectly:
    def test_subscription_active(self):
        n = normalize_dodo_event(SUBSCRIPTION_ACTIVE, external_event_id="msg_1")
        assert n.event_type == WebhookEventType.SUBSCRIPTION_CREATED
        assert n.subscription_reference == "sub_dodo_1"
        assert n.customer_reference == "cus_dodo_1"
        assert n.external_event_id == "msg_1"

    def test_subscription_updated(self):
        n = normalize_dodo_event(SUBSCRIPTION_UPDATED, external_event_id="msg_2")
        assert n.event_type == WebhookEventType.SUBSCRIPTION_UPDATED

    def test_subscription_plan_changed(self):
        n = normalize_dodo_event(SUBSCRIPTION_PLAN_CHANGED, external_event_id="msg_3")
        assert n.event_type == WebhookEventType.SUBSCRIPTION_UPDATED

    def test_subscription_on_hold(self):
        n = normalize_dodo_event(SUBSCRIPTION_ON_HOLD, external_event_id="msg_4")
        assert n.event_type == WebhookEventType.PAYMENT_PAST_DUE

    def test_subscription_cancelled(self):
        n = normalize_dodo_event(SUBSCRIPTION_CANCELLED, external_event_id="msg_5")
        assert n.event_type == WebhookEventType.SUBSCRIPTION_CANCELED
        assert n.subscription_status == "cancelled"

    def test_subscription_failed(self):
        n = normalize_dodo_event(SUBSCRIPTION_FAILED, external_event_id="msg_6")
        assert n.event_type == WebhookEventType.TRANSACTION_FAILED

    def test_subscription_expired(self):
        n = normalize_dodo_event(SUBSCRIPTION_EXPIRED, external_event_id="msg_7")
        assert n.event_type == WebhookEventType.SUBSCRIPTION_CANCELED
        assert n.raw_event_name == "subscription.expired"

    def test_payment_succeeded(self):
        n = normalize_dodo_event(PAYMENT_SUCCEEDED, external_event_id="msg_8")
        assert n.event_type == WebhookEventType.TRANSACTION_COMPLETED
        assert n.transaction_reference == "pay_dodo_1"

    def test_payment_failed(self):
        n = normalize_dodo_event(PAYMENT_FAILED, external_event_id="msg_9")
        assert n.event_type == WebhookEventType.TRANSACTION_FAILED

    def test_dunning_started(self):
        n = normalize_dodo_event(DUNNING_STARTED, external_event_id="msg_10")
        assert n.event_type == WebhookEventType.PAYMENT_PAST_DUE

    def test_dunning_recovered(self):
        n = normalize_dodo_event(DUNNING_RECOVERED, external_event_id="msg_11")
        assert n.event_type == WebhookEventType.TRANSACTION_COMPLETED


class TestUnknownEventsSafelyAcknowledged:
    def test_unrecognized_event_name_maps_to_unknown(self):
        fixture = _fixture("refund.succeeded", {"id": "x"})
        n = normalize_dodo_event(fixture, external_event_id="msg_x")
        assert n.event_type == WebhookEventType.UNKNOWN

    def test_unknown_event_still_carries_raw_event_name(self):
        fixture = _fixture("dispute.opened", {"id": "x"})
        n = normalize_dodo_event(fixture, external_event_id="msg_y")
        assert n.raw_event_name == "dispute.opened"


class TestNormalizationSafety:
    def test_occurred_at_parsed(self):
        n = normalize_dodo_event(SUBSCRIPTION_ACTIVE, external_event_id="msg_1")
        assert n.occurred_at is not None
        assert n.occurred_at.year == 2026

    def test_malformed_timestamp_yields_none_not_exception(self):
        fixture = _fixture("subscription.active", {"subscription_id": "s"}, timestamp="not-a-timestamp")
        n = normalize_dodo_event(fixture, external_event_id="msg_z")
        assert n.occurred_at is None

    def test_normalized_payload_never_carries_full_customer_object(self):
        n = normalize_dodo_event(SUBSCRIPTION_ACTIVE, external_event_id="msg_1")
        assert "customer" not in n.normalized_payload
        assert set(n.normalized_payload.keys()) <= {"raw_event_name", "status"}


class TestStatusNormalization:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("pending", NormalizedSubscriptionStatus.INCOMPLETE),
            ("active", NormalizedSubscriptionStatus.ACTIVE),
            ("on_hold", NormalizedSubscriptionStatus.PAST_DUE),
            ("cancelled", NormalizedSubscriptionStatus.CANCELED),
            ("failed", NormalizedSubscriptionStatus.INCOMPLETE),
            ("expired", NormalizedSubscriptionStatus.EXPIRED),
        ],
    )
    def test_known_statuses_map_correctly(self, raw, expected):
        assert normalize_dodo_status(raw) == expected

    def test_unknown_status_maps_to_incomplete(self):
        assert normalize_dodo_status("some_future_status") == NormalizedSubscriptionStatus.INCOMPLETE

    @pytest.mark.parametrize(
        "already_normalized",
        [
            NormalizedSubscriptionStatus.TRIALING,
            NormalizedSubscriptionStatus.ACTIVE,
            NormalizedSubscriptionStatus.PAST_DUE,
            NormalizedSubscriptionStatus.GRACE_PERIOD,
            NormalizedSubscriptionStatus.PAUSED,
            NormalizedSubscriptionStatus.CANCELED,
            NormalizedSubscriptionStatus.EXPIRED,
            NormalizedSubscriptionStatus.INCOMPLETE,
        ],
    )
    def test_re_normalizing_an_already_normalized_value_is_a_safe_no_op(self, already_normalized):
        """Regression test for a real bug found during Test Mode
        verification: app/routers/billing.py's get_current_subscription
        re-runs normalize_dodo_status on NormalizedSubscription.status,
        which already holds a normalized value (written by
        _apply_normalized_event). Before this fix, re-normalizing
        "past_due" fell through to INCOMPLETE (Dodo's raw vocabulary
        spells it "on_hold", not "past_due"), silently revoking paid
        access for any Dodo subscription read after being set to
        past_due/paused/trialing/grace_period/incomplete."""
        assert normalize_dodo_status(already_normalized.value) == already_normalized


# ── End-to-end processing (real Postgres-backed rows) ───────────────────────


@pytest.fixture
def e2e_workspace(db_session, test_user):
    ws = Workspace(name=f"dodo-webhook-e2e-{_uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(BillingAuditEvent).filter(BillingAuditEvent.workspace_id == ws.id).delete()
    db_session.query(BillingWebhookEvent).delete()
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.delete(ws)
    db_session.commit()


def _fresh(event: dict, event_id_suffix: str = "", **data_overrides: object) -> tuple[dict, str]:
    fresh = dict(event)
    fresh["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if data_overrides:
        fresh["data"] = {**fresh["data"], **data_overrides}
    return fresh, f"msg_fresh{event_id_suffix or _uuid.uuid4().hex[:8]}"


def _local_sub(db_session, workspace, **overrides):
    kwargs = dict(
        workspace_id=workspace.id, provider="dodo", provider_customer_reference="cus_dodo_1",
        provider_subscription_reference="sub_dodo_1", plan_id="team", status="active",
    )
    kwargs.update(overrides)
    sub = NormalizedSubscription(**kwargs)
    db_session.add(sub)
    db_session.commit()
    db_session.refresh(sub)
    return sub


class TestFirstDeliveryProcessed:
    def test_subscription_active_updates_local_status(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="incomplete")
        event, event_id = _fresh(SUBSCRIPTION_ACTIVE, status="active")
        status = process_dodo_webhook(event, event_id, db_session)
        db_session.refresh(sub)
        assert status == "processed"
        assert sub.status == "active"


class TestDuplicateDeliveryReturnsSuccessNoDuplicateMutation:
    def test_duplicate_delivery_does_not_reapply_or_error(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="incomplete")
        event, event_id = _fresh(SUBSCRIPTION_ACTIVE, status="active")
        process_dodo_webhook(event, event_id, db_session)
        version_after_first = sub.version

        status = process_dodo_webhook(event, event_id, db_session)
        db_session.refresh(sub)
        assert status == "duplicate_ignored"
        assert sub.version == version_after_first

    def test_duplicate_delivery_does_not_create_duplicate_audit_entry(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="active")
        event, event_id = _fresh(SUBSCRIPTION_CANCELLED)
        process_dodo_webhook(event, event_id, db_session)
        count_after_first = (
            db_session.query(BillingAuditEvent)
            .filter(BillingAuditEvent.workspace_id == e2e_workspace.id, BillingAuditEvent.event_type == BillingAuditEventType.SUBSCRIPTION_CANCELED.value)
            .count()
        )
        process_dodo_webhook(event, event_id, db_session)
        count_after_second = (
            db_session.query(BillingAuditEvent)
            .filter(BillingAuditEvent.workspace_id == e2e_workspace.id, BillingAuditEvent.event_type == BillingAuditEventType.SUBSCRIPTION_CANCELED.value)
            .count()
        )
        assert count_after_first == 1
        assert count_after_second == 1


class TestUnsupportedEventNeverMutatesState:
    def test_unsupported_event_leaves_subscription_untouched(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="active")
        version_before = sub.version
        event, event_id = _fresh(_fixture("refund.succeeded", {"id": "sub_dodo_1"}))
        status = process_dodo_webhook(event, event_id, db_session)
        db_session.refresh(sub)
        assert status == "unknown_event_acknowledged"
        assert sub.status == "active"
        assert sub.version == version_before


class TestOutOfOrderEventIgnored:
    def test_stale_active_event_after_newer_cancellation_is_ignored(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="cancelled")
        stale_event = _fixture(
            "subscription.updated",
            {"subscription_id": "sub_dodo_1", "customer": {"customer_id": "cus_dodo_1"}, "status": "active"},
            timestamp="2020-01-01T00:00:00Z",  # long before sub.updated_at
        )
        process_dodo_webhook(stale_event, "msg_stale", db_session)
        db_session.refresh(sub)
        assert sub.status == "cancelled"  # unchanged — stale event ignored


class TestUnknownSubscriptionReferenceWithoutMetadataFailsClosed:
    def test_lifecycle_event_for_unknown_subscription_reference_and_no_metadata_is_unresolved(
        self, db_session, e2e_workspace
    ):
        """A lifecycle event (subscription.updated) that matches no
        existing row AND carries no checkout-metadata workspace_id hint
        can never be associated with a workspace — this must be reported
        as "unresolved_workspace" (BillingWebhookEvent processing_status
        = failed / error_category = unknown_reference), never silently
        "processed", per the production bug this fixes: a real Dodo
        subscription.active/updated reported "processed" while no
        NormalizedSubscription row was ever created."""
        event = dict(SUBSCRIPTION_UPDATED)
        event["data"] = {**event["data"], "subscription_id": "sub_completely_unknown"}
        status = process_dodo_webhook(event, "msg_unknown_sub", db_session)
        assert status == "unresolved_workspace"


class TestPaymentFailureAndRecovery:
    def test_payment_failed_sets_past_due_and_grace_period(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="active")
        event, event_id = _fresh(PAYMENT_FAILED)
        process_dodo_webhook(event, event_id, db_session)
        db_session.refresh(sub)
        assert sub.status == "past_due"
        assert sub.grace_period_end is not None

    def test_successful_payment_recovers_from_past_due(self, db_session, e2e_workspace):
        sub = _local_sub(
            db_session, e2e_workspace, status="past_due",
            grace_period_end=datetime.now(timezone.utc) + timedelta(days=3),
        )
        event, event_id = _fresh(PAYMENT_SUCCEEDED)
        process_dodo_webhook(event, event_id, db_session)
        db_session.refresh(sub)
        assert sub.status == "active"
        assert sub.grace_period_end is None

    def test_dunning_started_sets_past_due(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="active")
        event, event_id = _fresh(DUNNING_STARTED)
        process_dodo_webhook(event, event_id, db_session)
        db_session.refresh(sub)
        assert sub.status == "past_due"

    def test_dunning_recovered_restores_active(self, db_session, e2e_workspace):
        sub = _local_sub(
            db_session, e2e_workspace, status="past_due",
            grace_period_end=datetime.now(timezone.utc) + timedelta(days=1),
        )
        event, event_id = _fresh(DUNNING_RECOVERED)
        process_dodo_webhook(event, event_id, db_session)
        db_session.refresh(sub)
        assert sub.status == "active"


class TestExpiredEventSetsExactExpiredStatus:
    def test_subscription_expired_sets_expired_not_canceled(self, db_session, e2e_workspace):
        sub = _local_sub(db_session, e2e_workspace, status="past_due")
        event, event_id = _fresh(SUBSCRIPTION_EXPIRED)
        process_dodo_webhook(event, event_id, db_session)
        db_session.refresh(sub)
        assert sub.status == NormalizedSubscriptionStatus.EXPIRED.value
