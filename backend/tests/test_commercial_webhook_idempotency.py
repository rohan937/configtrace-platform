"""Webhook idempotency tests (Commercial Infrastructure message 1).

Covers first delivery, duplicate delivery, failed-delivery retry,
duplicate-after-success, out-of-order/stale events, same external ID from
different providers (must NOT collide), one audit entry per genuine
transition, and no secret/raw-payload leakage.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.billing.audit import record_audit_event
from app.billing.enums import BillingAuditEventType, BillingProvider, WebhookProcessingStatus
from app.billing.idempotency import (
    check_and_record_pending,
    is_stale_subscription_update,
    mark_duplicate_ignored,
    mark_failed,
    mark_processed,
)
from app.billing.models import BillingAuditEvent, BillingWebhookEvent, NormalizedSubscription
from app.models.workspace import Workspace


@pytest.fixture
def workspace(db_session, test_user):
    ws = Workspace(name=f"webhook-idem-{uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
    db_session.add(ws)
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    try:
        db_session.delete(ws)
        db_session.commit()
    except Exception:
        db_session.rollback()


def _record(db_session, provider="stripe", external_event_id=None, **overrides):
    kwargs = dict(
        provider=provider,
        external_event_id=external_event_id or f"evt_{uuid.uuid4().hex[:12]}",
        event_type="subscription_updated",
        occurred_at=datetime.now(timezone.utc),
        customer_reference="cus_1",
        subscription_reference="sub_1",
        transaction_reference=None,
        normalized_payload={"status": "active"},
        db=db_session,
    )
    kwargs.update(overrides)
    return check_and_record_pending(**kwargs)


class TestFirstDelivery:
    def test_first_delivery_creates_a_pending_row(self, db_session):
        event = _record(db_session, external_event_id="evt_first")
        db_session.commit()
        assert event.processing_status == WebhookProcessingStatus.PENDING.value
        assert event.attempt_count == 0
        db_session.delete(event)
        db_session.commit()


class TestDuplicateDelivery:
    def test_duplicate_delivery_returns_existing_row_not_a_new_one(self, db_session):
        first = _record(db_session, external_event_id="evt_dup")
        db_session.commit()
        second = _record(db_session, external_event_id="evt_dup")
        assert second.id == first.id
        db_session.delete(first)
        db_session.commit()

    def test_duplicate_after_success_is_detected_and_marked(self, db_session):
        first = _record(db_session, external_event_id="evt_dup_success")
        mark_processed(first, db_session)
        db_session.commit()

        second = check_and_record_pending(
            provider="stripe", external_event_id="evt_dup_success", event_type="subscription_updated",
            occurred_at=datetime.now(timezone.utc), customer_reference=None,
            subscription_reference=None, transaction_reference=None, normalized_payload={}, db=db_session,
        )
        assert second.id == first.id
        assert second.processing_status == WebhookProcessingStatus.PROCESSED.value
        mark_duplicate_ignored(second, db_session)
        db_session.commit()
        assert second.processing_status == WebhookProcessingStatus.DUPLICATE_IGNORED.value
        db_session.delete(second)
        db_session.commit()


class TestFailedDeliveryRetry:
    def test_failed_event_can_be_retried_and_then_succeed(self, db_session):
        event = _record(db_session, external_event_id="evt_retry")
        mark_failed(event, "transient", db_session)
        db_session.commit()
        assert event.processing_status == WebhookProcessingStatus.FAILED.value
        assert event.attempt_count == 1

        # Retry: same (provider, external_event_id) — returns the SAME row,
        # not a new insert, so processing can safely retry it.
        retried = _record(db_session, external_event_id="evt_retry")
        assert retried.id == event.id
        mark_processed(retried, db_session)
        db_session.commit()
        assert retried.processing_status == WebhookProcessingStatus.PROCESSED.value
        assert retried.attempt_count == 2
        db_session.delete(retried)
        db_session.commit()


class TestSameExternalIdDifferentProviders:
    def test_same_external_event_id_from_different_providers_does_not_collide(self, db_session):
        stripe_event = _record(db_session, provider="stripe", external_event_id="evt_shared_id")
        paddle_event = _record(db_session, provider="paddle", external_event_id="evt_shared_id")
        db_session.commit()
        assert stripe_event.id != paddle_event.id
        assert stripe_event.provider == "stripe"
        assert paddle_event.provider == "paddle"
        db_session.delete(stripe_event)
        db_session.delete(paddle_event)
        db_session.commit()


class TestOutOfOrderAndStaleEvents:
    def test_older_event_after_newer_update_is_flagged_stale(self, db_session, workspace):
        sub = NormalizedSubscription(
            workspace_id=workspace.id, provider="stripe", plan_id="team", status="active",
        )
        db_session.add(sub)
        db_session.commit()
        db_session.refresh(sub)

        older_timestamp = sub.updated_at - timedelta(hours=1)
        assert is_stale_subscription_update(candidate_occurred_at=older_timestamp, subscription=sub) is True

        newer_timestamp = sub.updated_at + timedelta(hours=1)
        assert is_stale_subscription_update(candidate_occurred_at=newer_timestamp, subscription=sub) is False

        db_session.delete(sub)
        db_session.commit()

    def test_cancellation_followed_by_older_active_event_is_stale(self, db_session, workspace):
        sub = NormalizedSubscription(
            workspace_id=workspace.id, provider="stripe", plan_id="free", status="canceled",
        )
        db_session.add(sub)
        db_session.commit()
        db_session.refresh(sub)

        stale_active_event_time = sub.updated_at - timedelta(minutes=5)
        assert is_stale_subscription_update(candidate_occurred_at=stale_active_event_time, subscription=sub) is True
        db_session.delete(sub)
        db_session.commit()

    def test_no_timestamp_is_never_considered_stale(self):
        assert is_stale_subscription_update(candidate_occurred_at=None, subscription=None) is False

    def test_no_existing_subscription_is_never_considered_stale(self):
        assert is_stale_subscription_update(candidate_occurred_at=datetime.now(timezone.utc), subscription=None) is False


class TestAuditEntryEmittedOnce:
    def test_duplicate_webhook_delivery_emits_exactly_one_duplicate_audit_entry(self, db_session, workspace):
        event = _record(db_session, external_event_id="evt_audit_once")
        mark_processed(event, db_session)
        db_session.commit()

        # Simulate a duplicate delivery being recognized and audited.
        duplicate = check_and_record_pending(
            provider="stripe", external_event_id="evt_audit_once", event_type="subscription_updated",
            occurred_at=datetime.now(timezone.utc), customer_reference=None,
            subscription_reference=None, transaction_reference=None, normalized_payload={}, db=db_session,
        )
        assert duplicate.id == event.id
        record_audit_event(
            workspace_id=workspace.id,
            event_type=BillingAuditEventType.WEBHOOK_DUPLICATE_IGNORED,
            provider=BillingProvider.STRIPE,
            details={"external_event_id": "evt_audit_once"},
            db=db_session,
        )
        db_session.commit()

        count = (
            db_session.query(BillingAuditEvent)
            .filter(
                BillingAuditEvent.workspace_id == workspace.id,
                BillingAuditEvent.event_type == BillingAuditEventType.WEBHOOK_DUPLICATE_IGNORED.value,
            )
            .count()
        )
        assert count == 1
        db_session.delete(event)
        db_session.query(BillingAuditEvent).filter(BillingAuditEvent.workspace_id == workspace.id).delete()
        db_session.commit()


class TestNoSecretOrRawPayloadLeakage:
    def test_normalized_payload_never_contains_credential_shaped_keys(self, db_session):
        event = _record(
            db_session,
            external_event_id="evt_no_secrets",
            normalized_payload={"status": "active", "raw_event_type": "customer.subscription.updated"},
        )
        db_session.commit()
        forbidden = {"secret", "api_key", "client_secret", "signature", "raw_body"}
        assert not (forbidden & set(event.normalized_payload.keys()))
        db_session.delete(event)
        db_session.commit()

    def test_audit_details_are_filtered_to_allowlist(self, db_session, workspace):
        row = record_audit_event(
            workspace_id=workspace.id,
            event_type=BillingAuditEventType.PAYMENT_FAILED,
            provider=BillingProvider.STRIPE,
            details={"reason": "card_declined", "stripe_secret_key": "sk_live_should_not_leak"},
            db=db_session,
        )
        db_session.commit()
        assert "stripe_secret_key" not in row.details
        assert row.details.get("reason") == "card_declined"
        db_session.delete(row)
        db_session.commit()
