"""Provider-neutral webhook event normalization tests (Commercial Infrastructure message 1)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.billing.enums import BillingProvider, WebhookEventType
from app.billing.events import normalize_stripe_event


def _stripe_event(event_type: str, obj: dict, event_id: str = "evt_123", created: int | None = 1700000000):
    return {
        "id": event_id,
        "type": event_type,
        "created": created,
        "data": {"object": obj},
    }


class TestNormalizedEventTypes:
    @pytest.mark.parametrize(
        "stripe_type,expected",
        [
            ("checkout.session.completed", WebhookEventType.SUBSCRIPTION_CREATED),
            ("customer.subscription.created", WebhookEventType.SUBSCRIPTION_CREATED),
            ("customer.subscription.updated", WebhookEventType.SUBSCRIPTION_UPDATED),
            ("customer.subscription.deleted", WebhookEventType.SUBSCRIPTION_CANCELED),
            ("customer.subscription.paused", WebhookEventType.SUBSCRIPTION_PAUSED),
            ("customer.subscription.resumed", WebhookEventType.SUBSCRIPTION_RESUMED),
            ("invoice.payment_failed", WebhookEventType.TRANSACTION_FAILED),
            ("invoice.payment_succeeded", WebhookEventType.TRANSACTION_COMPLETED),
            ("invoice.paid", WebhookEventType.TRANSACTION_COMPLETED),
            ("customer.updated", WebhookEventType.CUSTOMER_UPDATED),
        ],
    )
    def test_stripe_event_type_maps_correctly(self, stripe_type, expected):
        event = _stripe_event(stripe_type, {"id": "sub_1", "customer": "cus_1"})
        normalized = normalize_stripe_event(event)
        assert normalized.event_type == expected
        assert normalized.provider == BillingProvider.STRIPE

    def test_unrecognized_stripe_event_type_maps_to_unknown(self):
        event = _stripe_event("some.future.event", {})
        normalized = normalize_stripe_event(event)
        assert normalized.event_type == WebhookEventType.UNKNOWN


class TestReferenceExtraction:
    def test_subscription_event_extracts_subscription_and_customer_reference(self):
        event = _stripe_event(
            "customer.subscription.updated", {"id": "sub_abc", "customer": "cus_xyz", "status": "active"}
        )
        normalized = normalize_stripe_event(event)
        assert normalized.subscription_reference == "sub_abc"
        assert normalized.customer_reference == "cus_xyz"

    def test_invoice_event_extracts_transaction_reference(self):
        event = _stripe_event(
            "invoice.payment_failed", {"id": "in_123", "customer": "cus_xyz", "subscription": "sub_abc"}
        )
        normalized = normalize_stripe_event(event)
        assert normalized.transaction_reference == "in_123"
        assert normalized.subscription_reference == "sub_abc"


class TestOccurredAt:
    def test_created_timestamp_converted_to_utc_datetime(self):
        event = _stripe_event("customer.updated", {}, created=1700000000)
        normalized = normalize_stripe_event(event)
        assert normalized.occurred_at == datetime.fromtimestamp(1700000000, tz=timezone.utc)

    def test_missing_created_timestamp_yields_none(self):
        event = _stripe_event("customer.updated", {}, created=None)
        normalized = normalize_stripe_event(event)
        assert normalized.occurred_at is None


class TestNoRawPayloadPersisted:
    def test_normalized_payload_is_small_allowlisted_summary_not_full_object(self):
        obj = {
            "id": "sub_1",
            "customer": "cus_1",
            "status": "active",
            "some_future_sensitive_looking_field": "should-not-appear",
        }
        event = _stripe_event("customer.subscription.updated", obj)
        normalized = normalize_stripe_event(event)
        assert "some_future_sensitive_looking_field" not in normalized.normalized_payload
        assert set(normalized.normalized_payload.keys()) <= {"raw_event_type", "status"}


class TestExternalEventId:
    def test_external_event_id_extracted(self):
        event = _stripe_event("customer.updated", {}, event_id="evt_unique_1")
        normalized = normalize_stripe_event(event)
        assert normalized.external_event_id == "evt_unique_1"
