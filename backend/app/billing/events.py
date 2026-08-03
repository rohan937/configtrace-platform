"""Provider-neutral webhook event normalization (Commercial Infrastructure message 1).

Only Stripe normalization is implemented in message 1 (Paddle has no live
webhooks yet — message-1 spec item 16/24). Adding Paddle normalization in a
future message means adding one function here; existing call sites are
unaffected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.billing.enums import BillingProvider, WebhookEventType

# Existing Stripe event types actually handled by
# app.services.billing_service.handle_webhook_event, mapped to the
# normalized taxonomy (message-1 spec item 24).
_STRIPE_EVENT_TYPE_MAP: dict[str, WebhookEventType] = {
    "checkout.session.completed": WebhookEventType.SUBSCRIPTION_CREATED,
    "customer.subscription.created": WebhookEventType.SUBSCRIPTION_CREATED,
    "customer.subscription.updated": WebhookEventType.SUBSCRIPTION_UPDATED,
    "customer.subscription.deleted": WebhookEventType.SUBSCRIPTION_CANCELED,
    "customer.subscription.paused": WebhookEventType.SUBSCRIPTION_PAUSED,
    "customer.subscription.resumed": WebhookEventType.SUBSCRIPTION_RESUMED,
    "invoice.payment_failed": WebhookEventType.TRANSACTION_FAILED,
    "invoice.payment_succeeded": WebhookEventType.TRANSACTION_COMPLETED,
    "invoice.paid": WebhookEventType.TRANSACTION_COMPLETED,
    "customer.updated": WebhookEventType.CUSTOMER_UPDATED,
}


@dataclass(frozen=True)
class NormalizedWebhookEvent:
    """Provider-neutral, allowlisted summary of one webhook event — never
    the raw provider payload (message-1 spec item 23)."""

    provider: BillingProvider
    external_event_id: str
    event_type: WebhookEventType
    occurred_at: datetime | None
    customer_reference: str | None
    subscription_reference: str | None
    transaction_reference: str | None
    normalized_payload: dict = field(default_factory=dict)


def normalize_stripe_event(event: dict[str, Any]) -> NormalizedWebhookEvent:
    """Normalize a verified, parsed Stripe webhook event dict (the output
    of ``billing_service.verify_stripe_signature``) into a
    ``NormalizedWebhookEvent``. Only a small, allowlisted set of fields is
    ever extracted — never the full raw object."""
    event_id = event.get("id", "")
    event_type_raw = event.get("type", "")
    data_obj = event.get("data", {}).get("object", {})
    created = event.get("created")

    normalized_type = _STRIPE_EVENT_TYPE_MAP.get(event_type_raw, WebhookEventType.UNKNOWN)

    customer_ref = data_obj.get("customer")
    subscription_ref = data_obj.get("id") if event_type_raw.startswith("customer.subscription") else data_obj.get("subscription")
    transaction_ref = data_obj.get("id") if event_type_raw.startswith("invoice") else None

    occurred_at = (
        datetime.fromtimestamp(created, tz=timezone.utc) if isinstance(created, (int, float)) else None
    )

    return NormalizedWebhookEvent(
        provider=BillingProvider.STRIPE,
        external_event_id=event_id,
        event_type=normalized_type,
        occurred_at=occurred_at,
        customer_reference=customer_ref,
        subscription_reference=subscription_ref,
        transaction_reference=transaction_ref,
        normalized_payload={
            "raw_event_type": event_type_raw,
            "status": data_obj.get("status"),
        },
    )
