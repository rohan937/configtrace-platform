"""Paddle webhook signature verification and event normalization
(Commercial Infrastructure message 2).

Signature scheme (Paddle Billing)
----------------------------------
Paddle signs webhook notifications with the ``Paddle-Signature`` header:

    ts=<unix_timestamp>;h1=<hex_hmac_sha256>

where ``hex_hmac_sha256 = HMAC-SHA256(webhook_secret, f"{ts}:{raw_body}")``,
computed over the EXACT raw request body bytes — never a re-serialized
JSON representation, which could differ in key ordering/whitespace from
what Paddle actually signed. This mirrors the existing Stripe signature
verification pattern in ``app/services/billing_service.py`` almost
exactly (Stripe: ``f"{ts}.{raw_body}"`` with ``t=``/``v1=`` keys; Paddle:
``f"{ts}:{raw_body}"`` with ``ts=``/``h1=`` keys).

Documented limitation: this implementation is written from Paddle's
publicly documented webhook signature scheme as of this message's
authoring; it has not been verified against a live Paddle sandbox
notification in this message (see
``commercial_infrastructure_paddle_security_review.md`` for the explicit
verification-pending note). The verification logic is intentionally
narrow and testable against fixture signatures so a real sandbox delivery
can validate it in a follow-up smoke test without changing this module's
shape.

Event mapping
--------------
Maps actual Paddle Billing event names into the message-1
``WebhookEventType`` normalized taxonomy. Unknown/unrecognized event names
map to ``WebhookEventType.UNKNOWN`` — acknowledged and auditable, but
NEVER mutate subscription state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.billing.enums import BillingProvider, WebhookEventType

_DEFAULT_TOLERANCE_SECONDS = 300  # 5 minutes — matches the existing Stripe tolerance


class PaddleSignatureError(ValueError):
    """Raised for any signature verification failure — missing header,
    malformed header, invalid HMAC, or stale timestamp. Never includes the
    webhook secret or the full raw body in its message."""


def verify_paddle_signature(
    raw_body: bytes, sig_header: str, webhook_secret: str, *, tolerance_seconds: int = _DEFAULT_TOLERANCE_SECONDS
) -> dict[str, Any]:
    """Verify a Paddle-Signature header against the raw body and return
    the parsed JSON event dict.

    Raises ``PaddleSignatureError`` on any failure:
      * missing/empty header
      * malformed header (no ts=/h1= pairs)
      * multiple h1 values, none of which match (constant-time compared)
      * timestamp outside ``tolerance_seconds`` of "now"
      * HMAC mismatch (modified body or wrong secret)
    """
    if not webhook_secret:
        raise PaddleSignatureError("Paddle webhook secret is not configured.")
    if not sig_header:
        raise PaddleSignatureError("Missing Paddle-Signature header.")

    pairs: dict[str, list[str]] = {}
    for part in sig_header.split(";"):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        pairs.setdefault(key.strip(), []).append(value.strip())

    timestamps = pairs.get("ts", [])
    signatures = pairs.get("h1", [])
    if not timestamps or not signatures:
        raise PaddleSignatureError("Malformed Paddle-Signature header.")

    timestamp_str = timestamps[0]
    try:
        ts = int(timestamp_str)
    except ValueError:
        raise PaddleSignatureError("Non-integer timestamp in Paddle-Signature header.")

    if abs(time.time() - ts) > tolerance_seconds:
        raise PaddleSignatureError(f"Paddle webhook timestamp too old or too far in the future: {ts}")

    signed_payload = f"{timestamp_str}:{raw_body.decode('utf-8')}"
    expected = hmac.new(webhook_secret.encode("utf-8"), signed_payload.encode("utf-8"), hashlib.sha256).hexdigest()

    # Multiple h1 values may be present during a secret-rotation window —
    # accept if ANY one matches, constant-time compared against each.
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise PaddleSignatureError("Paddle webhook signature mismatch.")

    return json.loads(raw_body)


# Actual Paddle Billing v2 event names mapped to the message-1 normalized
# taxonomy. See this module's docstring for the documented
# verification-pending caveat on exact event-name coverage.
_PADDLE_EVENT_TYPE_MAP: dict[str, WebhookEventType] = {
    "subscription.created": WebhookEventType.SUBSCRIPTION_CREATED,
    "subscription.updated": WebhookEventType.SUBSCRIPTION_UPDATED,
    "subscription.activated": WebhookEventType.SUBSCRIPTION_UPDATED,
    "subscription.canceled": WebhookEventType.SUBSCRIPTION_CANCELED,
    "subscription.paused": WebhookEventType.SUBSCRIPTION_PAUSED,
    "subscription.resumed": WebhookEventType.SUBSCRIPTION_RESUMED,
    "subscription.past_due": WebhookEventType.PAYMENT_PAST_DUE,
    "subscription.trialing": WebhookEventType.SUBSCRIPTION_UPDATED,
    "transaction.completed": WebhookEventType.TRANSACTION_COMPLETED,
    "transaction.paid": WebhookEventType.TRANSACTION_COMPLETED,
    "transaction.payment_failed": WebhookEventType.TRANSACTION_FAILED,
    "transaction.past_due": WebhookEventType.PAYMENT_PAST_DUE,
    "customer.updated": WebhookEventType.CUSTOMER_UPDATED,
}


@dataclass(frozen=True)
class NormalizedPaddleWebhookEvent:
    provider: BillingProvider
    external_event_id: str
    event_type: WebhookEventType
    raw_event_name: str
    occurred_at: datetime | None
    customer_reference: str | None
    subscription_reference: str | None
    transaction_reference: str | None
    subscription_status: str | None
    normalized_payload: dict = field(default_factory=dict)


def normalize_paddle_event(event: dict[str, Any]) -> NormalizedPaddleWebhookEvent:
    """Normalize a verified, parsed Paddle event dict into
    ``NormalizedPaddleWebhookEvent``. Only a small, allowlisted set of
    fields is ever extracted — never the full raw payload."""
    event_id = event.get("event_id", "")
    raw_event_name = event.get("event_type", "")
    data = event.get("data", {}) or {}
    occurred_at_str = event.get("occurred_at")

    normalized_type = _PADDLE_EVENT_TYPE_MAP.get(raw_event_name, WebhookEventType.UNKNOWN)

    is_subscription_event = raw_event_name.startswith("subscription.")
    is_transaction_event = raw_event_name.startswith("transaction.")

    customer_ref = data.get("customer_id")
    subscription_ref = data.get("id") if is_subscription_event else data.get("subscription_id")
    transaction_ref = data.get("id") if is_transaction_event else None
    status = data.get("status") if is_subscription_event else None

    occurred_at = None
    if occurred_at_str:
        try:
            occurred_at = datetime.fromisoformat(occurred_at_str.replace("Z", "+00:00"))
        except ValueError:
            occurred_at = None

    return NormalizedPaddleWebhookEvent(
        provider=BillingProvider.PADDLE,
        external_event_id=event_id,
        event_type=normalized_type,
        raw_event_name=raw_event_name,
        occurred_at=occurred_at,
        customer_reference=customer_ref,
        subscription_reference=subscription_ref,
        transaction_reference=transaction_ref,
        subscription_status=status,
        normalized_payload={"raw_event_name": raw_event_name, "status": status},
    )
