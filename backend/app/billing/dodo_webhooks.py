"""Dodo webhook signature verification and event normalization (Dodo
Payments message 1).

Signature scheme — Standard Webhooks (verified)
------------------------------------------------
Dodo's own documentation (docs.dodopayments.com/developer-resources/webhooks,
fetched during this message's research) states webhook delivery "follows
the Standard Webhooks specification" and documents three headers:

    webhook-id          — unique event identifier
    webhook-timestamp    — unix timestamp (seconds) of the delivery attempt
    webhook-signature    — space-delimited list of "v1,<base64_signature>"

This module implements the exact algorithm from the authoritative
Standard Webhooks spec itself
(github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md,
fetched during this message's research, since Dodo's own page does not
restate the low-level byte format):

    signed_content = f"{webhook_id}.{webhook_timestamp}.{raw_body}"
    secret         = base64-decode(DODO_WEBHOOK_SECRET with "whsec_" stripped)
    signature      = base64(HMAC-SHA256(secret, signed_content))
    header value   = "v1,<signature>" (space-delimited for multiple, to
                     support zero-downtime secret rotation)

This is DELIBERATELY NOT the same encoding as Paddle's scheme (Paddle:
hex-encoded HMAC over "{ts}:{raw_body}", no secret-prefix/base64-decode
step) — Dodo's is a genuinely different, independently-verified contract,
not a copy of Paddle's assumptions.

Timestamp tolerance: the Standard Webhooks spec recommends a tolerance
window but does not mandate a specific value ("implementers must define
their own acceptable window" — confirmed from the spec fetch). This
module defaults to 300 seconds, matching the tolerance already used for
Stripe and Paddle elsewhere in this codebase — a ConfigTrace convention,
not a Dodo-mandated number.

Event names — verified
-----------------------
The full ``EventType`` enum was fetched from Dodo's own OpenAPI-derived
"Create Webhook" reference page during this message's research. Only the
subset ConfigTrace's billing domain needs is mapped below; every other
documented event (refund.*, dispute.*, payout.*, credit.*, license_key.*,
abandoned_checkout.*, entitlement_grant.*) maps to UNKNOWN and is safely
acknowledged, never dropped silently.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.billing.enums import BillingProvider, WebhookEventType

_DEFAULT_TOLERANCE_SECONDS = 300  # ConfigTrace convention — not Dodo-mandated; see module docstring.
_WHSEC_PREFIX = "whsec_"


class DodoSignatureError(ValueError):
    """Raised for any signature verification failure — missing header,
    malformed header, invalid HMAC, or stale timestamp. Never includes the
    webhook secret or the full raw body in its message."""


def _decode_secret(webhook_secret: str) -> bytes:
    """Strip the documented 'whsec_' prefix and base64-decode the
    remainder, per the Standard Webhooks spec."""
    raw = webhook_secret[len(_WHSEC_PREFIX):] if webhook_secret.startswith(_WHSEC_PREFIX) else webhook_secret
    try:
        return base64.b64decode(raw)
    except Exception as exc:
        raise DodoSignatureError("Dodo webhook secret is not valid base64 after prefix removal.") from exc


def verify_dodo_signature(
    raw_body: bytes,
    headers: dict[str, str],
    webhook_secret: str,
    *,
    tolerance_seconds: int = _DEFAULT_TOLERANCE_SECONDS,
) -> dict[str, Any]:
    """Verify a Dodo (Standard Webhooks) delivery against the raw body and
    return the parsed JSON event dict.

    ``headers`` must be a case-insensitive-safe mapping already lowercased
    by the caller (the router lowercases FastAPI/Starlette header keys
    before calling this, matching how ``Request.headers`` already
    normalizes to lowercase).

    Raises ``DodoSignatureError`` on any failure: missing/empty
    webhook-id/webhook-timestamp/webhook-signature headers, a non-integer
    timestamp, a timestamp outside ``tolerance_seconds`` of "now", or an
    HMAC mismatch across every candidate signature in the header (modified
    body or wrong secret).
    """
    if not webhook_secret:
        raise DodoSignatureError("Dodo webhook secret is not configured.")

    webhook_id = headers.get("webhook-id", "")
    webhook_timestamp = headers.get("webhook-timestamp", "")
    webhook_signature = headers.get("webhook-signature", "")

    if not webhook_id or not webhook_timestamp or not webhook_signature:
        raise DodoSignatureError(
            "Missing one or more required Standard Webhooks headers "
            "(webhook-id / webhook-timestamp / webhook-signature)."
        )

    try:
        ts = int(webhook_timestamp)
    except ValueError:
        raise DodoSignatureError("Non-integer webhook-timestamp header.")

    if abs(time.time() - ts) > tolerance_seconds:
        raise DodoSignatureError(f"Dodo webhook timestamp too old or too far in the future: {ts}")

    signed_content = f"{webhook_id}.{webhook_timestamp}.{raw_body.decode('utf-8')}"
    secret_bytes = _decode_secret(webhook_secret)
    expected = base64.b64encode(
        hmac.new(secret_bytes, signed_content.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii")

    # webhook-signature is a space-delimited list of "v1,<base64sig>"
    # entries — accept if ANY candidate matches (secret-rotation window),
    # constant-time compared.
    candidates = []
    for part in webhook_signature.split(" "):
        part = part.strip()
        if not part:
            continue
        _, _, sig = part.partition(",")
        candidates.append(sig or part)

    if not candidates:
        raise DodoSignatureError("Malformed webhook-signature header.")

    if not any(hmac.compare_digest(expected, candidate) for candidate in candidates):
        raise DodoSignatureError("Dodo webhook signature mismatch.")

    return json.loads(raw_body)


# Verified event names (see module docstring) mapped to the message-1
# normalized taxonomy. Unknown/unrecognized event names map to
# WebhookEventType.UNKNOWN — acknowledged and auditable, but NEVER mutate
# subscription state.
_DODO_EVENT_TYPE_MAP: dict[str, WebhookEventType] = {
    "subscription.active": WebhookEventType.SUBSCRIPTION_CREATED,
    "subscription.renewed": WebhookEventType.SUBSCRIPTION_UPDATED,
    "subscription.updated": WebhookEventType.SUBSCRIPTION_UPDATED,
    "subscription.plan_changed": WebhookEventType.SUBSCRIPTION_UPDATED,
    "subscription.on_hold": WebhookEventType.PAYMENT_PAST_DUE,
    "subscription.paused": WebhookEventType.SUBSCRIPTION_PAUSED,
    "subscription.cancelled": WebhookEventType.SUBSCRIPTION_CANCELED,
    "subscription.failed": WebhookEventType.TRANSACTION_FAILED,
    "subscription.expired": WebhookEventType.SUBSCRIPTION_CANCELED,
    "subscription.update_payment_method": WebhookEventType.CUSTOMER_UPDATED,
    "payment.succeeded": WebhookEventType.TRANSACTION_COMPLETED,
    "payment.failed": WebhookEventType.TRANSACTION_FAILED,
    "dunning.started": WebhookEventType.PAYMENT_PAST_DUE,
    "dunning.recovered": WebhookEventType.TRANSACTION_COMPLETED,
}


@dataclass(frozen=True)
class NormalizedDodoWebhookEvent:
    provider: BillingProvider
    external_event_id: str
    event_type: WebhookEventType
    raw_event_name: str
    occurred_at: datetime | None
    customer_reference: str | None
    subscription_reference: str | None
    transaction_reference: str | None
    subscription_status: str | None
    # Explicit ConfigTrace identity ConfigTrace itself sent at checkout time
    # (adapters.dodo.DodoBillingAdapter.create_checkout's `metadata` dict)
    # and Dodo echoes back onto the resulting object — NEVER inferred from
    # `idempotency_reference` or any other opaque reference. Each is parsed
    # defensively: a missing/malformed value is `None`, never an exception
    # — the caller (dodo_webhook_service) is responsible for treating a
    # missing/invalid hint as "workspace unresolved", never for guessing.
    workspace_id_hint: uuid.UUID | None = None
    plan_id_hint: str | None = None
    additional_seat_count_hint: int | None = None
    # payload["data"]["product_id"] — a fallback plan-identification signal
    # for when metadata.plan_id is absent or stale (e.g. Dodo's own
    # subscription object metadata not yet reflecting a very recent plan
    # change). Never trusted alone without cross-checking against the
    # configured catalog IDs — see dodo_webhook_service._resolve_plan_id.
    product_id_hint: str | None = None
    # payload["data"]["previous_billing_date"] / ["next_billing_date"] —
    # same field names already used by
    # adapters.dodo.DodoBillingAdapter._snapshot_from_dodo_subscription
    # for the GET /subscriptions/{id} response; the webhook's `data`
    # object is the same subscription representation, so the same field
    # names are used here. Parsed defensively: malformed/absent is None,
    # never an exception, and a None hint never overwrites an existing
    # stored date (see dodo_webhook_service._apply_normalized_event).
    current_period_start_hint: datetime | None = None
    current_period_end_hint: datetime | None = None
    normalized_payload: dict = field(default_factory=dict)


def _parse_metadata_workspace_id(metadata: dict) -> uuid.UUID | None:
    raw = metadata.get("workspace_id")
    if not raw:
        return None
    try:
        return uuid.UUID(str(raw))
    except (ValueError, AttributeError, TypeError):
        return None


def _parse_metadata_plan_id(metadata: dict) -> str | None:
    raw = metadata.get("plan_id")
    if raw in ("pro", "team"):
        return raw
    return None


def _parse_metadata_additional_seat_count(metadata: dict) -> int | None:
    raw = metadata.get("additional_seat_count")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _parse_billing_date(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_dodo_event(event: dict[str, Any], *, external_event_id: str) -> NormalizedDodoWebhookEvent:
    """Normalize a verified, parsed Dodo event dict into
    ``NormalizedDodoWebhookEvent``. Only a small, allowlisted set of
    fields is ever extracted — never the full raw payload.

    ``external_event_id`` is passed in separately rather than read from
    the body: Dodo's ``webhook-id`` HEADER (not a body field) is the
    idempotency key per the Standard Webhooks spec, and is the value the
    caller (``dodo_webhook_service.process_dodo_webhook``) already
    extracted during signature verification.
    """
    raw_event_name = event.get("type", "")
    data = event.get("data", {}) or {}
    occurred_at_str = event.get("timestamp")

    normalized_type = _DODO_EVENT_TYPE_MAP.get(raw_event_name, WebhookEventType.UNKNOWN)

    is_subscription_event = raw_event_name.startswith("subscription.") or raw_event_name.startswith("dunning.")
    is_payment_event = raw_event_name.startswith("payment.")

    customer_obj = data.get("customer") or {}
    customer_ref = customer_obj.get("customer_id") if isinstance(customer_obj, dict) else None
    subscription_ref = data.get("subscription_id") if not is_subscription_event else data.get("subscription_id")
    transaction_ref = data.get("payment_id") if is_payment_event else None
    status = data.get("status") if is_subscription_event else None
    product_id_hint = data.get("product_id") if is_subscription_event else None
    current_period_start_hint = _parse_billing_date(data.get("previous_billing_date")) if is_subscription_event else None
    current_period_end_hint = _parse_billing_date(data.get("next_billing_date")) if is_subscription_event else None

    occurred_at = None
    if occurred_at_str:
        try:
            occurred_at = datetime.fromisoformat(str(occurred_at_str).replace("Z", "+00:00"))
        except ValueError:
            occurred_at = None

    # ConfigTrace's own checkout metadata (workspace_id, plan_id,
    # additional_seat_count, configtrace_user_id, idempotency_reference —
    # see adapters.dodo.DodoBillingAdapter.create_checkout), echoed back by
    # Dodo on the subscription/payment object. Never trusted blindly: each
    # value is parsed and validated by the caller before ever being used
    # to create or match a workspace's subscription row.
    metadata = data.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    workspace_id_hint = _parse_metadata_workspace_id(metadata)
    plan_id_hint = _parse_metadata_plan_id(metadata)
    additional_seat_count_hint = _parse_metadata_additional_seat_count(metadata)

    return NormalizedDodoWebhookEvent(
        provider=BillingProvider.DODO,
        external_event_id=external_event_id,
        event_type=normalized_type,
        raw_event_name=raw_event_name,
        occurred_at=occurred_at,
        customer_reference=customer_ref,
        subscription_reference=subscription_ref,
        transaction_reference=transaction_ref,
        subscription_status=status,
        workspace_id_hint=workspace_id_hint,
        plan_id_hint=plan_id_hint,
        additional_seat_count_hint=additional_seat_count_hint,
        product_id_hint=product_id_hint,
        current_period_start_hint=current_period_start_hint,
        current_period_end_hint=current_period_end_hint,
        normalized_payload={"raw_event_name": raw_event_name, "status": status},
    )
