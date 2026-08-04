"""Paddle webhook processing service (Commercial Infrastructure message 2).

Orchestrates: signature verification -> normalization -> idempotency ->
staleness/ordering protection -> subscription-state application ->
entitlement sync -> audit logging. This is the single place all of that
happens for Paddle — the router (``app/routers/paddle_webhook.py``) stays
a thin HTTP shell around this.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.billing.adapters.paddle import PaddleBillingAdapter
from app.billing.audit import record_audit_event
from app.billing.entitlements import decide_entitlements, normalize_stripe_status
from app.billing.enums import (
    BillingAuditEventType,
    BillingProvider,
    NormalizedSubscriptionStatus,
    PlanId,
    WebhookEventType,
    WebhookProcessingStatus,
)
from app.billing.idempotency import (
    check_and_record_pending,
    is_stale_subscription_update,
    mark_duplicate_ignored,
    mark_failed,
    mark_processed,
)
from app.billing.models import NormalizedSubscription
from app.billing.paddle_webhooks import NormalizedPaddleWebhookEvent, normalize_paddle_event, verify_paddle_signature

# Paddle subscription status strings mapped to the normalized taxonomy.
# Distinct from Stripe's mapping in app.billing.entitlements — Paddle's
# vocabulary differs (e.g. "trialing"/"active"/"past_due"/"paused"/
# "canceled" are shared spellings, but this mapping is kept SEPARATE so a
# future divergence in either provider's vocabulary never silently
# cross-contaminates the other).
_PADDLE_STATUS_MAP: dict[str, NormalizedSubscriptionStatus] = {
    "trialing": NormalizedSubscriptionStatus.TRIALING,
    "active": NormalizedSubscriptionStatus.ACTIVE,
    "past_due": NormalizedSubscriptionStatus.PAST_DUE,
    "paused": NormalizedSubscriptionStatus.PAUSED,
    "canceled": NormalizedSubscriptionStatus.CANCELED,
}


def normalize_paddle_status(paddle_status: str) -> NormalizedSubscriptionStatus:
    return _PADDLE_STATUS_MAP.get(paddle_status, NormalizedSubscriptionStatus.INCOMPLETE)


class PaddleWebhookProcessingError(Exception):
    """Raised when webhook processing fails in a way the caller should
    treat as a retryable failure (never raised for "safely ignore" cases,
    which return normally instead)."""


def verify_and_parse(raw_body: bytes, sig_header: str, webhook_secret: str) -> dict:
    return verify_paddle_signature(raw_body, sig_header, webhook_secret)


def process_paddle_webhook(event: dict, db: Session) -> str:
    """Process one verified, parsed Paddle webhook event.

    Returns a short status string: "processed" | "duplicate_ignored" |
    "unknown_event_acknowledged". Raises ``PaddleWebhookProcessingError``
    on failure (caller should mark the delivery failed and allow Paddle's
    natural retry).
    """
    normalized = normalize_paddle_event(event)

    webhook_row = check_and_record_pending(
        provider=BillingProvider.PADDLE.value,
        external_event_id=normalized.external_event_id,
        event_type=normalized.event_type.value,
        occurred_at=normalized.occurred_at,
        customer_reference=normalized.customer_reference,
        subscription_reference=normalized.subscription_reference,
        transaction_reference=normalized.transaction_reference,
        normalized_payload=normalized.normalized_payload,
        db=db,
    )

    if webhook_row.processing_status in (
        WebhookProcessingStatus.PROCESSED.value,
        WebhookProcessingStatus.DUPLICATE_IGNORED.value,
    ):
        mark_duplicate_ignored(webhook_row, db)
        return "duplicate_ignored"

    try:
        if normalized.event_type == WebhookEventType.UNKNOWN:
            # Safely acknowledged and auditable, never mutates state
            # (message-2 spec item 13).
            mark_processed(webhook_row, db)
            return "unknown_event_acknowledged"

        _apply_normalized_event(normalized, db)
        mark_processed(webhook_row, db)
        return "processed"
    except Exception as exc:
        mark_failed(webhook_row, "unexpected", db)
        raise PaddleWebhookProcessingError(str(exc)) from exc


def _find_subscription_by_paddle_reference(
    subscription_reference: str | None, customer_reference: str | None, db: Session
) -> NormalizedSubscription | None:
    query = db.query(NormalizedSubscription).filter(NormalizedSubscription.provider == BillingProvider.PADDLE.value)
    if subscription_reference:
        row = query.filter(NormalizedSubscription.provider_subscription_reference == subscription_reference).first()
        if row is not None:
            return row
    if customer_reference:
        row = query.filter(NormalizedSubscription.provider_customer_reference == customer_reference).first()
        if row is not None:
            return row
    return None


def _apply_normalized_event(normalized: NormalizedPaddleWebhookEvent, db: Session) -> None:
    sub = _find_subscription_by_paddle_reference(normalized.subscription_reference, normalized.customer_reference, db)

    if sub is None:
        # No local row yet (e.g. subscription_created for a brand-new
        # checkout whose custom_data-driven row hasn't been created by the
        # checkout-return flow). Safely acknowledged without mutation —
        # a later reconciliation pass (or a subsequent webhook once the
        # row exists) will catch up. Never fabricate a workspace_id.
        return

    if is_stale_subscription_update(candidate_occurred_at=normalized.occurred_at, subscription=sub):
        record_audit_event(
            workspace_id=sub.workspace_id,
            event_type=BillingAuditEventType.WEBHOOK_DUPLICATE_IGNORED,
            provider=BillingProvider.PADDLE,
            details={"reason": "stale_event", "event_type": normalized.event_type.value},
            db=db,
        )
        return

    previous_status = sub.status

    if normalized.event_type in (
        WebhookEventType.SUBSCRIPTION_CREATED,
        WebhookEventType.SUBSCRIPTION_UPDATED,
        WebhookEventType.SUBSCRIPTION_RESUMED,
    ):
        if normalized.subscription_status:
            sub.status = normalize_paddle_status(normalized.subscription_status).value
        sub.last_provider_event = normalized.event_type.value
        sub.version += 1

    elif normalized.event_type == WebhookEventType.SUBSCRIPTION_CANCELED:
        sub.status = NormalizedSubscriptionStatus.CANCELED.value
        sub.cancel_at_period_end = False
        sub.last_provider_event = normalized.event_type.value
        sub.version += 1
        record_audit_event(
            workspace_id=sub.workspace_id, event_type=BillingAuditEventType.SUBSCRIPTION_CANCELED,
            provider=BillingProvider.PADDLE, details={"previous_status": previous_status, "new_status": sub.status},
            db=db,
        )

    elif normalized.event_type == WebhookEventType.SUBSCRIPTION_PAUSED:
        sub.status = NormalizedSubscriptionStatus.PAUSED.value
        sub.last_provider_event = normalized.event_type.value
        sub.version += 1

    elif normalized.event_type == WebhookEventType.PAYMENT_PAST_DUE:
        sub.status = NormalizedSubscriptionStatus.PAST_DUE.value
        sub.grace_period_end = datetime.now(timezone.utc) + timedelta(days=_grace_period_days())
        sub.last_provider_event = normalized.event_type.value
        sub.version += 1
        record_audit_event(
            workspace_id=sub.workspace_id, event_type=BillingAuditEventType.PAYMENT_FAILED,
            provider=BillingProvider.PADDLE, details={"reason": "payment_past_due"}, db=db,
        )
        record_audit_event(
            workspace_id=sub.workspace_id, event_type=BillingAuditEventType.GRACE_PERIOD_STARTED,
            provider=BillingProvider.PADDLE,
            details={"grace_period_end": sub.grace_period_end.isoformat()}, db=db,
        )

    elif normalized.event_type == WebhookEventType.TRANSACTION_FAILED:
        sub.status = NormalizedSubscriptionStatus.PAST_DUE.value
        sub.grace_period_end = datetime.now(timezone.utc) + timedelta(days=_grace_period_days())
        sub.last_provider_event = normalized.event_type.value
        sub.version += 1
        record_audit_event(
            workspace_id=sub.workspace_id, event_type=BillingAuditEventType.PAYMENT_FAILED,
            provider=BillingProvider.PADDLE, details={"reason": "transaction_failed"}, db=db,
        )

    elif normalized.event_type == WebhookEventType.TRANSACTION_COMPLETED:
        # A successful payment recovers from past_due/incomplete.
        if sub.status in (NormalizedSubscriptionStatus.PAST_DUE.value, NormalizedSubscriptionStatus.INCOMPLETE.value):
            sub.status = NormalizedSubscriptionStatus.ACTIVE.value
            sub.grace_period_end = None
        sub.last_provider_event = normalized.event_type.value
        sub.version += 1

    elif normalized.event_type == WebhookEventType.CUSTOMER_UPDATED:
        pass  # no local subscription-state change required

    db.flush()

    if previous_status != sub.status:
        record_audit_event(
            workspace_id=sub.workspace_id, event_type=BillingAuditEventType.SUBSCRIPTION_CHANGED,
            provider=BillingProvider.PADDLE,
            details={"previous_status": previous_status, "new_status": sub.status}, db=db,
        )


def _grace_period_days() -> int:
    from app.config import settings

    return settings.BILLING_GRACE_PERIOD_DAYS
