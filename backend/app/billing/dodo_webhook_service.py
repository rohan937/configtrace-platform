"""Dodo webhook processing service (Dodo Payments message 1).

Orchestrates: signature verification -> normalization -> idempotency ->
staleness/ordering protection -> subscription-state application ->
entitlement sync -> audit logging. This is the single place all of that
happens for Dodo — the router (``app/routers/dodo_webhook.py``) stays a
thin HTTP shell around this, mirroring the existing Stripe/Paddle webhook
services' shape.

Idempotency key note (Dodo-specific)
--------------------------------------
Unlike Stripe/Paddle (whose idempotency key is a field INSIDE the parsed
JSON body), the Standard Webhooks spec Dodo follows puts the unique event
identifier in the ``webhook-id`` HEADER, not the body. This service
therefore takes ``external_event_id`` as an explicit parameter rather than
reading it off the parsed event dict.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.billing.audit import record_audit_event
from app.billing.dodo_webhooks import NormalizedDodoWebhookEvent, normalize_dodo_event
from app.billing.enums import (
    BillingAuditEventType,
    BillingProvider,
    NormalizedSubscriptionStatus,
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

# Dodo subscription status strings, verified from the documented PATCH
# /subscriptions/{id} `status` enum: pending | active | on_hold |
# cancelled | failed | expired. Kept SEPARATE from Stripe's and Paddle's
# mappings (app.billing.entitlements / app.billing.paddle_webhook_service)
# — a future divergence in any provider's vocabulary never
# cross-contaminates another.
#
# Idempotency entries (bug found during Test Mode verification, fixed
# here): ``NormalizedSubscription.status`` is written as an ALREADY
# NORMALIZED value by ``_apply_normalized_event`` below
# (``sub.status = normalize_dodo_status(...).value``), but
# ``app/routers/billing.py``'s ``get_current_subscription`` re-runs
# ``normalize_dodo_status(sub.status)`` on that already-normalized value
# every time it's read. For Stripe and Paddle this double-normalization
# is harmlessly idempotent by coincidence — their raw provider status
# spellings ("past_due", "canceled", "trialing", "paused") happen to be
# spelled identically to the normalized enum values. Dodo's raw
# vocabulary does NOT overlap ("on_hold" vs "past_due", "cancelled" vs
# "canceled" — note the double L), so re-normalizing an
# already-normalized "past_due" fell through to the INCOMPLETE default,
# silently downgrading a paying, grace-period Dodo customer to
# no-paid-access on every subscription read. The entries below make
# ``normalize_dodo_status`` a safe no-op on every value it could ever
# legitimately be asked to re-normalize, without changing how any RAW
# Dodo webhook status string is mapped.
_DODO_STATUS_MAP: dict[str, NormalizedSubscriptionStatus] = {
    # Raw Dodo status strings (from Dodo's documented status enum).
    "pending": NormalizedSubscriptionStatus.INCOMPLETE,
    "active": NormalizedSubscriptionStatus.ACTIVE,
    "on_hold": NormalizedSubscriptionStatus.PAST_DUE,
    "cancelled": NormalizedSubscriptionStatus.CANCELED,
    "failed": NormalizedSubscriptionStatus.INCOMPLETE,
    "expired": NormalizedSubscriptionStatus.EXPIRED,
    # Identity entries for already-normalized values (see note above) —
    # never produced by a raw Dodo webhook, only by re-normalizing a
    # value this module itself already wrote.
    "trialing": NormalizedSubscriptionStatus.TRIALING,
    "past_due": NormalizedSubscriptionStatus.PAST_DUE,
    "grace_period": NormalizedSubscriptionStatus.GRACE_PERIOD,
    "paused": NormalizedSubscriptionStatus.PAUSED,
    "canceled": NormalizedSubscriptionStatus.CANCELED,
    "incomplete": NormalizedSubscriptionStatus.INCOMPLETE,
}


def normalize_dodo_status(dodo_status: str) -> NormalizedSubscriptionStatus:
    """Map a raw Dodo subscription-status string — OR an already
    normalized ``NormalizedSubscriptionStatus`` value re-read from
    storage — to a normalized status. Unknown/unexpected strings map to
    INCOMPLETE rather than raising — an unrecognized status must never be
    silently treated as ACTIVE."""
    return _DODO_STATUS_MAP.get(dodo_status, NormalizedSubscriptionStatus.INCOMPLETE)


class DodoWebhookProcessingError(Exception):
    """Raised when webhook processing fails in a way the caller should
    treat as a retryable failure (never raised for "safely ignore" cases,
    which return normally instead)."""


def process_dodo_webhook(event: dict, external_event_id: str, db: Session) -> str:
    """Process one verified, parsed Dodo webhook event.

    Returns a short status string: "processed" | "duplicate_ignored" |
    "unknown_event_acknowledged". Raises ``DodoWebhookProcessingError`` on
    failure (caller should mark the delivery failed and allow Dodo's
    natural retry — up to 8 attempts over ~10 hours, per Dodo's documented
    retry schedule).
    """
    normalized = normalize_dodo_event(event, external_event_id=external_event_id)

    webhook_row = check_and_record_pending(
        provider=BillingProvider.DODO.value,
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
            # Safely acknowledged and auditable, never mutates state.
            mark_processed(webhook_row, db)
            return "unknown_event_acknowledged"

        _apply_normalized_event(normalized, db)
        mark_processed(webhook_row, db)
        return "processed"
    except Exception as exc:
        mark_failed(webhook_row, "unexpected", db)
        raise DodoWebhookProcessingError(str(exc)) from exc


def _find_subscription_by_dodo_reference(
    subscription_reference: str | None, customer_reference: str | None, db: Session
) -> NormalizedSubscription | None:
    query = db.query(NormalizedSubscription).filter(NormalizedSubscription.provider == BillingProvider.DODO.value)
    if subscription_reference:
        row = query.filter(NormalizedSubscription.provider_subscription_reference == subscription_reference).first()
        if row is not None:
            return row
    if customer_reference:
        row = query.filter(NormalizedSubscription.provider_customer_reference == customer_reference).first()
        if row is not None:
            return row
    return None


def _apply_normalized_event(normalized: NormalizedDodoWebhookEvent, db: Session) -> None:
    sub = _find_subscription_by_dodo_reference(normalized.subscription_reference, normalized.customer_reference, db)

    if sub is None:
        # No local row yet — safely acknowledged without mutation, same
        # documented behavior as the existing Paddle webhook service
        # (app.billing.paddle_webhook_service._apply_normalized_event).
        # Never fabricate a workspace_id.
        return

    if is_stale_subscription_update(candidate_occurred_at=normalized.occurred_at, subscription=sub):
        record_audit_event(
            workspace_id=sub.workspace_id,
            event_type=BillingAuditEventType.WEBHOOK_DUPLICATE_IGNORED,
            provider=BillingProvider.DODO,
            details={"reason": "stale_event", "event_type": normalized.event_type.value},
            db=db,
        )
        return

    previous_status = sub.status

    # subscription.expired is bucketed as SUBSCRIPTION_CANCELED (no finer
    # WebhookEventType exists for it), but its raw event name still lets
    # us apply the more specific EXPIRED normalized status rather than
    # CANCELED — see dodo_webhooks.py's module docstring.
    if normalized.raw_event_name == "subscription.expired":
        sub.status = NormalizedSubscriptionStatus.EXPIRED.value
        sub.last_provider_event = normalized.event_type.value
        sub.version += 1
        record_audit_event(
            workspace_id=sub.workspace_id, event_type=BillingAuditEventType.SUBSCRIPTION_CANCELED,
            provider=BillingProvider.DODO, details={"previous_status": previous_status, "new_status": sub.status},
            db=db,
        )

    elif normalized.event_type in (WebhookEventType.SUBSCRIPTION_CREATED, WebhookEventType.SUBSCRIPTION_UPDATED):
        if normalized.subscription_status:
            sub.status = normalize_dodo_status(normalized.subscription_status).value
        sub.last_provider_event = normalized.event_type.value
        sub.version += 1

    elif normalized.event_type == WebhookEventType.SUBSCRIPTION_CANCELED:
        sub.status = NormalizedSubscriptionStatus.CANCELED.value
        sub.cancel_at_period_end = False
        sub.last_provider_event = normalized.event_type.value
        sub.version += 1
        record_audit_event(
            workspace_id=sub.workspace_id, event_type=BillingAuditEventType.SUBSCRIPTION_CANCELED,
            provider=BillingProvider.DODO, details={"previous_status": previous_status, "new_status": sub.status},
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
            provider=BillingProvider.DODO, details={"reason": "payment_past_due"}, db=db,
        )
        record_audit_event(
            workspace_id=sub.workspace_id, event_type=BillingAuditEventType.GRACE_PERIOD_STARTED,
            provider=BillingProvider.DODO,
            details={"grace_period_end": sub.grace_period_end.isoformat()}, db=db,
        )

    elif normalized.event_type == WebhookEventType.TRANSACTION_FAILED:
        sub.status = NormalizedSubscriptionStatus.PAST_DUE.value
        sub.grace_period_end = datetime.now(timezone.utc) + timedelta(days=_grace_period_days())
        sub.last_provider_event = normalized.event_type.value
        sub.version += 1
        record_audit_event(
            workspace_id=sub.workspace_id, event_type=BillingAuditEventType.PAYMENT_FAILED,
            provider=BillingProvider.DODO, details={"reason": "transaction_failed"}, db=db,
        )

    elif normalized.event_type == WebhookEventType.TRANSACTION_COMPLETED:
        # A successful payment (payment.succeeded) or a dunning recovery
        # (dunning.recovered) both recover from past_due/incomplete.
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
            provider=BillingProvider.DODO,
            details={"previous_status": previous_status, "new_status": sub.status}, db=db,
        )


def _grace_period_days() -> int:
    from app.config import settings

    return settings.BILLING_GRACE_PERIOD_DAYS
