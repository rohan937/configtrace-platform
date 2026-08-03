"""Provider-neutral webhook idempotency (Commercial Infrastructure message 1).

Idempotency key: (provider, external_event_id) — enforced by the unique
constraint ``uq_commercial_webhook_event`` on
``commercial_webhook_events`` (see ``app.billing.models.BillingWebhookEvent``).

This is deliberately a SEPARATE table from the existing
``app.models.billing.StripeWebhookEvent`` (message-1 spec item 6/22:
additive, non-destructive) — the legacy table keeps working for the
existing Stripe-only compatibility path in ``billing_service.py``
unmodified; this new table is the provider-neutral idempotency mechanism
any adapter (Stripe or future Paddle) records into going forward.

Ordering / staleness protection (message-1 spec item 26): webhooks are not
guaranteed to arrive in order. ``is_stale_subscription_update`` compares a
candidate event's ``occurred_at`` against the stored subscription's
``updated_at`` (BaseMixin's mutation timestamp, used as the "last applied
event time") — an event that occurred before the last-applied update is
stale and must not overwrite newer state, even if it arrives later.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.billing.enums import WebhookProcessingStatus
from app.billing.models import BillingWebhookEvent, NormalizedSubscription


class DuplicateWebhookEventError(Exception):
    """Raised when the caller must treat this delivery as an already-seen
    duplicate — first delivery already recorded, or a concurrent race lost
    at flush/commit time."""


def check_and_record_pending(
    *, provider: str, external_event_id: str, event_type: str,
    occurred_at: datetime | None, customer_reference: str | None,
    subscription_reference: str | None, transaction_reference: str | None,
    normalized_payload: dict, db: Session,
) -> BillingWebhookEvent:
    """Idempotently begin processing one webhook event.

    Returns the existing row (untouched) if this (provider,
    external_event_id) pair was already recorded — regardless of whether
    that prior attempt succeeded, failed, or is still pending; the caller
    is expected to check ``.processing_status`` and short-circuit if it is
    already ``processed`` or ``duplicate_ignored`` (message-1 spec item 25:
    "duplicate delivery returns success without duplicate state
    transition"). If no row exists yet, inserts a new ``pending`` row and
    returns it. A concurrent insert race is resolved by the unique
    constraint: the loser catches ``IntegrityError``, rolls back its own
    insert attempt, and re-queries to return the winner's row.
    """
    existing = (
        db.query(BillingWebhookEvent)
        .filter(
            BillingWebhookEvent.provider == provider,
            BillingWebhookEvent.external_event_id == external_event_id,
        )
        .first()
    )
    if existing is not None:
        return existing

    row = BillingWebhookEvent(
        provider=provider,
        external_event_id=external_event_id,
        event_type=event_type,
        occurred_at=occurred_at,
        customer_reference=customer_reference,
        subscription_reference=subscription_reference,
        transaction_reference=transaction_reference,
        normalized_payload=normalized_payload,
        processing_status=WebhookProcessingStatus.PENDING.value,
        attempt_count=0,
        error_category="none",
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        winner = (
            db.query(BillingWebhookEvent)
            .filter(
                BillingWebhookEvent.provider == provider,
                BillingWebhookEvent.external_event_id == external_event_id,
            )
            .first()
        )
        if winner is None:
            raise
        return winner
    return row


def mark_processed(event: BillingWebhookEvent, db: Session) -> None:
    event.processing_status = WebhookProcessingStatus.PROCESSED.value
    event.attempt_count += 1
    event.error_category = "none"
    db.flush()


def mark_failed(event: BillingWebhookEvent, error_category: str, db: Session) -> None:
    event.processing_status = WebhookProcessingStatus.FAILED.value
    event.attempt_count += 1
    event.error_category = error_category
    db.flush()


def mark_duplicate_ignored(event: BillingWebhookEvent, db: Session) -> None:
    event.processing_status = WebhookProcessingStatus.DUPLICATE_IGNORED.value
    db.flush()


def is_stale_subscription_update(
    *, candidate_occurred_at: datetime | None, subscription: NormalizedSubscription | None,
) -> bool:
    """True if ``candidate_occurred_at`` is older than the subscription's
    last-known-update time — meaning this event must NOT be applied even
    though it just arrived (out-of-order / replayed delivery protection).
    A candidate with no timestamp, or a subscription that doesn't exist
    yet, is never considered stale (nothing to compare against)."""
    if candidate_occurred_at is None or subscription is None:
        return False
    if subscription.updated_at is None:
        return False
    return candidate_occurred_at < subscription.updated_at
