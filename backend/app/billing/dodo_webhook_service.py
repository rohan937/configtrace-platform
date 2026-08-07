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
    BillingInterval,
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
from app.billing.pricing import TEAM_INCLUDED_SEATS
from app.models.workspace import Workspace

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
    "unknown_event_acknowledged" | "unresolved_workspace". Raises
    ``DodoWebhookProcessingError`` on failure (caller should mark the
    delivery failed and allow Dodo's natural retry — up to 8 attempts
    over ~10 hours, per Dodo's documented retry schedule).

    "unresolved_workspace" (bug found during Test Mode production
    verification, fixed here) is a DISTINCT outcome from "processed": it
    means the signature verified and the event was well-formed, but a
    subscription-lifecycle event (subscription.active/updated/etc.)
    could not be matched OR safely used to create a
    ``NormalizedSubscription`` row — e.g. the workspace_id metadata was
    missing/malformed, or named a workspace that doesn't exist. The
    underlying ``BillingWebhookEvent`` row is marked ``failed`` with
    ``error_category="unknown_reference"`` (not ``processed``), so it is
    visible via ``scripts/dodo_live_cutover.py webhook-events --status
    failed`` / ``unresolved-events`` instead of silently looking
    successful — this is exactly the gap that let a real Dodo Test Mode
    Pro subscription report "processed" while no NormalizedSubscription
    row was ever created for its workspace.
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

        unresolved_reason = _apply_normalized_event(normalized, db)
        if unresolved_reason is not None:
            mark_failed(webhook_row, unresolved_reason, db)
            return "unresolved_workspace"

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


# Event types that represent a subscription's own lifecycle (as opposed to
# a payment/transaction event) — the ONLY event types allowed to CREATE the
# first NormalizedSubscription row for a workspace. A payment.succeeded
# arriving with no matching row must never grant access by itself; it is
# a safe, silent no-op exactly as before this fix (see module docstring
# on process_dodo_webhook and the module docstring's design rationale).
_SUBSCRIPTION_LIFECYCLE_EVENT_TYPES = (
    WebhookEventType.SUBSCRIPTION_CREATED,
    WebhookEventType.SUBSCRIPTION_UPDATED,
    WebhookEventType.SUBSCRIPTION_CANCELED,
    WebhookEventType.SUBSCRIPTION_PAUSED,
)


def _create_subscription_from_hint(normalized: NormalizedDodoWebhookEvent, db: Session) -> NormalizedSubscription | None:
    """Create the FIRST ``NormalizedSubscription`` row for a workspace
    from a Dodo subscription-lifecycle event, using the explicit
    ``workspace_id`` ConfigTrace itself sent in checkout metadata
    (``adapters.dodo.DodoBillingAdapter.create_checkout``) and Dodo echoes
    back onto the resulting object — NEVER inferred from
    ``idempotency_reference`` or any other opaque reference.

    Returns ``None`` (never raises) for any condition that makes creation
    unsafe — this function fails closed:
      * the event isn't a subscription-lifecycle type,
      * the workspace_id/plan_id metadata is missing or malformed,
      * no workspace with that ID exists (never trust arbitrary
        customer-provided metadata without validating it against a real
        workspace),
      * the event carries no subscription status to record,
      * a ``NormalizedSubscription`` row already exists for this
        workspace under ANY provider (never silently reassign an
        existing subscription's provider — mirrors the
        ``WorkspaceCustomerMismatchError`` discipline in
        ``reconciliation_service.py``; the unique constraint on
        ``workspace_id`` would reject a second row anyway).
    """
    if normalized.event_type not in _SUBSCRIPTION_LIFECYCLE_EVENT_TYPES:
        return None
    if normalized.workspace_id_hint is None or normalized.plan_id_hint is None:
        return None
    if not normalized.subscription_status:
        return None

    workspace = db.get(Workspace, normalized.workspace_id_hint)
    if workspace is None:
        return None

    already_exists = (
        db.query(NormalizedSubscription)
        .filter(NormalizedSubscription.workspace_id == normalized.workspace_id_hint)
        .first()
    )
    if already_exists is not None:
        return None

    plan_id = normalized.plan_id_hint  # "pro" | "team" — already validated by normalize_dodo_event
    additional_seats = normalized.additional_seat_count_hint or 0
    billable_seats = (TEAM_INCLUDED_SEATS + additional_seats) if plan_id == "team" else 0

    sub = NormalizedSubscription(
        workspace_id=normalized.workspace_id_hint,
        provider=BillingProvider.DODO.value,
        provider_customer_reference=normalized.customer_reference,
        provider_subscription_reference=normalized.subscription_reference,
        plan_id=plan_id,
        billing_interval=BillingInterval.MONTH.value,
        status=normalize_dodo_status(normalized.subscription_status).value,
        billable_seats=billable_seats,
        additional_seat_quantity=additional_seats if plan_id == "team" else 0,
        last_provider_event=normalized.event_type.value,
        version=0,
    )
    db.add(sub)
    db.flush()

    record_audit_event(
        workspace_id=sub.workspace_id, event_type=BillingAuditEventType.SUBSCRIPTION_ACTIVATED,
        provider=BillingProvider.DODO,
        details={
            "plan_id": plan_id,
            "billing_interval": BillingInterval.MONTH.value,
            "billable_seats": billable_seats,
        },
        db=db,
    )
    return sub


def _apply_normalized_event(normalized: NormalizedDodoWebhookEvent, db: Session) -> str | None:
    """Apply one normalized event's effect on the local subscription
    state. Returns ``None`` on a legitimate outcome (state mutated, or a
    safe intentional no-op), or an ``error_category`` string (currently
    only ``"unknown_reference"``) when a subscription-lifecycle event
    could not be associated with any workspace — the caller
    (``process_dodo_webhook``) marks the webhook row ``failed`` with that
    category instead of ``processed`` in that case."""
    sub = _find_subscription_by_dodo_reference(normalized.subscription_reference, normalized.customer_reference, db)

    if sub is None:
        sub = _create_subscription_from_hint(normalized, db)
        if sub is None:
            if normalized.event_type in _SUBSCRIPTION_LIFECYCLE_EVENT_TYPES:
                # A subscription-lifecycle event that SHOULD represent a
                # real workspace's subscription, but couldn't be matched
                # to an existing row or safely used to create one — this
                # is the exact condition that must never be reported as
                # "processed" (see process_dodo_webhook's docstring).
                return "unknown_reference"
            # A payment/transaction event with no matching row yet — safe,
            # intentional no-op (same documented behavior as the existing
            # Paddle webhook service). Never fabricate a workspace_id, and
            # never let a bare payment event grant access by itself.
            return None
        return None

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

    return None


def _grace_period_days() -> int:
    from app.config import settings

    return settings.BILLING_GRACE_PERIOD_DAYS
