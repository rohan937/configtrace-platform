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

import logging
import uuid
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
from app.billing.models import BillingWebhookEvent, NormalizedSubscription
from app.billing.pricing import TEAM_INCLUDED_SEATS
from app.models.workspace import Workspace

logger = logging.getLogger(__name__)

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

    # Structured, secret-free diagnostic — never the raw payload, never a
    # customer email or card detail, only booleans/short IDs already
    # treated as non-secret elsewhere in this codebase (workspace/
    # subscription/customer references). This is what makes it possible
    # to tell, from Render logs alone, WHERE in the pipeline a real
    # delivery diverged from the test fixtures' assumed payload shape —
    # added while diagnosing why a real Dodo Test Mode checkout still
    # didn't create a NormalizedSubscription after the first workspace-
    # sync fix (commit 2177eba).
    logger.info(
        "dodo_webhook received event_type=%s workspace_hint_present=%s "
        "plan_hint=%s subscription_reference_present=%s customer_reference_present=%s",
        normalized.raw_event_name,
        normalized.workspace_id_hint is not None,
        normalized.plan_id_hint,
        bool(normalized.subscription_reference),
        bool(normalized.customer_reference),
    )

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
        logger.info("dodo_webhook outcome=duplicate_ignored event_type=%s", normalized.raw_event_name)
        return "duplicate_ignored"

    try:
        if normalized.event_type == WebhookEventType.UNKNOWN:
            # Safely acknowledged and auditable, never mutates state.
            mark_processed(webhook_row, db)
            logger.info("dodo_webhook outcome=unknown_event_acknowledged event_type=%s", normalized.raw_event_name)
            return "unknown_event_acknowledged"

        unresolved_reason = _apply_normalized_event(normalized, db)
        if unresolved_reason is not None:
            mark_failed(webhook_row, unresolved_reason, db)
            # This branch does NOT raise, so the router's normal
            # db.commit() (not db.rollback()) applies — this row survives
            # without any special handling. The rollback-swallows-the-row
            # bug only affects the "except Exception" branch below, where
            # the router instead calls db.rollback().
            logger.info(
                "dodo_webhook outcome=unresolved_workspace event_type=%s reason=%s",
                normalized.raw_event_name, unresolved_reason,
            )
            return "unresolved_workspace"

        mark_processed(webhook_row, db)
        logger.info("dodo_webhook outcome=processed event_type=%s", normalized.raw_event_name)
        return "processed"
    except Exception as exc:
        # Bug found during real Dodo Test Mode verification (fixed here):
        # app/routers/dodo_webhook.py calls db.rollback() whenever this
        # function raises DodoWebhookProcessingError. Since
        # check_and_record_pending's insert above, and mark_failed below,
        # were only db.flush()'d (never committed) within that same
        # session/transaction, that rollback silently discarded BOTH —
        # leaving literally zero trace of the delivery (no
        # NormalizedSubscription row, no BillingWebhookEvent row at all,
        # not even a failed one) even though Dodo received HTTP 200. This
        # is exactly why `unresolved-events` and `subscription` both came
        # back empty for a real failed delivery. Fix: roll back the
        # failed attempt's partial mutations ourselves, re-record the
        # pending row fresh, mark it failed, and COMMIT immediately —
        # durably, before the exception is allowed to propagate — so the
        # router's subsequent db.rollback() has nothing left to lose.
        db.rollback()
        logger.exception("dodo_webhook outcome=unexpected_error event_type=%s", normalized.raw_event_name)
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
        mark_failed(webhook_row, "unexpected", db)
        db.commit()
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
        logger.info(
            "dodo_create_subscription skip reason=not_a_lifecycle_event event_type=%s", normalized.raw_event_name
        )
        return None
    if normalized.workspace_id_hint is None or normalized.plan_id_hint is None:
        logger.info(
            "dodo_create_subscription skip reason=missing_metadata_hint event_type=%s "
            "workspace_hint_present=%s plan_hint_present=%s",
            normalized.raw_event_name, normalized.workspace_id_hint is not None, normalized.plan_id_hint is not None,
        )
        return None
    if not normalized.subscription_status:
        logger.info(
            "dodo_create_subscription skip reason=missing_subscription_status event_type=%s workspace_hint=%s",
            normalized.raw_event_name, normalized.workspace_id_hint,
        )
        return None

    workspace = db.get(Workspace, normalized.workspace_id_hint)
    if workspace is None:
        logger.info(
            "dodo_create_subscription skip reason=unknown_workspace event_type=%s workspace_hint=%s",
            normalized.raw_event_name, normalized.workspace_id_hint,
        )
        return None

    already_exists = (
        db.query(NormalizedSubscription)
        .filter(NormalizedSubscription.workspace_id == normalized.workspace_id_hint)
        .first()
    )
    if already_exists is not None:
        logger.info(
            "dodo_create_subscription skip reason=workspace_already_has_subscription event_type=%s "
            "workspace_hint=%s existing_provider=%s",
            normalized.raw_event_name, normalized.workspace_id_hint, already_exists.provider,
        )
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
    logger.info(
        "dodo_create_subscription created workspace_id=%s plan_id=%s billable_seats=%s",
        sub.workspace_id, plan_id, billable_seats,
    )
    return sub


def _latest_processed_dodo_event_occurred_at(
    *, subscription_reference: str | None, customer_reference: str | None,
    exclude_external_event_id: str, db: Session,
) -> datetime | None:
    """The ``occurred_at`` of the most recently PROCESSED Dodo webhook
    event for this same subscription/customer — the correct staleness
    baseline (see ``idempotency.is_stale_subscription_update``'s
    ``reference_time`` docstring for the bug this fixes). Matches the
    SAME precedence ``_find_subscription_by_dodo_reference`` uses
    (subscription_reference first, then customer_reference), so it stays
    correct across a plan-change/new-checkout scenario where a workspace's
    NEW event carries a DIFFERENT subscription_reference than the row's
    stored one but the SAME customer_reference."""
    base_query = (
        db.query(BillingWebhookEvent)
        .filter(BillingWebhookEvent.provider == BillingProvider.DODO.value)
        .filter(BillingWebhookEvent.processing_status == WebhookProcessingStatus.PROCESSED.value)
        .filter(BillingWebhookEvent.external_event_id != exclude_external_event_id)
        .filter(BillingWebhookEvent.occurred_at.isnot(None))
    )
    candidates: list[datetime] = []
    if subscription_reference:
        row = (
            base_query.filter(BillingWebhookEvent.subscription_reference == subscription_reference)
            .order_by(BillingWebhookEvent.occurred_at.desc())
            .first()
        )
        if row is not None and row.occurred_at is not None:
            candidates.append(row.occurred_at)
    if customer_reference:
        row = (
            base_query.filter(BillingWebhookEvent.customer_reference == customer_reference)
            .order_by(BillingWebhookEvent.occurred_at.desc())
            .first()
        )
        if row is not None and row.occurred_at is not None:
            candidates.append(row.occurred_at)
    return max(candidates) if candidates else None


def _resolve_plan_id(plan_id_hint: str | None, product_id_hint: str | None) -> str | None:
    """Prefer the checkout-metadata plan hint; fall back to matching
    ``product_id`` against the configured catalog when the metadata hint
    is absent or stale (see dodo_webhooks.NormalizedDodoWebhookEvent's
    docstring). Returns ``None`` — never guesses — when neither resolves
    to a known plan, which the caller treats as "don't touch plan_id"."""
    if plan_id_hint in ("pro", "team"):
        return plan_id_hint
    if product_id_hint:
        from app.config import settings

        if product_id_hint == settings.DODO_PRO_PRODUCT_ID:
            return "pro"
        if product_id_hint == settings.DODO_TEAM_PRODUCT_ID:
            return "team"
    return None


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

    reference_time = _latest_processed_dodo_event_occurred_at(
        subscription_reference=normalized.subscription_reference,
        customer_reference=normalized.customer_reference,
        exclude_external_event_id=normalized.external_event_id,
        db=db,
    )
    if is_stale_subscription_update(
        candidate_occurred_at=normalized.occurred_at, subscription=sub, reference_time=reference_time,
    ):
        record_audit_event(
            workspace_id=sub.workspace_id,
            event_type=BillingAuditEventType.WEBHOOK_DUPLICATE_IGNORED,
            provider=BillingProvider.DODO,
            details={"reason": "stale_event", "event_type": normalized.event_type.value},
            db=db,
        )
        return None

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
        # Bug found in production (real Dodo Test Mode Pro -> Team
        # checkout): this branch previously only ever touched `status`.
        # A legitimate plan change — whether Dodo's own change-plan on
        # the SAME subscription, or (as ConfigTrace's checkout currently
        # produces) a brand-new Dodo subscription for the SAME
        # customer/workspace — was silently invisible: subscription_
        # created/updated events kept arriving and were marked
        # "processed", but plan_id, seats, the subscription reference,
        # and period dates were never re-derived from the event, so the
        # workspace stayed on its old plan forever.
        if normalized.subscription_status:
            sub.status = normalize_dodo_status(normalized.subscription_status).value

        previous_plan_id = sub.plan_id
        previous_subscription_reference = sub.provider_subscription_reference
        resolved_plan_id = _resolve_plan_id(normalized.plan_id_hint, normalized.product_id_hint)
        # Never touch plan_id/seats when the plan can't be confidently
        # resolved (unknown product_id, no metadata) — fails closed,
        # keeping the workspace's existing plan rather than guessing.
        plan_changed = resolved_plan_id is not None and resolved_plan_id != sub.plan_id
        # A different provider_subscription_reference than the one on
        # file — e.g. checkout created a second Dodo subscription for
        # this customer rather than changing the existing one. This is
        # NOT silently ignored NOR silently treated as routine: it's
        # applied (ConfigTrace must track whichever subscription Dodo's
        # newest event says is current) but explicitly audited below so
        # it's never indistinguishable from an ordinary status update —
        # see this commit's report for why the PREVIOUS subscription may
        # still be active and billable in Dodo and require a manual
        # cancellation there; this code does not do that automatically.
        reference_changed = (
            normalized.subscription_reference is not None
            and normalized.subscription_reference != sub.provider_subscription_reference
        )

        if plan_changed:
            sub.plan_id = resolved_plan_id
            additional_seats = normalized.additional_seat_count_hint or 0
            sub.billable_seats = (TEAM_INCLUDED_SEATS + additional_seats) if resolved_plan_id == "team" else 0
            sub.additional_seat_quantity = additional_seats if resolved_plan_id == "team" else 0

        if reference_changed:
            sub.provider_subscription_reference = normalized.subscription_reference

        if normalized.current_period_start_hint is not None:
            sub.current_period_start = normalized.current_period_start_hint
        if normalized.current_period_end_hint is not None:
            sub.current_period_end = normalized.current_period_end_hint

        sub.last_provider_event = normalized.event_type.value
        sub.version += 1

        if plan_changed or reference_changed:
            details = {}
            if plan_changed:
                details["previous_plan_id"] = previous_plan_id
                details["new_plan_id"] = resolved_plan_id
                details["billable_seats"] = sub.billable_seats
            if reference_changed:
                details["reason"] = (
                    "provider_subscription_reference_changed — previous Dodo "
                    "subscription may still be active/billable; verify in the "
                    "Dodo dashboard"
                )
            record_audit_event(
                workspace_id=sub.workspace_id, event_type=BillingAuditEventType.SUBSCRIPTION_CHANGED,
                provider=BillingProvider.DODO, details=details, db=db,
            )
        else:
            logger.info(
                "dodo_webhook supported_event_no_mutation event_type=%s workspace_id=%s "
                "reason=%s",
                normalized.event_type.value, sub.workspace_id,
                "status_unchanged_and_no_resolvable_plan_or_reference_change",
            )

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


# ── Read-only reconciliation fallback (webhook-delivery-independent) ───────
#
# Webhook processing above remains the SOLE AUTOMATIC source of truth —
# nothing here is invoked by any webhook, scheduled job, or request
# handler. This exists only for the explicit, operator-invoked command
# ``scripts/dodo_live_cutover.py reconcile-from-dodo``, for exactly the
# situation this module's diagnostics were built to investigate: a real
# Dodo subscription exists and is genuinely paid, but the webhook that
# should have told ConfigTrace about it never arrived (or was delayed) —
# root-caused, in the incident this function was added for, to Dodo
# itself never attempting delivery of the real subscription/payment
# events (confirmed via Dodo's own webhook Activity log showing zero
# delivery attempts for the affected transactions — a Dodo-dashboard
# configuration/platform issue, not a ConfigTrace defect; see the
# investigation report for this commit).


class DodoReconciliationError(Exception):
    """Raised for any reconciliation precondition that fails closed —
    never for a successful outcome. Never carries a secret, a full raw
    payload, or PII — only a short, structural reason string."""


# Raw Dodo subscription statuses (docs.dodopayments.com's documented
# subscription-status enum) considered "still live" — an existing row
# backed by one of these must never be silently replaced by reconciliation.
_DODO_RAW_LIVE_STATUSES = {"active", "on_hold", "pending"}
# Raw Dodo statuses that make a subscription safe to treat as OBSOLETE and
# therefore replaceable — the exact set the historical-recovery edge case
# (old checkout bug leaving a stray canceled subscription behind) needs.
_DODO_RAW_REPLACEABLE_STATUSES = {"cancelled", "canceled", "failed", "expired"}


def reconcile_workspace_from_dodo_subscription(
    *, workspace_id: uuid.UUID, dodo_subscription_id: str, db: Session, apply: bool, live: bool = False,
) -> dict:
    """Fetch the ACTUAL current state of a real Dodo subscription (a
    single read-only ``GET /subscriptions/{id}`` call — Test or Live,
    whichever ``DODO_ENVIRONMENT`` is configured for, gated the same way
    ``scripts/dodo_live_cutover.py catalog-verify`` gates Live access) and,
    only when ``apply=True``, either create the first ``NormalizedSubscription``
    row for it, OR — the historical-recovery edge case — REPLACE an
    existing, obsolete/canceled Dodo row IN PLACE with this verified
    active Dodo subscription for the SAME workspace (fix for stray rows
    left behind by the old checkout-creates-a-second-subscription bug;
    see ``DodoBillingAdapter.change_subscription_plan``'s docstring for
    the original bug this is repairing residue from).

    Fails closed (raises ``DodoReconciliationError`` with a specific,
    safe reason) for every unsafe condition:
      * the workspace doesn't exist,
      * a ``NormalizedSubscription`` row already exists for this
        workspace under a DIFFERENT provider (Stripe/Paddle) — this can
        NEVER overwrite a non-Dodo row,
      * an existing Dodo row is still live (its CURRENT, freshly
        re-fetched Dodo status is active/on_hold/pending) — only an
        obsolete row (canceled/failed/expired) may ever be replaced,
      * Dodo is not configured, or the requested environment doesn't
        match ``DODO_ENVIRONMENT`` (mirrors ``catalog-verify``'s
        Live/Test mismatch guard — an accidental default invocation can
        never touch Live),
      * the target Dodo subscription ID doesn't resolve to a real object,
      * the target Dodo subscription's own ``data.metadata.workspace_id``
        (if present on the raw response) does NOT match the workspace_id
        given — cross-checking Dodo's own record against the operator's
        claim; never trusting either side alone,
      * the target subscription's ``product_id`` doesn't map to a known
        plan in the configured catalog,
      * the target subscription's own current status is not ``active``,
      * (replace case only) the target subscription belongs to a
        different Dodo customer than the existing row's stored customer
        reference — ambiguous ownership, never assumed,
      * (replace case only) the target subscription is already attached
        to a DIFFERENT workspace's ``NormalizedSubscription`` row.

    Never grants access from a bare payment/transaction state — this
    function only ever reads *subscription* objects, never a payment or
    transaction; a workspace with only successful payments and no real
    Dodo subscription object has nothing for this function to reconcile
    from, by construction.

    Idempotent: re-running with the exact subscription ID already stored
    on the workspace's row is a safe no-op (``already_reconciled: True``),
    never an error and never a second write.

    Returns a dict describing what was found (and, when ``apply=True``,
    what was written) — ``created``/``replaced`` are both ``False`` for a
    dry run.
    """
    from app.billing.adapters.dodo import DodoBillingAdapter, DodoCatalogMapping
    from app.billing.enums import ObjectType
    from app.billing.provider import BillingProviderReference
    from app.config import settings

    workspace = db.get(Workspace, workspace_id)
    if workspace is None:
        raise DodoReconciliationError("workspace_not_found")

    existing = (
        db.query(NormalizedSubscription)
        .filter(NormalizedSubscription.workspace_id == workspace_id)
        .first()
    )

    # Idempotent no-op: already reconciled to exactly this subscription.
    if existing is not None and existing.provider_subscription_reference == dodo_subscription_id:
        return {
            "workspace_id": str(workspace_id),
            "dodo_subscription_id": dodo_subscription_id,
            "plan_id": existing.plan_id,
            "status": existing.status,
            "billable_seats": existing.billable_seats,
            "created": False,
            "replaced": False,
            "already_reconciled": True,
        }

    replacing_existing = existing is not None
    if replacing_existing and existing.provider != BillingProvider.DODO.value:
        raise DodoReconciliationError(f"workspace_already_has_subscription:provider={existing.provider}")

    if not settings.is_dodo_configured:
        raise DodoReconciliationError("dodo_not_configured")

    resolved_env = settings.dodo_environment_normalized
    if resolved_env not in ("test", "live"):
        raise DodoReconciliationError("dodo_environment_not_configured")
    if resolved_env == "live" and not live:
        raise DodoReconciliationError("refused_live_without_explicit_flag")
    if resolved_env == "test" and live:
        raise DodoReconciliationError("refused_live_flag_but_configured_environment_is_test")

    mapping = DodoCatalogMapping(
        environment=resolved_env,
        pro_product_id=settings.DODO_PRO_PRODUCT_ID,
        team_product_id=settings.DODO_TEAM_PRODUCT_ID,
        team_seat_addon_id=settings.DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID,
    )
    client = adapter_client_for(resolved_env, settings.DODO_API_KEY)
    adapter = DodoBillingAdapter(mapping, client)

    if replacing_existing:
        # Re-verify the EXISTING row's status directly against Dodo right
        # now — never trust the possibly-stale locally-stored status to
        # decide whether it's safe to replace, EXCEPT for the two narrow
        # carve-outs below (both needed for the Test->Live pilot cutover
        # to be repairable without hand-editing the database):
        #
        # 1. No stored reference at all (e.g. a workspace prepared via
        #    ``prepare_dodo_workspace_for_live_pilot``, which deliberately
        #    clears the reference so a stray webhook can never re-match
        #    this row) — nothing to query, so the locally-recorded
        #    NORMALIZED status is trusted instead. That status can only
        #    have gotten here through our own audited webhook/
        #    reconciliation/pilot-preparation code paths, never organic
        #    drift, so trusting it here is safe.
        # 2. The stored reference resolves to a real HTTP 404 in the
        #    CURRENTLY CONFIGURED environment — i.e. it definitively does
        #    not exist there right now. This is exactly what a Test-mode
        #    subscription ID looks like once ``DODO_ENVIRONMENT`` has been
        #    switched to Live (separate ID spaces per environment): it
        #    cannot possibly be a live, entitlement-granting subscription
        #    in the environment we're now querying, so it's safe to
        #    proceed with replacement. Any OTHER API error (auth failure,
        #    network error, 5xx, rate limit) still refuses — only a
        #    confirmed "does not exist here" is treated as safe.
        if not existing.provider_subscription_reference:
            if existing.status not in ("canceled", "expired", "incomplete"):
                raise DodoReconciliationError(f"existing_dodo_subscription_still_live:status={existing.status}")
        else:
            from app.billing.dodo_client import DodoAPIError

            existing_data: dict | None
            try:
                existing_data = client.get_subscription(existing.provider_subscription_reference)
            except DodoAPIError as exc:
                if exc.status_code == 404:
                    existing_data = None  # confirmed nonexistent in the current environment — safe
                else:
                    raise DodoReconciliationError(f"existing_subscription_status_unverifiable:{exc}") from exc
            except Exception as exc:
                raise DodoReconciliationError(f"existing_subscription_status_unverifiable:{exc}") from exc

            if existing_data:
                existing_raw_status = existing_data.get("status", "")
                if existing_raw_status in _DODO_RAW_LIVE_STATUSES:
                    raise DodoReconciliationError(f"existing_dodo_subscription_still_live:status={existing_raw_status}")
                if existing_raw_status not in _DODO_RAW_REPLACEABLE_STATUSES:
                    raise DodoReconciliationError(
                        f"existing_dodo_subscription_status_unrecognized:status={existing_raw_status}"
                    )
            # else: empty/not-found response — treated as confirmed nonexistent, safe to replace.

    try:
        data = client.get_subscription(dodo_subscription_id)
    except Exception as exc:  # DodoAPIError subclasses — already-sanitized messages, safe to surface
        raise DodoReconciliationError(f"dodo_api_error:{exc}") from exc

    if not data:
        raise DodoReconciliationError("dodo_subscription_not_found")

    target_raw_status = data.get("status", "")
    if target_raw_status != "active":
        raise DodoReconciliationError(f"target_subscription_not_active:status={target_raw_status}")

    raw_metadata = data.get("metadata")
    if isinstance(raw_metadata, dict) and raw_metadata.get("workspace_id"):
        try:
            echoed_workspace_id = uuid.UUID(str(raw_metadata["workspace_id"]))
        except (ValueError, TypeError):
            echoed_workspace_id = None
        if echoed_workspace_id is not None and echoed_workspace_id != workspace_id:
            raise DodoReconciliationError("workspace_mismatch_with_dodo_metadata")

    snapshot = adapter._snapshot_from_dodo_subscription(data, workspace_id)
    product_id = data.get("product_id", "")
    if product_id not in (mapping.pro_product_id, mapping.team_product_id):
        raise DodoReconciliationError("unknown_product_id")

    if replacing_existing and existing.provider_customer_reference:
        target_customer_id = snapshot.customer_reference.external_id or None
        if target_customer_id and target_customer_id != existing.provider_customer_reference:
            raise DodoReconciliationError("customer_mismatch_with_existing_subscription")

    if replacing_existing:
        conflicting = (
            db.query(NormalizedSubscription)
            .filter(
                NormalizedSubscription.provider_subscription_reference == dodo_subscription_id,
                NormalizedSubscription.workspace_id != workspace_id,
            )
            .first()
        )
        if conflicting is not None:
            raise DodoReconciliationError("target_subscription_already_attached_to_another_workspace")

    plan_id = snapshot.plan_id.value
    additional_seats = max(0, snapshot.billable_seats - TEAM_INCLUDED_SEATS) if plan_id == "team" else 0
    normalized_status = normalize_dodo_status(snapshot.status).value

    result = {
        "workspace_id": str(workspace_id),
        "dodo_subscription_id": dodo_subscription_id,
        "plan_id": plan_id,
        "status": normalized_status,
        "billable_seats": snapshot.billable_seats,
        "created": False,
        "replaced": False,
    }

    if not apply:
        result["would_replace"] = replacing_existing
        return result

    if replacing_existing:
        previous_plan_id = existing.plan_id
        previous_subscription_reference = existing.provider_subscription_reference
        existing.provider_subscription_reference = snapshot.subscription_reference.external_id or None
        existing.provider_customer_reference = snapshot.customer_reference.external_id or existing.provider_customer_reference
        existing.plan_id = plan_id
        existing.billing_interval = snapshot.billing_interval.value
        existing.status = normalized_status
        existing.billable_seats = snapshot.billable_seats
        existing.additional_seat_quantity = additional_seats
        existing.current_period_start = snapshot.current_period_start
        existing.current_period_end = snapshot.current_period_end
        existing.cancel_at_period_end = snapshot.cancel_at_period_end
        existing.last_provider_event = "reconciled_from_dodo"
        existing.version += 1
        db.flush()

        record_audit_event(
            workspace_id=workspace_id, event_type=BillingAuditEventType.PROVIDER_RECONCILIATION,
            provider=BillingProvider.DODO,
            details={
                "previous_plan_id": previous_plan_id, "new_plan_id": plan_id,
                "billing_interval": snapshot.billing_interval.value, "billable_seats": snapshot.billable_seats,
                "reason": (
                    f"replaced_obsolete_dodo_subscription:{previous_subscription_reference}"
                    ":historical_duplicate_subscription_recovery"
                ),
            },
            db=db,
        )
        result["replaced"] = True
        result["previous_subscription_reference"] = previous_subscription_reference
        return result

    sub = NormalizedSubscription(
        workspace_id=workspace_id,
        provider=BillingProvider.DODO.value,
        provider_customer_reference=snapshot.customer_reference.external_id or None,
        provider_subscription_reference=snapshot.subscription_reference.external_id or None,
        plan_id=plan_id,
        billing_interval=snapshot.billing_interval.value,
        status=normalized_status,
        billable_seats=snapshot.billable_seats,
        additional_seat_quantity=additional_seats,
        current_period_start=snapshot.current_period_start,
        current_period_end=snapshot.current_period_end,
        cancel_at_period_end=snapshot.cancel_at_period_end,
        last_provider_event="reconciled_from_dodo",
        version=0,
    )
    db.add(sub)
    db.flush()

    record_audit_event(
        workspace_id=workspace_id, event_type=BillingAuditEventType.PROVIDER_RECONCILIATION,
        provider=BillingProvider.DODO,
        details={"plan_id": plan_id, "billing_interval": snapshot.billing_interval.value, "billable_seats": snapshot.billable_seats},
        db=db,
    )
    result["created"] = True
    return result


class DodoLivePilotPreparationError(Exception):
    """Raised for any precondition failure in
    ``prepare_dodo_workspace_for_live_pilot`` — never for a successful
    outcome. Never carries a secret, a full raw payload, or PII."""


def prepare_dodo_workspace_for_live_pilot(
    *, workspace_id: uuid.UUID, expected_test_subscription_reference: str, db: Session, apply: bool,
) -> dict:
    """Test->Live pilot cutover preparation — a PURE LOCAL DATABASE
    operation, never a Dodo API call of any kind (Test or Live), so it is
    always safe to run regardless of which environment ``DODO_ENVIRONMENT``
    is currently pointed at.

    Root problem this repairs: a pilot workspace's ``NormalizedSubscription``
    row still references an active Dodo TEST subscription. Once
    ``DODO_ENVIRONMENT`` is switched to Live, two things go wrong if this
    row is left as-is:
      1. ``_create_plan_checkout`` (app/routers/billing.py) sees the row's
         status is still "live" (active/trialing/past_due/grace_period)
         and routes a Pro/Team click to ``change_subscription_plan``
         against the OLD TEST subscription ID using the NEW LIVE
         credentials — Dodo Live has no such subscription, so the call
         fails and the first real Live checkout is blocked entirely.
      2. Even if that were bypassed, entitlement would still nominally be
         "granted" from a subscription that no longer represents a real,
         current Live payment relationship.

    This function marks the existing row's TEST subscription obsolete —
    status becomes ``canceled`` (immediately denies paid entitlement via
    ``decide_entitlements``, which only grants access for
    trialing/active/past_due/grace_period), and BOTH
    ``provider_subscription_reference`` and ``provider_customer_reference``
    are cleared to ``None``. Clearing (rather than leaving the old Test
    IDs in place) is a deliberate defense-in-depth choice: it guarantees
    NO future webhook delivery — including a stray, late-arriving Test
    webhook retry — can ever re-match this row via
    ``_find_subscription_by_dodo_reference`` and silently revive stale
    Test-mode entitlement. The row itself, and its full webhook/audit
    history, are preserved — never deleted (message requirement: prefer
    an audited state transition over deletion). ``version`` is
    incremented and ``last_provider_event`` is set to
    ``"prepared_for_live_cutover"`` so this transition is unambiguous in
    any future inspection.

    After preparation, the workspace's ``NormalizedSubscription`` no
    longer matches ``_DODO_LIVE_STATUSES``, so the next Pro/Team click
    correctly falls through to a FRESH ``adapter.create_checkout`` call —
    a normal new Dodo (now Live) checkout, exactly like a workspace that
    never had a subscription. Because the row still exists (deliberately
    preserved, not deleted), the resulting Live webhook's
    ``_create_subscription_from_hint`` will decline to auto-create a
    second row (its "workspace already has a subscription" guard) — by
    design, this makes the FIRST Live subscription's activation an
    explicit operator action via ``reconcile-from-dodo <workspace>
    <new_live_sub_id> --live --yes`` (which already knows how to replace
    an obsolete Dodo row in place — see
    ``reconcile_workspace_from_dodo_subscription``'s replace path, which
    trusts a cleared reference's locally-recorded ``canceled`` status
    without any further Dodo call). This is intentional, not a bug:
    activating the very first real-money Live subscription for the pilot
    should never happen silently.

    Fails closed for every unsafe condition:
      * the workspace doesn't exist,
      * no ``NormalizedSubscription`` row exists for the workspace,
      * the row's provider is not ``dodo`` (Stripe/Paddle rows are never
        touched by this function, unconditionally),
      * the row's stored ``provider_subscription_reference`` does not
        exactly match the operator-supplied
        ``expected_test_subscription_reference`` — this is the core
        safety check: the operator must prove they know exactly which
        subscription they intend to obsolete, so a copy-paste mistake
        (wrong workspace, stale expectation) can never silently cancel
        the wrong subscription's entitlement.

    Idempotent: if the row was already prepared (``last_provider_event ==
    "prepared_for_live_cutover"``), re-running is a safe no-op
    (``already_prepared: True``) regardless of the expected-reference
    argument — the reference is already cleared, so there's nothing left
    to compare it against.

    Returns a dict describing the current/would-be state. ``prepared`` is
    ``False`` for a dry run or for the idempotent-no-op case.
    """
    workspace = db.get(Workspace, workspace_id)
    if workspace is None:
        raise DodoLivePilotPreparationError("workspace_not_found")

    sub = (
        db.query(NormalizedSubscription)
        .filter(NormalizedSubscription.workspace_id == workspace_id)
        .first()
    )
    if sub is None:
        raise DodoLivePilotPreparationError("no_subscription_found")

    if sub.provider != BillingProvider.DODO.value:
        raise DodoLivePilotPreparationError(f"not_a_dodo_subscription:provider={sub.provider}")

    if sub.last_provider_event == "prepared_for_live_cutover":
        return {
            "workspace_id": str(workspace_id),
            "provider": sub.provider,
            "plan_id": sub.plan_id,
            "status": sub.status,
            "provider_subscription_reference": sub.provider_subscription_reference,
            "already_prepared": True,
            "prepared": False,
            "eligible_for_live_checkout": True,
        }

    if sub.provider_subscription_reference != expected_test_subscription_reference:
        raise DodoLivePilotPreparationError(
            f"expected_subscription_mismatch:stored={sub.provider_subscription_reference!r}"
        )

    result = {
        "workspace_id": str(workspace_id),
        "provider": sub.provider,
        "plan_id": sub.plan_id,
        "status": sub.status,
        "provider_subscription_reference": sub.provider_subscription_reference,
        "already_prepared": False,
        "prepared": False,
        "eligible_for_live_checkout": False,
    }

    if not apply:
        result["would_prepare"] = True
        result["action"] = (
            "mark status=canceled, clear provider_subscription_reference and "
            "provider_customer_reference, preserve the row and all history"
        )
        return result

    previous_status = sub.status
    previous_subscription_reference = sub.provider_subscription_reference
    previous_customer_reference = sub.provider_customer_reference

    sub.status = "canceled"
    sub.provider_subscription_reference = None
    sub.provider_customer_reference = None
    sub.last_provider_event = "prepared_for_live_cutover"
    sub.version += 1
    db.flush()

    record_audit_event(
        workspace_id=workspace_id,
        event_type=BillingAuditEventType.SUBSCRIPTION_CHANGED,
        provider=BillingProvider.DODO,
        details={
            "previous_status": previous_status,
            "new_status": "canceled",
            "reason": (
                f"prepared_for_live_pilot_cutover:previous_test_subscription="
                f"{previous_subscription_reference}:previous_customer={previous_customer_reference}"
            ),
        },
        db=db,
    )

    result["status"] = "canceled"
    result["provider_subscription_reference"] = None
    result["prepared"] = True
    result["eligible_for_live_checkout"] = True
    result["previous_subscription_reference"] = previous_subscription_reference
    return result


def adapter_client_for(environment: str, api_key: str | None):
    """Small factory kept separate so tests can monkeypatch the client
    construction without touching the reconciliation logic itself."""
    from app.billing.dodo_client import DodoAPIClient, DodoClientConfig

    return DodoAPIClient(DodoClientConfig(environment=environment, api_key=api_key or ""))
