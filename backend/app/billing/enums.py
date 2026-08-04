"""Bounded enums for the provider-neutral billing domain (message 1).

Every enum here is a closed, stable set of string values — never an
arbitrary string constructed ad hoc elsewhere in the codebase. Extending a
set requires a deliberate code change and review, not a typo-prone literal
scattered across call sites.
"""

from __future__ import annotations

import enum


class BillingProvider(str, enum.Enum):
    """The bounded set of billing providers this codebase knows how to
    adapt to. Paddle is the target/replacement provider; Stripe remains a
    supported compatibility adapter during migration (message 1) and is
    removed only after the message-2+ cutover and rollback window. Dodo
    Payments (Commercial Infrastructure — Dodo message 1) is a THIRD,
    independent adapter — added for Test Mode implementation only; it does
    not change the ``BILLING_PROVIDER`` default and is never routed to in
    any deployed environment by this change."""

    STRIPE = "stripe"
    PADDLE = "paddle"
    DODO = "dodo"


class BillingInterval(str, enum.Enum):
    """Billing interval taxonomy. Only MONTH is used in message 1 — the
    set exists as an enum (not a bare string) specifically so a future
    ANNUAL interval can be added without any call site needing to change
    from a string literal to an enum member."""

    MONTH = "month"
    YEAR = "year"  # reserved for a future annual-pricing message; unused in M1


class PlanId(str, enum.Enum):
    """Stable internal plan identity. Never a Paddle, Stripe, or Dodo
    product ID — those are external references mapped via
    ``BillingProviderReference``. PRO was added alongside the Dodo Payments
    integration (flat $10/month, no seat component) — see
    ``app.billing.plans.PRO_PLAN`` and ``app.billing.pricing`` for its
    canonical definition. Adding it does not change FREE or TEAM behavior."""

    FREE = "free"
    PRO = "pro"
    TEAM = "team"


class ObjectType(str, enum.Enum):
    """The kinds of external, provider-owned objects a
    ``BillingProviderReference`` row may point to."""

    CUSTOMER = "customer"
    SUBSCRIPTION = "subscription"
    PRODUCT = "product"
    PRICE = "price"
    TRANSACTION = "transaction"
    INVOICE = "invoice"


class NormalizedSubscriptionStatus(str, enum.Enum):
    """Provider-neutral subscription status. Every provider-specific status
    string (Stripe's ``active``/``past_due``/... , Paddle's own status
    vocabulary) is mapped into exactly one of these — feature gates and
    entitlement decisions read ONLY this enum, never a raw provider string."""

    TRIALING = "trialing"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    GRACE_PERIOD = "grace_period"
    PAUSED = "paused"
    CANCELED = "canceled"
    EXPIRED = "expired"
    INCOMPLETE = "incomplete"


class WebhookEventType(str, enum.Enum):
    """Provider-neutral webhook event taxonomy. Every provider-specific
    event name (Stripe's ``customer.subscription.updated``, a future
    Paddle event name) is normalized into exactly one of these before
    persistence or processing."""

    SUBSCRIPTION_CREATED = "subscription_created"
    SUBSCRIPTION_UPDATED = "subscription_updated"
    SUBSCRIPTION_CANCELED = "subscription_canceled"
    SUBSCRIPTION_PAUSED = "subscription_paused"
    SUBSCRIPTION_RESUMED = "subscription_resumed"
    TRANSACTION_COMPLETED = "transaction_completed"
    TRANSACTION_FAILED = "transaction_failed"
    PAYMENT_PAST_DUE = "payment_past_due"
    CUSTOMER_UPDATED = "customer_updated"
    UNKNOWN = "unknown"


class WebhookProcessingStatus(str, enum.Enum):
    """Lifecycle status of a persisted ``BillingWebhookEvent`` row."""

    PENDING = "pending"
    PROCESSED = "processed"
    FAILED = "failed"
    DUPLICATE_IGNORED = "duplicate_ignored"


class WebhookErrorCategory(str, enum.Enum):
    """Coarse error classification for a failed webhook processing attempt
    — enough to distinguish "retry will help" from "this will never
    succeed" without persisting exception internals."""

    NONE = "none"
    SIGNATURE_INVALID = "signature_invalid"
    UNKNOWN_REFERENCE = "unknown_reference"
    STALE_EVENT = "stale_event"
    TRANSIENT = "transient"
    UNEXPECTED = "unexpected"


class DesiredSubscriptionReason(str, enum.Enum):
    """Why a ``DesiredSubscriptionState`` was (re)calculated."""

    MEMBER_ADDED = "member_added"
    MEMBER_REMOVED = "member_removed"
    INVITE_ACCEPTED = "invite_accepted"
    MEMBER_DEACTIVATED = "member_deactivated"
    PLAN_CHANGED = "plan_changed"
    RECONCILIATION = "reconciliation"


class BillingAuditEventType(str, enum.Enum):
    """Append-only commercial audit event taxonomy."""

    CHECKOUT_CREATED = "checkout_created"
    SUBSCRIPTION_ACTIVATED = "subscription_activated"
    SUBSCRIPTION_CHANGED = "subscription_changed"
    SEAT_COUNT_CHANGED = "seat_count_changed"
    PAYMENT_FAILED = "payment_failed"
    GRACE_PERIOD_STARTED = "grace_period_started"
    SUBSCRIPTION_CANCELED = "subscription_canceled"
    ENTITLEMENT_CHANGED = "entitlement_changed"
    PROVIDER_RECONCILIATION = "provider_reconciliation"
    WEBHOOK_DUPLICATE_IGNORED = "webhook_duplicate_ignored"
