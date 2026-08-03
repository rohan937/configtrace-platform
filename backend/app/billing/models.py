"""Provider-neutral commercial persistence models (Commercial Infrastructure message 1).

All four tables here are NEW and ADDITIVE — they sit alongside the existing
``app.models.billing.WorkspaceBilling`` / ``StripeWebhookEvent`` tables
without modifying them. Existing Stripe fields
(``stripe_customer_id``/``stripe_subscription_id``/``stripe_price_id``) are
preserved unchanged as documented compatibility fields (message-1 spec
item 6) — this message does not remove or migrate them.

Tables
------
billing_provider_references   — BillingProviderReference: pointer to one
                                 external, provider-owned object.
commercial_subscriptions      — NormalizedSubscription: the provider-neutral
                                 subscription aggregate (message-1 spec item 21).
commercial_webhook_events     — BillingWebhookEvent: provider-neutral webhook
                                 log + (provider, external_event_id) idempotency.
commercial_audit_events       — BillingAuditEvent: append-only commercial audit log.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseImmutable, BaseMixin


class BillingProviderReference(BaseMixin, Base):
    """A pointer to one external, provider-owned object (message-1 spec
    item 5). ``external_id`` is NEVER treated as application authority —
    only as a lookup key back to the provider.

    Uniqueness: one (provider, object_type, external_id) triple identifies
    exactly one external object; one (workspace_id, provider, object_type)
    identifies at most one CURRENT reference of that type for a workspace
    (a workspace may have had a prior Stripe customer superseded by a new
    Paddle customer post-cutover, but at any given time only one active
    reference per type should exist — enforced at the service layer via
    this composite uniqueness, not by a partial index, since "current"
    depends on cutover state this message does not build).
    """

    __tablename__ = "billing_provider_references"
    __table_args__ = (
        UniqueConstraint(
            "provider", "object_type", "external_id",
            name="uq_billing_provider_reference_external",
        ),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # "stripe" | "paddle" — see app.billing.enums.BillingProvider
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    # "customer" | "subscription" | "product" | "price" | "transaction" | "invoice"
    object_type: Mapped[str] = mapped_column(Text, nullable=False)
    external_id: Mapped[str] = mapped_column(Text, nullable=False)
    reference_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    def __repr__(self) -> str:
        return (
            f"<BillingProviderReference {self.provider}:{self.object_type}:"
            f"{self.external_id}>"
        )


class NormalizedSubscription(BaseMixin, Base):
    """Provider-neutral subscription aggregate (message-1 spec item 21).

    One row per workspace's CURRENT commercial subscription state, kept in
    sync (message 2+) from provider webhooks via
    ``app.billing.adapters.*``. ``version`` supports optimistic
    concurrency / stale-event detection (message-1 spec item 26) — a
    webhook whose provider-side version/timestamp is not newer than the
    stored one is treated as a stale, non-authoritative update rather than
    applied blindly.
    """

    __tablename__ = "commercial_subscriptions"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    provider_customer_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    provider_subscription_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    plan_id: Mapped[str] = mapped_column(Text, nullable=False, default="free")
    billing_interval: Mapped[str] = mapped_column(Text, nullable=False, default="month")
    # Normalized status — see app.billing.enums.NormalizedSubscriptionStatus
    status: Mapped[str] = mapped_column(Text, nullable=False, default="active")
    billable_seats: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    base_quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    additional_seat_quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_period_start: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    grace_period_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_provider_event: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    def __repr__(self) -> str:
        return (
            f"<NormalizedSubscription workspace={self.workspace_id} "
            f"provider={self.provider!r} status={self.status!r}>"
        )


class BillingWebhookEvent(BaseMixin, Base):
    """Provider-neutral webhook event log + idempotency (message-1 spec
    items 23-26). Uniqueness on (provider, external_event_id) is the
    idempotency key — a duplicate delivery is detected by this constraint,
    never by re-parsing the payload.

    Raw-payload handling policy (message-1 spec item 23): the raw provider
    payload is NOT persisted by default — only ``normalized_payload``
    (a small, allowlisted, non-sensitive JSON summary) is stored. This
    matches the existing ``StripeWebhookEvent`` table's policy of storing
    only the event_id + event_type, extended here with a normalized,
    reference-only payload for the additional fields entitlement/audit
    logic needs (customer/subscription/transaction references, occurred_at).
    """

    __tablename__ = "commercial_webhook_events"
    __table_args__ = (
        UniqueConstraint("provider", "external_event_id", name="uq_commercial_webhook_event"),
    )

    provider: Mapped[str] = mapped_column(Text, nullable=False)
    external_event_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    # See app.billing.enums.WebhookEventType
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    customer_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    subscription_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    transaction_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Small, allowlisted, non-sensitive normalized summary — never the raw
    # provider payload (which may contain more than we've reviewed for PII).
    normalized_payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # "pending" | "processed" | "failed" | "duplicate_ignored"
    processing_status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # "none" | "signature_invalid" | "unknown_reference" | "stale_event" | "transient" | "unexpected"
    error_category: Mapped[str] = mapped_column(Text, nullable=False, default="none")

    def __repr__(self) -> str:
        return (
            f"<BillingWebhookEvent {self.provider}:{self.external_event_id} "
            f"status={self.processing_status!r}>"
        )


class BillingAuditEvent(BaseImmutable, Base):
    """Append-only commercial audit log (message-1 spec item 27). Never
    logs credentials or a complete provider payload — only the
    small, allowlisted ``details`` summary."""

    __tablename__ = "commercial_audit_events"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # See app.billing.enums.BillingAuditEventType
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    def __repr__(self) -> str:
        return f"<BillingAuditEvent workspace={self.workspace_id} type={self.event_type!r}>"
