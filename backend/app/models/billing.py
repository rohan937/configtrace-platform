"""WorkspaceBilling model — M52: Billing + Usage Limits.

One row per workspace. Created as "free" when a workspace is first used in a
billing context (lazy creation).  Updated by Stripe webhook events.

Plans
-----
free  — 3 integrations, 1 member (owner only), 60-min sync interval, 30d history
pro   — 20 integrations, 5 members, 15-min sync interval, 180d history
team  — 100 integrations, 25 members, 5-min sync interval, 365d history

Status values (mirrors Stripe subscription statuses)
------------------------------------------------------
active        — paid and current
trialing      — in a free trial
past_due      — payment failed; grace period still running
canceled      — subscription ended; workspace reverted to free limits
unpaid        — payment failed after all retries
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


class WorkspaceBilling(BaseMixin, Base):
    """Billing record for a workspace.

    Security invariants
    -------------------
    * stripe_customer_id and stripe_subscription_id are Stripe-generated
      identifiers — safe to store; they convey no payment information.
    * No card numbers, CVVs, or bank details are ever stored here.
    * stripe_price_id is Stripe's price identifier — safe to log.
    """

    __tablename__ = "workspace_billing"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,  # One billing record per workspace.
        index=True,
    )

    # "free" | "pro" | "team"
    plan: Mapped[str] = mapped_column(Text, nullable=False, default="free")

    # Mirrors Stripe subscription status.  "active" for free plan (no Stripe sub).
    # "active" | "trialing" | "past_due" | "canceled" | "unpaid"
    status: Mapped[str] = mapped_column(Text, nullable=False, default="active")

    # Stripe Customer ID (cus_...) — created when the workspace first clicks
    # "Upgrade"; NULL until then.
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Stripe Subscription ID (sub_...) — NULL for free plan.
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Stripe Price ID that drives the subscription — NULL for free plan.
    stripe_price_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Subscription billing period boundaries (UTC).  NULL for free plan.
    current_period_start: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    current_period_end: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # True when the user has scheduled a cancellation at period end.
    cancel_at_period_end: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    # Trial end date — NULL when no trial is active.
    trial_end: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"<WorkspaceBilling workspace={self.workspace_id} "
            f"plan={self.plan!r} status={self.status!r}>"
        )


class StripeWebhookEvent(Base):
    """Processed Stripe webhook event log — M59.4 idempotency.

    Stripe occasionally re-delivers webhooks on transient network errors;
    this table records the ``event_id`` of every successfully-processed
    event so duplicates can be detected and short-circuited.

    Security invariants
    -------------------
    * ``event_id`` is Stripe-generated (``evt_*``) — safe to store.
    * No customer or subscription PII is stored here; lookup is by event id only.
    * Row is inserted at the END of successful processing (same transaction as
      any billing-row writes).  If processing rolls back, the row rolls back
      too — a subsequent retry will re-process cleanly.
    """

    __tablename__ = "stripe_webhook_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    event_id: Mapped[str] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )

    def __repr__(self) -> str:
        return f"<StripeWebhookEvent {self.event_id!r} type={self.event_type!r}>"
