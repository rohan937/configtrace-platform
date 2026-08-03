"""Commercial Infrastructure message 1 — provider-neutral billing domain.

Purely ADDITIVE: creates four new tables
(billing_provider_references, commercial_subscriptions,
commercial_webhook_events, commercial_audit_events) alongside the
existing workspace_billing / stripe_webhook_events tables, which are left
completely unmodified — no column is renamed, dropped, or backfilled.

Revision ID: mig036
Revises: mig035
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "mig036"
down_revision = "mig035"
branch_labels = None
depends_on = None

_REFERENCES = "billing_provider_references"
_SUBSCRIPTIONS = "commercial_subscriptions"
_WEBHOOK_EVENTS = "commercial_webhook_events"
_AUDIT_EVENTS = "commercial_audit_events"


def upgrade() -> None:
    op.create_table(
        _REFERENCES,
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.Text, nullable=False),
        sa.Column("object_type", sa.Text, nullable=False),
        sa.Column("external_id", sa.Text, nullable=False),
        sa.Column("reference_metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_billing_provider_references_workspace_id", _REFERENCES, ["workspace_id"])
    op.create_index(
        "uq_billing_provider_reference_external",
        _REFERENCES,
        ["provider", "object_type", "external_id"],
        unique=True,
    )

    op.create_table(
        _SUBSCRIPTIONS,
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("provider", sa.Text, nullable=False),
        sa.Column("provider_customer_reference", sa.Text, nullable=True),
        sa.Column("provider_subscription_reference", sa.Text, nullable=True),
        sa.Column("plan_id", sa.Text, nullable=False, server_default="free"),
        sa.Column("billing_interval", sa.Text, nullable=False, server_default="month"),
        sa.Column("status", sa.Text, nullable=False, server_default="active"),
        sa.Column("billable_seats", sa.Integer, nullable=False, server_default="0"),
        sa.Column("base_quantity", sa.Integer, nullable=False, server_default="0"),
        sa.Column("additional_seat_quantity", sa.Integer, nullable=False, server_default="0"),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_at_period_end", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("grace_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_provider_event", sa.Text, nullable=True),
        sa.Column("version", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_commercial_subscriptions_workspace_id", _SUBSCRIPTIONS, ["workspace_id"])

    op.create_table(
        _WEBHOOK_EVENTS,
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("provider", sa.Text, nullable=False),
        sa.Column("external_event_id", sa.Text, nullable=False),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("customer_reference", sa.Text, nullable=True),
        sa.Column("subscription_reference", sa.Text, nullable=True),
        sa.Column("transaction_reference", sa.Text, nullable=True),
        sa.Column("normalized_payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("processing_status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("attempt_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_category", sa.Text, nullable=False, server_default="none"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_commercial_webhook_events_external_event_id", _WEBHOOK_EVENTS, ["external_event_id"])
    op.create_index(
        "uq_commercial_webhook_event",
        _WEBHOOK_EVENTS,
        ["provider", "external_event_id"],
        unique=True,
    )

    op.create_table(
        _AUDIT_EVENTS,
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("provider", sa.Text, nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_commercial_audit_events_workspace_id", _AUDIT_EVENTS, ["workspace_id"])


def downgrade() -> None:
    op.drop_index("ix_commercial_audit_events_workspace_id", _AUDIT_EVENTS)
    op.drop_table(_AUDIT_EVENTS)

    op.drop_index("uq_commercial_webhook_event", _WEBHOOK_EVENTS)
    op.drop_index("ix_commercial_webhook_events_external_event_id", _WEBHOOK_EVENTS)
    op.drop_table(_WEBHOOK_EVENTS)

    op.drop_index("ix_commercial_subscriptions_workspace_id", _SUBSCRIPTIONS)
    op.drop_table(_SUBSCRIPTIONS)

    op.drop_index("uq_billing_provider_reference_external", _REFERENCES)
    op.drop_index("ix_billing_provider_references_workspace_id", _REFERENCES)
    op.drop_table(_REFERENCES)
