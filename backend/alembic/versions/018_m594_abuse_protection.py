"""M59.4: abuse-protection columns and Stripe webhook event-id dedupe.

Adds:
* ``workspace_notification_settings.last_test_notification_at`` — workspace-wide
  cooldown timestamp for /test endpoints (Slack/push/webhook/digest).
* ``stripe_webhook_events`` — processed-Stripe-event log (idempotency).

Revision ID: mig018
Revises:     mig017
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "mig018"
down_revision = "mig017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Notification-test cooldown timestamp ──────────────────────────────────
    op.add_column(
        "workspace_notification_settings",
        sa.Column(
            "last_test_notification_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # ── Processed Stripe webhook events (idempotency log) ─────────────────────
    op.create_table(
        "stripe_webhook_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        # Stripe's event id (evt_*).  Unique — duplicates are dedup'd.
        sa.Column("event_id", sa.Text(), nullable=False, unique=True),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column(
            "processed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_stripe_webhook_events_event_id",
        "stripe_webhook_events",
        ["event_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_stripe_webhook_events_event_id", table_name="stripe_webhook_events")
    op.drop_table("stripe_webhook_events")
    op.drop_column("workspace_notification_settings", "last_test_notification_at")
