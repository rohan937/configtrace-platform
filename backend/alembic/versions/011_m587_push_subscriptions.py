"""M58.7: workspace_push_subscriptions table.

Revision ID: mig011
Revises: mig010
Create Date: 2026-05-26
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "mig011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workspace_push_subscriptions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        # Encrypted push subscription data (endpoint + p256dh + auth keys together).
        # NEVER store plaintext endpoint or keys.
        sa.Column("subscription_encrypted", sa.LargeBinary, nullable=False),
        sa.Column("subscription_iv", sa.LargeBinary, nullable=False),
        # Safe metadata.
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("browser_name", sa.Text, nullable=True),
        sa.Column("device_label", sa.Text, nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("min_risk_level", sa.Text, nullable=False, server_default="high"),
        # Timestamps.
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        # Sanitized last delivery error.
        sa.Column("last_error", sa.Text, nullable=True),
    )
    op.create_index("ix_workspace_push_subscriptions_workspace_id", "workspace_push_subscriptions", ["workspace_id"])
    op.create_index("ix_workspace_push_subscriptions_enabled", "workspace_push_subscriptions", ["workspace_id", "enabled"])


def downgrade() -> None:
    op.drop_index("ix_workspace_push_subscriptions_enabled", "workspace_push_subscriptions")
    op.drop_index("ix_workspace_push_subscriptions_workspace_id", "workspace_push_subscriptions")
    op.drop_table("workspace_push_subscriptions")
