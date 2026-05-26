"""M57.1: Workspace Notification Settings (Slack + Webhook).

Creates:
- workspace_notification_settings — one row per workspace; stores encrypted
  Slack and generic webhook URLs alongside enabled flags and a risk-level
  filter.

Design notes:
- Uses BaseMixin (id + created_at + updated_at) because the row is mutated
  whenever the user updates their notification settings.
- unique constraint on workspace_id enforces the one-row-per-workspace
  invariant at the database level.
- No backfill: rows are created lazily on first GET or PUT for a workspace.
  This avoids requiring a valid ENCRYPTION_KEY at migration time.

Revision ID: 007
Revises:     006
Create Date: 2026-05-25
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "workspace_notification_settings",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("workspace_id", PG_UUID(as_uuid=True), nullable=False),
        # Slack incoming webhook
        sa.Column(
            "slack_enabled",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column("slack_webhook_url_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("slack_webhook_iv", sa.LargeBinary(), nullable=True),
        # Generic webhook
        sa.Column(
            "webhook_enabled",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column("webhook_url_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("webhook_iv", sa.LargeBinary(), nullable=True),
        # Risk-level filter
        sa.Column(
            "notify_on_risk_level",
            sa.Text(),
            nullable=False,
            server_default="high_and_critical",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"], ["workspaces.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workspace_id",
            name="uq_workspace_notification_settings_workspace",
        ),
    )
    op.create_index(
        "ix_workspace_notification_settings_workspace_id",
        "workspace_notification_settings",
        ["workspace_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_workspace_notification_settings_workspace_id",
        table_name="workspace_notification_settings",
    )
    op.drop_table("workspace_notification_settings")
