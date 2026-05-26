"""010 — M58.5: Slack App installation columns.

Revision ID: 010
Revises: 009
Create Date: 2026-05-26

Adds Slack App installation columns to ``workspace_notification_settings``.
These columns store the encrypted bot token, channel selection, and
installation metadata for the Slack App OAuth flow.

Security constraints
--------------------
* ``slack_bot_token_encrypted`` and ``slack_bot_iv`` store the AES-256-GCM
  encrypted bot token.  The plaintext token is NEVER stored.
* The bot token is NEVER returned in any API response.
* The bot token is NEVER written to logs.

No destructive changes to existing tables or columns.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Slack App installation ─────────────────────────────────────────────────
    op.add_column(
        "workspace_notification_settings",
        sa.Column(
            "slack_app_enabled",
            sa.Boolean,
            nullable=False,
            server_default="false",
        ),
    )
    op.add_column(
        "workspace_notification_settings",
        sa.Column("slack_team_id", sa.Text, nullable=True),
    )
    op.add_column(
        "workspace_notification_settings",
        sa.Column("slack_team_name", sa.Text, nullable=True),
    )
    # AES-256-GCM encrypted bot token.  NEVER store plaintext.
    op.add_column(
        "workspace_notification_settings",
        sa.Column("slack_bot_token_encrypted", sa.LargeBinary, nullable=True),
    )
    # 12-byte nonce for AES-GCM decryption of the bot token.
    op.add_column(
        "workspace_notification_settings",
        sa.Column("slack_bot_iv", sa.LargeBinary, nullable=True),
    )
    op.add_column(
        "workspace_notification_settings",
        sa.Column("slack_bot_user_id", sa.Text, nullable=True),
    )
    # Chosen delivery channel.
    op.add_column(
        "workspace_notification_settings",
        sa.Column("slack_channel_id", sa.Text, nullable=True),
    )
    op.add_column(
        "workspace_notification_settings",
        sa.Column("slack_channel_name", sa.Text, nullable=True),
    )
    # Audit fields.
    op.add_column(
        "workspace_notification_settings",
        sa.Column(
            "slack_installed_by_user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "workspace_notification_settings",
        sa.Column(
            "slack_installed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "workspace_notification_settings",
        sa.Column(
            "slack_app_last_test_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "workspace_notification_settings",
        sa.Column("slack_app_last_error", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("workspace_notification_settings", "slack_app_last_error")
    op.drop_column("workspace_notification_settings", "slack_app_last_test_at")
    op.drop_column("workspace_notification_settings", "slack_installed_at")
    op.drop_column("workspace_notification_settings", "slack_installed_by_user_id")
    op.drop_column("workspace_notification_settings", "slack_channel_name")
    op.drop_column("workspace_notification_settings", "slack_channel_id")
    op.drop_column("workspace_notification_settings", "slack_bot_user_id")
    op.drop_column("workspace_notification_settings", "slack_bot_iv")
    op.drop_column("workspace_notification_settings", "slack_bot_token_encrypted")
    op.drop_column("workspace_notification_settings", "slack_team_name")
    op.drop_column("workspace_notification_settings", "slack_team_id")
    op.drop_column("workspace_notification_settings", "slack_app_enabled")
