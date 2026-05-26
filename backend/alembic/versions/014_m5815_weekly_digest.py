"""M58.15: Add weekly digest settings columns to workspace_notification_settings.

Revision ID: mig014
Revises: mig013
Create Date: 2026-05-26
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "mig014"
down_revision = "mig013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "workspace_notification_settings",
        sa.Column(
            "weekly_digest_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "workspace_notification_settings",
        sa.Column(
            "weekly_digest_day",
            sa.SmallInteger(),
            nullable=False,
            server_default=sa.text("0"),
            comment="Day of week 0=Monday … 6=Sunday",
        ),
    )
    op.add_column(
        "workspace_notification_settings",
        sa.Column(
            "weekly_digest_hour",
            sa.SmallInteger(),
            nullable=False,
            server_default=sa.text("9"),
            comment="Hour of day 0–23 (UTC)",
        ),
    )
    op.add_column(
        "workspace_notification_settings",
        sa.Column(
            "weekly_digest_timezone",
            sa.Text(),
            nullable=True,
            comment="IANA timezone string e.g. 'America/New_York'. Null = UTC.",
        ),
    )
    op.add_column(
        "workspace_notification_settings",
        sa.Column(
            "weekly_digest_last_sent_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("workspace_notification_settings", "weekly_digest_last_sent_at")
    op.drop_column("workspace_notification_settings", "weekly_digest_timezone")
    op.drop_column("workspace_notification_settings", "weekly_digest_hour")
    op.drop_column("workspace_notification_settings", "weekly_digest_day")
    op.drop_column("workspace_notification_settings", "weekly_digest_enabled")
