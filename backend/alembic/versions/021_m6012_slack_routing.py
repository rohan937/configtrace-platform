"""M60.12: separate Slack channel routing for Drift vs Security.

Adds opt-in routing columns to workspace_notification_settings:
  * slack_drift_channel_id        — drift alerts channel override (NULL → default)
  * slack_security_channel_id     — security alerts channel override (NULL → default)
  * slack_security_alerts_enabled — opt-in to send security exposure alerts to
                                    Slack (default false → existing workspaces
                                    keep log-only behavior, no surprise messages)
  * slack_security_resolved_enabled — opt-in to send resolved-exposure messages
                                      (default false; resolved is low-noise)

No data backfill: new columns default to NULL / false on existing rows.

Revision ID: mig021
Revises:     mig020
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "mig021"
down_revision = "mig020"
branch_labels = None
depends_on = None

_TABLE = "workspace_notification_settings"


def upgrade() -> None:
    op.add_column(
        _TABLE, sa.Column("slack_drift_channel_id", sa.Text(), nullable=True)
    )
    op.add_column(
        _TABLE, sa.Column("slack_security_channel_id", sa.Text(), nullable=True)
    )
    op.add_column(
        _TABLE,
        sa.Column(
            "slack_security_alerts_enabled",
            sa.Boolean(),
            server_default="false",
            nullable=False,
        ),
    )
    op.add_column(
        _TABLE,
        sa.Column(
            "slack_security_resolved_enabled",
            sa.Boolean(),
            server_default="false",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column(_TABLE, "slack_security_resolved_enabled")
    op.drop_column(_TABLE, "slack_security_alerts_enabled")
    op.drop_column(_TABLE, "slack_security_channel_id")
    op.drop_column(_TABLE, "slack_drift_channel_id")
