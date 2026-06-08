"""M61.8: Drift-vs-Security email routing settings.

Adds three nullable/defaulted columns to workspace_notification_settings:
  * email_security_alerts_enabled    — default FALSE (opt-in; no surprise emails)
  * email_security_resolved_enabled  — default FALSE (low-noise)
  * email_security_recipients        — TEXT nullable (blank = default recipient)

Drift/change email behavior is unchanged. No backfill — existing workspaces keep
security email OFF and continue sending drift emails exactly as before.

Revision ID: mig027
Revises:     mig026
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "mig027"
down_revision = "mig026"
branch_labels = None
depends_on = None

_TABLE = "workspace_notification_settings"


def upgrade() -> None:
    op.add_column(
        _TABLE,
        sa.Column(
            "email_security_alerts_enabled",
            sa.Boolean(),
            server_default="false",
            nullable=False,
        ),
    )
    op.add_column(
        _TABLE,
        sa.Column(
            "email_security_resolved_enabled",
            sa.Boolean(),
            server_default="false",
            nullable=False,
        ),
    )
    op.add_column(
        _TABLE,
        sa.Column("email_security_recipients", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column(_TABLE, "email_security_recipients")
    op.drop_column(_TABLE, "email_security_alerts_enabled")
    op.drop_column(_TABLE, "email_security_resolved_enabled")
