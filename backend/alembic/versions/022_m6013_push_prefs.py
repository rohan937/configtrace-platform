"""M60.13: per-device browser push preferences for Drift vs Security.

Adds three per-subscription preference columns to workspace_push_subscriptions:
  * drift_push_enabled            — default TRUE (preserves existing drift push)
  * security_push_enabled         — default FALSE (opt-in; no surprise alerts)
  * security_resolved_push_enabled — default FALSE (low-noise)

No data backfill: existing subscriptions get drift ON / security OFF, matching
current behavior.

Revision ID: mig022
Revises:     mig021
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "mig022"
down_revision = "mig021"
branch_labels = None
depends_on = None

_TABLE = "workspace_push_subscriptions"


def upgrade() -> None:
    op.add_column(
        _TABLE,
        sa.Column(
            "drift_push_enabled",
            sa.Boolean(),
            server_default="true",
            nullable=False,
        ),
    )
    op.add_column(
        _TABLE,
        sa.Column(
            "security_push_enabled",
            sa.Boolean(),
            server_default="false",
            nullable=False,
        ),
    )
    op.add_column(
        _TABLE,
        sa.Column(
            "security_resolved_push_enabled",
            sa.Boolean(),
            server_default="false",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column(_TABLE, "security_resolved_push_enabled")
    op.drop_column(_TABLE, "security_push_enabled")
    op.drop_column(_TABLE, "drift_push_enabled")
