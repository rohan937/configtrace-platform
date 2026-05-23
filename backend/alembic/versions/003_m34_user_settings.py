"""M34: Dashboard Command Center + Advanced Settings.

Creates the ``user_settings`` table — one row per user, lazily created on
first GET /settings.  All columns have safe server-side defaults that match
existing hardcoded behavior so no backfill is needed and existing users see
no change.

Schema rationale
----------------
* ``alert_risk_threshold = 'high_and_critical'``
    Matches ``_ALERTABLE_LEVELS = frozenset({"high", "critical"})`` in
    ``alert_service.py``.

* ``sync_failure_threshold = 3``
    Matches ``NEEDS_ATTENTION_THRESHOLD = 3`` in ``failure_classifier.py``.

* ``sync_failure_cooldown_hours = 24``
    Matches ``FAILURE_ALERT_COOLDOWN_SECONDS = 86_400`` (86400 / 3600 = 24).

* ``default_sync_enabled = false``
    New integrations start with scheduled sync off (existing behavior).

Revision ID: 003
Revises: 002
Create Date: 2026-05-23
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ─────────────────────────────────────────────────────────────────────────────
# UPGRADE
# ─────────────────────────────────────────────────────────────────────────────

def upgrade() -> None:
    op.create_table(
        "user_settings",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
            primary_key=True,
        ),
        sa.Column(
            "user_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Alert policy
        sa.Column(
            "alert_risk_threshold",
            sa.Text(),
            nullable=False,
            server_default="high_and_critical",
        ),
        sa.Column(
            "sync_failure_alerts_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "sync_failure_threshold",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("3"),
        ),
        sa.Column(
            "sync_failure_cooldown_hours",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("24"),
        ),
        # Sync defaults (new integrations only)
        sa.Column(
            "default_sync_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "default_sync_interval_minutes",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("60"),
        ),
        sa.Column(
            "default_change_alerts_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        # UI preferences
        sa.Column(
            "default_timeline_range",
            sa.Text(),
            nullable=False,
            server_default="7d",
        ),
        sa.Column(
            "default_provider_filter",
            sa.Text(),
            nullable=False,
            server_default="all",
        ),
        # Timestamps
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
        # Unique constraint — one settings row per user
        sa.UniqueConstraint("user_id", name="uq_user_settings_user_id"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# DOWNGRADE
# ─────────────────────────────────────────────────────────────────────────────

def downgrade() -> None:
    op.drop_table("user_settings")
