"""M32: Sync Reliability — failure classification, consecutive failure tracking.

Adds structured failure fields to sync_runs and consecutive failure tracking
to integrations.  No data is lost; all new columns are nullable or have safe
defaults so existing rows continue to work without backfilling.

Revision ID: 002
Revises: 001
Create Date: 2026-05-23
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ─────────────────────────────────────────────────────────────────────────────
# UPGRADE
# ─────────────────────────────────────────────────────────────────────────────

def upgrade() -> None:
    # ── sync_runs: structured failure fields ──────────────────────────────────
    # failure_category — broad category (authentication, network, config_error …)
    # error_code       — provider-specific code (github_token_revoked, …)
    # recommended_action — user-facing remediation hint
    op.add_column("sync_runs", sa.Column("failure_category", sa.Text(), nullable=True))
    op.add_column("sync_runs", sa.Column("error_code", sa.Text(), nullable=True))
    op.add_column("sync_runs", sa.Column("recommended_action", sa.Text(), nullable=True))

    # Index: fast lookup of failed runs by category (for dashboards / alerts)
    op.create_index(
        "ix_sync_runs_integration_id_status",
        "sync_runs",
        ["integration_id", "status"],
    )

    # ── integrations: consecutive failure tracking ────────────────────────────
    # consecutive_failure_count — incremented on each scheduled failure, reset
    #   on any success.  Manual sync failures are NOT counted.
    # last_failure_at — UTC timestamp of the most recent failure (any trigger).
    # last_failure_alert_sent_at — when we last emailed the user about failures.
    #   Used for the 24-hour cooldown: we never send more than one failure alert
    #   per integration per 24 hours regardless of how many syncs fail.
    op.add_column(
        "integrations",
        sa.Column(
            "consecutive_failure_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.add_column(
        "integrations",
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "integrations",
        sa.Column(
            "last_failure_alert_sent_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# DOWNGRADE
# ─────────────────────────────────────────────────────────────────────────────

def downgrade() -> None:
    op.drop_column("integrations", "last_failure_alert_sent_at")
    op.drop_column("integrations", "last_failure_at")
    op.drop_column("integrations", "consecutive_failure_count")

    op.drop_index("ix_sync_runs_integration_id_status", table_name="sync_runs")
    op.drop_column("sync_runs", "recommended_action")
    op.drop_column("sync_runs", "error_code")
    op.drop_column("sync_runs", "failure_category")
