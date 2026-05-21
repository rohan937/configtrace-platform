"""Initial schema — all seven MVP tables.

Creates tables in FK dependency order:
  users → integrations → resources → sync_runs → snapshots → changes → alerts

All indexes from DatabaseSchema.txt are included.  DESC and GIN indexes are
created via op.execute() because Alembic's create_index helper does not natively
support sort-direction hints or non-default index access methods.

Revision ID: 001
Revises:
Create Date: 2026-05-21
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ─────────────────────────────────────────────────────────────────────────────
# UPGRADE
# ─────────────────────────────────────────────────────────────────────────────

def upgrade() -> None:

    # ── 1. users ─────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("clerk_id", sa.Text(), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
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
        sa.PrimaryKeyConstraint("id"),
    )
    # UNIQUE index doubles as the fast JWT-to-user lookup on every request.
    op.create_index("ix_users_clerk_id", "users", ["clerk_id"], unique=True)

    # ── 2. integrations ───────────────────────────────────────────────────────
    op.create_table(
        "integrations",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", UUID(as_uuid=True), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("encrypted_credentials", sa.LargeBinary(), nullable=False),
        sa.Column("credential_iv", sa.LargeBinary(), nullable=False),
        sa.Column(
            "status",
            sa.Text(),
            server_default=sa.text("'active'"),
            nullable=False,
        ),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "scheduled_sync_enabled",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("sync_interval_minutes", sa.Integer(), nullable=True),
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
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_integrations_user_id", "integrations", ["user_id"])
    op.create_index(
        "ix_integrations_user_id_status", "integrations", ["user_id", "status"]
    )

    # ── 3. resources ──────────────────────────────────────────────────────────
    op.create_table(
        "resources",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("integration_id", UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), nullable=False),
        sa.Column("provider_resource_type", sa.Text(), nullable=False),
        sa.Column("provider_resource_id", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("metadata", JSONB(), nullable=True),
        sa.Column("last_snapshot_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("true"),
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
        sa.ForeignKeyConstraint(
            ["integration_id"], ["integrations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "integration_id",
            "provider_resource_id",
            name="uq_resource_integration_provider",
        ),
    )
    op.create_index("ix_resources_integration_id", "resources", ["integration_id"])
    op.create_index("ix_resources_user_id", "resources", ["user_id"])

    # ── 4. sync_runs ──────────────────────────────────────────────────────────
    op.create_table(
        "sync_runs",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("integration_id", UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), nullable=False),
        sa.Column("triggered_by", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.Text(),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("change_count", sa.Integer(), nullable=True),
        sa.Column("snapshot_count", sa.Integer(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["integration_id"], ["integrations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    # DESC index: sync history view paginates newest-first.
    op.execute(
        "CREATE INDEX ix_sync_runs_integration_id_started_at"
        " ON sync_runs (integration_id, started_at DESC)"
    )
    op.execute(
        "CREATE INDEX ix_sync_runs_user_id_started_at"
        " ON sync_runs (user_id, started_at DESC)"
    )
    # Non-DESC: used by the scheduler to detect running syncs before enqueueing.
    op.create_index(
        "ix_sync_runs_status_started_at", "sync_runs", ["status", "started_at"]
    )

    # ── 5. snapshots ──────────────────────────────────────────────────────────
    op.create_table(
        "snapshots",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("resource_id", UUID(as_uuid=True), nullable=False),
        sa.Column("integration_id", UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), nullable=False),
        sa.Column("state", JSONB(), nullable=False),
        sa.Column("content_hash", sa.Text(), nullable=False),
        sa.Column("triggered_by", sa.Text(), nullable=False),
        sa.Column("sync_run_id", UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["integration_id"], ["integrations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["resource_id"], ["resources.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["sync_run_id"], ["sync_runs.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    # DESC indexes: diff service always queries the two most-recent snapshots.
    op.execute(
        "CREATE INDEX ix_snapshots_resource_id_created_at"
        " ON snapshots (resource_id, created_at DESC)"
    )
    op.execute(
        "CREATE INDEX ix_snapshots_integration_id_created_at"
        " ON snapshots (integration_id, created_at DESC)"
    )
    op.execute(
        "CREATE INDEX ix_snapshots_user_id_created_at"
        " ON snapshots (user_id, created_at DESC)"
    )
    # Plain index: deduplication check compares content_hash before writing.
    op.create_index("ix_snapshots_content_hash", "snapshots", ["content_hash"])
    # GIN index: enables JSONB path queries over snapshot state (Phase 2 search).
    op.execute("CREATE INDEX ix_snapshots_state_gin ON snapshots USING gin (state)")

    # ── 6. changes ────────────────────────────────────────────────────────────
    op.create_table(
        "changes",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("resource_id", UUID(as_uuid=True), nullable=False),
        sa.Column("integration_id", UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), nullable=False),
        sa.Column("prev_snapshot_id", UUID(as_uuid=True), nullable=False),
        sa.Column("new_snapshot_id", UUID(as_uuid=True), nullable=False),
        sa.Column("change_type", sa.Text(), nullable=False),
        sa.Column("record_identifier", sa.Text(), nullable=False),
        sa.Column("field_path", sa.Text(), nullable=True),
        sa.Column("prev_value", JSONB(), nullable=True),
        sa.Column("new_value", JSONB(), nullable=True),
        sa.Column("risk_level", sa.Text(), nullable=False),
        sa.Column("risk_reason", sa.Text(), nullable=True),
        sa.Column("provider_metadata", JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["integration_id"], ["integrations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["new_snapshot_id"], ["snapshots.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["prev_snapshot_id"], ["snapshots.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["resource_id"], ["resources.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    # All five changes indexes use DESC on created_at for timeline queries.
    op.execute(
        "CREATE INDEX ix_changes_user_id_created_at"
        " ON changes (user_id, created_at DESC)"
    )
    op.execute(
        "CREATE INDEX ix_changes_resource_id_created_at"
        " ON changes (resource_id, created_at DESC)"
    )
    op.execute(
        "CREATE INDEX ix_changes_integration_id_created_at"
        " ON changes (integration_id, created_at DESC)"
    )
    op.execute(
        "CREATE INDEX ix_changes_risk_level_created_at"
        " ON changes (risk_level, created_at DESC)"
    )
    # Composite: the most common dashboard query — user-scoped + risk filter.
    op.execute(
        "CREATE INDEX ix_changes_user_id_risk_level_created_at"
        " ON changes (user_id, risk_level, created_at DESC)"
    )

    # ── 7. alerts ─────────────────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("change_id", UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), nullable=False),
        sa.Column("integration_id", UUID(as_uuid=True), nullable=False),
        # nullable — alert_configs table added in Phase 3
        sa.Column("alert_config_id", UUID(as_uuid=True), nullable=True),
        sa.Column("channel", sa.Text(), nullable=False),
        sa.Column("destination", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=True),
        sa.Column(
            "status",
            sa.Text(),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "retry_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["change_id"], ["changes.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["integration_id"], ["integrations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.execute(
        "CREATE INDEX ix_alerts_user_id_created_at"
        " ON alerts (user_id, created_at DESC)"
    )
    op.create_index("ix_alerts_change_id", "alerts", ["change_id"])
    op.execute(
        "CREATE INDEX ix_alerts_status_created_at"
        " ON alerts (status, created_at DESC)"
    )


# ─────────────────────────────────────────────────────────────────────────────
# DOWNGRADE  (reverse dependency order)
# ─────────────────────────────────────────────────────────────────────────────

def downgrade() -> None:
    # DROP TABLE automatically drops all indexes on that table.
    op.drop_table("alerts")
    op.drop_table("changes")
    op.drop_table("snapshots")
    op.drop_table("sync_runs")
    op.drop_table("resources")
    op.drop_table("integrations")
    op.drop_table("users")
