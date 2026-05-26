"""M58.16: expected_change_windows table.

Revision ID: mig015
Revises:     mig014
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "mig015"
down_revision = "mig014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "expected_change_windows",
        # ── Primary key ────────────────────────────────────────────────────
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        # ── Ownership ──────────────────────────────────────────────────────
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "approved_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # ── Window definition ──────────────────────────────────────────────
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=False),
        # ── Workflow state ─────────────────────────────────────────────────
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default="pending",
        ),
        # ── Alert behaviour ────────────────────────────────────────────────
        sa.Column(
            "alert_behavior",
            sa.Text(),
            nullable=False,
            server_default="annotate_only",
        ),
        # ── Optional filters ───────────────────────────────────────────────
        sa.Column("filter_provider", sa.Text(), nullable=True),
        sa.Column(
            "filter_integration_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("filter_risk_level", sa.Text(), nullable=True),
        # ── Approval / rejection metadata ──────────────────────────────────
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        # ── Timestamps ────────────────────────────────────────────────────
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
    )

    # Indices
    op.create_index(
        "ix_expected_change_windows_workspace_id",
        "expected_change_windows",
        ["workspace_id"],
    )
    op.create_index(
        "ix_expected_change_windows_status",
        "expected_change_windows",
        ["status"],
    )
    op.create_index(
        "ix_expected_change_windows_start_end",
        "expected_change_windows",
        ["start_time", "end_time"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_expected_change_windows_start_end",
        table_name="expected_change_windows",
    )
    op.drop_index(
        "ix_expected_change_windows_status",
        table_name="expected_change_windows",
    )
    op.drop_index(
        "ix_expected_change_windows_workspace_id",
        table_name="expected_change_windows",
    )
    op.drop_table("expected_change_windows")
