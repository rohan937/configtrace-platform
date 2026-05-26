"""M57.2 – change_reviews table.

Revision ID: 008
Revises:     007
Create Date: 2026-05-26

Adds:
    change_reviews       — mutable review state per Change (ack / expected / snooze)
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# ── Revision chain ────────────────────────────────────────────────────────────
revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "change_reviews",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("change_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("review_status", sa.Text(), server_default="needs_review", nullable=False),
        sa.Column("reviewed_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_note", sa.Text(), nullable=True),
        sa.Column("snoozed_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("snooze_reason", sa.Text(), nullable=True),
        # ── Primary key ────────────────────────────────────────────────────────
        sa.PrimaryKeyConstraint("id", name="pk_change_reviews"),
        # ── Foreign keys ───────────────────────────────────────────────────────
        sa.ForeignKeyConstraint(
            ["change_id"], ["changes.id"],
            name="fk_change_reviews_change_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"], ["workspaces.id"],
            name="fk_change_reviews_workspace_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by_user_id"], ["users.id"],
            name="fk_change_reviews_reviewer",
            ondelete="SET NULL",
        ),
        # ── Unique constraint ──────────────────────────────────────────────────
        sa.UniqueConstraint("change_id", name="uq_change_reviews_change_id"),
    )

    # Index on change_id (unique also creates this, but being explicit for FK lookups)
    op.create_index(
        "ix_change_reviews_change_id",
        "change_reviews",
        ["change_id"],
        unique=True,
    )
    # Index on workspace_id for workspace-scoped queries
    op.create_index(
        "ix_change_reviews_workspace_id",
        "change_reviews",
        ["workspace_id"],
    )
    # Index on review_status for filtering "needs_review" counts
    op.create_index(
        "ix_change_reviews_status",
        "change_reviews",
        ["review_status"],
    )
    # Composite index for snoozed-until expiry sweeps
    op.create_index(
        "ix_change_reviews_snoozed_until",
        "change_reviews",
        ["snoozed_until"],
    )


def downgrade() -> None:
    op.drop_index("ix_change_reviews_snoozed_until", table_name="change_reviews")
    op.drop_index("ix_change_reviews_status", table_name="change_reviews")
    op.drop_index("ix_change_reviews_workspace_id", table_name="change_reviews")
    op.drop_index("ix_change_reviews_change_id", table_name="change_reviews")
    op.drop_table("change_reviews")
