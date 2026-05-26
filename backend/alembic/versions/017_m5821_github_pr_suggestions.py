"""M58.21: github_pr_suggestions audit table.

Revision ID: mig017
Revises:     mig016
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "mig017"
down_revision = "mig016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "github_pr_suggestions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        # ── Ownership ──────────────────────────────────────────────────────────
        sa.Column(
            "change_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("changes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "iac_repository_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("iac_repositories.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # ── Actor ─────────────────────────────────────────────────────────────
        sa.Column("actor_user_id", sa.Text(), nullable=False),
        # ── GitHub PR metadata ────────────────────────────────────────────────
        sa.Column("pr_url", sa.Text(), nullable=False),
        sa.Column("pr_number", sa.Integer(), nullable=False),
        sa.Column("branch_name", sa.Text(), nullable=False),
        sa.Column("base_branch", sa.Text(), nullable=False),
        sa.Column("patch_file_path", sa.Text(), nullable=False),
        sa.Column("commit_sha", sa.Text(), nullable=True),
        sa.Column(
            "pr_state",
            sa.Text(),
            nullable=False,
            server_default="open",
        ),
        # ── Timestamps ────────────────────────────────────────────────────────
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

    op.create_index(
        "ix_github_pr_suggestions_change_id",
        "github_pr_suggestions",
        ["change_id"],
    )
    op.create_index(
        "ix_github_pr_suggestions_workspace_id",
        "github_pr_suggestions",
        ["workspace_id"],
    )
    op.create_index(
        "ix_github_pr_suggestions_iac_repository_id",
        "github_pr_suggestions",
        ["iac_repository_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_github_pr_suggestions_iac_repository_id",
        table_name="github_pr_suggestions",
    )
    op.drop_index(
        "ix_github_pr_suggestions_workspace_id",
        table_name="github_pr_suggestions",
    )
    op.drop_index(
        "ix_github_pr_suggestions_change_id",
        table_name="github_pr_suggestions",
    )
    op.drop_table("github_pr_suggestions")
