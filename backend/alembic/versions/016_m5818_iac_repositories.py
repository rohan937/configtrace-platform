"""M58.18: iac_repositories and iac_resource_mappings tables.

Revision ID: mig016
Revises:     mig015
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "mig016"
down_revision = "mig015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── iac_repositories ──────────────────────────────────────────────────────
    op.create_table(
        "iac_repositories",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        # ── Ownership ──────────────────────────────────────────────────────────
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "integration_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("integrations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # ── Repository details ─────────────────────────────────────────────────
        sa.Column(
            "provider",
            sa.Text(),
            nullable=False,
            server_default="github",
        ),
        sa.Column("repo_full_name", sa.Text(), nullable=False),
        sa.Column("default_branch", sa.Text(), nullable=True),
        sa.Column("installation_id", sa.Text(), nullable=True),
        sa.Column(
            "scanning_enabled",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        # ── Scan state ─────────────────────────────────────────────────────────
        sa.Column("last_scan_status", sa.Text(), nullable=True),
        sa.Column(
            "last_scan_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
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
        "ix_iac_repositories_workspace_id",
        "iac_repositories",
        ["workspace_id"],
    )
    op.create_index(
        "ix_iac_repositories_workspace_repo",
        "iac_repositories",
        ["workspace_id", "repo_full_name"],
    )

    # ── iac_resource_mappings ─────────────────────────────────────────────────
    op.create_table(
        "iac_resource_mappings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        # ── Ownership ──────────────────────────────────────────────────────────
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "iac_repository_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("iac_repositories.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # ── Resource identification ────────────────────────────────────────────
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.Text(), nullable=False),
        sa.Column("terraform_resource_type", sa.Text(), nullable=True),
        sa.Column("terraform_resource_name", sa.Text(), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=True),
        sa.Column("line_end", sa.Integer(), nullable=True),
        # Safe cloud identifiers only — no credentials or full ARNs with secrets.
        sa.Column("cloud_resource_identifier", sa.Text(), nullable=True),
        sa.Column("cloud_resource_name", sa.Text(), nullable=True),
        # ── Match metadata ─────────────────────────────────────────────────────
        sa.Column("match_confidence", sa.Text(), nullable=False),
        sa.Column("match_reason", sa.Text(), nullable=False),
        sa.Column("mapping_source", sa.Text(), nullable=False),
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
        "ix_iac_resource_mappings_workspace_id",
        "iac_resource_mappings",
        ["workspace_id"],
    )
    op.create_index(
        "ix_iac_resource_mappings_repository_id",
        "iac_resource_mappings",
        ["iac_repository_id"],
    )
    op.create_index(
        "ix_iac_resource_mappings_tf_type",
        "iac_resource_mappings",
        ["terraform_resource_type"],
    )


def downgrade() -> None:
    op.drop_index("ix_iac_resource_mappings_tf_type", table_name="iac_resource_mappings")
    op.drop_index("ix_iac_resource_mappings_repository_id", table_name="iac_resource_mappings")
    op.drop_index("ix_iac_resource_mappings_workspace_id", table_name="iac_resource_mappings")
    op.drop_table("iac_resource_mappings")

    op.drop_index("ix_iac_repositories_workspace_repo", table_name="iac_repositories")
    op.drop_index("ix_iac_repositories_workspace_id", table_name="iac_repositories")
    op.drop_table("iac_repositories")
