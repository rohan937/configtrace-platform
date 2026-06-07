"""M60.3: add security_findings table.

Foundation for Security Exposure findings (the "what is dangerous right now"
product mode). This migration ONLY creates the table, its indexes, and the
partial unique index that prevents duplicate *active* findings. No evaluation
engine, no data backfill.

Active-finding uniqueness
-------------------------
A partial unique index enforces at most one ACTIVE finding per logical issue
(workspace_id, integration_id, resource_id, finding_key). A NULL resource_id is
COALESCEd to a sentinel UUID so integration-level findings dedup too. Because
the predicate is ``WHERE status = 'active'``, resolved/accepted/snoozed rows
never block a fresh active finding.

Revision ID: mig020
Revises:     mig019
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "mig020"
down_revision = "mig019"
branch_labels = None
depends_on = None


_ACTIVE_UNIQUE_INDEX = "uq_security_findings_active_logical"


def upgrade() -> None:
    op.create_table(
        "security_findings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "workspace_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "integration_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "linked_change_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("finding_key", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.Text(),
            server_default="active",
            nullable=False,
        ),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=True),
        sa.Column("remediation", postgresql.JSONB(), nullable=True),
        sa.Column(
            "first_detected_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "reviewed_by_user_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
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
            ["workspace_id"], ["workspaces.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["integration_id"], ["integrations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["resource_id"], ["resources.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["linked_change_id"], ["changes.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Practical single-column indexes for common filters.
    op.create_index(
        "ix_security_findings_workspace_id", "security_findings", ["workspace_id"]
    )
    op.create_index(
        "ix_security_findings_integration_id",
        "security_findings",
        ["integration_id"],
    )
    op.create_index(
        "ix_security_findings_resource_id", "security_findings", ["resource_id"]
    )
    op.create_index(
        "ix_security_findings_provider", "security_findings", ["provider"]
    )
    op.create_index(
        "ix_security_findings_status", "security_findings", ["status"]
    )
    op.create_index(
        "ix_security_findings_severity", "security_findings", ["severity"]
    )
    op.create_index(
        "ix_security_findings_finding_key", "security_findings", ["finding_key"]
    )
    op.create_index(
        "ix_security_findings_first_detected_at",
        "security_findings",
        ["first_detected_at"],
    )
    op.create_index(
        "ix_security_findings_last_seen_at",
        "security_findings",
        ["last_seen_at"],
    )
    # Common list query: a workspace's findings filtered by status.
    op.create_index(
        "ix_security_findings_workspace_status",
        "security_findings",
        ["workspace_id", "status"],
    )

    # Partial unique index: one ACTIVE finding per logical issue. NULL
    # resource_id is COALESCEd to a sentinel so integration-level findings
    # also dedup. Created via raw SQL because it uses both an expression and a
    # WHERE predicate.
    op.execute(
        f"""
        CREATE UNIQUE INDEX {_ACTIVE_UNIQUE_INDEX}
        ON security_findings (
            workspace_id,
            integration_id,
            COALESCE(resource_id, '00000000-0000-0000-0000-000000000000'::uuid),
            finding_key
        )
        WHERE status = 'active'
        """
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS {_ACTIVE_UNIQUE_INDEX}")
    op.drop_index(
        "ix_security_findings_workspace_status", table_name="security_findings"
    )
    op.drop_index(
        "ix_security_findings_last_seen_at", table_name="security_findings"
    )
    op.drop_index(
        "ix_security_findings_first_detected_at", table_name="security_findings"
    )
    op.drop_index(
        "ix_security_findings_finding_key", table_name="security_findings"
    )
    op.drop_index(
        "ix_security_findings_severity", table_name="security_findings"
    )
    op.drop_index("ix_security_findings_status", table_name="security_findings")
    op.drop_index(
        "ix_security_findings_provider", table_name="security_findings"
    )
    op.drop_index(
        "ix_security_findings_resource_id", table_name="security_findings"
    )
    op.drop_index(
        "ix_security_findings_integration_id", table_name="security_findings"
    )
    op.drop_index(
        "ix_security_findings_workspace_id", table_name="security_findings"
    )
    op.drop_table("security_findings")
