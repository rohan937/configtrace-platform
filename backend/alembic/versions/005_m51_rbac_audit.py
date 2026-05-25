"""M51: RBAC + Workspace Audit Log Polish.

Creates:
- workspace_audit_logs  — append-only record of workspace actions

No columns are added to existing tables in this migration.  Workspace
scoping for resources/changes/sync_runs is achieved via JOINs through the
integrations.workspace_id column (already present and indexed from M50).

Design note: workspace_audit_logs uses BaseImmutable (id + created_at only)
since audit records are never modified after write.

Revision ID: 005
Revises:     004
Create Date: 2026-05-25
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "workspace_audit_logs",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("workspace_id", PG_UUID(as_uuid=True), nullable=False),
        sa.Column("actor_user_id", PG_UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=True),
        sa.Column("target_id", sa.Text(), nullable=True),
        sa.Column("target_display_name", sa.Text(), nullable=True),
        sa.Column("metadata_json", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"], ["workspaces.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_workspace_audit_logs_workspace",
        "workspace_audit_logs",
        ["workspace_id", "created_at"],
    )
    op.create_index(
        "ix_workspace_audit_logs_actor",
        "workspace_audit_logs",
        ["actor_user_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_workspace_audit_logs_actor", table_name="workspace_audit_logs")
    op.drop_index("ix_workspace_audit_logs_workspace", table_name="workspace_audit_logs")
    op.drop_table("workspace_audit_logs")
