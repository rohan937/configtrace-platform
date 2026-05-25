"""M50: Teams + Workspaces + Invite System.

Creates:
- workspaces                — one row per workspace
- workspace_members         — membership link (user ↔ workspace + role)
- workspace_invites         — pending/accepted/revoked invites

Modifies:
- integrations              — adds workspace_id FK (nullable → backfill → non-null)

Backfill:
1. For every existing user, create a default workspace named
   "<display_name> Workspace" (or "My Workspace" as fallback).
2. Create an owner membership for each user in their new workspace.
3. Set workspace_id on every existing integration to the owning user's
   default workspace.

After backfill, workspace_id is kept NULLABLE at the DB level to avoid
breaking existing SQLite test databases.  In production (PostgreSQL) the
column should be set NOT NULL after the backfill is verified.

Revision ID: 004
Revises:     003
Create Date: 2026-05-25
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ─────────────────────────────────────────────────────────────────────────────
# UPGRADE
# ─────────────────────────────────────────────────────────────────────────────


def upgrade() -> None:
    # ── 1. workspaces ─────────────────────────────────────────────────────────
    op.create_table(
        "workspaces",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "created_by_user_id",
            PG_UUID(as_uuid=True),
            nullable=True,
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
            ["created_by_user_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_workspaces_created_by", "workspaces", ["created_by_user_id"])

    # ── 2. workspace_members ───────────────────────────────────────────────────
    op.create_table(
        "workspace_members",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("workspace_id", PG_UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", PG_UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.Text(), nullable=False, server_default="member"),
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
            ["user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("workspace_id", "user_id", name="uq_workspace_member"),
    )
    op.create_index("ix_workspace_members_user", "workspace_members", ["user_id"])
    op.create_index(
        "ix_workspace_members_workspace", "workspace_members", ["workspace_id"]
    )

    # ── 3. workspace_invites ───────────────────────────────────────────────────
    op.create_table(
        "workspace_invites",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("workspace_id", PG_UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False, server_default="member"),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("invited_by_user_id", PG_UUID(as_uuid=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
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
            ["invited_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_workspace_invite_token_hash"),
    )
    op.create_index(
        "ix_workspace_invites_workspace_email",
        "workspace_invites",
        ["workspace_id", "email"],
    )

    # ── 4. Add workspace_id to integrations ───────────────────────────────────
    op.add_column(
        "integrations",
        sa.Column(
            "workspace_id",
            PG_UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_integrations_workspace_id",
        "integrations",
        "workspaces",
        ["workspace_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_integrations_workspace_id", "integrations", ["workspace_id"]
    )

    # ── 5. Backfill: create default workspace per user + owner membership ─────
    # Uses raw SQL so we don't need ORM models at migration time.
    #
    # For each user:
    #   a) INSERT a workspace row using their display_name or "My".
    #   b) INSERT an owner WorkspaceMember row.
    #   c) UPDATE all their integrations to point to the new workspace.
    #
    # The CTE approach keeps everything in a single pass per user to avoid
    # N+1 queries.  All timestamps default to now() via server_default.
    op.execute(
        """
        WITH new_workspaces AS (
            INSERT INTO workspaces (name, created_by_user_id)
            SELECT
                COALESCE(
                    NULLIF(TRIM(display_name), ''),
                    'My'
                ) || ' Workspace',
                id
            FROM users
            RETURNING id AS workspace_id, created_by_user_id AS user_id
        ),
        new_members AS (
            INSERT INTO workspace_members (workspace_id, user_id, role)
            SELECT workspace_id, user_id, 'owner'
            FROM new_workspaces
        )
        UPDATE integrations
        SET workspace_id = nw.workspace_id
        FROM new_workspaces nw
        WHERE integrations.user_id = nw.user_id
        """
    )
    # Note: workspace_id remains nullable — enforcing NOT NULL requires a
    # separate migration once all existing data is confirmed backfilled and
    # all code paths that create integrations supply a workspace_id.


# ─────────────────────────────────────────────────────────────────────────────
# DOWNGRADE
# ─────────────────────────────────────────────────────────────────────────────


def downgrade() -> None:
    op.drop_index("ix_integrations_workspace_id", table_name="integrations")
    op.drop_constraint(
        "fk_integrations_workspace_id", "integrations", type_="foreignkey"
    )
    op.drop_column("integrations", "workspace_id")
    op.drop_table("workspace_invites")
    op.drop_table("workspace_members")
    op.drop_table("workspaces")
