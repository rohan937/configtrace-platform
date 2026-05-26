"""M58.8: change_notes table.

Revision ID: mig012
Revises: mig011
Create Date: 2026-05-26
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "mig012"
down_revision = "mig011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "change_notes",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "change_id",
            UUID(as_uuid=True),
            sa.ForeignKey("changes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Denormalised workspace FK — nullable so old/orphan rows remain valid.
        sa.Column(
            "workspace_id",
            UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "author_user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("body", sa.Text, nullable=False),
        # Timestamps — managed by BaseMixin defaults and onupdate.
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_change_notes_change_id", "change_notes", ["change_id"])
    op.create_index("ix_change_notes_workspace_id", "change_notes", ["workspace_id"])


def downgrade() -> None:
    op.drop_index("ix_change_notes_workspace_id", "change_notes")
    op.drop_index("ix_change_notes_change_id", "change_notes")
    op.drop_table("change_notes")
