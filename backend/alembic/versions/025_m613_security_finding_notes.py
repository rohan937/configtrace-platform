"""M61.3: security_finding_notes table (review notes + audit/activity layer).

Append-only review notes attached to a security finding. The activity feed is
DERIVED at read time from finding lifecycle fields + these notes, so no extra
audit table is introduced.

Revision ID: mig025
Revises:     mig024
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "mig025"
down_revision = "mig024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_finding_notes",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "finding_id",
            UUID(as_uuid=True),
            sa.ForeignKey("security_findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Denormalised workspace FK — nullable so orphaned rows stay valid.
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
    op.create_index(
        "ix_security_finding_notes_finding_id",
        "security_finding_notes",
        ["finding_id"],
    )
    op.create_index(
        "ix_security_finding_notes_workspace_id",
        "security_finding_notes",
        ["workspace_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_security_finding_notes_workspace_id", "security_finding_notes")
    op.drop_index("ix_security_finding_notes_finding_id", "security_finding_notes")
    op.drop_table("security_finding_notes")
