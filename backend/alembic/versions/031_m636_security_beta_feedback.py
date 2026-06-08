"""M63.6 — security_beta_feedback table (qualitative beta feedback).

First-party, append-only, workspace-scoped feedback captured after a Security
Exposure report export. Context is allowlisted + truncated at the service layer.

Revision ID: mig031
Revises: mig030
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "mig031"
down_revision = "mig030"
branch_labels = None
depends_on = None

_TABLE = "security_beta_feedback"


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "workspace_id",
            UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "feedback_type",
            sa.Text,
            nullable=False,
            server_default="report_export",
        ),
        sa.Column("rating", sa.Text, nullable=False),
        sa.Column("comment", sa.Text, nullable=True),
        sa.Column(
            "context",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_security_beta_feedback_workspace_id", _TABLE, ["workspace_id"]
    )
    op.create_index("ix_security_beta_feedback_user_id", _TABLE, ["user_id"])
    op.create_index("ix_security_beta_feedback_created_at", _TABLE, ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_security_beta_feedback_created_at", _TABLE)
    op.drop_index("ix_security_beta_feedback_user_id", _TABLE)
    op.drop_index("ix_security_beta_feedback_workspace_id", _TABLE)
    op.drop_table(_TABLE)
