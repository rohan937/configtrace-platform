"""M63.1 — security_beta_events table (beta usage instrumentation).

First-party, append-only, workspace-scoped event log for Security Exposure
beta learning. Metadata is allowlisted + truncated at the service layer.

Revision ID: mig029
Revises: mig028
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "mig029"
down_revision = "mig028"
branch_labels = None
depends_on = None

_TABLE = "security_beta_events"


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
        sa.Column("event_name", sa.Text, nullable=False),
        sa.Column(
            "event_category",
            sa.Text,
            nullable=False,
            server_default="security_beta",
        ),
        sa.Column("page_path", sa.Text, nullable=True),
        sa.Column(
            "metadata",
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
        "ix_security_beta_events_workspace_id", _TABLE, ["workspace_id"]
    )
    op.create_index("ix_security_beta_events_user_id", _TABLE, ["user_id"])
    op.create_index("ix_security_beta_events_event_name", _TABLE, ["event_name"])
    op.create_index("ix_security_beta_events_created_at", _TABLE, ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_security_beta_events_created_at", _TABLE)
    op.drop_index("ix_security_beta_events_event_name", _TABLE)
    op.drop_index("ix_security_beta_events_user_id", _TABLE)
    op.drop_index("ix_security_beta_events_workspace_id", _TABLE)
    op.drop_table(_TABLE)
