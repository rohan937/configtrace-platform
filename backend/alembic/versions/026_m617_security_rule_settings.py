"""M61.7: security_rule_settings table (workspace rule enable/disable).

Sparse, workspace-scoped overrides for security rules. A missing row means the
rule is enabled (default); a row records an explicit choice. No backfill — all
existing workspaces keep every rule enabled.

Revision ID: mig026
Revises:     mig025
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "mig026"
down_revision = "mig025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_rule_settings",
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
        sa.Column("rule_key", sa.Text, nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "updated_by_user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
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
        sa.UniqueConstraint(
            "workspace_id", "rule_key", name="uq_security_rule_settings_ws_key"
        ),
    )
    op.create_index(
        "ix_security_rule_settings_workspace_id",
        "security_rule_settings",
        ["workspace_id"],
    )
    op.create_index(
        "ix_security_rule_settings_rule_key",
        "security_rule_settings",
        ["rule_key"],
    )


def downgrade() -> None:
    op.drop_index("ix_security_rule_settings_rule_key", "security_rule_settings")
    op.drop_index("ix_security_rule_settings_workspace_id", "security_rule_settings")
    op.drop_table("security_rule_settings")
