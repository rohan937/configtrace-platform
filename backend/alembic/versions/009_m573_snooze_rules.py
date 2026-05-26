"""009 — M57.3: change_snooze_rules table.

Revision ID: 009
Revises: 008
Create Date: 2026-05-26

Adds the ``change_snooze_rules`` table which stores workspace-scoped rules
that suppress alert dispatch for future Change rows matching the rule's
criteria (integration_id, optional record_identifier_pattern, field_path,
risk_level).

No destructive changes to existing tables.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "change_snooze_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        # Scope
        sa.Column(
            "workspace_id",
            UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "integration_id",
            UUID(as_uuid=True),
            sa.ForeignKey("integrations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Optional match criteria
        sa.Column("record_identifier_pattern", sa.Text, nullable=True),
        sa.Column("field_path", sa.Text, nullable=True),
        sa.Column("risk_level", sa.Text, nullable=True),
        # Expiry + metadata
        sa.Column("snoozed_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column(
            "created_by_user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "is_active",
            sa.Boolean,
            nullable=False,
            server_default="true",
        ),
    )

    # Indexes
    op.create_index(
        "ix_snooze_rules_workspace_id",
        "change_snooze_rules",
        ["workspace_id"],
    )
    op.create_index(
        "ix_snooze_rules_integration_id",
        "change_snooze_rules",
        ["integration_id"],
    )
    op.create_index(
        "ix_snooze_rules_snoozed_until",
        "change_snooze_rules",
        ["snoozed_until"],
    )
    op.create_index(
        "ix_snooze_rules_integ_active_until",
        "change_snooze_rules",
        ["integration_id", "is_active", "snoozed_until"],
    )


def downgrade() -> None:
    op.drop_index("ix_snooze_rules_integ_active_until", table_name="change_snooze_rules")
    op.drop_index("ix_snooze_rules_snoozed_until", table_name="change_snooze_rules")
    op.drop_index("ix_snooze_rules_integration_id", table_name="change_snooze_rules")
    op.drop_index("ix_snooze_rules_workspace_id", table_name="change_snooze_rules")
    op.drop_table("change_snooze_rules")
