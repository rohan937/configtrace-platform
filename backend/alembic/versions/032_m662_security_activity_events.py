"""M66.2 — security_activity_events table (normalized control-plane activity).

The data spine for the future Incident Signals product. Stores normalized
GitHub (initially) audit-log / control-plane activity events — branch-protection
changes, deploy keys, webhooks, collaborator changes, app installs, rulesets,
secret-scanning alerts.

This table only stores activity events. It does NOT detect breaches, identify
attackers, or confirm compromise — correlation logic is a future milestone.

Privacy: no raw payloads/secrets/tokens; source IP stored only as a salted hash.

Revision ID: mig032
Revises: mig031
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "mig032"
down_revision = "mig031"
branch_labels = None
depends_on = None

_TABLE = "security_activity_events"


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
            "integration_id",
            UUID(as_uuid=True),
            sa.ForeignKey("integrations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("provider", sa.Text, nullable=False),
        sa.Column("source", sa.Text, nullable=False, server_default="audit_log"),
        sa.Column("provider_event_id", sa.Text, nullable=True),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("actor_id", sa.Text, nullable=True),
        sa.Column("actor_type", sa.Text, nullable=True),
        sa.Column("resource_type", sa.Text, nullable=True),
        sa.Column("resource_id", sa.Text, nullable=True),
        sa.Column("source_ip_hash", sa.Text, nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("raw_ref", sa.Text, nullable=True),
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

    # Single-column indexes (mirror the inline index=True on the model).
    op.create_index("ix_security_activity_events_workspace_id", _TABLE, ["workspace_id"])
    op.create_index(
        "ix_security_activity_events_integration_id", _TABLE, ["integration_id"]
    )
    op.create_index("ix_security_activity_events_provider", _TABLE, ["provider"])
    op.create_index("ix_security_activity_events_event_type", _TABLE, ["event_type"])
    op.create_index("ix_security_activity_events_occurred_at", _TABLE, ["occurred_at"])

    # Compound query-path indexes.
    op.create_index(
        "ix_sec_activity_ws_provider_occurred",
        _TABLE,
        ["workspace_id", "provider", "occurred_at"],
    )
    op.create_index(
        "ix_sec_activity_ws_resource_occurred",
        _TABLE,
        ["workspace_id", "resource_id", "occurred_at"],
    )
    op.create_index(
        "ix_sec_activity_ws_actor_occurred",
        _TABLE,
        ["workspace_id", "actor_id", "occurred_at"],
    )
    op.create_index(
        "ix_sec_activity_ws_event_type_occurred",
        _TABLE,
        ["workspace_id", "event_type", "occurred_at"],
    )

    # Idempotency: at most one row per stable provider event id.
    op.create_index(
        "uq_sec_activity_provider_event",
        _TABLE,
        ["workspace_id", "provider", "source", "provider_event_id"],
        unique=True,
        postgresql_where=sa.text("provider_event_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_sec_activity_provider_event", _TABLE)
    op.drop_index("ix_sec_activity_ws_event_type_occurred", _TABLE)
    op.drop_index("ix_sec_activity_ws_actor_occurred", _TABLE)
    op.drop_index("ix_sec_activity_ws_resource_occurred", _TABLE)
    op.drop_index("ix_sec_activity_ws_provider_occurred", _TABLE)
    op.drop_index("ix_security_activity_events_occurred_at", _TABLE)
    op.drop_index("ix_security_activity_events_event_type", _TABLE)
    op.drop_index("ix_security_activity_events_provider", _TABLE)
    op.drop_index("ix_security_activity_events_integration_id", _TABLE)
    op.drop_index("ix_security_activity_events_workspace_id", _TABLE)
    op.drop_table(_TABLE)
