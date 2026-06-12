"""M66.3 — security_incident_signals table (control-plane Incident Signals).

First review-signal layer derived from normalized GitHub audit activity
(security_activity_events, M66.2). Signals flag control-plane actions that may
require review — they do NOT confirm breaches, attackers, or compromise.

Privacy: no raw audit blobs/IPs/secrets/tokens — metadata is allowlisted.

Revision ID: mig033
Revises: mig032
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "mig033"
down_revision = "mig032"
branch_labels = None
depends_on = None

_TABLE = "security_incident_signals"


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
        sa.Column("signal_key", sa.Text, nullable=False),
        sa.Column("signal_type", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="open"),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column("evidence_level", sa.Text, nullable=False, server_default="activity"),
        sa.Column("confidence", sa.Text, nullable=False, server_default="high"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "linked_activity_event_id",
            UUID(as_uuid=True),
            sa.ForeignKey("security_activity_events.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "linked_finding_id",
            UUID(as_uuid=True),
            sa.ForeignKey("security_findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("linked_change_id", UUID(as_uuid=True), nullable=True),
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
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # Single-column indexes (mirror inline index=True on the model).
    op.create_index("ix_security_incident_signals_workspace_id", _TABLE, ["workspace_id"])
    op.create_index(
        "ix_security_incident_signals_integration_id", _TABLE, ["integration_id"]
    )
    op.create_index("ix_security_incident_signals_provider", _TABLE, ["provider"])
    op.create_index("ix_security_incident_signals_signal_key", _TABLE, ["signal_key"])
    op.create_index("ix_security_incident_signals_signal_type", _TABLE, ["signal_type"])
    op.create_index("ix_security_incident_signals_severity", _TABLE, ["severity"])
    op.create_index("ix_security_incident_signals_status", _TABLE, ["status"])
    op.create_index("ix_security_incident_signals_first_seen_at", _TABLE, ["first_seen_at"])
    op.create_index("ix_security_incident_signals_last_seen_at", _TABLE, ["last_seen_at"])
    op.create_index(
        "ix_security_incident_signals_linked_activity_event_id",
        _TABLE,
        ["linked_activity_event_id"],
    )

    # Compound query-path indexes.
    op.create_index(
        "ix_sec_signal_ws_status_severity",
        _TABLE,
        ["workspace_id", "status", "severity"],
    )
    op.create_index(
        "ix_sec_signal_ws_provider_first_seen",
        _TABLE,
        ["workspace_id", "provider", "first_seen_at"],
    )
    op.create_index(
        "ix_sec_signal_ws_signal_type_first_seen",
        _TABLE,
        ["workspace_id", "signal_type", "first_seen_at"],
    )

    # Idempotency: one signal per (provider, rule, source activity event).
    op.create_index(
        "uq_sec_signal_activity",
        _TABLE,
        ["workspace_id", "provider", "signal_key", "linked_activity_event_id"],
        unique=True,
        postgresql_where=sa.text("linked_activity_event_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_sec_signal_activity", _TABLE)
    op.drop_index("ix_sec_signal_ws_signal_type_first_seen", _TABLE)
    op.drop_index("ix_sec_signal_ws_provider_first_seen", _TABLE)
    op.drop_index("ix_sec_signal_ws_status_severity", _TABLE)
    op.drop_index("ix_security_incident_signals_linked_activity_event_id", _TABLE)
    op.drop_index("ix_security_incident_signals_last_seen_at", _TABLE)
    op.drop_index("ix_security_incident_signals_first_seen_at", _TABLE)
    op.drop_index("ix_security_incident_signals_status", _TABLE)
    op.drop_index("ix_security_incident_signals_severity", _TABLE)
    op.drop_index("ix_security_incident_signals_signal_type", _TABLE)
    op.drop_index("ix_security_incident_signals_signal_key", _TABLE)
    op.drop_index("ix_security_incident_signals_provider", _TABLE)
    op.drop_index("ix_security_incident_signals_integration_id", _TABLE)
    op.drop_index("ix_security_incident_signals_workspace_id", _TABLE)
    op.drop_table(_TABLE)
