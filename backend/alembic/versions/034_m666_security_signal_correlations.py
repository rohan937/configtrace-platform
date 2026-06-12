"""M66.6 — security_signal_correlations table (risk × activity correlation).

Links GitHub Configuration Risk findings to GitHub audit activity on the same
repository within a review window — the core "configuration risk aligned with
audit activity" evidence layer.

A correlation is evidence for review. It does NOT confirm breaches, attackers, or
compromise. Privacy: no raw payloads/IPs/secrets/tokens — metadata allowlisted.

Revision ID: mig034
Revises: mig033
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "mig034"
down_revision = "mig033"
branch_labels = None
depends_on = None

_TABLE = "security_signal_correlations"


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
        sa.Column("provider", sa.Text, nullable=False),
        sa.Column("correlation_key", sa.Text, nullable=False),
        sa.Column("correlation_type", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("confidence", sa.Text, nullable=False, server_default="medium"),
        sa.Column("status", sa.Text, nullable=False, server_default="open"),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column(
            "linked_signal_id",
            UUID(as_uuid=True),
            sa.ForeignKey("security_incident_signals.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "linked_finding_id",
            UUID(as_uuid=True),
            sa.ForeignKey("security_findings.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "linked_activity_event_id",
            UUID(as_uuid=True),
            sa.ForeignKey("security_activity_events.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("linked_change_id", UUID(as_uuid=True), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
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

    op.create_index("ix_security_signal_correlations_workspace_id", _TABLE, ["workspace_id"])
    op.create_index("ix_security_signal_correlations_provider", _TABLE, ["provider"])
    op.create_index("ix_security_signal_correlations_correlation_key", _TABLE, ["correlation_key"])
    op.create_index("ix_security_signal_correlations_correlation_type", _TABLE, ["correlation_type"])
    op.create_index("ix_security_signal_correlations_severity", _TABLE, ["severity"])
    op.create_index("ix_security_signal_correlations_confidence", _TABLE, ["confidence"])
    op.create_index("ix_security_signal_correlations_status", _TABLE, ["status"])
    op.create_index("ix_security_signal_correlations_linked_signal_id", _TABLE, ["linked_signal_id"])
    op.create_index("ix_security_signal_correlations_linked_finding_id", _TABLE, ["linked_finding_id"])
    op.create_index(
        "ix_security_signal_correlations_linked_activity_event_id",
        _TABLE,
        ["linked_activity_event_id"],
    )
    op.create_index("ix_security_signal_correlations_linked_change_id", _TABLE, ["linked_change_id"])
    op.create_index("ix_security_signal_correlations_window_start", _TABLE, ["window_start"])
    op.create_index("ix_security_signal_correlations_window_end", _TABLE, ["window_end"])
    op.create_index("ix_security_signal_correlations_first_seen_at", _TABLE, ["first_seen_at"])
    op.create_index("ix_security_signal_correlations_last_seen_at", _TABLE, ["last_seen_at"])

    op.create_index(
        "ix_sec_corr_ws_status_severity", _TABLE, ["workspace_id", "status", "severity"]
    )
    op.create_index(
        "ix_sec_corr_ws_provider_first_seen",
        _TABLE,
        ["workspace_id", "provider", "first_seen_at"],
    )
    op.create_index(
        "ix_sec_corr_ws_type_first_seen",
        _TABLE,
        ["workspace_id", "correlation_type", "first_seen_at"],
    )

    op.create_index(
        "uq_sec_corr_finding_activity",
        _TABLE,
        ["workspace_id", "correlation_key", "linked_finding_id", "linked_activity_event_id"],
        unique=True,
        postgresql_where=sa.text(
            "linked_finding_id IS NOT NULL AND linked_activity_event_id IS NOT NULL"
        ),
    )


def downgrade() -> None:
    op.drop_index("uq_sec_corr_finding_activity", _TABLE)
    op.drop_index("ix_sec_corr_ws_type_first_seen", _TABLE)
    op.drop_index("ix_sec_corr_ws_provider_first_seen", _TABLE)
    op.drop_index("ix_sec_corr_ws_status_severity", _TABLE)
    for col in (
        "last_seen_at",
        "first_seen_at",
        "window_end",
        "window_start",
        "linked_change_id",
        "linked_activity_event_id",
        "linked_finding_id",
        "linked_signal_id",
        "status",
        "confidence",
        "severity",
        "correlation_type",
        "correlation_key",
        "provider",
        "workspace_id",
    ):
        op.drop_index(f"ix_security_signal_correlations_{col}", _TABLE)
    op.drop_table(_TABLE)
