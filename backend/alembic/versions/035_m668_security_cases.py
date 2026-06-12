"""M66.8 — security_cases + security_case_links (Investigations workflow).

A case is a HUMAN-MANAGED investigation container that groups GitHub incident
evidence (signals, correlations, configuration risks, activity events). Cases let
a user reason about evidence — they do NOT auto-confirm breaches/attackers/
compromise. ``confirmed_by_user`` / ``dismissed`` are HUMAN actions only.

Privacy: case metadata is allowlisted (no raw payloads/IPs/secrets/tokens).

Revision ID: mig035
Revises: mig034
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "mig035"
down_revision = "mig034"
branch_labels = None
depends_on = None

_CASES = "security_cases"
_LINKS = "security_case_links"


def upgrade() -> None:
    op.create_table(
        _CASES,
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("status", sa.Text, nullable=False, server_default="open"),
        sa.Column("severity", sa.Text, nullable=False, server_default="medium"),
        sa.Column("confidence", sa.Text, nullable=False, server_default="medium"),
        sa.Column("provider", sa.Text, nullable=True),
        sa.Column("opened_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("confirmed_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dismissed_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_security_cases_workspace_id", _CASES, ["workspace_id"])
    op.create_index("ix_security_cases_status", _CASES, ["status"])
    op.create_index("ix_security_cases_severity", _CASES, ["severity"])
    op.create_index("ix_security_cases_confidence", _CASES, ["confidence"])
    op.create_index("ix_security_cases_provider", _CASES, ["provider"])
    op.create_index("ix_sec_cases_ws_status", _CASES, ["workspace_id", "status"])

    op.create_table(
        _LINKS,
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("case_id", UUID(as_uuid=True), sa.ForeignKey("security_cases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("linked_object_type", sa.Text, nullable=False),
        sa.Column("linked_object_id", UUID(as_uuid=True), nullable=False),
        sa.Column("created_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_security_case_links_workspace_id", _LINKS, ["workspace_id"])
    op.create_index("ix_security_case_links_case_id", _LINKS, ["case_id"])
    op.create_index("ix_security_case_links_linked_object_type", _LINKS, ["linked_object_type"])
    op.create_index("ix_security_case_links_linked_object_id", _LINKS, ["linked_object_id"])
    op.create_index(
        "uq_security_case_links_object",
        _LINKS,
        ["case_id", "linked_object_type", "linked_object_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_security_case_links_object", _LINKS)
    op.drop_index("ix_security_case_links_linked_object_id", _LINKS)
    op.drop_index("ix_security_case_links_linked_object_type", _LINKS)
    op.drop_index("ix_security_case_links_case_id", _LINKS)
    op.drop_index("ix_security_case_links_workspace_id", _LINKS)
    op.drop_table(_LINKS)

    op.drop_index("ix_sec_cases_ws_status", _CASES)
    op.drop_index("ix_security_cases_provider", _CASES)
    op.drop_index("ix_security_cases_confidence", _CASES)
    op.drop_index("ix_security_cases_severity", _CASES)
    op.drop_index("ix_security_cases_status", _CASES)
    op.drop_index("ix_security_cases_workspace_id", _CASES)
    op.drop_table(_CASES)
