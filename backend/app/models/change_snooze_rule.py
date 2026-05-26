"""ChangeSnoozeRule model — M57.3.

A workspace-scoped rule that suppresses alert dispatch for future Change rows
that match the rule's criteria.

Design decisions
----------------
* ``integration_id`` is REQUIRED — we do not support broad workspace-wide
  wildcards like "snooze all AWS high-risk changes" (spec constraint).
* ``record_identifier_pattern``, ``field_path``, and ``risk_level`` are all
  optional.  When None, that dimension matches any value.
* Matching is exact (no regex/glob wildcards) — keeps the suppression logic
  deterministic and auditable.
* Expiry is enforced by ``snoozed_until``; rules are never auto-deleted, only
  expired.  ``is_active`` allows manual deactivation without row deletion.

Security
--------
* No raw credential, token, or secret value may appear in any field of this
  model.  The ``reason`` field is free text — callers must strip secrets.
* ``workspace_id`` scoping ensures rules cannot affect other workspaces.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


class ChangeSnoozeRule(BaseMixin, Base):
    """A rule that suppresses alert dispatch for matching future Change rows.

    Scope
    -----
    A rule is always scoped to a specific ``workspace_id`` + ``integration_id``
    pair.  The optional dimensions (``record_identifier_pattern``,
    ``field_path``, ``risk_level``) narrow the match further.

    Lifecycle
    ---------
    Rules expire when ``snoozed_until <= now``.  They can also be deactivated
    immediately by setting ``is_active = False``.  Neither action deletes the
    row — the full history is preserved for the audit trail.
    """

    __tablename__ = "change_snooze_rules"

    # ── Scope ─────────────────────────────────────────────────────────────────

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("integrations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Optional match criteria (all None → match any) ────────────────────────

    record_identifier_pattern: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    """Exact record identifier to match.  None matches any identifier."""

    field_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    """Exact field path to match (e.g. 'proxied').  None matches any path."""

    risk_level: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    """Exact risk level to match ('critical', 'high', etc.).  None matches all."""

    # ── Expiry + metadata ─────────────────────────────────────────────────────

    snoozed_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    """UTC datetime after which this rule is expired and no longer suppresses."""

    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    """Human-readable explanation.  Must NOT contain raw secrets or credentials."""

    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    """The workspace member who created this rule."""

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    """False when manually deactivated.  Expired rules are still is_active=True."""

    # ── Indexes ───────────────────────────────────────────────────────────────

    __table_args__ = (
        Index("ix_snooze_rules_workspace_id", "workspace_id"),
        Index("ix_snooze_rules_integration_id", "integration_id"),
        Index("ix_snooze_rules_snoozed_until", "snoozed_until"),
        # Composite: fast lookup by (integration_id, is_active, snoozed_until)
        # — the hot path for alert suppression checks.
        Index(
            "ix_snooze_rules_integ_active_until",
            "integration_id",
            "is_active",
            "snoozed_until",
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ChangeSnoozeRule id={self.id} integration={self.integration_id} "
            f"until={self.snoozed_until} active={self.is_active}>"
        )
