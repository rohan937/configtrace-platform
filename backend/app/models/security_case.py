"""SecurityCase + SecurityCaseLink — Investigations workflow (M66.8).

A **case** is a HUMAN-MANAGED investigation container that groups GitHub incident
evidence — Incident Signals, Correlations, Configuration Risks, Activity Events —
so a person can review them together.

CLAIM DISCIPLINE — read before extending:
  A case may contain evidence that "may require review". ConfigTrace does NOT
  automatically confirm breaches, attackers, compromise, or unauthorized access.
  ``confirmed_by_user`` and ``dismissed`` are HUMAN actions only — no automated
  service may set ``status="confirmed_by_user"``.

PRIVACY: case/link ``metadata`` is allowlisted (no raw payloads/IPs/secrets/tokens).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseImmutable, BaseMixin

# Case lifecycle. ``confirmed_by_user`` / ``dismissed`` are human-only.
VALID_CASE_STATUSES = frozenset(
    {"open", "investigating", "confirmed_by_user", "dismissed", "resolved"}
)
VALID_CASE_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
# Object types a case can group.
VALID_LINK_TYPES = frozenset({"signal", "correlation", "finding", "activity_event"})


class SecurityCase(BaseMixin, Base):
    __tablename__ = "security_cases"
    __table_args__ = (
        Index("ix_sec_cases_ws_status", "workspace_id", "status"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="open", default="open", index=True
    )
    severity: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="medium", default="medium", index=True
    )
    confidence: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="medium", default="medium", index=True
    )
    provider: Mapped[Optional[str]] = mapped_column(Text, nullable=True, index=True)

    opened_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    confirmed_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    dismissed_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    dismissed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    case_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict
    )


class SecurityCaseLink(BaseImmutable, Base):
    __tablename__ = "security_case_links"
    __table_args__ = (
        Index(
            "uq_security_case_links_object",
            "case_id",
            "linked_object_type",
            "linked_object_id",
            unique=True,
        ),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("security_cases.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    # One of VALID_LINK_TYPES.
    linked_object_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    linked_object_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    created_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    link_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict
    )
