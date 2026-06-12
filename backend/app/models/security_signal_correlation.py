"""SecuritySignalCorrelation — Configuration Risk × audit-activity correlation (M66.6).

The core differentiator: links a GitHub **Configuration Risk** finding to GitHub
**audit activity** on the same repository within a review window. Where a finding
says "this setting is risky" and an activity event says "this control-plane action
happened", a correlation says "a risky configuration was accompanied by audit
activity on the same repository — this may require review".

CLAIM DISCIPLINE — read before extending:
  A correlation is EVIDENCE FOR REVIEW. It is the first step toward a "potential
  compromise signal" but it does NOT confirm a breach, attacker, compromise, or
  unauthorized access. Severity reflects review priority; confidence reflects
  that this is circumstantial co-occurrence, not proof.

PRIVACY INVARIANTS (enforced in security_signal_correlation_service):
  * ``metadata`` keys must be on a small allowlist; values flat + truncated.
  * NEVER store raw payloads, raw IPs, secrets, or tokens.

Idempotency: a unique partial index on
``(workspace_id, correlation_key, linked_finding_id, linked_activity_event_id)``
makes re-generating the same correlation a no-op.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


class SecuritySignalCorrelation(BaseMixin, Base):
    __tablename__ = "security_signal_correlations"
    __table_args__ = (
        Index(
            "ix_sec_corr_ws_status_severity",
            "workspace_id",
            "status",
            "severity",
        ),
        Index(
            "ix_sec_corr_ws_provider_first_seen",
            "workspace_id",
            "provider",
            "first_seen_at",
        ),
        Index(
            "ix_sec_corr_ws_type_first_seen",
            "workspace_id",
            "correlation_type",
            "first_seen_at",
        ),
        # Idempotency: one correlation per (rule, finding, activity event).
        Index(
            "uq_sec_corr_finding_activity",
            "workspace_id",
            "correlation_key",
            "linked_finding_id",
            "linked_activity_event_id",
            unique=True,
            postgresql_where=text(
                "linked_finding_id IS NOT NULL AND linked_activity_event_id IS NOT NULL"
            ),
        ),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    # Stable rule identifier (e.g. "github_webhook_risk_activity").
    correlation_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    # Category (e.g. "webhook_change", "branch_protection_change").
    correlation_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="medium", default="medium", index=True
    )
    status: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="open", default="open", index=True
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)

    # Links to the correlated artifacts.
    linked_signal_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("security_incident_signals.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    linked_finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("security_findings.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    linked_activity_event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("security_activity_events.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    linked_change_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )

    # Review window the correlation was matched within.
    window_start: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    window_end: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    # SQLAlchemy reserves ``metadata`` → ``correlation_metadata``.
    correlation_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict
    )
