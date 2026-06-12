"""SecurityIncidentSignal — first control-plane Incident Signals (M66.3).

Derived from normalized ``security_activity_events`` (M66.2). A signal flags a
control-plane action that *may require review* — e.g. branch protection disabled,
a deploy key added, GitHub App permissions changed.

CLAIM DISCIPLINE — read before extending:
  Incident signals are REVIEW signals based on audit activity. They do NOT
  confirm a breach, identify an attacker, or confirm compromise/access. Severity
  reflects *review priority*, not confirmed impact. ``evidence_level`` is
  ``"activity"`` — never ``"confirmed_breach"``. Exposure×activity correlation
  (which would raise confidence) is a FUTURE milestone.

PRIVACY INVARIANTS (enforced in security_incident_signal_service):
  * ``metadata`` keys must be on a small allowlist; values flat + truncated.
  * NEVER store raw audit-event blobs, raw IPs, secrets, tokens, or payloads.

Idempotency: a unique partial index on
``(workspace_id, provider, signal_key, linked_activity_event_id)`` (where the
link is not null) makes re-generating signals over the same activity a no-op.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin

# Valid review-priority severities (NOT confirmed-impact levels).
VALID_SIGNAL_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
# Lifecycle status of a review signal.
VALID_SIGNAL_STATUSES = frozenset({"open", "acknowledged", "dismissed", "resolved"})


class SecurityIncidentSignal(BaseMixin, Base):
    __tablename__ = "security_incident_signals"
    __table_args__ = (
        Index(
            "ix_sec_signal_ws_status_severity",
            "workspace_id",
            "status",
            "severity",
        ),
        Index(
            "ix_sec_signal_ws_provider_first_seen",
            "workspace_id",
            "provider",
            "first_seen_at",
        ),
        Index(
            "ix_sec_signal_ws_signal_type_first_seen",
            "workspace_id",
            "signal_type",
            "first_seen_at",
        ),
        # Idempotency: one signal per (provider, rule, source activity event).
        Index(
            "uq_sec_signal_activity",
            "workspace_id",
            "provider",
            "signal_key",
            "linked_activity_event_id",
            unique=True,
            postgresql_where=text("linked_activity_event_id IS NOT NULL"),
        ),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    integration_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("integrations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    provider: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    # Stable rule identifier (e.g. "github_branch_protection_disabled").
    signal_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    # Category (e.g. "branch_protection_change", "deploy_key_added").
    signal_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="open", default="open", index=True
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    # Evidence tier — "activity" for this milestone. NEVER "confirmed_breach".
    evidence_level: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="activity", default="activity"
    )
    # Confidence that the action happened (high — the audit event states it).
    confidence: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="high", default="high"
    )
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    # Source link (the activity event that produced this signal).
    linked_activity_event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("security_activity_events.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Forward-compat link slots for FUTURE correlation (kept null this milestone).
    linked_finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("security_findings.id", ondelete="SET NULL"),
        nullable=True,
    )
    linked_change_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    # SQLAlchemy reserves ``metadata`` on declarative classes → ``signal_metadata``.
    signal_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict
    )
