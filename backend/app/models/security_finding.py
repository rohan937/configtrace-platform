"""SecurityFinding model — M60.3.

A SecurityFinding represents a *risky current state* (a "security exposure")
discovered on a connected provider — NOT merely a change event.

Product distinction
-------------------
  • Drift Detection (Change)        → "what changed"
  • Security Exposure (SecurityFinding) → "what is dangerous right now"

A finding MAY be linked to a drift Change (``linked_change_id``) but never
requires one — an exposure can be a standing misconfiguration that no recent
change produced.

Scope & lifecycle
-----------------
* Workspace-scoped (``workspace_id`` is required) — all access is gated by
  workspace membership, mirroring the Change/ChangeReview pattern.
* Integration-aware (``integration_id`` required); resource-aware where
  possible (``resource_id`` nullable for integration-level findings).
* Lifecycle via ``status``:
      active        — currently risky
      resolved      — the underlying setting was fixed
      accepted_risk — a human accepted the risk (optionally until accepted_until)
      snoozed       — deferred review

Uniqueness
----------
At most ONE *active* finding may exist per logical issue, identified by
(workspace_id, integration_id, resource_id, finding_key). Enforced by a
PARTIAL UNIQUE index ``WHERE status = 'active'`` (see migration mig020), so
resolved/accepted/snoozed rows never block a fresh active finding. The index
COALESCEs a NULL ``resource_id`` to a sentinel UUID so integration-level
findings dedup correctly too.

This milestone (M60.3) is the data foundation ONLY. The evaluation engine that
produces findings lands in M60.4 — nothing here evaluates provider state.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


# Lifecycle states a finding may hold.
VALID_FINDING_STATUSES = frozenset(
    {"active", "resolved", "accepted_risk", "snoozed"}
)

# Severity scale — aligned with the existing risk_level convention on Change
# (low/medium/high/critical) plus an "info" level for advisory exposures.
VALID_FINDING_SEVERITIES = frozenset(
    {"critical", "high", "medium", "low", "info"}
)

# Sentinel used by the partial unique index to dedup NULL-resource findings.
# Kept in Python only for documentation; the value lives in the migration.
RESOURCE_ID_SENTINEL = "00000000-0000-0000-0000-000000000000"


class SecurityFinding(BaseMixin, Base):
    """A risky current security state on a connected provider (M60.3)."""

    __tablename__ = "security_findings"

    # ── Scope ────────────────────────────────────────────────────────────────
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
    # Resource-level findings set this; integration-level findings leave it NULL.
    resource_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("resources.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Optional link to the drift change that surfaced this exposure.
    linked_change_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("changes.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Classification ───────────────────────────────────────────────────────
    provider: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    # Stable rule identifier, e.g. "github_webhook_http". Set by the future
    # M60.4 engine; part of the active-finding uniqueness key.
    finding_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="active",
        server_default="active",
        index=True,
    )

    # ── Human-facing content ─────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Structured supporting data (the observed values that make this risky) and
    # remediation guidance. JSONB matches the Change.provider_metadata pattern.
    evidence: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    remediation: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONB, nullable=True
    )

    # ── Lifecycle timestamps ─────────────────────────────────────────────────
    first_detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
        nullable=False,
        index=True,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
        nullable=False,
        index=True,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # When an accepted-risk acceptance expires (NULL = indefinite).
    accepted_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Review attribution ───────────────────────────────────────────────────
    reviewed_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Free-text rationale captured when a finding is marked accepted_risk (M61.1).
    # NULL for findings that have never been through the accept-risk workflow.
    acceptance_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<SecurityFinding id={self.id} key={self.finding_key!r} "
            f"sev={self.severity!r} status={self.status!r}>"
        )
