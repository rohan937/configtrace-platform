"""ExpectedChangeWindow model — M58.16.

An expected change window defines a time range during which certain
infrastructure changes are anticipated (e.g. a planned deployment).
Changes that fall inside an approved window can be annotated or,
optionally, have their alerts suppressed.

Workflow
--------
  pending   → approved (admin)   — window is active for matching
  pending   → rejected (admin)   — window was denied
  pending   → cancelled (creator or admin) — withdrawn before approval
  approved  → cancelled (admin)  — active window revoked mid-window

alert_behavior
--------------
  annotate_only  (default) — the match is surfaced in the API response
                             but no alerts are suppressed.
  suppress       — alert dispatch is skipped for matched changes.
                   Only applies when the window is approved.

Filter columns
--------------
All filter columns are nullable.  NULL means "match anything".
The match logic ANDs all non-null filters together.

Security notes
--------------
* rejection_reason and title are free-text fields; callers must not
  store credential values here.
* filter_integration_id is a UUID that references an Integration, but
  the FK is intentionally omitted to avoid cross-schema coupling.  The
  service layer validates that the integration belongs to the workspace.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


class ExpectedChangeWindow(BaseMixin, Base):
    """Mutable record describing one expected change window."""

    __tablename__ = "expected_change_windows"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    approved_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Window definition ─────────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    end_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # ── Workflow state ────────────────────────────────────────────────────────
    # "pending" | "approved" | "rejected" | "cancelled"
    status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="pending",
        server_default="pending",
    )

    # ── Alert behaviour when this window is matched ───────────────────────────
    # "annotate_only" (default) | "suppress"
    alert_behavior: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="annotate_only",
        server_default="annotate_only",
    )

    # ── Optional filters (null = match any) ──────────────────────────────────
    filter_provider: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    filter_integration_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    filter_risk_level: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── Approval / rejection metadata ─────────────────────────────────────────
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"<ExpectedChangeWindow id={self.id}"
            f" workspace={self.workspace_id}"
            f" title={self.title!r}"
            f" status={self.status!r}>"
        )
