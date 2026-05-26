"""ChangeReview model — M57.2.

One mutable row per Change that records the team's review state.  The Change
row itself is BaseImmutable (never updated); this separate table holds all
review metadata so the event log stays append-only.

Review lifecycle
----------------
  needs_review  ← default for any change (row may not exist yet)
  acknowledged  ← team reviewed and noted the change
  expected      ← team flagged this as expected/planned drift
  snoozed       ← team deferred review until snoozed_until

Any status can return to ``needs_review`` via the reopen action.

Security / audit
----------------
* ``review_note`` and ``snooze_reason`` are plain text; callers must ensure
  they contain no credential values.
* ``reviewed_by_user_id`` records who performed the last action (not a thread
  — single reviewe per change for M57.2).
* ``workspace_id`` is denormalised from ``Change.integration_id →
  Integration.workspace_id`` at write time; used for audit log scoping.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


_VALID_REVIEW_STATUSES = frozenset(
    {"needs_review", "acknowledged", "expected", "snoozed"}
)

# Maximum character length for free-text review fields.
_NOTE_MAX_LEN = 1000


class ChangeReview(BaseMixin, Base):
    """Mutable review state for a single Change.

    Columns
    -------
    change_id
        FK → changes.id.  UNIQUE: exactly one review row per change.
        We use RESTRICT on delete so we never silently lose review history
        if the change is somehow referenced by the UI.

    workspace_id
        Denormalised FK → workspaces.id.  Set at creation from
        Change.integration_id → Integration.workspace_id.  Used for
        audit log scoping and for future workspace-level queries.

    review_status
        One of: needs_review · acknowledged · expected · snoozed

    reviewed_by_user_id
        The user who performed the most recent review action.

    reviewed_at
        Timestamp of the most recent review action (UTC).

    review_note
        Optional free-text note recorded alongside the action.

    snoozed_until
        Only set when review_status == "snoozed".  The datetime (UTC) after
        which this change should surface again for review.

    snooze_reason
        Optional free-text reason for the snooze.
    """

    __tablename__ = "change_reviews"

    change_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("changes.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
        index=True,
    )
    # Denormalised from Integration.workspace_id for audit/scoping.
    workspace_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ── Review status ──────────────────────────────────────────────────────────
    review_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="needs_review",
        server_default="needs_review",
    )

    # ── Reviewer ───────────────────────────────────────────────────────────────
    reviewed_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    review_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── Snooze ────────────────────────────────────────────────────────────────
    snoozed_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    snooze_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<ChangeReview change={self.change_id} "
            f"status={self.review_status!r} by={self.reviewed_by_user_id}>"
        )
