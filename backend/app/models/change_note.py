"""ChangeNote model — M58.8.

Collaborative team notes attached to a Change for investigation purposes.
These are distinct from ChangeReview.review_note (which is the action note
recorded alongside a review event).

Design
------
* Notes are append-only for simplicity — no edit endpoint, no delete endpoint.
* body is plain text (max 2000 chars); the API layer enforces the limit.
* author_user_id is nullable so notes can be created by system processes.
* workspace_id is denormalised from Change → Integration at write time.
* deleted_at is omitted for M58.8 MVP.

Security
--------
* body is stored and returned as plain text — no HTML, no markdown rendering
  is performed server-side.  Clients decide how to display it.
* workspace_id ensures notes stay scoped to one workspace; the router uses
  _get_change_and_workspace to verify membership before writing.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


_NOTE_BODY_MAX_LEN = 2000


class ChangeNote(BaseMixin, Base):
    """A single team note attached to a Change."""

    __tablename__ = "change_notes"

    change_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("changes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Denormalised from Integration.workspace_id for scoping / auth checks.
    workspace_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # NULL = system-generated or migrated note without a known author.
    author_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    body: Mapped[str] = mapped_column(Text, nullable=False)

    def __repr__(self) -> str:
        preview = self.body[:40].replace("\n", " ") if self.body else ""
        return (
            f"<ChangeNote change={self.change_id} "
            f"author={self.author_user_id} body={preview!r}>"
        )
