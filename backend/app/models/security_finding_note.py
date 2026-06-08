"""SecurityFindingNote model — M61.3.

Collaborative review notes attached to a SecurityFinding for investigation
context (owner handoff, follow-up, triage detail). Mirrors the ChangeNote
pattern (M58.8): append-only, plain text, workspace-scoped.

Design
------
* Notes are append-only — no edit endpoint, no delete endpoint.
* body is plain text (max 2000 chars); the API layer enforces the limit.
* author_user_id is nullable so notes can be created by system processes.
* workspace_id is denormalised from SecurityFinding at write time for scoping.

Security
--------
* body is stored and returned as plain text — no HTML/markdown rendering is
  performed server-side. Clients decide how to display it.
* A note NEVER mutates the finding's status or lifecycle fields.
* workspace_id keeps notes scoped to one workspace; the router verifies
  membership (via get_finding_for_user) before reading or writing.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin

_NOTE_BODY_MAX_LEN = 2000


class SecurityFindingNote(BaseMixin, Base):
    """A single review note attached to a SecurityFinding."""

    __tablename__ = "security_finding_notes"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("security_findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Denormalised from SecurityFinding.workspace_id for scoping / auth checks.
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
            f"<SecurityFindingNote finding={self.finding_id} "
            f"author={self.author_user_id} body={preview!r}>"
        )
