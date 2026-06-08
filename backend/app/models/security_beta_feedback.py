"""SecurityBetaFeedback — lightweight qualitative beta feedback (M63.6).

Captures an optional "was this report useful?" rating (+ optional short comment)
at the moment a user exports a Security Exposure report. First-party storage
only; no third-party survey tools.

Privacy invariants (enforced in security_beta_feedback_service):
  * ``rating`` ∈ {useful, somewhat, not_useful}.
  * ``feedback_type`` is allowlisted (currently only "report_export").
  * ``comment`` is truncated to a short max length.
  * ``context`` keys are allowlisted + scalar-only; NEVER stores report
    markdown/JSON/CSV, evidence, remediation, notes, secrets, tokens, raw
    provider payloads, acceptance reasons, or rule JSON.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from sqlalchemy import ForeignKey, Index, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseImmutable


class SecurityBetaFeedback(BaseImmutable, Base):
    __tablename__ = "security_beta_feedback"
    __table_args__ = (
        Index("ix_security_beta_feedback_created_at", "created_at"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    feedback_type: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="report_export", default="report_export"
    )
    rating: Mapped[str] = mapped_column(Text, nullable=False)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    context: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict
    )
