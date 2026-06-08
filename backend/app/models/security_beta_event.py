"""SecurityBetaEvent — lightweight first-party beta usage instrumentation (M63.1).

Append-only log of *coarse* Security Exposure usage events (page views, demo
load, report export, etc.) so we can learn whether beta users can navigate the
workflow. First-party storage only — NO third-party analytics SDK.

Privacy invariants (enforced in security_beta_event_service):
  * ``event_name`` must be on a fixed allowlist.
  * ``metadata`` keys must be on a small allowlist; everything else is dropped.
  * String values are truncated; nested objects/arrays are dropped.
  * NEVER stores evidence, remediation, secrets, tokens, payloads, raw provider
    data, raw rule JSON, note bodies, or other customer data.

This is for beta learning, not surveillance.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from sqlalchemy import ForeignKey, Index, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseImmutable


class SecurityBetaEvent(BaseImmutable, Base):
    __tablename__ = "security_beta_events"
    __table_args__ = (
        Index("ix_security_beta_events_created_at", "created_at"),
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
    event_name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    event_category: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="security_beta", default="security_beta"
    )
    page_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # SQLAlchemy reserves the ``metadata`` attribute name on declarative classes,
    # so the Python attribute is ``event_metadata`` mapped to the DB column "metadata".
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict
    )
