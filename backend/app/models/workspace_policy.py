"""WorkspacePolicy model — M58.14.

Stores per-workspace policy enable/disable overrides.
Built-in policy metadata (name, description, severity, etc.) lives entirely
in the catalog (policy_engine_service.py) — only the enabled flag is persisted.
"""
from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


class WorkspacePolicy(BaseMixin, Base):
    """Per-workspace enable/disable override for a built-in policy.

    If no row exists for a (workspace_id, policy_key) pair, the policy
    is treated as enabled (default).  Only explicit disables are stored.
    """

    __tablename__ = "workspace_policies"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "policy_key",
            name="uq_workspace_policies_workspace_policy",
        ),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    policy_key: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
