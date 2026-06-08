"""SecurityRuleSetting model — M61.7.

Workspace-scoped enable/disable override for a single security rule. Storage is
SPARSE: a missing row means the rule is ENABLED (the default). A row records an
explicit choice (typically ``enabled=False`` to suppress a noisy/irrelevant
rule, but an ``enabled=True`` row can also exist after a re-enable, preserving
who/when).

Disabling a rule only affects FUTURE evaluation — it never deletes, resolves, or
mutates existing findings.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import Boolean, ForeignKey, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


class SecurityRuleSetting(BaseMixin, Base):
    """A per-workspace enable/disable override for one security rule."""

    __tablename__ = "security_rule_settings"
    __table_args__ = (
        UniqueConstraint("workspace_id", "rule_key", name="uq_security_rule_settings_ws_key"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # The base rule key (matches app/services/security_rule_registry.KNOWN_RULE_KEYS).
    rule_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)

    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    # Who last changed this setting (NULL = unknown / system).
    updated_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityRuleSetting workspace={self.workspace_id} "
            f"rule={self.rule_key!r} enabled={self.enabled}>"
        )
