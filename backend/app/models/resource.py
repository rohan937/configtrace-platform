from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, BaseMixin

if TYPE_CHECKING:
    from app.models.change import Change
    from app.models.integration import Integration
    from app.models.snapshot import Snapshot


class Resource(BaseMixin, Base):
    """One record per monitored resource within an integration.

    For Cloudflare, a resource is a DNS zone.  Snapshots and diffs operate at
    this granularity, not at the integration level.

    provider_resource_type examples: 'cloudflare_dns_zone', 'stripe_webhook_endpoints'
    """

    __tablename__ = "resources"
    __table_args__ = (
        UniqueConstraint(
            "integration_id",
            "provider_resource_id",
            name="uq_resource_integration_provider",
        ),
    )

    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("integrations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Denormalised from integrations for direct user-scoped queries without a
    # join — a deliberate write-redundancy / read-simplicity tradeoff.
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider_resource_type: Mapped[str] = mapped_column(Text, nullable=False)
    provider_resource_id: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)

    # Provider-specific metadata for display/debugging; not used in diffs.
    # Named resource_metadata in Python to avoid shadowing Base.metadata.
    resource_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        "metadata", JSONB, nullable=True
    )
    last_snapshot_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Soft-delete: set False when integration is deactivated.  Snapshots and
    # changes are preserved via RESTRICT foreign keys.
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    # ── Relationships ────────────────────────────────────────────────────────
    integration: Mapped[Integration] = relationship(
        "Integration", back_populates="resources"
    )
    snapshots: Mapped[list[Snapshot]] = relationship(
        "Snapshot",
        back_populates="resource",
        order_by="Snapshot.created_at.desc()",
        lazy="dynamic",
    )
    changes: Mapped[list[Change]] = relationship(
        "Change",
        back_populates="resource",
        order_by="Change.created_at.desc()",
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        return (
            f"<Resource id={self.id} type={self.provider_resource_type!r}"
            f" provider_id={self.provider_resource_id!r}>"
        )
