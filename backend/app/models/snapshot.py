from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, BaseImmutable

if TYPE_CHECKING:
    from app.models.resource import Resource


class Snapshot(BaseImmutable, Base):
    """Point-in-time snapshot of a resource's full configuration state.

    Snapshots are immutable — never updated or deleted after creation.
    They are the raw material from which diffs and change records are derived.

    state:        full normalised config as JSONB (e.g. list of DNS records)
    content_hash: SHA-256 of canonical serialisation; used for deduplication
    triggered_by: 'manual' or 'scheduled'
    sync_run_id:  nullable FK; populated in Phase 4 when sync_runs is active
    """

    __tablename__ = "snapshots"

    resource_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        # RESTRICT: snapshots must outlive their resource (historical record).
        ForeignKey("resources.id", ondelete="RESTRICT"),
        nullable=False,
    )
    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("integrations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # Denormalised for direct user-scoped queries without a join.
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    state: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    content_hash: Mapped[str] = mapped_column(Text, nullable=False)
    triggered_by: Mapped[str] = mapped_column(Text, nullable=False)
    # nullable until Phase 4 activates sync_runs
    sync_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sync_runs.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Relationships ────────────────────────────────────────────────────────
    resource: Mapped[Resource] = relationship("Resource", back_populates="snapshots")

    def __repr__(self) -> str:
        return (
            f"<Snapshot id={self.id} resource_id={self.resource_id}"
            f" hash={self.content_hash[:8]!r}...>"
        )
