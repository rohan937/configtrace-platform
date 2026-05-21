from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, BaseImmutable

if TYPE_CHECKING:
    from app.models.resource import Resource


class Change(BaseImmutable, Base):
    """One row per detected change between two consecutive snapshots.

    Written once by the diff service; never updated.
    These rows are the primary data shown in the timeline.

    change_type:       'added', 'removed', 'modified'
    record_identifier: human-readable label, e.g. 'A record: api.example.com'
    field_path:        dot-notation field name for 'modified' changes (e.g. 'ttl')
    prev_value:        JSONB — null for 'added'; full record for 'removed';
                       scalar wrapped in JSONB for 'modified'
    new_value:         JSONB — full record for 'added'; null for 'removed';
                       scalar wrapped in JSONB for 'modified'
    risk_level:        'low', 'medium', 'high', 'critical'
    risk_reason:       plain-English explanation shown in the UI
    """

    __tablename__ = "changes"

    resource_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("resources.id", ondelete="RESTRICT"),
        nullable=False,
    )
    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("integrations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # Denormalised for direct user-scoped timeline queries without a join.
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    prev_snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("snapshots.id", ondelete="RESTRICT"),
        nullable=False,
    )
    new_snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("snapshots.id", ondelete="RESTRICT"),
        nullable=False,
    )
    change_type: Mapped[str] = mapped_column(Text, nullable=False)
    record_identifier: Mapped[str] = mapped_column(Text, nullable=False)
    field_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    prev_value: Mapped[Optional[Any]] = mapped_column(JSONB, nullable=True)
    new_value: Mapped[Optional[Any]] = mapped_column(JSONB, nullable=True)
    risk_level: Mapped[str] = mapped_column(Text, nullable=False)
    risk_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Provider-specific context for display/debugging — not queried directly.
    provider_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONB, nullable=True
    )

    # ── Relationships ────────────────────────────────────────────────────────
    resource: Mapped[Resource] = relationship("Resource", back_populates="changes")

    def __repr__(self) -> str:
        return (
            f"<Change id={self.id} type={self.change_type!r}"
            f" risk={self.risk_level!r} field={self.field_path!r}>"
        )
