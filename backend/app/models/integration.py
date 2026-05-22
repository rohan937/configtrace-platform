from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, BaseMixin

if TYPE_CHECKING:
    from app.models.resource import Resource
    from app.models.user import User


class Integration(BaseMixin, Base):
    """One record per connected provider account (e.g. a Cloudflare account).

    Stores encrypted API credentials, provider identifier, connection status,
    and timestamps. Every resource, snapshot, and change traces back here.

    Valid status values: 'active', 'paused', 'error'
    Valid provider values (MVP): 'cloudflare'
    """

    __tablename__ = "integrations"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)

    # AES-GCM ciphertext of the serialised credentials JSON.
    encrypted_credentials: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Initialisation vector stored alongside ciphertext for AES-GCM decryption.
    credential_iv: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Valid values: 'active', 'paused', 'error'
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default="active", server_default="active"
    )
    last_synced_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Phase 4 fields — present in schema from the start to avoid structural
    # migrations when scheduled sync is activated.
    scheduled_sync_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    sync_interval_minutes: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )

    # ── Relationships ────────────────────────────────────────────────────────
    user: Mapped[User] = relationship("User", back_populates="integrations")
    resources: Mapped[list[Resource]] = relationship(
        "Resource",
        back_populates="integration",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    # ── Computed helpers ─────────────────────────────────────────────────────
    # These are exposed via Pydantic ``from_attributes=True`` — the schema
    # declares the matching field and Pydantic calls ``getattr`` on the ORM
    # object, which resolves to the property.  The ``resources`` relationship
    # uses ``lazy="selectin"`` so it is always loaded alongside the parent row
    # — no extra query is issued here.

    @property
    def resource_count(self) -> int:
        """Number of Resource rows attached to this integration."""
        return len(self.resources)

    def __repr__(self) -> str:
        return (
            f"<Integration id={self.id} provider={self.provider!r}"
            f" display_name={self.display_name!r}>"
        )
