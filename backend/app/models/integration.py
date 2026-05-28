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
    from app.models.workspace import Workspace


class Integration(BaseMixin, Base):
    """One record per connected provider account (e.g. a Cloudflare account).

    Stores encrypted API credentials, provider identifier, connection status,
    and timestamps. Every resource, snapshot, and change traces back here.

    Valid status values:
      * ``active``           — credentials valid, scheduler will run syncs
      * ``paused``           — user-paused; manual + scheduled syncs blocked
      * ``needs_reconnect``  — provider auth revoked / installation removed /
                                token rotated externally.  Set automatically by
                                the sync exception handler when the failure
                                classifier returns ``failure_category=='authentication'``.
                                Scheduler skips these (it filters ``status=='active'``);
                                manual Sync Now returns 409; reconnect clears it.
      * ``error``            — legacy, retained for backwards-compat; new
                                authentication failures use ``needs_reconnect``.
      * ``deleted``          — soft-deleted by the user via DELETE /integrations/{id}.

    Valid provider values (MVP): 'cloudflare'
    """

    __tablename__ = "integrations"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    # ── M50: workspace ownership ──────────────────────────────────────────────
    # Nullable during migration backfill; non-null after 004_m50_workspaces.
    workspace_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)

    # AES-GCM ciphertext of the serialised credentials JSON.
    encrypted_credentials: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Initialisation vector stored alongside ciphertext for AES-GCM decryption.
    credential_iv: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Valid values: 'active', 'paused', 'needs_reconnect', 'error', 'deleted'
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

    # ── M32: consecutive failure tracking ─────────────────────────────────────
    # consecutive_failure_count: incremented on each *scheduled* sync failure,
    #   reset to 0 on any successful sync.  Manual failures do not change it.
    # last_failure_at: UTC timestamp of the most recent sync failure (any type).
    # last_failure_alert_sent_at: when we last emailed the user about failures.
    #   Used to enforce a 24-hour cooldown — never send more than one failure
    #   alert per integration per 24 hours.
    consecutive_failure_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    last_failure_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failure_alert_sent_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Relationships ────────────────────────────────────────────────────────
    user: Mapped[User] = relationship("User", back_populates="integrations")
    workspace: Mapped[Optional[Workspace]] = relationship(
        "Workspace", foreign_keys=[workspace_id]
    )
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
