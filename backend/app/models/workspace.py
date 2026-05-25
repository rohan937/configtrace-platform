"""Workspace, WorkspaceMember, WorkspaceInvite, and WorkspaceAuditLog models — M50/M51."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, BaseImmutable, BaseMixin, _utcnow

if TYPE_CHECKING:
    from app.models.user import User


class Workspace(BaseMixin, Base):
    """A workspace groups integrations, resources, and members.

    Every user gets a default workspace on first login (created by the
    backfill migration).  Users may belong to multiple workspaces as members.
    """

    __tablename__ = "workspaces"

    name: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Relationships ────────────────────────────────────────────────────────
    members: Mapped[list[WorkspaceMember]] = relationship(
        "WorkspaceMember",
        back_populates="workspace",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    invites: Mapped[list[WorkspaceInvite]] = relationship(
        "WorkspaceInvite",
        back_populates="workspace",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Workspace id={self.id} name={self.name!r}>"


class WorkspaceMember(BaseMixin, Base):
    """Membership link between a User and a Workspace.

    Roles
    -----
    owner   — full control; cannot be removed while sole owner
    admin   — can invite/remove members (not owners); manage integrations
    member  — view only; cannot invite/remove/change roles
    """

    __tablename__ = "workspace_members"
    __table_args__ = (
        UniqueConstraint("workspace_id", "user_id", name="uq_workspace_member"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    # "owner" | "admin" | "member"
    role: Mapped[str] = mapped_column(Text, nullable=False, default="member")

    # ── Relationships ────────────────────────────────────────────────────────
    workspace: Mapped[Workspace] = relationship(
        "Workspace", back_populates="members"
    )
    user: Mapped[User] = relationship("User")

    def __repr__(self) -> str:
        return (
            f"<WorkspaceMember workspace={self.workspace_id} "
            f"user={self.user_id} role={self.role!r}>"
        )


class WorkspaceInvite(BaseMixin, Base):
    """A pending invite to join a workspace.

    Security design
    ---------------
    * ``token_hash`` stores the SHA-256 hex digest of the raw token.
      The raw token is returned exactly once (in the creation response)
      and never persisted.
    * ``email`` is always normalised to lowercase at write time.
    * An invite is "active" when accepted_at IS NULL AND revoked_at IS NULL
      AND expires_at > now().
    """

    __tablename__ = "workspace_invites"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Normalised lowercase email of the invitee.
    email: Mapped[str] = mapped_column(Text, nullable=False)
    # "admin" | "member" (owner is not directly inviteable)
    role: Mapped[str] = mapped_column(Text, nullable=False, default="member")
    # SHA-256 hex digest of the one-time raw token.
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    invited_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Relationships ────────────────────────────────────────────────────────
    workspace: Mapped[Workspace] = relationship(
        "Workspace", back_populates="invites"
    )

    @property
    def is_active(self) -> bool:
        """True when not accepted, not revoked, and not expired."""
        from datetime import timezone
        return (
            self.accepted_at is None
            and self.revoked_at is None
            and self.expires_at > datetime.now(timezone.utc)
        )

    def __repr__(self) -> str:
        return (
            f"<WorkspaceInvite workspace={self.workspace_id} "
            f"email={self.email!r} role={self.role!r}>"
        )


# ── M51: Workspace Audit Log ──────────────────────────────────────────────────


class WorkspaceAuditLog(BaseImmutable, Base):
    """Append-only record of important workspace actions.

    Security guarantees
    -------------------
    * ``target_id`` stores a human-safe identifier (UUID as string, email,
      or display name) — never a raw token, credential, or secret.
    * ``metadata_json`` contains display-safe context only.
    * Raw invite tokens, provider API keys, and credential values are
      NEVER stored here.

    Common event_type values
    ------------------------
    workspace_created / workspace_renamed
    member_invited / invite_revoked / invite_accepted
    member_removed / member_role_changed
    integration_created / integration_deleted
    manual_sync_triggered
    """

    __tablename__ = "workspace_audit_logs"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
    )
    # NULL when the action was system-initiated (e.g. migration backfill).
    actor_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    # "workspace" | "integration" | "member" | "invite" | "sync" | …
    target_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # UUID or other non-secret identifier of the affected object.
    target_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Human-readable label, e.g. "alice@example.com", "My AWS Integration".
    target_display_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Small, safe JSON blob — display context only, no secrets.
    metadata_json: Mapped[Optional[dict]] = mapped_column(
        "metadata_json",
        JSONB,
        nullable=True,
    )

    def __repr__(self) -> str:
        return (
            f"<WorkspaceAuditLog workspace={self.workspace_id} "
            f"event={self.event_type!r} actor={self.actor_user_id}>"
        )
