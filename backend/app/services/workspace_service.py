"""Workspace business logic — M50/M51.

Responsibilities
----------------
* Create, read, update workspaces.
* Manage workspace members (invite, role change, removal).
* Invite token lifecycle (create, accept, revoke, lookup).
* Audit log: append workspace action records (M51).
* Helper: ensure every user has a default workspace (called on first login).
* Helper: verify workspace membership for scoped queries.
* Helper: verify workspace role for RBAC enforcement.

Security invariants
-------------------
* Invite tokens are never stored; only their SHA-256 hash is persisted.
* email is always normalised to lowercase at write time.
* Sole owner cannot be removed or demoted (sole_owner_guard).
* admin cannot remove or demote owner.
* member cannot invite, remove, or change roles.
* Users cannot access workspaces they are not members of.
* Audit logs never store raw tokens, credentials, or secret values.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models.workspace import (
    Workspace,
    WorkspaceAuditLog,
    WorkspaceInvite,
    WorkspaceMember,
)

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_INVITE_EXPIRY_DAYS = 7
_INVITE_TOKEN_BYTES = 32  # 256 bits → 43 URL-safe chars

# Numeric rank for role comparisons (higher = more privilege).
_ROLE_RANK: dict[str, int] = {"owner": 3, "admin": 2, "member": 1}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _hash_token(raw_token: str) -> str:
    """Return the SHA-256 hex digest of a raw invite token."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _rank(role: str) -> int:
    return _ROLE_RANK.get(role, 0)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Audit log helpers ─────────────────────────────────────────────────────────


def log_audit_event(
    workspace_id: uuid.UUID,
    actor_user_id: Optional[uuid.UUID],
    event_type: str,
    db: Session,
    *,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    target_display_name: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Append an audit log entry in the current transaction.

    Fire-and-forget — caller commits; if the outer tx rolls back so does this.
    Never stores raw tokens, credentials, or secret values.
    """
    entry = WorkspaceAuditLog(
        workspace_id=workspace_id,
        actor_user_id=actor_user_id,
        event_type=event_type,
        target_type=target_type,
        target_id=target_id,
        target_display_name=target_display_name,
        metadata_json=metadata,
    )
    db.add(entry)


def get_audit_logs(
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    db: Session,
    *,
    limit: int = 50,
    offset: int = 0,
    event_type_filter: Optional[str] = None,
) -> tuple[list[WorkspaceAuditLog], int]:
    """Return (logs, total) for a workspace.  Actor must be a member.

    Joins actor User for email/display_name enrichment.
    Raises LookupError if actor is not a member.
    """
    from app.models.user import User

    _require_membership(workspace_id, actor_user_id, db)

    q = db.query(WorkspaceAuditLog).filter(
        WorkspaceAuditLog.workspace_id == workspace_id
    )
    if event_type_filter:
        q = q.filter(WorkspaceAuditLog.event_type == event_type_filter)

    total = q.count()
    logs = (
        q.order_by(WorkspaceAuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    # Enrich with actor user info (best-effort; actor may have been deleted).
    actor_ids = {log.actor_user_id for log in logs if log.actor_user_id}
    if actor_ids:
        users = (
            db.query(User).filter(User.id.in_(actor_ids)).all()
        )
        user_map: Dict[uuid.UUID, Any] = {u.id: u for u in users}
        for log in logs:
            if log.actor_user_id and log.actor_user_id in user_map:
                u = user_map[log.actor_user_id]
                log.actor_email = getattr(u, "email", None)  # type: ignore[attr-defined]
                log.actor_display_name = getattr(u, "display_name", None)  # type: ignore[attr-defined]

    return logs, total


def require_role(
    workspace_id: uuid.UUID,
    user_id: uuid.UUID,
    min_role: str,
    db: Session,
) -> WorkspaceMember:
    """Return the membership row if user has at least min_role, else raise.

    Raises LookupError if not a member.
    Raises PermissionError if role is insufficient.
    """
    member = _require_membership(workspace_id, user_id, db)
    if _rank(member.role) < _rank(min_role):
        raise PermissionError(
            f"This action requires at least the '{min_role}' role."
        )
    return member


# ── Workspace CRUD ────────────────────────────────────────────────────────────


def create_workspace(
    name: str,
    created_by_user_id: uuid.UUID,
    db: Session,
) -> tuple[Workspace, WorkspaceMember]:
    """Create a workspace and add the creator as owner.

    Returns (workspace, owner_membership).
    """
    workspace = Workspace(
        name=name.strip(),
        created_by_user_id=created_by_user_id,
    )
    db.add(workspace)
    db.flush()  # populate workspace.id

    member = WorkspaceMember(
        workspace_id=workspace.id,
        user_id=created_by_user_id,
        role="owner",
    )
    db.add(member)

    log_audit_event(
        workspace.id,
        created_by_user_id,
        "workspace_created",
        db,
        target_type="workspace",
        target_id=str(workspace.id),
        target_display_name=workspace.name,
    )

    db.commit()
    db.refresh(workspace)
    db.refresh(member)
    return workspace, member


def get_workspaces_for_user(
    user_id: uuid.UUID,
    db: Session,
) -> list[Workspace]:
    """Return all workspaces where the user is a member (any role)."""
    memberships = (
        db.query(WorkspaceMember)
        .filter(WorkspaceMember.user_id == user_id)
        .all()
    )
    workspace_ids = [m.workspace_id for m in memberships]
    if not workspace_ids:
        return []
    return (
        db.query(Workspace)
        .filter(Workspace.id.in_(workspace_ids))
        .order_by(Workspace.created_at)
        .all()
    )


def get_user_workspace_ids(user_id: uuid.UUID, db: Session) -> list[uuid.UUID]:
    """Return every workspace_id the user is a member of (any role).

    The single canonical source for "which workspaces can this user see" —
    used by read-path authorization across resources/changes/security
    findings so a workspace member (not just the row's original creator)
    can see data belonging to their own workspace. A cheap, single-column
    query; callers should treat an empty list as "nothing visible" rather
    than fetching unfiltered."""
    rows = (
        db.query(WorkspaceMember.workspace_id)
        .filter(WorkspaceMember.user_id == user_id)
        .all()
    )
    return [r[0] for r in rows]


def get_workspace(
    workspace_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> Optional[Workspace]:
    """Return workspace if user is a member, else None."""
    member = get_membership(workspace_id, user_id, db)
    if member is None:
        return None
    return db.get(Workspace, workspace_id)


def update_workspace_name(
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    new_name: str,
    db: Session,
) -> Workspace:
    """Rename a workspace.  Actor must be owner or admin.

    Raises LookupError if not a member or workspace not found.
    Raises PermissionError if actor is member (view-only).
    """
    actor = _require_membership(workspace_id, actor_user_id, db)
    if _rank(actor.role) < _rank("admin"):
        raise PermissionError("Only owners and admins can rename a workspace.")
    workspace = db.get(Workspace, workspace_id)
    if workspace is None:
        raise LookupError("Workspace not found.")
    old_name = workspace.name
    workspace.name = new_name.strip()

    log_audit_event(
        workspace_id,
        actor_user_id,
        "workspace_renamed",
        db,
        target_type="workspace",
        target_id=str(workspace_id),
        target_display_name=workspace.name,
        metadata={"old_name": old_name, "new_name": workspace.name},
    )

    db.commit()
    db.refresh(workspace)
    return workspace


# ── Membership helpers ────────────────────────────────────────────────────────


def get_membership(
    workspace_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> Optional[WorkspaceMember]:
    """Return the WorkspaceMember row for (workspace_id, user_id), or None."""
    return (
        db.query(WorkspaceMember)
        .filter(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == user_id,
        )
        .first()
    )


def _require_membership(
    workspace_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> WorkspaceMember:
    """Return membership or raise LookupError."""
    member = get_membership(workspace_id, user_id, db)
    if member is None:
        raise LookupError("Workspace not found or you are not a member.")
    return member


def list_members(
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    db: Session,
) -> list[WorkspaceMember]:
    """Return all members of a workspace.  Actor must be a member."""
    _require_membership(workspace_id, actor_user_id, db)
    return (
        db.query(WorkspaceMember)
        .filter(WorkspaceMember.workspace_id == workspace_id)
        .order_by(WorkspaceMember.created_at)
        .all()
    )


def update_member_role(
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    target_member_id: uuid.UUID,
    new_role: str,
    db: Session,
) -> WorkspaceMember:
    """Change a member's role.  Only owners can change roles.

    Sole-owner protection: an owner cannot be demoted while they are the
    only owner in the workspace.

    Raises LookupError if workspace/target not found.
    Raises PermissionError if actor lacks permission.
    Raises ValueError if the operation would leave the workspace owner-less.
    """
    actor = _require_membership(workspace_id, actor_user_id, db)
    if actor.role != "owner":
        raise PermissionError("Only owners can change member roles.")

    target = db.get(WorkspaceMember, target_member_id)
    if target is None or target.workspace_id != workspace_id:
        raise LookupError("Member not found in this workspace.")

    # Sole-owner guard: cannot demote the last owner.
    if target.role == "owner" and new_role != "owner":
        owner_count = (
            db.query(WorkspaceMember)
            .filter(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.role == "owner",
            )
            .count()
        )
        if owner_count <= 1:
            raise ValueError(
                "Cannot demote the sole owner. "
                "Transfer ownership first or add another owner."
            )

    old_role = target.role
    target.role = new_role

    log_audit_event(
        workspace_id,
        actor_user_id,
        "member_role_changed",
        db,
        target_type="member",
        target_id=str(target.user_id),
        metadata={"old_role": old_role, "new_role": new_role},
    )

    db.commit()
    db.refresh(target)
    return target


def remove_member(
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    target_member_id: uuid.UUID,
    db: Session,
) -> None:
    """Remove a member from the workspace.

    Rules:
    - Owner can remove anyone except themselves if sole owner.
    - Admin can remove members but NOT owners.
    - Member cannot remove anyone.
    - Sole owner cannot be removed.

    Raises LookupError if workspace/target not found.
    Raises PermissionError if actor lacks permission.
    Raises ValueError if sole-owner removal is attempted.
    """
    actor = _require_membership(workspace_id, actor_user_id, db)
    if _rank(actor.role) < _rank("admin"):
        raise PermissionError("Only owners and admins can remove members.")

    target = db.get(WorkspaceMember, target_member_id)
    if target is None or target.workspace_id != workspace_id:
        raise LookupError("Member not found in this workspace.")

    # Admin cannot remove owner.
    if actor.role == "admin" and target.role == "owner":
        raise PermissionError("Admins cannot remove workspace owners.")

    # Sole-owner guard.
    if target.role == "owner":
        owner_count = (
            db.query(WorkspaceMember)
            .filter(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.role == "owner",
            )
            .count()
        )
        if owner_count <= 1:
            raise ValueError(
                "Cannot remove the sole owner. "
                "Transfer ownership first or add another owner."
            )

    log_audit_event(
        workspace_id,
        actor_user_id,
        "member_removed",
        db,
        target_type="member",
        target_id=str(target.user_id),
        metadata={"removed_role": target.role},
    )

    db.delete(target)
    db.commit()


# ── Invite lifecycle ──────────────────────────────────────────────────────────


def create_invite(
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    email: str,
    role: str,
    db: Session,
    base_url: str = "http://localhost:3000",
) -> tuple[WorkspaceInvite, str]:
    """Create an invite and return (invite_row, raw_token).

    The raw token is returned exactly once; only its hash is stored.

    Raises LookupError if workspace not found or actor not a member.
    Raises PermissionError if actor is a plain member.
    Raises ValueError on duplicate active invite or if target is already member.
    """
    actor = _require_membership(workspace_id, actor_user_id, db)
    if _rank(actor.role) < _rank("admin"):
        raise PermissionError("Only owners and admins can send invites.")

    normalised_email = email.strip().lower()

    # Reject if target is already a member (join through User).
    from app.models.user import User

    target_user = (
        db.query(User).filter(User.email == normalised_email).first()
    )
    if target_user:
        existing_member = get_membership(workspace_id, target_user.id, db)
        if existing_member:
            raise ValueError(
                f"{normalised_email!r} is already a member of this workspace."
            )

    # Reject duplicate active invites.
    existing_invite = (
        db.query(WorkspaceInvite)
        .filter(
            WorkspaceInvite.workspace_id == workspace_id,
            WorkspaceInvite.email == normalised_email,
            WorkspaceInvite.accepted_at.is_(None),
            WorkspaceInvite.revoked_at.is_(None),
            WorkspaceInvite.expires_at > _utcnow(),
        )
        .first()
    )
    if existing_invite:
        raise ValueError(
            f"An active invite for {normalised_email!r} already exists. "
            "Revoke it first to re-invite."
        )

    raw_token = secrets.token_urlsafe(_INVITE_TOKEN_BYTES)
    token_hash = _hash_token(raw_token)

    invite = WorkspaceInvite(
        workspace_id=workspace_id,
        email=normalised_email,
        role=role,
        token_hash=token_hash,
        invited_by_user_id=actor_user_id,
        expires_at=_utcnow() + timedelta(days=_INVITE_EXPIRY_DAYS),
    )
    db.add(invite)

    log_audit_event(
        workspace_id,
        actor_user_id,
        "member_invited",
        db,
        target_type="invite",
        target_id=None,  # invite.id not yet populated before flush; omit
        target_display_name=normalised_email,
        metadata={"role": role},
    )

    db.commit()
    db.refresh(invite)
    return invite, raw_token


def list_invites(
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    db: Session,
    active_only: bool = False,
) -> list[WorkspaceInvite]:
    """Return invites for a workspace.  Actor must be owner or admin."""
    actor = _require_membership(workspace_id, actor_user_id, db)
    if _rank(actor.role) < _rank("admin"):
        raise PermissionError("Only owners and admins can view invites.")

    q = db.query(WorkspaceInvite).filter(
        WorkspaceInvite.workspace_id == workspace_id
    )
    if active_only:
        q = q.filter(
            WorkspaceInvite.accepted_at.is_(None),
            WorkspaceInvite.revoked_at.is_(None),
            WorkspaceInvite.expires_at > _utcnow(),
        )
    return q.order_by(WorkspaceInvite.created_at.desc()).all()


def revoke_invite(
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    invite_id: uuid.UUID,
    db: Session,
) -> None:
    """Revoke a pending invite.  Actor must be owner or admin."""
    actor = _require_membership(workspace_id, actor_user_id, db)
    if _rank(actor.role) < _rank("admin"):
        raise PermissionError("Only owners and admins can revoke invites.")

    invite = db.get(WorkspaceInvite, invite_id)
    if invite is None or invite.workspace_id != workspace_id:
        raise LookupError("Invite not found in this workspace.")
    if invite.revoked_at is not None:
        return  # idempotent — already revoked
    if invite.accepted_at is not None:
        raise ValueError("Cannot revoke an already-accepted invite.")

    invite.revoked_at = _utcnow()

    log_audit_event(
        workspace_id,
        actor_user_id,
        "invite_revoked",
        db,
        target_type="invite",
        target_id=str(invite_id),
        target_display_name=invite.email,
    )

    db.commit()


def get_invite_by_token(
    raw_token: str,
    db: Session,
) -> Optional[WorkspaceInvite]:
    """Look up an invite by the raw token (hashes internally)."""
    token_hash = _hash_token(raw_token)
    return (
        db.query(WorkspaceInvite)
        .filter(WorkspaceInvite.token_hash == token_hash)
        .first()
    )


def accept_invite(
    raw_token: str,
    accepting_user_id: uuid.UUID,
    db: Session,
) -> WorkspaceMember:
    """Accept an invite and create a WorkspaceMember row.

    The accepting user's account email does not need to match the invite email
    (users may sign up with a different address than they were invited with).
    This is a product decision — M51 can tighten if needed.

    Raises ValueError if the invite is expired, revoked, or already accepted.
    Raises ValueError if the user is already a member of the workspace.
    """
    invite = get_invite_by_token(raw_token, db)
    if invite is None:
        raise ValueError("Invite not found or token is invalid.")
    if invite.revoked_at is not None:
        raise ValueError("This invite has been revoked.")
    if invite.accepted_at is not None:
        raise ValueError("This invite has already been accepted.")
    if invite.expires_at <= _utcnow():
        raise ValueError("This invite has expired.")

    # Check already a member.
    existing = get_membership(invite.workspace_id, accepting_user_id, db)
    if existing:
        raise ValueError(
            "You are already a member of this workspace."
        )

    # M52: Enforce member limit at accept-time (plan may have changed since
    # the invite was sent).  Raises HTTPException 402 if at the limit.
    try:
        from app.services.billing_service import assert_can_add_member
        assert_can_add_member(invite.workspace_id, db)
    except Exception as exc:
        # Re-raise HTTPExceptions directly; wrap anything else as ValueError.
        from fastapi import HTTPException as _HTTP
        if isinstance(exc, _HTTP):
            raise
        raise ValueError(f"Workspace member limit reached: {exc}") from exc

    member = WorkspaceMember(
        workspace_id=invite.workspace_id,
        user_id=accepting_user_id,
        role=invite.role,
    )
    db.add(member)

    invite.accepted_at = _utcnow()

    log_audit_event(
        invite.workspace_id,
        accepting_user_id,
        "invite_accepted",
        db,
        target_type="invite",
        target_id=str(invite.id),
        target_display_name=invite.email,
        metadata={"role": invite.role},
    )

    db.commit()
    db.refresh(member)
    return member


# ── Default workspace bootstrapping ──────────────────────────────────────────


def get_or_create_default_workspace(
    user_id: uuid.UUID,
    user_display_name: Optional[str],
    db: Session,
) -> Workspace:
    """Ensure the user has at least one workspace; return their primary one.

    "Primary" = oldest workspace where the user is an owner.  If none exists,
    creates a new default workspace named after the user.

    Called on first login (by the auth dependency) and in integration creation
    when no workspace_id is supplied.
    """
    # Find existing owner workspace (oldest).
    owner_memberships = (
        db.query(WorkspaceMember)
        .filter(
            WorkspaceMember.user_id == user_id,
            WorkspaceMember.role == "owner",
        )
        .order_by(WorkspaceMember.created_at)
        .all()
    )
    for membership in owner_memberships:
        ws = db.get(Workspace, membership.workspace_id)
        if ws is not None:
            return ws

    # No owned workspace — create default.
    name = f"{user_display_name or 'My'} Workspace"
    workspace, _ = create_workspace(name, user_id, db)
    return workspace


def get_default_workspace_for_user(
    user_id: uuid.UUID,
    db: Session,
) -> Optional[Workspace]:
    """Return the user's primary workspace (oldest owned), or None."""
    membership = (
        db.query(WorkspaceMember)
        .filter(
            WorkspaceMember.user_id == user_id,
            WorkspaceMember.role == "owner",
        )
        .order_by(WorkspaceMember.created_at)
        .first()
    )
    if membership is None:
        # Fall back to any membership (admin, member).
        membership = (
            db.query(WorkspaceMember)
            .filter(WorkspaceMember.user_id == user_id)
            .order_by(WorkspaceMember.created_at)
            .first()
        )
    if membership is None:
        return None
    return db.get(Workspace, membership.workspace_id)
