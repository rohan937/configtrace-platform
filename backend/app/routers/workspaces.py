"""Workspace and member management routes — M50/M51.

Routes
------
GET    /workspaces                                   — list user's workspaces
POST   /workspaces                                   — create workspace
GET    /workspaces/{workspace_id}                    — get workspace detail
PATCH  /workspaces/{workspace_id}                    — rename workspace
GET    /workspaces/{workspace_id}/members            — list members
PATCH  /workspaces/{workspace_id}/members/{id}       — change member role
DELETE /workspaces/{workspace_id}/members/{id}       — remove member
GET    /workspaces/{workspace_id}/invites            — list invites
POST   /workspaces/{workspace_id}/invites            — create invite
DELETE /workspaces/{workspace_id}/invites/{id}       — revoke invite
GET    /workspaces/{workspace_id}/audit-logs         — workspace audit history (M51)
"""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import UUID4
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.database import get_db
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.schemas.workspace import (
    AuditLogListResponse,
    InviteCreateRequest,
    InviteCreateResponse,
    InviteListResponse,
    InviteRole,
    MemberListResponse,
    MemberUpdateRequest,
    WorkspaceAuditLogResponse,
    WorkspaceCreateRequest,
    WorkspaceInviteResponse,
    WorkspaceListResponse,
    WorkspaceMemberResponse,
    WorkspaceResponse,
    WorkspaceUpdateRequest,
)
from app.services import workspace_service

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


# ── Helpers ───────────────────────────────────────────────────────────────────


def _member_response(member: WorkspaceMember, db: Session) -> WorkspaceMemberResponse:
    """Build WorkspaceMemberResponse with user email/name joined in."""
    user = db.get(User, member.user_id)
    return WorkspaceMemberResponse(
        id=member.id,
        workspace_id=member.workspace_id,
        user_id=member.user_id,
        role=member.role,  # type: ignore[arg-type]
        email=user.email if user else None,
        display_name=user.display_name if user else None,
        created_at=member.created_at,
        updated_at=member.updated_at,
    )


def _base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")


# ── Workspace CRUD ────────────────────────────────────────────────────────────


@router.get("", response_model=WorkspaceListResponse)
def list_workspaces(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkspaceListResponse:
    """Return all workspaces where the authenticated user is a member."""
    workspaces = workspace_service.get_workspaces_for_user(current_user.id, db)
    return WorkspaceListResponse(
        workspaces=[WorkspaceResponse.model_validate(w) for w in workspaces],
        total=len(workspaces),
    )


@router.post("", response_model=WorkspaceResponse, status_code=201)
def create_workspace(
    body: WorkspaceCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkspaceResponse:
    """Create a new workspace.  The creator is automatically assigned the owner role."""
    workspace, _ = workspace_service.create_workspace(
        name=body.name,
        created_by_user_id=current_user.id,
        db=db,
    )
    return WorkspaceResponse.model_validate(workspace)


@router.get("/{workspace_id}", response_model=WorkspaceResponse)
def get_workspace(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkspaceResponse:
    """Return workspace detail.  User must be a member."""
    workspace = workspace_service.get_workspace(workspace_id, current_user.id, db)
    if workspace is None:
        raise HTTPException(
            status_code=404,
            detail="Workspace not found or you are not a member.",
        )
    return WorkspaceResponse.model_validate(workspace)


@router.patch("/{workspace_id}", response_model=WorkspaceResponse)
def update_workspace(
    workspace_id: UUID4,
    body: WorkspaceUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkspaceResponse:
    """Rename a workspace.  Requires owner or admin role."""
    try:
        workspace = workspace_service.update_workspace_name(
            workspace_id=workspace_id,
            actor_user_id=current_user.id,
            new_name=body.name,
            db=db,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return WorkspaceResponse.model_validate(workspace)


# ── Members ───────────────────────────────────────────────────────────────────


@router.get("/{workspace_id}/members", response_model=MemberListResponse)
def list_members(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MemberListResponse:
    """Return all workspace members.  User must be a member of the workspace."""
    try:
        members = workspace_service.list_members(workspace_id, current_user.id, db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return MemberListResponse(
        members=[_member_response(m, db) for m in members],
        total=len(members),
    )


@router.patch(
    "/{workspace_id}/members/{member_id}",
    response_model=WorkspaceMemberResponse,
)
def update_member(
    workspace_id: UUID4,
    member_id: UUID4,
    body: MemberUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkspaceMemberResponse:
    """Change a member's role.  Requires owner role."""
    try:
        member = workspace_service.update_member_role(
            workspace_id=workspace_id,
            actor_user_id=current_user.id,
            target_member_id=member_id,
            new_role=body.role,
            db=db,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _member_response(member, db)


@router.delete("/{workspace_id}/members/{member_id}", status_code=204, response_class=Response)
def remove_member(
    workspace_id: UUID4,
    member_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Remove a member from the workspace.  Requires owner or admin role."""
    try:
        workspace_service.remove_member(
            workspace_id=workspace_id,
            actor_user_id=current_user.id,
            target_member_id=member_id,
            db=db,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=204)


# ── Invites ───────────────────────────────────────────────────────────────────


@router.get("/{workspace_id}/invites", response_model=InviteListResponse)
def list_invites(
    workspace_id: UUID4,
    active_only: bool = Query(False, description="Only return pending/active invites."),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> InviteListResponse:
    """Return invites for a workspace.  Requires owner or admin role."""
    try:
        invites = workspace_service.list_invites(
            workspace_id, current_user.id, db, active_only=active_only
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return InviteListResponse(
        invites=[WorkspaceInviteResponse.model_validate(i) for i in invites],
        total=len(invites),
    )


@router.post(
    "/{workspace_id}/invites",
    response_model=InviteCreateResponse,
    status_code=201,
)
def create_invite(
    workspace_id: UUID4,
    body: InviteCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> InviteCreateResponse:
    """Create a workspace invite.  Requires owner or admin role.

    The raw invite token is returned once in the response.  It is NOT stored
    and cannot be recovered after this call.  Share the ``invite_url`` with
    the invitee.
    """
    try:
        invite, raw_token = workspace_service.create_invite(
            workspace_id=workspace_id,
            actor_user_id=current_user.id,
            email=body.email,
            role=body.role,
            db=db,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    invite_url = f"{_base_url(request)}/invites/{raw_token}"
    return InviteCreateResponse(
        id=invite.id,
        workspace_id=invite.workspace_id,
        email=invite.email,
        role=invite.role,  # type: ignore[arg-type]
        invited_by_user_id=invite.invited_by_user_id,
        expires_at=invite.expires_at,
        accepted_at=invite.accepted_at,
        revoked_at=invite.revoked_at,
        created_at=invite.created_at,
        is_active=invite.is_active,
        invite_token=raw_token,
        invite_url=invite_url,
    )


@router.delete("/{workspace_id}/invites/{invite_id}", status_code=204, response_class=Response)
def revoke_invite(
    workspace_id: UUID4,
    invite_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Revoke a pending invite.  Requires owner or admin role."""
    try:
        workspace_service.revoke_invite(
            workspace_id=workspace_id,
            actor_user_id=current_user.id,
            invite_id=invite_id,
            db=db,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=204)


# ── Audit log (M51) ───────────────────────────────────────────────────────────


@router.get("/{workspace_id}/audit-logs", response_model=AuditLogListResponse)
def list_audit_logs(
    workspace_id: UUID4,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = Query(None, description="Filter by event type."),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditLogListResponse:
    """Return workspace audit history.  Any workspace member can view logs."""
    try:
        logs, total = workspace_service.get_audit_logs(
            workspace_id=workspace_id,
            actor_user_id=current_user.id,
            db=db,
            limit=limit,
            offset=offset,
            event_type_filter=event_type,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return AuditLogListResponse(
        logs=[
            WorkspaceAuditLogResponse(
                id=log.id,
                workspace_id=log.workspace_id,
                actor_user_id=log.actor_user_id,
                event_type=log.event_type,
                target_type=log.target_type,
                target_id=log.target_id,
                target_display_name=log.target_display_name,
                metadata_json=log.metadata_json,
                created_at=log.created_at,
                actor_email=getattr(log, "actor_email", None),
                actor_display_name=getattr(log, "actor_display_name", None),
            )
            for log in logs
        ],
        total=total,
    )
