"""Invite accept/preview routes — M50.

Routes
------
GET  /invites/{token}         — preview invite info (no auth required)
POST /invites/{token}/accept  — accept invite (auth required)

These routes are separate from /workspaces/{id}/invites to allow an
unauthenticated user to preview invite details before signing in.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.workspace import InvitePreviewResponse, WorkspaceMemberResponse
from app.services import workspace_service

router = APIRouter(prefix="/invites", tags=["invites"])


@router.get("/{token}", response_model=InvitePreviewResponse)
def preview_invite(
    token: str,
    db: Session = Depends(get_db),
) -> InvitePreviewResponse:
    """Return public invite info — safe to show before the user authenticates.

    Returns 404 if the token is not found (expired/revoked/accepted invites
    still return their info so the frontend can show a useful error state).
    """
    invite = workspace_service.get_invite_by_token(token, db)
    if invite is None:
        raise HTTPException(status_code=404, detail="Invite not found.")

    from app.models.workspace import Workspace

    workspace = db.get(Workspace, invite.workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found.")

    inviter_email: str | None = None
    if invite.invited_by_user_id:
        inviter = db.get(User, invite.invited_by_user_id)
        if inviter:
            inviter_email = inviter.email

    return InvitePreviewResponse(
        workspace_name=workspace.name,
        inviter_email=inviter_email,
        role=invite.role,  # type: ignore[arg-type]
        email=invite.email,
        expires_at=invite.expires_at,
        is_active=invite.is_active,
    )


@router.post("/{token}/accept", response_model=WorkspaceMemberResponse)
def accept_invite(
    token: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkspaceMemberResponse:
    """Accept an invite and join the workspace.

    The accepting user must be authenticated.  Returns the new membership row.

    HTTP 409 if:
    - Token is invalid, expired, revoked, or already accepted.
    - User is already a member of the workspace.
    """
    try:
        member = workspace_service.accept_invite(
            raw_token=token,
            accepting_user_id=current_user.id,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

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
