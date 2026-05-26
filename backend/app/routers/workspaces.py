"""Workspace and member management routes — M50/M51/M57.1/M58.5/M58.7/M58.14.

Routes
------
GET    /workspaces                                              — list user's workspaces
POST   /workspaces                                             — create workspace
GET    /workspaces/{workspace_id}                              — get workspace detail
PATCH  /workspaces/{workspace_id}                              — rename workspace
GET    /workspaces/{workspace_id}/members                      — list members
PATCH  /workspaces/{workspace_id}/members/{id}                 — change member role
DELETE /workspaces/{workspace_id}/members/{id}                 — remove member
GET    /workspaces/{workspace_id}/invites                      — list invites
POST   /workspaces/{workspace_id}/invites                      — create invite
DELETE /workspaces/{workspace_id}/invites/{id}                 — revoke invite
GET    /workspaces/{workspace_id}/audit-logs                   — workspace audit history (M51)
GET    /workspaces/{workspace_id}/notification-settings        — get notification settings (M57.1)
PUT    /workspaces/{workspace_id}/notification-settings        — update notification settings (M57.1)
POST   /workspaces/{workspace_id}/notification-settings/test   — send test notification (M57.1)
GET    /workspaces/{workspace_id}/notifications/slack/install-url  — Slack App install URL (M58.5)
GET    /workspaces/{workspace_id}/notifications/slack/channels     — list Slack channels (M58.5)
PUT    /workspaces/{workspace_id}/notifications/slack/channel      — select Slack channel (M58.5)
POST   /workspaces/{workspace_id}/notifications/slack/test         — test Slack App delivery (M58.5)
DELETE /workspaces/{workspace_id}/notifications/slack              — disconnect Slack App (M58.5)
GET    /workspaces/{workspace_id}/notifications/push/public-key    — VAPID public key (M58.7)
POST   /workspaces/{workspace_id}/notifications/push/subscriptions — register push sub (M58.7)
GET    /workspaces/{workspace_id}/notifications/push/subscriptions — list push subs (M58.7)
DELETE /workspaces/{workspace_id}/notifications/push/subscriptions/{sub_id} — remove sub (M58.7)
POST   /workspaces/{workspace_id}/notifications/push/test          — test push delivery (M58.7)
GET    /workspaces/{workspace_id}/policies                         — list policy catalog with enabled state (M58.14)
PUT    /workspaces/{workspace_id}/policies/{policy_key}            — enable/disable a policy (M58.14)
GET    /workspaces/{workspace_id}/weekly-digest/preview            — preview digest for last 7 days (M58.15)
GET    /workspaces/{workspace_id}/weekly-digest/settings           — get digest schedule settings (M58.15)
PUT    /workspaces/{workspace_id}/weekly-digest/settings           — update digest schedule settings (M58.15)
POST   /workspaces/{workspace_id}/weekly-digest/test               — send test digest to current user (M58.15)
"""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
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
from app.schemas.notification_settings import (
    NotificationSettingsResponse,
    NotificationSettingsUpdateRequest,
    SlackChannelUpdateRequest,
    SlackChannelsListResponse,
    SlackChannelResponse,
    SlackInstallUrlResponse,
    TestNotificationResponse,
    # M58.7 — Web Push
    PushPublicKeyResponse,
    PushSubscribeRequest,
    PushSubscriptionListResponse,
    PushSubscriptionResponse,
    PushTestResponse,
)
from app.schemas.policy import (
    PolicyListResponse,
    PolicyUpdateRequest,
    WorkspacePolicyResponse,
)
from app.schemas.weekly_digest import (
    WeeklyDigest,
    WeeklyDigestSettings,
    WeeklyDigestSettingsUpdateRequest,
    WeeklyDigestTestResponse,
)
from app.services import workspace_service
from app.services import notification_service
from app.services import policy_engine_service
from app.services import weekly_digest_service

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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> InviteCreateResponse:
    """Create a workspace invite.  Requires owner or admin role.

    The raw invite token is returned once in the response.  It is NOT stored
    and cannot be recovered after this call.  Share the ``invite_url`` with
    the invitee.

    Sends an invite email via Resend when EMAIL_FROM + RESEND_API_KEY are
    configured.  If email fails or is unconfigured, invite creation still
    succeeds and ``email_sent`` is returned as ``false`` — the frontend
    shows the copy-link fallback.
    """
    # M52: Enforce member limit before creating the invite.
    # We check here (not just at accept-time) so the admin gets early feedback.
    from app.services.billing_service import assert_can_add_member
    assert_can_add_member(workspace_id, db)  # type: ignore[arg-type]

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

    # Build the invite URL from the configured frontend origin so the link
    # opens the human-readable accept page, not the backend JSON API endpoint.
    # This is used both for the response (copy-link) and the invite email.
    from app.config import settings as _settings
    frontend_invite_url = (
        f"{_settings.effective_frontend_url}/invites/{raw_token}"
    )

    # Send invite email via Resend (fire-and-forget — never rolls back the invite).
    # SECURITY: raw_token is in invite_url — never log it.
    email_sent = False
    from app.services import email_service as _email_svc
    try:
        # Fetch workspace name for the email body.
        from app.models.workspace import Workspace as _Workspace
        workspace_obj = db.get(_Workspace, workspace_id)
        workspace_name = workspace_obj.name if workspace_obj else "your workspace"
        inviter_display = current_user.email or current_user.display_name

        _email_svc.send_invite_email(
            to=invite.email,
            workspace_name=workspace_name,
            role=invite.role,
            invite_url=frontend_invite_url,  # SECURITY: contains raw token — not logged
            inviter_display=inviter_display,
        )
        email_sent = True
    except _email_svc.EmailNotConfigured:
        # Email not configured — silently fall back to copy-link.
        import logging as _logging
        _logging.getLogger(__name__).info(
            "Invite email skipped (email not configured) for workspace %s",
            workspace_id,
        )
    except Exception as _exc:
        # Email send error — log safely (no token) and fall through.
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "Invite email failed for workspace %s: %s",
            workspace_id,
            type(_exc).__name__,  # Only type, not message — message might contain PII
        )

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
        invite_url=frontend_invite_url,
        email_sent=email_sent,
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


# ── Notification settings (M57.1) ─────────────────────────────────────────────


@router.get(
    "/{workspace_id}/notification-settings",
    response_model=NotificationSettingsResponse,
)
def get_notification_settings(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NotificationSettingsResponse:
    """Return notification settings for a workspace.

    Any workspace member can read settings.  Creates a default row on first
    access (both channels disabled, no URLs).

    Security: webhook URLs are NEVER returned in full — only masked forms.
    """
    # Require membership (any role can read).
    try:
        workspace_service.require_role(
            workspace_id, current_user.id, "member", db
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    row = notification_service.get_or_create_notification_settings(
        workspace_id, db
    )
    data = notification_service.build_settings_response(row)
    return NotificationSettingsResponse(**data)


@router.put(
    "/{workspace_id}/notification-settings",
    response_model=NotificationSettingsResponse,
)
def update_notification_settings(
    workspace_id: UUID4,
    body: NotificationSettingsUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NotificationSettingsResponse:
    """Update notification settings for a workspace.

    Requires owner or admin role.  Only fields present in the request body
    are updated — omitted fields keep their current values.

    To clear a webhook URL and disable the channel, pass ``""`` for the URL
    field.

    Security:
    - URLs are validated (HTTPS, no private IPs, Slack prefix) before
      encryption.  Invalid URLs return HTTP 422.
    - Webhook URLs are NEVER logged in full.
    - Audit event ``notification_settings_updated`` is recorded (without URLs).
    """
    try:
        workspace_service.require_role(
            workspace_id, current_user.id, "admin", db
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    from app.services.notification_service import WebhookURLError

    try:
        row = notification_service.update_notification_settings(
            workspace_id=workspace_id,
            actor_user_id=current_user.id,
            slack_enabled=body.slack_enabled,
            slack_webhook_url=body.slack_webhook_url,
            webhook_enabled=body.webhook_enabled,
            webhook_url=body.webhook_url,
            notify_on_risk_level=body.notify_on_risk_level,
            db=db,
        )
    except WebhookURLError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Audit log — safe metadata only (no URLs).
    workspace_service.log_audit_event(
        workspace_id=workspace_id,
        actor_user_id=current_user.id,
        event_type="notification_settings_updated",
        db=db,
        target_type="notification_settings",
        target_id=str(row.id),
        metadata={
            "slack_enabled": row.slack_enabled,
            "webhook_enabled": row.webhook_enabled,
            "notify_on_risk_level": row.notify_on_risk_level,
        },
    )
    db.commit()

    data = notification_service.build_settings_response(row)
    return NotificationSettingsResponse(**data)


@router.post(
    "/{workspace_id}/notification-settings/test",
    response_model=TestNotificationResponse,
)
def test_notification(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TestNotificationResponse:
    """Send a test notification to all enabled channels.

    Requires owner or admin role.  Returns which channels received the test
    message and any error details.

    If no channels are configured/enabled, both ``slack_sent`` and
    ``webhook_sent`` will be False — this is not an error.
    """
    try:
        workspace_service.require_role(
            workspace_id, current_user.id, "admin", db
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    result = notification_service.send_test_notification(workspace_id, db)
    return TestNotificationResponse(
        slack_sent=result["slack_sent"],
        webhook_sent=result["webhook_sent"],
        error=result.get("error"),
    )


# ── Slack App install flow (M58.5) ────────────────────────────────────────────


@router.get(
    "/{workspace_id}/notifications/slack/install-url",
    response_model=SlackInstallUrlResponse,
)
def get_slack_install_url(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SlackInstallUrlResponse:
    """Return a signed Slack OAuth install URL.

    Requires owner or admin role.  Returns HTTP 503 if the server is not
    configured with Slack App credentials (SLACK_CLIENT_ID / SLACK_CLIENT_SECRET).

    The returned ``state`` token is HMAC-signed and expires in 10 minutes.
    The frontend must store it for CSRF verification in the callback flow.
    """
    try:
        workspace_service.require_role(
            workspace_id, current_user.id, "admin", db
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    from app.config import settings as _settings
    if not _settings.is_slack_app_configured:
        raise HTTPException(
            status_code=503,
            detail=(
                "Slack App is not configured on this server. "
                "Set SLACK_CLIENT_ID, SLACK_CLIENT_SECRET, and SLACK_APP_STATE_SECRET."
            ),
        )

    try:
        from app.services.slack_service import build_install_url
        result = build_install_url(
            user_id=str(current_user.id),
            workspace_id=str(workspace_id),
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return SlackInstallUrlResponse(
        install_url=result["install_url"],
        state=result["state"],
    )


@router.get(
    "/{workspace_id}/notifications/slack/channels",
    response_model=SlackChannelsListResponse,
)
def list_slack_channels(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SlackChannelsListResponse:
    """List Slack channels accessible to the installed bot.

    Requires owner or admin role.  Returns HTTP 422 if no Slack App
    installation is found for this workspace.
    """
    try:
        workspace_service.require_role(
            workspace_id, current_user.id, "admin", db
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    try:
        from app.services.slack_service import list_channels
        channels = list_channels(workspace_id, db)
    except RuntimeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to reach Slack API: {type(exc).__name__}",
        ) from exc

    return SlackChannelsListResponse(
        channels=[
            SlackChannelResponse(
                id=ch["id"],
                name=ch["name"],
                is_private=ch["is_private"],
                is_member=ch["is_member"],
            )
            for ch in channels
        ]
    )


@router.put(
    "/{workspace_id}/notifications/slack/channel",
    response_model=NotificationSettingsResponse,
)
def update_slack_channel(
    workspace_id: UUID4,
    body: SlackChannelUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NotificationSettingsResponse:
    """Select a Slack channel for alert delivery.

    Requires owner or admin role.  Returns HTTP 422 if no Slack App
    installation is found.

    Audit note: channel ID and name are recorded in the audit log.
    """
    try:
        workspace_service.require_role(
            workspace_id, current_user.id, "admin", db
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    try:
        from app.services.slack_service import update_channel
        row = update_channel(
            workspace_id=workspace_id,
            channel_id=body.channel_id,
            channel_name=body.channel_name,
            db=db,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    workspace_service.log_audit_event(
        workspace_id=workspace_id,
        actor_user_id=current_user.id,
        event_type="slack_app_channel_updated",
        db=db,
        target_type="notification_settings",
        target_id=str(row.id),
        metadata={
            "slack_channel_id": body.channel_id,
            "slack_channel_name": body.channel_name,
        },
    )
    db.commit()

    data = notification_service.build_settings_response(row)
    return NotificationSettingsResponse(**data)


@router.post(
    "/{workspace_id}/notifications/slack/test",
    response_model=TestNotificationResponse,
)
def test_slack_app(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TestNotificationResponse:
    """Send a test message via the installed Slack App bot.

    Requires owner or admin role.  Returns HTTP 422 if no installation or
    channel is configured.
    """
    try:
        workspace_service.require_role(
            workspace_id, current_user.id, "admin", db
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    try:
        from app.services.slack_service import send_test
        send_test(workspace_id, db)
        db.commit()
        return TestNotificationResponse(slack_sent=True, webhook_sent=False, error=None)
    except RuntimeError as exc:
        db.rollback()
        return TestNotificationResponse(
            slack_sent=False,
            webhook_sent=False,
            error=str(exc),
        )
    except Exception as exc:
        db.rollback()
        return TestNotificationResponse(
            slack_sent=False,
            webhook_sent=False,
            error=f"Unexpected error: {type(exc).__name__}",
        )


@router.delete(
    "/{workspace_id}/notifications/slack",
    status_code=204,
    response_class=Response,
)
def disconnect_slack_app(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Remove the Slack App installation from a workspace.

    Requires owner or admin role.  Clears all Slack App columns and
    disables the channel.  Does NOT revoke the bot token at Slack.

    The existing Slack incoming-webhook configuration (if any) is
    unaffected — it remains as a fallback.
    """
    try:
        workspace_service.require_role(
            workspace_id, current_user.id, "admin", db
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    from app.services.slack_service import disconnect
    row = disconnect(workspace_id, db)

    workspace_service.log_audit_event(
        workspace_id=workspace_id,
        actor_user_id=current_user.id,
        event_type="slack_app_disconnected",
        db=db,
        target_type="notification_settings",
        target_id=str(row.id),
        metadata={},
    )
    db.commit()
    return Response(status_code=204)


# ── M58.7 — Web Push / PWA notifications ─────────────────────────────────────


@router.get(
    "/{workspace_id}/notifications/push/public-key",
    response_model=PushPublicKeyResponse,
    summary="Get VAPID public key for Web Push subscriptions",
)
def get_push_public_key(
    workspace_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PushPublicKeyResponse:
    """Return the VAPID public key needed to subscribe to push notifications.

    This is the ONLY VAPID value ever returned in API responses.
    The VAPID private key is never exposed.
    Any authenticated workspace member can call this.
    """
    try:
        workspace_service.require_role(workspace_id, current_user.id, "member", db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    from app.services.push_notification_service import get_vapid_public_key
    pub_key = get_vapid_public_key()
    return PushPublicKeyResponse(
        vapid_public_key=pub_key,
        configured=bool(pub_key),
    )


@router.post(
    "/{workspace_id}/notifications/push/subscriptions",
    response_model=PushSubscriptionResponse,
    status_code=201,
    summary="Register a browser push subscription",
)
def create_push_subscription(
    workspace_id: uuid.UUID,
    body: PushSubscribeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PushSubscriptionResponse:
    """Store a Web Push API subscription for this browser/device.

    The subscription endpoint and keys are encrypted before storage.
    They are NEVER returned in any API response.

    Requires workspace member role.
    """
    try:
        workspace_service.require_role(workspace_id, current_user.id, "member", db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    # Detect browser from user agent (best-effort, not required).
    from app.services.push_notification_service import subscribe as push_subscribe

    sub = push_subscribe(
        workspace_id=workspace_id,
        user_id=current_user.id,
        endpoint=body.subscription.endpoint,
        p256dh=body.subscription.keys.p256dh,
        auth=body.subscription.keys.auth,
        device_label=body.device_label,
        min_risk_level=body.min_risk_level,
        user_agent=None,
        browser_name=None,
        db=db,
    )
    db.commit()
    db.refresh(sub)
    return PushSubscriptionResponse.model_validate(sub)


@router.get(
    "/{workspace_id}/notifications/push/subscriptions",
    response_model=PushSubscriptionListResponse,
    summary="List push subscriptions for this workspace",
)
def list_push_subscriptions(
    workspace_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PushSubscriptionListResponse:
    """List all push subscriptions (safe metadata only — no secrets).

    Requires workspace member role.
    """
    try:
        workspace_service.require_role(workspace_id, current_user.id, "member", db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    from app.services.push_notification_service import list_subscriptions
    subs = list_subscriptions(workspace_id, db)
    return PushSubscriptionListResponse(
        subscriptions=[PushSubscriptionResponse.model_validate(s) for s in subs]
    )


@router.delete(
    "/{workspace_id}/notifications/push/subscriptions/{subscription_id}",
    status_code=204,
    summary="Disable a push subscription",
)
def delete_push_subscription(
    workspace_id: uuid.UUID,
    subscription_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    """Disable a browser push subscription.

    The subscription row is kept for audit purposes (enabled=False).
    Requires workspace member role.
    """
    try:
        workspace_service.require_role(workspace_id, current_user.id, "member", db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    from app.services.push_notification_service import delete_subscription
    found = delete_subscription(subscription_id, workspace_id, db)
    if not found:
        raise HTTPException(status_code=404, detail="Push subscription not found.")
    db.commit()
    return Response(status_code=204)


@router.post(
    "/{workspace_id}/notifications/push/test",
    response_model=PushTestResponse,
    summary="Send test push notification to all enabled subscriptions",
)
def test_push_notification(
    workspace_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PushTestResponse:
    """Send a test Web Push notification to all enabled subscriptions.

    Requires workspace admin or owner role (same as other test endpoints).
    """
    try:
        workspace_service.require_role(workspace_id, current_user.id, "admin", db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    from app.services.push_notification_service import send_test_push
    result = send_test_push(workspace_id, db)
    db.commit()
    return PushTestResponse(
        sent=result["sent"],
        total_subscriptions=result["total_subscriptions"],
        error=result.get("error"),
    )


# ── Policy engine endpoints (M58.14) ─────────────────────────────────────────


@router.get("/{workspace_id}/policies", response_model=PolicyListResponse)
def list_workspace_policies(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PolicyListResponse:
    """Return the full built-in policy catalog with each policy's enabled state.

    Any workspace member may read policies.  Policies not explicitly overridden
    in the database are returned with ``enabled=True`` (default).
    """
    try:
        workspace_service.require_role(workspace_id, current_user.id, "member", db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return policy_engine_service.get_workspace_policies(workspace_id, db)


@router.put(
    "/{workspace_id}/policies/{policy_key}",
    response_model=WorkspacePolicyResponse,
)
def update_workspace_policy(
    workspace_id: UUID4,
    policy_key: str,
    body: PolicyUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkspacePolicyResponse:
    """Enable or disable a built-in policy for this workspace.

    Only workspace admins (role ``admin``) may change policy settings.
    Returns the updated policy with its full catalog metadata merged in.
    """
    try:
        workspace_service.require_role(workspace_id, current_user.id, "admin", db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    try:
        result = policy_engine_service.set_policy_enabled(
            workspace_id=workspace_id,
            policy_key=policy_key,
            enabled=body.enabled,
            db=db,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    db.commit()
    return result


# ── Weekly digest endpoints (M58.15) ─────────────────────────────────────────


@router.get("/{workspace_id}/weekly-digest/preview", response_model=WeeklyDigest)
def preview_weekly_digest(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WeeklyDigest:
    """Return a live digest preview for the last 7 days.

    Any workspace member may request a preview.  Computed on demand — nothing
    persisted.  Useful for checking what the next scheduled digest will look like.
    """
    try:
        workspace_service.require_role(workspace_id, current_user.id, "member", db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return weekly_digest_service.compute_digest(workspace_id, db)


@router.get(
    "/{workspace_id}/weekly-digest/settings",
    response_model=WeeklyDigestSettings,
)
def get_weekly_digest_settings(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WeeklyDigestSettings:
    """Return the current weekly digest schedule settings for this workspace."""
    try:
        workspace_service.require_role(workspace_id, current_user.id, "member", db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return weekly_digest_service.get_digest_settings(workspace_id, db)


@router.put(
    "/{workspace_id}/weekly-digest/settings",
    response_model=WeeklyDigestSettings,
)
def update_weekly_digest_settings(
    workspace_id: UUID4,
    body: WeeklyDigestSettingsUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WeeklyDigestSettings:
    """Update the weekly digest schedule settings.

    Only workspace admins may update digest settings.
    """
    try:
        workspace_service.require_role(workspace_id, current_user.id, "admin", db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    try:
        result = weekly_digest_service.update_digest_settings(workspace_id, body, db)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    db.commit()
    return result


@router.post(
    "/{workspace_id}/weekly-digest/test",
    response_model=WeeklyDigestTestResponse,
)
def test_weekly_digest(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WeeklyDigestTestResponse:
    """Send a test digest to the requesting user's email.

    If email is not configured, returns the rendered digest body so you can
    preview the content without actually sending.  Admins only.
    """
    try:
        workspace_service.require_role(workspace_id, current_user.id, "admin", db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return weekly_digest_service.test_send_digest(workspace_id, current_user.id, db)
