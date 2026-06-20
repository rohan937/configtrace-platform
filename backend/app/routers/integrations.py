"""Integration routes — M30: Integration Detail + Sync History.

Routes
------
POST   /integrations                        — create a new integration
GET    /integrations                        — list non-deleted integrations
GET    /integrations/{id}                   — single integration detail
PATCH  /integrations/{id}                   — rename / update interval / pause / resume
DELETE /integrations/{id}                   — soft-delete (sets status='deleted')
POST   /integrations/{id}/reconnect         — token-only credential update
GET    /integrations/{id}/sync-runs         — last N sync runs for this integration

Credentials (api_token, zone_id, github_token, etc.) and their encrypted forms
are **never** present in any response shape.  This is enforced at the schema
level.

Supported providers
-------------------
``cloudflare``  — Credentials: ``api_token`` + ``zone_id``
``github``      — Credentials: ``github_token`` + ``repo_owner`` + ``repo_name``
``stripe``      — Credentials: ``stripe_api_key``
"""

from __future__ import annotations

import uuid

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.connectors.exceptions import AuthenticationError, ConnectorError, NetworkError
from app.core.auth import get_current_user
from app.core.encryption import EncryptionKeyError
from app.database import get_db
from app.models.integration import Integration
from app.models.user import User
from app.schemas.integration import (
    IntegrationCreateRequest,
    IntegrationListResponse,
    IntegrationReconnectRequest,
    IntegrationResponse,
    IntegrationUpdateRequest,
)
from app.schemas.sync import SyncRunListResponse, SyncRunResponse
from app.services import integration_service
from app.services.settings_service import get_or_create_settings
from pydantic import UUID4

router = APIRouter(prefix="/integrations", tags=["integrations"])


# ── Response builder ──────────────────────────────────────────────────────────

def _build_response(integration: Integration, db: Session) -> IntegrationResponse:
    """Build an IntegrationResponse including last-sync status from SyncRun.

    ``last_sync_status`` and ``last_sync_error`` are not ORM attributes —
    they are populated by querying the most recent SyncRun for this
    integration.  This helper centralises that enrichment so every route
    returns a consistent shape.

    ``connection_method`` is derived from the first resource's metadata
    without credential decryption — safe to expose.

    ``consecutive_failure_count`` comes from the Integration column (M32).
    ``needs_attention`` is derived: True when consecutive_failure_count >= 3.

    Performance note: this does one extra SELECT per integration.  At M29
    scale (single user, small integration count) this is acceptable.  If
    the list endpoint becomes a bottleneck, batch the SyncRun query.
    """
    from app.core.failure_classifier import NEEDS_ATTENTION_THRESHOLD

    last_status, last_error, last_failure_category = (
        integration_service.get_latest_sync_run_summary(integration.id, db)
    )
    connection_method = integration_service.get_connection_method(integration)
    consecutive = integration.consecutive_failure_count or 0
    return IntegrationResponse(
        id=integration.id,
        provider=integration.provider,
        display_name=integration.display_name,
        status=integration.status,
        last_synced_at=integration.last_synced_at,
        created_at=integration.created_at,
        resource_count=integration.resource_count,
        sync_interval_minutes=integration.sync_interval_minutes,
        last_sync_status=last_status,
        last_sync_error=last_error,
        # M59.15: stable failure category from the M32 classifier — lets the
        # frontend pick a display status (Active / Needs attention / Degraded)
        # without string-matching on the free-text error message.
        last_sync_failure_category=last_failure_category,
        connection_method=connection_method,
        consecutive_failure_count=consecutive,
        needs_attention=consecutive >= NEEDS_ATTENTION_THRESHOLD,
        # M57.6: expose scheduled sync flag and last failure timestamp so the
        # frontend can display honest monitoring cadence and stale-sync warnings.
        scheduled_sync_enabled=bool(integration.scheduled_sync_enabled),
        last_failure_at=integration.last_failure_at,
    )


# ── Credential extraction helper (unchanged from M28) ─────────────────────────

def _build_credentials(body: IntegrationCreateRequest) -> dict:
    """Extract the provider-specific credentials dict from the request body.

    Credentials are never stored in plaintext — this dict is passed to the
    connector for validation and to the encryption layer for storage.

    Cloudflare:  ``{"api_token": str, "zone_id": str}``
    GitHub:      ``{"github_token": str, "repo_owner": str, "repo_name": str}``
    Vercel:      ``{"vercel_token": str, "vercel_project_id": str}``
    Stripe:      ``{"stripe_api_key": str}``

    SECURITY (Stripe): ``stripe_api_key`` is passed to the connector for
    validation and to the encryption layer for storage.  It is NEVER logged,
    NEVER returned to the frontend, and NEVER stored in plaintext.
    """
    if body.provider == "cloudflare":
        return {
            "api_token": body.api_token,
            "zone_id":   body.zone_id,
        }
    elif body.provider == "github":
        return {
            "github_token": body.github_token,
            "repo_owner":   body.repo_owner,
            "repo_name":    body.repo_name,
        }
    elif body.provider == "vercel":
        return {
            "vercel_token":      body.vercel_token,
            "vercel_project_id": body.vercel_project_id,
        }
    elif body.provider == "stripe":
        # SECURITY: stripe_api_key is never logged here or in the service.
        return {
            "stripe_api_key": body.stripe_api_key,
        }
    elif body.provider == "aws":
        # SECURITY: aws_secret_access_key is never logged here or in the service.
        return {
            "aws_access_key_id":     body.aws_access_key_id,
            "aws_secret_access_key": body.aws_secret_access_key,
            "aws_default_region":    body.aws_default_region or "us-east-1",
            "aws_selected_regions":  body.aws_selected_regions or [body.aws_default_region or "us-east-1"],
        }
    elif body.provider == "firebase":
        # SECURITY: The service account private_key is stored encrypted only.
        # It is NEVER logged, NEVER returned to the frontend, and NEVER stored
        # in plaintext.  The service_account_json string is parsed here and the
        # private_key is embedded in the encrypted credentials dict.
        return {
            "service_account_json": body.firebase_service_account_json,
        }
    elif body.provider == "supabase":
        # SECURITY: supabase_access_token is stored encrypted only.
        # It is NEVER logged, NEVER returned to the frontend, and NEVER stored
        # in plaintext.
        return {
            "access_token": body.supabase_access_token,
            "project_ref": body.supabase_project_ref,
        }
    elif body.provider == "shopify":
        # SECURITY: shopify_access_token is stored encrypted only.
        # It is NEVER logged, NEVER returned to the frontend, and NEVER stored
        # in plaintext.
        # shop_domain is normalised (lowercase, strip https://) in the connector.
        return {
            "shop_domain": body.shopify_shop_domain,
            "shopify_access_token": body.shopify_access_token,
        }
    # ── M82-pre.1 — connectable security providers ────────────────────────────
    # SECURITY: credentials are passed through to encrypt_credentials() and
    # NEVER logged, NEVER returned to the frontend, and NEVER stored in
    # plaintext. The dict keys here match the connector's expected
    # credentials-dict shape (without the front-end's provider prefix).
    elif body.provider == "azure":
        # SECURITY: azure_client_secret is never logged here or in the service.
        return {
            "tenant_id":       body.azure_tenant_id,
            "client_id":       body.azure_client_id,
            "client_secret":   body.azure_client_secret,
            "subscription_id": body.azure_subscription_id,
        }
    elif body.provider == "google_cloud":
        # SECURITY: the service-account JSON embeds a private_key. The full
        # JSON string is stored encrypted only and NEVER logged or returned.
        return {
            "project_id":           body.google_cloud_project_id,
            "service_account_json": body.google_cloud_service_account_json,
        }
    elif body.provider == "twilio":
        # SECURITY: twilio_auth_token is never logged here or in the service.
        return {
            "account_sid": body.twilio_account_sid,
            "auth_token":  body.twilio_auth_token,
        }
    elif body.provider == "sendgrid":
        # SECURITY: sendgrid_api_key is never logged here or in the service.
        return {
            "api_key": body.sendgrid_api_key,
        }
    elif body.provider == "auth0":
        # SECURITY: auth0_client_secret and auth0_management_api_token are
        # never logged here or in the service. Only present keys are included
        # so the connector can pick the appropriate auth mode.
        creds: dict = {"domain": body.auth0_domain}
        if body.auth0_client_id:
            creds["client_id"] = body.auth0_client_id
        if body.auth0_client_secret:
            creds["client_secret"] = body.auth0_client_secret
        if body.auth0_management_api_token:
            creds["management_api_token"] = body.auth0_management_api_token
        return creds
    # ── M82A — Datadog drift provider ────────────────────────────────────────
    elif body.provider == "datadog":
        # SECURITY: datadog_api_key and datadog_application_key are never
        # logged here or in the service. site is not a secret.
        return {
            "api_key":         body.datadog_api_key,
            "application_key": body.datadog_application_key,
            "site":            body.datadog_site or "datadoghq.com",
        }
    # ── M83A — Clerk drift provider ──────────────────────────────────────────
    elif body.provider == "clerk":
        # SECURITY: clerk_secret_key is NEVER logged here or in the service.
        creds: dict = {"secret_key": body.clerk_secret_key}
        if body.clerk_frontend_api_url:
            creds["frontend_api_url"] = body.clerk_frontend_api_url
        return creds
    # ── M84A — PagerDuty drift provider ──────────────────────────────────────
    elif body.provider == "pagerduty":
        # SECURITY: pagerduty_api_token is NEVER logged here or in the service.
        return {"api_token": body.pagerduty_api_token}
    # ── M85A — Linear drift provider ─────────────────────────────────────────
    elif body.provider == "linear":
        # SECURITY: linear_api_key is NEVER logged here or in the service.
        return {"api_key": body.linear_api_key}
    # ── M86A — Jira drift provider ────────────────────────────────────────────
    elif body.provider == "jira":
        # SECURITY: jira_site_url, jira_email, and jira_api_token are NEVER logged here.
        return {
            "site_url": body.jira_site_url,
            "email": body.jira_email,
            "api_token": body.jira_api_token,
        }
    # ── M87A — GitLab drift provider ─────────────────────────────────────────
    elif body.provider == "gitlab":
        # SECURITY: gitlab_access_token is NEVER logged here or in the service.
        creds: dict = {"access_token": body.gitlab_access_token}
        if body.gitlab_base_url:
            creds["base_url"] = body.gitlab_base_url
        return creds
    return {}


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("", response_model=IntegrationResponse, status_code=201)
def create_integration(
    body: IntegrationCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IntegrationResponse:
    """Create and validate a new provider integration.

    Validates the provider credentials against the live API before writing
    anything to the database.  Returns HTTP 400 if credentials are invalid,
    expired, or lack the required permissions.

    Credential fields in the request body are **not** stored in plaintext.
    Only the AES-256-GCM ciphertext and IV are persisted.  The response
    never includes credentials in any form.
    """
    credentials = _build_credentials(body)

    # Apply the user's sync defaults to the new integration so the setting
    # actually affects behavior (not just persisted state).
    user_settings = get_or_create_settings(current_user.id, db)

    # Resolve workspace: use body.workspace_id if provided, else user's default.
    from app.services.workspace_service import (
        get_membership,
        get_or_create_default_workspace,
    )

    _INTEGRATION_ALLOWED_ROLES = {"owner", "admin"}

    target_workspace_id = getattr(body, "workspace_id", None)
    if target_workspace_id is not None:
        membership = get_membership(target_workspace_id, current_user.id, db)
        if membership is None:
            raise HTTPException(
                status_code=403, detail="Not a member of this workspace."
            )
        # Members are view-only — only admins and owners can add integrations.
        if membership.role not in _INTEGRATION_ALLOWED_ROLES:
            raise HTTPException(
                status_code=403,
                detail="Only workspace owners and admins can add integrations.",
            )
        resolved_workspace_id = target_workspace_id
    else:
        default_ws = get_or_create_default_workspace(
            current_user.id, current_user.display_name, db
        )
        resolved_workspace_id = default_ws.id

    # M52: Enforce integration limit before attempting to create.
    # assert_can_create_integration raises HTTP 402 if the plan limit is reached.
    from app.services.billing_service import assert_can_create_integration
    assert_can_create_integration(resolved_workspace_id, db)

    try:
        integration = integration_service.create_integration(
            user_id=current_user.id,
            provider=body.provider,
            display_name=body.display_name,
            credentials=credentials,
            scheduled_sync_enabled=user_settings.default_sync_enabled,
            sync_interval_minutes=user_settings.default_sync_interval_minutes,
            workspace_id=resolved_workspace_id,
            db=db,
        )
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Authentication failed: {exc}",
        ) from exc
    except ConnectorError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Provider validation error: {exc}",
        ) from exc
    except NetworkError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach provider API: {exc}",
        ) from exc
    except EncryptionKeyError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Server misconfiguration — ENCRYPTION_KEY not set correctly: {exc}",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Audit: integration_created (fire-and-forget in separate transaction).
    if resolved_workspace_id is not None:
        try:
            from app.services.workspace_service import log_audit_event
            log_audit_event(
                resolved_workspace_id,
                current_user.id,
                "integration_created",
                db,
                target_type="integration",
                target_id=str(integration.id),
                target_display_name=integration.display_name,
                metadata={"provider": integration.provider},
            )
            db.commit()
        except Exception:  # noqa: BLE001
            pass  # Audit failure must never break the main flow.

    return _build_response(integration, db)


@router.get("", response_model=IntegrationListResponse)
def list_integrations(
    workspace_id: Optional[uuid.UUID] = Query(
        None,
        description=(
            "M50: filter to a specific workspace. "
            "When provided, user must be a member of that workspace."
        ),
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IntegrationListResponse:
    """List all non-deleted integrations belonging to the authenticated user.

    When ``workspace_id`` is provided, results are scoped to that workspace
    and the caller must be a member.  Without ``workspace_id``, all integrations
    owned by the user are returned (backward-compatible behaviour).

    Soft-deleted integrations (status='deleted') are excluded.  Their
    historical changes remain accessible via GET /changes.
    """
    if workspace_id is not None:
        # Workspace-scoped path: verify membership first.
        from app.services.workspace_service import get_membership
        membership = get_membership(workspace_id, current_user.id, db)
        if membership is None:
            raise HTTPException(
                status_code=403,
                detail="Not a member of this workspace.",
            )
        rows = integration_service.get_integrations_by_workspace(
            workspace_id=workspace_id, db=db
        )
    else:
        rows = integration_service.get_integrations(user_id=current_user.id, db=db)
    return IntegrationListResponse(
        integrations=[_build_response(r, db) for r in rows],
        total=len(rows),
    )


@router.get("/{integration_id}", response_model=IntegrationResponse)
def get_integration(
    integration_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IntegrationResponse:
    """Return detail for a single non-deleted integration.

    Returns the same safe ``IntegrationResponse`` shape as the list endpoint.
    Deleted integrations return HTTP 404.  A missing integration and an
    integration belonging to another user both return HTTP 404 to avoid
    leaking object existence across user boundaries.

    Credentials (api_token, zone_id, github_token, encrypted bytes) are never
    included in the response — this is enforced at the schema level.
    """
    # Allow owner OR workspace member to view (M51 workspace scoping).
    integration = integration_service.get_integration_for_viewer(
        integration_id=integration_id,
        actor_user_id=current_user.id,
        db=db,
    )
    if integration is None:
        raise HTTPException(
            status_code=404,
            detail="Integration not found or does not belong to this user.",
        )
    return _build_response(integration, db)


@router.get("/{integration_id}/sync-runs", response_model=SyncRunListResponse)
def get_integration_sync_runs(
    integration_id: UUID4,
    page: int = Query(1, ge=1, description="Page number (1-indexed)."),
    page_size: int = Query(25, ge=1, le=100, description="Rows per page (1–100)."),
    status: str | None = Query(
        None,
        description="Filter by status: pending | running | completed | failed.",
    ),
    trigger: str | None = Query(
        None,
        description="Filter by trigger: manual | scheduled.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SyncRunListResponse:
    """Return paginated sync runs for a single integration.

    Ownership is verified before querying runs.  Deleted integrations return
    HTTP 404.  The response includes ``total`` (filtered count), ``page``,
    ``page_size``, and ``total_pages`` for the frontend paginator.

    Optional filters:
    - ``status``:  restrict to a specific run status.
    - ``trigger``: restrict to ``'manual'`` or ``'scheduled'`` runs.

    Sync run records do not contain credentials.
    """
    # Verify ownership and non-deleted status before querying runs.
    integration = integration_service.get_integration_by_id(
        integration_id=integration_id,
        user_id=current_user.id,
        db=db,
    )
    if integration is None:
        raise HTTPException(
            status_code=404,
            detail="Integration not found or does not belong to this user.",
        )

    # Validate filter values to return clear errors instead of empty results.
    _VALID_STATUSES = {"pending", "running", "completed", "failed"}
    _VALID_TRIGGERS = {"manual", "scheduled"}
    if status is not None and status not in _VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status filter {status!r}. "
                   f"Allowed: {sorted(_VALID_STATUSES)}.",
        )
    if trigger is not None and trigger not in _VALID_TRIGGERS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid trigger filter {trigger!r}. "
                   f"Allowed: {sorted(_VALID_TRIGGERS)}.",
        )

    runs, total = integration_service.get_recent_sync_runs(
        integration_id=integration_id,
        user_id=current_user.id,
        page=page,
        page_size=page_size,
        status_filter=status,
        trigger_filter=trigger,
        db=db,
    )
    total_pages = max(1, -(-total // page_size))  # ceiling division
    return SyncRunListResponse(
        sync_runs=[SyncRunResponse.model_validate(r) for r in runs],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.patch("/{integration_id}", response_model=IntegrationResponse)
def update_integration(
    integration_id: UUID4,
    body: IntegrationUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IntegrationResponse:
    """Update an integration's display name, sync interval, or status.

    All body fields are optional — only the provided fields are written.
    At least one field must be present (enforced by the schema validator).

    Status transitions via this endpoint:
    - ``'active'``  → ``'paused'``  (disable scheduled sync + block Sync Now)
    - ``'paused'``  → ``'active'``  (re-enable)

    To soft-delete an integration use ``DELETE /integrations/{id}`` instead.
    Setting ``status='deleted'`` via PATCH is rejected with HTTP 422.

    Returns HTTP 404 if the integration does not exist, is already deleted,
    or belongs to a different user (no object-existence leak).
    """
    # Allow owner OR workspace admin+ to update (M51 workspace scoping).
    managed = integration_service.get_integration_for_manager(
        integration_id=integration_id,
        actor_user_id=current_user.id,
        db=db,
    )
    if managed is None:
        raise HTTPException(
            status_code=404,
            detail="Integration not found or does not belong to this user.",
        )

    try:
        integration = integration_service.update_integration(
            integration_id=integration_id,
            user_id=managed.user_id,  # use integration owner's ID for the DB write
            display_name=body.display_name,
            sync_interval_minutes=body.sync_interval_minutes,
            status=body.status,
            db=db,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return _build_response(integration, db)


@router.delete("/{integration_id}", status_code=204)
def delete_integration(
    integration_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Soft-delete an integration (sets ``status='deleted'``).

    Soft-delete behaviour:
    - The integration no longer appears in ``GET /integrations``.
    - Scheduled syncs are skipped for deleted integrations.
    - Manual ``POST /syncs`` for a deleted integration returns HTTP 404.
    - Historical changes, resources, and snapshots are **preserved** — they
      remain visible in the timeline (``GET /changes``).

    This operation is idempotent — deleting an already-deleted integration
    returns 204 without error.

    Returns HTTP 404 if the integration never existed or belongs to a
    different user.
    """
    # Allow owner OR workspace admin+ to delete (M51 workspace scoping).
    managed = integration_service.get_integration_for_manager(
        integration_id=integration_id,
        actor_user_id=current_user.id,
        db=db,
    )
    if managed is None:
        raise HTTPException(
            status_code=404,
            detail="Integration not found or does not belong to this user.",
        )

    # Capture display name before delete (status changes; name stays).
    _integration_display_name = managed.display_name
    _integration_workspace_id = managed.workspace_id

    try:
        integration_service.soft_delete_integration(
            integration_id=integration_id,
            user_id=managed.user_id,  # use integration owner's ID for the DB write
            db=db,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    # Audit: integration_deleted.
    if _integration_workspace_id is not None:
        try:
            from app.services.workspace_service import log_audit_event
            log_audit_event(
                _integration_workspace_id,
                current_user.id,
                "integration_deleted",
                db,
                target_type="integration",
                target_id=str(integration_id),
                target_display_name=_integration_display_name,
            )
            db.commit()
        except Exception:  # noqa: BLE001
            pass  # Audit failure must never break the main flow.

    return Response(status_code=204)


@router.post("/{integration_id}/reconnect", response_model=IntegrationResponse)
def reconnect_integration(
    integration_id: UUID4,
    body: IntegrationReconnectRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IntegrationResponse:
    """Update the API token for an existing integration (token-only reconnect).

    The integration's underlying resource (Cloudflare zone_id or GitHub
    owner/repo) cannot be changed via this endpoint.  Only the token is
    replaced.

    The new token is validated against the live provider API before the
    database row is updated.  If validation fails, the existing credentials
    remain unchanged.

    If the integration's status was 'error' (e.g. from a previous credential
    failure), it is reset to 'active' on success.

    Provider-specific field requirements:
    - Cloudflare: provide ``api_token``
    - GitHub: provide ``github_token``

    Returns HTTP 400 if the token is invalid, expired, or lacks required
    permissions.  Returns HTTP 404 if the integration does not exist, is
    deleted, or belongs to a different user.
    """
    # Fetch integration first to determine provider (before reading token).
    integration = integration_service.get_integration_by_id(
        integration_id=integration_id,
        user_id=current_user.id,
        db=db,
    )
    if integration is None:
        raise HTTPException(
            status_code=404,
            detail="Integration not found or does not belong to this user.",
        )

    # Extract the correct token for this integration's provider.
    if integration.provider == "cloudflare":
        if not body.api_token:
            raise HTTPException(
                status_code=422,
                detail="api_token is required for Cloudflare integrations.",
            )
        new_token = body.api_token
    elif integration.provider == "github":
        # M31: GitHub App integrations cannot be reconnected via PAT.
        # The user must re-install the GitHub App through the App install flow.
        conn_method = integration_service.get_connection_method(integration)
        if conn_method == "github_app":
            raise HTTPException(
                status_code=422,
                detail=(
                    "This integration uses GitHub App authentication. "
                    "To update credentials, use the 'Re-install GitHub App' "
                    "option — there is no token to update."
                ),
            )
        if not body.github_token:
            raise HTTPException(
                status_code=422,
                detail="github_token is required for GitHub integrations.",
            )
        new_token = body.github_token
    elif integration.provider == "vercel":
        if not body.vercel_token:
            raise HTTPException(
                status_code=422,
                detail="vercel_token is required for Vercel integrations.",
            )
        new_token = body.vercel_token
    elif integration.provider == "stripe":
        if not body.stripe_api_key:
            raise HTTPException(
                status_code=422,
                detail="stripe_api_key is required for Stripe integrations.",
            )
        new_token = body.stripe_api_key
    elif integration.provider == "aws":
        if not body.aws_access_key_id:
            raise HTTPException(
                status_code=422,
                detail="aws_access_key_id is required for AWS integrations.",
            )
        if not body.aws_secret_access_key:
            raise HTTPException(
                status_code=422,
                detail="aws_secret_access_key is required for AWS integrations.",
            )
        try:
            integration = integration_service.reconnect_credentials_aws(
                integration_id=integration_id,
                user_id=current_user.id,
                new_access_key_id=body.aws_access_key_id,
                new_secret_access_key=body.aws_secret_access_key,
                db=db,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AuthenticationError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Authentication failed: {exc}",
            ) from exc
        except ConnectorError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Provider validation error: {exc}",
            ) from exc
        except NetworkError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Could not reach AWS: {exc}",
            ) from exc
        return _build_response(integration, db)
    elif integration.provider == "firebase":
        if not body.firebase_service_account_json:
            raise HTTPException(
                status_code=422,
                detail="firebase_service_account_json is required for Firebase integrations.",
            )
        try:
            integration = integration_service.reconnect_credentials_firebase(
                integration_id=integration_id,
                user_id=current_user.id,
                new_service_account_json=body.firebase_service_account_json,
                db=db,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AuthenticationError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Authentication failed: {exc}",
            ) from exc
        except ConnectorError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Provider validation error: {exc}",
            ) from exc
        except NetworkError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Could not reach Firebase: {exc}",
            ) from exc
        return _build_response(integration, db)
    elif integration.provider == "supabase":
        if not body.supabase_access_token:
            raise HTTPException(
                status_code=422,
                detail="supabase_access_token is required for Supabase integrations.",
            )
        try:
            integration = integration_service.reconnect_credentials_supabase(
                integration_id=integration_id,
                user_id=current_user.id,
                new_access_token=body.supabase_access_token,
                db=db,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AuthenticationError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Authentication failed: {exc}",
            ) from exc
        except ConnectorError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Provider validation error: {exc}",
            ) from exc
        except NetworkError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Could not reach Supabase: {exc}",
            ) from exc
        return _build_response(integration, db)
    elif integration.provider == "shopify":
        if not body.shopify_access_token:
            raise HTTPException(
                status_code=422,
                detail="shopify_access_token is required for Shopify integrations.",
            )
        try:
            integration = integration_service.reconnect_credentials_shopify(
                integration_id=integration_id,
                user_id=current_user.id,
                new_access_token=body.shopify_access_token,
                db=db,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AuthenticationError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Authentication failed: {exc}",
            ) from exc
        except ConnectorError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Provider validation error: {exc}",
            ) from exc
        except NetworkError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Could not reach Shopify: {exc}",
            ) from exc
        return _build_response(integration, db)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Reconnect is not supported for provider: {integration.provider!r}",
        )

    try:
        integration = integration_service.reconnect_credentials(
            integration_id=integration_id,
            user_id=current_user.id,
            new_token=new_token,
            db=db,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Authentication failed: {exc}",
        ) from exc
    except ConnectorError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Provider validation error: {exc}",
        ) from exc
    except NetworkError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach provider API: {exc}",
        ) from exc
    except EncryptionKeyError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Server misconfiguration — ENCRYPTION_KEY not set correctly: {exc}",
        ) from exc

    return _build_response(integration, db)
