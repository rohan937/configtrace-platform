"""Integration business logic.

Handles the full creation flow (credential validation → encryption → DB write)
and read operations.  All functions are database-session aware and never return
plaintext credentials in any form.

Supported providers
-------------------
``cloudflare``
    Creates one Resource of type ``cloudflare_dns_zone`` (keyed by Zone ID).
``github``
    Creates one Resource of type ``github_repo`` (keyed by ``"{owner}/{repo}"``).
    Enforces uniqueness: a given authenticated user cannot connect the same
    ``{owner}/{repo}`` twice.  Different users connecting the same repo is
    permitted (no cross-user uniqueness check).
``vercel``
    Creates one Resource of type ``vercel_project`` (keyed by Project ID).
    Enforces uniqueness: a given user cannot connect the same project ID twice.
``stripe``
    Creates one Resource of type ``stripe_account`` (keyed by Stripe account ID).
    Enforces uniqueness: a given user cannot connect the same Stripe account twice.
    The ``stripe_api_key`` is encrypted and never returned.  Customer PII, payment
    data, and webhook signing secrets are NEVER fetched or stored.
``aws``
    Creates one Resource of type ``aws_account`` (keyed by AWS account ID).
    Enforces uniqueness: a given user cannot connect the same AWS account twice.
    AWS credentials are encrypted and never returned.  No AWS resource data
    beyond account identity is fetched or stored.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.connectors.cloudflare import CloudflareConnector
from app.connectors.exceptions import AuthenticationError, ConnectorError, NetworkError
from app.core.encryption import EncryptionKeyError, decrypt_credentials, encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource


def create_integration(
    *,
    user_id: uuid.UUID,
    provider: str,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a new integration after validating and encrypting credentials.

    Execution order
    ---------------
    1. Provider-specific pre-checks (e.g. duplicate-repo detection for GitHub).
    2. Validate credentials against the live provider API.  Raises immediately
       on bad credentials so nothing is written to the database.
    3. Encrypt credentials with AES-256-GCM.
    4. Insert the ``Integration`` row.
    5. Insert a ``Resource`` row for the monitored target.
    6. Commit and return the refreshed ``Integration`` ORM object.

    Args:
        user_id:                UUID of the authenticated user.
        provider:               ``"cloudflare"``, ``"github"``, ``"vercel"``,
                                ``"stripe"``, ``"aws"``, or ``"firebase"``.
        display_name:           User-supplied label shown in the integrations list.
        credentials:            Provider-specific dict — see module docstring.
        scheduled_sync_enabled: Whether to enable scheduled sync immediately.
                                Defaults to False.  Callers pass the user's
                                ``default_sync_enabled`` setting so the new
                                integration inherits the user's preference.
        sync_interval_minutes:  Sync cadence for this integration (minutes).
                                None means the scheduler uses 60 min fallback.
                                Callers pass the user's ``default_sync_interval_minutes``.
        db:                     Active SQLAlchemy session.

    Returns:
        The newly persisted ``Integration`` object.

    Raises:
        ValueError:           Unsupported provider, or duplicate resource.
        AuthenticationError:  Provider returns 401/403.
        ConnectorError:       Provider returns another API error.
        NetworkError:         Transport-level failure reaching the provider.
        EncryptionKeyError:   ``ENCRYPTION_KEY`` is not configured server-side.
    """
    if provider == "cloudflare":
        return _create_cloudflare_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    elif provider == "github":
        return _create_github_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    elif provider == "vercel":
        return _create_vercel_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    elif provider == "stripe":
        return _create_stripe_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    elif provider == "aws":
        return _create_aws_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    elif provider == "firebase":
        return create_firebase_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    elif provider == "supabase":
        return create_supabase_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    # ── M82-pre.1 — credential-connect parity for completed security providers ──
    # These providers have full security arcs (drift rules, activity ingestion,
    # signals, correlations, demo cases) and connectors with tested sync paths.
    # Credentials are validated for presence at the schema level and stored
    # encrypted. Live API validation is deferred to the first sync (the
    # existing connector.validate_credentials() is called by the sync_task
    # path on demand), so create-time failures cannot leak secret values
    # through synchronous error messages.
    elif provider == "azure":
        return _create_azure_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    elif provider == "google_cloud":
        return _create_google_cloud_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    elif provider == "twilio":
        return _create_twilio_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    elif provider == "sendgrid":
        return _create_sendgrid_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    elif provider == "auth0":
        return _create_auth0_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    # ── M82A — Datadog drift provider ─────────────────────────────────────────
    elif provider == "datadog":
        return _create_datadog_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    # ── M83A — Clerk drift provider ────────────────────────────────────────────
    elif provider == "clerk":
        return _create_clerk_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    # ── M84A — PagerDuty drift provider ────────────────────────────────────────
    elif provider == "pagerduty":
        return _create_pagerduty_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    elif provider == "linear":
        return _create_linear_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    # ── M86A — Jira drift provider ─────────────────────────────────────────────
    elif provider == "jira":
        return _create_jira_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    elif provider == "kubernetes":
        return _create_kubernetes_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            scheduled_sync_enabled=scheduled_sync_enabled,
            sync_interval_minutes=sync_interval_minutes,
            workspace_id=workspace_id,
            db=db,
        )
    else:
        raise ValueError(
            f"Unsupported provider: {provider!r}. "
            "Supported values: 'cloudflare', 'github', 'vercel', 'stripe', "
            "'aws', 'firebase', 'supabase', 'azure', 'google_cloud', "
            "'twilio', 'sendgrid', 'auth0', 'datadog', 'clerk', 'pagerduty', "
            "'linear', 'jira', 'kubernetes'."
        )


# ── Provider-specific creation helpers ───────────────────────────────────────

def _create_cloudflare_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a Cloudflare integration + DNS-zone resource."""
    # ── 1. Validate credentials against the live API ─────────────────────────
    CloudflareConnector().validate_credentials(credentials)

    # ── 2. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 3. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="cloudflare",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()  # Populate integration.id before the Resource FK reference

    # ── 4. Create Resource row for the DNS zone ───────────────────────────────
    zone_id: str = credentials["zone_id"]
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="cloudflare_dns_zone",
        provider_resource_id=zone_id,
        display_name=f"{display_name} (DNS Zone)",
        resource_metadata={"zone_id": zone_id},
        is_active=True,
    )
    db.add(resource)

    # ── 5. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_github_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a GitHub integration + repository resource.

    Uniqueness enforcement: a given user cannot connect the same
    ``"{owner}/{repo}"`` twice.  Raises ``ValueError`` with a user-facing
    message on collision.  Different users connecting the same repo is allowed.

    Note: the duplicate check joins with the Integration table to exclude
    soft-deleted integrations.  A deleted integration's Resource row stays in
    the DB for historical purposes, but should not block a reconnect.
    """
    from app.connectors.github import GitHubConnector

    owner: str = credentials["repo_owner"]
    repo_name: str = credentials["repo_name"]
    slug = f"{owner}/{repo_name}"

    # ── 1. Duplicate-repo check (same user, same repo, non-deleted only) ──────
    # Join with Integration to exclude resources belonging to soft-deleted
    # integrations — a deleted integration's resource must not block reconnection.
    existing = (
        db.query(Resource)
        .join(Integration, Integration.id == Resource.integration_id)
        .filter(
            Resource.user_id == user_id,
            Resource.provider_resource_type == "github_repo",
            Resource.provider_resource_id == slug,
            Integration.status != "deleted",
        )
        .first()
    )
    if existing is not None:
        raise ValueError("This GitHub repository is already connected.")

    # ── 2. Validate credentials against the live API ─────────────────────────
    GitHubConnector().validate_credentials(credentials)

    # ── 3. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 4. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="github",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()  # Populate integration.id before the Resource FK reference

    # ── 5. Create Resource row for the repository ─────────────────────────────
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="github_repo",
        provider_resource_id=slug,
        display_name=f"{display_name} ({slug})",
        resource_metadata={"repo_owner": owner, "repo_name": repo_name},
        is_active=True,
    )
    db.add(resource)

    # ── 6. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_vercel_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a Vercel integration + project resource.

    Uniqueness enforcement: a given user cannot connect the same
    ``vercel_project_id`` twice.  Different users connecting the same project
    is allowed.

    SECURITY: ``vercel_token`` is never logged, never returned, and is only
    used transiently during validation before being passed to the encryption
    layer.
    """
    from app.connectors.vercel import VercelConnector

    project_id: str = credentials["vercel_project_id"]

    # ── 1. Duplicate-project check (same user, same project, non-deleted) ───────
    existing = (
        db.query(Resource)
        .join(Integration, Integration.id == Resource.integration_id)
        .filter(
            Resource.user_id == user_id,
            Resource.provider_resource_type == "vercel_project",
            Resource.provider_resource_id == project_id,
            Integration.status != "deleted",
        )
        .first()
    )
    if existing is not None:
        raise ValueError("This Vercel project is already connected.")

    # ── 2. Validate credentials against the live API ─────────────────────────
    VercelConnector().validate_credentials(credentials)

    # ── 3. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 4. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="vercel",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()  # Populate integration.id before the Resource FK reference

    # ── 5. Create Resource row for the project ────────────────────────────────
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="vercel_project",
        provider_resource_id=project_id,
        display_name=f"{display_name} ({project_id})",
        resource_metadata={"vercel_project_id": project_id},
        is_active=True,
    )
    db.add(resource)

    # ── 6. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_stripe_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a Stripe integration + account resource.

    Uniqueness enforcement: a given user cannot connect the same Stripe
    account ID twice.  Different users connecting the same account is allowed
    (multi-team support).

    SECURITY:
    - ``stripe_api_key`` is never logged, never returned, and is only used
      transiently during validation before being passed to the encryption layer.
    - Customer PII, payment data, and webhook signing secrets are NEVER fetched.
    - For restricted keys (rk_...) that lack the "Account" permission, the
      resource identifier is a non-reversible SHA-256 fingerprint of the key.
    """
    from app.connectors.stripe import StripeConnector

    # ── 1. Validate credentials against the live API ─────────────────────────
    # Multi-probe validation — succeeds even if /v1/account returns 403 (common
    # for restricted keys that don't have the "Account" permission).
    connector = StripeConnector()
    connector.validate_credentials(credentials)

    # ── 2. Resolve the stable account identifier ──────────────────────────────
    # _resolve_account_id() tries GET /v1/account first.  If the key is a
    # restricted key without "Account" permission (HTTP 403), it falls back to
    # a SHA-256 fingerprint of the key — stable, non-reversible, safe to store.
    # SECURITY: do not log the API key.
    account_id, is_real_account_id = connector._resolve_account_id(credentials)

    # ── 3. Duplicate-account check (same user, same Stripe account, non-deleted) ─
    # Bug fix (visibility issue): join with Integration to exclude resources
    # belonging to soft-deleted integrations.  A deleted Stripe integration's
    # Resource row persists for historical audit, but must NOT block the user
    # from reconnecting the same Stripe account after deleting the integration.
    existing = (
        db.query(Resource)
        .join(Integration, Integration.id == Resource.integration_id)
        .filter(
            Resource.user_id == user_id,
            Resource.provider_resource_type == "stripe_account",
            Resource.provider_resource_id == account_id,
            Integration.status != "deleted",
        )
        .first()
    )
    if existing is not None:
        raise ValueError("This Stripe account is already connected.")

    # ── 4. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 5. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="stripe",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()  # Populate integration.id before the Resource FK reference

    # ── 6. Create Resource row for the Stripe account ─────────────────────────
    # account_id_source distinguishes real Stripe account IDs (acct_xxx) from
    # key fingerprints used when /v1/account is inaccessible to restricted keys.
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="stripe_account",
        provider_resource_id=account_id,
        display_name=f"{display_name} ({account_id})",
        resource_metadata={
            "stripe_account_id": account_id,
            "account_id_source": "stripe_api" if is_real_account_id else "key_fingerprint",
        },
        is_active=True,
    )
    db.add(resource)

    # ── 7. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_aws_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create an AWS integration + account resource.

    Uniqueness enforcement: a given user cannot connect the same AWS
    account ID twice. Different users connecting the same account is allowed.

    SECURITY:
    - aws_access_key_id is never logged in full.
    - aws_secret_access_key is never logged, never returned.
    - Only account-level inventory is fetched — no resource or customer data.
    """
    from app.connectors.aws import AWSConnector

    connector = AWSConnector()

    # ── 1. Validate credentials ───────────────────────────────────────────────
    connector.validate_credentials(credentials)

    # ── 2. Get stable account ID ──────────────────────────────────────────────
    # SECURITY: do not log the full access key ID.
    account_id = connector.get_account_id(credentials)

    # ── 3. Duplicate-account check (non-deleted only) ────────────────────────
    existing = (
        db.query(Resource)
        .join(Integration, Integration.id == Resource.integration_id)
        .filter(
            Resource.user_id == user_id,
            Resource.provider_resource_type == "aws_account",
            Resource.provider_resource_id == account_id,
            Integration.status != "deleted",
        )
        .first()
    )
    if existing is not None:
        raise ValueError("This AWS account is already connected.")

    # ── 4. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 5. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="aws",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 6. Create Resource row ────────────────────────────────────────────────
    selected_regions = credentials.get("aws_selected_regions") or [
        credentials.get("aws_default_region", "us-east-1")
    ]
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="aws_account",
        provider_resource_id=account_id,
        display_name=f"{display_name} ({account_id})",
        resource_metadata={
            "aws_account_id":   account_id,
            "default_region":   credentials.get("aws_default_region", "us-east-1"),
            "selected_regions": selected_regions,
        },
        is_active=True,
    )
    db.add(resource)

    # ── 7. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def create_firebase_integration(
    *,
    credentials: dict,
    display_name: str,
    user_id: uuid.UUID,
    workspace_id: uuid.UUID | None = None,
    scheduled_sync_enabled: bool = True,
    sync_interval_minutes: int = 60,
    db: Session,
) -> Integration:
    """Create and validate a Firebase integration using a service account JSON.

    SECURITY:
    - credentials["service_account_json"]["private_key"] is never logged.
    - The service account JSON is stored encrypted only.
    - Firebase project metadata is fetched to confirm access.
    """
    import json as _json

    from app.connectors.firebase import FirebaseConnector

    connector = FirebaseConnector()

    # Parse the service account JSON to extract project_id for dedup.
    raw_sa = credentials.get("service_account_json", "")
    if isinstance(raw_sa, str):
        try:
            sa_dict = _json.loads(raw_sa)
        except _json.JSONDecodeError as exc:
            raise ValueError(
                "Firebase service account JSON is not valid JSON. "
                "Paste the complete service account JSON file."
            ) from exc
    else:
        sa_dict = raw_sa or {}

    project_id = sa_dict.get("project_id", "")

    # ── 1. Validate credentials ───────────────────────────────────────────────
    connector.validate_credentials(credentials)

    # ── 2. Duplicate-project check (non-deleted only) ─────────────────────────
    if project_id:
        existing = (
            db.query(Resource)
            .join(Integration, Integration.id == Resource.integration_id)
            .filter(
                Resource.user_id == user_id,
                Resource.provider_resource_type == "firebase_project",
                Resource.provider_resource_id == project_id,
                Integration.status != "deleted",
            )
            .first()
        )
        if existing is not None:
            raise ValueError(
                f"Firebase project {project_id!r} is already connected."
            )

    # ── 3. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 4. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="firebase",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 5. Create Resource row ────────────────────────────────────────────────
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="firebase_project",
        provider_resource_id=project_id or str(integration.id),
        display_name=f"{display_name} ({project_id})" if project_id else display_name,
        resource_metadata={
            "project_id": project_id,
            "client_email": sa_dict.get("client_email", ""),
        },
        is_active=True,
    )
    db.add(resource)

    # ── 6. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


# ── M82-pre.1 — credential-connect parity helpers ────────────────────────────
#
# Shared design for the five M82-pre.1 helpers (azure, google_cloud, twilio,
# sendgrid, auth0):
#
#   1. Presence / shape validation happens in IntegrationCreateRequest
#      (Pydantic model_validator). By the time we reach these helpers the
#      credentials dict has every required key.
#   2. Live API validation is intentionally NOT performed here. The first
#      scheduled or manual sync will call connector.validate_credentials()
#      and surface errors through the normal SyncRun failure path. This
#      prevents secret-bearing API error messages from being raised
#      synchronously through the create endpoint.
#   3. Credentials are encrypted with AES-256-GCM via encrypt_credentials().
#      The plaintext dict is dropped immediately after.
#   4. A Resource row is created with a stable, opaque provider_resource_id
#      derived from the credential identity field (subscription_id, project_id,
#      account_sid, integration.id fallback for SendGrid, or domain).
#   5. The resource_metadata dict carries only non-secret identifiers — never
#      a token, secret, JWT, private key, or PEM material.
#
# SECURITY: at no point are these credentials returned to the caller, written
# to a log, or stored in plaintext. The encrypted_credentials column is the
# only persistent home.


def _create_azure_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create an Azure integration + subscription resource (M82-pre.1).

    SECURITY: credentials["client_secret"] is NEVER logged, NEVER returned,
    NEVER stored in plaintext. tenant_id, client_id, and subscription_id
    are opaque identifiers used for resource keying.
    """
    subscription_id: str = credentials.get("subscription_id", "")

    # ── 1. Duplicate-subscription check (non-deleted only) ────────────────────
    if subscription_id:
        existing = (
            db.query(Resource)
            .join(Integration, Integration.id == Resource.integration_id)
            .filter(
                Resource.user_id == user_id,
                Resource.provider_resource_type == "azure_subscription",
                Resource.provider_resource_id == subscription_id,
                Integration.status != "deleted",
            )
            .first()
        )
        if existing is not None:
            raise ValueError(
                f"Azure subscription {subscription_id!r} is already connected."
            )

    # ── 2. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 3. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="azure",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 4. Create Resource row ────────────────────────────────────────────────
    # SECURITY: resource_metadata stores only opaque identifiers (tenant_id
    # and subscription_id are GUIDs that are not secret). client_id and
    # client_secret are NEVER stored here.
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="azure_subscription",
        provider_resource_id=subscription_id or str(integration.id),
        display_name=(
            f"{display_name} ({subscription_id})"
            if subscription_id
            else display_name
        ),
        resource_metadata={
            "tenant_id": credentials.get("tenant_id", ""),
            "subscription_id": subscription_id,
        },
        is_active=True,
    )
    db.add(resource)

    # ── 5. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_google_cloud_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a Google Cloud integration + project resource (M82-pre.1).

    SECURITY: the service account JSON embeds a private_key. The full JSON
    string is stored encrypted only and NEVER logged or returned. The
    private_key is NEVER copied into resource_metadata or any other field.
    """
    import json as _json

    # ── 1. Resolve project_id ─────────────────────────────────────────────────
    # Prefer the explicit project_id; fall back to parsing the SA JSON if it
    # contains one. Parsing failures here are non-fatal — the connector will
    # raise a clearer error at sync time.
    project_id: str = (credentials.get("project_id") or "").strip()
    sa_raw = credentials.get("service_account_json") or ""
    if not project_id and isinstance(sa_raw, str) and sa_raw.strip():
        try:
            sa_dict = _json.loads(sa_raw)
            if isinstance(sa_dict, dict):
                project_id = (sa_dict.get("project_id") or "").strip()
        except (_json.JSONDecodeError, ValueError):
            # Parsing failure — defer to first-sync validation. We do NOT
            # raise here because the error message could echo the JSON text
            # back into the response, which might re-surface private_key
            # bytes if the user pasted them by accident.
            project_id = ""

    # ── 2. Duplicate-project check (non-deleted only) ─────────────────────────
    if project_id:
        existing = (
            db.query(Resource)
            .join(Integration, Integration.id == Resource.integration_id)
            .filter(
                Resource.user_id == user_id,
                Resource.provider_resource_type == "google_cloud_project",
                Resource.provider_resource_id == project_id,
                Integration.status != "deleted",
            )
            .first()
        )
        if existing is not None:
            raise ValueError(
                f"Google Cloud project {project_id!r} is already connected."
            )

    # ── 3. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 4. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="google_cloud",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 5. Create Resource row ────────────────────────────────────────────────
    # SECURITY: resource_metadata stores ONLY the safe project_id. The
    # service_account_json (and its embedded private_key, private_key_id,
    # client_email) is NEVER copied here.
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="google_cloud_project",
        provider_resource_id=project_id or str(integration.id),
        display_name=(
            f"{display_name} ({project_id})" if project_id else display_name
        ),
        resource_metadata={"project_id": project_id},
        is_active=True,
    )
    db.add(resource)

    # ── 6. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_twilio_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a Twilio integration + account resource (M82-pre.1).

    SECURITY: credentials["auth_token"] is NEVER logged, NEVER returned,
    NEVER stored in plaintext. Only the account_sid is exposed as the
    resource key.
    """
    account_sid: str = credentials.get("account_sid", "")

    # ── 1. Duplicate-account check (non-deleted only) ─────────────────────────
    if account_sid:
        existing = (
            db.query(Resource)
            .join(Integration, Integration.id == Resource.integration_id)
            .filter(
                Resource.user_id == user_id,
                Resource.provider_resource_type == "twilio_account",
                Resource.provider_resource_id == account_sid,
                Integration.status != "deleted",
            )
            .first()
        )
        if existing is not None:
            raise ValueError(
                "This Twilio account is already connected."
            )

    # ── 2. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 3. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="twilio",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 4. Create Resource row ────────────────────────────────────────────────
    # SECURITY: resource_metadata stores ONLY a prefix of the account_sid
    # (first 8 chars) so the full identifier is not echoed back through
    # downstream UIs that render resource metadata directly.
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="twilio_account",
        provider_resource_id=account_sid or str(integration.id),
        display_name=(
            f"{display_name} (Twilio account)"
            if account_sid
            else display_name
        ),
        resource_metadata={
            "account_sid_prefix": account_sid[:8] if account_sid else "",
        },
        is_active=True,
    )
    db.add(resource)

    # ── 5. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_sendgrid_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a SendGrid integration + account resource (M82-pre.1).

    SECURITY: credentials["api_key"] is NEVER logged, NEVER returned,
    NEVER stored in plaintext. SendGrid does not expose an account-level
    GUID at create time, so the resource is keyed by integration.id —
    duplicate connections are intentionally allowed (the user may have
    multiple sub-accounts on the same SendGrid plan).
    """
    # ── 1. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 2. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="sendgrid",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 3. Create Resource row ────────────────────────────────────────────────
    # SECURITY: resource_metadata is empty (no SendGrid identifier is safe to
    # store at create time without a live API call). The api_key value is
    # NEVER copied here.
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="sendgrid_account",
        provider_resource_id=str(integration.id),
        display_name=display_name,
        resource_metadata={},
        is_active=True,
    )
    db.add(resource)

    # ── 4. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_auth0_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create an Auth0 integration + tenant resource (M82-pre.1).

    SECURITY: credentials["client_secret"] and
    credentials["management_api_token"] are NEVER logged, NEVER returned,
    NEVER stored in plaintext. Only the safe domain string is exposed
    through resource_metadata.
    """
    domain: str = (credentials.get("domain") or "").strip().lower()

    # ── 1. Duplicate-tenant check (non-deleted only) ──────────────────────────
    if domain:
        existing = (
            db.query(Resource)
            .join(Integration, Integration.id == Resource.integration_id)
            .filter(
                Resource.user_id == user_id,
                Resource.provider_resource_type == "auth0_tenant",
                Resource.provider_resource_id == domain,
                Integration.status != "deleted",
            )
            .first()
        )
        if existing is not None:
            raise ValueError(
                f"Auth0 tenant {domain!r} is already connected."
            )

    # ── 2. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 3. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="auth0",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 4. Create Resource row ────────────────────────────────────────────────
    # SECURITY: resource_metadata stores ONLY the safe domain string. client_id,
    # client_secret, and management_api_token are NEVER copied here.
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="auth0_tenant",
        provider_resource_id=domain or str(integration.id),
        display_name=(
            f"{display_name} ({domain})" if domain else display_name
        ),
        resource_metadata={"domain": domain},
        is_active=True,
    )
    db.add(resource)

    # ── 5. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_datadog_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a Datadog integration + account resource (M82A).

    SECURITY: credentials["api_key"] and credentials["application_key"] are
    NEVER logged, NEVER returned, NEVER stored in plaintext. Only the safe
    site string is exposed through resource_metadata.

    Live API validation is deferred to the first sync — the connector's
    validate_credentials() is called at sync time. This prevents synchronous
    error messages from potentially surfacing credential values and avoids
    network dependency at create time.
    """
    site: str = (credentials.get("site") or "datadoghq.com").strip().lower()

    # ── 1. Encrypt credentials ────────────────────────────────────────────────
    # SECURITY: api_key and application_key are encrypted here and NEVER
    # stored in plaintext or returned in any response.
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 2. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="datadog",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 3. Create Resource row ────────────────────────────────────────────────
    # SECURITY: resource_metadata stores ONLY the safe site string and
    # a provider_family label. api_key and application_key are NEVER copied here.
    # Normalize site to a safe label for display without exposing full URL.
    site_category = "us" if "datadoghq.com" in site and "eu" not in site and "ap" not in site and "gov" not in site else site.split(".")[0] if "." in site else site
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="datadog_account",
        provider_resource_id=str(integration.id),
        display_name=f"{display_name} ({site})" if site else display_name,
        resource_metadata={
            "site": site,
            "site_category": site_category,
            "provider_family": "observability",
        },
        is_active=True,
    )
    db.add(resource)

    # ── 4. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_clerk_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a Clerk integration + identity resource (M83A).

    SECURITY: credentials["secret_key"] is NEVER logged, NEVER returned,
    NEVER stored in plaintext. No secret key values, publishable key values,
    session tokens, JWTs, OAuth tokens, webhook secrets, redirect URLs,
    user data, or PII are stored in resource_metadata.

    Live API validation is deferred to the first sync — the connector's
    validate_credentials() is called at sync time. This prevents synchronous
    error messages from potentially surfacing credential values and avoids
    network dependency at create time.
    """
    # ── 1. Encrypt credentials ────────────────────────────────────────────────
    # SECURITY: secret_key is encrypted here and NEVER stored in plaintext
    # or returned in any response.
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 2. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="clerk",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 3. Create Resource row ────────────────────────────────────────────────
    # SECURITY: resource_metadata stores ONLY a safe provider_family label.
    # secret_key, publishable_key, frontend_api_url, session tokens, JWTs,
    # user data, and all customer-identifying data are NEVER copied here.
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="clerk_instance",
        provider_resource_id=str(integration.id),
        display_name=display_name,
        resource_metadata={"provider_family": "identity"},
        is_active=True,
    )
    db.add(resource)

    # ── 4. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_pagerduty_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a PagerDuty integration + incident-management resource (M84A).

    SECURITY: credentials["api_token"] is NEVER logged, NEVER returned,
    NEVER stored in plaintext.  No API token values, routing keys,
    integration keys, webhook secrets, user data, or PII are stored in
    resource_metadata.

    Live API validation is deferred to the first sync.
    """
    # ── 1. Encrypt credentials ────────────────────────────────────────────────
    # SECURITY: api_token is encrypted here and NEVER stored in plaintext.
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 2. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="pagerduty",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 3. Create Resource row ────────────────────────────────────────────────
    # SECURITY: resource_metadata stores ONLY a safe provider_family label.
    # api_token, routing keys, integration keys, and all sensitive values
    # are NEVER copied here.
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="pagerduty_account",
        provider_resource_id=str(integration.id),
        display_name=display_name,
        resource_metadata={"provider_family": "incident_management"},
        is_active=True,
    )
    db.add(resource)

    # ── 4. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_linear_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a Linear integration + devops resource (M85A).

    SECURITY: credentials["api_key"] is NEVER logged, NEVER returned,
    NEVER stored in plaintext.  No API key values, webhook secrets, user
    data, issue content, or PII are stored in resource_metadata.

    Live API validation is deferred to the first sync.
    """
    # ── 1. Encrypt credentials ────────────────────────────────────────────────
    # SECURITY: api_key is encrypted here and NEVER stored in plaintext.
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 2. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="linear",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 3. Create Resource row ────────────────────────────────────────────────
    # SECURITY: resource_metadata stores ONLY a safe provider_family label.
    # api_key, webhook secrets, and all sensitive values are NEVER copied here.
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="linear_account",
        provider_resource_id=str(integration.id),
        display_name=display_name,
        resource_metadata={"provider_family": "devops"},
        is_active=True,
    )
    db.add(resource)

    # ── 4. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_jira_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a Jira integration + project-management resource (M86A).

    SECURITY: credentials["api_token"] is NEVER logged, NEVER returned,
    NEVER stored in plaintext.  credentials["email"] is also NEVER stored
    in resource_metadata.  Only the safe site_url (hostname) is exposed
    through resource_metadata.

    Live API validation is deferred to the first sync.
    """
    site_url: str = (credentials.get("site_url") or "").strip().lower()

    # ── 1. Encrypt credentials ────────────────────────────────────────────────
    # SECURITY: api_token and email are encrypted here and NEVER stored in
    # plaintext or returned in any response.
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 2. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="jira",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 3. Create Resource row ────────────────────────────────────────────────
    # SECURITY: resource_metadata stores ONLY the safe site_url and a
    # provider_family label.  api_token and email are NEVER copied here.
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="jira_site",
        provider_resource_id=site_url or str(integration.id),
        display_name=f"{display_name} ({site_url})" if site_url else display_name,
        resource_metadata={
            "site_url": site_url,
            "provider_family": "project_management",
        },
        is_active=True,
    )
    db.add(resource)

    # ── 4. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def _create_kubernetes_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    workspace_id: uuid.UUID | None = None,
    db: Session,
) -> Integration:
    """Create a Kubernetes integration + cluster resource (Kubernetes message 1).

    SECURITY: credentials["kubeconfig"] (and any bearer token, client key,
    or client certificate it embeds) is NEVER logged, NEVER returned, NEVER
    stored in plaintext outside the encrypted credentials column, and NEVER
    copied into resource_metadata. Only the user-supplied display name and
    optional cluster_name/context are used for resource identity — both are
    non-secret, user-chosen labels.

    Message 9 (public launch): the kubeconfig is validated synchronously
    against the live API server before anything is written — kubeconfig
    parsing, exec/auth-provider plugin rejection, and context resolution
    happen in ``_build_api_client()``; a live ``/version`` call confirms
    the cluster is reachable and the credential is not obviously invalid.
    This matches every other provider's create-time validation and gives
    the "Invalid" launch-certification state (malformed kubeconfig,
    nonexistent context, auth failure, unreachable cluster) immediate
    feedback instead of a silent 201.

    Full resource collection (and therefore the Full/Partial coverage
    determination) is intentionally NOT run synchronously here — it can
    involve dozens of paginated calls across many API groups, so it stays
    on the first sync, same as every other multi-resource provider.
    """
    from app.connectors.kubernetes import KubernetesConnector

    context_name: str = (credentials.get("context") or "").strip()
    cluster_name: str = (credentials.get("cluster_name") or "").strip()
    resource_key = cluster_name or context_name or str(user_id)

    # Raises AuthenticationError / NetworkError / ConnectorError — caught by
    # the router and returned as a 400/502, matching every other provider.
    KubernetesConnector().validate_credentials(credentials)

    # ── 1. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 2. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="kubernetes",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 3. Create Resource row ─────────────────────────────────────────────────
    # SECURITY: resource_metadata stores ONLY the user-supplied display
    # labels (cluster_name / context). kubeconfig content, tokens, client
    # keys, and certificates are NEVER copied here — the real stable
    # cluster_id is computed by the connector from the kube-system
    # namespace UID (or a host hash) during fetch(), not at creation time.
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="kubernetes_cluster",
        provider_resource_id=str(integration.id),
        display_name=f"{display_name} ({resource_key})" if resource_key else display_name,
        resource_metadata={
            "cluster_name": cluster_name or None,
            "context_name": context_name or None,
        },
        is_active=True,
    )
    db.add(resource)

    # ── 4. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def get_integrations_by_workspace(
    *,
    workspace_id: uuid.UUID,
    db: Session,
) -> list[Integration]:
    """Return non-deleted integrations for a workspace.

    Called when workspace_id is provided in the list request (M50).
    Membership verification is done at the router level before this call.
    """
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.status != "deleted",
        )
        .order_by(Integration.created_at.desc())
        .all()
    )


def get_integrations(*, user_id: uuid.UUID, db: Session) -> list[Integration]:
    """Return all non-deleted integrations for *user_id*, newest first.

    Soft-deleted integrations (``status == 'deleted'``) are excluded from
    the list view — their historical changes remain accessible via
    ``GET /changes``.
    """
    return (
        db.query(Integration)
        .filter(
            Integration.user_id == user_id,
            Integration.status != "deleted",
        )
        .order_by(Integration.created_at.desc())
        .all()
    )


def get_integration_by_id(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> Integration | None:
    """Return the integration if it belongs to *user_id* and is not deleted.

    Returns ``None`` if the integration does not exist, belongs to another
    user, or has been soft-deleted.  Both missing and unauthorised cases
    map to HTTP 404 at the router level to avoid leaking object existence.
    """
    return (
        db.query(Integration)
        .filter(
            Integration.id == integration_id,
            Integration.user_id == user_id,
            Integration.status != "deleted",
        )
        .first()
    )


def _get_integration_any_status(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> Integration | None:
    """Return the integration regardless of status (including deleted).

    Used internally by soft-delete for idempotent deletes — a second DELETE
    on an already-deleted integration should still return 204, not 404.
    """
    return (
        db.query(Integration)
        .filter(
            Integration.id == integration_id,
            Integration.user_id == user_id,
        )
        .first()
    )


def update_integration(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    display_name: str | None = None,
    sync_interval_minutes: int | None = None,
    status: str | None = None,
    db: Session,
) -> Integration:
    """Update a non-deleted integration's metadata fields.

    Only the fields that are explicitly passed (not None) are written.

    Raises:
        LookupError: Integration not found, not owned by *user_id*, or
                     already soft-deleted.
    """
    integration = get_integration_by_id(
        integration_id=integration_id,
        user_id=user_id,
        db=db,
    )
    if integration is None:
        raise LookupError("Integration not found.")

    if display_name is not None:
        integration.display_name = display_name
    if sync_interval_minutes is not None:
        integration.sync_interval_minutes = sync_interval_minutes
        # Setting an interval expresses intent to schedule.  Ensure the flag
        # is True so the integration is included in the eligibility scan even
        # if it was created before scheduled_sync_enabled defaulted to True.
        integration.scheduled_sync_enabled = True
    if status is not None:
        integration.status = status

    db.commit()
    db.refresh(integration)
    return integration


def soft_delete_integration(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> None:
    """Soft-delete an integration by setting ``status = 'deleted'``.

    Idempotent — calling this on an already-deleted integration is a no-op
    (no error raised, no second commit).

    Historical changes, resources, and snapshots for this integration are
    preserved in the database.  The integration will no longer appear in
    ``GET /integrations`` or be eligible for scheduled syncs.

    ``scheduled_sync_enabled`` is also set to False as defence-in-depth.
    It is **not** the source of truth for scheduling (``status`` is), but
    keeping the column coherent simplifies any future direct-SQL audits.

    Raises:
        LookupError: Integration never existed or never belonged to *user_id*.
    """
    integration = _get_integration_any_status(
        integration_id=integration_id,
        user_id=user_id,
        db=db,
    )
    if integration is None:
        raise LookupError("Integration not found.")

    if integration.status == "deleted":
        # Already deleted — idempotent, nothing to do.
        return

    integration.status = "deleted"
    # Defence-in-depth: not the scheduling source-of-truth, kept coherent.
    integration.scheduled_sync_enabled = False
    db.commit()


def reconnect_credentials(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    new_token: str,
    db: Session,
) -> Integration:
    """Replace the API token for an existing integration (token-only reconnect).

    The integration's underlying resource (Cloudflare ``zone_id`` or GitHub
    ``repo_owner`` / ``repo_name``) is pinned to its existing value — only
    the token changes.  The new token is validated against the live provider
    API before any write occurs.

    Security guarantees:
    - The new token is never logged (even on failure).
    - The new token is never present in any return value or exception message.
    - The old token is decrypted only to recover the resource identifier; it
      is not stored or returned anywhere.
    - If validation fails, the database row is not modified.

    Side-effect: if the integration's status was ``'error'`` (e.g. from a
    previous credential failure), it is reset to ``'active'`` on success.

    Raises:
        LookupError:          Integration not found or soft-deleted.
        AuthenticationError:  The new token fails validation.
        ConnectorError:       The provider API returns a non-auth error.
        NetworkError:         Transport-level failure reaching the provider.
        EncryptionKeyError:   Server-side encryption key misconfiguration.
    """
    from app.connectors.exceptions import AuthenticationError, ConnectorError, NetworkError  # noqa: F401
    from app.core.encryption import decrypt_credentials, encrypt_credentials

    integration = get_integration_by_id(
        integration_id=integration_id,
        user_id=user_id,
        db=db,
    )
    if integration is None:
        raise LookupError("Integration not found.")

    # Decrypt existing credentials to recover the pinned resource identifiers.
    # The decrypted dict is used only within this function and is not returned.
    existing_creds = decrypt_credentials(
        integration.encrypted_credentials,
        integration.credential_iv,
    )

    # Build a new credentials dict with the same resource identifiers but the
    # new token.  Validate against the live provider API before any DB write.
    if integration.provider == "cloudflare":
        from app.connectors.cloudflare import CloudflareConnector
        new_creds = {
            "api_token": new_token,
            "zone_id": existing_creds["zone_id"],
        }
        CloudflareConnector().validate_credentials(new_creds)

    elif integration.provider == "github":
        from app.connectors.github import GitHubConnector
        new_creds = {
            "github_token": new_token,
            "repo_owner": existing_creds["repo_owner"],
            "repo_name": existing_creds["repo_name"],
        }
        GitHubConnector().validate_credentials(new_creds)

    elif integration.provider == "vercel":
        from app.connectors.vercel import VercelConnector
        new_creds = {
            "vercel_token":      new_token,
            "vercel_project_id": existing_creds["vercel_project_id"],
        }
        VercelConnector().validate_credentials(new_creds)

    elif integration.provider == "stripe":
        from app.connectors.stripe import StripeConnector
        new_creds = {
            "stripe_api_key": new_token,
        }
        StripeConnector().validate_credentials(new_creds)

    else:
        raise ValueError(
            f"Unsupported provider for reconnect: {integration.provider!r}"
        )

    # Validation passed — encrypt and store the new credentials.
    ciphertext, iv = encrypt_credentials(new_creds)
    integration.encrypted_credentials = ciphertext
    integration.credential_iv = iv

    # Clear error status if the credential update resolves a previous failure.
    # M59.14: clear both the legacy ``error`` status and the new
    # ``needs_reconnect`` status when a valid set of credentials lands.
    if integration.status in ("error", "needs_reconnect"):
        integration.status = "active"

    db.commit()
    db.refresh(integration)
    return integration


def reconnect_credentials_aws(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    new_access_key_id: str,
    new_secret_access_key: str,
    db: Session,
) -> Integration:
    """Replace AWS credentials for an existing AWS integration.

    Design note — credential rotation only
    ----------------------------------------
    This function intentionally rotates the access key pair
    (``aws_access_key_id`` + ``aws_secret_access_key``) and nothing else.
    The existing ``aws_default_region`` and ``aws_selected_regions`` are
    read from the currently-stored (decrypted) credentials and carried
    forward unchanged into the new encrypted blob.

    Changing region configuration is a separate concern and should be
    handled by a future dedicated settings / update endpoint, not by the
    reconnect flow.  Keeping reconnect narrowly scoped to key rotation
    avoids ambiguity about whether a reconnect request also silently
    updates monitoring scope.

    SECURITY: new_secret_access_key is never logged or returned.
    """
    from app.connectors.aws import AWSConnector
    from app.core.encryption import decrypt_credentials, encrypt_credentials

    integration = get_integration_by_id(
        integration_id=integration_id,
        user_id=user_id,
        db=db,
    )
    if integration is None:
        raise LookupError("Integration not found.")

    # Decrypt existing creds to preserve region configuration.
    existing_creds = decrypt_credentials(
        integration.encrypted_credentials,
        integration.credential_iv,
    )

    # Build new credentials with the same region settings.
    new_creds = {
        "aws_access_key_id":     new_access_key_id,
        "aws_secret_access_key": new_secret_access_key,
        "aws_default_region":    existing_creds.get("aws_default_region", "us-east-1"),
        "aws_selected_regions":  existing_creds.get("aws_selected_regions", []),
    }

    # Validate new credentials before saving.
    AWSConnector().validate_credentials(new_creds)

    # Encrypt and store.
    ciphertext, iv = encrypt_credentials(new_creds)
    integration.encrypted_credentials = ciphertext
    integration.credential_iv = iv

    # M59.14: clear both the legacy ``error`` status and the new
    # ``needs_reconnect`` status when a valid set of credentials lands.
    if integration.status in ("error", "needs_reconnect"):
        integration.status = "active"

    db.commit()
    db.refresh(integration)
    return integration


def reconnect_credentials_firebase(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    new_service_account_json: str,
    db: Session,
) -> Integration:
    """Replace the service account JSON for an existing Firebase integration.

    The new credentials are validated against the live Firebase API before the
    database row is updated.  If validation fails, the existing credentials
    remain unchanged.

    SECURITY: The service account private_key is stored encrypted only.
    It is NEVER logged or returned.
    """
    import json as _json

    from app.connectors.firebase import FirebaseConnector
    from app.core.encryption import encrypt_credentials

    integration = get_integration_by_id(
        integration_id=integration_id,
        user_id=user_id,
        db=db,
    )
    if integration is None:
        raise LookupError("Integration not found.")

    # Parse the service account JSON to validate it is well-formed.
    if isinstance(new_service_account_json, str):
        try:
            _json.loads(new_service_account_json)
        except _json.JSONDecodeError as exc:
            raise ValueError(
                "Firebase service account JSON is not valid JSON."
            ) from exc

    new_creds = {"service_account_json": new_service_account_json}

    # Validate new credentials against the live Firebase API.
    FirebaseConnector().validate_credentials(new_creds)

    # Encrypt and store.
    ciphertext, iv = encrypt_credentials(new_creds)
    integration.encrypted_credentials = ciphertext
    integration.credential_iv = iv

    # M59.14: clear both the legacy ``error`` status and the new
    # ``needs_reconnect`` status when a valid set of credentials lands.
    if integration.status in ("error", "needs_reconnect"):
        integration.status = "active"

    db.commit()
    db.refresh(integration)
    return integration


def create_supabase_integration(
    *,
    credentials: dict,
    display_name: str,
    user_id: uuid.UUID,
    workspace_id: uuid.UUID | None = None,
    scheduled_sync_enabled: bool = True,
    sync_interval_minutes: int = 60,
    db: Session,
) -> Integration:
    """Create and validate a Supabase integration using a Management API token.

    SECURITY:
    - credentials["access_token"] is never logged.
    - The token is stored encrypted only and never returned.
    - Only project configuration metadata is fetched; row data, auth user PII,
      secret values, and file contents are NEVER read.
    """
    from app.connectors.supabase import SupabaseConnector

    connector = SupabaseConnector()
    access_token: str = credentials.get("access_token", "")
    project_ref: str = credentials.get("project_ref", "")

    # ── 1. Validate credentials ───────────────────────────────────────────────
    connector.validate_credentials(credentials)

    # ── 2. Duplicate-project check (non-deleted only) ─────────────────────────
    if project_ref:
        existing = (
            db.query(Resource)
            .join(Integration, Integration.id == Resource.integration_id)
            .filter(
                Resource.user_id == user_id,
                Resource.provider_resource_type == "supabase_project",
                Resource.provider_resource_id == project_ref,
                Integration.status != "deleted",
            )
            .first()
        )
        if existing is not None:
            raise ValueError(
                f"Supabase project {project_ref!r} is already connected."
            )

    # ── 3. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 4. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="supabase",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        workspace_id=workspace_id,
    )
    db.add(integration)
    db.flush()

    # ── 5. Create Resource row ────────────────────────────────────────────────
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="supabase_project",
        provider_resource_id=project_ref or str(integration.id),
        display_name=f"{display_name} ({project_ref})" if project_ref else display_name,
        resource_metadata={
            "project_ref": project_ref,
            # Do NOT store the access_token in resource_metadata.
        },
        is_active=True,
    )
    db.add(resource)

    # ── 6. Commit ─────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def reconnect_credentials_supabase(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    new_access_token: str,
    db: Session,
) -> Integration:
    """Replace the Management API access token for an existing Supabase integration.

    The new token is validated against the live Supabase Management API before
    the database row is updated.  If validation fails, the existing credentials
    remain unchanged.

    SECURITY: The access token is stored encrypted only.
    It is NEVER logged or returned.
    """
    from app.connectors.supabase import SupabaseConnector
    from app.core.encryption import encrypt_credentials

    integration = get_integration_by_id(
        integration_id=integration_id,
        user_id=user_id,
        db=db,
    )
    if integration is None:
        raise LookupError("Integration not found.")

    # Retrieve the existing project_ref from the resource row.
    resource = (
        db.query(Resource)
        .filter(
            Resource.integration_id == integration_id,
            Resource.provider_resource_type == "supabase_project",
        )
        .first()
    )
    project_ref = ""
    if resource is not None:
        meta = resource.resource_metadata or {}
        project_ref = meta.get("project_ref", "") or resource.provider_resource_id or ""

    new_creds = {
        "access_token": new_access_token,
        "project_ref": project_ref,
    }

    # Validate new credentials against the live Supabase API.
    SupabaseConnector().validate_credentials(new_creds)

    # Encrypt and store.
    ciphertext, iv = encrypt_credentials(new_creds)
    integration.encrypted_credentials = ciphertext
    integration.credential_iv = iv

    # M59.14: clear both the legacy ``error`` status and the new
    # ``needs_reconnect`` status when a valid set of credentials lands.
    if integration.status in ("error", "needs_reconnect"):
        integration.status = "active"

    db.commit()
    db.refresh(integration)
    return integration


def reconnect_credentials_kubernetes(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    new_kubeconfig: str,
    new_context: str | None = None,
    new_cluster_name: str | None = None,
    new_namespace_allowlist: list[str] | None = None,
    db: Session,
) -> Integration:
    """Replace the kubeconfig for an existing Kubernetes integration.

    The new kubeconfig is validated against the live cluster before the
    database row is updated. If the new kubeconfig resolves to a genuinely
    different cluster identity (different ``kube-system`` UID / API server
    host) than the one this integration was originally connected to, the
    update is rejected rather than silently merged — a rotated credential
    for the SAME cluster is always accepted, but pointing this integration
    at a different cluster is not.

    SECURITY: The kubeconfig is stored encrypted only. It is NEVER logged
    or returned.
    """
    from app.connectors.kubernetes import KUBERNETES_CLUSTER, KubernetesConnector

    integration = get_integration_by_id(
        integration_id=integration_id,
        user_id=user_id,
        db=db,
    )
    if integration is None:
        raise LookupError("Integration not found.")

    new_creds: dict = {"kubeconfig": new_kubeconfig}
    if new_context:
        new_creds["context"] = new_context
    if new_cluster_name:
        new_creds["cluster_name"] = new_cluster_name
    if new_namespace_allowlist:
        new_creds["namespace_allowlist"] = new_namespace_allowlist

    connector = KubernetesConnector()
    # Validates parsing, context existence, exec/auth-provider rejection,
    # and API server reachability. Raises AuthenticationError/NetworkError/
    # ConnectorError on failure.
    connector.validate_credentials(new_creds)

    # Resolve the new cluster's identity by running the same collection
    # pipeline used in production, then compare it against the identity
    # already on file for this integration.
    new_records = connector.fetch(new_creds)
    new_cluster_record = next(
        (r for r in new_records if r.get("record_type") == KUBERNETES_CLUSTER),
        None,
    )
    new_cluster_id = new_cluster_record.get("cluster_id") if new_cluster_record else None

    existing_cluster_resource = (
        db.query(Resource)
        .filter(
            Resource.integration_id == integration_id,
            Resource.provider_resource_type == KUBERNETES_CLUSTER,
        )
        .first()
    )
    existing_cluster_id = (
        existing_cluster_resource.provider_resource_id
        if existing_cluster_resource is not None
        else None
    )

    if existing_cluster_id and new_cluster_id and existing_cluster_id != new_cluster_id:
        raise ConnectorError(
            "This kubeconfig points to a different Kubernetes cluster than the "
            "one this integration is connected to. To monitor a different "
            "cluster, create a new integration instead of replacing this one's "
            "credentials."
        )

    # Encrypt and store.
    ciphertext, iv = encrypt_credentials(new_creds)
    integration.encrypted_credentials = ciphertext
    integration.credential_iv = iv

    if integration.status in ("error", "needs_reconnect"):
        integration.status = "active"

    db.commit()
    db.refresh(integration)
    return integration


def reconnect_credentials_shopify(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    new_access_token: str,
    db: Session,
) -> Integration:
    """Replace the Admin API access token for an existing Shopify integration.

    The new token is validated against the live Shopify Admin API before the
    database row is updated.  If validation fails, the existing credentials
    remain unchanged.  The shop_domain is preserved from the existing
    encrypted credentials so the resource identity stays stable.

    SECURITY: The access token is stored encrypted only.
    It is NEVER logged or returned.
    """
    from app.connectors.shopify import ShopifyConnector, normalize_shop_domain

    integration = get_integration_by_id(
        integration_id=integration_id,
        user_id=user_id,
        db=db,
    )
    if integration is None:
        raise LookupError("Integration not found.")

    # Retrieve the existing shop_domain from the encrypted credentials.
    existing_creds = decrypt_credentials(
        integration.encrypted_credentials,
        integration.credential_iv,
    )
    shop_domain = normalize_shop_domain(existing_creds.get("shop_domain", "") or "")

    new_creds = {
        "shop_domain": shop_domain,
        "shopify_access_token": new_access_token,
    }

    # Validate new credentials against the live Shopify API.
    ShopifyConnector().validate_credentials(new_creds)

    # Encrypt and store.
    ciphertext, iv = encrypt_credentials(new_creds)
    integration.encrypted_credentials = ciphertext
    integration.credential_iv = iv

    # M59.14: clear both the legacy ``error`` status and the new
    # ``needs_reconnect`` status when a valid set of credentials lands.
    if integration.status in ("error", "needs_reconnect"):
        integration.status = "active"

    db.commit()
    db.refresh(integration)
    return integration


def create_github_app_integration(
    *,
    user_id: uuid.UUID,
    workspace_id: uuid.UUID | None = None,
    display_name: str,
    credentials: dict,
    scheduled_sync_enabled: bool = False,
    sync_interval_minutes: int | None = None,
    db: Session,
) -> Integration:
    """Create or auto-reconnect a GitHub App integration + repository resource.

    The *credentials* dict must contain::
        {
            "credential_type": "github_app",
            "installation_id": int,
            "repo_owner": str,
            "repo_name":  str,
        }

    Note: credential validation (via GitHubConnector) is performed by the
    calling route before this function is invoked.  This function only
    handles the DB writes.

    Uniqueness enforcement: a given user cannot have two *active* GitHub
    integrations pointing at the same ``"{owner}/{repo}"`` regardless of
    auth method.

    M59.16 — reconnect-on-broken behaviour
    ---------------------------------------
    If the user already has a GitHub integration for this repo whose status
    is ``needs_reconnect`` or ``error`` (i.e. the upstream credentials had
    been revoked or were failing), the function does *not* raise.  Instead
    it treats the install as a **reconnect** of the existing row:
      * the row's encrypted credentials are replaced with the new ones;
      * the resource metadata is updated to mark it as ``github_app``;
      * ``status`` flips back to ``"active"`` and
        ``consecutive_failure_count`` is reset to 0;
      * the same row is returned.
    This means a user who re-installs the GitHub App after uninstalling it
    upstream lands back on their original integration — same UUID, same
    history, same snapshots — without having to delete it first.

    Soft-deleted rows (``status='deleted'``) continue to be ignored by the
    duplicate check, so a fresh install of a previously-deleted repo
    succeeds as before (a brand new row is created).

    Raises:
        ValueError:         Duplicate of an active/paused row.
        EncryptionKeyError: ENCRYPTION_KEY not configured.
    """
    owner: str = credentials["repo_owner"]
    repo_name: str = credentials["repo_name"]
    slug = f"{owner}/{repo_name}"

    # ── Look up any non-deleted existing integration for this repo ─────────────
    existing_integration: Integration | None = (
        db.query(Integration)
        .join(Resource, Resource.integration_id == Integration.id)
        .filter(
            Resource.user_id == user_id,
            Resource.provider_resource_type == "github_repo",
            Resource.provider_resource_id == slug,
            Integration.status != "deleted",
        )
        .first()
    )

    if existing_integration is not None:
        # M59.16: auto-reconnect when the existing row is broken.
        if existing_integration.status in ("needs_reconnect", "error"):
            ciphertext, iv = encrypt_credentials(credentials)
            existing_integration.encrypted_credentials = ciphertext
            existing_integration.credential_iv = iv
            existing_integration.status = "active"
            existing_integration.consecutive_failure_count = 0
            # M59.18: backfill workspace_id on legacy rows that pre-date the
            # workspace_id fix.  Without this, reconnecting a row that was
            # created during the broken window keeps Slack/push silently
            # skipped on every future sync.  Never overwrite an existing
            # workspace assignment.
            if existing_integration.workspace_id is None and workspace_id is not None:
                existing_integration.workspace_id = workspace_id

            # Make sure the resource metadata is correct for App-based auth so
            # ``get_connection_method()`` keeps returning ``"github_app"``.
            # If we are reconnecting a row that was previously a PAT, this
            # also migrates the metadata in place.
            for r in existing_integration.resources:
                if (
                    r.provider_resource_type == "github_repo"
                    and r.provider_resource_id == slug
                ):
                    new_meta = dict(r.resource_metadata or {})
                    new_meta["repo_owner"] = owner
                    new_meta["repo_name"] = repo_name
                    new_meta["connection_method"] = "github_app"
                    r.resource_metadata = new_meta
                    r.is_active = True

            db.commit()
            db.refresh(existing_integration)
            return existing_integration

        # Active / paused → genuine duplicate; preserve the existing error.
        raise ValueError("This GitHub repository is already connected.")

    # ── Encrypt credentials ───────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── Create Integration row ────────────────────────────────────────────────
    # M59.18: persist workspace_id on the integration row so the production
    # notification fanout (``dispatch_notifications_for_sync``) can resolve
    # the workspace's Slack / webhook / push settings.  Every other provider
    # creator in this module already sets this column; before M59.18 the
    # GitHub App path was the only one that didn't, which silently disabled
    # Slack and browser-push for any GitHub App integration even when the
    # workspace had those channels configured.
    integration = Integration(
        user_id=user_id,
        workspace_id=workspace_id,
        provider="github",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
        scheduled_sync_enabled=scheduled_sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
    )
    db.add(integration)
    db.flush()  # Populate integration.id before the Resource FK reference

    # ── Create Resource row — metadata marks this as GitHub App auth ──────────
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="github_repo",
        provider_resource_id=slug,
        display_name=f"{display_name} ({slug})",
        resource_metadata={
            "repo_owner": owner,
            "repo_name": repo_name,
            "connection_method": "github_app",
        },
        is_active=True,
    )
    db.add(resource)

    # ── Commit ────────────────────────────────────────────────────────────────
    db.commit()
    db.refresh(integration)
    return integration


def get_connection_method(integration: Integration) -> str | None:
    """Return the connection method for an integration without decrypting creds.

    Derived from the first resource's ``resource_metadata["connection_method"]``
    field, which is set at creation time.

    Returns:
        ``"github_app"`` — authenticated via GitHub App installation token.
        ``"pat"``        — authenticated via fine-grained Personal Access Token
                           (or legacy integrations created before M31).
        ``None``         — not a GitHub integration (e.g. Cloudflare).
    """
    if integration.provider != "github":
        return None
    if not integration.resources:
        return "pat"
    metadata = integration.resources[0].resource_metadata or {}
    return metadata.get("connection_method", "pat")


def get_recent_sync_runs(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    limit: int | None = None,
    page: int = 1,
    page_size: int = 25,
    status_filter: str | None = None,
    trigger_filter: str | None = None,
    db: Session,
) -> tuple[list, int]:
    """Return ``(runs, total)`` for an integration scoped to *user_id*.

    Supports offset pagination via *page* / *page_size*.  When the legacy
    *limit* kwarg is provided, it overrides *page_size* and forces *page=1*
    (backward-compatible — callers that just want the last N runs continue
    to work unchanged).

    The *total* reflects the count **after** any applied filters so the
    frontend can render "Page N of M" correctly.

    Both ``integration_id`` and ``user_id`` are filtered for defence-in-depth:
    the caller should have already verified ownership, but we filter here too
    so a mis-wired call cannot leak cross-user data.

    Args:
        integration_id: The integration whose runs are requested.
        user_id:        Must match the integration's owner.
        limit:          Legacy: if set, return at most this many runs (page=1).
        page:           1-indexed page number (ignored when *limit* is set).
        page_size:      Rows per page.
        status_filter:  If set, restrict to runs with this ``status`` value.
        trigger_filter: If set, restrict to runs with this ``triggered_by`` value.
        db:             Active SQLAlchemy session.
    """
    from app.models.sync_run import SyncRun

    q = (
        db.query(SyncRun)
        .filter(
            SyncRun.integration_id == integration_id,
            SyncRun.user_id == user_id,
        )
    )
    if status_filter is not None:
        q = q.filter(SyncRun.status == status_filter)
    if trigger_filter is not None:
        q = q.filter(SyncRun.triggered_by == trigger_filter)

    q = q.order_by(SyncRun.created_at.desc())
    total: int = q.count()

    if limit is not None:
        # Legacy: caller wants the last N runs (page-1 semantics).
        runs = q.limit(limit).all()
    else:
        offset = (page - 1) * page_size
        runs = q.offset(offset).limit(page_size).all()

    return runs, total


def get_latest_sync_run_summary(
    integration_id: uuid.UUID,
    db: Session,
) -> tuple[str | None, str | None, str | None]:
    """Return ``(status, error_message, failure_category)`` from the most recent SyncRun.

    Returns ``(None, None, None)`` if no SyncRun exists for this integration yet.
    Used by the router's ``_build_response`` helper to populate
    ``last_sync_status``, ``last_sync_error``, and ``last_sync_failure_category``
    in ``IntegrationResponse``.

    M59.15: ``failure_category`` is the stable, machine-readable category from
    the M32 failure classifier (``authentication``, ``resource_missing``,
    ``provider_unavailable``, ``rate_limited``, ``network``, ``config_error``,
    ``internal_error``, ``unknown``).  Exposing it lets the frontend pick a
    display state (Active / Needs attention / Degraded) without string-matching
    on the free-text error message.
    """
    from app.models.sync_run import SyncRun

    run = (
        db.query(SyncRun)
        .filter(SyncRun.integration_id == integration_id)
        .order_by(SyncRun.created_at.desc())
        .first()
    )
    if run is None:
        return None, None, None
    return run.status, run.error_message, run.failure_category


# ── Workspace-scoped integration access (M51) ─────────────────────────────────


def get_integration_for_viewer(
    *,
    integration_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    db: Session,
) -> Integration | None:
    """Return integration if actor is the owner OR a workspace member.

    Any workspace role (member/admin/owner) may view an integration.
    Returns None (→ 404) if not found, deleted, or actor has no access.
    """
    from app.services.workspace_service import get_membership

    integration = (
        db.query(Integration)
        .filter(
            Integration.id == integration_id,
            Integration.status != "deleted",
        )
        .first()
    )
    if integration is None:
        return None

    # Direct owner access.
    if integration.user_id == actor_user_id:
        return integration

    # Workspace member access.
    if integration.workspace_id is not None:
        membership = get_membership(integration.workspace_id, actor_user_id, db)
        if membership is not None:
            return integration

    return None


def get_integration_for_manager(
    *,
    integration_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    db: Session,
) -> Integration | None:
    """Return integration if actor can manage it (owner OR workspace admin+).

    'Manage' means update or delete.  Workspace members (view-only) are
    rejected (returns None so the router raises 404 — avoids leaking
    whether the integration exists).
    """
    from app.services.workspace_service import get_membership

    integration = (
        db.query(Integration)
        .filter(
            Integration.id == integration_id,
            Integration.status != "deleted",
        )
        .first()
    )
    if integration is None:
        return None

    # Direct owner always has management access.
    if integration.user_id == actor_user_id:
        return integration

    # Workspace admin or owner can also manage.
    if integration.workspace_id is not None:
        membership = get_membership(integration.workspace_id, actor_user_id, db)
        if membership is not None and membership.role in ("owner", "admin"):
            return integration

    return None
