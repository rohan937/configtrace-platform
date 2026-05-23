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
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.connectors.cloudflare import CloudflareConnector
from app.connectors.exceptions import AuthenticationError, ConnectorError, NetworkError
from app.core.encryption import EncryptionKeyError, encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource


def create_integration(
    *,
    user_id: uuid.UUID,
    provider: str,
    display_name: str,
    credentials: dict,
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
        user_id:      UUID of the authenticated user.
        provider:     ``"cloudflare"`` or ``"github"``.
        display_name: User-supplied label shown in the integrations list.
        credentials:  Provider-specific dict — see module docstring.
        db:           Active SQLAlchemy session.

    Returns:
        The newly persisted ``Integration`` object.

    Raises:
        ValueError:           Unsupported provider, or duplicate GitHub repo.
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
            db=db,
        )
    elif provider == "github":
        return _create_github_integration(
            user_id=user_id,
            display_name=display_name,
            credentials=credentials,
            db=db,
        )
    else:
        raise ValueError(
            f"Unsupported provider: {provider!r}. "
            "Supported values: 'cloudflare', 'github'."
        )


# ── Provider-specific creation helpers ───────────────────────────────────────

def _create_cloudflare_integration(
    *,
    user_id: uuid.UUID,
    display_name: str,
    credentials: dict,
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
    db: Session,
) -> Integration:
    """Create a GitHub integration + repository resource.

    Uniqueness enforcement: a given user cannot connect the same
    ``"{owner}/{repo}"`` twice.  Raises ``ValueError`` with a user-facing
    message on collision.  Different users connecting the same repo is allowed.
    """
    from app.connectors.github import GitHubConnector

    owner: str = credentials["repo_owner"]
    repo_name: str = credentials["repo_name"]
    slug = f"{owner}/{repo_name}"

    # ── 1. Duplicate-repo check (same user, same repo) ────────────────────────
    existing = (
        db.query(Resource)
        .filter(
            Resource.user_id == user_id,
            Resource.provider_resource_type == "github_repo",
            Resource.provider_resource_id == slug,
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

    else:
        raise ValueError(
            f"Unsupported provider for reconnect: {integration.provider!r}"
        )

    # Validation passed — encrypt and store the new credentials.
    ciphertext, iv = encrypt_credentials(new_creds)
    integration.encrypted_credentials = ciphertext
    integration.credential_iv = iv

    # Clear error status if the credential update resolves a previous failure.
    if integration.status == "error":
        integration.status = "active"

    db.commit()
    db.refresh(integration)
    return integration


def get_recent_sync_runs(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    limit: int,
    db: Session,
) -> tuple[list, int]:
    """Return (recent_runs, total) for an integration scoped to *user_id*.

    *recent_runs* contains the ``limit`` most recent SyncRuns ordered by
    ``created_at DESC``.  *total* is the all-time lifetime count so the
    frontend can show "Last N of M total runs".

    Both ``integration_id`` and ``user_id`` are filtered for defence-in-depth:
    the caller should have already verified ownership, but we filter here too
    so a mis-wired call cannot leak cross-user data.

    Args:
        integration_id: The integration whose runs are requested.
        user_id:        Must match the integration's owner.
        limit:          Maximum number of runs to return.
        db:             Active SQLAlchemy session.
    """
    from app.models.sync_run import SyncRun

    q = (
        db.query(SyncRun)
        .filter(
            SyncRun.integration_id == integration_id,
            SyncRun.user_id == user_id,
        )
        .order_by(SyncRun.created_at.desc())
    )
    total: int = q.count()
    runs = q.limit(limit).all()
    return runs, total


def get_latest_sync_run_summary(
    integration_id: uuid.UUID,
    db: Session,
) -> tuple[str | None, str | None]:
    """Return ``(status, error_message)`` from the most recent SyncRun.

    Returns ``(None, None)`` if no SyncRun exists for this integration yet.
    Used by the router's ``_build_response`` helper to populate
    ``last_sync_status`` and ``last_sync_error`` in ``IntegrationResponse``.
    """
    from app.models.sync_run import SyncRun

    run = (
        db.query(SyncRun)
        .filter(SyncRun.integration_id == integration_id)
        .order_by(SyncRun.created_at.desc())
        .first()
    )
    if run is None:
        return None, None
    return run.status, run.error_message
