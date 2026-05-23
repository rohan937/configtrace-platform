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
    """Return all integrations for *user_id*, newest first."""
    return (
        db.query(Integration)
        .filter(Integration.user_id == user_id)
        .order_by(Integration.created_at.desc())
        .all()
    )


def get_integration_by_id(
    *,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> Integration | None:
    """Return the integration if it belongs to *user_id*, else ``None``."""
    return (
        db.query(Integration)
        .filter(
            Integration.id == integration_id,
            Integration.user_id == user_id,
        )
        .first()
    )
