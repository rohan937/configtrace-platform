"""Integration business logic.

Handles the full creation flow (credential validation → encryption → DB write)
and read operations.  All functions are database-session aware and never return
plaintext credentials in any form.
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
    1. Validate credentials against the live provider API.  Raises immediately
       on bad credentials so nothing is written to the database.
    2. Encrypt credentials with AES-256-GCM.
    3. Insert the ``Integration`` row.
    4. Insert a ``Resource`` row for the DNS zone (one per Cloudflare integration
       in the MVP).
    5. Commit and return the refreshed ``Integration`` ORM object.

    Args:
        user_id:      UUID of the authenticated user.
        provider:     ``"cloudflare"`` (the only supported value in the MVP).
        display_name: User-supplied label shown in the integrations list.
        credentials:  ``{"api_token": str, "zone_id": str}`` for Cloudflare.
        db:           Active SQLAlchemy session.

    Returns:
        The newly persisted ``Integration`` object.

    Raises:
        ValueError:           Unsupported provider.
        AuthenticationError:  Cloudflare returns 401/403.
        ConnectorError:       Cloudflare returns another API error.
        NetworkError:         Transport-level failure reaching Cloudflare.
        EncryptionKeyError:   ``ENCRYPTION_KEY`` is not configured server-side.
    """
    if provider != "cloudflare":
        raise ValueError(
            f"Unsupported provider: {provider!r}.  Only 'cloudflare' is supported."
        )

    # ── 1. Validate credentials against the live API ─────────────────────────
    CloudflareConnector().validate_credentials(credentials)

    # ── 2. Encrypt credentials ────────────────────────────────────────────────
    ciphertext, iv = encrypt_credentials(credentials)

    # ── 3. Create Integration row ─────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider=provider,
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
