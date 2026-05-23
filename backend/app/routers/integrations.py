"""Integration routes.

POST /integrations  — create a new integration (validates + encrypts credentials)
GET  /integrations  — list integrations for the authenticated user

Credentials (api_token, zone_id, github_token, etc.) and their encrypted forms
are **never** present in any response shape.  This is enforced at the schema
level.

Supported providers
-------------------
``cloudflare``  — Credentials: ``api_token`` + ``zone_id``
``github``      — Credentials: ``github_token`` + ``repo_owner`` + ``repo_name``
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.connectors.exceptions import AuthenticationError, ConnectorError, NetworkError
from app.core.auth import get_current_user
from app.core.encryption import EncryptionKeyError
from app.database import get_db
from app.models.user import User
from app.schemas.integration import (
    IntegrationCreateRequest,
    IntegrationListResponse,
    IntegrationResponse,
)
from app.services import integration_service

router = APIRouter(prefix="/integrations", tags=["integrations"])


def _build_credentials(body: IntegrationCreateRequest) -> dict:
    """Extract the provider-specific credentials dict from the request body.

    Credentials are never stored in plaintext — this dict is passed to the
    connector for validation and to the encryption layer for storage.

    Cloudflare:  ``{"api_token": str, "zone_id": str}``
    GitHub:      ``{"github_token": str, "repo_owner": str, "repo_name": str}``
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
    # Unreachable when Pydantic validation passes (Literal["cloudflare", "github"]),
    # but included as a safety net for future providers.
    return {}


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

    try:
        integration = integration_service.create_integration(
            user_id=current_user.id,
            provider=body.provider,
            display_name=body.display_name,
            credentials=credentials,
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

    return integration


@router.get("", response_model=IntegrationListResponse)
def list_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IntegrationListResponse:
    """List all integrations belonging to the authenticated user.

    The response includes only safe metadata fields.  Encrypted credentials,
    IVs, and provider tokens are never included.
    """
    rows = integration_service.get_integrations(user_id=current_user.id, db=db)
    return IntegrationListResponse(integrations=rows, total=len(rows))
