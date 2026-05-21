"""Integration routes.

POST /integrations  — create a new integration (validates + encrypts credentials)
GET  /integrations  — list integrations for the authenticated user

Credentials (api_token, zone_id, IV, ciphertext) are **never** present in
any response shape.  This is enforced at the schema level.
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


@router.post("", response_model=IntegrationResponse, status_code=201)
def create_integration(
    body: IntegrationCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IntegrationResponse:
    """Create and validate a new provider integration.

    Validates the Cloudflare API token against the live Cloudflare API before
    writing anything to the database.  Returns HTTP 400 if the token is
    invalid, expired, or lacks ``Zone.DNS:Read`` permission.

    The request body includes the plaintext API token, but the token is
    **not** stored.  Only the AES-256-GCM ciphertext and IV are persisted.
    The response never includes credentials in any form.
    """
    try:
        integration = integration_service.create_integration(
            user_id=current_user.id,
            provider=body.provider,
            display_name=body.display_name,
            credentials={"api_token": body.api_token, "zone_id": body.zone_id},
            db=db,
        )
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Cloudflare authentication failed: {exc}",
        ) from exc
    except ConnectorError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Cloudflare validation error: {exc}",
        ) from exc
    except NetworkError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach Cloudflare API: {exc}",
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
