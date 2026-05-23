"""GitHub App installation routes — M31.

Routes (all mounted under /integrations/github/app):
  GET  /install-url           — generate state token + return GitHub App install URL
  GET  /installation-repos    — list repos for a given installation_id (picker)
  POST /complete              — exchange installation_id + repo selection for an integration

Security
--------
All routes are auth-gated by Clerk JWT (get_current_user).
State tokens are HMAC-SHA256 signed, 10-minute TTL, bound to user_id.
Installation tokens are minted ephemerally in-memory and never persisted or logged.
Private key, PATs, and installation tokens never appear in any response or log.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.core.auth import get_current_user
from app.core.encryption import EncryptionKeyError
from app.core.github_app import (
    decode_private_key,
    generate_state_token,
    list_installation_repos,
    mint_app_jwt,
    mint_installation_token,
    verify_state_token,
)
from app.database import get_db
from app.models.user import User
from app.schemas.integration import IntegrationResponse
from app.services import integration_service

router = APIRouter(
    prefix="/integrations/github/app",
    tags=["integrations-github-app"],
)

logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_app_configured() -> None:
    """Raise HTTP 503 if any required GitHub App env var is missing."""
    missing = [
        name
        for name, val in [
            ("GITHUB_APP_ID",               settings.GITHUB_APP_ID),
            ("GITHUB_APP_SLUG",             settings.GITHUB_APP_SLUG),
            ("GITHUB_APP_PRIVATE_KEY",      settings.GITHUB_APP_PRIVATE_KEY),
            ("GITHUB_APP_OAUTH_STATE_SECRET", settings.GITHUB_APP_OAUTH_STATE_SECRET),
        ]
        if not val
    ]
    if missing:
        raise HTTPException(
            status_code=503,
            detail=(
                "GitHub App is not configured on this server. "
                f"Missing env vars: {', '.join(missing)}."
            ),
        )


def _get_app_jwt() -> str:
    """Mint a GitHub App JWT from configured env vars."""
    private_key_pem = decode_private_key(settings.GITHUB_APP_PRIVATE_KEY)  # type: ignore[arg-type]
    return mint_app_jwt(settings.GITHUB_APP_ID, private_key_pem)  # type: ignore[arg-type]


def _build_response(integration, db: Session) -> IntegrationResponse:
    from app.routers.integrations import _build_response as _base
    return _base(integration, db)


# ── Schemas ───────────────────────────────────────────────────────────────────

class GitHubAppInstallUrlResponse(BaseModel):
    """Response for GET /install-url."""
    install_url: str
    state: str


class GitHubInstallationRepo(BaseModel):
    full_name: str
    owner: str
    name: str
    private: bool
    description: str | None = None


class GitHubInstallationReposResponse(BaseModel):
    """Response for GET /installation-repos."""
    repos: list[GitHubInstallationRepo]
    installation_id: int


class GitHubAppCompleteRequest(BaseModel):
    """Request body for POST /complete."""
    installation_id: int = Field(
        ...,
        description="GitHub installation ID from the callback URL.",
    )
    state: str = Field(
        ...,
        description="HMAC-signed state token from the install-url response.",
    )
    repo_owner: str = Field(
        ...,
        min_length=1,
        description="Repository owner (GitHub username or organisation).",
    )
    repo_name: str = Field(
        ...,
        min_length=1,
        description="Repository name (without owner prefix).",
    )
    display_name: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Human-readable label for this integration.",
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/install-url", response_model=GitHubAppInstallUrlResponse)
def get_install_url(
    current_user: User = Depends(get_current_user),
) -> GitHubAppInstallUrlResponse:
    """Generate a GitHub App install URL with a bound HMAC state token.

    The state token is HMAC-SHA256 signed, expires in 10 minutes, and is
    bound to the current user's ID.  The frontend must pass this state value
    in both the GitHub redirect URL (GitHub echoes it back) and in the
    POST /complete request body.

    Returns HTTP 503 if the GitHub App is not configured.
    """
    _require_app_configured()

    state = generate_state_token(
        str(current_user.id),
        settings.GITHUB_APP_OAUTH_STATE_SECRET,  # type: ignore[arg-type]
    )
    install_url = (
        f"https://github.com/apps/{settings.GITHUB_APP_SLUG}"
        f"/installations/new?state={state}"
    )
    return GitHubAppInstallUrlResponse(install_url=install_url, state=state)


@router.get("/installation-repos", response_model=GitHubInstallationReposResponse)
def get_installation_repos(
    installation_id: int = Query(..., description="GitHub App installation ID."),
    state: str = Query(..., description="HMAC state token from install-url."),
    current_user: User = Depends(get_current_user),
) -> GitHubInstallationReposResponse:
    """List repositories accessible to a GitHub App installation.

    Validates the state token, mints an ephemeral installation token (never
    logged or persisted), fetches the repo list, and returns the repos for
    the frontend picker.

    Returns HTTP 400 if the state token is invalid or expired.
    Returns HTTP 503 if the GitHub App is not configured.
    Returns HTTP 502 if the GitHub API is unreachable.
    """
    _require_app_configured()

    try:
        verify_state_token(
            state,
            str(current_user.id),
            settings.GITHUB_APP_OAUTH_STATE_SECRET,  # type: ignore[arg-type]
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        app_jwt = _get_app_jwt()
        repos = list_installation_repos(installation_id, app_jwt)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return GitHubInstallationReposResponse(
        repos=[GitHubInstallationRepo(**r) for r in repos],
        installation_id=installation_id,
    )


@router.post("/complete", response_model=IntegrationResponse, status_code=201)
def complete_github_app_install(
    body: GitHubAppCompleteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IntegrationResponse:
    """Complete a GitHub App installation — create the integration.

    Validates the HMAC state token, mints an ephemeral installation token to
    validate repo access, then creates a GitHub integration row.

    The installation token is used only for validation and is NEVER stored,
    logged, or returned.  At sync time a fresh installation token is minted.

    Duplicate-repo detection (same user, same owner/repo) prevents actual
    duplicate rows even if the state token is reused before it expires.

    Returns HTTP 400 on state token validation failure or duplicate repo.
    Returns HTTP 503 if the GitHub App is not configured or ENCRYPTION_KEY
    is not set.
    Returns HTTP 502 if the GitHub API is unreachable.
    """
    _require_app_configured()

    # ── Validate HMAC state token ─────────────────────────────────────────────
    try:
        verify_state_token(
            body.state,
            str(current_user.id),
            settings.GITHUB_APP_OAUTH_STATE_SECRET,  # type: ignore[arg-type]
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # ── Mint ephemeral installation token for validation ──────────────────────
    # SECURITY: this token is used only within this request and is never stored
    # or logged.  At each subsequent sync, a fresh token is minted by the worker.
    try:
        app_jwt = _get_app_jwt()
        install_token = mint_installation_token(body.installation_id, app_jwt)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    # ── Validate repo access with the installation token ──────────────────────
    # GitHubConnector is token-agnostic — it accepts any bearer token.
    from app.connectors.exceptions import (
        AuthenticationError,
        ConnectorError,
        NetworkError,
    )
    from app.connectors.github import GitHubConnector

    validation_creds = {
        "github_token": install_token,
        "repo_owner":   body.repo_owner,
        "repo_name":    body.repo_name,
    }
    try:
        GitHubConnector().validate_credentials(validation_creds)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Authentication failed: {exc}",
        ) from exc
    except ConnectorError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"GitHub API error: {exc}",
        ) from exc
    except NetworkError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Network error reaching GitHub: {exc}",
        ) from exc

    # ── Create the integration ────────────────────────────────────────────────
    credentials = {
        "credential_type": "github_app",
        "installation_id": body.installation_id,
        "repo_owner":      body.repo_owner,
        "repo_name":       body.repo_name,
    }
    try:
        integration = integration_service.create_github_app_integration(
            user_id=current_user.id,
            display_name=body.display_name,
            credentials=credentials,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except EncryptionKeyError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Server misconfiguration — ENCRYPTION_KEY not set: {exc}",
        ) from exc

    return _build_response(integration, db)
