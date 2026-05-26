"""Slack OAuth callback router — M58.5.

Routes
------
GET /slack/oauth/callback  — public OAuth callback; Slack redirects here after install

Security notes
--------------
* This endpoint is intentionally public (no auth middleware) because Slack
  redirects the user here without a session.  CSRF protection is provided
  by the HMAC-signed state token.
* The bot token returned by Slack is NEVER logged.
* On any error, the user is redirected to the frontend error page.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/slack", tags=["slack"])


@router.get("/oauth/callback", include_in_schema=False)
def slack_oauth_callback(
    code: str = Query(..., description="Slack OAuth code."),
    state: str = Query(..., description="HMAC-signed state token."),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Handle the Slack OAuth redirect after the user approves the installation.

    Steps:
    1. Verify the HMAC state token and extract workspace_id.
    2. Exchange the code for a bot token via ``oauth.v2.access``.
    3. Encrypt and store the bot token against the workspace.
    4. Redirect to the frontend notifications settings page.

    On any failure, redirect to the frontend with an error query parameter.
    The bot token is NEVER logged.
    """
    from app.config import settings as _settings

    frontend_base = _settings.effective_frontend_url
    success_redirect = (
        f"{frontend_base}/settings/workspace/notifications"
        "?slack_install=success"
    )
    error_redirect = (
        f"{frontend_base}/settings/workspace/notifications"
        "?slack_install=error"
    )

    # ── Verify state token ─────────────────────────────────────────────────────
    workspace_id_str: str | None = None
    try:
        from app.services.slack_service import verify_state_token_no_user
        payload = verify_state_token_no_user(state)
        workspace_id_str = payload.get("workspace_id")
        user_id_str = payload.get("user_id")

        if not workspace_id_str or not user_id_str:
            raise ValueError("Missing workspace_id or user_id in state token.")

        workspace_id = uuid.UUID(workspace_id_str)
        user_id = uuid.UUID(user_id_str)

    except Exception as exc:
        logger.warning(
            "slack_oauth: state token validation failed  error=%r",
            type(exc).__name__,
        )
        return RedirectResponse(url=f"{error_redirect}&reason=invalid_state")

    # ── Exchange code for bot token ────────────────────────────────────────────
    try:
        from app.services.slack_service import exchange_code_for_token
        token_data = exchange_code_for_token(code)
        # NOTE: token_data["bot_token"] is NEVER logged.
    except RuntimeError as exc:
        logger.warning(
            "slack_oauth: token exchange failed  workspace=%s  error=%r",
            workspace_id_str,
            str(exc),  # safe — does not include the token
        )
        return RedirectResponse(url=f"{error_redirect}&reason=token_exchange_failed")
    except Exception as exc:
        logger.error(
            "slack_oauth: unexpected error during token exchange  workspace=%s  error=%r",
            workspace_id_str,
            type(exc).__name__,
        )
        return RedirectResponse(url=f"{error_redirect}&reason=unexpected_error")

    # ── Store installation ─────────────────────────────────────────────────────
    try:
        from app.services.slack_service import store_installation
        store_installation(
            workspace_id=workspace_id,
            user_id=user_id,
            bot_token=token_data["bot_token"],   # encrypted inside store_installation
            team_id=token_data["team_id"],
            team_name=token_data["team_name"],
            bot_user_id=token_data["bot_user_id"],
            db=db,
        )
        db.commit()
        logger.info(
            "slack_oauth: installation complete  workspace=%s  team=%s",
            workspace_id_str,
            token_data["team_id"],
        )
    except Exception as exc:
        db.rollback()
        logger.error(
            "slack_oauth: failed to store installation  workspace=%s  error=%r",
            workspace_id_str,
            type(exc).__name__,
        )
        return RedirectResponse(url=f"{error_redirect}&reason=storage_failed")

    return RedirectResponse(url=success_redirect)
