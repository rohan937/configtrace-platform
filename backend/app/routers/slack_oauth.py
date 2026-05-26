"""Slack OAuth callback router — M58.5.
Slack interactive actions endpoint — M58.6.

Routes
------
GET  /slack/oauth/callback  — public OAuth callback; Slack redirects here after install
POST /slack/actions          — public endpoint for Slack interactive button actions

Security notes
--------------
* GET /oauth/callback: intentionally public; CSRF protected by HMAC-signed state token.
* POST /actions: intentionally public; authenticated by Slack HMAC-SHA256 request
  signature (X-Slack-Request-Timestamp + X-Slack-Signature headers).
* The bot token is NEVER logged.
* On any error in /actions, return 200 with an ephemeral error message (Slack best
  practice — a non-200 causes Slack to show a "Something went wrong" banner to the
  user, which is worse than a graceful ephemeral error).
"""

from __future__ import annotations

import json
import logging
import urllib.parse
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
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


# ── M58.6 — Interactive Actions ───────────────────────────────────────────────


@router.post("/actions", include_in_schema=False)
async def slack_actions(
    request: Request,
    db: Session = Depends(get_db),
    x_slack_request_timestamp: str | None = Header(
        default=None, alias="X-Slack-Request-Timestamp"
    ),
    x_slack_signature: str | None = Header(
        default=None, alias="X-Slack-Signature"
    ),
) -> JSONResponse:
    """Handle Slack interactive button actions (Block Kit / interactive components).

    Authentication
    --------------
    Slack signs every request with HMAC-SHA256 using the App Signing Secret.
    We verify the signature before processing anything.  No session auth is
    required — Slack's signature IS the auth mechanism for this endpoint.

    Payload
    -------
    Slack sends ``application/x-www-form-urlencoded`` with a single ``payload``
    field whose value is a JSON string.

    Response
    --------
    Always returns HTTP 200 with an ephemeral JSON body so Slack can show the
    user a brief acknowledgment message.  A non-200 response causes Slack to
    display a generic "Something went wrong" banner.
    """
    from app.config import settings as _settings
    from app.services.slack_service import handle_action, verify_request_signature

    # ── Read raw body (must happen before FastAPI consumes it) ────────────────
    raw_body: bytes = await request.body()

    # ── Signature verification ─────────────────────────────────────────────────
    signing_secret = _settings.SLACK_SIGNING_SECRET
    if not signing_secret:
        logger.error("slack_actions: SLACK_SIGNING_SECRET is not configured")
        raise HTTPException(status_code=403, detail="Slack integration not configured.")

    if not x_slack_request_timestamp or not x_slack_signature:
        logger.warning("slack_actions: missing Slack signature headers")
        raise HTTPException(status_code=403, detail="Missing Slack signature headers.")

    if not verify_request_signature(
        signing_secret=signing_secret,
        timestamp=x_slack_request_timestamp,
        body=raw_body,
        signature=x_slack_signature,
    ):
        logger.warning("slack_actions: invalid or stale Slack signature")
        raise HTTPException(status_code=403, detail="Invalid or stale Slack signature.")

    # ── Parse payload ──────────────────────────────────────────────────────────
    try:
        form_data = urllib.parse.parse_qs(
            raw_body.decode("utf-8", errors="replace"),
            keep_blank_values=True,
        )
        payload_values = form_data.get("payload", [])
        if not payload_values:
            raise ValueError("Missing 'payload' field in form data.")
        payload = json.loads(payload_values[0])
    except Exception as exc:
        logger.warning(
            "slack_actions: failed to parse payload  error=%r", type(exc).__name__
        )
        return JSONResponse(
            content={"response_type": "ephemeral", "text": "⚠ Could not parse action."},
            status_code=200,
        )

    # ── Dispatch to action handler ─────────────────────────────────────────────
    response_body = handle_action(payload, db)
    return JSONResponse(content=response_body, status_code=200)
