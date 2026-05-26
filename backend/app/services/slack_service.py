"""Slack App OAuth and delivery service — M58.5.

Provides:
  - HMAC-SHA256 state tokens for CSRF protection (mirroring github_app.py)
  - OAuth exchange: code → bot token
  - Encrypted bot token storage
  - Channel listing and channel selection
  - Test message delivery via chat.postMessage
  - Slack App message delivery (used by notification_service)
  - Disconnect (remove App installation from workspace)

Security constraints
--------------------
* Bot tokens are AES-256-GCM encrypted at rest.  The plaintext token is
  NEVER stored, logged, or returned in any API response.
* State tokens are HMAC-signed and expire in 10 minutes.
* State tokens bind to the requesting user_id and workspace_id; a mismatch
  is treated as a CSRF attack.
* SLACK_CLIENT_SECRET is NEVER logged.
* This module never applies configuration changes to any monitored provider.

Slack OAuth scopes required
---------------------------
  chat:write        — post messages as the bot
  channels:read     — list public channels
  groups:read       — list private channels the bot has been added to
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_lib
import json
import logging
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.models.notification_settings import WorkspaceNotificationSettings

logger = logging.getLogger(__name__)

_SLACK_API_BASE = "https://slack.com/api"
_SLACK_OAUTH_URL = "https://slack.com/oauth/v2/authorize"
_STATE_TOKEN_TTL = 600      # 10 minutes
_REQUEST_TIMEOUT = 15.0     # seconds


# ── Encryption helpers (re-uses the same AES-GCM pattern) ────────────────────

def _encrypt_token(raw: str) -> tuple[bytes, bytes]:
    """Encrypt a bot token using AES-256-GCM.

    Returns (ciphertext, iv).  Uses the same encrypt_credentials() helper
    used throughout the codebase so key management is consistent.

    Security: raw value is NEVER logged.
    """
    from app.core.encryption import encrypt_credentials
    # Wrap in JSON (same as webhook URLs) for forward compatibility.
    plaintext = json.dumps({"token": raw})
    encrypted, iv = encrypt_credentials(plaintext)
    return encrypted, iv


def _decrypt_token(ciphertext: bytes, iv: bytes) -> str:
    """Decrypt an AES-256-GCM encrypted bot token.

    Security: the returned plaintext must NEVER be logged.
    """
    from app.core.encryption import decrypt_credentials
    plaintext = decrypt_credentials(ciphertext, iv)
    obj = json.loads(plaintext)
    return obj["token"]


# ── State token helpers ───────────────────────────────────────────────────────

def _get_state_secret() -> str:
    """Return the HMAC state secret, raising RuntimeError if unconfigured."""
    from app.config import settings
    secret = settings.SLACK_APP_STATE_SECRET
    if not secret:
        raise RuntimeError(
            "SLACK_APP_STATE_SECRET is not configured. "
            "Set it in your environment to enable the Slack App installation flow."
        )
    return secret


def generate_state_token(user_id: str, workspace_id: str) -> str:
    """Generate a stateless HMAC-SHA256 state token.

    Payload: ``{user_id, workspace_id, nonce, expires_at}``
    Format:  ``<base64url-payload>.<hmac-hex>``

    Args:
        user_id:      The Clerk user UUID string.
        workspace_id: The workspace UUID string.

    Returns:
        A URL-safe state token string (10-minute TTL).

    Raises:
        RuntimeError: If SLACK_APP_STATE_SECRET is not configured.
    """
    secret = _get_state_secret()
    payload: dict[str, Any] = {
        "user_id": user_id,
        "workspace_id": workspace_id,
        "nonce": secrets.token_hex(16),
        "expires_at": int(time.time()) + _STATE_TOKEN_TTL,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode().rstrip("=")
    sig = hmac_lib.new(
        secret.encode(),
        payload_b64.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload_b64}.{sig}"


def verify_state_token(token: str, user_id: str, workspace_id: str) -> dict:
    """Verify and decode a state token from the Slack OAuth callback.

    Checks HMAC, expiry, user_id binding, and workspace_id binding in
    constant time.

    Args:
        token:        State token from the Slack redirect URL.
        user_id:      The Clerk user UUID string.
        workspace_id: The expected workspace UUID string.

    Returns:
        The decoded payload dict on success.

    Raises:
        ValueError: On any validation failure (bad HMAC, expired, mismatch).
                    The message is intentionally vague.
    """
    secret = _get_state_secret()
    parts = token.split(".", 1)
    if len(parts) != 2:
        raise ValueError("Invalid state token.")

    payload_b64, provided_sig = parts
    expected_sig = hmac_lib.new(
        secret.encode(),
        payload_b64.encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac_lib.compare_digest(expected_sig, provided_sig):
        raise ValueError("Invalid state token.")

    try:
        padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(payload_bytes.decode())
    except Exception:
        raise ValueError("Invalid state token.")

    if payload.get("expires_at", 0) < int(time.time()):
        raise ValueError("State token expired.")

    if payload.get("user_id") != user_id:
        raise ValueError("Invalid state token.")

    if payload.get("workspace_id") != workspace_id:
        raise ValueError("Invalid state token.")

    return payload


def verify_state_token_no_user(token: str) -> dict:
    """Verify a state token from the Slack OAuth callback without a known user.

    Used in the public OAuth callback endpoint where the user identity is
    embedded inside the token itself (Slack callback has no session context).
    Checks HMAC and expiry only — caller must verify user_id separately.

    Returns:
        The decoded payload dict on success.

    Raises:
        ValueError: On any validation failure.
    """
    secret = _get_state_secret()
    parts = token.split(".", 1)
    if len(parts) != 2:
        raise ValueError("Invalid state token.")

    payload_b64, provided_sig = parts
    expected_sig = hmac_lib.new(
        secret.encode(),
        payload_b64.encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac_lib.compare_digest(expected_sig, provided_sig):
        raise ValueError("Invalid state token.")

    try:
        padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(payload_bytes.decode())
    except Exception:
        raise ValueError("Invalid state token.")

    if payload.get("expires_at", 0) < int(time.time()):
        raise ValueError("State token expired.")

    return payload


# ── Install URL ───────────────────────────────────────────────────────────────

def build_install_url(user_id: str, workspace_id: str) -> dict:
    """Build the Slack OAuth authorisation URL.

    Args:
        user_id:      The Clerk user UUID string.
        workspace_id: The workspace UUID string.

    Returns:
        dict with keys:
          ``install_url`` — the URL to redirect the user to.
          ``state``       — the state token (for frontend CSRF verification).

    Raises:
        RuntimeError: If SLACK_CLIENT_ID or SLACK_APP_STATE_SECRET are missing.
    """
    from app.config import settings

    if not settings.is_slack_app_configured:
        raise RuntimeError(
            "Slack App is not configured. "
            "Set SLACK_CLIENT_ID and SLACK_CLIENT_SECRET in your environment."
        )

    scopes = "chat:write,channels:read,groups:read"
    state = generate_state_token(user_id, workspace_id)

    redirect_uri = settings.SLACK_REDIRECT_URI or ""
    params = f"client_id={settings.SLACK_CLIENT_ID}&scope={scopes}&state={state}"
    if redirect_uri:
        params += f"&redirect_uri={redirect_uri}"

    install_url = f"{_SLACK_OAUTH_URL}?{params}"
    return {"install_url": install_url, "state": state}


# ── OAuth exchange ────────────────────────────────────────────────────────────

def exchange_code_for_token(code: str) -> dict:
    """Exchange a Slack OAuth code for a bot token.

    Calls ``oauth.v2.access``.  The returned bot token is in the response —
    the caller MUST encrypt it before storage and MUST NOT log it.

    Args:
        code: The ``code`` query parameter from the Slack callback.

    Returns:
        dict with keys: ``bot_token``, ``team_id``, ``team_name``,
        ``bot_user_id``, ``scope``.

    Raises:
        RuntimeError: On Slack API error or network failure.
    """
    from app.config import settings

    if not settings.is_slack_app_configured:
        raise RuntimeError("Slack App is not configured.")

    redirect_uri = settings.SLACK_REDIRECT_URI or None

    data: dict[str, str] = {
        "code": code,
        "client_id": settings.SLACK_CLIENT_ID,    # type: ignore[assignment]
        "client_secret": settings.SLACK_CLIENT_SECRET,  # type: ignore[assignment]
    }
    if redirect_uri:
        data["redirect_uri"] = redirect_uri

    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            resp = client.post(
                f"{_SLACK_API_BASE}/oauth.v2.access",
                data=data,
            )
    except httpx.RequestError as exc:
        raise RuntimeError(f"Network error during Slack OAuth: {exc}") from exc

    if not resp.is_success:
        raise RuntimeError(
            f"Slack OAuth failed (HTTP {resp.status_code})."
        )

    body = resp.json()
    if not body.get("ok"):
        error_code = body.get("error", "unknown_error")
        raise RuntimeError(f"Slack OAuth error: {error_code}")

    # Extract bot token — NEVER log this value.
    bot_token: str = body.get("access_token", "")
    team = body.get("team", {})
    authed_user = body.get("authed_user", {})
    bot_user_id = authed_user.get("id", "")

    return {
        "bot_token": bot_token,
        "team_id": team.get("id", ""),
        "team_name": team.get("name", ""),
        "bot_user_id": bot_user_id,
        "scope": body.get("scope", ""),
    }


# ── Installation storage ──────────────────────────────────────────────────────

def store_installation(
    *,
    workspace_id: uuid.UUID,
    user_id: uuid.UUID,
    bot_token: str,
    team_id: str,
    team_name: str,
    bot_user_id: str,
    db: Session,
) -> WorkspaceNotificationSettings:
    """Persist a Slack App installation.

    Encrypts the bot token before storage.  NEVER logs the token.

    Args:
        workspace_id: UUID of the workspace.
        user_id:      UUID of the installing user.
        bot_token:    Plaintext Slack bot token — encrypted before storage.
        team_id:      Slack team/workspace ID.
        team_name:    Slack team/workspace display name.
        bot_user_id:  Slack bot user ID.
        db:           Active SQLAlchemy session.

    Returns:
        Updated WorkspaceNotificationSettings row.
    """
    from app.services.notification_service import get_or_create_notification_settings

    row = get_or_create_notification_settings(workspace_id, db)

    # Encrypt bot token — NEVER store plaintext.
    encrypted, iv = _encrypt_token(bot_token)

    row.slack_app_enabled = True
    row.slack_team_id = team_id
    row.slack_team_name = team_name
    row.slack_bot_token_encrypted = encrypted
    row.slack_bot_iv = iv
    row.slack_bot_user_id = bot_user_id
    row.slack_app_last_error = None
    row.slack_installed_by_user_id = user_id
    row.slack_installed_at = datetime.now(timezone.utc)

    db.add(row)
    db.flush()
    logger.info(
        "slack_service: installation stored  workspace=%s  team=%s",
        workspace_id,
        team_id,
    )
    return row


# ── Channel listing ───────────────────────────────────────────────────────────

def list_channels(workspace_id: uuid.UUID, db: Session) -> list[dict]:
    """List Slack channels accessible to the installed bot.

    Fetches from Slack's ``conversations.list`` using the decrypted bot token.
    Returns public channels and any private channels the bot has been invited to.

    Args:
        workspace_id: UUID of the workspace.
        db:           Active SQLAlchemy session.

    Returns:
        List of dicts with ``id``, ``name``, ``is_private``, ``is_member``.

    Raises:
        RuntimeError: If no installation exists or Slack API call fails.
    """
    row = _get_installed_row(workspace_id, db)
    bot_token = _decrypt_token(
        row.slack_bot_token_encrypted,   # type: ignore[arg-type]
        row.slack_bot_iv,                # type: ignore[arg-type]
    )

    channels: list[dict] = []
    cursor: str | None = None

    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            while True:
                params: dict[str, str] = {
                    "types": "public_channel,private_channel",
                    "limit": "200",
                    "exclude_archived": "true",
                }
                if cursor:
                    params["cursor"] = cursor

                resp = client.get(
                    f"{_SLACK_API_BASE}/conversations.list",
                    headers={"Authorization": f"Bearer {bot_token}"},
                    params=params,
                )
                if not resp.is_success:
                    raise RuntimeError(
                        f"Slack API error listing channels (HTTP {resp.status_code})."
                    )

                body = resp.json()
                if not body.get("ok"):
                    raise RuntimeError(
                        f"Slack conversations.list error: {body.get('error', 'unknown')}"
                    )

                for ch in body.get("channels", []):
                    channels.append({
                        "id": ch.get("id", ""),
                        "name": ch.get("name", ""),
                        "is_private": bool(ch.get("is_private", False)),
                        "is_member": bool(ch.get("is_member", False)),
                    })

                meta = body.get("response_metadata", {})
                next_cursor = meta.get("next_cursor", "")
                if not next_cursor:
                    break
                cursor = next_cursor

    except RuntimeError:
        raise
    except httpx.RequestError as exc:
        raise RuntimeError(f"Network error listing Slack channels: {exc}") from exc

    logger.info(
        "slack_service: listed channels  workspace=%s  count=%d",
        workspace_id,
        len(channels),
    )
    return channels


# ── Channel selection ─────────────────────────────────────────────────────────

def update_channel(
    workspace_id: uuid.UUID,
    channel_id: str,
    channel_name: str,
    db: Session,
) -> WorkspaceNotificationSettings:
    """Set the Slack channel for alert delivery.

    Args:
        workspace_id:  UUID of the workspace.
        channel_id:    Slack channel ID (e.g. ``C01234567``).
        channel_name:  Display name of the channel (e.g. ``#alerts``).
        db:            Active SQLAlchemy session.

    Returns:
        Updated WorkspaceNotificationSettings row.

    Raises:
        RuntimeError: If no Slack App installation exists for this workspace.
    """
    row = _get_installed_row(workspace_id, db)
    row.slack_channel_id = channel_id
    row.slack_channel_name = channel_name
    db.add(row)
    db.flush()
    logger.info(
        "slack_service: channel updated  workspace=%s  channel=%s",
        workspace_id,
        channel_name,
    )
    return row


# ── Message delivery ──────────────────────────────────────────────────────────

def send_message(bot_token: str, channel_id: str, text: str) -> None:
    """POST a message to a Slack channel via chat.postMessage.

    Args:
        bot_token:  Plaintext Slack bot token.  NEVER log this value.
        channel_id: Slack channel ID.
        text:       Message text (mrkdwn-formatted).

    Raises:
        RuntimeError: On Slack API error or network failure.
    """
    payload = {
        "channel": channel_id,
        "text": text,
    }
    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            resp = client.post(
                f"{_SLACK_API_BASE}/chat.postMessage",
                json=payload,
                headers={
                    "Authorization": f"Bearer {bot_token}",
                    "Content-Type": "application/json",
                },
            )
    except httpx.RequestError as exc:
        raise RuntimeError(f"Network error sending Slack message: {exc}") from exc

    if not resp.is_success:
        raise RuntimeError(
            f"Slack API error sending message (HTTP {resp.status_code})."
        )

    body = resp.json()
    if not body.get("ok"):
        error_code = body.get("error", "unknown_error")
        # channel_not_found, not_in_channel, etc. — safe to surface.
        raise RuntimeError(f"Slack chat.postMessage error: {error_code}")


def send_app_message(workspace_id: uuid.UUID, text: str, db: Session) -> None:
    """Send a message to the workspace's configured Slack channel.

    Decrypts the bot token, sends the message, and updates
    ``slack_app_last_error`` on failure.

    Args:
        workspace_id: UUID of the workspace.
        text:         Message text.
        db:           Active SQLAlchemy session.

    Raises:
        RuntimeError: If no installation + channel are configured, or delivery fails.
    """
    row = _get_installed_row(workspace_id, db)

    if not row.slack_channel_id:
        raise RuntimeError(
            "Slack App is installed but no channel has been selected. "
            "Select a channel before enabling notifications."
        )

    bot_token = _decrypt_token(
        row.slack_bot_token_encrypted,   # type: ignore[arg-type]
        row.slack_bot_iv,                # type: ignore[arg-type]
    )
    try:
        send_message(bot_token, row.slack_channel_id, text)
        # Clear last error on success.
        row.slack_app_last_error = None
        db.add(row)
        db.flush()
    except RuntimeError as exc:
        err_text = str(exc)
        row.slack_app_last_error = err_text
        db.add(row)
        db.flush()
        raise


# ── Test delivery ─────────────────────────────────────────────────────────────

def send_test(workspace_id: uuid.UUID, db: Session) -> None:
    """Send a test message to the configured Slack channel.

    Updates ``slack_app_last_test_at`` on success.

    Raises:
        RuntimeError: On delivery failure.
    """
    row = _get_installed_row(workspace_id, db)
    send_app_message(
        workspace_id,
        (
            "*[ConfigTrace] Test notification*\n\n"
            "Your Slack App is configured correctly. "
            "ConfigTrace will deliver alerts to this channel."
        ),
        db,
    )
    row.slack_app_last_test_at = datetime.now(timezone.utc)
    db.add(row)
    db.flush()
    logger.info("slack_service: test sent  workspace=%s", workspace_id)


# ── Disconnect ────────────────────────────────────────────────────────────────

def disconnect(workspace_id: uuid.UUID, db: Session) -> WorkspaceNotificationSettings:
    """Remove the Slack App installation from a workspace.

    Clears all Slack App columns and disables the channel.  Does NOT revoke
    the token at Slack — the user should do that manually from the Slack UI
    if desired.

    Args:
        workspace_id: UUID of the workspace.
        db:           Active SQLAlchemy session.

    Returns:
        Updated WorkspaceNotificationSettings row.
    """
    from app.services.notification_service import get_or_create_notification_settings

    row = get_or_create_notification_settings(workspace_id, db)
    row.slack_app_enabled = False
    row.slack_team_id = None
    row.slack_team_name = None
    row.slack_bot_token_encrypted = None
    row.slack_bot_iv = None
    row.slack_bot_user_id = None
    row.slack_channel_id = None
    row.slack_channel_name = None
    row.slack_installed_by_user_id = None
    row.slack_installed_at = None
    row.slack_app_last_test_at = None
    row.slack_app_last_error = None
    db.add(row)
    db.flush()
    logger.info("slack_service: disconnected  workspace=%s", workspace_id)
    return row


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_installed_row(
    workspace_id: uuid.UUID, db: Session
) -> WorkspaceNotificationSettings:
    """Return the settings row, asserting that a Slack App installation exists."""
    from app.services.notification_service import get_or_create_notification_settings

    row = get_or_create_notification_settings(workspace_id, db)
    if not row.slack_bot_token_encrypted or not row.slack_bot_iv:
        raise RuntimeError(
            "No Slack App installation found for this workspace. "
            "Complete the OAuth installation flow first."
        )
    return row
