"""Slack App OAuth, delivery, and interactive actions service — M58.5/M58.6.

Provides (M58.5):
  - HMAC-SHA256 state tokens for CSRF protection (mirroring github_app.py)
  - OAuth exchange: code → bot token
  - Encrypted bot token storage
  - Channel listing and channel selection
  - Test message delivery via chat.postMessage
  - Slack App message delivery (used by notification_service)
  - Disconnect (remove App installation from workspace)

Provides (M58.6):
  - Request signature verification (SLACK_SIGNING_SECRET / HMAC-SHA256)
  - Block Kit interactive alert messages (buttons: Open Change, Acknowledge,
    Snooze 24h, View Remediation Preview)
  - Interactive action routing (POST /slack/actions)
  - Acknowledge / Snooze from Slack (ConfigTrace review state only)

Security constraints
--------------------
* Bot tokens are AES-256-GCM encrypted at rest.  The plaintext token is
  NEVER stored, logged, or returned in any API response.
* State tokens are HMAC-signed and expire in 10 minutes.
* State tokens bind to the requesting user_id and workspace_id; a mismatch
  is treated as a CSRF attack.
* SLACK_CLIENT_SECRET and SLACK_SIGNING_SECRET are NEVER logged.
* This module never applies configuration changes to any monitored provider.
* Interactive actions only update ConfigTrace review state (acknowledge/snooze).
  No provider resources are mutated.

Slack OAuth scopes required
---------------------------
  chat:write          — post messages as the bot in channels it is a member of
  chat:write.public   — post messages to any public channel without first being
                        invited (required because users select an alert channel
                        in our UI without `/invite @ConfigTrace`); without this
                        scope Slack returns `not_in_channel` on chat.postMessage
  channels:read       — list public channels so the channel picker can populate
  groups:read         — list private channels the bot has been added to
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

    # Order matters only for readability — Slack treats this as an unordered
    # comma-separated set. `chat:write.public` is what fixes the
    # `not_in_channel` error when posting to a channel the bot has not been
    # explicitly invited to.
    scopes = "chat:write,chat:write.public,channels:read,groups:read"
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


# ════════════════════════════════════════════════════════════════════════════════
# M58.6 — Slack interactive actions
# ════════════════════════════════════════════════════════════════════════════════

# ── Slack request signature verification ─────────────────────────────────────

_REPLAY_WINDOW_SECONDS = 300  # 5 minutes — reject stale timestamps


def verify_request_signature(
    signing_secret: str,
    timestamp: str,
    body: bytes,
    signature: str,
) -> bool:
    """Verify a Slack request using HMAC-SHA256.

    Algorithm:
    1. Reject if ``|now - timestamp| > REPLAY_WINDOW_SECONDS``.
    2. Compute: ``base = f"v0:{timestamp}:{body_text}"``
    3. ``expected = "v0=" + HMAC(signing_secret, base, SHA256).hexdigest()``
    4. Constant-time compare: ``expected == signature``.

    Security:
    * Uses ``hmac.compare_digest`` to prevent timing attacks.
    * Timestamps are checked against the current time to prevent replay.
    * SLACK_SIGNING_SECRET is NEVER logged.

    Args:
        signing_secret: Slack App signing secret (from config).
        timestamp:      Value of ``X-Slack-Request-Timestamp`` header.
        body:           Raw request body bytes.
        signature:      Value of ``X-Slack-Signature`` header.

    Returns:
        True if signature is valid and timestamp is fresh.
    """
    # ── Reject stale / missing timestamp ──────────────────────────────────────
    try:
        ts_int = int(timestamp)
    except (ValueError, TypeError):
        return False

    age = abs(int(time.time()) - ts_int)
    if age > _REPLAY_WINDOW_SECONDS:
        return False

    # ── Compute expected signature ────────────────────────────────────────────
    try:
        body_text = body.decode("utf-8", errors="replace")
    except Exception:
        return False

    base_string = f"v0:{timestamp}:{body_text}"
    computed_mac = hmac_lib.new(
        signing_secret.encode("utf-8"),
        base_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    expected_sig = f"v0={computed_mac}"

    # ── Constant-time compare ─────────────────────────────────────────────────
    return hmac_lib.compare_digest(expected_sig, signature)


# ── Block Kit message composition ────────────────────────────────────────────

# Action IDs for interactive buttons.
ACTION_ACKNOWLEDGE = "configtrace_acknowledge_change"
ACTION_SNOOZE_24H = "configtrace_snooze_change_24h"
ACTION_OPEN_CHANGE = "configtrace_open_change"
ACTION_VIEW_REMEDIATION = "configtrace_view_remediation"

_RISK_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "⚪",
}


def compose_alert_blocks(
    change: Any,
    integration_name: str,
    provider: str,
    base_url: str,
) -> list[dict]:
    """Build Slack Block Kit blocks for a single high/critical change.

    Includes:
    - Risk badge + record identifier + field path
    - Risk reason
    - Compact remediation summary (M58.4, fail-open)
    - Four buttons: Open Change, Acknowledge, Snooze 24h, View Remediation

    Security:
    - No raw prev_value / new_value forwarded.
    - No secrets, tokens, or customer PII.
    - No provider-mutation commands.

    Args:
        change:           Change ORM row or dict with standard fields.
        integration_name: Display name of the integration.
        provider:         Provider string (e.g. "aws").
        base_url:         ConfigTrace frontend base URL (no trailing slash).

    Returns:
        List of Slack block dicts.
    """
    from app.services.remediation_summary_service import build_alert_remediation_summary

    change_id = str(_get(change, "id") or "")
    risk_level = _s(_get(change, "risk_level")) or "unknown"
    risk_reason = _s(_get(change, "risk_reason")) or ""
    record_id = _s(_get(change, "record_identifier")) or "unknown"
    field_path = _s(_get(change, "field_path")) or ""
    risk_upper = risk_level.upper()
    emoji = _RISK_EMOJI.get(risk_level, "⚪")

    change_url = f"{base_url}/changes/{change_id}"
    remediation_url = f"{base_url}/changes/{change_id}#section-remediation"

    # ── Action button value (just change_id — workspace validated via team_id) ─
    action_value = json.dumps({"change_id": change_id})

    # ── Header block ──────────────────────────────────────────────────────────
    header_text = (
        f"{emoji} *{risk_upper}: Configuration change detected*\n"
        f"_{integration_name}_ · {provider}"
    )

    # ── Change detail block ───────────────────────────────────────────────────
    detail_text = f"*{record_id}*"
    if field_path:
        detail_text += f" — `{field_path}`"
    if risk_reason:
        detail_text += f"\n{risk_reason}"

    blocks: list[dict] = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": header_text},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": detail_text},
        },
    ]

    # ── Remediation summary block (M58.4, fail-open) ──────────────────────────
    try:
        rem = build_alert_remediation_summary(change)
        if rem and rem.get("available"):
            rem_lines = [f"*Suggested fix:* {rem['title']}"]
            summary = rem.get("summary", "")
            if summary:
                rem_lines.append(summary)
            if rem.get("remediation_preview_available"):
                rem_lines.append("_Remediation preview available in ConfigTrace._")
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "\n".join(rem_lines)},
            })
    except Exception:
        pass  # fail-open: omit remediation block on error

    # ── Divider ───────────────────────────────────────────────────────────────
    blocks.append({"type": "divider"})

    # ── Action buttons ────────────────────────────────────────────────────────
    blocks.append({
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Open Change", "emoji": True},
                "url": change_url,
                "action_id": ACTION_OPEN_CHANGE,
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Acknowledge", "emoji": True},
                "action_id": ACTION_ACKNOWLEDGE,
                "value": action_value,
                "style": "primary",
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Snooze 24h", "emoji": True},
                "action_id": ACTION_SNOOZE_24H,
                "value": action_value,
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View Remediation", "emoji": True},
                "url": remediation_url,
                "action_id": ACTION_VIEW_REMEDIATION,
            },
        ],
    })

    return blocks


def compose_multi_alert_blocks(
    changes: list[Any],
    integration_name: str,
    provider: str,
    base_url: str,
) -> list[dict]:
    """Build Slack blocks for 2–5 changes (no per-change action buttons).

    Lists each change as a section.  A footer links to the full timeline.
    For multi-change alerts, only a single "Open Timeline" link is provided.
    Per-change action buttons are omitted to keep the message manageable.

    Args:
        changes:          List of Change rows (1–5 recommended; truncated at 5).
        integration_name: Display name of the integration.
        provider:         Provider string.
        base_url:         ConfigTrace frontend base URL.

    Returns:
        List of Slack block dicts.
    """
    n = len(changes)
    has_critical = any(_s(_get(c, "risk_level")) == "critical" for c in changes)
    risk_word = "critical" if has_critical else "high-risk"

    header_text = (
        f"🔔 *{n} {risk_word} configuration changes detected*\n"
        f"_{integration_name}_ · {provider}"
    )

    blocks: list[dict] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": header_text}},
        {"type": "divider"},
    ]

    for c in changes[:5]:
        risk_level = _s(_get(c, "risk_level")) or "unknown"
        emoji = _RISK_EMOJI.get(risk_level, "⚪")
        record_id = _s(_get(c, "record_identifier")) or "unknown"
        field_path = _s(_get(c, "field_path")) or ""
        risk_reason = _s(_get(c, "risk_reason")) or ""
        change_id = str(_get(c, "id") or "")

        line = f"{emoji} *{record_id}*"
        if field_path:
            line += f" — `{field_path}`"
        if risk_reason:
            line += f"\n  _{risk_reason}_"

        url_text = f" <{base_url}/changes/{change_id}|View>"
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": line + url_text},
        })

    if n > 5:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"_…and {n - 5} more change(s)._"},
        })

    blocks.append({"type": "divider"})
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"<{base_url}|Open ConfigTrace> to review and triage all changes.",
        },
    })

    return blocks


def send_interactive_message(
    bot_token: str,
    channel_id: str,
    blocks: list[dict],
    fallback_text: str,
) -> None:
    """Send a Block Kit message to a Slack channel.

    Args:
        bot_token:     Plaintext Slack bot token.  NEVER log this value.
        channel_id:    Slack channel ID.
        blocks:        Block Kit blocks list.
        fallback_text: Plain-text fallback (shown in notifications / old clients).

    Raises:
        RuntimeError: On Slack API error or network failure.
    """
    payload = {
        "channel": channel_id,
        "text": fallback_text,
        "blocks": blocks,
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
            f"Slack API error sending interactive message (HTTP {resp.status_code})."
        )

    body = resp.json()
    if not body.get("ok"):
        error_code = body.get("error", "unknown_error")
        raise RuntimeError(f"Slack chat.postMessage error: {error_code}")


def dispatch_alert_message(
    *,
    bot_token: str,
    channel_id: str,
    changes: list[Any],
    integration_name: str,
    provider: str,
    fallback_text: str,
    base_url: str,
) -> None:
    """Dispatch an interactive Slack alert for one or more changes.

    Routing:
    - 1 change:    Full interactive blocks with action buttons.
    - 2–5 changes: Summary blocks (no per-change buttons).
    - >5 changes:  Plain text fallback (send_message).

    Args:
        bot_token:        Plaintext Slack bot token.  NEVER log.
        channel_id:       Slack channel ID.
        changes:          List of qualifying Change rows.
        integration_name: Display name of the integration.
        provider:         Provider string.
        fallback_text:    Plain-text fallback text.
        base_url:         ConfigTrace frontend base URL.

    Raises:
        RuntimeError: On Slack API error.
    """
    n = len(changes)

    if n == 1:
        blocks = compose_alert_blocks(
            change=changes[0],
            integration_name=integration_name,
            provider=provider,
            base_url=base_url,
        )
        send_interactive_message(bot_token, channel_id, blocks, fallback_text)
    elif n <= 5:
        blocks = compose_multi_alert_blocks(
            changes=changes,
            integration_name=integration_name,
            provider=provider,
            base_url=base_url,
        )
        send_interactive_message(bot_token, channel_id, blocks, fallback_text)
    else:
        # >5 changes — fall back to plain text
        send_message(bot_token, channel_id, fallback_text)


# ── Workspace lookup by Slack team_id ────────────────────────────────────────

def get_workspace_by_team_id(
    team_id: str,
    db: Session,
) -> "uuid.UUID | None":
    """Return the workspace_id that has this Slack team installed, or None.

    Used by the actions endpoint to authenticate incoming action payloads.

    Args:
        team_id: Slack team/workspace ID from the action payload.
        db:      Active SQLAlchemy session.

    Returns:
        Workspace UUID if found, else None.
    """
    row = (
        db.query(WorkspaceNotificationSettings)
        .filter(
            WorkspaceNotificationSettings.slack_team_id == team_id,
            WorkspaceNotificationSettings.slack_bot_token_encrypted.isnot(None),
        )
        .first()
    )
    if row is None:
        return None
    return row.workspace_id


def get_change_for_workspace(
    change_id_str: str,
    workspace_id: "uuid.UUID",
    db: Session,
) -> "Any | None":
    """Look up a Change and verify it belongs to the given workspace.

    Returns the Change row if found and workspace-verified, else None.

    Security: workspace scope is verified by joining Change → Integration.
    """
    from app.models.change import Change
    from app.models.integration import Integration

    try:
        change_id = uuid.UUID(change_id_str)
    except (ValueError, AttributeError):
        return None

    return (
        db.query(Change)
        .join(Integration, Change.integration_id == Integration.id)
        .filter(
            Change.id == change_id,
            Integration.workspace_id == workspace_id,
        )
        .first()
    )


# ── Slack action handlers ─────────────────────────────────────────────────────

def acknowledge_change_from_slack(
    change_id_str: str,
    workspace_id: "uuid.UUID",
    slack_user_id: str,
    db: Session,
) -> str:
    """Acknowledge a change from a Slack button action.

    Uses the workspace installer's ConfigTrace user ID as the actor.  The
    note records the Slack user ID so the action is attributable.

    This only updates ConfigTrace review state — no provider changes are made.

    Args:
        change_id_str: String UUID of the change.
        workspace_id:  Workspace UUID (derived from Slack team_id).
        slack_user_id: Slack user ID of the person who clicked the button.
        db:            Active SQLAlchemy session.

    Returns:
        Human-readable status string for the Slack response.

    Raises:
        RuntimeError: If the change is not found or the action fails.
    """
    from app.services.change_review_service import acknowledge_change

    change = get_change_for_workspace(change_id_str, workspace_id, db)
    if change is None:
        raise RuntimeError("Change not found or does not belong to this workspace.")

    actor_user_id = _get_actor_user_id(workspace_id, change, db)
    note = f"Acknowledged from Slack by {slack_user_id}."

    acknowledge_change(change, actor_user_id, db, note=note)
    logger.info(
        "slack_actions: acknowledged  change=%s  slack_user=%s",
        change_id_str,
        slack_user_id,
    )
    return "✓ Acknowledged in ConfigTrace."


def snooze_change_from_slack(
    change_id_str: str,
    workspace_id: "uuid.UUID",
    slack_user_id: str,
    db: Session,
    *,
    hours: int = 24,
) -> str:
    """Snooze a change from a Slack button action.

    This only updates ConfigTrace review state — no provider changes are made.

    Args:
        change_id_str: String UUID of the change.
        workspace_id:  Workspace UUID (derived from Slack team_id).
        slack_user_id: Slack user ID of the person who clicked the button.
        db:            Active SQLAlchemy session.
        hours:         Number of hours to snooze (default: 24).

    Returns:
        Human-readable status string for the Slack response.

    Raises:
        RuntimeError: If the change is not found or the action fails.
    """
    from datetime import timedelta
    from app.services.change_review_service import snooze_change

    change = get_change_for_workspace(change_id_str, workspace_id, db)
    if change is None:
        raise RuntimeError("Change not found or does not belong to this workspace.")

    actor_user_id = _get_actor_user_id(workspace_id, change, db)
    reason = f"Snoozed for {hours}h from Slack by {slack_user_id}."
    until = datetime.now(timezone.utc) + timedelta(hours=hours)

    snooze_change(change, actor_user_id, db, until=until, reason=reason)
    logger.info(
        "slack_actions: snoozed  change=%s  hours=%d  slack_user=%s",
        change_id_str,
        hours,
        slack_user_id,
    )
    return f"⏸ Snoozed for {hours} hours in ConfigTrace."


def _get_actor_user_id(
    workspace_id: "uuid.UUID",
    change: "Any",
    db: Session,
) -> "uuid.UUID":
    """Derive a ConfigTrace user ID to use as the actor for Slack actions.

    Preference order:
    1. The user who installed the Slack App (stored in notification settings).
    2. The Change's own user_id (change creator / owner).

    This avoids creating fake/synthetic user IDs.  The review note always
    records the Slack user ID for attribution.
    """
    from app.services.notification_service import get_or_create_notification_settings

    try:
        row = get_or_create_notification_settings(workspace_id, db)
        installer_id = getattr(row, "slack_installed_by_user_id", None)
        if installer_id is not None:
            return installer_id
    except Exception:
        pass

    # Fallback: change owner
    return change.user_id


# ── Interactive action router ─────────────────────────────────────────────────

def handle_action(payload: dict, db: Session) -> dict:
    """Route an incoming Slack interactive action to the appropriate handler.

    Called by ``POST /slack/actions`` after signature verification.

    Validates:
    - team_id maps to an installed workspace
    - change_id belongs to that workspace
    - action_id is a known safe action

    Returns a dict suitable for a Slack response body (200 OK):
    ``{"response_type": "ephemeral", "text": "..."}``
    or ``{"response_type": "in_channel", "replace_original": False, "text": "..."}``

    Never raises — always returns a safe response.  Errors are surfaced as
    user-facing ephemeral messages.
    """
    try:
        team_id: str = (payload.get("team") or {}).get("id", "")
        slack_user_id: str = (payload.get("user") or {}).get("id", "unknown")
        actions: list = payload.get("actions") or []

        if not actions:
            return _ephemeral("No action found in payload.")

        action = actions[0]
        action_id: str = action.get("action_id", "")
        raw_value: str = action.get("value", "")

        # ── Skip URL-only buttons (no server-side action needed) ────────────
        if action_id in (ACTION_OPEN_CHANGE, ACTION_VIEW_REMEDIATION):
            # These are link buttons — Slack sends the event but no action needed.
            return _ephemeral("Opening in ConfigTrace…")

        # ── Validate team → workspace ────────────────────────────────────────
        if not team_id:
            return _ephemeral("Could not process action: missing team context.")

        workspace_id = get_workspace_by_team_id(team_id, db)
        if workspace_id is None:
            logger.warning(
                "slack_actions: unknown team_id=%s — no installation found",
                team_id,
            )
            return _ephemeral(
                "ConfigTrace could not complete this action. "
                "The Slack App may no longer be installed in this workspace."
            )

        # ── Parse action value ───────────────────────────────────────────────
        try:
            value_obj = json.loads(raw_value)
            change_id_str = str(value_obj.get("change_id", ""))
        except (json.JSONDecodeError, AttributeError):
            return _ephemeral("Could not complete this action. Please open ConfigTrace.")

        if not change_id_str:
            return _ephemeral("Could not complete this action. Please open ConfigTrace.")

        # ── Route to handler ─────────────────────────────────────────────────
        if action_id == ACTION_ACKNOWLEDGE:
            msg = acknowledge_change_from_slack(
                change_id_str, workspace_id, slack_user_id, db
            )
            return _ephemeral(msg)

        elif action_id == ACTION_SNOOZE_24H:
            msg = snooze_change_from_slack(
                change_id_str, workspace_id, slack_user_id, db, hours=24
            )
            return _ephemeral(msg)

        else:
            logger.warning(
                "slack_actions: unknown action_id=%r  team=%s",
                action_id,
                team_id,
            )
            return _ephemeral("Unknown action. Please open ConfigTrace.")

    except RuntimeError as exc:
        # Safe user-facing error (e.g. change not found, workspace mismatch).
        logger.warning(
            "slack_actions: action failed  error=%r",
            str(exc)[:200],
        )
        return _ephemeral(
            f"ConfigTrace could not complete this action: {exc} "
            "Open the change in ConfigTrace to take action."
        )
    except Exception as exc:
        # Unexpected error — log type only, not message (may contain PII).
        logger.error(
            "slack_actions: unexpected error  error_type=%r",
            type(exc).__name__,
        )
        return _ephemeral(
            "An unexpected error occurred. "
            "Open the change in ConfigTrace to take action."
        )


def _ephemeral(text: str) -> dict:
    """Return a Slack ephemeral response body."""
    return {"response_type": "ephemeral", "text": text}


# ── Private helper ─────────────────────────────────────────────────────────────

def _get(obj: Any, key: str) -> Any:
    """Return obj[key] for dicts, or getattr(obj, key, None) for objects."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _s(value: Any) -> str:
    """Safely coerce to lowercase string; returns '' for non-strings."""
    return value.lower() if isinstance(value, str) else ""


# ── M60.12 — Security exposure Slack messages ─────────────────────────────────
# Metadata-only: severity, provider, status, title, and navigation links. NEVER
# includes evidence blobs, secrets, tokens, payloads, or raw rules. Careful
# wording: "Security exposure opened/resolved" — never "breach"/"attack".

_SECURITY_EVENT_HEADLINE = {
    "security_exposure_opened": "Security exposure opened",
    "security_exposure_reopened": "Security exposure re-opened",
    "security_exposure_resolved": "Security exposure resolved",
}

_SECURITY_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def compose_security_exposure_blocks(*, event: Any, base_url: str) -> list[dict]:
    """Build Block Kit blocks for a security exposure lifecycle event.

    ``event`` is a SecurityExposureEvent (duck-typed here to avoid a hard import
    cycle). Only metadata fields are read.
    """
    headline = _SECURITY_EVENT_HEADLINE.get(event.event_type, "Security exposure")
    severity = (event.severity or "").lower()
    emoji = _SECURITY_SEVERITY_EMOJI.get(severity, "⚪")
    base = base_url.rstrip("/")
    detail_url = f"{base}{event.detail_path}"

    detail_lines = [
        f"*Severity:* {severity.upper() or 'UNKNOWN'}",
        f"*Provider:* {event.provider}",
        f"*Status:* {event.status}",
    ]

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} {headline}", "emoji": True},
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{event.title}*"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(detail_lines)}},
    ]

    action_elements: list[dict] = [
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "Open exposure", "emoji": True},
            "url": detail_url,
        }
    ]
    if getattr(event, "linked_change_id", None):
        action_elements.append(
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View linked drift", "emoji": True},
                "url": f"{base}/changes/{event.linked_change_id}",
            }
        )
    blocks.append({"type": "actions", "elements": action_elements})
    return blocks


def dispatch_security_exposure_alert(
    *,
    bot_token: str,
    channel_id: str,
    event: Any,
    base_url: str,
) -> None:
    """Post a security exposure event to a Slack channel (metadata-only).

    Raises RuntimeError on Slack API / network failure (callers must guard).
    """
    headline = _SECURITY_EVENT_HEADLINE.get(event.event_type, "Security exposure")
    fallback = f"{headline}: {event.title} ({(event.severity or '').upper()})"
    blocks = compose_security_exposure_blocks(event=event, base_url=base_url)
    send_interactive_message(bot_token, channel_id, blocks, fallback)
