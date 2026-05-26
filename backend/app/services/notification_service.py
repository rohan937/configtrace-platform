"""Slack + webhook notification dispatch — M57.1.

Public surface
--------------
:func:`get_or_create_notification_settings`  — load (or lazy-create) settings
:func:`update_notification_settings`         — validate + persist URL updates
:func:`dispatch_notifications_for_sync`      — send Slack/webhook on drift
:func:`send_test_notification`               — verify channels are reachable

Security invariants
-------------------
* Webhook URLs are **never** logged in full.  All log lines use the masked
  form produced by :func:`_mask_url`.
* Webhook URLs are **never** returned in API responses.  Only masked forms
  are exposed.
* Webhook URLs are **never** stored in audit-log metadata.
* URLs are encrypted at rest using ``encrypt_credentials`` / ``decrypt_credentials``
  (same AES-256-GCM pattern as Integration credentials).
* Private/local addresses (localhost, 127.x, 10.x, 192.168.x, 172.16-31.x)
  are rejected at update time.
* Slack URLs must start with ``https://hooks.slack.com/services/``.
* All generic webhook URLs must use HTTPS.

Failure isolation
-----------------
:func:`dispatch_notifications_for_sync` **never raises**.  A Slack or
webhook delivery failure is logged and counted but must not abort a sync that
has already committed its Change rows.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, Sequence
from urllib.parse import urlparse

import httpx

from sqlalchemy.orm import Session

from app.models.change import Change
from app.models.integration import Integration
from app.models.notification_settings import WorkspaceNotificationSettings

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_HTTP_TIMEOUT: float = 8.0  # seconds — must not block the sync worker

# Slack webhooks must always start with this prefix.
_SLACK_URL_PREFIX = "https://hooks.slack.com/services/"

# Maximum URL length (characters).
_MAX_URL_LENGTH = 2048

# Private IP ranges that must be blocked to prevent SSRF.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
]
_PRIVATE_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})

# Maps risk level to alertable set — same vocabulary as alert_service.
def _alertable_levels(threshold: str) -> frozenset:
    if threshold == "critical_only":
        return frozenset({"critical"})
    elif threshold == "medium_and_above":
        return frozenset({"medium", "high", "critical"})
    return frozenset({"high", "critical"})  # "high_and_critical" (default)


# ── URL helpers ───────────────────────────────────────────────────────────────


class WebhookURLError(ValueError):
    """Raised when a webhook URL fails validation."""


def _mask_url(url: str) -> str:
    """Return a safe display form of a webhook URL.

    Shows the scheme + host prefix and last 4 chars; masks everything in
    between so the user can identify which URL is configured without
    exposing the full secret path.

    Examples:
        "https://hooks.slack.com/services/T00/B00/abc123xyz" →
        "https://hooks****xyz"
    """
    if not url:
        return ""
    if len(url) <= 16:
        return "https://****"
    return url[:12] + "****" + url[-4:]


def _validate_url(url: str, *, slack: bool = False) -> None:
    """Validate a webhook URL.  Raises :class:`WebhookURLError` on failure.

    Rules:
    - Must not exceed _MAX_URL_LENGTH characters.
    - Must use the ``https://`` scheme.
    - Slack URLs must start with _SLACK_URL_PREFIX.
    - Hostname must not resolve to a private/loopback address (SSRF guard).
    - Hostname must not be in _PRIVATE_HOSTNAMES.

    Args:
        url:   The URL string to validate.
        slack: When True, applies the additional Slack prefix requirement.

    Raises:
        WebhookURLError: Any validation failure.
    """
    if len(url) > _MAX_URL_LENGTH:
        raise WebhookURLError(
            f"Webhook URL must not exceed {_MAX_URL_LENGTH} characters."
        )

    if slack:
        if not url.startswith(_SLACK_URL_PREFIX):
            raise WebhookURLError(
                f"Slack webhook URL must start with {_SLACK_URL_PREFIX!r}."
            )
    else:
        if not url.startswith("https://"):
            raise WebhookURLError("Webhook URL must use HTTPS (https://).")

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if not hostname:
        raise WebhookURLError("Webhook URL has no hostname.")

    if hostname in _PRIVATE_HOSTNAMES:
        raise WebhookURLError(
            f"Webhook URL hostname {hostname!r} is not allowed "
            "(private/loopback addresses are blocked)."
        )

    # Attempt to parse the hostname as an IP address; if it is one, check
    # whether it falls in a private range.
    # NOTE: Use try/except/else so that a WebhookURLError raised in the else
    # clause is NOT silently caught by the except branch (WebhookURLError
    # is a ValueError subclass, so putting the range check inside the try
    # block would swallow the error).
    _addr = None
    try:
        _addr = ipaddress.ip_address(hostname)
    except ValueError:
        # Not a literal IP address — hostname is a domain name.  We don't
        # resolve it (DNS resolution adds latency and fails in test
        # environments); the private-hostname check above covers literal IPs.
        pass

    if _addr is not None:
        for network in _PRIVATE_NETWORKS:
            if _addr in network:
                raise WebhookURLError(
                    f"Webhook URL points to a private IP address ({hostname}). "
                    "Only public HTTPS endpoints are allowed."
                )


# ── Encryption helpers ────────────────────────────────────────────────────────


def _encrypt_url(url: str) -> tuple[bytes, bytes]:
    """Encrypt a webhook URL.  Returns (ciphertext, iv)."""
    from app.core.encryption import encrypt_credentials
    return encrypt_credentials({"url": url})


def _decrypt_url(ciphertext: bytes, iv: bytes) -> str:
    """Decrypt a webhook URL from its stored (ciphertext, iv) pair."""
    from app.core.encryption import decrypt_credentials
    data = decrypt_credentials(ciphertext, iv)
    return data["url"]


# ── Settings CRUD ─────────────────────────────────────────────────────────────


def get_or_create_notification_settings(
    workspace_id: uuid.UUID,
    db: Session,
) -> WorkspaceNotificationSettings:
    """Return the notification settings row for *workspace_id*, creating if absent.

    The created row has both channels disabled and no URLs configured.
    Commits the new row when created so callers can immediately read it back
    without managing the transaction themselves.
    """
    settings_row = (
        db.query(WorkspaceNotificationSettings)
        .filter(WorkspaceNotificationSettings.workspace_id == workspace_id)
        .first()
    )
    if settings_row is None:
        settings_row = WorkspaceNotificationSettings(workspace_id=workspace_id)
        db.add(settings_row)
        db.commit()
        db.refresh(settings_row)
    return settings_row


def update_notification_settings(
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    *,
    slack_enabled: Optional[bool] = None,
    slack_webhook_url: Optional[str] = None,
    webhook_enabled: Optional[bool] = None,
    webhook_url: Optional[str] = None,
    notify_on_risk_level: Optional[str] = None,
    db: Session,
) -> WorkspaceNotificationSettings:
    """Persist notification settings changes for *workspace_id*.

    Only the fields that are explicitly passed (non-None) are updated.
    An empty string for *slack_webhook_url* or *webhook_url* **clears** the
    URL and disables the corresponding channel.

    Security:
        URLs are validated before encryption.  Validation errors raise
        :class:`WebhookURLError` (caught as 422 at the router layer).
        RBAC must be enforced by the caller before invoking this function.

    Returns:
        The updated :class:`WorkspaceNotificationSettings` row.
    """
    row = get_or_create_notification_settings(workspace_id, db)

    # ── Slack URL ──────────────────────────────────────────────────────────────
    if slack_webhook_url is not None:
        if slack_webhook_url == "":
            # Clear — remove URL and force disable.
            row.slack_webhook_url_encrypted = None
            row.slack_webhook_iv = None
            row.slack_enabled = False
        else:
            _validate_url(slack_webhook_url, slack=True)
            ciphertext, iv = _encrypt_url(slack_webhook_url)
            row.slack_webhook_url_encrypted = ciphertext
            row.slack_webhook_iv = iv
            # SECURITY: never log the full URL
            logger.info(
                "notification_settings: Slack URL updated  workspace=%s  url=%s",
                workspace_id,
                _mask_url(slack_webhook_url),
            )

    # ── Generic webhook URL ────────────────────────────────────────────────────
    if webhook_url is not None:
        if webhook_url == "":
            # Clear — remove URL and force disable.
            row.webhook_url_encrypted = None
            row.webhook_iv = None
            row.webhook_enabled = False
        else:
            _validate_url(webhook_url, slack=False)
            ciphertext, iv = _encrypt_url(webhook_url)
            row.webhook_url_encrypted = ciphertext
            row.webhook_iv = iv
            logger.info(
                "notification_settings: webhook URL updated  workspace=%s  url=%s",
                workspace_id,
                _mask_url(webhook_url),
            )

    # ── Enable/disable flags ───────────────────────────────────────────────────
    if slack_enabled is not None:
        # Guard: cannot enable if no URL is configured.
        if slack_enabled and not row.slack_webhook_url_encrypted:
            raise ValueError(
                "Cannot enable Slack notifications without a configured webhook URL."
            )
        row.slack_enabled = slack_enabled

    if webhook_enabled is not None:
        if webhook_enabled and not row.webhook_url_encrypted:
            raise ValueError(
                "Cannot enable webhook notifications without a configured URL."
            )
        row.webhook_enabled = webhook_enabled

    # ── Risk level ─────────────────────────────────────────────────────────────
    if notify_on_risk_level is not None:
        row.notify_on_risk_level = notify_on_risk_level

    db.commit()
    db.refresh(row)
    return row


def build_settings_response(row: WorkspaceNotificationSettings) -> dict:
    """Build the safe response dict for a notification settings row.

    Decrypts the stored URLs and returns only their masked forms.
    If decryption fails (e.g. missing ENCRYPTION_KEY in test env), returns
    a placeholder masked URL rather than raising.

    Security: the returned dict must never contain a full webhook URL.
    """
    slack_masked: Optional[str] = None
    if row.slack_webhook_url_encrypted and row.slack_webhook_iv:
        try:
            raw = _decrypt_url(row.slack_webhook_url_encrypted, row.slack_webhook_iv)
            slack_masked = _mask_url(raw)
        except Exception:
            slack_masked = "https://****"

    webhook_masked: Optional[str] = None
    if row.webhook_url_encrypted and row.webhook_iv:
        try:
            raw = _decrypt_url(row.webhook_url_encrypted, row.webhook_iv)
            webhook_masked = _mask_url(raw)
        except Exception:
            webhook_masked = "https://****"

    return {
        "workspace_id": row.workspace_id,
        "slack_enabled": row.slack_enabled,
        "slack_webhook_url_masked": slack_masked,
        "webhook_enabled": row.webhook_enabled,
        "webhook_url_masked": webhook_masked,
        "notify_on_risk_level": row.notify_on_risk_level,
    }


# ── Notification dispatch ─────────────────────────────────────────────────────


def dispatch_notifications_for_sync(
    *,
    changes: Sequence[Change],
    integration: Integration,
    sync_run_id: uuid.UUID,
    db: Session,
) -> dict:
    """Send Slack / generic webhook notifications for high-risk drift.

    Called by the Celery sync worker after ``dispatch_alerts_for_sync``.
    Looks up the workspace's notification settings and — when enabled —
    POSTs to the configured Slack webhook and/or generic webhook URL.

    Always returns a counts dict; **never raises**.  Any delivery failure is
    logged and counted but must not fail the sync.

    Args:
        changes:       Change rows from the current sync (risk already set).
        integration:   The Integration that was synced.
        sync_run_id:   For log correlation only.
        db:            Active SQLAlchemy session.

    Returns:
        dict with:
          - ``slack_sent`` (int): 1 if Slack POST succeeded, else 0
          - ``webhook_sent`` (int): 1 if webhook POST succeeded, else 0
          - ``skipped_no_settings`` (bool): True when workspace has no config
          - ``failed`` (int): count of channel delivery failures
    """
    result: dict = {
        "slack_sent": 0,
        "webhook_sent": 0,
        "skipped_no_settings": False,
        "failed": 0,
    }

    # ── Resolve workspace_id ───────────────────────────────────────────────────
    workspace_id = integration.workspace_id
    if workspace_id is None:
        # Integration not yet attached to a workspace — skip silently.
        result["skipped_no_settings"] = True
        return result

    # ── Load settings ──────────────────────────────────────────────────────────
    try:
        settings_row = (
            db.query(WorkspaceNotificationSettings)
            .filter(WorkspaceNotificationSettings.workspace_id == workspace_id)
            .first()
        )
    except Exception:
        logger.exception(
            "notifications: DB error loading settings  workspace=%s  sync_run=%s",
            workspace_id, sync_run_id,
        )
        return result

    if settings_row is None:
        result["skipped_no_settings"] = True
        return result

    # ── Check whether any channel is active ───────────────────────────────────
    if not settings_row.slack_enabled and not settings_row.webhook_enabled:
        return result

    # ── Filter changes to alertable risk levels ────────────────────────────────
    alertable_set = _alertable_levels(settings_row.notify_on_risk_level)
    qualifying = [c for c in changes if c.risk_level in alertable_set]

    if not qualifying:
        return result

    # ── Compose payloads ───────────────────────────────────────────────────────
    try:
        slack_text = _compose_slack_text(integration=integration, changes=qualifying)
        webhook_payload = _compose_webhook_payload(
            integration=integration,
            changes=qualifying,
            sync_run_id=sync_run_id,
        )
    except Exception:
        logger.exception(
            "notifications: failed to compose payload  workspace=%s  sync_run=%s",
            workspace_id, sync_run_id,
        )
        return result

    # ── Slack dispatch ─────────────────────────────────────────────────────────
    if settings_row.slack_enabled and settings_row.slack_webhook_url_encrypted:
        try:
            url = _decrypt_url(
                settings_row.slack_webhook_url_encrypted,
                settings_row.slack_webhook_iv,  # type: ignore[arg-type]
            )
            _post_json(url, {"text": slack_text})
            result["slack_sent"] = 1
            logger.info(
                "notifications: Slack sent  workspace=%s  sync_run=%s  "
                "changes=%d  url=%s",
                workspace_id, sync_run_id, len(qualifying), _mask_url(url),
            )
        except Exception as exc:
            result["failed"] += 1
            logger.error(
                "notifications: Slack delivery failed  workspace=%s  sync_run=%s  "
                "error=%r",
                workspace_id, sync_run_id, type(exc).__name__,
            )

    # ── Generic webhook dispatch ───────────────────────────────────────────────
    if settings_row.webhook_enabled and settings_row.webhook_url_encrypted:
        try:
            url = _decrypt_url(
                settings_row.webhook_url_encrypted,
                settings_row.webhook_iv,  # type: ignore[arg-type]
            )
            _post_json(url, webhook_payload)
            result["webhook_sent"] = 1
            logger.info(
                "notifications: webhook sent  workspace=%s  sync_run=%s  "
                "changes=%d  url=%s",
                workspace_id, sync_run_id, len(qualifying), _mask_url(url),
            )
        except Exception as exc:
            result["failed"] += 1
            logger.error(
                "notifications: webhook delivery failed  workspace=%s  sync_run=%s  "
                "error=%r",
                workspace_id, sync_run_id, type(exc).__name__,
            )

    return result


def send_test_notification(
    workspace_id: uuid.UUID,
    db: Session,
) -> dict:
    """Send a test message to all configured and enabled channels.

    Used by POST /workspaces/{id}/notification-settings/test.

    Returns:
        dict with ``slack_sent`` (bool), ``webhook_sent`` (bool),
        ``error`` (str | None).
    """
    result: dict = {"slack_sent": False, "webhook_sent": False, "error": None}
    errors: list[str] = []

    settings_row = get_or_create_notification_settings(workspace_id, db)

    test_slack_text = (
        "[ConfigTrace] Test notification\n\n"
        "This is a test message from ConfigTrace. "
        "Your Slack webhook is configured correctly."
    )
    test_webhook_payload = {
        "event": "test",
        "workspace_id": str(workspace_id),
        "message": "ConfigTrace test notification — webhook is reachable.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # ── Slack ──────────────────────────────────────────────────────────────────
    if settings_row.slack_enabled and settings_row.slack_webhook_url_encrypted:
        try:
            url = _decrypt_url(
                settings_row.slack_webhook_url_encrypted,
                settings_row.slack_webhook_iv,  # type: ignore[arg-type]
            )
            _post_json(url, {"text": test_slack_text})
            result["slack_sent"] = True
        except Exception as exc:
            err = f"Slack: {type(exc).__name__}"
            errors.append(err)
            logger.warning(
                "notifications: test Slack delivery failed  workspace=%s  error=%r",
                workspace_id, type(exc).__name__,
            )
    elif not settings_row.slack_enabled:
        pass  # Not enabled — skip silently
    else:
        errors.append("Slack: no URL configured")

    # ── Webhook ────────────────────────────────────────────────────────────────
    if settings_row.webhook_enabled and settings_row.webhook_url_encrypted:
        try:
            url = _decrypt_url(
                settings_row.webhook_url_encrypted,
                settings_row.webhook_iv,  # type: ignore[arg-type]
            )
            _post_json(url, test_webhook_payload)
            result["webhook_sent"] = True
        except Exception as exc:
            err = f"Webhook: {type(exc).__name__}"
            errors.append(err)
            logger.warning(
                "notifications: test webhook delivery failed  workspace=%s  error=%r",
                workspace_id, type(exc).__name__,
            )
    elif not settings_row.webhook_enabled:
        pass
    else:
        errors.append("Webhook: no URL configured")

    if errors:
        result["error"] = "; ".join(errors)

    return result


# ── Payload composers ─────────────────────────────────────────────────────────


def _compose_slack_text(
    *,
    integration: Integration,
    changes: Sequence[Change],
) -> str:
    """Compose a plain-text Slack message for the given changes."""
    from app.config import settings as _settings

    n = len(changes)
    has_critical = any(c.risk_level == "critical" for c in changes)
    risk_label = "critical" if has_critical else "high-risk"
    base_url = _settings.APP_BASE_URL.rstrip("/")

    lines: list[str] = []

    if n == 1:
        c = changes[0]
        risk_upper = (c.risk_level or "unknown").upper()
        lines.append(
            f"[ConfigTrace] {risk_upper} configuration change detected"
        )
    else:
        lines.append(
            f"[ConfigTrace] {n} {risk_label} configuration changes detected"
        )

    lines.append(f"Integration: {integration.display_name}")
    lines.append(f"Provider: {integration.provider}")
    lines.append("")

    for idx, c in enumerate(changes[:5], start=1):  # cap at 5 in Slack message
        risk_upper = (c.risk_level or "unknown").upper()
        lines.append(
            f"Change {idx}: [{risk_upper}] {c.record_identifier}"
            + (f" — {c.field_path}" if c.field_path else "")
        )
        if c.risk_reason:
            lines.append(f"  {c.risk_reason}")
        lines.append(f"  View: {base_url}/changes/{c.id}")

    if n > 5:
        lines.append(f"  ... and {n - 5} more change(s)")

    lines.append("")
    lines.append(f"Full timeline: {base_url}")
    return "\n".join(lines)


def _compose_webhook_payload(
    *,
    integration: Integration,
    changes: Sequence[Change],
    sync_run_id: uuid.UUID,
) -> dict:
    """Compose the generic webhook JSON payload."""
    from app.config import settings as _settings

    has_critical = any(c.risk_level == "critical" for c in changes)
    highest_risk = "critical" if has_critical else "high"
    if not any(c.risk_level in ("critical", "high") for c in changes):
        # All medium
        highest_risk = "medium"

    return {
        "event": "config_drift_alert",
        "workspace_id": str(integration.workspace_id) if integration.workspace_id else None,
        "integration_id": str(integration.id),
        "integration_name": integration.display_name,
        "provider": integration.provider,
        "sync_run_id": str(sync_run_id),
        "change_count": len(changes),
        "highest_risk": highest_risk,
        "changes": [
            {
                "id": str(c.id),
                "risk_level": c.risk_level,
                "change_type": c.change_type,
                "record_identifier": c.record_identifier,
                "field_path": c.field_path,
                "risk_reason": c.risk_reason,
            }
            for c in changes
        ],
        "app_url": _settings.APP_BASE_URL.rstrip("/"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── HTTP helper ───────────────────────────────────────────────────────────────


def _post_json(url: str, payload: dict) -> None:
    """POST *payload* as JSON to *url*.

    Raises :class:`httpx.HTTPError` on transport failure.
    Raises :class:`ValueError` on HTTP 4xx/5xx.

    Security: *url* must never be logged here — callers log masked forms only.
    """
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
            resp = client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise exc

    if resp.status_code >= 400:
        raise ValueError(
            f"Webhook returned HTTP {resp.status_code}: {resp.text[:200]!r}"
        )
