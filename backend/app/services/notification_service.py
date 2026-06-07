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
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Sequence
from urllib.parse import urlparse

import httpx

from sqlalchemy.orm import Session

from app.models.change import Change
from app.models.integration import Integration
from app.models.notification_settings import WorkspaceNotificationSettings

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_HTTP_TIMEOUT: float = 8.0  # seconds — must not block the sync worker

# M59.4 — Workspace-wide cooldown (seconds) between "send test notification"
# calls.  Applied to the legacy webhook test, Slack-App test, push test, and
# weekly-digest test endpoints.  Per-channel cooldown is intentionally NOT
# implemented in this milestone: a single shared timer is simpler and admin-gating
# keeps the abuse surface bounded.
_TEST_NOTIFICATION_COOLDOWN: int = 60


class TestNotificationCooldownError(RuntimeError):
    """Raised when a test-notification endpoint is called within the cooldown.

    Carries ``retry_after`` (seconds) so the router can populate the
    HTTP ``Retry-After`` header.
    """

    def __init__(self, retry_after: int) -> None:
        super().__init__(
            f"Test notification cooldown active; retry in {retry_after}s."
        )
        self.retry_after = retry_after


def assert_test_notification_cooldown(
    workspace_id: uuid.UUID,
    db: Session,
) -> None:
    """Raise :class:`TestNotificationCooldownError` if within the cooldown.

    Reads ``WorkspaceNotificationSettings.last_test_notification_at`` and
    compares to ``now()``.  Idempotent — does NOT update the timestamp; that
    is done by ``mark_test_notification_sent`` after the test fires.

    Args:
        workspace_id: Workspace to check.
        db:           Active SQLAlchemy session.

    Raises:
        TestNotificationCooldownError: When ``now - last_test_notification_at``
            is less than ``_TEST_NOTIFICATION_COOLDOWN``.
    """
    row = (
        db.query(WorkspaceNotificationSettings)
        .filter(WorkspaceNotificationSettings.workspace_id == workspace_id)
        .first()
    )
    if row is None:
        return
    last = getattr(row, "last_test_notification_at", None)
    # Defensive: a non-datetime value (e.g. an unset MagicMock under tests, or
    # a freshly-created row whose column default is NULL) means "no prior test".
    if not isinstance(last, datetime):
        return
    elapsed = (datetime.now(timezone.utc) - last).total_seconds()
    if elapsed < _TEST_NOTIFICATION_COOLDOWN:
        retry_after = max(1, int(_TEST_NOTIFICATION_COOLDOWN - elapsed))
        raise TestNotificationCooldownError(retry_after=retry_after)


def mark_test_notification_sent(
    workspace_id: uuid.UUID,
    db: Session,
) -> None:
    """Update ``last_test_notification_at`` to now.  Caller commits."""
    row = (
        db.query(WorkspaceNotificationSettings)
        .filter(WorkspaceNotificationSettings.workspace_id == workspace_id)
        .first()
    )
    if row is None:
        # Lazy-create so the cooldown takes effect even on the first test.
        row = WorkspaceNotificationSettings(workspace_id=workspace_id)
        db.add(row)
    row.last_test_notification_at = datetime.now(timezone.utc)
    db.flush()

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
    _is_literal_ip = False
    try:
        _addr = ipaddress.ip_address(hostname)
        _is_literal_ip = True
    except ValueError:
        # Not a literal IP — hostname is a DNS name.  Resolve below (M59.4).
        pass

    if _addr is not None:
        for network in _PRIVATE_NETWORKS:
            if _addr in network:
                raise WebhookURLError(
                    f"Webhook URL points to a private IP address ({hostname}). "
                    "Only public HTTPS endpoints are allowed."
                )

    # M59.4 — DNS-rebinding protection for hostname-form generic webhook URLs.
    # We resolve the hostname via socket.getaddrinfo and reject if ANY resolved
    # address is private/loopback/link-local/multicast/unspecified/reserved.
    # Applied only to generic webhooks; Slack URLs are already pinned to
    # ``hooks.slack.com`` by the prefix check above so their hostname is trusted.
    # DNS failures fail closed: a hostname we cannot resolve is rejected rather
    # than allowed.  Tests monkeypatch ``socket.getaddrinfo`` for determinism.
    if not slack and not _is_literal_ip:
        _assert_hostname_resolves_public(hostname)


def _assert_hostname_resolves_public(hostname: str) -> None:
    """Resolve *hostname* and raise WebhookURLError if any A/AAAA record is
    private/loopback/link-local/multicast/unspecified/reserved.

    Fails closed on DNS errors and empty result sets.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise WebhookURLError(
            f"Webhook URL hostname {hostname!r} could not be resolved: {exc}. "
            "Only resolvable public HTTPS endpoints are allowed."
        ) from exc
    except Exception as exc:  # noqa: BLE001
        # Any unexpected resolver error → fail closed.
        raise WebhookURLError(
            f"Webhook URL hostname {hostname!r} could not be resolved."
        ) from exc

    if not infos:
        raise WebhookURLError(
            f"Webhook URL hostname {hostname!r} did not resolve to any address."
        )

    for _family, _type, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0] if sockaddr else ""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            # getaddrinfo gave us something we can't parse — fail closed.
            raise WebhookURLError(
                f"Webhook URL hostname {hostname!r} resolved to an "
                "unparseable address."
            )
        # 1. Block app's curated private-network set (covers IPv4 + IPv6 ULA + metadata).
        for network in _PRIVATE_NETWORKS:
            if addr in network:
                raise WebhookURLError(
                    f"Webhook URL hostname {hostname!r} resolves to a private "
                    f"or metadata IP ({addr}). Only public HTTPS endpoints are allowed."
                )
        # 2. Belt-and-braces: ipaddress.is_* flags cover anything missed
        # by the curated list (link-local, multicast, unspecified, reserved).
        if (
            addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
            or addr.is_reserved
            or addr.is_private
        ):
            raise WebhookURLError(
                f"Webhook URL hostname {hostname!r} resolves to a "
                f"non-public IP ({addr})."
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
    slack_drift_channel_id: Optional[str] = None,
    slack_security_channel_id: Optional[str] = None,
    slack_security_alerts_enabled: Optional[bool] = None,
    slack_security_resolved_enabled: Optional[bool] = None,
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

    # ── M60.12 Slack routing (Drift vs Security) ───────────────────────────────
    # Empty string clears an override (→ fall back to the default channel).
    if slack_drift_channel_id is not None:
        row.slack_drift_channel_id = slack_drift_channel_id or None
    if slack_security_channel_id is not None:
        row.slack_security_channel_id = slack_security_channel_id or None
    if slack_security_alerts_enabled is not None:
        row.slack_security_alerts_enabled = slack_security_alerts_enabled
    if slack_security_resolved_enabled is not None:
        row.slack_security_resolved_enabled = slack_security_resolved_enabled

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

    # ── Slack App status (M58.5) — no token returned ─────────────────────────
    slack_app_installed = bool(
        getattr(row, "slack_bot_token_encrypted", None)
        and getattr(row, "slack_bot_iv", None)
    )

    return {
        "workspace_id": row.workspace_id,
        "slack_enabled": row.slack_enabled,
        "slack_webhook_url_masked": slack_masked,
        "webhook_enabled": row.webhook_enabled,
        "webhook_url_masked": webhook_masked,
        "notify_on_risk_level": row.notify_on_risk_level,
        # Slack App fields — never include bot_token_encrypted.
        "slack_app_enabled": bool(getattr(row, "slack_app_enabled", False)),
        "slack_app_installed": slack_app_installed,
        "slack_team_id": getattr(row, "slack_team_id", None),
        "slack_team_name": getattr(row, "slack_team_name", None),
        "slack_channel_id": getattr(row, "slack_channel_id", None),
        "slack_channel_name": getattr(row, "slack_channel_name", None),
        # M60.12 Slack routing (Drift vs Security).
        "slack_drift_channel_id": getattr(row, "slack_drift_channel_id", None),
        "slack_security_channel_id": getattr(row, "slack_security_channel_id", None),
        "slack_security_alerts_enabled": bool(
            getattr(row, "slack_security_alerts_enabled", False)
        ),
        "slack_security_resolved_enabled": bool(
            getattr(row, "slack_security_resolved_enabled", False)
        ),
        "slack_installed_at": getattr(row, "slack_installed_at", None),
        "slack_app_last_test_at": getattr(row, "slack_app_last_test_at", None),
        "slack_app_last_error": getattr(row, "slack_app_last_error", None),
        # Web Push (M58.7) — VAPID public key only; private key is never returned.
        "vapid_public_key": _get_vapid_public_key_safe(),
    }


def _get_vapid_public_key_safe() -> Optional[str]:
    """Return the VAPID public key from config, or None if unconfigured.

    This is the only VAPID value ever returned in API responses.
    The private key is NEVER included.
    """
    try:
        from app.services.push_notification_service import get_vapid_public_key
        return get_vapid_public_key()
    except Exception:
        return None


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
        "push_sent": 0,
        "skipped_no_settings": False,
        "failed": 0,
    }

    # ── Resolve workspace_id ───────────────────────────────────────────────────
    # M59.18: GitHub App integrations created before M59.18 have
    # ``workspace_id = NULL`` because the App-creator was the one provider
    # path that didn't pass it through.  Fall back to the user's default
    # workspace so production fanout works for those legacy rows without
    # requiring a manual backfill, and best-effort persist the discovered
    # workspace_id so subsequent syncs don't have to redo the lookup.
    workspace_id = integration.workspace_id
    if workspace_id is None:
        try:
            from app.services.workspace_service import get_default_workspace_for_user
            _fallback_ws = get_default_workspace_for_user(integration.user_id, db)
        except Exception:
            logger.exception(
                "notifications: workspace fallback lookup failed  user=%s  "
                "sync_run=%s",
                integration.user_id, sync_run_id,
            )
            _fallback_ws = None
        if _fallback_ws is None:
            logger.info(
                "notifications: dispatch skipped — integration has no "
                "workspace_id and user has no workspace  integration=%s  "
                "user=%s  sync_run=%s",
                integration.id, integration.user_id, sync_run_id,
            )
            result["skipped_no_settings"] = True
            return result
        workspace_id = _fallback_ws.id
        logger.info(
            "notifications: backfilled workspace_id on integration "
            "(was NULL)  integration=%s  workspace=%s  sync_run=%s",
            integration.id, workspace_id, sync_run_id,
        )
        try:
            integration.workspace_id = workspace_id
            db.add(integration)
            db.flush()
        except Exception:
            # Backfill is best-effort — never let it abort dispatch.
            logger.exception(
                "notifications: persisting backfilled workspace_id failed — "
                "continuing with in-memory value  integration=%s",
                integration.id,
            )

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
        # M59.18: surface this skip in logs — previously silent.
        logger.info(
            "notifications: dispatch skipped — workspace has no notification "
            "settings row  workspace=%s  sync_run=%s",
            workspace_id, sync_run_id,
        )
        result["skipped_no_settings"] = True
        return result

    # ── Determine whether the Slack App channel is fully configured ───────────
    # The Slack App path (bot token + selected channel) is independent of the
    # legacy `slack_enabled` flag, which only governs the incoming-webhook
    # flow. Without this check, a workspace that has installed the Slack App
    # but never set up the legacy webhook would be early-returned below before
    # the Slack App dispatch at the bottom of this function ever ran — which
    # is exactly the bug reported in real-alert traffic where
    # `slack_sent=0 webhook_sent=0` while push delivery succeeded.
    _slack_app_active = bool(
        getattr(settings_row, "slack_app_enabled", False)
        and getattr(settings_row, "slack_bot_token_encrypted", None)
        and getattr(settings_row, "slack_bot_iv", None)
        and getattr(settings_row, "slack_channel_id", None)
    )

    # ── Check whether ANY non-push channel is active ──────────────────────────
    # If none of: legacy Slack webhook, generic webhook, or Slack App — then
    # we fall through to the push-only branch and return. Otherwise we
    # continue into the main dispatch path so the Slack App branch gets a
    # chance to fire.
    if (
        not settings_row.slack_enabled
        and not settings_row.webhook_enabled
        and not _slack_app_active
    ):
        # Push (M58.7) may still be active — attempt push dispatch with its
        # own qualifying filter, then return.
        try:
            alertable_set_push = _alertable_levels(settings_row.notify_on_risk_level)
            push_qualifying = [c for c in changes if c.risk_level in alertable_set_push]
            if push_qualifying:
                from app.services.push_notification_service import dispatch_push_for_sync
                result["push_sent"] = dispatch_push_for_sync(
                    workspace_id=workspace_id,
                    changes=push_qualifying,
                    integration=integration,
                    sync_run_id=sync_run_id,
                    db=db,
                )
        except Exception:
            logger.debug(
                "notifications: push-only dispatch skipped  workspace=%s  sync_run=%s",
                workspace_id, sync_run_id,
            )
        return result

    # Diagnostic: helps operators confirm which channels were eligible BEFORE
    # the per-channel dispatch logic runs. We log booleans only — no tokens,
    # URLs, channel IDs, or push endpoints are emitted here.
    logger.info(
        "notifications: dispatch eligible  workspace=%s  sync_run=%s  "
        "slack_app=%s  slack_webhook=%s  webhook=%s",
        workspace_id, sync_run_id,
        _slack_app_active,
        bool(settings_row.slack_enabled and settings_row.slack_webhook_url_encrypted),
        bool(settings_row.webhook_enabled and settings_row.webhook_url_encrypted),
    )

    # ── Filter changes to alertable risk levels ────────────────────────────────
    alertable_set = _alertable_levels(settings_row.notify_on_risk_level)
    qualifying = [c for c in changes if c.risk_level in alertable_set]

    if not qualifying:
        return result

    # ── M57.3: Suppress changes matched by an active SnoozeRule ──────────────
    # Fail-open: any snooze-rule lookup error keeps the change in the list.
    try:
        from app.services.snooze_rule_service import is_change_snoozed_by_rule
        unsnoozed = []
        for c in qualifying:
            if is_change_snoozed_by_rule(c, workspace_id, db):
                logger.info(
                    "notifications: suppressed by snooze rule  change_id=%s  "
                    "sync_run=%s",
                    c.id, sync_run_id,
                )
            else:
                unsnoozed.append(c)
        qualifying = unsnoozed
    except Exception:
        logger.exception(
            "notifications: snooze-rule check failed — failing open  sync_run=%s",
            sync_run_id,
        )

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
    # M58.5: Prefer Slack App (bot token) over legacy incoming webhook.
    _slack_app_enabled = bool(getattr(settings_row, "slack_app_enabled", False))
    _slack_app_token = getattr(settings_row, "slack_bot_token_encrypted", None)
    _slack_app_iv = getattr(settings_row, "slack_bot_iv", None)
    # M60.12: drift alerts use the drift channel override when set, else the
    # default channel (blank override → unchanged behavior for existing setups).
    _slack_app_channel = getattr(
        settings_row, "slack_drift_channel_id", None
    ) or getattr(settings_row, "slack_channel_id", None)

    if _slack_app_enabled and _slack_app_token and _slack_app_iv and _slack_app_channel:
        # ── Slack App path (M58.5/M58.6 interactive) ──────────────────────
        logger.info(
            "notifications: Slack App dispatch attempt  workspace=%s  "
            "sync_run=%s  changes=%d",
            workspace_id, sync_run_id, len(qualifying),
        )
        try:
            from app.services.slack_service import _decrypt_token, dispatch_alert_message
            from app.config import settings as _settings
            bot_token = _decrypt_token(_slack_app_token, _slack_app_iv)
            dispatch_alert_message(
                bot_token=bot_token,
                channel_id=_slack_app_channel,
                changes=list(qualifying),
                integration_name=integration.display_name,
                provider=integration.provider,
                fallback_text=slack_text,
                base_url=_settings.APP_BASE_URL.rstrip("/"),
            )
            result["slack_sent"] = 1
            # Channel ID is safe to log — it's a Slack-side identifier like
            # CABC123, not a secret. We never log the bot token.
            logger.info(
                "notifications: Slack App sent  workspace=%s  sync_run=%s  "
                "changes=%d  channel=%s",
                workspace_id, sync_run_id, len(qualifying), _slack_app_channel,
            )
        except Exception as exc:
            result["failed"] += 1
            # Record error on settings row (best-effort — don't fail the sync).
            try:
                settings_row.slack_app_last_error = str(exc)[:500]
                db.add(settings_row)
                db.flush()
            except Exception:
                pass
            logger.error(
                "notifications: Slack App delivery failed  workspace=%s  "
                "sync_run=%s  error_type=%r",
                workspace_id, sync_run_id, type(exc).__name__,
            )
    elif settings_row.slack_enabled and settings_row.slack_webhook_url_encrypted:
        # ── Legacy incoming webhook fallback ───────────────────────────────
        try:
            url = _decrypt_url(
                settings_row.slack_webhook_url_encrypted,
                settings_row.slack_webhook_iv,  # type: ignore[arg-type]
            )
            _post_json(url, {"text": slack_text})
            result["slack_sent"] = 1
            logger.info(
                "notifications: Slack webhook sent  workspace=%s  sync_run=%s  "
                "changes=%d  url=%s",
                workspace_id, sync_run_id, len(qualifying), _mask_url(url),
            )
        except Exception as exc:
            result["failed"] += 1
            logger.error(
                "notifications: Slack webhook delivery failed  workspace=%s  "
                "sync_run=%s  error=%r",
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

    # ── Push dispatch (M58.7 — independent of Slack/webhook settings) ─────────
    # Runs after traditional channels.  Fail-safe: never raises or blocks sync.
    try:
        from app.services.push_notification_service import dispatch_push_for_sync
        result["push_sent"] = dispatch_push_for_sync(
            workspace_id=workspace_id,
            changes=list(qualifying),
            integration=integration,
            sync_run_id=sync_run_id,
            db=db,
        )
    except Exception:
        logger.debug(
            "notifications: push dispatch skipped/failed  workspace=%s  sync_run=%s",
            workspace_id, sync_run_id,
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
    # M58.5: Prefer Slack App over legacy webhook for test delivery.
    _t_app_enabled = bool(getattr(settings_row, "slack_app_enabled", False))
    _t_app_token = getattr(settings_row, "slack_bot_token_encrypted", None)
    _t_app_iv = getattr(settings_row, "slack_bot_iv", None)
    _t_app_channel = getattr(settings_row, "slack_channel_id", None)

    if _t_app_enabled and _t_app_token and _t_app_iv and _t_app_channel:
        try:
            from app.services.slack_service import _decrypt_token, send_message
            bot_token = _decrypt_token(_t_app_token, _t_app_iv)
            send_message(bot_token, _t_app_channel, test_slack_text)
            result["slack_sent"] = True
        except Exception as exc:
            errors.append(f"Slack App: {type(exc).__name__}")
            logger.warning(
                "notifications: test Slack App delivery failed  workspace=%s  error=%r",
                workspace_id, type(exc).__name__,
            )
    elif settings_row.slack_enabled and settings_row.slack_webhook_url_encrypted:
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
    elif not settings_row.slack_enabled and not _t_app_enabled:
        pass  # Not enabled — skip silently
    else:
        errors.append("Slack: no URL or channel configured")

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

    # M58.4: load remediation summary helper once (fail-open if unavailable)
    try:
        from app.services.remediation_summary_service import build_alert_remediation_summary as _rem_summary
    except Exception:
        _rem_summary = None  # type: ignore[assignment]

    for idx, c in enumerate(changes[:5], start=1):  # cap at 5 in Slack message
        risk_upper = (c.risk_level or "unknown").upper()
        lines.append(
            f"Change {idx}: [{risk_upper}] {c.record_identifier}"
            + (f" — {c.field_path}" if c.field_path else "")
        )
        if c.risk_reason:
            lines.append(f"  {c.risk_reason}")

        # ── M58.4: compact suggested-fix line (1–2 lines max) ─────────────
        # No full commands, no manual steps, no sensitive data.
        if _rem_summary is not None:
            try:
                rem = _rem_summary(c)
                if rem and rem.get("available"):
                    lines.append(f"  Suggested fix: {rem['title']}")
                    if rem.get("remediation_preview_available"):
                        lines.append("  Remediation preview available in ConfigTrace")
            except Exception:
                pass
        # ─────────────────────────────────────────────────────────────────

        lines.append(f"  View: {base_url}/changes/{c.id}")

    if n > 5:
        lines.append(f"  ... and {n - 5} more change(s)")

    lines.append("")
    lines.append(f"Full timeline: {base_url}")
    return "\n".join(lines)


def _build_webhook_remediation(change: Any, change_url: str) -> dict:
    """Build the remediation sub-object for a single change in the webhook payload.

    M58.4: Always includes execution_enabled: false.
    No full commands, no manual steps, no sensitive data.
    """
    try:
        from app.services.remediation_summary_service import build_alert_remediation_summary
        rem = build_alert_remediation_summary(change)
        if rem and rem.get("available"):
            return {
                "available": True,
                "title": rem["title"],
                "summary": rem["summary"],
                "confidence": rem.get("confidence", "low"),
                "fix_plan_available": bool(rem.get("fix_plan_available")),
                "remediation_preview_available": bool(rem.get("remediation_preview_available")),
                "execution_enabled": False,  # hard constant — never True
                "url": change_url,
            }
    except Exception:
        pass
    return {"available": False}


def _compose_webhook_payload(
    *,
    integration: Integration,
    changes: Sequence[Change],
    sync_run_id: uuid.UUID,
) -> dict:
    """Compose the generic webhook JSON payload.

    M58.4: Each change in the ``changes`` array now includes a ``remediation``
    sub-object.  Existing top-level fields are unchanged (backwards-compatible).
    The ``remediation.execution_enabled`` field is always False.
    """
    from app.config import settings as _settings

    has_critical = any(c.risk_level == "critical" for c in changes)
    highest_risk = "critical" if has_critical else "high"
    if not any(c.risk_level in ("critical", "high") for c in changes):
        # All medium
        highest_risk = "medium"

    base_url = _settings.APP_BASE_URL.rstrip("/")

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
                # M58.4: compact remediation summary — no commands, no secrets.
                "remediation": _build_webhook_remediation(
                    c, f"{base_url}/changes/{c.id}"
                ),
            }
            for c in changes
        ],
        "app_url": base_url,
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
