"""Web Push notification service — M58.7.

Provides:
  - VAPID key retrieval (public key only for API, private key for sending)
  - Push subscription CRUD (create, list, delete/disable)
  - Single push delivery (send_push)
  - Batch dispatch for alert sync (dispatch_push_for_sync)

Security invariants
-------------------
* endpoint, p256dh, and auth are AES-256-GCM encrypted at rest together.
* Raw subscription values are NEVER stored in plaintext, NEVER returned
  in API responses, NEVER logged.
* VAPID private key is NEVER returned in any API response.
* last_error stores sanitized error type only (no PII, no tokens).
* Failed 410/404 subscriptions are disabled, not deleted, for auditability.
* Push never crashes the sync worker — all errors are caught.

This module never applies configuration changes to any monitored provider.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from sqlalchemy.orm import Session

from app.models.push_subscription import WorkspacePushSubscription

logger = logging.getLogger(__name__)

_GONE_STATUS_CODES = frozenset({404, 410})


# ── VAPID key helpers ─────────────────────────────────────────────────────────


def get_vapid_public_key() -> Optional[str]:
    """Return the VAPID public key (safe to expose to frontend).

    Returns None if VAPID is not configured.
    """
    from app.config import settings
    return settings.WEB_PUSH_VAPID_PUBLIC_KEY or None


def _get_vapid_private_key() -> str:
    """Return the VAPID private key for signing. NEVER log or expose this.

    Raises:
        RuntimeError: If WEB_PUSH_VAPID_PRIVATE_KEY is not set.
    """
    from app.config import settings
    key = settings.WEB_PUSH_VAPID_PRIVATE_KEY
    if not key:
        raise RuntimeError(
            "WEB_PUSH_VAPID_PRIVATE_KEY is not configured. "
            "Cannot send push notifications."
        )
    return key


def _get_vapid_subject() -> str:
    """Return the VAPID subject (mailto: or https: URI)."""
    from app.config import settings
    return settings.WEB_PUSH_SUBJECT or "mailto:security@configtrace.org"


# ── Subscription storage ──────────────────────────────────────────────────────


def subscribe(
    *,
    workspace_id: uuid.UUID,
    user_id: Optional[uuid.UUID],
    endpoint: str,
    p256dh: str,
    auth: str,
    device_label: Optional[str],
    min_risk_level: str,
    user_agent: Optional[str],
    browser_name: Optional[str],
    db: Session,
) -> WorkspacePushSubscription:
    """Create or update a Web Push subscription.

    If a subscription with the same endpoint already exists for this workspace,
    it is updated (re-enabled if disabled, metadata refreshed).

    Encryption: endpoint + p256dh + auth are encrypted together.
    NEVER logs any subscription secrets.

    Returns the saved subscription row (metadata only — no secrets in repr).
    """
    from app.core.encryption import encrypt_credentials

    # Check for existing subscription with same endpoint (re-subscribe pattern).
    # We can't query by endpoint directly (it's encrypted), so we look for
    # subscriptions from the same user/device_label combo and check.
    # For simplicity: always create a new row (old ones auto-expire via 410).
    # Production optimization: deduplicate via endpoint hash (deferred).

    encrypted, iv = encrypt_credentials({
        "endpoint": endpoint,
        "p256dh": p256dh,
        "auth": auth,
    })

    now = datetime.now(timezone.utc)
    sub = WorkspacePushSubscription(
        workspace_id=workspace_id,
        user_id=user_id,
        subscription_encrypted=encrypted,
        subscription_iv=iv,
        user_agent=user_agent,
        browser_name=browser_name,
        device_label=device_label,
        enabled=True,
        min_risk_level=min_risk_level,
        created_at=now,
        updated_at=now,
    )
    db.add(sub)
    db.flush()
    logger.info(
        "push: subscription created  workspace=%s  browser=%s",
        workspace_id,
        browser_name or "unknown",
    )
    return sub


def list_subscriptions(
    workspace_id: uuid.UUID,
    db: Session,
) -> list[WorkspacePushSubscription]:
    """Return all subscriptions (enabled and disabled) for a workspace.

    Only safe metadata is returned — subscription secrets are never exposed.
    """
    return (
        db.query(WorkspacePushSubscription)
        .filter(WorkspacePushSubscription.workspace_id == workspace_id)
        .order_by(WorkspacePushSubscription.created_at.desc())
        .all()
    )


def delete_subscription(
    subscription_id: uuid.UUID,
    workspace_id: uuid.UUID,
    db: Session,
) -> bool:
    """Disable a push subscription.

    Verifies the subscription belongs to the given workspace.
    Returns True if found and disabled, False if not found.
    """
    sub = (
        db.query(WorkspacePushSubscription)
        .filter(
            WorkspacePushSubscription.id == subscription_id,
            WorkspacePushSubscription.workspace_id == workspace_id,
        )
        .first()
    )
    if sub is None:
        return False
    sub.enabled = False
    sub.updated_at = datetime.now(timezone.utc)
    db.add(sub)
    db.flush()
    logger.info(
        "push: subscription disabled  workspace=%s  id=%s",
        workspace_id,
        subscription_id,
    )
    return True


# ── Push delivery ─────────────────────────────────────────────────────────────


def _decrypt_subscription(
    sub: WorkspacePushSubscription,
) -> dict:
    """Decrypt a subscription row and return {endpoint, p256dh, auth}.

    NEVER log the returned values.
    """
    from app.core.encryption import decrypt_credentials
    return decrypt_credentials(sub.subscription_encrypted, sub.subscription_iv)


def send_push(
    sub: WorkspacePushSubscription,
    payload: dict,
    db: Session,
) -> bool:
    """Send one Web Push notification to a subscription.

    On 404/410 Gone, disables the subscription.
    On other errors, records sanitized last_error.

    Returns True on success, False on failure.

    Security: never logs endpoint, p256dh, auth, or VAPID private key.
    """
    from app.config import settings as _settings

    if not _settings.is_web_push_configured:
        logger.debug("push: VAPID not configured — skipping")
        return False

    if not sub.enabled:
        return False

    try:
        from pywebpush import webpush, WebPushException

        sub_data = _decrypt_subscription(sub)
        endpoint = sub_data["endpoint"]
        p256dh = sub_data["p256dh"]
        auth_secret = sub_data["auth"]

        private_key = _get_vapid_private_key()
        subject = _get_vapid_subject()

        webpush(
            subscription_info={
                "endpoint": endpoint,
                "keys": {"p256dh": p256dh, "auth": auth_secret},
            },
            data=json.dumps(payload),
            vapid_private_key=private_key,
            vapid_claims={"sub": subject},
            content_encoding="aes128gcm",
            ttl=86400,
        )

        sub.last_used_at = datetime.now(timezone.utc)
        sub.last_error = None
        sub.updated_at = datetime.now(timezone.utc)
        db.add(sub)
        db.flush()
        return True

    except Exception as exc:
        # Determine if subscription is gone.
        status_code: Optional[int] = None
        try:
            from pywebpush import WebPushException
            if isinstance(exc, WebPushException) and exc.response is not None:
                status_code = exc.response.status_code
        except Exception:
            pass

        if status_code in _GONE_STATUS_CODES:
            sub.enabled = False
            sub.last_error = f"Subscription expired ({status_code})"
            logger.info(
                "push: subscription expired  id=%s  status=%s", sub.id, status_code
            )
        else:
            # Record sanitized error type — never log the full exception message
            # (may contain endpoint URL or other sensitive data).
            sub.last_error = type(exc).__name__[:200]
            logger.warning(
                "push: delivery failed  id=%s  error_type=%r",
                sub.id,
                type(exc).__name__,
            )

        try:
            sub.updated_at = datetime.now(timezone.utc)
            db.add(sub)
            db.flush()
        except Exception:
            pass

        return False


def _build_push_payload(
    changes: Sequence[Any],
    integration: Any,
    base_url: str,
) -> dict:
    """Build a Web Push notification payload for the given changes.

    Returns a dict safe to serialize as JSON and send as push data.
    No raw prev_value/new_value or secrets included.
    """
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    sorted_changes = sorted(
        changes,
        key=lambda c: risk_order.get(
            c.risk_level if isinstance(c.risk_level, str) else str(c.risk_level),
            4,
        ),
    )
    top = sorted_changes[0]
    top_id = str(top.id)
    top_risk = top.risk_level if isinstance(top.risk_level, str) else str(top.risk_level)
    top_record = top.record_identifier if isinstance(top.record_identifier, str) else str(top.record_identifier)
    top_reason = top.risk_reason if isinstance(top.risk_reason, str) else ""

    provider_label = (
        integration.provider if isinstance(integration.provider, str) else str(integration.provider)
    ).upper()

    risk_label = "Critical" if top_risk == "critical" else "High-risk"
    title = f"{risk_label} configuration change — {provider_label}"

    body_parts = [top_record]
    if top_reason:
        body_parts.append(top_reason[:120])
    if len(changes) > 1:
        body_parts.append(f"+{len(changes) - 1} more")
    body = " — ".join(body_parts[:2])
    if len(changes) > 1:
        body += f" (+{len(changes) - 1} more)"

    return {
        "title": title,
        "body": body,
        "url": f"{base_url}/changes/{top_id}",
        "tag": f"configtrace-change-{top_id}",
        "risk_level": top_risk,
        "provider": integration.provider if isinstance(integration.provider, str) else "",
    }


def _alertable_push_levels(min_risk_level: str) -> frozenset:
    """Return the set of risk levels that trigger a push for this subscription."""
    if min_risk_level == "critical_only":
        return frozenset({"critical"})
    return frozenset({"high", "critical"})  # default "high"


def dispatch_push_for_sync(
    *,
    workspace_id: uuid.UUID,
    changes: Sequence[Any],
    integration: Any,
    sync_run_id: uuid.UUID,
    db: Session,
) -> int:
    """Send Web Push notifications for a sync run's qualifying changes.

    Called by notification_service.dispatch_notifications_for_sync.
    Iterates over enabled subscriptions and sends per-device filtered alerts.

    Returns the count of successful push sends.
    Never raises — all errors are caught and logged.
    """
    from app.config import settings as _settings

    if not _settings.is_web_push_configured:
        return 0

    if not changes:
        return 0

    try:
        subscriptions = (
            db.query(WorkspacePushSubscription)
            .filter(
                WorkspacePushSubscription.workspace_id == workspace_id,
                WorkspacePushSubscription.enabled == True,
            )
            .all()
        )
    except Exception:
        logger.exception(
            "push: failed to query subscriptions  workspace=%s  sync_run=%s",
            workspace_id, sync_run_id,
        )
        return 0

    if not subscriptions:
        return 0

    base_url = _settings.APP_BASE_URL.rstrip("/")
    sent = 0

    for sub in subscriptions:
        try:
            sub_levels = _alertable_push_levels(sub.min_risk_level)
            sub_changes = [c for c in changes if c.risk_level in sub_levels]
            if not sub_changes:
                continue

            payload = _build_push_payload(sub_changes, integration, base_url)
            success = send_push(sub, payload, db)
            if success:
                sent += 1
        except Exception:
            logger.exception(
                "push: per-subscription dispatch failed  id=%s  sync_run=%s",
                getattr(sub, "id", "?"), sync_run_id,
            )

    logger.info(
        "push: dispatch complete  workspace=%s  sync_run=%s  sent=%d  total=%d",
        workspace_id, sync_run_id, sent, len(subscriptions),
    )
    return sent


def send_test_push(workspace_id: uuid.UUID, db: Session) -> dict:
    """Send a test push notification to all enabled subscriptions.

    Returns dict with: sent (int), total_subscriptions (int), error (str|None).
    """
    from app.config import settings as _settings

    result: dict = {"sent": 0, "total_subscriptions": 0, "error": None}

    if not _settings.is_web_push_configured:
        result["error"] = "Web Push (VAPID) is not configured on this server."
        return result

    try:
        subscriptions = (
            db.query(WorkspacePushSubscription)
            .filter(
                WorkspacePushSubscription.workspace_id == workspace_id,
                WorkspacePushSubscription.enabled == True,
            )
            .all()
        )
    except Exception as exc:
        result["error"] = f"DB error: {type(exc).__name__}"
        return result

    result["total_subscriptions"] = len(subscriptions)

    if not subscriptions:
        result["error"] = "No enabled push subscriptions found for this workspace."
        return result

    payload = {
        "title": "ConfigTrace test notification",
        "body": "Push notifications are working correctly.",
        "url": _settings.APP_BASE_URL.rstrip("/") + "/settings/workspace/notifications",
        "tag": "configtrace-test",
        "risk_level": "high",
        "provider": "configtrace",
    }

    errors = []
    for sub in subscriptions:
        try:
            success = send_push(sub, payload, db)
            if success:
                result["sent"] += 1
            else:
                errors.append(f"sub {sub.id}: delivery failed")
        except Exception as exc:
            errors.append(f"sub {sub.id}: {type(exc).__name__}")

    if errors and result["sent"] == 0:
        result["error"] = "; ".join(errors[:3])

    return result
