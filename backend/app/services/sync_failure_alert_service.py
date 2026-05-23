"""Sync failure alert dispatch — M32.

Sends an email notification when an integration has accumulated enough
consecutive scheduled sync failures to warrant alerting the user.

Alert policy
------------
An alert is sent when ALL of the following conditions hold:

1. ``consecutive_failure_count >= NEEDS_ATTENTION_THRESHOLD`` (default: 3)
2. The failing sync was **scheduled** (not manual) — manual retries must not
   inflate the streak or trigger alerts.
3. The last failure alert was sent more than 24 hours ago (cooldown), OR no
   alert has ever been sent for this integration.

The 24-hour cooldown is stored in ``integrations.last_failure_alert_sent_at``
so it survives worker restarts and is visible in the database for debugging.

Failure isolation
-----------------
Like the change-alert dispatcher, this module **never raises** to the worker.
An email-provider outage must not turn a sync failure into a worker exception.

User isolation
--------------
The recipient address is always taken from the integration's owning User row.
No untrusted input is used as the recipient.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import settings
from app.core.failure_classifier import FAILURE_ALERT_COOLDOWN_SECONDS, NEEDS_ATTENTION_THRESHOLD
from app.models.integration import Integration
from app.models.sync_run import SyncRun
from app.models.user import User
from app.services import email_service
from app.services.email_service import EmailNotConfigured, EmailSendError

logger = logging.getLogger(__name__)

_PLACEHOLDER_EMAIL_SUFFIX = "@clerk.user"


def maybe_send_failure_alert(
    *,
    integration: Integration,
    sync_run: SyncRun,
    consecutive_count: int,
    db: Session,
) -> bool:
    """Send a failure alert email if the policy conditions are met.

    Always returns — never raises.  All exceptions become log lines.

    Args:
        integration:       The integration that failed.
        sync_run:          The SyncRun that just failed (for error details).
        consecutive_count: The current consecutive_failure_count (already
                           incremented by the caller before this call).
        db:                Active SQLAlchemy session.

    Returns:
        ``True`` if an email was sent, ``False`` otherwise.
    """
    try:
        return _attempt_alert(
            integration=integration,
            sync_run=sync_run,
            consecutive_count=consecutive_count,
            db=db,
        )
    except Exception:
        logger.exception(
            "sync_failure_alert: unexpected error for integration_id=%s  "
            "sync_run_id=%s",
            integration.id,
            sync_run.id,
        )
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Internal implementation
# ─────────────────────────────────────────────────────────────────────────────


def _attempt_alert(
    *,
    integration: Integration,
    sync_run: SyncRun,
    consecutive_count: int,
    db: Session,
) -> bool:
    """Inner dispatch — allowed to raise (caller wraps in try/except)."""
    # ── Check threshold ───────────────────────────────────────────────────────
    if consecutive_count < NEEDS_ATTENTION_THRESHOLD:
        logger.debug(
            "sync_failure_alert: skipped — consecutive_count=%d < threshold=%d  "
            "integration_id=%s",
            consecutive_count,
            NEEDS_ATTENTION_THRESHOLD,
            integration.id,
        )
        return False

    # ── Check cooldown ────────────────────────────────────────────────────────
    now = datetime.now(timezone.utc)
    if integration.last_failure_alert_sent_at is not None:
        elapsed = (now - integration.last_failure_alert_sent_at).total_seconds()
        if elapsed < FAILURE_ALERT_COOLDOWN_SECONDS:
            logger.info(
                "sync_failure_alert: suppressed — cooldown active  "
                "integration_id=%s  elapsed_hours=%.1f",
                integration.id,
                elapsed / 3600,
            )
            return False

    # ── Check email configured ────────────────────────────────────────────────
    if not settings.is_email_alerting_configured:
        logger.warning(
            "sync_failure_alert: email not configured — skipping  "
            "integration_id=%s  consecutive_count=%d",
            integration.id,
            consecutive_count,
        )
        return False

    # ── Resolve recipient ─────────────────────────────────────────────────────
    recipient = _resolve_recipient(integration, db)
    if recipient is None:
        logger.warning(
            "sync_failure_alert: no deliverable recipient  "
            "integration_id=%s  user_id=%s",
            integration.id,
            integration.user_id,
        )
        return False

    # ── Compose + send ────────────────────────────────────────────────────────
    subject, body = _compose_failure_email(
        integration=integration,
        sync_run=sync_run,
        consecutive_count=consecutive_count,
    )

    try:
        email_service.send_email(to=recipient, subject=subject, body=body)
    except EmailNotConfigured:
        logger.warning(
            "sync_failure_alert: email not configured at send time  "
            "integration_id=%s",
            integration.id,
        )
        return False
    except EmailSendError as exc:
        logger.error(
            "sync_failure_alert: email send failed  integration_id=%s  error=%r",
            integration.id,
            exc,
        )
        return False

    # ── Record send timestamp (cooldown) ──────────────────────────────────────
    integration.last_failure_alert_sent_at = now
    db.commit()

    logger.info(
        "sync_failure_alert: sent  integration_id=%s  recipient=%s  "
        "consecutive_count=%d",
        integration.id,
        recipient,
        consecutive_count,
    )
    return True


def _resolve_recipient(integration: Integration, db: Session) -> str | None:
    """Return the integration owner's email, or None if undeliverable."""
    user = db.get(User, integration.user_id)
    if user is None:
        return None
    email = (user.email or "").strip()
    if not email:
        return None
    if email.endswith(_PLACEHOLDER_EMAIL_SUFFIX):
        return None
    return email


def _compose_failure_email(
    *,
    integration: Integration,
    sync_run: SyncRun,
    consecutive_count: int,
) -> tuple[str, str]:
    """Return (subject, body) for the failure alert email."""
    provider_label = {
        "cloudflare": "Cloudflare DNS",
        "github": "GitHub repository",
    }.get(integration.provider, integration.provider)

    base_url = settings.APP_BASE_URL.rstrip("/")
    integration_url = f"{base_url}/integrations/{integration.id}"

    subject = (
        f"[ConfigTrace] Sync failures: {integration.display_name} "
        f"({consecutive_count} consecutive)"
    )

    lines: list[str] = [
        f"Your {provider_label} integration has failed {consecutive_count} "
        f"consecutive scheduled syncs.",
        "",
        f"Integration: {integration.display_name}",
        f"Provider:    {provider_label}",
        "",
        "─" * 60,
        "",
    ]

    if sync_run.failure_category:
        lines.append(f"Failure category: {sync_run.failure_category}")
    if sync_run.error_code:
        lines.append(f"Error code:       {sync_run.error_code}")
    if sync_run.error_message:
        lines.append(f"Error detail:     {sync_run.error_message[:500]}")
    if sync_run.recommended_action:
        lines.append("")
        lines.append(f"Recommended action:")
        lines.append(f"  {sync_run.recommended_action}")

    lines += [
        "",
        "─" * 60,
        "",
        f"View integration: {integration_url}",
        "",
        "You are receiving this email because ConfigTrace detected repeated "
        "sync failures for an integration you own.",
        "Alerts are sent at most once every 24 hours per integration.",
    ]

    return subject, "\n".join(lines)
