"""High-risk alert dispatch — Milestone 24.

What this module does
---------------------
After a sync persists Change rows and risk classification runs, the worker
calls :func:`dispatch_alerts_for_sync` with the freshly-created Change list.
This module:

1. Filters the list down to changes with ``risk_level in {"high", "critical"}``.
2. Skips any change that already has an ``alerts`` row for channel ``email``
   (idempotency — protects against worker retries and duplicate Sync Now
   clicks).
3. Composes one **digest email** per sync listing all qualifying changes.
4. Sends the email via :mod:`app.services.email_service`.
5. Records one ``alerts`` row per change for the audit trail / idempotency
   lookup — whether the send succeeded (``status='delivered'``) or failed
   (``status='failed'``, with the exception message in ``error_message``).

Failure isolation
-----------------
Every exception inside this module is caught and logged.  The dispatcher
**never raises** to the worker.  An email-provider outage must not turn a
successful DNS sync into a failed one.

User isolation
--------------
The recipient address is taken from ``integration.user.email``.  The user is
re-loaded inside this function from the integration's ``user_id`` — no
recipient address is ever derived from a request header, task argument,
or any other untrusted input.

Why digest (not per-change emails)
----------------------------------
A single sync can detect many related changes — a zone reconfiguration
might surface 8 critical CNAME changes at once.  Eight separate emails in
the same minute is noise, not signal.  The digest approach keeps each
individual Change auditable (one Alert row per change) while delivering
one readable summary per sync.
"""

from __future__ import annotations

import logging
import uuid
from typing import Sequence

from sqlalchemy.orm import Session

from app.config import settings
from app.models.alert import Alert
from app.models.change import Change
from app.models.integration import Integration
from app.models.user import User
from app.services import email_service
from app.services.email_service import EmailNotConfigured, EmailSendError

logger = logging.getLogger(__name__)

# Risk levels that trigger alerts.  ``low`` and ``medium`` are intentionally
# excluded — they would create noise without adding signal.
_ALERTABLE_LEVELS = frozenset({"high", "critical"})

# The channel string written to ``alerts.channel`` for email dispatch.
# Kept as a constant so the idempotency query and the insert agree.
_EMAIL_CHANNEL = "email"

# Email addresses ending in this suffix are placeholders generated when
# Clerk's session template doesn't include the email claim.  Sending to them
# is pointless and would generate bounces.
_PLACEHOLDER_EMAIL_SUFFIX = "@clerk.user"


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────


def dispatch_alerts_for_sync(
    *,
    changes: Sequence[Change],
    integration: Integration,
    sync_run_id: uuid.UUID,
    db: Session,
) -> dict:
    """Send a digest email for any high/critical changes in *changes*.

    Always returns — never raises.  All exceptions become log lines.

    Args:
        changes:       The Change rows created by the current sync's diff
                       pass.  Risk classification must already have run.
        integration:   The Integration row this sync ran against.  The
                       recipient is ``integration.user.email``.
        sync_run_id:   Used only for log correlation.
        db:            Active SQLAlchemy session.  This function will
                       ``db.flush()`` after inserting Alert rows but leaves
                       ``db.commit()`` to the caller — matching the
                       transactional pattern of snapshot/diff/risk services.

    Returns:
        Counts dict for log correlation and tests:
            - ``eligible``: how many changes matched the high/critical filter
            - ``already_alerted``: skipped because an alert row exists
            - ``sent``: digest emails actually dispatched (0 or 1)
            - ``recorded``: alert rows inserted (one per delivered change)
            - ``failed``: alert rows inserted with status='failed'
    """
    result = {
        "eligible": 0,
        "already_alerted": 0,
        "sent": 0,
        "recorded": 0,
        "failed": 0,
    }

    # ── Filter to alertable risk levels ───────────────────────────────────
    alertable = [c for c in changes if c.risk_level in _ALERTABLE_LEVELS]
    result["eligible"] = len(alertable)
    if not alertable:
        return result

    # ── Short-circuit when email alerting isn't configured ────────────────
    # Avoids the wasted call into email_service.send_email — and, more
    # importantly, makes the no-op intent explicit so tests that assert
    # "send_email is never called when unconfigured" hold cleanly.  Logged
    # once per sync at WARNING so misconfigured prod surfaces in logs.
    if not settings.is_email_alerting_configured:
        logger.warning(
            "alerts: email alerting not configured — skipping %d change(s)  "
            "sync_run_id=%s",
            len(alertable),
            sync_run_id,
        )
        return result

    # ── Idempotency filter ────────────────────────────────────────────────
    # Drop any change that already has an email-channel Alert row.  This
    # protects against Celery retries and duplicate manual Sync Now clicks.
    pending = [c for c in alertable if not _already_alerted(c.id, db)]
    result["already_alerted"] = len(alertable) - len(pending)
    if not pending:
        logger.info(
            "alerts: all %d eligible change(s) already alerted  sync_run_id=%s",
            len(alertable),
            sync_run_id,
        )
        return result

    # ── Resolve recipient ─────────────────────────────────────────────────
    recipient = _resolve_recipient(integration, db)
    if recipient is None:
        logger.warning(
            "alerts: skipping dispatch — no deliverable recipient for "
            "integration_id=%s user_id=%s  (placeholder email or user not "
            "found)",
            integration.id,
            integration.user_id,
        )
        # Don't record failed Alert rows for this case — the next sync
        # for the same change would be re-blocked by the idempotency check
        # below.  Instead, leave the changes unrecorded so a fixed email
        # configuration can re-attempt them.  This is intentional.
        return result

    # ── Compose + send ────────────────────────────────────────────────────
    subject, body = _compose_digest(integration=integration, changes=pending)

    try:
        provider_response = email_service.send_email(
            to=recipient,
            subject=subject,
            body=body,
        )
        send_status = "delivered"
        error_message = None
        result["sent"] = 1
        logger.info(
            "alerts: digest sent  sync_run_id=%s integration_id=%s "
            "recipient=%s change_count=%d",
            sync_run_id,
            integration.id,
            recipient,
            len(pending),
        )
    except EmailNotConfigured as exc:
        # Don't record Alert rows — leaving the rows absent means a future
        # sync (after the operator fixes config) will still try.  Log once,
        # at WARNING level, so a misconfigured prod surfaces in logs.
        logger.warning(
            "alerts: email alerting not configured — skipping %d change(s)  "
            "sync_run_id=%s  detail=%s",
            len(pending),
            sync_run_id,
            exc,
        )
        return result
    except EmailSendError as exc:
        # Record failed Alert rows so an operator can audit.  Idempotency
        # check above means the next retry of the same sync won't re-send.
        send_status = "failed"
        error_message = str(exc)[:1000]
        provider_response = None
        result["failed"] = len(pending)
        logger.error(
            "alerts: email send failed  sync_run_id=%s integration_id=%s "
            "error=%r",
            sync_run_id,
            integration.id,
            exc,
        )

    # ── Record one Alert row per change ───────────────────────────────────
    payload_summary = {
        "subject": subject,
        "recipient": recipient,
        "change_ids": [str(c.id) for c in pending],
    }
    if provider_response is not None:
        payload_summary["provider_response_id"] = provider_response.get("id")

    for change in pending:
        alert = Alert(
            change_id=change.id,
            user_id=integration.user_id,
            integration_id=integration.id,
            channel=_EMAIL_CHANNEL,
            destination=recipient,
            payload=payload_summary,
            status=send_status,
            error_message=error_message,
        )
        if send_status == "delivered":
            from datetime import datetime, timezone

            alert.delivered_at = datetime.now(timezone.utc)
        db.add(alert)
        result["recorded"] += 1

    db.flush()
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Internals
# ─────────────────────────────────────────────────────────────────────────────


def _already_alerted(change_id: uuid.UUID, db: Session) -> bool:
    """Return True if an email-channel Alert row already exists for *change_id*.

    Uses the ``ix_alerts_change_id`` index from the initial schema.
    """
    return (
        db.query(Alert.id)
        .filter(Alert.change_id == change_id, Alert.channel == _EMAIL_CHANNEL)
        .first()
        is not None
    )


def _resolve_recipient(integration: Integration, db: Session) -> str | None:
    """Return the integration owner's email, or ``None`` if undeliverable.

    Loaded explicitly from the User row (not from a relationship attribute)
    so this function works whether or not the caller has eager-loaded the
    integration's user.
    """
    user = db.get(User, integration.user_id)
    if user is None:
        return None
    email = (user.email or "").strip()
    if not email:
        return None
    if email.endswith(_PLACEHOLDER_EMAIL_SUFFIX):
        # Clerk session template didn't include the email claim, so the
        # stored value is a placeholder.  Refuse to send to it.
        return None
    return email


def _compose_digest(
    *,
    integration: Integration,
    changes: Sequence[Change],
) -> tuple[str, str]:
    """Return (subject, body) for the alert digest email.

    Subject form:
        [ConfigTrace] Critical DNS change detected for <display_name>
        [ConfigTrace] High-risk DNS changes detected for <display_name>

    If there are multiple changes with mixed risk, the highest level wins
    in the subject ("Critical" beats "High").  The body lists each change
    in detail with a deep link to the change detail page.
    """
    has_critical = any(c.risk_level == "critical" for c in changes)
    level_label = "Critical" if has_critical else "High-risk"
    plural = "change" if len(changes) == 1 else "changes"

    subject = (
        f"[ConfigTrace] {level_label} DNS {plural} detected "
        f"for {integration.display_name}"
    )

    base_url = settings.APP_BASE_URL.rstrip("/")
    lines: list[str] = []
    lines.append(f"ConfigTrace detected {len(changes)} {plural} that may affect production.")
    lines.append("")
    lines.append(f"Provider:     Cloudflare DNS")
    lines.append(f"Integration:  {integration.display_name}")
    lines.append("")
    lines.append("─" * 60)

    for idx, change in enumerate(changes, start=1):
        lines.append("")
        lines.append(f"Change {idx} of {len(changes)} — risk: {change.risk_level.upper()}")
        lines.append(f"  Record:       {change.record_identifier}")
        lines.append(f"  Change type:  {change.change_type}")
        if change.field_path:
            lines.append(f"  Field:        {change.field_path}")
        old_val = _format_value(change.prev_value)
        new_val = _format_value(change.new_value)
        if old_val is not None:
            lines.append(f"  Old value:    {old_val}")
        if new_val is not None:
            lines.append(f"  New value:    {new_val}")
        if change.risk_reason:
            lines.append(f"  Why:          {change.risk_reason}")
        lines.append(f"  Detected at:  {change.created_at.isoformat()}")
        lines.append(f"  View change:  {base_url}/changes/{change.id}")

    lines.append("")
    lines.append("─" * 60)
    lines.append("")
    lines.append("You are receiving this email because you are the owner of the")
    lines.append("ConfigTrace integration above.  Low- and medium-risk changes are")
    lines.append("not emailed — review them in the timeline at:")
    lines.append(f"  {base_url}")

    return subject, "\n".join(lines)


def _format_value(value) -> str | None:
    """Render a JSONB value for the email body.

    Returns ``None`` when the value is ``None`` (so the calling code can
    omit the line entirely for ``added``/``removed`` half-pairs).
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value
    # Short JSON-ish representation for dicts / lists / scalars.
    try:
        import json

        return json.dumps(value, separators=(", ", ": "), default=str)
    except (TypeError, ValueError):
        return repr(value)
