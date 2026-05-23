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

# The channel string written to ``alerts.channel`` for email dispatch.

# The channel string written to ``alerts.channel`` for email dispatch.
# Kept as a constant so the idempotency query and the insert agree.
_EMAIL_CHANNEL = "email"

# Risk-level sets per alert threshold value.  Computed once at call time from
# the user's persisted ``alert_risk_threshold`` setting.  The fallback
# ("high_and_critical") matches the previous hardcoded _ALERTABLE_LEVELS.
def _alertable_levels_for_threshold(threshold: str) -> frozenset:
    """Return the set of risk-level strings that trigger alerts for *threshold*.

    Allowed threshold values (validated at PATCH /settings):
      ``critical_only``      → {"critical"}
      ``high_and_critical``  → {"high", "critical"}  (default)
      ``medium_and_above``   → {"medium", "high", "critical"}
    """
    if threshold == "critical_only":
        return frozenset({"critical"})
    elif threshold == "medium_and_above":
        return frozenset({"medium", "high", "critical"})
    return frozenset({"high", "critical"})  # "high_and_critical" (default)

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
    # Load the user's alert threshold from settings (creates defaults if absent).
    from app.services.settings_service import get_or_create_settings  # local import avoids circular
    try:
        user_settings = get_or_create_settings(integration.user_id, db)
        alertable_levels = _alertable_levels_for_threshold(user_settings.alert_risk_threshold)
    except Exception:
        # Settings read failure must never block alert dispatch.  Fall back to
        # the conservative default so the user doesn't miss critical alerts.
        logger.exception(
            "alerts: could not read user settings — falling back to high_and_critical  "
            "user_id=%s  sync_run_id=%s",
            integration.user_id,
            sync_run_id,
        )
        alertable_levels = frozenset({"high", "critical"})

    alertable = [c for c in changes if c.risk_level in alertable_levels]
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


# Human-readable provider labels used in email bodies.
#   "Cloudflare DNS" → "Provider:    Cloudflare DNS"
#   "GitHub repo configuration" → "Provider:    GitHub repo configuration"
_PROVIDER_BODY_LABELS: dict[str, str] = {
    "cloudflare": "Cloudflare DNS",
    "github":     "GitHub repo configuration",
}


def _compose_digest(
    *,
    integration: Integration,
    changes: Sequence[Change],
) -> tuple[str, str]:
    """Return (subject, body) for the alert digest email.

    Subject forms (single change):
        [ConfigTrace] High-risk DNS change: CNAME exx.configtrace.org target changed
        [ConfigTrace] Critical GitHub change: repository visibility changed

    Subject forms (multiple changes):
        [ConfigTrace] 2 critical DNS changes detected
        [ConfigTrace] 3 high-risk GitHub configuration changes detected

    If there are multiple changes with mixed risk, the highest level wins
    in the subject ("critical" beats "high-risk").  The body lists each
    change with: summary, what changed, why it matters, suggested checks,
    detected time, and a deep link to the change detail page.
    """
    from app.services.change_explainer import explain_change

    has_critical = any(c.risk_level == "critical" for c in changes)
    provider     = integration.provider
    body_label   = _PROVIDER_BODY_LABELS.get(provider, provider)
    base_url     = settings.APP_BASE_URL.rstrip("/")
    n            = len(changes)

    # ── Build per-change explanations ─────────────────────────────────────
    explanations = [explain_change(c) for c in changes]

    # ── Subject ───────────────────────────────────────────────────────────
    if n == 1:
        exp         = explanations[0]
        risk_label  = "Critical" if has_critical else "High-risk"
        if provider == "cloudflare":
            subject = f"[ConfigTrace] {risk_label} DNS change: {exp.subject_fragment}"
        elif provider == "github":
            subject = f"[ConfigTrace] {risk_label} GitHub change: {exp.subject_fragment}"
        else:
            subject = f"[ConfigTrace] {risk_label} configuration change: {exp.subject_fragment}"
    else:
        risk_label = "critical" if has_critical else "high-risk"
        if provider == "cloudflare":
            subject = f"[ConfigTrace] {n} {risk_label} DNS changes detected"
        elif provider == "github":
            subject = f"[ConfigTrace] {n} {risk_label} GitHub configuration changes detected"
        else:
            subject = f"[ConfigTrace] {n} {risk_label} configuration changes detected"

    # ── Body header ───────────────────────────────────────────────────────
    lines: list[str] = []

    if n == 1:
        exp        = explanations[0]
        risk_upper = (changes[0].risk_level or "unknown").upper()
        lines.append(f"{risk_upper} RISK: {exp.summary}")
    else:
        risk_cap = "Critical" if has_critical else "High-risk"
        lines.append(
            f"{risk_cap} configuration changes detected in {integration.display_name}"
        )

    lines.append("")
    lines.append(f"Provider:    {body_label}")
    lines.append(f"Integration: {integration.display_name}")
    lines.append("")
    lines.append("─" * 60)

    # ── Per-change blocks ─────────────────────────────────────────────────
    for idx, (change, exp) in enumerate(zip(changes, explanations), start=1):
        risk_upper = (change.risk_level or "unknown").upper()
        lines.append("")

        if n > 1:
            lines.append(f"Change {idx} of {n} — {risk_upper}")
            lines.append(exp.summary)
            lines.append("")

        lines.append("What changed:")
        lines.append(f"  {exp.what_changed}")
        lines.append("")

        lines.append("Why this matters:")
        lines.append(f"  {exp.why_it_matters}")
        lines.append("")

        if exp.suggested_checks:
            lines.append("Suggested checks:")
            for check in exp.suggested_checks:
                lines.append(f"  • {check}")
            lines.append("")

        lines.append(f"Detected:         {_format_timestamp(change.created_at)}")
        lines.append(f"View full change: {base_url}/changes/{change.id}")

        if idx < n:
            lines.append("")
            lines.append("─" * 60)

    # ── Footer ────────────────────────────────────────────────────────────
    lines.append("")
    lines.append("─" * 60)
    lines.append("")
    lines.append("You are receiving this email because you are the owner of the")
    lines.append("ConfigTrace integration above. Low- and medium-risk changes are")
    lines.append("not emailed — review them in the timeline at:")
    lines.append(f"  {base_url}")

    return subject, "\n".join(lines)


def _format_timestamp(dt: object) -> str:
    """Format a datetime object as a clean UTC string for email bodies."""
    if dt is None:
        return "unknown"
    try:
        if hasattr(dt, "strftime"):
            return dt.strftime("%Y-%m-%d %H:%M UTC")  # type: ignore[union-attr]
    except Exception:
        pass
    return str(dt)
