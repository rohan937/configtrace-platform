"""Security exposure email alerts — M61.8.

Category-aware email routing for security exposure events, parallel to the
M60.12 Slack and M60.13 push security routing. Drift/change emails are
UNCHANGED (see alert_service.dispatch_alerts_for_sync) — this module only adds
opt-in security exposure emails.

Gating:
  * opened / reopened → require ``email_security_alerts_enabled`` + alertable
    severity (critical/high). Medium/low/info never email.
  * resolved          → require ``email_security_resolved_enabled`` + alertable.

Recipients: an explicit comma/newline list on the workspace settings, else the
workspace default recipient (the integration owner — same as drift email).

Privacy: metadata-only. The email body NEVER includes evidence/remediation
blobs, secrets, tokens, payloads, or raw rules. Careful wording is used
("security exposure opened", "risky configuration state") — never breach/attack/
compromise. Failures never raise to the sync worker.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from app.services import email_service
from app.services.security_exposure_events import (
    EVENT_OPENED,
    EVENT_REOPENED,
    EVENT_RESOLVED,
)

logger = logging.getLogger(__name__)

_PLACEHOLDER_SUFFIX = "@clerk.user"
_SPLIT_RE = re.compile(r"[,\n;]+")


def _parse_recipients(raw: Optional[str]) -> list[str]:
    """Parse a comma/newline/semicolon recipient list into clean addresses."""
    if not raw:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for part in _SPLIT_RE.split(raw):
        addr = part.strip()
        if not addr or "@" not in addr or addr.endswith(_PLACEHOLDER_SUFFIX):
            continue
        key = addr.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(addr)
    return out


def _valid_recipient(addr: Optional[str]) -> bool:
    return bool(addr) and "@" in addr and not addr.endswith(_PLACEHOLDER_SUFFIX)


def _build_security_email(event: Any, base_url: str) -> tuple[str, str]:
    """Build a metadata-only (subject, body) for a security exposure event."""
    severity = (event.severity or "").lower()
    sev_label = "Critical" if severity == "critical" else "High"
    is_resolved = event.event_type == EVENT_RESOLVED

    if is_resolved:
        subject = "[ConfigTrace] Security exposure resolved"
    else:
        verb = "re-opened" if event.event_type == EVENT_REOPENED else "opened"
        subject = f"[ConfigTrace] {sev_label} security exposure {verb}"

    provider = (event.provider or "").upper()
    lines = [
        subject,
        "",
        f"Severity: {severity or 'unknown'}",
        f"Provider: {provider or 'unknown'}",
        f"Title: {event.title}",
        f"Status: {event.status}",
        f"First detected: {event.first_detected_at or '-'}",
        f"Last seen: {event.last_seen_at or '-'}",
    ]
    if event.resolved_at:
        lines.append(f"Resolved at: {event.resolved_at}")
    lines.append("")
    lines.append(f"Exposure detail: {base_url}{event.detail_path}")
    if getattr(event, "linked_change_id", None):
        lines.append(f"Linked drift change: {base_url}/changes/{event.linked_change_id}")
    lines.append("")
    lines.append(
        "This reports a risky configuration state detected from connected "
        "provider metadata that may expose systems or could weaken security "
        "controls. It does not confirm any unauthorized access and does not "
        "inspect payloads, secrets, or customer data."
    )
    return subject, "\n".join(lines)


def dispatch_security_email_for_event(
    *,
    event: Any,
    settings: Any,
    base_url: str,
    fallback_recipient: Optional[str] = None,
) -> int:
    """Send security exposure email(s) for a single event. Returns count sent.

    Returns 0 (no send) when: email isn't configured; settings missing; the
    event isn't alertable (medium/low/info); or the workspace hasn't opted into
    the relevant category. Never raises — the sync worker must not fail.
    """
    from app.config import settings as _cfg

    if not _cfg.is_email_alerting_configured:
        return 0
    if settings is None:
        return 0
    if not getattr(event, "is_alertable", False):
        return 0

    is_resolved = event.event_type == EVENT_RESOLVED
    if is_resolved:
        if getattr(settings, "email_security_resolved_enabled", False) is not True:
            return 0
    else:
        if event.event_type not in (EVENT_OPENED, EVENT_REOPENED):
            return 0
        if getattr(settings, "email_security_alerts_enabled", False) is not True:
            return 0

    recipients = _parse_recipients(getattr(settings, "email_security_recipients", None))
    if not recipients and _valid_recipient(fallback_recipient):
        recipients = [fallback_recipient]  # type: ignore[list-item]
    if not recipients:
        logger.info(
            "security_email_alerts: no valid recipient  finding_id=%s",
            getattr(event, "finding_id", "?"),
        )
        return 0

    subject, body = _build_security_email(event, base_url)
    sent = 0
    for addr in recipients:
        try:
            email_service.send_email(to=addr, subject=subject, body=body)
            sent += 1
        except Exception:
            logger.exception(
                "security_email_alerts: send failed  finding_id=%s",
                getattr(event, "finding_id", "?"),
            )

    if sent:
        logger.info(
            "security_email_alerts: sent=%d finding_id=%s event=%s",
            sent,
            getattr(event, "finding_id", "?"),
            event.event_type,
        )
    return sent
