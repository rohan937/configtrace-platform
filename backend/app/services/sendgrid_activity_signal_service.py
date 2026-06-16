"""SendGrid Configuration Activity Incident Signals (M80E).

Promotes SendGrid configuration-state activity events (provider=sendgrid,
source=sendgrid_activity_event, synthesized in M80D) into review-worthy Incident
Signals covering account configuration, API key management, sender identity,
domain authentication, mail/tracking settings, event webhook, inbound parse,
and suppression settings changes.

Conservative + deterministic + idempotent: events are grouped by
(signal_type, resource_identity); each group yields one signal anchored on
the group's latest event, with a deterministic signal_key so re-running
creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration review signals.
They NEVER assert that a breach, compromise, unauthorized access, leaked
secret, exposed data, or attacker presence has been confirmed. Severity
reflects review priority only.

PRIVACY: signal metadata is allowlisted + flat. NEVER API key values, bearer
tokens, authorization headers, email bodies, subject lines, recipient emails,
sender personal emails, suppression recipient emails, template content, raw
webhook URLs, raw inbound parse hostnames, mail event payloads (bounce/click/
open/delivered/dropped/spamreport/unsubscribe/processed), message IDs, raw
SendGrid API responses, raw HTTP request/response bodies, customer data, or PII.
Only safe booleans, counts, opaque identifiers, and configuration summaries.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "sendgrid"
SOURCE = "sendgrid_activity_event"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is evidence for review and may require review. ConfigTrace does not "
    "confirm compromise, unauthorized access, or data exposure."
)

# ── Event type → signal_type ──────────────────────────────────────────────────
SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE: dict[str, str] = {
    "sendgrid.account.updated": "sendgrid_account_config_changed",
    "sendgrid.api_key.created": "sendgrid_api_key_config_changed",
    "sendgrid.api_key.updated": "sendgrid_api_key_config_changed",
    "sendgrid.api_key.deleted": "sendgrid_api_key_config_changed",
    "sendgrid.sender_identity.created": "sendgrid_sender_identity_config_changed",
    "sendgrid.sender_identity.updated": "sendgrid_sender_identity_config_changed",
    "sendgrid.sender_identity.verified": "sendgrid_sender_identity_config_changed",
    "sendgrid.sender_identity.deleted": "sendgrid_sender_identity_config_changed",
    "sendgrid.domain_authentication.created": "sendgrid_domain_authentication_config_changed",
    "sendgrid.domain_authentication.updated": "sendgrid_domain_authentication_config_changed",
    "sendgrid.domain_authentication.deleted": "sendgrid_domain_authentication_config_changed",
    "sendgrid.mail_settings.updated": "sendgrid_mail_settings_config_changed",
    "sendgrid.tracking_settings.updated": "sendgrid_tracking_settings_config_changed",
    "sendgrid.event_webhook.updated": "sendgrid_event_webhook_config_changed",
    "sendgrid.inbound_parse.updated": "sendgrid_inbound_parse_config_changed",
    "sendgrid.suppression_settings.updated": "sendgrid_suppression_settings_config_changed",
    "sendgrid.config.event": "sendgrid_config_activity",
}

SENDGRID_SIGNAL_TYPES: frozenset[str] = frozenset(
    SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE.values()
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> datetime:
    if not isinstance(dt, datetime):
        return datetime.min.replace(tzinfo=timezone.utc)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _when(ev: SecurityActivityEvent) -> datetime:
    return _aware(ev.occurred_at or ev.ingested_at or ev.created_at)


def _md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    """Read a string metadata field from the activity event (never raises)."""
    data = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = data.get(key)
    return v if isinstance(v, str) and v.strip() else None


def _mdbool(ev: SecurityActivityEvent, key: str) -> Optional[bool]:
    """Read a bool metadata field from the activity event (never raises)."""
    data = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = data.get(key)
    return v if isinstance(v, bool) else None


def _mdint(ev: SecurityActivityEvent, key: str) -> Optional[int]:
    """Read an int metadata field from the activity event (never raises)."""
    data = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = data.get(key)
    return v if isinstance(v, int) else None


def _resource_key(ev: SecurityActivityEvent) -> str:
    """Pick the most specific safe resource identifier for grouping.

    Uses safe opaque identifiers only — never email addresses, API key values,
    webhook URLs, hostnames, or any customer data.
    """
    return (
        _md(ev, "api_key_id")
        or _md(ev, "sender_id")
        or _md(ev, "domain_id")
        or _md(ev, "resource_id")
        or ev.resource_id
        or "global"
    )


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    """Deterministic group key — one signal per (signal_type, resource)."""
    signal_type = SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE.get(ev.event_type)
    if signal_type is None:
        return None
    rkey = _resource_key(ev)
    return "|".join(["sendgrid.activity", signal_type, rkey])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id)."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(signal_type: str) -> str:
    """Conservative review-priority severity. Never asserts confirmed impact."""
    if signal_type in (
        "sendgrid_api_key_config_changed",
        "sendgrid_event_webhook_config_changed",
        "sendgrid_inbound_parse_config_changed",
        "sendgrid_sender_identity_config_changed",
        "sendgrid_domain_authentication_config_changed",
    ):
        return "medium"
    # Account, mail/tracking settings, suppression, and generic config events
    # are lower review priority.
    return "low"


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    signal_type = SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE.get(anchor.event_type)
    if signal_type is None:
        return None

    # Collect unique event types in this group (sorted for determinism).
    unique_event_types = sorted({ev.event_type for ev in group})
    event_types_str = ", ".join(unique_event_types)

    resource_type = _md(anchor, "resource_type") or anchor.resource_type or "configuration"

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    title = (
        f"SendGrid {resource_type} activity: {len(group)} "
        f"{signal_type.replace('_', ' ')} event(s)"
    )
    summary = (
        f"Review-worthy SendGrid configuration activity detected on {resource_type}. "
        f"{len(group)} event(s) recorded in the review window. "
        f"Does not confirm compromise or unauthorized access — evidence for review. "
        f"{_REVIEW_NOTE}"
    ).strip()

    gk = _group_key(anchor)

    # Gather safe metadata fields from anchor event.
    # PRIVACY: NEVER include API key values, email addresses, webhook URLs,
    # hostnames, raw payloads, or any customer/PII data.
    md_raw: dict[str, Any] = {
        "source": SOURCE,
        "event_types": event_types_str,
        "event_count": len(group),
        "resource_type": resource_type,
        "resource_id": _md(anchor, "resource_id"),
        "resource_name": _md(anchor, "resource_name"),
        "api_key_id": _md(anchor, "api_key_id"),
        "sender_id": _md(anchor, "sender_id"),
        "domain_id": _md(anchor, "domain_id"),
        "mail_setting_name": _md(anchor, "mail_setting_name"),
        "tracking_setting_name": _md(anchor, "tracking_setting_name"),
        "operation_family": _md(anchor, "operation_family"),
        "operation_action": _md(anchor, "operation_action"),
        "category": _md(anchor, "category"),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        # Safe boolean/count config fields — never raw URLs, hostnames, or content.
        "event_webhook_enabled": _mdbool(anchor, "event_webhook_enabled"),
        "event_webhook_has_url": _mdbool(anchor, "event_webhook_has_url"),
        "inbound_parse_enabled": _mdbool(anchor, "inbound_parse_enabled"),
        "inbound_parse_spam_check_enabled": _mdbool(anchor, "inbound_parse_spam_check_enabled"),
        "inbound_parse_send_raw_enabled": _mdbool(anchor, "inbound_parse_send_raw_enabled"),
        "domain_valid": _mdbool(anchor, "domain_valid"),
        "automatic_security": _mdbool(anchor, "automatic_security"),
        "dns_record_count": _mdint(anchor, "dns_record_count"),
        "sender_verified": _mdbool(anchor, "sender_verified"),
        "sender_locked": _mdbool(anchor, "sender_locked"),
        "suppression_group_count": _mdint(anchor, "suppression_group_count"),
    }

    metadata = signal_svc.sanitize_signal_metadata(md_raw)

    return {
        "provider": PROVIDER,
        "integration_id": anchor.integration_id,
        "signal_key": gk,
        "signal_type": signal_type,
        "severity": _severity(signal_type),
        "status": "open",
        "title": title[:240],
        "summary": summary,
        "evidence_level": EVIDENCE_LEVEL,
        "confidence": CONFIDENCE,
        "first_seen_at": window_start,
        "last_seen_at": window_end,
        "linked_activity_event_id": anchor.id,
        "metadata": metadata,
    }


def generate_sendgrid_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate SendGrid configuration review signals for a workspace.

    Reads normalized sendgrid / sendgrid_activity_event activity events and
    promotes selected config-state events into Incident Signals. Idempotent —
    re-running creates no duplicates. Never raises.

    PRIVACY: only safe, allowlisted fields are stored in signal metadata.
    API key values, email bodies, subject lines, recipient emails, template
    content, raw webhook URLs, raw inbound parse hostnames, mail event payloads
    (bounce/click/open/delivered/dropped/spamreport/unsubscribe/processed),
    message IDs, and customer data are never stored.

    Args:
        workspace_id:   Workspace UUID for data scoping.
        db:             Database session.
        lookback_hours: Lookback window (1–168 hours; capped internally).
        max_signals:    Maximum signals to create (1–1000; capped internally).
        scan_limit:     Maximum activity events to scan.

    Returns:
        Summary dict with provider/source/events_scanned/groups_scanned/
        signals_created/signals_skipped fields.
    """
    hours = max(1, min(int(lookback_hours or 24), 168))
    cap = max(1, min(int(max_signals or 100), 1000))
    cutoff = _utcnow() - timedelta(hours=hours)

    raw = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER,
            SecurityActivityEvent.source == SOURCE,
        )
        .order_by(
            SecurityActivityEvent.occurred_at.desc().nullslast(),
            SecurityActivityEvent.created_at.desc(),
        )
        .limit(scan_limit)
        .all()
    )
    events = [e for e in raw if _when(e) >= cutoff]

    groups: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        gk = _group_key(ev)
        if gk is None:
            continue
        groups.setdefault(gk, []).append(ev)

    created = skipped = 0
    for _gk, group in groups.items():
        if created >= cap:
            break
        try:
            signal = _build_signal(group)
            if signal is None:
                continue
            outcome, _row = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=signal, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1
        except Exception:  # noqa: BLE001
            import logging
            logging.getLogger(__name__).warning(
                "sendgrid_signals: failed to build or upsert one group; continuing"
            )
            continue

    return {
        "provider": PROVIDER,
        "source": SOURCE,
        "events_scanned": len(events),
        "groups_scanned": len(groups),
        "signals_created": created,
        "signals_skipped": skipped,
    }
