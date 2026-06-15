"""Twilio Monitor Activity Incident Signals (M79E).

Promotes Twilio Monitor configuration-change events (provider=twilio,
source=twilio_activity_event, ingested in M79D) into review-worthy Incident
Signals covering phone number create/update/delete, messaging service
create/update/delete, messaging service sender pool changes, Verify service
create/update/delete, API key create/update/delete, and account configuration
changes.

Conservative + deterministic + idempotent: events are grouped by
(signal_type, resource_sid_prefix); each group yields one signal anchored on
the group's latest event, with a deterministic signal_key so re-running
creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration-change review signals.
They NEVER assert that a breach, compromise, unauthorized access, leaked
secret, exposed data, or attacker presence has been confirmed. Severity
reflects review priority only.

PRIVACY: signal metadata is allowlisted + flat. NEVER auth tokens, API key
secrets, full account SIDs, full phone number strings, webhook/callback URL
strings, message bodies, call SIDs, call legs, recording data, customer PII
(caller name, verification payloads), raw Twilio API response dicts, raw HTTP
request or response bodies, or any value that could re-identify a customer or
expose a credential. Only the last-4 digits of a phone number (phone_number_last4)
are permitted — never full numbers.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "twilio"
SOURCE = "twilio_activity_event"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is evidence for review and may require review. ConfigTrace does not "
    "confirm compromise, unauthorized access, or data exposure."
)

# ── Event type → signal_type ──────────────────────────────────────────────────
TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE: dict[str, str] = {
    "twilio.phone_number.created": "twilio_phone_number_config_changed",
    "twilio.phone_number.updated": "twilio_phone_number_config_changed",
    "twilio.phone_number.deleted": "twilio_phone_number_config_changed",
    "twilio.messaging_service.created": "twilio_messaging_service_config_changed",
    "twilio.messaging_service.updated": "twilio_messaging_service_config_changed",
    "twilio.messaging_service.deleted": "twilio_messaging_service_config_changed",
    "twilio.messaging_service.sender_pool.updated": "twilio_messaging_sender_pool_changed",
    "twilio.verify_service.created": "twilio_verify_service_config_changed",
    "twilio.verify_service.updated": "twilio_verify_service_config_changed",
    "twilio.verify_service.deleted": "twilio_verify_service_config_changed",
    "twilio.api_key.created": "twilio_api_key_config_changed",
    "twilio.api_key.updated": "twilio_api_key_config_changed",
    "twilio.api_key.deleted": "twilio_api_key_config_changed",
    "twilio.account.updated": "twilio_account_config_changed",
    "twilio.config.event": "twilio_config_activity",
}

TWILIO_SIGNAL_TYPES: frozenset[str] = frozenset(
    TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE.values()
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


def _resource_key(ev: SecurityActivityEvent) -> str:
    """Pick the most specific resource identifier for grouping.

    Uses safe identifiers only — never full phone numbers, auth tokens, or
    API secrets.
    """
    return (
        _md(ev, "twilio_resource_sid_prefix")
        or _md(ev, "messaging_service_sid")
        or _md(ev, "verify_service_sid")
        or _md(ev, "api_key_sid")
        or "global"
    )


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    """Deterministic group key — one signal per (signal_type, resource)."""
    signal_type = TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE.get(ev.event_type)
    if signal_type is None:
        return None
    rkey = _resource_key(ev)
    return "|".join(["twilio.activity", signal_type, rkey])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id)."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(signal_type: str) -> str:
    """Conservative review-priority severity. Never asserts confirmed impact."""
    if signal_type in (
        "twilio_phone_number_config_changed",
        "twilio_messaging_service_config_changed",
        "twilio_messaging_sender_pool_changed",
        "twilio_verify_service_config_changed",
        "twilio_api_key_config_changed",
    ):
        return "medium"
    # account.updated and generic config events are low priority.
    return "low"


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    signal_type = TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE.get(anchor.event_type)
    if signal_type is None:
        return None

    # Collect unique event types in this group (sorted for determinism).
    unique_event_types = sorted({ev.event_type for ev in group})
    event_types_str = ", ".join(unique_event_types)

    resource_type = _md(anchor, "resource_type") or anchor.resource_type or "configuration"

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    title = (
        f"Twilio {resource_type} activity: {len(group)} "
        f"{signal_type.replace('_', ' ')} event(s)"
    )
    summary = (
        f"Review-worthy Twilio configuration activity detected on {resource_type}. "
        f"{len(group)} event(s) recorded in the review window. "
        f"Does not confirm compromise or unauthorized access — evidence for review. "
        f"{_REVIEW_NOTE}"
    ).strip()

    gk = _group_key(anchor)

    # Gather safe metadata fields from anchor event (never full phone number,
    # never auth token, never API secret, never webhook URL).
    md_raw: dict[str, Any] = {
        "source": SOURCE,
        "event_types": event_types_str,
        "event_count": len(group),
        "resource_type": resource_type,
        "twilio_resource_sid_prefix": _md(anchor, "twilio_resource_sid_prefix"),
        "messaging_service_sid": _md(anchor, "messaging_service_sid"),
        "verify_service_sid": _md(anchor, "verify_service_sid"),
        "api_key_sid": _md(anchor, "api_key_sid"),
        # phone_number_last4: last 4 digits ONLY — never the full number.
        "phone_number_last4": _md(anchor, "phone_number_last4"),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
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


def generate_twilio_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Twilio Monitor configuration-change review signals for a workspace.

    Reads normalized twilio / twilio_activity_event activity events and promotes
    selected control-plane change events into Incident Signals. Idempotent —
    re-running creates no duplicates. Never raises.

    PRIVACY: only safe, allowlisted fields are stored in signal metadata.
    Message bodies, call logs, recordings, full phone numbers, auth tokens,
    API secrets, webhook URLs, and customer data are never stored.

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
                "twilio_signals: failed to build or upsert one group; continuing"
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
