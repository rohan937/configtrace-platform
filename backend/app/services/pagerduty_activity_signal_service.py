"""PagerDuty Configuration Activity Incident Signals (M84E).

Promotes PagerDuty configuration-state activity events (provider=pagerduty,
source=pagerduty_activity_event, synthesized in M84D) into review-worthy
Incident Signals covering service, escalation policy, schedule, service
integration, webhook subscription, event orchestration, business service,
and response play configuration activity.

Conservative + deterministic + idempotent: events are grouped by
(signal_type, resource_identity); each group yields one signal anchored on
the group's latest event, with a deterministic signal_key so re-running
creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration review signals.
They NEVER assert that a breach, compromise, unauthorized access, leaked
secret, exposed data, or attacker presence has been confirmed. Severity
reflects review priority only.

PRIVACY: signal metadata is allowlisted + flat. NEVER stored:
- PagerDuty API tokens, routing keys, integration keys
- Webhook secrets, delivery URLs, custom header names/values
- User emails, user names, phone numbers, contact methods
- On-call user identities, responder identities, subscriber identities
- Incident payloads, alert payloads, conference phone numbers
- Raw routing expressions, IP addresses, user agents
- Raw PagerDuty audit payloads, raw API response dicts
- Customer data, PII of any kind.
Only safe opaque identifiers, booleans, counts, and category labels.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "pagerduty"
SOURCE = "pagerduty_activity_event"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is PagerDuty configuration activity evidence for review and may require "
    "review. ConfigTrace does not confirm compromise, unauthorized access, or data "
    "exposure."
)

# ── Event type → signal_type ──────────────────────────────────────────────────
PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE: dict[str, str] = {
    "pagerduty.service.updated": "pagerduty_service_config_changed",
    "pagerduty.escalation_policy.updated": "pagerduty_escalation_policy_config_changed",
    "pagerduty.schedule.updated": "pagerduty_schedule_config_changed",
    "pagerduty.service_integration.updated": "pagerduty_service_integration_config_changed",
    "pagerduty.webhook_subscription.updated": "pagerduty_webhook_subscription_config_changed",
    "pagerduty.event_orchestration.updated": "pagerduty_event_orchestration_config_changed",
    "pagerduty.business_service.updated": "pagerduty_business_service_config_changed",
    "pagerduty.response_play.updated": "pagerduty_response_play_config_changed",
    "pagerduty.config.event": "pagerduty_config_activity",
}

PAGERDUTY_SIGNAL_TYPES: frozenset[str] = frozenset(
    PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE.values()
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
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _resource_key(ev: SecurityActivityEvent) -> str:
    """Pick the most specific safe resource identifier for grouping.

    Uses safe opaque identifiers only — NEVER PagerDuty API tokens, routing
    keys, integration keys, webhook secrets, delivery URLs, user emails, user
    names, phone numbers, contact methods, IP addresses, incident payloads,
    alert payloads, or any credential/PII.
    """
    return (
        _md(ev, "resource_id")
        or ev.resource_id
        or "global"
    )


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    """Deterministic group key — one signal per (signal_type, resource)."""
    signal_type = PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE.get(ev.event_type)
    if signal_type is None:
        return None
    rkey = _resource_key(ev)
    return "|".join(["pagerduty.activity", signal_type, rkey])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id)."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(signal_type: str) -> str:
    """Conservative review-priority severity. Never asserts confirmed impact."""
    if signal_type in (
        "pagerduty_service_config_changed",
        "pagerduty_escalation_policy_config_changed",
        "pagerduty_webhook_subscription_config_changed",
    ):
        return "medium"
    # Schedule, integration, orchestration, business service, response play,
    # and generic config events are lower review priority.
    return "low"


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    signal_type = PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE.get(anchor.event_type)
    if signal_type is None:
        return None

    # Collect unique event types in this group (sorted for determinism).
    unique_event_types = sorted({ev.event_type for ev in group})
    event_types_str = ", ".join(unique_event_types)

    resource_type = _md(anchor, "resource_type") or anchor.resource_type or "configuration"

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    title = (
        f"PagerDuty {resource_type} activity: {len(group)} "
        f"{signal_type.replace('_', ' ')} event(s)"
    )
    summary = (
        f"Review-worthy PagerDuty incident-response configuration activity detected "
        f"on {resource_type}. "
        f"{len(group)} event(s) recorded in the review window. "
        f"Does not confirm compromise or unauthorized access — escalation "
        f"configuration evidence for review. "
        f"{_REVIEW_NOTE}"
    ).strip()

    gk = _group_key(anchor)

    # Gather safe metadata fields from anchor event.
    # PRIVACY: NEVER include PagerDuty API tokens, routing keys, integration
    # keys, webhook secrets, delivery URLs, custom header values, user emails,
    # user names, phone numbers, contact methods, on-call user identities,
    # responder identities, subscriber identities, incident payloads, alert
    # payloads, conference phone numbers, raw routing expressions, IP addresses,
    # user agents, raw PagerDuty audit payloads, or customer PII.
    md_raw: dict[str, Any] = {
        "source": SOURCE,
        "event_types": event_types_str,
        "event_count": len(group),
        "resource_type": resource_type,
        "resource_id": _md(anchor, "resource_id"),
        "operation_family": _md(anchor, "operation_family"),
        "operation_action": _md(anchor, "operation_action"),
        "category": _md(anchor, "category"),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        # Safe service posture fields
        "status_category": _md(anchor, "status_category"),
        "alert_creation_category": _md(anchor, "alert_creation_category"),
        "acknowledgement_timeout_category": _md(anchor, "acknowledgement_timeout_category"),
        "auto_resolve_timeout_category": _md(anchor, "auto_resolve_timeout_category"),
        "support_hours_enabled": _mdbool(anchor, "support_hours_enabled"),
        "scheduled_actions_count": _mdint(anchor, "scheduled_actions_count"),
        # Safe escalation policy posture fields
        "escalation_rule_count": _mdint(anchor, "escalation_rule_count"),
        "escalation_level_count": _mdint(anchor, "escalation_level_count"),
        "target_count": _mdint(anchor, "target_count"),
        "schedule_target_count": _mdint(anchor, "schedule_target_count"),
        "has_schedule_targets": _mdbool(anchor, "has_schedule_targets"),
        "repeat_enabled": _mdbool(anchor, "repeat_enabled"),
        # Safe schedule posture fields
        "layer_count": _mdint(anchor, "layer_count"),
        "user_count": _mdint(anchor, "user_count"),
        "team_count": _mdint(anchor, "team_count"),
        "restriction_count": _mdint(anchor, "restriction_count"),
        "has_restrictions": _mdbool(anchor, "has_restrictions"),
        "time_zone_present": _mdbool(anchor, "time_zone_present"),
        # Safe service integration posture fields
        "integration_type_category": _md(anchor, "integration_type_category"),
        "key_present": _mdbool(anchor, "key_present"),
        "routing_key_present": _mdbool(anchor, "routing_key_present"),
        # Safe webhook subscription posture fields
        "active": _mdbool(anchor, "active"),
        "event_count": _mdint(anchor, "event_count"),
        "url_scheme_category": _md(anchor, "url_scheme_category"),
        "event_scope_category": _md(anchor, "event_scope_category"),
        "custom_headers_present": _mdbool(anchor, "custom_headers_present"),
        # Safe event orchestration posture fields
        "route_count": _mdint(anchor, "route_count"),
        "team_present": _mdbool(anchor, "team_present"),
        # Safe response play posture fields
        "responder_count": _mdint(anchor, "responder_count"),
        "subscriber_count": _mdint(anchor, "subscriber_count"),
        "runnable": _md(anchor, "runnable"),
        "conference_present": _mdbool(anchor, "conference_present"),
        # Safe business service posture field
        "point_of_contact_present": _mdbool(anchor, "point_of_contact_present"),
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


def generate_pagerduty_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate PagerDuty configuration review signals for a workspace.

    Reads normalized pagerduty / pagerduty_activity_event activity events (M84D)
    and promotes selected config-state events into Incident Signals. Idempotent —
    re-running creates no duplicates. Never raises.

    PRIVACY: only safe, allowlisted fields are stored in signal metadata.
    PagerDuty API tokens, routing keys, integration keys, webhook secrets,
    delivery URLs, custom header values, user emails, user names, phone numbers,
    contact methods, on-call user identities, responder identities, subscriber
    identities, incident payloads, alert payloads, conference phone numbers,
    raw routing expressions, IP addresses, user agents, raw audit payloads,
    and customer PII are never stored.

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
                "pagerduty_signals: failed to build or upsert one group; continuing"
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
