"""Datadog Configuration Activity Incident Signals (M82E).

Promotes Datadog configuration-state activity events (provider=datadog,
source=datadog_activity_event, synthesized in M82D) into review-worthy Incident
Signals covering monitor, SLO, dashboard, webhook integration, notification
integration, API key metadata, application key metadata, role, team, and cloud
integration configuration activity.

Conservative + deterministic + idempotent: events are grouped by
(signal_type, resource_identity); each group yields one signal anchored on
the group's latest event, with a deterministic signal_key so re-running
creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration review signals.
They NEVER assert that a breach, compromise, unauthorized access, leaked
secret, exposed data, or attacker presence has been confirmed. Severity
reflects review priority only.

PRIVACY: signal metadata is allowlisted + flat. NEVER stored:
- API key values, application key values, OAuth tokens, bearer tokens
- Webhook secrets, integration secrets
- Raw monitor queries or messages
- Raw dashboard JSON, widget queries
- Webhook URLs, custom headers, payload templates
- Notification handles, Slack channels, PagerDuty service IDs
- Email addresses, user names, user IDs
- Team member identities
- IP addresses, user agents
- Raw Datadog audit payloads, raw API response dicts
- Customer data, PII
Only safe opaque identifiers, booleans, counts, and category labels.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "datadog"
SOURCE = "datadog_activity_event"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is evidence for review and may require review. ConfigTrace does not "
    "confirm compromise, unauthorized access, or data exposure."
)

# ── Event type → signal_type ──────────────────────────────────────────────────
DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE: dict[str, str] = {
    "datadog.monitor.created": "datadog_monitor_config_changed",
    "datadog.monitor.updated": "datadog_monitor_config_changed",
    "datadog.monitor.deleted": "datadog_monitor_config_changed",
    "datadog.slo.created": "datadog_slo_config_changed",
    "datadog.slo.updated": "datadog_slo_config_changed",
    "datadog.slo.deleted": "datadog_slo_config_changed",
    "datadog.dashboard.created": "datadog_dashboard_config_changed",
    "datadog.dashboard.updated": "datadog_dashboard_config_changed",
    "datadog.dashboard.deleted": "datadog_dashboard_config_changed",
    "datadog.webhook_integration.created": "datadog_webhook_integration_config_changed",
    "datadog.webhook_integration.updated": "datadog_webhook_integration_config_changed",
    "datadog.webhook_integration.deleted": "datadog_webhook_integration_config_changed",
    "datadog.notification_integration.created": "datadog_notification_integration_config_changed",
    "datadog.notification_integration.updated": "datadog_notification_integration_config_changed",
    "datadog.notification_integration.deleted": "datadog_notification_integration_config_changed",
    "datadog.api_key_metadata.created": "datadog_api_key_metadata_config_changed",
    "datadog.api_key_metadata.updated": "datadog_api_key_metadata_config_changed",
    "datadog.api_key_metadata.disabled": "datadog_api_key_metadata_config_changed",
    "datadog.api_key_metadata.deleted": "datadog_api_key_metadata_config_changed",
    "datadog.application_key_metadata.created": "datadog_application_key_metadata_config_changed",
    "datadog.application_key_metadata.updated": "datadog_application_key_metadata_config_changed",
    "datadog.application_key_metadata.deleted": "datadog_application_key_metadata_config_changed",
    "datadog.role.created": "datadog_role_config_changed",
    "datadog.role.updated": "datadog_role_config_changed",
    "datadog.role.deleted": "datadog_role_config_changed",
    "datadog.team.created": "datadog_team_config_changed",
    "datadog.team.updated": "datadog_team_config_changed",
    "datadog.team.deleted": "datadog_team_config_changed",
    "datadog.cloud_integration.created": "datadog_cloud_integration_config_changed",
    "datadog.cloud_integration.updated": "datadog_cloud_integration_config_changed",
    "datadog.cloud_integration.deleted": "datadog_cloud_integration_config_changed",
    "datadog.config.event": "datadog_config_activity",
}

DATADOG_SIGNAL_TYPES: frozenset[str] = frozenset(
    DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE.values()
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

    Uses safe opaque identifiers only — never API key values, application key
    values, webhook URLs, raw monitor queries, user emails, or any credential.
    """
    return (
        _md(ev, "monitor_id")
        or _md(ev, "slo_id")
        or _md(ev, "dashboard_id")
        or _md(ev, "webhook_id")
        or _md(ev, "notification_integration_id")
        or _md(ev, "api_key_id")
        or _md(ev, "application_key_id")
        or _md(ev, "role_id")
        or _md(ev, "team_id")
        or _md(ev, "cloud_integration_id")
        or _md(ev, "resource_id")
        or ev.resource_id
        or "global"
    )


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    """Deterministic group key — one signal per (signal_type, resource)."""
    signal_type = DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE.get(ev.event_type)
    if signal_type is None:
        return None
    rkey = _resource_key(ev)
    return "|".join(["datadog.activity", signal_type, rkey])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id)."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(signal_type: str) -> str:
    """Conservative review-priority severity. Never asserts confirmed impact."""
    if signal_type in (
        "datadog_monitor_config_changed",
        "datadog_slo_config_changed",
        "datadog_dashboard_config_changed",
        "datadog_webhook_integration_config_changed",
        "datadog_notification_integration_config_changed",
        "datadog_api_key_metadata_config_changed",
        "datadog_application_key_metadata_config_changed",
        "datadog_role_config_changed",
    ):
        return "medium"
    # Cloud integration, team, and generic config events are lower priority.
    return "low"


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    signal_type = DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE.get(anchor.event_type)
    if signal_type is None:
        return None

    unique_event_types = sorted({ev.event_type for ev in group})
    event_types_str = ", ".join(unique_event_types)

    resource_type = _md(anchor, "resource_type") or anchor.resource_type or "configuration"

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    title = (
        f"Datadog {resource_type} activity: {len(group)} "
        f"{signal_type.replace('_', ' ')} event(s)"
    )
    summary = (
        f"Review-worthy Datadog configuration activity detected on {resource_type}. "
        f"{len(group)} event(s) recorded in the review window. "
        f"Does not confirm compromise or unauthorized access — evidence for review. "
        f"{_REVIEW_NOTE}"
    ).strip()

    gk = _group_key(anchor)

    # Gather safe metadata fields from anchor event.
    # PRIVACY: NEVER include API key values, application key values, OAuth tokens,
    # bearer tokens, webhook secrets, raw monitor queries, raw monitor messages,
    # raw dashboard JSON, webhook URLs, headers, payload templates, notification
    # handles, Slack channels, PagerDuty service IDs, email addresses, user IDs,
    # team member identities, IP addresses, user agents, raw audit payloads, or PII.
    md_raw: dict[str, Any] = {
        "source": SOURCE,
        "event_types": event_types_str,
        "event_count": len(group),
        "resource_type": resource_type,
        "resource_id": _md(anchor, "resource_id"),
        "resource_name": _md(anchor, "resource_name"),
        # Safe opaque resource identifiers — NEVER key values or credentials.
        "monitor_id": _md(anchor, "monitor_id"),
        "slo_id": _md(anchor, "slo_id"),
        "dashboard_id": _md(anchor, "dashboard_id"),
        "webhook_id": _md(anchor, "webhook_id"),
        "notification_integration_id": _md(anchor, "notification_integration_id"),
        "api_key_id": _md(anchor, "api_key_id"),
        "application_key_id": _md(anchor, "application_key_id"),
        "role_id": _md(anchor, "role_id"),
        "team_id": _md(anchor, "team_id"),
        "cloud_integration_id": _md(anchor, "cloud_integration_id"),
        "operation_family": _md(anchor, "operation_family"),
        "operation_action": _md(anchor, "operation_action"),
        "category": _md(anchor, "category"),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        # Safe monitor config posture fields (never raw query or message text).
        "monitor_type": _md(anchor, "monitor_type"),
        "enabled": _mdbool(anchor, "enabled"),
        "status_category": _md(anchor, "status_category"),
        "priority_category": _md(anchor, "priority_category"),
        "query_present": _mdbool(anchor, "query_present"),
        "query_complexity_category": _md(anchor, "query_complexity_category"),
        "message_present": _mdbool(anchor, "message_present"),
        "message_length_category": _md(anchor, "message_length_category"),
        "notification_routing_present": _mdbool(anchor, "notification_routing_present"),
        "notification_count": _mdint(anchor, "notification_count"),
        "message_template_present": _mdbool(anchor, "message_template_present"),
        "query_uses_wildcard_scope": _mdbool(anchor, "query_uses_wildcard_scope"),
        "query_group_by_count": _mdint(anchor, "query_group_by_count"),
        "threshold_critical_present": _mdbool(anchor, "threshold_critical_present"),
        "threshold_warning_present": _mdbool(anchor, "threshold_warning_present"),
        "threshold_recovery_present": _mdbool(anchor, "threshold_recovery_present"),
        "threshold_count": _mdint(anchor, "threshold_count"),
        "renotify_enabled": _mdbool(anchor, "renotify_enabled"),
        "renotify_interval_category": _md(anchor, "renotify_interval_category"),
        "restricted_roles_count": _mdint(anchor, "restricted_roles_count"),
        "notify_audit": _mdbool(anchor, "notify_audit"),
        "require_full_window": _mdbool(anchor, "require_full_window"),
        "silenced_scope_count": _mdint(anchor, "silenced_scope_count"),
        "no_data_timeframe_category": _md(anchor, "no_data_timeframe_category"),
        "tag_count": _mdint(anchor, "tag_count"),
        # Safe SLO config posture fields.
        "slo_type": _md(anchor, "slo_type"),
        "target_category": _md(anchor, "target_category"),
        "warning_target_category": _md(anchor, "warning_target_category"),
        "timeframe_count": _mdint(anchor, "timeframe_count"),
        "monitor_count": _mdint(anchor, "monitor_count"),
        "group_count": _mdint(anchor, "group_count"),
        # Safe dashboard config posture fields (never raw JSON or widget queries).
        "layout_type": _md(anchor, "layout_type"),
        "widget_count": _mdint(anchor, "widget_count"),
        "template_variable_count": _mdint(anchor, "template_variable_count"),
        "public_url_present": _mdbool(anchor, "public_url_present"),
        # Safe webhook integration config posture fields
        # (never URL, headers, payload, or secrets).
        "url_present": _mdbool(anchor, "url_present"),
        "url_scheme_category": _md(anchor, "url_scheme_category"),
        "custom_headers_present": _mdbool(anchor, "custom_headers_present"),
        "custom_header_count": _mdint(anchor, "custom_header_count"),
        "auth_material_present": _mdbool(anchor, "auth_material_present"),
        "payload_template_present": _mdbool(anchor, "payload_template_present"),
        "payload_template_length_category": _md(anchor, "payload_template_length_category"),
        "secret_headers_present": _mdbool(anchor, "secret_headers_present"),
        "secret_headers_count": _mdint(anchor, "secret_headers_count"),
        "encode_as_category": _md(anchor, "encode_as_category"),
        # Safe notification integration config posture fields
        # (never destination handles, channel names, or service keys).
        "integration_type": _md(anchor, "integration_type"),
        "handle_count": _mdint(anchor, "handle_count"),
        "channel_count": _mdint(anchor, "channel_count"),
        # Safe key metadata posture fields (never key value or last4 digits).
        "created_present": _mdbool(anchor, "created_present"),
        "modified_present": _mdbool(anchor, "modified_present"),
        "created_by_present": _mdbool(anchor, "created_by_present"),
        "scopes_count": _mdint(anchor, "scopes_count"),
        "owned_by_present": _mdbool(anchor, "owned_by_present"),
        # Safe role config posture fields (never user identities).
        "permission_count": _mdint(anchor, "permission_count"),
        "user_count": _mdint(anchor, "user_count"),
        "team_count": _mdint(anchor, "team_count"),
        # Safe team config posture fields (never member identities or handles).
        "member_count": _mdint(anchor, "member_count"),
        "handle_present": _mdbool(anchor, "handle_present"),
        "link_count": _mdint(anchor, "link_count"),
        # Safe cloud integration config posture fields (never account IDs).
        "cloud_provider": _md(anchor, "cloud_provider"),
        "account_id_present": _mdbool(anchor, "account_id_present"),
        "resource_collection_enabled": _mdbool(anchor, "resource_collection_enabled"),
        "metric_collection_enabled": _mdbool(anchor, "metric_collection_enabled"),
        "log_collection_enabled": _mdbool(anchor, "log_collection_enabled"),
        "account_tags_count": _mdint(anchor, "account_tags_count"),
        "namespace_count": _mdint(anchor, "namespace_count"),
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


def generate_datadog_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Datadog configuration review signals for a workspace.

    Reads normalized datadog / datadog_activity_event activity events (M82D) and
    promotes selected config-state events into Incident Signals. Idempotent —
    re-running creates no duplicates. Never raises.

    PRIVACY: only safe, allowlisted fields are stored in signal metadata.
    API key values, application key values, OAuth tokens, bearer tokens,
    webhook secrets, raw monitor queries/messages, raw dashboard JSON,
    webhook URLs/headers/payload templates, notification handles, email
    addresses, user IDs, team member identities, IP addresses, user agents,
    and raw Datadog audit payloads are never stored.

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
                "datadog_signals: failed to build or upsert one group; continuing"
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
