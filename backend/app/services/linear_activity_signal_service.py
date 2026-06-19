"""Linear Configuration Activity Incident Signals (M85E).

Promotes Linear configuration-state activity events (provider=linear,
source=linear_activity_event, synthesized in M85D) into review-worthy
Incident Signals covering workspace, team, project, workflow state, label,
webhook, view, cycle, and integration configuration activity.

Conservative + deterministic + idempotent: events are grouped by
(signal_type, resource_identity); each group yields one signal anchored on
the group's latest event, with a deterministic signal_key so re-running
creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration review signals.
They NEVER assert that a breach, compromise, unauthorized access, leaked
secret, exposed data, or attacker presence has been confirmed. Severity
reflects review priority only.

PRIVACY: signal metadata is allowlisted + flat. NEVER stored:
- Linear API key values, OAuth tokens
- Webhook secrets, raw webhook URLs
- Issue titles, descriptions, comments, attachments
- User emails, user names, member identities, customer names
- IP addresses, user agents, request/response payloads
- Raw audit payloads, raw API response dicts
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

PROVIDER = "linear"
SOURCE = "linear_activity_event"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is Linear configuration activity evidence for review. ConfigTrace does "
    "not confirm compromise, unauthorized access, or data exposure."
)

# -- Event type -> signal_type -----------------------------------------------
LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE: dict[str, str] = {
    "linear.workspace.updated": "linear_workspace_config_changed",
    "linear.team.updated": "linear_team_config_changed",
    "linear.project.updated": "linear_project_config_changed",
    "linear.workflow_state.updated": "linear_workflow_state_config_changed",
    "linear.label.updated": "linear_label_config_changed",
    "linear.webhook.updated": "linear_webhook_config_changed",
    "linear.view.updated": "linear_view_config_changed",
    "linear.cycle.updated": "linear_cycle_config_changed",
    "linear.integration.updated": "linear_integration_config_changed",
    "linear.config.event": "linear_config_activity",
}

LINEAR_SIGNAL_TYPES: frozenset[str] = frozenset(
    LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE.values()
)


# -- Helpers ------------------------------------------------------------------


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

    Uses safe opaque identifiers only -- NEVER Linear API keys, OAuth tokens,
    webhook secrets, raw webhook URLs, issue content, comment bodies,
    attachment content, user emails, user names, member identities, IP
    addresses, user agents, raw audit payloads, or any credential/PII.
    """
    return (
        _md(ev, "resource_id")
        or ev.resource_id
        or "global"
    )


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    """Deterministic group key -- one signal per (signal_type, resource)."""
    signal_type = LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE.get(ev.event_type)
    if signal_type is None:
        return None
    rkey = _resource_key(ev)
    return "|".join(["linear.activity", signal_type, rkey])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id)."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(signal_type: str) -> str:
    """Conservative review-priority severity. Never asserts confirmed impact."""
    if signal_type in (
        "linear_webhook_config_changed",
        "linear_workspace_config_changed",
        "linear_team_config_changed",
    ):
        return "medium"
    # Project, workflow state, label, view, cycle, integration, and generic
    # config events are lower review priority.
    return "low"


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    signal_type = LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE.get(anchor.event_type)
    if signal_type is None:
        return None

    # Collect unique event types in this group (sorted for determinism).
    unique_event_types = sorted({ev.event_type for ev in group})
    event_types_str = ", ".join(unique_event_types)

    resource_type = _md(anchor, "resource_type") or anchor.resource_type or "configuration"

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    title = (
        f"Linear {resource_type} activity: {len(group)} "
        f"{signal_type.replace('_', ' ')} event(s)"
    )
    summary = (
        f"Review-worthy Linear configuration activity detected on {resource_type}. "
        f"{len(group)} event(s) recorded in the review window. "
        f"Does not confirm compromise or unauthorized access -- configuration "
        f"activity evidence for review. "
        f"{_REVIEW_NOTE}"
    ).strip()

    gk = _group_key(anchor)

    # Gather safe metadata fields from anchor event.
    # PRIVACY: NEVER include Linear API keys, OAuth tokens, webhook secrets,
    # raw webhook URLs, issue titles, descriptions, comments, attachments,
    # user emails, user names, member identities, customer names, IP addresses,
    # user agents, request/response payloads, raw audit payloads, or PII.
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
        # Safe workspace posture fields
        "url_key_present": _mdbool(anchor, "url_key_present"),
        "logo_present": _mdbool(anchor, "logo_present"),
        "team_count": _mdint(anchor, "team_count"),
        "webhook_count": _mdint(anchor, "webhook_count"),
        "integration_count": _mdint(anchor, "integration_count"),
        # Safe team posture fields
        "private_team": _mdbool(anchor, "private_team"),
        "team_visibility_category": _md(anchor, "team_visibility_category"),
        "member_count_category": _md(anchor, "member_count_category"),
        "project_count": _mdint(anchor, "project_count"),
        "auto_archive_enabled": _mdbool(anchor, "auto_archive_enabled"),
        "cycle_enabled": _mdbool(anchor, "cycle_enabled"),
        "cycle_duration_category": _md(anchor, "cycle_duration_category"),
        "workflow_state_count": _mdint(anchor, "workflow_state_count"),
        "has_backlog_state": _mdbool(anchor, "has_backlog_state"),
        "has_started_state": _mdbool(anchor, "has_started_state"),
        "has_completed_state": _mdbool(anchor, "has_completed_state"),
        "has_canceled_state": _mdbool(anchor, "has_canceled_state"),
        "label_count": _mdint(anchor, "label_count"),
        # Safe project posture fields
        "project_status_category": _md(anchor, "project_status_category"),
        "project_health_category": _md(anchor, "project_health_category"),
        "lead_present": _mdbool(anchor, "lead_present"),
        "issue_count_category": _md(anchor, "issue_count_category"),
        # Safe workflow state posture fields
        "state_type_category": _md(anchor, "state_type_category"),
        "position_category": _md(anchor, "position_category"),
        # Safe label posture fields
        "is_group_label": _mdbool(anchor, "is_group_label"),
        "parent_id_present": _mdbool(anchor, "parent_id_present"),
        # Safe webhook posture fields
        "webhook_enabled": _mdbool(anchor, "webhook_enabled"),
        "webhook_secret_present": _mdbool(anchor, "webhook_secret_present"),
        "webhook_url_present": _mdbool(anchor, "webhook_url_present"),
        "webhook_url_scheme_category": _md(anchor, "webhook_url_scheme_category"),
        "webhook_resource_types_count": _mdint(anchor, "webhook_resource_types_count"),
        "webhook_has_comment_type": _mdbool(anchor, "webhook_has_comment_type"),
        "webhook_has_attachment_type": _mdbool(anchor, "webhook_has_attachment_type"),
        # Safe view posture fields
        "view_shared": _mdbool(anchor, "view_shared"),
        "filter_count_category": _md(anchor, "filter_count_category"),
        # Safe integration posture fields
        "integration_type_category": _md(anchor, "integration_type_category"),
        "integration_enabled": _mdbool(anchor, "integration_enabled"),
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


def generate_linear_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Linear configuration review signals for a workspace.

    Reads normalized linear / linear_activity_event activity events (M85D) and
    promotes selected config-state events into Incident Signals. Idempotent --
    re-running creates no duplicates. Never raises.

    PRIVACY: only safe, allowlisted fields are stored in signal metadata.
    Linear API keys, OAuth tokens, webhook secrets, raw webhook URLs, issue
    titles, descriptions, comments, attachments, user emails, user names,
    member identities, customer names, IP addresses, user agents,
    request/response payloads, raw audit payloads, and customer PII are never
    stored.

    Args:
        workspace_id:   Workspace UUID for data scoping.
        db:             Database session.
        lookback_hours: Lookback window (1-168 hours; capped internally).
        max_signals:    Maximum signals to create (1-1000; capped internally).
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
                "linear_signals: failed to build or upsert one group; continuing"
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
