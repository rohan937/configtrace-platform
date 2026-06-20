"""Jira Configuration Activity Incident Signals (M86E).

Promotes Jira configuration-state activity events (provider=jira,
source=jira_activity_event, synthesized in M86D) into review-worthy
Incident Signals covering site, project, board, workflow, workflow scheme,
permission scheme, notification scheme, issue type scheme, field
configuration scheme, screen scheme, webhook, and automation rule
configuration activity.

Conservative + deterministic + idempotent: events are grouped by
(signal_type, resource_identity); each group yields one signal anchored on
the group's latest event, with a deterministic signal_key so re-running
creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration review signals.
They NEVER assert that a breach, compromise, unauthorized access, leaked
secret, exposed data, or attacker presence has been confirmed. Severity
reflects review priority only — Jira configuration activity that may require
review.

PRIVACY: signal metadata is allowlisted + flat. NEVER stored:
- Jira API tokens, OAuth tokens, webhook secrets, integration secrets
- Raw webhook / delivery URLs, site base URLs, redirect URLs
- JQL, filter expressions, board column/quick-filter/swimlane names
- Issue keys, issue titles, issue descriptions, comments, attachments
- Customer names, user emails, user names, account IDs, member identities
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

PROVIDER = "jira"
SOURCE = "jira_activity_event"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is Jira configuration activity evidence for review and may require review. "
    "ConfigTrace does not confirm compromise, unauthorized access, or data exposure."
)

# ── Event type → signal_type ──────────────────────────────────────────────────
JIRA_EVENT_TYPE_TO_SIGNAL_TYPE: dict[str, str] = {
    "jira.site.updated": "jira_site_config_changed",
    "jira.project.updated": "jira_project_config_changed",
    "jira.board.updated": "jira_board_config_changed",
    "jira.workflow.updated": "jira_workflow_config_changed",
    "jira.workflow_scheme.updated": "jira_workflow_scheme_config_changed",
    "jira.permission_scheme.updated": "jira_permission_scheme_config_changed",
    "jira.notification_scheme.updated": "jira_notification_scheme_config_changed",
    "jira.issue_type_scheme.updated": "jira_issue_type_scheme_config_changed",
    "jira.field_configuration_scheme.updated": "jira_field_configuration_scheme_config_changed",
    "jira.screen_scheme.updated": "jira_screen_scheme_config_changed",
    "jira.webhook.updated": "jira_webhook_config_changed",
    "jira.automation_rule.updated": "jira_automation_rule_config_changed",
    "jira.config.event": "jira_config_activity",
}

JIRA_SIGNAL_TYPES: frozenset[str] = frozenset(
    JIRA_EVENT_TYPE_TO_SIGNAL_TYPE.values()
)

# Per signal_type, the record-type-specific opaque-ID metadata key to carry
# forward onto the signal so a consumer can correlate the signal back to a
# specific config object — without ever storing an identity-linked id.
_SIGNAL_TYPE_TO_ID_KEY: dict[str, str] = {
    "jira_site_config_changed": "site_id",
    "jira_project_config_changed": "project_id",
    "jira_board_config_changed": "board_id",
    "jira_workflow_config_changed": "workflow_id",
    "jira_workflow_scheme_config_changed": "workflow_scheme_id",
    "jira_permission_scheme_config_changed": "permission_scheme_id",
    "jira_notification_scheme_config_changed": "notification_scheme_id",
    "jira_issue_type_scheme_config_changed": "issue_type_scheme_id",
    "jira_field_configuration_scheme_config_changed": "field_configuration_scheme_id",
    "jira_screen_scheme_config_changed": "screen_scheme_id",
    "jira_webhook_config_changed": "webhook_id",
    "jira_automation_rule_config_changed": "automation_rule_id",
}

# Safe count/boolean/category fields per signal_type that may be carried from
# the activity-event metadata onto the signal. Every key here is also present
# in ALLOWED_METADATA_KEYS — the sanitizer is a second, hard privacy gate. No
# raw text, URLs, JQL, identities, secrets, or payloads ever appear here.
_SAFE_FIELDS_BY_SIGNAL_TYPE: dict[str, tuple[str, ...]] = {
    "jira_site_config_changed": (
        "deployment_type",
        "major_version",
        "build_number",
        "scm_info_present",
    ),
    "jira_project_config_changed": (
        "has_key",
        "project_type_key",
        "style",
        "is_private",
        "is_archived",
        "is_deleted",
        "is_simplified",
    ),
    "jira_board_config_changed": (
        "board_type",
        "location_present",
        "board_filter_present",
        "board_jql_filter_broad",
        "board_column_count",
        "board_quick_filter_count",
        "board_swimlane_strategy_category",
    ),
    "jira_workflow_config_changed": (
        "is_default",
        "transition_count",
        "status_count",
        "has_description",
        "workflow_global_transition_count",
        "workflow_active",
        "workflow_draft",
        "workflow_has_done_status",
        "workflow_has_in_progress_status",
        "workflow_transition_rule_count",
        "workflow_validator_count",
        "workflow_condition_count",
        "workflow_post_function_count",
        "workflow_orphan_status_count",
        "workflow_status_category_count",
    ),
    "jira_workflow_scheme_config_changed": (
        "is_default",
        "issue_type_mapping_count",
        "has_draft",
        "has_description",
        "workflow_scheme_workflow_count",
        "workflow_scheme_issue_type_mapping_count",
        "workflow_scheme_unmapped_issue_type_count",
    ),
    "jira_permission_scheme_config_changed": (
        "permission_grant_count",
        "has_description",
        "permission_public_browse_projects",
        "permission_public_administer_projects",
        "permission_public_manage_sprints",
        "permission_public_create_issues",
        "permission_public_transition_issues",
        "permission_unknown_holder_count",
        "permission_high_privilege_grant_count",
        "permission_public_grant_count",
    ),
    "jira_notification_scheme_config_changed": (
        "event_count",
        "notification_count",
        "has_description",
        "notification_all_watchers_recipient_count",
        "notification_unknown_recipient_count",
        "notification_event_count",
    ),
    "jira_issue_type_scheme_config_changed": (
        "is_default",
        "has_default_issue_type",
        "has_description",
    ),
    "jira_field_configuration_scheme_config_changed": (
        "has_description",
    ),
    "jira_screen_scheme_config_changed": (
        "screen_mapping_count",
        "has_default_screen",
        "has_description",
        "screen_tab_count",
        "screen_unmapped_screen_count",
    ),
    "jira_webhook_config_changed": (
        "enabled",
        "event_count",
        "webhook_url_present",
        "webhook_url_scheme_category",
        "has_filter",
        "webhook_has_issue_events",
        "webhook_has_comment_events",
        "webhook_has_attachment_events",
        "webhook_has_project_events",
        "webhook_has_sprint_events",
        "webhook_has_worklog_events",
        "webhook_all_issue_events",
        "webhook_jql_empty_or_broad",
        "webhook_event_scope_category",
    ),
    "jira_automation_rule_config_changed": (
        "enabled",
        "state",
        "component_count",
        "has_description",
        "automation_action_count",
        "automation_condition_count",
        "automation_branch_count",
        "automation_scope_category",
        "automation_has_web_request_action",
        "automation_has_email_action",
        "automation_has_external_action",
        "automation_has_comment_action",
    ),
}


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


def _mdval(ev: SecurityActivityEvent, key: str) -> Optional[Any]:
    """Read a safe scalar metadata field (bool/int/float/str) (never raises)."""
    data = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = data.get(key)
    if isinstance(v, (bool, int, float, str)):
        return v
    return None


def _resource_key(ev: SecurityActivityEvent) -> str:
    """Pick the most specific safe resource identifier for grouping.

    Uses safe opaque identifiers only — NEVER Jira API tokens, OAuth tokens,
    webhook secrets, raw webhook/delivery URLs, site base URLs, JQL, filter
    expressions, issue keys, issue content, comment bodies, attachment content,
    user emails, user names, account IDs, IP addresses, user agents, raw audit
    payloads, or any credential/PII.
    """
    return (
        _md(ev, "resource_id")
        or ev.resource_id
        or "global"
    )


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    """Deterministic group key — one signal per (signal_type, resource)."""
    signal_type = JIRA_EVENT_TYPE_TO_SIGNAL_TYPE.get(ev.event_type)
    if signal_type is None:
        return None
    rkey = _resource_key(ev)
    return "|".join(["jira.activity", signal_type, rkey])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id)."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(signal_type: str) -> str:
    """Conservative review-priority severity. Never asserts confirmed impact."""
    if signal_type in (
        "jira_site_config_changed",
        "jira_permission_scheme_config_changed",
        "jira_webhook_config_changed",
        "jira_automation_rule_config_changed",
    ):
        return "medium"
    # Project, board, workflow, workflow scheme, notification scheme, issue
    # type scheme, field configuration scheme, screen scheme, and generic
    # config events are lower review priority.
    return "low"


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    signal_type = JIRA_EVENT_TYPE_TO_SIGNAL_TYPE.get(anchor.event_type)
    if signal_type is None:
        return None

    # Collect unique event types in this group (sorted for determinism).
    unique_event_types = sorted({ev.event_type for ev in group})
    event_types_str = ", ".join(unique_event_types)

    resource_type = _md(anchor, "resource_type") or anchor.resource_type or "configuration"

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    title = (
        f"Jira {resource_type} activity: {len(group)} "
        f"{signal_type.replace('_', ' ')} event(s)"
    )
    summary = (
        f"Review-worthy Jira configuration activity detected on {resource_type}. "
        f"{len(group)} event(s) recorded in the review window. "
        f"Does not confirm compromise or unauthorized access — this is a "
        f"configuration signal for review. "
        f"{_REVIEW_NOTE}"
    ).strip()

    gk = _group_key(anchor)

    # Gather safe metadata fields from anchor event.
    # PRIVACY: NEVER include Jira API tokens, OAuth tokens, webhook secrets,
    # raw webhook/delivery URLs, site base URLs, JQL, filter expressions, issue
    # keys, issue titles, issue descriptions, comment bodies, attachment
    # content, customer names, user emails, user names, account IDs, member
    # identities, IP addresses, user agents, request/response payloads, raw
    # audit payloads, or PII.
    md_raw: dict[str, Any] = {
        "provider": PROVIDER,
        "source": SOURCE,
        "event_source": _md(anchor, "event_source") or SOURCE,
        "event_type": anchor.event_type,
        "event_types": event_types_str,
        "signal_type": signal_type,
        "event_count": len(group),
        "record_type": _md(anchor, "record_type") or _md(anchor, "resource_type"),
        "resource_type": resource_type,
        "resource_id": _md(anchor, "resource_id"),
        "operation_family": "jira_configuration",
        "operation_action": "configuration_updated",
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
    }

    # Carry forward the record-type-specific opaque resource id key.
    id_key = _SIGNAL_TYPE_TO_ID_KEY.get(signal_type)
    if id_key is not None:
        md_raw[id_key] = _md(anchor, id_key) or _md(anchor, "resource_id")

    # Copy only the safe count/boolean/category fields for this signal type.
    for field in _SAFE_FIELDS_BY_SIGNAL_TYPE.get(signal_type, ()):
        value = _mdval(anchor, field)
        if value is not None:
            md_raw[field] = value

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


def generate_jira_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Jira configuration review signals for a workspace.

    Reads normalized jira / jira_activity_event activity events (M86D) and
    promotes selected config-state events into Incident Signals. Idempotent —
    re-running creates no duplicates. Never raises.

    PRIVACY: only safe, allowlisted fields are stored in signal metadata. Jira
    API tokens, OAuth tokens, webhook secrets, raw webhook/delivery URLs, site
    base URLs, JQL, filter expressions, issue keys, issue titles, issue
    descriptions, comment bodies, attachment content, customer names, user
    emails, user names, account IDs, member identities, IP addresses, user
    agents, request/response payloads, raw audit payloads, and customer PII are
    never stored.

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
                "jira_signals: failed to build or upsert one group; continuing"
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
