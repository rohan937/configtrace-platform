"""Jira configuration activity ingestion (M86D).

Jira's audit log / issue / user activity APIs are identity-heavy: every entry
includes actor account IDs, actor emails, IP addresses, user agents, issue
keys, and issue content.  ConfigTrace NEVER ingests from those endpoints.
Instead, this service synthesizes config-state activity events from the same
safe configuration posture records the Jira drift connector already stored in
ConfigTrace's database (M86A–M86C) — site, projects, boards, workflows,
workflow schemes, permission schemes, notification schemes, issue type
schemes, field configuration schemes, screen schemes, webhooks, and automation
rules.

INGESTION SCOPE (deliberate):
  Only configuration posture summaries persisted by the drift connector: opaque
  IDs, safe booleans, counts, and category labels.  Raw Jira API responses,
  audit logs, issue content, comment bodies, attachment content, actor
  identities, JQL, filter expressions, and operational payloads are NEVER
  fetched, ingested, or stored.

CLAIM DISCIPLINE: events are configuration activity evidence for review. This
service does NOT confirm a breach, attacker, compromise, unauthorized access,
data exposure, or leaked credential.  Each event is Jira configuration activity
that may require review.

NON-FATAL BY DESIGN: missing snapshots / missing integration / malformed
records are captured in the returned summary, never raised.

PRIVACY: only allowlisted, flat, safe fields are stored — opaque IDs, safe
booleans, counts, and category labels. NEVER stored:
- Jira API tokens, OAuth tokens, webhook secrets, integration secrets.
- Raw webhook / delivery URLs, site base URLs, redirect URLs.
- JQL, filter expressions, board column/quick-filter/swimlane names.
- Issue keys, issue titles, issue descriptions, comments, attachments.
- Customer names, user emails, user names, account IDs, member identities.
- IP addresses, user agents, request/response payloads.
- Raw audit payloads, raw API response dicts.
- Customer data or PII of any kind.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "jira"
SOURCE = "jira_activity_event"
EVENT_SOURCE = "jira_activity_event"

# Map each Jira drift record_type → its config-state event type.  Any other
# jira_ record type falls back to the generic "jira.config.event"; non-Jira
# record types are ignored entirely.
_RECORD_TYPE_TO_EVENT_TYPE: dict[str, str] = {
    "jira_site": "jira.site.updated",
    "jira_project": "jira.project.updated",
    "jira_board": "jira.board.updated",
    "jira_workflow": "jira.workflow.updated",
    "jira_workflow_scheme": "jira.workflow_scheme.updated",
    "jira_permission_scheme": "jira.permission_scheme.updated",
    "jira_notification_scheme": "jira.notification_scheme.updated",
    "jira_issue_type_scheme": "jira.issue_type_scheme.updated",
    "jira_field_configuration_scheme": "jira.field_configuration_scheme.updated",
    "jira_screen_scheme": "jira.screen_scheme.updated",
    "jira_webhook": "jira.webhook.updated",
    "jira_automation_rule": "jira.automation_rule.updated",
}

_FALLBACK_EVENT_TYPE = "jira.config.event"

# Hard allowlist of Jira config-state event types.  Only these may be
# normalized and stored.  Raw audit/issue/comment/user event types can NEVER
# be added here.
_JIRA_CONFIG_EVENT_TYPES: frozenset[str] = frozenset(
    set(_RECORD_TYPE_TO_EVENT_TYPE.values()) | {_FALLBACK_EVENT_TYPE}
)

# Expose for tests and the router.
JIRA_CONFIG_EVENT_TYPES = _JIRA_CONFIG_EVENT_TYPES
RECORD_TYPE_TO_EVENT_TYPE = _RECORD_TYPE_TO_EVENT_TYPE

# Per record_type, the opaque-ID metadata key that names the resource.  Lets a
# downstream consumer correlate an event back to a specific config object
# without ever storing an identity-linked id.
_RECORD_TYPE_TO_ID_KEY: dict[str, str] = {
    "jira_site": "site_id",
    "jira_project": "project_id",
    "jira_board": "board_id",
    "jira_workflow": "workflow_id",
    "jira_workflow_scheme": "workflow_scheme_id",
    "jira_permission_scheme": "permission_scheme_id",
    "jira_notification_scheme": "notification_scheme_id",
    "jira_issue_type_scheme": "issue_type_scheme_id",
    "jira_field_configuration_scheme": "field_configuration_scheme_id",
    "jira_screen_scheme": "screen_scheme_id",
    "jira_webhook": "webhook_id",
    "jira_automation_rule": "automation_rule_id",
}

# Safe count/boolean/category fields that may be copied from a drift record
# into event metadata, keyed by record_type.  Every key here is also present in
# ALLOWED_METADATA_KEYS — the sanitizer is a second, hard privacy gate.  No raw
# text, URLs, JQL, identities, secrets, or payloads ever appear in these lists.
_SAFE_FIELDS_BY_RECORD_TYPE: dict[str, tuple[str, ...]] = {
    "jira_site": (
        "deployment_type",
        "major_version",
        "build_number",
        "scm_info_present",
        # Schema-aligned site rollup fields (M86H).
        "site_url_present",
        "project_count",
        "webhook_count",
        "automation_rule_count",
    ),
    "jira_project": (
        "has_key",
        "project_type_key",
        "style",
        "is_private",
        "is_archived",
        "is_deleted",
        "is_simplified",
        # Schema-aligned project fields (M86H).
        "project_key_present",
        "project_type_category",
        "project_private",
        "project_archived",
        "project_deleted",
        "project_simplified",
        "project_style_category",
        "lead_present",
    ),
    "jira_board": (
        "board_type",
        "location_present",
        # Schema-aligned board fields (M86H).
        "board_type_category",
        "board_location_type_category",
        "board_filter_present",
        "board_jql_filter_broad",
        "board_column_count",
        "board_quick_filter_count",
        "board_swimlane_strategy_category",
    ),
    "jira_workflow": (
        "is_default",
        "transition_count",
        "status_count",
        "has_description",
        # Schema-aligned workflow fields (M86H).
        "workflow_status_count",
        "workflow_transition_count",
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
    "jira_workflow_scheme": (
        "is_default",
        "issue_type_mapping_count",
        "has_draft",
        "has_description",
        # Schema-aligned workflow scheme fields (M86H).
        "workflow_scheme_project_count",
        "workflow_scheme_default_present",
        "workflow_scheme_workflow_count",
        "workflow_scheme_issue_type_mapping_count",
        "workflow_scheme_unmapped_issue_type_count",
    ),
    "jira_permission_scheme": (
        "permission_grant_count",
        "has_description",
        # Schema-aligned permission scheme fields (M86H).
        "permission_anonymous_grant_count",
        "permission_anyone_grant_count",
        "permission_logged_in_grant_count",
        "permission_project_role_grant_count",
        "permission_public_browse_projects",
        "permission_public_administer_projects",
        "permission_public_manage_sprints",
        "permission_public_create_issues",
        "permission_public_transition_issues",
        "permission_unknown_holder_count",
        "permission_high_privilege_grant_count",
        "permission_public_grant_count",
    ),
    "jira_notification_scheme": (
        "event_count",
        "notification_count",
        "has_description",
        # Schema-aligned notification scheme fields (M86H).
        "notification_email_recipient_count",
        "notification_group_recipient_count",
        "notification_project_role_recipient_count",
        "notification_all_watchers_recipient_count",
        "notification_unknown_recipient_count",
        "notification_event_count",
    ),
    "jira_issue_type_scheme": (
        "is_default",
        "has_default_issue_type",
        "has_description",
        # Schema-aligned issue type scheme fields (M86H).
        "issue_type_count",
        "default_issue_type_present",
    ),
    "jira_field_configuration_scheme": (
        "has_description",
        # Schema-aligned field configuration scheme fields (M86H).
        "field_configuration_count",
        "required_field_count",
        "hidden_field_count",
    ),
    "jira_screen_scheme": (
        "screen_mapping_count",
        "has_default_screen",
        "has_description",
        # Schema-aligned screen scheme fields (M86H).
        "screen_count",
        "tab_count",
        "field_count",
        "screen_tab_count",
        "screen_unmapped_screen_count",
    ),
    "jira_webhook": (
        "enabled",
        "event_count",
        "webhook_url_present",
        "webhook_url_scheme_category",
        "has_filter",
        # Schema-aligned webhook fields (M86H).
        "webhook_enabled",
        "webhook_event_count",
        "webhook_jql_filter_present",
        "webhook_secret_present",
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
    "jira_automation_rule": (
        "enabled",
        "state",
        "component_count",
        "has_description",
        # Schema-aligned automation rule fields (M86H).
        "automation_enabled",
        "automation_trigger_type_category",
        "automation_component_count",
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


def _event_type_for_record_type(record_type: Optional[str]) -> Optional[str]:
    """Map a record_type to its event_type, or None if it is not a Jira type.

    Returns the generic fallback event type for any unrecognised ``jira_``
    record type, and None for non-Jira record types (which are ignored safely).
    """
    if not isinstance(record_type, str) or not record_type.strip():
        return None
    rt = record_type.strip()
    if rt in _RECORD_TYPE_TO_EVENT_TYPE:
        return _RECORD_TYPE_TO_EVENT_TYPE[rt]
    if rt.startswith("jira_"):
        return _FALLBACK_EVENT_TYPE
    return None


def compute_jira_event_id(
    *,
    record_type: str,
    resource_id: str,
    updated_at: str,
) -> str:
    """Deterministic event id: hash(provider + record_type + resource_id + updated_at).

    Re-running the ingest with the same record observed at the same time yields
    the same id, so ``upsert_activity_event`` treats it as an idempotent no-op.
    """
    basis = "|".join([PROVIDER, record_type, resource_id, updated_at])
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return f"jira:{digest[:40]}"


def build_jira_activity_event(
    record: dict[str, Any],
    *,
    updated_at: str,
) -> Optional[dict[str, Any]]:
    """Synthesize one config-state activity entry from a safe Jira drift record.

    Returns a flat entry dict (event_type, provider, source, event_source,
    provider_event_id, metadata) ready for ``normalize_jira_activity_event``,
    or None for:
      * malformed records (not a dict, no record_type), OR
      * non-Jira record types (ignored safely).

    Only allowlisted safe fields are copied into metadata.  Raw text, URLs,
    JQL, identities, secrets, and payloads are NEVER included.
    """
    if not isinstance(record, dict):
        return None

    record_type = record.get("record_type")
    event_type = _event_type_for_record_type(record_type)
    if event_type is None:
        return None

    rt = str(record_type).strip()
    resource_id = (
        record.get("resource_id")
        or record.get("record_id")
        or "unknown"
    )
    resource_id = str(resource_id)[: activity_svc.MAX_STR_LEN]

    eid = compute_jira_event_id(
        record_type=rt,
        resource_id=resource_id,
        updated_at=updated_at,
    )

    metadata: dict[str, Any] = {
        "resource_type": rt,
        "resource_id": resource_id,
        "operation_family": "configuration",
        "operation_action": "updated",
        "jira_event_id": eid,
    }

    # Name the resource via its record-type-specific opaque id key.
    id_key = _RECORD_TYPE_TO_ID_KEY.get(rt)
    if id_key is not None:
        metadata[id_key] = resource_id

    # Copy only the safe count/boolean/category fields for this record type.
    for field in _SAFE_FIELDS_BY_RECORD_TYPE.get(rt, ()):  # () for fallback type
        if field in record:
            value = record.get(field)
            if isinstance(value, (bool, int, float, str)):
                metadata[field] = value

    return {
        "event_type": event_type,
        "provider": PROVIDER,
        "source": SOURCE,
        "event_source": EVENT_SOURCE,
        "provider_event_id": eid,
        "metadata": metadata,
    }


def normalize_jira_activity_event(
    entry: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Map one config-state entry → a normalized activity event.

    The ``entry`` dict is produced by ``build_jira_activity_event`` and contains
    only safe flat fields: event_type, provider, source, event_source,
    provider_event_id, metadata.

    Returns None for:
      * malformed entries missing required fields, OR
      * ANY event_type not in the Jira config-event allowlist.

    This is a hard privacy gate: audit/issue/comment/user event types can NEVER
    be normalized or stored, even if a caller passes them.

    NEVER touches raw Jira API payloads, API tokens, OAuth tokens, webhook
    secrets, raw URLs, JQL, issue content, user identities, or any
    credential/PII material.
    """
    if not isinstance(entry, dict):
        return None

    event_type = entry.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        return None

    # Hard allowlist gate — drop any non-config event type.
    if event_type not in _JIRA_CONFIG_EVENT_TYPES:
        return None

    provider_event_id: Optional[str] = entry.get("provider_event_id") or None
    if isinstance(provider_event_id, str) and not provider_event_id.strip():
        provider_event_id = None

    metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}

    resource_type = metadata.get("resource_type") or None
    resource_id = metadata.get("resource_id") or None

    # Compute deterministic fingerprint fallback if no stable provider_event_id.
    if not provider_event_id:
        provider_event_id = activity_svc.compute_event_fingerprint(
            provider=PROVIDER,
            source=SOURCE,
            event_type=event_type,
            actor_id=None,
            resource_id=resource_id,
            occurred_at=None,
        )

    metadata_with_source = dict(metadata)
    metadata_with_source["event_source"] = EVENT_SOURCE

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        occurred_at=None,
        provider_event_id=provider_event_id,
        # Jira config-state synthesized events carry no actor identity — we
        # intentionally store no actor to avoid any risk of ingesting PII.
        actor_id=None,
        actor_type=None,
        resource_type=resource_type,
        resource_id=resource_id,
        source_ip=None,
        metadata=metadata_with_source,
        raw_ref=provider_event_id or None,
    )


def _empty_summary(lookback_hours: int, max_events: int) -> dict[str, Any]:
    return {
        "provider": PROVIDER,
        "source": SOURCE,
        "events_scanned": 0,
        "events_created": 0,
        "events_skipped": 0,
        "groups_scanned": 0,
        "lookback_hours": lookback_hours,
        "max_events": max_events,
    }


def _latest_snapshot_for_resource(
    db: Session, resource: Resource
) -> Optional[Snapshot]:
    """Return the most recent snapshot for a resource, or None."""
    return (
        db.query(Snapshot)
        .filter(Snapshot.resource_id == resource.id)
        .order_by(Snapshot.created_at.desc())
        .first()
    )


def ingest_jira_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Synthesize Jira configuration activity events from stored drift records.

    Reads the latest snapshot per Jira resource for this integration, maps each
    safe drift record to a config-state activity event, applies the lookback
    and max-events caps, and idempotently stores each event.

    Never raises.  All errors are captured in the returned summary dict.

    Args:
        integration:    A ``jira`` Integration model row.
        workspace_id:   Workspace UUID for storage scoping.
        db:             Database session.
        lookback_hours: Only process records observed within this window
                        (1–168 hours; capped internally).
        max_events:     Maximum events to create (1–1000; capped internally).

    Returns:
        Summary dict compatible with JiraActivitySyncResponse.
    """
    lookback_hours = min(max(1, int(lookback_hours)), 168)
    max_events = min(max(1, int(max_events)), 1000)
    summary = _empty_summary(lookback_hours, max_events)

    if integration.provider != PROVIDER:
        return summary

    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    try:
        resources = (
            db.query(Resource)
            .filter(Resource.integration_id == integration.id)
            .all()
        )
    except Exception:  # noqa: BLE001
        logger.exception("jira_activity: failed to load resources")
        return summary

    scanned = created = skipped = groups = 0

    for resource in resources:
        snapshot = _latest_snapshot_for_resource(db, resource)
        if snapshot is None:
            continue
        groups += 1

        # Snapshot observation time is the record's "updated_at".  Apply the
        # lookback cap: skip whole snapshots observed before the cutoff.
        observed_at = getattr(snapshot, "created_at", None)
        if isinstance(observed_at, datetime):
            obs = observed_at
            if obs.tzinfo is None:
                obs = obs.replace(tzinfo=timezone.utc)
            if obs < cutoff:
                continue
            updated_at = obs.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            # No usable timestamp — fall back to a day-scoped marker so the
            # event id stays deterministic per UTC day.
            updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        state = snapshot.state if isinstance(snapshot.state, list) else []
        for record in state:
            if not isinstance(record, dict):
                continue
            entry = build_jira_activity_event(record, updated_at=updated_at)
            if entry is None:
                continue  # non-Jira / malformed record ignored safely
            scanned += 1

            normalized = normalize_jira_activity_event(entry)
            if normalized is None:
                continue

            if created >= max_events:
                # Reached the max-events cap; stop creating new events.
                break

            try:
                outcome, _row = activity_svc.upsert_activity_event(
                    workspace_id=workspace_id,
                    integration_id=integration.id,
                    normalized=normalized,
                    db=db,
                )
            except Exception:  # noqa: BLE001
                logger.warning(
                    "jira_activity: failed to upsert one event; continuing"
                )
                continue
            if outcome == "inserted":
                created += 1
            else:
                skipped += 1

        if created >= max_events:
            break

    summary["events_scanned"] = scanned
    summary["events_created"] = created
    summary["events_skipped"] = skipped
    summary["groups_scanned"] = groups
    return summary


def sync_jira_activity(
    *,
    workspace_id: uuid.UUID,
    integration_id: Optional[str],
    lookback_hours: int = 24,
    max_events: int = 100,
    db: Session,
) -> dict[str, Any]:
    """Look up the Jira integration and delegate to ingest_jira_activity.

    Convenience wrapper used by the router endpoint.  Never raises — all errors
    are captured in the returned summary dict.

    Args:
        workspace_id:   Workspace UUID for storage scoping.
        integration_id: Optional integration UUID string to target a specific
                        integration; when None the first active Jira
                        integration for the workspace is used.
        lookback_hours: Lookback window (1–168 hours; capped internally).
        max_events:     Maximum events to create (1–1000; capped internally).
        db:             Database session.

    Returns:
        Summary dict compatible with JiraActivitySyncResponse.
    """
    summary = _empty_summary(
        min(max(1, int(lookback_hours)), 168),
        min(max(1, int(max_events)), 1000),
    )

    try:
        q = db.query(Integration).filter(
            Integration.provider == PROVIDER,
            Integration.workspace_id == workspace_id,
        )

        if integration_id:
            try:
                iid = uuid.UUID(str(integration_id))
            except (ValueError, AttributeError, TypeError):
                return summary
            integration = q.filter(Integration.id == iid).first()
            if integration is None:
                return summary
        else:
            integration = (
                q.filter(Integration.status == "active")
                .order_by(Integration.created_at.asc())
                .first()
            )
            if integration is None:
                return summary

        return ingest_jira_activity(
            integration=integration,
            workspace_id=workspace_id,
            db=db,
            lookback_hours=lookback_hours,
            max_events=max_events,
        )
    except Exception:  # noqa: BLE001
        logger.exception("jira_activity: unexpected error in sync_jira_activity")
        return summary
