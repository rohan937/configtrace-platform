"""Terraform Cloud Configuration Activity Incident Signals (M88E).

Promotes Terraform Cloud configuration-state activity events (provider=
terraform_cloud, source=terraform_cloud_activity_event, synthesized in M88D)
into review-worthy Incident Signals covering organization access posture,
workspace execution, VCS, run control, variable posture, variable set scope,
policy set enforcement, notification transport, run trigger, team access
posture, and state version metadata.

Conservative + deterministic + idempotent: events are grouped by
(signal_type, resource_identity); each group yields one signal anchored on
the group's latest event, with a deterministic signal_key so re-running
creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration review signals.
They NEVER assert that a breach, compromise, unauthorized access, leaked
secret, state exposure, tfstate exposure, secret exposure, token leak,
credential exposure, infrastructure exposure, or data exposure has been
confirmed. Severity reflects review priority only — Terraform Cloud
configuration activity that may require review.

PRIVACY: signal metadata is allowlisted + flat. NEVER stored:
- Terraform Cloud API tokens, OAuth tokens, VCS tokens, authorization headers.
- Variable names or values, state files, state outputs, resource addresses.
- Plan logs, apply logs, run logs, webhook URLs, notification tokens.
- Organization names, workspace names, project names, VCS URLs, branch names.
- Commit SHAs, team names, user emails, usernames, Slack channels, email
  recipients, customer infrastructure data, PII.
- Raw API payloads, request/response bodies.
Only safe opaque identifiers, booleans, counts, and category labels.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "terraform_cloud"
SOURCE = "terraform_cloud_activity_event"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is Terraform Cloud configuration activity evidence for review and "
    "may require review. "
    "This does not confirm compromise, unauthorized access, state exposure, "
    "secret exposure, token exposure, credential exposure, infrastructure "
    "exposure, or data exposure."
)

# ── Event type → signal type ──────────────────────────────────────────────────
TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE: dict[str, str] = {
    # Organization access posture
    "terraform_cloud.organization.two_factor_not_required": "terraform_cloud_organization_access_posture_signal",
    "terraform_cloud.organization.sso_not_enabled": "terraform_cloud_organization_access_posture_signal",
    "terraform_cloud.organization.posture_changed": "terraform_cloud_organization_access_posture_signal",
    # Workspace execution/run posture
    "terraform_cloud.workspace.auto_apply_enabled": "terraform_cloud_workspace_auto_apply_signal",
    "terraform_cloud.workspace.global_remote_state_enabled": "terraform_cloud_workspace_global_remote_state_signal",
    "terraform_cloud.workspace.execution_mode_changed": "terraform_cloud_workspace_execution_mode_signal",
    "terraform_cloud.workspace.vcs_connection_missing": "terraform_cloud_workspace_vcs_posture_signal",
    "terraform_cloud.workspace.queue_all_runs_disabled": "terraform_cloud_workspace_run_control_signal",
    "terraform_cloud.workspace.file_triggers_disabled": "terraform_cloud_workspace_run_control_signal",
    "terraform_cloud.workspace.speculative_plans_disabled": "terraform_cloud_workspace_run_control_signal",
    "terraform_cloud.workspace.run_triggers_present": "terraform_cloud_workspace_run_control_signal",
    "terraform_cloud.workspace.latest_run_failed": "terraform_cloud_workspace_run_control_signal",
    "terraform_cloud.workspace.unpinned_terraform_version": "terraform_cloud_workspace_version_posture_signal",
    # Variable posture
    "terraform_cloud.variables.non_sensitive_variables_detected": "terraform_cloud_variable_posture_signal",
    "terraform_cloud.variables.no_sensitive_variables_detected": "terraform_cloud_variable_posture_signal",
    # Variable set scope posture
    "terraform_cloud.variable_set.global_scope_detected": "terraform_cloud_variable_set_scope_signal",
    "terraform_cloud.variable_set.broad_scope_detected": "terraform_cloud_variable_set_scope_signal",
    "terraform_cloud.variable_set.non_sensitive_variables_detected": "terraform_cloud_variable_set_scope_signal",
    # Policy set enforcement posture
    "terraform_cloud.policy_set.advisory_enforcement_detected": "terraform_cloud_policy_set_enforcement_signal",
    "terraform_cloud.policy_set.empty_detected": "terraform_cloud_policy_set_enforcement_signal",
    "terraform_cloud.policy_set.broad_scope_advisory_detected": "terraform_cloud_policy_set_enforcement_signal",
    # Policy set scope posture
    "terraform_cloud.policy_set.global_scope_detected": "terraform_cloud_policy_set_scope_signal",
    "terraform_cloud.policy_set.unscoped_detected": "terraform_cloud_policy_set_scope_signal",
    # Notification transport posture
    "terraform_cloud.notification.http_webhook_detected": "terraform_cloud_notification_transport_signal",
    "terraform_cloud.notification.token_missing": "terraform_cloud_notification_transport_signal",
    # Notification posture
    "terraform_cloud.notification.broad_trigger_scope": "terraform_cloud_notification_posture_signal",
    "terraform_cloud.notification.disabled": "terraform_cloud_notification_posture_signal",
    # Run trigger posture
    "terraform_cloud.run_trigger.enabled": "terraform_cloud_run_trigger_signal",
    # Team access posture
    "terraform_cloud.team_access.admin_detected": "terraform_cloud_team_access_posture_signal",
    "terraform_cloud.team_access.apply_detected": "terraform_cloud_team_access_posture_signal",
    "terraform_cloud.team_access.write_detected": "terraform_cloud_team_access_posture_signal",
    "terraform_cloud.team_access.custom_permissions_detected": "terraform_cloud_team_access_posture_signal",
    # State version metadata posture
    "terraform_cloud.state_version.metadata_present": "terraform_cloud_state_version_metadata_signal",
    # Generic fallback (not emitted in practice)
    "terraform_cloud.config.event": "terraform_cloud_configuration_activity_signal",
}

TERRAFORM_CLOUD_SIGNAL_TYPES: frozenset[str] = frozenset(
    TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE.values()
)

# ── Severity mapping per event type ──────────────────────────────────────────
# Conservative review-priority severity. Never asserts confirmed impact.
# High = immediately review-worthy configuration posture.
# Medium = significant posture signal worth review.
# Low = informational posture signal.
_EVENT_TYPE_SEVERITY: dict[str, str] = {
    # High
    "terraform_cloud.workspace.auto_apply_enabled": "high",
    "terraform_cloud.workspace.global_remote_state_enabled": "high",
    "terraform_cloud.notification.http_webhook_detected": "high",
    "terraform_cloud.team_access.admin_detected": "high",
    "terraform_cloud.variables.non_sensitive_variables_detected": "high",
    "terraform_cloud.variable_set.global_scope_detected": "high",
    "terraform_cloud.policy_set.broad_scope_advisory_detected": "high",
    # Medium
    "terraform_cloud.organization.two_factor_not_required": "medium",
    "terraform_cloud.organization.sso_not_enabled": "medium",
    "terraform_cloud.organization.posture_changed": "medium",
    "terraform_cloud.workspace.execution_mode_changed": "medium",
    "terraform_cloud.workspace.vcs_connection_missing": "medium",
    "terraform_cloud.workspace.queue_all_runs_disabled": "medium",
    "terraform_cloud.workspace.file_triggers_disabled": "medium",
    "terraform_cloud.workspace.run_triggers_present": "medium",
    "terraform_cloud.variable_set.broad_scope_detected": "medium",
    "terraform_cloud.variable_set.non_sensitive_variables_detected": "medium",
    "terraform_cloud.variables.no_sensitive_variables_detected": "medium",
    "terraform_cloud.policy_set.advisory_enforcement_detected": "medium",
    "terraform_cloud.policy_set.global_scope_detected": "medium",
    "terraform_cloud.notification.token_missing": "medium",
    "terraform_cloud.notification.broad_trigger_scope": "medium",
    "terraform_cloud.run_trigger.enabled": "medium",
    "terraform_cloud.team_access.apply_detected": "medium",
    "terraform_cloud.team_access.write_detected": "medium",
    # Low
    "terraform_cloud.workspace.unpinned_terraform_version": "low",
    "terraform_cloud.workspace.speculative_plans_disabled": "low",
    "terraform_cloud.workspace.latest_run_failed": "low",
    "terraform_cloud.policy_set.empty_detected": "low",
    "terraform_cloud.policy_set.unscoped_detected": "low",
    "terraform_cloud.notification.disabled": "low",
    "terraform_cloud.team_access.custom_permissions_detected": "low",
    "terraform_cloud.state_version.metadata_present": "low",
    "terraform_cloud.config.event": "low",
}

# Safe posture fields per signal type carried from activity-event metadata.
# All keys must also appear in security_incident_signal_service.ALLOWED_METADATA_KEYS.
# NEVER includes raw names, URLs, tokens, secrets, identities, or payloads.
_SAFE_FIELDS_BY_SIGNAL_TYPE: dict[str, tuple[str, ...]] = {
    "terraform_cloud_organization_access_posture_signal": (
        "organization_resource_id",
        "two_factor_requirement_enabled",
        "sso_enabled",
        "workspace_count",
        "policy_set_count",
        "variable_set_count",
    ),
    "terraform_cloud_workspace_auto_apply_signal": (
        "workspace_resource_id",
        "auto_apply",
        "execution_mode_category",
        "vcs_connected",
    ),
    "terraform_cloud_workspace_global_remote_state_signal": (
        "workspace_resource_id",
        "global_remote_state",
        "execution_mode_category",
    ),
    "terraform_cloud_workspace_execution_mode_signal": (
        "workspace_resource_id",
        "execution_mode_category",
        "vcs_connected",
        "auto_apply",
    ),
    "terraform_cloud_workspace_vcs_posture_signal": (
        "workspace_resource_id",
        "vcs_connected",
        "execution_mode_category",
    ),
    "terraform_cloud_workspace_run_control_signal": (
        "workspace_resource_id",
        "queue_all_runs",
        "file_triggers_enabled",
        "speculative_enabled",
        "run_trigger_count",
        "latest_run_status_category",
        "execution_mode_category",
    ),
    "terraform_cloud_workspace_version_posture_signal": (
        "workspace_resource_id",
        "terraform_version_category",
        "execution_mode_category",
    ),
    "terraform_cloud_variable_posture_signal": (
        "workspace_resource_id",
        "variable_count",
        "sensitive_variable_count",
        "non_sensitive_variable_count",
        "environment_variable_count",
        "terraform_variable_count",
        "raw_value_never_read",
    ),
    "terraform_cloud_variable_set_scope_signal": (
        "variable_set_resource_id",
        "global_scope",
        "workspace_count",
        "variable_count",
        "sensitive_variable_count",
        "non_sensitive_variable_count",
    ),
    "terraform_cloud_policy_set_enforcement_signal": (
        "policy_set_resource_id",
        "enforcement_level_category",
        "policy_count",
        "global_scope",
        "workspace_count",
    ),
    "terraform_cloud_policy_set_scope_signal": (
        "policy_set_resource_id",
        "global_scope",
        "workspace_count",
        "policy_count",
        "enforcement_level_category",
    ),
    "terraform_cloud_notification_transport_signal": (
        "notification_resource_id",
        "workspace_resource_id",
        "enabled",
        "destination_type_category",
        "webhook_url_scheme_category",
        "token_present",
        "trigger_count",
    ),
    "terraform_cloud_notification_posture_signal": (
        "notification_resource_id",
        "workspace_resource_id",
        "enabled",
        "destination_type_category",
        "trigger_count",
    ),
    "terraform_cloud_run_trigger_signal": (
        "run_trigger_resource_id",
        "workspace_resource_id",
        "sourceable_type_category",
    ),
    "terraform_cloud_team_access_posture_signal": (
        "workspace_resource_id",
        "team_access_count",
        "admin_access_count",
        "apply_access_count",
        "write_access_count",
        "custom_permission_count",
    ),
    "terraform_cloud_state_version_metadata_signal": (
        "workspace_resource_id",
        "state_version_present",
        "state_version_count_category",
        "raw_state_never_fetched",
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


def _mdval(ev: SecurityActivityEvent, key: str) -> Optional[Any]:
    """Read a safe scalar metadata field (bool/int/float/str) (never raises)."""
    data = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = data.get(key)
    if isinstance(v, (bool, int, float, str)):
        return v
    return None


def _resource_key(ev: SecurityActivityEvent) -> str:
    """Pick the most specific safe opaque resource identifier for grouping.

    Uses safe opaque identifiers only — NEVER Terraform Cloud API tokens,
    variable names/values, state files, webhook URLs, notification tokens,
    VCS URLs, organization/workspace/project names, team names, user emails,
    or other sensitive values.
    """
    return _md(ev, "resource_id") or ev.resource_id or "global"


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    """Deterministic group key — one signal per (signal_type, resource)."""
    signal_type = TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE.get(ev.event_type)
    if signal_type is None:
        return None
    rkey = _resource_key(ev)
    return "|".join(["terraform_cloud.activity", signal_type, rkey])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id)."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(event_type: str) -> str:
    """Conservative review-priority severity from the anchor event type.

    Never asserts confirmed impact — severity reflects review priority only.
    """
    return _EVENT_TYPE_SEVERITY.get(event_type, "medium")


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    signal_type = TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE.get(anchor.event_type)
    if signal_type is None:
        return None

    unique_event_types = sorted({ev.event_type for ev in group})
    event_types_str = ", ".join(unique_event_types)

    resource_type = (
        _md(anchor, "resource_type") or anchor.resource_type or "terraform_cloud_configuration"
    )

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    title = (
        f"Terraform Cloud {resource_type} activity: {len(group)} "
        f"{signal_type.replace('_', ' ')} event(s)"
    )
    summary = (
        f"Review-worthy Terraform Cloud configuration activity detected on {resource_type}. "
        f"{len(group)} event(s) recorded in the review window. "
        f"Does not confirm compromise or unauthorized access — this is a "
        f"Terraform Cloud configuration signal for review. "
        f"{_REVIEW_NOTE}"
    ).strip()

    gk = _group_key(anchor)

    # Gather safe metadata fields from anchor event.
    # PRIVACY: NEVER include Terraform Cloud API tokens, OAuth tokens, VCS tokens,
    # variable names/values, state files, state outputs, plan/apply logs, webhook
    # URLs, notification tokens, organization names, workspace names, project names,
    # VCS URLs, branch names, commit SHAs, team names, user emails, customer
    # infrastructure data, PII, or raw API payloads.
    md_raw: dict[str, Any] = {
        "provider": PROVIDER,
        "source": SOURCE,
        "event_source": _md(anchor, "event_source") or SOURCE,
        "event_type": anchor.event_type,
        "event_types": event_types_str,
        "signal_type": signal_type,
        "event_count": len(group),
        "record_type": _md(anchor, "resource_type"),
        "resource_type": resource_type,
        "resource_id": _md(anchor, "resource_id"),
        "operation_family": "terraform_cloud_configuration",
        "operation_action": "configuration_observed",
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "terraform_cloud_event_id": _md(anchor, "terraform_cloud_event_id"),
    }

    # Copy only the safe posture fields for this signal type.
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
        "severity": _severity(anchor.event_type),
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


def generate_terraform_cloud_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Terraform Cloud configuration review signals for a workspace.

    Reads normalized terraform_cloud / terraform_cloud_activity_event activity
    events (M88D) and promotes selected config-state events into Incident
    Signals. Idempotent — re-running creates no duplicates. Never raises.

    PRIVACY: only safe, allowlisted fields are stored in signal metadata.
    Terraform Cloud API tokens, OAuth tokens, VCS tokens, variable names/
    values, state files, state outputs, plan/apply logs, webhook URLs,
    notification tokens, organization names, workspace names, project names,
    VCS URLs, branch names, team names, user emails, customer infrastructure
    data, PII, and raw API payloads are never stored.

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
                "terraform_cloud_signals: failed to build or upsert one group; continuing"
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
