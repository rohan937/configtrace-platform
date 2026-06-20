"""Terraform Cloud configuration activity ingestion (M88D).

Terraform Cloud's audit-log APIs are identity-heavy: every entry includes
actor user IDs, actor emails, IP addresses, and user agents.  ConfigTrace
NEVER ingests from those endpoints.  Instead, this service synthesizes
config-state activity events from the same safe configuration posture records
the Terraform Cloud drift connector already stored in ConfigTrace's database
(M88A–M88C): organization, workspaces, workspace variable summaries, variable
sets, policy sets, notification configurations, run triggers, team access
summaries, and state version summaries.

INGESTION SCOPE (deliberate):
  Only configuration posture summaries persisted by the drift connector: opaque
  IDs, safe booleans, counts, and category labels.  Raw Terraform Cloud API
  responses, audit logs, state files, state outputs, resource addresses,
  plan/apply logs, run logs, variable names/values, VCS repository names/URLs,
  branch names, commit SHAs, webhook URLs, notification tokens, team names,
  user emails, usernames, organization names, workspace names, project names,
  customer infrastructure data, and PII are NEVER fetched, ingested, or stored.

CLAIM DISCIPLINE: events are Terraform Cloud configuration activity evidence
for review.  This service does NOT confirm a breach, compromise, unauthorized
access, state exposure, secret exposure, token exposure, credential exposure,
infrastructure exposure, or data exposure.  Each event is Terraform Cloud
configuration activity that may require review.

NON-FATAL BY DESIGN: missing snapshots / missing integration / malformed
records are captured in the returned summary, never raised.

PRIVACY: only allowlisted, flat, safe fields are stored — opaque IDs, safe
booleans, counts, and category labels.  NEVER stored: Terraform Cloud API
tokens, OAuth tokens, VCS tokens, authorization headers, variable names or
values, Terraform state files, state outputs, resource addresses, plan logs,
apply logs, run logs, webhook URLs, notification tokens, Slack channels,
email recipients, user emails, usernames, team names, organization names,
workspace names, project names, VCS URLs, branch names, commit SHAs,
customer infrastructure data, PII, or raw API payloads.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.connectors.terraform_cloud_schema import (
    TERRAFORM_CLOUD_NOTIFICATION_CONFIGURATION,
    TERRAFORM_CLOUD_ORGANIZATION,
    TERRAFORM_CLOUD_POLICY_SET,
    TERRAFORM_CLOUD_RUN_TRIGGER,
    TERRAFORM_CLOUD_STATE_VERSION_SUMMARY,
    TERRAFORM_CLOUD_TEAM_ACCESS_SUMMARY,
    TERRAFORM_CLOUD_VARIABLE_SET,
    TERRAFORM_CLOUD_WORKSPACE,
    TERRAFORM_CLOUD_WORKSPACE_VARIABLE_SUMMARY,
)
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "terraform_cloud"
SOURCE = "terraform_cloud_activity_event"
EVENT_SOURCE = "terraform_cloud_activity_event"

# ── Event types (hard allowlist) ──────────────────────────────────────────────
# Every event type ConfigTrace may synthesize for Terraform Cloud.  Names are
# precise, stable, and review-safe — none claims breach, compromise, attack,
# leak, or confirmed exposure.  Raw audit/identity event types can NEVER be
# added.

# Organization posture
EVT_ORG_TWO_FACTOR_NOT_REQUIRED = "terraform_cloud.organization.two_factor_not_required"
EVT_ORG_SSO_NOT_ENABLED = "terraform_cloud.organization.sso_not_enabled"
EVT_ORG_POSTURE_CHANGED = "terraform_cloud.organization.posture_changed"

# Workspace execution/run posture
EVT_WORKSPACE_AUTO_APPLY_ENABLED = "terraform_cloud.workspace.auto_apply_enabled"
EVT_WORKSPACE_GLOBAL_REMOTE_STATE = "terraform_cloud.workspace.global_remote_state_enabled"
EVT_WORKSPACE_EXECUTION_MODE_CHANGED = "terraform_cloud.workspace.execution_mode_changed"
EVT_WORKSPACE_VCS_CONNECTION_MISSING = "terraform_cloud.workspace.vcs_connection_missing"
EVT_WORKSPACE_QUEUE_ALL_RUNS_DISABLED = "terraform_cloud.workspace.queue_all_runs_disabled"
EVT_WORKSPACE_UNPINNED_TF_VERSION = "terraform_cloud.workspace.unpinned_terraform_version"
EVT_WORKSPACE_FILE_TRIGGERS_DISABLED = "terraform_cloud.workspace.file_triggers_disabled"
EVT_WORKSPACE_SPECULATIVE_DISABLED = "terraform_cloud.workspace.speculative_plans_disabled"
EVT_WORKSPACE_RUN_TRIGGERS_PRESENT = "terraform_cloud.workspace.run_triggers_present"
EVT_WORKSPACE_LATEST_RUN_FAILED = "terraform_cloud.workspace.latest_run_failed"

# Variable posture
EVT_VARIABLES_NON_SENSITIVE = "terraform_cloud.variables.non_sensitive_variables_detected"
EVT_VARIABLES_NO_SENSITIVE = "terraform_cloud.variables.no_sensitive_variables_detected"

# Variable set posture
EVT_VARSET_GLOBAL_SCOPE = "terraform_cloud.variable_set.global_scope_detected"
EVT_VARSET_BROAD_SCOPE = "terraform_cloud.variable_set.broad_scope_detected"
EVT_VARSET_NON_SENSITIVE = "terraform_cloud.variable_set.non_sensitive_variables_detected"

# Policy set posture
EVT_POLICY_ADVISORY = "terraform_cloud.policy_set.advisory_enforcement_detected"
EVT_POLICY_EMPTY = "terraform_cloud.policy_set.empty_detected"
EVT_POLICY_GLOBAL_SCOPE = "terraform_cloud.policy_set.global_scope_detected"
EVT_POLICY_BROAD_SCOPE_ADVISORY = "terraform_cloud.policy_set.broad_scope_advisory_detected"
EVT_POLICY_UNSCOPED = "terraform_cloud.policy_set.unscoped_detected"

# Notification posture
EVT_NOTIFICATION_HTTP = "terraform_cloud.notification.http_webhook_detected"
EVT_NOTIFICATION_TOKEN_MISSING = "terraform_cloud.notification.token_missing"
EVT_NOTIFICATION_BROAD_TRIGGERS = "terraform_cloud.notification.broad_trigger_scope"
EVT_NOTIFICATION_DISABLED = "terraform_cloud.notification.disabled"

# Run trigger posture
EVT_RUN_TRIGGER_ENABLED = "terraform_cloud.run_trigger.enabled"

# Team access posture
EVT_TEAM_ADMIN = "terraform_cloud.team_access.admin_detected"
EVT_TEAM_APPLY = "terraform_cloud.team_access.apply_detected"
EVT_TEAM_WRITE = "terraform_cloud.team_access.write_detected"
EVT_TEAM_CUSTOM = "terraform_cloud.team_access.custom_permissions_detected"

# State version posture (metadata-only; NEVER fetches or claims state content)
EVT_STATE_VERSION_METADATA = "terraform_cloud.state_version.metadata_present"

# Forward-compat fallback (never emitted by this service)
EVT_CONFIG_EVENT = "terraform_cloud.config.event"

_TERRAFORM_CLOUD_CONFIG_EVENT_TYPES: frozenset[str] = frozenset(
    {
        EVT_ORG_TWO_FACTOR_NOT_REQUIRED,
        EVT_ORG_SSO_NOT_ENABLED,
        EVT_ORG_POSTURE_CHANGED,
        EVT_WORKSPACE_AUTO_APPLY_ENABLED,
        EVT_WORKSPACE_GLOBAL_REMOTE_STATE,
        EVT_WORKSPACE_EXECUTION_MODE_CHANGED,
        EVT_WORKSPACE_VCS_CONNECTION_MISSING,
        EVT_WORKSPACE_QUEUE_ALL_RUNS_DISABLED,
        EVT_WORKSPACE_UNPINNED_TF_VERSION,
        EVT_WORKSPACE_FILE_TRIGGERS_DISABLED,
        EVT_WORKSPACE_SPECULATIVE_DISABLED,
        EVT_WORKSPACE_RUN_TRIGGERS_PRESENT,
        EVT_WORKSPACE_LATEST_RUN_FAILED,
        EVT_VARIABLES_NON_SENSITIVE,
        EVT_VARIABLES_NO_SENSITIVE,
        EVT_VARSET_GLOBAL_SCOPE,
        EVT_VARSET_BROAD_SCOPE,
        EVT_VARSET_NON_SENSITIVE,
        EVT_POLICY_ADVISORY,
        EVT_POLICY_EMPTY,
        EVT_POLICY_GLOBAL_SCOPE,
        EVT_POLICY_BROAD_SCOPE_ADVISORY,
        EVT_POLICY_UNSCOPED,
        EVT_NOTIFICATION_HTTP,
        EVT_NOTIFICATION_TOKEN_MISSING,
        EVT_NOTIFICATION_BROAD_TRIGGERS,
        EVT_NOTIFICATION_DISABLED,
        EVT_RUN_TRIGGER_ENABLED,
        EVT_TEAM_ADMIN,
        EVT_TEAM_APPLY,
        EVT_TEAM_WRITE,
        EVT_TEAM_CUSTOM,
        EVT_STATE_VERSION_METADATA,
        EVT_CONFIG_EVENT,
    }
)

# Expose for tests and the router.
TERRAFORM_CLOUD_CONFIG_EVENT_TYPES = _TERRAFORM_CLOUD_CONFIG_EVENT_TYPES

# Thresholds (mirror M88C security rule thresholds)
_NOTIFICATION_TRIGGER_THRESHOLD = 5
_VARSET_BROAD_VARIABLE_THRESHOLD = 5
_POLICY_BROAD_WORKSPACE_THRESHOLD = 5
_FAILED_RUN_STATUSES: frozenset[str] = frozenset(
    {"errored", "canceled", "policy_override", "discarded"}
)

# Safe posture fields per record type — copied verbatim into event metadata.
# Each name here is a safe field whose key contains no token/url/secret/name/
# branch/payload substring.  Only booleans, ints, opaque IDs, and safe
# category strings.
_SAFE_FIELDS_BY_RECORD_TYPE: dict[str, tuple[str, ...]] = {
    TERRAFORM_CLOUD_ORGANIZATION: (
        "organization_resource_id",
        "workspace_count",
        "project_count",
        "policy_set_count",
        "variable_set_count",
        "two_factor_requirement_enabled",
        "sso_enabled",
        "cost_estimation_enabled",
    ),
    TERRAFORM_CLOUD_WORKSPACE: (
        "workspace_resource_id",
        "organization_resource_id",
        "execution_mode_category",
        "terraform_version_category",
        "auto_apply",
        "file_triggers_enabled",
        "queue_all_runs",
        "speculative_enabled",
        "global_remote_state",
        "vcs_connected",
        "trigger_prefix_count",
        "run_trigger_count",
        "variable_count",
        "sensitive_variable_count",
        "non_sensitive_variable_count",
        "notification_count",
        "team_access_count",
        "latest_run_status_category",
    ),
    TERRAFORM_CLOUD_WORKSPACE_VARIABLE_SUMMARY: (
        "workspace_resource_id",
        "variable_count",
        "sensitive_variable_count",
        "non_sensitive_variable_count",
        "environment_variable_count",
        "terraform_variable_count",
        "raw_value_never_read",
    ),
    TERRAFORM_CLOUD_VARIABLE_SET: (
        "variable_set_resource_id",
        "organization_resource_id",
        "global_scope",
        "workspace_count",
        "project_count",
        "variable_count",
        "sensitive_variable_count",
        "non_sensitive_variable_count",
    ),
    TERRAFORM_CLOUD_POLICY_SET: (
        "policy_set_resource_id",
        "organization_resource_id",
        "global_scope",
        "workspace_count",
        "project_count",
        "policy_count",
        "enforcement_level_category",
    ),
    TERRAFORM_CLOUD_NOTIFICATION_CONFIGURATION: (
        "notification_resource_id",
        "workspace_resource_id",
        "enabled",
        "destination_type_category",
        "trigger_count",
        "token_present",
    ),
    TERRAFORM_CLOUD_RUN_TRIGGER: (
        "run_trigger_resource_id",
        "workspace_resource_id",
        "sourceable_type_category",
    ),
    TERRAFORM_CLOUD_TEAM_ACCESS_SUMMARY: (
        "workspace_resource_id",
        "team_access_count",
        "admin_access_count",
        "write_access_count",
        "read_access_count",
        "plan_access_count",
        "apply_access_count",
        "custom_permission_count",
    ),
    TERRAFORM_CLOUD_STATE_VERSION_SUMMARY: (
        "workspace_resource_id",
        "state_version_present",
        "state_version_count_category",
        "raw_state_never_fetched",
    ),
}


def _as_int(value: Any) -> int:
    """Coerce a posture count to int; non-ints (None/str/etc.) become 0."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _get_bool(record: dict[str, Any], key: str) -> bool | None:
    val = record.get(key)
    return val if isinstance(val, bool) else None


def _get_str(record: dict[str, Any], key: str) -> str | None:
    val = record.get(key)
    return val if isinstance(val, str) else None


def _event_types_for_record(record: dict[str, Any]) -> list[str]:
    """Return the ordered, deduplicated event types triggered by one record.

    Inspects only safe posture fields.  Returns an empty list when nothing
    meaningful is observed (e.g. a healthy record with no posture signals)
    so no misleading activity is created.
    """
    rt = record.get("record_type")
    out: list[str] = []

    if rt == TERRAFORM_CLOUD_ORGANIZATION:
        two_fa = _get_bool(record, "two_factor_requirement_enabled")
        sso = _get_bool(record, "sso_enabled")
        if two_fa is False:
            out.append(EVT_ORG_TWO_FACTOR_NOT_REQUIRED)
        if sso is False:
            out.append(EVT_ORG_SSO_NOT_ENABLED)
        if not out:
            # Only emit posture_changed if there is something of note; skip
            # healthy org records to avoid noise.
            pass

    elif rt == TERRAFORM_CLOUD_WORKSPACE:
        auto_apply = _get_bool(record, "auto_apply")
        global_state = _get_bool(record, "global_remote_state")
        exec_mode = _get_str(record, "execution_mode_category")
        vcs = _get_bool(record, "vcs_connected")
        queue = _get_bool(record, "queue_all_runs")
        tf_ver = _get_str(record, "terraform_version_category")
        file_trig = _get_bool(record, "file_triggers_enabled")
        spec = _get_bool(record, "speculative_enabled")
        run_trig_count = _as_int(record.get("run_trigger_count"))
        run_status = _get_str(record, "latest_run_status_category")

        if auto_apply is True:
            out.append(EVT_WORKSPACE_AUTO_APPLY_ENABLED)
        if global_state is True:
            out.append(EVT_WORKSPACE_GLOBAL_REMOTE_STATE)
        if exec_mode in ("local", "agent"):
            out.append(EVT_WORKSPACE_EXECUTION_MODE_CHANGED)
        if vcs is False and exec_mode == "remote":
            out.append(EVT_WORKSPACE_VCS_CONNECTION_MISSING)
        if queue is False:
            out.append(EVT_WORKSPACE_QUEUE_ALL_RUNS_DISABLED)
        if tf_ver in ("latest", "unknown"):
            out.append(EVT_WORKSPACE_UNPINNED_TF_VERSION)
        if file_trig is False:
            out.append(EVT_WORKSPACE_FILE_TRIGGERS_DISABLED)
        if spec is False:
            out.append(EVT_WORKSPACE_SPECULATIVE_DISABLED)
        if run_trig_count > 0:
            out.append(EVT_WORKSPACE_RUN_TRIGGERS_PRESENT)
        if run_status and run_status in _FAILED_RUN_STATUSES:
            out.append(EVT_WORKSPACE_LATEST_RUN_FAILED)

    elif rt == TERRAFORM_CLOUD_WORKSPACE_VARIABLE_SUMMARY:
        var_count = _as_int(record.get("variable_count"))
        non_sensitive = _as_int(record.get("non_sensitive_variable_count"))
        sensitive = _as_int(record.get("sensitive_variable_count"))

        if var_count > 0 and non_sensitive > 0:
            out.append(EVT_VARIABLES_NON_SENSITIVE)
        if var_count > 0 and sensitive == 0:
            out.append(EVT_VARIABLES_NO_SENSITIVE)

    elif rt == TERRAFORM_CLOUD_VARIABLE_SET:
        global_scope = _get_bool(record, "global_scope")
        var_count = _as_int(record.get("variable_count"))
        non_sensitive = _as_int(record.get("non_sensitive_variable_count"))

        if global_scope is True:
            out.append(EVT_VARSET_GLOBAL_SCOPE)
            if var_count >= _VARSET_BROAD_VARIABLE_THRESHOLD:
                out.append(EVT_VARSET_BROAD_SCOPE)
        if non_sensitive > 0:
            out.append(EVT_VARSET_NON_SENSITIVE)

    elif rt == TERRAFORM_CLOUD_POLICY_SET:
        enforcement = _get_str(record, "enforcement_level_category")
        policy_count = _as_int(record.get("policy_count"))
        global_scope = _get_bool(record, "global_scope")
        ws_count = _as_int(record.get("workspace_count"))
        proj_count = _as_int(record.get("project_count"))

        if enforcement == "advisory":
            out.append(EVT_POLICY_ADVISORY)
        if policy_count == 0:
            out.append(EVT_POLICY_EMPTY)
        if global_scope is True:
            out.append(EVT_POLICY_GLOBAL_SCOPE)
            if enforcement == "advisory":
                out.append(EVT_POLICY_BROAD_SCOPE_ADVISORY)
        elif enforcement == "advisory" and ws_count >= _POLICY_BROAD_WORKSPACE_THRESHOLD:
            out.append(EVT_POLICY_BROAD_SCOPE_ADVISORY)
        if (
            global_scope is False
            and record.get("workspace_count") is not None
            and ws_count == 0
            and record.get("project_count") is not None
            and proj_count == 0
        ):
            out.append(EVT_POLICY_UNSCOPED)

    elif rt == TERRAFORM_CLOUD_NOTIFICATION_CONFIGURATION:
        enabled = _get_bool(record, "enabled")
        dest = _get_str(record, "destination_type_category")
        scheme = _get_str(record, "webhook_url_scheme_category")
        token_present = _get_bool(record, "token_present")
        trig_count = _as_int(record.get("trigger_count"))
        is_webhook = dest == "webhook"

        if enabled is True:
            if is_webhook and scheme == "http":
                out.append(EVT_NOTIFICATION_HTTP)
            if is_webhook and token_present is False:
                out.append(EVT_NOTIFICATION_TOKEN_MISSING)
            if trig_count >= _NOTIFICATION_TRIGGER_THRESHOLD:
                out.append(EVT_NOTIFICATION_BROAD_TRIGGERS)
        elif enabled is False:
            out.append(EVT_NOTIFICATION_DISABLED)

    elif rt == TERRAFORM_CLOUD_RUN_TRIGGER:
        # Every emitted run trigger record represents an active trigger.
        out.append(EVT_RUN_TRIGGER_ENABLED)

    elif rt == TERRAFORM_CLOUD_TEAM_ACCESS_SUMMARY:
        admin = _as_int(record.get("admin_access_count"))
        apply_ = _as_int(record.get("apply_access_count"))
        write = _as_int(record.get("write_access_count"))
        custom = _as_int(record.get("custom_permission_count"))

        if admin > 0:
            out.append(EVT_TEAM_ADMIN)
        if apply_ > 0:
            out.append(EVT_TEAM_APPLY)
        if write > 0:
            out.append(EVT_TEAM_WRITE)
        if custom > 0:
            out.append(EVT_TEAM_CUSTOM)

    elif rt == TERRAFORM_CLOUD_STATE_VERSION_SUMMARY:
        state_present = _get_bool(record, "state_version_present")
        # Emit only if state is present. NEVER fetches state, outputs, or content.
        if state_present is True:
            out.append(EVT_STATE_VERSION_METADATA)

    # terraform_cloud_project: no activity events at M88D — no meaningful
    # posture signals defined yet.

    # Deduplicate while preserving order.
    seen: set[str] = set()
    deduped: list[str] = []
    for evt in out:
        if evt not in seen:
            seen.add(evt)
            deduped.append(evt)
    return deduped


def _safe_metadata(record: dict[str, Any], rt: str, resource_id: str) -> dict[str, Any]:
    """Build the flat, allowlisted metadata for a record (shared by its events)."""
    metadata: dict[str, Any] = {
        "resource_type": rt,
        "resource_id": resource_id,
        "operation_family": "configuration",
        "operation_action": "observed",
    }

    for field in _SAFE_FIELDS_BY_RECORD_TYPE.get(rt, ()):
        if field in record:
            value = record.get(field)
            if isinstance(value, (bool, int, str)):
                metadata[field] = value

    # Notification: also store the webhook URL scheme category under a
    # route-safe key name (never the URL itself).
    if rt == TERRAFORM_CLOUD_NOTIFICATION_CONFIGURATION:
        scheme = record.get("webhook_url_scheme_category")
        if isinstance(scheme, str):
            metadata["webhook_url_scheme_category"] = scheme

    return metadata


def compute_terraform_cloud_event_id(
    *,
    record_type: str,
    resource_id: str,
    event_type: str,
    updated_at: str,
) -> str:
    """Deterministic event id: hash(provider + record_type + resource_id + event_type + updated_at).

    Including the event_type keeps multiple events synthesized from the same
    record distinct, while re-running ingestion on the same record observed at
    the same time yields the same id — an idempotent no-op in upsert.
    """
    basis = "|".join([PROVIDER, record_type, resource_id, event_type, updated_at])
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return f"terraform_cloud:{digest[:40]}"


def build_terraform_cloud_activity_events(
    record: dict[str, Any],
    *,
    updated_at: str,
) -> list[dict[str, Any]]:
    """Synthesize zero or more config-state activity entries from one Terraform Cloud record.

    Returns a list of flat entry dicts (event_type, provider, source,
    event_source, provider_event_id, metadata) ready for
    ``normalize_terraform_cloud_activity_event``.  Returns an empty list for:
      * malformed records (not a dict, no record_type), OR
      * non-Terraform-Cloud record types (ignored safely), OR
      * Terraform Cloud records that observe nothing meaningful.

    Only allowlisted safe fields are copied into metadata.  Raw text, URLs,
    tokens, secrets, key material, identities, and payloads are NEVER included.
    """
    if not isinstance(record, dict):
        return []

    record_type = record.get("record_type")
    if not isinstance(record_type, str) or not record_type.startswith("terraform_cloud_"):
        return []  # non-TC / malformed record ignored safely

    rt = record_type
    event_types = _event_types_for_record(record)
    if not event_types:
        return []

    resource_id = (
        record.get("resource_id") or record.get("record_id") or "unknown"
    )
    resource_id = str(resource_id)[: activity_svc.MAX_STR_LEN]

    base_metadata = _safe_metadata(record, rt, resource_id)

    entries: list[dict[str, Any]] = []
    for event_type in event_types:
        eid = compute_terraform_cloud_event_id(
            record_type=rt,
            resource_id=resource_id,
            event_type=event_type,
            updated_at=updated_at,
        )
        metadata = dict(base_metadata)
        metadata["terraform_cloud_event_id"] = eid
        entries.append(
            {
                "event_type": event_type,
                "provider": PROVIDER,
                "source": SOURCE,
                "event_source": EVENT_SOURCE,
                "provider_event_id": eid,
                "metadata": metadata,
            }
        )
    return entries


def normalize_terraform_cloud_activity_event(
    entry: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Map one config-state entry → a normalized activity event.

    The ``entry`` dict is produced by ``build_terraform_cloud_activity_events``
    and contains only safe flat fields.  Returns None for:
      * malformed entries missing required fields, OR
      * ANY event_type not in the Terraform Cloud config-event allowlist.

    This is a hard privacy gate: raw audit/member/identity event types can
    NEVER be normalized or stored, even if a caller passes them.
    """
    if not isinstance(entry, dict):
        return None

    event_type = entry.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        return None

    # Hard allowlist gate — drop any non-config event type.
    if event_type not in _TERRAFORM_CLOUD_CONFIG_EVENT_TYPES:
        return None

    provider_event_id: Optional[str] = entry.get("provider_event_id") or None
    if isinstance(provider_event_id, str) and not provider_event_id.strip():
        provider_event_id = None

    metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
    resource_type = metadata.get("resource_type") or None
    resource_id = metadata.get("resource_id") or None

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
        # Terraform Cloud config-state synthesized events carry no actor
        # identity — intentionally, to avoid any risk of ingesting PII.
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


def ingest_terraform_cloud_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Synthesize Terraform Cloud configuration activity events from stored drift records.

    Reads the latest snapshot per Terraform Cloud resource for this
    integration, maps each safe drift record to zero or more config-state
    activity events, applies the lookback and max-events caps, and
    idempotently stores each event.

    Never raises.  All errors are captured in the returned summary dict.

    Terraform Cloud API tokens, OAuth tokens, VCS tokens, variable names/
    values, state files, state outputs, plan/apply logs, webhook URLs,
    notification tokens, team names, user emails, organization names, workspace
    names, project names, VCS URLs, branch names, customer infrastructure data,
    PII, and raw API payloads are NEVER fetched, read, or stored.
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
        logger.exception("terraform_cloud_activity: failed to load resources")
        return summary

    scanned = created = skipped = groups = 0

    for resource in resources:
        snapshot = _latest_snapshot_for_resource(db, resource)
        if snapshot is None:
            continue
        groups += 1

        observed_at = getattr(snapshot, "created_at", None)
        if isinstance(observed_at, datetime):
            obs = observed_at
            if obs.tzinfo is None:
                obs = obs.replace(tzinfo=timezone.utc)
            if obs < cutoff:
                continue
            updated_at = obs.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        state = snapshot.state if isinstance(snapshot.state, list) else []
        for record in state:
            if not isinstance(record, dict):
                continue
            entries = build_terraform_cloud_activity_events(
                record, updated_at=updated_at
            )
            for entry in entries:
                scanned += 1
                normalized = normalize_terraform_cloud_activity_event(entry)
                if normalized is None:
                    continue
                if created >= max_events:
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
                        "terraform_cloud_activity: failed to upsert one event; continuing"
                    )
                    continue
                if outcome == "inserted":
                    created += 1
                else:
                    skipped += 1
            if created >= max_events:
                break
        if created >= max_events:
            break

    summary["events_scanned"] = scanned
    summary["events_created"] = created
    summary["events_skipped"] = skipped
    summary["groups_scanned"] = groups
    return summary


def sync_terraform_cloud_activity(
    *,
    workspace_id: uuid.UUID,
    integration_id: Optional[str],
    lookback_hours: int = 24,
    max_events: int = 100,
    db: Session,
) -> dict[str, Any]:
    """Look up the Terraform Cloud integration and delegate to ingest_terraform_cloud_activity.

    Convenience wrapper used by the router endpoint.  Never raises — all
    errors are captured in the returned summary dict.
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

        return ingest_terraform_cloud_activity(
            integration=integration,
            workspace_id=workspace_id,
            db=db,
            lookback_hours=lookback_hours,
            max_events=max_events,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "terraform_cloud_activity: unexpected error in sync_terraform_cloud_activity"
        )
        return summary
