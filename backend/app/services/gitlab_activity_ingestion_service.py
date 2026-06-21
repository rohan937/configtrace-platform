"""GitLab configuration activity ingestion (M87D).

GitLab's audit-event APIs are identity-heavy: every entry includes actor user
IDs, actor emails, IP addresses, and user agents.  ConfigTrace NEVER ingests
from those endpoints.  Instead, this service synthesizes config-state activity
events from the same safe configuration posture records the GitLab drift
connector already stored in ConfigTrace's database (M87A–M87C) — instance,
projects, groups, branch protection rules, webhooks, CI variable summaries,
deploy key summaries, runner summaries, and MR approval summaries.

INGESTION SCOPE (deliberate):
  Only configuration posture summaries persisted by the drift connector: opaque
  IDs, safe booleans, counts, and category labels.  Raw GitLab API responses,
  audit logs, repository content, project/group names, namespace paths, branch
  names, commit messages, merge request titles, CI/CD variable names/values,
  deploy key material, runner tokens/IPs, webhook URLs/secrets, access tokens,
  and actor identities are NEVER fetched, ingested, or stored.

CLAIM DISCIPLINE: events are GitLab configuration activity evidence for review.
This service does NOT confirm a breach, compromise, unauthorized access,
source-code exposure, secret exposure, token exposure, credential exposure, or
data exposure.  Each event is GitLab configuration activity that may require
review.

NON-FATAL BY DESIGN: missing snapshots / missing integration / malformed
records are captured in the returned summary, never raised.

PRIVACY: only allowlisted, flat, safe fields are stored — opaque IDs, safe
booleans, counts, and category labels.  NEVER stored: GitLab access tokens,
OAuth tokens, PRIVATE-TOKEN values, authorization headers, webhook secret
tokens, webhook URLs, CI/CD variable names/values, deploy key material, SSH
keys, deploy key fingerprints, runner tokens, runner IPs, project/group names,
namespace paths, repo URLs, branch names, commit messages, merge request
titles, issue titles, pipeline/job logs, artifacts, user emails/names/usernames,
customer data, PII, or raw GitLab API payloads of any kind.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.connectors.gitlab_schema import (
    GITLAB_BRANCH_PROTECTION,
    GITLAB_CI_VARIABLE_SUMMARY,
    GITLAB_DEPLOY_KEY_SUMMARY,
    GITLAB_GROUP,
    GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY,
    GITLAB_PROJECT,
    GITLAB_RUNNER_SUMMARY,
    GITLAB_WEBHOOK,
)
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "gitlab"
SOURCE = "gitlab_activity_event"
EVENT_SOURCE = "gitlab_activity_event"

# ── Event types (hard allowlist) ──────────────────────────────────────────────
# Every event type ConfigTrace may synthesize for GitLab.  Names are precise,
# stable, and review-safe — none claims breach, compromise, attack, leak, or
# confirmed exposure.  Raw audit/member/identity event types can NEVER be added.
EVT_PROJECT_VISIBILITY_CHANGED = "gitlab.project.visibility_changed"
EVT_GROUP_VISIBILITY_CHANGED = "gitlab.group.visibility_changed"
EVT_BRANCH_PROTECTION_UPDATED = "gitlab.branch_protection.updated"
EVT_BRANCH_PROTECTION_FORCE_PUSH_ENABLED = "gitlab.branch_protection.force_push_enabled"
EVT_WEBHOOK_UPDATED = "gitlab.webhook.updated"
EVT_WEBHOOK_SECRET_REMOVED = "gitlab.webhook.secret_removed"
EVT_WEBHOOK_SSL_VERIFICATION_DISABLED = "gitlab.webhook.ssl_verification_disabled"
EVT_WEBHOOK_HTTP_SCHEME_DETECTED = "gitlab.webhook.http_scheme_detected"
EVT_CI_VARIABLES_POSTURE_CHANGED = "gitlab.ci_variables.posture_changed"
EVT_CI_VARIABLES_UNPROTECTED_UNMASKED_DETECTED = (
    "gitlab.ci_variables.unprotected_unmasked_detected"
)
EVT_DEPLOY_KEY_POSTURE_CHANGED = "gitlab.deploy_key.posture_changed"
EVT_DEPLOY_KEY_WRITE_ENABLED_DETECTED = "gitlab.deploy_key.write_enabled_detected"
EVT_RUNNER_POSTURE_CHANGED = "gitlab.runner.posture_changed"
EVT_RUNNER_SHARED_ENABLED = "gitlab.runner.shared_enabled"
EVT_MR_APPROVAL_UPDATED = "gitlab.merge_request_approval.updated"
EVT_MR_APPROVAL_REQUIREMENT_REDUCED = "gitlab.merge_request_approval.requirement_reduced"
EVT_PROJECT_FEATURE_PUBLIC_FEATURE_ENABLED = "gitlab.project_feature.public_feature_enabled"
EVT_CONFIG_EVENT = "gitlab.config.event"  # forward-compat fallback (not emitted)

_GITLAB_CONFIG_EVENT_TYPES: frozenset[str] = frozenset(
    {
        EVT_PROJECT_VISIBILITY_CHANGED,
        EVT_GROUP_VISIBILITY_CHANGED,
        EVT_BRANCH_PROTECTION_UPDATED,
        EVT_BRANCH_PROTECTION_FORCE_PUSH_ENABLED,
        EVT_WEBHOOK_UPDATED,
        EVT_WEBHOOK_SECRET_REMOVED,
        EVT_WEBHOOK_SSL_VERIFICATION_DISABLED,
        EVT_WEBHOOK_HTTP_SCHEME_DETECTED,
        EVT_CI_VARIABLES_POSTURE_CHANGED,
        EVT_CI_VARIABLES_UNPROTECTED_UNMASKED_DETECTED,
        EVT_DEPLOY_KEY_POSTURE_CHANGED,
        EVT_DEPLOY_KEY_WRITE_ENABLED_DETECTED,
        EVT_RUNNER_POSTURE_CHANGED,
        EVT_RUNNER_SHARED_ENABLED,
        EVT_MR_APPROVAL_UPDATED,
        EVT_MR_APPROVAL_REQUIREMENT_REDUCED,
        EVT_PROJECT_FEATURE_PUBLIC_FEATURE_ENABLED,
        EVT_CONFIG_EVENT,
    }
)

# Expose for tests and the router.
GITLAB_CONFIG_EVENT_TYPES = _GITLAB_CONFIG_EVENT_TYPES

# Broad branch-access categories (mirrors the M87C branch-protection rules).
_BROAD_ACCESS_LEVELS: frozenset[str] = frozenset({"developer", "reporter", "guest"})

# Webhook event_count above this is treated as a broad subscription.
_WEBHOOK_BROAD_EVENT_COUNT = 5

# Per record_type, the safe count/boolean/category fields copied verbatim into
# event metadata.  Each name here is a safe posture field whose KEY contains no
# token/url/secret-value/name/branch/payload substring.  Renamed/derived fields
# (webhook scheme/host/secret, approver override) are handled explicitly below.
_SAFE_FIELDS_BY_RECORD_TYPE: dict[str, tuple[str, ...]] = {
    GITLAB_PROJECT: (
        "visibility_category",
        "archived",
        "default_branch_present",
        "issues_enabled",
        "wiki_enabled",
        "snippets_enabled",
        "container_registry_enabled",
        "packages_enabled",
        "shared_runners_enabled",
        "protected_branch_count",
        "webhook_count",
        "ci_variable_count",
        "deploy_key_count",
        "approval_rule_count",
    ),
    GITLAB_GROUP: (
        "visibility_category",
        "project_count",
        "subgroup_count",
        "member_count_category",
        "two_factor_requirement_enabled",
        "membership_lock",
        "shared_runners_setting_category",
    ),
    GITLAB_BRANCH_PROTECTION: (
        "project_resource_id",
        "pattern_category",
        "allow_force_push",
        "code_owner_approval_required",
        "push_access_level_category",
        "merge_access_level_category",
        "allowed_to_push_count",
        "allowed_to_merge_count",
    ),
    GITLAB_WEBHOOK: (
        "owner_resource_id",
        "owner_type",
        "enabled",
        "ssl_verification_enabled",
        "event_count",
        "push_events",
        "pipeline_events",
        "job_events",
    ),
    GITLAB_CI_VARIABLE_SUMMARY: (
        "owner_resource_id",
        "owner_type",
        "variable_count",
        "protected_variable_count",
        "masked_variable_count",
        "environment_scoped_count",
        "unprotected_unmasked_count",
    ),
    GITLAB_DEPLOY_KEY_SUMMARY: (
        "project_resource_id",
        "deploy_key_count",
        "write_enabled_count",
        "read_only_count",
        "enabled_count",
    ),
    GITLAB_RUNNER_SUMMARY: (
        "owner_resource_id",
        "owner_type",
        "runner_count",
        "shared_runner_enabled",
        "locked_runner_count",
        "paused_runner_count",
        "tagged_runner_count",
        "untagged_runner_count",
    ),
    GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY: (
        "project_resource_id",
        "approval_rule_count",
        "approvals_required",
        "author_approval_allowed",
        "reset_approvals_on_push",
    ),
}


def _as_int(value: Any) -> int:
    """Coerce a posture count to int; non-ints (None/str/etc.) become 0."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _event_types_for_record(record: dict[str, Any]) -> list[str]:
    """Return the ordered, deduplicated event types triggered by one record.

    Inspects only safe posture fields.  Returns an empty list when nothing
    meaningful is observed (e.g. a private project, an instance record, or a
    record whose fields are missing/None) so no misleading activity is created.
    """
    rt = record.get("record_type")
    out: list[str] = []

    if rt == GITLAB_PROJECT:
        if record.get("visibility_category") == "public":
            out.append(EVT_PROJECT_VISIBILITY_CHANGED)
            if any(
                record.get(f) is True
                for f in (
                    "wiki_enabled",
                    "snippets_enabled",
                    "container_registry_enabled",
                    "packages_enabled",
                )
            ):
                out.append(EVT_PROJECT_FEATURE_PUBLIC_FEATURE_ENABLED)

    elif rt == GITLAB_GROUP:
        if record.get("visibility_category") == "public":
            out.append(EVT_GROUP_VISIBILITY_CHANGED)

    elif rt == GITLAB_BRANCH_PROTECTION:
        if record.get("allow_force_push") is True:
            out.append(EVT_BRANCH_PROTECTION_FORCE_PUSH_ENABLED)
        broad = (
            record.get("push_access_level_category") in _BROAD_ACCESS_LEVELS
            or record.get("merge_access_level_category") in _BROAD_ACCESS_LEVELS
        )
        if record.get("code_owner_approval_required") is False or broad:
            out.append(EVT_BRANCH_PROTECTION_UPDATED)

    elif rt == GITLAB_WEBHOOK:
        if record.get("enabled") is True:
            if record.get("secret_token_present") is False:
                out.append(EVT_WEBHOOK_SECRET_REMOVED)
            if record.get("ssl_verification_enabled") is False:
                out.append(EVT_WEBHOOK_SSL_VERIFICATION_DISABLED)
            if record.get("url_scheme") == "http":
                out.append(EVT_WEBHOOK_HTTP_SCHEME_DETECTED)
            if _as_int(record.get("event_count")) > _WEBHOOK_BROAD_EVENT_COUNT:
                out.append(EVT_WEBHOOK_UPDATED)

    elif rt == GITLAB_CI_VARIABLE_SUMMARY:
        if _as_int(record.get("unprotected_unmasked_count")) > 0:
            out.append(EVT_CI_VARIABLES_UNPROTECTED_UNMASKED_DETECTED)
        variable_count = _as_int(record.get("variable_count"))
        if variable_count > 0 and (
            _as_int(record.get("protected_variable_count")) == 0
            or _as_int(record.get("masked_variable_count")) == 0
        ):
            out.append(EVT_CI_VARIABLES_POSTURE_CHANGED)

    elif rt == GITLAB_DEPLOY_KEY_SUMMARY:
        if _as_int(record.get("write_enabled_count")) > 0:
            out.append(EVT_DEPLOY_KEY_WRITE_ENABLED_DETECTED)

    elif rt == GITLAB_RUNNER_SUMMARY:
        if record.get("shared_runner_enabled") is True:
            out.append(EVT_RUNNER_SHARED_ENABLED)
        if _as_int(record.get("untagged_runner_count")) > 0:
            out.append(EVT_RUNNER_POSTURE_CHANGED)

    elif rt == GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY:
        if record.get("approvals_required") == 0:
            out.append(EVT_MR_APPROVAL_REQUIREMENT_REDUCED)
        if (
            record.get("reset_approvals_on_push") is False
            or record.get("disable_overriding_approvers_per_merge_request") is False
        ):
            out.append(EVT_MR_APPROVAL_UPDATED)

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

    for field in _SAFE_FIELDS_BY_RECORD_TYPE.get(rt, ()):  # () = unknown type
        if field in record:
            value = record.get(field)
            if isinstance(value, (bool, int, float, str)):
                metadata[field] = value

    # Renamed / derived webhook posture — never the raw URL or secret value.
    if rt == GITLAB_WEBHOOK:
        scheme = record.get("url_scheme")
        if isinstance(scheme, str):
            metadata["webhook_scheme_category"] = scheme
        host_cat = record.get("url_host_category")
        if isinstance(host_cat, str):
            metadata["webhook_host_category"] = host_cat
        if isinstance(record.get("secret_token_present"), bool):
            metadata["webhook_secret_present"] = record["secret_token_present"]

    # MR approval override posture — store under a request-free key name.
    if rt == GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY:
        override = record.get("disable_overriding_approvers_per_merge_request")
        if isinstance(override, bool):
            metadata["override_approvers_disabled"] = override

    return metadata


def compute_gitlab_event_id(
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
    return f"gitlab:{digest[:40]}"


def build_gitlab_activity_events(
    record: dict[str, Any],
    *,
    updated_at: str,
) -> list[dict[str, Any]]:
    """Synthesize zero or more config-state activity entries from one GitLab record.

    Returns a list of flat entry dicts (event_type, provider, source,
    event_source, provider_event_id, metadata) ready for
    ``normalize_gitlab_activity_event``.  Returns an empty list for:
      * malformed records (not a dict, no record_type), OR
      * non-GitLab record types (ignored safely), OR
      * GitLab records that observe nothing meaningful.

    Only allowlisted safe fields are copied into metadata.  Raw text, URLs,
    tokens, secrets, key material, identities, and payloads are NEVER included.
    """
    if not isinstance(record, dict):
        return []

    record_type = record.get("record_type")
    if not isinstance(record_type, str) or not record_type.startswith("gitlab_"):
        return []  # non-GitLab / malformed record ignored safely

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
        eid = compute_gitlab_event_id(
            record_type=rt,
            resource_id=resource_id,
            event_type=event_type,
            updated_at=updated_at,
        )
        metadata = dict(base_metadata)
        metadata["gitlab_event_id"] = eid
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


def normalize_gitlab_activity_event(
    entry: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Map one config-state entry → a normalized activity event.

    The ``entry`` dict is produced by ``build_gitlab_activity_events`` and
    contains only safe flat fields.  Returns None for:
      * malformed entries missing required fields, OR
      * ANY event_type not in the GitLab config-event allowlist.

    This is a hard privacy gate: raw audit/member/identity event types can NEVER
    be normalized or stored, even if a caller passes them.
    """
    if not isinstance(entry, dict):
        return None

    event_type = entry.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        return None

    # Hard allowlist gate — drop any non-config event type.
    if event_type not in _GITLAB_CONFIG_EVENT_TYPES:
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
        # GitLab config-state synthesized events carry no actor identity — we
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


def ingest_gitlab_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Synthesize GitLab configuration activity events from stored drift records.

    Reads the latest snapshot per GitLab resource for this integration, maps each
    safe drift record to zero or more config-state activity events, applies the
    lookback and max-events caps, and idempotently stores each event.

    Never raises.  All errors are captured in the returned summary dict.
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
        logger.exception("gitlab_activity: failed to load resources")
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
            entries = build_gitlab_activity_events(record, updated_at=updated_at)
            for entry in entries:
                scanned += 1
                normalized = normalize_gitlab_activity_event(entry)
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
                        "gitlab_activity: failed to upsert one event; continuing"
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


def sync_gitlab_activity(
    *,
    workspace_id: uuid.UUID,
    integration_id: Optional[str],
    lookback_hours: int = 24,
    max_events: int = 100,
    db: Session,
) -> dict[str, Any]:
    """Look up the GitLab integration and delegate to ingest_gitlab_activity.

    Convenience wrapper used by the router endpoint.  Never raises — all errors
    are captured in the returned summary dict.
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

        return ingest_gitlab_activity(
            integration=integration,
            workspace_id=workspace_id,
            db=db,
            lookback_hours=lookback_hours,
            max_events=max_events,
        )
    except Exception:  # noqa: BLE001
        logger.exception("gitlab_activity: unexpected error in sync_gitlab_activity")
        return summary
