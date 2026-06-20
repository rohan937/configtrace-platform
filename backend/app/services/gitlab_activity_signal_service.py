"""GitLab Configuration Activity Incident Signals (M87E).

Promotes GitLab configuration-state activity events (provider=gitlab,
source=gitlab_activity_event, synthesized in M87D) into review-worthy
Incident Signals covering project visibility, group visibility, branch
protection, webhook security, CI/CD variable posture, deploy key posture,
runner posture, and merge request approval configuration activity.

Conservative + deterministic + idempotent: events are grouped by
(signal_type, resource_identity); each group yields one signal anchored on
the group's latest event, with a deterministic signal_key so re-running
creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration review signals.
They NEVER assert that a breach, compromise, unauthorized access, leaked
secret, exposed source code, repo exposure, exposed credential, token leak,
or exposed data has been confirmed. Severity reflects review priority only —
GitLab configuration activity that may require review.

PRIVACY: signal metadata is allowlisted + flat. NEVER stored:
- GitLab access tokens, OAuth tokens, PRIVATE-TOKEN values, webhook secret
  tokens, CI/CD variable names/values, deploy key material, SSH keys,
  runner tokens, runner IPs.
- Raw webhook URLs, raw base URLs, namespace paths, repo URLs, branch names.
- Project/group names, commit messages, merge request titles, issue titles.
- Pipeline logs, job logs, artifacts.
- User emails, user names, usernames, customer data, PII.
- Raw GitLab API payloads of any kind.
Only safe opaque identifiers, booleans, counts, and category labels.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "gitlab"
SOURCE = "gitlab_activity_event"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is GitLab configuration activity evidence for review and may require review. "
    "This does not confirm compromise, unauthorized access, source-code exposure, "
    "secret exposure, token exposure, credential exposure, or data exposure."
)

# ── Event type → signal type ──────────────────────────────────────────────────
GITLAB_EVENT_TO_SIGNAL_TYPE: dict[str, str] = {
    "gitlab.project.visibility_changed": "gitlab_project_visibility_signal",
    "gitlab.project_feature.public_feature_enabled": "gitlab_project_public_feature_signal",
    "gitlab.group.visibility_changed": "gitlab_group_visibility_signal",
    "gitlab.branch_protection.force_push_enabled": "gitlab_force_push_enabled_signal",
    "gitlab.branch_protection.updated": "gitlab_branch_protection_weakened",
    "gitlab.webhook.secret_removed": "gitlab_webhook_secret_removed_signal",
    "gitlab.webhook.ssl_verification_disabled": "gitlab_webhook_ssl_disabled_signal",
    "gitlab.webhook.http_scheme_detected": "gitlab_webhook_http_scheme_signal",
    "gitlab.webhook.updated": "gitlab_webhook_broad_event_scope_signal",
    "gitlab.ci_variables.unprotected_unmasked_detected": "gitlab_ci_unprotected_unmasked_variables_signal",
    "gitlab.ci_variables.posture_changed": "gitlab_ci_variable_posture_signal",
    "gitlab.deploy_key.write_enabled_detected": "gitlab_deploy_key_write_enabled_signal",
    "gitlab.deploy_key.posture_changed": "gitlab_deploy_key_posture_signal",
    "gitlab.runner.shared_enabled": "gitlab_shared_runner_enabled_signal",
    "gitlab.runner.posture_changed": "gitlab_runner_posture_signal",
    "gitlab.merge_request_approval.requirement_reduced": "gitlab_merge_request_approval_weakened",
    "gitlab.merge_request_approval.updated": "gitlab_merge_request_approval_weakened",
    "gitlab.config.event": "gitlab_configuration_activity_signal",
}

GITLAB_SIGNAL_TYPES: frozenset[str] = frozenset(
    GITLAB_EVENT_TO_SIGNAL_TYPE.values()
)

# High-severity signal types — these reflect immediately review-worthy
# configuration posture. NEVER implies a breach or confirmed access.
_HIGH_SIGNAL_TYPES: frozenset[str] = frozenset(
    {
        "gitlab_project_visibility_signal",
        "gitlab_group_visibility_signal",
        "gitlab_force_push_enabled_signal",
        "gitlab_webhook_secret_removed_signal",
        "gitlab_webhook_ssl_disabled_signal",
        "gitlab_webhook_http_scheme_signal",
        "gitlab_ci_unprotected_unmasked_variables_signal",
        "gitlab_deploy_key_write_enabled_signal",
    }
)

# Low-severity fallback — generic config observation.
_LOW_SIGNAL_TYPES: frozenset[str] = frozenset({"gitlab_configuration_activity_signal"})

# Safe count/boolean/category fields per signal type that may be carried from
# the activity-event metadata onto the signal. Every key must also be present in
# the signal service's ALLOWED_METADATA_KEYS. No raw text, URLs, tokens,
# secrets, key material, identities, or payloads ever appear here.
_SAFE_FIELDS_BY_SIGNAL_TYPE: dict[str, tuple[str, ...]] = {
    "gitlab_project_visibility_signal": (
        "visibility_category",
        "archived",
        "shared_runners_enabled",
        "protected_branch_count",
        "webhook_count",
        "ci_variable_count",
        "deploy_key_count",
        "approval_rule_count",
    ),
    "gitlab_project_public_feature_signal": (
        "visibility_category",
        "wiki_enabled",
        "snippets_enabled",
        "container_registry_enabled",
        "packages_enabled",
    ),
    "gitlab_group_visibility_signal": (
        "visibility_category",
        "project_count",
        "subgroup_count",
        "member_count_category",
        "two_factor_requirement_enabled",
        "membership_lock",
        "shared_runners_setting_category",
    ),
    "gitlab_force_push_enabled_signal": (
        "project_resource_id",
        "pattern_category",
        "allow_force_push",
        "code_owner_approval_required",
        "push_access_level_category",
        "merge_access_level_category",
    ),
    "gitlab_branch_protection_weakened": (
        "project_resource_id",
        "pattern_category",
        "allow_force_push",
        "code_owner_approval_required",
        "push_access_level_category",
        "merge_access_level_category",
        "allowed_to_push_count",
        "allowed_to_merge_count",
    ),
    "gitlab_webhook_secret_removed_signal": (
        "owner_resource_id",
        "owner_type",
        "enabled",
        "webhook_secret_present",
        "ssl_verification_enabled",
        "webhook_scheme_category",
        "event_count",
    ),
    "gitlab_webhook_ssl_disabled_signal": (
        "owner_resource_id",
        "owner_type",
        "enabled",
        "ssl_verification_enabled",
        "webhook_secret_present",
        "webhook_scheme_category",
        "event_count",
    ),
    "gitlab_webhook_http_scheme_signal": (
        "owner_resource_id",
        "owner_type",
        "enabled",
        "webhook_scheme_category",
        "webhook_host_category",
        "ssl_verification_enabled",
        "event_count",
    ),
    "gitlab_webhook_broad_event_scope_signal": (
        "owner_resource_id",
        "owner_type",
        "enabled",
        "event_count",
        "push_events",
        "pipeline_events",
        "job_events",
        "ssl_verification_enabled",
        "webhook_scheme_category",
    ),
    "gitlab_ci_unprotected_unmasked_variables_signal": (
        "owner_resource_id",
        "owner_type",
        "variable_count",
        "protected_variable_count",
        "masked_variable_count",
        "unprotected_unmasked_count",
    ),
    "gitlab_ci_variable_posture_signal": (
        "owner_resource_id",
        "owner_type",
        "variable_count",
        "protected_variable_count",
        "masked_variable_count",
        "environment_scoped_count",
        "unprotected_unmasked_count",
    ),
    "gitlab_deploy_key_write_enabled_signal": (
        "project_resource_id",
        "deploy_key_count",
        "write_enabled_count",
        "read_only_count",
        "enabled_count",
    ),
    "gitlab_deploy_key_posture_signal": (
        "project_resource_id",
        "deploy_key_count",
        "write_enabled_count",
        "read_only_count",
        "enabled_count",
    ),
    "gitlab_shared_runner_enabled_signal": (
        "owner_resource_id",
        "owner_type",
        "runner_count",
        "shared_runner_enabled",
        "locked_runner_count",
        "untagged_runner_count",
    ),
    "gitlab_runner_posture_signal": (
        "owner_resource_id",
        "owner_type",
        "runner_count",
        "shared_runner_enabled",
        "tagged_runner_count",
        "untagged_runner_count",
    ),
    "gitlab_merge_request_approval_weakened": (
        "project_resource_id",
        "approval_rule_count",
        "approvals_required",
        "code_owner_approval_required",
        "reset_approvals_on_push",
        "override_approvers_disabled",
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

    Uses safe opaque identifiers only — NEVER GitLab access tokens, webhook
    secret tokens, raw URLs, branch names, project/group names, namespace
    paths, user emails, or other sensitive values.
    """
    return _md(ev, "resource_id") or ev.resource_id or "global"


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    """Deterministic group key — one signal per (signal_type, resource)."""
    signal_type = GITLAB_EVENT_TO_SIGNAL_TYPE.get(ev.event_type)
    if signal_type is None:
        return None
    rkey = _resource_key(ev)
    return "|".join(["gitlab.activity", signal_type, rkey])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id)."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(signal_type: str) -> str:
    """Conservative review-priority severity. Never asserts confirmed impact."""
    if signal_type in _HIGH_SIGNAL_TYPES:
        return "high"
    if signal_type in _LOW_SIGNAL_TYPES:
        return "low"
    return "medium"


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    signal_type = GITLAB_EVENT_TO_SIGNAL_TYPE.get(anchor.event_type)
    if signal_type is None:
        return None

    unique_event_types = sorted({ev.event_type for ev in group})
    event_types_str = ", ".join(unique_event_types)

    resource_type = (
        _md(anchor, "resource_type") or anchor.resource_type or "gitlab_configuration"
    )

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    title = (
        f"GitLab {resource_type} activity: {len(group)} "
        f"{signal_type.replace('_', ' ')} event(s)"
    )
    summary = (
        f"Review-worthy GitLab configuration activity detected on {resource_type}. "
        f"{len(group)} event(s) recorded in the review window. "
        f"Does not confirm compromise or unauthorized access — this is a "
        f"GitLab configuration signal for review. "
        f"{_REVIEW_NOTE}"
    ).strip()

    gk = _group_key(anchor)

    # Gather safe metadata fields from anchor event.
    # PRIVACY: NEVER include GitLab access tokens, OAuth tokens, PRIVATE-TOKEN
    # values, webhook secret tokens, CI/CD variable names/values, deploy key
    # material, SSH keys, runner tokens/IPs, project/group names, namespace
    # paths, repo URLs, raw webhook URLs, branch names, commit messages, merge
    # request titles, issue titles, pipeline/job logs, artifacts, user
    # emails/names/usernames, customer data, PII, or raw API payloads.
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
        "operation_family": "gitlab_configuration",
        "operation_action": "configuration_observed",
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "gitlab_event_id": _md(anchor, "gitlab_event_id"),
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


def generate_gitlab_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate GitLab configuration review signals for a workspace.

    Reads normalized gitlab / gitlab_activity_event activity events (M87D) and
    promotes selected config-state events into Incident Signals. Idempotent —
    re-running creates no duplicates. Never raises.

    PRIVACY: only safe, allowlisted fields are stored in signal metadata. GitLab
    access tokens, OAuth tokens, PRIVATE-TOKEN values, webhook secret tokens,
    CI/CD variable names/values, deploy key material, SSH keys, runner tokens,
    runner IPs, project/group names, namespace paths, repo URLs, raw webhook
    URLs, branch names, commit messages, merge request titles, issue titles,
    pipeline/job logs, artifacts, user emails, usernames, customer data, PII,
    and raw GitLab API payloads are never stored.

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
                "gitlab_signals: failed to build or upsert one group; continuing"
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
