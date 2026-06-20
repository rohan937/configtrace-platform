"""GitLab Risk × Activity Correlations (M87F).

Joins active GitLab configuration-risk findings (provider=gitlab, from M87B/
M87C) with GitLab activity signals (provider=gitlab, from M87E) on the same
resource within a review window. Produces SecuritySignalCorrelation rows with
evidence_level="correlation".

CORRELATION STRATEGY
--------------------
Eleven specialized correlation families, one per GitLab configuration surface:

  public_visibility             — visibility findings ↔ visibility activity
  branch_protection_risk        — branch findings ↔ branch activity
  webhook_secret_risk           — webhook auth findings ↔ webhook activity
  webhook_transport_risk        — webhook HTTP/scheme findings ↔ webhook activity
  webhook_event_scope_risk      — webhook scope findings ↔ webhook activity
  ci_variable_risk              — CI variable findings ↔ CI variable activity
  deploy_key_risk               — deploy key findings ↔ deploy key activity
  runner_risk                   — runner findings ↔ runner activity
  merge_request_approval_risk   — MR approval findings ↔ approval activity
  public_feature_risk           — public feature findings ↔ public feature activity
  config (fallback)             — any other gitlab_ rule ↔ generic config activity

Each family also matches against the generic gitlab_configuration_activity_signal
type (lower confidence) when no resource-specific signal is available. Findings
whose base rule key does not match a specialized family fall back to the generic
gitlab_configuration_risk_with_activity family.

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They never assert that
a breach, compromise, unauthorized access, source-code exposure, repo exposure,
secret exposure, token leak, credential exposure, or data exposure has occurred
or been confirmed. Severity = review priority only. Confidence = "medium"
(circumstantial co-occurrence, not proof).

PRIVACY: metadata is allowlisted + flat. NEVER stored:
  GitLab access tokens, OAuth tokens, PRIVATE-TOKEN values, webhook secret
  tokens, CI/CD variable names/values, deploy key material, SSH keys, runner
  tokens/IPs, project/group names, namespace paths, repo URLs, raw webhook URLs,
  branch names, commit messages, merge request titles, issue titles, pipeline/job
  logs, artifacts, user emails/names/usernames, customer data, PII, or raw
  GitLab API payloads of any kind.
Only safe opaque identifiers, booleans, counts, and category labels.

Idempotent — re-running over the same data creates no duplicate rows.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.services import security_signal_correlation_service as corr_svc

_log = logging.getLogger(__name__)

PROVIDER = "gitlab"

_WINDOW = timedelta(hours=24)

_REVIEW_NOTE = (
    "GitLab configuration risk correlated with related GitLab configuration "
    "activity on the same resource. Configuration evidence for review that may "
    "require review. Does not confirm compromise, unauthorized access, "
    "source-code exposure, secret exposure, token exposure, credential exposure, "
    "or data exposure."
)

# ── Generic / fallback signal type every family also accepts ──────────────────
_GENERIC_SIGNAL = "gitlab_configuration_activity_signal"

# ── Rule key → expected signal type mapping ───────────────────────────────────
GITLAB_RULE_KEY_TO_SIGNAL_TYPE: dict[str, str] = {
    # Public visibility rules → project/group visibility signals
    "gitlab_project_public_visibility": "gitlab_project_visibility_signal",
    "gitlab_group_public_visibility": "gitlab_group_visibility_signal",
    # Branch protection rules → branch protection signals
    "gitlab_branch_force_push_enabled": "gitlab_force_push_enabled_signal",
    "gitlab_branch_code_owner_approval_missing": "gitlab_branch_protection_weakened",
    "gitlab_branch_push_access_broad": "gitlab_branch_protection_weakened",
    "gitlab_branch_merge_access_broad": "gitlab_branch_protection_weakened",
    # Webhook secret/auth rules → webhook security signals
    "gitlab_webhook_secret_missing": "gitlab_webhook_secret_removed_signal",
    "gitlab_webhook_ssl_verification_disabled": "gitlab_webhook_ssl_disabled_signal",
    # Webhook transport rules → webhook HTTP scheme signals
    "gitlab_webhook_http_scheme": "gitlab_webhook_http_scheme_signal",
    # Webhook event scope rules → webhook event scope signals
    "gitlab_webhook_broad_event_scope": "gitlab_webhook_broad_event_scope_signal",
    "gitlab_webhook_pipeline_job_events": "gitlab_webhook_broad_event_scope_signal",
    # CI variable rules → CI variable posture signals
    "gitlab_ci_unprotected_unmasked_variables": "gitlab_ci_unprotected_unmasked_variables_signal",
    "gitlab_ci_variables_unprotected": "gitlab_ci_variable_posture_signal",
    "gitlab_ci_variables_unmasked": "gitlab_ci_variable_posture_signal",
    # Deploy key rules → deploy key signals
    "gitlab_deploy_key_write_enabled": "gitlab_deploy_key_write_enabled_signal",
    # Runner rules → runner posture signals
    "gitlab_runner_untagged": "gitlab_runner_posture_signal",
    "gitlab_runner_shared_enabled": "gitlab_shared_runner_enabled_signal",
    "gitlab_project_shared_runners_enabled": "gitlab_shared_runner_enabled_signal",
    # MR approval rules → approval weakened signals
    "gitlab_merge_request_approval_not_required": "gitlab_merge_request_approval_weakened",
    "gitlab_mr_approval_reset_disabled": "gitlab_merge_request_approval_weakened",
    "gitlab_mr_approver_override_allowed": "gitlab_merge_request_approval_weakened",
    # Public feature rules → public feature signals
    "gitlab_project_snippets_enabled_public": "gitlab_project_public_feature_signal",
    "gitlab_project_wiki_enabled_public": "gitlab_project_public_feature_signal",
    "gitlab_project_packages_enabled_public": "gitlab_project_public_feature_signal",
    "gitlab_project_container_registry_enabled_public": "gitlab_project_public_feature_signal",
}


# ── Correlation family definitions ────────────────────────────────────────────

def _family(
    *,
    rule_keys: set[str],
    specific_signals: set[str],
    match_key: str,
    severity: str,
    title_phrase: str,
    subject_phrase: str,
) -> dict[str, Any]:
    return {
        "rule_keys": rule_keys,
        "signal_types": specific_signals | {_GENERIC_SIGNAL},
        "specific_signals": specific_signals,
        "match_key": match_key,
        "severity": severity,
        "title_phrase": title_phrase,
        "subject_phrase": subject_phrase,
    }


GITLAB_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "gitlab_public_visibility_with_activity": _family(
        rule_keys={
            "gitlab_project_public_visibility",
            "gitlab_group_public_visibility",
        },
        specific_signals={
            "gitlab_project_visibility_signal",
            "gitlab_group_visibility_signal",
        },
        match_key="visibility",
        severity="high",
        title_phrase="GitLab public visibility risk aligned with related GitLab configuration activity",
        subject_phrase="GitLab public project/group visibility posture risk",
    ),
    "gitlab_branch_protection_risk_with_activity": _family(
        rule_keys={
            "gitlab_branch_force_push_enabled",
            "gitlab_branch_code_owner_approval_missing",
            "gitlab_branch_push_access_broad",
            "gitlab_branch_merge_access_broad",
        },
        specific_signals={
            "gitlab_force_push_enabled_signal",
            "gitlab_branch_protection_weakened",
        },
        match_key="branch_protection",
        severity="high",
        title_phrase="GitLab branch protection risk aligned with related GitLab configuration activity",
        subject_phrase="GitLab branch protection posture risk",
    ),
    "gitlab_webhook_secret_risk_with_activity": _family(
        rule_keys={
            "gitlab_webhook_secret_missing",
            "gitlab_webhook_ssl_verification_disabled",
        },
        specific_signals={
            "gitlab_webhook_secret_removed_signal",
            "gitlab_webhook_ssl_disabled_signal",
        },
        match_key="webhook_security",
        severity="high",
        title_phrase="GitLab webhook authentication/security risk aligned with related GitLab configuration activity",
        subject_phrase="GitLab webhook authentication/SSL posture risk",
    ),
    "gitlab_webhook_transport_risk_with_activity": _family(
        rule_keys={
            "gitlab_webhook_http_scheme",
        },
        specific_signals={
            "gitlab_webhook_http_scheme_signal",
        },
        match_key="webhook_transport",
        severity="high",
        title_phrase="GitLab webhook transport risk aligned with related GitLab configuration activity",
        subject_phrase="GitLab webhook HTTP scheme transport posture risk",
    ),
    "gitlab_webhook_event_scope_risk_with_activity": _family(
        rule_keys={
            "gitlab_webhook_broad_event_scope",
            "gitlab_webhook_pipeline_job_events",
        },
        specific_signals={
            "gitlab_webhook_broad_event_scope_signal",
        },
        match_key="webhook_scope",
        severity="medium",
        title_phrase="GitLab webhook event scope risk aligned with related GitLab configuration activity",
        subject_phrase="GitLab webhook event scope posture risk",
    ),
    "gitlab_ci_variable_risk_with_activity": _family(
        rule_keys={
            "gitlab_ci_unprotected_unmasked_variables",
            "gitlab_ci_variables_unprotected",
            "gitlab_ci_variables_unmasked",
        },
        specific_signals={
            "gitlab_ci_unprotected_unmasked_variables_signal",
            "gitlab_ci_variable_posture_signal",
        },
        match_key="ci_variable",
        severity="high",
        title_phrase="GitLab CI/CD variable posture risk aligned with related GitLab configuration activity",
        subject_phrase="GitLab CI/CD variable protection/masking posture risk",
    ),
    "gitlab_deploy_key_risk_with_activity": _family(
        rule_keys={
            "gitlab_deploy_key_write_enabled",
        },
        specific_signals={
            "gitlab_deploy_key_write_enabled_signal",
            "gitlab_deploy_key_posture_signal",
        },
        match_key="deploy_key",
        severity="high",
        title_phrase="GitLab deploy key posture risk aligned with related GitLab configuration activity",
        subject_phrase="GitLab deploy key write-access posture risk",
    ),
    "gitlab_runner_risk_with_activity": _family(
        rule_keys={
            "gitlab_runner_untagged",
            "gitlab_runner_shared_enabled",
            "gitlab_project_shared_runners_enabled",
        },
        specific_signals={
            "gitlab_runner_posture_signal",
            "gitlab_shared_runner_enabled_signal",
        },
        match_key="runner",
        severity="medium",
        title_phrase="GitLab runner posture risk aligned with related GitLab configuration activity",
        subject_phrase="GitLab runner posture risk",
    ),
    "gitlab_merge_request_approval_risk_with_activity": _family(
        rule_keys={
            "gitlab_merge_request_approval_not_required",
            "gitlab_mr_approval_reset_disabled",
            "gitlab_mr_approver_override_allowed",
        },
        specific_signals={
            "gitlab_merge_request_approval_weakened",
        },
        match_key="merge_request_approval",
        severity="high",
        title_phrase="GitLab merge request approval risk aligned with related GitLab configuration activity",
        subject_phrase="GitLab merge request approval posture risk",
    ),
    "gitlab_public_feature_risk_with_activity": _family(
        rule_keys={
            "gitlab_project_snippets_enabled_public",
            "gitlab_project_wiki_enabled_public",
            "gitlab_project_packages_enabled_public",
            "gitlab_project_container_registry_enabled_public",
        },
        specific_signals={
            "gitlab_project_public_feature_signal",
        },
        match_key="public_feature",
        severity="medium",
        title_phrase="GitLab public project feature risk aligned with related GitLab configuration activity",
        subject_phrase="GitLab public project feature posture risk",
    ),
    # Fallback family — any other gitlab_ rule key not matched above.
    "gitlab_configuration_risk_with_activity": _family(
        rule_keys=set(),  # populated dynamically for unknown gitlab_ rule keys
        specific_signals={_GENERIC_SIGNAL},
        match_key="config",
        severity="low",
        title_phrase="GitLab configuration risk aligned with related GitLab configuration activity",
        subject_phrase="GitLab configuration posture risk",
    ),
}

GITLAB_CORRELATION_TYPES: frozenset[str] = frozenset(GITLAB_CORRELATION_RULES.keys())

# Reverse index: base rule key → correlation family key.
_RULE_KEY_TO_FAMILY: dict[str, str] = {}
for _ct, _rule in GITLAB_CORRELATION_RULES.items():
    for _rk in _rule["rule_keys"]:
        _RULE_KEY_TO_FAMILY[_rk] = _ct

_FALLBACK_FAMILY = "gitlab_configuration_risk_with_activity"

# All signal types this service consumes.
_ALL_SIGNAL_TYPES: frozenset[str] = frozenset(
    st for rule in GITLAB_CORRELATION_RULES.values() for st in rule["signal_types"]
)

# Safe posture fields per specific signal type that may be carried from signal
# metadata onto the correlation. Every key must also be in
# corr_svc.ALLOWED_METADATA_KEYS — the sanitizer is the second hard gate.
_SAFE_SIGNAL_FIELDS: dict[str, tuple[str, ...]] = {
    "gitlab_project_visibility_signal": (
        "visibility_category",
        "archived",
        "shared_runners_enabled",
        "protected_branch_count",
    ),
    "gitlab_group_visibility_signal": (
        "visibility_category",
        "project_count",
        "subgroup_count",
        "member_count_category",
        "two_factor_requirement_enabled",
        "membership_lock",
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
        "event_count",
    ),
    "gitlab_webhook_http_scheme_signal": (
        "owner_resource_id",
        "owner_type",
        "webhook_scheme_category",
        "ssl_verification_enabled",
        "event_count",
    ),
    "gitlab_webhook_broad_event_scope_signal": (
        "owner_resource_id",
        "owner_type",
        "event_count",
        "push_events",
        "pipeline_events",
        "job_events",
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
        "unprotected_unmasked_count",
    ),
    "gitlab_deploy_key_write_enabled_signal": (
        "project_resource_id",
        "write_enabled_count",
        "read_only_count",
        "enabled_count",
    ),
    "gitlab_deploy_key_posture_signal": (
        "project_resource_id",
        "write_enabled_count",
        "enabled_count",
    ),
    "gitlab_shared_runner_enabled_signal": (
        "owner_resource_id",
        "owner_type",
        "runner_count",
        "shared_runner_enabled",
        "untagged_runner_count",
    ),
    "gitlab_runner_posture_signal": (
        "owner_resource_id",
        "owner_type",
        "runner_count",
        "shared_runner_enabled",
        "untagged_runner_count",
    ),
    "gitlab_merge_request_approval_weakened": (
        "project_resource_id",
        "approvals_required",
        "code_owner_approval_required",
        "reset_approvals_on_push",
        "override_approvers_disabled",
    ),
    "gitlab_project_public_feature_signal": (
        "visibility_category",
        "wiki_enabled",
        "snippets_enabled",
        "container_registry_enabled",
        "packages_enabled",
    ),
    _GENERIC_SIGNAL: (),
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _fmd(finding: SecurityFinding, key: str) -> Optional[str]:
    """Read a string from finding.evidence (never raises).

    PRIVACY: never returns GitLab access tokens, webhook secrets, CI variable
    names/values, deploy key material, runner tokens/IPs, project/group names,
    namespace paths, raw URLs, branch names, user emails, or PII.
    """
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    v = ev.get(key)
    if isinstance(v, str) and v.strip():
        return v
    return None


def _smd(signal: SecurityIncidentSignal, key: str) -> Optional[str]:
    """Read a string from signal.signal_metadata (never raises)."""
    md = signal.signal_metadata if isinstance(signal.signal_metadata, dict) else {}
    v = md.get(key)
    if isinstance(v, str) and v.strip():
        return v
    return None


def _smdint(signal: SecurityIncidentSignal, key: str) -> Optional[int]:
    """Read an int from signal.signal_metadata (never raises)."""
    md = signal.signal_metadata if isinstance(signal.signal_metadata, dict) else {}
    v = md.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _smdval(signal: SecurityIncidentSignal, key: str) -> Optional[Any]:
    """Read a safe scalar from signal_metadata (never raises)."""
    md = signal.signal_metadata if isinstance(signal.signal_metadata, dict) else {}
    v = md.get(key)
    if isinstance(v, (bool, int, float, str)):
        return v
    return None


def _base_rule_key(finding_key: str) -> str:
    """Strip any ':resource_id' suffix to get the base rule key."""
    return finding_key.split(":", 1)[0] if finding_key else ""


def _family_for_rule_key(rule_key: str) -> str:
    """Resolve a base rule key to its correlation family key."""
    fam = _RULE_KEY_TO_FAMILY.get(rule_key)
    if fam is not None:
        return fam
    return _FALLBACK_FAMILY


def _signal_type_for_rule_key(rule_key: str) -> str:
    """Resolve a base rule key to its expected activity signal type."""
    return GITLAB_RULE_KEY_TO_SIGNAL_TYPE.get(rule_key, _GENERIC_SIGNAL)


def _resource_id_from_finding(finding: SecurityFinding) -> Optional[str]:
    """Extract the safe opaque resource identifier from a finding.

    NEVER uses project/group names, namespace paths, webhook URLs, branch
    names, user emails, tokens, or PII.
    """
    return finding.resource_id or _fmd(finding, "record_id")


def _resource_id_from_signal(signal: SecurityIncidentSignal) -> Optional[str]:
    """Extract the safe opaque resource identifier from a signal's metadata."""
    return _smd(signal, "resource_id")


def _record_type_from_signal(signal: SecurityIncidentSignal) -> Optional[str]:
    return _smd(signal, "record_type") or _smd(signal, "resource_type")


def _match_pair(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
) -> Optional[str]:
    """Attempt to match a finding to a signal.

    Primary: exact safe opaque resource_id on both sides.
    Fallback: record_type → signal_type family matching.

    PRIVACY: never matches on project/group names, namespace paths, raw URLs,
    branch names, user emails, tokens, key material, or PII.
    """
    f_rid = _resource_id_from_finding(finding)
    s_rid = _resource_id_from_signal(signal)
    if f_rid and s_rid and f_rid == s_rid:
        return "resource_id_match"

    rule_key = _base_rule_key(finding.finding_key)
    expected_signal = _signal_type_for_rule_key(rule_key)
    if signal.signal_type in (expected_signal, _GENERIC_SIGNAL):
        return "record_type_match"
    return None


def _match_strength(
    match_reason: str,
    signal_type: str,
    finding_integration_id: Any,
    signal_integration_id: Any,
) -> str:
    if match_reason == "record_type_match":
        return "low"
    if match_reason != "resource_id_match":
        return "low"
    if _GENERIC_SIGNAL in signal_type:
        return "medium"
    if (finding_integration_id and signal_integration_id
            and str(finding_integration_id) == str(signal_integration_id)):
        return "high"
    return "medium"


def _correlation_key(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
    correlation_type: str,
) -> str:
    """Deterministic correlation key — one correlation per (type, finding, signal)."""
    return "|".join([
        "gitlab.correlation",
        correlation_type,
        str(finding.id),
        str(signal.id),
    ])


def _build_correlation(
    *,
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
    correlation_type: str,
    rule: dict[str, Any],
    match_reason: str,
    lookback_hours: int = 24,
) -> dict[str, Any]:
    """Build a correlation dict (not yet persisted).

    PRIVACY: metadata uses only safe opaque identifiers, booleans, counts, and
    category labels. NEVER GitLab access tokens, OAuth tokens, PRIVATE-TOKEN
    values, webhook secret tokens, CI/CD variable names/values, deploy key
    material, SSH keys, runner tokens/IPs, project/group names, namespace
    paths, repo URLs, raw webhook URLs, branch names, commit messages, merge
    request titles, issue titles, pipeline/job logs, artifacts, user identities,
    customer data, PII, or raw GitLab API payloads.
    """
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    s_first = _aware(signal.first_seen_at)
    s_last = _aware(signal.last_seen_at)

    times = [t for t in [f_start, f_end, s_first, s_last] if t is not None]
    window_start = min(times) if times else _utcnow() - _WINDOW
    window_end = max(times) if times else _utcnow()

    match_strength = _match_strength(
        match_reason,
        signal.signal_type,
        finding.integration_id,
        signal.integration_id,
    )
    confidence = match_strength

    title = f"{rule['title_phrase']} ({match_reason})"[:240]
    summary = (
        f"{rule['subject_phrase']} correlated with {signal.signal_type} "
        f"evidence ({match_reason}). {_REVIEW_NOTE}"
    )

    rule_key = _base_rule_key(finding.finding_key)
    resource_id = _resource_id_from_finding(finding) or _resource_id_from_signal(signal)
    resource_type = _fmd(finding, "resource_type") or _smd(signal, "resource_type")
    record_type = _fmd(finding, "record_type") or _record_type_from_signal(signal)

    md_raw: dict[str, Any] = {
        "provider": PROVIDER,
        "correlation_type": correlation_type,
        "source": "gitlab_activity_event",
        "event_source": _smd(signal, "event_source") or "gitlab_activity_event",
        "event_type": _smd(signal, "event_type"),
        "rule_key": rule_key,
        "finding_id": str(finding.id),
        "finding_rule_key": rule_key,
        "finding_severity": finding.severity,
        "finding_record_type": record_type,
        "finding_resource_type": resource_type or rule["match_key"],
        "finding_resource_id": _resource_id_from_finding(finding),
        "signal_id": str(signal.id),
        "signal_type": signal.signal_type,
        "record_type": record_type,
        "resource_type": resource_type or rule["match_key"],
        "resource_id": resource_id,
        "operation_family": _smd(signal, "operation_family") or "gitlab_configuration",
        "operation_action": _smd(signal, "operation_action") or "configuration_observed",
        "event_types": _smd(signal, "event_types"),
        "event_count": _smdint(signal, "event_count"),
        "signal_count": 1,
        "activity_count": _smdint(signal, "event_count"),
        "risk_count": 1,
        "matched_on": match_reason,
        "match_reason": match_reason,
        "match_confidence": match_strength,
        "match_strength": match_strength,
        "risk_family": rule["match_key"],
        "activity_family": rule["match_key"],
        "correlation_reason": f"gitlab_{rule['match_key']}_risk_activity",
        "correlation_strength": match_strength,
        "lookback_hours": int(lookback_hours),
        "window_start": window_start.isoformat() if window_start else None,
        "window_end": window_end.isoformat() if window_end else None,
    }

    # Carry forward safe posture fields from the signal.
    # The specific_signals set may contain multiple signal types; the first
    # one that matches is used for field lookup.
    signal_fields_key = signal.signal_type
    if signal_fields_key not in _SAFE_SIGNAL_FIELDS:
        signal_fields_key = _GENERIC_SIGNAL

    for field in _SAFE_SIGNAL_FIELDS.get(signal_fields_key, ()):
        value = _smdval(signal, field)
        if value is not None:
            md_raw[field] = value

    metadata = corr_svc.sanitize_correlation_metadata(md_raw)

    return {
        "provider": PROVIDER,
        "correlation_key": _correlation_key(finding, signal, correlation_type),
        "correlation_type": correlation_type,
        "severity": rule["severity"],
        "confidence": confidence,
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": signal.linked_activity_event_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": window_start,
        "last_seen_at": window_end,
        "metadata": metadata,
    }


def _in_window(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
) -> bool:
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    if f_start is None or f_end is None:
        return True

    s_time = _aware(signal.last_seen_at) or _aware(signal.first_seen_at)
    if s_time is None:
        return True

    window_open = f_start - _WINDOW
    window_close = f_end + _WINDOW
    return window_open <= s_time <= window_close


# ── Main function ─────────────────────────────────────────────────────────────


def generate_gitlab_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_correlations: int = 100,
) -> dict[str, Any]:
    """Generate GitLab Risk × Activity correlations for a workspace.

    Joins active GitLab configuration-risk findings with GitLab activity
    signals on the same safe opaque resource_id within a review window,
    falling back to record_type → signal_type family matching when no exact
    resource match is available.

    Covers eleven correlation families: public_visibility,
    branch_protection_risk, webhook_secret_risk, webhook_transport_risk,
    webhook_event_scope_risk, ci_variable_risk, deploy_key_risk, runner_risk,
    merge_request_approval_risk, public_feature_risk, and a generic config
    fallback. Each family also correlates against the generic
    gitlab_configuration_activity_signal when no resource-specific signal is
    available.

    GitLab access tokens, OAuth tokens, PRIVATE-TOKEN values, webhook secret
    tokens, CI/CD variable names/values, deploy key material, SSH keys, runner
    tokens/IPs, project/group names, namespace paths, repo URLs, raw webhook
    URLs, branch names, commit messages, merge request titles, issue titles,
    pipeline/job logs, artifacts, user emails, usernames, customer data, PII,
    and raw GitLab API payloads are never used or stored.
    Does not confirm compromise, unauthorized access, source-code exposure,
    secret exposure, token exposure, credential exposure, or data exposure.
    Idempotent — re-running creates no duplicates. Never raises.

    Returns:
        Summary dict with provider/findings_scanned/signals_scanned/
        events_scanned/correlations_created/correlations_skipped/groups_scanned/
        lookback_hours/max_correlations fields.
    """
    hours = max(1, min(int(lookback_hours or 24), 168))
    cap = max(1, min(int(max_correlations or 100), 1000))
    cutoff = _utcnow() - timedelta(hours=hours)

    # ── Load active GitLab findings ───────────────────────────────────────────
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER,
            SecurityFinding.status == "active",
        )
        .order_by(SecurityFinding.last_seen_at.desc().nullslast())
        .limit(2000)
        .all()
    )

    # ── Load recent GitLab activity signals ───────────────────────────────────
    signals = (
        db.query(SecurityIncidentSignal)
        .filter(
            SecurityIncidentSignal.workspace_id == workspace_id,
            SecurityIncidentSignal.provider == PROVIDER,
            SecurityIncidentSignal.signal_type.in_(_ALL_SIGNAL_TYPES),
            SecurityIncidentSignal.last_seen_at >= cutoff,
        )
        .order_by(SecurityIncidentSignal.last_seen_at.desc().nullslast())
        .limit(2000)
        .all()
    )

    findings_by_family: dict[str, list[SecurityFinding]] = {}
    for f in findings:
        rk = _base_rule_key(f.finding_key)
        fam = _family_for_rule_key(rk)
        findings_by_family.setdefault(fam, []).append(f)

    signals_by_type: dict[str, list[SecurityIncidentSignal]] = {}
    for s in signals:
        signals_by_type.setdefault(s.signal_type, []).append(s)

    created = skipped = candidate_pairs = 0

    for correlation_type, rule in GITLAB_CORRELATION_RULES.items():
        if created >= cap:
            break

        candidate_findings = findings_by_family.get(correlation_type, [])
        if not candidate_findings:
            continue

        candidate_signals: list[SecurityIncidentSignal] = []
        for st in rule["signal_types"]:
            candidate_signals.extend(signals_by_type.get(st, []))

        if not candidate_signals:
            continue

        for finding in candidate_findings:
            if created >= cap:
                break
            for signal in candidate_signals:
                if created >= cap:
                    break
                if not _in_window(finding, signal):
                    continue
                match_reason = _match_pair(finding, signal)
                if match_reason is None:
                    continue
                candidate_pairs += 1
                try:
                    correlation = _build_correlation(
                        finding=finding,
                        signal=signal,
                        correlation_type=correlation_type,
                        rule=rule,
                        match_reason=match_reason,
                        lookback_hours=hours,
                    )
                    outcome, _row = corr_svc.upsert_correlation(
                        workspace_id=workspace_id,
                        correlation=correlation,
                        db=db,
                    )
                    if outcome == "created":
                        created += 1
                    else:
                        skipped += 1
                except Exception:  # noqa: BLE001
                    _log.warning(
                        "gitlab_correlations: failed to upsert one pair; continuing"
                    )
                    continue

    return {
        "provider": PROVIDER,
        "findings_scanned": len(findings),
        "signals_scanned": len(signals),
        "events_scanned": len(signals),
        "correlations_created": created,
        "correlations_skipped": skipped,
        "groups_scanned": candidate_pairs,
        "lookback_hours": hours,
        "max_correlations": cap,
    }
