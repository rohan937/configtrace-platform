"""Terraform Cloud Risk × Activity Correlations (M88F).

Joins active Terraform Cloud configuration-risk findings (provider=
terraform_cloud, from M88B/M88C) with Terraform Cloud activity signals
(provider=terraform_cloud, from M88E) on the same resource within a review
window. Produces SecuritySignalCorrelation rows with evidence_level=
"correlation".

CORRELATION STRATEGY
--------------------
Fourteen specialized correlation families, one per Terraform Cloud
configuration surface:

  organization_access        — org 2FA/SSO findings ↔ org access posture signals
  workspace_auto_apply       — auto-apply findings ↔ auto-apply signals
  workspace_remote_state     — global remote state findings ↔ remote state signals
  workspace_execution        — local/agent execution findings ↔ execution mode signals
  workspace_vcs              — VCS-missing findings ↔ VCS posture signals
  workspace_run_control      — run-control findings ↔ run-control signals
  workspace_version          — unpinned TF version findings ↔ version posture signals
  variable                   — variable posture findings ↔ variable posture signals
  variable_set_scope         — variable set findings ↔ variable set scope signals
  policy_set                 — policy set findings ↔ policy enforcement/scope signals
  notification               — notification findings ↔ notification transport/posture signals
  run_trigger                — run trigger findings ↔ run trigger signals
  team_access                — team access findings ↔ team access posture signals
  state_version_metadata     — state version findings ↔ state version metadata signals
  config (fallback)          — any other terraform_cloud_ rule ↔ generic config signal

Each family also matches against the generic
terraform_cloud_configuration_activity_signal type (lower confidence) when no
resource-specific signal is available.

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They never assert that
a breach, compromise, unauthorized access, state exposure, tfstate exposure,
secret exposure, token leak, credential exposure, infrastructure exposure, or
data exposure has occurred or been confirmed. Severity = review priority only.
Confidence = "medium" (circumstantial co-occurrence, not proof).

PRIVACY: metadata is allowlisted + flat. NEVER stored:
  Terraform Cloud API tokens, OAuth tokens, VCS tokens, authorization headers.
  Variable names or values, state files, state outputs, resource addresses.
  Plan logs, apply logs, run logs, webhook URLs, notification tokens.
  Organization names, workspace names, project names, VCS URLs, branch names.
  Commit SHAs, team names, user emails, usernames, Slack channels, email
  recipients, customer infrastructure data, PII, or raw API payloads.
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

PROVIDER = "terraform_cloud"

_WINDOW = timedelta(hours=24)

_REVIEW_NOTE = (
    "Terraform Cloud configuration risk correlated with related Terraform Cloud "
    "configuration activity on the same resource. Configuration evidence for "
    "review that may require review. Does not confirm compromise, unauthorized "
    "access, state exposure, secret exposure, token exposure, credential "
    "exposure, infrastructure exposure, or data exposure."
)

# ── Generic / fallback signal type every family also accepts ──────────────────
_GENERIC_SIGNAL = "terraform_cloud_configuration_activity_signal"

# ── Rule key → expected signal type mapping ───────────────────────────────────
TERRAFORM_CLOUD_RULE_KEY_TO_SIGNAL_TYPE: dict[str, str] = {
    # Organization access posture
    "terraform_cloud_organization_two_factor_not_required": "terraform_cloud_organization_access_posture_signal",
    "terraform_cloud_organization_sso_not_enabled": "terraform_cloud_organization_access_posture_signal",
    # Workspace auto-apply
    "terraform_cloud_workspace_auto_apply_enabled": "terraform_cloud_workspace_auto_apply_signal",
    # Workspace global remote state
    "terraform_cloud_workspace_global_remote_state_enabled": "terraform_cloud_workspace_global_remote_state_signal",
    # Workspace execution mode
    "terraform_cloud_workspace_local_execution_mode": "terraform_cloud_workspace_execution_mode_signal",
    "terraform_cloud_workspace_agent_execution_mode": "terraform_cloud_workspace_execution_mode_signal",
    # Workspace VCS posture
    "terraform_cloud_workspace_vcs_connection_missing": "terraform_cloud_workspace_vcs_posture_signal",
    # Workspace run control
    "terraform_cloud_workspace_queue_all_runs_disabled": "terraform_cloud_workspace_run_control_signal",
    "terraform_cloud_workspace_file_triggers_disabled": "terraform_cloud_workspace_run_control_signal",
    "terraform_cloud_workspace_speculative_plans_disabled": "terraform_cloud_workspace_run_control_signal",
    "terraform_cloud_workspace_run_triggers_present": "terraform_cloud_workspace_run_control_signal",
    "terraform_cloud_workspace_many_trigger_prefixes": "terraform_cloud_workspace_run_control_signal",
    "terraform_cloud_workspace_latest_run_failed": "terraform_cloud_workspace_run_control_signal",
    # Workspace version posture
    "terraform_cloud_workspace_unpinned_terraform_version": "terraform_cloud_workspace_version_posture_signal",
    # Variable posture
    "terraform_cloud_workspace_non_sensitive_variables_present": "terraform_cloud_variable_posture_signal",
    "terraform_cloud_workspace_no_sensitive_variables": "terraform_cloud_variable_posture_signal",
    "terraform_cloud_workspace_environment_variables_non_sensitive": "terraform_cloud_variable_posture_signal",
    "terraform_cloud_workspace_terraform_variables_non_sensitive": "terraform_cloud_variable_posture_signal",
    # Variable set scope
    "terraform_cloud_variable_set_global_scope": "terraform_cloud_variable_set_scope_signal",
    "terraform_cloud_variable_set_non_sensitive_variables": "terraform_cloud_variable_set_scope_signal",
    "terraform_cloud_variable_set_broad_scope": "terraform_cloud_variable_set_scope_signal",
    # Policy set enforcement/scope
    "terraform_cloud_policy_set_advisory_enforcement": "terraform_cloud_policy_set_enforcement_signal",
    "terraform_cloud_policy_set_empty": "terraform_cloud_policy_set_enforcement_signal",
    "terraform_cloud_policy_set_global_scope": "terraform_cloud_policy_set_scope_signal",
    "terraform_cloud_policy_set_broad_scope_advisory": "terraform_cloud_policy_set_enforcement_signal",
    "terraform_cloud_policy_set_no_workspace_or_project_scope": "terraform_cloud_policy_set_scope_signal",
    # Notification transport/posture
    "terraform_cloud_notification_http_webhook": "terraform_cloud_notification_transport_signal",
    "terraform_cloud_notification_token_missing": "terraform_cloud_notification_transport_signal",
    "terraform_cloud_notification_broad_trigger_scope": "terraform_cloud_notification_posture_signal",
    "terraform_cloud_notification_disabled": "terraform_cloud_notification_posture_signal",
    # Run trigger
    "terraform_cloud_run_trigger_enabled": "terraform_cloud_run_trigger_signal",
    # Team access posture
    "terraform_cloud_team_admin_access": "terraform_cloud_team_access_posture_signal",
    "terraform_cloud_team_apply_access": "terraform_cloud_team_access_posture_signal",
    "terraform_cloud_team_write_access": "terraform_cloud_team_access_posture_signal",
    "terraform_cloud_team_custom_permissions": "terraform_cloud_team_access_posture_signal",
    # State version metadata
    "terraform_cloud_state_version_present": "terraform_cloud_state_version_metadata_signal",
}


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


TERRAFORM_CLOUD_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "terraform_cloud_organization_access_risk_with_activity": _family(
        rule_keys={
            "terraform_cloud_organization_two_factor_not_required",
            "terraform_cloud_organization_sso_not_enabled",
        },
        specific_signals={"terraform_cloud_organization_access_posture_signal"},
        match_key="organization_access",
        severity="medium",
        title_phrase="Terraform Cloud organization access posture risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud organization access posture risk",
    ),
    "terraform_cloud_workspace_auto_apply_risk_with_activity": _family(
        rule_keys={"terraform_cloud_workspace_auto_apply_enabled"},
        specific_signals={"terraform_cloud_workspace_auto_apply_signal"},
        match_key="workspace_auto_apply",
        severity="high",
        title_phrase="Terraform Cloud workspace auto-apply risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud workspace auto-apply posture risk",
    ),
    "terraform_cloud_workspace_remote_state_risk_with_activity": _family(
        rule_keys={"terraform_cloud_workspace_global_remote_state_enabled"},
        specific_signals={"terraform_cloud_workspace_global_remote_state_signal"},
        match_key="workspace_remote_state",
        severity="high",
        title_phrase="Terraform Cloud workspace global remote state risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud workspace global remote state posture risk",
    ),
    "terraform_cloud_workspace_execution_risk_with_activity": _family(
        rule_keys={
            "terraform_cloud_workspace_local_execution_mode",
            "terraform_cloud_workspace_agent_execution_mode",
        },
        specific_signals={"terraform_cloud_workspace_execution_mode_signal"},
        match_key="workspace_execution",
        severity="medium",
        title_phrase="Terraform Cloud workspace execution mode risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud workspace execution mode posture risk",
    ),
    "terraform_cloud_workspace_vcs_risk_with_activity": _family(
        rule_keys={"terraform_cloud_workspace_vcs_connection_missing"},
        specific_signals={"terraform_cloud_workspace_vcs_posture_signal"},
        match_key="workspace_vcs",
        severity="medium",
        title_phrase="Terraform Cloud workspace VCS posture risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud workspace VCS connection posture risk",
    ),
    "terraform_cloud_workspace_run_control_risk_with_activity": _family(
        rule_keys={
            "terraform_cloud_workspace_queue_all_runs_disabled",
            "terraform_cloud_workspace_file_triggers_disabled",
            "terraform_cloud_workspace_speculative_plans_disabled",
            "terraform_cloud_workspace_run_triggers_present",
            "terraform_cloud_workspace_many_trigger_prefixes",
            "terraform_cloud_workspace_latest_run_failed",
        },
        specific_signals={"terraform_cloud_workspace_run_control_signal"},
        match_key="workspace_run_control",
        severity="medium",
        title_phrase="Terraform Cloud workspace run control risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud workspace run control posture risk",
    ),
    "terraform_cloud_workspace_version_risk_with_activity": _family(
        rule_keys={"terraform_cloud_workspace_unpinned_terraform_version"},
        specific_signals={"terraform_cloud_workspace_version_posture_signal"},
        match_key="workspace_version",
        severity="low",
        title_phrase="Terraform Cloud workspace version posture risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud workspace unpinned Terraform version posture risk",
    ),
    "terraform_cloud_variable_risk_with_activity": _family(
        rule_keys={
            "terraform_cloud_workspace_non_sensitive_variables_present",
            "terraform_cloud_workspace_no_sensitive_variables",
            "terraform_cloud_workspace_environment_variables_non_sensitive",
            "terraform_cloud_workspace_terraform_variables_non_sensitive",
        },
        specific_signals={"terraform_cloud_variable_posture_signal"},
        match_key="variable",
        severity="medium",
        title_phrase="Terraform Cloud variable posture risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud workspace variable posture risk",
    ),
    "terraform_cloud_variable_set_scope_risk_with_activity": _family(
        rule_keys={
            "terraform_cloud_variable_set_global_scope",
            "terraform_cloud_variable_set_non_sensitive_variables",
            "terraform_cloud_variable_set_broad_scope",
        },
        specific_signals={"terraform_cloud_variable_set_scope_signal"},
        match_key="variable_set_scope",
        severity="medium",
        title_phrase="Terraform Cloud variable set scope risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud variable set scope posture risk",
    ),
    "terraform_cloud_policy_set_risk_with_activity": _family(
        rule_keys={
            "terraform_cloud_policy_set_advisory_enforcement",
            "terraform_cloud_policy_set_empty",
            "terraform_cloud_policy_set_global_scope",
            "terraform_cloud_policy_set_broad_scope_advisory",
            "terraform_cloud_policy_set_no_workspace_or_project_scope",
        },
        specific_signals={
            "terraform_cloud_policy_set_enforcement_signal",
            "terraform_cloud_policy_set_scope_signal",
        },
        match_key="policy_set",
        severity="medium",
        title_phrase="Terraform Cloud policy set risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud policy set enforcement and scope posture risk",
    ),
    "terraform_cloud_notification_risk_with_activity": _family(
        rule_keys={
            "terraform_cloud_notification_http_webhook",
            "terraform_cloud_notification_token_missing",
            "terraform_cloud_notification_broad_trigger_scope",
            "terraform_cloud_notification_disabled",
        },
        specific_signals={
            "terraform_cloud_notification_transport_signal",
            "terraform_cloud_notification_posture_signal",
        },
        match_key="notification",
        severity="medium",
        title_phrase="Terraform Cloud notification configuration risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud notification transport and posture risk",
    ),
    "terraform_cloud_run_trigger_risk_with_activity": _family(
        rule_keys={"terraform_cloud_run_trigger_enabled"},
        specific_signals={"terraform_cloud_run_trigger_signal"},
        match_key="run_trigger",
        severity="medium",
        title_phrase="Terraform Cloud run trigger risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud run trigger posture risk",
    ),
    "terraform_cloud_team_access_risk_with_activity": _family(
        rule_keys={
            "terraform_cloud_team_admin_access",
            "terraform_cloud_team_apply_access",
            "terraform_cloud_team_write_access",
            "terraform_cloud_team_custom_permissions",
        },
        specific_signals={"terraform_cloud_team_access_posture_signal"},
        match_key="team_access",
        severity="medium",
        title_phrase="Terraform Cloud team access posture risk aligned with related configuration activity",
        subject_phrase="Terraform Cloud team access posture risk",
    ),
    "terraform_cloud_state_version_metadata_risk_with_activity": _family(
        rule_keys={"terraform_cloud_state_version_present"},
        specific_signals={"terraform_cloud_state_version_metadata_signal"},
        match_key="state_version_metadata",
        severity="low",
        title_phrase="Terraform Cloud state version metadata posture aligned with related configuration activity",
        subject_phrase="Terraform Cloud state version metadata posture",
    ),
    # Fallback family — any other terraform_cloud_ rule key not matched above.
    "terraform_cloud_configuration_risk_with_activity": _family(
        rule_keys=set(),  # populated dynamically for unknown terraform_cloud_ rule keys
        specific_signals={_GENERIC_SIGNAL},
        match_key="config",
        severity="low",
        title_phrase="Terraform Cloud configuration risk aligned with related Terraform Cloud configuration activity",
        subject_phrase="Terraform Cloud configuration posture risk",
    ),
}

TERRAFORM_CLOUD_CORRELATION_TYPES: frozenset[str] = frozenset(
    TERRAFORM_CLOUD_CORRELATION_RULES.keys()
)

# Reverse index: base rule key → correlation family key.
_RULE_KEY_TO_FAMILY: dict[str, str] = {}
for _ct, _rule in TERRAFORM_CLOUD_CORRELATION_RULES.items():
    for _rk in _rule["rule_keys"]:
        _RULE_KEY_TO_FAMILY[_rk] = _ct

_FALLBACK_FAMILY = "terraform_cloud_configuration_risk_with_activity"

# All signal types this service consumes.
_ALL_SIGNAL_TYPES: frozenset[str] = frozenset(
    st for rule in TERRAFORM_CLOUD_CORRELATION_RULES.values() for st in rule["signal_types"]
)

# Safe posture fields per signal type carried from signal metadata onto the
# correlation. All keys must also be in corr_svc.ALLOWED_METADATA_KEYS.
# NEVER raw names, URLs, tokens, secrets, variable values, state content, or PII.
_SAFE_SIGNAL_FIELDS: dict[str, tuple[str, ...]] = {
    "terraform_cloud_organization_access_posture_signal": (
        "organization_resource_id",
        "two_factor_requirement_enabled",
        "sso_enabled",
        "workspace_count",
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
    ),
    "terraform_cloud_workspace_version_posture_signal": (
        "workspace_resource_id",
        "terraform_version_category",
    ),
    "terraform_cloud_variable_posture_signal": (
        "workspace_resource_id",
        "variable_count",
        "sensitive_variable_count",
        "non_sensitive_variable_count",
        "raw_value_never_read",
    ),
    "terraform_cloud_variable_set_scope_signal": (
        "variable_set_resource_id",
        "global_scope",
        "workspace_count",
        "variable_count",
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

    PRIVACY: never returns API tokens, variable names/values, state content,
    VCS URLs, webhook URLs, team names, user emails, org/workspace/project
    names, plan/apply log content, or raw API payloads.
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
    # Only terraform_cloud_ prefixed rules fall back to the generic family.
    if rule_key.startswith("terraform_cloud_"):
        return _FALLBACK_FAMILY
    return ""  # Non-TC rules: skip entirely


def _signal_type_for_rule_key(rule_key: str) -> str:
    """Resolve a base rule key to its expected activity signal type."""
    return TERRAFORM_CLOUD_RULE_KEY_TO_SIGNAL_TYPE.get(rule_key, _GENERIC_SIGNAL)


def _resource_id_from_finding(finding: SecurityFinding) -> Optional[str]:
    """Extract the safe opaque resource identifier from a finding.

    NEVER uses org/workspace/project names, VCS URLs, webhook URLs, variable
    names/values, team names, user emails, or PII.
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
    Fallback: rule_key → signal_type family matching.

    PRIVACY: never matches on org/workspace/project names, VCS URLs, webhook
    URLs, variable names/values, team names, user emails, or PII.
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
    if (
        finding_integration_id
        and signal_integration_id
        and str(finding_integration_id) == str(signal_integration_id)
    ):
        return "high"
    return "medium"


def _correlation_key(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
    correlation_type: str,
) -> str:
    """Deterministic correlation key — one correlation per (type, finding, signal)."""
    return "|".join([
        "terraform_cloud.correlation",
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
    category labels. NEVER Terraform Cloud API tokens, OAuth tokens, VCS tokens,
    variable names/values, state files, state outputs, plan/apply logs, webhook
    URLs, notification tokens, org/workspace/project names, VCS URLs, branch
    names, team names, user emails, customer infrastructure data, PII, or raw
    API payloads.
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
    resource_id = (
        _resource_id_from_finding(finding) or _resource_id_from_signal(signal)
    )
    resource_type = (
        _fmd(finding, "resource_type") or _smd(signal, "resource_type")
    )
    record_type = (
        _fmd(finding, "record_type") or _record_type_from_signal(signal)
    )

    md_raw: dict[str, Any] = {
        "provider": PROVIDER,
        "correlation_type": correlation_type,
        "source": "terraform_cloud_activity_event",
        "event_source": (
            _smd(signal, "event_source") or "terraform_cloud_activity_event"
        ),
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
        "operation_family": (
            _smd(signal, "operation_family") or "terraform_cloud_configuration"
        ),
        "operation_action": (
            _smd(signal, "operation_action") or "configuration_observed"
        ),
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
        "correlation_reason": f"terraform_cloud_{rule['match_key']}_risk_activity",
        "correlation_strength": match_strength,
        "lookback_hours": int(lookback_hours),
        "window_start": window_start.isoformat() if window_start else None,
        "window_end": window_end.isoformat() if window_end else None,
    }

    # Carry forward safe posture fields from the signal.
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


# ── Main function ──────────────────────────────────────────────────────────────


def generate_terraform_cloud_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_correlations: int = 100,
) -> dict[str, Any]:
    """Generate Terraform Cloud Risk × Activity correlations for a workspace.

    Joins active Terraform Cloud configuration-risk findings with Terraform
    Cloud activity signals on the same safe opaque resource_id within a review
    window, falling back to rule_key → signal_type family matching when no
    exact resource match is available.

    Covers fourteen correlation families: organization_access,
    workspace_auto_apply, workspace_remote_state, workspace_execution,
    workspace_vcs, workspace_run_control, workspace_version, variable,
    variable_set_scope, policy_set, notification, run_trigger, team_access,
    state_version_metadata, and a generic config fallback.

    Terraform Cloud API tokens, OAuth tokens, VCS tokens, variable names/values,
    state files, state outputs, plan/apply logs, webhook URLs, notification
    tokens, org/workspace/project names, VCS URLs, branch names, team names,
    user emails, customer infrastructure data, PII, and raw API payloads are
    never used or stored. Does not confirm compromise, unauthorized access,
    state exposure, secret exposure, token exposure, credential exposure,
    infrastructure exposure, or data exposure. Idempotent — re-running creates
    no duplicates. Never raises.

    Returns:
        Summary dict with provider/findings_scanned/signals_scanned/
        events_scanned/correlations_created/correlations_skipped/groups_scanned/
        lookback_hours/max_correlations fields.
    """
    hours = max(1, min(int(lookback_hours or 24), 168))
    cap = max(1, min(int(max_correlations or 100), 1000))
    cutoff = _utcnow() - timedelta(hours=hours)

    # Load active Terraform Cloud findings.
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

    # Load recent Terraform Cloud activity signals.
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
        if not fam:
            continue  # Non-TC rule — skip
        findings_by_family.setdefault(fam, []).append(f)

    signals_by_type: dict[str, list[SecurityIncidentSignal]] = {}
    for s in signals:
        signals_by_type.setdefault(s.signal_type, []).append(s)

    created = skipped = candidate_pairs = 0

    for correlation_type, rule in TERRAFORM_CLOUD_CORRELATION_RULES.items():
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
                        "terraform_cloud_correlations: failed to upsert one pair; continuing"
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
