"""Jira Risk × Activity Correlations (M86F).

Joins active Jira configuration-risk findings (provider=jira, from M86B/M86C)
with Jira activity signals (provider=jira, from M86E) on the same resource
within a review window. Produces SecuritySignalCorrelation rows with
evidence_level="correlation".

CORRELATION STRATEGY
--------------------
Thirteen specialized correlation families, one per Jira configuration surface:

  permission_scheme            — permission scheme findings ↔ permission scheme activity
  webhook                      — webhook findings ↔ webhook activity
  workflow                     — workflow findings ↔ workflow activity
  workflow_scheme              — workflow scheme findings ↔ workflow scheme activity
  automation_rule              — automation rule findings ↔ automation rule activity
  board                        — board findings ↔ board activity
  notification_scheme          — notification scheme findings ↔ notification scheme activity
  screen_scheme                — screen scheme findings ↔ screen scheme activity
  field_configuration_scheme   — field configuration scheme findings ↔ field config activity
  issue_type_scheme            — issue type scheme findings ↔ issue type scheme activity
  project                      — project findings ↔ project activity
  site                         — site findings ↔ site activity
  config (fallback)            — any other jira_ rule ↔ generic config activity

Each family also matches against the generic jira_config_activity signal type
(lower confidence) when no resource-specific signal is available. Findings whose
base rule key does not match a specialized family fall back to the generic
jira_config_risk_with_activity family.

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They never assert that a
breach, compromise, unauthorized access, or data exposure has occurred or been
confirmed. Severity = review priority only. Confidence = "medium"
(circumstantial co-occurrence, not proof). They describe related Jira
configuration activity that may require review using configuration evidence.

PRIVACY: metadata is allowlisted + flat. NEVER stored:
  Jira API tokens, OAuth tokens, webhook secrets, integration secrets, raw
  webhook / delivery URLs, site base URLs, redirect URLs, JQL, filter
  expressions, board column / quick-filter / swimlane names, issue keys, issue
  titles, issue descriptions, comment bodies, attachment content, customer
  names, user emails, user names, account IDs, member identities, IP addresses,
  user agents, request/response payloads, raw audit payloads, raw API response
  dicts, or customer PII.
Only safe opaque identifiers, booleans, counts, and category labels.

Idempotent — re-running over the same data creates no duplicate correlation
rows.
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

PROVIDER = "jira"

_WINDOW = timedelta(hours=24)

_REVIEW_NOTE = (
    "Jira configuration risk correlated with related Jira configuration activity "
    "on the same resource. Configuration evidence for review that may require "
    "review. Does not confirm compromise, unauthorized access, or data exposure."
)

# ── Generic / fallback signal type every family also accepts ──────────────────
_GENERIC_SIGNAL = "jira_config_activity"

# ── Rule key → signal type mapping ────────────────────────────────────────────
# Direct mapping from a finding's base rule key to the Jira activity signal type
# its configuration activity is expected to surface as (M86E signal types). Any
# jira_ rule key not present here falls back to the generic jira_config_activity
# signal type.
JIRA_RULE_KEY_TO_SIGNAL_TYPE: dict[str, str] = {
    # Permission scheme rules → jira_permission_scheme_config_changed
    "jira_permission_scheme_anonymous_grants": "jira_permission_scheme_config_changed",
    "jira_permission_scheme_anyone_grants": "jira_permission_scheme_config_changed",
    "jira_permission_scheme_logged_in_grants": "jira_permission_scheme_config_changed",
    "jira_permission_scheme_high_grant_count": "jira_permission_scheme_config_changed",
    "jira_permission_scheme_public_browse_projects": "jira_permission_scheme_config_changed",
    "jira_permission_scheme_public_administer_projects": "jira_permission_scheme_config_changed",
    "jira_permission_scheme_public_manage_sprints": "jira_permission_scheme_config_changed",
    "jira_permission_scheme_public_create_issues": "jira_permission_scheme_config_changed",
    "jira_permission_scheme_public_transition_issues": "jira_permission_scheme_config_changed",
    "jira_permission_scheme_unknown_holder": "jira_permission_scheme_config_changed",
    "jira_permission_scheme_high_privilege_grants": "jira_permission_scheme_config_changed",
    "jira_permission_scheme_high_public_grant_count": "jira_permission_scheme_config_changed",
    # Webhook rules → jira_webhook_config_changed
    "jira_webhook_non_https": "jira_webhook_config_changed",
    "jira_webhook_no_secret_indicator": "jira_webhook_config_changed",
    "jira_webhook_no_jql_filter": "jira_webhook_config_changed",
    "jira_webhook_broad_event_scope": "jira_webhook_config_changed",
    "jira_webhook_comment_event_scope": "jira_webhook_config_changed",
    "jira_webhook_attachment_event_scope": "jira_webhook_config_changed",
    "jira_webhook_sprint_event_scope": "jira_webhook_config_changed",
    "jira_webhook_worklog_event_scope": "jira_webhook_config_changed",
    "jira_webhook_empty_or_broad_jql": "jira_webhook_config_changed",
    "jira_webhook_all_issue_events": "jira_webhook_config_changed",
    "jira_webhook_no_events": "jira_webhook_config_changed",
    "jira_webhook_disabled": "jira_webhook_config_changed",
    # Workflow rules → jira_workflow_config_changed
    "jira_workflow_draft": "jira_workflow_config_changed",
    "jira_workflow_low_transition_count": "jira_workflow_config_changed",
    "jira_workflow_no_done_status": "jira_workflow_config_changed",
    "jira_workflow_no_in_progress_status": "jira_workflow_config_changed",
    "jira_workflow_high_transition_rule_count": "jira_workflow_config_changed",
    "jira_workflow_high_validator_count": "jira_workflow_config_changed",
    "jira_workflow_high_condition_count": "jira_workflow_config_changed",
    "jira_workflow_high_post_function_count": "jira_workflow_config_changed",
    "jira_workflow_orphan_statuses": "jira_workflow_config_changed",
    "jira_workflow_inactive": "jira_workflow_config_changed",
    "jira_workflow_low_status_count": "jira_workflow_config_changed",
    # Workflow scheme rules → jira_workflow_scheme_config_changed
    "jira_workflow_scheme_no_projects": "jira_workflow_scheme_config_changed",
    "jira_workflow_scheme_no_default": "jira_workflow_scheme_config_changed",
    "jira_workflow_scheme_low_project_count": "jira_workflow_scheme_config_changed",
    "jira_workflow_scheme_unmapped_issue_types": "jira_workflow_scheme_config_changed",
    "jira_workflow_scheme_low_workflow_count": "jira_workflow_scheme_config_changed",
    "jira_workflow_scheme_high_issue_type_mapping_count": "jira_workflow_scheme_config_changed",
    # Automation rules → jira_automation_rule_config_changed
    "jira_automation_rule_disabled": "jira_automation_rule_config_changed",
    "jira_automation_rule_workspace_scope": "jira_automation_rule_config_changed",
    "jira_automation_rule_multi_project_scope": "jira_automation_rule_config_changed",
    "jira_automation_rule_unknown_scope": "jira_automation_rule_config_changed",
    "jira_automation_rule_web_request_action": "jira_automation_rule_config_changed",
    "jira_automation_rule_email_action": "jira_automation_rule_config_changed",
    "jira_automation_rule_external_action": "jira_automation_rule_config_changed",
    "jira_automation_rule_comment_action": "jira_automation_rule_config_changed",
    "jira_automation_rule_high_action_count": "jira_automation_rule_config_changed",
    "jira_automation_rule_high_branch_count": "jira_automation_rule_config_changed",
    # Board rules → jira_board_config_changed
    "jira_board_no_projects": "jira_board_config_changed",
    "jira_board_unknown_type": "jira_board_config_changed",
    "jira_board_broad_location": "jira_board_config_changed",
    "jira_board_broad_jql_filter": "jira_board_config_changed",
    "jira_board_no_filter_indicator": "jira_board_config_changed",
    "jira_board_high_quick_filter_count": "jira_board_config_changed",
    "jira_board_unknown_swimlane_strategy": "jira_board_config_changed",
    "jira_board_no_columns": "jira_board_config_changed",
    # Notification scheme rules → jira_notification_scheme_config_changed
    "jira_notification_scheme_high_email_recipients": "jira_notification_scheme_config_changed",
    "jira_notification_scheme_group_recipients": "jira_notification_scheme_config_changed",
    "jira_notification_scheme_project_role_recipients": "jira_notification_scheme_config_changed",
    "jira_notification_scheme_no_notifications": "jira_notification_scheme_config_changed",
    "jira_notification_scheme_unknown_recipients": "jira_notification_scheme_config_changed",
    "jira_notification_scheme_high_event_count": "jira_notification_scheme_config_changed",
    # Screen scheme rules → jira_screen_scheme_config_changed
    "jira_screen_scheme_high_field_count": "jira_screen_scheme_config_changed",
    "jira_screen_scheme_high_screen_field_count": "jira_screen_scheme_config_changed",
    "jira_screen_scheme_unmapped_screens": "jira_screen_scheme_config_changed",
    "jira_screen_scheme_low_screen_count": "jira_screen_scheme_config_changed",
    # Field configuration scheme rules → jira_field_configuration_scheme_config_changed
    "jira_field_configuration_scheme_high_required_fields": "jira_field_configuration_scheme_config_changed",
    "jira_field_configuration_scheme_high_hidden_fields": "jira_field_configuration_scheme_config_changed",
    # Issue type scheme rules → jira_issue_type_scheme_config_changed
    "jira_issue_type_scheme_no_default": "jira_issue_type_scheme_config_changed",
    "jira_issue_type_scheme_low_issue_type_count": "jira_issue_type_scheme_config_changed",
    # Project rules → jira_project_config_changed
    "jira_project_key_missing": "jira_project_config_changed",
    "jira_project_public_or_not_private": "jira_project_config_changed",
    "jira_project_archived": "jira_project_config_changed",
    "jira_project_deleted": "jira_project_config_changed",
    "jira_project_unknown_type": "jira_project_config_changed",
    "jira_project_unknown_style": "jira_project_config_changed",
    # Site rules → jira_site_config_changed
    "jira_site_missing_site_url_indicator": "jira_site_config_changed",
    "jira_site_low_project_count": "jira_site_config_changed",
}


# ── Correlation rule definitions ──────────────────────────────────────────────
# One family per Jira configuration surface. Each family lists the base rule
# keys it covers, the specific activity signal type it correlates with, plus the
# generic jira_config_activity fallback signal type.

def _family(
    *,
    rule_keys: set[str],
    specific_signal: str,
    match_key: str,
    severity: str,
    title_phrase: str,
    subject_phrase: str,
    id_key: Optional[str],
) -> dict[str, Any]:
    return {
        "rule_keys": rule_keys,
        "signal_types": {specific_signal, _GENERIC_SIGNAL},
        "specific_signal": specific_signal,
        "match_key": match_key,
        "severity": severity,
        "title_phrase": title_phrase,
        "subject_phrase": subject_phrase,
        "id_key": id_key,
    }


JIRA_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "jira_permission_scheme_risk_with_activity": _family(
        rule_keys={
            "jira_permission_scheme_anonymous_grants",
            "jira_permission_scheme_anyone_grants",
            "jira_permission_scheme_logged_in_grants",
            "jira_permission_scheme_high_grant_count",
            "jira_permission_scheme_public_browse_projects",
            "jira_permission_scheme_public_administer_projects",
            "jira_permission_scheme_public_manage_sprints",
            "jira_permission_scheme_public_create_issues",
            "jira_permission_scheme_public_transition_issues",
            "jira_permission_scheme_unknown_holder",
            "jira_permission_scheme_high_privilege_grants",
            "jira_permission_scheme_high_public_grant_count",
        },
        specific_signal="jira_permission_scheme_config_changed",
        match_key="permission_scheme",
        severity="high",
        title_phrase="Jira permission scheme risk aligned with related Jira configuration activity",
        subject_phrase="Jira permission scheme access posture risk",
        id_key="permission_scheme_id",
    ),
    "jira_webhook_risk_with_activity": _family(
        rule_keys={
            "jira_webhook_non_https",
            "jira_webhook_no_secret_indicator",
            "jira_webhook_no_jql_filter",
            "jira_webhook_broad_event_scope",
            "jira_webhook_comment_event_scope",
            "jira_webhook_attachment_event_scope",
            "jira_webhook_sprint_event_scope",
            "jira_webhook_worklog_event_scope",
            "jira_webhook_empty_or_broad_jql",
            "jira_webhook_all_issue_events",
            "jira_webhook_no_events",
            "jira_webhook_disabled",
        },
        specific_signal="jira_webhook_config_changed",
        match_key="webhook",
        severity="high",
        title_phrase="Jira webhook risk aligned with related Jira configuration activity",
        subject_phrase="Jira webhook transport / authentication posture risk",
        id_key="webhook_id",
    ),
    "jira_workflow_risk_with_activity": _family(
        rule_keys={
            "jira_workflow_draft",
            "jira_workflow_low_transition_count",
            "jira_workflow_no_done_status",
            "jira_workflow_no_in_progress_status",
            "jira_workflow_high_transition_rule_count",
            "jira_workflow_high_validator_count",
            "jira_workflow_high_condition_count",
            "jira_workflow_high_post_function_count",
            "jira_workflow_orphan_statuses",
            "jira_workflow_inactive",
            "jira_workflow_low_status_count",
        },
        specific_signal="jira_workflow_config_changed",
        match_key="workflow",
        severity="low",
        title_phrase="Jira workflow risk aligned with related Jira configuration activity",
        subject_phrase="Jira workflow configuration posture risk",
        id_key="workflow_id",
    ),
    "jira_workflow_scheme_risk_with_activity": _family(
        rule_keys={
            "jira_workflow_scheme_no_projects",
            "jira_workflow_scheme_no_default",
            "jira_workflow_scheme_low_project_count",
            "jira_workflow_scheme_unmapped_issue_types",
            "jira_workflow_scheme_low_workflow_count",
            "jira_workflow_scheme_high_issue_type_mapping_count",
        },
        specific_signal="jira_workflow_scheme_config_changed",
        match_key="workflow_scheme",
        severity="low",
        title_phrase="Jira workflow scheme risk aligned with related Jira configuration activity",
        subject_phrase="Jira workflow scheme mapping posture risk",
        id_key="workflow_scheme_id",
    ),
    "jira_automation_rule_risk_with_activity": _family(
        rule_keys={
            "jira_automation_rule_disabled",
            "jira_automation_rule_workspace_scope",
            "jira_automation_rule_multi_project_scope",
            "jira_automation_rule_unknown_scope",
            "jira_automation_rule_web_request_action",
            "jira_automation_rule_email_action",
            "jira_automation_rule_external_action",
            "jira_automation_rule_comment_action",
            "jira_automation_rule_high_action_count",
            "jira_automation_rule_high_branch_count",
        },
        specific_signal="jira_automation_rule_config_changed",
        match_key="automation_rule",
        severity="medium",
        title_phrase="Jira automation rule risk aligned with related Jira configuration activity",
        subject_phrase="Jira automation rule action / scope posture risk",
        id_key="automation_rule_id",
    ),
    "jira_board_risk_with_activity": _family(
        rule_keys={
            "jira_board_no_projects",
            "jira_board_unknown_type",
            "jira_board_broad_location",
            "jira_board_broad_jql_filter",
            "jira_board_no_filter_indicator",
            "jira_board_high_quick_filter_count",
            "jira_board_unknown_swimlane_strategy",
            "jira_board_no_columns",
        },
        specific_signal="jira_board_config_changed",
        match_key="board",
        severity="low",
        title_phrase="Jira board risk aligned with related Jira configuration activity",
        subject_phrase="Jira board scoping / filter posture risk",
        id_key="board_id",
    ),
    "jira_notification_scheme_risk_with_activity": _family(
        rule_keys={
            "jira_notification_scheme_high_email_recipients",
            "jira_notification_scheme_group_recipients",
            "jira_notification_scheme_project_role_recipients",
            "jira_notification_scheme_no_notifications",
            "jira_notification_scheme_unknown_recipients",
            "jira_notification_scheme_high_event_count",
        },
        specific_signal="jira_notification_scheme_config_changed",
        match_key="notification_scheme",
        severity="low",
        title_phrase="Jira notification scheme risk aligned with related Jira configuration activity",
        subject_phrase="Jira notification scheme recipient posture risk",
        id_key="notification_scheme_id",
    ),
    "jira_screen_scheme_risk_with_activity": _family(
        rule_keys={
            "jira_screen_scheme_high_field_count",
            "jira_screen_scheme_high_screen_field_count",
            "jira_screen_scheme_unmapped_screens",
            "jira_screen_scheme_low_screen_count",
        },
        specific_signal="jira_screen_scheme_config_changed",
        match_key="screen_scheme",
        severity="low",
        title_phrase="Jira screen scheme risk aligned with related Jira configuration activity",
        subject_phrase="Jira screen scheme mapping posture risk",
        id_key="screen_scheme_id",
    ),
    "jira_field_configuration_scheme_risk_with_activity": _family(
        rule_keys={
            "jira_field_configuration_scheme_high_required_fields",
            "jira_field_configuration_scheme_high_hidden_fields",
        },
        specific_signal="jira_field_configuration_scheme_config_changed",
        match_key="field_configuration_scheme",
        severity="low",
        title_phrase="Jira field configuration scheme risk aligned with related Jira configuration activity",
        subject_phrase="Jira field configuration scheme posture risk",
        id_key="field_configuration_scheme_id",
    ),
    "jira_issue_type_scheme_risk_with_activity": _family(
        rule_keys={
            "jira_issue_type_scheme_no_default",
            "jira_issue_type_scheme_low_issue_type_count",
        },
        specific_signal="jira_issue_type_scheme_config_changed",
        match_key="issue_type_scheme",
        severity="low",
        title_phrase="Jira issue type scheme risk aligned with related Jira configuration activity",
        subject_phrase="Jira issue type scheme posture risk",
        id_key="issue_type_scheme_id",
    ),
    "jira_project_risk_with_activity": _family(
        rule_keys={
            "jira_project_key_missing",
            "jira_project_public_or_not_private",
            "jira_project_archived",
            "jira_project_deleted",
            "jira_project_unknown_type",
            "jira_project_unknown_style",
        },
        specific_signal="jira_project_config_changed",
        match_key="project",
        severity="medium",
        title_phrase="Jira project risk aligned with related Jira configuration activity",
        subject_phrase="Jira project visibility / lifecycle posture risk",
        id_key="project_id",
    ),
    "jira_site_risk_with_activity": _family(
        rule_keys={
            "jira_site_missing_site_url_indicator",
            "jira_site_low_project_count",
        },
        specific_signal="jira_site_config_changed",
        match_key="site",
        severity="low",
        title_phrase="Jira site risk aligned with related Jira configuration activity",
        subject_phrase="Jira site configuration posture risk",
        id_key="site_id",
    ),
    # Fallback family — any other jira_ rule key not matched above correlates
    # with the generic jira_config_activity signal type.
    "jira_config_risk_with_activity": _family(
        rule_keys=set(),  # populated dynamically for unknown jira_ rule keys
        specific_signal=_GENERIC_SIGNAL,
        match_key="config",
        severity="low",
        title_phrase="Jira configuration risk aligned with related Jira configuration activity",
        subject_phrase="Jira configuration posture risk",
        id_key=None,
    ),
}

JIRA_CORRELATION_TYPES: frozenset[str] = frozenset(JIRA_CORRELATION_RULES.keys())

# Reverse index: base rule key → correlation family key. Built from the family
# rule_keys sets; unknown jira_ rule keys resolve to the fallback family.
_RULE_KEY_TO_FAMILY: dict[str, str] = {}
for _ct, _rule in JIRA_CORRELATION_RULES.items():
    for _rk in _rule["rule_keys"]:
        _RULE_KEY_TO_FAMILY[_rk] = _ct

_FALLBACK_FAMILY = "jira_config_risk_with_activity"

# All signal types this service consumes.
_ALL_SIGNAL_TYPES: frozenset[str] = frozenset(
    st for rule in JIRA_CORRELATION_RULES.values() for st in rule["signal_types"]
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _fmd(finding: SecurityFinding, key: str) -> Optional[str]:
    """Read a string from finding.evidence (never raises).

    PRIVACY: never returns Jira API tokens, OAuth tokens, webhook secrets, raw
    webhook/delivery URLs, site base URLs, JQL, filter expressions, issue keys,
    issue content, comment bodies, attachment content, user emails, user names,
    account IDs, IP addresses, or PII.
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
    """Read a safe scalar (bool/int/float/str) from signal_metadata (never raises)."""
    md = signal.signal_metadata if isinstance(signal.signal_metadata, dict) else {}
    v = md.get(key)
    if isinstance(v, (bool, int, float, str)):
        return v
    return None


def _base_rule_key(finding_key: str) -> str:
    """Strip any ':resource_id' suffix to get the base rule key."""
    return finding_key.split(":", 1)[0] if finding_key else ""


def _family_for_rule_key(rule_key: str) -> str:
    """Resolve a base rule key to its correlation family key.

    Known rule keys map to their specialized family. Any other jira_ rule key
    resolves to the generic fallback family. Unknown / non-jira rule keys also
    resolve to the fallback family (handled safely by signal-type filtering).
    """
    fam = _RULE_KEY_TO_FAMILY.get(rule_key)
    if fam is not None:
        return fam
    return _FALLBACK_FAMILY


def _signal_type_for_rule_key(rule_key: str) -> str:
    """Resolve a base rule key to its expected activity signal type."""
    return JIRA_RULE_KEY_TO_SIGNAL_TYPE.get(rule_key, _GENERIC_SIGNAL)


def _resource_id_from_finding(finding: SecurityFinding) -> Optional[str]:
    """Extract the safe resource identifier from a finding.

    Uses finding.resource_id first, then falls back to evidence record_id.
    NEVER uses user emails, API tokens, OAuth tokens, webhook secrets, JQL,
    URLs, issue keys, or PII.
    """
    return finding.resource_id or _fmd(finding, "record_id")


def _resource_id_from_signal(signal: SecurityIncidentSignal) -> Optional[str]:
    """Extract the safe resource identifier from a signal's metadata."""
    return _smd(signal, "resource_id")


def _record_type_from_signal(signal: SecurityIncidentSignal) -> Optional[str]:
    """Extract the safe record_type label from a signal's metadata."""
    return _smd(signal, "record_type") or _smd(signal, "resource_type")


def _match_pair(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
) -> Optional[str]:
    """Attempt to match a finding to a signal.

    Primary join: exact safe opaque resource_id on both sides. If either side
    lacks a resource_id (or they differ), fall back to record_type → signal_type
    family matching: a finding whose family's specific signal equals the
    signal's type (or the generic fallback) matches on record type.

    Returns a match_reason string or None if no match.

    PRIVACY: never matches on user emails, user IDs, display names, member
    identities, webhook secrets, delivery URLs, JQL, issue keys, issue content,
    comment bodies, attachment content, or any credential/PII.
    """
    f_rid = _resource_id_from_finding(finding)
    s_rid = _resource_id_from_signal(signal)
    if f_rid and s_rid and f_rid == s_rid:
        return "resource_id_match"

    # Fallback: record_type → signal_type family matching.
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
    """Return confidence level for the match."""
    if match_reason == "record_type_match":
        # Family-level co-occurrence (no exact resource match) — low confidence.
        return "low"
    if match_reason != "resource_id_match":
        return "low"
    if "config_activity" in signal_type:
        # Generic signal — medium confidence.
        return "medium"
    # Specific signal type matched on the same resource.
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
        "jira.correlation",
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
    category labels. NEVER Jira API tokens, OAuth tokens, webhook secrets,
    integration secrets, raw webhook/delivery URLs, site base URLs, redirect
    URLs, JQL, filter expressions, board column / quick-filter / swimlane names,
    issue keys, issue titles, issue descriptions, comment bodies, attachment
    content, customer names, user emails, user names, account IDs, member
    identities, IP addresses, user agents, request/response payloads, raw audit
    payloads, or customer PII.
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
    confidence = match_strength  # "high" | "medium" | "low"

    title = f"{rule['title_phrase']} ({match_reason})"[:240]
    summary = (
        f"{rule['subject_phrase']} correlated with {signal.signal_type} "
        f"evidence ({match_reason}). {_REVIEW_NOTE}"
    )

    rule_key = _base_rule_key(finding.finding_key)

    # Safe resource identifiers from both sides.
    resource_id = _resource_id_from_finding(finding) or _resource_id_from_signal(signal)
    resource_type = _fmd(finding, "resource_type") or _smd(signal, "resource_type")
    record_type = _fmd(finding, "record_type") or _record_type_from_signal(signal)

    md_raw: dict[str, Any] = {
        "provider": PROVIDER,
        "correlation_type": correlation_type,
        "source": "jira_activity_event",
        "event_source": _smd(signal, "event_source") or "jira_activity_event",
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
        "operation_family": _smd(signal, "operation_family") or "jira_configuration",
        "operation_action": _smd(signal, "operation_action") or "configuration_updated",
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
        "correlation_reason": f"jira_{rule['match_key']}_risk_activity",
        "correlation_strength": match_strength,
        "lookback_hours": int(lookback_hours),
        "window_start": window_start.isoformat() if window_start else None,
        "window_end": window_end.isoformat() if window_end else None,
    }

    # Carry the record-type-specific opaque resource id key, when known.
    id_key = rule.get("id_key")
    if id_key is not None:
        md_raw[id_key] = (
            _smd(signal, id_key)
            or _fmd(finding, id_key)
            or resource_id
        )

    # Carry forward safe count/boolean/category fields from the signal that are
    # gated by ALLOWED_METADATA_KEYS — the sanitizer is the hard second gate.
    for field in _SAFE_SIGNAL_FIELDS.get(rule["specific_signal"], ()):
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


# Safe count/boolean/category fields per specific signal type that may be carried
# from the signal metadata onto the correlation. Every key here is also present
# in corr_svc.ALLOWED_METADATA_KEYS — the sanitizer is a second, hard gate.
_SAFE_SIGNAL_FIELDS: dict[str, tuple[str, ...]] = {
    "jira_site_config_changed": (
        "deployment_type",
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
    _GENERIC_SIGNAL: (),
}


def _in_window(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
) -> bool:
    """True if the signal's time range overlaps with the finding's review window."""
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


def generate_jira_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_correlations: int = 100,
) -> dict[str, Any]:
    """Generate Jira Risk × Activity correlations for a workspace.

    Joins active Jira configuration-risk findings with Jira activity signals on
    the same safe opaque resource_id within a review window, falling back to
    record_type → signal_type family matching when no exact resource match is
    available.

    Covers thirteen correlation families: permission_scheme, webhook, workflow,
    workflow_scheme, automation_rule, board, notification_scheme, screen_scheme,
    field_configuration_scheme, issue_type_scheme, project, site, and a generic
    config fallback. Each family also correlates against generic
    jira_config_activity signals when a resource-specific signal is unavailable.

    Jira API tokens, OAuth tokens, webhook secrets, integration secrets, raw
    webhook/delivery URLs, site base URLs, redirect URLs, JQL, filter
    expressions, board column / quick-filter / swimlane names, issue keys, issue
    titles, issue descriptions, comment bodies, attachment content, customer
    names, user emails, user names, account IDs, member identities, IP
    addresses, user agents, request/response payloads, raw audit payloads, and
    PII are never used or stored.
    Does not confirm compromise, unauthorized access, or data exposure.
    Idempotent — re-running creates no duplicates. Never raises.

    Args:
        workspace_id:      Workspace UUID for data scoping.
        db:                Database session.
        lookback_hours:    Lookback window for signal recency (1–168 hours).
        max_correlations:  Maximum correlations to create (1–1000).

    Returns:
        Summary dict with provider/findings_scanned/signals_scanned/
        events_scanned/correlations_created/correlations_skipped/groups_scanned/
        lookback_hours/max_correlations fields.
    """
    hours = max(1, min(int(lookback_hours or 24), 168))
    cap = max(1, min(int(max_correlations or 100), 1000))
    cutoff = _utcnow() - timedelta(hours=hours)

    # ── Load active Jira findings ─────────────────────────────────────────────
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

    # ── Load recent Jira activity signals ─────────────────────────────────────
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

    # Group findings by their resolved correlation family.
    findings_by_family: dict[str, list[SecurityFinding]] = {}
    for f in findings:
        rk = _base_rule_key(f.finding_key)
        fam = _family_for_rule_key(rk)
        findings_by_family.setdefault(fam, []).append(f)

    signals_by_type: dict[str, list[SecurityIncidentSignal]] = {}
    for s in signals:
        signals_by_type.setdefault(s.signal_type, []).append(s)

    created = skipped = candidate_pairs = 0

    for correlation_type, rule in JIRA_CORRELATION_RULES.items():
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
                        "jira_correlations: failed to upsert one pair; continuing"
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
