"""Linear configuration-risk security rules — M85B.

Every rule fires only on explicit, reliable normalized fields produced by
the Linear connector (app/connectors/linear.py + linear_schema.py, M85A).
Evidence is metadata-only: booleans, counts, categories, opaque identifiers,
and safe string labels.

NEVER read, stored, or surfaced:
  Linear API keys, OAuth tokens, webhook secrets, webhook URLs, issue titles,
  issue descriptions, comment bodies, attachment content, user emails, user
  names, member identities, team member identities, raw URLs, IP addresses,
  user agents, request/response payloads, customer data, or PII of any kind.

CLAIM DISCIPLINE
----------------
These are configuration posture findings that may require review.  A finding
is evidence for review only.  It never asserts that a credential was leaked,
that unauthorized access occurred, or that any data was exposed.  Severity
reflects review priority, not confirmed impact.

Record types evaluated (M85A)
------------------------------
  linear_workspace       — workspace/organization configuration
  linear_team            — team visibility, membership, project, and cycle
  linear_project         — project status, health, membership, and ownership
  linear_workflow_state  — individual workflow state type classification
  linear_label           — issue label team scope
  linear_webhook         — webhook subscription transport and secret posture
  linear_view            — custom view sharing
  linear_cycle           — active sprint/cycle issue volume
  linear_integration     — external service integration status

Rules skipped (not cleanly mappable to available M85A fields)
-------------------------------------------------------------
  linear_workspace_low_team_count — team count is not in the workspace record
  linear_workflow_no_default_state
  linear_workflow_no_terminal_state
  linear_workflow_no_backlog_state
  linear_workflow_no_started_state
  linear_workflow_no_completed_state
  linear_workflow_no_canceled_state
    — all six require cross-record aggregation by team_id; the flat per-record
      evaluator cannot aggregate across records in a single pass
  linear_label_group_without_parent
    — in Linear's label hierarchy, group labels (is_group_label=True) are by
      definition top-level parents; the condition would fire for every group
      label regardless of any misconfiguration
  linear_cycle_inactive
    — the connector queries only active cycles (isActive: { eq: true }), so
      active=False can never appear on a fetched record
  linear_view_high_filter_count
    — filter_count_category="many" (>=10 filters) is not a reliable security
      risk signal; filter complexity is a productivity preference
"""

from __future__ import annotations

from typing import Any

from app.connectors.linear_schema import (
    LINEAR_CYCLE,
    LINEAR_INTEGRATION,
    LINEAR_LABEL,
    LINEAR_PROJECT,
    LINEAR_TEAM,
    LINEAR_VIEW,
    LINEAR_WEBHOOK,
    LINEAR_WORKFLOW_STATE,
    LINEAR_WORKSPACE,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule key constants ─────────────────────────────────────────────────────────

# Workspace rules
_RULE_WORKSPACE_MISSING_URL_KEY = "linear_workspace_missing_url_key"
_RULE_WORKSPACE_MISSING_LOGO = "linear_workspace_missing_logo"

# Team rules
_RULE_TEAM_PRIVATE = "linear_team_private"
_RULE_TEAM_LOW_MEMBER_COUNT = "linear_team_low_member_count"
_RULE_TEAM_NO_PROJECTS = "linear_team_no_projects"
_RULE_TEAM_AUTO_ARCHIVE_DISABLED = "linear_team_auto_archive_disabled"
_RULE_TEAM_CYCLES_DISABLED = "linear_team_cycles_disabled"
_RULE_TEAM_LONG_CYCLE_DURATION = "linear_team_long_cycle_duration"

# Project rules
_RULE_PROJECT_NO_LEAD = "linear_project_no_lead"
_RULE_PROJECT_NO_MEMBERS = "linear_project_no_members"
_RULE_PROJECT_HIGH_ISSUE_COUNT = "linear_project_high_issue_count"
_RULE_PROJECT_UNHEALTHY = "linear_project_unhealthy"
_RULE_PROJECT_UNKNOWN_STATUS = "linear_project_unknown_status"

# Workflow state rules
_RULE_WORKFLOW_STATE_UNKNOWN_TYPE = "linear_workflow_state_unknown_type"

# Label rules
_RULE_LABEL_MISSING_TEAM_SCOPE = "linear_label_missing_team_scope"

# Webhook rules
_RULE_WEBHOOK_DISABLED = "linear_webhook_disabled"
_RULE_WEBHOOK_NO_SECRET_INDICATOR = "linear_webhook_no_secret_indicator"
_RULE_WEBHOOK_NON_HTTPS = "linear_webhook_non_https"
_RULE_WEBHOOK_NO_EVENTS = "linear_webhook_no_events"
_RULE_WEBHOOK_BROAD_RESOURCE_SCOPE = "linear_webhook_broad_resource_scope"

# View rules
_RULE_VIEW_SHARED = "linear_view_shared"

# Cycle rules
_RULE_CYCLE_HIGH_ISSUE_COUNT = "linear_cycle_high_issue_count"

# Integration rules
_RULE_INTEGRATION_DISABLED = "linear_integration_disabled"
_RULE_INTEGRATION_UNKNOWN_TYPE = "linear_integration_unknown_type"

# ── Thresholds ─────────────────────────────────────────────────────────────────

# Webhooks subscribing to this many or more resource types are flagged as
# broad scope (harder to audit event delivery intent).
_BROAD_RESOURCE_TYPES_THRESHOLD = 5

# ── All Linear rule keys implemented in this module ───────────────────────────

LINEAR_RULE_KEYS: frozenset[str] = frozenset({
    # Workspace
    _RULE_WORKSPACE_MISSING_URL_KEY,
    _RULE_WORKSPACE_MISSING_LOGO,
    # Team
    _RULE_TEAM_PRIVATE,
    _RULE_TEAM_LOW_MEMBER_COUNT,
    _RULE_TEAM_NO_PROJECTS,
    _RULE_TEAM_AUTO_ARCHIVE_DISABLED,
    _RULE_TEAM_CYCLES_DISABLED,
    _RULE_TEAM_LONG_CYCLE_DURATION,
    # Project
    _RULE_PROJECT_NO_LEAD,
    _RULE_PROJECT_NO_MEMBERS,
    _RULE_PROJECT_HIGH_ISSUE_COUNT,
    _RULE_PROJECT_UNHEALTHY,
    _RULE_PROJECT_UNKNOWN_STATUS,
    # Workflow state
    _RULE_WORKFLOW_STATE_UNKNOWN_TYPE,
    # Label
    _RULE_LABEL_MISSING_TEAM_SCOPE,
    # Webhook
    _RULE_WEBHOOK_DISABLED,
    _RULE_WEBHOOK_NO_SECRET_INDICATOR,
    _RULE_WEBHOOK_NON_HTTPS,
    _RULE_WEBHOOK_NO_EVENTS,
    _RULE_WEBHOOK_BROAD_RESOURCE_SCOPE,
    # View
    _RULE_VIEW_SHARED,
    # Cycle
    _RULE_CYCLE_HIGH_ISSUE_COUNT,
    # Integration
    _RULE_INTEGRATION_DISABLED,
    _RULE_INTEGRATION_UNKNOWN_TYPE,
})

# ── Helpers ────────────────────────────────────────────────────────────────────


def _bool(record: dict[str, Any], key: str) -> bool | None:
    """Return the boolean field value, or None if absent/wrong type."""
    val = record.get(key)
    return val if isinstance(val, bool) else None


def _int(record: dict[str, Any], key: str, default: int = 0) -> int:
    val = record.get(key, default)
    if isinstance(val, int) and not isinstance(val, bool):
        return max(0, val)
    return default


# ── Workspace evaluator ───────────────────────────────────────────────────────


def _eval_workspace(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one linear_workspace record.

    SECURITY: API keys, OAuth tokens, and workspace identifiers that could
    expose customer names or PII are NEVER stored in evidence.
    """
    record_id = get_str(record, "record_id") or "linear_workspace_unknown"
    findings: list[FindingCandidate] = []

    url_key_present = _bool(record, "url_key_present")
    logo_present = _bool(record, "logo_present")

    # ── linear_workspace_missing_url_key ──────────────────────────────────────
    if url_key_present is False:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_WORKSPACE_MISSING_URL_KEY,
            finding_key=make_finding_key(_RULE_WORKSPACE_MISSING_URL_KEY, record_id),
            severity="low",
            title="Linear workspace has no URL key configured",
            description=(
                "A Linear workspace does not have a URL key configured. The URL key "
                "is used to identify the workspace in URLs and browser navigation. "
                "An absent URL key may indicate an incomplete workspace setup. "
                "This workspace configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_WORKSPACE_MISSING_URL_KEY,
                "record_id": record_id,
                "url_key_present": False,
            },
            remediation={
                "summary": "Configure a URL key for this Linear workspace.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → Workspace.",
                    "Set a URL key for the workspace.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_workspace_missing_logo ─────────────────────────────────────────
    if logo_present is False:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_WORKSPACE_MISSING_LOGO,
            finding_key=make_finding_key(_RULE_WORKSPACE_MISSING_LOGO, record_id),
            severity="low",
            title="Linear workspace has no logo configured",
            description=(
                "A Linear workspace does not have a logo set. A workspace without a "
                "logo may be harder to identify visually and may indicate an incomplete "
                "workspace setup. This workspace configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_WORKSPACE_MISSING_LOGO,
                "record_id": record_id,
                "logo_present": False,
            },
            remediation={
                "summary": "Upload a logo for this Linear workspace.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → Workspace.",
                    "Upload a workspace logo.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Team evaluator ────────────────────────────────────────────────────────────


def _eval_team(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one linear_team record.

    SECURITY: team member identities, emails, and names are NEVER stored.
    Evidence uses only booleans, counts, categories, and the opaque record_id.
    """
    record_id = get_str(record, "record_id") or "linear_team_unknown"
    findings: list[FindingCandidate] = []

    private_team = _bool(record, "private_team")
    member_count_cat = get_str(record, "member_count_category")
    project_count = _int(record, "project_count")
    auto_archive_enabled = _bool(record, "auto_archive_enabled")
    cycle_enabled = _bool(record, "cycle_enabled")
    cycle_duration_cat = get_str(record, "cycle_duration_category")

    # ── linear_team_private ────────────────────────────────────────────────────
    if private_team is True:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_TEAM_PRIVATE,
            finding_key=make_finding_key(_RULE_TEAM_PRIVATE, record_id),
            severity="low",
            title="Linear team has private visibility",
            description=(
                "A Linear team is configured with private visibility. Private teams "
                "restrict access to team members only, which may limit cross-team "
                "collaboration and visibility into project status. This team "
                "configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_TEAM_PRIVATE,
                "record_id": record_id,
                "team_visibility_category": "private",
            },
            remediation={
                "summary": "Review whether private team visibility is appropriate.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → Teams.",
                    "Open the team settings and review the visibility configuration.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_team_low_member_count ──────────────────────────────────────────
    if member_count_cat == "none":
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_TEAM_LOW_MEMBER_COUNT,
            finding_key=make_finding_key(_RULE_TEAM_LOW_MEMBER_COUNT, record_id),
            severity="low",
            title="Linear team has no members",
            description=(
                "A Linear team has no members assigned. A team with no members "
                "cannot be assigned work, will not receive notifications, and "
                "may indicate an orphaned or misconfigured team. This team "
                "configuration evidence may require review. Member identities "
                "are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_TEAM_LOW_MEMBER_COUNT,
                "record_id": record_id,
                "member_count_category": "none",
            },
            remediation={
                "summary": "Add members to this team or remove the team if unused.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → Teams.",
                    "Open the team and add members, or delete the team if no longer needed.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_team_no_projects ────────────────────────────────────────────────
    if project_count == 0:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_TEAM_NO_PROJECTS,
            finding_key=make_finding_key(_RULE_TEAM_NO_PROJECTS, record_id),
            severity="low",
            title="Linear team has no projects",
            description=(
                "A Linear team has no projects associated with it. Teams with no "
                "projects may indicate an unused or incomplete team setup. This "
                "team configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_TEAM_NO_PROJECTS,
                "record_id": record_id,
                "project_count": 0,
            },
            remediation={
                "summary": "Associate projects with this team or review if the team is still needed.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to the team's page.",
                    "Create or assign a project to this team.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_team_auto_archive_disabled ─────────────────────────────────────
    if auto_archive_enabled is False:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_TEAM_AUTO_ARCHIVE_DISABLED,
            finding_key=make_finding_key(_RULE_TEAM_AUTO_ARCHIVE_DISABLED, record_id),
            severity="medium",
            title="Linear team has auto-archive disabled",
            description=(
                "A Linear team does not have an auto-archive period configured. "
                "Without auto-archive, completed issues accumulate indefinitely, "
                "which can make it harder to identify actively relevant work and "
                "audit recent project activity. This team configuration evidence "
                "may require review."
            ),
            evidence={
                "rule": _RULE_TEAM_AUTO_ARCHIVE_DISABLED,
                "record_id": record_id,
                "auto_archive_enabled": False,
            },
            remediation={
                "summary": "Enable an auto-archive period for this team.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → Teams.",
                    "Open the team settings and configure an auto-archive period.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_team_cycles_disabled ───────────────────────────────────────────
    if cycle_enabled is False:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_TEAM_CYCLES_DISABLED,
            finding_key=make_finding_key(_RULE_TEAM_CYCLES_DISABLED, record_id),
            severity="medium",
            title="Linear team has cycles (sprints) disabled",
            description=(
                "A Linear team has cycles (sprint planning) disabled. Without "
                "cycles, the team cannot scope and track work in time-bounded "
                "iterations, which may reduce visibility into delivery cadence "
                "and sprint-level scope changes. This team workflow configuration "
                "evidence may require review."
            ),
            evidence={
                "rule": _RULE_TEAM_CYCLES_DISABLED,
                "record_id": record_id,
                "cycle_enabled": False,
            },
            remediation={
                "summary": "Enable cycles for this team if sprint-based planning is intended.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → Teams.",
                    "Open the team settings and enable Cycles.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_team_long_cycle_duration ───────────────────────────────────────
    if cycle_duration_cat == "long":
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_TEAM_LONG_CYCLE_DURATION,
            finding_key=make_finding_key(_RULE_TEAM_LONG_CYCLE_DURATION, record_id),
            severity="low",
            title="Linear team has a long cycle duration",
            description=(
                "A Linear team has a cycle duration longer than two weeks. "
                "Long sprint cycles reduce the frequency of review checkpoints "
                "and may make it harder to audit scope changes or catch drift in "
                "project direction. This workflow configuration evidence may "
                "require review."
            ),
            evidence={
                "rule": _RULE_TEAM_LONG_CYCLE_DURATION,
                "record_id": record_id,
                "cycle_duration_category": "long",
            },
            remediation={
                "summary": "Review whether the cycle duration is appropriate for this team.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → Teams.",
                    "Open the team settings and adjust the cycle duration.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Project evaluator ─────────────────────────────────────────────────────────


def _eval_project(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one linear_project record.

    SECURITY: project names, issue titles, issue descriptions, comments,
    and member identities are NEVER stored. Evidence uses only booleans,
    categories, and the opaque record_id.
    """
    record_id = get_str(record, "record_id") or "linear_project_unknown"
    findings: list[FindingCandidate] = []

    status_cat = get_str(record, "project_status_category")
    health_cat = get_str(record, "project_health_category")
    lead_present = _bool(record, "lead_present")
    member_count_cat = get_str(record, "member_count_category")
    issue_count_cat = get_str(record, "issue_count_category")

    # ── linear_project_no_lead ────────────────────────────────────────────────
    if lead_present is False:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_PROJECT_NO_LEAD,
            finding_key=make_finding_key(_RULE_PROJECT_NO_LEAD, record_id),
            severity="medium",
            title="Linear project has no lead assigned",
            description=(
                "A Linear project does not have a lead assigned. Projects without "
                "a designated lead may lack clear ownership and accountability for "
                "delivery progress and security posture reviews. This project "
                "configuration evidence may require review. Lead identities are "
                "never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_PROJECT_NO_LEAD,
                "record_id": record_id,
                "lead_present": False,
            },
            remediation={
                "summary": "Assign a lead to this project.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Open the project.",
                    "Assign a lead in the project settings.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_project_no_members ─────────────────────────────────────────────
    if member_count_cat == "none":
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_PROJECT_NO_MEMBERS,
            finding_key=make_finding_key(_RULE_PROJECT_NO_MEMBERS, record_id),
            severity="low",
            title="Linear project has no members",
            description=(
                "A Linear project has no members assigned. A project with no "
                "members may be an orphaned or unused project. This project "
                "configuration evidence may require review. Member identities "
                "are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_PROJECT_NO_MEMBERS,
                "record_id": record_id,
                "member_count_category": "none",
            },
            remediation={
                "summary": "Add members to this project or archive it if no longer needed.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Open the project.",
                    "Add members in the project settings or archive the project.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_project_high_issue_count ───────────────────────────────────────
    if issue_count_cat == "many":
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_PROJECT_HIGH_ISSUE_COUNT,
            finding_key=make_finding_key(_RULE_PROJECT_HIGH_ISSUE_COUNT, record_id),
            severity="low",
            title="Linear project has a high open issue count",
            description=(
                "A Linear project has a high number of open issues (more than 50). "
                "A large open-issue backlog may indicate accumulated technical debt "
                "or unreviewed work. This project configuration evidence may require "
                "review. Issue titles and descriptions are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_PROJECT_HIGH_ISSUE_COUNT,
                "record_id": record_id,
                "issue_count_category": "many",
            },
            remediation={
                "summary": "Review and triage the open issues in this project.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Open the project and review all open issues.",
                    "Close, reassign, or archive issues that are no longer relevant.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_project_unhealthy ───────────────────────────────────────────────
    if health_cat in ("atrisk", "offtrack"):
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_PROJECT_UNHEALTHY,
            finding_key=make_finding_key(_RULE_PROJECT_UNHEALTHY, record_id),
            severity="medium",
            title="Linear project has an unhealthy status",
            description=(
                "A Linear project has a health status indicating it is at risk or "
                "off track. Projects in an unhealthy state may require closer review "
                "of scope, ownership, and delivery timelines. This project "
                "configuration evidence may require review. Issue content is never "
                "stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_PROJECT_UNHEALTHY,
                "record_id": record_id,
                "project_health_category": health_cat,
            },
            remediation={
                "summary": "Review the project health and update the status if appropriate.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Open the project and review open issues and milestones.",
                    "Update the project health status and address blocking issues.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_project_unknown_status ─────────────────────────────────────────
    if status_cat == "unknown":
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_PROJECT_UNKNOWN_STATUS,
            finding_key=make_finding_key(_RULE_PROJECT_UNKNOWN_STATUS, record_id),
            severity="low",
            title="Linear project has an unknown status",
            description=(
                "A Linear project has a status that could not be classified as a "
                "standard lifecycle state. An unknown project status may indicate "
                "a misconfigured or custom workflow state. This project "
                "configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_PROJECT_UNKNOWN_STATUS,
                "record_id": record_id,
                "project_status_category": "unknown",
            },
            remediation={
                "summary": "Review and update the project status.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Open the project and review its current status.",
                    "Set an appropriate lifecycle status.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Workflow state evaluator ──────────────────────────────────────────────────


def _eval_workflow_state(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one linear_workflow_state record.

    SECURITY: state names, descriptions, and team identities are NEVER stored.
    Evidence uses only the state_type_category and the opaque record_id.
    """
    record_id = get_str(record, "record_id") or "linear_workflow_state_unknown"
    findings: list[FindingCandidate] = []

    state_type_cat = get_str(record, "state_type_category")

    # ── linear_workflow_state_unknown_type ────────────────────────────────────
    if state_type_cat == "unknown":
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_WORKFLOW_STATE_UNKNOWN_TYPE,
            finding_key=make_finding_key(_RULE_WORKFLOW_STATE_UNKNOWN_TYPE, record_id),
            severity="low",
            title="Linear workflow state has an unrecognized type",
            description=(
                "A Linear workflow state has a type that is not recognized as one of "
                "the standard state types (backlog, unstarted, started, completed, "
                "cancelled). An unrecognized state type may indicate a custom or "
                "misconfigured workflow configuration. This workflow configuration "
                "evidence may require review."
            ),
            evidence={
                "rule": _RULE_WORKFLOW_STATE_UNKNOWN_TYPE,
                "record_id": record_id,
                "state_type_category": "unknown",
            },
            remediation={
                "summary": "Review the workflow state type configuration.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → Workflows.",
                    "Open the workflow and review this state's type.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Label evaluator ───────────────────────────────────────────────────────────


def _eval_label(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one linear_label record.

    SECURITY: label names, parent label values, and team member identities
    are NEVER stored. Evidence uses only the team_id presence boolean and the
    opaque record_id.
    """
    record_id = get_str(record, "record_id") or "linear_label_unknown"
    findings: list[FindingCandidate] = []

    team_id = record.get("team_id")
    team_id_present = team_id is not None and team_id != ""

    # ── linear_label_missing_team_scope ───────────────────────────────────────
    if not team_id_present:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_LABEL_MISSING_TEAM_SCOPE,
            finding_key=make_finding_key(_RULE_LABEL_MISSING_TEAM_SCOPE, record_id),
            severity="low",
            title="Linear label has no team scope",
            description=(
                "A Linear issue label is not scoped to any specific team, making "
                "it a workspace-wide label. Workspace-wide labels are visible and "
                "usable across all teams, which may lead to labeling inconsistency "
                "and make it harder to audit label usage by team. This label "
                "configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_LABEL_MISSING_TEAM_SCOPE,
                "record_id": record_id,
                "team_id_present": False,
            },
            remediation={
                "summary": "Review whether this label should be scoped to a specific team.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → Labels.",
                    "Review the label scope and assign it to a specific team if appropriate.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Webhook evaluator ─────────────────────────────────────────────────────────


def _eval_webhook(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one linear_webhook record.

    SECURITY: webhook URL values, webhook secret values, and authentication
    credentials are NEVER stored. Evidence uses only booleans, counts, and
    the url_scheme_category derived before the URL was discarded.
    """
    record_id = get_str(record, "record_id") or "linear_webhook_unknown"
    findings: list[FindingCandidate] = []

    webhook_enabled = _bool(record, "webhook_enabled")
    secret_present = _bool(record, "webhook_secret_present")
    url_scheme_cat = get_str(record, "webhook_url_scheme_category")
    resource_types_count = _int(record, "webhook_resource_types_count")

    # ── linear_webhook_disabled ───────────────────────────────────────────────
    if webhook_enabled is False:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_WEBHOOK_DISABLED,
            finding_key=make_finding_key(_RULE_WEBHOOK_DISABLED, record_id),
            severity="medium",
            title="Linear webhook subscription is disabled",
            description=(
                "A Linear webhook subscription is currently disabled. A disabled "
                "webhook will not deliver events to the configured endpoint. This "
                "may indicate a previously failed delivery or an intentionally "
                "paused webhook. This webhook configuration evidence may require "
                "review. Webhook URLs are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_DISABLED,
                "record_id": record_id,
                "webhook_enabled": False,
            },
            remediation={
                "summary": "Review and re-enable this webhook subscription if still needed.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → API → Webhooks.",
                    "Review the webhook and re-enable it, or remove it if no longer needed.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_webhook_no_secret_indicator ───────────────────────────────────
    if secret_present is False:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_WEBHOOK_NO_SECRET_INDICATOR,
            finding_key=make_finding_key(_RULE_WEBHOOK_NO_SECRET_INDICATOR, record_id),
            severity="high",
            title="Linear webhook subscription has no signing secret",
            description=(
                "A Linear webhook subscription does not have a signing secret "
                "configured. Without a signing secret, the endpoint receiving "
                "this webhook cannot verify that events originate from Linear. "
                "This webhook configuration evidence may require review. "
                "Webhook secret values are never stored by ConfigTrace — only the "
                "presence or absence of a secret is recorded."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_NO_SECRET_INDICATOR,
                "record_id": record_id,
                "webhook_secret_present": False,
            },
            remediation={
                "summary": "Configure a signing secret for this webhook subscription.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → API → Webhooks.",
                    "Open this webhook and add a signing secret.",
                    "Update the receiving endpoint to validate the Linear-Signature header.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_webhook_non_https ──────────────────────────────────────────────
    if url_scheme_cat == "non_https":
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_WEBHOOK_NON_HTTPS,
            finding_key=make_finding_key(_RULE_WEBHOOK_NON_HTTPS, record_id),
            severity="high",
            title="Linear webhook subscription uses a non-HTTPS endpoint",
            description=(
                "A Linear webhook subscription is configured with an endpoint URL "
                "that does not use HTTPS. Webhook payloads delivered over plain "
                "HTTP may be transmitted without transport-layer encryption. "
                "This webhook configuration evidence may require review. "
                "The webhook URL value is never stored by ConfigTrace — only the "
                "URL scheme category is recorded."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_NON_HTTPS,
                "record_id": record_id,
                "webhook_url_scheme_category": "non_https",
            },
            remediation={
                "summary": "Update the webhook endpoint URL to use HTTPS.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → API → Webhooks.",
                    "Open this webhook and update the URL to start with https://.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_webhook_no_events ──────────────────────────────────────────────
    if resource_types_count == 0:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_WEBHOOK_NO_EVENTS,
            finding_key=make_finding_key(_RULE_WEBHOOK_NO_EVENTS, record_id),
            severity="medium",
            title="Linear webhook subscription has no resource types configured",
            description=(
                "A Linear webhook subscription has no resource types subscribed. "
                "Without subscribed resource types, the webhook endpoint will not "
                "receive any event notifications from Linear, making the "
                "subscription non-functional. This webhook configuration evidence "
                "may require review."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_NO_EVENTS,
                "record_id": record_id,
                "webhook_resource_types_count": 0,
            },
            remediation={
                "summary": "Add resource type subscriptions to this webhook.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → API → Webhooks.",
                    "Open this webhook and add the relevant resource types.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_webhook_broad_resource_scope ───────────────────────────────────
    if resource_types_count >= _BROAD_RESOURCE_TYPES_THRESHOLD:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_WEBHOOK_BROAD_RESOURCE_SCOPE,
            finding_key=make_finding_key(_RULE_WEBHOOK_BROAD_RESOURCE_SCOPE, record_id),
            severity="medium",
            title="Linear webhook subscription has a broad resource scope",
            description=(
                "A Linear webhook subscription subscribes to "
                f"{_BROAD_RESOURCE_TYPES_THRESHOLD} or more resource types. "
                "Broad subscriptions increase the volume of events delivered to "
                "the endpoint and may exceed the intended scope of the integration. "
                "This webhook configuration evidence may require review. "
                "Resource type names are not stored — only the count."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_BROAD_RESOURCE_SCOPE,
                "record_id": record_id,
                "webhook_resource_types_count": resource_types_count,
            },
            remediation={
                "summary": "Narrow the resource type subscription to only what the endpoint requires.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → API → Webhooks.",
                    "Open this webhook and reduce the subscribed resource types.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── View evaluator ────────────────────────────────────────────────────────────


def _eval_view(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one linear_view record.

    SECURITY: view filter values, raw filter expressions, team member
    identities, and view names are NEVER stored in evidence.
    """
    record_id = get_str(record, "record_id") or "linear_view_unknown"
    findings: list[FindingCandidate] = []

    view_shared = _bool(record, "view_shared")

    # ── linear_view_shared ────────────────────────────────────────────────────
    if view_shared is True:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_VIEW_SHARED,
            finding_key=make_finding_key(_RULE_VIEW_SHARED, record_id),
            severity="low",
            title="Linear custom view is shared with the workspace",
            description=(
                "A Linear custom view is shared with the entire workspace. "
                "Shared views are visible to all workspace members and may "
                "expose filtered issue queries or project scopes that were "
                "intended for private use. This view configuration evidence "
                "may require review."
            ),
            evidence={
                "rule": _RULE_VIEW_SHARED,
                "record_id": record_id,
                "view_shared": True,
            },
            remediation={
                "summary": "Review whether this view should be shared or made private.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Open the custom view.",
                    "Update the sharing settings to restrict visibility if appropriate.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Cycle evaluator ───────────────────────────────────────────────────────────


def _eval_cycle(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one linear_cycle record.

    SECURITY: cycle names, issue titles, and member identities are NEVER
    stored. Evidence uses only the issue_count_category and opaque record_id.
    """
    record_id = get_str(record, "record_id") or "linear_cycle_unknown"
    findings: list[FindingCandidate] = []

    issue_count_cat = get_str(record, "issue_count_category")

    # ── linear_cycle_high_issue_count ─────────────────────────────────────────
    if issue_count_cat == "many":
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_CYCLE_HIGH_ISSUE_COUNT,
            finding_key=make_finding_key(_RULE_CYCLE_HIGH_ISSUE_COUNT, record_id),
            severity="low",
            title="Linear cycle has a high number of issues",
            description=(
                "An active Linear cycle has a high number of issues (more than 50). "
                "A cycle with many issues may indicate overloaded sprint scope, "
                "which can reduce delivery predictability and make it harder to "
                "audit what was committed in the cycle. This cycle configuration "
                "evidence may require review. Issue titles and descriptions are "
                "never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_CYCLE_HIGH_ISSUE_COUNT,
                "record_id": record_id,
                "issue_count_category": "many",
            },
            remediation={
                "summary": "Review the cycle scope and reduce the number of active issues.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Open the active cycle.",
                    "Review the issues and move lower-priority items out of the cycle.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Integration evaluator ─────────────────────────────────────────────────────


def _eval_integration(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one linear_integration record.

    SECURITY: integration tokens, OAuth credentials, service-specific
    API keys, and account identifiers are NEVER stored.
    """
    record_id = get_str(record, "record_id") or "linear_integration_unknown"
    findings: list[FindingCandidate] = []

    integration_enabled = _bool(record, "integration_enabled")
    type_cat = get_str(record, "integration_type_category")

    # ── linear_integration_disabled ───────────────────────────────────────────
    if integration_enabled is False:
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_INTEGRATION_DISABLED,
            finding_key=make_finding_key(_RULE_INTEGRATION_DISABLED, record_id),
            severity="medium",
            title="Linear integration is disabled",
            description=(
                "A Linear external service integration is currently disabled. "
                "A disabled integration will not deliver events or synchronize "
                "data with the connected service. This may indicate a broken "
                "connection or an intentionally paused integration. This "
                "integration configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_INTEGRATION_DISABLED,
                "record_id": record_id,
                "integration_enabled": False,
                "integration_type_category": type_cat or "unknown",
            },
            remediation={
                "summary": "Review and re-enable this integration if still needed.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → Integrations.",
                    "Review the integration and re-enable it, or disconnect it if no longer needed.",
                ],
            },
            record_id=record_id,
        ))

    # ── linear_integration_unknown_type ───────────────────────────────────────
    if type_cat == "unknown":
        findings.append(FindingCandidate(
            provider="linear",
            rule_key=_RULE_INTEGRATION_UNKNOWN_TYPE,
            finding_key=make_finding_key(_RULE_INTEGRATION_UNKNOWN_TYPE, record_id),
            severity="low",
            title="Linear integration has an unrecognized service type",
            description=(
                "A Linear external service integration has a service type that "
                "was not recognized. Unrecognized integration types may indicate "
                "a legacy, unsupported, or misconfigured integration. This "
                "integration configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_INTEGRATION_UNKNOWN_TYPE,
                "record_id": record_id,
                "integration_type_category": "unknown",
            },
            remediation={
                "summary": "Review the type and configuration of this integration.",
                "steps": [
                    "Sign in to your Linear workspace.",
                    "Navigate to Settings → Integrations.",
                    "Inspect this integration and update or disconnect it if not actively used.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Dispatch ───────────────────────────────────────────────────────────────────


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one normalized Linear drift record and return any findings.

    Accepts any dict.  Unknown record_type values return an empty list — never
    raises.  Each evaluator is self-contained and never mutates the record.

    SECURITY: no rule reads or stores Linear API key values, OAuth tokens,
    webhook secrets, webhook URLs, issue titles, issue descriptions, comment
    bodies, attachment content, user emails, user names, member identities,
    team member identities, raw URLs, request or response payloads, customer
    data, IP addresses, user agents, or PII of any kind.
    """
    if not isinstance(record, dict):
        return []

    rtype = record.get("record_type")

    if rtype == LINEAR_WORKSPACE:
        return _eval_workspace(record)
    if rtype == LINEAR_TEAM:
        return _eval_team(record)
    if rtype == LINEAR_PROJECT:
        return _eval_project(record)
    if rtype == LINEAR_WORKFLOW_STATE:
        return _eval_workflow_state(record)
    if rtype == LINEAR_LABEL:
        return _eval_label(record)
    if rtype == LINEAR_WEBHOOK:
        return _eval_webhook(record)
    if rtype == LINEAR_VIEW:
        return _eval_view(record)
    if rtype == LINEAR_CYCLE:
        return _eval_cycle(record)
    if rtype == LINEAR_INTEGRATION:
        return _eval_integration(record)

    return []
