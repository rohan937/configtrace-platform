"""Jira configuration-risk security rules — M86B.

Every rule fires only on explicit, reliable normalized fields produced by the
Jira connector (app/connectors/jira.py + jira_schema.py, M86A).  Evidence is
metadata-only: booleans, counts, categories, opaque identifiers, and safe
record_type labels.

NEVER read, stored, or surfaced:
  Jira API tokens, OAuth tokens, session cookies, user emails, user names,
  account IDs, issue keys, issue titles, issue descriptions, comment bodies,
  attachment content, raw site URLs, raw webhook URLs, request payloads,
  response payloads, headers, audit logs, customer data, or PII of any kind.

CLAIM DISCIPLINE
----------------
These are configuration posture findings that **may require review**.  A
finding is evidence for review only.  It never asserts that a credential was
leaked, that unauthorized access occurred, or that any data was exposed.
Severity reflects review priority, not confirmed impact.

Record types evaluated (M86A)
-----------------------------
  jira_site                       — Jira Cloud site metadata posture
  jira_project                    — project visibility, lifecycle, ownership
  jira_board                      — board scope and project linkage
  jira_workflow                   — workflow statuses, transitions, lifecycle
  jira_workflow_scheme            — workflow scheme adoption posture
  jira_permission_scheme          — permission grant posture
  jira_notification_scheme        — notification recipient posture
  jira_issue_type_scheme          — issue type taxonomy posture
  jira_field_configuration_scheme — required/hidden field posture
  jira_screen_scheme              — screen scheme posture
  jira_webhook                    — webhook transport / signing / scope
  jira_automation_rule            — automation rule trigger / scope posture
"""

from __future__ import annotations

from typing import Any, Optional

from app.connectors.jira_schema import (
    JIRA_AUTOMATION_RULE,
    JIRA_BOARD,
    JIRA_FIELD_CONFIGURATION_SCHEME,
    JIRA_ISSUE_TYPE_SCHEME,
    JIRA_NOTIFICATION_SCHEME,
    JIRA_PERMISSION_SCHEME,
    JIRA_PROJECT,
    JIRA_SCREEN_SCHEME,
    JIRA_SITE,
    JIRA_WEBHOOK,
    JIRA_WORKFLOW,
    JIRA_WORKFLOW_SCHEME,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule key constants ─────────────────────────────────────────────────────────

# Site (4)
_RULE_SITE_MISSING_URL = "jira_site_missing_url"
_RULE_SITE_NO_PROJECTS = "jira_site_no_projects"
_RULE_SITE_NO_WEBHOOKS = "jira_site_no_webhooks"
_RULE_SITE_NO_AUTOMATION_RULES = "jira_site_no_automation_rules"

# Project (10)
_RULE_PROJECT_MISSING_KEY = "jira_project_missing_key"
_RULE_PROJECT_PRIVATE = "jira_project_private"
_RULE_PROJECT_ARCHIVED = "jira_project_archived"
_RULE_PROJECT_DELETED = "jira_project_deleted"
_RULE_PROJECT_SIMPLIFIED = "jira_project_simplified"
_RULE_PROJECT_UNKNOWN_TYPE_CATEGORY = "jira_project_unknown_type_category"
_RULE_PROJECT_UNKNOWN_STYLE_CATEGORY = "jira_project_unknown_style_category"
_RULE_PROJECT_NO_BOARDS = "jira_project_no_boards"
_RULE_PROJECT_NO_ISSUE_TYPES = "jira_project_no_issue_types"
_RULE_PROJECT_NO_LEAD = "jira_project_no_lead"

# Board (3)
_RULE_BOARD_UNKNOWN_TYPE_CATEGORY = "jira_board_unknown_type_category"
_RULE_BOARD_UNKNOWN_LOCATION_TYPE = "jira_board_unknown_location_type"
_RULE_BOARD_MISSING_PROJECT_LINK = "jira_board_missing_project_link"

# Workflow (4)
_RULE_WORKFLOW_NO_STATUSES = "jira_workflow_no_statuses"
_RULE_WORKFLOW_NO_TRANSITIONS = "jira_workflow_no_transitions"
_RULE_WORKFLOW_EXCESSIVE_GLOBAL_TRANSITIONS = "jira_workflow_excessive_global_transitions"
_RULE_WORKFLOW_INACTIVE = "jira_workflow_inactive"

# Workflow scheme (2)
_RULE_WORKFLOW_SCHEME_UNUSED = "jira_workflow_scheme_unused"
_RULE_WORKFLOW_SCHEME_NO_DEFAULT = "jira_workflow_scheme_no_default"

# Permission scheme (3)
_RULE_PERMISSION_SCHEME_ANONYMOUS_GRANT = "jira_permission_scheme_anonymous_grant"
_RULE_PERMISSION_SCHEME_ANYONE_GRANT = "jira_permission_scheme_anyone_grant"
_RULE_PERMISSION_SCHEME_LOGGED_IN_GRANT = "jira_permission_scheme_logged_in_grant"

# Notification scheme (3)
_RULE_NOTIFICATION_SCHEME_NO_NOTIFICATIONS = "jira_notification_scheme_no_notifications"
_RULE_NOTIFICATION_SCHEME_EMAIL_RECIPIENTS = "jira_notification_scheme_email_recipients"
_RULE_NOTIFICATION_SCHEME_GROUP_RECIPIENTS = "jira_notification_scheme_group_recipients"

# Issue type scheme (2)
_RULE_ISSUE_TYPE_SCHEME_NO_TYPES = "jira_issue_type_scheme_no_types"
_RULE_ISSUE_TYPE_SCHEME_NO_DEFAULT = "jira_issue_type_scheme_no_default"

# Field configuration scheme (2)
_RULE_FIELD_CONFIGURATION_SCHEME_NO_CONFIGURATIONS = "jira_field_configuration_scheme_no_configurations"
_RULE_FIELD_CONFIGURATION_SCHEME_HIDDEN_REQUIRED_CONFLICT = "jira_field_configuration_scheme_hidden_required_conflict"

# Screen scheme (2)
_RULE_SCREEN_SCHEME_NO_SCREENS = "jira_screen_scheme_no_screens"
_RULE_SCREEN_SCHEME_NO_FIELDS = "jira_screen_scheme_no_fields"

# Webhook (5)
_RULE_WEBHOOK_DISABLED = "jira_webhook_disabled"
_RULE_WEBHOOK_NO_SECRET_INDICATOR = "jira_webhook_no_secret_indicator"
_RULE_WEBHOOK_NON_HTTPS = "jira_webhook_non_https"
_RULE_WEBHOOK_NO_EVENTS = "jira_webhook_no_events"
_RULE_WEBHOOK_NO_JQL_FILTER = "jira_webhook_no_jql_filter"

# Automation rule (3)
_RULE_AUTOMATION_RULE_DISABLED = "jira_automation_rule_disabled"
_RULE_AUTOMATION_RULE_UNKNOWN_TRIGGER = "jira_automation_rule_unknown_trigger"
_RULE_AUTOMATION_RULE_GLOBAL_SCOPE = "jira_automation_rule_global_scope"


# ── All Jira rule keys implemented in this module ─────────────────────────────

JIRA_RULE_KEYS: frozenset[str] = frozenset({
    _RULE_SITE_MISSING_URL,
    _RULE_SITE_NO_PROJECTS,
    _RULE_SITE_NO_WEBHOOKS,
    _RULE_SITE_NO_AUTOMATION_RULES,
    _RULE_PROJECT_MISSING_KEY,
    _RULE_PROJECT_PRIVATE,
    _RULE_PROJECT_ARCHIVED,
    _RULE_PROJECT_DELETED,
    _RULE_PROJECT_SIMPLIFIED,
    _RULE_PROJECT_UNKNOWN_TYPE_CATEGORY,
    _RULE_PROJECT_UNKNOWN_STYLE_CATEGORY,
    _RULE_PROJECT_NO_BOARDS,
    _RULE_PROJECT_NO_ISSUE_TYPES,
    _RULE_PROJECT_NO_LEAD,
    _RULE_BOARD_UNKNOWN_TYPE_CATEGORY,
    _RULE_BOARD_UNKNOWN_LOCATION_TYPE,
    _RULE_BOARD_MISSING_PROJECT_LINK,
    _RULE_WORKFLOW_NO_STATUSES,
    _RULE_WORKFLOW_NO_TRANSITIONS,
    _RULE_WORKFLOW_EXCESSIVE_GLOBAL_TRANSITIONS,
    _RULE_WORKFLOW_INACTIVE,
    _RULE_WORKFLOW_SCHEME_UNUSED,
    _RULE_WORKFLOW_SCHEME_NO_DEFAULT,
    _RULE_PERMISSION_SCHEME_ANONYMOUS_GRANT,
    _RULE_PERMISSION_SCHEME_ANYONE_GRANT,
    _RULE_PERMISSION_SCHEME_LOGGED_IN_GRANT,
    _RULE_NOTIFICATION_SCHEME_NO_NOTIFICATIONS,
    _RULE_NOTIFICATION_SCHEME_EMAIL_RECIPIENTS,
    _RULE_NOTIFICATION_SCHEME_GROUP_RECIPIENTS,
    _RULE_ISSUE_TYPE_SCHEME_NO_TYPES,
    _RULE_ISSUE_TYPE_SCHEME_NO_DEFAULT,
    _RULE_FIELD_CONFIGURATION_SCHEME_NO_CONFIGURATIONS,
    _RULE_FIELD_CONFIGURATION_SCHEME_HIDDEN_REQUIRED_CONFLICT,
    _RULE_SCREEN_SCHEME_NO_SCREENS,
    _RULE_SCREEN_SCHEME_NO_FIELDS,
    _RULE_WEBHOOK_DISABLED,
    _RULE_WEBHOOK_NO_SECRET_INDICATOR,
    _RULE_WEBHOOK_NON_HTTPS,
    _RULE_WEBHOOK_NO_EVENTS,
    _RULE_WEBHOOK_NO_JQL_FILTER,
    _RULE_AUTOMATION_RULE_DISABLED,
    _RULE_AUTOMATION_RULE_UNKNOWN_TRIGGER,
    _RULE_AUTOMATION_RULE_GLOBAL_SCOPE,
})


# ── Thresholds ─────────────────────────────────────────────────────────────────

_EXCESSIVE_GLOBAL_TRANSITIONS_THRESHOLD = 3


# ── Safe field readers ─────────────────────────────────────────────────────────

def _bool(record: dict[str, Any], key: str) -> Optional[bool]:
    val = record.get(key)
    return val if isinstance(val, bool) else None


def _int_opt(record: dict[str, Any], key: str) -> Optional[int]:
    val = record.get(key)
    if isinstance(val, bool):
        return None
    return val if isinstance(val, int) else None


# ── Common safe wording snippet ───────────────────────────────────────────────

_DOES_NOT_CONFIRM = (
    "Configuration evidence only — does not confirm compromise "
    "or unauthorized access."
)


def _fc(
    *,
    rule_key: str,
    record_id: str,
    record_type: str,
    severity: str,
    title: str,
    description: str,
    extra_evidence: dict[str, Any],
    remediation_summary: str,
) -> FindingCandidate:
    """Build a FindingCandidate with the standard safe evidence shape."""
    evidence: dict[str, Any] = {
        "rule": rule_key,
        "record_id": record_id,
        "record_type": record_type,
    }
    evidence.update(extra_evidence)
    return FindingCandidate(
        provider="jira",
        rule_key=rule_key,
        finding_key=make_finding_key(rule_key, record_id),
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        remediation={"summary": remediation_summary},
        record_id=record_id,
    )


# ── Per-record-type evaluators ────────────────────────────────────────────────


def _eval_site(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "jira_site_unknown"
    findings: list[FindingCandidate] = []
    site_url_present = _bool(record, "site_url_present")
    project_count = _int_opt(record, "project_count")
    webhook_count = _int_opt(record, "webhook_count")
    automation_rule_count = _int_opt(record, "automation_rule_count")

    if site_url_present is False:
        findings.append(_fc(
            rule_key=_RULE_SITE_MISSING_URL, record_id=record_id, record_type=JIRA_SITE,
            severity="low",
            title="Jira site is missing a configured site URL indicator",
            description=(
                "The connector could not derive a site URL indicator from Jira "
                f"site metadata. This Jira site configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"site_url_present": False},
            remediation_summary="Confirm the Jira site URL is configured in the integration credentials.",
        ))

    if project_count is not None and project_count == 0:
        findings.append(_fc(
            rule_key=_RULE_SITE_NO_PROJECTS, record_id=record_id, record_type=JIRA_SITE,
            severity="low",
            title="Jira site has no projects",
            description=(
                f"This Jira site reports zero projects. This site configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"project_count": project_count},
            remediation_summary="Verify whether projects are expected; otherwise create at least one project.",
        ))

    if webhook_count is not None and webhook_count == 0:
        findings.append(_fc(
            rule_key=_RULE_SITE_NO_WEBHOOKS, record_id=record_id, record_type=JIRA_SITE,
            severity="low",
            title="Jira site has no webhook subscriptions",
            description=(
                f"This Jira site reports zero webhook subscriptions. This site configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"webhook_count": webhook_count},
            remediation_summary="Confirm whether webhook integrations are expected on this Jira site.",
        ))

    if automation_rule_count is not None and automation_rule_count == 0:
        findings.append(_fc(
            rule_key=_RULE_SITE_NO_AUTOMATION_RULES, record_id=record_id, record_type=JIRA_SITE,
            severity="low",
            title="Jira site has no automation rules",
            description=(
                f"This Jira site reports zero automation rules. This site configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"automation_rule_count": automation_rule_count},
            remediation_summary="Confirm whether automation rules are expected on this Jira site.",
        ))

    return findings


def _eval_project(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "jira_project_unknown"
    findings: list[FindingCandidate] = []

    project_key_present = _bool(record, "project_key_present")
    project_private = _bool(record, "project_private")
    project_archived = _bool(record, "project_archived")
    project_deleted = _bool(record, "project_deleted")
    project_simplified = _bool(record, "project_simplified")
    project_type_category = get_str(record, "project_type_category")
    project_style_category = get_str(record, "project_style_category")
    board_count = _int_opt(record, "board_count")
    issue_type_count = _int_opt(record, "issue_type_count")
    lead_present = _bool(record, "lead_present")

    if project_key_present is False:
        findings.append(_fc(
            rule_key=_RULE_PROJECT_MISSING_KEY, record_id=record_id, record_type=JIRA_PROJECT,
            severity="low",
            title="Jira project is missing a project key indicator",
            description=(
                f"The connector could not derive a project key indicator. This project configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"project_key_present": False},
            remediation_summary="Confirm the Jira project has a project key in its configuration.",
        ))

    if project_private is True:
        findings.append(_fc(
            rule_key=_RULE_PROJECT_PRIVATE, record_id=record_id, record_type=JIRA_PROJECT,
            severity="medium",
            title="Jira project is configured as private",
            description=(
                "This Jira project is configured as private. Private project posture "
                f"may require review depending on whether the project is intended for restricted access. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"project_private": True},
            remediation_summary="Confirm the project's private visibility matches the team's access policy.",
        ))

    if project_archived is True:
        findings.append(_fc(
            rule_key=_RULE_PROJECT_ARCHIVED, record_id=record_id, record_type=JIRA_PROJECT,
            severity="low",
            title="Jira project is archived",
            description=(
                f"This Jira project is archived. Archived project lifecycle posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"project_archived": True},
            remediation_summary="Confirm the archived state matches the team's intended lifecycle.",
        ))

    if project_deleted is True:
        findings.append(_fc(
            rule_key=_RULE_PROJECT_DELETED, record_id=record_id, record_type=JIRA_PROJECT,
            severity="low",
            title="Jira project is marked deleted",
            description=(
                f"This Jira project is marked deleted. Deleted project lifecycle posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"project_deleted": True},
            remediation_summary="Confirm the deleted state matches the team's intended lifecycle.",
        ))

    if project_simplified is True:
        findings.append(_fc(
            rule_key=_RULE_PROJECT_SIMPLIFIED, record_id=record_id, record_type=JIRA_PROJECT,
            severity="low",
            title="Jira project uses the simplified (team-managed) workflow surface",
            description=(
                "This Jira project is configured as a simplified (team-managed) project. "
                f"Simplified project configuration may require review depending on the team's governance needs. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"project_simplified": True},
            remediation_summary="Confirm the simplified project style matches the team's governance expectations.",
        ))

    if project_type_category and project_type_category.lower() == "unknown":
        findings.append(_fc(
            rule_key=_RULE_PROJECT_UNKNOWN_TYPE_CATEGORY, record_id=record_id, record_type=JIRA_PROJECT,
            severity="low",
            title="Jira project type category is unknown",
            description=(
                f"The connector could not classify the Jira project type. This project configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"project_type_category": project_type_category},
            remediation_summary="Review the project type and confirm it is a supported Jira project type.",
        ))

    if project_style_category and project_style_category.lower() == "unknown":
        findings.append(_fc(
            rule_key=_RULE_PROJECT_UNKNOWN_STYLE_CATEGORY, record_id=record_id, record_type=JIRA_PROJECT,
            severity="low",
            title="Jira project style category is unknown",
            description=(
                f"The connector could not classify the Jira project style. This project configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"project_style_category": project_style_category},
            remediation_summary="Review the project style and confirm it is a supported Jira style.",
        ))

    if board_count is not None and board_count == 0:
        findings.append(_fc(
            rule_key=_RULE_PROJECT_NO_BOARDS, record_id=record_id, record_type=JIRA_PROJECT,
            severity="low",
            title="Jira project has no boards",
            description=(
                f"This Jira project reports zero boards. This project configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"board_count": board_count},
            remediation_summary="Confirm whether boards are expected; create at least one if needed.",
        ))

    if issue_type_count is not None and issue_type_count == 0:
        findings.append(_fc(
            rule_key=_RULE_PROJECT_NO_ISSUE_TYPES, record_id=record_id, record_type=JIRA_PROJECT,
            severity="low",
            title="Jira project has no issue types",
            description=(
                f"This Jira project reports zero issue types. This project configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"issue_type_count": issue_type_count},
            remediation_summary="Confirm the project has at least one issue type defined.",
        ))

    if lead_present is False:
        findings.append(_fc(
            rule_key=_RULE_PROJECT_NO_LEAD, record_id=record_id, record_type=JIRA_PROJECT,
            severity="low",
            title="Jira project has no project lead indicator",
            description=(
                f"This Jira project has no project lead indicator. This project ownership posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"lead_present": False},
            remediation_summary="Assign a project lead to the Jira project.",
        ))

    return findings


def _eval_board(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "jira_board_unknown"
    findings: list[FindingCandidate] = []
    board_type_category = get_str(record, "board_type_category")
    board_location_type_category = get_str(record, "board_location_type_category")
    project_id = record.get("project_id")

    if board_type_category and board_type_category.lower() == "unknown":
        findings.append(_fc(
            rule_key=_RULE_BOARD_UNKNOWN_TYPE_CATEGORY, record_id=record_id, record_type=JIRA_BOARD,
            severity="low",
            title="Jira board type category is unknown",
            description=(
                f"The connector could not classify the Jira board type. This board configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"board_type_category": board_type_category},
            remediation_summary="Review the board type and confirm it is a supported Jira board.",
        ))

    if board_location_type_category and board_location_type_category.lower() == "unknown":
        findings.append(_fc(
            rule_key=_RULE_BOARD_UNKNOWN_LOCATION_TYPE, record_id=record_id, record_type=JIRA_BOARD,
            severity="low",
            title="Jira board location type is unknown",
            description=(
                f"The connector could not classify the Jira board location type. This board configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"board_location_type_category": board_location_type_category},
            remediation_summary="Review the board location and confirm it is a supported location type.",
        ))

    if project_id is None or (isinstance(project_id, str) and not project_id.strip()):
        findings.append(_fc(
            rule_key=_RULE_BOARD_MISSING_PROJECT_LINK, record_id=record_id, record_type=JIRA_BOARD,
            severity="low",
            title="Jira board is missing a project link",
            description=(
                f"This Jira board has no associated project identifier. This board configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"project_link_present": False},
            remediation_summary="Link the board to a Jira project, or confirm it is intended user-scoped.",
        ))

    return findings


def _eval_workflow(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "jira_workflow_unknown"
    findings: list[FindingCandidate] = []

    status_count = _int_opt(record, "workflow_status_count")
    transition_count = _int_opt(record, "workflow_transition_count")
    global_transition_count = _int_opt(record, "workflow_global_transition_count")
    active = _bool(record, "workflow_active")

    if status_count is not None and status_count == 0:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_NO_STATUSES, record_id=record_id, record_type=JIRA_WORKFLOW,
            severity="low",
            title="Jira workflow has no statuses",
            description=(
                f"This Jira workflow reports zero statuses. This workflow configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_status_count": status_count},
            remediation_summary="Define at least one status in the workflow.",
        ))

    if transition_count is not None and transition_count == 0:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_NO_TRANSITIONS, record_id=record_id, record_type=JIRA_WORKFLOW,
            severity="medium",
            title="Jira workflow has no transitions",
            description=(
                "This Jira workflow reports zero transitions. Issues cannot move "
                f"between states under this workflow configuration. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_transition_count": transition_count},
            remediation_summary="Add at least one transition between workflow states.",
        ))

    if (
        global_transition_count is not None
        and global_transition_count >= _EXCESSIVE_GLOBAL_TRANSITIONS_THRESHOLD
    ):
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_EXCESSIVE_GLOBAL_TRANSITIONS, record_id=record_id, record_type=JIRA_WORKFLOW,
            severity="medium",
            title="Jira workflow has an excessive number of global transitions",
            description=(
                "This Jira workflow has many global transitions, which bypass "
                f"per-status transition controls. This workflow configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_global_transition_count": global_transition_count},
            remediation_summary="Reduce global transitions in favor of explicit per-status transitions.",
        ))

    if active is False:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_INACTIVE, record_id=record_id, record_type=JIRA_WORKFLOW,
            severity="low",
            title="Jira workflow is inactive",
            description=(
                f"This Jira workflow is reported inactive. This workflow lifecycle posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_active": False},
            remediation_summary="Confirm the workflow's inactive state matches the team's intent.",
        ))

    return findings


def _eval_workflow_scheme(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "jira_workflow_scheme_unknown"
    findings: list[FindingCandidate] = []
    project_count = _int_opt(record, "workflow_scheme_project_count")
    default_present = _bool(record, "workflow_scheme_default_present")

    if project_count is not None and project_count == 0:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_SCHEME_UNUSED, record_id=record_id, record_type=JIRA_WORKFLOW_SCHEME,
            severity="low",
            title="Jira workflow scheme has no associated projects",
            description=(
                f"This Jira workflow scheme is associated with zero projects. This workflow scheme configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_scheme_project_count": project_count},
            remediation_summary="Associate the workflow scheme with at least one project, or remove it.",
        ))

    if default_present is False:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_SCHEME_NO_DEFAULT, record_id=record_id, record_type=JIRA_WORKFLOW_SCHEME,
            severity="low",
            title="Jira workflow scheme has no default workflow indicator",
            description=(
                f"This Jira workflow scheme has no default workflow indicator. This workflow scheme configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_scheme_default_present": False},
            remediation_summary="Designate a default workflow within this scheme.",
        ))

    return findings


def _eval_permission_scheme(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "jira_permission_scheme_unknown"
    findings: list[FindingCandidate] = []

    anon = _int_opt(record, "permission_anonymous_grant_count")
    anyone = _int_opt(record, "permission_anyone_grant_count")
    logged_in = _int_opt(record, "permission_logged_in_grant_count")

    if anon is not None and anon > 0:
        findings.append(_fc(
            rule_key=_RULE_PERMISSION_SCHEME_ANONYMOUS_GRANT, record_id=record_id, record_type=JIRA_PERMISSION_SCHEME,
            severity="high",
            title="Jira permission scheme grants permissions to anonymous principals",
            description=(
                f"This Jira permission scheme grants one or more permissions to anonymous principals. This permission scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"permission_anonymous_grant_count": anon},
            remediation_summary="Remove anonymous grants from the permission scheme unless explicitly required.",
        ))

    if anyone is not None and anyone > 0:
        findings.append(_fc(
            rule_key=_RULE_PERMISSION_SCHEME_ANYONE_GRANT, record_id=record_id, record_type=JIRA_PERMISSION_SCHEME,
            severity="high",
            title="Jira permission scheme grants permissions to 'anyone'",
            description=(
                f"This Jira permission scheme grants one or more permissions to the 'anyone' principal. This permission scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"permission_anyone_grant_count": anyone},
            remediation_summary="Restrict grants from 'anyone' to specific groups or project roles.",
        ))

    if logged_in is not None and logged_in > 0:
        findings.append(_fc(
            rule_key=_RULE_PERMISSION_SCHEME_LOGGED_IN_GRANT, record_id=record_id, record_type=JIRA_PERMISSION_SCHEME,
            severity="medium",
            title="Jira permission scheme grants permissions to all logged-in users",
            description=(
                f"This Jira permission scheme grants one or more permissions to all logged-in users. This permission scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"permission_logged_in_grant_count": logged_in},
            remediation_summary="Restrict broad logged-in grants to specific groups or project roles.",
        ))

    return findings


def _eval_notification_scheme(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "jira_notification_scheme_unknown"
    findings: list[FindingCandidate] = []

    notif_count = _int_opt(record, "notification_count")
    email_count = _int_opt(record, "notification_email_recipient_count")
    group_count = _int_opt(record, "notification_group_recipient_count")

    if notif_count is not None and notif_count == 0:
        findings.append(_fc(
            rule_key=_RULE_NOTIFICATION_SCHEME_NO_NOTIFICATIONS, record_id=record_id, record_type=JIRA_NOTIFICATION_SCHEME,
            severity="low",
            title="Jira notification scheme has no notifications configured",
            description=(
                f"This Jira notification scheme reports zero notifications. This notification scheme configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"notification_count": notif_count},
            remediation_summary="Configure at least one notification, or remove the empty scheme.",
        ))

    if email_count is not None and email_count > 0:
        findings.append(_fc(
            rule_key=_RULE_NOTIFICATION_SCHEME_EMAIL_RECIPIENTS, record_id=record_id, record_type=JIRA_NOTIFICATION_SCHEME,
            severity="low",
            title="Jira notification scheme uses single-email recipients",
            description=(
                "This Jira notification scheme uses individual email recipients. "
                f"This notification scheme posture may require review — individual email recipients can drift as people leave the team. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"notification_email_recipient_count": email_count},
            remediation_summary="Prefer groups or project roles over individual email recipients.",
        ))

    if group_count is not None and group_count > 0:
        findings.append(_fc(
            rule_key=_RULE_NOTIFICATION_SCHEME_GROUP_RECIPIENTS, record_id=record_id, record_type=JIRA_NOTIFICATION_SCHEME,
            severity="low",
            title="Jira notification scheme uses group recipients",
            description=(
                f"This Jira notification scheme delivers notifications to groups. Group recipients should be reviewed periodically. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"notification_group_recipient_count": group_count},
            remediation_summary="Confirm the group recipients are appropriate for this notification scheme.",
        ))

    return findings


def _eval_issue_type_scheme(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "jira_issue_type_scheme_unknown"
    findings: list[FindingCandidate] = []

    issue_type_count = _int_opt(record, "issue_type_count")
    default_present = _bool(record, "default_issue_type_present")

    if issue_type_count is not None and issue_type_count == 0:
        findings.append(_fc(
            rule_key=_RULE_ISSUE_TYPE_SCHEME_NO_TYPES, record_id=record_id, record_type=JIRA_ISSUE_TYPE_SCHEME,
            severity="low",
            title="Jira issue type scheme has no issue types",
            description=(
                f"This Jira issue type scheme has zero issue types. This issue type scheme configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"issue_type_count": issue_type_count},
            remediation_summary="Add at least one issue type to the scheme.",
        ))

    if default_present is False:
        findings.append(_fc(
            rule_key=_RULE_ISSUE_TYPE_SCHEME_NO_DEFAULT, record_id=record_id, record_type=JIRA_ISSUE_TYPE_SCHEME,
            severity="low",
            title="Jira issue type scheme has no default issue type indicator",
            description=(
                f"This Jira issue type scheme has no default issue type indicator. This issue type scheme configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"default_issue_type_present": False},
            remediation_summary="Set a default issue type for this scheme.",
        ))

    return findings


def _eval_field_configuration_scheme(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "jira_field_configuration_scheme_unknown"
    findings: list[FindingCandidate] = []

    field_config_count = _int_opt(record, "field_configuration_count")
    required_count = _int_opt(record, "required_field_count")
    hidden_count = _int_opt(record, "hidden_field_count")

    if field_config_count is not None and field_config_count == 0:
        findings.append(_fc(
            rule_key=_RULE_FIELD_CONFIGURATION_SCHEME_NO_CONFIGURATIONS, record_id=record_id, record_type=JIRA_FIELD_CONFIGURATION_SCHEME,
            severity="low",
            title="Jira field configuration scheme has no field configurations",
            description=(
                f"This Jira field configuration scheme reports zero field configurations. This scheme configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"field_configuration_count": field_config_count},
            remediation_summary="Add at least one field configuration, or remove the empty scheme.",
        ))

    if (
        required_count is not None and required_count > 0
        and hidden_count is not None and hidden_count > 0
        and hidden_count >= required_count
    ):
        findings.append(_fc(
            rule_key=_RULE_FIELD_CONFIGURATION_SCHEME_HIDDEN_REQUIRED_CONFLICT, record_id=record_id, record_type=JIRA_FIELD_CONFIGURATION_SCHEME,
            severity="medium",
            title="Jira field configuration scheme has both required and hidden fields",
            description=(
                "This Jira field configuration scheme reports both required and hidden "
                "field counts greater than zero. A field marked both required and hidden "
                "creates a misconfiguration where users may be unable to satisfy required "
                f"input. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={
                "required_field_count": required_count,
                "hidden_field_count": hidden_count,
            },
            remediation_summary="Review the scheme so no field is both required and hidden.",
        ))

    return findings


def _eval_screen_scheme(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "jira_screen_scheme_unknown"
    findings: list[FindingCandidate] = []

    screen_count = _int_opt(record, "screen_count")
    field_count = _int_opt(record, "field_count")

    if screen_count is not None and screen_count == 0:
        findings.append(_fc(
            rule_key=_RULE_SCREEN_SCHEME_NO_SCREENS, record_id=record_id, record_type=JIRA_SCREEN_SCHEME,
            severity="low",
            title="Jira screen scheme has no screens",
            description=(
                f"This Jira screen scheme reports zero screens. This screen scheme configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"screen_count": screen_count},
            remediation_summary="Add at least one screen to the screen scheme, or remove it.",
        ))

    if field_count is not None and field_count == 0:
        findings.append(_fc(
            rule_key=_RULE_SCREEN_SCHEME_NO_FIELDS, record_id=record_id, record_type=JIRA_SCREEN_SCHEME,
            severity="low",
            title="Jira screen scheme has no fields",
            description=(
                f"This Jira screen scheme reports zero fields across its screens. This screen scheme configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"field_count": field_count},
            remediation_summary="Add at least one field to the screen scheme.",
        ))

    return findings


def _eval_webhook(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate jira_webhook posture rules.

    PRIVACY: raw webhook URLs and signing secrets are never read or stored —
    rules operate only on safe derived booleans / category labels.
    """
    record_id = get_str(record, "record_id") or "jira_webhook_unknown"
    findings: list[FindingCandidate] = []

    enabled = _bool(record, "webhook_enabled")
    secret_present = _bool(record, "webhook_secret_present")
    url_present = _bool(record, "webhook_url_present")
    url_scheme_category = get_str(record, "webhook_url_scheme_category")
    event_count = _int_opt(record, "webhook_event_count")
    jql_present = _bool(record, "webhook_jql_filter_present")

    if enabled is False:
        findings.append(_fc(
            rule_key=_RULE_WEBHOOK_DISABLED, record_id=record_id, record_type=JIRA_WEBHOOK,
            severity="low",
            title="Jira webhook subscription is disabled",
            description=(
                f"This Jira webhook subscription is disabled. This webhook configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"webhook_enabled": False},
            remediation_summary="Re-enable the webhook if it is still required, or remove it.",
        ))

    if secret_present is False:
        findings.append(_fc(
            rule_key=_RULE_WEBHOOK_NO_SECRET_INDICATOR, record_id=record_id, record_type=JIRA_WEBHOOK,
            severity="high",
            title="Jira webhook has no signing secret indicator",
            description=(
                "This Jira webhook reports no signing secret indicator. Without a "
                "signing secret, downstream receivers cannot verify event authenticity. "
                f"This webhook configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"webhook_secret_present": False},
            remediation_summary="Configure a webhook signing secret for downstream verification.",
        ))

    if (
        url_present is True
        and url_scheme_category
        and url_scheme_category.lower() == "non_https"
    ):
        findings.append(_fc(
            rule_key=_RULE_WEBHOOK_NON_HTTPS, record_id=record_id, record_type=JIRA_WEBHOOK,
            severity="high",
            title="Jira webhook uses a non-HTTPS delivery endpoint",
            description=(
                f"This Jira webhook is configured with a non-HTTPS delivery endpoint. This webhook configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"webhook_url_scheme_category": url_scheme_category},
            remediation_summary="Reconfigure the webhook to deliver over HTTPS.",
        ))

    if event_count is not None and event_count == 0:
        findings.append(_fc(
            rule_key=_RULE_WEBHOOK_NO_EVENTS, record_id=record_id, record_type=JIRA_WEBHOOK,
            severity="low",
            title="Jira webhook subscribes to no events",
            description=(
                f"This Jira webhook reports zero subscribed events. This webhook configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"webhook_event_count": event_count},
            remediation_summary="Subscribe the webhook to at least one event, or remove it.",
        ))

    if jql_present is False:
        findings.append(_fc(
            rule_key=_RULE_WEBHOOK_NO_JQL_FILTER, record_id=record_id, record_type=JIRA_WEBHOOK,
            severity="medium",
            title="Jira webhook has no JQL scope filter indicator",
            description=(
                "This Jira webhook has no JQL scope filter indicator, meaning subscribed "
                "events may be delivered for issues across the entire site. This webhook "
                f"configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"webhook_jql_filter_present": False},
            remediation_summary="Add a JQL filter to scope webhook deliveries to relevant issues only.",
        ))

    return findings


def _eval_automation_rule(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "jira_automation_rule_unknown"
    findings: list[FindingCandidate] = []

    enabled = _bool(record, "automation_enabled")
    trigger_category = get_str(record, "automation_trigger_type_category")
    scope_category = get_str(record, "automation_scope_category")

    if enabled is False:
        findings.append(_fc(
            rule_key=_RULE_AUTOMATION_RULE_DISABLED, record_id=record_id, record_type=JIRA_AUTOMATION_RULE,
            severity="medium",
            title="Jira automation rule is disabled",
            description=(
                f"This Jira automation rule is disabled. This automation rule configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"automation_enabled": False},
            remediation_summary="Re-enable the automation rule if still required, or remove it.",
        ))

    if trigger_category and trigger_category.lower() == "unknown":
        findings.append(_fc(
            rule_key=_RULE_AUTOMATION_RULE_UNKNOWN_TRIGGER, record_id=record_id, record_type=JIRA_AUTOMATION_RULE,
            severity="low",
            title="Jira automation rule trigger type category is unknown",
            description=(
                f"The connector could not classify the Jira automation rule trigger. This automation rule configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"automation_trigger_type_category": trigger_category},
            remediation_summary="Review the trigger type and confirm it is a supported Jira trigger.",
        ))

    if scope_category and scope_category.lower() == "global":
        findings.append(_fc(
            rule_key=_RULE_AUTOMATION_RULE_GLOBAL_SCOPE, record_id=record_id, record_type=JIRA_AUTOMATION_RULE,
            severity="medium",
            title="Jira automation rule has global scope",
            description=(
                "This Jira automation rule is configured with global scope, applying to "
                "all projects on the site. Broad automation scope may require review. "
                f"{_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"automation_scope_category": scope_category},
            remediation_summary="Narrow automation scope to specific projects unless global scope is required.",
        ))

    return findings


# ── Dispatcher ────────────────────────────────────────────────────────────────

_EVAL_BY_RECORD_TYPE = {
    JIRA_SITE: _eval_site,
    JIRA_PROJECT: _eval_project,
    JIRA_BOARD: _eval_board,
    JIRA_WORKFLOW: _eval_workflow,
    JIRA_WORKFLOW_SCHEME: _eval_workflow_scheme,
    JIRA_PERMISSION_SCHEME: _eval_permission_scheme,
    JIRA_NOTIFICATION_SCHEME: _eval_notification_scheme,
    JIRA_ISSUE_TYPE_SCHEME: _eval_issue_type_scheme,
    JIRA_FIELD_CONFIGURATION_SCHEME: _eval_field_configuration_scheme,
    JIRA_SCREEN_SCHEME: _eval_screen_scheme,
    JIRA_WEBHOOK: _eval_webhook,
    JIRA_AUTOMATION_RULE: _eval_automation_rule,
}


def evaluate(record: Any) -> list[FindingCandidate]:
    """Dispatch a normalized Jira record to its per-record-type evaluator.

    Unknown record types and non-dict input return an empty list (defensive).
    """
    if not isinstance(record, dict):
        return []
    record_type = get_str(record, "record_type")
    fn = _EVAL_BY_RECORD_TYPE.get(record_type)
    if fn is None:
        return []
    return fn(record)
