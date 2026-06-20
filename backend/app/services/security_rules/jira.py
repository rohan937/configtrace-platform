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


# ── M86C rule keys (Workflow / Webhook Risk Expansion) ────────────────────────

# Workflow (7)
_RULE_WORKFLOW_NO_DONE_STATUS = "jira_workflow_no_done_status"
_RULE_WORKFLOW_NO_IN_PROGRESS_STATUS = "jira_workflow_no_in_progress_status"
_RULE_WORKFLOW_HIGH_TRANSITION_RULE_COUNT = "jira_workflow_high_transition_rule_count"
_RULE_WORKFLOW_HIGH_VALIDATOR_COUNT = "jira_workflow_high_validator_count"
_RULE_WORKFLOW_HIGH_CONDITION_COUNT = "jira_workflow_high_condition_count"
_RULE_WORKFLOW_HIGH_POST_FUNCTION_COUNT = "jira_workflow_high_post_function_count"
_RULE_WORKFLOW_ORPHAN_STATUSES = "jira_workflow_orphan_statuses"

# Workflow scheme (3)
_RULE_WORKFLOW_SCHEME_UNMAPPED_ISSUE_TYPES = "jira_workflow_scheme_unmapped_issue_types"
_RULE_WORKFLOW_SCHEME_LOW_WORKFLOW_COUNT = "jira_workflow_scheme_low_workflow_count"
_RULE_WORKFLOW_SCHEME_HIGH_ISSUE_TYPE_MAPPING_COUNT = "jira_workflow_scheme_high_issue_type_mapping_count"

# Permission scheme (8)
_RULE_PERMISSION_SCHEME_PUBLIC_BROWSE_PROJECTS = "jira_permission_scheme_public_browse_projects"
_RULE_PERMISSION_SCHEME_PUBLIC_ADMINISTER_PROJECTS = "jira_permission_scheme_public_administer_projects"
_RULE_PERMISSION_SCHEME_PUBLIC_MANAGE_SPRINTS = "jira_permission_scheme_public_manage_sprints"
_RULE_PERMISSION_SCHEME_PUBLIC_CREATE_ISSUES = "jira_permission_scheme_public_create_issues"
_RULE_PERMISSION_SCHEME_PUBLIC_TRANSITION_ISSUES = "jira_permission_scheme_public_transition_issues"
_RULE_PERMISSION_SCHEME_UNKNOWN_HOLDER = "jira_permission_scheme_unknown_holder"
_RULE_PERMISSION_SCHEME_HIGH_PRIVILEGE_GRANTS = "jira_permission_scheme_high_privilege_grants"
_RULE_PERMISSION_SCHEME_HIGH_PUBLIC_GRANT_COUNT = "jira_permission_scheme_high_public_grant_count"

# Notification scheme (2)
_RULE_NOTIFICATION_SCHEME_UNKNOWN_RECIPIENTS = "jira_notification_scheme_unknown_recipients"
_RULE_NOTIFICATION_SCHEME_HIGH_EVENT_COUNT = "jira_notification_scheme_high_event_count"

# Webhook (5)
_RULE_WEBHOOK_COMMENT_EVENT_SCOPE = "jira_webhook_comment_event_scope"
_RULE_WEBHOOK_ATTACHMENT_EVENT_SCOPE = "jira_webhook_attachment_event_scope"
_RULE_WEBHOOK_SPRINT_EVENT_SCOPE = "jira_webhook_sprint_event_scope"
_RULE_WEBHOOK_WORKLOG_EVENT_SCOPE = "jira_webhook_worklog_event_scope"
_RULE_WEBHOOK_ALL_ISSUE_EVENTS = "jira_webhook_all_issue_events"

# Automation rule (8)
_RULE_AUTOMATION_RULE_WEB_REQUEST_ACTION = "jira_automation_rule_web_request_action"
_RULE_AUTOMATION_RULE_EMAIL_ACTION = "jira_automation_rule_email_action"
_RULE_AUTOMATION_RULE_EXTERNAL_ACTION = "jira_automation_rule_external_action"
_RULE_AUTOMATION_RULE_COMMENT_ACTION = "jira_automation_rule_comment_action"
_RULE_AUTOMATION_RULE_HIGH_ACTION_COUNT = "jira_automation_rule_high_action_count"
_RULE_AUTOMATION_RULE_HIGH_BRANCH_COUNT = "jira_automation_rule_high_branch_count"
_RULE_AUTOMATION_RULE_MULTI_PROJECT_SCOPE = "jira_automation_rule_multi_project_scope"
_RULE_AUTOMATION_RULE_UNKNOWN_SCOPE = "jira_automation_rule_unknown_scope"

# Board (5)
_RULE_BOARD_NO_FILTER_INDICATOR = "jira_board_no_filter_indicator"
_RULE_BOARD_BROAD_JQL_FILTER = "jira_board_broad_jql_filter"
_RULE_BOARD_HIGH_QUICK_FILTER_COUNT = "jira_board_high_quick_filter_count"
_RULE_BOARD_UNKNOWN_SWIMLANE_STRATEGY = "jira_board_unknown_swimlane_strategy"
_RULE_BOARD_NO_COLUMNS = "jira_board_no_columns"

# Screen scheme (1)
_RULE_SCREEN_SCHEME_UNMAPPED_SCREENS = "jira_screen_scheme_unmapped_screens"


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
    # M86C — Workflow / Webhook Risk Expansion
    _RULE_WORKFLOW_NO_DONE_STATUS,
    _RULE_WORKFLOW_NO_IN_PROGRESS_STATUS,
    _RULE_WORKFLOW_HIGH_TRANSITION_RULE_COUNT,
    _RULE_WORKFLOW_HIGH_VALIDATOR_COUNT,
    _RULE_WORKFLOW_HIGH_CONDITION_COUNT,
    _RULE_WORKFLOW_HIGH_POST_FUNCTION_COUNT,
    _RULE_WORKFLOW_ORPHAN_STATUSES,
    _RULE_WORKFLOW_SCHEME_UNMAPPED_ISSUE_TYPES,
    _RULE_WORKFLOW_SCHEME_LOW_WORKFLOW_COUNT,
    _RULE_WORKFLOW_SCHEME_HIGH_ISSUE_TYPE_MAPPING_COUNT,
    _RULE_PERMISSION_SCHEME_PUBLIC_BROWSE_PROJECTS,
    _RULE_PERMISSION_SCHEME_PUBLIC_ADMINISTER_PROJECTS,
    _RULE_PERMISSION_SCHEME_PUBLIC_MANAGE_SPRINTS,
    _RULE_PERMISSION_SCHEME_PUBLIC_CREATE_ISSUES,
    _RULE_PERMISSION_SCHEME_PUBLIC_TRANSITION_ISSUES,
    _RULE_PERMISSION_SCHEME_UNKNOWN_HOLDER,
    _RULE_PERMISSION_SCHEME_HIGH_PRIVILEGE_GRANTS,
    _RULE_PERMISSION_SCHEME_HIGH_PUBLIC_GRANT_COUNT,
    _RULE_NOTIFICATION_SCHEME_UNKNOWN_RECIPIENTS,
    _RULE_NOTIFICATION_SCHEME_HIGH_EVENT_COUNT,
    _RULE_WEBHOOK_COMMENT_EVENT_SCOPE,
    _RULE_WEBHOOK_ATTACHMENT_EVENT_SCOPE,
    _RULE_WEBHOOK_SPRINT_EVENT_SCOPE,
    _RULE_WEBHOOK_WORKLOG_EVENT_SCOPE,
    _RULE_WEBHOOK_ALL_ISSUE_EVENTS,
    _RULE_AUTOMATION_RULE_WEB_REQUEST_ACTION,
    _RULE_AUTOMATION_RULE_EMAIL_ACTION,
    _RULE_AUTOMATION_RULE_EXTERNAL_ACTION,
    _RULE_AUTOMATION_RULE_COMMENT_ACTION,
    _RULE_AUTOMATION_RULE_HIGH_ACTION_COUNT,
    _RULE_AUTOMATION_RULE_HIGH_BRANCH_COUNT,
    _RULE_AUTOMATION_RULE_MULTI_PROJECT_SCOPE,
    _RULE_AUTOMATION_RULE_UNKNOWN_SCOPE,
    _RULE_BOARD_NO_FILTER_INDICATOR,
    _RULE_BOARD_BROAD_JQL_FILTER,
    _RULE_BOARD_HIGH_QUICK_FILTER_COUNT,
    _RULE_BOARD_UNKNOWN_SWIMLANE_STRATEGY,
    _RULE_BOARD_NO_COLUMNS,
    _RULE_SCREEN_SCHEME_UNMAPPED_SCREENS,
})


# ── Thresholds ─────────────────────────────────────────────────────────────────

_EXCESSIVE_GLOBAL_TRANSITIONS_THRESHOLD = 3

# M86C thresholds
_HIGH_TRANSITION_RULE_THRESHOLD = 15
_HIGH_VALIDATOR_THRESHOLD = 5
_HIGH_CONDITION_THRESHOLD = 5
_HIGH_POST_FUNCTION_THRESHOLD = 10
_HIGH_ISSUE_TYPE_MAPPING_THRESHOLD = 20
_HIGH_PRIVILEGE_GRANT_THRESHOLD = 5
_HIGH_PUBLIC_GRANT_THRESHOLD = 3
_HIGH_NOTIFICATION_EVENT_THRESHOLD = 20
_HIGH_AUTOMATION_ACTION_THRESHOLD = 10
_HIGH_AUTOMATION_BRANCH_THRESHOLD = 5
_HIGH_QUICK_FILTER_THRESHOLD = 10


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

    # ── M86C board scope posture ───────────────────────────────────────────
    filter_present = _bool(record, "board_filter_present")
    jql_broad = _bool(record, "board_jql_filter_broad")
    quick_filter_count = _int_opt(record, "board_quick_filter_count")
    swimlane_category = get_str(record, "board_swimlane_strategy_category")
    column_count = _int_opt(record, "board_column_count")

    if filter_present is False:
        findings.append(_fc(
            rule_key=_RULE_BOARD_NO_FILTER_INDICATOR, record_id=record_id, record_type=JIRA_BOARD,
            severity="low",
            title="Jira board has no filter indicator",
            description=(
                f"This Jira board reports no associated filter indicator. This board configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"board_filter_present": False},
            remediation_summary="Confirm the board's filter scope is configured as intended.",
        ))

    if jql_broad is True:
        findings.append(_fc(
            rule_key=_RULE_BOARD_BROAD_JQL_FILTER, record_id=record_id, record_type=JIRA_BOARD,
            severity="medium",
            title="Jira board uses a broad filter scope",
            description=(
                "This Jira board reports a broad (unbounded) filter scope, which can surface "
                f"issues beyond the intended team. This board configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"board_jql_filter_broad": True},
            remediation_summary="Scope the board's filter to the relevant project or team.",
        ))

    if quick_filter_count is not None and quick_filter_count > _HIGH_QUICK_FILTER_THRESHOLD:
        findings.append(_fc(
            rule_key=_RULE_BOARD_HIGH_QUICK_FILTER_COUNT, record_id=record_id, record_type=JIRA_BOARD,
            severity="low",
            title="Jira board has a high quick-filter count",
            description=(
                f"This Jira board has many quick filters. This board configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"board_quick_filter_count": quick_filter_count},
            remediation_summary="Review the board's quick filters and remove any that are unused.",
        ))

    if swimlane_category and swimlane_category.lower() == "unknown":
        findings.append(_fc(
            rule_key=_RULE_BOARD_UNKNOWN_SWIMLANE_STRATEGY, record_id=record_id, record_type=JIRA_BOARD,
            severity="low",
            title="Jira board swimlane strategy is unknown",
            description=(
                f"The connector could not classify the Jira board swimlane strategy. This board configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"board_swimlane_strategy_category": swimlane_category},
            remediation_summary="Review the board's swimlane strategy and confirm it is supported.",
        ))

    if column_count is not None and column_count < 1:
        findings.append(_fc(
            rule_key=_RULE_BOARD_NO_COLUMNS, record_id=record_id, record_type=JIRA_BOARD,
            severity="low",
            title="Jira board has no columns",
            description=(
                f"This Jira board reports fewer than one column. This board configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"board_column_count": column_count},
            remediation_summary="Configure at least one column for the board.",
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

    # ── M86C workflow structure posture ────────────────────────────────────
    has_done = _bool(record, "workflow_has_done_status")
    has_in_progress = _bool(record, "workflow_has_in_progress_status")
    transition_rule_count = _int_opt(record, "workflow_transition_rule_count")
    validator_count = _int_opt(record, "workflow_validator_count")
    condition_count = _int_opt(record, "workflow_condition_count")
    post_function_count = _int_opt(record, "workflow_post_function_count")
    orphan_status_count = _int_opt(record, "workflow_orphan_status_count")

    if has_done is False:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_NO_DONE_STATUS, record_id=record_id, record_type=JIRA_WORKFLOW,
            severity="low",
            title="Jira workflow has no done-category status",
            description=(
                f"This Jira workflow reports no status in the done category. This workflow configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_has_done_status": False},
            remediation_summary="Add a status in the done category so issues can reach completion.",
        ))

    if has_in_progress is False:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_NO_IN_PROGRESS_STATUS, record_id=record_id, record_type=JIRA_WORKFLOW,
            severity="low",
            title="Jira workflow has no in-progress-category status",
            description=(
                f"This Jira workflow reports no status in the in-progress category. This workflow configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_has_in_progress_status": False},
            remediation_summary="Add a status in the in-progress category to represent active work.",
        ))

    if transition_rule_count is not None and transition_rule_count > _HIGH_TRANSITION_RULE_THRESHOLD:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_HIGH_TRANSITION_RULE_COUNT, record_id=record_id, record_type=JIRA_WORKFLOW,
            severity="medium",
            title="Jira workflow has a high transition-rule count",
            description=(
                "This Jira workflow has a high number of transition rules (conditions, "
                f"validators, and post-functions combined). This workflow configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_transition_rule_count": transition_rule_count},
            remediation_summary="Review transition rules and remove any that are redundant or unused.",
        ))

    if validator_count is not None and validator_count > _HIGH_VALIDATOR_THRESHOLD:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_HIGH_VALIDATOR_COUNT, record_id=record_id, record_type=JIRA_WORKFLOW,
            severity="medium",
            title="Jira workflow has a high validator count",
            description=(
                f"This Jira workflow has many transition validators. This workflow configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_validator_count": validator_count},
            remediation_summary="Review workflow validators and consolidate where possible.",
        ))

    if condition_count is not None and condition_count > _HIGH_CONDITION_THRESHOLD:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_HIGH_CONDITION_COUNT, record_id=record_id, record_type=JIRA_WORKFLOW,
            severity="medium",
            title="Jira workflow has a high condition count",
            description=(
                f"This Jira workflow has many transition conditions. This workflow configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_condition_count": condition_count},
            remediation_summary="Review workflow conditions and consolidate where possible.",
        ))

    if post_function_count is not None and post_function_count > _HIGH_POST_FUNCTION_THRESHOLD:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_HIGH_POST_FUNCTION_COUNT, record_id=record_id, record_type=JIRA_WORKFLOW,
            severity="low",
            title="Jira workflow has a high post-function count",
            description=(
                f"This Jira workflow has many transition post-functions. This workflow configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_post_function_count": post_function_count},
            remediation_summary="Review workflow post-functions and remove any that are no longer needed.",
        ))

    if orphan_status_count is not None and orphan_status_count > 0:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_ORPHAN_STATUSES, record_id=record_id, record_type=JIRA_WORKFLOW,
            severity="medium",
            title="Jira workflow has orphaned statuses",
            description=(
                "This Jira workflow reports statuses that are not reachable through any "
                f"transition. This workflow configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_orphan_status_count": orphan_status_count},
            remediation_summary="Connect orphaned statuses with transitions or remove them.",
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

    # ── M86C workflow scheme mapping posture ───────────────────────────────
    unmapped_count = _int_opt(record, "workflow_scheme_unmapped_issue_type_count")
    workflow_count = _int_opt(record, "workflow_scheme_workflow_count")
    mapping_count = _int_opt(record, "workflow_scheme_issue_type_mapping_count")

    if unmapped_count is not None and unmapped_count > 0:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_SCHEME_UNMAPPED_ISSUE_TYPES, record_id=record_id, record_type=JIRA_WORKFLOW_SCHEME,
            severity="medium",
            title="Jira workflow scheme has unmapped issue types",
            description=(
                "This Jira workflow scheme reports issue types not explicitly mapped to a "
                f"workflow. This workflow scheme configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_scheme_unmapped_issue_type_count": unmapped_count},
            remediation_summary="Map each issue type to a workflow, or confirm the default workflow is intended.",
        ))

    if workflow_count is not None and workflow_count < 1:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_SCHEME_LOW_WORKFLOW_COUNT, record_id=record_id, record_type=JIRA_WORKFLOW_SCHEME,
            severity="low",
            title="Jira workflow scheme references no workflows",
            description=(
                f"This Jira workflow scheme references fewer than one workflow. This workflow scheme configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_scheme_workflow_count": workflow_count},
            remediation_summary="Confirm the workflow scheme references at least one workflow.",
        ))

    if mapping_count is not None and mapping_count > _HIGH_ISSUE_TYPE_MAPPING_THRESHOLD:
        findings.append(_fc(
            rule_key=_RULE_WORKFLOW_SCHEME_HIGH_ISSUE_TYPE_MAPPING_COUNT, record_id=record_id, record_type=JIRA_WORKFLOW_SCHEME,
            severity="low",
            title="Jira workflow scheme has a high issue-type mapping count",
            description=(
                f"This Jira workflow scheme has many issue-type-to-workflow mappings. This workflow scheme configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"workflow_scheme_issue_type_mapping_count": mapping_count},
            remediation_summary="Review the mappings and consolidate where workflows are shared.",
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

    # ── M86C public / high-privilege grant posture ─────────────────────────
    public_browse = _bool(record, "permission_public_browse_projects")
    public_admin = _bool(record, "permission_public_administer_projects")
    public_sprints = _bool(record, "permission_public_manage_sprints")
    public_create = _bool(record, "permission_public_create_issues")
    public_transition = _bool(record, "permission_public_transition_issues")
    unknown_holder_count = _int_opt(record, "permission_unknown_holder_count")
    high_privilege_count = _int_opt(record, "permission_high_privilege_grant_count")
    public_grant_count = _int_opt(record, "permission_public_grant_count")

    if public_browse is True:
        findings.append(_fc(
            rule_key=_RULE_PERMISSION_SCHEME_PUBLIC_BROWSE_PROJECTS, record_id=record_id, record_type=JIRA_PERMISSION_SCHEME,
            severity="medium",
            title="Jira permission scheme grants public browse-projects access",
            description=(
                "This Jira permission scheme grants browse-projects permission to a public "
                f"principal. This permission scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"permission_public_browse_projects": True},
            remediation_summary="Restrict browse-projects to specific groups or project roles unless public access is intended.",
        ))

    if public_admin is True:
        findings.append(_fc(
            rule_key=_RULE_PERMISSION_SCHEME_PUBLIC_ADMINISTER_PROJECTS, record_id=record_id, record_type=JIRA_PERMISSION_SCHEME,
            severity="high",
            title="Jira permission scheme grants public administer-projects access",
            description=(
                "This Jira permission scheme grants administer-projects permission to a public "
                f"principal. This permission scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"permission_public_administer_projects": True},
            remediation_summary="Remove public administer-projects grants and restrict to project administrators.",
        ))

    if public_sprints is True:
        findings.append(_fc(
            rule_key=_RULE_PERMISSION_SCHEME_PUBLIC_MANAGE_SPRINTS, record_id=record_id, record_type=JIRA_PERMISSION_SCHEME,
            severity="high",
            title="Jira permission scheme grants public manage-sprints access",
            description=(
                "This Jira permission scheme grants manage-sprints permission to a public "
                f"principal. This permission scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"permission_public_manage_sprints": True},
            remediation_summary="Restrict manage-sprints to specific groups or project roles.",
        ))

    if public_create is True:
        findings.append(_fc(
            rule_key=_RULE_PERMISSION_SCHEME_PUBLIC_CREATE_ISSUES, record_id=record_id, record_type=JIRA_PERMISSION_SCHEME,
            severity="high",
            title="Jira permission scheme grants public create-issues access",
            description=(
                "This Jira permission scheme grants create-issues permission to a public "
                f"principal. This permission scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"permission_public_create_issues": True},
            remediation_summary="Restrict create-issues to authenticated, scoped principals unless public intake is intended.",
        ))

    if public_transition is True:
        findings.append(_fc(
            rule_key=_RULE_PERMISSION_SCHEME_PUBLIC_TRANSITION_ISSUES, record_id=record_id, record_type=JIRA_PERMISSION_SCHEME,
            severity="medium",
            title="Jira permission scheme grants public transition-issues access",
            description=(
                "This Jira permission scheme grants transition-issues permission to a public "
                f"principal. This permission scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"permission_public_transition_issues": True},
            remediation_summary="Restrict transition-issues to specific groups or project roles.",
        ))

    if unknown_holder_count is not None and unknown_holder_count > 0:
        findings.append(_fc(
            rule_key=_RULE_PERMISSION_SCHEME_UNKNOWN_HOLDER, record_id=record_id, record_type=JIRA_PERMISSION_SCHEME,
            severity="medium",
            title="Jira permission scheme has grants with unrecognised holder types",
            description=(
                "This Jira permission scheme has one or more grants whose holder type could "
                f"not be classified. This permission scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"permission_unknown_holder_count": unknown_holder_count},
            remediation_summary="Review unclassified grant holder types to confirm they are intended.",
        ))

    if high_privilege_count is not None and high_privilege_count > _HIGH_PRIVILEGE_GRANT_THRESHOLD:
        findings.append(_fc(
            rule_key=_RULE_PERMISSION_SCHEME_HIGH_PRIVILEGE_GRANTS, record_id=record_id, record_type=JIRA_PERMISSION_SCHEME,
            severity="medium",
            title="Jira permission scheme has many public high-privilege grants",
            description=(
                "This Jira permission scheme grants many high-privilege permissions to public "
                f"principals. This permission scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"permission_high_privilege_grant_count": high_privilege_count},
            remediation_summary="Review high-privilege grants and restrict them to specific administrators.",
        ))

    if public_grant_count is not None and public_grant_count > _HIGH_PUBLIC_GRANT_THRESHOLD:
        findings.append(_fc(
            rule_key=_RULE_PERMISSION_SCHEME_HIGH_PUBLIC_GRANT_COUNT, record_id=record_id, record_type=JIRA_PERMISSION_SCHEME,
            severity="medium",
            title="Jira permission scheme has a high public-grant count",
            description=(
                "This Jira permission scheme has many grants to public principals. This "
                f"permission scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"permission_public_grant_count": public_grant_count},
            remediation_summary="Review public grants and restrict them to specific groups or project roles.",
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

    # ── M86C notification recipient posture ────────────────────────────────
    unknown_recipient_count = _int_opt(record, "notification_unknown_recipient_count")
    event_count = _int_opt(record, "notification_event_count")

    if unknown_recipient_count is not None and unknown_recipient_count > 0:
        findings.append(_fc(
            rule_key=_RULE_NOTIFICATION_SCHEME_UNKNOWN_RECIPIENTS, record_id=record_id, record_type=JIRA_NOTIFICATION_SCHEME,
            severity="medium",
            title="Jira notification scheme has unrecognised recipient types",
            description=(
                "This Jira notification scheme has one or more recipients whose type could "
                f"not be classified. This notification scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"notification_unknown_recipient_count": unknown_recipient_count},
            remediation_summary="Review unclassified recipient types to confirm they are intended.",
        ))

    if event_count is not None and event_count > _HIGH_NOTIFICATION_EVENT_THRESHOLD:
        findings.append(_fc(
            rule_key=_RULE_NOTIFICATION_SCHEME_HIGH_EVENT_COUNT, record_id=record_id, record_type=JIRA_NOTIFICATION_SCHEME,
            severity="low",
            title="Jira notification scheme has a high event count",
            description=(
                f"This Jira notification scheme configures notifications across many events. This notification scheme posture may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"notification_event_count": event_count},
            remediation_summary="Review configured events and trim notifications that are not needed.",
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

    # ── M86C screen scheme mapping posture ─────────────────────────────────
    unmapped_screen_count = _int_opt(record, "screen_unmapped_screen_count")

    if unmapped_screen_count is not None and unmapped_screen_count > 0:
        findings.append(_fc(
            rule_key=_RULE_SCREEN_SCHEME_UNMAPPED_SCREENS, record_id=record_id, record_type=JIRA_SCREEN_SCHEME,
            severity="low",
            title="Jira screen scheme has unmapped operation slots",
            description=(
                "This Jira screen scheme has one or more operation slots (default, create, "
                f"edit, view) without a mapped screen. This screen scheme configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"screen_unmapped_screen_count": unmapped_screen_count},
            remediation_summary="Map a screen to each operation slot, or confirm the default screen is intended.",
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

    # ── M86C webhook event-scope posture ───────────────────────────────────
    # NOTE: jira_webhook_empty_or_broad_jql is intentionally NOT added — the
    # existing jira_webhook_no_jql_filter rule already covers broad JQL scope.
    has_comment_events = _bool(record, "webhook_has_comment_events")
    has_attachment_events = _bool(record, "webhook_has_attachment_events")
    has_sprint_events = _bool(record, "webhook_has_sprint_events")
    has_worklog_events = _bool(record, "webhook_has_worklog_events")
    all_issue_events = _bool(record, "webhook_all_issue_events")

    if has_comment_events is True:
        findings.append(_fc(
            rule_key=_RULE_WEBHOOK_COMMENT_EVENT_SCOPE, record_id=record_id, record_type=JIRA_WEBHOOK,
            severity="medium",
            title="Jira webhook subscribes to comment events",
            description=(
                "This Jira webhook subscribes to comment events, which can deliver comment "
                f"activity to an external endpoint. This webhook configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"webhook_has_comment_events": True},
            remediation_summary="Confirm comment event delivery to this endpoint is intended.",
        ))

    if has_attachment_events is True:
        findings.append(_fc(
            rule_key=_RULE_WEBHOOK_ATTACHMENT_EVENT_SCOPE, record_id=record_id, record_type=JIRA_WEBHOOK,
            severity="medium",
            title="Jira webhook subscribes to attachment events",
            description=(
                "This Jira webhook subscribes to attachment events, which can deliver "
                f"attachment activity to an external endpoint. This webhook configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"webhook_has_attachment_events": True},
            remediation_summary="Confirm attachment event delivery to this endpoint is intended.",
        ))

    if has_sprint_events is True:
        findings.append(_fc(
            rule_key=_RULE_WEBHOOK_SPRINT_EVENT_SCOPE, record_id=record_id, record_type=JIRA_WEBHOOK,
            severity="low",
            title="Jira webhook subscribes to sprint events",
            description=(
                f"This Jira webhook subscribes to sprint events. This webhook configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"webhook_has_sprint_events": True},
            remediation_summary="Confirm sprint event delivery to this endpoint is intended.",
        ))

    if has_worklog_events is True:
        findings.append(_fc(
            rule_key=_RULE_WEBHOOK_WORKLOG_EVENT_SCOPE, record_id=record_id, record_type=JIRA_WEBHOOK,
            severity="low",
            title="Jira webhook subscribes to worklog events",
            description=(
                f"This Jira webhook subscribes to worklog events. This webhook configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"webhook_has_worklog_events": True},
            remediation_summary="Confirm worklog event delivery to this endpoint is intended.",
        ))

    if all_issue_events is True:
        findings.append(_fc(
            rule_key=_RULE_WEBHOOK_ALL_ISSUE_EVENTS, record_id=record_id, record_type=JIRA_WEBHOOK,
            severity="medium",
            title="Jira webhook subscribes to all issue lifecycle events",
            description=(
                "This Jira webhook subscribes to all issue lifecycle events (created, "
                f"updated, and deleted). This broad webhook scope may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"webhook_all_issue_events": True},
            remediation_summary="Subscribe only to the specific issue events required by the integration.",
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

    # ── M86C automation action posture ─────────────────────────────────────
    # NOTE: jira_automation_rule_global_scope already exists (M86B) and covers
    # the global scope case, so no new workspace-scope rule is added here.
    has_web_request = _bool(record, "automation_has_web_request_action")
    has_email = _bool(record, "automation_has_email_action")
    has_external = _bool(record, "automation_has_external_action")
    has_comment = _bool(record, "automation_has_comment_action")
    action_count = _int_opt(record, "automation_action_count")
    branch_count = _int_opt(record, "automation_branch_count")

    if has_web_request is True:
        findings.append(_fc(
            rule_key=_RULE_AUTOMATION_RULE_WEB_REQUEST_ACTION, record_id=record_id, record_type=JIRA_AUTOMATION_RULE,
            severity="high",
            title="Jira automation rule sends outbound web requests",
            description=(
                "This Jira automation rule includes a send-web-request action, which can "
                f"deliver data to an external endpoint. This automation rule configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"automation_has_web_request_action": True},
            remediation_summary="Confirm the outbound web-request destination and payload scope are intended.",
        ))

    if has_email is True:
        findings.append(_fc(
            rule_key=_RULE_AUTOMATION_RULE_EMAIL_ACTION, record_id=record_id, record_type=JIRA_AUTOMATION_RULE,
            severity="medium",
            title="Jira automation rule sends email",
            description=(
                "This Jira automation rule includes a send-email action. This automation "
                f"rule configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"automation_has_email_action": True},
            remediation_summary="Confirm the email recipients and content of the automation are intended.",
        ))

    if has_external is True:
        findings.append(_fc(
            rule_key=_RULE_AUTOMATION_RULE_EXTERNAL_ACTION, record_id=record_id, record_type=JIRA_AUTOMATION_RULE,
            severity="high",
            title="Jira automation rule sends to an external integration",
            description=(
                "This Jira automation rule includes an action that delivers to an external "
                f"integration. This automation rule configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"automation_has_external_action": True},
            remediation_summary="Confirm the external integration destination and data scope are intended.",
        ))

    if has_comment is True:
        findings.append(_fc(
            rule_key=_RULE_AUTOMATION_RULE_COMMENT_ACTION, record_id=record_id, record_type=JIRA_AUTOMATION_RULE,
            severity="low",
            title="Jira automation rule posts comments",
            description=(
                f"This Jira automation rule includes a comment action. This automation rule configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"automation_has_comment_action": True},
            remediation_summary="Confirm automated comments are intended for the targeted issues.",
        ))

    if action_count is not None and action_count > _HIGH_AUTOMATION_ACTION_THRESHOLD:
        findings.append(_fc(
            rule_key=_RULE_AUTOMATION_RULE_HIGH_ACTION_COUNT, record_id=record_id, record_type=JIRA_AUTOMATION_RULE,
            severity="medium",
            title="Jira automation rule has a high action count",
            description=(
                f"This Jira automation rule includes many actions. This automation rule configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"automation_action_count": action_count},
            remediation_summary="Review the rule's actions and split or simplify where appropriate.",
        ))

    if branch_count is not None and branch_count > _HIGH_AUTOMATION_BRANCH_THRESHOLD:
        findings.append(_fc(
            rule_key=_RULE_AUTOMATION_RULE_HIGH_BRANCH_COUNT, record_id=record_id, record_type=JIRA_AUTOMATION_RULE,
            severity="medium",
            title="Jira automation rule has a high branch count",
            description=(
                f"This Jira automation rule includes many branches. This automation rule configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"automation_branch_count": branch_count},
            remediation_summary="Review the rule's branches and simplify where appropriate.",
        ))

    if scope_category and scope_category.lower() == "multi-project":
        findings.append(_fc(
            rule_key=_RULE_AUTOMATION_RULE_MULTI_PROJECT_SCOPE, record_id=record_id, record_type=JIRA_AUTOMATION_RULE,
            severity="medium",
            title="Jira automation rule spans multiple projects",
            description=(
                "This Jira automation rule is scoped to multiple projects. Broad automation "
                f"scope may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"automation_scope_category": scope_category},
            remediation_summary="Confirm the multi-project scope is intended, or narrow to a single project.",
        ))

    if scope_category and scope_category.lower() == "unknown":
        findings.append(_fc(
            rule_key=_RULE_AUTOMATION_RULE_UNKNOWN_SCOPE, record_id=record_id, record_type=JIRA_AUTOMATION_RULE,
            severity="low",
            title="Jira automation rule scope category is unknown",
            description=(
                f"The connector could not classify the Jira automation rule scope. This automation rule configuration may require review. {_DOES_NOT_CONFIRM}"
            ),
            extra_evidence={"automation_scope_category": scope_category},
            remediation_summary="Review the automation rule scope to confirm it is correctly configured.",
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
