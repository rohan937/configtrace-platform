from __future__ import annotations

from typing import Optional

from typing_extensions import TypedDict

# ── Record type constants ─────────────────────────────────────────────────────
JIRA_SITE = "jira_site"
JIRA_PROJECT = "jira_project"
JIRA_BOARD = "jira_board"
JIRA_WORKFLOW = "jira_workflow"
JIRA_WORKFLOW_SCHEME = "jira_workflow_scheme"
JIRA_PERMISSION_SCHEME = "jira_permission_scheme"
JIRA_NOTIFICATION_SCHEME = "jira_notification_scheme"
JIRA_ISSUE_TYPE_SCHEME = "jira_issue_type_scheme"
JIRA_FIELD_CONFIGURATION_SCHEME = "jira_field_configuration_scheme"
JIRA_SCREEN_SCHEME = "jira_screen_scheme"
JIRA_WEBHOOK = "jira_webhook"
JIRA_AUTOMATION_RULE = "jira_automation_rule"

JIRA_RECORD_TYPES: frozenset[str] = frozenset(
    {
        JIRA_SITE,
        JIRA_PROJECT,
        JIRA_BOARD,
        JIRA_WORKFLOW,
        JIRA_WORKFLOW_SCHEME,
        JIRA_PERMISSION_SCHEME,
        JIRA_NOTIFICATION_SCHEME,
        JIRA_ISSUE_TYPE_SCHEME,
        JIRA_FIELD_CONFIGURATION_SCHEME,
        JIRA_SCREEN_SCHEME,
        JIRA_WEBHOOK,
        JIRA_AUTOMATION_RULE,
    }
)


# ── TypedDict schemas ─────────────────────────────────────────────────────────


class JiraSiteRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    site_url_present: bool
    project_count: Optional[int]
    webhook_count: Optional[int]
    automation_rule_count: Optional[int]


class JiraProjectRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    project_key_present: bool
    project_type_category: str
    project_private: bool
    project_archived: bool
    project_deleted: bool
    project_simplified: bool
    project_style_category: str
    board_count: Optional[int]
    issue_type_count: Optional[int]
    lead_present: bool


class JiraBoardRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    board_type_category: str
    board_location_type_category: str
    project_id: Optional[str]


class JiraWorkflowRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    workflow_status_count: int
    workflow_transition_count: int
    workflow_global_transition_count: int
    workflow_active: bool
    workflow_draft: bool


class JiraWorkflowSchemeRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    workflow_scheme_project_count: int
    workflow_scheme_default_present: bool


class JiraPermissionSchemeRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    permission_grant_count: int
    permission_anonymous_grant_count: int
    permission_anyone_grant_count: int
    permission_logged_in_grant_count: int
    permission_project_role_grant_count: int


class JiraNotificationSchemeRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    notification_count: int
    notification_email_recipient_count: int
    notification_group_recipient_count: int
    notification_project_role_recipient_count: int


class JiraIssueTypeSchemeRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    issue_type_count: int
    default_issue_type_present: bool


class JiraFieldConfigurationSchemeRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    field_configuration_count: int
    required_field_count: int
    hidden_field_count: int


class JiraScreenSchemeRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    screen_count: int
    tab_count: int
    field_count: int


class JiraWebhookRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    webhook_enabled: bool
    webhook_event_count: int
    webhook_url_present: bool
    webhook_url_scheme_category: str
    webhook_jql_filter_present: bool
    webhook_secret_present: bool


class JiraAutomationRuleRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    automation_enabled: bool
    automation_trigger_type_category: str
    automation_component_count: int
    automation_scope_category: str
