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
    # M86C — safe board scope posture (no raw JQL stored)
    board_filter_present: bool
    board_jql_filter_broad: bool
    board_column_count: int
    board_quick_filter_count: int
    board_swimlane_strategy_category: str


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
    # M86C — safe workflow structure posture (counts/booleans only)
    workflow_has_done_status: bool
    workflow_has_in_progress_status: bool
    workflow_transition_rule_count: int
    workflow_validator_count: int
    workflow_condition_count: int
    workflow_post_function_count: int
    workflow_orphan_status_count: int
    workflow_status_category_count: int


class JiraWorkflowSchemeRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    workflow_scheme_project_count: int
    workflow_scheme_default_present: bool
    # M86C — safe workflow scheme mapping posture (counts only)
    workflow_scheme_workflow_count: int
    workflow_scheme_issue_type_mapping_count: int
    workflow_scheme_unmapped_issue_type_count: int


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
    # M86C — safe public/high-privilege grant posture (booleans/counts only)
    permission_public_browse_projects: bool
    permission_public_administer_projects: bool
    permission_public_manage_sprints: bool
    permission_public_create_issues: bool
    permission_public_transition_issues: bool
    permission_unknown_holder_count: int
    permission_high_privilege_grant_count: int
    permission_public_grant_count: int


class JiraNotificationSchemeRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    notification_count: int
    notification_email_recipient_count: int
    notification_group_recipient_count: int
    notification_project_role_recipient_count: int
    # M86C — safe notification recipient posture (counts only)
    notification_all_watchers_recipient_count: int
    notification_current_assignee_recipient_count: int
    notification_reporter_recipient_count: int
    notification_unknown_recipient_count: int
    notification_event_count: int
    notification_public_recipient_count: int


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
    # M86C — safe screen scheme mapping posture (counts only)
    screen_tab_count: int
    screen_unmapped_screen_count: int


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
    # M86C — safe webhook event-scope posture (booleans/category only)
    webhook_has_issue_events: bool
    webhook_has_comment_events: bool
    webhook_has_attachment_events: bool
    webhook_has_project_events: bool
    webhook_has_sprint_events: bool
    webhook_has_worklog_events: bool
    webhook_all_issue_events: bool
    webhook_jql_empty_or_broad: bool
    webhook_event_scope_category: str


class JiraAutomationRuleRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    automation_enabled: bool
    automation_trigger_type_category: str
    automation_component_count: int
    automation_scope_category: str
    # M86C — safe automation action posture (counts/booleans/category only)
    automation_action_count: int
    automation_condition_count: int
    automation_branch_count: int
    automation_has_web_request_action: bool
    automation_has_email_action: bool
    automation_has_external_action: bool
    automation_has_comment_action: bool
    automation_recently_updated: bool
