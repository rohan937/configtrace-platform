"""Terraform Cloud connector schema (M88A).

Defines record type constants, the frozenset of all known record types, and
TypedDict schemas for each safe normalized record that the Terraform Cloud
connector produces. All records contain only booleans, counts, categories, and
opaque IDs — never organization names, workspace names, project names, variable
names or values, state file contents, plan/apply logs, VCS URLs, team names,
user emails, or customer infrastructure data.
"""

from __future__ import annotations

from typing import Optional

from typing_extensions import TypedDict

# ── Record type constants ─────────────────────────────────────────────────────

TERRAFORM_CLOUD_ORGANIZATION = "terraform_cloud_organization"
TERRAFORM_CLOUD_WORKSPACE = "terraform_cloud_workspace"
TERRAFORM_CLOUD_PROJECT = "terraform_cloud_project"
TERRAFORM_CLOUD_VARIABLE_SET = "terraform_cloud_variable_set"
TERRAFORM_CLOUD_WORKSPACE_VARIABLE_SUMMARY = "terraform_cloud_workspace_variable_summary"
TERRAFORM_CLOUD_POLICY_SET = "terraform_cloud_policy_set"
TERRAFORM_CLOUD_NOTIFICATION_CONFIGURATION = "terraform_cloud_notification_configuration"
TERRAFORM_CLOUD_TEAM_ACCESS_SUMMARY = "terraform_cloud_team_access_summary"
TERRAFORM_CLOUD_RUN_TRIGGER = "terraform_cloud_run_trigger"
TERRAFORM_CLOUD_STATE_VERSION_SUMMARY = "terraform_cloud_state_version_summary"

TERRAFORM_CLOUD_RECORD_TYPES: frozenset[str] = frozenset(
    {
        TERRAFORM_CLOUD_ORGANIZATION,
        TERRAFORM_CLOUD_WORKSPACE,
        TERRAFORM_CLOUD_PROJECT,
        TERRAFORM_CLOUD_VARIABLE_SET,
        TERRAFORM_CLOUD_WORKSPACE_VARIABLE_SUMMARY,
        TERRAFORM_CLOUD_POLICY_SET,
        TERRAFORM_CLOUD_NOTIFICATION_CONFIGURATION,
        TERRAFORM_CLOUD_TEAM_ACCESS_SUMMARY,
        TERRAFORM_CLOUD_RUN_TRIGGER,
        TERRAFORM_CLOUD_STATE_VERSION_SUMMARY,
    }
)


# ── TypedDict schemas ─────────────────────────────────────────────────────────


class TerraformCloudOrganizationRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    organization_resource_id: str
    workspace_count: Optional[int]
    project_count: Optional[int]
    policy_set_count: Optional[int]
    variable_set_count: Optional[int]
    team_count_category: Optional[str]
    sso_enabled: Optional[bool]
    two_factor_requirement_enabled: Optional[bool]
    cost_estimation_enabled: Optional[bool]
    collaborator_auth_policy_category: Optional[str]


class TerraformCloudWorkspaceRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    workspace_resource_id: str
    organization_resource_id: str
    execution_mode_category: str
    terraform_version_category: str
    auto_apply: bool
    file_triggers_enabled: bool
    queue_all_runs: bool
    speculative_enabled: bool
    global_remote_state: bool
    vcs_connected: bool
    working_directory_present: bool
    trigger_prefix_count: int
    run_trigger_count: int
    variable_count: int
    sensitive_variable_count: int
    non_sensitive_variable_count: int
    environment_variable_count: int
    terraform_variable_count: int
    notification_count: int
    team_access_count: int
    current_state_version_present: bool
    latest_run_status_category: Optional[str]


class TerraformCloudProjectRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    project_resource_id: str
    organization_resource_id: str
    workspace_count: Optional[int]
    team_access_count: Optional[int]


class TerraformCloudVariableSetRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    variable_set_resource_id: str
    organization_resource_id: str
    global_scope: bool
    workspace_count: int
    project_count: int
    variable_count: int
    sensitive_variable_count: int
    non_sensitive_variable_count: int
    environment_variable_count: int
    terraform_variable_count: int


class TerraformCloudWorkspaceVariableSummaryRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    workspace_resource_id: str
    variable_count: int
    sensitive_variable_count: int
    non_sensitive_variable_count: int
    environment_variable_count: int
    terraform_variable_count: int
    unprotected_non_sensitive_count: int
    raw_value_never_read: bool


class TerraformCloudPolicySetRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    policy_set_resource_id: str
    organization_resource_id: str
    global_scope: bool
    workspace_count: int
    project_count: int
    policy_count: int
    enforcement_level_category: str
    vcs_connected: bool


class TerraformCloudNotificationConfigurationRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    notification_resource_id: str
    workspace_resource_id: str
    enabled: bool
    destination_type_category: str
    trigger_count: int
    webhook_url_present: bool
    webhook_url_scheme_category: Optional[str]
    token_present: bool


class TerraformCloudTeamAccessSummaryRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    workspace_resource_id: str
    team_access_count: int
    admin_access_count: int
    write_access_count: int
    read_access_count: int
    plan_access_count: int
    custom_permission_count: int


class TerraformCloudRunTriggerRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    run_trigger_resource_id: str
    workspace_resource_id: str
    sourceable_type_category: str


class TerraformCloudStateVersionSummaryRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    workspace_resource_id: str
    state_version_present: bool
    state_version_count_category: str
    raw_state_never_fetched: bool
