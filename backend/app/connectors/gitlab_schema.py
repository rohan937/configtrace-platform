from __future__ import annotations

from typing import Optional

from typing_extensions import TypedDict

# ── Record type constants ─────────────────────────────────────────────────────
GITLAB_INSTANCE = "gitlab_instance"
GITLAB_PROJECT = "gitlab_project"
GITLAB_GROUP = "gitlab_group"
GITLAB_BRANCH_PROTECTION = "gitlab_branch_protection"
GITLAB_WEBHOOK = "gitlab_webhook"
GITLAB_CI_VARIABLE_SUMMARY = "gitlab_ci_variable_summary"
GITLAB_DEPLOY_KEY_SUMMARY = "gitlab_deploy_key_summary"
GITLAB_RUNNER_SUMMARY = "gitlab_runner_summary"
GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY = "gitlab_merge_request_approval_summary"

GITLAB_RECORD_TYPES: frozenset[str] = frozenset(
    {
        GITLAB_INSTANCE,
        GITLAB_PROJECT,
        GITLAB_GROUP,
        GITLAB_BRANCH_PROTECTION,
        GITLAB_WEBHOOK,
        GITLAB_CI_VARIABLE_SUMMARY,
        GITLAB_DEPLOY_KEY_SUMMARY,
        GITLAB_RUNNER_SUMMARY,
        GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY,
    }
)


# ── TypedDict schemas ─────────────────────────────────────────────────────────


class GitLabInstanceRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    version_present: bool
    revision_present: bool
    enterprise: bool
    project_count: Optional[int]
    group_count: Optional[int]
    two_factor_requirement_enabled: Optional[bool]
    sign_up_enabled: Optional[bool]
    visibility_restriction_category: Optional[str]
    shared_runners_enabled: Optional[bool]


class GitLabProjectRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    visibility_category: str
    archived: bool
    default_branch_present: bool
    merge_requests_enabled: bool
    issues_enabled: bool
    wiki_enabled: bool
    snippets_enabled: bool
    container_registry_enabled: bool
    packages_enabled: Optional[bool]
    shared_runners_enabled: Optional[bool]
    protected_branch_count: Optional[int]
    webhook_count: Optional[int]
    ci_variable_count: Optional[int]
    deploy_key_count: Optional[int]
    approval_rule_count: Optional[int]


class GitLabGroupRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    visibility_category: str
    project_count: Optional[int]
    subgroup_count: Optional[int]
    member_count_category: str
    two_factor_requirement_enabled: Optional[bool]
    membership_lock: Optional[bool]
    shared_runners_setting_category: Optional[str]


class GitLabBranchProtectionRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    project_resource_id: str
    pattern_category: str
    allow_force_push: bool
    code_owner_approval_required: bool
    push_access_level_category: str
    merge_access_level_category: str
    allowed_to_push_count: int
    allowed_to_merge_count: int


class GitLabWebhookRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    owner_resource_id: str
    owner_type: str
    enabled: bool
    url_scheme: str
    url_host_category: str
    ssl_verification_enabled: bool
    secret_token_present: bool
    event_count: int
    push_events: bool
    merge_requests_events: bool
    pipeline_events: bool
    job_events: bool


class GitLabCIVariableSummaryRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    owner_resource_id: str
    owner_type: str
    variable_count: int
    protected_variable_count: int
    masked_variable_count: int
    environment_scoped_count: int
    unprotected_unmasked_count: int


class GitLabDeployKeySummaryRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    project_resource_id: str
    deploy_key_count: int
    write_enabled_count: int
    read_only_count: int
    enabled_count: int


class GitLabRunnerSummaryRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    owner_resource_id: str
    owner_type: str
    runner_count: int
    shared_runner_enabled: bool
    locked_runner_count: int
    paused_runner_count: int
    tagged_runner_count: int
    untagged_runner_count: int


class GitLabMRApprovalSummaryRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    project_resource_id: str
    approval_rule_count: int
    approvals_required: Optional[int]
    code_owner_approval_required: Optional[bool]
    reset_approvals_on_push: Optional[bool]
    disable_overriding_approvers_per_merge_request: Optional[bool]
