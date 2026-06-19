from __future__ import annotations

from typing import Optional

from typing_extensions import TypedDict

# ── Record type constants ─────────────────────────────────────────────────────
LINEAR_WORKSPACE = "linear_workspace"
LINEAR_TEAM = "linear_team"
LINEAR_PROJECT = "linear_project"
LINEAR_WORKFLOW_STATE = "linear_workflow_state"
LINEAR_LABEL = "linear_label"
LINEAR_WEBHOOK = "linear_webhook"
LINEAR_VIEW = "linear_view"
LINEAR_CYCLE = "linear_cycle"
LINEAR_INTEGRATION = "linear_integration"

LINEAR_RECORD_TYPES: frozenset[str] = frozenset(
    {
        LINEAR_WORKSPACE,
        LINEAR_TEAM,
        LINEAR_PROJECT,
        LINEAR_WORKFLOW_STATE,
        LINEAR_LABEL,
        LINEAR_WEBHOOK,
        LINEAR_VIEW,
        LINEAR_CYCLE,
        LINEAR_INTEGRATION,
    }
)


# ── TypedDict schemas ─────────────────────────────────────────────────────────


class LinearWorkspaceRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    resource_name: str
    url_key_present: bool
    logo_present: bool


class LinearTeamRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    resource_name: str
    private_team: bool
    team_visibility_category: str
    member_count_category: str
    project_count: int
    auto_archive_enabled: bool
    cycle_enabled: bool
    cycle_duration_category: str


class LinearProjectRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    resource_name: str
    project_status_category: str
    project_health_category: str
    lead_present: bool
    member_count_category: str
    issue_count_category: str


class LinearWorkflowStateRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    resource_name: str
    state_type_category: str
    position_category: str
    team_id: Optional[str]


class LinearLabelRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    resource_name: str
    is_group_label: bool
    parent_id_present: bool
    team_id: Optional[str]


class LinearWebhookRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    webhook_resource_types_count: int
    webhook_enabled: bool
    webhook_secret_present: bool
    webhook_url_present: bool
    webhook_url_scheme_category: str
    team_id: Optional[str]


class LinearViewRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    resource_name: str
    view_shared: bool
    filter_count_category: str
    team_id: Optional[str]


class LinearCycleRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    resource_name: str
    active: bool
    team_id: Optional[str]
    issue_count_category: str


class LinearIntegrationRecord(TypedDict):
    record_type: str
    provider: str
    record_id: str
    resource_id: str
    integration_type_category: str
    integration_enabled: bool
    team_id: Optional[str]
