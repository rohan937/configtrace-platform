"""Terraform Cloud certification manifest (message 6 of N).

Generic discovery is fully sufficient for Terraform Cloud — no adapter needed.
Terraform Cloud is registered in the capability matrix as maturity='partial'.
"""

from __future__ import annotations

from app.provider_certification.models import (
    CapabilityEvidenceDeclaration,
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ProviderCertificationManifest,
)
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "terraform_cloud_notification_configuration",
    "terraform_cloud_organization",
    "terraform_cloud_policy_set",
    "terraform_cloud_project",
    "terraform_cloud_run_trigger",
    "terraform_cloud_state_version_summary",
    "terraform_cloud_team_access_summary",
    "terraform_cloud_variable_set",
    "terraform_cloud_workspace",
    "terraform_cloud_workspace_variable_summary",
)

_FINDING_RULE_IDS = (
    "terraform_cloud_notification_broad_trigger_scope",
    "terraform_cloud_notification_disabled",
    "terraform_cloud_notification_http_webhook",
    "terraform_cloud_notification_token_missing",
    "terraform_cloud_organization_sso_not_enabled",
    "terraform_cloud_organization_two_factor_not_required",
    "terraform_cloud_policy_set_advisory_enforcement",
    "terraform_cloud_policy_set_broad_scope_advisory",
    "terraform_cloud_policy_set_empty",
    "terraform_cloud_policy_set_global_scope",
    "terraform_cloud_policy_set_no_workspace_or_project_scope",
    "terraform_cloud_run_trigger_enabled",
    "terraform_cloud_state_version_present",
    "terraform_cloud_team_admin_access",
    "terraform_cloud_team_custom_permissions",
    "terraform_cloud_team_plan_access",
    "terraform_cloud_team_write_access",
    "terraform_cloud_variable_set_broad_scope",
    "terraform_cloud_variable_set_global_scope",
    "terraform_cloud_variable_set_non_sensitive_variables",
    "terraform_cloud_workspace_agent_execution_mode",
    "terraform_cloud_workspace_auto_apply_enabled",
    "terraform_cloud_workspace_environment_variables_non_sensitive",
    "terraform_cloud_workspace_file_triggers_disabled",
    "terraform_cloud_workspace_global_remote_state_enabled",
    "terraform_cloud_workspace_latest_run_failed",
    "terraform_cloud_workspace_local_execution_mode",
    "terraform_cloud_workspace_many_trigger_prefixes",
    "terraform_cloud_workspace_no_sensitive_variables",
    "terraform_cloud_workspace_non_sensitive_variables_present",
    "terraform_cloud_workspace_queue_all_runs_disabled",
    "terraform_cloud_workspace_run_triggers_present",
    "terraform_cloud_workspace_speculative_plans_disabled",
    "terraform_cloud_workspace_terraform_variables_non_sensitive",
    "terraform_cloud_workspace_unpinned_terraform_version",
    "terraform_cloud_workspace_vcs_connection_missing",
)

TERRAFORM_CLOUD_MANIFEST = ProviderCertificationManifest(
    provider_id="terraform_cloud",
    display_name="Terraform Cloud",
    category="devops",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=False,
    credential_fields=("terraform_cloud_api_token", "terraform_cloud_base_url", "terraform_cloud_organization"),
    sensitive_credential_fields=("terraform_cloud_api_token",),
    authentication_model="api_token",
    expected_record_types=_EXPECTED_RECORD_TYPES,
    security_finding_rule_ids=_FINDING_RULE_IDS,
    supported_capabilities=(
        "security_findings",
        "activity_ingestion",
        "activity_signals",
        "risk_activity_correlations",
        "demo_case_reporting",
    ),
    unsupported_capabilities=(),
    completeness_scopes=(),
    false_removal_scopes=(),
    expected_frontend_form="TerraformCloudIntegrationForm.tsx",
    expected_reconnect=False,
    prohibited_dependencies=(),
    known_limitations=(
        "State file contents are never ingested.",
        "Workspace and team-access variables are tracked via count summaries only — variable names and values are never ingested.",
        "Policy sets are tracked via scope/count/enforcement-level only — policy code is never ingested.",
        "Organization and workspace/project names are never stored — only counts and posture booleans.",
        "No reconnect function or dispatch is wired for Terraform Cloud yet.",
        "No false-removal suppression function exists for Terraform Cloud yet.",
    ),
    evidence_test_files=(
        "tests/test_terraform_cloud_provider_depth_qa.py",
        "tests/test_terraform_cloud_provider_depth_qa.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="terraform_cloud",
            test_file="tests/test_terraform_cloud_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=25,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="terraform_cloud",
            test_file="tests/test_terraform_cloud_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=25,
            quality="direct",
        ),
    ),
    capability_evidence=(
        CapabilityEvidenceDeclaration(
            capability="security_findings",
            supporting_record_types=("terraform_cloud_workspace", "terraform_cloud_policy_set", "terraform_cloud_team_access_summary", "terraform_cloud_workspace_variable_summary"),
            supporting_finding_rule_ids=_FINDING_RULE_IDS,
            evidence_tests=("tests/test_terraform_cloud_provider_depth_qa.py",),
            limitation_note="State file contents, variable names, and variable values are never ingested — only workspace/policy/team count summaries.",
        ),
    ),
)

register_manifest(TERRAFORM_CLOUD_MANIFEST)
