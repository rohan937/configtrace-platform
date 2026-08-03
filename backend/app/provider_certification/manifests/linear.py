"""Linear certification manifest (message 6 of N).

Generic discovery is fully sufficient for Linear — no adapter needed.
Linear is registered in the capability matrix as maturity='partial'.
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
    "linear_cycle",
    "linear_integration",
    "linear_label",
    "linear_project",
    "linear_team",
    "linear_view",
    "linear_webhook",
    "linear_workflow_state",
    "linear_workspace",
)

_FINDING_RULE_IDS = (
    "linear_cycle_high_issue_count",
    "linear_integration_disabled",
    "linear_integration_unknown_type",
    "linear_integration_workspace_scoped",
    "linear_label_missing_team_scope",
    "linear_project_high_issue_count",
    "linear_project_no_lead",
    "linear_project_no_members",
    "linear_project_no_team_scope",
    "linear_project_unhealthy",
    "linear_project_unknown_status",
    "linear_team_auto_archive_disabled",
    "linear_team_cycles_disabled",
    "linear_team_long_cycle_duration",
    "linear_team_low_member_count",
    "linear_team_low_workflow_state_count",
    "linear_team_no_backlog_state",
    "linear_team_no_canceled_state",
    "linear_team_no_completed_state",
    "linear_team_no_labels",
    "linear_team_no_projects",
    "linear_team_no_started_state",
    "linear_team_no_webhooks",
    "linear_team_private",
    "linear_view_shared",
    "linear_view_shared_without_team_scope",
    "linear_webhook_attachment_scope",
    "linear_webhook_broad_resource_scope",
    "linear_webhook_disabled",
    "linear_webhook_issue_comment_scope",
    "linear_webhook_no_events",
    "linear_webhook_no_secret_indicator",
    "linear_webhook_non_https",
    "linear_workflow_state_unknown_type",
    "linear_workspace_low_team_count",
    "linear_workspace_missing_logo",
    "linear_workspace_missing_url_key",
    "linear_workspace_no_integrations",
    "linear_workspace_no_webhooks",
)

LINEAR_MANIFEST = ProviderCertificationManifest(
    provider_id="linear",
    display_name="Linear",
    category="devops",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=False,
    credential_fields=("linear_api_key",),
    sensitive_credential_fields=("linear_api_key",),
    authentication_model="api_key",
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
    expected_frontend_form="LinearIntegrationForm.tsx",
    expected_reconnect=False,
    prohibited_dependencies=(),
    known_limitations=(
        "Issue titles, descriptions, and comment bodies are NEVER fetched or stored — only workflow-state enum labels, webhook posture, and team/workspace counts.",
        "Webhook URLs are never stored — only scheme posture (https/non_https/absent).",
        "The API key is never stored on the connector instance.",
        "No reconnect function or dispatch is wired for Linear yet.",
        "No false-removal suppression function exists for Linear yet.",
    ),
    evidence_test_files=(
        "tests/test_linear_provider_depth_qa.py",
        "tests/test_linear_provider_depth_qa.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="linear",
            test_file="tests/test_linear_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=21,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="linear",
            test_file="tests/test_linear_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=21,
            quality="direct",
        ),
    ),
    capability_evidence=(
        CapabilityEvidenceDeclaration(
            capability="security_findings",
            supporting_record_types=("linear_team", "linear_webhook", "linear_workflow_state", "linear_workspace"),
            supporting_finding_rule_ids=_FINDING_RULE_IDS,
            evidence_tests=("tests/test_linear_provider_depth_qa.py",),
            limitation_note="Issue titles/descriptions/comment bodies are never fetched or stored — only workflow/webhook/team configuration metadata and counts.",
        ),
    ),
)

register_manifest(LINEAR_MANIFEST)
