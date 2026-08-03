"""Vercel certification manifest (message 5 of N).

Generic discovery is fully sufficient for Vercel — no adapter needed.
Reconnect is fully wired via the SHARED generic reconnect_credentials()
dispatcher (an inline `elif integration.provider == "vercel":` branch in
integration_service.py), not a dedicated reconnect_credentials_vercel()
function — the same pattern used by GitHub. expected_reconnect=True.
"""

from __future__ import annotations

from app.provider_certification.models import (
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ProviderCertificationManifest,
)
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "vercel_deploy_hook_metadata",
    "vercel_deployment_protection",
    "vercel_domain",
    "vercel_env_var",
    "vercel_project",
)

_FINDING_RULE_IDS = (
    "vercel_deploy_hook_production_branch",
    "vercel_domain_unverified",
    "vercel_env_var_broad_target",
    "vercel_preview_unprotected",
    "vercel_production_branch_missing",
    "vercel_production_branch_unusual",
    "vercel_sensitive_env_var_broad_scope",
)

VERCEL_MANIFEST = ProviderCertificationManifest(
    provider_id="vercel",
    display_name="Vercel",
    category="devops",
    maturity="complete",
    expected_public=True,
    expected_connectable=True,
    expected_live=False,
    credential_fields=("vercel_project_id", "vercel_token"),
    sensitive_credential_fields=("vercel_token",),
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
    expected_frontend_form="VercelIntegrationForm.tsx",
    expected_reconnect=True,
    prohibited_dependencies=(),
    known_limitations=(
        "No source-code ingestion, deployment logs, request analytics, runtime logs, or build output are ingested — only project/domain/environment-variable/deployment-protection CONFIGURATION metadata.",
        "Environment-variable VALUES (secrets) are never ingested — only variable name, target, and type metadata.",
        "No deployment-history ingestion — only the current deployment-protection configuration is tracked.",
        "7 schema-declared record-type constants (vercel_cron_job, vercel_deployment, vercel_edge_config_item, vercel_firewall_rule, vercel_function_runtime, vercel_integration_installation, vercel_team_member) are dispatched by the classifier module but never referenced anywhere in the connector — confirmed by grep, genuinely unimplemented.",
        "Reconnect is wired through the SHARED generic reconnect_credentials() dispatcher's inline branch, not a dedicated reconnect_credentials_vercel() function — the same pattern used by GitHub; both wiring forms count as valid reconnect support.",
        "No false-removal suppression function exists for Vercel yet.",
    ),
    evidence_test_files=(
        "tests/test_vercel_provider_depth_qa.py",
        "tests/test_vercel_risk_audit.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="vercel",
            test_file="tests/test_vercel_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=25,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="vercel",
            test_file="tests/test_vercel_risk_audit.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=30,
            quality="direct",
        ),
    ),
)

register_manifest(VERCEL_MANIFEST)
