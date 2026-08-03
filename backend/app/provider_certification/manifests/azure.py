"""Microsoft Azure certification manifest (message 6 of N).

Generic discovery is fully sufficient for Microsoft Azure — no adapter needed.
Microsoft Azure is registered in the capability matrix as maturity='partial'.
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
    "azure_aks_cluster",
    "azure_app_service",
    "azure_key_vault",
    "azure_network_security_group",
    "azure_resource_group",
    "azure_role_assignment",
    "azure_sql_server",
    "azure_storage_account",
    "azure_subscription",
)

_FINDING_RULE_IDS = (
    "azure_aks_local_accounts_enabled",
    "azure_aks_network_policy_missing",
    "azure_aks_public_api_access",
    "azure_app_service_ftp_enabled",
    "azure_app_service_https_disabled",
    "azure_app_service_public_network_access",
    "azure_app_service_weak_tls",
    "azure_key_vault_public_network_access",
    "azure_key_vault_purge_protection_disabled",
    "azure_key_vault_rbac_disabled",
    "azure_key_vault_soft_delete_disabled",
    "azure_nsg_public_admin_ingress",
    "azure_nsg_public_broad_ingress",
    "azure_role_assignment_broad_privilege",
    "azure_sql_public_network_access",
    "azure_sql_weak_tls",
    "azure_storage_https_only_disabled",
    "azure_storage_public_blob_access",
    "azure_storage_public_network_access",
    "azure_storage_shared_key_enabled",
    "azure_storage_weak_tls",
)

AZURE_MANIFEST = ProviderCertificationManifest(
    provider_id="azure",
    display_name="Microsoft Azure",
    category="cloud",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=False,
    credential_fields=("azure_client_id", "azure_client_secret", "azure_subscription_id", "azure_tenant_id"),
    sensitive_credential_fields=("azure_client_secret",),
    authentication_model="oauth_client_credentials",
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
    expected_frontend_form="AzureIntegrationForm.tsx",
    expected_reconnect=False,
    prohibited_dependencies=(),
    known_limitations=(
        "No resource contents, secrets, packet data, or log data are ingested — only configuration/posture metadata across subscriptions, NSGs, storage accounts, key vaults, role assignments, App Services, SQL Servers, and AKS clusters.",
        "Access tokens are never stored as instance attributes, never returned in records, and never logged.",
        "No reconnect function or dispatch is wired for Azure yet.",
        "No false-removal suppression function exists for Azure yet.",
    ),
    evidence_test_files=(
        "tests/test_azure_provider_depth_qa.py",
        "tests/test_azure_provider_depth_qa.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="azure",
            test_file="tests/test_azure_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=23,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="azure",
            test_file="tests/test_azure_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=23,
            quality="direct",
        ),
    ),
    capability_evidence=(
        CapabilityEvidenceDeclaration(
            capability="security_findings",
            supporting_record_types=("azure_network_security_group", "azure_storage_account", "azure_key_vault", "azure_role_assignment"),
            supporting_finding_rule_ids=_FINDING_RULE_IDS,
            evidence_tests=("tests/test_azure_provider_depth_qa.py",),
            limitation_note="Configuration/posture metadata only — never resource contents, secrets, or packet/log data.",
        ),
    ),
)

register_manifest(AZURE_MANIFEST)
