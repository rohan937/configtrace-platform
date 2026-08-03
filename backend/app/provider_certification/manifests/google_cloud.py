"""Google Cloud certification manifest (message 6 of N).

Generic discovery is fully sufficient for Google Cloud — no adapter needed.
Google Cloud is registered in the capability matrix as maturity='partial'.
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
    "google_cloud_firewall_rule",
    "google_cloud_gke_cluster",
    "google_cloud_iam_policy_summary",
    "google_cloud_project",
    "google_cloud_run_service",
    "google_cloud_secret_manager_summary",
    "google_cloud_service_account_key_summary",
    "google_cloud_sql_instance",
    "google_cloud_storage_bucket",
    "google_cloud_vpc_network",
)

_FINDING_RULE_IDS = (
    "google_cloud_firewall_public_admin_ingress",
    "google_cloud_firewall_public_broad_ingress",
    "google_cloud_firewall_rule_no_targets",
    "google_cloud_gke_legacy_abac_enabled",
    "google_cloud_gke_network_policy_disabled",
    "google_cloud_gke_public_control_plane",
    "google_cloud_gke_shielded_nodes_disabled",
    "google_cloud_gke_workload_identity_disabled",
    "google_cloud_iam_broad_privileged_role",
    "google_cloud_iam_public_member",
    "google_cloud_run_all_ingress",
    "google_cloud_run_public_invoker",
    "google_cloud_secret_manager_auto_replication_without_cmek",
    "google_cloud_service_account_old_keys",
    "google_cloud_service_account_user_managed_keys",
    "google_cloud_sql_backups_disabled",
    "google_cloud_sql_deletion_protection_disabled",
    "google_cloud_sql_public_network_access",
    "google_cloud_sql_weak_tls",
    "google_cloud_storage_public_access_prevention_disabled",
    "google_cloud_storage_retention_not_locked",
    "google_cloud_storage_uniform_access_disabled",
    "google_cloud_storage_versioning_disabled",
)

GOOGLE_CLOUD_MANIFEST = ProviderCertificationManifest(
    provider_id="google_cloud",
    display_name="Google Cloud",
    category="cloud",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=False,
    credential_fields=("google_cloud_project_id", "google_cloud_service_account_json"),
    sensitive_credential_fields=("google_cloud_service_account_json",),
    authentication_model="service_account",
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
    expected_frontend_form="GoogleCloudIntegrationForm.tsx",
    expected_reconnect=False,
    prohibited_dependencies=(),
    known_limitations=(
        "No resource contents are ingested — only project/IAM-policy-summary/VPC/firewall/storage-bucket configuration metadata.",
        "IAM principals are bucketed by type and counted only — service account emails and member identifiers are never stored.",
        "The connector performs read-only operations and never performs a write/delete operation against any Google Cloud API.",
        "No reconnect function or dispatch is wired for Google Cloud yet.",
        "No false-removal suppression function exists for Google Cloud yet.",
    ),
    evidence_test_files=(
        "tests/test_google_cloud_provider_depth_qa.py",
        "tests/test_google_cloud_provider_depth_qa.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="google_cloud",
            test_file="tests/test_google_cloud_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=26,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="google_cloud",
            test_file="tests/test_google_cloud_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=26,
            quality="direct",
        ),
    ),
    capability_evidence=(
        CapabilityEvidenceDeclaration(
            capability="security_findings",
            supporting_record_types=("google_cloud_firewall_rule", "google_cloud_iam_policy_summary", "google_cloud_storage_bucket", "google_cloud_vpc_network"),
            supporting_finding_rule_ids=_FINDING_RULE_IDS,
            evidence_tests=("tests/test_google_cloud_provider_depth_qa.py",),
            limitation_note="Configuration/posture metadata only — never resource contents; principal identifiers are tracked as counts, never emails/IDs.",
        ),
    ),
)

register_manifest(GOOGLE_CLOUD_MANIFEST)
