"""Snowflake certification manifest (pilot provider, message 1 of N).

Derived from the real Snowflake launch arc (messages 1-8 of 8,
culminating in ``tests/reports/snowflake_provider_certification.md``) —
not copied from that Markdown report. Every field below is independently
checked against discovered repository reality by
``app.provider_certification.gates``.
"""

from __future__ import annotations

from app.provider_certification.models import ProviderCertificationManifest
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "snowflake_account",
    "snowflake_api_capability",
    "snowflake_user",
    "snowflake_account_role",
    "snowflake_database_role",
    "snowflake_user_role_grant",
    "snowflake_role_hierarchy_grant",
    "snowflake_database",
    "snowflake_schema",
    "snowflake_warehouse",
    "snowflake_share",
    "snowflake_object_grant",
    "snowflake_network_policy",
    "snowflake_network_rule",
    "snowflake_authentication_policy",
    "snowflake_security_integration",
    "snowflake_storage_integration",
    "snowflake_external_access_integration",
    "snowflake_privileged_user",
    "snowflake_privileged_role",
    "snowflake_public_exposure",
)

_DERIVED_RECORD_TYPES = (
    "snowflake_privileged_user",
    "snowflake_privileged_role",
    "snowflake_public_exposure",
)

_SECURITY_FINDING_RULE_IDS = (
    "snowflake_custom_role_high_privilege",
    "snowflake_custom_role_manage_grants",
    "snowflake_custom_role_manage_grants_identity_admin",
    "snowflake_disabled_privileged_user",
    "snowflake_future_ownership_grant",
    "snowflake_high_privilege_role_owns_database",
    "snowflake_legacy_service_user",
    "snowflake_legacy_service_user_privileged",
    "snowflake_mfa_optional_for_person_auth",
    "snowflake_mfa_optional_with_password",
    "snowflake_mfa_password_only_scope",
    "snowflake_network_policy_allows_anywhere",
    "snowflake_public_future_broad_privilege",
    "snowflake_public_future_data_access",
    "snowflake_public_future_ownership_grant",
    "snowflake_public_future_write_access",
    "snowflake_role_controls_managed_access_schema",
    "snowflake_role_owns_authentication_policy_high_privilege",
    "snowflake_role_owns_external_access_integration_high_privilege",
    "snowflake_role_owns_network_policy_high_privilege",
    "snowflake_role_owns_security_integration_high_privilege",
    "snowflake_role_owns_storage_integration_high_privilege",
    "snowflake_saml_integration_incomplete_config",
    "snowflake_scim_critical_privilege_run_as",
    "snowflake_scim_high_privilege_run_as",
    "snowflake_service_user_accountadmin",
    "snowflake_user_accountadmin",
    "snowflake_user_can_manage_grants",
    "snowflake_user_high_risk_future_grant",
    "snowflake_user_securityadmin",
    "snowflake_user_sysadmin_or_useradmin",
)

SNOWFLAKE_MANIFEST = ProviderCertificationManifest(
    provider_id="snowflake",
    display_name="Snowflake",
    category="database_backend",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=True,
    credential_fields=(
        "snowflake_account_identifier",
        "snowflake_username",
        "snowflake_programmatic_access_token",
        "snowflake_role",
    ),
    sensitive_credential_fields=("snowflake_programmatic_access_token",),
    authentication_model="programmatic_access_token",
    expected_record_types=_EXPECTED_RECORD_TYPES,
    derived_record_types=_DERIVED_RECORD_TYPES,
    security_finding_rule_ids=_SECURITY_FINDING_RULE_IDS,
    supported_capabilities=("security_findings",),
    unsupported_capabilities=(
        "activity_ingestion",
        "activity_signals",
        "risk_activity_correlations",
        "demo_case_reporting",
    ),
    completeness_scopes=(
        "account_wide_family_completeness",
        "per_database_completeness",
        "per_role_completeness",
        "per_detail_integration_policy_family_completeness",
        "derived_privilege_records",
    ),
    false_removal_scopes=(
        "account_wide_family_completeness",
        "per_database_completeness",
        "per_role_completeness",
        "per_detail_integration_policy_family_completeness",
        "derived_privilege_records",
    ),
    expected_frontend_form="SnowflakeIntegrationForm.tsx",
    expected_reconnect=True,
    allowed_dependencies=("httpx",),
    prohibited_dependencies=("snowflake-connector-python", "snowflake-sqlalchemy", "snowflake-cli"),
    required_env_vars=(),
    prohibited_env_vars=("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PASSWORD", "SNOWFLAKE_PRIVATE_KEY"),
    known_limitations=(
        "No active warehouse required for the current connector request shape",
        "No table/view row (query-result) ingestion",
        "No query-history or login-history ingestion",
        "No runtime session monitoring or anomaly detection",
        "No sensitive-data discovery/classification",
        "No current (non-future) PUBLIC object-grant Finding — only future grants are collected",
        "No SQL API cancellation-endpoint or result-partition pagination usage (unimplemented, documented gap)",
        "No activity ingestion, incident signals, risk x activity correlations, or demo/case tooling (dual-stack scope: drift + Security Findings only)",
        "SHOW/DESCRIBE visibility constrained by whatever the monitoring role can see; some families may remain Partial indefinitely for an intentionally minimal role",
    ),
    evidence_test_files=(
        "tests/test_snowflake_change_classification.py",
        "tests/test_snowflake_change_parity.py",
        "tests/test_snowflake_partial_sync.py",
        "tests/test_snowflake_sql_api_reliability.py",
        "tests/test_snowflake_scale_reliability.py",
        "tests/test_snowflake_provider_depth_qa.py",
        "tests/test_snowflake_integration_creation.py",
    ),
    evidence_reports=(
        "tests/reports/snowflake_reliability_certification.md",
        "tests/reports/snowflake_provider_certification.md",
        "tests/reports/snowflake_provider_depth_matrix.md",
        "tests/reports/snowflake_access_requirement_matrix.md",
    ),
)

register_manifest(SNOWFLAKE_MANIFEST)
