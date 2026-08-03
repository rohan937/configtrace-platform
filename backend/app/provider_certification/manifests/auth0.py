"""Auth0 certification manifest (message 6 of N).

Generic discovery is fully sufficient for Auth0 — no adapter needed.
Auth0 is registered in the capability matrix as maturity='partial'.
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
    "auth0_action",
    "auth0_application",
    "auth0_connection",
    "auth0_custom_domain",
    "auth0_mfa_factor",
    "auth0_resource_server",
    "auth0_rule",
    "auth0_tenant_settings",
)

_FINDING_RULE_IDS = (
    "auth0_action_not_deployed",
    "auth0_action_secrets_present",
    "auth0_application_callback_missing_https",
    "auth0_application_device_code_grant_enabled",
    "auth0_application_implicit_grant_enabled",
    "auth0_application_localhost_callback",
    "auth0_application_localhost_origin",
    "auth0_application_many_allowed_origins",
    "auth0_application_many_callbacks",
    "auth0_application_many_grant_types",
    "auth0_application_no_callbacks",
    "auth0_application_oidc_non_conformant",
    "auth0_application_origin_missing_https",
    "auth0_application_password_grant_enabled",
    "auth0_application_public_client_credentials_enabled",
    "auth0_application_refresh_grant_without_rotation",
    "auth0_application_token_endpoint_auth_none",
    "auth0_application_weak_jwt_algorithm",
    "auth0_application_wildcard_allowed_origin",
    "auth0_application_wildcard_callback",
    "auth0_application_wildcard_logout_url",
    "auth0_connection_mfa_disabled",
    "auth0_connection_no_enabled_clients",
    "auth0_connection_weak_password_policy",
    "auth0_custom_domain_not_ready",
    "auth0_custom_domain_weak_tls_policy",
    "auth0_mfa_factor_disabled",
    "auth0_public_client_refresh_tokens_enabled",
    "auth0_refresh_token_lifetime_extended",
    "auth0_refresh_token_rotation_disabled",
    "auth0_resource_server_offline_access_enabled",
    "auth0_resource_server_rbac_disabled",
    "auth0_resource_server_token_lifetime_extended",
    "auth0_resource_server_weak_signing_algorithm",
    "auth0_rule_disabled",
    "auth0_rule_large_script",
    "auth0_tenant_dynamic_client_registration_enabled",
    "auth0_tenant_idle_session_lifetime_extended",
    "auth0_tenant_session_lifetime_extended",
)

AUTH0_MANIFEST = ProviderCertificationManifest(
    provider_id="auth0",
    display_name="Auth0",
    category="auth",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=False,
    credential_fields=("auth0_client_id", "auth0_client_secret", "auth0_domain", "auth0_management_api_token"),
    sensitive_credential_fields=("auth0_client_secret", "auth0_management_api_token"),
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
    expected_frontend_form="Auth0IntegrationForm.tsx",
    expected_reconnect=False,
    prohibited_dependencies=(),
    known_limitations=(
        "Rules and Actions are tracked as name/enabled/status/runtime metadata only — script or code content is never ingested.",
        "Applications/clients are tracked via counts and safe fields only — client_secret and other credential material are never ingested.",
        "Connections are tracked via strategy and safe posture only — credentials or end-user data are never ingested.",
        "No reconnect function or dispatch is wired for Auth0 yet.",
        "No false-removal suppression function exists for Auth0 yet.",
    ),
    evidence_test_files=(
        "tests/test_auth0_provider_depth_qa.py",
        "tests/test_auth0_provider_depth_qa.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="auth0",
            test_file="tests/test_auth0_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=27,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="auth0",
            test_file="tests/test_auth0_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=27,
            quality="direct",
        ),
    ),
    capability_evidence=(
        CapabilityEvidenceDeclaration(
            capability="security_findings",
            supporting_record_types=("auth0_rule", "auth0_action", "auth0_connection", "auth0_application"),
            supporting_finding_rule_ids=_FINDING_RULE_IDS,
            evidence_tests=("tests/test_auth0_provider_depth_qa.py",),
            limitation_note="Rule/Action script and code content are never ingested — only enabled/status/runtime metadata.",
        ),
    ),
)

register_manifest(AUTH0_MANIFEST)
