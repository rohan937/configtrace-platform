"""Okta certification manifest (message 2 of N).

Derived from the real Okta launch arc (messages 1-8 of 8, culminating in
``tests/reports/okta_provider_certification.md``) — every field below was
independently re-derived from discovered repository state (schema
constants, registry/confidence/pack/coverage dicts, diff_service tracked
fields and removal-suppression function, capability matrix entry) rather
than copied from that Markdown report or from memory. See
``test_provider_certification_okta.py`` for the tests that confirm
discovery matches every field exactly.
"""

from __future__ import annotations

from app.provider_certification.models import ProviderCertificationManifest
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "okta_organization",
    "okta_api_capability",
    "okta_user",
    "okta_group",
    "okta_group_membership",
    "okta_application",
    "okta_application_user_assignment",
    "okta_application_group_assignment",
    "okta_policy",
    "okta_policy_rule",
    "okta_authenticator",
    "okta_admin_role",
    "okta_user_admin_role_assignment",
    "okta_group_admin_role_assignment",
    "okta_privileged_identity",
    "okta_privileged_group",
)

_DERIVED_RECORD_TYPES = (
    "okta_privileged_identity",
    "okta_privileged_group",
)

_SECURITY_FINDING_RULE_IDS = (
    "okta_admin_role_broad_resource_set",
    "okta_app_assigned_to_everyone_group",
    "okta_broad_allow_rule_without_mfa",
    "okta_broad_privileged_group",
    "okta_custom_admin_role_high_risk",
    "okta_deprovisioned_identity_retains_admin_privilege",
    "okta_deprovisioned_user_retains_app_assignment",
    "okta_dormant_privileged_identity",
    "okta_high_tier_admin_assigned",
    "okta_never_used_privileged_identity",
    "okta_oidc_custom_scheme_redirect_non_native",
    "okta_oidc_http_redirect",
    "okta_oidc_wildcard_redirect",
    "okta_password_policy_no_complexity",
    "okta_password_policy_no_history",
    "okta_password_policy_no_lockout",
    "okta_password_policy_weak_min_length",
    "okta_phishing_resistant_not_required",
    "okta_privileged_group_grants_high_tier_admin",
    "okta_privileged_group_grants_super_admin",
    "okta_saml_assertion_signing_disabled",
    "okta_saml_response_signing_disabled",
    "okta_signon_mfa_not_required",
    "okta_signon_mfa_optional",
    "okta_super_admin_assigned",
    "okta_suspended_identity_retains_admin_privilege",
    "okta_suspended_user_retains_app_assignment",
    "okta_unscoped_admin_role_assignment",
    "okta_weak_authenticator_enabled",
    "okta_weak_token_endpoint_auth",
)

OKTA_MANIFEST = ProviderCertificationManifest(
    provider_id="okta",
    display_name="Okta",
    category="auth",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=True,
    credential_fields=("okta_org_url", "okta_api_token"),
    sensitive_credential_fields=("okta_api_token",),
    authentication_model="api_token",
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
        "tenant_wide_family_completeness",
        "per_group_membership_completeness",
        "per_app_user_assignment_completeness",
        "per_app_group_assignment_completeness",
        "per_policy_rule_completeness",
        "derived_privileged_identity_group_completeness",
    ),
    false_removal_scopes=(
        "tenant_wide_family_completeness",
        "per_group_membership_completeness",
        "per_app_user_assignment_completeness",
        "per_app_group_assignment_completeness",
        "per_policy_rule_completeness",
        "derived_privileged_identity_group_completeness",
    ),
    expected_frontend_form="OktaIntegrationForm.tsx",
    expected_reconnect=True,
    allowed_dependencies=("httpx",),
    prohibited_dependencies=("okta", "okta-sdk-python"),
    required_env_vars=(),
    prohibited_env_vars=("OKTA_API_TOKEN", "OKTA_ORG_URL", "OKTA_ORGANIZATION"),
    known_limitations=(
        "No activity/System Log ingestion, activity signals, risk x activity correlations, demo seed/clear, "
        "case reporting, or evidence timeline/graph — Okta's security stack is drift + Security Findings only, "
        "the same dual-stack scope as Kubernetes",
        "OAuth 2.0 service-app (client_credentials with private key/DPoP) authentication is not implemented — "
        "API-token auth is the officially supported minimal-privilege pattern for this use case",
        "Raw System Log payloads, passwords, password hashes, recovery answers, MFA secrets, OTP seeds, "
        "session/refresh/access tokens, and private keys are permanently unsupported",
        "Custom admin roles / resource-set edge cases may be unreadable under a least-privileged (non-Super-Admin) "
        "token — reported as denied/unavailable in coverage diagnostics, never treated as invalid",
        "Frontend reconnect UI (ReconnectIntegrationModal) does not yet support Okta's two-field (org URL + API "
        "token) credential shape — backend reconnect_credentials_okta() and router branch are fully implemented "
        "and tested at the API layer; this is a pre-existing gap shared by most non-original-8 providers",
    ),
    evidence_test_files=(
        "tests/test_okta_change_classification.py",
        "tests/test_okta_change_parity.py",
        "tests/test_okta_partial_sync.py",
        "tests/test_okta_pagination_reliability.py",
        "tests/test_okta_scale_reliability.py",
        "tests/test_okta_security_finding_parity.py",
        "tests/test_okta_security_findings_reachability.py",
        "tests/test_okta_provider_depth_qa.py",
        "tests/test_okta_integration_creation.py",
    ),
    evidence_reports=(
        "tests/reports/okta_provider_certification.md",
        "tests/reports/okta_provider_depth_matrix.md",
        "tests/reports/okta_reliability_change_matrix.md",
        "tests/reports/okta_security_findings_matrix.md",
    ),
)

register_manifest(OKTA_MANIFEST)
