"""Microsoft Entra ID certification manifest (message 2 of N).

Derived from the real Entra launch arc (messages 1-8 of 8, culminating in
``tests/reports/entra_provider_certification.md``) — every field below was
independently re-derived from discovered repository state (schema
constants, registry/confidence/pack/coverage dicts, diff_service tracked
fields and removal-suppression function, capability matrix entry) rather
than copied from that Markdown report or from memory.

Canonical provider_id is ``"entra"`` (confirmed via
``provider_capability_matrix_service.get_provider_capability("entra")``),
not ``microsoft_entra_id`` or ``azure_ad`` — this repository has no
provider aliasing for Entra; see
``test_provider_certification_cross_manifest.py`` for the alias-drift
audit. Distinct from this repository's unrelated ``azure`` (Azure cloud
infrastructure) provider — the two are never merged.
"""

from __future__ import annotations

from app.provider_certification.models import ProviderCertificationManifest
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "entra_organization",
    "entra_api_capability",
    "entra_user",
    "entra_group",
    "entra_group_membership",
    "entra_application",
    "entra_service_principal",
    "entra_application_user_assignment",
    "entra_application_group_assignment",
    "entra_service_principal_app_role_assignment",
    "entra_oauth2_permission_grant",
    "entra_conditional_access_policy",
    "entra_authentication_strength",
    "entra_authentication_method",
    "entra_directory_role",
    "entra_directory_role_assignment",
    "entra_privileged_identity",
    "entra_privileged_group",
    "entra_privileged_service_principal",
)

_DERIVED_RECORD_TYPES = (
    "entra_privileged_identity",
    "entra_privileged_group",
    "entra_privileged_service_principal",
)

_SECURITY_FINDING_RULE_IDS = (
    "entra_application_custom_scheme_redirect_unexpected",
    "entra_application_expired_credential",
    "entra_application_http_redirect",
    "entra_application_wildcard_redirect",
    "entra_authentication_strength_not_phishing_resistant",
    "entra_ca_access_without_mfa",
    "entra_ca_broad_access_without_mfa",
    "entra_ca_legacy_auth_not_blocked",
    "entra_ca_mfa_optional_within_grant_controls",
    "entra_ca_report_only_broad_protection",
    "entra_disabled_guest_retains_high_privilege",
    "entra_disabled_identity_retains_admin_privilege",
    "entra_disabled_service_principal_retains_privilege",
    "entra_disabled_user_retains_application_assignment",
    "entra_dynamic_group_assigned_to_application",
    "entra_external_unverified_app_tenant_wide_consent",
    "entra_global_admin_assigned",
    "entra_group_has_global_admin",
    "entra_group_has_high_privilege",
    "entra_guest_global_admin",
    "entra_guest_has_high_privilege",
    "entra_guest_member_in_privileged_group",
    "entra_high_tier_admin_assigned",
    "entra_privileged_authentication_administrator_assigned",
    "entra_privileged_group_broad_membership",
    "entra_privileged_role_administrator_assigned",
    "entra_role_assignable_group_assigned_to_application",
    "entra_service_principal_assignment_not_required",
    "entra_service_principal_can_grant_arbitrary_permissions",
    "entra_service_principal_can_manage_app_role_assignments",
    "entra_service_principal_can_manage_directory_roles",
    "entra_service_principal_can_modify_authentication_methods",
    "entra_service_principal_can_modify_conditional_access",
    "entra_service_principal_expired_credential",
    "entra_service_principal_has_application_management_permission",
    "entra_service_principal_has_critical_privilege",
    "entra_service_principal_has_directory_write_permission",
    "entra_service_principal_has_group_write_permission",
    "entra_service_principal_has_high_privilege",
    "entra_service_principal_has_user_write_permission",
    "entra_tenant_wide_critical_delegated_consent",
    "entra_tenant_wide_high_risk_delegated_consent",
    "entra_user_scoped_critical_consent",
    "entra_user_scoped_high_risk_consent",
    "entra_weak_authentication_method_enabled",
)

ENTRA_MANIFEST = ProviderCertificationManifest(
    provider_id="entra",
    display_name="Microsoft Entra ID",
    category="auth",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=True,
    credential_fields=("entra_tenant_id", "entra_client_id", "entra_client_secret"),
    sensitive_credential_fields=("entra_client_secret",),
    authentication_model="oauth2_client_credentials",
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
        "per_service_principal_assignment_completeness",
        "derived_privileged_identity_group_service_principal_completeness",
    ),
    false_removal_scopes=(
        "tenant_wide_family_completeness",
        "per_group_membership_completeness",
        "per_service_principal_assignment_completeness",
        "derived_privileged_identity_group_service_principal_completeness",
    ),
    expected_frontend_form="EntraIntegrationForm.tsx",
    expected_reconnect=True,
    allowed_dependencies=("httpx",),
    prohibited_dependencies=("msal", "azure-identity", "msgraph-sdk", "msgraph-core"),
    required_env_vars=(),
    prohibited_env_vars=("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET", "AZURE_CLIENT_SECRET"),
    known_limitations=(
        "No runtime sign-in-event ingestion and no Identity Protection risk-event ingestion — "
        "configuration/posture snapshots only",
        "No per-user authentication-method enumeration (tenant-wide authenticationMethodsPolicy "
        "configuration only)",
        "No exact effective Conditional Access evaluation for a specific sign-in — policy configuration "
        "only, not a policy simulator",
        "No nested/transitive group membership flattening — direct memberships only",
        "PIM eligible-role schedules are NOT modeled — entra_directory_role_assignment is collected via "
        "GET /roleManagement/directory/roleAssignments, which returns only active role assignments; "
        "privileged-identity/group/service-principal derivation and related Security Findings are based "
        "on active assignment state only",
        "No certificate-based ConfigTrace authentication — client secret only",
        "Commercial/global Microsoft cloud only — no GCC, GCC High, DoD, or China (21Vianet) support",
        "No runtime token/session telemetry of any kind",
        "Reconnect UI (ReconnectIntegrationModal) does not yet support Entra's multi-field credential shape "
        "— backend reconnect_credentials_entra() and router branch are fully implemented and tested at the "
        "API layer; this is a pre-existing gap shared by most non-original-8 providers",
        "No activity ingestion, incident signals, risk x activity correlations, or demo/case tooling — "
        "Entra's security stack is drift + Security Findings only, the same dual-stack scope as Okta/Kubernetes",
    ),
    evidence_test_files=(
        "tests/test_entra_change_classification.py",
        "tests/test_entra_change_parity.py",
        "tests/test_entra_partial_sync.py",
        "tests/test_entra_pagination_reliability.py",
        "tests/test_entra_scale_reliability.py",
        "tests/test_entra_security_finding_parity.py",
        "tests/test_entra_security_findings_reachability.py",
        "tests/test_entra_provider_depth_qa.py",
        "tests/test_entra_integration_creation.py",
    ),
    evidence_reports=(
        "tests/reports/entra_provider_certification.md",
        "tests/reports/entra_provider_depth_matrix.md",
        "tests/reports/entra_reliability_change_matrix.md",
        "tests/reports/entra_security_findings_matrix.md",
    ),
)

register_manifest(ENTRA_MANIFEST)
