"""Clerk certification manifest (message 6 of N).

Generic discovery is fully sufficient for Clerk — no adapter needed.
Clerk is registered in the capability matrix as maturity='partial'.
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
    "clerk_application",
    "clerk_auth_strategy",
    "clerk_domain",
    "clerk_email_sms_settings",
    "clerk_instance_settings",
    "clerk_jwt_template",
    "clerk_organization_settings",
    "clerk_redirect_url_config",
    "clerk_session_policy",
    "clerk_webhook_endpoint",
)

_FINDING_RULE_IDS = (
    "clerk_application_many_allowed_origins",
    "clerk_application_many_redirect_urls",
    "clerk_application_mfa_not_required",
    "clerk_application_oauth_without_mfa",
    "clerk_application_password_without_mfa",
    "clerk_application_saml_without_mfa",
    "clerk_application_sign_up_enabled",
    "clerk_auth_strategy_mfa_not_required",
    "clerk_auth_strategy_password_without_mfa",
    "clerk_domain_ssl_disabled",
    "clerk_domain_unverified",
    "clerk_email_sms_custom_sender_present",
    "clerk_instance_mfa_disabled",
    "clerk_instance_password_without_mfa",
    "clerk_instance_sign_up_enabled",
    "clerk_jwt_template_audience_missing",
    "clerk_jwt_template_custom_claims_present",
    "clerk_jwt_template_issuer_missing",
    "clerk_jwt_template_long_lifetime",
    "clerk_jwt_template_many_claims",
    "clerk_org_admin_role_missing",
    "clerk_org_high_permission_count",
    "clerk_org_high_role_count",
    "clerk_org_invitations_enabled",
    "clerk_org_verified_domains_not_required",
    "clerk_redirect_url_custom_scheme_present",
    "clerk_redirect_url_localhost_present",
    "clerk_redirect_url_non_https",
    "clerk_redirect_url_wildcard_present",
    "clerk_session_device_tracking_disabled",
    "clerk_session_inactivity_timeout_extended",
    "clerk_session_lifetime_extended",
    "clerk_session_long_lifetime_without_single_session",
    "clerk_session_reverification_disabled",
    "clerk_session_single_session_disabled",
    "clerk_session_token_rotation_disabled",
    "clerk_webhook_broad_event_scope",
    "clerk_webhook_endpoint_disabled",
    "clerk_webhook_non_https",
    "clerk_webhook_without_signing",
)

CLERK_MANIFEST = ProviderCertificationManifest(
    provider_id="clerk",
    display_name="Clerk",
    category="identity",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=False,
    credential_fields=("clerk_frontend_api_url", "clerk_secret_key"),
    sensitive_credential_fields=("clerk_secret_key",),
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
    expected_frontend_form="ClerkIntegrationForm.tsx",
    expected_reconnect=False,
    prohibited_dependencies=(),
    known_limitations=(
        "Domains, redirect URLs, and webhook endpoints are tracked via status/posture booleans only — raw domain names, URL strings, and webhook secrets are never ingested.",
        "JWT templates are tracked via name/claims-count/lifetime only — template body content is never ingested.",
        "Session tokens and session IDs are never ingested — only session policy lifetime categories.",
        "No reconnect function or dispatch is wired for Clerk yet.",
        "No false-removal suppression function exists for Clerk yet.",
    ),
    evidence_test_files=(
        "tests/test_clerk_provider_depth_qa.py",
        "tests/test_clerk_provider_depth_qa.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="clerk",
            test_file="tests/test_clerk_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=69,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="clerk",
            test_file="tests/test_clerk_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=69,
            quality="direct",
        ),
    ),
    capability_evidence=(
        CapabilityEvidenceDeclaration(
            capability="security_findings",
            supporting_record_types=("clerk_domain", "clerk_webhook_endpoint", "clerk_jwt_template", "clerk_redirect_url_config"),
            supporting_finding_rule_ids=_FINDING_RULE_IDS,
            evidence_tests=("tests/test_clerk_provider_depth_qa.py",),
            limitation_note="Posture/boolean metadata only — never raw domains, URLs, secrets, session tokens, or template bodies.",
        ),
    ),
)

register_manifest(CLERK_MANIFEST)
