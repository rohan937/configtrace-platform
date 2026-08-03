"""Supabase certification manifest (message 4 of N).

Generic discovery is fully sufficient for Supabase — no adapter is
needed. Credential fields (``supabase_access_token``,
``supabase_project_ref``) already carry the ``supabase_`` prefix,
record-type constants are all wired 1:1 into the connector, and the
classifier dispatches all 10 wired types directly from
``risk_rules/supabase.py``. Reconnect uses a named
``reconnect_credentials_supabase`` function (not the generic dispatcher).

Supabase is project-scoped: every record family is metadata ABOUT the
project's configuration (auth policy, RLS status, storage config,
network restrictions, ...), never the data plane itself.
"""

from __future__ import annotations

from app.provider_certification.models import (
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ProviderCertificationManifest,
)
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "supabase_api_config",
    "supabase_auth_config",
    "supabase_custom_domain",
    "supabase_database_config",
    "supabase_edge_function",
    "supabase_network_restriction",
    "supabase_oauth_provider",
    "supabase_project",
    "supabase_rls_status",
    "supabase_storage_config",
)

_FINDING_RULE_IDS = (
    "supabase_anonymous_access_enabled",
    "supabase_auth_protection_missing",
    "supabase_captcha_disabled",
    "supabase_edge_function_jwt_disabled",
    "supabase_jwt_expiry_long",
    "supabase_password_update_reauth_disabled",
    "supabase_public_select_sensitive_table",
    "supabase_public_write_policy",
    "supabase_refresh_token_rotation_disabled",
    "supabase_rls_disabled",
)

SUPABASE_MANIFEST = ProviderCertificationManifest(
    provider_id="supabase",
    display_name="Supabase",
    category="database_backend",
    maturity="complete",
    expected_public=True,
    expected_connectable=True,
    expected_live=True,
    credential_fields=("supabase_access_token", "supabase_project_ref"),
    sensitive_credential_fields=("supabase_access_token",),
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
    expected_frontend_form="SupabaseIntegrationForm.tsx",
    expected_reconnect=True,
    prohibited_dependencies=(),
    known_limitations=(
        "No table-row ingestion — only project/API/auth/storage/RLS "
        "CONFIGURATION metadata is collected, never row contents.",
        "No auth-user ingestion — user records/sessions are never read; "
        "only project-level auth POLICY settings (JWT expiry, CAPTCHA, "
        "anonymous sign-ins) are collected.",
        "No database query history and no Edge Function source code is "
        "ingested — only edge_function metadata (JWT-verification flag, "
        "name, status).",
        "No false-removal suppression function exists for Supabase yet "
        "(diff_service has no _supabase_removal_suppressed) — "
        "completeness_scopes/false_removal_scopes are honestly declared "
        "empty rather than claiming protection that doesn't exist.",
    ),
    evidence_test_files=(
        "tests/test_milestone71a_supabase_security_provider_foundation.py",
        "tests/test_supabase_change_classification_qa.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="supabase",
            test_file="tests/test_milestone71a_supabase_security_provider_foundation.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=10,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="supabase",
            test_file="tests/test_supabase_change_classification_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=40,
            quality="direct",
        ),
    ),
)

register_manifest(SUPABASE_MANIFEST)
