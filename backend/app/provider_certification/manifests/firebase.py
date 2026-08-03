"""Firebase certification manifest (message 4 of N).

Generic discovery is fully sufficient for Firebase — no adapter needed.
Credential is a single ``firebase_service_account_json`` field, all 13
schema record-type constants are wired 1:1 into the connector, and the
classifier dispatches all 13 directly from ``risk_rules/firebase.py``.
Reconnect uses a named ``reconnect_credentials_firebase`` function.

Firebase's record families are all project-level CONFIGURATION/RULESET
metadata (Firestore/RTDB/Storage security-rule TEXT and auth/hosting/App
Check settings) — never document, object, or user data itself.
"""

from __future__ import annotations

from app.provider_certification.models import (
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ProviderCertificationManifest,
)
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "firebase_app_check_config",
    "firebase_auth_config",
    "firebase_auth_provider",
    "firebase_authorized_domain",
    "firebase_database_ruleset",
    "firebase_firestore_ruleset",
    "firebase_function_metadata",
    "firebase_hosting_domain",
    "firebase_hosting_site",
    "firebase_project",
    "firebase_remote_config_template",
    "firebase_storage_bucket",
    "firebase_storage_ruleset",
)

_FINDING_RULE_IDS = (
    "firebase_anonymous_auth_enabled",
    "firebase_app_check_unenforced_services",
    "firebase_auth_protection_missing",
    "firebase_database_public_read",
    "firebase_database_public_write",
    "firebase_rules_public",
    "firebase_storage_public_access_prevention_disabled",
    "firebase_storage_rules_public",
)

FIREBASE_MANIFEST = ProviderCertificationManifest(
    provider_id="firebase",
    display_name="Firebase",
    category="database_backend",
    maturity="complete",
    expected_public=True,
    expected_connectable=True,
    expected_live=True,
    credential_fields=("firebase_service_account_json",),
    sensitive_credential_fields=("firebase_service_account_json",),
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
    expected_frontend_form="FirebaseIntegrationForm.tsx",
    expected_reconnect=True,
    prohibited_dependencies=(),
    known_limitations=(
        "No Firestore document contents are ingested — only the "
        "Firestore security-rules TEXT (firebase_firestore_ruleset).",
        "No Storage object contents are ingested — only the "
        "Storage security-rules TEXT and bucket metadata.",
        "No Authentication user records are ingested — only project-"
        "level auth CONFIGURATION (providers, authorized domains, "
        "anonymous sign-in flag).",
        "No Cloud Function source code is ingested — only function "
        "metadata (name, trigger type, runtime, IAM invoker policy).",
        "No analytics/event data is ingested from Firebase at all.",
        "No false-removal suppression function exists for Firebase yet "
        "(diff_service has no _firebase_removal_suppressed) — "
        "completeness_scopes/false_removal_scopes are honestly declared "
        "empty rather than claiming protection that doesn't exist.",
    ),
    evidence_test_files=(
        "tests/test_milestone72a_firebase_security_provider_foundation.py",
        "tests/test_firebase_change_classification_qa.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="firebase",
            test_file="tests/test_milestone72a_firebase_security_provider_foundation.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=10,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="firebase",
            test_file="tests/test_firebase_change_classification_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=20,
            quality="direct",
        ),
    ),
)

register_manifest(FIREBASE_MANIFEST)
