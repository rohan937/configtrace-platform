"""GitHub certification manifest (message 3 of N).

GitHub is the most mature dual-stack provider in the repository —
`provider_capability_matrix_service.get_provider_capability("github")`
reports maturity ``"complete"`` with every dual-stack capability
(``security_rules``, ``activity_ingestion``, ``activity_signals``,
``risk_activity_correlations``, ``demo_seed_clear``/``case_report``)
enabled. This manifest declares all five accordingly — NOT because the
framework assumes it, but because that is what discovery independently
confirms (see ``test_provider_certification_github.py``).

11 of 17 record-type identity constants declared in ``github_schema.py``
are ACTUALLY wired into the connector (discovered via
``discovery.discover_schema_record_type_constants``'s connector-wiring
precision filter, message 3); the other 6 (``github_app_installation``,
``github_codeowners``, ``github_collaborator``, ``github_oidc_trust``,
``github_security_features``, ``github_workflow_file``) are declared in
the schema but never referenced anywhere in ``github.py`` — a real,
pre-existing gap between the declared taxonomy and the implemented
connector, correctly EXCLUDED from ``expected_record_types`` rather than
advertised as certified.

No code-scanning RESULT content, secret-scanning secret VALUES, or raw
webhook payload content is ever ingested — only safe posture metadata
(alert counts/categories, boolean flags) per the activity-ingestion
messages (69.4a-i). This manifest does not advertise otherwise.

GitHub predates the per-provider ``reconnect_credentials_<provider>()``
convention — its reconnect is wired through the shared, generic
``reconnect_credentials()`` dispatcher's inline branch instead (a real,
legitimate second form of wiring; see
``discovery.discover_generic_reconnect_dispatch`` and
``gates._reconnect_wired_for``, both added generically in message 3, not
GitHub-specific).
"""

from __future__ import annotations

from app.provider_certification.models import (
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ProviderCertificationManifest,
)
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "github_repo_settings",
    "github_branch_protection",
    "github_actions_secret",
    "github_actions_variable",
    "github_webhook",
    "github_actions_permissions",
    "github_deploy_key",
    "github_environment_protection",
    "github_ruleset",
    "github_automation_permissions",
    "github_pages",
)

_SECURITY_FINDING_RULE_IDS = (
    "github_actions_broad_permissions",
    "github_actions_can_approve_pull_requests",
    "github_actions_workflow_token_write_permission",
    "github_automation_admin_permission",
    "github_automation_write_permission",
    "github_branch_admin_bypass_allowed",
    "github_branch_deletion_allowed",
    "github_branch_protection_missing",
    "github_deploy_key_write_access",
    "github_env_protection_missing",
    "github_force_pushes_allowed",
    "github_pages_enabled",
    "github_pr_review_not_required",
    "github_ruleset_bypass_actors_present",
    "github_ruleset_force_push_allowed",
    "github_ruleset_not_enforced",
    "github_ruleset_pr_review_missing",
    "github_ruleset_status_checks_missing",
    "github_ruleset_weak_target_coverage",
    "github_status_checks_not_required",
    "github_token_broad_scopes",
    "github_webhook_http",
    "github_webhook_secret_missing",
    "github_webhook_ssl_verification_disabled",
    "github_wiki_enabled",
)

GITHUB_MANIFEST = ProviderCertificationManifest(
    provider_id="github",
    display_name="GitHub",
    category="devops",
    maturity="complete",
    expected_public=True,
    expected_connectable=True,
    expected_live=True,
    credential_fields=("github_token",),
    sensitive_credential_fields=("github_token",),
    authentication_model="personal_access_token",
    expected_record_types=_EXPECTED_RECORD_TYPES,
    derived_record_types=(),
    security_finding_rule_ids=_SECURITY_FINDING_RULE_IDS,
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
    expected_frontend_form="GitHubIntegrationForm.tsx",
    expected_reconnect=True,
    allowed_dependencies=("httpx",),
    prohibited_dependencies=("PyGithub", "github3.py"),
    required_env_vars=(),
    prohibited_env_vars=("GITHUB_TOKEN", "GH_TOKEN"),
    known_limitations=(
        "6 of 17 declared github_schema.py record-type constants are not wired into the connector "
        "(github_app_installation, github_codeowners, github_collaborator, github_oidc_trust, "
        "github_security_features, github_workflow_file) — not certified, not advertised as supported",
        "No code-scanning alert RESULT content (no code snippets, file paths as free text, rule descriptions "
        "beyond safe categories) — only safe posture metadata and counts",
        "No secret-scanning SECRET VALUES — only safe alert counts/categories",
        "No raw webhook payload content — only safe configuration metadata (URL scheme, SSL flag, secret presence)",
        "No family-level or per-parent completeness reporting; no false-removal suppression function exists",
        "Reconnect is wired through the shared reconnect_credentials() dispatcher, not a dedicated "
        "reconnect_credentials_github() function — a pre-existing, original-8-era pattern",
    ),
    evidence_test_files=(
        "tests/test_milestone60_4_1_github_rules.py",
        "tests/test_github_change_classification_qa.py",
        "tests/test_github_detection_qa.py",
        "tests/test_github_risk_audit.py",
        "tests/test_github_extras_risk_audit.py",
        "tests/test_github_provider_depth_qa.py",
        "tests/test_github_connector.py",
    ),
    evidence_reports=(),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="github",
            test_file="tests/test_milestone60_4_1_github_rules.py",
            test_selector="",
            covered_rule_ids=_SECURITY_FINDING_RULE_IDS,
            minimum_test_count=22,
            note="Grouped evidence: normalized fixture -> evaluate() across all 25 rules.",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="github",
            test_file="tests/test_github_change_classification_qa.py",
            test_selector="",
            covered_rule_ids=_SECURITY_FINDING_RULE_IDS,
            minimum_test_count=19,
            note="Grouped evidence: real compute_diff()-pipeline severity parity, including TestSecurityFindingSeverityParity.",
        ),
    ),
)

register_manifest(GITHUB_MANIFEST)
