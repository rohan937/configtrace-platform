"""GitLab certification manifest (message 3 of N).

Canonical `provider_id` is `"gitlab"` — confirmed via
`provider_capability_matrix_service.get_provider_capability("gitlab")`
(no alias). GitLab's capability-matrix entry lives in
`PROVIDER_CAPABILITIES_PARTIAL`, not `PROVIDER_CAPABILITIES` — this is
NOT a "not really launched" signal (a dozen fully-launched, connectable
providers permanently live in that second list; `get_provider_capability()`
merges both into one lookup) — see the message-3
`gate_capability_matrix_parity` fix in `gates.py` that corrected this
genuine framework gate defect.

GitLab predates the per-provider connectable convention entirely: it has
NO `_create_gitlab_integration()` service function (creation is inline
in the POST /integrations router handler — see
`discovery.discover_router_create_dispatch`, generic, message 3) and NO
reconnect wiring of any kind (neither a dedicated function nor a branch
in the shared generic dispatcher) — `expected_reconnect=False` and
`expected_live=False` below are honest reflections of that real,
pre-existing state, not certification failures to paper over.

The connector emits `record_type` via raw string literals
(`"record_type": "gitlab_project"`) rather than importing its own
schema module's named constants — discovery's connector-wiring
precision filter (message 3) resolves this by matching the literal
STRING VALUE when the constant NAME isn't referenced, which is why no
GitLab-specific discovery adapter was needed for record-type discovery.

No dedicated Finding-vs-Change severity-parity test file exists for
GitLab yet (unlike Sentry/Snowflake/Okta/Entra/Kubernetes/GitHub) — per
the explicit "do not fabricate PASS" instruction, `change_parity_evidence`
is deliberately left empty; `gate_finding_change_parity` correctly
resolves this to `deferred` (non-blocking), not a fabricated pass.
"""

from __future__ import annotations

from app.provider_certification.models import (
    FindingReachabilityEvidence,
    ProviderCertificationManifest,
)
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "gitlab_instance",
    "gitlab_project",
    "gitlab_group",
    "gitlab_branch_protection",
    "gitlab_webhook",
    "gitlab_ci_variable_summary",
    "gitlab_deploy_key_summary",
    "gitlab_runner_summary",
    "gitlab_merge_request_approval_summary",
)

_SECURITY_FINDING_RULE_IDS = (
    "gitlab_branch_code_owner_approval_missing",
    "gitlab_branch_force_push_enabled",
    "gitlab_branch_merge_access_broad",
    "gitlab_branch_push_access_broad",
    "gitlab_ci_unprotected_unmasked_variables",
    "gitlab_ci_variables_unmasked",
    "gitlab_ci_variables_unprotected",
    "gitlab_deploy_key_write_enabled",
    "gitlab_group_public_visibility",
    "gitlab_merge_request_approval_not_required",
    "gitlab_mr_approval_reset_disabled",
    "gitlab_mr_approver_override_allowed",
    "gitlab_project_container_registry_enabled_public",
    "gitlab_project_packages_enabled_public",
    "gitlab_project_public_visibility",
    "gitlab_project_shared_runners_enabled",
    "gitlab_project_snippets_enabled_public",
    "gitlab_project_wiki_enabled_public",
    "gitlab_runner_shared_enabled",
    "gitlab_runner_untagged",
    "gitlab_webhook_broad_event_scope",
    "gitlab_webhook_http_scheme",
    "gitlab_webhook_pipeline_job_events",
    "gitlab_webhook_secret_missing",
    "gitlab_webhook_ssl_verification_disabled",
)

GITLAB_MANIFEST = ProviderCertificationManifest(
    provider_id="gitlab",
    display_name="GitLab",
    category="devops",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=False,
    credential_fields=("gitlab_access_token", "gitlab_base_url"),
    sensitive_credential_fields=("gitlab_access_token",),
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
    expected_frontend_form="GitLabIntegrationForm.tsx",
    expected_reconnect=False,
    allowed_dependencies=("httpx",),
    prohibited_dependencies=("python-gitlab",),
    required_env_vars=(),
    prohibited_env_vars=("GITLAB_TOKEN", "CI_JOB_TOKEN"),
    known_limitations=(
        "No dedicated per-provider creation-dispatch function — creation is wired inline in the "
        "POST /integrations router handler (a pre-existing, original-8-era pattern)",
        "No reconnect support of any kind yet (neither a dedicated function nor a generic-dispatcher branch)",
        "No family-level or per-parent completeness reporting; no false-removal suppression function exists",
        "Never stores access tokens, webhook URLs/secrets, CI variable names/values, deploy key material, "
        "runner tokens/IPs, branch names, project/group names or paths, or user identities/PII",
        "No dedicated Finding-vs-Change severity-parity test file exists yet — change_parity_evidence is "
        "empty and the finding_change_parity gate correctly resolves to deferred, not a fabricated pass",
    ),
    evidence_test_files=(
        "tests/test_milestone87a_gitlab_drift_provider_foundation.py",
        "tests/test_milestone87b_gitlab_core_security_foundation.py",
        "tests/test_milestone87c_gitlab_branch_webhook_ci_risk_expansion.py",
        "tests/test_milestone87h_gitlab_provider_depth_qa.py",
        "tests/test_gitlab_provider_depth_qa.py",
    ),
    evidence_reports=(),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="gitlab",
            test_file="tests/test_milestone87h_gitlab_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_SECURITY_FINDING_RULE_IDS,
            minimum_test_count=72,
            note="Grouped evidence: connector-normalized-shape fixture -> evaluate() across all 25 rules.",
        ),
    ),
    change_parity_evidence=(),
    change_parity_exceptions=(),
)

register_manifest(GITLAB_MANIFEST)
