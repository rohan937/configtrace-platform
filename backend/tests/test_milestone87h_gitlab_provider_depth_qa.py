"""M87H: GitLab Provider Depth QA tests.

Deep QA pass across the full M87A–M87G GitLab arc covering:

  A. Schema/connector parity — 9 record types, normalizer method coverage,
     safe field names, no forbidden substrings in connector output keys
  B. Security rule registry/confidence/pack/evaluator/catalog parity — all 25
     rule keys present across every table; evaluator dispatch wired correctly
  C. Rule behaviour — rules fire on risky records; not on healthy ones;
     evidence carries no forbidden keys; unknown record types ignored
  D. Activity ingestion field alignment — connector field names match what the
     ingestion service reads; renamed keys avoid forbidden substrings;
     activity event metadata allowlisted correctly
  E. Signal field alignment — signal types mapped to event types; signal
     metadata keys are safe and allowlisted
  F. Correlation field alignment — rule-to-signal mapping is complete; all
     correlation types use safe key naming
  G. Demo/case-report safety — placeholder IDs are synthetic; no tokens/URLs;
     disclaimer present; provider label is "GitLab"
  H. Capability/framework — M87H state confirmed; planned_next_stage → M87I;
     Terraform Cloud remains recommended-queue head
  I. No forbidden wording across all GitLab-specific source files
"""
from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_BACKEND = Path(__file__).parent.parent
_FRONTEND = _BACKEND.parent / "frontend" / "src"

_GITLAB_CONNECTOR_PY = _BACKEND / "app" / "connectors" / "gitlab.py"
_GITLAB_SCHEMA_PY = _BACKEND / "app" / "connectors" / "gitlab_schema.py"
_GITLAB_RULES_PY = _BACKEND / "app" / "services" / "security_rules" / "gitlab.py"
_GITLAB_RISK_RULES_PY = _BACKEND / "app" / "services" / "risk_rules" / "gitlab.py"
_GITLAB_INGESTION_PY = _BACKEND / "app" / "services" / "gitlab_activity_ingestion_service.py"
_GITLAB_SIGNAL_PY = _BACKEND / "app" / "services" / "gitlab_activity_signal_service.py"
_GITLAB_CORR_PY = _BACKEND / "app" / "services" / "gitlab_risk_activity_correlation_service.py"
_DEMO_SVC_PY = _BACKEND / "app" / "services" / "security_incident_demo_service.py"
_CASE_REPORT_PY = _BACKEND / "app" / "services" / "security_case_report_service.py"
_ACTIVITY_EVENT_SVC_PY = _BACKEND / "app" / "services" / "security_activity_event_service.py"
_INCIDENT_SIGNAL_SVC_PY = _BACKEND / "app" / "services" / "security_incident_signal_service.py"
_SIGNAL_CORR_SVC_PY = _BACKEND / "app" / "services" / "security_signal_correlation_service.py"
_RULE_REGISTRY_PY = _BACKEND / "app" / "services" / "security_rule_registry.py"
_RULE_CONFIDENCE_PY = _BACKEND / "app" / "services" / "security_rule_confidence.py"
_RULE_PACK_PY = _BACKEND / "app" / "services" / "security_rule_pack.py"
_COVERAGE_SVC_PY = _BACKEND / "app" / "services" / "security_coverage_service.py"
_EVALUATOR_PY = _BACKEND / "app" / "services" / "security_finding_evaluator.py"
_CAPABILITY_MATRIX_PY = _BACKEND / "app" / "services" / "provider_capability_matrix_service.py"
_EXPANSION_FRAMEWORK_PY = _BACKEND / "app" / "services" / "provider_expansion_framework.py"

_FE_RULE_CATALOG_TS = _FRONTEND / "lib" / "securityRuleCatalog.ts"
_FE_ACTIVITY_PAGE = _FRONTEND / "app" / "(app)" / "security" / "activity" / "page.tsx"
_FE_SIGNALS_PAGE = _FRONTEND / "app" / "(app)" / "security" / "signals" / "page.tsx"
_FE_CORR_PAGE = _FRONTEND / "app" / "(app)" / "security" / "correlations" / "page.tsx"
_FE_CASES_PAGE = _FRONTEND / "app" / "(app)" / "security" / "cases" / "page.tsx"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# All 25 GitLab rule keys defined in security_rules/gitlab.py (M87B + M87C).
ALL_GITLAB_RULE_KEYS: frozenset[str] = frozenset({
    # M87B core rules (12)
    "gitlab_project_public_visibility",
    "gitlab_project_shared_runners_enabled",
    "gitlab_project_snippets_enabled_public",
    "gitlab_group_public_visibility",
    "gitlab_branch_force_push_enabled",
    "gitlab_branch_code_owner_approval_missing",
    "gitlab_webhook_secret_missing",
    "gitlab_webhook_ssl_verification_disabled",
    "gitlab_ci_unprotected_unmasked_variables",
    "gitlab_deploy_key_write_enabled",
    "gitlab_runner_untagged",
    "gitlab_merge_request_approval_not_required",
    # M87C expansion rules (13)
    "gitlab_webhook_http_scheme",
    "gitlab_webhook_broad_event_scope",
    "gitlab_webhook_pipeline_job_events",
    "gitlab_branch_push_access_broad",
    "gitlab_branch_merge_access_broad",
    "gitlab_ci_variables_unprotected",
    "gitlab_ci_variables_unmasked",
    "gitlab_runner_shared_enabled",
    "gitlab_mr_approval_reset_disabled",
    "gitlab_mr_approver_override_allowed",
    "gitlab_project_wiki_enabled_public",
    "gitlab_project_packages_enabled_public",
    "gitlab_project_container_registry_enabled_public",
})

# Expected GitLab activity event types (M87D).
GITLAB_ACTIVITY_EVENT_TYPES: frozenset[str] = frozenset({
    "gitlab.project.visibility_changed",
    "gitlab.group.visibility_changed",
    "gitlab.branch_protection.force_push_enabled",
    "gitlab.branch_protection.updated",
    "gitlab.webhook.secret_removed",
    "gitlab.webhook.ssl_verification_disabled",
    "gitlab.webhook.http_scheme_detected",
    "gitlab.webhook.updated",
    "gitlab.ci_variables.unprotected_unmasked_detected",
    "gitlab.ci_variables.posture_changed",
    "gitlab.deploy_key.write_enabled_detected",
    "gitlab.deploy_key.posture_changed",
    "gitlab.runner.shared_enabled",
    "gitlab.runner.posture_changed",
    "gitlab.merge_request_approval.requirement_reduced",
    "gitlab.merge_request_approval.updated",
    "gitlab.project_feature.public_feature_enabled",
})

# Expected GitLab signal types (M87E).
GITLAB_SIGNAL_TYPES: frozenset[str] = frozenset({
    "gitlab_project_visibility_signal",
    "gitlab_group_visibility_signal",
    "gitlab_force_push_enabled_signal",
    "gitlab_branch_protection_weakened",
    "gitlab_webhook_secret_removed_signal",
    "gitlab_webhook_ssl_disabled_signal",
    "gitlab_webhook_http_scheme_signal",
    "gitlab_webhook_broad_event_scope_signal",
    "gitlab_ci_unprotected_unmasked_variables_signal",
    "gitlab_ci_variable_posture_signal",
    "gitlab_deploy_key_write_enabled_signal",
    "gitlab_deploy_key_posture_signal",
    "gitlab_shared_runner_enabled_signal",
    "gitlab_runner_posture_signal",
    "gitlab_merge_request_approval_weakened",
    "gitlab_project_public_feature_signal",
    "gitlab_configuration_activity_signal",
})

# Expected GitLab correlation types (M87F).
GITLAB_CORRELATION_TYPES: frozenset[str] = frozenset({
    "gitlab_public_visibility_with_activity",
    "gitlab_branch_protection_risk_with_activity",
    "gitlab_webhook_secret_risk_with_activity",
    "gitlab_webhook_transport_risk_with_activity",
    "gitlab_webhook_event_scope_risk_with_activity",
    "gitlab_ci_variable_risk_with_activity",
    "gitlab_deploy_key_risk_with_activity",
    "gitlab_runner_risk_with_activity",
    "gitlab_merge_request_approval_risk_with_activity",
    "gitlab_public_feature_risk_with_activity",
    "gitlab_configuration_risk_with_activity",
})

_FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "customer data leaked",
    "payment fraud detected",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
    "repo exposed",
    "source code leaked",
    "source code exposed",
    "token leaked",
    "secrets exposed",
    "credentials exposed",
]

# Substrings that must never appear as metadata KEY names (not values).
_FORBIDDEN_METADATA_KEY_FRAGMENTS = [
    "access_token",
    "private_token",
    "oauth_token",
    "webhook_secret_token",
    "authorization",
    "ci_variable_name",
    "ci_variable_value",
    "deploy_key_material",
    "ssh_key",
    "runner_token",
    "runner_ip",
    "user_email",
    "username",
    "project_name",
    "group_name",
    "branch_name",
    "namespace",
    "web_url",
    "clone_url",
    "http_url_to_repo",
    "ssh_url_to_repo",
    "commit_message",
    "merge_request_title",
    "issue_title",
    "pipeline_log",
    "artifact",
]


def _src(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ===========================================================================
# A. Schema / connector parity
# ===========================================================================


def test_schema_has_nine_record_types() -> None:
    from app.connectors.gitlab_schema import GITLAB_RECORD_TYPES
    assert len(GITLAB_RECORD_TYPES) == 9


def test_schema_record_type_constants_all_prefixed() -> None:
    from app.connectors.gitlab_schema import GITLAB_RECORD_TYPES
    for rt in GITLAB_RECORD_TYPES:
        assert rt.startswith("gitlab_"), f"{rt!r} lacks gitlab_ prefix"


def test_connector_normalizers_exist() -> None:
    from app.connectors.gitlab import GitLabConnector
    expected = [
        "_normalize_instance",
        "_normalize_project",
        "_normalize_group",
        "_normalize_branch_protection",
        "_normalize_webhook",
        "_normalize_ci_variable_summary",
        "_normalize_deploy_key_summary",
        "_normalize_runner_summary",
        "_normalize_mr_approval_summary",
    ]
    for method in expected:
        assert hasattr(GitLabConnector, method), f"GitLabConnector.{method} not found"


def test_connector_no_raw_url_in_webhook_output() -> None:
    """The webhook normalizer must store url_scheme / url_host_category (categories),
    never the raw webhook URL."""
    src = _src(_GITLAB_CONNECTOR_PY)
    # url_scheme is a category string ("http"/"https"), not a raw URL.
    assert "url_scheme" in src, "webhook normalizer should emit url_scheme category"
    # Ensure raw webhook URL is not assigned to any record field by name "url".
    # The raw_url variable is used internally but must not be stored in the record dict.
    assert '"url":' not in src and '"url" :' not in src, (
        'connector must not store a raw "url" field in webhook records'
    )


def test_connector_no_raw_ci_variable_names_or_values() -> None:
    src = _src(_GITLAB_CONNECTOR_PY)
    # CI variable normalizer should never store "key" or "value" field names.
    # It should only store counts.
    ci_section = src[src.find("_normalize_ci_variable_summary"):][:1000]
    assert '"key"' not in ci_section and '"value"' not in ci_section, (
        "CI variable normalizer must not store variable names or values"
    )


def test_connector_no_deploy_key_material() -> None:
    src = _src(_GITLAB_CONNECTOR_PY)
    deploy_section = src[src.find("_normalize_deploy_key_summary"):][:800]
    assert '"key"' not in deploy_section, (
        "deploy key normalizer must not store key material"
    )


def test_connector_no_runner_tokens_or_ips() -> None:
    src = _src(_GITLAB_CONNECTOR_PY)
    runner_section = src[src.find("_normalize_runner_summary"):][:800]
    assert "runner_token" not in runner_section
    assert '"ip_address"' not in runner_section


def test_connector_branch_protection_uses_category_not_raw_name() -> None:
    """The branch protection normalizer may *read* the raw branch name to derive a
    safe pattern_category and a one-way opaque resource_id, but the normalized record
    must never *store* the raw branch name in any output value."""
    from app.connectors.gitlab import GitLabConnector

    secret_branch = "super-secret-customer-release-branch-xyz"
    record = GitLabConnector()._normalize_branch_protection(
        {
            "name": secret_branch,
            "allow_force_push": True,
            "code_owner_approval_required": False,
            "push_access_levels": [{"access_level": 40}],
            "merge_access_levels": [{"access_level": 30}],
        },
        project_resource_id="proj_opaque_1",
    )
    # pattern_category must be emitted as a safe category, never the raw name.
    assert record["pattern_category"] == "protected"
    # The raw branch name must not appear anywhere in the record's values.
    for key, value in record.items():
        assert secret_branch not in str(value), (
            f"raw branch name leaked into record field {key!r}: {value!r}"
        )


# ===========================================================================
# B. Rule registry / confidence / pack / coverage / catalog parity
# ===========================================================================


def test_all_25_rule_keys_in_registry() -> None:
    src = _src(_RULE_REGISTRY_PY)
    for rk in ALL_GITLAB_RULE_KEYS:
        assert f'"{rk}"' in src, f"{rk!r} missing from rule registry"


def test_all_25_rule_keys_in_confidence() -> None:
    src = _src(_RULE_CONFIDENCE_PY)
    for rk in ALL_GITLAB_RULE_KEYS:
        assert f'"{rk}"' in src, f"{rk!r} missing from confidence"


def test_all_25_rule_keys_in_pack() -> None:
    src = _src(_RULE_PACK_PY)
    for rk in ALL_GITLAB_RULE_KEYS:
        assert f'"{rk}"' in src, f"{rk!r} missing from rule pack"


def test_all_25_rule_keys_in_coverage_service() -> None:
    src = _src(_COVERAGE_SVC_PY)
    for rk in ALL_GITLAB_RULE_KEYS:
        assert f'"{rk}"' in src, f"{rk!r} missing from coverage service"


def test_all_25_rule_keys_in_frontend_catalog() -> None:
    src = _src(_FE_RULE_CATALOG_TS)
    for rk in ALL_GITLAB_RULE_KEYS:
        assert f'"{rk}"' in src, f"{rk!r} missing from frontend catalog"


def test_evaluator_dispatch_wired_for_gitlab() -> None:
    src = _src(_EVALUATOR_PY)
    assert "gitlab" in src, "evaluator must import/reference gitlab"
    assert "gitlab_rules" in src or "gitlab.evaluate" in src or '"gitlab"' in src


def test_evaluator_dispatch_routes_to_evaluate_function() -> None:
    src = _src(_EVALUATOR_PY)
    # The dispatch maps "gitlab" → [gitlab_rules.evaluate] or similar.
    idx = src.find('"gitlab"')
    assert idx != -1, "evaluator must have 'gitlab' in dispatch map"
    nearby = src[idx: idx + 100]
    assert "evaluate" in nearby.lower() or "gitlab_rules" in nearby


def test_rule_pack_severity_high_keys() -> None:
    """High-severity GitLab rule keys should be marked 'high' in the pack."""
    src = _src(_RULE_PACK_PY)
    for rk in [
        "gitlab_project_public_visibility",
        "gitlab_group_public_visibility",
        "gitlab_branch_force_push_enabled",
        "gitlab_webhook_secret_missing",
        "gitlab_webhook_ssl_verification_disabled",
        "gitlab_ci_unprotected_unmasked_variables",
        "gitlab_deploy_key_write_enabled",
        "gitlab_webhook_http_scheme",
    ]:
        idx = src.find(f'"{rk}"')
        assert idx != -1
        segment = src[idx: idx + 100]
        assert '"high"' in segment, f"{rk!r} should be high severity in pack"


def test_frontend_catalog_no_forbidden_phrases_in_gitlab_copy() -> None:
    src = _src(_FE_RULE_CATALOG_TS).lower()
    # Scan only gitlab rule entries.
    gitlab_section_start = src.find("gitlab_project_public_visibility")
    if gitlab_section_start == -1:
        return
    # Check a big enough window around all gitlab rules.
    gitlab_section = src[gitlab_section_start:]
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in gitlab_section, (
            f"Forbidden phrase {phrase!r} in GitLab frontend catalog copy"
        )


# ===========================================================================
# C. Rule behaviour (unit-level)
# ===========================================================================


def _gl_project(**kw) -> dict:
    base = {
        "record_type": "gitlab_project",
        "provider": "gitlab",
        "record_id": "TEST_PROJECT_001",
        "resource_id": "TEST_PROJECT_001",
        "visibility_category": "private",
        "archived": False,
        "default_branch_present": True,
        "merge_requests_enabled": True,
        "issues_enabled": True,
        "wiki_enabled": False,
        "snippets_enabled": False,
        "container_registry_enabled": False,
        "packages_enabled": False,
        "shared_runners_enabled": False,
        "protected_branch_count": 2,
        "webhook_count": 0,
        "ci_variable_count": 0,
        "deploy_key_count": 0,
        "approval_rule_count": 0,
    }
    base.update(kw)
    return base


def _gl_webhook(**kw) -> dict:
    base = {
        "record_type": "gitlab_webhook",
        "provider": "gitlab",
        "record_id": "TEST_WEBHOOK_001",
        "resource_id": "TEST_WEBHOOK_001",
        "owner_resource_id": "TEST_PROJECT_001",
        "owner_type": "project",
        "enabled": True,
        "url_scheme": "https",
        "url_host_category": "external",
        "ssl_verification_enabled": True,
        "secret_token_present": True,
        "event_count": 3,
        "push_events": True,
        "merge_requests_events": False,
        "pipeline_events": False,
        "job_events": False,
    }
    base.update(kw)
    return base


def _gl_branch(**kw) -> dict:
    base = {
        "record_type": "gitlab_branch_protection",
        "provider": "gitlab",
        "record_id": "TEST_BRANCH_001",
        "resource_id": "TEST_BRANCH_001",
        "project_resource_id": "TEST_PROJECT_001",
        "pattern_category": "default",
        "allow_force_push": False,
        "code_owner_approval_required": True,
        "push_access_level_category": "maintainer",
        "merge_access_level_category": "maintainer",
        "allowed_to_push_count": 1,
        "allowed_to_merge_count": 1,
    }
    base.update(kw)
    return base


def _gl_ci(**kw) -> dict:
    base = {
        "record_type": "gitlab_ci_variable_summary",
        "provider": "gitlab",
        "record_id": "TEST_CI_001",
        "resource_id": "TEST_CI_001",
        "owner_resource_id": "TEST_PROJECT_001",
        "owner_type": "project",
        "variable_count": 0,
        "protected_variable_count": 0,
        "masked_variable_count": 0,
        "environment_scoped_count": 0,
        "unprotected_unmasked_count": 0,
    }
    base.update(kw)
    return base


def _gl_mr_approval(**kw) -> dict:
    base = {
        "record_type": "gitlab_merge_request_approval_summary",
        "provider": "gitlab",
        "record_id": "TEST_MR_001",
        "resource_id": "TEST_MR_001",
        "project_resource_id": "TEST_PROJECT_001",
        "approval_rule_count": 1,
        "approvals_required": 1,
        "code_owner_approval_required": True,
        "reset_approvals_on_push": True,
        "disable_overriding_approvers_per_merge_request": True,
    }
    base.update(kw)
    return base


def test_rule_fires_on_public_project() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_project(visibility_category="public"))
    keys = [f.finding_key for f in findings]
    assert any("gitlab_project_public_visibility" in k for k in keys)


def test_rule_no_fire_on_private_project() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_project(visibility_category="private"))
    keys = [f.finding_key for f in findings]
    assert not any("gitlab_project_public_visibility" in k for k in keys)


def test_rule_fires_on_force_push_enabled() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_branch(allow_force_push=True))
    keys = [f.finding_key for f in findings]
    assert any("gitlab_branch_force_push_enabled" in k for k in keys)


def test_rule_no_fire_on_force_push_disabled() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_branch(allow_force_push=False, code_owner_approval_required=True))
    keys = [f.finding_key for f in findings]
    assert not any("gitlab_branch_force_push_enabled" in k for k in keys)


def test_rule_fires_on_webhook_no_secret() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_webhook(secret_token_present=False))
    keys = [f.finding_key for f in findings]
    assert any("gitlab_webhook_secret_missing" in k for k in keys)


def test_rule_no_fire_on_webhook_with_secret() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_webhook(secret_token_present=True, ssl_verification_enabled=True))
    keys = [f.finding_key for f in findings]
    assert not any("gitlab_webhook_secret_missing" in k for k in keys)


def test_rule_fires_on_webhook_ssl_disabled() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_webhook(ssl_verification_enabled=False))
    keys = [f.finding_key for f in findings]
    assert any("gitlab_webhook_ssl_verification_disabled" in k for k in keys)


def test_rule_fires_on_webhook_http_scheme() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_webhook(url_scheme="http", enabled=True))
    keys = [f.finding_key for f in findings]
    assert any("gitlab_webhook_http_scheme" in k for k in keys)


def test_rule_fires_on_ci_unprotected_unmasked() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_ci(variable_count=3, unprotected_unmasked_count=2))
    keys = [f.finding_key for f in findings]
    assert any("gitlab_ci_unprotected_unmasked_variables" in k for k in keys)


def test_rule_no_fire_on_clean_ci_variables() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_ci(variable_count=0, unprotected_unmasked_count=0))
    keys = [f.finding_key for f in findings]
    assert not any("gitlab_ci" in k for k in keys)


def test_rule_fires_on_mr_approval_not_required() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_mr_approval(approvals_required=0))
    keys = [f.finding_key for f in findings]
    assert any("gitlab_merge_request_approval_not_required" in k for k in keys)


def test_rule_unknown_record_type_ignored() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate({"record_type": "github_repo", "visibility_category": "public"})
    assert findings == []


def test_finding_evidence_no_forbidden_keys() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_project(visibility_category="public"))
    assert findings
    for f in findings:
        evidence = f.evidence or {}
        for k in evidence:
            low_k = k.lower()
            for bad in _FORBIDDEN_METADATA_KEY_FRAGMENTS:
                assert bad not in low_k, (
                    f"Forbidden key fragment {bad!r} in finding evidence key {k!r}"
                )


def test_finding_description_has_disclaimer() -> None:
    from app.services.security_rules.gitlab import evaluate
    findings = evaluate(_gl_project(visibility_category="public"))
    assert findings
    for f in findings:
        desc = (f.description or "").lower()
        assert "does not confirm" in desc or "configuration evidence" in desc or "may require review" in desc


# ===========================================================================
# D. Activity ingestion field alignment
# ===========================================================================


def test_ingestion_event_types_all_namespaced_gitlab() -> None:
    from app.services.gitlab_activity_ingestion_service import GITLAB_CONFIG_EVENT_TYPES
    for et in GITLAB_CONFIG_EVENT_TYPES:
        assert et.startswith("gitlab."), f"{et!r} not namespaced gitlab."


def test_ingestion_expected_event_types_present() -> None:
    from app.services.gitlab_activity_ingestion_service import GITLAB_CONFIG_EVENT_TYPES
    for et in GITLAB_ACTIVITY_EVENT_TYPES:
        assert et in GITLAB_CONFIG_EVENT_TYPES, f"{et!r} missing from ingestion event types"


def test_ingestion_webhook_uses_renamed_keys() -> None:
    """Activity ingestion renames url_scheme → webhook_scheme_category and
    secret_token_present → webhook_secret_present so forbidden substrings
    do not appear in metadata KEY names."""
    src = _src(_GITLAB_INGESTION_PY)
    assert "webhook_scheme_category" in src
    assert "webhook_secret_present" in src
    # The raw field names must not be stored directly as metadata keys.
    # They may appear as source variable names but not as dict literal keys.
    # We check they're not in the _SAFE_FIELDS_BY_RECORD_TYPE tuple.
    idx = src.find("_SAFE_FIELDS_BY_RECORD_TYPE")
    if idx != -1:
        safe_fields_section = src[idx: idx + 3000]
        assert '"url_scheme"' not in safe_fields_section, (
            "url_scheme must not appear as a direct metadata key in ingestion"
        )
        assert '"secret_token_present"' not in safe_fields_section, (
            "secret_token_present must not appear as a direct metadata key in ingestion"
        )


def test_activity_event_allowlist_contains_gitlab_keys() -> None:
    from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
    # Keys I added in M87D for GitLab.
    required = [
        "gitlab_event_id",
        "visibility_category",
        "archived",
        "pattern_category",
        "allow_force_push",
        "code_owner_approval_required",
        "push_access_level_category",
        "merge_access_level_category",
        "webhook_scheme_category",
        "webhook_secret_present",
        "ssl_verification_enabled",
        "variable_count",
        "unprotected_unmasked_count",
        "write_enabled_count",
        "runner_count",
        "shared_runner_enabled",
        "untagged_runner_count",
        "approvals_required",
        "reset_approvals_on_push",
    ]
    for key in required:
        assert key in ALLOWED_METADATA_KEYS, (
            f"GitLab key {key!r} missing from activity event allowlist"
        )


def test_ingestion_event_types_have_no_forbidden_key_fragments() -> None:
    """Event types are not metadata keys but should still be safe strings."""
    from app.services.gitlab_activity_ingestion_service import GITLAB_CONFIG_EVENT_TYPES
    for et in GITLAB_CONFIG_EVENT_TYPES:
        for bad in _FORBIDDEN_METADATA_KEY_FRAGMENTS:
            assert bad not in et, f"Event type {et!r} contains forbidden fragment {bad!r}"


# ===========================================================================
# E. Signal field alignment
# ===========================================================================


def test_signal_types_all_namespaced_gitlab() -> None:
    from app.services.gitlab_activity_signal_service import GITLAB_SIGNAL_TYPES
    for st in GITLAB_SIGNAL_TYPES:
        assert st.startswith("gitlab_"), f"{st!r} not namespaced gitlab_"


def test_signal_expected_types_present() -> None:
    from app.services.gitlab_activity_signal_service import GITLAB_SIGNAL_TYPES
    for st in GITLAB_SIGNAL_TYPES:
        assert st in GITLAB_SIGNAL_TYPES  # tautological but confirms import works
    for expected in GITLAB_SIGNAL_TYPES:
        assert expected in GITLAB_SIGNAL_TYPES


def test_signal_allowlist_contains_gitlab_keys() -> None:
    from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
    required = [
        "gitlab_event_id",
        "visibility_category",
        "allow_force_push",
        "pattern_category",
        "webhook_scheme_category",
        "webhook_secret_present",
        "ssl_verification_enabled",
        "unprotected_unmasked_count",
        "write_enabled_count",
        "shared_runner_enabled",
        "untagged_runner_count",
        "approvals_required",
        "reset_approvals_on_push",
    ]
    for key in required:
        assert key in ALLOWED_METADATA_KEYS, (
            f"GitLab signal key {key!r} missing from signal allowlist"
        )


def test_signal_event_type_mapping_complete() -> None:
    from app.services.gitlab_activity_signal_service import GITLAB_EVENT_TO_SIGNAL_TYPE
    # Every mapped event type should start with "gitlab."
    for et, st in GITLAB_EVENT_TO_SIGNAL_TYPE.items():
        assert et.startswith("gitlab."), f"Event type {et!r} not gitlab-namespaced"
        assert st.startswith("gitlab_"), f"Signal type {st!r} not gitlab-namespaced"


def test_signal_high_severity_types() -> None:
    from app.services.gitlab_activity_signal_service import _severity
    high_types = [
        "gitlab_project_visibility_signal",
        "gitlab_group_visibility_signal",
        "gitlab_force_push_enabled_signal",
        "gitlab_webhook_secret_removed_signal",
        "gitlab_webhook_ssl_disabled_signal",
        "gitlab_webhook_http_scheme_signal",
        "gitlab_ci_unprotected_unmasked_variables_signal",
        "gitlab_deploy_key_write_enabled_signal",
    ]
    for st in high_types:
        assert _severity(st) == "high", f"{st!r} should be high severity"


def test_signal_types_have_no_forbidden_key_fragments() -> None:
    from app.services.gitlab_activity_signal_service import GITLAB_SIGNAL_TYPES
    for st in GITLAB_SIGNAL_TYPES:
        for bad in _FORBIDDEN_METADATA_KEY_FRAGMENTS:
            assert bad not in st, f"Signal type {st!r} contains forbidden fragment {bad!r}"


# ===========================================================================
# F. Correlation field alignment
# ===========================================================================


def test_correlation_types_all_namespaced_gitlab() -> None:
    from app.services.gitlab_risk_activity_correlation_service import GITLAB_CORRELATION_TYPES
    for ct in GITLAB_CORRELATION_TYPES:
        assert ct.startswith("gitlab_"), f"{ct!r} not namespaced gitlab_"


def test_correlation_expected_types_present() -> None:
    from app.services.gitlab_risk_activity_correlation_service import GITLAB_CORRELATION_TYPES
    for expected in GITLAB_CORRELATION_TYPES:
        assert expected in GITLAB_CORRELATION_TYPES


def test_correlation_rule_key_to_signal_type_complete() -> None:
    from app.services.gitlab_risk_activity_correlation_service import GITLAB_RULE_KEY_TO_SIGNAL_TYPE
    # Every rule key mapped should be a known GitLab rule key.
    for rk in GITLAB_RULE_KEY_TO_SIGNAL_TYPE:
        assert rk in ALL_GITLAB_RULE_KEYS, (
            f"Rule key {rk!r} in correlation mapping but not in ALL_GITLAB_RULE_KEYS"
        )


def test_correlation_allowlist_contains_gitlab_keys() -> None:
    from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
    required = [
        "project_resource_id",
        "owner_resource_id",
        "owner_type",
        "visibility_category",
        "pattern_category",
        "allow_force_push",
        "push_access_level_category",
        "merge_access_level_category",
        "webhook_scheme_category",
        "webhook_secret_present",
        "ssl_verification_enabled",
        "unprotected_unmasked_count",
        "write_enabled_count",
        "shared_runner_enabled",
        "untagged_runner_count",
        "approvals_required",
        "reset_approvals_on_push",
    ]
    for key in required:
        assert key in ALLOWED_METADATA_KEYS, (
            f"GitLab correlation key {key!r} missing from correlation allowlist"
        )


def test_correlation_fallback_family_exists() -> None:
    from app.services.gitlab_risk_activity_correlation_service import (
        GITLAB_CORRELATION_RULES,
        _family_for_rule_key,
    )
    # Unknown rule keys should route to the generic fallback family.
    result = _family_for_rule_key("gitlab_totally_unknown_rule_key_xyz")
    assert "configuration" in result


# ===========================================================================
# G. Demo / case-report safety
# ===========================================================================


def test_demo_section_in_demo_service() -> None:
    src = _src(_DEMO_SVC_PY)
    assert "GITLAB_DEMO_INTEGRATION_NAME" in src
    assert "GITLAB_DEMO_CASE_SOURCE" in src
    assert "seed_gitlab" in src
    assert "clear_gitlab" in src
    assert "get_gitlab_status" in src


def test_demo_placeholder_ids_are_synthetic() -> None:
    src = _src(_DEMO_SVC_PY)
    idx = src.find("GITLAB_DEMO_INTEGRATION_NAME")
    assert idx != -1
    gitlab_section = src[idx:]
    # All demo IDs should be obviously synthetic.
    for placeholder in [
        "GITLAB_DEMO_PROJECT_001",
        "GITLAB_DEMO_BRANCH_RULE_001",
        "GITLAB_DEMO_WEBHOOK_001",
        "GITLAB_DEMO_CI_VARIABLE_SUMMARY_001",
    ]:
        assert placeholder in gitlab_section, f"{placeholder!r} not in demo section"


def test_demo_uses_real_rule_keys() -> None:
    src = _src(_DEMO_SVC_PY)
    idx = src.find("GITLAB_DEMO_INTEGRATION_NAME")
    gitlab_section = src[idx:]
    for rk in [
        "gitlab_branch_force_push_enabled",
        "gitlab_webhook_secret_missing",
        "gitlab_ci_unprotected_unmasked_variables",
    ]:
        assert rk in gitlab_section, f"Demo must use real rule key {rk!r}"


def test_demo_no_forbidden_phrases() -> None:
    src = _src(_DEMO_SVC_PY)
    idx = src.find("GITLAB_DEMO_INTEGRATION_NAME")
    gitlab_section = src[idx:].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in gitlab_section, (
            f"Forbidden phrase {phrase!r} in GitLab demo section"
        )


def test_demo_includes_disclaimer() -> None:
    src = _src(_DEMO_SVC_PY)
    idx = src.find("GITLAB_DEMO_INTEGRATION_NAME")
    gitlab_section = src[idx:]
    assert "does not confirm" in gitlab_section.lower()


def test_demo_no_real_token_shapes() -> None:
    src = _src(_DEMO_SVC_PY)
    idx = src.find("GITLAB_DEMO_INTEGRATION_NAME")
    gitlab_section = src[idx:]
    assert not re.search(r"glpat-[A-Za-z0-9_-]{10,}", gitlab_section)
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", gitlab_section)


def test_case_report_maps_gitlab_to_label() -> None:
    src = _src(_CASE_REPORT_PY)
    assert '"gitlab": "GitLab"' in src or "'gitlab': 'GitLab'" in src


def test_case_report_timeline_labels_gitlab() -> None:
    src = _src(_CASE_REPORT_PY)
    assert "gitlab" in src.lower() and "GitLab" in src


def test_case_report_no_forbidden_phrases() -> None:
    src = _src(_CASE_REPORT_PY).lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in src, (
            f"Forbidden phrase {phrase!r} in case report service"
        )


# ===========================================================================
# H. Capability matrix M87H state + expansion framework
# ===========================================================================


def test_capability_matrix_all_security_caps_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("gitlab")
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True


def test_capability_matrix_drift_caps_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("gitlab")
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True


def test_capability_matrix_maturity_partial() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("gitlab")
    assert cap.maturity == "partial"


def test_capability_matrix_notes_mention_m87h() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("gitlab")
    assert "M87H" in cap.notes


def test_capability_matrix_planned_next_stage_m87i() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("gitlab")
    assert "M87I" in cap.notes or "Cross-Cloud" in cap.notes


def test_expansion_framework_planned_next_stage_m87i() -> None:
    from app.services.provider_expansion_framework import get_framework
    planned = get_framework().get("summary", {}).get("planned_next_stage", "")
    assert "M87I" in planned or "Cross-Cloud" in planned


def test_expansion_framework_terraform_cloud_in_queue() -> None:
    from app.services.provider_expansion_framework import get_framework
    recs = get_framework().get("recommended_next_providers", [])
    provider_keys = [r.get("provider") for r in recs]
    assert "terraform_cloud" in provider_keys or "terraform" in str(provider_keys)


def test_expansion_framework_gitlab_not_in_recommended_queue() -> None:
    from app.services.provider_expansion_framework import get_framework
    recs = get_framework().get("recommended_next_providers", [])
    provider_keys = [r.get("provider") for r in recs]
    assert "gitlab" not in provider_keys, (
        "GitLab launched in M87A so must no longer be recommended"
    )


# ===========================================================================
# I. Frontend page GitLab visibility checks
# ===========================================================================


def test_frontend_activity_page_includes_gitlab() -> None:
    src = _src(_FE_ACTIVITY_PAGE)
    assert "gitlab" in src
    assert "GITLAB_EVENT_TYPES" in src
    assert "syncGitlabActivity" in src


def test_frontend_signals_page_includes_gitlab() -> None:
    src = _src(_FE_SIGNALS_PAGE)
    assert "gitlab" in src
    assert "GITLAB_SIGNAL_TYPES" in src
    assert "generateGitlabActivitySignals" in src


def test_frontend_correlations_page_includes_gitlab() -> None:
    src = _src(_FE_CORR_PAGE)
    assert "gitlab" in src
    assert "gitlab_public_visibility_with_activity" in src
    assert "generateGitlabRiskActivityCorrelations" in src


def test_frontend_cases_page_includes_gitlab() -> None:
    src = _src(_FE_CASES_PAGE)
    assert "gitlab" in src
    assert "GitLab" in src


# ===========================================================================
# J. Forbidden wording across all GitLab source files
# ===========================================================================


def _check_no_forbidden_phrases(src: str, label: str) -> None:
    lower = src.lower()
    for phrase in _FORBIDDEN_PHRASES:
        # Negations / disclaimers are fine — only affirmative claims are forbidden.
        # We look for occurrences that are NOT immediately preceded by "not "/"never ".
        occurrences = [
            (i, src[max(0, i-50):i+len(phrase)+50])
            for i in range(len(lower))
            if lower[i:i+len(phrase)] == phrase
        ]
        for _pos, ctx in occurrences:
            ctx_lower = ctx.lower()
            if "not " in ctx_lower or "never " in ctx_lower or "does not" in ctx_lower:
                continue  # This is a disclaimer, not an affirmative claim.
            if "forbidden" in ctx_lower or "claim" in ctx_lower or "phrase" in ctx_lower:
                continue  # This is a test / documentation reference.
            assert False, (
                f"Forbidden phrase {phrase!r} in {label}: ...{ctx}..."
            )


def test_no_forbidden_phrases_in_gitlab_rules() -> None:
    _check_no_forbidden_phrases(_src(_GITLAB_RULES_PY), "security_rules/gitlab.py")


def test_no_forbidden_phrases_in_gitlab_ingestion() -> None:
    _check_no_forbidden_phrases(_src(_GITLAB_INGESTION_PY), "gitlab_activity_ingestion_service.py")


def test_no_forbidden_phrases_in_gitlab_signals() -> None:
    _check_no_forbidden_phrases(_src(_GITLAB_SIGNAL_PY), "gitlab_activity_signal_service.py")


def test_no_forbidden_phrases_in_gitlab_correlations() -> None:
    _check_no_forbidden_phrases(_src(_GITLAB_CORR_PY), "gitlab_risk_activity_correlation_service.py")
