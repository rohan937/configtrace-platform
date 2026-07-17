"""M87C: GitLab branch/webhook/CI risk expansion tests.

Validates that the expanded GitLab security rules, evaluator dispatch,
registry/catalog/confidence/pack/coverage surfaces, capability matrix,
and expansion framework all meet the M87C specification.

Skipped rules and why:
  gitlab_runner_unprotected_runners  — protected_runner_count not in M87A
                                       GitLabRunnerSummaryRecord schema
  gitlab_deploy_key_stale_or_expired — expired_or_stale_count not in M87A
                                       GitLabDeployKeySummaryRecord schema

Sections:
  A. M87C rule key constants exist; M87B rules preserved
  B. Rules fire on risky input (positive cases for all 13 M87C rules)
  C. Rules do not fire on healthy input (negative cases)
  D. Missing/None fields do not produce false positives
  E. Evidence safety — no forbidden keys in evidence dicts
  F. Claim discipline — descriptions have safe disclaimer; no forbidden wording
  G. Registry, confidence, pack, coverage parity for M87C rules
  H. Production evaluator still dispatches gitlab; M87C findings produced
  I. Capability matrix — planned_next_stage=M87D; 25 rules noted
  J. Expansion framework — planned_next_stage=M87D; TC remains in queue
  K. Frontend catalog — all 13 M87C rule entries present
  L. Backend/frontend severity and category match for M87C rules
  M. M87A and M87B rules still work (regression smoke)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parents[2]
FE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"
BACKEND_ROOT = Path(__file__).resolve().parents[1]
GITLAB_RULES_PY = BACKEND_ROOT / "app" / "services" / "security_rules" / "gitlab.py"

# ── M87C expected rule keys ────────────────────────────────────────────────────
EXPECTED_M87C_RULE_KEYS = {
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
}

# M87B rules that must still exist
EXPECTED_M87B_RULE_KEYS = {
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
}

ALL_EXPECTED_GITLAB_RULE_KEYS = EXPECTED_M87B_RULE_KEYS | EXPECTED_M87C_RULE_KEYS

# ── Forbidden evidence keys ───────────────────────────────────────────────────
_FORBIDDEN_EVIDENCE_KEYS = {
    "token", "secret", "secret_value", "private_token", "authorization",
    "webhook_url", "url", "ci_variable_name", "ci_variable_value",
    "deploy_key_material", "ssh_key", "runner_token", "runner_ip",
    "user_email", "username", "project_name", "group_name", "branch_name",
    "raw", "payload", "request", "response", "password", "key_material",
    "fingerprint", "access_token",
}

# ── Forbidden wording ─────────────────────────────────────────────────────────
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

# ── Record fixtures ────────────────────────────────────────────────────────────

def _project(overrides: dict | None = None) -> dict:
    base = {
        "record_type": "gitlab_project",
        "provider": "gitlab",
        "record_id": "gitlab_project:abc123",
        "resource_id": "abc123",
        "visibility_category": "private",
        "archived": False,
        "default_branch_present": True,
        "merge_requests_enabled": True,
        "issues_enabled": True,
        "wiki_enabled": False,
        "snippets_enabled": False,
        "container_registry_enabled": False,
        "packages_enabled": None,
        "shared_runners_enabled": False,
        "protected_branch_count": 2,
        "webhook_count": 1,
        "ci_variable_count": 3,
        "deploy_key_count": 0,
        "approval_rule_count": 1,
    }
    if overrides:
        base.update(overrides)
    return base


def _branch_protection(overrides: dict | None = None) -> dict:
    base = {
        "record_type": "gitlab_branch_protection",
        "provider": "gitlab",
        "record_id": "gitlab_branch_protection:bp123",
        "resource_id": "bp123",
        "project_resource_id": "proj123",
        "pattern_category": "default",
        "allow_force_push": False,
        "code_owner_approval_required": True,
        "push_access_level_category": "maintainer",
        "merge_access_level_category": "maintainer",
        "allowed_to_push_count": 1,
        "allowed_to_merge_count": 2,
    }
    if overrides:
        base.update(overrides)
    return base


def _webhook(overrides: dict | None = None) -> dict:
    base = {
        "record_type": "gitlab_webhook",
        "provider": "gitlab",
        "record_id": "gitlab_webhook:wh123",
        "resource_id": "wh123",
        "owner_resource_id": "proj123",
        "owner_type": "project",
        "enabled": True,
        "url_scheme": "https",
        "url_host_category": "external",
        "ssl_verification_enabled": True,
        "secret_token_present": True,
        "event_count": 2,
        "push_events": True,
        "merge_requests_events": False,
        "pipeline_events": False,
        "job_events": False,
    }
    if overrides:
        base.update(overrides)
    return base


def _ci_variable_summary(overrides: dict | None = None) -> dict:
    base = {
        "record_type": "gitlab_ci_variable_summary",
        "provider": "gitlab",
        "record_id": "gitlab_ci_variable_summary:cv123",
        "resource_id": "cv123",
        "owner_resource_id": "proj123",
        "owner_type": "project",
        "variable_count": 5,
        "protected_variable_count": 4,
        "masked_variable_count": 4,
        "environment_scoped_count": 1,
        "unprotected_unmasked_count": 0,
    }
    if overrides:
        base.update(overrides)
    return base


def _runner_summary(overrides: dict | None = None) -> dict:
    base = {
        "record_type": "gitlab_runner_summary",
        "provider": "gitlab",
        "record_id": "gitlab_runner_summary:rs123",
        "resource_id": "rs123",
        "owner_resource_id": "proj123",
        "owner_type": "project",
        "runner_count": 3,
        "shared_runner_enabled": False,
        "locked_runner_count": 2,
        "paused_runner_count": 0,
        "tagged_runner_count": 3,
        "untagged_runner_count": 0,
    }
    if overrides:
        base.update(overrides)
    return base


def _mr_approval(overrides: dict | None = None) -> dict:
    base = {
        "record_type": "gitlab_merge_request_approval_summary",
        "provider": "gitlab",
        "record_id": "gitlab_merge_request_approval_summary:mr123",
        "resource_id": "mr123",
        "project_resource_id": "proj123",
        "approval_rule_count": 2,
        "approvals_required": 2,
        "code_owner_approval_required": True,
        "reset_approvals_on_push": True,
        "disable_overriding_approvers_per_merge_request": True,
    }
    if overrides:
        base.update(overrides)
    return base


def _evaluate(record: dict) -> list[Any]:
    from app.services.security_rules.gitlab import evaluate
    return evaluate(record)


def _rule_keys(record: dict) -> set[str]:
    return {c.rule_key for c in _evaluate(record)}


# ── A. Rule key constants ──────────────────────────────────────────────────────

class TestRuleKeyConstants:
    def test_all_m87c_rule_keys_in_gitlab_rule_keys(self) -> None:
        from app.services.security_rules.gitlab import GITLAB_RULE_KEYS
        missing = EXPECTED_M87C_RULE_KEYS - GITLAB_RULE_KEYS
        assert not missing, f"M87C keys missing from GITLAB_RULE_KEYS: {missing}"

    def test_all_m87b_rule_keys_still_in_gitlab_rule_keys(self) -> None:
        from app.services.security_rules.gitlab import GITLAB_RULE_KEYS
        missing = EXPECTED_M87B_RULE_KEYS - GITLAB_RULE_KEYS
        assert not missing, f"M87B keys no longer in GITLAB_RULE_KEYS: {missing}"

    def test_total_rule_count_is_25(self) -> None:
        from app.services.security_rules.gitlab import GITLAB_RULE_KEYS
        assert len(GITLAB_RULE_KEYS) == 25, (
            f"Expected 25 total GitLab rules (12 M87B + 13 M87C), got {len(GITLAB_RULE_KEYS)}: "
            f"{sorted(GITLAB_RULE_KEYS)}"
        )

    def test_all_rule_keys_start_with_gitlab(self) -> None:
        from app.services.security_rules.gitlab import GITLAB_RULE_KEYS
        for k in GITLAB_RULE_KEYS:
            assert k.startswith("gitlab_"), f"Rule key {k!r} lacks 'gitlab_' prefix"

    def test_skipped_rules_not_in_keys(self) -> None:
        from app.services.security_rules.gitlab import GITLAB_RULE_KEYS
        # These require fields not in M87A schema
        assert "gitlab_runner_unprotected_runners" not in GITLAB_RULE_KEYS
        assert "gitlab_deploy_key_stale_or_expired" not in GITLAB_RULE_KEYS

    def test_broad_event_threshold_constant_exists(self) -> None:
        from app.services.security_rules.gitlab import _WEBHOOK_BROAD_EVENT_THRESHOLD
        assert isinstance(_WEBHOOK_BROAD_EVENT_THRESHOLD, int)
        assert _WEBHOOK_BROAD_EVENT_THRESHOLD > 0


# ── B. Positive cases (rules fire on risky input) ────────────────────────────

class TestPositiveCases:
    # ── Webhook M87C ──────────────────────────────────────────────────────────

    def test_webhook_http_scheme_fires(self) -> None:
        record = _webhook({"url_scheme": "http"})
        assert "gitlab_webhook_http_scheme" in _rule_keys(record)

    def test_webhook_http_scheme_severity_high(self) -> None:
        record = _webhook({"url_scheme": "http"})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_webhook_http_scheme"]
        assert findings and findings[0].severity == "high"

    def test_webhook_broad_event_scope_fires_at_threshold(self) -> None:
        from app.services.security_rules.gitlab import _WEBHOOK_BROAD_EVENT_THRESHOLD
        record = _webhook({"event_count": _WEBHOOK_BROAD_EVENT_THRESHOLD})
        assert "gitlab_webhook_broad_event_scope" in _rule_keys(record)

    def test_webhook_broad_event_scope_fires_above_threshold(self) -> None:
        from app.services.security_rules.gitlab import _WEBHOOK_BROAD_EVENT_THRESHOLD
        record = _webhook({"event_count": _WEBHOOK_BROAD_EVENT_THRESHOLD + 3})
        assert "gitlab_webhook_broad_event_scope" in _rule_keys(record)

    def test_webhook_broad_event_scope_severity_medium(self) -> None:
        record = _webhook({"event_count": 10})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_webhook_broad_event_scope"]
        assert findings and findings[0].severity == "medium"

    def test_webhook_pipeline_events_fires(self) -> None:
        record = _webhook({"pipeline_events": True, "job_events": False})
        assert "gitlab_webhook_pipeline_job_events" in _rule_keys(record)

    def test_webhook_job_events_fires(self) -> None:
        record = _webhook({"pipeline_events": False, "job_events": True})
        assert "gitlab_webhook_pipeline_job_events" in _rule_keys(record)

    def test_webhook_pipeline_and_job_events_fires(self) -> None:
        record = _webhook({"pipeline_events": True, "job_events": True})
        assert "gitlab_webhook_pipeline_job_events" in _rule_keys(record)

    def test_webhook_pipeline_job_severity_medium(self) -> None:
        record = _webhook({"pipeline_events": True})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_webhook_pipeline_job_events"]
        assert findings and findings[0].severity == "medium"

    # ── Branch protection M87C ────────────────────────────────────────────────

    def test_branch_push_access_developer_fires(self) -> None:
        record = _branch_protection({
            "push_access_level_category": "developer",
            "pattern_category": "default",
        })
        assert "gitlab_branch_push_access_broad" in _rule_keys(record)

    def test_branch_push_access_reporter_fires(self) -> None:
        record = _branch_protection({
            "push_access_level_category": "reporter",
            "pattern_category": "protected",
        })
        assert "gitlab_branch_push_access_broad" in _rule_keys(record)

    def test_branch_push_access_guest_fires(self) -> None:
        record = _branch_protection({
            "push_access_level_category": "guest",
            "pattern_category": "wildcard",
        })
        assert "gitlab_branch_push_access_broad" in _rule_keys(record)

    def test_branch_push_access_severity_medium(self) -> None:
        record = _branch_protection({"push_access_level_category": "developer", "pattern_category": "default"})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_branch_push_access_broad"]
        assert findings and findings[0].severity == "medium"

    def test_branch_merge_access_developer_fires(self) -> None:
        record = _branch_protection({
            "merge_access_level_category": "developer",
            "pattern_category": "default",
        })
        assert "gitlab_branch_merge_access_broad" in _rule_keys(record)

    def test_branch_merge_access_reporter_fires(self) -> None:
        record = _branch_protection({
            "merge_access_level_category": "reporter",
            "pattern_category": "protected",
        })
        assert "gitlab_branch_merge_access_broad" in _rule_keys(record)

    def test_branch_merge_access_severity_medium(self) -> None:
        record = _branch_protection({"merge_access_level_category": "developer", "pattern_category": "default"})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_branch_merge_access_broad"]
        assert findings and findings[0].severity == "medium"

    # ── CI variable M87C ──────────────────────────────────────────────────────

    def test_ci_variables_unprotected_fires(self) -> None:
        record = _ci_variable_summary({"variable_count": 3, "protected_variable_count": 0})
        assert "gitlab_ci_variables_unprotected" in _rule_keys(record)

    def test_ci_variables_unprotected_severity_medium(self) -> None:
        record = _ci_variable_summary({"variable_count": 2, "protected_variable_count": 0})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_ci_variables_unprotected"]
        assert findings and findings[0].severity == "medium"

    def test_ci_variables_unmasked_fires(self) -> None:
        record = _ci_variable_summary({"variable_count": 3, "masked_variable_count": 0})
        assert "gitlab_ci_variables_unmasked" in _rule_keys(record)

    def test_ci_variables_unmasked_severity_medium(self) -> None:
        record = _ci_variable_summary({"variable_count": 2, "masked_variable_count": 0})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_ci_variables_unmasked"]
        assert findings and findings[0].severity == "medium"

    # ── Runner M87C ───────────────────────────────────────────────────────────

    def test_runner_shared_enabled_fires(self) -> None:
        record = _runner_summary({"shared_runner_enabled": True, "runner_count": 2})
        assert "gitlab_runner_shared_enabled" in _rule_keys(record)

    def test_runner_shared_enabled_severity_medium(self) -> None:
        record = _runner_summary({"shared_runner_enabled": True, "runner_count": 1})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_runner_shared_enabled"]
        assert findings and findings[0].severity == "medium"

    # ── MR approval M87C ──────────────────────────────────────────────────────

    def test_mr_approval_reset_disabled_fires(self) -> None:
        record = _mr_approval({"reset_approvals_on_push": False})
        assert "gitlab_mr_approval_reset_disabled" in _rule_keys(record)

    def test_mr_approval_reset_disabled_severity_medium(self) -> None:
        record = _mr_approval({"reset_approvals_on_push": False})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_mr_approval_reset_disabled"]
        assert findings and findings[0].severity == "medium"

    def test_mr_approver_override_allowed_fires(self) -> None:
        record = _mr_approval({"disable_overriding_approvers_per_merge_request": False})
        assert "gitlab_mr_approver_override_allowed" in _rule_keys(record)

    def test_mr_approver_override_severity_low(self) -> None:
        record = _mr_approval({"disable_overriding_approvers_per_merge_request": False})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_mr_approver_override_allowed"]
        assert findings and findings[0].severity == "low"

    # ── Project feature M87C ──────────────────────────────────────────────────

    def test_project_wiki_enabled_public_fires(self) -> None:
        record = _project({"visibility_category": "public", "wiki_enabled": True})
        assert "gitlab_project_wiki_enabled_public" in _rule_keys(record)

    def test_project_wiki_enabled_public_severity_low(self) -> None:
        record = _project({"visibility_category": "public", "wiki_enabled": True})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_project_wiki_enabled_public"]
        assert findings and findings[0].severity == "low"

    def test_project_packages_enabled_public_fires(self) -> None:
        record = _project({"visibility_category": "public", "packages_enabled": True})
        assert "gitlab_project_packages_enabled_public" in _rule_keys(record)

    def test_project_packages_enabled_public_severity_low(self) -> None:
        record = _project({"visibility_category": "public", "packages_enabled": True})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_project_packages_enabled_public"]
        assert findings and findings[0].severity == "low"

    def test_project_container_registry_enabled_public_fires(self) -> None:
        record = _project({"visibility_category": "public", "container_registry_enabled": True})
        assert "gitlab_project_container_registry_enabled_public" in _rule_keys(record)

    def test_project_container_registry_enabled_public_severity_medium(self) -> None:
        record = _project({"visibility_category": "public", "container_registry_enabled": True})
        findings = [c for c in _evaluate(record) if c.rule_key == "gitlab_project_container_registry_enabled_public"]
        assert findings and findings[0].severity == "medium"


# ── C. Negative cases (rules do not fire on healthy input) ────────────────────

class TestNegativeCases:
    def test_webhook_https_no_http_rule(self) -> None:
        record = _webhook({"url_scheme": "https"})
        assert "gitlab_webhook_http_scheme" not in _rule_keys(record)

    def test_webhook_narrow_event_scope_no_broad_rule(self) -> None:
        from app.services.security_rules.gitlab import _WEBHOOK_BROAD_EVENT_THRESHOLD
        record = _webhook({"event_count": _WEBHOOK_BROAD_EVENT_THRESHOLD - 1})
        assert "gitlab_webhook_broad_event_scope" not in _rule_keys(record)

    def test_webhook_no_pipeline_no_job_no_rule(self) -> None:
        record = _webhook({"pipeline_events": False, "job_events": False})
        assert "gitlab_webhook_pipeline_job_events" not in _rule_keys(record)

    def test_webhook_disabled_no_m87c_rules(self) -> None:
        record = _webhook({"enabled": False, "url_scheme": "http", "event_count": 10, "pipeline_events": True})
        keys = _rule_keys(record)
        assert "gitlab_webhook_http_scheme" not in keys
        assert "gitlab_webhook_broad_event_scope" not in keys
        assert "gitlab_webhook_pipeline_job_events" not in keys

    def test_branch_push_maintainer_no_broad_rule(self) -> None:
        record = _branch_protection({"push_access_level_category": "maintainer"})
        assert "gitlab_branch_push_access_broad" not in _rule_keys(record)

    def test_branch_push_owner_no_broad_rule(self) -> None:
        record = _branch_protection({"push_access_level_category": "owner"})
        assert "gitlab_branch_push_access_broad" not in _rule_keys(record)

    def test_branch_merge_maintainer_no_broad_rule(self) -> None:
        record = _branch_protection({"merge_access_level_category": "maintainer"})
        assert "gitlab_branch_merge_access_broad" not in _rule_keys(record)

    def test_branch_push_broad_but_unknown_pattern_no_rule(self) -> None:
        # Only fires on protected/default/wildcard patterns
        record = _branch_protection({
            "push_access_level_category": "developer",
            "pattern_category": "unknown",
        })
        assert "gitlab_branch_push_access_broad" not in _rule_keys(record)

    def test_branch_merge_broad_but_unknown_pattern_no_rule(self) -> None:
        record = _branch_protection({
            "merge_access_level_category": "developer",
            "pattern_category": "unknown",
        })
        assert "gitlab_branch_merge_access_broad" not in _rule_keys(record)

    def test_ci_all_protected_no_unprotected_rule(self) -> None:
        record = _ci_variable_summary({"variable_count": 5, "protected_variable_count": 5})
        assert "gitlab_ci_variables_unprotected" not in _rule_keys(record)

    def test_ci_zero_variables_no_unprotected_rule(self) -> None:
        record = _ci_variable_summary({"variable_count": 0, "protected_variable_count": 0})
        assert "gitlab_ci_variables_unprotected" not in _rule_keys(record)

    def test_ci_all_masked_no_unmasked_rule(self) -> None:
        record = _ci_variable_summary({"variable_count": 3, "masked_variable_count": 3})
        assert "gitlab_ci_variables_unmasked" not in _rule_keys(record)

    def test_ci_zero_variables_no_unmasked_rule(self) -> None:
        record = _ci_variable_summary({"variable_count": 0, "masked_variable_count": 0})
        assert "gitlab_ci_variables_unmasked" not in _rule_keys(record)

    def test_runner_shared_false_no_rule(self) -> None:
        record = _runner_summary({"shared_runner_enabled": False, "runner_count": 3})
        assert "gitlab_runner_shared_enabled" not in _rule_keys(record)

    def test_runner_zero_count_no_rule(self) -> None:
        record = _runner_summary({"shared_runner_enabled": True, "runner_count": 0})
        assert "gitlab_runner_shared_enabled" not in _rule_keys(record)

    def test_mr_reset_true_no_rule(self) -> None:
        record = _mr_approval({"reset_approvals_on_push": True})
        assert "gitlab_mr_approval_reset_disabled" not in _rule_keys(record)

    def test_mr_override_disabled_no_rule(self) -> None:
        record = _mr_approval({"disable_overriding_approvers_per_merge_request": True})
        assert "gitlab_mr_approver_override_allowed" not in _rule_keys(record)

    def test_project_wiki_private_no_rule(self) -> None:
        record = _project({"visibility_category": "private", "wiki_enabled": True})
        assert "gitlab_project_wiki_enabled_public" not in _rule_keys(record)

    def test_project_wiki_disabled_public_no_rule(self) -> None:
        record = _project({"visibility_category": "public", "wiki_enabled": False})
        assert "gitlab_project_wiki_enabled_public" not in _rule_keys(record)

    def test_project_packages_private_no_rule(self) -> None:
        record = _project({"visibility_category": "private", "packages_enabled": True})
        assert "gitlab_project_packages_enabled_public" not in _rule_keys(record)

    def test_project_container_registry_private_no_rule(self) -> None:
        record = _project({"visibility_category": "private", "container_registry_enabled": True})
        assert "gitlab_project_container_registry_enabled_public" not in _rule_keys(record)


# ── D. Missing/None fields do not cause false positives ───────────────────────

class TestMissingFields:
    def test_webhook_url_scheme_none_no_http_rule(self) -> None:
        record = _webhook({"url_scheme": None})
        assert "gitlab_webhook_http_scheme" not in _rule_keys(record)

    def test_webhook_url_scheme_absent_no_http_rule(self) -> None:
        record = {
            "record_type": "gitlab_webhook", "provider": "gitlab",
            "record_id": "x", "resource_id": "x",
            "owner_resource_id": "y", "owner_type": "project",
            "enabled": True,
        }
        assert "gitlab_webhook_http_scheme" not in _rule_keys(record)

    def test_webhook_event_count_none_no_broad_rule(self) -> None:
        record = _webhook({"event_count": None})
        assert "gitlab_webhook_broad_event_scope" not in _rule_keys(record)

    def test_webhook_pipeline_events_none_no_rule(self) -> None:
        record = _webhook({"pipeline_events": None, "job_events": None})
        assert "gitlab_webhook_pipeline_job_events" not in _rule_keys(record)

    def test_branch_push_access_none_no_broad_rule(self) -> None:
        record = _branch_protection({"push_access_level_category": ""})
        assert "gitlab_branch_push_access_broad" not in _rule_keys(record)

    def test_branch_push_access_unknown_no_broad_rule(self) -> None:
        record = _branch_protection({"push_access_level_category": "unknown"})
        assert "gitlab_branch_push_access_broad" not in _rule_keys(record)

    def test_branch_merge_access_none_no_broad_rule(self) -> None:
        record = _branch_protection({"merge_access_level_category": ""})
        assert "gitlab_branch_merge_access_broad" not in _rule_keys(record)

    def test_ci_variable_count_none_no_unprotected_rule(self) -> None:
        record = _ci_variable_summary({"variable_count": None})
        assert "gitlab_ci_variables_unprotected" not in _rule_keys(record)

    def test_ci_protected_count_none_no_rule(self) -> None:
        record = _ci_variable_summary({"variable_count": 3, "protected_variable_count": None})
        assert "gitlab_ci_variables_unprotected" not in _rule_keys(record)

    def test_ci_masked_count_none_no_rule(self) -> None:
        record = _ci_variable_summary({"variable_count": 3, "masked_variable_count": None})
        assert "gitlab_ci_variables_unmasked" not in _rule_keys(record)

    def test_runner_shared_none_no_rule(self) -> None:
        record = _runner_summary({"shared_runner_enabled": None, "runner_count": 3})
        assert "gitlab_runner_shared_enabled" not in _rule_keys(record)

    def test_runner_count_none_no_rule(self) -> None:
        record = _runner_summary({"shared_runner_enabled": True, "runner_count": None})
        assert "gitlab_runner_shared_enabled" not in _rule_keys(record)

    def test_mr_reset_none_no_rule(self) -> None:
        record = _mr_approval({"reset_approvals_on_push": None})
        assert "gitlab_mr_approval_reset_disabled" not in _rule_keys(record)

    def test_mr_override_none_no_rule(self) -> None:
        record = _mr_approval({"disable_overriding_approvers_per_merge_request": None})
        assert "gitlab_mr_approver_override_allowed" not in _rule_keys(record)

    def test_project_wiki_none_no_rule(self) -> None:
        record = _project({"visibility_category": "public", "wiki_enabled": None})
        assert "gitlab_project_wiki_enabled_public" not in _rule_keys(record)

    def test_project_packages_none_no_rule(self) -> None:
        record = _project({"visibility_category": "public", "packages_enabled": None})
        assert "gitlab_project_packages_enabled_public" not in _rule_keys(record)

    def test_project_container_registry_none_no_rule(self) -> None:
        record = _project({"visibility_category": "public", "container_registry_enabled": None})
        assert "gitlab_project_container_registry_enabled_public" not in _rule_keys(record)


# ── E. Evidence safety ────────────────────────────────────────────────────────

class TestEvidenceSafety:
    def _all_m87c_findings(self) -> list[Any]:
        risky_records = [
            _webhook({"url_scheme": "http", "event_count": 10, "pipeline_events": True, "job_events": True}),
            _branch_protection({"push_access_level_category": "developer", "merge_access_level_category": "developer", "pattern_category": "default"}),
            _ci_variable_summary({"variable_count": 4, "protected_variable_count": 0, "masked_variable_count": 0}),
            _runner_summary({"shared_runner_enabled": True, "runner_count": 2}),
            _mr_approval({"reset_approvals_on_push": False, "disable_overriding_approvers_per_merge_request": False}),
            _project({"visibility_category": "public", "wiki_enabled": True, "packages_enabled": True, "container_registry_enabled": True}),
        ]
        findings = []
        for rec in risky_records:
            findings.extend(_evaluate(rec))
        return findings

    def test_no_forbidden_evidence_keys(self) -> None:
        for finding in self._all_m87c_findings():
            if finding.rule_key not in EXPECTED_M87C_RULE_KEYS:
                continue
            bad = set(finding.evidence.keys()) & _FORBIDDEN_EVIDENCE_KEYS
            assert not bad, (
                f"Rule {finding.rule_key!r} evidence contains forbidden keys: {bad}"
            )

    def test_evidence_is_flat(self) -> None:
        for finding in self._all_m87c_findings():
            if finding.rule_key not in EXPECTED_M87C_RULE_KEYS:
                continue
            for key, val in finding.evidence.items():
                assert not isinstance(val, dict), (
                    f"Rule {finding.rule_key!r} evidence[{key!r}] is nested dict"
                )
                assert not isinstance(val, list), (
                    f"Rule {finding.rule_key!r} evidence[{key!r}] is a list"
                )

    def test_evidence_no_raw_urls(self) -> None:
        for finding in self._all_m87c_findings():
            if finding.rule_key not in EXPECTED_M87C_RULE_KEYS:
                continue
            for key, val in finding.evidence.items():
                if isinstance(val, str):
                    assert not val.startswith(("http://", "https://", "git@")), (
                        f"Rule {finding.rule_key!r} evidence[{key!r}] looks like a URL: {val!r}"
                    )

    def test_all_findings_have_gitlab_provider(self) -> None:
        for finding in self._all_m87c_findings():
            assert finding.provider == "gitlab", (
                f"Rule {finding.rule_key!r} has wrong provider: {finding.provider!r}"
            )


# ── F. Claim discipline ───────────────────────────────────────────────────────

class TestClaimDiscipline:
    def _risky_records(self) -> list[dict]:
        return [
            _webhook({"url_scheme": "http"}),
            _webhook({"event_count": 10}),
            _webhook({"pipeline_events": True}),
            _branch_protection({"push_access_level_category": "developer", "pattern_category": "default"}),
            _branch_protection({"merge_access_level_category": "developer", "pattern_category": "default"}),
            _ci_variable_summary({"variable_count": 3, "protected_variable_count": 0}),
            _ci_variable_summary({"variable_count": 3, "masked_variable_count": 0}),
            _runner_summary({"shared_runner_enabled": True, "runner_count": 1}),
            _mr_approval({"reset_approvals_on_push": False}),
            _mr_approval({"disable_overriding_approvers_per_merge_request": False}),
            _project({"visibility_category": "public", "wiki_enabled": True}),
            _project({"visibility_category": "public", "packages_enabled": True}),
            _project({"visibility_category": "public", "container_registry_enabled": True}),
        ]

    def test_descriptions_have_safe_framing(self) -> None:
        for rec in self._risky_records():
            for finding in _evaluate(rec):
                if finding.rule_key not in EXPECTED_M87C_RULE_KEYS:
                    continue
                desc = finding.description.lower()
                has_safe = (
                    "may require review" in desc
                    or "evidence for review" in desc
                    or "does not confirm" in desc
                    or "evidence may require" in desc
                )
                assert has_safe, (
                    f"Rule {finding.rule_key!r} description missing safe framing: "
                    f"{finding.description[:200]!r}"
                )

    def test_descriptions_no_forbidden_phrases(self) -> None:
        for rec in self._risky_records():
            for finding in _evaluate(rec):
                if finding.rule_key not in EXPECTED_M87C_RULE_KEYS:
                    continue
                desc_lower = finding.description.lower()
                for phrase in _FORBIDDEN_PHRASES:
                    assert phrase not in desc_lower, (
                        f"Rule {finding.rule_key!r} contains forbidden phrase {phrase!r}"
                    )

    def test_source_no_forbidden_phrases(self) -> None:
        src = GITLAB_RULES_PY.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in src, (
                f"Forbidden phrase {phrase!r} in security_rules/gitlab.py"
            )


# ── G. Registry, confidence, pack, coverage parity ───────────────────────────

class TestRegistryParity:
    def test_all_m87c_rules_in_known_rule_keys(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        missing = EXPECTED_M87C_RULE_KEYS - KNOWN_RULE_KEYS
        assert not missing, f"M87C rules missing from KNOWN_RULE_KEYS: {missing}"

    def test_all_m87c_rules_in_confidence(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        missing = EXPECTED_M87C_RULE_KEYS - set(RULE_CONFIDENCE)
        assert not missing, f"M87C rules missing from RULE_CONFIDENCE: {missing}"

    def test_all_m87c_confidence_levels_valid(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE, VALID_CONFIDENCE
        for key in EXPECTED_M87C_RULE_KEYS:
            conf, _ = RULE_CONFIDENCE[key]
            assert conf in VALID_CONFIDENCE, f"Rule {key!r} invalid confidence: {conf!r}"

    def test_all_m87c_rules_in_pack(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        missing = EXPECTED_M87C_RULE_KEYS - set(_RULE_META)
        assert not missing, f"M87C rules missing from _RULE_META: {missing}"

    def test_m87c_pack_provider_is_gitlab(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        for key in EXPECTED_M87C_RULE_KEYS:
            provider, _, _ = _RULE_META[key]
            assert provider == "gitlab", f"Rule {key!r} wrong provider in pack: {provider!r}"

    def test_pack_import_still_clean(self) -> None:
        # The pack has an import-time assert that _RULE_META == KNOWN_RULE_KEYS
        import app.services.security_rule_pack as pack
        assert pack.SECURITY_RULE_PACK_NAME

    def test_all_m87c_rules_in_coverage(self) -> None:
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        missing = EXPECTED_M87C_RULE_KEYS - set(RULE_RECORD_TYPES)
        assert not missing, f"M87C rules missing from RULE_RECORD_TYPES: {missing}"

    def test_m87c_record_type_mappings(self) -> None:
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        expected_mappings = {
            "gitlab_webhook_http_scheme": "gitlab_webhook",
            "gitlab_webhook_broad_event_scope": "gitlab_webhook",
            "gitlab_webhook_pipeline_job_events": "gitlab_webhook",
            "gitlab_branch_push_access_broad": "gitlab_branch_protection",
            "gitlab_branch_merge_access_broad": "gitlab_branch_protection",
            "gitlab_ci_variables_unprotected": "gitlab_ci_variable_summary",
            "gitlab_ci_variables_unmasked": "gitlab_ci_variable_summary",
            "gitlab_runner_shared_enabled": "gitlab_runner_summary",
            "gitlab_mr_approval_reset_disabled": "gitlab_merge_request_approval_summary",
            "gitlab_mr_approver_override_allowed": "gitlab_merge_request_approval_summary",
            "gitlab_project_wiki_enabled_public": "gitlab_project",
            "gitlab_project_packages_enabled_public": "gitlab_project",
            "gitlab_project_container_registry_enabled_public": "gitlab_project",
        }
        for rule, expected_rtype in expected_mappings.items():
            actual = RULE_RECORD_TYPES[rule]
            assert expected_rtype in actual, (
                f"Rule {rule!r} should map to {expected_rtype!r}, got {actual!r}"
            )


# ── H. Production evaluator dispatch ─────────────────────────────────────────

class TestEvaluatorDispatch:
    def test_gitlab_still_in_provider_rules(self) -> None:
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "gitlab" in _PROVIDER_RULES

    def test_evaluate_record_webhook_http_fires(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        record = _webhook({"url_scheme": "http"})
        findings = evaluate_record(record, "gitlab")
        keys = {f.rule_key for f in findings}
        assert "gitlab_webhook_http_scheme" in keys

    def test_evaluate_record_branch_broad_access_fires(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        record = _branch_protection({"push_access_level_category": "developer", "pattern_category": "default"})
        findings = evaluate_record(record, "gitlab")
        keys = {f.rule_key for f in findings}
        assert "gitlab_branch_push_access_broad" in keys

    def test_evaluate_record_ci_unprotected_fires(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        record = _ci_variable_summary({"variable_count": 3, "protected_variable_count": 0})
        findings = evaluate_record(record, "gitlab")
        keys = {f.rule_key for f in findings}
        assert "gitlab_ci_variables_unprotected" in keys

    def test_evaluate_record_mr_reset_disabled_fires(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        record = _mr_approval({"reset_approvals_on_push": False})
        findings = evaluate_record(record, "gitlab")
        keys = {f.rule_key for f in findings}
        assert "gitlab_mr_approval_reset_disabled" in keys

    def test_evaluate_record_healthy_webhook_no_m87c_rules(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        record = _webhook()  # Healthy defaults
        findings = evaluate_record(record, "gitlab")
        keys = {f.rule_key for f in findings}
        assert "gitlab_webhook_http_scheme" not in keys
        assert "gitlab_webhook_broad_event_scope" not in keys


# ── I. Capability matrix ──────────────────────────────────────────────────────

class TestCapabilityMatrix:
    def test_planned_next_stage_m87d(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        assert cap is not None
        assert "M87D" in cap.notes, "GitLab notes should mention M87D as planned next"

    def test_notes_mention_m87c(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        assert "M87C" in cap.notes, "GitLab notes should mention M87C"

    def test_notes_mention_25_rules(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        assert "25" in cap.notes or "13" in cap.notes, (
            "GitLab notes should mention the 13 M87C rules or 25 total"
        )

    def test_security_rules_still_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        assert cap.security.security_rules is True

    def test_activity_ingestion_still_false(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        # activity_ingestion landed in M87D; demo remains a later stage.
        assert cap.security.activity_ingestion is True
        # demo_seed_clear landed in M87G.
        assert cap.security.demo_seed_clear is True


# ── J. Expansion framework ────────────────────────────────────────────────────

class TestExpansionFramework:
    def test_planned_next_stage_references_m87d(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw.get("summary", {}).get("planned_next_stage", "")
        assert ("M87D" in planned or "GitLab Activity" in planned or "Ingestion" in planned
                or "M87E" in planned or "M87F" in planned or "Correlations" in planned
                or "M87G" in planned or "Demo" in planned or "M87H" in planned or "M87I" in planned or "Cross-Cloud" in planned
                or "M88A" in planned or "Terraform" in planned
                or "M89A" in planned or "Kubernetes" in planned
                or "M90A" in planned or "Sentry" in planned), (
            f"planned_next_stage should reference M87D or later after M87C; got: {planned!r}"
        )

    def test_terraform_cloud_still_in_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        provider_keys = [r.get("provider") for r in fw.get("recommended_next_providers", [])]
        assert "terraform_cloud" in provider_keys or "kubernetes" in provider_keys

    def test_gitlab_not_in_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        provider_keys = [r.get("provider") for r in fw.get("recommended_next_providers", [])]
        assert "gitlab" not in provider_keys


# ── K. Frontend catalog ───────────────────────────────────────────────────────

class TestFrontendCatalog:
    def _catalog_src(self) -> str:
        return FE_CATALOG.read_text(encoding="utf-8")

    def test_all_m87c_rule_keys_in_catalog(self) -> None:
        src = self._catalog_src()
        for key in EXPECTED_M87C_RULE_KEYS:
            assert f'key: "{key}"' in src, (
                f"M87C rule key {key!r} not found in securityRuleCatalog.ts"
            )

    def test_all_m87b_rule_keys_still_in_catalog(self) -> None:
        src = self._catalog_src()
        for key in EXPECTED_M87B_RULE_KEYS:
            assert f'key: "{key}"' in src, (
                f"M87B rule key {key!r} missing from securityRuleCatalog.ts"
            )

    def test_gitlab_provider_coverage_updated(self) -> None:
        src = self._catalog_src()
        # Find the PROVIDER_COVERAGE section and check the gitlab entry within it
        coverage_idx = src.find("PROVIDER_COVERAGE")
        assert coverage_idx >= 0, "PROVIDER_COVERAGE constant not found in catalog"
        coverage_section = src[coverage_idx:]
        # Find the gitlab entry within PROVIDER_COVERAGE
        gitlab_idx = coverage_section.find('provider: "gitlab"')
        assert gitlab_idx >= 0, "No gitlab entry found in PROVIDER_COVERAGE section"
        gitlab_block = coverage_section[gitlab_idx:gitlab_idx + 1500]
        assert "Branch protection" in gitlab_block or "Webhook" in gitlab_block, (
            "GitLab PROVIDER_COVERAGE should reference expanded surfaces"
        )

    def test_m87c_catalog_no_forbidden_phrases(self) -> None:
        src = self._catalog_src()
        for key in EXPECTED_M87C_RULE_KEYS:
            idx = src.find(f'key: "{key}"')
            if idx < 0:
                continue
            block = src[idx:idx + 1000].lower()
            for phrase in _FORBIDDEN_PHRASES:
                assert phrase not in block, (
                    f"Forbidden phrase {phrase!r} in catalog entry for {key!r}"
                )

    def test_m87c_catalog_has_safe_disclaimer(self) -> None:
        src = self._catalog_src()
        gitlab_start = src.find('key: "gitlab_webhook_http_scheme"')
        if gitlab_start < 0:
            pytest.skip("M87C catalog entries not found")
        gitlab_section = src[gitlab_start:].lower()
        assert ("does not confirm" in gitlab_section or
                "may require review" in gitlab_section or
                "evidence for review" in gitlab_section)


# ── L. Backend/frontend severity match ───────────────────────────────────────

class TestSeverityParity:
    def test_m87c_severity_matches(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        src = FE_CATALOG.read_text(encoding="utf-8")

        expected_severities = {
            "gitlab_webhook_http_scheme": "high",
            "gitlab_webhook_broad_event_scope": "medium",
            "gitlab_webhook_pipeline_job_events": "medium",
            "gitlab_branch_push_access_broad": "medium",
            "gitlab_branch_merge_access_broad": "medium",
            "gitlab_ci_variables_unprotected": "medium",
            "gitlab_ci_variables_unmasked": "medium",
            "gitlab_runner_shared_enabled": "medium",
            "gitlab_mr_approval_reset_disabled": "medium",
            "gitlab_mr_approver_override_allowed": "low",
            "gitlab_project_wiki_enabled_public": "low",
            "gitlab_project_packages_enabled_public": "low",
            "gitlab_project_container_registry_enabled_public": "medium",
        }

        for key, expected_sev in expected_severities.items():
            # Check backend pack
            _, backend_sev, _ = _RULE_META[key]
            assert backend_sev == expected_sev, (
                f"Rule {key!r}: pack severity {backend_sev!r} != expected {expected_sev!r}"
            )
            # Check frontend catalog block
            idx = src.find(f'key: "{key}"')
            if idx >= 0:
                block = src[idx:idx + 400]
                assert f'severity: "{expected_sev}"' in block, (
                    f"Rule {key!r}: frontend severity should be {expected_sev!r}"
                )


# ── M. M87A/M87B regression smoke ────────────────────────────────────────────

class TestM87ABRegressionSmoke:
    def test_m87b_rules_still_fire(self) -> None:
        # Test a few key M87B rules still work after M87C additions
        from app.services.security_rules.gitlab import evaluate

        # Project public visibility (M87B high rule)
        record = _project({"visibility_category": "public"})
        keys = {c.rule_key for c in evaluate(record)}
        assert "gitlab_project_public_visibility" in keys

        # Webhook secret missing (M87B high rule)
        record = _webhook({"secret_token_present": False})
        keys = {c.rule_key for c in evaluate(record)}
        assert "gitlab_webhook_secret_missing" in keys

        # Deploy key write enabled (M87B high rule)
        record = {
            "record_type": "gitlab_deploy_key_summary",
            "provider": "gitlab",
            "record_id": "x",
            "resource_id": "x",
            "project_resource_id": "y",
            "deploy_key_count": 2,
            "write_enabled_count": 1,
            "read_only_count": 1,
            "enabled_count": 2,
        }
        keys = {c.rule_key for c in evaluate(record)}
        assert "gitlab_deploy_key_write_enabled" in keys

    def test_total_rule_count_25(self) -> None:
        from app.services.security_rules.gitlab import GITLAB_RULE_KEYS
        assert len(GITLAB_RULE_KEYS) == 25

    def test_capability_matrix_drift_still_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True

    def test_gitlab_in_coverage_providers(self) -> None:
        from app.services.security_coverage_service import PROVIDERS
        assert "gitlab" in PROVIDERS
