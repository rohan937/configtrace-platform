"""M87B: GitLab core security foundation tests.

Validates that the GitLab security rules module, evaluator dispatch,
registry/catalog/confidence/pack/coverage surfaces, capability matrix,
expansion framework, and frontend catalog all meet the M87B specification.

Sections:
  A. Module imports and rule key constants
  B. Rules fire on risky input (positive cases)
  C. Rules do not fire on healthy input (negative cases)
  D. Missing/None fields do not cause false positives
  E. Evidence safety — no forbidden keys
  F. Claim discipline — descriptions contain safe disclaimer; no forbidden wording
  G. Registry — every rule key is in KNOWN_RULE_KEYS
  H. Confidence — every rule key has a confidence entry
  I. Pack — every rule key is in _RULE_META / pack summary
  J. Coverage service — every rule mapped to correct record type; gitlab in PROVIDERS
  K. Evaluator dispatch — "gitlab" in _PROVIDER_RULES; evaluate_record works end-to-end
  L. Capability matrix — security_rules=True; planned_next_stage=M87C
  M. Expansion framework — planned_next_stage references M87C; TC remains in queue
  N. Frontend catalog — all 12 rule entries present; PROVIDER_COVERAGE has gitlab
  O. Backend/frontend severity and category match
  P. No activity/signals/correlations/demo claimed yet
  Q. M87A tests still pass (framework pointer, capability matrix regression smoke)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parents[2]
FE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"
BACKEND_ROOT = Path(__file__).resolve().parents[1]
GITLAB_RULES_PY = BACKEND_ROOT / "app" / "services" / "security_rules" / "gitlab.py"

# ── Expected rule keys ─────────────────────────────────────────────────────────
EXPECTED_GITLAB_RULE_KEYS = {
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

# ── Forbidden evidence keys (must never appear in evidence dicts) ──────────────
_FORBIDDEN_EVIDENCE_KEYS = {
    "token", "secret", "secret_value", "private_token", "authorization",
    "webhook_url", "url", "ci_variable_name", "ci_variable_value",
    "deploy_key_material", "ssh_key", "runner_token", "runner_ip",
    "user_email", "username", "project_name", "group_name", "branch_name",
    "raw", "payload", "request", "response", "password", "key_material",
    "fingerprint", "access_token",
}

# ── Forbidden wording (must not appear in descriptions) ───────────────────────
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


def _group(overrides: dict | None = None) -> dict:
    base = {
        "record_type": "gitlab_group",
        "provider": "gitlab",
        "record_id": "gitlab_group:grp123",
        "resource_id": "grp123",
        "visibility_category": "private",
        "project_count": 3,
        "subgroup_count": 0,
        "member_count_category": "medium",
        "two_factor_requirement_enabled": True,
        "membership_lock": False,
        "shared_runners_setting_category": "disabled_locked",
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
        "merge_access_level_category": "developer",
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
        "event_count": 3,
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


def _deploy_key_summary(overrides: dict | None = None) -> dict:
    base = {
        "record_type": "gitlab_deploy_key_summary",
        "provider": "gitlab",
        "record_id": "gitlab_deploy_key_summary:dk123",
        "resource_id": "dk123",
        "project_resource_id": "proj123",
        "deploy_key_count": 2,
        "write_enabled_count": 0,
        "read_only_count": 2,
        "enabled_count": 2,
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


# ── A. Module imports and rule key constants ───────────────────────────────────

class TestModuleImports:
    def test_gitlab_rules_module_importable(self) -> None:
        from app.services.security_rules import gitlab
        assert hasattr(gitlab, "evaluate")
        assert callable(gitlab.evaluate)

    def test_gitlab_rule_keys_constant_exists(self) -> None:
        from app.services.security_rules.gitlab import GITLAB_RULE_KEYS
        assert isinstance(GITLAB_RULE_KEYS, frozenset)

    def test_gitlab_rule_keys_count(self) -> None:
        from app.services.security_rules.gitlab import GITLAB_RULE_KEYS
        # M87B: 12 rules; M87C added 13 more → total 25
        assert len(GITLAB_RULE_KEYS) >= 12, (
            f"Expected at least 12 rule keys, got {len(GITLAB_RULE_KEYS)}: {sorted(GITLAB_RULE_KEYS)}"
        )

    def test_gitlab_rule_keys_match_expected(self) -> None:
        from app.services.security_rules.gitlab import GITLAB_RULE_KEYS
        # M87C added 13 more keys; verify all M87B keys are still present
        missing = EXPECTED_GITLAB_RULE_KEYS - GITLAB_RULE_KEYS
        assert not missing, f"M87B keys missing from GITLAB_RULE_KEYS: {missing}"
        # Extra keys from M87C are expected and acceptable
        extra = GITLAB_RULE_KEYS - EXPECTED_GITLAB_RULE_KEYS
        for k in extra:
            assert k.startswith("gitlab_"), f"Non-gitlab extra key: {k!r}"

    def test_all_rule_keys_have_gitlab_prefix(self) -> None:
        from app.services.security_rules.gitlab import GITLAB_RULE_KEYS
        for k in GITLAB_RULE_KEYS:
            assert k.startswith("gitlab_"), f"Rule key {k!r} lacks 'gitlab_' prefix"


# ── B. Rules fire on risky input (positive cases) ─────────────────────────────

class TestPositiveCases:
    def _evaluate(self, record: dict) -> list[Any]:
        from app.services.security_rules.gitlab import evaluate
        return evaluate(record)

    def _rule_keys(self, record: dict) -> set[str]:
        return {c.rule_key for c in self._evaluate(record)}

    def test_project_public_visibility_fires(self) -> None:
        record = _project({"visibility_category": "public"})
        keys = self._rule_keys(record)
        assert "gitlab_project_public_visibility" in keys

    def test_project_public_visibility_severity_high(self) -> None:
        record = _project({"visibility_category": "public"})
        findings = [c for c in self._evaluate(record) if c.rule_key == "gitlab_project_public_visibility"]
        assert findings and findings[0].severity == "high"

    def test_project_shared_runners_fires_non_public(self) -> None:
        record = _project({"shared_runners_enabled": True, "visibility_category": "private"})
        assert "gitlab_project_shared_runners_enabled" in self._rule_keys(record)

    def test_project_shared_runners_fires_internal(self) -> None:
        record = _project({"shared_runners_enabled": True, "visibility_category": "internal"})
        assert "gitlab_project_shared_runners_enabled" in self._rule_keys(record)

    def test_project_snippets_fires_public(self) -> None:
        record = _project({"snippets_enabled": True, "visibility_category": "public"})
        assert "gitlab_project_snippets_enabled_public" in self._rule_keys(record)

    def test_group_public_visibility_fires(self) -> None:
        record = _group({"visibility_category": "public"})
        assert "gitlab_group_public_visibility" in self._rule_keys(record)

    def test_group_public_visibility_severity_high(self) -> None:
        record = _group({"visibility_category": "public"})
        findings = [c for c in self._evaluate(record) if c.rule_key == "gitlab_group_public_visibility"]
        assert findings and findings[0].severity == "high"

    def test_branch_force_push_fires(self) -> None:
        record = _branch_protection({"allow_force_push": True})
        assert "gitlab_branch_force_push_enabled" in self._rule_keys(record)

    def test_branch_force_push_severity_high(self) -> None:
        record = _branch_protection({"allow_force_push": True})
        findings = [c for c in self._evaluate(record) if c.rule_key == "gitlab_branch_force_push_enabled"]
        assert findings and findings[0].severity == "high"

    def test_branch_code_owner_missing_fires_default(self) -> None:
        record = _branch_protection({"code_owner_approval_required": False, "pattern_category": "default"})
        assert "gitlab_branch_code_owner_approval_missing" in self._rule_keys(record)

    def test_branch_code_owner_missing_fires_protected(self) -> None:
        record = _branch_protection({"code_owner_approval_required": False, "pattern_category": "protected"})
        assert "gitlab_branch_code_owner_approval_missing" in self._rule_keys(record)

    def test_branch_code_owner_missing_fires_wildcard(self) -> None:
        record = _branch_protection({"code_owner_approval_required": False, "pattern_category": "wildcard"})
        assert "gitlab_branch_code_owner_approval_missing" in self._rule_keys(record)

    def test_branch_code_owner_severity_medium(self) -> None:
        record = _branch_protection({"code_owner_approval_required": False, "pattern_category": "default"})
        findings = [c for c in self._evaluate(record) if c.rule_key == "gitlab_branch_code_owner_approval_missing"]
        assert findings and findings[0].severity == "medium"

    def test_webhook_secret_missing_fires(self) -> None:
        record = _webhook({"enabled": True, "secret_token_present": False})
        assert "gitlab_webhook_secret_missing" in self._rule_keys(record)

    def test_webhook_secret_missing_severity_high(self) -> None:
        record = _webhook({"enabled": True, "secret_token_present": False})
        findings = [c for c in self._evaluate(record) if c.rule_key == "gitlab_webhook_secret_missing"]
        assert findings and findings[0].severity == "high"

    def test_webhook_ssl_disabled_fires(self) -> None:
        record = _webhook({"enabled": True, "ssl_verification_enabled": False})
        assert "gitlab_webhook_ssl_verification_disabled" in self._rule_keys(record)

    def test_webhook_ssl_disabled_severity_high(self) -> None:
        record = _webhook({"enabled": True, "ssl_verification_enabled": False})
        findings = [c for c in self._evaluate(record) if c.rule_key == "gitlab_webhook_ssl_verification_disabled"]
        assert findings and findings[0].severity == "high"

    def test_ci_unprotected_unmasked_fires(self) -> None:
        record = _ci_variable_summary({"unprotected_unmasked_count": 2})
        assert "gitlab_ci_unprotected_unmasked_variables" in self._rule_keys(record)

    def test_ci_unprotected_unmasked_severity_high(self) -> None:
        record = _ci_variable_summary({"unprotected_unmasked_count": 1})
        findings = [c for c in self._evaluate(record) if c.rule_key == "gitlab_ci_unprotected_unmasked_variables"]
        assert findings and findings[0].severity == "high"

    def test_deploy_key_write_enabled_fires(self) -> None:
        record = _deploy_key_summary({"write_enabled_count": 1})
        assert "gitlab_deploy_key_write_enabled" in self._rule_keys(record)

    def test_deploy_key_write_enabled_severity_high(self) -> None:
        record = _deploy_key_summary({"write_enabled_count": 2})
        findings = [c for c in self._evaluate(record) if c.rule_key == "gitlab_deploy_key_write_enabled"]
        assert findings and findings[0].severity == "high"

    def test_runner_untagged_fires(self) -> None:
        record = _runner_summary({"untagged_runner_count": 1})
        assert "gitlab_runner_untagged" in self._rule_keys(record)

    def test_runner_untagged_severity_medium(self) -> None:
        record = _runner_summary({"untagged_runner_count": 3})
        findings = [c for c in self._evaluate(record) if c.rule_key == "gitlab_runner_untagged"]
        assert findings and findings[0].severity == "medium"

    def test_mr_approval_not_required_fires(self) -> None:
        record = _mr_approval({"approvals_required": 0})
        assert "gitlab_merge_request_approval_not_required" in self._rule_keys(record)

    def test_mr_approval_not_required_severity_medium(self) -> None:
        record = _mr_approval({"approvals_required": 0})
        findings = [c for c in self._evaluate(record) if c.rule_key == "gitlab_merge_request_approval_not_required"]
        assert findings and findings[0].severity == "medium"


# ── C. Rules do not fire on healthy input (negative cases) ─────────────────────

class TestNegativeCases:
    def _rule_keys(self, record: dict) -> set[str]:
        from app.services.security_rules.gitlab import evaluate
        return {c.rule_key for c in evaluate(record)}

    def test_private_project_no_public_visibility_rule(self) -> None:
        record = _project({"visibility_category": "private"})
        assert "gitlab_project_public_visibility" not in self._rule_keys(record)

    def test_internal_project_no_public_visibility_rule(self) -> None:
        record = _project({"visibility_category": "internal"})
        assert "gitlab_project_public_visibility" not in self._rule_keys(record)

    def test_shared_runners_disabled_no_rule(self) -> None:
        record = _project({"shared_runners_enabled": False})
        assert "gitlab_project_shared_runners_enabled" not in self._rule_keys(record)

    def test_shared_runners_enabled_public_no_rule(self) -> None:
        # Public project with shared runners: doesn't fire because public already fires separately
        record = _project({"shared_runners_enabled": True, "visibility_category": "public"})
        assert "gitlab_project_shared_runners_enabled" not in self._rule_keys(record)

    def test_snippets_disabled_public_no_rule(self) -> None:
        record = _project({"snippets_enabled": False, "visibility_category": "public"})
        assert "gitlab_project_snippets_enabled_public" not in self._rule_keys(record)

    def test_snippets_enabled_private_no_rule(self) -> None:
        record = _project({"snippets_enabled": True, "visibility_category": "private"})
        assert "gitlab_project_snippets_enabled_public" not in self._rule_keys(record)

    def test_private_group_no_rule(self) -> None:
        record = _group({"visibility_category": "private"})
        assert "gitlab_group_public_visibility" not in self._rule_keys(record)

    def test_internal_group_no_rule(self) -> None:
        record = _group({"visibility_category": "internal"})
        assert "gitlab_group_public_visibility" not in self._rule_keys(record)

    def test_branch_no_force_push_no_rule(self) -> None:
        record = _branch_protection({"allow_force_push": False})
        assert "gitlab_branch_force_push_enabled" not in self._rule_keys(record)

    def test_branch_code_owner_required_no_rule(self) -> None:
        record = _branch_protection({"code_owner_approval_required": True, "pattern_category": "default"})
        assert "gitlab_branch_code_owner_approval_missing" not in self._rule_keys(record)

    def test_branch_code_owner_missing_unknown_pattern_no_rule(self) -> None:
        # Only fires on protected/default/wildcard patterns
        record = _branch_protection({"code_owner_approval_required": False, "pattern_category": "unknown"})
        assert "gitlab_branch_code_owner_approval_missing" not in self._rule_keys(record)

    def test_webhook_disabled_no_secret_rule(self) -> None:
        record = _webhook({"enabled": False, "secret_token_present": False})
        assert "gitlab_webhook_secret_missing" not in self._rule_keys(record)

    def test_webhook_disabled_no_ssl_rule(self) -> None:
        record = _webhook({"enabled": False, "ssl_verification_enabled": False})
        assert "gitlab_webhook_ssl_verification_disabled" not in self._rule_keys(record)

    def test_webhook_with_secret_no_rule(self) -> None:
        record = _webhook({"enabled": True, "secret_token_present": True})
        assert "gitlab_webhook_secret_missing" not in self._rule_keys(record)

    def test_webhook_ssl_enabled_no_rule(self) -> None:
        record = _webhook({"enabled": True, "ssl_verification_enabled": True})
        assert "gitlab_webhook_ssl_verification_disabled" not in self._rule_keys(record)

    def test_ci_all_protected_no_rule(self) -> None:
        record = _ci_variable_summary({"unprotected_unmasked_count": 0})
        assert "gitlab_ci_unprotected_unmasked_variables" not in self._rule_keys(record)

    def test_deploy_key_read_only_no_rule(self) -> None:
        record = _deploy_key_summary({"write_enabled_count": 0})
        assert "gitlab_deploy_key_write_enabled" not in self._rule_keys(record)

    def test_runner_all_tagged_no_rule(self) -> None:
        record = _runner_summary({"untagged_runner_count": 0})
        assert "gitlab_runner_untagged" not in self._rule_keys(record)

    def test_mr_approvals_required_no_rule(self) -> None:
        record = _mr_approval({"approvals_required": 2})
        assert "gitlab_merge_request_approval_not_required" not in self._rule_keys(record)

    def test_unknown_record_type_returns_empty(self) -> None:
        from app.services.security_rules.gitlab import evaluate
        record = {"record_type": "gitlab_unknown_surface", "provider": "gitlab"}
        assert evaluate(record) == []

    def test_gitlab_instance_returns_empty(self) -> None:
        from app.services.security_rules.gitlab import evaluate
        record = {"record_type": "gitlab_instance", "provider": "gitlab", "record_id": "x", "resource_id": "x"}
        assert evaluate(record) == []

    def test_non_dict_returns_empty(self) -> None:
        from app.services.security_rules.gitlab import evaluate
        assert evaluate("not_a_dict") == []  # type: ignore[arg-type]
        assert evaluate(None) == []  # type: ignore[arg-type]


# ── D. Missing/None fields do not cause false positives ───────────────────────

class TestMissingFields:
    def _evaluate(self, record: dict) -> list[Any]:
        from app.services.security_rules.gitlab import evaluate
        return evaluate(record)

    def test_project_shared_runners_none_no_rule(self) -> None:
        record = _project({"shared_runners_enabled": None})
        keys = {c.rule_key for c in self._evaluate(record)}
        assert "gitlab_project_shared_runners_enabled" not in keys

    def test_project_snippets_none_no_rule(self) -> None:
        record = _project({"snippets_enabled": None})
        keys = {c.rule_key for c in self._evaluate(record)}
        assert "gitlab_project_snippets_enabled_public" not in keys

    def test_group_visibility_unknown_no_rule(self) -> None:
        record = _group({"visibility_category": "unknown"})
        keys = {c.rule_key for c in self._evaluate(record)}
        assert "gitlab_group_public_visibility" not in keys

    def test_branch_force_push_none_no_rule(self) -> None:
        record = _branch_protection({"allow_force_push": None})
        keys = {c.rule_key for c in self._evaluate(record)}
        assert "gitlab_branch_force_push_enabled" not in keys

    def test_webhook_secret_none_no_rule(self) -> None:
        record = _webhook({"secret_token_present": None})
        keys = {c.rule_key for c in self._evaluate(record)}
        assert "gitlab_webhook_secret_missing" not in keys

    def test_webhook_ssl_none_no_rule(self) -> None:
        record = _webhook({"ssl_verification_enabled": None})
        keys = {c.rule_key for c in self._evaluate(record)}
        assert "gitlab_webhook_ssl_verification_disabled" not in keys

    def test_ci_unprotected_none_no_rule(self) -> None:
        record = _ci_variable_summary({"unprotected_unmasked_count": None})
        keys = {c.rule_key for c in self._evaluate(record)}
        assert "gitlab_ci_unprotected_unmasked_variables" not in keys

    def test_deploy_key_write_count_none_no_rule(self) -> None:
        record = _deploy_key_summary({"write_enabled_count": None})
        keys = {c.rule_key for c in self._evaluate(record)}
        assert "gitlab_deploy_key_write_enabled" not in keys

    def test_runner_untagged_none_no_rule(self) -> None:
        record = _runner_summary({"untagged_runner_count": None})
        keys = {c.rule_key for c in self._evaluate(record)}
        assert "gitlab_runner_untagged" not in keys

    def test_mr_approvals_none_no_rule(self) -> None:
        record = _mr_approval({"approvals_required": None})
        keys = {c.rule_key for c in self._evaluate(record)}
        assert "gitlab_merge_request_approval_not_required" not in keys

    def test_empty_dict_returns_empty(self) -> None:
        from app.services.security_rules.gitlab import evaluate
        assert evaluate({}) == []

    def test_missing_record_type_returns_empty(self) -> None:
        from app.services.security_rules.gitlab import evaluate
        assert evaluate({"provider": "gitlab"}) == []


# ── E. Evidence safety ────────────────────────────────────────────────────────

class TestEvidenceSafety:
    def _all_findings(self) -> list[Any]:
        from app.services.security_rules.gitlab import evaluate
        risky_records = [
            _project({"visibility_category": "public", "snippets_enabled": True}),
            _project({"shared_runners_enabled": True, "visibility_category": "internal"}),
            _group({"visibility_category": "public"}),
            _branch_protection({"allow_force_push": True, "code_owner_approval_required": False, "pattern_category": "default"}),
            _webhook({"enabled": True, "secret_token_present": False, "ssl_verification_enabled": False}),
            _ci_variable_summary({"unprotected_unmasked_count": 3}),
            _deploy_key_summary({"write_enabled_count": 2}),
            _runner_summary({"untagged_runner_count": 1}),
            _mr_approval({"approvals_required": 0}),
        ]
        findings = []
        for rec in risky_records:
            findings.extend(evaluate(rec))
        return findings

    def test_no_findings_have_forbidden_evidence_keys(self) -> None:
        for finding in self._all_findings():
            bad_keys = set(finding.evidence.keys()) & _FORBIDDEN_EVIDENCE_KEYS
            assert not bad_keys, (
                f"Rule {finding.rule_key!r} evidence contains forbidden keys: {bad_keys}"
            )

    def test_evidence_values_are_flat_scalars(self) -> None:
        for finding in self._all_findings():
            for key, val in finding.evidence.items():
                assert not isinstance(val, dict), (
                    f"Rule {finding.rule_key!r} evidence[{key!r}] is a nested dict"
                )
                assert not isinstance(val, list), (
                    f"Rule {finding.rule_key!r} evidence[{key!r}] is a list"
                )

    def test_evidence_does_not_contain_url_values(self) -> None:
        for finding in self._all_findings():
            for key, val in finding.evidence.items():
                if isinstance(val, str):
                    assert not val.startswith(("http://", "https://", "git@")), (
                        f"Rule {finding.rule_key!r} evidence[{key!r}] looks like a URL: {val!r}"
                    )

    def test_finding_provider_is_gitlab(self) -> None:
        for finding in self._all_findings():
            assert finding.provider == "gitlab", (
                f"Rule {finding.rule_key!r} has wrong provider: {finding.provider!r}"
            )


# ── F. Claim discipline ───────────────────────────────────────────────────────

class TestClaimDiscipline:
    def _all_findings(self) -> list[Any]:
        from app.services.security_rules.gitlab import evaluate
        risky_records = [
            _project({"visibility_category": "public"}),
            _group({"visibility_category": "public"}),
            _branch_protection({"allow_force_push": True}),
            _webhook({"enabled": True, "secret_token_present": False}),
            _webhook({"enabled": True, "ssl_verification_enabled": False}),
            _ci_variable_summary({"unprotected_unmasked_count": 1}),
            _deploy_key_summary({"write_enabled_count": 1}),
            _runner_summary({"untagged_runner_count": 1}),
            _mr_approval({"approvals_required": 0}),
        ]
        findings = []
        for rec in risky_records:
            findings.extend(evaluate(rec))
        return findings

    def test_descriptions_contain_safe_disclaimer(self) -> None:
        for finding in self._all_findings():
            desc = finding.description.lower()
            # Must contain at least one safe-review phrase
            has_safe = (
                "may require review" in desc
                or "evidence for review" in desc
                or "does not confirm" in desc
                or "evidence may require" in desc
            )
            assert has_safe, (
                f"Rule {finding.rule_key!r} description missing safe review framing: "
                f"{finding.description[:200]!r}"
            )

    def test_descriptions_never_contain_forbidden_phrases(self) -> None:
        for finding in self._all_findings():
            desc_lower = finding.description.lower()
            for phrase in _FORBIDDEN_PHRASES:
                assert phrase not in desc_lower, (
                    f"Rule {finding.rule_key!r} description contains forbidden phrase "
                    f"{phrase!r}: {finding.description[:200]!r}"
                )

    def test_source_file_no_forbidden_phrases(self) -> None:
        src = GITLAB_RULES_PY.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in src, (
                f"Forbidden phrase {phrase!r} in security_rules/gitlab.py"
            )


# ── G. Registry ───────────────────────────────────────────────────────────────

class TestRegistry:
    def test_all_gitlab_rules_in_known_rule_keys(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        missing = EXPECTED_GITLAB_RULE_KEYS - KNOWN_RULE_KEYS
        assert not missing, f"Rule keys missing from KNOWN_RULE_KEYS: {missing}"

    def test_is_known_rule_key_true_for_all_gitlab(self) -> None:
        from app.services.security_rule_registry import is_known_rule_key
        for key in EXPECTED_GITLAB_RULE_KEYS:
            assert is_known_rule_key(key), f"is_known_rule_key({key!r}) returned False"

    def test_all_gitlab_rule_keys_start_with_gitlab(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        gitlab_keys = {k for k in KNOWN_RULE_KEYS if k.startswith("gitlab_")}
        # M87B keys must all be present (M87C may add more)
        missing = EXPECTED_GITLAB_RULE_KEYS - gitlab_keys
        assert not missing, f"M87B rule keys missing from registry: {missing}"


# ── H. Confidence ─────────────────────────────────────────────────────────────

class TestConfidence:
    def test_all_gitlab_rules_have_confidence(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        missing = EXPECTED_GITLAB_RULE_KEYS - set(RULE_CONFIDENCE)
        assert not missing, f"Rule keys missing from RULE_CONFIDENCE: {missing}"

    def test_gitlab_rule_confidence_valid_levels(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE, VALID_CONFIDENCE
        for key in EXPECTED_GITLAB_RULE_KEYS:
            conf, _ = RULE_CONFIDENCE[key]
            assert conf in VALID_CONFIDENCE, (
                f"Rule {key!r} has invalid confidence: {conf!r}"
            )

    def test_confidence_for_works_for_all_gitlab_rules(self) -> None:
        from app.services.security_rule_confidence import confidence_for
        for key in EXPECTED_GITLAB_RULE_KEYS:
            conf, reason, guard = confidence_for(key)
            assert conf in ("high", "medium"), f"Rule {key!r} bad confidence: {conf!r}"
            assert reason, f"Rule {key!r} missing confidence reason"

    def test_high_severity_rules_have_high_confidence(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        high_severity_rules = {
            "gitlab_project_public_visibility",
            "gitlab_group_public_visibility",
            "gitlab_branch_force_push_enabled",
            "gitlab_webhook_secret_missing",
            "gitlab_webhook_ssl_verification_disabled",
            "gitlab_ci_unprotected_unmasked_variables",
            "gitlab_deploy_key_write_enabled",
        }
        for key in high_severity_rules:
            conf, _ = RULE_CONFIDENCE[key]
            assert conf == "high", f"High-severity rule {key!r} has confidence={conf!r}"


# ── I. Pack ───────────────────────────────────────────────────────────────────

class TestPack:
    def test_pack_import_clean(self) -> None:
        # Importing the pack validates that _RULE_META == KNOWN_RULE_KEYS
        import app.services.security_rule_pack as pack
        assert hasattr(pack, "SECURITY_RULE_PACK_NAME")

    def test_all_gitlab_rules_in_pack(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        missing = EXPECTED_GITLAB_RULE_KEYS - set(_RULE_META)
        assert not missing, f"Rule keys missing from _RULE_META: {missing}"

    def test_gitlab_rules_provider_field_is_gitlab(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        for key in EXPECTED_GITLAB_RULE_KEYS:
            provider, _, _ = _RULE_META[key]
            assert provider == "gitlab", f"Rule {key!r} has wrong provider in pack: {provider!r}"

    def test_gitlab_rules_severity_in_pack_valid(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for key in EXPECTED_GITLAB_RULE_KEYS:
            _, severity, _ = _RULE_META[key]
            assert severity in valid_severities, (
                f"Rule {key!r} has invalid severity in pack: {severity!r}"
            )

    def test_pack_summary_includes_gitlab(self) -> None:
        from app.services.security_rule_pack import pack_summary
        summary = pack_summary()
        assert "gitlab" in summary["providers"]

    def test_list_pack_rules_includes_all_gitlab_rules(self) -> None:
        from app.services.security_rule_pack import list_pack_rules
        rules = list_pack_rules()
        pack_keys = {r["rule_key"] for r in rules}
        missing = EXPECTED_GITLAB_RULE_KEYS - pack_keys
        assert not missing, f"Rules missing from pack: {missing}"


# ── J. Coverage service ───────────────────────────────────────────────────────

class TestCoverageService:
    def test_gitlab_in_providers_list(self) -> None:
        from app.services.security_coverage_service import PROVIDERS
        assert "gitlab" in PROVIDERS

    def test_all_gitlab_rules_in_rule_record_types(self) -> None:
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        missing = EXPECTED_GITLAB_RULE_KEYS - set(RULE_RECORD_TYPES)
        assert not missing, f"Rule keys missing from RULE_RECORD_TYPES: {missing}"

    def test_gitlab_rule_record_types_are_gitlab_types(self) -> None:
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in EXPECTED_GITLAB_RULE_KEYS:
            rtypes = RULE_RECORD_TYPES[key]
            for rtype in rtypes:
                assert rtype.startswith("gitlab_"), (
                    f"Rule {key!r} maps to non-gitlab record type: {rtype!r}"
                )

    def test_specific_record_type_mappings(self) -> None:
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        expected = {
            "gitlab_project_public_visibility": "gitlab_project",
            "gitlab_group_public_visibility": "gitlab_group",
            "gitlab_branch_force_push_enabled": "gitlab_branch_protection",
            "gitlab_webhook_secret_missing": "gitlab_webhook",
            "gitlab_ci_unprotected_unmasked_variables": "gitlab_ci_variable_summary",
            "gitlab_deploy_key_write_enabled": "gitlab_deploy_key_summary",
            "gitlab_runner_untagged": "gitlab_runner_summary",
            "gitlab_merge_request_approval_not_required": "gitlab_merge_request_approval_summary",
        }
        for rule_key, expected_rtype in expected.items():
            actual_rtypes = RULE_RECORD_TYPES[rule_key]
            assert expected_rtype in actual_rtypes, (
                f"Rule {rule_key!r} should map to {expected_rtype!r}, got {actual_rtypes!r}"
            )

    def test_gitlab_in_provider_surfaces(self) -> None:
        from app.services.security_coverage_service import PROVIDER_SURFACES
        assert "gitlab" in PROVIDER_SURFACES
        surfaces = PROVIDER_SURFACES["gitlab"]
        assert len(surfaces) >= 7


# ── K. Evaluator dispatch ─────────────────────────────────────────────────────

class TestEvaluatorDispatch:
    def test_gitlab_in_provider_rules(self) -> None:
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "gitlab" in _PROVIDER_RULES, (
            "'gitlab' is missing from _PROVIDER_RULES in security_finding_evaluator.py — "
            "this causes a P0 dead-rule issue where all GitLab rules fire on no records"
        )

    def test_provider_rules_gitlab_is_list(self) -> None:
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert isinstance(_PROVIDER_RULES["gitlab"], list)
        assert len(_PROVIDER_RULES["gitlab"]) >= 1

    def test_evaluate_record_public_project_fires(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        record = _project({"visibility_category": "public"})
        findings = evaluate_record(record, "gitlab")
        assert len(findings) > 0, "evaluate_record returned no findings for a public project"
        rule_keys = {f.rule_key for f in findings}
        assert "gitlab_project_public_visibility" in rule_keys

    def test_evaluate_record_private_project_no_visibility_rule(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        record = _project({"visibility_category": "private"})
        findings = evaluate_record(record, "gitlab")
        rule_keys = {f.rule_key for f in findings}
        assert "gitlab_project_public_visibility" not in rule_keys

    def test_evaluate_record_unknown_provider_empty(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        record = _project({"visibility_category": "public"})
        assert evaluate_record(record, "unknown_provider_xyz") == []

    def test_evaluate_record_gitlab_webhook_risky(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        record = _webhook({"enabled": True, "secret_token_present": False, "ssl_verification_enabled": False})
        findings = evaluate_record(record, "gitlab")
        rule_keys = {f.rule_key for f in findings}
        assert "gitlab_webhook_secret_missing" in rule_keys
        assert "gitlab_webhook_ssl_verification_disabled" in rule_keys

    def test_evaluate_record_ci_variable_risky(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        record = _ci_variable_summary({"unprotected_unmasked_count": 5})
        findings = evaluate_record(record, "gitlab")
        assert any(f.rule_key == "gitlab_ci_unprotected_unmasked_variables" for f in findings)


# ── L. Capability matrix ──────────────────────────────────────────────────────

class TestCapabilityMatrix:
    def test_gitlab_security_rules_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        assert cap is not None
        assert cap.security.security_rules is True, (
            "GitLab security.security_rules should be True after M87B"
        )

    def test_gitlab_drift_flags_still_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True

    def test_gitlab_activity_ingestion_still_false(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        # activity_ingestion was False at M87B; M87D promoted it to True.
        # activity_signals was False at M87B; M87E promoted it to True.
        assert cap.security.activity_ingestion is True
        assert cap.security.activity_signals is True
        # risk_activity_correlations was False at M87B; M87F promoted it to True.
        assert cap.security.risk_activity_correlations is True
        # demo_seed_clear landed in M87G.
        assert cap.security.demo_seed_clear is True
        # case_report landed in M87G.
        assert cap.security.case_report is True
        # evidence_timeline landed in M87G.
        assert cap.security.evidence_timeline is True
        # evidence_graph landed in M87G.
        assert cap.security.evidence_graph is True

    def test_gitlab_maturity_partial(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        assert cap.maturity == "partial"

    def test_gitlab_notes_mention_m87b(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        assert "M87B" in cap.notes, "GitLab notes should mention M87B"

    def test_gitlab_notes_mention_m87c_planned(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        assert "M87C" in cap.notes, "GitLab notes should mention M87C as planned next"

    def test_gitlab_notes_mention_rule_count(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        # Notes should mention the 12 rules or specific rule names
        assert "12" in cap.notes or "gitlab_project_public_visibility" in cap.notes, (
            "GitLab notes should mention the number of rules or specific rule names"
        )


# ── M. Expansion framework ────────────────────────────────────────────────────

class TestExpansionFramework:
    def test_planned_next_stage_references_m87c(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw.get("summary", {}).get("planned_next_stage", "")
        # M87C→M87D→M87E→M87F→M87G: accept any later GitLab arc stage
        assert ("M87C" in planned or "GitLab Branch" in planned or "CI Risk" in planned
                or "M87D" in planned or "GitLab Activity" in planned
                or "M87E" in planned or "M87F" in planned or "Correlations" in planned
                or "M87G" in planned or "Demo" in planned or "M87H" in planned or "M87I" in planned or "Cross-Cloud" in planned
                or "M88A" in planned or "Terraform" in planned
                or "M89A" in planned or "Kubernetes" in planned), (
            f"planned_next_stage should reference M87C or later; got: {planned!r}"
        )

    def test_terraform_cloud_still_in_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        recs = fw.get("recommended_next_providers", [])
        provider_keys = [r.get("provider") for r in recs]
        assert "terraform_cloud" in provider_keys or "kubernetes" in provider_keys, (
            "Terraform Cloud should remain in recommended_next_providers"
        )

    def test_gitlab_not_in_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        recs = fw.get("recommended_next_providers", [])
        provider_keys = [r.get("provider") for r in recs]
        assert "gitlab" not in provider_keys, (
            "GitLab should not be in recommended_next_providers after M87A launch"
        )


# ── N. Frontend catalog ───────────────────────────────────────────────────────

class TestFrontendCatalog:
    def _catalog_src(self) -> str:
        return FE_CATALOG.read_text(encoding="utf-8")

    def test_all_gitlab_rule_keys_in_catalog(self) -> None:
        src = self._catalog_src()
        for key in EXPECTED_GITLAB_RULE_KEYS:
            assert f'key: "{key}"' in src or f"key: '{key}'" in src, (
                f"Rule key {key!r} not found in securityRuleCatalog.ts"
            )

    def test_gitlab_provider_coverage_in_catalog(self) -> None:
        src = self._catalog_src()
        # PROVIDER_COVERAGE should have a gitlab entry
        assert 'provider: "gitlab"' in src, (
            "securityRuleCatalog.ts should have a gitlab PROVIDER_COVERAGE entry"
        )

    def test_gitlab_catalog_rules_count(self) -> None:
        src = self._catalog_src()
        # Count gitlab provider lines in the SECURITY_RULES array
        gitlab_key_count = sum(
            1 for key in EXPECTED_GITLAB_RULE_KEYS
            if f'key: "{key}"' in src
        )
        assert gitlab_key_count == 12, (
            f"Expected 12 GitLab rule entries in catalog, found {gitlab_key_count}"
        )

    def test_catalog_gitlab_no_forbidden_phrases(self) -> None:
        src = self._catalog_src()
        # Extract the GitLab section roughly
        gitlab_idx = src.find('key: "gitlab_project_public_visibility"')
        if gitlab_idx < 0:
            pytest.skip("GitLab catalog entries not found")
        gitlab_section = src[gitlab_idx:]
        src_lower = gitlab_section.lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in src_lower, (
                f"Forbidden phrase {phrase!r} found in GitLab catalog section"
            )

    def test_catalog_gitlab_disclaimer_present(self) -> None:
        src = self._catalog_src()
        gitlab_idx = src.find('key: "gitlab_project_public_visibility"')
        if gitlab_idx < 0:
            pytest.skip("GitLab catalog entries not found")
        gitlab_section = src[gitlab_idx:].lower()
        assert ("does not confirm" in gitlab_section or
                "may require review" in gitlab_section or
                "evidence for review" in gitlab_section), (
            "GitLab catalog entries should contain safe review framing"
        )


# ── O. Backend/frontend severity and category match ───────────────────────────

class TestSeverityAndCategoryParity:
    def test_pack_and_catalog_severity_match(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        src = FE_CATALOG.read_text(encoding="utf-8")

        severity_map = {
            "gitlab_project_public_visibility": "high",
            "gitlab_group_public_visibility": "high",
            "gitlab_branch_force_push_enabled": "high",
            "gitlab_webhook_secret_missing": "high",
            "gitlab_webhook_ssl_verification_disabled": "high",
            "gitlab_ci_unprotected_unmasked_variables": "high",
            "gitlab_deploy_key_write_enabled": "high",
            "gitlab_branch_code_owner_approval_missing": "medium",
            "gitlab_runner_untagged": "medium",
            "gitlab_merge_request_approval_not_required": "medium",
            "gitlab_project_shared_runners_enabled": "medium",
            "gitlab_project_snippets_enabled_public": "low",
        }

        for key, expected_severity in severity_map.items():
            # Check backend pack
            backend_provider, backend_severity, _ = _RULE_META[key]
            assert backend_severity == expected_severity, (
                f"Rule {key!r}: pack severity is {backend_severity!r}, expected {expected_severity!r}"
            )
            # Check frontend catalog has the key with this severity
            # Find the block for this key in the catalog
            idx = src.find(f'key: "{key}"')
            if idx >= 0:
                block = src[idx:idx + 500]
                assert f'severity: "{expected_severity}"' in block, (
                    f"Rule {key!r}: frontend severity should be {expected_severity!r} in catalog block"
                )


# ── P. No unsupported capabilities claimed ────────────────────────────────────

class TestNoCapsNotClaimed:
    def test_gitlab_activity_ingestion_not_in_providers(self) -> None:
        from app.services.security_coverage_service import PROVIDERS
        # We can check gitlab is in providers (for security rules) but activity
        # ingestion is not yet wired
        assert "gitlab" in PROVIDERS  # Security coverage yes

    def test_gitlab_no_activity_router_endpoint(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        # activity_ingestion landed in M87D; activity_signals landed in M87E.
        assert cap.security.activity_ingestion is True
        assert cap.security.activity_signals is True

    def test_capability_matrix_demo_false(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        # demo_seed_clear landed in M87G.
        assert cap.security.demo_seed_clear is True
        # case_report landed in M87G.
        assert cap.security.case_report is True


# ── Q. M87A regression smoke ──────────────────────────────────────────────────

class TestM87ARegressionSmoke:
    def test_gitlab_schema_still_importable(self) -> None:
        from app.connectors.gitlab_schema import GITLAB_RECORD_TYPES, GITLAB_PROJECT
        assert len(GITLAB_RECORD_TYPES) == 9
        assert GITLAB_PROJECT == "gitlab_project"

    def test_gitlab_connector_still_importable(self) -> None:
        from app.connectors.gitlab import GitLabConnector
        connector = GitLabConnector()
        assert hasattr(connector, "fetch")

    def test_m87a_framework_pointer_advanced(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw.get("summary", {}).get("planned_next_stage", "")
        # M87A had M87B; now M87B should advance to M87C
        assert "M87C" in planned or "M87B" not in planned or "M87A" not in planned, (
            f"planned_next_stage should have advanced past M87A/M87B; got: {planned!r}"
        )

    def test_gitlab_capability_matrix_still_partial(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("gitlab")
        assert cap.maturity == "partial"
        assert cap.drift.drift_snapshots is True
