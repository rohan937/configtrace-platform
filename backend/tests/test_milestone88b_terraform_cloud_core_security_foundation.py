"""M88B — Terraform Cloud core security foundation guardrails.

Verifies that the Terraform Cloud security rules module, evaluator dispatch,
registry/catalog/coverage parity, and capability matrix all meet the M88B
requirements.

Sections:
  A. Module imports and rule key set
  B. Rules fire on risky input
  C. Rules do not fire on healthy input
  D. Missing/None fields — no false positives
  E. Evidence safety — no forbidden keys
  F. Finding descriptions — disclaimer present, no forbidden wording
  G. Registry / confidence / pack parity
  H. Coverage service parity
  I. Frontend catalog parity
  J. Evaluator dispatch
  K. Capability matrix and expansion framework
  L. Regression smoke
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_RULE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"

# ── Constants ──────────────────────────────────────────────────────────────────

ALL_RULE_KEYS = {
    # M88B rules
    "terraform_cloud_organization_two_factor_not_required",
    "terraform_cloud_organization_sso_not_enabled",
    "terraform_cloud_workspace_auto_apply_enabled",
    "terraform_cloud_workspace_global_remote_state_enabled",
    "terraform_cloud_workspace_local_execution_mode",
    "terraform_cloud_workspace_vcs_connection_missing",
    "terraform_cloud_workspace_queue_all_runs_disabled",
    "terraform_cloud_workspace_unpinned_terraform_version",
    "terraform_cloud_workspace_non_sensitive_variables_present",
    "terraform_cloud_workspace_no_sensitive_variables",
    "terraform_cloud_notification_http_webhook",
    "terraform_cloud_notification_token_missing",
    "terraform_cloud_policy_set_advisory_enforcement",
    "terraform_cloud_policy_set_empty",
    "terraform_cloud_team_admin_access",
    "terraform_cloud_team_apply_access",
    "terraform_cloud_variable_set_global_scope",
    "terraform_cloud_state_version_present",
    # M88C rules (added in M88C; reflected here for forward-compatibility)
    "terraform_cloud_workspace_agent_execution_mode",
    "terraform_cloud_workspace_file_triggers_disabled",
    "terraform_cloud_workspace_speculative_plans_disabled",
    "terraform_cloud_workspace_run_triggers_present",
    "terraform_cloud_workspace_many_trigger_prefixes",
    "terraform_cloud_workspace_latest_run_failed",
    "terraform_cloud_workspace_environment_variables_non_sensitive",
    "terraform_cloud_workspace_terraform_variables_non_sensitive",
    "terraform_cloud_variable_set_non_sensitive_variables",
    "terraform_cloud_variable_set_broad_scope",
    "terraform_cloud_policy_set_global_scope",
    "terraform_cloud_policy_set_broad_scope_advisory",
    "terraform_cloud_policy_set_no_workspace_or_project_scope",
    "terraform_cloud_notification_broad_trigger_scope",
    "terraform_cloud_notification_disabled",
    "terraform_cloud_run_trigger_enabled",
    "terraform_cloud_team_write_access",
    "terraform_cloud_team_custom_permissions",
}

FORBIDDEN_EVIDENCE_KEYS = {
    "token", "secret_value", "api_token", "authorization",
    "webhook_url", "url", "notification_url",
    "variable_name", "variable_key", "key", "value", "variable_value",
    "hcl_value", "hcl", "description",
    "organization_name", "org_name", "organization",
    "workspace_name", "project_name", "variable_set_name",
    "vcs_url", "vcs_repo_url", "repo_url", "repo_name", "repository",
    "branch_name", "branch", "commit_sha", "commit",
    "team_name", "user_email", "username", "user_name", "email",
    "plan_log", "apply_log", "run_log", "state", "tfstate",
    "state_json", "state_output", "state_file", "resource_address",
    "raw", "payload", "request", "response", "name",
}

FORBIDDEN_DESCRIPTION_PHRASES = [
    "breach confirmed", "compromise confirmed", "attacker found",
    "someone has access", "data leaked", "secret leaked",
    "customer data exposed", "unauthorized access confirmed",
    "payment fraud detected", "attack detected", "orders exposed",
    "card data exposed", "state leaked", "tfstate leaked",
    "state exposed", "tfstate exposed", "token leaked",
    "secrets exposed", "credentials exposed", "infrastructure exposed",
]

_DISCLAIMER_FRAGMENT = "does not confirm"


# ── Fixtures ───────────────────────────────────────────────────────────────────

def _ws(overrides: dict) -> dict:
    base = {
        "record_type": "terraform_cloud_workspace",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_workspace:abc123",
        "resource_id": "abc123",
        "workspace_resource_id": "ws_opaque_1",
        "organization_resource_id": "org_opaque_1",
        "execution_mode_category": "remote",
        "terraform_version_category": "pinned",
        "auto_apply": False,
        "file_triggers_enabled": True,
        "queue_all_runs": True,
        "speculative_enabled": True,
        "global_remote_state": False,
        "vcs_connected": True,
        "working_directory_present": False,
        "trigger_prefix_count": 0,
        "run_trigger_count": 0,
        "variable_count": 0,
        "sensitive_variable_count": 0,
        "non_sensitive_variable_count": 0,
        "environment_variable_count": 0,
        "terraform_variable_count": 0,
        "notification_count": 0,
        "team_access_count": 0,
        "current_state_version_present": False,
        "latest_run_status_category": None,
    }
    base.update(overrides)
    return base


def _org(overrides: dict) -> dict:
    base = {
        "record_type": "terraform_cloud_organization",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_organization:org123",
        "resource_id": "org123",
        "organization_resource_id": "org_opaque_1",
        "workspace_count": 5,
        "project_count": 2,
        "policy_set_count": None,
        "variable_set_count": None,
        "team_count_category": "medium",
        "sso_enabled": True,
        "two_factor_requirement_enabled": True,
        "cost_estimation_enabled": False,
        "collaborator_auth_policy_category": "two_factor_mandatory",
    }
    base.update(overrides)
    return base


def _var_summary(overrides: dict) -> dict:
    base = {
        "record_type": "terraform_cloud_workspace_variable_summary",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_workspace_variable_summary:vs123",
        "resource_id": "vs123",
        "workspace_resource_id": "ws_opaque_1",
        "variable_count": 3,
        "sensitive_variable_count": 2,
        "non_sensitive_variable_count": 1,
        "environment_variable_count": 2,
        "terraform_variable_count": 1,
        "unprotected_non_sensitive_count": 1,
        "raw_value_never_read": True,
    }
    base.update(overrides)
    return base


def _notification(overrides: dict) -> dict:
    base = {
        "record_type": "terraform_cloud_notification_configuration",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_notification_configuration:nc123",
        "resource_id": "nc123",
        "notification_resource_id": "nc_opaque_1",
        "workspace_resource_id": "ws_opaque_1",
        "enabled": True,
        "destination_type_category": "webhook",
        "trigger_count": 3,
        "webhook_url_present": True,
        "webhook_url_scheme_category": "https",
        "token_present": True,
    }
    base.update(overrides)
    return base


def _policy_set(overrides: dict) -> dict:
    base = {
        "record_type": "terraform_cloud_policy_set",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_policy_set:ps123",
        "resource_id": "ps123",
        "policy_set_resource_id": "ps_opaque_1",
        "organization_resource_id": "org_opaque_1",
        "global_scope": False,
        "workspace_count": 3,
        "project_count": 0,
        "policy_count": 5,
        "enforcement_level_category": "mandatory",
        "vcs_connected": False,
    }
    base.update(overrides)
    return base


def _team_access(overrides: dict) -> dict:
    base = {
        "record_type": "terraform_cloud_team_access_summary",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_team_access_summary:ta123",
        "resource_id": "ta123",
        "workspace_resource_id": "ws_opaque_1",
        "team_access_count": 2,
        "admin_access_count": 0,
        "write_access_count": 1,
        "read_access_count": 1,
        "plan_access_count": 0,
        "custom_permission_count": 0,
    }
    base.update(overrides)
    return base


def _varset(overrides: dict) -> dict:
    base = {
        "record_type": "terraform_cloud_variable_set",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_variable_set:vs123",
        "resource_id": "vs123",
        "variable_set_resource_id": "vs_opaque_1",
        "organization_resource_id": "org_opaque_1",
        "global_scope": False,
        "workspace_count": 2,
        "project_count": 0,
        "variable_count": 3,
        "sensitive_variable_count": 2,
        "non_sensitive_variable_count": 1,
        "environment_variable_count": 1,
        "terraform_variable_count": 2,
    }
    base.update(overrides)
    return base


def _state_version(overrides: dict) -> dict:
    base = {
        "record_type": "terraform_cloud_state_version_summary",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_state_version_summary:sv123",
        "resource_id": "sv123",
        "workspace_resource_id": "ws_opaque_1",
        "state_version_present": False,
        "state_version_count_category": "none",
        "raw_state_never_fetched": True,
    }
    base.update(overrides)
    return base


def _rule_keys(findings: list) -> set:
    return {f.rule_key for f in findings}


# ══════════════════════════════════════════════════════════════════════════════
# A. Module imports and rule key set
# ══════════════════════════════════════════════════════════════════════════════


def test_module_importable() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    assert callable(evaluate)


def test_terraform_cloud_rule_keys_importable() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    assert TERRAFORM_CLOUD_RULE_KEYS == ALL_RULE_KEYS


def test_rule_keys_count() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    # M88C expanded from 18 to 36 rules
    assert len(TERRAFORM_CLOUD_RULE_KEYS) == 36


def test_all_rule_keys_prefixed() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    for key in TERRAFORM_CLOUD_RULE_KEYS:
        assert key.startswith("terraform_cloud_"), (
            f"Rule key {key!r} must have terraform_cloud_ prefix"
        )


# ══════════════════════════════════════════════════════════════════════════════
# B. Rules fire on risky input
# ══════════════════════════════════════════════════════════════════════════════


def test_org_2fa_fires_when_false() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_org({"two_factor_requirement_enabled": False}))
    assert any(f.rule_key == "terraform_cloud_organization_two_factor_not_required" for f in findings)


def test_org_sso_fires_when_false() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_org({"sso_enabled": False}))
    assert any(f.rule_key == "terraform_cloud_organization_sso_not_enabled" for f in findings)


def test_workspace_auto_apply_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_ws({"auto_apply": True}))
    assert any(f.rule_key == "terraform_cloud_workspace_auto_apply_enabled" for f in findings)


def test_workspace_global_remote_state_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_ws({"global_remote_state": True}))
    assert any(f.rule_key == "terraform_cloud_workspace_global_remote_state_enabled" for f in findings)


def test_workspace_local_execution_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_ws({"execution_mode_category": "local"}))
    assert any(f.rule_key == "terraform_cloud_workspace_local_execution_mode" for f in findings)


def test_workspace_vcs_missing_fires_for_remote_without_vcs() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_ws({"vcs_connected": False, "execution_mode_category": "remote"}))
    assert any(f.rule_key == "terraform_cloud_workspace_vcs_connection_missing" for f in findings)


def test_workspace_queue_all_runs_disabled_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_ws({"queue_all_runs": False}))
    assert any(f.rule_key == "terraform_cloud_workspace_queue_all_runs_disabled" for f in findings)


def test_workspace_unpinned_tf_version_latest_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_ws({"terraform_version_category": "latest"}))
    assert any(f.rule_key == "terraform_cloud_workspace_unpinned_terraform_version" for f in findings)


def test_workspace_unpinned_tf_version_unknown_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_ws({"terraform_version_category": "unknown"}))
    assert any(f.rule_key == "terraform_cloud_workspace_unpinned_terraform_version" for f in findings)


def test_variable_non_sensitive_present_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_var_summary({"non_sensitive_variable_count": 2}))
    assert any(f.rule_key == "terraform_cloud_workspace_non_sensitive_variables_present" for f in findings)


def test_variable_no_sensitive_fires_when_all_non_sensitive() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_var_summary({
        "variable_count": 3, "sensitive_variable_count": 0, "non_sensitive_variable_count": 3
    }))
    assert any(f.rule_key == "terraform_cloud_workspace_no_sensitive_variables" for f in findings)


def test_notification_http_webhook_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_notification({
        "webhook_url_scheme_category": "http", "token_present": True
    }))
    assert any(f.rule_key == "terraform_cloud_notification_http_webhook" for f in findings)


def test_notification_token_missing_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_notification({"token_present": False}))
    assert any(f.rule_key == "terraform_cloud_notification_token_missing" for f in findings)


def test_policy_advisory_enforcement_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_policy_set({"enforcement_level_category": "advisory", "policy_count": 3}))
    assert any(f.rule_key == "terraform_cloud_policy_set_advisory_enforcement" for f in findings)


def test_policy_empty_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_policy_set({"policy_count": 0}))
    assert any(f.rule_key == "terraform_cloud_policy_set_empty" for f in findings)


def test_team_admin_access_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_team_access({"admin_access_count": 2}))
    assert any(f.rule_key == "terraform_cloud_team_admin_access" for f in findings)


def test_team_apply_access_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_team_access({"apply_access_count": 1}))
    assert any(f.rule_key == "terraform_cloud_team_apply_access" for f in findings)


def test_variable_set_global_scope_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_varset({"global_scope": True}))
    assert any(f.rule_key == "terraform_cloud_variable_set_global_scope" for f in findings)


def test_state_version_present_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_state_version({
        "state_version_present": True, "state_version_count_category": "few"
    }))
    assert any(f.rule_key == "terraform_cloud_state_version_present" for f in findings)


# ══════════════════════════════════════════════════════════════════════════════
# C. Rules do NOT fire on healthy input
# ══════════════════════════════════════════════════════════════════════════════


def test_healthy_org_no_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_org({
        "two_factor_requirement_enabled": True,
        "sso_enabled": True,
    }))
    assert not findings


def test_healthy_workspace_no_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws({
        "auto_apply": False,
        "global_remote_state": False,
        "execution_mode_category": "remote",
        "vcs_connected": True,
        "queue_all_runs": True,
        "terraform_version_category": "pinned",
    })
    findings = evaluate(record)
    assert not findings, f"Unexpected findings on healthy workspace: {[f.rule_key for f in findings]}"


def test_healthy_variable_summary_no_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_var_summary({"sensitive_variable_count": 3, "non_sensitive_variable_count": 0}))
    assert not findings


def test_variable_summary_empty_no_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_var_summary({"variable_count": 0, "sensitive_variable_count": 0, "non_sensitive_variable_count": 0}))
    assert not findings


def test_healthy_notification_https_with_token_no_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_notification({
        "webhook_url_scheme_category": "https", "token_present": True
    }))
    assert not findings


def test_disabled_notification_no_m88b_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    # M88C adds terraform_cloud_notification_disabled for disabled notifications;
    # M88B rules (http_webhook, token_missing) must not fire on disabled notification.
    M88B_NOTIFICATION_RULES = {
        "terraform_cloud_notification_http_webhook",
        "terraform_cloud_notification_token_missing",
    }
    findings = evaluate(_notification({"enabled": False, "webhook_url_scheme_category": "http"}))
    fired_m88b = {f.rule_key for f in findings} & M88B_NOTIFICATION_RULES
    assert not fired_m88b, f"M88B notification rules fired on disabled notification: {fired_m88b}"


def test_healthy_policy_set_mandatory_no_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_policy_set({
        "enforcement_level_category": "mandatory", "policy_count": 5
    }))
    assert not findings


def test_policy_set_soft_mandatory_no_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_policy_set({
        "enforcement_level_category": "soft_mandatory", "policy_count": 3
    }))
    assert not findings


def test_healthy_team_access_no_admin_no_apply_no_m88b_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    # M88C adds write_access and custom_permissions rules; the _team_access builder
    # has write_access_count=1 by default. Only verify M88B rules don't fire here.
    M88B_TEAM_RULES = {"terraform_cloud_team_admin_access", "terraform_cloud_team_apply_access"}
    findings = evaluate(_team_access({"admin_access_count": 0, "apply_access_count": 0}))
    fired_m88b = {f.rule_key for f in findings} & M88B_TEAM_RULES
    assert not fired_m88b, f"M88B team rules fired when no admin/apply: {fired_m88b}"


def test_healthy_varset_scoped_no_m88b_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    # M88C adds non_sensitive_variables rule that fires on the default varset
    # (non_sensitive_variable_count=1). Only verify M88B rule doesn't fire.
    M88B_VARSET_RULE = "terraform_cloud_variable_set_global_scope"
    findings = evaluate(_varset({"global_scope": False}))
    fired_m88b = {f.rule_key for f in findings if f.rule_key == M88B_VARSET_RULE}
    assert not fired_m88b, "M88B varset global_scope rule fired on non-global varset"


def test_state_version_absent_no_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_state_version({"state_version_present": False}))
    assert not findings


def test_local_execution_vcs_missing_does_not_fire_for_vcs() -> None:
    """vcs_missing rule only fires when execution_mode_category is 'remote'."""
    from app.services.security_rules.terraform_cloud import evaluate
    # Local mode + no VCS → vcs_missing should NOT fire (only local_execution fires)
    findings = evaluate(_ws({"execution_mode_category": "local", "vcs_connected": False}))
    rule_keys = _rule_keys(findings)
    assert "terraform_cloud_workspace_vcs_connection_missing" not in rule_keys
    assert "terraform_cloud_workspace_local_execution_mode" in rule_keys


def test_unknown_record_type_no_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate({
        "record_type": "terraform_cloud_unknown_surface",
        "provider": "terraform_cloud",
    })
    assert findings == []


def test_non_dict_input_no_error() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate("not a dict")  # type: ignore[arg-type]
    assert findings == []


# ══════════════════════════════════════════════════════════════════════════════
# D. Missing/None fields — no false positives
# ══════════════════════════════════════════════════════════════════════════════


def test_missing_auto_apply_no_finding() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws({})
    del record["auto_apply"]
    findings = evaluate(record)
    assert "terraform_cloud_workspace_auto_apply_enabled" not in _rule_keys(findings)


def test_none_auto_apply_no_finding() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    findings = evaluate(_ws({"auto_apply": None}))  # type: ignore[arg-type]
    assert "terraform_cloud_workspace_auto_apply_enabled" not in _rule_keys(findings)


def test_missing_two_fa_no_finding() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _org({})
    del record["two_factor_requirement_enabled"]
    findings = evaluate(record)
    assert "terraform_cloud_organization_two_factor_not_required" not in _rule_keys(findings)


def test_missing_notification_token_field_no_finding() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _notification({"webhook_url_scheme_category": "https"})
    del record["token_present"]
    findings = evaluate(record)
    assert "terraform_cloud_notification_token_missing" not in _rule_keys(findings)


def test_empty_dict_no_error() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    assert evaluate({}) == []


def test_variable_summary_none_variable_count_no_finding() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _var_summary({"variable_count": None, "non_sensitive_variable_count": 5})  # type: ignore[arg-type]
    findings = evaluate(record)
    # When variable_count is None, rules should skip safely
    assert not findings


def test_policy_set_none_policy_count_no_finding() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _policy_set({"policy_count": None, "enforcement_level_category": "mandatory"})  # type: ignore[arg-type]
    findings = evaluate(record)
    assert "terraform_cloud_policy_set_empty" not in _rule_keys(findings)


def test_team_access_none_admin_count_no_finding() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _team_access({"admin_access_count": None})  # type: ignore[arg-type]
    findings = evaluate(record)
    assert "terraform_cloud_team_admin_access" not in _rule_keys(findings)


# ══════════════════════════════════════════════════════════════════════════════
# E. Evidence safety — no forbidden keys
# ══════════════════════════════════════════════════════════════════════════════


def _all_findings() -> list:
    """Generate findings covering all record types."""
    from app.services.security_rules.terraform_cloud import evaluate
    findings = []
    findings.extend(evaluate(_org({"two_factor_requirement_enabled": False, "sso_enabled": False})))
    findings.extend(evaluate(_ws({
        "auto_apply": True, "global_remote_state": True, "execution_mode_category": "local",
        "vcs_connected": False, "queue_all_runs": False, "terraform_version_category": "latest",
    })))
    findings.extend(evaluate(_var_summary({
        "variable_count": 5, "sensitive_variable_count": 0, "non_sensitive_variable_count": 5
    })))
    findings.extend(evaluate(_notification({
        "webhook_url_scheme_category": "http", "token_present": False
    })))
    findings.extend(evaluate(_policy_set({
        "enforcement_level_category": "advisory", "policy_count": 0
    })))
    findings.extend(evaluate(_team_access({"admin_access_count": 2, "apply_access_count": 1})))
    findings.extend(evaluate(_varset({"global_scope": True})))
    findings.extend(evaluate(_state_version({"state_version_present": True})))
    return findings


def test_evidence_no_forbidden_keys() -> None:
    findings = _all_findings()
    assert findings, "Should have generated at least some findings"
    for f in findings:
        for key in f.evidence:
            assert key not in FORBIDDEN_EVIDENCE_KEYS, (
                f"Forbidden key {key!r} in evidence for rule {f.rule_key}"
            )


def test_evidence_values_are_flat_scalars() -> None:
    """All evidence values must be booleans, ints, or short strings — never dicts/lists."""
    findings = _all_findings()
    for f in findings:
        for key, val in f.evidence.items():
            assert isinstance(val, (bool, int, str, type(None))), (
                f"Evidence value for {key!r} in {f.rule_key} must be scalar, got {type(val)}"
            )


def test_evidence_strings_no_raw_data() -> None:
    """Evidence string values must not contain raw secrets, URLs, or names."""
    SUSPICIOUS_PATTERNS = [
        r"https?://",
        r"glpat-",
        r"eyJ[A-Za-z0-9_-]{10,}",
        r"@[a-zA-Z0-9]+\.[a-zA-Z]{2,}",  # email-like
    ]
    findings = _all_findings()
    for f in findings:
        for key, val in f.evidence.items():
            if isinstance(val, str):
                for pattern in SUSPICIOUS_PATTERNS:
                    assert not re.search(pattern, val), (
                        f"Suspicious pattern {pattern!r} found in evidence {key!r}={val!r} "
                        f"for rule {f.rule_key}"
                    )


# ══════════════════════════════════════════════════════════════════════════════
# F. Finding descriptions — disclaimer present, no forbidden wording
# ══════════════════════════════════════════════════════════════════════════════


def test_all_findings_have_disclaimer() -> None:
    findings = _all_findings()
    for f in findings:
        assert _DISCLAIMER_FRAGMENT in f.description.lower(), (
            f"Rule {f.rule_key} description missing disclaimer. Got: {f.description!r}"
        )


def test_no_forbidden_wording_in_descriptions() -> None:
    findings = _all_findings()
    for f in findings:
        desc_lower = f.description.lower()
        for phrase in FORBIDDEN_DESCRIPTION_PHRASES:
            assert phrase not in desc_lower, (
                f"Forbidden phrase {phrase!r} in rule {f.rule_key} description: {f.description!r}"
            )


def test_findings_have_provider_terraform_cloud() -> None:
    findings = _all_findings()
    for f in findings:
        assert f.provider == "terraform_cloud", (
            f"Finding {f.rule_key} has wrong provider: {f.provider!r}"
        )


def test_findings_have_valid_severity() -> None:
    findings = _all_findings()
    valid = {"critical", "high", "medium", "low", "info"}
    for f in findings:
        assert f.severity in valid, (
            f"Rule {f.rule_key} has invalid severity: {f.severity!r}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# G. Registry / confidence / pack parity
# ══════════════════════════════════════════════════════════════════════════════


def test_all_rule_keys_in_registry() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    missing = ALL_RULE_KEYS - KNOWN_RULE_KEYS
    assert not missing, f"Rule keys missing from registry: {sorted(missing)}"


def test_all_rule_keys_in_confidence() -> None:
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    missing = ALL_RULE_KEYS - set(RULE_CONFIDENCE)
    assert not missing, f"Rule keys missing from confidence: {sorted(missing)}"


def test_all_rule_keys_in_pack() -> None:
    from app.services.security_rule_pack import _RULE_META
    missing = ALL_RULE_KEYS - set(_RULE_META)
    assert not missing, f"Rule keys missing from pack: {sorted(missing)}"


def test_pack_severities_match_rule_module() -> None:
    """Pack severity must match actual finding severity for each rule."""
    from app.services.security_rules.terraform_cloud import evaluate
    from app.services.security_rule_pack import _RULE_META

    # Map from rule_key → finding severity (from actual evaluation)
    rule_to_sev: dict[str, str] = {}
    for f in _all_findings():
        if f.rule_key not in rule_to_sev:
            rule_to_sev[f.rule_key] = f.severity

    for rule_key, (provider, pack_sev, _cat) in _RULE_META.items():
        if not rule_key.startswith("terraform_cloud_"):
            continue
        if rule_key in rule_to_sev:
            assert pack_sev == rule_to_sev[rule_key], (
                f"Pack severity {pack_sev!r} != finding severity {rule_to_sev[rule_key]!r} "
                f"for rule {rule_key}"
            )


def test_pack_provider_is_terraform_cloud_for_all_rules() -> None:
    from app.services.security_rule_pack import _RULE_META
    for rule_key, (provider, _sev, _cat) in _RULE_META.items():
        if rule_key.startswith("terraform_cloud_"):
            assert provider == "terraform_cloud", (
                f"Pack provider for {rule_key} is {provider!r}, expected 'terraform_cloud'"
            )


# ══════════════════════════════════════════════════════════════════════════════
# H. Coverage service parity
# ══════════════════════════════════════════════════════════════════════════════


def test_all_rule_keys_in_coverage_rule_record_types() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    missing = ALL_RULE_KEYS - set(RULE_RECORD_TYPES)
    assert not missing, f"Rule keys missing from RULE_RECORD_TYPES: {sorted(missing)}"


def test_coverage_rule_record_types_are_terraform_cloud() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    for rule_key, record_types in RULE_RECORD_TYPES.items():
        if rule_key.startswith("terraform_cloud_"):
            for rt in record_types:
                assert rt.startswith("terraform_cloud_"), (
                    f"Rule {rule_key} maps to non-terraform_cloud record type {rt!r}"
                )


def test_coverage_provider_surfaces_includes_terraform_cloud() -> None:
    from app.services.security_coverage_service import PROVIDER_SURFACES
    assert "terraform_cloud" in PROVIDER_SURFACES
    assert len(PROVIDER_SURFACES["terraform_cloud"]) >= 5


# ══════════════════════════════════════════════════════════════════════════════
# I. Frontend catalog parity
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_all_rule_keys_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text()
    missing = [key for key in ALL_RULE_KEYS if key not in text]
    assert not missing, f"Rule keys missing from securityRuleCatalog.ts: {sorted(missing)}"


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_terraform_cloud_provider_label() -> None:
    text = FE_RULE_CATALOG.read_text()
    assert 'provider: "terraform_cloud"' in text


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_terraform_cloud_count() -> None:
    text = FE_RULE_CATALOG.read_text()
    catalog_keys = set(re.findall(r'key: "terraform_cloud_([a-z_]+)"', text))
    # M88C expanded from 18 to 36 terraform_cloud catalog entries
    assert len(catalog_keys) == 36, (
        f"Expected 36 terraform_cloud catalog entries, found {len(catalog_keys)}: {sorted(catalog_keys)}"
    )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_severities_match_pack() -> None:
    """For each TC rule in catalog, severity must match the pack."""
    from app.services.security_rule_pack import _RULE_META
    text = FE_RULE_CATALOG.read_text()

    # Extract key → severity from catalog
    catalog_sevs: dict[str, str] = {}
    for m in re.finditer(r'key: "(terraform_cloud_[a-z_]+)".*?severity: "(\w+)"', text, re.DOTALL):
        if m.end() - m.start() < 500:  # guard against runaway match
            catalog_sevs[m.group(1)] = m.group(2)

    for rule_key, (provider, pack_sev, _cat) in _RULE_META.items():
        if not rule_key.startswith("terraform_cloud_"):
            continue
        if rule_key in catalog_sevs:
            assert catalog_sevs[rule_key] == pack_sev, (
                f"Catalog severity {catalog_sevs[rule_key]!r} != pack {pack_sev!r} for {rule_key}"
            )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_no_forbidden_wording_in_terraform_entries() -> None:
    text = FE_RULE_CATALOG.read_text()
    # Find terraform_cloud section only
    lines = text.splitlines()
    in_tc = False
    for line in lines:
        ll = line.lower()
        if 'provider: "terraform_cloud"' in ll:
            in_tc = True
        elif re.search(r'provider: "[a-z_]+"', ll) and "terraform" not in ll:
            in_tc = False
        if not in_tc:
            continue
        for phrase in FORBIDDEN_DESCRIPTION_PHRASES:
            assert phrase not in ll, (
                f"Forbidden phrase {phrase!r} in Terraform Cloud catalog: {line.strip()!r}"
            )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_terraform_cloud_in_provider_coverage() -> None:
    text = FE_RULE_CATALOG.read_text()
    idx = text.find("PROVIDER_COVERAGE")
    assert idx != -1
    coverage_section = text[idx:]
    assert "terraform_cloud" in coverage_section


# ══════════════════════════════════════════════════════════════════════════════
# J. Evaluator dispatch
# ══════════════════════════════════════════════════════════════════════════════


def test_evaluator_has_terraform_cloud_in_provider_rules() -> None:
    from app.services.security_finding_evaluator import _PROVIDER_RULES
    assert "terraform_cloud" in _PROVIDER_RULES, (
        "terraform_cloud missing from _PROVIDER_RULES in security_finding_evaluator"
    )


def test_evaluator_evaluate_record_risky_workspace() -> None:
    from app.services.security_finding_evaluator import evaluate_record
    record = _ws({"auto_apply": True, "global_remote_state": True})
    findings = evaluate_record(record, "terraform_cloud")
    assert len(findings) >= 2
    rule_keys = _rule_keys(findings)
    assert "terraform_cloud_workspace_auto_apply_enabled" in rule_keys
    assert "terraform_cloud_workspace_global_remote_state_enabled" in rule_keys


def test_evaluator_evaluate_record_healthy_returns_empty() -> None:
    from app.services.security_finding_evaluator import evaluate_record
    record = _ws({})
    findings = evaluate_record(record, "terraform_cloud")
    assert findings == []


def test_evaluator_unknown_record_type_returns_empty() -> None:
    from app.services.security_finding_evaluator import evaluate_record
    record = {"record_type": "terraform_cloud_unknown", "provider": "terraform_cloud"}
    findings = evaluate_record(record, "terraform_cloud")
    assert findings == []


def test_evaluator_provider_not_in_rules_returns_empty() -> None:
    from app.services.security_finding_evaluator import evaluate_record
    record = _ws({"auto_apply": True})
    findings = evaluate_record(record, "not_a_provider")
    assert findings == []


# ══════════════════════════════════════════════════════════════════════════════
# K. Capability matrix and expansion framework
# ══════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_security_rules_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.security.security_rules is True


def test_capability_matrix_no_activity_yet() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    # activity_ingestion added in M88D — accept True or False for forward compat
    assert cap.security.activity_signals is False
    assert cap.security.risk_activity_correlations is False
    assert cap.security.demo_seed_clear is False
    assert cap.security.case_report is False


def test_capability_matrix_notes_mention_m88b() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert "M88B" in cap.notes or "core security" in cap.notes.lower() or "18" in cap.notes


def test_capability_matrix_planned_next_stage_is_m88c() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert "M88C" in cap.notes or "Risk Expansion" in cap.notes or "Variable/Policy" in cap.notes


def test_expansion_framework_planned_next_stage_m88c() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    # M88D complete — planned_next_stage advanced to M88E
    assert (
        "M88C" in planned or "Variable/Policy" in planned or "Risk Expansion" in planned
        or "M88D" in planned or "Activity" in planned or "Event Ingestion" in planned
        or "M88E" in planned or "Signals" in planned
    ), (
        f"planned_next_stage should point to M88C or later; got: {planned!r}"
    )


def test_expansion_framework_kubernetes_after_terraform_cloud() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    providers = [r.get("provider", "") for r in recommended if isinstance(r, dict)]
    tc_idx = next((i for i, p in enumerate(providers) if "terraform" in p.lower()), None)
    k8s_idx = next((i for i, p in enumerate(providers) if "kubernetes" in p.lower()), None)
    if tc_idx is not None and k8s_idx is not None:
        assert tc_idx < k8s_idx


# ══════════════════════════════════════════════════════════════════════════════
# L. Regression smoke
# ══════════════════════════════════════════════════════════════════════════════


def test_gitlab_rules_still_dispatch() -> None:
    """M87 GitLab rules must still work after M88B changes."""
    from app.services.security_finding_evaluator import evaluate_record
    record = {
        "record_type": "gitlab_project",
        "provider": "gitlab",
        "record_id": "gitlab_project:abc",
        "resource_id": "abc",
        "visibility_category": "public",
        "archived": False,
        "default_branch_present": True,
    }
    findings = evaluate_record(record, "gitlab")
    assert any(f.rule_key == "gitlab_project_public_visibility" for f in findings)


def test_m88a_connector_still_importable() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    assert TerraformCloudConnector is not None


def test_m88a_schema_still_importable() -> None:
    from app.connectors.terraform_cloud_schema import TERRAFORM_CLOUD_RECORD_TYPES
    assert len(TERRAFORM_CLOUD_RECORD_TYPES) == 10
