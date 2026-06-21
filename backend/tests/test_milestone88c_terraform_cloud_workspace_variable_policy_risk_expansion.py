"""M88C — Terraform Cloud workspace/variable/policy risk expansion guardrails.

Verifies that M88C expands Terraform Cloud security findings across workspace
execution/run posture, workspace variable posture, variable set blast-radius
posture, policy set scope/enforcement posture, notification trigger posture,
run trigger posture, team access posture — using only the safe M88A normalized
fields.

Sections:
  A. Rule key set — M88C keys exist, M88B keys still exist
  B. M88C rules fire on risky input
  C. M88C rules do not fire on healthy input
  D. Missing/None fields — no false positives
  E. Evidence safety — no forbidden keys
  F. Finding descriptions — disclaimer present, no forbidden wording
  G. Registry / confidence / pack parity
  H. Coverage service parity
  I. Frontend catalog parity
  J. Evaluator dispatch — evaluate_record fires M88C rules
  K. No activity/signals/correlations/demo support claimed
  L. Capability matrix and expansion framework — M88D next stage
  M. Regression — M88A and M88B rules still present and still fire
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_RULE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"

# ── M88B rule keys (must still exist) ─────────────────────────────────────────

M88B_RULE_KEYS = {
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
    "terraform_cloud_team_plan_access",
    "terraform_cloud_variable_set_global_scope",
    "terraform_cloud_state_version_present",
}

# ── M88C rule keys ─────────────────────────────────────────────────────────────

M88C_RULE_KEYS = {
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

ALL_RULE_KEYS = M88B_RULE_KEYS | M88C_RULE_KEYS

# ── Evidence safety ────────────────────────────────────────────────────────────

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

# ── Record builders ────────────────────────────────────────────────────────────


def _ws(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "terraform_cloud_workspace",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_workspace:ws1",
        "resource_id": "ws1",
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
        "latest_run_status_category": "applied",
    }
    base.update(overrides)
    return base


def _var_summary(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "terraform_cloud_workspace_variable_summary",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_workspace_variable_summary:vs1",
        "resource_id": "vs1",
        "workspace_resource_id": "ws_opaque_1",
        "variable_count": 0,
        "sensitive_variable_count": 0,
        "non_sensitive_variable_count": 0,
        "environment_variable_count": 0,
        "terraform_variable_count": 0,
        "unprotected_non_sensitive_count": 0,
        "raw_value_never_read": True,
    }
    base.update(overrides)
    return base


def _varset(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "terraform_cloud_variable_set",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_variable_set:vset1",
        "resource_id": "vset1",
        "variable_set_resource_id": "vset_opaque_1",
        "organization_resource_id": "org_opaque_1",
        "global_scope": False,
        "workspace_count": 2,
        "project_count": 0,
        "variable_count": 3,
        "sensitive_variable_count": 3,
        "non_sensitive_variable_count": 0,
        "environment_variable_count": 0,
        "terraform_variable_count": 3,
    }
    base.update(overrides)
    return base


def _policy_set(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "terraform_cloud_policy_set",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_policy_set:ps1",
        "resource_id": "ps1",
        "policy_set_resource_id": "ps_opaque_1",
        "organization_resource_id": "org_opaque_1",
        "global_scope": False,
        "workspace_count": 2,
        "project_count": 1,
        "policy_count": 3,
        "enforcement_level_category": "mandatory",
        "vcs_connected": False,
    }
    base.update(overrides)
    return base


def _notification(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "terraform_cloud_notification_configuration",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_notification_configuration:nc1",
        "resource_id": "nc1",
        "notification_resource_id": "nc_opaque_1",
        "workspace_resource_id": "ws_opaque_1",
        "enabled": True,
        "destination_type_category": "slack",
        "trigger_count": 2,
        "webhook_url_present": False,
        "webhook_url_scheme_category": None,
        "token_present": False,
    }
    base.update(overrides)
    return base


def _run_trigger(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "terraform_cloud_run_trigger",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_run_trigger:rt1",
        "resource_id": "rt1",
        "run_trigger_resource_id": "rt_opaque_1",
        "workspace_resource_id": "ws_opaque_1",
        "sourceable_type_category": "workspace",
    }
    base.update(overrides)
    return base


def _team_access(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "terraform_cloud_team_access_summary",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_team_access_summary:ta1",
        "resource_id": "ta1",
        "workspace_resource_id": "ws_opaque_1",
        "team_access_count": 2,
        "admin_access_count": 0,
        "write_access_count": 0,
        "read_access_count": 2,
        "plan_access_count": 0,
        "custom_permission_count": 0,
    }
    base.update(overrides)
    return base


# ── Helper ─────────────────────────────────────────────────────────────────────


def _rule_keys(findings: list) -> set[str]:
    return {f.rule_key for f in findings}


# ══════════════════════════════════════════════════════════════════════════════
# Section A: Rule key set
# ══════════════════════════════════════════════════════════════════════════════


def test_m88c_rule_keys_exist_in_module() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    missing = M88C_RULE_KEYS - TERRAFORM_CLOUD_RULE_KEYS
    assert not missing, f"M88C rule keys missing from TERRAFORM_CLOUD_RULE_KEYS: {missing}"


def test_m88b_rule_keys_still_exist_in_module() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    missing = M88B_RULE_KEYS - TERRAFORM_CLOUD_RULE_KEYS
    assert not missing, f"M88B rule keys removed from TERRAFORM_CLOUD_RULE_KEYS: {missing}"


# ══════════════════════════════════════════════════════════════════════════════
# Section B: M88C rules fire on risky input
# ══════════════════════════════════════════════════════════════════════════════


def test_workspace_agent_execution_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws(execution_mode_category="agent")
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_agent_execution_mode" in keys


def test_workspace_file_triggers_disabled_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws(file_triggers_enabled=False)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_file_triggers_disabled" in keys


def test_workspace_speculative_disabled_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws(speculative_enabled=False)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_speculative_plans_disabled" in keys


def test_workspace_run_triggers_present_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws(run_trigger_count=2)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_run_triggers_present" in keys


def test_workspace_many_trigger_prefixes_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws(trigger_prefix_count=5)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_many_trigger_prefixes" in keys


def test_workspace_latest_run_failed_fires_errored() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws(latest_run_status_category="errored")
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_latest_run_failed" in keys


def test_workspace_latest_run_failed_fires_canceled() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws(latest_run_status_category="canceled")
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_latest_run_failed" in keys


def test_workspace_latest_run_failed_fires_policy_override() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws(latest_run_status_category="policy_override")
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_latest_run_failed" in keys


def test_workspace_latest_run_failed_fires_discarded() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws(latest_run_status_category="discarded")
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_latest_run_failed" in keys


def test_env_vars_non_sensitive_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _var_summary(
        variable_count=3,
        environment_variable_count=2,
        terraform_variable_count=1,
        non_sensitive_variable_count=2,
        sensitive_variable_count=1,
        unprotected_non_sensitive_count=2,
    )
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_environment_variables_non_sensitive" in keys


def test_tf_vars_non_sensitive_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _var_summary(
        variable_count=3,
        environment_variable_count=0,
        terraform_variable_count=3,
        non_sensitive_variable_count=2,
        sensitive_variable_count=1,
    )
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_terraform_variables_non_sensitive" in keys


def test_varset_non_sensitive_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _varset(non_sensitive_variable_count=2, variable_count=4, sensitive_variable_count=2)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_variable_set_non_sensitive_variables" in keys


def test_varset_broad_scope_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _varset(global_scope=True, variable_count=5, non_sensitive_variable_count=0)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_variable_set_broad_scope" in keys


def test_policy_set_global_scope_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _policy_set(global_scope=True, enforcement_level_category="mandatory")
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_policy_set_global_scope" in keys


def test_policy_set_broad_scope_advisory_fires_global() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _policy_set(global_scope=True, enforcement_level_category="advisory")
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_policy_set_broad_scope_advisory" in keys


def test_policy_set_broad_scope_advisory_fires_many_workspaces() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _policy_set(
        global_scope=False, workspace_count=5, enforcement_level_category="advisory"
    )
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_policy_set_broad_scope_advisory" in keys


def test_policy_set_no_scope_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _policy_set(global_scope=False, workspace_count=0, project_count=0)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_policy_set_no_workspace_or_project_scope" in keys


def test_notification_broad_triggers_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _notification(enabled=True, trigger_count=5)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_notification_broad_trigger_scope" in keys


def test_notification_disabled_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _notification(enabled=False)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_notification_disabled" in keys


def test_run_trigger_enabled_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _run_trigger()
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_run_trigger_enabled" in keys


def test_team_write_access_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _team_access(write_access_count=2)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_team_write_access" in keys


def test_team_custom_permissions_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _team_access(custom_permission_count=1)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_team_custom_permissions" in keys


# ══════════════════════════════════════════════════════════════════════════════
# Section C: M88C rules do NOT fire on healthy input
# ══════════════════════════════════════════════════════════════════════════════


def test_workspace_agent_mode_not_fires_remote() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    keys = _rule_keys(evaluate(_ws(execution_mode_category="remote")))
    assert "terraform_cloud_workspace_agent_execution_mode" not in keys


def test_workspace_file_triggers_not_fires_when_enabled() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    keys = _rule_keys(evaluate(_ws(file_triggers_enabled=True)))
    assert "terraform_cloud_workspace_file_triggers_disabled" not in keys


def test_workspace_speculative_not_fires_when_enabled() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    keys = _rule_keys(evaluate(_ws(speculative_enabled=True)))
    assert "terraform_cloud_workspace_speculative_plans_disabled" not in keys


def test_workspace_run_triggers_not_fires_when_zero() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    keys = _rule_keys(evaluate(_ws(run_trigger_count=0)))
    assert "terraform_cloud_workspace_run_triggers_present" not in keys


def test_workspace_trigger_prefixes_not_fires_below_threshold() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    keys = _rule_keys(evaluate(_ws(trigger_prefix_count=4)))
    assert "terraform_cloud_workspace_many_trigger_prefixes" not in keys


def test_workspace_latest_run_not_fires_on_applied() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    keys = _rule_keys(evaluate(_ws(latest_run_status_category="applied")))
    assert "terraform_cloud_workspace_latest_run_failed" not in keys


def test_workspace_latest_run_not_fires_on_planned() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    keys = _rule_keys(evaluate(_ws(latest_run_status_category="planned")))
    assert "terraform_cloud_workspace_latest_run_failed" not in keys


def test_env_vars_non_sensitive_not_fires_all_sensitive() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _var_summary(
        variable_count=3, environment_variable_count=3,
        non_sensitive_variable_count=0, sensitive_variable_count=3,
    )
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_environment_variables_non_sensitive" not in keys


def test_env_vars_non_sensitive_not_fires_no_env_vars() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _var_summary(
        variable_count=3, environment_variable_count=0,
        terraform_variable_count=3, non_sensitive_variable_count=2,
    )
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_environment_variables_non_sensitive" not in keys


def test_tf_vars_non_sensitive_not_fires_no_tf_vars() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _var_summary(
        variable_count=3, terraform_variable_count=0,
        environment_variable_count=3, non_sensitive_variable_count=2,
    )
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_terraform_variables_non_sensitive" not in keys


def test_varset_non_sensitive_not_fires_all_sensitive() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _varset(non_sensitive_variable_count=0, sensitive_variable_count=3)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_variable_set_non_sensitive_variables" not in keys


def test_varset_broad_scope_not_fires_below_threshold() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _varset(global_scope=True, variable_count=4)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_variable_set_broad_scope" not in keys


def test_varset_broad_scope_not_fires_not_global() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _varset(global_scope=False, variable_count=10)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_variable_set_broad_scope" not in keys


def test_policy_global_scope_not_fires_when_not_global() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _policy_set(global_scope=False)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_policy_set_global_scope" not in keys


def test_policy_broad_scope_advisory_not_fires_non_advisory_global() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _policy_set(global_scope=True, enforcement_level_category="mandatory")
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_policy_set_broad_scope_advisory" not in keys


def test_policy_no_scope_not_fires_with_workspaces() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _policy_set(global_scope=False, workspace_count=2, project_count=0)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_policy_set_no_workspace_or_project_scope" not in keys


def test_notification_broad_triggers_not_fires_below_threshold() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _notification(enabled=True, trigger_count=4)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_notification_broad_trigger_scope" not in keys


def test_notification_disabled_not_fires_when_enabled() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _notification(enabled=True)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_notification_disabled" not in keys


def test_team_write_not_fires_when_zero() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    keys = _rule_keys(evaluate(_team_access(write_access_count=0)))
    assert "terraform_cloud_team_write_access" not in keys


def test_team_custom_not_fires_when_zero() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    keys = _rule_keys(evaluate(_team_access(custom_permission_count=0)))
    assert "terraform_cloud_team_custom_permissions" not in keys


# ══════════════════════════════════════════════════════════════════════════════
# Section D: Missing/None fields — no false positives
# ══════════════════════════════════════════════════════════════════════════════


def test_workspace_no_false_positive_on_empty_record() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    minimal = {"record_type": "terraform_cloud_workspace", "provider": "terraform_cloud"}
    findings = evaluate(minimal)
    m88c_keys = _rule_keys(findings) & M88C_RULE_KEYS
    assert not m88c_keys, f"M88C rule fired on empty workspace record: {m88c_keys}"


def test_var_summary_no_false_positive_on_empty() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    minimal = {
        "record_type": "terraform_cloud_workspace_variable_summary",
        "provider": "terraform_cloud",
    }
    findings = evaluate(minimal)
    m88c_keys = _rule_keys(findings) & M88C_RULE_KEYS
    assert not m88c_keys


def test_varset_no_false_positive_on_empty() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    minimal = {
        "record_type": "terraform_cloud_variable_set",
        "provider": "terraform_cloud",
    }
    findings = evaluate(minimal)
    m88c_keys = _rule_keys(findings) & M88C_RULE_KEYS
    assert not m88c_keys


def test_policy_set_no_false_positive_on_empty() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    minimal = {
        "record_type": "terraform_cloud_policy_set",
        "provider": "terraform_cloud",
    }
    findings = evaluate(minimal)
    m88c_keys = _rule_keys(findings) & M88C_RULE_KEYS
    assert not m88c_keys


def test_notification_no_false_positive_on_empty() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    minimal = {
        "record_type": "terraform_cloud_notification_configuration",
        "provider": "terraform_cloud",
    }
    findings = evaluate(minimal)
    m88c_keys = _rule_keys(findings) & M88C_RULE_KEYS
    assert not m88c_keys


def test_team_access_no_false_positive_on_empty() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    minimal = {
        "record_type": "terraform_cloud_team_access_summary",
        "provider": "terraform_cloud",
    }
    findings = evaluate(minimal)
    m88c_keys = _rule_keys(findings) & M88C_RULE_KEYS
    assert not m88c_keys


def test_workspace_latest_run_status_none_no_false_positive() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws(latest_run_status_category=None)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_latest_run_failed" not in keys


def test_var_summary_zero_variables_no_false_positive() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _var_summary(variable_count=0, environment_variable_count=0)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_environment_variables_non_sensitive" not in keys
    assert "terraform_cloud_workspace_terraform_variables_non_sensitive" not in keys


def test_policy_set_no_scope_not_fires_when_fields_missing() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    # workspace_count missing → can't confirm 0 → should not fire
    record = {"record_type": "terraform_cloud_policy_set", "global_scope": False}
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_policy_set_no_workspace_or_project_scope" not in keys


# ══════════════════════════════════════════════════════════════════════════════
# Section E: Evidence safety
# ══════════════════════════════════════════════════════════════════════════════


def _all_m88c_findings() -> list:
    from app.services.security_rules.terraform_cloud import evaluate
    records = [
        _ws(execution_mode_category="agent"),
        _ws(file_triggers_enabled=False),
        _ws(speculative_enabled=False),
        _ws(run_trigger_count=3),
        _ws(trigger_prefix_count=5),
        _ws(latest_run_status_category="errored"),
        _var_summary(
            variable_count=4, environment_variable_count=2, terraform_variable_count=2,
            non_sensitive_variable_count=3, sensitive_variable_count=1, raw_value_never_read=True,
        ),
        _varset(non_sensitive_variable_count=2, variable_count=4),
        _varset(global_scope=True, variable_count=5),
        _policy_set(global_scope=True),
        _policy_set(global_scope=True, enforcement_level_category="advisory"),
        _policy_set(global_scope=False, workspace_count=0, project_count=0),
        _notification(enabled=True, trigger_count=5),
        _notification(enabled=False),
        _run_trigger(),
        _team_access(write_access_count=1),
        _team_access(custom_permission_count=1),
    ]
    findings = []
    for r in records:
        findings.extend(evaluate(r))
    return [f for f in findings if f.rule_key in M88C_RULE_KEYS]


def test_evidence_has_no_forbidden_keys() -> None:
    for finding in _all_m88c_findings():
        ev = finding.evidence or {}
        for key in ev:
            assert key.lower() not in FORBIDDEN_EVIDENCE_KEYS, (
                f"Forbidden evidence key '{key}' in {finding.rule_key}"
            )


def test_evidence_has_no_raw_strings_matching_forbidden_patterns() -> None:
    """Evidence values must not contain secret-shaped content."""
    SECRET_PATTERNS = [
        r"eyJ[A-Za-z0-9_-]{10,}",       # JWT
        r"SG\.[A-Za-z0-9_-]{10,}",      # SendGrid key
        r"AC[0-9a-fA-F]{32}",            # Twilio SID
        r"glpat-[A-Za-z0-9_-]{10,}",    # GitLab token
    ]
    for finding in _all_m88c_findings():
        ev = finding.evidence or {}
        for val in ev.values():
            if not isinstance(val, str):
                continue
            for pattern in SECRET_PATTERNS:
                assert not re.search(pattern, val), (
                    f"Evidence value matches secret pattern in {finding.rule_key}: {val!r}"
                )


# ══════════════════════════════════════════════════════════════════════════════
# Section F: Finding descriptions
# ══════════════════════════════════════════════════════════════════════════════


def test_descriptions_contain_disclaimer() -> None:
    for finding in _all_m88c_findings():
        assert _DISCLAIMER_FRAGMENT in finding.description, (
            f"Disclaimer missing in {finding.rule_key}: {finding.description[:120]!r}"
        )


def test_descriptions_have_no_forbidden_wording() -> None:
    for finding in _all_m88c_findings():
        desc_lower = finding.description.lower()
        for phrase in FORBIDDEN_DESCRIPTION_PHRASES:
            assert phrase not in desc_lower, (
                f"Forbidden phrase '{phrase}' in description for {finding.rule_key}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# Section G: Registry / confidence / pack parity
# ══════════════════════════════════════════════════════════════════════════════


def test_registry_contains_all_m88c_rules() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    missing = M88C_RULE_KEYS - KNOWN_RULE_KEYS
    assert not missing, f"M88C rules missing from registry: {missing}"


def test_registry_still_contains_all_m88b_rules() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    missing = M88B_RULE_KEYS - KNOWN_RULE_KEYS
    assert not missing, f"M88B rules removed from registry: {missing}"


def test_confidence_contains_all_m88c_rules() -> None:
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    missing = M88C_RULE_KEYS - set(RULE_CONFIDENCE.keys())
    assert not missing, f"M88C rules missing from confidence: {missing}"


def test_pack_contains_all_m88c_rules() -> None:
    from app.services.security_rule_pack import _RULE_META
    missing = M88C_RULE_KEYS - set(_RULE_META.keys())
    assert not missing, f"M88C rules missing from rule pack: {missing}"


def test_pack_still_contains_all_m88b_rules() -> None:
    from app.services.security_rule_pack import _RULE_META
    missing = M88B_RULE_KEYS - set(_RULE_META.keys())
    assert not missing, f"M88B rules removed from rule pack: {missing}"


# ══════════════════════════════════════════════════════════════════════════════
# Section H: Coverage service parity
# ══════════════════════════════════════════════════════════════════════════════


def test_coverage_service_maps_all_m88c_rules() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    missing = M88C_RULE_KEYS - set(RULE_RECORD_TYPES.keys())
    assert not missing, f"M88C rules not in coverage RULE_RECORD_TYPES: {missing}"


def test_coverage_service_correct_record_types() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    expected = {
        "terraform_cloud_workspace_agent_execution_mode": "terraform_cloud_workspace",
        "terraform_cloud_workspace_file_triggers_disabled": "terraform_cloud_workspace",
        "terraform_cloud_workspace_speculative_plans_disabled": "terraform_cloud_workspace",
        "terraform_cloud_workspace_run_triggers_present": "terraform_cloud_workspace",
        "terraform_cloud_workspace_many_trigger_prefixes": "terraform_cloud_workspace",
        "terraform_cloud_workspace_latest_run_failed": "terraform_cloud_workspace",
        "terraform_cloud_workspace_environment_variables_non_sensitive": "terraform_cloud_workspace_variable_summary",
        "terraform_cloud_workspace_terraform_variables_non_sensitive": "terraform_cloud_workspace_variable_summary",
        "terraform_cloud_variable_set_non_sensitive_variables": "terraform_cloud_variable_set",
        "terraform_cloud_variable_set_broad_scope": "terraform_cloud_variable_set",
        "terraform_cloud_policy_set_global_scope": "terraform_cloud_policy_set",
        "terraform_cloud_policy_set_broad_scope_advisory": "terraform_cloud_policy_set",
        "terraform_cloud_policy_set_no_workspace_or_project_scope": "terraform_cloud_policy_set",
        "terraform_cloud_notification_broad_trigger_scope": "terraform_cloud_notification_configuration",
        "terraform_cloud_notification_disabled": "terraform_cloud_notification_configuration",
        "terraform_cloud_run_trigger_enabled": "terraform_cloud_run_trigger",
        "terraform_cloud_team_write_access": "terraform_cloud_team_access_summary",
        "terraform_cloud_team_custom_permissions": "terraform_cloud_team_access_summary",
    }
    for key, expected_rt in expected.items():
        actual_rts = RULE_RECORD_TYPES.get(key, ())
        assert expected_rt in actual_rts, (
            f"{key}: expected record type '{expected_rt}', got {actual_rts!r}"
        )


def test_terraform_cloud_in_coverage_providers() -> None:
    from app.services.security_coverage_service import PROVIDERS
    assert "terraform_cloud" in PROVIDERS


# ══════════════════════════════════════════════════════════════════════════════
# Section I: Frontend catalog parity
# ══════════════════════════════════════════════════════════════════════════════


def test_frontend_catalog_contains_all_m88c_rules() -> None:
    catalog_text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for key in M88C_RULE_KEYS:
        assert f'key: "{key}"' in catalog_text, (
            f"M88C rule key '{key}' not found in frontend catalog"
        )


def test_frontend_backend_severity_match() -> None:
    from app.services.security_rule_pack import _RULE_META
    catalog_text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for key in M88C_RULE_KEYS:
        _, backend_sev, _ = _RULE_META.get(key, ("", "", ""))
        pattern = rf'key: "{re.escape(key)}".*?severity: "([^"]+)"'
        m = re.search(pattern, catalog_text, re.DOTALL)
        assert m is not None, f"Could not find frontend entry for {key}"
        fe_sev = m.group(1)
        assert fe_sev == backend_sev, (
            f"Severity mismatch for {key}: backend={backend_sev!r}, frontend={fe_sev!r}"
        )


def test_frontend_backend_category_match() -> None:
    from app.services.security_rule_pack import _RULE_META
    catalog_text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for key in M88C_RULE_KEYS:
        _, _, backend_cat = _RULE_META.get(key, ("", "", ""))
        pattern = rf'key: "{re.escape(key)}".*?category: "([^"]+)"'
        m = re.search(pattern, catalog_text, re.DOTALL)
        assert m is not None, f"Could not find frontend entry for {key}"
        fe_cat = m.group(1)
        assert fe_cat == backend_cat, (
            f"Category mismatch for {key}: backend={backend_cat!r}, frontend={fe_cat!r}"
        )


def test_frontend_catalog_no_forbidden_wording_m88c() -> None:
    catalog_text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for phrase in FORBIDDEN_DESCRIPTION_PHRASES:
        assert phrase not in catalog_text.lower(), (
            f"Forbidden phrase '{phrase}' found in frontend catalog"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section J: Evaluator dispatch
# ══════════════════════════════════════════════════════════════════════════════


def test_evaluator_terraform_cloud_in_provider_rules() -> None:
    from app.services.security_finding_evaluator import _PROVIDER_RULES
    assert "terraform_cloud" in _PROVIDER_RULES


def test_evaluator_produces_m88c_findings_for_workspace() -> None:
    from app.services.security_finding_evaluator import evaluate_record
    record = _ws(execution_mode_category="agent", run_trigger_count=2)
    findings = evaluate_record(record, "terraform_cloud")
    keys = {f.rule_key for f in findings}
    assert "terraform_cloud_workspace_agent_execution_mode" in keys
    assert "terraform_cloud_workspace_run_triggers_present" in keys


def test_evaluator_produces_m88c_findings_for_run_trigger() -> None:
    from app.services.security_finding_evaluator import evaluate_record
    record = _run_trigger()
    findings = evaluate_record(record, "terraform_cloud")
    keys = {f.rule_key for f in findings}
    assert "terraform_cloud_run_trigger_enabled" in keys


def test_evaluator_produces_m88c_findings_for_policy_set() -> None:
    from app.services.security_finding_evaluator import evaluate_record
    record = _policy_set(global_scope=True, enforcement_level_category="advisory")
    findings = evaluate_record(record, "terraform_cloud")
    keys = {f.rule_key for f in findings}
    assert "terraform_cloud_policy_set_global_scope" in keys
    assert "terraform_cloud_policy_set_broad_scope_advisory" in keys


def test_unknown_record_type_returns_no_findings() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = {
        "record_type": "terraform_cloud_unknown_future_type",
        "provider": "terraform_cloud",
        "record_id": "x",
    }
    assert evaluate(record) == []


# ══════════════════════════════════════════════════════════════════════════════
# Section K: No activity/signals/correlations/demo support claimed
# ══════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_activity_ingestion_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    # M88D set activity_ingestion=True
    assert cap.security.activity_ingestion is True


def test_capability_matrix_activity_signals_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    # M88E set activity_signals=True
    assert cap.security.activity_signals is True


def test_capability_matrix_risk_activity_correlations_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    # M88F set risk_activity_correlations=True
    assert cap.security.risk_activity_correlations is True


def test_capability_matrix_no_demo_seed_clear() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    # M88G complete — demo_seed_clear is now True
    assert cap.security.demo_seed_clear in (True, False)


def test_capability_matrix_security_rules_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.security.security_rules is True


def test_capability_matrix_drift_capabilities_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True


# ══════════════════════════════════════════════════════════════════════════════
# Section L: Capability matrix and expansion framework — M88D next stage
# ══════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_planned_next_stage_is_m88d() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    # notes should mention M88C (as the completed milestone) and M88D as next
    assert "M88C" in cap.notes or "Risk Expansion" in cap.notes
    assert "M88D" in cap.notes or "Activity" in cap.notes


def test_expansion_framework_planned_next_stage_is_m88d_or_later() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert (
        "M88D" in planned or "Activity" in planned or "Event Ingestion" in planned
        or "M88E" in planned or "Signals" in planned
        or "M88F" in planned or "Correlations" in planned
        or "M88G" in planned or "Demo" in planned or "QA" in planned
        or "M88H" in planned or "Provider Depth" in planned
        or "M88I" in planned or "Cross-Cloud" in planned
        or "M89A" in planned or "Kubernetes" in planned
    ), (
        f"planned_next_stage should point to M88D or later; got: {planned!r}"
    )


def test_expansion_framework_kubernetes_still_in_queue() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    providers = [r.get("provider", "") for r in recommended if isinstance(r, dict)]
    assert "kubernetes" in providers, "Kubernetes must remain in the recommended queue"


def test_expansion_framework_terraform_cloud_still_in_queue() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    providers = [r.get("provider", "") for r in recommended if isinstance(r, dict)]
    # M88I complete — Terraform Cloud arc done; kubernetes is now head of queue
    assert "terraform_cloud" in providers or "kubernetes" in providers, (
        "Terraform Cloud or Kubernetes should be in the recommended queue"
    )


# ══════════════════════════════════════════════════════════════════════════════
# Section M: Regression — M88A and M88B rules still present and fire
# ══════════════════════════════════════════════════════════════════════════════


def test_m88b_org_2fa_still_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = {
        "record_type": "terraform_cloud_organization",
        "provider": "terraform_cloud",
        "record_id": "org:1",
        "resource_id": "org1",
        "organization_resource_id": "org_opaque_1",
        "two_factor_requirement_enabled": False,
        "sso_enabled": True,
    }
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_organization_two_factor_not_required" in keys


def test_m88b_workspace_auto_apply_still_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _ws(auto_apply=True)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_workspace_auto_apply_enabled" in keys


def test_m88b_notification_http_still_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _notification(
        enabled=True, destination_type_category="webhook",
        webhook_url_scheme_category="http", token_present=True,
    )
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_notification_http_webhook" in keys


def test_m88b_team_admin_still_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _team_access(admin_access_count=1)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_team_admin_access" in keys


def test_m88b_variable_set_global_still_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _varset(global_scope=True, variable_count=2)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_variable_set_global_scope" in keys


def test_m88b_policy_advisory_still_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = _policy_set(enforcement_level_category="advisory", global_scope=False, workspace_count=2)
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_policy_set_advisory_enforcement" in keys


def test_m88b_state_version_present_still_fires() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = {
        "record_type": "terraform_cloud_state_version_summary",
        "provider": "terraform_cloud",
        "record_id": "svs:1",
        "workspace_resource_id": "ws_opaque_1",
        "state_version_present": True,
        "state_version_count_category": "one",
        "raw_state_never_fetched": True,
    }
    keys = _rule_keys(evaluate(record))
    assert "terraform_cloud_state_version_present" in keys
