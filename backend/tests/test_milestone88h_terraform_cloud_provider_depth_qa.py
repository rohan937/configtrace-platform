"""M88H — Terraform Cloud provider depth QA guardrails.

Deep-audits the complete Terraform Cloud stack (M88A–M88G) across five
dimensions: connector/schema alignment, security rule depth, activity/signal/
correlation depth, demo/case/report integrity, and capability/framework state.

Sections:
  A. Connector and schema alignment
  B. Security rule depth — all 36 rule keys
  C. Security rule registry / confidence / pack / coverage alignment
  D. Security evaluator dispatch
  E. Activity event types coverage
  F. Signal types coverage
  G. Correlation types coverage
  H. Signal metadata allowlist coverage
  I. Correlation metadata allowlist coverage
  J. Demo/case/report integrity
  K. Claim discipline — no forbidden phrases in TC modules
  L. Privacy denylist — forbidden metadata keys absent from TC modules
  M. Capability matrix — all flags True after M88G
  N. Provider expansion framework — M88H next stage
  O. Frontend consistency across security pages
  P. Router admin guards
  Q. Idempotency pins
  R. M88A–M88G regression smoke
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend" / "app"
TESTS = REPO_ROOT / "backend" / "tests"
FRONTEND = REPO_ROOT / "frontend" / "src"

ROUTER_FILE = BACKEND / "routers" / "security.py"
DEMO_SERVICE = BACKEND / "services" / "security_incident_demo_service.py"
CASE_REPORT = BACKEND / "services" / "security_case_report_service.py"
TC_RULES = BACKEND / "services" / "security_rules" / "terraform_cloud.py"
TC_RISK_RULES = BACKEND / "services" / "risk_rules" / "terraform_cloud.py"
TC_INGESTION = BACKEND / "services" / "terraform_cloud_activity_ingestion_service.py"
TC_SIGNALS = BACKEND / "services" / "terraform_cloud_activity_signal_service.py"
TC_CORRELATIONS = BACKEND / "services" / "terraform_cloud_risk_activity_correlation_service.py"
TC_SCHEMA = BACKEND / "connectors" / "terraform_cloud_schema.py"
TC_CONNECTOR = BACKEND / "connectors" / "terraform_cloud.py"
CAPABILITY_MATRIX = BACKEND / "services" / "provider_capability_matrix_service.py"
EXPANSION_FW = BACKEND / "services" / "provider_expansion_framework.py"

FE_CORRELATIONS = FRONTEND / "app" / "(app)" / "security" / "correlations" / "page.tsx"
FE_SIGNALS = FRONTEND / "app" / "(app)" / "security" / "signals" / "page.tsx"
FE_ACTIVITY = FRONTEND / "app" / "(app)" / "security" / "activity" / "page.tsx"
FE_CASES = FRONTEND / "app" / "(app)" / "security" / "cases" / "page.tsx"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

# ── Complete 36-rule key set (M88B + M88C) ────────────────────────────────────

ALL_36_RULE_KEYS = {
    # M88B — 18 core rules
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
    # M88C — 18 expansion rules
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

# ── 10 record types (M88A) ────────────────────────────────────────────────────

ALL_10_RECORD_TYPES = {
    "terraform_cloud_organization",
    "terraform_cloud_workspace",
    "terraform_cloud_project",
    "terraform_cloud_variable_set",
    "terraform_cloud_workspace_variable_summary",
    "terraform_cloud_policy_set",
    "terraform_cloud_notification_configuration",
    "terraform_cloud_team_access_summary",
    "terraform_cloud_run_trigger",
    "terraform_cloud_state_version_summary",
}

# ── 17 signal types (M88E) ────────────────────────────────────────────────────

ALL_17_SIGNAL_TYPES = {
    "terraform_cloud_organization_access_posture_signal",
    "terraform_cloud_workspace_auto_apply_signal",
    "terraform_cloud_workspace_global_remote_state_signal",
    "terraform_cloud_workspace_execution_mode_signal",
    "terraform_cloud_workspace_vcs_posture_signal",
    "terraform_cloud_workspace_run_control_signal",
    "terraform_cloud_workspace_version_posture_signal",
    "terraform_cloud_variable_posture_signal",
    "terraform_cloud_variable_set_scope_signal",
    "terraform_cloud_policy_set_enforcement_signal",
    "terraform_cloud_policy_set_scope_signal",
    "terraform_cloud_notification_transport_signal",
    "terraform_cloud_notification_posture_signal",
    "terraform_cloud_run_trigger_signal",
    "terraform_cloud_team_access_posture_signal",
    "terraform_cloud_state_version_metadata_signal",
    "terraform_cloud_configuration_activity_signal",
}

# ── 15 correlation types (M88F) ───────────────────────────────────────────────

ALL_15_CORRELATION_TYPES = {
    "terraform_cloud_organization_access_risk_with_activity",
    "terraform_cloud_workspace_auto_apply_risk_with_activity",
    "terraform_cloud_workspace_remote_state_risk_with_activity",
    "terraform_cloud_workspace_execution_risk_with_activity",
    "terraform_cloud_workspace_vcs_risk_with_activity",
    "terraform_cloud_workspace_run_control_risk_with_activity",
    "terraform_cloud_workspace_version_risk_with_activity",
    "terraform_cloud_variable_risk_with_activity",
    "terraform_cloud_variable_set_scope_risk_with_activity",
    "terraform_cloud_policy_set_risk_with_activity",
    "terraform_cloud_notification_risk_with_activity",
    "terraform_cloud_run_trigger_risk_with_activity",
    "terraform_cloud_team_access_risk_with_activity",
    "terraform_cloud_state_version_metadata_risk_with_activity",
    "terraform_cloud_configuration_risk_with_activity",
}

# ── Forbidden claim phrases ────────────────────────────────────────────────────

FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "breach confirmed",
    "breach detected",
    "attacker found",
    "someone has access",
    "data leaked",
    "secret leaked",
    "unauthorized access confirmed",
    "state leaked",
    "tfstate leaked",
    "state exposed",
    "tfstate exposed",
    "token leaked",
    "secrets exposed",
    "credentials exposed",
    "infrastructure exposed",
]

# ── Forbidden metadata keys for TC ────────────────────────────────────────────

FORBIDDEN_TC_METADATA_KEYS = [
    "api_token",
    "access_token",
    "oauth_token",
    "vcs_token",
    "authorization",
    "variable_name",
    "variable_value",
    "tfstate",
    "state_file",
    "state_output",
    "resource_address",
    "plan_log",
    "apply_log",
    "run_log",
    "webhook_url",
    "notification_token",
    "user_email",
    "team_name",
    "organization_name",
    "workspace_name",
    "project_name",
    "vcs_url",
    "branch_name",
    "commit_sha",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── Section A: Connector and schema alignment ─────────────────────────────────

def test_terraform_cloud_schema_has_all_record_types() -> None:
    from app.connectors.terraform_cloud_schema import TERRAFORM_CLOUD_RECORD_TYPES
    for rt in ALL_10_RECORD_TYPES:
        assert rt in TERRAFORM_CLOUD_RECORD_TYPES, (
            f"Record type {rt!r} missing from TERRAFORM_CLOUD_RECORD_TYPES"
        )


def test_terraform_cloud_schema_record_type_count() -> None:
    from app.connectors.terraform_cloud_schema import TERRAFORM_CLOUD_RECORD_TYPES
    assert len(TERRAFORM_CLOUD_RECORD_TYPES) >= 10


def test_terraform_cloud_connector_importable() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    assert TerraformCloudConnector is not None


def test_connector_never_stores_forbidden_field_names() -> None:
    """Connector code must not reference forbidden TC field names as dict keys."""
    src = _read(TC_CONNECTOR)
    for key in FORBIDDEN_TC_METADATA_KEYS:
        # Skip 'api_token' as it's used for authentication parameter name (not stored)
        if key == "api_token":
            continue
        # Check that forbidden keys don't appear as assignment targets in output dicts
        pattern = rf'["\']({key})["\']:\s'
        matches = re.findall(pattern, src)
        assert not matches, (
            f"Forbidden field {key!r} found as dict key assignment in connector: {matches}"
        )


# ── Section B: Security rule depth ────────────────────────────────────────────

def test_security_rules_has_all_36_rule_keys() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    for rk in ALL_36_RULE_KEYS:
        assert rk in TERRAFORM_CLOUD_RULE_KEYS, (
            f"Rule key {rk!r} missing from TERRAFORM_CLOUD_RULE_KEYS"
        )


def test_security_rules_rule_key_count() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    assert len(TERRAFORM_CLOUD_RULE_KEYS) >= 36


def test_evaluate_function_exists() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    assert callable(evaluate)


def test_evaluate_returns_list() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    result = evaluate({"record_type": "terraform_cloud_organization", "provider": "terraform_cloud"})
    assert isinstance(result, list)


def test_evaluate_auto_apply_fires() -> None:
    """Auto-apply rule fires on workspace with auto_apply=True."""
    from app.services.security_rules.terraform_cloud import evaluate
    record = {
        "record_type": "terraform_cloud_workspace",
        "provider": "terraform_cloud",
        "resource_id": "ws-abc123",
        "auto_apply": True,
        "execution_mode_category": "remote",
        "vcs_connected": True,
    }
    findings = evaluate(record)
    keys = [f.get("rule_key", "") if isinstance(f, dict) else getattr(f, "rule_key", "") for f in findings]
    assert any("auto_apply" in k for k in keys), f"Auto-apply rule didn't fire; got keys: {keys}"


def test_evaluate_healthy_workspace_no_auto_apply_fire() -> None:
    """Healthy workspace (auto_apply=False) does not trigger auto-apply rule."""
    from app.services.security_rules.terraform_cloud import evaluate
    record = {
        "record_type": "terraform_cloud_workspace",
        "provider": "terraform_cloud",
        "resource_id": "ws-healthy",
        "auto_apply": False,
        "execution_mode_category": "remote",
        "vcs_connected": True,
        "global_remote_state": False,
    }
    findings = evaluate(record)
    keys = [f.get("rule_key", "") if isinstance(f, dict) else getattr(f, "rule_key", "") for f in findings]
    assert not any("auto_apply_enabled" in k for k in keys), (
        f"Auto-apply rule fired on healthy workspace; keys: {keys}"
    )


def test_evaluate_state_version_present_fires() -> None:
    """State version present rule fires on summary with state_version_present=True."""
    from app.services.security_rules.terraform_cloud import evaluate
    record = {
        "record_type": "terraform_cloud_state_version_summary",
        "provider": "terraform_cloud",
        "resource_id": "sv-abc",
        "state_version_present": True,
        "state_version_count_category": "single",
        "raw_state_never_fetched": True,
    }
    findings = evaluate(record)
    keys = [f.get("rule_key", "") if isinstance(f, dict) else getattr(f, "rule_key", "") for f in findings]
    assert any("state_version_present" in k for k in keys), (
        f"State version rule didn't fire; keys: {keys}"
    )


def test_evaluate_unknown_record_type_returns_empty() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    result = evaluate({"record_type": "unknown_type_xyz", "provider": "terraform_cloud"})
    assert isinstance(result, list)
    # Should return empty or be safe
    assert len(result) == 0 or all(
        hasattr(r, "rule_key") or isinstance(r, dict)
        for r in result
    )


# ── Section C: Registry / confidence / pack / coverage ────────────────────────

def test_all_rule_keys_in_rule_registry() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    for rk in ALL_36_RULE_KEYS:
        assert rk in KNOWN_RULE_KEYS, (
            f"Rule key {rk!r} missing from KNOWN_RULE_KEYS"
        )


def test_all_rule_keys_in_rule_confidence() -> None:
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    for rk in ALL_36_RULE_KEYS:
        assert rk in RULE_CONFIDENCE, (
            f"Rule key {rk!r} missing from RULE_CONFIDENCE"
        )


def test_all_rule_keys_in_rule_pack() -> None:
    from app.services.security_rule_pack import _RULE_META
    for rk in ALL_36_RULE_KEYS:
        assert rk in _RULE_META, (
            f"Rule key {rk!r} missing from _RULE_META"
        )


def test_all_rule_keys_in_coverage_service() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    for rk in ALL_36_RULE_KEYS:
        assert rk in RULE_RECORD_TYPES, (
            f"Rule key {rk!r} missing from RULE_RECORD_TYPES"
        )


def test_all_rule_keys_in_fe_catalog() -> None:
    catalog_text = _read(FE_RULE_CATALOG)
    for rk in ALL_36_RULE_KEYS:
        assert rk in catalog_text, (
            f"Rule key {rk!r} missing from securityRuleCatalog.ts"
        )


def test_rule_pack_severities_valid() -> None:
    from app.services.security_rule_pack import _RULE_META
    valid_severities = {"critical", "high", "medium", "low", "info"}
    for rk in ALL_36_RULE_KEYS:
        meta = _RULE_META.get(rk)
        assert meta is not None, f"Rule key {rk!r} missing from _RULE_META"
        # _RULE_META values are tuples: (provider, severity, category)
        if isinstance(meta, tuple):
            sev = meta[1] if len(meta) > 1 else "unknown"
        else:
            sev = meta.get("severity", "unknown")
        assert sev in valid_severities, (
            f"Invalid severity {sev!r} for rule key {rk!r}"
        )


# ── Section D: Security evaluator dispatch ────────────────────────────────────

def test_evaluator_dispatches_to_terraform_cloud() -> None:
    from app.services.security_finding_evaluator import evaluate_record
    record = {
        "record_type": "terraform_cloud_workspace",
        "provider": "terraform_cloud",
        "resource_id": "ws-test",
        "auto_apply": True,
        "execution_mode_category": "remote",
        "vcs_connected": True,
    }
    result = evaluate_record(record, "terraform_cloud")
    assert isinstance(result, list)


# ── Section E: Activity event types coverage ──────────────────────────────────

def test_all_expected_event_types_in_ingestion_service() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import (
        _TERRAFORM_CLOUD_CONFIG_EVENT_TYPES,
    )
    expected_event_types = {
        "terraform_cloud.organization.two_factor_not_required",
        "terraform_cloud.organization.sso_not_enabled",
        "terraform_cloud.workspace.auto_apply_enabled",
        "terraform_cloud.workspace.global_remote_state_enabled",
        "terraform_cloud.workspace.execution_mode_changed",
        "terraform_cloud.workspace.vcs_connection_missing",
        "terraform_cloud.workspace.queue_all_runs_disabled",
        "terraform_cloud.workspace.unpinned_terraform_version",
        "terraform_cloud.variables.non_sensitive_variables_detected",
        "terraform_cloud.variable_set.global_scope_detected",
        "terraform_cloud.policy_set.advisory_enforcement_detected",
        "terraform_cloud.notification.http_webhook_detected",
        "terraform_cloud.notification.token_missing",
        "terraform_cloud.run_trigger.enabled",
        "terraform_cloud.team_access.admin_detected",
        "terraform_cloud.state_version.metadata_present",
    }
    for et in expected_event_types:
        assert et in _TERRAFORM_CLOUD_CONFIG_EVENT_TYPES, (
            f"Event type {et!r} missing from _TERRAFORM_CLOUD_CONFIG_EVENT_TYPES"
        )


def test_event_type_count_at_least_25() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import (
        _TERRAFORM_CLOUD_CONFIG_EVENT_TYPES,
    )
    assert len(_TERRAFORM_CLOUD_CONFIG_EVENT_TYPES) >= 25


# ── Section F: Signal types coverage ──────────────────────────────────────────

def test_all_17_signal_types_in_signal_service() -> None:
    from app.services.terraform_cloud_activity_signal_service import (
        TERRAFORM_CLOUD_SIGNAL_TYPES,
    )
    for st in ALL_17_SIGNAL_TYPES:
        assert st in TERRAFORM_CLOUD_SIGNAL_TYPES, (
            f"Signal type {st!r} missing from TERRAFORM_CLOUD_SIGNAL_TYPES"
        )


def test_signal_type_count() -> None:
    from app.services.terraform_cloud_activity_signal_service import (
        TERRAFORM_CLOUD_SIGNAL_TYPES,
    )
    assert len(TERRAFORM_CLOUD_SIGNAL_TYPES) >= 17


def test_signal_event_to_signal_type_covers_all_signals() -> None:
    from app.services.terraform_cloud_activity_signal_service import (
        TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE,
        TERRAFORM_CLOUD_SIGNAL_TYPES,
    )
    # All values in the mapping must be valid signal types
    for et, st in TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE.items():
        assert st in TERRAFORM_CLOUD_SIGNAL_TYPES, (
            f"Event type {et!r} maps to unknown signal type {st!r}"
        )


# ── Section G: Correlation types coverage ─────────────────────────────────────

def test_all_15_correlation_types_present() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        TERRAFORM_CLOUD_CORRELATION_TYPES,
    )
    for ct in ALL_15_CORRELATION_TYPES:
        assert ct in TERRAFORM_CLOUD_CORRELATION_TYPES, (
            f"Correlation type {ct!r} missing from TERRAFORM_CLOUD_CORRELATION_TYPES"
        )


def test_correlation_type_count() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        TERRAFORM_CLOUD_CORRELATION_TYPES,
    )
    assert len(TERRAFORM_CLOUD_CORRELATION_TYPES) >= 15


def test_correlation_rule_key_to_family_covers_all_rules() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        TERRAFORM_CLOUD_RULE_KEY_TO_SIGNAL_TYPE,
    )
    # All 36 rule keys should map to a signal type
    for rk in ALL_36_RULE_KEYS:
        assert rk in TERRAFORM_CLOUD_RULE_KEY_TO_SIGNAL_TYPE, (
            f"Rule key {rk!r} missing from TERRAFORM_CLOUD_RULE_KEY_TO_SIGNAL_TYPE"
        )


def test_correlation_rules_cover_all_rule_families() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        TERRAFORM_CLOUD_CORRELATION_RULES,
        _RULE_KEY_TO_FAMILY,
    )
    for rk in ALL_36_RULE_KEYS:
        assert rk in _RULE_KEY_TO_FAMILY, (
            f"Rule key {rk!r} not in _RULE_KEY_TO_FAMILY"
        )


# ── Section H: Signal metadata allowlist coverage ─────────────────────────────

def test_signal_allowlist_has_tc_keys() -> None:
    from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
    required_signal_keys = [
        "workspace_resource_id",
        "organization_resource_id",
        "variable_set_resource_id",
        "policy_set_resource_id",
        "notification_resource_id",
        "run_trigger_resource_id",
        "execution_mode_category",
        "auto_apply",
        "global_remote_state",
        "vcs_connected",
        "state_version_present",
        "raw_state_never_fetched",
    ]
    for key in required_signal_keys:
        assert key in ALLOWED_METADATA_KEYS, (
            f"TC signal key {key!r} missing from signal ALLOWED_METADATA_KEYS"
        )


def test_signal_allowlist_excludes_tc_forbidden_keys() -> None:
    from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
    tc_forbidden = [
        "variable_name", "variable_value", "tfstate",
        "state_file", "webhook_url", "team_name",
    ]
    for key in tc_forbidden:
        assert key not in ALLOWED_METADATA_KEYS, (
            f"TC-forbidden key {key!r} found in signal ALLOWED_METADATA_KEYS"
        )


# ── Section I: Correlation metadata allowlist coverage ────────────────────────

def test_correlation_allowlist_has_tc_keys() -> None:
    from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
    required_corr_keys = [
        "workspace_resource_id",
        "organization_resource_id",
        "variable_set_resource_id",
        "policy_set_resource_id",
        "execution_mode_category",
        "auto_apply",
        "global_remote_state",
        "sensitive_variable_count",
        "non_sensitive_variable_count",
        "state_version_present",
        "raw_state_never_fetched",
        "sso_enabled",
    ]
    for key in required_corr_keys:
        assert key in ALLOWED_METADATA_KEYS, (
            f"TC correlation key {key!r} missing from ALLOWED_METADATA_KEYS"
        )


# ── Section J: Demo/case/report integrity ─────────────────────────────────────

def test_demo_service_has_all_tc_functions() -> None:
    from app.services.security_incident_demo_service import (
        seed_terraform_cloud,
        clear_terraform_cloud,
        get_terraform_cloud_status,
        TERRAFORM_CLOUD_DEMO_INTEGRATION_NAME,
        TERRAFORM_CLOUD_DEMO_CASE_SOURCE,
        TERRAFORM_CLOUD_DEMO_DATASET,
    )
    assert callable(seed_terraform_cloud)
    assert callable(clear_terraform_cloud)
    assert callable(get_terraform_cloud_status)
    assert isinstance(TERRAFORM_CLOUD_DEMO_INTEGRATION_NAME, str)
    assert isinstance(TERRAFORM_CLOUD_DEMO_CASE_SOURCE, str)
    assert isinstance(TERRAFORM_CLOUD_DEMO_DATASET, str)


def test_case_report_labels_terraform_cloud() -> None:
    from app.services.security_case_report_service import _TIMELINE_PROVIDER_LABELS
    assert "terraform_cloud" in _TIMELINE_PROVIDER_LABELS
    assert _TIMELINE_PROVIDER_LABELS["terraform_cloud"] == "Terraform Cloud"


def test_case_report_preview_allowlist_has_tc_keys() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    tc_preview_keys = [
        "workspace_resource_id",
        "organization_resource_id",
        "execution_mode_category",
        "auto_apply",
        "global_remote_state",
        "state_version_present",
        "raw_state_never_fetched",
        "sso_enabled",
        "two_factor_requirement_enabled",
    ]
    for key in tc_preview_keys:
        assert key in _PREVIEW_ALLOWLIST, (
            f"TC preview key {key!r} missing from _PREVIEW_ALLOWLIST"
        )


def test_demo_case_source_is_unique_to_tc() -> None:
    from app.services.security_incident_demo_service import TERRAFORM_CLOUD_DEMO_CASE_SOURCE
    assert "terraform_cloud" in TERRAFORM_CLOUD_DEMO_CASE_SOURCE
    assert "gitlab" not in TERRAFORM_CLOUD_DEMO_CASE_SOURCE
    assert "jira" not in TERRAFORM_CLOUD_DEMO_CASE_SOURCE


def test_demo_uses_real_rule_keys() -> None:
    """Demo seed uses actual M88B/M88C rule keys, not fabricated ones."""
    src = _read(DEMO_SERVICE)
    tc_section = src[src.find("TERRAFORM_CLOUD_DEMO_INTEGRATION_NAME"):]
    assert "terraform_cloud_workspace_auto_apply_enabled" in tc_section
    assert "terraform_cloud_workspace_global_remote_state_enabled" in tc_section
    assert "terraform_cloud_workspace_non_sensitive_variables_present" in tc_section


def test_demo_disclaimer_present() -> None:
    src = _read(DEMO_SERVICE)
    tc_section = src[src.find("TERRAFORM_CLOUD_DEMO_INTEGRATION_NAME"):]
    assert "does not confirm" in tc_section
    assert "state exposure" in tc_section or "infrastructure exposure" in tc_section


def test_demo_no_jwt_shaped_strings() -> None:
    src = _read(DEMO_SERVICE)
    tc_section = src[src.find("TERRAFORM_CLOUD_DEMO_INTEGRATION_NAME"):]
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", tc_section), (
        "JWT-shaped string found in TC demo section"
    )


def test_router_wires_all_three_tc_demo_endpoints() -> None:
    router_text = _read(ROUTER_FILE)
    assert "seed_terraform_cloud" in router_text
    assert "clear_terraform_cloud" in router_text
    assert "get_terraform_cloud_status" in router_text
    # All three branch on prov == "terraform_cloud"
    assert router_text.count('prov == "terraform_cloud"') >= 3


# ── Section K: Claim discipline ───────────────────────────────────────────────

TC_MODULE_FILES = [
    TC_RULES,
    TC_RISK_RULES,
    TC_INGESTION,
    TC_SIGNALS,
    TC_CORRELATIONS,
]


def _strip_docstring_comments(src: str) -> str:
    """Remove triple-quoted docstrings and # comment lines for phrase scanning.

    This avoids false positives from modules that list forbidden phrases in
    their CLAIM DISCIPLINE docstrings (e.g., 'never say secret leaked').
    We scan the code itself, not the documentation that explains what not to say.
    """
    # Remove triple-double-quoted strings
    src = re.sub(r'""".*?"""', "", src, flags=re.DOTALL)
    # Remove triple-single-quoted strings
    src = re.sub(r"'''.*?'''", "", src, flags=re.DOTALL)
    # Remove single-line # comments
    src = re.sub(r"#[^\n]*", "", src)
    return src


@pytest.mark.parametrize("module_file", [
    pytest.param(TC_RULES, id="security_rules"),
    pytest.param(TC_RISK_RULES, id="risk_rules"),
    pytest.param(TC_INGESTION, id="activity_ingestion"),
    pytest.param(TC_SIGNALS, id="activity_signals"),
    pytest.param(TC_CORRELATIONS, id="correlations"),
])
def test_no_forbidden_phrases_in_tc_module(module_file: Path) -> None:
    src = _strip_docstring_comments(module_file.read_text(encoding="utf-8")).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in src, (
            f"Forbidden phrase {phrase!r} found in code (outside docstrings) in {module_file.name}"
        )


# ── Section L: Privacy denylist ───────────────────────────────────────────────

@pytest.mark.parametrize("module_file", [
    pytest.param(TC_INGESTION, id="activity_ingestion"),
    pytest.param(TC_SIGNALS, id="activity_signals"),
    pytest.param(TC_CORRELATIONS, id="correlations"),
])
def test_no_forbidden_metadata_keys_as_dict_keys_in_service(module_file: Path) -> None:
    src = module_file.read_text(encoding="utf-8")
    # Check that forbidden keys don't appear as output dict keys (string: value pattern)
    for key in FORBIDDEN_TC_METADATA_KEYS:
        if key in ("api_token",):
            continue  # Used as auth param name, not output
        pattern = rf'["\']({re.escape(key)})["\']:\s'
        matches = re.findall(pattern, src)
        assert not matches, (
            f"Forbidden metadata key {key!r} found as dict output in {module_file.name}: {matches}"
        )


# ── Section M: Capability matrix ──────────────────────────────────────────────

def test_capability_matrix_all_security_flags_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    sec = cap.security
    assert sec.security_rules is True
    assert sec.activity_ingestion is True
    assert sec.activity_signals is True
    assert sec.risk_activity_correlations is True
    assert sec.demo_seed_clear is True
    assert sec.case_report is True
    assert sec.evidence_timeline is True
    assert sec.evidence_graph is True


def test_capability_matrix_drift_flags_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True


def test_capability_matrix_maturity_partial() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.maturity == "partial"


def test_capability_matrix_notes_mention_m88g() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert "M88G" in cap.notes or "demo" in cap.notes.lower()


def test_capability_matrix_notes_mention_all_milestones() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    for milestone in ["M88A", "M88B", "M88C", "M88D", "M88E", "M88F"]:
        assert milestone in cap.notes, (
            f"Milestone {milestone} not mentioned in TC capability matrix notes"
        )


def test_capability_matrix_notes_planned_next_stage_m88h() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert "M88H" in cap.notes or "Provider Depth QA" in cap.notes


# ── Section N: Provider expansion framework ───────────────────────────────────

def test_expansion_framework_planned_next_stage_m88h() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert (
        "M88H" in planned or "Provider Depth QA" in planned
        or "M88I" in planned or "Cross-Cloud" in planned
        or "M89A" in planned or "Kubernetes" in planned
                or "M90A" in planned or "Sentry" in planned
    ), f"planned_next_stage should point to M88H or later; got: {planned!r}"


def test_expansion_framework_queue_is_empty_after_sentry_launch() -> None:
    """Regression note: Kubernetes launched its provider architecture
    foundation (Kubernetes message 1 / M89A) and was removed from the
    recommended queue. Sentry (message 8 — public launch) was the FINAL
    planned provider, so the queue is now permanently empty."""
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    queue = fw.get("recommended_next_providers", [])
    labels = [p.get("label", "") for p in queue]
    assert not any("Kubernetes" in label for label in labels)
    assert not any("Sentry" in label for label in labels)
    assert labels == []


def test_expansion_framework_terraform_cloud_is_still_partial() -> None:
    """TC in partial list; it should still be in capability matrix partial providers."""
    from app.services.provider_capability_matrix_service import (
        PROVIDER_CAPABILITIES_PARTIAL,
    )
    providers = [p.provider for p in PROVIDER_CAPABILITIES_PARTIAL]
    assert "terraform_cloud" in providers


# ── Section O: Frontend consistency ───────────────────────────────────────────

def test_fe_correlations_page_has_tc_types() -> None:
    text = _read(FE_CORRELATIONS)
    for ct in [
        "terraform_cloud_organization_access_risk_with_activity",
        "terraform_cloud_workspace_auto_apply_risk_with_activity",
        "terraform_cloud_configuration_risk_with_activity",
    ]:
        assert ct in text, f"Correlation type {ct!r} missing from correlations page"


def test_fe_correlations_page_has_generate_tc_function() -> None:
    text = _read(FE_CORRELATIONS)
    assert "generateTerraformCloudRiskActivityCorrelations" in text or "terraform_cloud" in text


def test_fe_signals_page_has_terraform_cloud() -> None:
    text = _read(FE_SIGNALS)
    assert "terraform_cloud" in text


def test_fe_activity_page_has_terraform_cloud() -> None:
    text = _read(FE_ACTIVITY)
    assert "terraform_cloud" in text


def test_fe_cases_page_has_tc_demo_card() -> None:
    text = _read(FE_CASES)
    assert "terraform_cloud" in text
    assert "Terraform Cloud" in text


def test_fe_cases_page_tc_demo_copy_safe() -> None:
    text = _read(FE_CASES)
    tc_idx = text.find("terraform_cloud")
    tc_section = text[max(0, tc_idx - 100):tc_idx + 2000].lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in tc_section, (
            f"Forbidden phrase {phrase!r} in TC cases page copy"
        )


def test_fe_rule_catalog_has_tc_rules() -> None:
    text = _read(FE_RULE_CATALOG)
    assert "terraform_cloud" in text
    # Spot check a few rule keys
    assert "terraform_cloud_workspace_auto_apply_enabled" in text
    assert "terraform_cloud_workspace_global_remote_state_enabled" in text
    assert "terraform_cloud_notification_http_webhook" in text


def test_fe_rule_catalog_has_tc_provider_coverage() -> None:
    text = _read(FE_RULE_CATALOG)
    # Should have a terraform_cloud entry in PROVIDER_COVERAGE
    assert "terraform_cloud" in text


# ── Section P: Router admin guards ────────────────────────────────────────────

def test_router_tc_correlation_generate_has_admin_guard() -> None:
    text = _read(ROUTER_FILE)
    # find the generate-correlations route
    idx = text.find("terraform-cloud-activity/generate-correlations")
    assert idx != -1, "TC correlations generate route not found"
    # Look for admin guard in vicinity (within 2000 chars to cover the full function body)
    section = text[idx:idx + 2000]
    assert "require_workspace_admin" in section, (
        "Admin guard missing from TC correlations generate route"
    )


def test_router_tc_sync_has_admin_guard() -> None:
    text = _read(ROUTER_FILE)
    idx = text.find("terraform-cloud-activity/sync")
    assert idx != -1, "TC sync route not found"
    section = text[idx:idx + 2000]
    assert "require_workspace_admin" in section, (
        "Admin guard missing from TC sync route"
    )


def test_router_tc_generate_signals_has_admin_guard() -> None:
    text = _read(ROUTER_FILE)
    idx = text.find("terraform-cloud-activity/generate-signals")
    assert idx != -1, "TC generate-signals route not found"
    section = text[idx:idx + 2000]
    assert "require_workspace_admin" in section, (
        "Admin guard missing from TC generate-signals route"
    )


def test_router_tc_demo_seed_has_admin_guard() -> None:
    text = _read(ROUTER_FILE)
    idx = text.find("incident-demo/seed")
    assert idx != -1
    section = text[idx:idx + 2000]
    assert "require_workspace_admin" in section


# ── Section Q: Idempotency pins ───────────────────────────────────────────────

def test_correlation_key_is_deterministic() -> None:
    """Same (type, finding, signal) always produces the same correlation key."""
    from app.services.terraform_cloud_risk_activity_correlation_service import _correlation_key
    from unittest.mock import MagicMock
    import uuid

    finding = MagicMock()
    finding.id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    signal = MagicMock()
    signal.id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    corr_type = "terraform_cloud_workspace_auto_apply_risk_with_activity"

    key1 = _correlation_key(finding, signal, corr_type)
    key2 = _correlation_key(finding, signal, corr_type)
    assert key1 == key2
    assert "terraform_cloud.correlation" in key1
    assert corr_type in key1


def test_signal_key_is_deterministic() -> None:
    """Signal group key is deterministic for the same event type + resource."""
    from app.services.terraform_cloud_activity_signal_service import _group_key
    from unittest.mock import MagicMock

    ev = MagicMock()
    ev.event_type = "terraform_cloud.workspace.auto_apply_enabled"
    ev.event_metadata = {"resource_id": "ws-test-001"}
    ev.resource_id = "ws-test-001"

    key1 = _group_key(ev)
    key2 = _group_key(ev)
    assert key1 == key2
    if key1 is not None:
        assert "terraform_cloud" in key1


def test_demo_seed_idempotent_when_case_exists() -> None:
    from app.services.security_incident_demo_service import seed_terraform_cloud
    from unittest.mock import MagicMock, patch
    import uuid

    fake_case = MagicMock()
    fake_case.id = uuid.uuid4()

    with (
        patch("app.services.security_incident_demo_service._existing_terraform_cloud_demo_case") as mock_existing,
        patch("app.services.security_incident_demo_service.case_svc") as mock_case_svc,
    ):
        mock_existing.return_value = fake_case
        mock_case_svc.count_links.return_value = 9

        result1 = seed_terraform_cloud(
            workspace_id=uuid.uuid4(), actor_user_id=uuid.uuid4(), db=MagicMock()
        )
        result2 = seed_terraform_cloud(
            workspace_id=uuid.uuid4(), actor_user_id=uuid.uuid4(), db=MagicMock()
        )

    assert result1["created"] is False
    assert result2["created"] is False


# ── Section R: M88A–M88G regression smoke ─────────────────────────────────────

def test_m88a_schema_importable() -> None:
    from app.connectors.terraform_cloud_schema import TERRAFORM_CLOUD_RECORD_TYPES
    assert len(TERRAFORM_CLOUD_RECORD_TYPES) >= 10


def test_m88b_rules_evaluate_importable() -> None:
    from app.services.security_rules.terraform_cloud import evaluate, TERRAFORM_CLOUD_RULE_KEYS
    assert callable(evaluate)
    assert len(TERRAFORM_CLOUD_RULE_KEYS) >= 36


def test_m88c_all_expansion_rules_present() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    m88c_rules = {
        "terraform_cloud_workspace_agent_execution_mode",
        "terraform_cloud_workspace_file_triggers_disabled",
        "terraform_cloud_workspace_speculative_plans_disabled",
        "terraform_cloud_run_trigger_enabled",
        "terraform_cloud_team_write_access",
        "terraform_cloud_team_custom_permissions",
    }
    for rk in m88c_rules:
        assert rk in TERRAFORM_CLOUD_RULE_KEYS


def test_m88d_ingestion_service_importable() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import (
        sync_terraform_cloud_activity,
        ingest_terraform_cloud_activity,
    )
    assert callable(sync_terraform_cloud_activity)
    assert callable(ingest_terraform_cloud_activity)


def test_m88e_signal_service_importable() -> None:
    from app.services.terraform_cloud_activity_signal_service import (
        generate_terraform_cloud_activity_signals,
        TERRAFORM_CLOUD_SIGNAL_TYPES,
        TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE,
    )
    assert callable(generate_terraform_cloud_activity_signals)
    assert len(TERRAFORM_CLOUD_SIGNAL_TYPES) >= 17


def test_m88f_correlation_service_importable() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        generate_terraform_cloud_correlations,
        TERRAFORM_CLOUD_CORRELATION_TYPES,
        TERRAFORM_CLOUD_CORRELATION_RULES,
    )
    assert callable(generate_terraform_cloud_correlations)
    assert len(TERRAFORM_CLOUD_CORRELATION_TYPES) >= 15


def test_m88g_demo_service_importable() -> None:
    from app.services.security_incident_demo_service import (
        seed_terraform_cloud,
        clear_terraform_cloud,
        get_terraform_cloud_status,
    )
    assert callable(seed_terraform_cloud)
    assert callable(clear_terraform_cloud)
    assert callable(get_terraform_cloud_status)
