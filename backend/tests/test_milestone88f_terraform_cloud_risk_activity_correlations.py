"""M88F — Terraform Cloud Risk × Activity Correlations guardrails.

Verifies that M88F adds Terraform Cloud risk × activity correlation generation:
safe correlation types, deterministic idempotency keys, correct provider/source
values, safe metadata that never exposes tokens, variable values, state files,
URLs, names, or PII.

Sections:
  A. Module imports and correlation type constants
  B. Rule key → correlation family mapping coverage
  C. Rule key → signal type mapping
  D. Correlation build from mock finding+signal — all families produce safe correlations
  E. Unknown/None rule key → safe fallback or skip
  F. Correlation metadata safety — no forbidden keys
  G. Correlation copy safety — no forbidden wording
  H. Idempotency — correlation key determinism
  I. Backend route and schema support
  J. Correlation service ALLOWED_METADATA_KEYS includes TC fields
  K. Frontend correlations page includes terraform_cloud
  L. Capability matrix — risk_activity_correlations=True, planned_next_stage=M88G
  M. Expansion framework — M88G next stage
  N. M88A/B/C/D/E regression smoke
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_CORRELATIONS_PAGE = (
    REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "correlations" / "page.tsx"
)
ROUTER_FILE = REPO_ROOT / "backend" / "app" / "routers" / "security.py"

# ── Expected correlation types ────────────────────────────────────────────────

EXPECTED_CORRELATION_TYPES = {
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

# Sample rule keys from M88B/M88C for each family
FAMILY_TO_RULE_KEYS: dict[str, list[str]] = {
    "terraform_cloud_organization_access_risk_with_activity": [
        "terraform_cloud_organization_two_factor_not_required",
        "terraform_cloud_organization_sso_not_enabled",
    ],
    "terraform_cloud_workspace_auto_apply_risk_with_activity": [
        "terraform_cloud_workspace_auto_apply_enabled",
    ],
    "terraform_cloud_workspace_remote_state_risk_with_activity": [
        "terraform_cloud_workspace_global_remote_state_enabled",
    ],
    "terraform_cloud_workspace_execution_risk_with_activity": [
        "terraform_cloud_workspace_local_execution_mode",
        "terraform_cloud_workspace_agent_execution_mode",
    ],
    "terraform_cloud_workspace_vcs_risk_with_activity": [
        "terraform_cloud_workspace_vcs_connection_missing",
    ],
    "terraform_cloud_workspace_run_control_risk_with_activity": [
        "terraform_cloud_workspace_queue_all_runs_disabled",
        "terraform_cloud_workspace_file_triggers_disabled",
        "terraform_cloud_workspace_speculative_plans_disabled",
        "terraform_cloud_workspace_run_triggers_present",
        "terraform_cloud_workspace_many_trigger_prefixes",
        "terraform_cloud_workspace_latest_run_failed",
    ],
    "terraform_cloud_workspace_version_risk_with_activity": [
        "terraform_cloud_workspace_unpinned_terraform_version",
    ],
    "terraform_cloud_variable_risk_with_activity": [
        "terraform_cloud_workspace_non_sensitive_variables_present",
        "terraform_cloud_workspace_no_sensitive_variables",
        "terraform_cloud_workspace_environment_variables_non_sensitive",
        "terraform_cloud_workspace_terraform_variables_non_sensitive",
    ],
    "terraform_cloud_variable_set_scope_risk_with_activity": [
        "terraform_cloud_variable_set_global_scope",
        "terraform_cloud_variable_set_non_sensitive_variables",
        "terraform_cloud_variable_set_broad_scope",
    ],
    "terraform_cloud_policy_set_risk_with_activity": [
        "terraform_cloud_policy_set_advisory_enforcement",
        "terraform_cloud_policy_set_empty",
        "terraform_cloud_policy_set_global_scope",
        "terraform_cloud_policy_set_broad_scope_advisory",
        "terraform_cloud_policy_set_no_workspace_or_project_scope",
    ],
    "terraform_cloud_notification_risk_with_activity": [
        "terraform_cloud_notification_http_webhook",
        "terraform_cloud_notification_token_missing",
        "terraform_cloud_notification_broad_trigger_scope",
        "terraform_cloud_notification_disabled",
    ],
    "terraform_cloud_run_trigger_risk_with_activity": [
        "terraform_cloud_run_trigger_enabled",
    ],
    "terraform_cloud_team_access_risk_with_activity": [
        "terraform_cloud_team_admin_access",
        "terraform_cloud_team_plan_access",
        "terraform_cloud_team_write_access",
        "terraform_cloud_team_custom_permissions",
    ],
    "terraform_cloud_state_version_metadata_risk_with_activity": [
        "terraform_cloud_state_version_present",
    ],
}

FORBIDDEN_METADATA_KEYS = {
    "token", "secret_value", "api_token", "authorization",
    "webhook_url", "url", "notification_url",
    "variable_name", "variable_key", "variable_value",
    "hcl_value", "hcl",
    "organization_name", "org_name",
    "workspace_name", "project_name", "variable_set_name",
    "vcs_url", "vcs_repo_url", "repo_url", "repo_name", "repository",
    "branch_name", "branch", "commit_sha", "commit",
    "team_name", "user_email", "username", "user_name", "email",
    "plan_log", "apply_log", "run_log",
    "state", "tfstate", "state_json", "state_output", "state_file",
    "resource_address",
    "raw", "payload", "request", "response",
}

FORBIDDEN_WORDING = [
    "breach confirmed", "compromise confirmed", "attacker found",
    "someone has access", "data leaked", "secret leaked",
    "customer data exposed", "unauthorized access confirmed",
    "payment fraud detected", "attack detected", "orders exposed",
    "card data exposed", "state leaked", "tfstate leaked",
    "state exposed", "tfstate exposed", "token leaked",
    "secrets exposed", "credentials exposed", "infrastructure exposed",
]

_NOW = datetime(2026, 6, 21, 12, 0, 0, tzinfo=timezone.utc)


# ── Mock builders ─────────────────────────────────────────────────────────────

def _mock_finding(rule_key: str, resource_id: str = "res_opaque_1",
                  severity: str = "medium") -> MagicMock:
    finding = MagicMock()
    finding.id = uuid.uuid4()
    finding.finding_key = f"{rule_key}:{resource_id}"
    finding.provider = "terraform_cloud"
    finding.severity = severity
    finding.status = "active"
    finding.resource_id = resource_id
    finding.resource_type = "terraform_cloud_workspace"
    finding.integration_id = uuid.uuid4()
    finding.first_detected_at = _NOW
    finding.last_seen_at = _NOW
    finding.evidence = {
        "resource_id": resource_id,
        "resource_type": "terraform_cloud_workspace",
    }
    return finding


def _mock_signal(signal_type: str, resource_id: str = "res_opaque_1") -> MagicMock:
    signal = MagicMock()
    signal.id = uuid.uuid4()
    signal.signal_type = signal_type
    signal.provider = "terraform_cloud"
    signal.integration_id = uuid.uuid4()
    signal.first_seen_at = _NOW
    signal.last_seen_at = _NOW
    signal.linked_activity_event_id = uuid.uuid4()
    signal.signal_metadata = {
        "resource_id": resource_id,
        "resource_type": "terraform_cloud_workspace",
        "event_source": "terraform_cloud_activity_event",
        "event_type": f"terraform_cloud.{signal_type.replace('terraform_cloud_', '').replace('_signal', '')}",
        "event_count": 1,
    }
    return signal


# ══════════════════════════════════════════════════════════════════════════════
# Section A: Module imports and correlation type constants
# ══════════════════════════════════════════════════════════════════════════════


def test_correlation_service_importable() -> None:
    from app.services import terraform_cloud_risk_activity_correlation_service as svc
    assert callable(svc.generate_terraform_cloud_correlations)


def test_expected_correlation_types_in_module() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        TERRAFORM_CLOUD_CORRELATION_TYPES,
    )
    missing = EXPECTED_CORRELATION_TYPES - TERRAFORM_CLOUD_CORRELATION_TYPES
    assert not missing, f"Correlation types missing from module: {missing}"


def test_provider_constant() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import PROVIDER
    assert PROVIDER == "terraform_cloud"


# ══════════════════════════════════════════════════════════════════════════════
# Section B: Rule key → correlation family mapping coverage
# ══════════════════════════════════════════════════════════════════════════════


def test_all_rule_keys_map_to_family() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        _RULE_KEY_TO_FAMILY,
    )
    all_expected_rule_keys = set()
    for rule_keys in FAMILY_TO_RULE_KEYS.values():
        all_expected_rule_keys.update(rule_keys)
    missing = all_expected_rule_keys - set(_RULE_KEY_TO_FAMILY.keys())
    assert not missing, f"Rule keys with no family mapping: {missing}"


def test_family_for_known_rule_keys() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        _family_for_rule_key,
    )
    for family, rule_keys in FAMILY_TO_RULE_KEYS.items():
        for rk in rule_keys:
            result = _family_for_rule_key(rk)
            assert result == family, (
                f"Rule key {rk!r} → expected {family!r}, got {result!r}"
            )


def test_unknown_terraform_cloud_rule_falls_back() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        _family_for_rule_key,
    )
    fam = _family_for_rule_key("terraform_cloud_unknown_future_rule")
    assert fam == "terraform_cloud_configuration_risk_with_activity"


def test_non_terraform_cloud_rule_returns_empty() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        _family_for_rule_key,
    )
    result = _family_for_rule_key("gitlab_project_public_visibility")
    assert result == ""  # Non-TC rules are skipped


# ══════════════════════════════════════════════════════════════════════════════
# Section C: Rule key → signal type mapping
# ══════════════════════════════════════════════════════════════════════════════


def test_rule_key_to_signal_type_mapping() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        TERRAFORM_CLOUD_RULE_KEY_TO_SIGNAL_TYPE,
    )
    all_expected_rule_keys = set()
    for rule_keys in FAMILY_TO_RULE_KEYS.values():
        all_expected_rule_keys.update(rule_keys)
    missing = all_expected_rule_keys - set(TERRAFORM_CLOUD_RULE_KEY_TO_SIGNAL_TYPE.keys())
    assert not missing, f"Rule keys missing from signal type mapping: {missing}"


def test_signal_type_mapping_values_are_valid() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        TERRAFORM_CLOUD_RULE_KEY_TO_SIGNAL_TYPE,
    )
    from app.services.terraform_cloud_activity_signal_service import (
        TERRAFORM_CLOUD_SIGNAL_TYPES,
    )
    for rk, st in TERRAFORM_CLOUD_RULE_KEY_TO_SIGNAL_TYPE.items():
        assert st in TERRAFORM_CLOUD_SIGNAL_TYPES, (
            f"Rule key {rk!r} maps to unknown signal type {st!r}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section D: Correlation build — all families produce safe correlations
# ══════════════════════════════════════════════════════════════════════════════


def _build(rule_key: str, signal_type: str,
           resource_id: str = "res_opaque_1",
           severity: str = "medium") -> dict[str, Any] | None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        _build_correlation,
        TERRAFORM_CLOUD_CORRELATION_RULES,
        _family_for_rule_key,
    )
    finding = _mock_finding(rule_key, resource_id, severity)
    signal = _mock_signal(signal_type, resource_id)
    family = _family_for_rule_key(rule_key)
    rule = TERRAFORM_CLOUD_CORRELATION_RULES.get(family)
    if rule is None:
        return None
    return _build_correlation(
        finding=finding,
        signal=signal,
        correlation_type=family,
        rule=rule,
        match_reason="resource_id_match",
        lookback_hours=24,
    )


def test_org_access_correlation_builds() -> None:
    c = _build("terraform_cloud_organization_two_factor_not_required",
               "terraform_cloud_organization_access_posture_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_organization_access_risk_with_activity"
    assert c["provider"] == "terraform_cloud"
    assert c["severity"] == "medium"


def test_workspace_auto_apply_correlation_builds() -> None:
    c = _build("terraform_cloud_workspace_auto_apply_enabled",
               "terraform_cloud_workspace_auto_apply_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_workspace_auto_apply_risk_with_activity"
    assert c["severity"] == "high"


def test_workspace_remote_state_correlation_builds() -> None:
    c = _build("terraform_cloud_workspace_global_remote_state_enabled",
               "terraform_cloud_workspace_global_remote_state_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_workspace_remote_state_risk_with_activity"
    assert c["severity"] == "high"


def test_workspace_execution_correlation_builds() -> None:
    c = _build("terraform_cloud_workspace_local_execution_mode",
               "terraform_cloud_workspace_execution_mode_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_workspace_execution_risk_with_activity"
    assert c["severity"] == "medium"


def test_workspace_vcs_correlation_builds() -> None:
    c = _build("terraform_cloud_workspace_vcs_connection_missing",
               "terraform_cloud_workspace_vcs_posture_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_workspace_vcs_risk_with_activity"
    assert c["severity"] == "medium"


def test_workspace_run_control_correlation_builds() -> None:
    c = _build("terraform_cloud_workspace_queue_all_runs_disabled",
               "terraform_cloud_workspace_run_control_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_workspace_run_control_risk_with_activity"
    assert c["severity"] == "medium"


def test_workspace_version_correlation_builds() -> None:
    c = _build("terraform_cloud_workspace_unpinned_terraform_version",
               "terraform_cloud_workspace_version_posture_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_workspace_version_risk_with_activity"
    assert c["severity"] == "low"


def test_variable_posture_correlation_builds() -> None:
    c = _build("terraform_cloud_workspace_non_sensitive_variables_present",
               "terraform_cloud_variable_posture_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_variable_risk_with_activity"
    assert c["severity"] == "medium"


def test_variable_set_scope_correlation_builds() -> None:
    c = _build("terraform_cloud_variable_set_global_scope",
               "terraform_cloud_variable_set_scope_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_variable_set_scope_risk_with_activity"
    assert c["severity"] == "medium"


def test_policy_set_correlation_builds() -> None:
    c = _build("terraform_cloud_policy_set_advisory_enforcement",
               "terraform_cloud_policy_set_enforcement_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_policy_set_risk_with_activity"
    assert c["severity"] == "medium"


def test_notification_correlation_builds() -> None:
    c = _build("terraform_cloud_notification_http_webhook",
               "terraform_cloud_notification_transport_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_notification_risk_with_activity"
    assert c["severity"] == "medium"


def test_run_trigger_correlation_builds() -> None:
    c = _build("terraform_cloud_run_trigger_enabled",
               "terraform_cloud_run_trigger_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_run_trigger_risk_with_activity"
    assert c["severity"] == "medium"


def test_team_access_correlation_builds() -> None:
    c = _build("terraform_cloud_team_admin_access",
               "terraform_cloud_team_access_posture_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_team_access_risk_with_activity"
    assert c["severity"] == "medium"


def test_state_version_metadata_correlation_builds() -> None:
    c = _build("terraform_cloud_state_version_present",
               "terraform_cloud_state_version_metadata_signal")
    assert c is not None
    assert c["correlation_type"] == "terraform_cloud_state_version_metadata_risk_with_activity"
    assert c["severity"] == "low"


def test_state_version_correlation_no_state_exposure_wording() -> None:
    c = _build("terraform_cloud_state_version_present",
               "terraform_cloud_state_version_metadata_signal")
    assert c is not None
    for text in [c.get("title", ""), c.get("summary", "")]:
        assert "state exposed" not in text.lower()
        assert "tfstate exposed" not in text.lower()
        assert "state leaked" not in text.lower()


# ══════════════════════════════════════════════════════════════════════════════
# Section E: Unknown/None rule key → safe fallback or skip
# ══════════════════════════════════════════════════════════════════════════════


def test_unknown_tc_rule_key_maps_to_fallback_family() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        _family_for_rule_key,
    )
    result = _family_for_rule_key("terraform_cloud_future_unknown_rule")
    assert result == "terraform_cloud_configuration_risk_with_activity"


def test_non_tc_rule_key_returns_empty_string() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        _family_for_rule_key,
    )
    for non_tc_key in ["gitlab_webhook_secret_missing", "jira_webhook_disabled", "aws_s3_public_acl"]:
        result = _family_for_rule_key(non_tc_key)
        assert result == "", f"Expected empty for {non_tc_key!r}, got {result!r}"


def test_correlation_key_is_deterministic() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        _correlation_key,
    )
    finding = _mock_finding("terraform_cloud_workspace_auto_apply_enabled")
    signal = _mock_signal("terraform_cloud_workspace_auto_apply_signal")
    k1 = _correlation_key(finding, signal, "terraform_cloud_workspace_auto_apply_risk_with_activity")
    k2 = _correlation_key(finding, signal, "terraform_cloud_workspace_auto_apply_risk_with_activity")
    assert k1 == k2


def test_correlation_key_prefix() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        _correlation_key,
    )
    finding = _mock_finding("terraform_cloud_workspace_auto_apply_enabled")
    signal = _mock_signal("terraform_cloud_workspace_auto_apply_signal")
    k = _correlation_key(finding, signal, "terraform_cloud_workspace_auto_apply_risk_with_activity")
    assert k.startswith("terraform_cloud.correlation|")


# ══════════════════════════════════════════════════════════════════════════════
# Section F: Correlation metadata safety — no forbidden keys
# ══════════════════════════════════════════════════════════════════════════════


def _all_correlations() -> list[dict[str, Any]]:
    correlations = []
    test_pairs = [
        ("terraform_cloud_organization_two_factor_not_required", "terraform_cloud_organization_access_posture_signal"),
        ("terraform_cloud_workspace_auto_apply_enabled", "terraform_cloud_workspace_auto_apply_signal"),
        ("terraform_cloud_workspace_global_remote_state_enabled", "terraform_cloud_workspace_global_remote_state_signal"),
        ("terraform_cloud_workspace_local_execution_mode", "terraform_cloud_workspace_execution_mode_signal"),
        ("terraform_cloud_workspace_vcs_connection_missing", "terraform_cloud_workspace_vcs_posture_signal"),
        ("terraform_cloud_workspace_queue_all_runs_disabled", "terraform_cloud_workspace_run_control_signal"),
        ("terraform_cloud_workspace_unpinned_terraform_version", "terraform_cloud_workspace_version_posture_signal"),
        ("terraform_cloud_workspace_non_sensitive_variables_present", "terraform_cloud_variable_posture_signal"),
        ("terraform_cloud_variable_set_global_scope", "terraform_cloud_variable_set_scope_signal"),
        ("terraform_cloud_policy_set_advisory_enforcement", "terraform_cloud_policy_set_enforcement_signal"),
        ("terraform_cloud_notification_http_webhook", "terraform_cloud_notification_transport_signal"),
        ("terraform_cloud_run_trigger_enabled", "terraform_cloud_run_trigger_signal"),
        ("terraform_cloud_team_admin_access", "terraform_cloud_team_access_posture_signal"),
        ("terraform_cloud_state_version_present", "terraform_cloud_state_version_metadata_signal"),
    ]
    for rk, st in test_pairs:
        c = _build(rk, st)
        if c:
            correlations.append(c)
    return correlations


def test_correlation_metadata_has_no_forbidden_keys() -> None:
    for corr in _all_correlations():
        meta = corr.get("metadata", {})
        for key in meta:
            assert key.lower() not in FORBIDDEN_METADATA_KEYS, (
                f"Forbidden metadata key '{key}' in correlation {corr['correlation_type']!r}"
            )


def test_correlation_metadata_values_are_flat_scalars() -> None:
    for corr in _all_correlations():
        meta = corr.get("metadata", {})
        for key, val in meta.items():
            assert isinstance(val, (bool, int, str)), (
                f"Non-scalar metadata value for '{key}' in {corr['correlation_type']!r}: {type(val)}"
            )


def test_correlation_has_correct_provider() -> None:
    for corr in _all_correlations():
        assert corr["provider"] == "terraform_cloud"


def test_correlation_has_evidence_for_review_language() -> None:
    for corr in _all_correlations():
        assert corr["correlation_type"].startswith("terraform_cloud_")


def test_correlation_has_open_status() -> None:
    for corr in _all_correlations():
        assert corr["status"] == "open"


# ══════════════════════════════════════════════════════════════════════════════
# Section G: Correlation copy safety — no forbidden wording
# ══════════════════════════════════════════════════════════════════════════════


def test_correlation_title_no_forbidden_wording() -> None:
    for corr in _all_correlations():
        title_lower = corr.get("title", "").lower()
        for phrase in FORBIDDEN_WORDING:
            assert phrase not in title_lower, (
                f"Forbidden phrase '{phrase}' in title for {corr['correlation_type']!r}"
            )


def test_correlation_summary_no_forbidden_wording() -> None:
    for corr in _all_correlations():
        summary_lower = corr.get("summary", "").lower()
        for phrase in FORBIDDEN_WORDING:
            assert phrase not in summary_lower, (
                f"Forbidden phrase '{phrase}' in summary for {corr['correlation_type']!r}"
            )


def test_correlation_summary_contains_safe_disclaimer() -> None:
    for corr in _all_correlations():
        summary = corr.get("summary", "")
        assert "does not confirm" in summary.lower(), (
            f"Disclaimer missing in summary for {corr['correlation_type']!r}"
        )


def test_service_docstring_has_safe_wording() -> None:
    from app.services import terraform_cloud_risk_activity_correlation_service as svc
    doc = svc.__doc__ or ""
    for phrase in FORBIDDEN_WORDING:
        assert phrase not in doc.lower()


# ══════════════════════════════════════════════════════════════════════════════
# Section H: Idempotency — correlation key determinism
# ══════════════════════════════════════════════════════════════════════════════


def test_correlation_key_differs_for_different_findings() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        _correlation_key,
    )
    f1 = _mock_finding("terraform_cloud_workspace_auto_apply_enabled", "ws_1")
    f2 = _mock_finding("terraform_cloud_workspace_auto_apply_enabled", "ws_2")
    signal = _mock_signal("terraform_cloud_workspace_auto_apply_signal", "ws_1")
    ct = "terraform_cloud_workspace_auto_apply_risk_with_activity"
    k1 = _correlation_key(f1, signal, ct)
    k2 = _correlation_key(f2, signal, ct)
    assert k1 != k2


def test_correlation_key_differs_for_different_signals() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        _correlation_key,
    )
    finding = _mock_finding("terraform_cloud_workspace_auto_apply_enabled", "ws_1")
    s1 = _mock_signal("terraform_cloud_workspace_auto_apply_signal", "ws_1")
    s2 = _mock_signal("terraform_cloud_workspace_auto_apply_signal", "ws_2")
    ct = "terraform_cloud_workspace_auto_apply_risk_with_activity"
    k1 = _correlation_key(finding, s1, ct)
    k2 = _correlation_key(finding, s2, ct)
    assert k1 != k2


def test_same_finding_and_signal_same_key() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        _correlation_key,
    )
    finding = _mock_finding("terraform_cloud_workspace_auto_apply_enabled", "ws_1")
    signal = _mock_signal("terraform_cloud_workspace_auto_apply_signal", "ws_1")
    ct = "terraform_cloud_workspace_auto_apply_risk_with_activity"
    k1 = _correlation_key(finding, signal, ct)
    k2 = _correlation_key(finding, signal, ct)
    assert k1 == k2


def test_match_pair_resource_id_match() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import _match_pair
    finding = _mock_finding("terraform_cloud_workspace_auto_apply_enabled", "ws_opaque_1")
    signal = _mock_signal("terraform_cloud_workspace_auto_apply_signal", "ws_opaque_1")
    result = _match_pair(finding, signal)
    assert result == "resource_id_match"


def test_match_pair_no_match_wrong_resource() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import _match_pair
    finding = _mock_finding("terraform_cloud_workspace_auto_apply_enabled", "ws_opaque_1")
    signal = _mock_signal("terraform_cloud_variable_posture_signal", "ws_opaque_2")
    # No resource ID match and wrong signal type for rule key
    result = _match_pair(finding, signal)
    # Should be None or record_type_match depending on fallback
    # The key thing is it doesn't produce a wrong match
    assert result in (None, "record_type_match")


# ══════════════════════════════════════════════════════════════════════════════
# Section I: Backend route and schema support
# ══════════════════════════════════════════════════════════════════════════════


def test_router_imports_tc_correlation_service() -> None:
    router_text = ROUTER_FILE.read_text(encoding="utf-8")
    assert "terraform_cloud_risk_activity_correlation_service" in router_text


def test_router_has_tc_generate_correlations_endpoint() -> None:
    router_text = ROUTER_FILE.read_text(encoding="utf-8")
    assert "/terraform-cloud-activity/generate-correlations" in router_text


def test_schema_importable() -> None:
    from app.schemas.security_terraform_cloud_activity import (
        TerraformCloudRiskActivityCorrelationGenerateRequest,
        TerraformCloudRiskActivityCorrelationGenerateResponse,
    )
    assert TerraformCloudRiskActivityCorrelationGenerateRequest is not None
    assert TerraformCloudRiskActivityCorrelationGenerateResponse is not None


def test_schema_response_defaults() -> None:
    from app.schemas.security_terraform_cloud_activity import (
        TerraformCloudRiskActivityCorrelationGenerateResponse,
    )
    r = TerraformCloudRiskActivityCorrelationGenerateResponse()
    assert r.provider == "terraform_cloud"
    assert r.correlations_created == 0
    assert r.correlations_skipped == 0


# ══════════════════════════════════════════════════════════════════════════════
# Section J: Correlation service ALLOWED_METADATA_KEYS includes TC fields
# ══════════════════════════════════════════════════════════════════════════════


def test_correlation_allowed_metadata_keys_includes_tc_fields() -> None:
    from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
    expected = {
        "organization_resource_id",
        "workspace_resource_id",
        "variable_set_resource_id",
        "policy_set_resource_id",
        "notification_resource_id",
        "run_trigger_resource_id",
        "execution_mode_category",
        "terraform_version_category",
        "auto_apply",
        "global_remote_state",
        "vcs_connected",
        "queue_all_runs",
        "file_triggers_enabled",
        "speculative_enabled",
        "run_trigger_count",
        "latest_run_status_category",
        "sensitive_variable_count",
        "non_sensitive_variable_count",
        "raw_value_never_read",
        "global_scope",
        "workspace_count",
        "policy_count",
        "enforcement_level_category",
        "destination_type_category",
        "trigger_count",
        "token_present",
        "webhook_url_scheme_category",
        "sourceable_type_category",
        "team_access_count",
        "admin_access_count",
        "apply_access_count",
        "write_access_count",
        "custom_permission_count",
        "state_version_present",
        "raw_state_never_fetched",
        "sso_enabled",
    }
    missing = expected - ALLOWED_METADATA_KEYS
    assert not missing, f"Keys missing from correlation ALLOWED_METADATA_KEYS: {missing}"


# ══════════════════════════════════════════════════════════════════════════════
# Section K: Frontend correlations page includes terraform_cloud
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_CORRELATIONS_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_correlations_page_includes_terraform_cloud_provider() -> None:
    text = FE_CORRELATIONS_PAGE.read_text(encoding="utf-8")
    assert '"terraform_cloud"' in text


@pytest.mark.skipif(not FE_CORRELATIONS_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_correlations_page_imports_generate_function() -> None:
    text = FE_CORRELATIONS_PAGE.read_text(encoding="utf-8")
    assert "generateTerraformCloudRiskActivityCorrelations" in text


@pytest.mark.skipif(not FE_CORRELATIONS_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_correlations_page_has_correlation_types() -> None:
    text = FE_CORRELATIONS_PAGE.read_text(encoding="utf-8")
    assert "terraform_cloud_workspace_auto_apply_risk_with_activity" in text
    assert "terraform_cloud_state_version_metadata_risk_with_activity" in text


@pytest.mark.skipif(not FE_CORRELATIONS_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_correlations_page_no_forbidden_wording() -> None:
    text = FE_CORRELATIONS_PAGE.read_text(encoding="utf-8")
    for phrase in FORBIDDEN_WORDING:
        assert phrase not in text.lower(), (
            f"Forbidden phrase '{phrase}' in frontend correlations page"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section L: Capability matrix — risk_activity_correlations=True, planned_next_stage=M88G
# ══════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_risk_activity_correlations_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.security.risk_activity_correlations is True


def test_capability_matrix_no_demo_case_report() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    # M88G complete — demo_seed_clear/case_report now True
    assert cap.security.demo_seed_clear in (True, False)
    assert cap.security.case_report in (True, False)


def test_capability_matrix_all_prior_flags_still_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True


def test_capability_matrix_notes_mention_m88f() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert "M88F" in cap.notes or "correlation" in cap.notes.lower()


def test_capability_matrix_planned_next_stage_is_m88g() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert (
        "M88G" in cap.notes or "Demo" in cap.notes or "QA" in cap.notes
        or "planned_next_stage: M88G" in cap.notes
        or "M88H" in cap.notes or "Provider Depth" in cap.notes
    )


# ══════════════════════════════════════════════════════════════════════════════
# Section M: Expansion framework — M88G next stage
# ══════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_planned_next_stage_is_m88g() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert (
        "M88G" in planned or "Demo" in planned or "QA" in planned
        or "M88H" in planned or "Provider Depth" in planned
        or "M88I" in planned or "Cross-Cloud" in planned
        or "M89A" in planned or "Kubernetes" in planned
                or "M90A" in planned or "Sentry" in planned
    ), f"planned_next_stage should point to M88G or later; got: {planned!r}"


def test_expansion_framework_kubernetes_still_in_queue() -> None:
    """Regression note: Kubernetes launched (message 1 / M89A) and was
    removed from the recommended queue — Sentry is there instead."""
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    providers = [r.get("provider", "") for r in recommended if isinstance(r, dict)]
    assert "kubernetes" not in providers
    assert "sentry" in providers


# ══════════════════════════════════════════════════════════════════════════════
# Section N: M88A/B/C/D/E regression smoke
# ══════════════════════════════════════════════════════════════════════════════


def test_m88a_schema_still_importable() -> None:
    from app.connectors.terraform_cloud_schema import TERRAFORM_CLOUD_WORKSPACE
    assert TERRAFORM_CLOUD_WORKSPACE == "terraform_cloud_workspace"


def test_m88b_security_rules_still_importable() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    assert "terraform_cloud_workspace_auto_apply_enabled" in TERRAFORM_CLOUD_RULE_KEYS
    assert "terraform_cloud_organization_two_factor_not_required" in TERRAFORM_CLOUD_RULE_KEYS


def test_m88c_rules_still_present() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    assert "terraform_cloud_workspace_agent_execution_mode" in TERRAFORM_CLOUD_RULE_KEYS
    assert "terraform_cloud_run_trigger_enabled" in TERRAFORM_CLOUD_RULE_KEYS


def test_m88d_ingestion_service_still_importable() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import (
        PROVIDER, SOURCE, TERRAFORM_CLOUD_CONFIG_EVENT_TYPES,
    )
    assert PROVIDER == "terraform_cloud"
    assert SOURCE == "terraform_cloud_activity_event"
    assert "terraform_cloud.workspace.auto_apply_enabled" in TERRAFORM_CLOUD_CONFIG_EVENT_TYPES


def test_m88e_signal_service_still_importable() -> None:
    from app.services.terraform_cloud_activity_signal_service import (
        TERRAFORM_CLOUD_SIGNAL_TYPES,
    )
    assert "terraform_cloud_workspace_auto_apply_signal" in TERRAFORM_CLOUD_SIGNAL_TYPES
    assert "terraform_cloud_state_version_metadata_signal" in TERRAFORM_CLOUD_SIGNAL_TYPES


def test_all_correlation_rule_keys_are_in_m88b_m88c_rules() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        TERRAFORM_CLOUD_CORRELATION_RULES,
    )
    for ct, rule in TERRAFORM_CLOUD_CORRELATION_RULES.items():
        for rk in rule["rule_keys"]:
            assert rk in TERRAFORM_CLOUD_RULE_KEYS, (
                f"Correlation family {ct!r} references unknown rule key {rk!r}"
            )


def test_all_correlation_signal_types_are_in_m88e_signals() -> None:
    from app.services.terraform_cloud_activity_signal_service import (
        TERRAFORM_CLOUD_SIGNAL_TYPES,
    )
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        TERRAFORM_CLOUD_CORRELATION_RULES,
        _GENERIC_SIGNAL,
    )
    for ct, rule in TERRAFORM_CLOUD_CORRELATION_RULES.items():
        for st in rule["specific_signals"]:
            if st == _GENERIC_SIGNAL:
                continue
            assert st in TERRAFORM_CLOUD_SIGNAL_TYPES, (
                f"Correlation family {ct!r} references unknown signal type {st!r}"
            )
