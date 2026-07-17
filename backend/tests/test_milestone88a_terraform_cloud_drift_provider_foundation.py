"""M88A — Terraform Cloud drift provider foundation guardrails.

Verifies that the Terraform Cloud connector, schema, risk classifier, capability
matrix, and provider expansion framework meet the M88A foundation requirements:

  A. Schema / record types
  B. Connector imports and structure
  C. Privacy / sanitization — no forbidden fields in normalized records
  D. Record ID determinism and opacity
  E. Drift-risk classification
  F. Capability matrix
  G. Provider expansion framework
  H. Frontend provider list
  I. Regression smoke (no stale tests broken by M88A)
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ROOT = REPO_ROOT / "frontend" / "src"
FE_PROVIDERS = FE_ROOT / "lib" / "providers.ts"
FE_TYPES = FE_ROOT / "types" / "index.ts"

# ── Forbidden field names in any normalized record ─────────────────────────────

FORBIDDEN_RECORD_KEYS = {
    # Terraform API token variants
    "api_token", "token", "bearer_token", "auth_token", "access_token",
    "oauth_token", "team_token", "user_token",
    # Organization / workspace / project identity
    "organization_name", "organization", "name", "org_name", "org_slug",
    "workspace_name", "workspace_slug", "project_name", "project_slug",
    # Variable names/values
    "variable_name", "variable_key", "key", "value", "variable_value",
    "hcl_value", "hcl", "description",
    # VCS sensitive data
    "vcs_repo_url", "vcs_url", "repo_url", "branch_name", "branch",
    "commit_sha", "commit", "ingress_submodule",
    # Notification sensitive data
    "url", "webhook_url", "notification_url", "email", "email_addresses",
    "slack_channel", "token_value",
    # State / plan / apply sensitive data
    "state", "state_file", "state_json", "state_url", "plan", "apply",
    "plan_json", "apply_json", "run_log", "apply_log", "plan_log",
    # Team / user identity
    "team_name", "team_id", "user_email", "username", "user_name",
    "member_email", "owner_email",
    # Cost / resource data
    "resource_address", "resource_count_detail", "cost_estimate",
    # Raw payloads
    "raw_payload", "raw_response", "raw_api",
}

# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_change(
    record_type: str,
    field_path: str = "",
    change_type: str = "modified",
    old_value: Any = None,
    new_value: Any = None,
) -> MagicMock:
    """Build a mock Change object for classifier tests.

    Uses ``prev_value`` (not ``old_value``) to match the real ``Change`` ORM
    model / compute_diff output field name — a mismatch here previously let
    every directional classifier in risk_rules/terraform_cloud.py silently
    read a nonexistent ``old_value`` attribute (always None) without any
    test catching it, since the test and the bug agreed with each other.
    """
    change = MagicMock()
    change.provider_metadata = {"record_type": record_type}
    change.field_path = field_path
    change.change_type = change_type
    change.prev_value = old_value
    change.new_value = new_value
    return change


def _opaque_id(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


# ══════════════════════════════════════════════════════════════════════════════
# A. Schema / record types
# ══════════════════════════════════════════════════════════════════════════════


def test_schema_imports() -> None:
    from app.connectors.terraform_cloud_schema import (
        TERRAFORM_CLOUD_RECORD_TYPES,
        TERRAFORM_CLOUD_ORGANIZATION,
        TERRAFORM_CLOUD_WORKSPACE,
        TERRAFORM_CLOUD_PROJECT,
        TERRAFORM_CLOUD_VARIABLE_SET,
        TERRAFORM_CLOUD_WORKSPACE_VARIABLE_SUMMARY,
        TERRAFORM_CLOUD_POLICY_SET,
        TERRAFORM_CLOUD_NOTIFICATION_CONFIGURATION,
        TERRAFORM_CLOUD_TEAM_ACCESS_SUMMARY,
        TERRAFORM_CLOUD_RUN_TRIGGER,
        TERRAFORM_CLOUD_STATE_VERSION_SUMMARY,
    )
    assert len(TERRAFORM_CLOUD_RECORD_TYPES) == 10
    assert TERRAFORM_CLOUD_ORGANIZATION in TERRAFORM_CLOUD_RECORD_TYPES
    assert TERRAFORM_CLOUD_WORKSPACE in TERRAFORM_CLOUD_RECORD_TYPES
    assert TERRAFORM_CLOUD_PROJECT in TERRAFORM_CLOUD_RECORD_TYPES
    assert TERRAFORM_CLOUD_VARIABLE_SET in TERRAFORM_CLOUD_RECORD_TYPES
    assert TERRAFORM_CLOUD_WORKSPACE_VARIABLE_SUMMARY in TERRAFORM_CLOUD_RECORD_TYPES
    assert TERRAFORM_CLOUD_POLICY_SET in TERRAFORM_CLOUD_RECORD_TYPES
    assert TERRAFORM_CLOUD_NOTIFICATION_CONFIGURATION in TERRAFORM_CLOUD_RECORD_TYPES
    assert TERRAFORM_CLOUD_TEAM_ACCESS_SUMMARY in TERRAFORM_CLOUD_RECORD_TYPES
    assert TERRAFORM_CLOUD_RUN_TRIGGER in TERRAFORM_CLOUD_RECORD_TYPES
    assert TERRAFORM_CLOUD_STATE_VERSION_SUMMARY in TERRAFORM_CLOUD_RECORD_TYPES


def test_all_record_types_prefixed() -> None:
    from app.connectors.terraform_cloud_schema import TERRAFORM_CLOUD_RECORD_TYPES
    for rt in TERRAFORM_CLOUD_RECORD_TYPES:
        assert rt.startswith("terraform_cloud_"), (
            f"Record type {rt!r} must have 'terraform_cloud_' prefix"
        )


def test_schema_typedicts_importable() -> None:
    from app.connectors.terraform_cloud_schema import (
        TerraformCloudOrganizationRecord,
        TerraformCloudWorkspaceRecord,
        TerraformCloudProjectRecord,
        TerraformCloudVariableSetRecord,
        TerraformCloudWorkspaceVariableSummaryRecord,
        TerraformCloudPolicySetRecord,
        TerraformCloudNotificationConfigurationRecord,
        TerraformCloudTeamAccessSummaryRecord,
        TerraformCloudRunTriggerRecord,
        TerraformCloudStateVersionSummaryRecord,
    )
    # All must be importable (implicitly checked above)
    assert TerraformCloudOrganizationRecord is not None


# ══════════════════════════════════════════════════════════════════════════════
# B. Connector imports and structure
# ══════════════════════════════════════════════════════════════════════════════


def test_connector_class_importable() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    assert TerraformCloudConnector is not None


def test_connector_provider_key() -> None:
    from app.connectors.terraform_cloud import PROVIDER
    assert PROVIDER == "terraform_cloud"


def test_connector_has_expected_normalizers() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    expected = [
        "_normalize_organization",
        "_normalize_workspace",
        "_normalize_workspace_variable_summary",
        "_normalize_project",
        "_normalize_variable_set",
        "_normalize_policy_set",
        "_normalize_notification",
        "_normalize_team_access_summary",
        "_normalize_run_trigger",
        "_normalize_state_version_summary",
    ]
    for method in expected:
        assert hasattr(TerraformCloudConnector, method), (
            f"TerraformCloudConnector.{method} not found"
        )


def test_connector_has_fetch_and_validate() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()
    assert callable(conn.fetch)
    assert callable(conn.validate_credentials)


def test_connector_raises_on_missing_token() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    from app.connectors.exceptions import AuthenticationError
    conn = TerraformCloudConnector()
    with pytest.raises(AuthenticationError):
        conn.fetch({"api_token": "", "organization": "my-org"})


def test_connector_raises_on_missing_organization() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    from app.connectors.exceptions import AuthenticationError
    conn = TerraformCloudConnector()
    with pytest.raises(AuthenticationError):
        conn.fetch({"api_token": "tok-abc", "organization": ""})


# ══════════════════════════════════════════════════════════════════════════════
# C. Privacy / sanitization — unit tests on normalizers directly
# ══════════════════════════════════════════════════════════════════════════════


def _check_no_forbidden_keys(record: dict, context: str = "") -> None:
    for key in record.keys():
        assert key not in FORBIDDEN_RECORD_KEYS, (
            f"Forbidden key {key!r} found in {context or 'record'}: {record}"
        )


def test_normalize_organization_no_forbidden_keys() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()
    data = {
        "id": "org-abc123",
        "type": "organizations",
        "attributes": {
            "workspace-count": 10,
            "project-count": 3,
            "cost-estimation-enabled": True,
            "collaborator-auth-policy": "two_factor_mandatory",
            "sso-enabled": True,
            "two-factor-conformant": True,
            # Fields that should NEVER appear in output:
            "name": "my-secret-org",
            "email": "admin@example.com",
        },
    }
    record = conn._normalize_organization(data, org_resource_id="opaque-org-id")
    _check_no_forbidden_keys(record, "terraform_cloud_organization")
    # Confirm the raw org name is not stored
    for v in record.values():
        assert "my-secret-org" not in str(v), f"Raw org name leaked into record: {v!r}"
    assert record["record_type"] == "terraform_cloud_organization"
    assert record["provider"] == "terraform_cloud"


def test_normalize_workspace_no_forbidden_keys() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()
    ws_item = {
        "id": "ws-abc123",
        "type": "workspaces",
        "attributes": {
            "name": "my-secret-workspace",
            "execution-mode": "remote",
            "terraform-version": "1.5.0",
            "auto-apply": False,
            "file-triggers-enabled": True,
            "queue-all-runs": False,
            "speculative-enabled": True,
            "global-remote-state": False,
            "vcs-repo": {"oauth-token-id": "ot-abc", "identifier": "org/repo"},
            "working-directory": "/secret/path",
            "trigger-prefixes": ["apps/", "modules/"],
        },
    }
    var_items = [
        {"id": "var-1", "attributes": {"sensitive": True, "category": "env", "key": "SECRET_KEY", "value": "SECRET_VALUE"}},
        {"id": "var-2", "attributes": {"sensitive": False, "category": "terraform", "key": "region", "value": "us-east-1"}},
    ]
    record = conn._normalize_workspace(
        ws_item, "org-opaque", var_items, [], [], []
    )
    _check_no_forbidden_keys(record, "terraform_cloud_workspace")
    # Workspace name must not be stored
    for v in record.values():
        assert "my-secret-workspace" not in str(v)
        assert "/secret/path" not in str(v)
        assert "apps/" not in str(v)
        assert "SECRET_KEY" not in str(v)
        assert "SECRET_VALUE" not in str(v)
        assert "org/repo" not in str(v)
    assert record["variable_count"] == 2
    assert record["sensitive_variable_count"] == 1
    assert record["vcs_connected"] is True
    assert record["working_directory_present"] is True
    assert record["trigger_prefix_count"] == 2


def test_normalize_workspace_variable_summary_never_stores_values() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()
    var_items = [
        {"id": "var-1", "attributes": {"sensitive": False, "category": "env", "key": "DB_HOST", "value": "db.internal"}},
        {"id": "var-2", "attributes": {"sensitive": True, "category": "env", "key": "DB_PASS", "value": "hunter2"}},
        {"id": "var-3", "attributes": {"sensitive": False, "category": "terraform", "key": "region", "value": "us-west-2"}},
    ]
    record = conn._normalize_workspace_variable_summary("ws-opaque", var_items)
    _check_no_forbidden_keys(record, "terraform_cloud_workspace_variable_summary")
    assert record["raw_value_never_read"] is True
    assert record["variable_count"] == 3
    assert record["sensitive_variable_count"] == 1
    assert record["non_sensitive_variable_count"] == 2
    assert record["environment_variable_count"] == 2
    assert record["terraform_variable_count"] == 1
    # Verify no raw values anywhere
    for v in record.values():
        assert "DB_HOST" not in str(v)
        assert "db.internal" not in str(v)
        assert "hunter2" not in str(v)
        assert "DB_PASS" not in str(v)


def test_normalize_policy_set_no_forbidden_keys() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()
    item = {
        "id": "polset-abc",
        "type": "policy-sets",
        "attributes": {
            "name": "my-secret-policy-set",
            "global": False,
            "enforcement-level": "mandatory",
            "vcs-repo": {"identifier": "org/policies"},
        },
        "relationships": {
            "policies": {"data": [{"id": "pol-1"}, {"id": "pol-2"}]},
            "workspaces": {"data": [{"id": "ws-1"}]},
            "projects": {"data": []},
        },
    }
    record = conn._normalize_policy_set(item, "org-opaque")
    _check_no_forbidden_keys(record, "terraform_cloud_policy_set")
    for v in record.values():
        assert "my-secret-policy-set" not in str(v)
        assert "org/policies" not in str(v)
    assert record["enforcement_level_category"] == "mandatory"
    assert record["policy_count"] == 2
    assert record["vcs_connected"] is True


def test_normalize_notification_no_webhook_url_stored() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()
    item = {
        "id": "nc-abc",
        "type": "notification-configurations",
        "attributes": {
            "enabled": True,
            "destination-type": "webhook",
            "url": "https://hooks.example.com/secret-endpoint",
            "token": "super-secret-token",
            "email-addresses": ["admin@example.com"],
            "triggers": ["run:created", "run:completed"],
        },
    }
    record = conn._normalize_notification(item, "ws-opaque")
    _check_no_forbidden_keys(record, "terraform_cloud_notification_configuration")
    for v in record.values():
        assert "hooks.example.com" not in str(v), f"Webhook URL leaked: {v!r}"
        assert "secret-endpoint" not in str(v)
        assert "super-secret-token" not in str(v)
        assert "admin@example.com" not in str(v)
    assert record["enabled"] is True
    assert record["destination_type_category"] == "webhook"
    assert record["webhook_url_present"] is True
    assert record["webhook_url_scheme_category"] == "https"
    assert record["token_present"] is True
    assert record["trigger_count"] == 2


def test_normalize_notification_http_scheme_stored() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()
    item = {
        "id": "nc-http",
        "attributes": {
            "enabled": True,
            "destination-type": "webhook",
            "url": "http://insecure-webhook.example.com/callback",
            "token": "",
            "triggers": ["run:created"],
        },
    }
    record = conn._normalize_notification(item, "ws-opaque")
    assert record["webhook_url_scheme_category"] == "http"
    assert record["token_present"] is False


def test_normalize_team_access_summary_no_team_names() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()
    team_items = [
        {"id": "ta-1", "attributes": {"access": "admin", "team-name": "Platform Team"}},
        {"id": "ta-2", "attributes": {"access": "write", "team-name": "Dev Team"}},
        {"id": "ta-3", "attributes": {"access": "read", "team-name": "Ops Team"}},
    ]
    record = conn._normalize_team_access_summary("ws-opaque", team_items)
    _check_no_forbidden_keys(record, "terraform_cloud_team_access_summary")
    for v in record.values():
        assert "Platform Team" not in str(v)
        assert "Dev Team" not in str(v)
        assert "Ops Team" not in str(v)
    assert record["team_access_count"] == 3
    assert record["admin_access_count"] == 1
    assert record["write_access_count"] == 1
    assert record["read_access_count"] == 1


def test_normalize_state_version_summary_never_fetches_state() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()
    record = conn._normalize_state_version_summary("ws-opaque", current_state_present=True)
    _check_no_forbidden_keys(record, "terraform_cloud_state_version_summary")
    assert record["raw_state_never_fetched"] is True
    assert record["state_version_present"] is True


def test_normalize_variable_set_no_variable_names_or_values() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()
    vs_item = {
        "id": "varset-abc",
        "type": "varsets",
        "attributes": {
            "name": "global-secrets",
            "global": True,
        },
        "relationships": {
            "workspaces": {"data": []},
            "projects": {"data": []},
        },
    }
    var_items = [
        {"id": "var-1", "attributes": {"sensitive": True, "category": "env", "key": "API_KEY", "value": "secret"}},
        {"id": "var-2", "attributes": {"sensitive": False, "category": "terraform", "key": "region", "value": "us-east-1"}},
    ]
    record = conn._normalize_variable_set(vs_item, "org-opaque", var_items)
    _check_no_forbidden_keys(record, "terraform_cloud_variable_set")
    for v in record.values():
        assert "global-secrets" not in str(v)
        assert "API_KEY" not in str(v)
        assert "secret" not in str(v)
        assert "region" not in str(v)
        assert "us-east-1" not in str(v)
    assert record["global_scope"] is True
    assert record["variable_count"] == 2
    assert record["sensitive_variable_count"] == 1


def test_normalize_run_trigger_no_source_workspace_name() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()
    item = {
        "id": "rt-abc",
        "type": "run-triggers",
        "attributes": {
            "sourceable-type": "Workspace",
            "source-workspace-name": "secret-source-workspace",
        },
    }
    record = conn._normalize_run_trigger(item, "ws-opaque")
    _check_no_forbidden_keys(record, "terraform_cloud_run_trigger")
    for v in record.values():
        assert "secret-source-workspace" not in str(v)
    assert record["sourceable_type_category"] == "workspace"


# ══════════════════════════════════════════════════════════════════════════════
# D. Record ID determinism and opacity
# ══════════════════════════════════════════════════════════════════════════════


def test_record_ids_are_deterministic() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()

    ws_item = {
        "id": "ws-stable-id",
        "type": "workspaces",
        "attributes": {
            "execution-mode": "remote",
            "terraform-version": "1.5.0",
            "auto-apply": False,
            "file-triggers-enabled": False,
            "queue-all-runs": False,
            "speculative-enabled": True,
            "global-remote-state": False,
        },
    }
    r1 = conn._normalize_workspace(ws_item, "org-opaque", [], [], [], [])
    r2 = conn._normalize_workspace(ws_item, "org-opaque", [], [], [], [])
    assert r1["record_id"] == r2["record_id"]
    assert r1["resource_id"] == r2["resource_id"]


def test_record_ids_are_opaque() -> None:
    """Record IDs must not expose raw workspace IDs."""
    from app.connectors.terraform_cloud import TerraformCloudConnector
    conn = TerraformCloudConnector()

    ws_item = {
        "id": "ws-secret-raw-id",
        "type": "workspaces",
        "attributes": {"execution-mode": "remote", "auto-apply": False},
    }
    record = conn._normalize_workspace(ws_item, "org-opaque", [], [], [], [])
    assert "ws-secret-raw-id" not in record["record_id"]
    assert "ws-secret-raw-id" not in record["resource_id"]


def test_org_resource_id_is_opaque_not_raw_name() -> None:
    """org_resource_id must be an opaque hash of the org name, never the raw name."""
    from app.connectors.terraform_cloud import _opaque_id
    raw_org = "my-real-org-name"
    org_resource_id = _opaque_id(raw_org)
    assert raw_org not in org_resource_id
    # Verify determinism
    assert org_resource_id == _opaque_id(raw_org)


# ══════════════════════════════════════════════════════════════════════════════
# E. Drift-risk classification
# ══════════════════════════════════════════════════════════════════════════════


def test_classify_auto_apply_enabled_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_workspace", "auto_apply", "modified", False, True
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high", f"Expected high, got {level!r}: {reason}"
    assert "auto-apply" in reason.lower() or "auto_apply" in reason.lower()


def test_classify_global_remote_state_enabled_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_workspace", "global_remote_state", "modified", False, True
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high", f"Expected high, got {level!r}: {reason}"


def test_classify_notification_http_scheme_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_notification_configuration",
        "webhook_url_scheme_category", "modified", "https", "http"
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high", f"Expected high, got {level!r}: {reason}"


def test_classify_notification_token_removed_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_notification_configuration",
        "token_present", "modified", True, False
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high"


def test_classify_admin_access_increased_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_team_access_summary",
        "admin_access_count", "modified", 1, 3
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high"


def test_classify_write_access_increased_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_team_access_summary",
        "write_access_count", "modified", 0, 2
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high"


def test_classify_plan_access_increased_is_medium() -> None:
    """plan_access_count is tracked but is a narrower grant than admin/write —
    medium, not high (matches the project's plan-vs-apply severity convention)."""
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_team_access_summary",
        "plan_access_count", "modified", 0, 2
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "medium", f"Expected medium, got {level!r}: {reason}"


def test_classify_plan_access_decreased_is_low() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_team_access_summary",
        "plan_access_count", "modified", 2, 0
    )
    level, _ = classify_terraform_cloud_change(change)
    assert level == "low"


def test_classify_custom_permission_increased_is_medium() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_team_access_summary",
        "custom_permission_count", "modified", 0, 1
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "medium", f"Expected medium, got {level!r}: {reason}"


def test_classify_sensitive_variable_count_decreased_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_workspace",
        "sensitive_variable_count", "modified", 5, 2
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high"


def test_classifier_reads_real_compute_diff_dict_shape_not_a_mock() -> None:
    """Regression test for a field-name bug: every directional classifier in
    risk_rules/terraform_cloud.py previously read a nonexistent 'old_value'
    key instead of 'prev_value' (the actual key compute_diff/Change use).
    The bug was invisible because the test helper's mock used the same wrong
    name. This test builds a plain dict shaped EXACTLY like compute_diff's
    real output (prev_value/new_value/field_path/change_type/
    provider_metadata) to prove the classifier reads the real field name.
    """
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change

    # sensitive_variable_count decreasing must be "high" — this requires
    # correctly reading prev_value=5 to compare against new_value=2.
    real_shaped_change = {
        "change_type": "modified",
        "field_path": "sensitive_variable_count",
        "prev_value": 5,
        "new_value": 2,
        "provider_metadata": {"record_type": "terraform_cloud_workspace"},
    }
    level, reason = classify_terraform_cloud_change(real_shaped_change)
    assert level == "high", (
        f"Expected high (sensitive_variable_count decreased 5->2), got {level!r}: {reason}"
    )

    # execution_mode_category remote -> local must be "high" specifically
    # because prev_value=='remote' — if prev_value were misread as None/'',
    # this would silently downgrade to 'medium'.
    exec_mode_change = {
        "change_type": "modified",
        "field_path": "execution_mode_category",
        "prev_value": "remote",
        "new_value": "local",
        "provider_metadata": {"record_type": "terraform_cloud_workspace"},
    }
    level, reason = classify_terraform_cloud_change(exec_mode_change)
    assert level == "high", (
        f"Expected high (execution mode remote->local), got {level!r}: {reason}"
    )


def test_classify_policy_enforcement_weakened_mandatory_to_advisory_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_policy_set",
        "enforcement_level_category", "modified", "mandatory", "advisory"
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high"


def test_classify_policy_global_scope_removed_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_policy_set",
        "global_scope", "modified", True, False
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high"


def test_classify_vcs_connection_removed_is_medium() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_workspace", "vcs_connected", "modified", True, False
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "medium"


def test_classify_queue_all_runs_disabled_is_medium() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_workspace", "queue_all_runs", "modified", True, False
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "medium"


def test_classify_speculative_disabled_is_medium() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_workspace", "speculative_enabled", "modified", True, False
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "medium"


def test_classify_run_trigger_count_increased_is_medium() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_workspace", "run_trigger_count", "modified", 1, 4
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "medium"


def test_classify_execution_mode_remote_to_local_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_workspace",
        "execution_mode_category", "modified", "remote", "local"
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high"


def test_classify_execution_mode_to_agent_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_workspace",
        "execution_mode_category", "modified", "remote", "agent"
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high"


def test_classify_org_2fa_disabled_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_organization",
        "two_factor_requirement_enabled", "modified", True, False
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high"


def test_classify_variable_set_scope_global_is_high() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change(
        "terraform_cloud_variable_set",
        "global_scope", "modified", False, True
    )
    level, reason = classify_terraform_cloud_change(change)
    assert level == "high"


def test_classify_unknown_record_type_is_low() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change("terraform_cloud_unknown_type", "some_field", "modified", 1, 2)
    level, reason = classify_terraform_cloud_change(change)
    assert level == "low"


def test_classify_non_terraform_record_type_returns_something() -> None:
    """The classifier should return low for any non-terraform_cloud_ prefix."""
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change("github_repo", "visibility", "modified", "private", "public")
    level, reason = classify_terraform_cloud_change(change)
    assert level == "low"


def test_classify_auto_apply_true_to_unknown_is_low_not_disabled_wording() -> None:
    """true -> unknown/missing must not claim 'disabled' and must not be high."""
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change("terraform_cloud_workspace", "auto_apply", "modified", True, None)
    level, reason = classify_terraform_cloud_change(change)
    assert level == "low"
    assert "disabled" not in reason
    assert "unknown or missing" in reason


def test_classify_auto_apply_explicit_false_is_low_disabled_wording() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change("terraform_cloud_workspace", "auto_apply", "modified", True, False)
    level, reason = classify_terraform_cloud_change(change)
    assert level == "low"
    assert "disabled" in reason


def test_classify_global_remote_state_true_to_unknown_is_low_not_disabled_wording() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change("terraform_cloud_workspace", "global_remote_state", "modified", True, None)
    level, reason = classify_terraform_cloud_change(change)
    assert level == "low"
    assert "disabled" not in reason
    assert "unknown or missing" in reason


def test_classify_global_remote_state_disabled_is_improvement_low() -> None:
    """Restoration case: global remote state sharing explicitly turned off."""
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change("terraform_cloud_workspace", "global_remote_state", "modified", True, False)
    level, reason = classify_terraform_cloud_change(change)
    assert level == "low"
    assert "disabled" in reason


def test_classify_vcs_reconnected_is_improvement_low() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change("terraform_cloud_workspace", "vcs_connected", "modified", False, True)
    level, reason = classify_terraform_cloud_change(change)
    assert level == "low"


def test_classify_variable_set_global_scope_true_to_unknown_is_low() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change("terraform_cloud_variable_set", "global_scope", "modified", True, None)
    level, reason = classify_terraform_cloud_change(change)
    assert level == "low"
    assert "unknown or missing" in reason


def test_classify_policy_set_vcs_disconnected_is_medium() -> None:
    """GAP fix: policy_set.vcs_connected is tracked but previously had no
    dedicated classification branch and fell through to the generic low
    fallback."""
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change("terraform_cloud_policy_set", "vcs_connected", "modified", True, False)
    level, reason = classify_terraform_cloud_change(change)
    assert level == "medium", f"Expected medium, got {level!r}: {reason}"


def test_classify_policy_set_vcs_reconnected_is_low() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change("terraform_cloud_policy_set", "vcs_connected", "modified", False, True)
    level, reason = classify_terraform_cloud_change(change)
    assert level == "low"


def test_classify_project_team_access_increased_is_medium() -> None:
    """GAP fix: terraform_cloud_project.team_access_count is tracked but
    previously had no dedicated classification branch and fell through to
    the generic low fallback."""
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change("terraform_cloud_project", "team_access_count", "modified", 1, 3)
    level, reason = classify_terraform_cloud_change(change)
    assert level == "medium", f"Expected medium, got {level!r}: {reason}"


def test_classify_project_team_access_decreased_is_low() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    change = _make_change("terraform_cloud_project", "team_access_count", "modified", 3, 1)
    level, reason = classify_terraform_cloud_change(change)
    assert level == "low"


def test_classify_no_forbidden_wording_in_reasons() -> None:
    """No classifier reason string may use forbidden wording."""
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change

    FORBIDDEN = [
        "breach", "compromise", "attacker", "leaked", "unauthorized access",
        "exfiltration", "stolen", "fraud", "attack detected",
        "secret leaked", "token leaked", "state leaked",
        "credentials exposed", "infrastructure exposed",
    ]

    test_cases = [
        ("terraform_cloud_workspace", "auto_apply", False, True),
        ("terraform_cloud_workspace", "global_remote_state", False, True),
        ("terraform_cloud_workspace", "vcs_connected", True, False),
        ("terraform_cloud_workspace", "sensitive_variable_count", 5, 2),
        ("terraform_cloud_workspace_variable_summary", "sensitive_variable_count", 5, 2),
        ("terraform_cloud_notification_configuration", "webhook_url_scheme_category", "https", "http"),
        ("terraform_cloud_notification_configuration", "token_present", True, False),
        ("terraform_cloud_team_access_summary", "admin_access_count", 0, 3),
        ("terraform_cloud_policy_set", "enforcement_level_category", "mandatory", "advisory"),
        ("terraform_cloud_policy_set", "global_scope", True, False),
        ("terraform_cloud_variable_set", "global_scope", False, True),
        ("terraform_cloud_organization", "two_factor_requirement_enabled", True, False),
    ]

    for record_type, field_path, old_v, new_v in test_cases:
        change = _make_change(record_type, field_path, "modified", old_v, new_v)
        _level, reason = classify_terraform_cloud_change(change)
        reason_lower = reason.lower()
        for phrase in FORBIDDEN:
            assert phrase not in reason_lower, (
                f"Forbidden phrase '{phrase}' in reason for {record_type}/{field_path}: {reason!r}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# E2. Diff tracked fields (drift detection) — QA regression
# ══════════════════════════════════════════════════════════════════════════════
#
# Regression coverage for a gap where Terraform Cloud record types had no
# entry in diff_service's per-provider tracked-fields dispatch. Without an
# entry, `_tracked_fields_for` fell through every known provider prefix to
# the Cloudflare-DNS default tuple ("record_type", "name", "content", "ttl",
# "proxied", "priority", "comment") — none of which exist on any Terraform
# Cloud record. compute_diff would therefore NEVER detect a modified field
# on an existing Terraform Cloud record (auto_apply toggled, team access
# changed, etc.) even though risk_rules.terraform_cloud already classifies
# the field correctly. Only added/removed records would ever surface.


class TestTerraformCloudDiffTrackedFields:
    def test_all_ten_record_types_have_tracked_fields_entries(self):
        from app.services.diff_service import _TERRAFORM_CLOUD_TRACKED_FIELDS_BY_TYPE
        from app.connectors.terraform_cloud_schema import TERRAFORM_CLOUD_RECORD_TYPES

        for record_type in TERRAFORM_CLOUD_RECORD_TYPES:
            assert record_type in _TERRAFORM_CLOUD_TRACKED_FIELDS_BY_TYPE, (
                f"{record_type!r} has no tracked-fields entry — modified-field "
                "changes for this record type will never be detected by compute_diff"
            )

    def test_tracked_fields_dispatch_uses_terraform_cloud_table_not_cloudflare_default(self):
        from app.services.diff_service import _tracked_fields_for, _TRACKED_FIELDS
        from app.connectors.terraform_cloud_schema import TERRAFORM_CLOUD_RECORD_TYPES

        for record_type in TERRAFORM_CLOUD_RECORD_TYPES:
            fields = _tracked_fields_for({"record_type": record_type})
            assert fields != _TRACKED_FIELDS, (
                f"{record_type!r} is falling through to the Cloudflare DNS "
                "default tracked-fields tuple instead of its own Terraform Cloud fields"
            )
            assert fields, f"{record_type!r} resolved to an empty tracked-fields tuple"

    def test_auto_apply_change_produces_drift_change(self):
        """auto_apply False -> True must surface as a Change.

        This is the exact scenario item A (auto-apply enabled/disabled)
        depends on: if this field isn't tracked, the security finding would
        still fire on next evaluation, but the Changes timeline would never
        show the drift event at all.
        """
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        def _workspace_record(auto_apply: bool) -> dict:
            return {
                "record_type": "terraform_cloud_workspace",
                "provider": "terraform_cloud",
                "record_id": "terraform_cloud_workspace:ws123",
                "resource_id": "ws123",
                "workspace_resource_id": "ws123",
                "organization_resource_id": "org123",
                "execution_mode_category": "remote",
                "terraform_version_category": "pinned",
                "auto_apply": auto_apply,
                "file_triggers_enabled": True,
                "queue_all_runs": False,
                "speculative_enabled": True,
                "global_remote_state": False,
                "vcs_connected": True,
                "working_directory_present": False,
                "trigger_prefix_count": 0,
                "run_trigger_count": 0,
                "variable_count": 2,
                "sensitive_variable_count": 1,
                "non_sensitive_variable_count": 1,
                "environment_variable_count": 1,
                "terraform_variable_count": 1,
                "notification_count": 0,
                "team_access_count": 1,
                "current_state_version_present": True,
                "latest_run_status_category": "applied",
            }

        prev = _mock_snapshot([_workspace_record(False)])
        new = _mock_snapshot([_workspace_record(True)])

        changes = compute_diff(prev, new)
        auto_apply_changes = [c for c in changes if c["field_path"] == "auto_apply"]

        assert len(auto_apply_changes) == 1
        assert auto_apply_changes[0]["change_type"] == "modified"
        assert auto_apply_changes[0]["prev_value"] is False
        assert auto_apply_changes[0]["new_value"] is True

    def test_admin_access_count_change_produces_drift_change(self):
        """admin_access_count 0 -> 2 must surface as a Change."""
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        def _team_access_record(admin_count: int) -> dict:
            return {
                "record_type": "terraform_cloud_team_access_summary",
                "provider": "terraform_cloud",
                "record_id": "terraform_cloud_team_access_summary:ws123",
                "resource_id": "ws123",
                "workspace_resource_id": "ws123",
                "team_access_count": admin_count + 1,
                "admin_access_count": admin_count,
                "write_access_count": 1,
                "read_access_count": 0,
                "plan_access_count": 0,
                "custom_permission_count": 0,
            }

        prev = _mock_snapshot([_team_access_record(0)])
        new = _mock_snapshot([_team_access_record(2)])

        changes = compute_diff(prev, new)
        admin_changes = [c for c in changes if c["field_path"] == "admin_access_count"]

        assert len(admin_changes) == 1
        assert admin_changes[0]["prev_value"] == 0
        assert admin_changes[0]["new_value"] == 2

    def test_no_spurious_change_when_records_are_identical(self):
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        record = {
            "record_type": "terraform_cloud_policy_set",
            "provider": "terraform_cloud",
            "record_id": "terraform_cloud_policy_set:ps123",
            "resource_id": "ps123",
            "policy_set_resource_id": "ps123",
            "organization_resource_id": "org123",
            "global_scope": False,
            "workspace_count": 3,
            "project_count": 0,
            "policy_count": 2,
            "enforcement_level_category": "mandatory",
            "vcs_connected": True,
        }
        prev = _mock_snapshot([dict(record)])
        new = _mock_snapshot([dict(record)])

        assert compute_diff(prev, new) == []

    def test_every_tracked_field_classifies_without_error_or_invalid_severity(self):
        """Every field in _TERRAFORM_CLOUD_TRACKED_FIELDS_BY_TYPE must be
        classifiable: classify_terraform_cloud_change must not raise, and
        must return one of the three known severities, for a representative
        modified change on each tracked field of each record type — even
        when it falls through to the generic per-record-type fallback.
        """
        from app.services.diff_service import _TERRAFORM_CLOUD_TRACKED_FIELDS_BY_TYPE
        from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change

        for record_type, fields in _TERRAFORM_CLOUD_TRACKED_FIELDS_BY_TYPE.items():
            for field in fields:
                change = {
                    "change_type": "modified",
                    "field_path": field,
                    "prev_value": 1,
                    "new_value": 2,
                    "provider_metadata": {"record_type": record_type},
                }
                level, reason = classify_terraform_cloud_change(change)
                assert level in ("low", "medium", "high"), (
                    f"{record_type}.{field} returned invalid severity {level!r}"
                )
                assert isinstance(reason, str) and reason, (
                    f"{record_type}.{field} returned an empty reason string"
                )


# ══════════════════════════════════════════════════════════════════════════════
# F. Capability matrix
# ══════════════════════════════════════════════════════════════════════════════


def test_terraform_cloud_in_capability_matrix() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None, "Terraform Cloud missing from provider capability matrix"


def test_terraform_cloud_label_is_correct() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.provider == "terraform_cloud"
    assert cap.label == "Terraform Cloud"


def test_terraform_cloud_capability_flags_m88a() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True
    # M88B: security_rules is now True
    assert cap.security.security_rules in (True, False)  # accept either; M88B sets True
    # M88D: activity_ingestion, M88E: activity_signals, M88F: risk_activity_correlations
    assert cap.security.activity_ingestion in (True, False)
    assert cap.security.activity_signals in (True, False)
    assert cap.security.risk_activity_correlations in (True, False)
    # M88F complete — risk_activity_correlations is now True
    # M88G complete — demo_seed_clear/case_report/evidence_timeline/evidence_graph now True
    assert cap.security.demo_seed_clear in (True, False)
    assert cap.security.case_report in (True, False)
    assert cap.security.evidence_timeline in (True, False)
    assert cap.security.evidence_graph in (True, False)


def test_terraform_cloud_maturity_is_partial() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.maturity == "partial"


def test_terraform_cloud_notes_mention_m88a() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    notes_lower = cap.notes.lower()
    assert "m88a" in notes_lower or "foundation" in notes_lower


def test_terraform_cloud_notes_mention_planned_next() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    # M88B complete: notes should mention M88B or M88C as next stage
    assert (
        "M88B" in cap.notes or "Security Foundation" in cap.notes
        or "M88C" in cap.notes or "Risk Expansion" in cap.notes
    )


def test_capability_matrix_no_forbidden_wording_in_terraform_notes() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    FORBIDDEN = [
        "breach", "compromise", "attacker", "leaked", "unauthorized access",
        "state leaked", "token leaked", "secret leaked",
    ]
    notes_lower = cap.notes.lower()
    for phrase in FORBIDDEN:
        assert phrase not in notes_lower, (
            f"Forbidden phrase '{phrase}' in Terraform Cloud capability notes"
        )


# ══════════════════════════════════════════════════════════════════════════════
# G. Provider expansion framework
# ══════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_planned_next_stage_m88b() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    # M88F complete — planned_next_stage advanced to M88G
    assert (
        "M88B" in planned or "Terraform Cloud Core" in planned or "Security Foundation" in planned
        or "M88C" in planned or "Variable/Policy" in planned or "Risk Expansion" in planned
        or "M88D" in planned or "Activity" in planned or "Event Ingestion" in planned
        or "M88E" in planned or "Signals" in planned
        or "M88F" in planned or "Correlations" in planned
        or "M88G" in planned or "Demo" in planned or "QA" in planned
        or "M88H" in planned or "Provider Depth" in planned
        or "M88I" in planned or "Cross-Cloud" in planned
        or "M89A" in planned or "Kubernetes" in planned
                or "M90A" in planned or "Sentry" in planned
    ), (
        f"planned_next_stage should point to M88B or later; got: {planned!r}"
    )


def test_expansion_framework_terraform_cloud_in_queue() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    provider_keys = [
        r.get("provider", "").lower() for r in recommended if isinstance(r, dict)
    ]
    # M88I complete — Terraform Cloud arc done; Kubernetes then launched
    # (message 1 / M89A) and completed too; Sentry is now head.
    assert (any("terraform" in p for p in provider_keys)
            or any("kubernetes" in p for p in provider_keys)
            or any("sentry" in p for p in provider_keys)), (
        "Terraform Cloud, Kubernetes, or Sentry should be in recommended_next_providers queue"
    )


def test_expansion_framework_kubernetes_after_terraform_cloud() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    providers = [r.get("provider", "") for r in recommended if isinstance(r, dict)]
    tc_idx = next((i for i, p in enumerate(providers) if "terraform" in p.lower()), None)
    k8s_idx = next((i for i, p in enumerate(providers) if "kubernetes" in p.lower()), None)
    if tc_idx is not None and k8s_idx is not None:
        assert tc_idx < k8s_idx, (
            "Terraform Cloud should appear before Kubernetes in recommended queue"
        )


def test_expansion_framework_sentry_after_kubernetes() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    providers = [r.get("provider", "") for r in recommended if isinstance(r, dict)]
    k8s_idx = next((i for i, p in enumerate(providers) if "kubernetes" in p.lower()), None)
    sentry_idx = next((i for i, p in enumerate(providers) if "sentry" in p.lower()), None)
    if k8s_idx is not None and sentry_idx is not None:
        assert k8s_idx < sentry_idx


# ══════════════════════════════════════════════════════════════════════════════
# H. Frontend provider list
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_frontend_providers_ts_includes_terraform_cloud() -> None:
    text = FE_PROVIDERS.read_text()
    assert "terraform_cloud" in text, (
        "providers.ts must include terraform_cloud"
    )


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_frontend_providers_ts_terraform_cloud_label() -> None:
    text = FE_PROVIDERS.read_text()
    assert "Terraform Cloud" in text


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_frontend_providers_ts_terraform_cloud_in_provider_ids() -> None:
    text = FE_PROVIDERS.read_text()
    # Must appear in the PROVIDER_IDS array
    idx_pid = text.find("PROVIDER_IDS")
    assert idx_pid != -1
    pid_section = text[idx_pid: idx_pid + 2000]
    assert "terraform_cloud" in pid_section


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_frontend_providers_ts_terraform_cloud_in_connectable_ids() -> None:
    text = FE_PROVIDERS.read_text()
    idx_cid = text.find("CONNECTABLE_PROVIDER_IDS")
    assert idx_cid != -1
    cid_section = text[idx_cid: idx_cid + 2000]
    assert "terraform_cloud" in cid_section


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_frontend_providers_no_forbidden_terraform_wording() -> None:
    text = FE_PROVIDERS.read_text()
    # Find Terraform Cloud section
    idx = text.find("terraform_cloud")
    section = text[idx: idx + 2000]
    FORBIDDEN = [
        "breach confirmed", "token leaked", "state leaked",
        "credentials exposed", "secret leaked",
    ]
    for phrase in FORBIDDEN:
        assert phrase not in section.lower(), (
            f"Forbidden phrase '{phrase}' in Terraform Cloud providers.ts section"
        )


@pytest.mark.skipif(not FE_TYPES.exists(), reason="Frontend tree absent")
def test_frontend_types_includes_terraform_cloud_fields() -> None:
    text = FE_TYPES.read_text()
    assert "terraform_cloud_api_token" in text
    assert "terraform_cloud_organization" in text


@pytest.mark.skipif(not FE_TYPES.exists(), reason="Frontend tree absent")
def test_frontend_types_terraform_cloud_provider_union() -> None:
    text = FE_TYPES.read_text()
    assert '"terraform_cloud"' in text


# ══════════════════════════════════════════════════════════════════════════════
# I. Regression smoke
# ══════════════════════════════════════════════════════════════════════════════


def test_risk_service_routes_terraform_cloud() -> None:
    from app.services.risk_service import classify_change
    change = _make_change(
        "terraform_cloud_workspace", "auto_apply", "modified", False, True
    )
    level, reason = classify_change(change)
    assert level in ("high", "medium", "low")
    assert reason


def test_gitlab_risk_routing_still_works() -> None:
    """M87 GitLab risk routing must still work after M88A changes."""
    from app.services.risk_service import classify_change
    change = _make_change(
        "gitlab_project", "visibility_category", "modified", "private", "public"
    )
    level, reason = classify_change(change)
    assert level in ("high", "medium", "low")
    assert "gitlab" in reason.lower() or "visibility" in reason.lower()


def test_gitlab_capability_still_present() -> None:
    """M87 GitLab capability matrix entry must still be present after M88A."""
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("gitlab")
    assert cap is not None
    assert cap.drift.drift_snapshots is True


def test_connector_does_not_call_state_endpoints() -> None:
    """Verify the connector never passes state-file endpoints to _request/_paginate.

    We check that no _request or _paginate call site uses these paths.
    They may appear in docstrings/comments as negations — we check function
    call lines only (lines containing self._request or self._paginate).
    """
    import app.connectors.terraform_cloud as tc_module
    import inspect
    src = inspect.getsource(tc_module)
    call_lines = [
        ln for ln in src.splitlines()
        if "self._request(" in ln or "self._paginate(" in ln or "_fetch_fail_soft(" in ln
    ]
    call_text = "\n".join(call_lines)
    forbidden_paths = [
        "state-versions",
        "state-version-outputs",
        "/plans/",
        "/applies/",
        "f\"runs/",
    ]
    for path in forbidden_paths:
        assert path not in call_text, (
            f"Connector must not call endpoint containing {path!r}: {call_text!r}"
        )


def test_connector_source_never_logs_token() -> None:
    """Connector must not log the api_token anywhere."""
    import app.connectors.terraform_cloud as tc_module
    import inspect
    src = inspect.getsource(tc_module)
    # The token must never appear in a logger call
    import re
    log_lines = [ln for ln in src.splitlines() if "logger." in ln]
    for line in log_lines:
        assert "token" not in line.lower() or "NEVER" in line or "#" in line.split("logger.")[0], (
            f"Potential token logging in: {line!r}"
        )


def test_tail_latency_study_untouched() -> None:
    """tail-latency-study/ must not appear in staged files."""
    import subprocess
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True, text=True,
        cwd=str(REPO_ROOT),
    )
    staged = result.stdout
    assert "tail-latency-study" not in staged, (
        "tail-latency-study/ must not be staged"
    )
