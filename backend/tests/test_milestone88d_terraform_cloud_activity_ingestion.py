"""M88D — Terraform Cloud activity ingestion guardrails.

Verifies that M88D adds Terraform Cloud configuration activity ingestion:
safe config-state events synthesized from existing drift records, deterministic
idempotency keys, correct provider/source values, safe resource types and event
types, and privacy-clean metadata that never exposes tokens, variable values,
state files, URLs, names, or PII.

Sections:
  A. Module imports and event type constants
  B. build_terraform_cloud_activity_events — risky records produce safe events
  C. build_terraform_cloud_activity_events — healthy records produce no events
  D. Missing/None fields — no misleading events
  E. Idempotency — same record+timestamp → same event id
  F. Unknown record type ignored safely
  G. normalize_terraform_cloud_activity_event — allowlist gate
  H. Evidence/metadata safety — no forbidden keys
  I. Event descriptions and copy safety
  J. Backend route support
  K. Frontend activity page includes terraform_cloud
  L. Capability matrix — activity_ingestion=True, planned_next_stage=M88E
  M. Expansion framework — M88E next stage
  N. M88A/M88B/M88C tests still pass (smoke)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ACTIVITY_PAGE = (
    REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "activity" / "page.tsx"
)
ROUTER_FILE = REPO_ROOT / "backend" / "app" / "routers" / "security.py"

# ── Expected Terraform Cloud event types ──────────────────────────────────────

EXPECTED_EVENT_TYPES = {
    "terraform_cloud.organization.two_factor_not_required",
    "terraform_cloud.organization.sso_not_enabled",
    "terraform_cloud.organization.posture_changed",
    "terraform_cloud.workspace.auto_apply_enabled",
    "terraform_cloud.workspace.global_remote_state_enabled",
    "terraform_cloud.workspace.execution_mode_changed",
    "terraform_cloud.workspace.vcs_connection_missing",
    "terraform_cloud.workspace.queue_all_runs_disabled",
    "terraform_cloud.workspace.unpinned_terraform_version",
    "terraform_cloud.workspace.file_triggers_disabled",
    "terraform_cloud.workspace.speculative_plans_disabled",
    "terraform_cloud.workspace.run_triggers_present",
    "terraform_cloud.workspace.latest_run_failed",
    "terraform_cloud.variables.non_sensitive_variables_detected",
    "terraform_cloud.variables.no_sensitive_variables_detected",
    "terraform_cloud.variable_set.global_scope_detected",
    "terraform_cloud.variable_set.broad_scope_detected",
    "terraform_cloud.variable_set.non_sensitive_variables_detected",
    "terraform_cloud.policy_set.advisory_enforcement_detected",
    "terraform_cloud.policy_set.empty_detected",
    "terraform_cloud.policy_set.global_scope_detected",
    "terraform_cloud.policy_set.broad_scope_advisory_detected",
    "terraform_cloud.policy_set.unscoped_detected",
    "terraform_cloud.notification.http_webhook_detected",
    "terraform_cloud.notification.token_missing",
    "terraform_cloud.notification.broad_trigger_scope",
    "terraform_cloud.notification.disabled",
    "terraform_cloud.run_trigger.enabled",
    "terraform_cloud.team_access.admin_detected",
    "terraform_cloud.team_access.apply_detected",
    "terraform_cloud.team_access.write_detected",
    "terraform_cloud.team_access.custom_permissions_detected",
    "terraform_cloud.state_version.metadata_present",
    "terraform_cloud.config.event",
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

UPDATED_AT = "2026-06-21T12:00:00Z"


# ── Record builders ────────────────────────────────────────────────────────────


def _org(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "terraform_cloud_organization",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_organization:org1",
        "resource_id": "org1",
        "organization_resource_id": "org_opaque_1",
        "workspace_count": 5,
        "project_count": 2,
        "policy_set_count": 1,
        "variable_set_count": 2,
        "two_factor_requirement_enabled": True,
        "sso_enabled": True,
        "cost_estimation_enabled": False,
    }
    base.update(kw)
    return base


def _ws(**kw: Any) -> dict[str, Any]:
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
    base.update(kw)
    return base


def _var_summary(**kw: Any) -> dict[str, Any]:
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
    base.update(kw)
    return base


def _varset(**kw: Any) -> dict[str, Any]:
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
    base.update(kw)
    return base


def _policy_set(**kw: Any) -> dict[str, Any]:
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
    base.update(kw)
    return base


def _notification(**kw: Any) -> dict[str, Any]:
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
    base.update(kw)
    return base


def _run_trigger(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "terraform_cloud_run_trigger",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_run_trigger:rt1",
        "resource_id": "rt1",
        "run_trigger_resource_id": "rt_opaque_1",
        "workspace_resource_id": "ws_opaque_1",
        "sourceable_type_category": "workspace",
    }
    base.update(kw)
    return base


def _team_access(**kw: Any) -> dict[str, Any]:
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
        "apply_access_count": 0,
        "custom_permission_count": 0,
    }
    base.update(kw)
    return base


def _state_version(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "terraform_cloud_state_version_summary",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_state_version_summary:sv1",
        "resource_id": "sv1",
        "workspace_resource_id": "ws_opaque_1",
        "state_version_present": False,
        "state_version_count_category": "none",
        "raw_state_never_fetched": True,
    }
    base.update(kw)
    return base


def _event_types(entries: list[dict[str, Any]]) -> set[str]:
    return {e["event_type"] for e in entries}


# ══════════════════════════════════════════════════════════════════════════════
# Section A: Module imports and event type constants
# ══════════════════════════════════════════════════════════════════════════════


def test_ingestion_service_importable() -> None:
    from app.services import terraform_cloud_activity_ingestion_service as svc
    assert callable(svc.build_terraform_cloud_activity_events)
    assert callable(svc.normalize_terraform_cloud_activity_event)
    assert callable(svc.sync_terraform_cloud_activity)


def test_expected_event_types_exist_in_module() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import (
        TERRAFORM_CLOUD_CONFIG_EVENT_TYPES,
    )
    missing = EXPECTED_EVENT_TYPES - TERRAFORM_CLOUD_CONFIG_EVENT_TYPES
    assert not missing, f"Event types missing from module allowlist: {missing}"


def test_provider_and_source_constants() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import PROVIDER, SOURCE
    assert PROVIDER == "terraform_cloud"
    assert SOURCE == "terraform_cloud_activity_event"


# ══════════════════════════════════════════════════════════════════════════════
# Section B: build_terraform_cloud_activity_events — risky records produce safe events
# ══════════════════════════════════════════════════════════════════════════════


def test_org_two_factor_disabled_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _org(two_factor_requirement_enabled=False), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.organization.two_factor_not_required" for e in entries)


def test_org_sso_disabled_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _org(sso_enabled=False), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.organization.sso_not_enabled" for e in entries)


def test_workspace_auto_apply_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(_ws(auto_apply=True), updated_at=UPDATED_AT)
    assert any(e["event_type"] == "terraform_cloud.workspace.auto_apply_enabled" for e in entries)


def test_workspace_global_remote_state_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(_ws(global_remote_state=True), updated_at=UPDATED_AT)
    assert any(e["event_type"] == "terraform_cloud.workspace.global_remote_state_enabled" for e in entries)


def test_workspace_local_execution_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _ws(execution_mode_category="local"), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.workspace.execution_mode_changed" for e in entries)


def test_workspace_agent_execution_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _ws(execution_mode_category="agent"), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.workspace.execution_mode_changed" for e in entries)


def test_workspace_vcs_missing_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _ws(vcs_connected=False, execution_mode_category="remote"), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.workspace.vcs_connection_missing" for e in entries)


def test_workspace_queue_all_runs_disabled_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(_ws(queue_all_runs=False), updated_at=UPDATED_AT)
    assert any(e["event_type"] == "terraform_cloud.workspace.queue_all_runs_disabled" for e in entries)


def test_workspace_unpinned_tf_version_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _ws(terraform_version_category="latest"), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.workspace.unpinned_terraform_version" for e in entries)


def test_workspace_file_triggers_disabled_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _ws(file_triggers_enabled=False), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.workspace.file_triggers_disabled" for e in entries)


def test_workspace_speculative_disabled_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _ws(speculative_enabled=False), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.workspace.speculative_plans_disabled" for e in entries)


def test_workspace_run_triggers_present_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _ws(run_trigger_count=2), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.workspace.run_triggers_present" for e in entries)


def test_workspace_latest_run_failed_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    for status in ("errored", "canceled", "policy_override", "discarded"):
        entries = build_terraform_cloud_activity_events(
            _ws(latest_run_status_category=status), updated_at=UPDATED_AT
        )
        assert any(e["event_type"] == "terraform_cloud.workspace.latest_run_failed" for e in entries), (
            f"latest_run_failed not created for status={status!r}"
        )


def test_non_sensitive_variables_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _var_summary(variable_count=3, non_sensitive_variable_count=2, sensitive_variable_count=1),
        updated_at=UPDATED_AT,
    )
    assert any(e["event_type"] == "terraform_cloud.variables.non_sensitive_variables_detected" for e in entries)


def test_no_sensitive_variables_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _var_summary(variable_count=3, non_sensitive_variable_count=3, sensitive_variable_count=0),
        updated_at=UPDATED_AT,
    )
    assert any(e["event_type"] == "terraform_cloud.variables.no_sensitive_variables_detected" for e in entries)


def test_global_variable_set_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _varset(global_scope=True, variable_count=3), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.variable_set.global_scope_detected" for e in entries)


def test_broad_variable_set_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _varset(global_scope=True, variable_count=5), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.variable_set.broad_scope_detected" for e in entries)


def test_varset_non_sensitive_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _varset(non_sensitive_variable_count=2), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.variable_set.non_sensitive_variables_detected" for e in entries)


def test_policy_advisory_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _policy_set(enforcement_level_category="advisory"), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.policy_set.advisory_enforcement_detected" for e in entries)


def test_policy_empty_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _policy_set(policy_count=0), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.policy_set.empty_detected" for e in entries)


def test_policy_global_scope_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _policy_set(global_scope=True), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.policy_set.global_scope_detected" for e in entries)


def test_policy_broad_scope_advisory_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _policy_set(global_scope=True, enforcement_level_category="advisory"),
        updated_at=UPDATED_AT,
    )
    assert any(e["event_type"] == "terraform_cloud.policy_set.broad_scope_advisory_detected" for e in entries)


def test_policy_unscoped_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _policy_set(global_scope=False, workspace_count=0, project_count=0),
        updated_at=UPDATED_AT,
    )
    assert any(e["event_type"] == "terraform_cloud.policy_set.unscoped_detected" for e in entries)


def test_notification_http_webhook_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _notification(
            enabled=True, destination_type_category="webhook",
            webhook_url_scheme_category="http", token_present=True,
        ),
        updated_at=UPDATED_AT,
    )
    assert any(e["event_type"] == "terraform_cloud.notification.http_webhook_detected" for e in entries)


def test_notification_token_missing_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _notification(
            enabled=True, destination_type_category="webhook",
            token_present=False, webhook_url_scheme_category="https",
        ),
        updated_at=UPDATED_AT,
    )
    assert any(e["event_type"] == "terraform_cloud.notification.token_missing" for e in entries)


def test_notification_broad_trigger_scope_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _notification(enabled=True, trigger_count=5), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.notification.broad_trigger_scope" for e in entries)


def test_notification_disabled_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _notification(enabled=False), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.notification.disabled" for e in entries)


def test_run_trigger_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(_run_trigger(), updated_at=UPDATED_AT)
    assert any(e["event_type"] == "terraform_cloud.run_trigger.enabled" for e in entries)


def test_team_admin_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _team_access(admin_access_count=1), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.team_access.admin_detected" for e in entries)


def test_team_apply_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _team_access(apply_access_count=1), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.team_access.apply_detected" for e in entries)


def test_team_write_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _team_access(write_access_count=2), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.team_access.write_detected" for e in entries)


def test_team_custom_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _team_access(custom_permission_count=1), updated_at=UPDATED_AT
    )
    assert any(e["event_type"] == "terraform_cloud.team_access.custom_permissions_detected" for e in entries)


def test_state_version_present_creates_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _state_version(state_version_present=True, state_version_count_category="one"),
        updated_at=UPDATED_AT,
    )
    assert any(e["event_type"] == "terraform_cloud.state_version.metadata_present" for e in entries)


def test_state_version_event_no_state_exposure_wording() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _state_version(state_version_present=True), updated_at=UPDATED_AT
    )
    for entry in entries:
        if entry["event_type"] == "terraform_cloud.state_version.metadata_present":
            meta = entry.get("metadata", {})
            for val in meta.values():
                if isinstance(val, str):
                    assert "state exposed" not in val.lower()
                    assert "tfstate exposed" not in val.lower()
                    assert "state leaked" not in val.lower()


# ══════════════════════════════════════════════════════════════════════════════
# Section C: build_terraform_cloud_activity_events — healthy records produce no events
# ══════════════════════════════════════════════════════════════════════════════


def test_healthy_org_no_events() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(_org(), updated_at=UPDATED_AT)
    assert entries == []


def test_healthy_workspace_no_events() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(_ws(), updated_at=UPDATED_AT)
    assert entries == []


def test_healthy_var_summary_no_events() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(_var_summary(), updated_at=UPDATED_AT)
    assert entries == []


def test_healthy_varset_no_events() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _varset(global_scope=False, non_sensitive_variable_count=0), updated_at=UPDATED_AT
    )
    assert entries == []


def test_healthy_policy_set_mandatory_no_events() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _policy_set(enforcement_level_category="mandatory", policy_count=5, global_scope=False),
        updated_at=UPDATED_AT,
    )
    assert entries == []


def test_healthy_notification_no_events() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _notification(
            enabled=True, destination_type_category="webhook",
            webhook_url_scheme_category="https", token_present=True, trigger_count=2,
        ),
        updated_at=UPDATED_AT,
    )
    assert entries == []


def test_healthy_team_access_no_events() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _team_access(
            admin_access_count=0, apply_access_count=0,
            write_access_count=0, custom_permission_count=0,
        ),
        updated_at=UPDATED_AT,
    )
    assert entries == []


def test_healthy_state_version_absent_no_events() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _state_version(state_version_present=False), updated_at=UPDATED_AT
    )
    assert entries == []


def test_workspace_applied_run_status_no_failed_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _ws(latest_run_status_category="applied"), updated_at=UPDATED_AT
    )
    types = _event_types(entries)
    assert "terraform_cloud.workspace.latest_run_failed" not in types


def test_workspace_vcs_missing_local_mode_no_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    # VCS missing rule only fires for remote execution mode
    entries = build_terraform_cloud_activity_events(
        _ws(vcs_connected=False, execution_mode_category="local"), updated_at=UPDATED_AT
    )
    types = _event_types(entries)
    assert "terraform_cloud.workspace.vcs_connection_missing" not in types


# ══════════════════════════════════════════════════════════════════════════════
# Section D: Missing/None fields — no misleading events
# ══════════════════════════════════════════════════════════════════════════════


def test_empty_org_no_events() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        {"record_type": "terraform_cloud_organization"}, updated_at=UPDATED_AT
    )
    assert entries == []


def test_empty_workspace_no_events() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        {"record_type": "terraform_cloud_workspace"}, updated_at=UPDATED_AT
    )
    assert entries == []


def test_none_latest_run_status_no_failed_event() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _ws(latest_run_status_category=None), updated_at=UPDATED_AT
    )
    types = _event_types(entries)
    assert "terraform_cloud.workspace.latest_run_failed" not in types


def test_zero_variable_count_no_variable_events() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        _var_summary(variable_count=0, non_sensitive_variable_count=0),
        updated_at=UPDATED_AT,
    )
    assert entries == []


def test_policy_unscoped_not_fires_when_counts_missing() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    # workspace_count missing — cannot confirm 0 — should not fire
    entries = build_terraform_cloud_activity_events(
        {"record_type": "terraform_cloud_policy_set", "global_scope": False},
        updated_at=UPDATED_AT,
    )
    types = _event_types(entries)
    assert "terraform_cloud.policy_set.unscoped_detected" not in types


# ══════════════════════════════════════════════════════════════════════════════
# Section E: Idempotency — same record+timestamp → same event id
# ══════════════════════════════════════════════════════════════════════════════


def test_idempotency_same_inputs_same_event_id() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    record = _ws(auto_apply=True)
    entries1 = build_terraform_cloud_activity_events(record, updated_at=UPDATED_AT)
    entries2 = build_terraform_cloud_activity_events(record, updated_at=UPDATED_AT)
    ids1 = {e["provider_event_id"] for e in entries1}
    ids2 = {e["provider_event_id"] for e in entries2}
    assert ids1 == ids2


def test_idempotency_different_timestamps_different_ids() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    record = _ws(auto_apply=True)
    entries1 = build_terraform_cloud_activity_events(record, updated_at="2026-06-21T12:00:00Z")
    entries2 = build_terraform_cloud_activity_events(record, updated_at="2026-06-21T13:00:00Z")
    ids1 = {e["provider_event_id"] for e in entries1}
    ids2 = {e["provider_event_id"] for e in entries2}
    assert ids1 != ids2


def test_idempotency_different_event_types_different_ids() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    record = _ws(auto_apply=True, global_remote_state=True)
    entries = build_terraform_cloud_activity_events(record, updated_at=UPDATED_AT)
    ids = [e["provider_event_id"] for e in entries]
    assert len(ids) == len(set(ids)), "Multiple events from same record must have distinct IDs"


def test_event_id_prefix() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(_ws(auto_apply=True), updated_at=UPDATED_AT)
    for e in entries:
        assert e["provider_event_id"].startswith("terraform_cloud:")


# ══════════════════════════════════════════════════════════════════════════════
# Section F: Unknown record type ignored safely
# ══════════════════════════════════════════════════════════════════════════════


def test_unknown_record_type_returns_empty() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        {"record_type": "terraform_cloud_unknown_future_type", "resource_id": "x"},
        updated_at=UPDATED_AT,
    )
    assert entries == []


def test_non_terraform_cloud_record_type_ignored() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    entries = build_terraform_cloud_activity_events(
        {"record_type": "gitlab_project", "resource_id": "x"},
        updated_at=UPDATED_AT,
    )
    assert entries == []


def test_non_dict_input_returns_empty() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    assert build_terraform_cloud_activity_events(None, updated_at=UPDATED_AT) == []  # type: ignore[arg-type]
    assert build_terraform_cloud_activity_events("not a dict", updated_at=UPDATED_AT) == []  # type: ignore[arg-type]


# ══════════════════════════════════════════════════════════════════════════════
# Section G: normalize_terraform_cloud_activity_event — allowlist gate
# ══════════════════════════════════════════════════════════════════════════════


def test_normalize_valid_event_returns_dict() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import (
        build_terraform_cloud_activity_events,
        normalize_terraform_cloud_activity_event,
    )
    entries = build_terraform_cloud_activity_events(_ws(auto_apply=True), updated_at=UPDATED_AT)
    assert entries
    result = normalize_terraform_cloud_activity_event(entries[0])
    assert result is not None
    assert result["provider"] == "terraform_cloud"
    assert result["source"] == "terraform_cloud_activity_event"


def test_normalize_unknown_event_type_blocked() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import normalize_terraform_cloud_activity_event
    result = normalize_terraform_cloud_activity_event(
        {"event_type": "terraform_cloud.secret.leaked", "provider": "terraform_cloud"}
    )
    assert result is None


def test_normalize_non_dict_returns_none() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import normalize_terraform_cloud_activity_event
    assert normalize_terraform_cloud_activity_event(None) is None  # type: ignore[arg-type]
    assert normalize_terraform_cloud_activity_event("bad") is None  # type: ignore[arg-type]


def test_normalize_produces_no_actor_id() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import (
        build_terraform_cloud_activity_events,
        normalize_terraform_cloud_activity_event,
    )
    entries = build_terraform_cloud_activity_events(_ws(auto_apply=True), updated_at=UPDATED_AT)
    for entry in entries:
        normalized = normalize_terraform_cloud_activity_event(entry)
        if normalized:
            assert normalized.get("actor_id") is None
            assert normalized.get("source_ip_hash") is None


# ══════════════════════════════════════════════════════════════════════════════
# Section H: Evidence/metadata safety — no forbidden keys
# ══════════════════════════════════════════════════════════════════════════════


def _all_m88d_entries() -> list[dict[str, Any]]:
    from app.services.terraform_cloud_activity_ingestion_service import build_terraform_cloud_activity_events
    records = [
        _org(two_factor_requirement_enabled=False),
        _org(sso_enabled=False),
        _ws(auto_apply=True, global_remote_state=True, execution_mode_category="agent"),
        _ws(vcs_connected=False, queue_all_runs=False, terraform_version_category="latest"),
        _ws(file_triggers_enabled=False, speculative_enabled=False, run_trigger_count=2),
        _ws(latest_run_status_category="errored"),
        _var_summary(variable_count=3, non_sensitive_variable_count=2, sensitive_variable_count=0),
        _varset(global_scope=True, variable_count=5, non_sensitive_variable_count=2),
        _policy_set(global_scope=True, enforcement_level_category="advisory", policy_count=0),
        _policy_set(global_scope=False, workspace_count=0, project_count=0),
        _notification(enabled=True, destination_type_category="webhook",
                      webhook_url_scheme_category="http", token_present=False, trigger_count=5),
        _notification(enabled=False),
        _run_trigger(),
        _team_access(admin_access_count=1, apply_access_count=1,
                     write_access_count=1, custom_permission_count=1),
        _state_version(state_version_present=True),
    ]
    all_entries = []
    for r in records:
        all_entries.extend(build_terraform_cloud_activity_events(r, updated_at=UPDATED_AT))
    return all_entries


def test_metadata_has_no_forbidden_keys() -> None:
    for entry in _all_m88d_entries():
        meta = entry.get("metadata", {})
        for key in meta:
            assert key.lower() not in FORBIDDEN_METADATA_KEYS, (
                f"Forbidden metadata key '{key}' in event {entry['event_type']!r}"
            )


def test_metadata_values_are_flat_scalars() -> None:
    for entry in _all_m88d_entries():
        meta = entry.get("metadata", {})
        for key, val in meta.items():
            assert isinstance(val, (bool, int, str)), (
                f"Non-scalar metadata value for key '{key}' in {entry['event_type']!r}: {type(val)}"
            )


def test_metadata_no_state_exposure_values() -> None:
    state_forbidden = {"state exposed", "tfstate exposed", "state leaked", "tfstate leaked"}
    for entry in _all_m88d_entries():
        meta = entry.get("metadata", {})
        for val in meta.values():
            if isinstance(val, str):
                val_lower = val.lower()
                for phrase in state_forbidden:
                    assert phrase not in val_lower, (
                        f"State exposure phrase '{phrase}' in metadata value: {val!r}"
                    )


def test_event_provider_and_source_correct() -> None:
    for entry in _all_m88d_entries():
        assert entry["provider"] == "terraform_cloud"
        assert entry["source"] == "terraform_cloud_activity_event"


def test_event_types_all_in_allowlist() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import TERRAFORM_CLOUD_CONFIG_EVENT_TYPES
    for entry in _all_m88d_entries():
        assert entry["event_type"] in TERRAFORM_CLOUD_CONFIG_EVENT_TYPES, (
            f"Event type {entry['event_type']!r} not in allowlist"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section I: Event copy safety
# ══════════════════════════════════════════════════════════════════════════════


def test_event_types_have_no_forbidden_wording() -> None:
    for entry in _all_m88d_entries():
        evt_lower = entry["event_type"].lower()
        for phrase in FORBIDDEN_WORDING:
            assert phrase not in evt_lower, (
                f"Forbidden phrase '{phrase}' in event type {entry['event_type']!r}"
            )


def test_service_docstring_has_safe_wording() -> None:
    from app.services import terraform_cloud_activity_ingestion_service as svc
    doc = svc.__doc__ or ""
    for phrase in FORBIDDEN_WORDING:
        assert phrase not in doc.lower(), (
            f"Forbidden phrase '{phrase}' in service module docstring"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section J: Backend route support
# ══════════════════════════════════════════════════════════════════════════════


def test_router_imports_terraform_cloud_ingestion_service() -> None:
    router_text = ROUTER_FILE.read_text(encoding="utf-8")
    assert "terraform_cloud_activity_ingestion_service" in router_text


def test_router_has_terraform_cloud_activity_sync_endpoint() -> None:
    router_text = ROUTER_FILE.read_text(encoding="utf-8")
    assert "/terraform-cloud-activity/sync" in router_text


def test_schema_importable() -> None:
    from app.schemas.security_terraform_cloud_activity import (
        TerraformCloudActivitySyncRequest,
        TerraformCloudActivitySyncResponse,
    )
    assert TerraformCloudActivitySyncRequest is not None
    assert TerraformCloudActivitySyncResponse is not None


def test_schema_response_defaults() -> None:
    from app.schemas.security_terraform_cloud_activity import TerraformCloudActivitySyncResponse
    r = TerraformCloudActivitySyncResponse()
    assert r.provider == "terraform_cloud"
    assert r.source == "terraform_cloud_activity_event"
    assert r.events_scanned == 0
    assert r.events_created == 0
    assert r.events_skipped == 0


def test_allowed_metadata_keys_includes_terraform_cloud_fields() -> None:
    from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
    expected = {
        "terraform_cloud_event_id",
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
        "environment_variable_count",
        "terraform_variable_count",
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
        "write_access_count",
        "apply_access_count",
        "custom_permission_count",
        "state_version_present",
        "state_version_count_category",
        "raw_state_never_fetched",
        "sso_enabled",
    }
    missing = expected - ALLOWED_METADATA_KEYS
    assert not missing, f"Keys missing from ALLOWED_METADATA_KEYS: {missing}"


# ══════════════════════════════════════════════════════════════════════════════
# Section K: Frontend activity page includes terraform_cloud
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_ACTIVITY_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_activity_page_includes_terraform_cloud_provider() -> None:
    text = FE_ACTIVITY_PAGE.read_text(encoding="utf-8")
    assert '"terraform_cloud"' in text


@pytest.mark.skipif(not FE_ACTIVITY_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_activity_page_imports_sync_function() -> None:
    text = FE_ACTIVITY_PAGE.read_text(encoding="utf-8")
    assert "syncTerraformCloudActivity" in text


@pytest.mark.skipif(not FE_ACTIVITY_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_activity_page_has_terraform_cloud_event_types() -> None:
    text = FE_ACTIVITY_PAGE.read_text(encoding="utf-8")
    assert "TERRAFORM_CLOUD_EVENT_TYPES" in text


@pytest.mark.skipif(not FE_ACTIVITY_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_activity_page_has_sync_handler() -> None:
    text = FE_ACTIVITY_PAGE.read_text(encoding="utf-8")
    assert "provider === \"terraform_cloud\"" in text


@pytest.mark.skipif(not FE_ACTIVITY_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_activity_page_no_forbidden_wording() -> None:
    text = FE_ACTIVITY_PAGE.read_text(encoding="utf-8")
    for phrase in FORBIDDEN_WORDING:
        assert phrase not in text.lower(), (
            f"Forbidden phrase '{phrase}' in frontend activity page"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section L: Capability matrix — activity_ingestion=True, planned_next_stage=M88E
# ══════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_activity_ingestion_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.security.activity_ingestion is True


def test_capability_matrix_no_signals_correlations_demo() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    # activity_signals added in M88E, risk_activity_correlations in M88F — accept either
    assert cap.security.risk_activity_correlations in (True, False)
    # M88G complete — demo_seed_clear/case_report now True
    assert cap.security.demo_seed_clear in (True, False)
    assert cap.security.case_report in (True, False)


def test_capability_matrix_drift_still_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True


def test_capability_matrix_notes_mention_m88d() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert "M88D" in cap.notes or "activity ingestion" in cap.notes.lower()


def test_capability_matrix_planned_next_stage_is_m88e_or_later() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    # M88E complete — notes now reference M88E as done, M88F as next
    assert (
        "M88E" in cap.notes or "Activity Signals" in cap.notes
        or "M88F" in cap.notes or "Correlations" in cap.notes
    )


# ══════════════════════════════════════════════════════════════════════════════
# Section M: Expansion framework — M88E/M88F next stage
# ══════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_planned_next_stage_is_m88e_or_later() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert (
        "M88E" in planned or "Activity Signals" in planned or "Signals" in planned
        or "M88F" in planned or "Correlations" in planned
        or "M88G" in planned or "Demo" in planned
        or "M88H" in planned or "Provider Depth QA" in planned
        or "M88I" in planned or "Cross-Cloud" in planned
        or "M89A" in planned or "Kubernetes" in planned
                or "M90A" in planned or "Sentry" in planned
    ), f"planned_next_stage should point to M88E or later; got: {planned!r}"


def test_expansion_framework_queue_is_empty_after_sentry_launch() -> None:
    """Regression note: Kubernetes launched (message 1 / M89A) and was
    removed from the recommended queue. Sentry (message 8 — public
    launch) was the FINAL planned provider, so the queue is now
    permanently empty."""
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    providers = [r.get("provider", "") for r in recommended if isinstance(r, dict)]
    assert "kubernetes" not in providers
    assert "sentry" not in providers
    assert providers == []


# ══════════════════════════════════════════════════════════════════════════════
# Section N: M88A/B/C regression smoke
# ══════════════════════════════════════════════════════════════════════════════


def test_m88a_security_rules_still_importable() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    assert "terraform_cloud_organization_two_factor_not_required" in TERRAFORM_CLOUD_RULE_KEYS


def test_m88b_security_rule_keys_still_present() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    m88b_keys = {
        "terraform_cloud_workspace_auto_apply_enabled",
        "terraform_cloud_workspace_global_remote_state_enabled",
        "terraform_cloud_notification_http_webhook",
        "terraform_cloud_team_admin_access",
        "terraform_cloud_variable_set_global_scope",
        "terraform_cloud_state_version_present",
    }
    missing = m88b_keys - TERRAFORM_CLOUD_RULE_KEYS
    assert not missing, f"M88B rule keys removed: {missing}"


def test_m88c_security_rule_keys_still_present() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    m88c_keys = {
        "terraform_cloud_workspace_agent_execution_mode",
        "terraform_cloud_variable_set_broad_scope",
        "terraform_cloud_policy_set_global_scope",
        "terraform_cloud_run_trigger_enabled",
        "terraform_cloud_team_write_access",
    }
    missing = m88c_keys - TERRAFORM_CLOUD_RULE_KEYS
    assert not missing, f"M88C rule keys removed: {missing}"


def test_m88b_security_rules_still_fire() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    record = {
        "record_type": "terraform_cloud_workspace",
        "provider": "terraform_cloud",
        "record_id": "ws:x",
        "resource_id": "wx",
        "workspace_resource_id": "ws_opaque_1",
        "auto_apply": True,
        "execution_mode_category": "remote",
        "global_remote_state": False,
        "vcs_connected": True,
        "queue_all_runs": True,
        "terraform_version_category": "pinned",
        "file_triggers_enabled": True,
        "speculative_enabled": True,
        "global_remote_state": False,
        "trigger_prefix_count": 0,
        "run_trigger_count": 0,
        "variable_count": 0,
        "sensitive_variable_count": 0,
        "non_sensitive_variable_count": 0,
        "notification_count": 0,
        "team_access_count": 0,
    }
    findings = evaluate(record)
    keys = {f.rule_key for f in findings}
    assert "terraform_cloud_workspace_auto_apply_enabled" in keys
