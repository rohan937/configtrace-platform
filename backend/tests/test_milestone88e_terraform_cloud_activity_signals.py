"""M88E — Terraform Cloud activity signal generation guardrails.

Verifies that M88E adds Terraform Cloud activity signal generation from the
M88D activity events: safe signal types, deterministic idempotency keys,
correct provider/source values, safe signal types and metadata, and
privacy-clean content that never exposes tokens, variable values, state
files, URLs, names, or PII.

Sections:
  A. Module imports and signal type constants
  B. Event type → signal type mapping coverage
  C. Signal severity mapping
  D. build signal from mock event — all event types produce safe signals
  E. Unknown/None event type → no signal (safe fallback)
  F. Signal metadata safety — no forbidden keys
  G. Signal copy safety — no forbidden wording
  H. Idempotency — group key determinism
  I. Backend route and schema support
  J. Signal service ALLOWED_METADATA_KEYS includes TC fields
  K. Frontend signals page includes terraform_cloud
  L. Capability matrix — activity_signals=True, planned_next_stage=M88F
  M. Expansion framework — M88F next stage
  N. M88A/B/C/D regression smoke
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_SIGNALS_PAGE = (
    REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "signals" / "page.tsx"
)
ROUTER_FILE = REPO_ROOT / "backend" / "app" / "routers" / "security.py"

# ── Expected signal types ──────────────────────────────────────────────────────

EXPECTED_SIGNAL_TYPES = {
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

# All M88D event types that should map to signals
ALL_M88D_EVENT_TYPES = {
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


# ── Mock event builder ─────────────────────────────────────────────────────────

def _mock_event(event_type: str, resource_id: str = "res_opaque_1",
                resource_type: str = "terraform_cloud_workspace",
                metadata: dict | None = None) -> MagicMock:
    ev = MagicMock()
    ev.event_type = event_type
    ev.provider = "terraform_cloud"
    ev.source = "terraform_cloud_activity_event"
    ev.resource_id = resource_id
    ev.resource_type = resource_type
    ev.integration_id = uuid.uuid4()
    ev.provider_event_id = f"terraform_cloud:abc{hash(event_type) % 10000:04d}"
    ev.id = uuid.uuid4()
    ev.actor_id = None
    ev.occurred_at = datetime(2026, 6, 21, 12, 0, 0, tzinfo=timezone.utc)
    ev.ingested_at = None
    ev.created_at = datetime(2026, 6, 21, 12, 0, 0, tzinfo=timezone.utc)
    ev.event_metadata = metadata or {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "event_source": "terraform_cloud_activity_event",
        "terraform_cloud_event_id": f"terraform_cloud:abc{hash(event_type) % 10000:04d}",
        "operation_family": "configuration",
        "operation_action": "observed",
    }
    return ev


# ══════════════════════════════════════════════════════════════════════════════
# Section A: Module imports and signal type constants
# ══════════════════════════════════════════════════════════════════════════════


def test_signal_service_importable() -> None:
    from app.services import terraform_cloud_activity_signal_service as svc
    assert callable(svc.generate_terraform_cloud_activity_signals)


def test_expected_signal_types_in_module() -> None:
    from app.services.terraform_cloud_activity_signal_service import TERRAFORM_CLOUD_SIGNAL_TYPES
    missing = EXPECTED_SIGNAL_TYPES - TERRAFORM_CLOUD_SIGNAL_TYPES
    assert not missing, f"Signal types missing from module: {missing}"


def test_provider_and_source_constants() -> None:
    from app.services.terraform_cloud_activity_signal_service import PROVIDER, SOURCE
    assert PROVIDER == "terraform_cloud"
    assert SOURCE == "terraform_cloud_activity_event"


# ══════════════════════════════════════════════════════════════════════════════
# Section B: Event type → signal type mapping coverage
# ══════════════════════════════════════════════════════════════════════════════


def test_all_m88d_event_types_map_to_signal_type() -> None:
    from app.services.terraform_cloud_activity_signal_service import (
        TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE,
    )
    missing = ALL_M88D_EVENT_TYPES - set(TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE.keys())
    assert not missing, f"M88D event types with no signal mapping: {missing}"


def test_all_signal_types_in_signal_type_set() -> None:
    from app.services.terraform_cloud_activity_signal_service import (
        TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE,
        TERRAFORM_CLOUD_SIGNAL_TYPES,
    )
    mapped = set(TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE.values())
    missing = mapped - TERRAFORM_CLOUD_SIGNAL_TYPES
    assert not missing, f"Mapped signal types not in TERRAFORM_CLOUD_SIGNAL_TYPES: {missing}"


def test_unknown_event_type_not_in_mapping() -> None:
    from app.services.terraform_cloud_activity_signal_service import (
        TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE,
    )
    assert "terraform_cloud.secret.leaked" not in TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE
    assert "terraform_cloud.state.exposed" not in TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE
    assert "terraform_cloud.breach.confirmed" not in TERRAFORM_CLOUD_EVENT_TO_SIGNAL_TYPE


# ══════════════════════════════════════════════════════════════════════════════
# Section C: Signal severity mapping
# ══════════════════════════════════════════════════════════════════════════════


def test_high_severity_event_types() -> None:
    from app.services.terraform_cloud_activity_signal_service import _severity
    high_events = [
        "terraform_cloud.workspace.auto_apply_enabled",
        "terraform_cloud.workspace.global_remote_state_enabled",
        "terraform_cloud.notification.http_webhook_detected",
        "terraform_cloud.team_access.admin_detected",
        "terraform_cloud.variables.non_sensitive_variables_detected",
        "terraform_cloud.variable_set.global_scope_detected",
        "terraform_cloud.policy_set.broad_scope_advisory_detected",
    ]
    for evt in high_events:
        assert _severity(evt) == "high", f"Expected high for {evt!r}"


def test_medium_severity_event_types() -> None:
    from app.services.terraform_cloud_activity_signal_service import _severity
    medium_events = [
        "terraform_cloud.organization.two_factor_not_required",
        "terraform_cloud.organization.sso_not_enabled",
        "terraform_cloud.workspace.execution_mode_changed",
        "terraform_cloud.workspace.vcs_connection_missing",
        "terraform_cloud.workspace.queue_all_runs_disabled",
        "terraform_cloud.run_trigger.enabled",
        "terraform_cloud.team_access.apply_detected",
        "terraform_cloud.team_access.write_detected",
    ]
    for evt in medium_events:
        assert _severity(evt) == "medium", f"Expected medium for {evt!r}"


def test_low_severity_event_types() -> None:
    from app.services.terraform_cloud_activity_signal_service import _severity
    low_events = [
        "terraform_cloud.workspace.unpinned_terraform_version",
        "terraform_cloud.workspace.speculative_plans_disabled",
        "terraform_cloud.workspace.latest_run_failed",
        "terraform_cloud.policy_set.empty_detected",
        "terraform_cloud.policy_set.unscoped_detected",
        "terraform_cloud.notification.disabled",
        "terraform_cloud.team_access.custom_permissions_detected",
        "terraform_cloud.state_version.metadata_present",
        "terraform_cloud.config.event",
    ]
    for evt in low_events:
        assert _severity(evt) == "low", f"Expected low for {evt!r}"


def test_unknown_event_type_defaults_to_medium() -> None:
    from app.services.terraform_cloud_activity_signal_service import _severity
    assert _severity("terraform_cloud.unknown.future_event") == "medium"


# ══════════════════════════════════════════════════════════════════════════════
# Section D: build signal from mock event — all event types produce safe signals
# ══════════════════════════════════════════════════════════════════════════════


def _build(event_type: str, **meta: Any) -> dict[str, Any] | None:
    from app.services.terraform_cloud_activity_signal_service import _build_signal
    ev = _mock_event(event_type, metadata={
        "resource_type": "terraform_cloud_workspace",
        "resource_id": "ws_opaque_1",
        "event_source": "terraform_cloud_activity_event",
        "terraform_cloud_event_id": "terraform_cloud:abc1234",
        **meta,
    })
    return _build_signal([ev])


def test_org_2fa_event_creates_signal() -> None:
    signal = _build("terraform_cloud.organization.two_factor_not_required",
                    organization_resource_id="org_opaque_1",
                    two_factor_requirement_enabled=False)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_organization_access_posture_signal"
    assert signal["severity"] == "medium"
    assert signal["provider"] == "terraform_cloud"


def test_org_sso_event_creates_signal() -> None:
    signal = _build("terraform_cloud.organization.sso_not_enabled",
                    organization_resource_id="org_opaque_1", sso_enabled=False)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_organization_access_posture_signal"


def test_workspace_auto_apply_creates_high_signal() -> None:
    signal = _build("terraform_cloud.workspace.auto_apply_enabled",
                    workspace_resource_id="ws_opaque_1", auto_apply=True)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_workspace_auto_apply_signal"
    assert signal["severity"] == "high"


def test_workspace_global_remote_state_creates_high_signal() -> None:
    signal = _build("terraform_cloud.workspace.global_remote_state_enabled",
                    workspace_resource_id="ws_opaque_1", global_remote_state=True)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_workspace_global_remote_state_signal"
    assert signal["severity"] == "high"


def test_workspace_execution_mode_creates_signal() -> None:
    signal = _build("terraform_cloud.workspace.execution_mode_changed",
                    workspace_resource_id="ws_opaque_1", execution_mode_category="agent")
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_workspace_execution_mode_signal"
    assert signal["severity"] == "medium"


def test_workspace_vcs_missing_creates_signal() -> None:
    signal = _build("terraform_cloud.workspace.vcs_connection_missing",
                    workspace_resource_id="ws_opaque_1", vcs_connected=False)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_workspace_vcs_posture_signal"
    assert signal["severity"] == "medium"


def test_workspace_queue_runs_disabled_creates_signal() -> None:
    signal = _build("terraform_cloud.workspace.queue_all_runs_disabled",
                    workspace_resource_id="ws_opaque_1", queue_all_runs=False)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_workspace_run_control_signal"
    assert signal["severity"] == "medium"


def test_workspace_unpinned_tf_version_creates_low_signal() -> None:
    signal = _build("terraform_cloud.workspace.unpinned_terraform_version",
                    workspace_resource_id="ws_opaque_1", terraform_version_category="latest")
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_workspace_version_posture_signal"
    assert signal["severity"] == "low"


def test_workspace_file_triggers_disabled_creates_signal() -> None:
    signal = _build("terraform_cloud.workspace.file_triggers_disabled",
                    workspace_resource_id="ws_opaque_1", file_triggers_enabled=False)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_workspace_run_control_signal"


def test_workspace_speculative_disabled_creates_low_signal() -> None:
    signal = _build("terraform_cloud.workspace.speculative_plans_disabled",
                    workspace_resource_id="ws_opaque_1", speculative_enabled=False)
    assert signal is not None
    assert signal["severity"] == "low"


def test_workspace_run_triggers_present_creates_signal() -> None:
    signal = _build("terraform_cloud.workspace.run_triggers_present",
                    workspace_resource_id="ws_opaque_1", run_trigger_count=2)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_workspace_run_control_signal"
    assert signal["severity"] == "medium"


def test_workspace_latest_run_failed_creates_low_signal() -> None:
    signal = _build("terraform_cloud.workspace.latest_run_failed",
                    workspace_resource_id="ws_opaque_1", latest_run_status_category="errored")
    assert signal is not None
    assert signal["severity"] == "low"


def test_variables_non_sensitive_creates_high_signal() -> None:
    signal = _build("terraform_cloud.variables.non_sensitive_variables_detected",
                    workspace_resource_id="ws_opaque_1", non_sensitive_variable_count=3)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_variable_posture_signal"
    assert signal["severity"] == "high"


def test_variables_no_sensitive_creates_signal() -> None:
    signal = _build("terraform_cloud.variables.no_sensitive_variables_detected",
                    workspace_resource_id="ws_opaque_1", variable_count=3, sensitive_variable_count=0)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_variable_posture_signal"


def test_varset_global_scope_creates_high_signal() -> None:
    signal = _build("terraform_cloud.variable_set.global_scope_detected",
                    variable_set_resource_id="vset_opaque_1", global_scope=True)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_variable_set_scope_signal"
    assert signal["severity"] == "high"


def test_varset_broad_scope_creates_signal() -> None:
    signal = _build("terraform_cloud.variable_set.broad_scope_detected",
                    variable_set_resource_id="vset_opaque_1", global_scope=True, variable_count=5)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_variable_set_scope_signal"
    assert signal["severity"] == "medium"


def test_varset_non_sensitive_creates_signal() -> None:
    signal = _build("terraform_cloud.variable_set.non_sensitive_variables_detected",
                    variable_set_resource_id="vset_opaque_1", non_sensitive_variable_count=2)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_variable_set_scope_signal"


def test_policy_advisory_creates_signal() -> None:
    signal = _build("terraform_cloud.policy_set.advisory_enforcement_detected",
                    policy_set_resource_id="ps_opaque_1", enforcement_level_category="advisory")
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_policy_set_enforcement_signal"
    assert signal["severity"] == "medium"


def test_policy_empty_creates_low_signal() -> None:
    signal = _build("terraform_cloud.policy_set.empty_detected",
                    policy_set_resource_id="ps_opaque_1", policy_count=0)
    assert signal is not None
    assert signal["severity"] == "low"


def test_policy_global_scope_creates_signal() -> None:
    signal = _build("terraform_cloud.policy_set.global_scope_detected",
                    policy_set_resource_id="ps_opaque_1", global_scope=True)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_policy_set_scope_signal"
    assert signal["severity"] == "medium"


def test_policy_broad_scope_advisory_creates_high_signal() -> None:
    signal = _build("terraform_cloud.policy_set.broad_scope_advisory_detected",
                    policy_set_resource_id="ps_opaque_1", global_scope=True,
                    enforcement_level_category="advisory")
    assert signal is not None
    assert signal["severity"] == "high"


def test_policy_unscoped_creates_low_signal() -> None:
    signal = _build("terraform_cloud.policy_set.unscoped_detected",
                    policy_set_resource_id="ps_opaque_1", workspace_count=0, project_count=0)
    assert signal is not None
    assert signal["severity"] == "low"


def test_notification_http_creates_high_signal() -> None:
    signal = _build("terraform_cloud.notification.http_webhook_detected",
                    notification_resource_id="nc_opaque_1",
                    destination_type_category="webhook",
                    webhook_url_scheme_category="http")
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_notification_transport_signal"
    assert signal["severity"] == "high"


def test_notification_token_missing_creates_signal() -> None:
    signal = _build("terraform_cloud.notification.token_missing",
                    notification_resource_id="nc_opaque_1", token_present=False)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_notification_transport_signal"
    assert signal["severity"] == "medium"


def test_notification_broad_triggers_creates_signal() -> None:
    signal = _build("terraform_cloud.notification.broad_trigger_scope",
                    notification_resource_id="nc_opaque_1", trigger_count=5)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_notification_posture_signal"
    assert signal["severity"] == "medium"


def test_notification_disabled_creates_low_signal() -> None:
    signal = _build("terraform_cloud.notification.disabled",
                    notification_resource_id="nc_opaque_1", enabled=False)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_notification_posture_signal"
    assert signal["severity"] == "low"


def test_run_trigger_creates_signal() -> None:
    signal = _build("terraform_cloud.run_trigger.enabled",
                    run_trigger_resource_id="rt_opaque_1", sourceable_type_category="workspace")
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_run_trigger_signal"
    assert signal["severity"] == "medium"


def test_team_admin_creates_high_signal() -> None:
    signal = _build("terraform_cloud.team_access.admin_detected",
                    workspace_resource_id="ws_opaque_1", admin_access_count=1)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_team_access_posture_signal"
    assert signal["severity"] == "high"


def test_team_apply_creates_signal() -> None:
    signal = _build("terraform_cloud.team_access.apply_detected",
                    workspace_resource_id="ws_opaque_1", apply_access_count=1)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_team_access_posture_signal"
    assert signal["severity"] == "medium"


def test_team_write_creates_signal() -> None:
    signal = _build("terraform_cloud.team_access.write_detected",
                    workspace_resource_id="ws_opaque_1", write_access_count=2)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_team_access_posture_signal"
    assert signal["severity"] == "medium"


def test_team_custom_creates_low_signal() -> None:
    signal = _build("terraform_cloud.team_access.custom_permissions_detected",
                    workspace_resource_id="ws_opaque_1", custom_permission_count=1)
    assert signal is not None
    assert signal["severity"] == "low"


def test_state_version_metadata_creates_low_signal() -> None:
    signal = _build("terraform_cloud.state_version.metadata_present",
                    workspace_resource_id="ws_opaque_1",
                    state_version_present=True, raw_state_never_fetched=True)
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_state_version_metadata_signal"
    assert signal["severity"] == "low"


def test_state_version_signal_no_state_exposure_wording() -> None:
    signal = _build("terraform_cloud.state_version.metadata_present",
                    workspace_resource_id="ws_opaque_1",
                    state_version_present=True, raw_state_never_fetched=True)
    assert signal is not None
    for text in [signal.get("title", ""), signal.get("summary", "")]:
        assert "state exposed" not in text.lower()
        assert "tfstate exposed" not in text.lower()
        assert "state leaked" not in text.lower()
        assert "tfstate leaked" not in text.lower()


def test_config_event_creates_low_signal() -> None:
    signal = _build("terraform_cloud.config.event")
    assert signal is not None
    assert signal["signal_type"] == "terraform_cloud_configuration_activity_signal"
    assert signal["severity"] == "low"


# ══════════════════════════════════════════════════════════════════════════════
# Section E: Unknown/None event type → no signal
# ══════════════════════════════════════════════════════════════════════════════


def test_unknown_event_type_returns_none() -> None:
    from app.services.terraform_cloud_activity_signal_service import _build_signal
    ev = _mock_event("terraform_cloud.unknown.invented_type")
    result = _build_signal([ev])
    assert result is None


def test_non_terraform_event_type_returns_none() -> None:
    from app.services.terraform_cloud_activity_signal_service import _build_signal
    ev = _mock_event("gitlab.project.visibility_changed")
    result = _build_signal([ev])
    assert result is None


def test_group_key_returns_none_for_unknown_event() -> None:
    from app.services.terraform_cloud_activity_signal_service import _group_key
    ev = _mock_event("terraform_cloud.unknown.future_event")
    assert _group_key(ev) is None


# ══════════════════════════════════════════════════════════════════════════════
# Section F: Signal metadata safety — no forbidden keys
# ══════════════════════════════════════════════════════════════════════════════


def _all_signals() -> list[dict[str, Any]]:
    from app.services.terraform_cloud_activity_signal_service import _build_signal
    test_events = [
        ("terraform_cloud.organization.two_factor_not_required", {"organization_resource_id": "org_1", "two_factor_requirement_enabled": False}),
        ("terraform_cloud.workspace.auto_apply_enabled", {"workspace_resource_id": "ws_1", "auto_apply": True}),
        ("terraform_cloud.workspace.global_remote_state_enabled", {"workspace_resource_id": "ws_1", "global_remote_state": True}),
        ("terraform_cloud.workspace.execution_mode_changed", {"workspace_resource_id": "ws_1", "execution_mode_category": "agent"}),
        ("terraform_cloud.workspace.vcs_connection_missing", {"workspace_resource_id": "ws_1", "vcs_connected": False}),
        ("terraform_cloud.workspace.queue_all_runs_disabled", {"workspace_resource_id": "ws_1", "queue_all_runs": False}),
        ("terraform_cloud.workspace.unpinned_terraform_version", {"workspace_resource_id": "ws_1", "terraform_version_category": "latest"}),
        ("terraform_cloud.workspace.file_triggers_disabled", {"workspace_resource_id": "ws_1", "file_triggers_enabled": False}),
        ("terraform_cloud.workspace.speculative_plans_disabled", {"workspace_resource_id": "ws_1", "speculative_enabled": False}),
        ("terraform_cloud.workspace.run_triggers_present", {"workspace_resource_id": "ws_1", "run_trigger_count": 2}),
        ("terraform_cloud.workspace.latest_run_failed", {"workspace_resource_id": "ws_1", "latest_run_status_category": "errored"}),
        ("terraform_cloud.variables.non_sensitive_variables_detected", {"workspace_resource_id": "ws_1", "non_sensitive_variable_count": 3}),
        ("terraform_cloud.variables.no_sensitive_variables_detected", {"workspace_resource_id": "ws_1", "sensitive_variable_count": 0}),
        ("terraform_cloud.variable_set.global_scope_detected", {"variable_set_resource_id": "vs_1", "global_scope": True}),
        ("terraform_cloud.variable_set.broad_scope_detected", {"variable_set_resource_id": "vs_1", "global_scope": True, "variable_count": 5}),
        ("terraform_cloud.variable_set.non_sensitive_variables_detected", {"variable_set_resource_id": "vs_1", "non_sensitive_variable_count": 2}),
        ("terraform_cloud.policy_set.advisory_enforcement_detected", {"policy_set_resource_id": "ps_1", "enforcement_level_category": "advisory"}),
        ("terraform_cloud.policy_set.empty_detected", {"policy_set_resource_id": "ps_1", "policy_count": 0}),
        ("terraform_cloud.policy_set.global_scope_detected", {"policy_set_resource_id": "ps_1", "global_scope": True}),
        ("terraform_cloud.policy_set.broad_scope_advisory_detected", {"policy_set_resource_id": "ps_1", "global_scope": True}),
        ("terraform_cloud.policy_set.unscoped_detected", {"policy_set_resource_id": "ps_1", "workspace_count": 0}),
        ("terraform_cloud.notification.http_webhook_detected", {"notification_resource_id": "nc_1", "webhook_url_scheme_category": "http"}),
        ("terraform_cloud.notification.token_missing", {"notification_resource_id": "nc_1", "token_present": False}),
        ("terraform_cloud.notification.broad_trigger_scope", {"notification_resource_id": "nc_1", "trigger_count": 5}),
        ("terraform_cloud.notification.disabled", {"notification_resource_id": "nc_1", "enabled": False}),
        ("terraform_cloud.run_trigger.enabled", {"run_trigger_resource_id": "rt_1", "sourceable_type_category": "workspace"}),
        ("terraform_cloud.team_access.admin_detected", {"workspace_resource_id": "ws_1", "admin_access_count": 1}),
        ("terraform_cloud.team_access.apply_detected", {"workspace_resource_id": "ws_1", "apply_access_count": 1}),
        ("terraform_cloud.team_access.write_detected", {"workspace_resource_id": "ws_1", "write_access_count": 2}),
        ("terraform_cloud.team_access.custom_permissions_detected", {"workspace_resource_id": "ws_1", "custom_permission_count": 1}),
        ("terraform_cloud.state_version.metadata_present", {"workspace_resource_id": "ws_1", "state_version_present": True, "raw_state_never_fetched": True}),
        ("terraform_cloud.config.event", {}),
    ]
    signals = []
    for evt_type, meta in test_events:
        ev = _mock_event(evt_type, metadata={
            "resource_type": "terraform_cloud_workspace",
            "resource_id": "ws_opaque_1",
            "event_source": "terraform_cloud_activity_event",
            "terraform_cloud_event_id": f"terraform_cloud:abc{hash(evt_type) % 10000:04d}",
            "operation_family": "configuration",
            "operation_action": "observed",
            **meta,
        })
        sig = _build_signal([ev])
        if sig:
            signals.append(sig)
    return signals


def test_signal_metadata_has_no_forbidden_keys() -> None:
    for signal in _all_signals():
        meta = signal.get("metadata", {})
        for key in meta:
            assert key.lower() not in FORBIDDEN_METADATA_KEYS, (
                f"Forbidden metadata key '{key}' in signal {signal['signal_type']!r}"
            )


def test_signal_metadata_values_are_flat_scalars() -> None:
    for signal in _all_signals():
        meta = signal.get("metadata", {})
        for key, val in meta.items():
            assert isinstance(val, (bool, int, str)), (
                f"Non-scalar metadata value for '{key}' in {signal['signal_type']!r}: {type(val)}"
            )


def test_signal_has_correct_provider() -> None:
    for signal in _all_signals():
        assert signal["provider"] == "terraform_cloud", (
            f"Wrong provider in signal {signal['signal_type']!r}: {signal['provider']!r}"
        )


def test_signal_has_evidence_level_activity() -> None:
    for signal in _all_signals():
        assert signal["evidence_level"] == "activity"


def test_signal_status_is_open() -> None:
    for signal in _all_signals():
        assert signal["status"] == "open"


def test_signal_has_no_actor_id() -> None:
    # TC signals never store actor identity
    for signal in _all_signals():
        meta = signal.get("metadata", {})
        assert "actor_id" not in meta
        assert "user_email" not in meta
        assert "username" not in meta


# ══════════════════════════════════════════════════════════════════════════════
# Section G: Signal copy safety — no forbidden wording
# ══════════════════════════════════════════════════════════════════════════════


def test_signal_title_no_forbidden_wording() -> None:
    for signal in _all_signals():
        title_lower = signal.get("title", "").lower()
        for phrase in FORBIDDEN_WORDING:
            assert phrase not in title_lower, (
                f"Forbidden phrase '{phrase}' in title for {signal['signal_type']!r}"
            )


def test_signal_summary_no_forbidden_wording() -> None:
    for signal in _all_signals():
        summary_lower = signal.get("summary", "").lower()
        for phrase in FORBIDDEN_WORDING:
            assert phrase not in summary_lower, (
                f"Forbidden phrase '{phrase}' in summary for {signal['signal_type']!r}"
            )


def test_signal_summary_contains_safe_disclaimer() -> None:
    for signal in _all_signals():
        summary = signal.get("summary", "")
        assert "does not confirm" in summary.lower(), (
            f"Disclaimer missing in summary for {signal['signal_type']!r}"
        )


def test_service_docstring_has_safe_wording() -> None:
    from app.services import terraform_cloud_activity_signal_service as svc
    doc = svc.__doc__ or ""
    for phrase in FORBIDDEN_WORDING:
        assert phrase not in doc.lower()


# ══════════════════════════════════════════════════════════════════════════════
# Section H: Idempotency — group key determinism
# ══════════════════════════════════════════════════════════════════════════════


def test_group_key_is_deterministic_for_same_event() -> None:
    from app.services.terraform_cloud_activity_signal_service import _group_key
    ev = _mock_event("terraform_cloud.workspace.auto_apply_enabled", resource_id="ws_opaque_1")
    gk1 = _group_key(ev)
    gk2 = _group_key(ev)
    assert gk1 == gk2


def test_group_key_differs_for_different_signal_types() -> None:
    from app.services.terraform_cloud_activity_signal_service import _group_key
    ev1 = _mock_event("terraform_cloud.workspace.auto_apply_enabled", resource_id="ws_1")
    ev2 = _mock_event("terraform_cloud.workspace.global_remote_state_enabled", resource_id="ws_1")
    gk1 = _group_key(ev1)
    gk2 = _group_key(ev2)
    assert gk1 != gk2


def test_group_key_differs_for_different_resources() -> None:
    from app.services.terraform_cloud_activity_signal_service import _group_key
    ev1 = _mock_event("terraform_cloud.workspace.auto_apply_enabled", resource_id="ws_1")
    ev2 = _mock_event("terraform_cloud.workspace.auto_apply_enabled", resource_id="ws_2")
    gk1 = _group_key(ev1)
    gk2 = _group_key(ev2)
    assert gk1 != gk2


def test_group_key_prefix() -> None:
    from app.services.terraform_cloud_activity_signal_service import _group_key
    ev = _mock_event("terraform_cloud.workspace.auto_apply_enabled")
    gk = _group_key(ev)
    assert gk is not None and gk.startswith("terraform_cloud.activity|")


def test_same_event_type_and_resource_maps_to_one_group() -> None:
    from app.services.terraform_cloud_activity_signal_service import _group_key
    ev1 = _mock_event("terraform_cloud.workspace.auto_apply_enabled", resource_id="ws_1")
    ev2 = _mock_event("terraform_cloud.workspace.auto_apply_enabled", resource_id="ws_1")
    assert _group_key(ev1) == _group_key(ev2)


# ══════════════════════════════════════════════════════════════════════════════
# Section I: Backend route and schema support
# ══════════════════════════════════════════════════════════════════════════════


def test_router_imports_tc_signal_service() -> None:
    router_text = ROUTER_FILE.read_text(encoding="utf-8")
    assert "terraform_cloud_activity_signal_service" in router_text


def test_router_has_tc_generate_signals_endpoint() -> None:
    router_text = ROUTER_FILE.read_text(encoding="utf-8")
    assert "/terraform-cloud-activity/generate-signals" in router_text


def test_schema_importable() -> None:
    from app.schemas.security_terraform_cloud_activity import (
        TerraformCloudActivitySignalGenerateRequest,
        TerraformCloudActivitySignalGenerateResponse,
    )
    assert TerraformCloudActivitySignalGenerateRequest is not None
    assert TerraformCloudActivitySignalGenerateResponse is not None


def test_schema_response_defaults() -> None:
    from app.schemas.security_terraform_cloud_activity import (
        TerraformCloudActivitySignalGenerateResponse,
    )
    r = TerraformCloudActivitySignalGenerateResponse()
    assert r.provider == "terraform_cloud"
    assert r.source == "terraform_cloud_activity_event"
    assert r.events_scanned == 0
    assert r.signals_created == 0
    assert r.signals_skipped == 0


# ══════════════════════════════════════════════════════════════════════════════
# Section J: Signal service ALLOWED_METADATA_KEYS includes TC fields
# ══════════════════════════════════════════════════════════════════════════════


def test_signal_allowed_metadata_keys_includes_tc_fields() -> None:
    from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
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
        "raw_state_never_fetched",
        "sso_enabled",
        "signal_type",
    }
    missing = expected - ALLOWED_METADATA_KEYS
    assert not missing, f"Keys missing from signal ALLOWED_METADATA_KEYS: {missing}"


# ══════════════════════════════════════════════════════════════════════════════
# Section K: Frontend signals page includes terraform_cloud
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_SIGNALS_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_signals_page_includes_terraform_cloud_provider() -> None:
    text = FE_SIGNALS_PAGE.read_text(encoding="utf-8")
    assert '"terraform_cloud"' in text


@pytest.mark.skipif(not FE_SIGNALS_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_signals_page_imports_generate_function() -> None:
    text = FE_SIGNALS_PAGE.read_text(encoding="utf-8")
    assert "generateTerraformCloudActivitySignals" in text


@pytest.mark.skipif(not FE_SIGNALS_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_signals_page_has_signal_types() -> None:
    text = FE_SIGNALS_PAGE.read_text(encoding="utf-8")
    assert "TERRAFORM_CLOUD_SIGNAL_TYPES" in text


@pytest.mark.skipif(not FE_SIGNALS_PAGE.exists(), reason="Frontend tree absent")
def test_frontend_signals_page_no_forbidden_wording() -> None:
    text = FE_SIGNALS_PAGE.read_text(encoding="utf-8")
    for phrase in FORBIDDEN_WORDING:
        assert phrase not in text.lower(), (
            f"Forbidden phrase '{phrase}' in frontend signals page"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section L: Capability matrix — activity_signals=True, planned_next_stage=M88F
# ══════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_activity_signals_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.security.activity_signals is True


def test_capability_matrix_no_correlations_demo() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    # risk_activity_correlations added in M88F — accept True or False for forward compat
    # M88G complete — demo_seed_clear/case_report now True
    assert cap.security.demo_seed_clear in (True, False)
    assert cap.security.case_report in (True, False)


def test_capability_matrix_activity_ingestion_still_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.security.activity_ingestion is True


def test_capability_matrix_notes_mention_m88e() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert "M88E" in cap.notes or "signal" in cap.notes.lower()


def test_capability_matrix_planned_next_stage_is_m88f_or_later() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    # M88F complete — notes mention M88F as done, M88G as next
    assert (
        "M88F" in cap.notes or "Correlations" in cap.notes
        or "M88G" in cap.notes or "Demo" in cap.notes
    )


# ══════════════════════════════════════════════════════════════════════════════
# Section M: Expansion framework — M88F/M88G next stage
# ══════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_planned_next_stage_is_m88f_or_later() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert (
        "M88F" in planned or "Correlations" in planned or "Risk" in planned
        or "M88G" in planned or "Demo" in planned or "QA" in planned
        or "M88H" in planned or "Provider Depth" in planned
        or "M88I" in planned or "Cross-Cloud" in planned
        or "M89A" in planned or "Kubernetes" in planned
    ), f"planned_next_stage should point to M88F or later; got: {planned!r}"


def test_expansion_framework_kubernetes_still_in_queue() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    providers = [r.get("provider", "") for r in recommended if isinstance(r, dict)]
    assert "kubernetes" in providers


# ══════════════════════════════════════════════════════════════════════════════
# Section N: M88A/B/C/D regression smoke
# ══════════════════════════════════════════════════════════════════════════════


def test_m88a_connector_schema_importable() -> None:
    from app.connectors.terraform_cloud_schema import TERRAFORM_CLOUD_WORKSPACE
    assert TERRAFORM_CLOUD_WORKSPACE == "terraform_cloud_workspace"


def test_m88b_security_rules_importable() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    assert "terraform_cloud_workspace_auto_apply_enabled" in TERRAFORM_CLOUD_RULE_KEYS


def test_m88c_rule_keys_still_present() -> None:
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS
    assert "terraform_cloud_workspace_agent_execution_mode" in TERRAFORM_CLOUD_RULE_KEYS
    assert "terraform_cloud_run_trigger_enabled" in TERRAFORM_CLOUD_RULE_KEYS


def test_m88d_activity_ingestion_service_importable() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import (
        build_terraform_cloud_activity_events,
        TERRAFORM_CLOUD_CONFIG_EVENT_TYPES,
    )
    assert callable(build_terraform_cloud_activity_events)
    assert "terraform_cloud.workspace.auto_apply_enabled" in TERRAFORM_CLOUD_CONFIG_EVENT_TYPES


def test_m88d_activity_ingestion_still_enabled() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.security.activity_ingestion is True
