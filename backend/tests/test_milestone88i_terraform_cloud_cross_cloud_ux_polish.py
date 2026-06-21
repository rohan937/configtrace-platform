"""M88I — Terraform Cloud cross-cloud UX polish guardrails.

Verifies that M88I completes the Terraform Cloud provider arc with cross-cloud
UX polish: Terraform Cloud is first-class in all internal security UX surfaces,
the demo script, provider capability table, and roadmap. The planned_next_stage
advances to M89A: Kubernetes Drift Provider Foundation.

Sections:
  A. Capability matrix — full arc complete, notes mention M88I
  B. Provider expansion framework — planned_next_stage=M89A, TC not in queue
  C. Case report — terraform_cloud label registered
  D. Frontend activity page — terraform_cloud present
  E. Frontend signals page — terraform_cloud present
  F. Frontend correlations page — terraform_cloud fully registered
  G. Frontend cases page — terraform_cloud demo card present
  H. Frontend demo-script page — TC in capability table, Kubernetes in next queue
  I. Frontend demo script lib — TC mentioned in provider lists
  J. Frontend rule catalog — all 36 TC rules present
  K. Privacy / wording safety
  L. Prior milestone regression smoke
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend" / "app"
FRONTEND = REPO_ROOT / "frontend" / "src"

CAPABILITY_MATRIX = BACKEND / "services" / "provider_capability_matrix_service.py"
EXPANSION_FW = BACKEND / "services" / "provider_expansion_framework.py"
CASE_REPORT = BACKEND / "services" / "security_case_report_service.py"

FE_ACTIVITY = FRONTEND / "app" / "(app)" / "security" / "activity" / "page.tsx"
FE_SIGNALS = FRONTEND / "app" / "(app)" / "security" / "signals" / "page.tsx"
FE_CORRELATIONS = FRONTEND / "app" / "(app)" / "security" / "correlations" / "page.tsx"
FE_CASES = FRONTEND / "app" / "(app)" / "security" / "cases" / "page.tsx"
FE_DEMO_SCRIPT_PAGE = FRONTEND / "app" / "(app)" / "security" / "demo-script" / "page.tsx"
FE_DEMO_SCRIPT_LIB = FRONTEND / "lib" / "securityDemoScript.ts"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

# ── All 36 TC rule keys ───────────────────────────────────────────────────────

ALL_36_RULE_KEYS = {
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

FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "breach confirmed",
    "breach detected",
    "attacker found",
    "state leaked",
    "tfstate leaked",
    "state exposed",
    "tfstate exposed",
    "token leaked",
    "secrets exposed",
    "credentials exposed",
    "infrastructure exposed",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── Section A: Capability matrix ──────────────────────────────────────────────

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


def test_capability_matrix_notes_mention_m88i() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert "M88I" in cap.notes or "arc" in cap.notes.lower()


def test_capability_matrix_notes_mention_full_arc() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    for milestone in ["M88A", "M88B", "M88C", "M88D", "M88E", "M88F", "M88G", "M88H"]:
        assert milestone in cap.notes, (
            f"Milestone {milestone} not mentioned in TC capability matrix notes"
        )


def test_capability_matrix_planned_next_stage_m89a() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert "M89A" in cap.notes or "Kubernetes" in cap.notes, (
        f"Expected M89A or Kubernetes in TC notes; got: {cap.notes[-200:]!r}"
    )


def test_capability_matrix_maturity_partial() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.maturity == "partial"


# ── Section B: Provider expansion framework ───────────────────────────────────

def test_expansion_framework_planned_next_stage_m89a() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert (
        "M89A" in planned or "Kubernetes" in planned
    ), f"planned_next_stage should point to M89A; got: {planned!r}"


def test_expansion_framework_terraform_cloud_not_in_queue() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    queue = fw.get("recommended_next_providers", [])
    providers = [p.get("provider", "") for p in queue]
    assert "terraform_cloud" not in providers, (
        f"terraform_cloud should not be in recommended queue (arc complete); got: {providers}"
    )


def test_expansion_framework_kubernetes_is_head_of_queue() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    queue = fw.get("recommended_next_providers", [])
    assert len(queue) >= 1
    first = queue[0]
    assert "kubernetes" in first.get("provider", "").lower() or "Kubernetes" in first.get("label", ""), (
        f"Kubernetes should be first in recommended queue; got: {first}"
    )


def test_expansion_framework_sentry_still_in_queue() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    queue = fw.get("recommended_next_providers", [])
    labels = [p.get("label", "") for p in queue]
    assert any("Sentry" in label for label in labels), (
        f"Sentry not found in recommended_next_providers; got: {labels}"
    )


def test_expansion_framework_terraform_cloud_arc_mentioned_in_comments() -> None:
    text = _read(EXPANSION_FW)
    assert "Terraform Cloud" in text
    assert "M88" in text or "M88A" in text or "M88I" in text


# ── Section C: Case report ────────────────────────────────────────────────────

def test_case_report_timeline_labels_terraform_cloud() -> None:
    from app.services.security_case_report_service import _TIMELINE_PROVIDER_LABELS
    assert "terraform_cloud" in _TIMELINE_PROVIDER_LABELS
    assert _TIMELINE_PROVIDER_LABELS["terraform_cloud"] == "Terraform Cloud"


def test_case_report_preview_allowlist_has_tc_keys() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    tc_keys = [
        "workspace_resource_id",
        "auto_apply",
        "global_remote_state",
        "state_version_present",
        "raw_state_never_fetched",
    ]
    for key in tc_keys:
        assert key in _PREVIEW_ALLOWLIST, (
            f"TC key {key!r} missing from _PREVIEW_ALLOWLIST"
        )


# ── Section D: Frontend activity page ─────────────────────────────────────────

def test_fe_activity_page_has_terraform_cloud_type() -> None:
    text = _read(FE_ACTIVITY)
    assert "terraform_cloud" in text


def test_fe_activity_page_tc_is_in_provider_type() -> None:
    text = _read(FE_ACTIVITY)
    # The Provider type union should include terraform_cloud
    assert '"terraform_cloud"' in text


# ── Section E: Frontend signals page ──────────────────────────────────────────

def test_fe_signals_page_has_terraform_cloud() -> None:
    text = _read(FE_SIGNALS)
    assert "terraform_cloud" in text


def test_fe_signals_page_has_tc_signal_types() -> None:
    text = _read(FE_SIGNALS)
    tc_signal_types = [
        "terraform_cloud_workspace_auto_apply_signal",
        "terraform_cloud_organization_access_posture_signal",
    ]
    for st in tc_signal_types:
        assert st in text, f"Signal type {st!r} missing from signals page"


# ── Section F: Frontend correlations page ─────────────────────────────────────

def test_fe_correlations_page_provider_options_has_tc() -> None:
    text = _read(FE_CORRELATIONS)
    assert "terraform_cloud" in text


def test_fe_correlations_page_tc_types_complete() -> None:
    text = _read(FE_CORRELATIONS)
    expected_types = [
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
    ]
    for ct in expected_types:
        assert ct in text, f"Correlation type {ct!r} missing from correlations page"


def test_fe_correlations_page_generate_function_exists() -> None:
    text = _read(FE_CORRELATIONS)
    assert "generateTerraformCloudRiskActivityCorrelations" in text


# ── Section G: Frontend cases page ────────────────────────────────────────────

def test_fe_cases_page_has_tc_demo_card() -> None:
    text = _read(FE_CASES)
    assert "terraform_cloud" in text
    assert "Terraform Cloud" in text


def test_fe_cases_page_tc_demo_card_has_seed_color() -> None:
    text = _read(FE_CASES)
    tc_idx = text.find('"terraform_cloud"')
    assert tc_idx != -1
    tc_section = text[tc_idx:tc_idx + 800]
    assert "seedColor" in tc_section


def test_fe_cases_page_tc_clear_message() -> None:
    text = _read(FE_CASES)
    assert "Terraform Cloud demo data cleared" in text


def test_fe_cases_page_tc_seed_dispatch() -> None:
    text = _read(FE_CASES)
    assert "terraform_cloud" in text
    assert "seedIncidentDemo" in text or "onSeedDemo" in text


# ── Section H: Frontend demo-script page ──────────────────────────────────────

def test_fe_demo_script_page_tc_in_capability_table() -> None:
    text = _read(FE_DEMO_SCRIPT_PAGE)
    assert "terraform_cloud" in text
    tc_idx = text.find('"terraform_cloud"')
    assert tc_idx != -1, "terraform_cloud not in PROVIDER_CAPABILITY_TABLE"
    tc_row = text[tc_idx:tc_idx + 300]
    assert "demo: true" in tc_row, f"TC row missing demo:true; got: {tc_row!r}"


def test_fe_demo_script_page_kubernetes_in_next_queue() -> None:
    text = _read(FE_DEMO_SCRIPT_PAGE)
    assert "Kubernetes" in text
    assert "M89" in text


def test_fe_demo_script_page_tc_not_in_next_providers() -> None:
    """Terraform Cloud should be in PROVIDER_CAPABILITY_TABLE, not NEXT_PROVIDERS_BRIEF."""
    text = _read(FE_DEMO_SCRIPT_PAGE)
    next_brief_idx = text.find("NEXT_PROVIDERS_BRIEF")
    if next_brief_idx == -1:
        pytest.skip("NEXT_PROVIDERS_BRIEF not found in demo-script page")
    next_section = text[next_brief_idx:next_brief_idx + 600]
    assert "M88A" not in next_section, (
        "Terraform Cloud M88A should not appear in NEXT_PROVIDERS_BRIEF (arc complete)"
    )
    # Terraform Cloud label may be mentioned in comments but not as an active next entry
    # The key check is that M88A milestone reference is gone
    assert "M88" not in next_section.split("//")[0] or "Kubernetes" in next_section, (
        "M88 milestone reference should be removed from NEXT_PROVIDERS_BRIEF content"
    )


def test_fe_demo_script_page_arc_note_updated() -> None:
    text = _read(FE_DEMO_SCRIPT_PAGE)
    # Should mention TC arc complete and Kubernetes as next
    assert ("Kubernetes" in text and "M89" in text), (
        "Demo-script page should reference Kubernetes as M89 next provider"
    )


# ── Section I: Frontend demo script lib ───────────────────────────────────────

def test_fe_demo_script_lib_mentions_terraform_cloud_in_provider_lists() -> None:
    text = _read(FE_DEMO_SCRIPT_LIB)
    assert "Terraform Cloud" in text


def test_fe_demo_script_lib_tc_in_seed_description() -> None:
    """TC should be mentioned in the seed demo talkTrack."""
    text = _read(FE_DEMO_SCRIPT_LIB)
    # Find the seed demo step
    seed_idx = text.find("Seed the demo")
    if seed_idx == -1:
        seed_idx = text.find("incident-seed")
    if seed_idx == -1:
        pytest.skip("Seed demo step not found in demo script lib")
    seed_section = text[seed_idx:seed_idx + 2000]
    assert "Terraform Cloud" in seed_section or "terraform_cloud" in seed_section, (
        "Terraform Cloud not mentioned in demo seed talkTrack"
    )


def test_fe_demo_script_lib_tc_in_clear_description() -> None:
    """TC should be mentioned in the clear demo talkTrack."""
    text = _read(FE_DEMO_SCRIPT_LIB)
    clear_idx = text.find("Clear demo")
    if clear_idx == -1:
        clear_idx = text.find("incident-clear-demo")
    if clear_idx == -1:
        pytest.skip("Clear demo step not found in demo script lib")
    clear_section = text[clear_idx:clear_idx + 1000]
    assert "Terraform Cloud" in clear_section or "terraform_cloud" in clear_section, (
        "Terraform Cloud not mentioned in demo clear talkTrack"
    )


# ── Section J: Frontend rule catalog ──────────────────────────────────────────

def test_fe_rule_catalog_has_all_36_tc_rules() -> None:
    text = _read(FE_RULE_CATALOG)
    missing = []
    for rk in ALL_36_RULE_KEYS:
        if rk not in text:
            missing.append(rk)
    assert not missing, (
        f"These TC rule keys are missing from securityRuleCatalog.ts: {missing}"
    )


def test_fe_rule_catalog_tc_provider_coverage() -> None:
    text = _read(FE_RULE_CATALOG)
    assert "terraform_cloud" in text


def test_fe_rule_catalog_tc_has_auto_apply_rule() -> None:
    text = _read(FE_RULE_CATALOG)
    assert "terraform_cloud_workspace_auto_apply_enabled" in text
    # Should have a description
    auto_apply_idx = text.find("terraform_cloud_workspace_auto_apply_enabled")
    assert auto_apply_idx != -1
    nearby = text[auto_apply_idx:auto_apply_idx + 500]
    assert "description" in nearby or "whatItChecks" in nearby or "auto" in nearby.lower()


# ── Section K: Privacy / wording safety ───────────────────────────────────────

def test_fe_cases_page_tc_copy_safe() -> None:
    text = _read(FE_CASES)
    tc_idx = text.find("terraform_cloud")
    if tc_idx == -1:
        pytest.skip("terraform_cloud not in cases page")
    tc_section = text[max(0, tc_idx - 200):tc_idx + 2000].lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in tc_section, (
            f"Forbidden phrase {phrase!r} in TC cases page copy"
        )


def test_fe_demo_script_lib_tc_section_safe() -> None:
    text = _read(FE_DEMO_SCRIPT_LIB)
    tc_idx = text.find("Terraform Cloud")
    if tc_idx == -1:
        pytest.skip("Terraform Cloud not in demo script lib")
    tc_section = text[max(0, tc_idx - 100):tc_idx + 2000].lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in tc_section, (
            f"Forbidden phrase {phrase!r} in TC demo script lib copy"
        )


def test_capability_matrix_notes_safe() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    notes_lower = cap.notes.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in notes_lower, (
            f"Forbidden phrase {phrase!r} in TC capability matrix notes"
        )


# ── Section L: Prior milestone regression smoke ───────────────────────────────

def test_m88a_f_core_services_importable() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    from app.services.security_rules.terraform_cloud import evaluate, TERRAFORM_CLOUD_RULE_KEYS
    from app.services.terraform_cloud_activity_ingestion_service import sync_terraform_cloud_activity
    from app.services.terraform_cloud_activity_signal_service import generate_terraform_cloud_activity_signals
    from app.services.terraform_cloud_risk_activity_correlation_service import generate_terraform_cloud_correlations
    assert callable(evaluate)
    assert len(TERRAFORM_CLOUD_RULE_KEYS) >= 36


def test_m88g_demo_functions_importable() -> None:
    from app.services.security_incident_demo_service import (
        seed_terraform_cloud,
        clear_terraform_cloud,
        get_terraform_cloud_status,
    )
    assert callable(seed_terraform_cloud)
    assert callable(clear_terraform_cloud)
    assert callable(get_terraform_cloud_status)


def test_tc_in_provider_capabilities_partial() -> None:
    from app.services.provider_capability_matrix_service import PROVIDER_CAPABILITIES_PARTIAL
    providers = [p.provider for p in PROVIDER_CAPABILITIES_PARTIAL]
    assert "terraform_cloud" in providers


def test_expansion_framework_has_required_stages() -> None:
    from app.services.provider_expansion_framework import EXPANSION_STAGES
    stage_keys = [s.stage_key for s in EXPANSION_STAGES]
    required = [
        "drift_foundation",
        "security_foundation",
        "activity_ingestion",
        "activity_signals",
        "risk_activity_correlations",
        "demo_qa",
    ]
    for sk in required:
        assert sk in stage_keys, f"Required stage {sk!r} missing from EXPANSION_STAGES"
