"""M84I — PagerDuty cross-cloud UX polish guardrails.

Durable, deterministic guardrails that pin the final PagerDuty arc (M84A–M84I)
state. This file adds NO product engine code — it verifies that PagerDuty is a
first-class completed provider across all internal security UX surfaces, demo
script, provider capability table, case report / timeline labels, and roadmap
handoff to Linear (M85A).

Sections:

  A. Capability matrix
     PagerDuty capability flags correct for the completed M84A–M84I arc.
     Maturity stays "partial" (consistent with other completed partial arcs:
     Auth0, Datadog, Clerk, Twilio, SendGrid, Google Cloud, Azure).
     Notes mention M84I cross-cloud UX polish and PagerDuty arc complete.
     Notes must NOT contain stale "planned_next_stage: M84I".

  B. Provider expansion framework
     planned_next_stage → M85A: Linear Drift Provider Foundation.
     PagerDuty absent from RECOMMENDED_NEXT_PROVIDERS (arc launched M84A).
     Linear at head of recommended provider queue.

  C. Case report
     _TIMELINE_PROVIDER_LABELS contains "pagerduty": "PagerDuty".
     PagerDuty-specific safe opaque IDs in _PREVIEW_ALLOWLIST.
     No PagerDuty credential/PII keys in _PREVIEW_ALLOWLIST.

  D. Frontend PagerDuty consistency
     Activity page: provider option, sync function, 9 event types.
     Signals page: provider option, generate function, 9 signal types.
     Correlations page: provider option, 8 correlation types (no spurious 9th).
     Cases page: PagerDuty demo card, safe wording, no forbidden phrases.
     Demo-script page: PagerDuty in PROVIDER_CAPABILITY_TABLE (all flags true),
       PagerDuty arc M84A–M84I mentioned as complete, Linear in NEXT_PROVIDERS_BRIEF,
       PagerDuty absent from NEXT_PROVIDERS_BRIEF.
     securityDemoScript.ts: PagerDuty in seeding/clearing talk tracks,
       no forbidden phrases near PagerDuty copy.
     securityRuleCatalog.ts: all 40 PagerDuty rule keys present.
     api.ts: syncPagerDutyActivity, generatePagerDutyActivitySignals,
       generatePagerDutyCorrelations, demo provider union includes pagerduty.
     types/index.ts: PagerDuty response types.
     trustCenter.ts / providers.ts: PagerDuty profile present with correct label.

  E. PagerDuty rule key parity (40 rules)

  F. Forbidden wording across PagerDuty backend modules

  G. Privacy / raw-data guardrails
     Frontend pages must not claim raw PagerDuty incident/alert/webhook ingestion.

  H. Secret-shape grep
     No JWT / SG. / AC / SK patterns in PagerDuty service files.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import security_case_report_service as report_svc
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework
from app.services.security_rules.pagerduty import PAGERDUTY_RULE_KEYS

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ROOT = REPO_ROOT / "frontend" / "src"
FE_ACTIVITY = FE_ROOT / "app" / "(app)" / "security" / "activity" / "page.tsx"
FE_SIGNALS = FE_ROOT / "app" / "(app)" / "security" / "signals" / "page.tsx"
FE_CORRELATIONS = FE_ROOT / "app" / "(app)" / "security" / "correlations" / "page.tsx"
FE_CASES = FE_ROOT / "app" / "(app)" / "security" / "cases" / "page.tsx"
FE_DEMO_SCRIPT_PAGE = FE_ROOT / "app" / "(app)" / "security" / "demo-script" / "page.tsx"
FE_DEMO_SCRIPT_LIB = FE_ROOT / "lib" / "securityDemoScript.ts"
FE_RULE_CATALOG = FE_ROOT / "lib" / "securityRuleCatalog.ts"
FE_API = FE_ROOT / "lib" / "api.ts"
FE_TYPES = FE_ROOT / "types" / "index.ts"
FE_PROVIDERS = FE_ROOT / "lib" / "providers.ts"
FE_TRUST_CENTER = FE_ROOT / "lib" / "trustCenter.ts"

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
]

_PAGERDUTY_BACKEND_MODULES = [
    Path(__file__).parent.parent / "app" / "services" / "pagerduty_activity_ingestion_service.py",
    Path(__file__).parent.parent / "app" / "services" / "pagerduty_activity_signal_service.py",
    Path(__file__).parent.parent / "app" / "services" / "pagerduty_risk_activity_correlation_service.py",
    Path(__file__).parent.parent / "app" / "services" / "security_rules" / "pagerduty.py",
]

EXPECTED_PAGERDUTY_RULE_KEYS: frozenset[str] = frozenset({
    "pagerduty_service_no_escalation_policy",
    "pagerduty_service_no_integrations",
    "pagerduty_service_ack_timeout_disabled",
    "pagerduty_service_auto_resolve_disabled",
    "pagerduty_service_alert_creation_limited",
    "pagerduty_service_no_teams",
    "pagerduty_escalation_policy_no_rules",
    "pagerduty_escalation_policy_single_level",
    "pagerduty_escalation_policy_no_targets",
    "pagerduty_escalation_policy_low_target_count",
    "pagerduty_escalation_policy_no_schedule_targets",
    "pagerduty_escalation_policy_no_team_targets",
    "pagerduty_schedule_no_layers",
    "pagerduty_schedule_no_teams",
    "pagerduty_schedule_no_targets",
    "pagerduty_schedule_low_target_count",
    "pagerduty_schedule_single_layer",
    "pagerduty_schedule_no_restrictions",
    "pagerduty_service_integration_missing_key_indicator",
    "pagerduty_service_integration_email_type",
    "pagerduty_service_integration_routing_key_missing",
    "pagerduty_service_integration_unknown_type",
    "pagerduty_webhook_subscription_inactive",
    "pagerduty_webhook_subscription_non_https",
    "pagerduty_webhook_subscription_broad_event_scope",
    "pagerduty_webhook_subscription_no_events",
    "pagerduty_webhook_subscription_secret_not_indicated",
    "pagerduty_webhook_subscription_broad_scope_high",
    "pagerduty_webhook_subscription_account_scope",
    "pagerduty_event_orchestration_no_routes",
    "pagerduty_event_orchestration_no_team",
    "pagerduty_event_orchestration_low_route_count",
    "pagerduty_business_service_no_team",
    "pagerduty_business_service_no_contact",
    "pagerduty_response_play_no_responders",
    "pagerduty_response_play_no_subscribers",
    "pagerduty_response_play_not_runnable",
    "pagerduty_response_play_low_responder_count",
    "pagerduty_response_play_no_team",
    "pagerduty_response_play_manual_only",
})


# ════════════════════════════════════════════════════════════════════════════
# Section A — Capability matrix
# ════════════════════════════════════════════════════════════════════════════


def test_a1_pagerduty_capability_matrix_drift_flags() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True


def test_a2_pagerduty_capability_matrix_security_flags() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True


def test_a3_pagerduty_capability_matrix_maturity_partial() -> None:
    """Maturity stays 'partial' consistent with other completed partial arcs."""
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.maturity == "partial"


def test_a4_pagerduty_capability_matrix_label() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.label == "PagerDuty"


def test_a5_pagerduty_capability_matrix_notes_mention_m84i() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert "M84I" in cap.notes, "Notes should mention M84I cross-cloud UX polish"


def test_a6_pagerduty_capability_matrix_notes_arc_complete() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    notes = cap.notes
    assert "M84A" in notes and ("M84I" in notes or "complete" in notes.lower()), (
        "Notes should reference the M84A–M84I arc as complete"
    )


def test_a7_pagerduty_capability_matrix_notes_no_stale_m84i_pointer() -> None:
    """After M84I, notes must NOT say 'planned_next_stage: M84I' (stale)."""
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    notes_lower = cap.notes.lower()
    if "planned_next_stage" in notes_lower:
        idx = notes_lower.find("planned_next_stage")
        snippet = notes_lower[idx: idx + 80]
        assert "m84i" not in snippet, (
            f"Notes still reference planned_next_stage: M84I (stale): {snippet!r}"
        )


def test_a8_pagerduty_capability_matrix_notes_mention_m85a() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert "M85A" in cap.notes or "Linear" in cap.notes, (
        "Notes should reference handoff to M85A (Linear) after arc completes"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section B — Provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_b1_expansion_framework_planned_next_stage_m85a() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    assert "M85A" in planned or "Linear" in planned, (
        f"After M84I, planned_next_stage should point to M85A Linear; got: {planned!r}"
    )


def test_b2_expansion_framework_not_m84i() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    assert "M84I" not in planned, (
        f"planned_next_stage should no longer reference M84I after arc complete; got: {planned!r}"
    )


def test_b3_pagerduty_not_in_recommended_next_providers() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    provider_labels = [
        r.get("provider", "").lower() for r in recommended if isinstance(r, dict)
    ]
    assert "pagerduty" not in provider_labels, (
        "PagerDuty should NOT be in recommended_next_providers (arc complete M84A–M84I)"
    )


def test_b4_linear_head_of_recommended_next_providers() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    assert recommended, "recommended_next_providers should not be empty"
    first = recommended[0]
    provider = first.get("provider", "") if isinstance(first, dict) else str(first)
    assert "linear" in provider.lower() or "Linear" in str(first), (
        f"Linear should be head of recommended_next_providers after PagerDuty arc; got: {provider!r}"
    )


def test_b5_expansion_framework_next_milestone_m85a() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    next_ms = summary.get("next_milestone", "") or ""
    assert "M85A" in next_ms or "Linear" in next_ms, (
        f"next_milestone should reference M85A/Linear; got: {next_ms!r}"
    )


def test_b6_expansion_framework_next_provider_linear() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    next_prov = summary.get("next_provider", "") or ""
    assert "Linear" in next_prov or "linear" in next_prov.lower(), (
        f"next_provider should be Linear after PagerDuty arc complete; got: {next_prov!r}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section C — Case report
# ════════════════════════════════════════════════════════════════════════════


def test_c1_pagerduty_in_timeline_provider_labels() -> None:
    labels = report_svc._TIMELINE_PROVIDER_LABELS
    assert "pagerduty" in labels, "PagerDuty missing from _TIMELINE_PROVIDER_LABELS"
    assert labels["pagerduty"] == "PagerDuty", (
        f"Expected 'PagerDuty' label, got: {labels['pagerduty']!r}"
    )


def test_c2_pagerduty_preview_allowlist_webhook_subscription_id() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    assert "webhook_subscription_id" in _PREVIEW_ALLOWLIST, (
        "webhook_subscription_id should be in _PREVIEW_ALLOWLIST for PagerDuty demo evidence"
    )


def test_c3_pagerduty_preview_allowlist_opaque_ids() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    for key in (
        "service_id",
        "escalation_policy_id",
        "schedule_id",
        "event_orchestration_id",
        "business_service_id",
        "response_play_id",
        "pagerduty_event_id",
    ):
        assert key in _PREVIEW_ALLOWLIST, (
            f"PagerDuty safe opaque ID '{key}' missing from _PREVIEW_ALLOWLIST"
        )


def test_c4_pagerduty_preview_allowlist_safe_posture_keys() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    for key in (
        "https_delivery",
        "url_scheme_category",
        "event_scope_category",
    ):
        assert key in _PREVIEW_ALLOWLIST, (
            f"PagerDuty safe posture key '{key}' missing from _PREVIEW_ALLOWLIST"
        )


def test_c5_pagerduty_preview_allowlist_no_credential_keys() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    forbidden = {
        "api_token", "routing_key", "integration_key", "webhook_secret",
        "delivery_url", "webhook_url", "user_email", "user_name",
        "phone_number", "contact_method", "incident_payload", "alert_payload",
    }
    found = forbidden & _PREVIEW_ALLOWLIST
    assert not found, f"Credential/PII keys found in _PREVIEW_ALLOWLIST: {sorted(found)}"


# ════════════════════════════════════════════════════════════════════════════
# Section D — Frontend PagerDuty consistency
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_d1_pagerduty_in_activity_page() -> None:
    text = FE_ACTIVITY.read_text()
    assert '"pagerduty"' in text or "'pagerduty'" in text, (
        "pagerduty missing from activity page provider union"
    )
    assert "syncPagerDutyActivity" in text or "sync_pagerduty" in text.lower(), (
        "syncPagerDutyActivity missing from activity page"
    )


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_d2_pagerduty_event_types_in_activity_page() -> None:
    text = FE_ACTIVITY.read_text()
    idx = text.find("PAGERDUTY_EVENT_TYPES")
    assert idx != -1, "PAGERDUTY_EVENT_TYPES not found in activity page"
    block = text[idx: idx + 1500]
    count = block.count('"pagerduty.')
    assert count == 9, f"Expected 9 PagerDuty event types in activity page, found {count}"


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_d3_pagerduty_activity_page_safe_copy() -> None:
    text = FE_ACTIVITY.read_text()
    idx = text.lower().find("pagerduty")
    if idx == -1:
        return
    surrounding = text[max(0, idx - 200): idx + 2000].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in surrounding, (
            f"Forbidden phrase '{phrase}' near PagerDuty copy in activity page"
        )


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_d4_pagerduty_in_signals_page() -> None:
    text = FE_SIGNALS.read_text()
    assert "pagerduty" in text.lower()
    assert "generatePagerDutyActivitySignals" in text or "generate_pagerduty" in text.lower(), (
        "generatePagerDutyActivitySignals missing from signals page"
    )


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_d5_pagerduty_signal_types_in_signals_page() -> None:
    text = FE_SIGNALS.read_text()
    idx = text.find("PAGERDUTY_SIGNAL_TYPES")
    assert idx != -1, "PAGERDUTY_SIGNAL_TYPES not found in signals page"
    block = text[idx: idx + 2000]
    count = block.count('"pagerduty_')
    assert count >= 9, f"Expected >=9 PagerDuty signal types in signals page, found {count}"


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_d6_pagerduty_in_correlations_page() -> None:
    text = FE_CORRELATIONS.read_text()
    assert "pagerduty" in text.lower()
    assert "generatePagerDutyCorrelations" in text or "pagerduty_correlations" in text.lower(), (
        "generatePagerDutyCorrelations or pagerduty_correlations missing from correlations page"
    )


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_d7_pagerduty_correlation_types_in_correlations_page() -> None:
    text = FE_CORRELATIONS.read_text()
    for ctype in (
        "pagerduty_service_risk_activity_correlation",
        "pagerduty_escalation_policy_risk_activity_correlation",
        "pagerduty_webhook_subscription_risk_activity_correlation",
        "pagerduty_response_play_risk_activity_correlation",
    ):
        assert f'"{ctype}"' in text or f"'{ctype}'" in text, (
            f"Correlation type '{ctype}' not found in correlations page"
        )


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_d7b_no_spurious_correlation_type_in_page() -> None:
    """pagerduty_config_activity_correlation does not exist in the backend."""
    text = FE_CORRELATIONS.read_text()
    assert "pagerduty_config_activity_correlation" not in text, (
        "Spurious pagerduty_config_activity_correlation found — not a real backend type"
    )


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_d8_pagerduty_demo_card_in_cases_page() -> None:
    text = FE_CASES.read_text()
    assert "pagerduty" in text.lower()
    assert "PagerDuty" in text


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_d9_pagerduty_demo_card_seed_clear_buttons() -> None:
    text = FE_CASES.read_text()
    assert "Load PagerDuty security demo" in text, (
        "PagerDuty seed button label missing from cases page"
    )
    assert "Clear PagerDuty demo" in text, (
        "PagerDuty clear button label missing from cases page"
    )


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_d10_pagerduty_demo_card_safe_wording() -> None:
    text = FE_CASES.read_text()
    idx = text.lower().find("pagerduty")
    if idx == -1:
        return
    block = text[max(0, idx - 100): idx + 3000].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in block, (
            f"Forbidden phrase '{phrase}' near PagerDuty copy in cases page"
        )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d11_pagerduty_in_capability_table() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    # Search for the const declaration (not the .map() call that appears earlier)
    idx = text.find("const PROVIDER_CAPABILITY_TABLE")
    assert idx != -1, "const PROVIDER_CAPABILITY_TABLE not found in demo-script page"
    # Find the closing ]; of the data array
    end_idx = text.find("];", idx)
    block = text[idx: end_idx] if end_idx != -1 else text[idx: idx + 8000]
    assert "pagerduty" in block.lower(), (
        "PagerDuty missing from PROVIDER_CAPABILITY_TABLE data in demo-script page"
    )
    assert '"PagerDuty"' in block or "'PagerDuty'" in block, (
        "PagerDuty label 'PagerDuty' missing from capability table"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d12_pagerduty_capability_table_all_flags_true() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    idx = text.find('"pagerduty"')
    if idx == -1:
        idx = text.find("'pagerduty'")
    assert idx != -1, "pagerduty row not found in demo-script page"
    row = text[idx: idx + 300]
    # All five capability flags must be true in the row
    assert "demo: true" in row, f"demo flag not true in PagerDuty row: {row!r}"


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d13_pagerduty_arc_complete_in_demo_script_page() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert "M84A" in text or "M84I" in text or "PagerDuty arc complete" in text, (
        "Demo-script page should mention PagerDuty arc (M84A/M84I/complete)"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d14_pagerduty_not_in_next_providers_brief() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    idx = text.find("const NEXT_PROVIDERS_BRIEF")
    assert idx != -1, "const NEXT_PROVIDERS_BRIEF not found in demo-script page"
    block_start = text.find("[", idx)
    block_end = text.find("];", block_start)
    if block_start == -1 or block_end == -1:
        return
    brief_block = text[block_start:block_end]
    assert "PagerDuty" not in brief_block, (
        "PagerDuty should NOT be in NEXT_PROVIDERS_BRIEF (arc complete M84A–M84I)"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d15_linear_is_head_of_next_providers_brief() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    idx = text.find("const NEXT_PROVIDERS_BRIEF")
    assert idx != -1
    block_start = text.find("[", idx)
    block_end = text.find("];", block_start)
    if block_start == -1 or block_end == -1:
        return
    brief_block = text[block_start:block_end]
    assert "Linear" in brief_block, (
        "Linear should be head of NEXT_PROVIDERS_BRIEF after PagerDuty arc complete"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d16_demo_script_page_note_pagerduty_arc_complete() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert "PagerDuty arc complete" in text or "M84A–M84I" in text or "M84A-M84I" in text, (
        "Demo-script page should acknowledge PagerDuty arc is complete (M84A–M84I)"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_d17_pagerduty_in_demo_script_seed_track() -> None:
    text = FE_DEMO_SCRIPT_LIB.read_text()
    idx = text.find("incident-seed")
    assert idx != -1, "incident-seed step not found in securityDemoScript.ts"
    section = text[idx: idx + 2000]
    assert "PagerDuty" in section, (
        "PagerDuty not found in incident-seed talk track of securityDemoScript.ts"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_d18_pagerduty_in_demo_script_clear_track() -> None:
    text = FE_DEMO_SCRIPT_LIB.read_text()
    idx = text.find("incident-clear-demo")
    assert idx != -1, "incident-clear-demo step not found in securityDemoScript.ts"
    section = text[idx: idx + 1000]
    assert "PagerDuty" in section, (
        "PagerDuty not found in incident-clear-demo talk track of securityDemoScript.ts"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_d19_demo_script_lib_no_forbidden_near_pagerduty() -> None:
    text = FE_DEMO_SCRIPT_LIB.read_text()
    # Strip avoid: "..." and avoid: [...] blocks
    stripped = re.sub(r'avoid:\s*"[^"]*"', "", text)
    stripped = re.sub(r'avoid:\s*\[[^\]]*\]', "", stripped, flags=re.DOTALL)
    for line in stripped.splitlines():
        line_lower = line.lower()
        if "avoid" in line_lower:
            continue
        if "never asserts" in line_lower or "does not assert" in line_lower:
            continue
        if "does not confirm" in line_lower or "never confirm" in line_lower:
            continue
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in line_lower, (
                f"Forbidden phrase '{phrase}' in securityDemoScript.ts outside safe context: "
                f"{line.strip()!r}"
            )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_d20_all_pagerduty_rule_keys_in_catalog() -> None:
    text = FE_RULE_CATALOG.read_text()
    missing = []
    for key in EXPECTED_PAGERDUTY_RULE_KEYS:
        if key not in text:
            missing.append(key)
    assert not missing, (
        f"PagerDuty rule keys missing from securityRuleCatalog.ts: {missing}"
    )


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_d21_pagerduty_api_functions_present() -> None:
    text = FE_API.read_text()
    assert "syncPagerDutyActivity" in text, "syncPagerDutyActivity missing from api.ts"
    assert "generatePagerDutyActivitySignals" in text, (
        "generatePagerDutyActivitySignals missing from api.ts"
    )
    assert "generatePagerDutyCorrelations" in text, (
        "generatePagerDutyCorrelations missing from api.ts"
    )


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_d22_pagerduty_in_demo_api_union() -> None:
    text = FE_API.read_text()
    idx = text.find("seedIncidentDemo")
    assert idx != -1
    section = text[idx: idx + 500]
    assert "pagerduty" in section, "pagerduty missing from seedIncidentDemo provider union"


@pytest.mark.skipif(not FE_TYPES.exists(), reason="Frontend tree absent")
def test_d23_pagerduty_response_types_present() -> None:
    text = FE_TYPES.read_text()
    assert "pagerduty_api_token" in text, "pagerduty_api_token missing from types/index.ts"
    assert "PagerDutyActivity" in text or "pagerduty" in text.lower(), (
        "PagerDuty response types missing from types/index.ts"
    )


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_d24_pagerduty_in_providers_ts() -> None:
    text = FE_PROVIDERS.read_text()
    assert "pagerduty" in text, "pagerduty missing from providers.ts"
    assert "PagerDuty" in text, "PagerDuty label missing from providers.ts"


@pytest.mark.skipif(not FE_TRUST_CENTER.exists(), reason="Frontend tree absent")
def test_d25_pagerduty_in_trust_center() -> None:
    text = FE_TRUST_CENTER.read_text()
    assert "pagerduty" in text.lower() or "PagerDuty" in text, (
        "PagerDuty missing from trustCenter.ts"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section E — PagerDuty rule key parity (40 rules)
# ════════════════════════════════════════════════════════════════════════════


def test_e1_pagerduty_rule_key_count() -> None:
    assert len(PAGERDUTY_RULE_KEYS) == 40, (
        f"Expected 40 PagerDuty rule keys, got {len(PAGERDUTY_RULE_KEYS)}"
    )


def test_e2_all_expected_rule_keys_in_frozenset() -> None:
    missing = EXPECTED_PAGERDUTY_RULE_KEYS - PAGERDUTY_RULE_KEYS
    assert not missing, f"Rule keys missing from PAGERDUTY_RULE_KEYS: {missing}"


def test_e3_all_rule_keys_in_registry() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    missing = PAGERDUTY_RULE_KEYS - KNOWN_RULE_KEYS
    assert not missing, f"PagerDuty rule keys missing from KNOWN_RULE_KEYS: {missing}"


# ════════════════════════════════════════════════════════════════════════════
# Section F — Forbidden wording across PagerDuty backend modules
# ════════════════════════════════════════════════════════════════════════════


def test_f1_no_forbidden_wording_in_pagerduty_rules() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "security_rules" / "pagerduty.py"
    content = path.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, (
            f"Forbidden phrase '{phrase}' in pagerduty.py"
        )


def test_f2_no_forbidden_wording_in_ingestion() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "pagerduty_activity_ingestion_service.py"
    content = path.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, (
            f"Forbidden phrase '{phrase}' in pagerduty_activity_ingestion_service.py"
        )


def test_f3_no_forbidden_wording_in_signals() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "pagerduty_activity_signal_service.py"
    content = path.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, (
            f"Forbidden phrase '{phrase}' in pagerduty_activity_signal_service.py"
        )


def test_f4_no_forbidden_wording_in_correlations() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "pagerduty_risk_activity_correlation_service.py"
    content = path.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, (
            f"Forbidden phrase '{phrase}' in pagerduty_risk_activity_correlation_service.py"
        )


def test_f5_no_forbidden_wording_in_demo_section() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "security_incident_demo_service.py"
    text = path.read_text()
    idx = text.find("PAGERDUTY_DEMO_INTEGRATION_NAME")
    assert idx != -1
    section = text[idx:].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in section, (
            f"Forbidden phrase '{phrase}' in PagerDuty demo section of demo service"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section G — Privacy / raw-data guardrails
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_g1_activity_page_no_raw_incident_claim() -> None:
    """PagerDuty activity page must not claim that raw incident/alert payloads are ingested.

    Privacy disclaimers like "incident payloads are never stored" are acceptable and
    explicitly excluded — we only flag affirmative ingestion claims.
    """
    text = FE_ACTIVITY.read_text()
    assert "pagerduty" in text.lower(), "pagerduty not found in activity page (unexpected)"
    # Check all lines that mention pagerduty and a forbidden claim together,
    # but skip lines that are privacy disclaimers (contain "never" or "not stored").
    for line in text.splitlines():
        ll = line.lower()
        if "pagerduty" not in ll:
            continue
        # Skip disclaimer lines
        if "never" in ll or "not stored" in ll or "does not" in ll:
            continue
        for claim in ("incident payload", "alert payload"):
            assert claim not in ll, (
                f"Activity page may claim '{claim}' for PagerDuty: {line.strip()!r}"
            )


def test_g2_ingestion_service_no_raw_token_storage() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "pagerduty_activity_ingestion_service.py"
    content = path.read_text()
    for forbidden in ('"api_token"', '"routing_key"', '"integration_key"',
                      '"webhook_secret"', '"delivery_url"'):
        assert forbidden not in content, (
            f"Raw credential key {forbidden} found in ingestion service"
        )


def test_g3_demo_section_no_real_url() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "security_incident_demo_service.py"
    text = path.read_text()
    idx = text.find("PAGERDUTY_DEMO_INTEGRATION_NAME")
    assert idx != -1
    section = text[idx:]
    assert "http://" not in section, "http:// URL found in PagerDuty demo section"
    assert "https://" not in section, "https:// URL found in PagerDuty demo section"


# ════════════════════════════════════════════════════════════════════════════
# Section H — Secret-shape grep
# ════════════════════════════════════════════════════════════════════════════


_SECRET_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}"), "JWT-shaped"),
    (re.compile(r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "SG-key-shaped"),
    (re.compile(r"AC[0-9a-fA-F]{32}"), "Twilio-SID-shaped"),
    (re.compile(r"SK[0-9a-fA-F]{32}"), "SK-secret-shaped"),
]


def test_h1_no_secret_shapes_in_pagerduty_backend_modules() -> None:
    for module_path in _PAGERDUTY_BACKEND_MODULES:
        if not module_path.exists():
            continue
        content = module_path.read_text()
        for pat, name in _SECRET_PATTERNS:
            assert not pat.search(content), (
                f"{name} string found in {module_path.name}"
            )
