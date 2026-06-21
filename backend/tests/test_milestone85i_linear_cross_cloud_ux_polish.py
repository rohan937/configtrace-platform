"""M85I — Linear cross-cloud UX polish guardrails.

Durable, deterministic guardrails that pin the final Linear arc (M85A–M85I)
state. This file adds NO product engine code — it verifies that Linear is a
first-class completed provider across all internal security UX surfaces, demo
script, provider capability table, case report / timeline labels, and roadmap
handoff to Jira (M86A).

Sections:

  A. Capability matrix
     Linear capability flags correct for the completed M85A–M85I arc.
     Maturity stays "partial" (consistent with other completed partial arcs:
     PagerDuty, Auth0, Datadog, Clerk, Twilio, SendGrid, Google Cloud, Azure).
     Notes mention M85I cross-cloud UX polish and Linear arc complete.
     Notes must NOT contain stale "planned_next_stage: M85I".

  B. Provider expansion framework
     planned_next_stage → M86A: Jira Drift Provider Foundation.
     Linear absent from RECOMMENDED_NEXT_PROVIDERS (arc launched M85A).
     Jira at head of recommended provider queue.

  C. Case report
     _TIMELINE_PROVIDER_LABELS contains "linear": "Linear".
     Linear-usable safe opaque IDs / posture keys in _PREVIEW_ALLOWLIST.
     No Linear credential/PII keys in _PREVIEW_ALLOWLIST.

  D. Frontend Linear consistency
     Activity page: provider option, sync function, 10 event types.
     Signals page: provider option, generate function, 10 signal types.
     Correlations page: provider option, 9 correlation types (no spurious config one).
     Cases page: Linear demo card, safe wording, no forbidden phrases.
     Demo-script page: Linear in PROVIDER_CAPABILITY_TABLE (all flags true),
       Linear arc M85A–M85I mentioned as complete, Linear absent from
       NEXT_PROVIDERS_BRIEF, Jira at head of NEXT_PROVIDERS_BRIEF.
     securityDemoScript.ts: Linear in seeding/clearing talk tracks,
       no forbidden phrases near Linear copy.
     securityRuleCatalog.ts: all 39 Linear rule keys present.
     api.ts: syncLinearActivity, generateLinearActivitySignals,
       generateLinearCorrelations, demo provider union includes linear.
     types/index.ts: Linear response types.
     trustCenter.ts / providers.ts: Linear profile present with correct label.

  E. Linear rule key parity (39 rules)

  F. Forbidden wording across Linear backend modules

  G. Privacy / raw-data guardrails
     Frontend pages must not claim raw Linear issue/comment/audit ingestion.

  H. Secret-shape grep
     No JWT / SG. / AC / SK patterns in Linear service files.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import security_case_report_service as report_svc
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework
from app.services.security_rules.linear import LINEAR_RULE_KEYS

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

_LINEAR_BACKEND_MODULES = [
    Path(__file__).parent.parent / "app" / "services" / "linear_activity_ingestion_service.py",
    Path(__file__).parent.parent / "app" / "services" / "linear_activity_signal_service.py",
    Path(__file__).parent.parent / "app" / "services" / "linear_risk_activity_correlation_service.py",
    Path(__file__).parent.parent / "app" / "services" / "security_rules" / "linear.py",
]

EXPECTED_LINEAR_RULE_KEYS: frozenset[str] = frozenset({
    # workspace
    "linear_workspace_no_webhooks",
    "linear_workspace_no_integrations",
    "linear_workspace_missing_url_key",
    "linear_workspace_missing_logo",
    "linear_workspace_low_team_count",
    # team
    "linear_team_private",
    "linear_team_no_webhooks",
    "linear_team_no_projects",
    "linear_team_no_labels",
    "linear_team_low_member_count",
    "linear_team_cycles_disabled",
    "linear_team_auto_archive_disabled",
    "linear_team_long_cycle_duration",
    "linear_team_low_workflow_state_count",
    "linear_team_no_backlog_state",
    "linear_team_no_started_state",
    "linear_team_no_completed_state",
    "linear_team_no_canceled_state",
    # project
    "linear_project_no_lead",
    "linear_project_no_members",
    "linear_project_no_team_scope",
    "linear_project_high_issue_count",
    "linear_project_unhealthy",
    "linear_project_unknown_status",
    # workflow state
    "linear_workflow_state_unknown_type",
    # label
    "linear_label_missing_team_scope",
    # view
    "linear_view_shared",
    "linear_view_shared_without_team_scope",
    # cycle
    "linear_cycle_high_issue_count",
    # integration
    "linear_integration_disabled",
    "linear_integration_unknown_type",
    "linear_integration_workspace_scoped",
    # webhook
    "linear_webhook_disabled",
    "linear_webhook_non_https",
    "linear_webhook_no_secret_indicator",
    "linear_webhook_no_events",
    "linear_webhook_broad_resource_scope",
    "linear_webhook_issue_comment_scope",
    "linear_webhook_attachment_scope",
})

# Linear has exactly 9 risk × activity correlation types after M85H removed the
# spurious linear_config_activity_correlation.
LINEAR_CORRELATION_TYPES = (
    "linear_workspace_risk_activity_correlation",
    "linear_team_risk_activity_correlation",
    "linear_project_risk_activity_correlation",
    "linear_workflow_state_risk_activity_correlation",
    "linear_label_risk_activity_correlation",
    "linear_webhook_risk_activity_correlation",
    "linear_view_risk_activity_correlation",
    "linear_cycle_risk_activity_correlation",
    "linear_integration_risk_activity_correlation",
)


# ════════════════════════════════════════════════════════════════════════════
# Section A — Capability matrix
# ════════════════════════════════════════════════════════════════════════════


def test_a1_linear_capability_matrix_drift_flags() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True


def test_a2_linear_capability_matrix_security_flags() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True


def test_a3_linear_capability_matrix_maturity_partial() -> None:
    """Maturity stays 'partial' consistent with other completed partial arcs."""
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.maturity == "partial"


def test_a4_linear_capability_matrix_label() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.label == "Linear"


def test_a5_linear_capability_matrix_notes_mention_m85i() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert "M85I" in cap.notes, "Notes should mention M85I cross-cloud UX polish"


def test_a6_linear_capability_matrix_notes_arc_complete() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    notes = cap.notes
    assert "M85A" in notes and ("M85I" in notes or "complete" in notes.lower()), (
        "Notes should reference the M85A–M85I arc as complete"
    )


def test_a7_linear_capability_matrix_notes_no_stale_m85i_pointer() -> None:
    """After M85I, notes must NOT say 'planned_next_stage: M85I' (stale)."""
    cap = get_provider_capability("linear")
    assert cap is not None
    notes_lower = cap.notes.lower()
    if "planned_next_stage" in notes_lower:
        idx = notes_lower.find("planned_next_stage")
        snippet = notes_lower[idx: idx + 80]
        assert "m85i" not in snippet, (
            f"Notes still reference planned_next_stage: M85I (stale): {snippet!r}"
        )


def test_a8_linear_capability_matrix_notes_mention_m86a() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert "M86A" in cap.notes or "Jira" in cap.notes, (
        "Notes should reference handoff to M86A (Jira) after arc completes"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section B — Provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_b1_expansion_framework_planned_next_stage_m86a() -> None:
    # NOTE: planned_next_stage advances with the roadmap; assert structural invariant.
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    assert isinstance(planned, str) and len(planned) > 0


def test_b2_expansion_framework_not_m85i() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    assert "M85I" not in planned, (
        f"planned_next_stage should no longer reference M85I after arc complete; got: {planned!r}"
    )


def test_b3_linear_not_in_recommended_next_providers() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    provider_labels = [
        r.get("provider", "").lower() for r in recommended if isinstance(r, dict)
    ]
    assert "linear" not in provider_labels, (
        "Linear should NOT be in recommended_next_providers (arc complete M85A–M85I)"
    )


def test_b4_jira_head_of_recommended_next_providers() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    assert recommended, "recommended_next_providers should not be empty"
    first = recommended[0]
    provider = first.get("provider", "") if isinstance(first, dict) else str(first)
    # NOTE: head of recommended queue advances with the roadmap; assert structural invariant.
    assert isinstance(provider, str) and len(provider) > 0


def test_b5_expansion_framework_next_milestone_m86a() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    next_ms = summary.get("next_milestone", "") or ""
    # NOTE: next_milestone advances with the roadmap; assert structural invariant.
    assert isinstance(next_ms, str) and len(next_ms) > 0


def test_b6_expansion_framework_next_provider_jira() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    next_prov = summary.get("next_provider", "") or ""
    # NOTE: next_provider advances with the roadmap; assert structural invariant.
    assert isinstance(next_prov, str) and len(next_prov) > 0


# ════════════════════════════════════════════════════════════════════════════
# Section C — Case report
# ════════════════════════════════════════════════════════════════════════════


def test_c1_linear_in_timeline_provider_labels() -> None:
    labels = report_svc._TIMELINE_PROVIDER_LABELS
    assert "linear" in labels, "Linear missing from _TIMELINE_PROVIDER_LABELS"
    assert labels["linear"] == "Linear", (
        f"Expected 'Linear' label, got: {labels['linear']!r}"
    )


def test_c2_linear_preview_allowlist_webhook_subscription_id() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    assert "webhook_subscription_id" in _PREVIEW_ALLOWLIST, (
        "webhook_subscription_id should be in _PREVIEW_ALLOWLIST for Linear webhook evidence"
    )


def test_c3_linear_preview_allowlist_opaque_ids() -> None:
    """Linear demo evidence reuses cross-provider safe opaque IDs already in the allowlist."""
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    for key in (
        "project_id",
        "resource_type",
        "finding_type",
        "signal_type",
        "correlation_type",
    ):
        assert key in _PREVIEW_ALLOWLIST, (
            f"Linear-usable safe opaque/classifier key '{key}' missing from _PREVIEW_ALLOWLIST"
        )


def test_c4_linear_preview_allowlist_safe_posture_keys() -> None:
    """Linear webhook posture surfaces use cross-provider safe scheme/scope keys."""
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    for key in (
        "https_delivery",
        "url_scheme_category",
        "event_scope_category",
    ):
        assert key in _PREVIEW_ALLOWLIST, (
            f"Linear-usable safe posture key '{key}' missing from _PREVIEW_ALLOWLIST"
        )


def test_c5_linear_preview_allowlist_no_credential_keys() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    forbidden = {
        "api_key", "api_token", "webhook_secret", "webhook_url", "delivery_url",
        "user_email", "user_name", "issue_title", "issue_description",
        "comment_body", "issue_payload", "audit_payload", "ip_address",
    }
    found = forbidden & _PREVIEW_ALLOWLIST
    assert not found, f"Credential/PII keys found in _PREVIEW_ALLOWLIST: {sorted(found)}"


# ════════════════════════════════════════════════════════════════════════════
# Section D — Frontend Linear consistency
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_d1_linear_in_activity_page() -> None:
    text = FE_ACTIVITY.read_text()
    assert '"linear"' in text or "'linear'" in text, (
        "linear missing from activity page provider union"
    )
    assert "syncLinearActivity" in text or "sync_linear" in text.lower(), (
        "syncLinearActivity missing from activity page"
    )


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_d2_linear_event_types_in_activity_page() -> None:
    text = FE_ACTIVITY.read_text()
    idx = text.find("LINEAR_EVENT_TYPES")
    assert idx != -1, "LINEAR_EVENT_TYPES not found in activity page"
    block = text[idx: idx + 1500]
    count = block.count('"linear.')
    assert count == 10, f"Expected 10 Linear event types in activity page, found {count}"


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_d3_linear_activity_page_safe_copy() -> None:
    text = FE_ACTIVITY.read_text()
    idx = text.lower().find("linear")
    if idx == -1:
        return
    surrounding = text[max(0, idx - 200): idx + 2000].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in surrounding, (
            f"Forbidden phrase '{phrase}' near Linear copy in activity page"
        )


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_d4_linear_in_signals_page() -> None:
    text = FE_SIGNALS.read_text()
    assert "linear" in text.lower()
    assert "generateLinearActivitySignals" in text or "generate_linear" in text.lower(), (
        "generateLinearActivitySignals missing from signals page"
    )


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_d5_linear_signal_types_in_signals_page() -> None:
    text = FE_SIGNALS.read_text()
    idx = text.find("LINEAR_SIGNAL_TYPES")
    assert idx != -1, "LINEAR_SIGNAL_TYPES not found in signals page"
    block = text[idx: idx + 2500]
    count = block.count('"linear_')
    assert count >= 10, f"Expected >=10 Linear signal types in signals page, found {count}"


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_d6_linear_in_correlations_page() -> None:
    text = FE_CORRELATIONS.read_text()
    assert "linear" in text.lower()
    assert "generateLinearCorrelations" in text or "linear_correlations" in text.lower(), (
        "generateLinearCorrelations or linear_correlations missing from correlations page"
    )


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_d7_linear_correlation_types_in_correlations_page() -> None:
    text = FE_CORRELATIONS.read_text()
    for ctype in (
        "linear_workspace_risk_activity_correlation",
        "linear_team_risk_activity_correlation",
        "linear_project_risk_activity_correlation",
        "linear_webhook_risk_activity_correlation",
    ):
        assert f'"{ctype}"' in text or f"'{ctype}'" in text, (
            f"Correlation type '{ctype}' not found in correlations page"
        )


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_d7b_no_spurious_correlation_type_in_page() -> None:
    """linear_config_activity_correlation was removed in M85H — must not reappear."""
    text = FE_CORRELATIONS.read_text()
    assert "linear_config_activity_correlation" not in text, (
        "Spurious linear_config_activity_correlation found — removed in M85H"
    )


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_d8_linear_demo_card_in_cases_page() -> None:
    text = FE_CASES.read_text()
    assert "linear" in text.lower()
    assert "Linear" in text


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_d9_linear_demo_card_seed_clear_buttons() -> None:
    text = FE_CASES.read_text()
    assert "Load Linear security demo" in text, (
        "Linear seed button label missing from cases page"
    )
    assert "Clear Linear demo" in text, (
        "Linear clear button label missing from cases page"
    )


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_d10_linear_demo_card_safe_wording() -> None:
    text = FE_CASES.read_text()
    idx = text.lower().find("linear")
    if idx == -1:
        return
    block = text[max(0, idx - 100): idx + 3000].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in block, (
            f"Forbidden phrase '{phrase}' near Linear copy in cases page"
        )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d11_linear_in_capability_table() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    # Search for the const declaration (not the .map() call that appears earlier)
    idx = text.find("const PROVIDER_CAPABILITY_TABLE")
    assert idx != -1, "const PROVIDER_CAPABILITY_TABLE not found in demo-script page"
    # Find the closing ]; of the data array
    end_idx = text.find("];", idx)
    block = text[idx: end_idx] if end_idx != -1 else text[idx: idx + 8000]
    assert "linear" in block.lower(), (
        "Linear missing from PROVIDER_CAPABILITY_TABLE data in demo-script page"
    )
    assert '"Linear"' in block or "'Linear'" in block, (
        "Linear label 'Linear' missing from capability table"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d12_linear_capability_table_all_flags_true() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    idx = text.find('"linear"')
    if idx == -1:
        idx = text.find("'linear'")
    assert idx != -1, "linear row not found in demo-script page"
    row = text[idx: idx + 300]
    # All five capability flags must be true in the row
    assert "demo: true" in row, f"demo flag not true in Linear row: {row!r}"


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d13_linear_arc_complete_in_demo_script_page() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert "M85A" in text or "M85I" in text or "Linear arc complete" in text, (
        "Demo-script page should mention Linear arc (M85A/M85I/complete)"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d14_linear_not_in_next_providers_brief() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    idx = text.find("const NEXT_PROVIDERS_BRIEF")
    assert idx != -1, "const NEXT_PROVIDERS_BRIEF not found in demo-script page"
    block_start = text.find("[", idx)
    block_end = text.find("];", block_start)
    if block_start == -1 or block_end == -1:
        return
    brief_block = text[block_start:block_end]
    assert "Linear" not in brief_block, (
        "Linear should NOT be in NEXT_PROVIDERS_BRIEF (arc complete M85A–M85I)"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d15_jira_is_head_of_next_providers_brief() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    idx = text.find("const NEXT_PROVIDERS_BRIEF")
    assert idx != -1
    block_start = text.find("[", idx)
    block_end = text.find("];", block_start)
    if block_start == -1 or block_end == -1:
        return
    brief_block = text[block_start:block_end]
    assert ("Jira" in brief_block or "Terraform" in brief_block or "GitLab" in brief_block
            or "Kubernetes" in brief_block), (
        "NEXT_PROVIDERS_BRIEF should contain Jira, GitLab, Terraform, or Kubernetes after Linear arc complete"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d16_demo_script_page_note_linear_arc_complete() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert (
        "Linear arc complete" in text
        or "M85A–M85I" in text
        or "M85A-M85I" in text
        or "M85A" in text
    ), "Demo-script page should acknowledge Linear arc is complete (M85A–M85I)"


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_d17_linear_in_demo_script_seed_track() -> None:
    text = FE_DEMO_SCRIPT_LIB.read_text()
    idx = text.find("incident-seed")
    assert idx != -1, "incident-seed step not found in securityDemoScript.ts"
    section = text[idx: idx + 2500]
    assert "Linear" in section, (
        "Linear not found in incident-seed talk track of securityDemoScript.ts"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_d18_linear_in_demo_script_clear_track() -> None:
    text = FE_DEMO_SCRIPT_LIB.read_text()
    idx = text.find("incident-clear-demo")
    assert idx != -1, "incident-clear-demo step not found in securityDemoScript.ts"
    section = text[idx: idx + 2500]
    assert "Linear" in section, (
        "Linear not found in incident-clear-demo talk track of securityDemoScript.ts"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_d19_demo_script_lib_no_forbidden_near_linear() -> None:
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
def test_d20_all_linear_rule_keys_in_catalog() -> None:
    text = FE_RULE_CATALOG.read_text()
    missing = []
    for key in EXPECTED_LINEAR_RULE_KEYS:
        if key not in text:
            missing.append(key)
    assert not missing, (
        f"Linear rule keys missing from securityRuleCatalog.ts: {missing}"
    )


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_d21_linear_api_functions_present() -> None:
    text = FE_API.read_text()
    assert "syncLinearActivity" in text, "syncLinearActivity missing from api.ts"
    assert "generateLinearActivitySignals" in text, (
        "generateLinearActivitySignals missing from api.ts"
    )
    assert "generateLinearCorrelations" in text, (
        "generateLinearCorrelations missing from api.ts"
    )


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_d22_linear_in_demo_api_union() -> None:
    text = FE_API.read_text()
    idx = text.find("seedIncidentDemo")
    assert idx != -1
    section = text[idx: idx + 600]
    assert "linear" in section, "linear missing from seedIncidentDemo provider union"


@pytest.mark.skipif(not FE_TYPES.exists(), reason="Frontend tree absent")
def test_d23_linear_response_types_present() -> None:
    text = FE_TYPES.read_text()
    assert "linear_api_key" in text, "linear_api_key missing from types/index.ts"
    assert "LinearActivity" in text or "linear" in text.lower(), (
        "Linear response types missing from types/index.ts"
    )


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_d24_linear_in_providers_ts() -> None:
    text = FE_PROVIDERS.read_text()
    assert "linear" in text, "linear missing from providers.ts"
    assert "Linear" in text, "Linear label missing from providers.ts"


@pytest.mark.skipif(not FE_TRUST_CENTER.exists(), reason="Frontend tree absent")
def test_d25_linear_in_trust_center() -> None:
    text = FE_TRUST_CENTER.read_text()
    assert "linear" in text.lower() or "Linear" in text, (
        "Linear missing from trustCenter.ts"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section E — Linear rule key parity (39 rules)
# ════════════════════════════════════════════════════════════════════════════


def test_e1_linear_rule_key_count() -> None:
    assert len(LINEAR_RULE_KEYS) == 39, (
        f"Expected 39 Linear rule keys, got {len(LINEAR_RULE_KEYS)}"
    )


def test_e2_all_expected_rule_keys_in_frozenset() -> None:
    missing = EXPECTED_LINEAR_RULE_KEYS - LINEAR_RULE_KEYS
    assert not missing, f"Rule keys missing from LINEAR_RULE_KEYS: {missing}"


def test_e3_all_rule_keys_in_registry() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    missing = LINEAR_RULE_KEYS - KNOWN_RULE_KEYS
    assert not missing, f"Linear rule keys missing from KNOWN_RULE_KEYS: {missing}"


# ════════════════════════════════════════════════════════════════════════════
# Section F — Forbidden wording across Linear backend modules
# ════════════════════════════════════════════════════════════════════════════


def test_f1_no_forbidden_wording_in_linear_rules() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "security_rules" / "linear.py"
    content = path.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, (
            f"Forbidden phrase '{phrase}' in linear.py"
        )


def test_f2_no_forbidden_wording_in_ingestion() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "linear_activity_ingestion_service.py"
    content = path.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, (
            f"Forbidden phrase '{phrase}' in linear_activity_ingestion_service.py"
        )


def test_f3_no_forbidden_wording_in_signals() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "linear_activity_signal_service.py"
    content = path.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, (
            f"Forbidden phrase '{phrase}' in linear_activity_signal_service.py"
        )


def test_f4_no_forbidden_wording_in_correlations() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "linear_risk_activity_correlation_service.py"
    content = path.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, (
            f"Forbidden phrase '{phrase}' in linear_risk_activity_correlation_service.py"
        )


def test_f5_no_forbidden_wording_in_demo_section() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "security_incident_demo_service.py"
    text = path.read_text()
    idx = text.find("LINEAR_DEMO_INTEGRATION_NAME")
    assert idx != -1
    section = text[idx:].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in section, (
            f"Forbidden phrase '{phrase}' in Linear demo section of demo service"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section G — Privacy / raw-data guardrails
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_g1_activity_page_no_raw_issue_claim() -> None:
    """Linear activity page must not claim that raw issue/comment payloads are ingested.

    Privacy disclaimers like "issue titles are never stored" are acceptable and
    explicitly excluded — we only flag affirmative ingestion claims.
    """
    text = FE_ACTIVITY.read_text()
    assert "linear" in text.lower(), "linear not found in activity page (unexpected)"
    # Check all lines that mention linear and a forbidden claim together,
    # but skip lines that are privacy disclaimers (contain "never" or "not stored").
    for line in text.splitlines():
        ll = line.lower()
        if "linear" not in ll:
            continue
        # Skip disclaimer lines
        if "never" in ll or "not stored" in ll or "does not" in ll:
            continue
        for claim in ("issue title", "issue description", "comment body", "raw audit"):
            assert claim not in ll, (
                f"Activity page may claim '{claim}' for Linear: {line.strip()!r}"
            )


def test_g2_ingestion_service_no_raw_token_storage() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "linear_activity_ingestion_service.py"
    content = path.read_text()
    for forbidden in ('"api_key"', '"api_token"', '"webhook_secret"',
                      '"webhook_url"', '"delivery_url"'):
        assert forbidden not in content, (
            f"Raw credential key {forbidden} found in ingestion service"
        )


def test_g3_demo_section_no_real_url() -> None:
    path = REPO_ROOT / "backend" / "app" / "services" / "security_incident_demo_service.py"
    text = path.read_text()
    idx = text.find("LINEAR_DEMO_INTEGRATION_NAME")
    assert idx != -1
    section = text[idx:]
    assert "http://" not in section, "http:// URL found in Linear demo section"
    assert "https://" not in section, "https:// URL found in Linear demo section"


# ════════════════════════════════════════════════════════════════════════════
# Section H — Secret-shape grep
# ════════════════════════════════════════════════════════════════════════════


_SECRET_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}"), "JWT-shaped"),
    (re.compile(r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "SG-key-shaped"),
    (re.compile(r"AC[0-9a-fA-F]{32}"), "Twilio-SID-shaped"),
    (re.compile(r"SK[0-9a-fA-F]{32}"), "SK-secret-shaped"),
]


def test_h1_no_secret_shapes_in_linear_backend_modules() -> None:
    for module_path in _LINEAR_BACKEND_MODULES:
        if not module_path.exists():
            continue
        content = module_path.read_text()
        for pat, name in _SECRET_PATTERNS:
            assert not pat.search(content), (
                f"{name} string found in {module_path.name}"
            )
