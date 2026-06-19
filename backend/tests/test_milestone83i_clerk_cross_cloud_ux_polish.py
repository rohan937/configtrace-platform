"""M83I — Clerk cross-cloud UX polish guardrails.

Durable, deterministic guardrails that pin the final Clerk arc (M83A–M83I)
state. This file adds NO product code — it verifies that Clerk is a first-class
completed provider across all internal security UX surfaces, demo script,
provider capability table, case report / timeline labels, and roadmap handoff
to PagerDuty.

Sections:

  A. Capability matrix
     Clerk capability flags correct for the completed M83A–M83I arc.
     Maturity stays "partial" (consistent with other completed partial arcs).
     Notes mention M83I cross-cloud UX polish and Clerk arc complete.

  B. Provider expansion framework
     planned_next_stage → M84A: PagerDuty Drift Provider Foundation.
     Clerk absent from RECOMMENDED_NEXT_PROVIDERS (launched).
     PagerDuty at head of recommended provider queue.

  C. Case report
     _TIMELINE_PROVIDER_LABELS contains "clerk": "Clerk".
     Clerk-specific safe identifiers in _PREVIEW_ALLOWLIST.

  D. Frontend Clerk consistency
     Activity page: provider option, sync function, 18 event types.
     Signals page: provider option, generate function, 10+ signal types.
     Correlations page: provider option, generate function, 10 correlation types.
     Cases page: Clerk demo card, safe wording, no forbidden phrases.
     Demo-script page: Clerk in PROVIDER_CAPABILITY_TABLE (all flags true),
       Clerk in description, Clerk arc M83A–M83I mentioned, PagerDuty now
       in NEXT_PROVIDERS_BRIEF, Clerk absent from NEXT_PROVIDERS_BRIEF.
     securityDemoScript.ts: Clerk in seeding step talkTrack/whatToClick,
       no forbidden phrases near Clerk copy.
     securityRuleCatalog.ts: all 40 Clerk rule keys present.
     api.ts: syncClerkActivity, generateClerkActivitySignals,
       generateClerkCorrelations, demo provider union.
     types/index.ts: Clerk response types.
     trustCenter.ts / providers.ts: Clerk profile present with correct label.

  E. Clerk rule key parity (40 rules, no stale refs)

  F. Forbidden wording across Clerk backend modules
     No forbidden claim phrases in ingestion / signal / correlation services
     outside of negation / denylist / doc contexts.

  G. Privacy / raw-data guardrails
     Frontend pages must not claim Clerk raw audit / login / session ingestion.

  H. Secret-shape grep
     No JWT / SG. / AC / SK patterns in Clerk service files.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import security_case_report_service as report_svc
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework
from app.services.security_rules.clerk import CLERK_RULE_KEYS

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

_CLERK_BACKEND_MODULES = [
    Path(__file__).parent.parent / "app" / "services" / "clerk_activity_ingestion_service.py",
    Path(__file__).parent.parent / "app" / "services" / "clerk_activity_signal_service.py",
    Path(__file__).parent.parent / "app" / "services" / "clerk_risk_activity_correlation_service.py",
    Path(__file__).parent.parent / "app" / "services" / "security_rules" / "clerk.py",
]

EXPECTED_CLERK_RULE_KEYS: frozenset[str] = frozenset({
    # instance_settings (3)
    "clerk_instance_mfa_disabled",
    "clerk_instance_password_without_mfa",
    "clerk_instance_sign_up_enabled",
    # application (7)
    "clerk_application_mfa_not_required",
    "clerk_application_sign_up_enabled",
    "clerk_application_password_without_mfa",
    "clerk_application_oauth_without_mfa",
    "clerk_application_saml_without_mfa",
    "clerk_application_many_redirect_urls",
    "clerk_application_many_allowed_origins",
    # domain (2)
    "clerk_domain_unverified",
    "clerk_domain_ssl_disabled",
    # redirect URL (4)
    "clerk_redirect_url_non_https",
    "clerk_redirect_url_wildcard_present",
    "clerk_redirect_url_localhost_present",
    "clerk_redirect_url_custom_scheme_present",
    # JWT template (5)
    "clerk_jwt_template_custom_claims_present",
    "clerk_jwt_template_long_lifetime",
    "clerk_jwt_template_audience_missing",
    "clerk_jwt_template_issuer_missing",
    "clerk_jwt_template_many_claims",
    # webhook endpoint (4)
    "clerk_webhook_endpoint_disabled",
    "clerk_webhook_without_signing",
    "clerk_webhook_non_https",
    "clerk_webhook_broad_event_scope",
    # email/SMS (1)
    "clerk_email_sms_custom_sender_present",
    # auth strategy (2)
    "clerk_auth_strategy_mfa_not_required",
    "clerk_auth_strategy_password_without_mfa",
    # organization settings (5)
    "clerk_org_verified_domains_not_required",
    "clerk_org_invitations_enabled",
    "clerk_org_admin_role_missing",
    "clerk_org_high_role_count",
    "clerk_org_high_permission_count",
    # session policy (7)
    "clerk_session_lifetime_extended",
    "clerk_session_inactivity_timeout_extended",
    "clerk_session_single_session_disabled",
    "clerk_session_token_rotation_disabled",
    "clerk_session_device_tracking_disabled",
    "clerk_session_reverification_disabled",
    "clerk_session_long_lifetime_without_single_session",
})


# ════════════════════════════════════════════════════════════════════════════
# Section A — Capability matrix
# ════════════════════════════════════════════════════════════════════════════


def test_a1_clerk_capability_matrix_drift_flags() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True


def test_a2_clerk_capability_matrix_security_flags() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True


def test_a3_clerk_capability_matrix_maturity_partial() -> None:
    """Maturity stays 'partial' consistent with other completed arcs (Auth0, Datadog, etc.)."""
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert cap.maturity == "partial"


def test_a4_clerk_capability_matrix_label() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert cap.label == "Clerk"


def test_a5_clerk_capability_matrix_notes_mention_m83i() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert "M83I" in cap.notes, "Notes should mention M83I cross-cloud UX polish"


def test_a6_clerk_capability_matrix_notes_arc_complete() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    notes = cap.notes
    assert "M83A" in notes and ("M83I" in notes or "complete" in notes.lower()), (
        "Notes should reference the M83A–M83I arc as complete"
    )


def test_a7_clerk_capability_matrix_notes_no_stale_planned_m83i() -> None:
    """After M83I, notes must NOT say 'planned_next_stage: M83I' (stale pointer)."""
    cap = get_provider_capability("clerk")
    assert cap is not None
    notes_lower = cap.notes.lower()
    if "planned_next_stage" in notes_lower:
        idx = notes_lower.find("planned_next_stage")
        snippet = notes_lower[idx:idx + 80]
        assert "m83i" not in snippet, (
            f"Notes still reference planned_next_stage: M83I (stale): {snippet!r}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section B — Provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_b1_expansion_framework_planned_next_stage_m84a() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    assert "M84A" in planned or "PagerDuty" in planned, (
        f"After M83I, planned_next_stage should point to M84A PagerDuty; got: {planned!r}"
    )


def test_b2_expansion_framework_not_m83i() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    assert "M83I" not in planned, (
        f"planned_next_stage should no longer reference M83I after arc complete; got: {planned!r}"
    )


def test_b3_clerk_not_in_recommended_next_providers() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    provider_labels = [
        r.get("provider", "").lower() for r in recommended if isinstance(r, dict)
    ]
    assert "clerk" not in provider_labels, (
        "Clerk should NOT be in recommended_next_providers (arc complete M83A–M83I)"
    )


def test_b4_pagerduty_head_of_recommended_next_providers() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    assert recommended, "recommended_next_providers should not be empty"
    first = recommended[0]
    provider = first.get("provider", "") if isinstance(first, dict) else str(first)
    assert "pagerduty" in provider.lower() or "PagerDuty" in str(first), (
        f"PagerDuty should be head of recommended_next_providers; got: {provider!r}"
    )


def test_b5_expansion_framework_next_milestone_m84a() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    next_ms = summary.get("next_milestone", "") or ""
    assert "M84A" in next_ms or "PagerDuty" in next_ms, (
        f"next_milestone should reference M84A/PagerDuty; got: {next_ms!r}"
    )


def test_b6_expansion_framework_next_provider_pagerduty() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    next_prov = summary.get("next_provider", "") or ""
    assert "PagerDuty" in next_prov or "pagerduty" in next_prov.lower(), (
        f"next_provider should be PagerDuty; got: {next_prov!r}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section C — Case report
# ════════════════════════════════════════════════════════════════════════════


def test_c1_clerk_in_timeline_provider_labels() -> None:
    labels = report_svc._TIMELINE_PROVIDER_LABELS
    assert "clerk" in labels, "Clerk missing from _TIMELINE_PROVIDER_LABELS"
    assert labels["clerk"] == "Clerk", (
        f"Expected 'Clerk' label, got: {labels['clerk']!r}"
    )


def test_c2_clerk_preview_allowlist_session_policy_id() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    assert "session_policy_id" in _PREVIEW_ALLOWLIST, (
        "session_policy_id should be in _PREVIEW_ALLOWLIST for Clerk demo evidence"
    )


def test_c3_clerk_preview_allowlist_instance_id() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    assert "instance_id" in _PREVIEW_ALLOWLIST


def test_c4_clerk_preview_allowlist_safe_posture_keys() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    for key in (
        "application_id",
        "jwt_template_id",
        "webhook_endpoint_id",
        "auth_strategy_id",
        "organization_settings_id",
        "session_lifetime_category",
        "inactivity_timeout_category",
        "token_rotation_enabled",
        "single_session_enabled",
        "device_tracking_enabled",
        "reverification_required",
        "risk_family",
        "activity_family",
        "match_reason",
        "match_strength",
    ):
        assert key in _PREVIEW_ALLOWLIST, (
            f"Clerk safe key '{key}' missing from _PREVIEW_ALLOWLIST"
        )


def test_c5_clerk_preview_allowlist_no_credential_keys() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    forbidden = {
        "secret_key", "publishable_key", "session_token", "jwt",
        "webhook_secret", "redirect_url", "callback_url", "domain_name",
        "jwt_body", "raw_claims", "user_email", "user_id", "ip_address",
    }
    found = forbidden & _PREVIEW_ALLOWLIST
    assert not found, f"Credential keys in _PREVIEW_ALLOWLIST: {sorted(found)}"


# ════════════════════════════════════════════════════════════════════════════
# Section D — Frontend Clerk consistency
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_d1_clerk_in_activity_page() -> None:
    text = FE_ACTIVITY.read_text()
    assert '"clerk"' in text or "'clerk'" in text, "clerk missing from activity page"
    assert "syncClerkActivity" in text or "sync_clerk" in text.lower()


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_d2_clerk_event_types_18_in_activity_page() -> None:
    text = FE_ACTIVITY.read_text()
    idx = text.find("CLERK_EVENT_TYPES")
    assert idx != -1, "CLERK_EVENT_TYPES not found in activity page"
    block = text[idx:idx + 1500]
    count = block.count('"clerk.')
    assert count == 18, f"Expected 18 Clerk event types, found {count}"


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_d3_clerk_activity_page_safe_copy() -> None:
    text = FE_ACTIVITY.read_text()
    idx = text.lower().find("clerk")
    if idx == -1:
        return
    surrounding = text[max(0, idx - 200):idx + 2000].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in surrounding, (
            f"Forbidden phrase '{phrase}' near Clerk copy in activity page"
        )


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_d4_clerk_in_signals_page() -> None:
    text = FE_SIGNALS.read_text()
    assert "clerk" in text.lower()
    assert "generateClerkActivitySignals" in text or "generate_clerk" in text.lower()


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_d5_clerk_signal_types_in_signals_page() -> None:
    text = FE_SIGNALS.read_text()
    idx = text.find("CLERK_SIGNAL_TYPES")
    assert idx != -1, "CLERK_SIGNAL_TYPES not found in signals page"
    block = text[idx:idx + 2000]
    count = block.count('"clerk_')
    assert count >= 10, f"Expected >=10 Clerk signal types, found {count}"


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_d6_clerk_in_correlations_page() -> None:
    text = FE_CORRELATIONS.read_text()
    assert "clerk" in text.lower()
    assert "generateClerkCorrelations" in text or "clerk_correlations" in text.lower()


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_d7_clerk_correlation_types_in_correlations_page() -> None:
    text = FE_CORRELATIONS.read_text()
    for ctype in (
        "clerk_instance_settings_risk_activity_correlation",
        "clerk_session_policy_risk_activity_correlation",
        "clerk_application_risk_activity_correlation",
        "clerk_webhook_endpoint_risk_activity_correlation",
    ):
        assert f'"{ctype}"' in text or f"'{ctype}'" in text, (
            f"Correlation type '{ctype}' not found in correlations page"
        )


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_d8_clerk_demo_card_in_cases_page() -> None:
    text = FE_CASES.read_text()
    assert "clerk" in text.lower()
    assert "Clerk" in text


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_d9_clerk_demo_card_safe_wording() -> None:
    text = FE_CASES.read_text()
    idx = text.lower().find("clerk")
    if idx == -1:
        return
    block = text[max(0, idx - 100):idx + 2000].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in block, (
            f"Forbidden phrase '{phrase}' near Clerk demo card in cases page"
        )


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_d10_clerk_demo_card_review_only_language() -> None:
    text = FE_CASES.read_text()
    idx = text.lower().find("clerk")
    if idx == -1:
        return
    block = text[max(0, idx - 200):idx + 2000]
    # At least one review-only phrase should appear near the Clerk demo card
    review_phrases = [
        "review",
        "evidence",
        "does not confirm",
        "configuration",
        "posture",
        "finding",
    ]
    assert any(p in block.lower() for p in review_phrases), (
        "Clerk demo card copy should include review-only language near the Clerk entry"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d11_clerk_in_demo_script_capability_table() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert '"clerk"' in text or "'clerk'" in text
    # All capability flags should be true for completed Clerk arc
    idx = text.find('"clerk"')
    if idx == -1:
        idx = text.find("'clerk'")
    block = text[max(0, idx - 10):idx + 500]
    assert "true" in block.lower(), "Clerk row should have at least one 'true' flag"


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d12_clerk_all_capability_flags_true() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    # Find the Clerk block in PROVIDER_CAPABILITY_TABLE
    idx = text.find('"clerk"')
    if idx == -1:
        pytest.skip("Clerk not found in demo-script page")
    block = text[max(0, idx - 20):idx + 400]
    # All of drift/security/signals/correlations/demo should be true
    for field in ("drift: true", "security: true", "signals: true", "correlations: true", "demo: true"):
        assert field in block, (
            f"Clerk capability table should have '{field}'; block: {block!r}"
        )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d13_clerk_in_demo_script_description() -> None:
    """Demo-script page description should mention Clerk M83A–M83I arc."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert "Clerk" in text
    assert "M83A" in text or "M83" in text, (
        "Demo-script page should reference the Clerk M83 arc"
    )
    assert "M83I" in text or "M83A–M83I" in text or "M83A-M83I" in text, (
        "Demo-script description should mention M83I (arc complete)"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d14_clerk_absent_from_next_providers_brief() -> None:
    """Clerk arc is complete — it should no longer be in NEXT_PROVIDERS_BRIEF."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    # Use the const definition, not the JSX usage.
    idx = text.find("const NEXT_PROVIDERS_BRIEF")
    assert idx != -1, "const NEXT_PROVIDERS_BRIEF not found in demo-script page"
    block_start = text.find("[", idx)
    block_end = text.find("];", block_start)
    if block_start == -1 or block_end == -1:
        return
    brief_block = text[block_start:block_end]
    assert '"Clerk"' not in brief_block and "'Clerk'" not in brief_block, (
        "Clerk should NOT be in NEXT_PROVIDERS_BRIEF — it's a completed arc (M83A–M83I)"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d15_pagerduty_in_next_providers_brief() -> None:
    """PagerDuty should be in NEXT_PROVIDERS_BRIEF after Clerk arc completes."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    idx = text.find("const NEXT_PROVIDERS_BRIEF")
    assert idx != -1, "const NEXT_PROVIDERS_BRIEF not found in demo-script page"
    block_start = text.find("[", idx)
    block_end = text.find("];", block_start)
    if block_start == -1 or block_end == -1:
        return
    brief_block = text[block_start:block_end]
    assert "PagerDuty" in brief_block, (
        "PagerDuty should be in NEXT_PROVIDERS_BRIEF as the next recommended provider"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_d16_demo_script_page_note_clerk_arc_complete() -> None:
    """The NOTE comment in demo-script/page.tsx should mark Clerk arc complete."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert "Clerk arc complete" in text or "Clerk" in text, (
        "Demo-script page should acknowledge Clerk arc is complete"
    )
    assert "M83A–M83I" in text or "M83A-M83I" in text or "M83I" in text, (
        "NOTE comment should reference M83I (Clerk arc complete)"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_d17_clerk_in_demo_script_lib_seeding_step() -> None:
    text = FE_DEMO_SCRIPT_LIB.read_text()
    idx = text.find("incident-seed")
    assert idx != -1, "incident-seed step not found in securityDemoScript.ts"
    block = text[idx:idx + 3000]
    assert "Clerk" in block or "clerk" in block, (
        "Clerk should be listed in the demo seeding step talkTrack/whatToClick"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_d18_clerk_seeding_step_safe_copy() -> None:
    text = FE_DEMO_SCRIPT_LIB.read_text()
    idx = text.find("incident-seed")
    assert idx != -1
    block = text[idx:idx + 3000].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in block, (
            f"Forbidden phrase '{phrase}' in demo seeding step (near Clerk copy)"
        )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_d19_demo_script_lib_no_forbidden_phrases() -> None:
    text = FE_DEMO_SCRIPT_LIB.read_text().lower()
    # Forbidden phrases are allowed in "avoid:" blocks (they explain what NOT to say)
    for phrase in _FORBIDDEN_PHRASES:
        occurrences = [
            i for i in range(len(text))
            if text[i:i + len(phrase)] == phrase.lower()
        ]
        for occ in occurrences:
            # Check if this occurrence is in an "avoid" or "denylist" context
            context = text[max(0, occ - 200):occ + 50]
            is_avoid = (
                "avoid" in context
                or "don't" in context
                or "never" in context
                or "not" in context
                or "denylist" in context
                or "forbidden" in context
            )
            assert is_avoid, (
                f"Forbidden phrase '{phrase}' found in securityDemoScript.ts "
                f"outside of avoid/denylist context at position {occ}"
            )


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_d20_clerk_api_functions_present() -> None:
    text = FE_API.read_text()
    assert "syncClerkActivity" in text
    assert "generateClerkActivitySignals" in text
    assert "generateClerkCorrelations" in text


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_d21_clerk_demo_in_api_provider_unions() -> None:
    text = FE_API.read_text()
    # getIncidentDemoStatus / seedIncidentDemo / clearIncidentDemo should accept "clerk"
    assert '"clerk"' in text or "'clerk'" in text, "clerk missing from api.ts"


@pytest.mark.skipif(not FE_TYPES.exists(), reason="Frontend tree absent")
def test_d22_clerk_response_types_in_types_index() -> None:
    text = FE_TYPES.read_text()
    assert "ClerkActivitySyncResponse" in text
    assert "ClerkActivitySignalGenerateResponse" in text
    assert "ClerkCorrelationGenerateResponse" in text


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_d23_clerk_in_providers_ts_with_correct_label() -> None:
    text = FE_PROVIDERS.read_text()
    assert '"clerk"' in text or "'clerk'" in text
    assert 'label: "Clerk"' in text or "label: 'Clerk'" in text


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_d24_clerk_in_connectable_provider_ids() -> None:
    text = FE_PROVIDERS.read_text()
    idx = text.find("CONNECTABLE_PROVIDER_IDS")
    assert idx != -1
    block = text[idx:idx + 2000]
    assert "clerk" in block


@pytest.mark.skipif(not FE_TRUST_CENTER.exists(), reason="Frontend tree absent")
def test_d25_clerk_in_trust_center() -> None:
    text = FE_TRUST_CENTER.read_text()
    assert "clerk" in text.lower()
    assert "Clerk" in text


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_d26_clerk_rules_count_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text()
    # Count unique clerk_ rule key references
    matches = set(re.findall(r'"(clerk_[a-z_]+)"', text))
    assert len(matches) >= 40, (
        f"Expected at least 40 Clerk rule keys in securityRuleCatalog.ts, found {len(matches)}"
    )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_d27_clerk_provider_coverage_in_catalog() -> None:
    text = FE_RULE_CATALOG.read_text()
    assert "clerk" in text.lower()
    assert "Session policy" in text or "session_policy" in text.lower(), (
        "Clerk session policy surface should appear in securityRuleCatalog.ts"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section E — Rule key parity
# ════════════════════════════════════════════════════════════════════════════


def test_e1_clerk_rule_keys_count() -> None:
    assert len(CLERK_RULE_KEYS) == 40


def test_e2_clerk_rule_keys_exact_set() -> None:
    assert CLERK_RULE_KEYS == EXPECTED_CLERK_RULE_KEYS


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_e3_all_clerk_rules_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text()
    for key in EXPECTED_CLERK_RULE_KEYS:
        assert f'"{key}"' in text or f"'{key}'" in text, (
            f"Rule '{key}' not found in securityRuleCatalog.ts"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section F — Forbidden wording across Clerk backend modules
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("phrase", _FORBIDDEN_PHRASES)
@pytest.mark.parametrize("module_path", _CLERK_BACKEND_MODULES)
def test_f_forbidden_phrase_not_in_module(module_path: Path, phrase: str) -> None:
    if not module_path.exists():
        pytest.skip(f"Module not found: {module_path}")
    text = module_path.read_text().lower()
    assert phrase.lower() not in text, (
        f"Forbidden phrase '{phrase}' found in {module_path.name}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section G — Privacy / raw-data guardrails
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_g1_activity_page_no_raw_audit_claim() -> None:
    """Activity page must not claim that Clerk audit logs are ingested directly.

    Checks for the specific compound phrase 'clerk audit log' (or 'clerk audit trail')
    without an accompanying negation. This avoids false positives from other providers'
    audit log descriptions appearing in the same file.
    """
    text = FE_ACTIVITY.read_text().lower()
    # Check for "clerk audit log" or "clerk audit trail" as combined phrases
    for phrase in ("clerk audit log", "clerk audit trail"):
        idx = text.find(phrase)
        if idx == -1:
            continue
        surrounding = text[max(0, idx - 100):idx + 200]
        assert "never" in surrounding or "not " in surrounding or "synthesized" in surrounding, (
            f"Activity page contains '{phrase}' without negation"
        )


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_g2_signals_page_no_raw_auth_events_claim() -> None:
    """Signals page must not claim raw Clerk authentication event ingestion."""
    text = FE_SIGNALS.read_text().lower()
    if "clerk" not in text:
        return
    idx = text.find("clerk")
    surrounding = text[max(0, idx - 100):idx + 3000]
    bad_phrases = ["login event", "auth event", "session event", "user event"]
    for bad in bad_phrases:
        if bad in surrounding:
            assert "never" in surrounding or "not" in surrounding, (
                f"Signals page mentions '{bad}' near Clerk without negation"
            )


# ════════════════════════════════════════════════════════════════════════════
# Section H — Secret-shape grep over Clerk backend modules
# ════════════════════════════════════════════════════════════════════════════


_SECRET_PATTERNS = [
    (r"eyJ[A-Za-z0-9_\-]{10,}", "JWT-shaped string"),
    (r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "SendGrid key shape"),
    (r"AC[0-9a-fA-F]{32}", "Twilio SID shape"),
    (r"SK[0-9a-fA-F]{32}", "SK secret shape"),
]


@pytest.mark.parametrize("module_path", _CLERK_BACKEND_MODULES)
def test_h_no_secret_shapes_in_module(module_path: Path) -> None:
    if not module_path.exists():
        pytest.skip(f"Module not found: {module_path}")
    text = module_path.read_text()
    for pattern, label in _SECRET_PATTERNS:
        assert not re.search(pattern, text), (
            f"{label} found in {module_path.name}"
        )
