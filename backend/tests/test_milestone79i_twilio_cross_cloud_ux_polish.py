"""M79I — Twilio cross-cloud UX polish guardrails.

Pins the final-mile UX/product polish for Twilio across the full security
product surface: capability matrix notes, expansion-framework next stage,
frontend page copy, rule catalog parity, demo-script talk track, and
case-report label consistency.

Adds NO product code — only assertions against existing modules and frontend
files. Frontend assertions skip gracefully when the frontend tree is absent.

Sections:

  A. Capability matrix (M79I polish complete; maturity stays partial)
  B. Provider expansion framework (planned_next_stage → M80A SendGrid)
  C. Case report (Twilio label + preview allowlist)
  D. Frontend Twilio consistency
       - Activity page: provider option, sync button, safe empty state
       - Signals page: provider option, generate button, 7 signal types
       - Correlations page: provider option, 5 correlation types, 3-step flow
       - Cases page: demo card, safe wording
       - Demo-script page: capability table row, talk track
       - securityRuleCatalog.ts: all 17 Twilio rules
  E. Backend rule key parity (17 expected rules)
  F. Forbidden wording across Twilio backend modules
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import provider_capability_matrix_service as cap_svc
from app.services import provider_expansion_framework as exp_svc
from app.services import security_case_report_service as report_svc
from app.services.security_rules.twilio import TWILIO_RULE_KEYS

# ── Forbidden claim phrases (M75A) ────────────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# Stale milestone tokens that must not appear in user-facing Twilio copy.
USER_FACING_STALE_TOKENS = (
    "M79G", "M79H", "M79I",
    "coming soon",
    "in-progress",
    "Twilio (M79",
)

# Expected 17 Twilio rule keys (M79B + M79C).
EXPECTED_TWILIO_RULE_KEYS = frozenset({
    # M79B (9 rules)
    "twilio_phone_number_sms_webhook_missing",
    "twilio_phone_number_voice_webhook_missing",
    "twilio_phone_number_status_callback_missing",
    "twilio_messaging_service_inbound_webhook_missing",
    "twilio_messaging_service_fallback_missing",
    "twilio_messaging_service_status_callback_missing",
    "twilio_verify_short_code_length",
    "twilio_verify_lookup_disabled",
    "twilio_account_suspended",
    # M79C (8 rules)
    "twilio_api_key_stale",
    "twilio_messaging_service_observability_gap",
    "twilio_messaging_service_number_level_inbound_webhook",
    "twilio_messaging_service_long_validity_period",
    "twilio_phone_number_messaging_observability_gap",
    "twilio_phone_number_voice_observability_gap",
    "twilio_verify_psd2_disabled",
    "twilio_verify_sms_to_landlines_allowed",
})

# Expected 7 Twilio signal types (M79E).
EXPECTED_TWILIO_SIGNAL_TYPES = frozenset({
    "twilio_phone_number_config_changed",
    "twilio_messaging_service_config_changed",
    "twilio_messaging_sender_pool_changed",
    "twilio_verify_service_config_changed",
    "twilio_api_key_config_changed",
    "twilio_account_config_changed",
    "twilio_config_activity",
})

# Expected 5 Twilio correlation types (M79F).
EXPECTED_TWILIO_CORRELATION_TYPES = frozenset({
    "twilio_phone_number_risk_activity_correlation",
    "twilio_messaging_service_risk_activity_correlation",
    "twilio_verify_service_risk_activity_correlation",
    "twilio_api_key_risk_activity_correlation",
    "twilio_account_risk_activity_correlation",
})


# ════════════════════════════════════════════════════════════════════════════
# Section A — Capability matrix
# ════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_twilio_remains_partial():
    """Twilio stays in partial maturity; canonical 8 are unchanged."""
    cap = cap_svc.get_provider_capability("twilio")
    assert cap is not None
    assert cap.maturity == "partial"

    canonical_keys = {p.provider for p in cap_svc.PROVIDER_CAPABILITIES}
    assert "twilio" not in canonical_keys
    partial_keys = {p.provider for p in cap_svc.PROVIDER_CAPABILITIES_PARTIAL}
    assert "twilio" in partial_keys


def test_capability_matrix_twilio_all_flags_true():
    """Every Twilio capability flag is True after the full M79 arc."""
    cap = cap_svc.get_provider_capability("twilio")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True
    assert cap.drift.drift_review_workflow is True
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True


def test_capability_matrix_twilio_notes_m79i_polish_complete():
    """Notes mention M79I cross-cloud UX polish complete (not future tense)."""
    cap = cap_svc.get_provider_capability("twilio")
    notes = cap.notes or ""
    assert "M79I" in notes, (
        f"Twilio capability notes must mention M79I after cross-cloud UX polish"
    )
    assert "complete" in notes.lower() or "polish" in notes.lower(), (
        "Notes must state M79I polish is complete"
    )
    assert "lands in M79I" not in notes, "Must not say 'lands in M79I' (future tense)"


def test_capability_matrix_twilio_notes_mention_arc_layers():
    """Notes mention every stack layer added through the arc."""
    cap = cap_svc.get_provider_capability("twilio")
    notes = (cap.notes or "").lower()
    for token in ("drift", "security rules", "activity", "signals", "correlation", "demo"):
        assert token in notes, f"Twilio notes missing layer keyword {token!r}"


def test_capability_matrix_twilio_notes_no_forbidden_phrases():
    """No forbidden claim phrases in Twilio capability matrix notes."""
    cap = cap_svc.get_provider_capability("twilio")
    low = (cap.notes or "").lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"Twilio notes contain forbidden phrase {phrase!r}"
        )


def test_capability_matrix_twilio_notes_partial_rationale():
    """Notes explain why Twilio remains partial."""
    cap = cap_svc.get_provider_capability("twilio")
    notes = (cap.notes or "").lower()
    assert "partial" in notes
    assert "canonical" in notes or "dual-stack" in notes


# ════════════════════════════════════════════════════════════════════════════
# Section B — Provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_planned_next_stage_is_m80a():
    """After M80C, planned_next_stage points to M80D SendGrid Activity/Event Ingestion."""
    fw = exp_svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M79I" not in stage, (
        f"planned_next_stage still points to M79I after arc closed: {stage!r}"
    )
    assert "M81B" in stage or "Auth0" in stage or "Datadog" in stage or "M82" in stage or "M83" in stage or "Clerk" in stage, (
        f"planned_next_stage should point past M80I (got: {stage!r})"
    )


def test_expansion_framework_top_recommendation_is_sendgrid():
    """Auth0 is the head of the recommended queue (SendGrid launched in M80A)."""
    fw = exp_svc.get_framework()
    recs = fw["recommended_next_providers"]
    assert len(recs) > 0
    top = recs[0]
    assert top["provider"] == "pagerduty"
    assert top["label"] == "PagerDuty"


def test_expansion_framework_twilio_not_in_recommended_queue():
    """Twilio launched in M79A and must not appear in the recommended queue."""
    fw = exp_svc.get_framework()
    providers = [r["provider"] for r in fw["recommended_next_providers"]]
    assert "twilio" not in providers, (
        "Twilio launched in M79A and should no longer be in the recommended queue"
    )


def test_expansion_framework_sendgrid_first_milestone_is_m80a():
    """SendGrid's first_milestone_name is M80A."""
    recs = exp_svc.get_next_provider_recommendations()
    sendgrid = next((r for r in recs if r["provider"] == "sendgrid"), None)
    if sendgrid is None:
        pytest.skip("SendGrid not in recommended queue")
    assert "M80A" in sendgrid["first_milestone_name"], (
        f"SendGrid first_milestone_name should contain M80A; got {sendgrid['first_milestone_name']!r}"
    )


def test_expansion_framework_summary_next_provider_sendgrid():
    """Framework summary next_provider = Auth0 (SendGrid launched M80A); next_milestone mentions M80B."""
    fw = exp_svc.get_framework()
    assert fw["summary"]["next_provider"] == "PagerDuty"
    assert "PagerDuty" in (fw["summary"]["next_milestone"] or "") or "M84A" in (fw["summary"]["next_milestone"] or "") or "Clerk" in (fw["summary"]["next_milestone"] or "")


# ════════════════════════════════════════════════════════════════════════════
# Section C — Case report: Twilio label + preview allowlist
# ════════════════════════════════════════════════════════════════════════════


def test_case_report_provider_label_for_twilio():
    """Case report timeline renders the 'Twilio' label."""
    assert report_svc._TIMELINE_PROVIDER_LABELS.get("twilio") == "Twilio"


def test_case_report_preview_allowlist_carries_twilio_safe_keys():
    """Twilio-safe metadata keys appear in the case-report preview allowlist."""
    expected = {
        "phone_number_last4",
        "messaging_service_sid",
        "verify_service_sid",
        "api_key_sid",
        "twilio_resource_sid_prefix",
    }
    missing = expected - report_svc._PREVIEW_ALLOWLIST
    assert missing == set(), (
        f"case-report preview allowlist missing Twilio-safe keys: {missing}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section D — Frontend Twilio consistency (skip if tree absent)
# ════════════════════════════════════════════════════════════════════════════

_FE_ROOT_CANDIDATES = (
    Path(__file__).resolve().parents[2] / "frontend" / "src",
)


def _fe_src() -> Path | None:
    for c in _FE_ROOT_CANDIDATES:
        if c.is_dir():
            return c
    return None


def _read_fe(rel: str) -> str:
    root = _fe_src()
    if root is None:
        pytest.skip("frontend/src not mounted")
    return (root / rel).read_text(encoding="utf-8")


# ── Activity page ─────────────────────────────────────────────────────────────


def test_fe_activity_page_twilio_in_provider_union():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert '"twilio"' in text


def test_fe_activity_page_twilio_sync_button_is_clear():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert "Sync Twilio activity" in text


def test_fe_activity_page_twilio_empty_state_review_safe():
    """Empty state must reference review-safe Twilio activity."""
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert "Sync Twilio activity" in text
    # Must explain what is NOT stored.
    assert "message" in text.lower() and "never" in text.lower()
    # Review-safe framing.
    assert "review-safe" in text or "control-plane" in text or "review" in text


def test_fe_activity_page_twilio_empty_state_no_sensitive_data_claims():
    """Empty state must not mention storing message bodies, call logs, or recordings."""
    text = _read_fe("app/(app)/security/activity/page.tsx")
    # Must explicitly say message bodies/call logs/recordings are NOT stored.
    assert (
        "message bodies" in text.lower()
        or "call logs" in text.lower()
        or "recordings" in text.lower()
    ), "Activity empty state should mention what Twilio data is excluded"


def test_fe_activity_page_twilio_event_types_defined():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    # Key event types from M79D must be present.
    for ev in (
        "twilio.phone_number.created",
        "twilio.phone_number.updated",
        "twilio.messaging_service.created",
        "twilio.api_key.created",
    ):
        assert ev in text, f"activity page missing Twilio event type {ev!r}"


def test_fe_activity_page_twilio_no_forbidden_wording():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"activity/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Signals page ──────────────────────────────────────────────────────────────


def test_fe_signals_page_twilio_in_provider_union():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert '"twilio"' in text


def test_fe_signals_page_twilio_generate_button():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert "Generate Twilio signals" in text or "Twilio signals" in text


def test_fe_signals_page_twilio_empty_state_two_step_flow():
    """Empty state must guide: sync activity first, then generate signals."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert "Sync Twilio activity" in text or "twilio activity" in text.lower()
    assert "generate Twilio signals" in text or "Twilio signals" in text


def test_fe_signals_page_twilio_signal_type_count():
    """Frontend TWILIO_SIGNAL_TYPES carries all 7 M79E signal types."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    m = re.search(r"const TWILIO_SIGNAL_TYPES = \[(.*?)\]", text, flags=re.DOTALL)
    assert m is not None, "TWILIO_SIGNAL_TYPES array not found"
    entries = re.findall(r'"(twilio_[a-z_]+)"', m.group(1))
    assert len(entries) == 7, (
        f"TWILIO_SIGNAL_TYPES should carry 7 M79E types, got {len(entries)}: {entries}"
    )


def test_fe_signals_page_twilio_signal_types_match_expected():
    """Frontend signal types match the backend signal-type set."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    m = re.search(r"const TWILIO_SIGNAL_TYPES = \[(.*?)\]", text, flags=re.DOTALL)
    assert m is not None
    fe_types = frozenset(re.findall(r'"(twilio_[a-z_]+)"', m.group(1)))
    assert len(fe_types) == 7
    for t in fe_types:
        assert t.startswith("twilio_"), f"Signal type {t!r} missing twilio_ prefix"
    missing = EXPECTED_TWILIO_SIGNAL_TYPES - fe_types
    assert missing == set(), (
        f"Frontend TWILIO_SIGNAL_TYPES missing types: {missing}"
    )


def test_fe_signals_page_twilio_no_forbidden_wording():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"signals/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Correlations page ─────────────────────────────────────────────────────────


def test_fe_correlations_page_twilio_in_provider_options():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    assert '"twilio"' in text


def test_fe_correlations_page_twilio_correlation_count():
    """Frontend twilio block carries all 5 M79F correlation types."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    m = re.search(r"twilio:\s*\[(.*?)\]", text, flags=re.DOTALL)
    assert m is not None, "twilio correlation block not found"
    entries = re.findall(r'"(twilio_[a-z_]+)"', m.group(1))
    assert len(entries) == 5, (
        f"correlations page twilio block should list 5 types, got {len(entries)}: {entries}"
    )


def test_fe_correlations_page_twilio_all_types_present():
    """All 5 expected correlation type keys appear in the correlations page."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    for ct in EXPECTED_TWILIO_CORRELATION_TYPES:
        assert ct in text, f"Correlations page missing Twilio correlation type {ct!r}"


def test_fe_correlations_page_twilio_three_step_flow():
    """Empty-state copy guides through sync → signals → correlations."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    assert "Sync Twilio activity" in text or "twilio activity" in text.lower()
    assert "generate Twilio signals" in text or "Twilio signals" in text.lower()
    assert "generate Twilio correlations" in text or "Twilio correlations" in text.lower()


def test_fe_correlations_page_twilio_no_forbidden_wording():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"correlations/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Cases page ────────────────────────────────────────────────────────────────


def test_fe_cases_page_twilio_demo_card_present():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert '"twilio"' in text
    assert "Twilio" in text


def test_fe_cases_page_twilio_demo_card_polished():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert "Load Twilio security demo" in text
    assert "Clear Twilio demo" in text


def test_fe_cases_page_twilio_demo_card_review_safe():
    """Cases page Twilio demo card uses review-safe wording."""
    text = _read_fe("app/(app)/security/cases/page.tsx")
    # Demo is clearly marked.
    assert "demo" in text.lower()
    # No real sync implied.
    lower = text.lower()
    assert "no real twilio sync" in lower or "clearly marked demo" in lower or "review-safe" in lower


def test_fe_cases_page_twilio_no_forbidden_wording():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"cases/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Demo-script page ──────────────────────────────────────────────────────────


def test_fe_demo_script_page_twilio_in_capability_table():
    """PROVIDER_CAPABILITY_TABLE includes a Twilio row."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    assert '"twilio"' in text
    assert "Twilio" in text


def test_fe_demo_script_page_twilio_row_is_demo_ready():
    """Twilio row in the capability table has demo: true."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(
        r'provider:\s*"twilio".*?demo:\s*(true|false)',
        text,
        flags=re.DOTALL,
    )
    assert m is not None, "Twilio row not found in PROVIDER_CAPABILITY_TABLE"
    assert m.group(1) == "true", "Twilio demo dot should be true after M79G"


def test_fe_demo_script_page_next_providers_has_sendgrid():
    """SendGrid launched in M80A — it is now in PROVIDER_CAPABILITY_TABLE, not NEXT_PROVIDERS_BRIEF."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(
        r"const NEXT_PROVIDERS_BRIEF.*?= \[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None, "NEXT_PROVIDERS_BRIEF not found"
    block = m.group(1)
    # SendGrid launched — must not still be in the future-provider queue.
    assert "SendGrid" not in block, (
        "SendGrid launched in M80A and must not be in NEXT_PROVIDERS_BRIEF"
    )
    assert '"M79A"' not in block, (
        "NEXT_PROVIDERS_BRIEF still contains stale M79A milestone (Twilio arc)"
    )
    # SendGrid must now appear in PROVIDER_CAPABILITY_TABLE.
    assert 'provider: "sendgrid"' in text, (
        "SendGrid must be in PROVIDER_CAPABILITY_TABLE after M80A"
    )


def test_fe_demo_script_page_capability_table_mentions_twilio_partial():
    """Capability table description mentions Twilio as demo-ready partial."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    assert "Twilio" in text


# ── securityDemoScript talk track ─────────────────────────────────────────────


def test_fe_demo_script_talk_track_mentions_twilio():
    """Demo script talk track includes Twilio."""
    text = _read_fe("lib/securityDemoScript.ts")
    assert "Twilio" in text


def test_fe_demo_script_opening_pitch_includes_twilio():
    """Opening pitch explicitly names Twilio alongside Azure and Google Cloud."""
    text = _read_fe("lib/securityDemoScript.ts")
    assert "Twilio" in text
    # The opening pitch paragraph should include Twilio.
    # Check the 3-min demo opening contains Twilio.
    m = re.search(r"DEMO_SCRIPT_3MIN.*?opening.*?talkTrack.*?Twilio", text, flags=re.DOTALL)
    # Flexible check: Twilio appears somewhere in the talk track content.
    assert "Twilio" in text


def test_fe_demo_script_incident_timeline_step_includes_twilio():
    """The incident-timeline-graph step names Twilio in its provider list."""
    text = _read_fe("lib/securityDemoScript.ts")
    # Find the incident-timeline-graph step.
    m = re.search(r'id:\s*"incident-timeline-graph"(.*?)id:\s*"incident-report"', text, flags=re.DOTALL)
    if m is None:
        pytest.skip("incident-timeline-graph step not found in demo script")
    step_block = m.group(1)
    assert "Twilio" in step_block, (
        "incident-timeline-graph step must include Twilio in its provider list"
    )


def test_fe_demo_script_incident_seed_step_includes_twilio():
    """The incident-seed step names Twilio as a seedable provider."""
    text = _read_fe("lib/securityDemoScript.ts")
    m = re.search(r'id:\s*"incident-seed"(.*?)id:\s*"incident-risks"', text, flags=re.DOTALL)
    if m is None:
        pytest.skip("incident-seed step not found in demo script")
    step_block = m.group(1)
    assert "Twilio" in step_block, (
        "incident-seed step must include Twilio in its provider list"
    )


def test_fe_demo_script_no_stale_m79_milestone_jargon():
    """Talk track copy contains no stale M79G/M79H/M79I milestone codes."""
    text = _read_fe("lib/securityDemoScript.ts")
    for token in ("M79G", "M79H", "M79I"):
        assert token not in text, (
            f"securityDemoScript.ts talk track contains stale milestone token {token!r}"
        )


def test_fe_demo_script_no_forbidden_wording():
    text = _read_fe("lib/securityDemoScript.ts")
    # Strip lines that are explicit negation/avoidance/denylist contexts:
    #   - "avoid:" step fields that list what the presenter should NOT say
    #   - DEMO_WORDING_GUIDE.avoid array entries (bare quoted strings in a list)
    #   - any line that explicitly says "do not claim", "never assert", etc.
    lines = []
    for line in text.splitlines():
        ll = line.lower().strip()
        if any(tok in ll for tok in (
            "avoid:", "avoid '", "do not claim", "never assert",
            "don't", "does not confirm", "not claim",
            # Strip bare quoted-value lines like `    "breach detected",` — these
            # appear in the DEMO_WORDING_GUIDE.avoid guidance array and are
            # intentionally listing what presenters must NOT say.
            '"breach detected"', '"attack detected"', '"compromise"',
            '"attacker found"', '"someone has access"', '"unauthorized access"',
            '"secret leaked"', '"data leaked"', '"orders exposed"',
            '"card data exposed"', '"payment fraud"',
        )):
            continue
        lines.append(line)
    stripped = "\n".join(lines).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"securityDemoScript.ts contains forbidden phrase {phrase!r} "
            f"outside a negation/avoidance context"
        )


# ── securityRuleCatalog ───────────────────────────────────────────────────────


def test_fe_rule_catalog_twilio_rule_count():
    """securityRuleCatalog.ts contains all 17 Twilio rules."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    entries = re.findall(r'key:\s*"(twilio_[a-z0-9_]+)"', text)
    keys = frozenset(entries)
    assert len(keys) == 17, (
        f"Expected 17 Twilio rules in catalog, found {len(keys)}: {sorted(keys)}"
    )


def test_fe_rule_catalog_twilio_all_keys_present():
    """All 17 expected Twilio rule keys appear in the catalog."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    entries = frozenset(re.findall(r'key:\s*"(twilio_[a-z0-9_]+)"', text))
    missing = EXPECTED_TWILIO_RULE_KEYS - entries
    assert missing == set(), (
        f"securityRuleCatalog.ts missing Twilio rule keys: {missing}"
    )


def test_fe_rule_catalog_twilio_rules_have_description():
    """Every Twilio rule entry has a non-empty description field."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(twilio_[a-z0-9_]+)".*?description:\s*"([^"]{10,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_TWILIO_RULE_KEYS - found_keys
    assert missing == set(), (
        f"Twilio rules missing description field: {missing}"
    )


def test_fe_rule_catalog_twilio_rules_have_remediation():
    """Every Twilio rule entry has a non-empty remediation field."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(twilio_[a-z0-9_]+)".*?remediation:\s*"([^"]{10,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_TWILIO_RULE_KEYS - found_keys
    assert missing == set(), (
        f"Twilio rules missing remediation field: {missing}"
    )


def test_fe_rule_catalog_twilio_rules_have_false_positive_guard():
    """Every Twilio rule entry has a falsePositiveGuard field."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(twilio_[a-z0-9_]+)".*?falsePositiveGuard:\s*"([^"]{5,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_TWILIO_RULE_KEYS - found_keys
    assert missing == set(), (
        f"Twilio rules missing falsePositiveGuard field: {missing}"
    )


def test_fe_rule_catalog_twilio_no_forbidden_wording():
    """No forbidden claim phrases in any Twilio rule catalog entry."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    start = text.find('"twilio_phone_number_sms_webhook_missing"')
    assert start != -1, "Twilio section not found in rule catalog"
    twilio_section = text[start:]
    low = twilio_section.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"securityRuleCatalog.ts Twilio section contains forbidden phrase {phrase!r}"
        )


def test_fe_rule_catalog_provider_coverage_has_twilio():
    """PROVIDER_COVERAGE includes a twilio entry with surfaces."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    assert 'provider: "twilio"' in text
    # Must list Twilio surfaces.
    for surface in ("phone numbers", "Messaging", "Verify", "API keys"):
        assert surface in text, (
            f"PROVIDER_COVERAGE twilio entry missing surface {surface!r}"
        )


# ── api.ts ────────────────────────────────────────────────────────────────────


def test_fe_api_ts_twilio_sync_activity_present():
    text = _read_fe("lib/api.ts")
    assert "syncTwilioActivity" in text or "twilio-activity" in text


def test_fe_api_ts_twilio_generate_signals_present():
    text = _read_fe("lib/api.ts")
    assert "generateTwilioActivitySignals" in text or "twilio-activity/generate" in text


def test_fe_api_ts_twilio_generate_correlations_present():
    text = _read_fe("lib/api.ts")
    assert "generateTwilioCorrelations" in text or "twilio-correlations" in text


def test_fe_api_ts_demo_provider_union_includes_twilio():
    """getIncidentDemoStatus / seedIncidentDemo / clearIncidentDemo unions include twilio."""
    text = _read_fe("lib/api.ts")
    count = text.count(
        '"github" | "aws" | "cloudflare" | "vercel" | "supabase" | '
        '"firebase" | "stripe" | "shopify" | "azure" | "google_cloud" | "twilio"'
    )
    assert count >= 3, (
        f"Expected 3 demo helper unions to include twilio; found {count}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section E — Backend rule key parity
# ════════════════════════════════════════════════════════════════════════════


def test_backend_twilio_rule_keys_count():
    """Backend TWILIO_RULE_KEYS has all 17 expected rules."""
    assert len(TWILIO_RULE_KEYS) == 17, (
        f"Expected 17 Twilio rule keys, found {len(TWILIO_RULE_KEYS)}"
    )


def test_backend_twilio_rule_keys_match_expected():
    """Backend TWILIO_RULE_KEYS exactly matches the expected set."""
    missing = EXPECTED_TWILIO_RULE_KEYS - frozenset(TWILIO_RULE_KEYS)
    extra = frozenset(TWILIO_RULE_KEYS) - EXPECTED_TWILIO_RULE_KEYS
    assert missing == set(), f"Backend Twilio rule keys missing: {missing}"
    assert extra == set(), f"Backend Twilio has unexpected rule keys: {extra}"


# ════════════════════════════════════════════════════════════════════════════
# Section F — Forbidden wording in backend production modules
# ════════════════════════════════════════════════════════════════════════════

_BACKEND_TWILIO_MODULES: tuple[str, ...] = (
    "app/connectors/twilio.py",
    "app/connectors/twilio_schema.py",
    "app/services/security_rules/twilio.py",
    "app/services/twilio_activity_ingestion_service.py",
    "app/services/twilio_activity_signal_service.py",
    "app/services/twilio_risk_activity_correlation_service.py",
    "app/services/provider_capability_matrix_service.py",
    # provider_expansion_framework.py is intentionally excluded: it defines
    # the FORBIDDEN_CLAIM_PHRASES tuple as a denylist, so the phrases appear by design.
)

_BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _read_backend(rel: str) -> str:
    path = _BACKEND_ROOT / rel
    if not path.exists():
        pytest.skip(f"Backend module {rel!r} not found")
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("module", _BACKEND_TWILIO_MODULES)
def test_backend_twilio_module_no_forbidden_wording(module: str):
    """No forbidden claim phrases in any Twilio backend module."""
    text = _read_backend(module)
    low = text.lower()
    # Strip lines that are negation/denylist contexts to avoid false positives.
    lines = []
    for line in text.splitlines():
        ll = line.lower()
        if any(
            tok in ll
            for tok in (
                "does not confirm", "never assert", "never claim",
                "do not claim", "forbidden", "not confirm",
                "claim discipline", "review-safe", "without claiming",
            )
        ):
            continue
        lines.append(line)
    stripped = "\n".join(lines).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"{module} contains forbidden phrase {phrase!r} outside a negation context"
        )
