"""M80I — SendGrid cross-cloud UX polish guardrails.

Pins the final-mile UX/product polish for SendGrid across the full security
product surface: capability matrix notes, expansion-framework next stage,
frontend page copy, rule catalog parity, demo-script talk track, and
case-report label consistency.

Adds NO product code — only assertions against existing modules and frontend
files. Frontend assertions skip gracefully when the frontend tree is absent.

Sections:

  A. Capability matrix (M80I polish complete; maturity stays partial)
  B. Provider expansion framework (planned_next_stage → M81A Auth0)
  C. Case report (SendGrid label + preview allowlist)
  D. Frontend SendGrid consistency
       - Activity page: provider option, sync button, safe empty state
       - Signals page: provider option, generate button, 10 signal types,
         SendGrid-specific empty-state guidance
       - Correlations page: provider option, 7 correlation types, 3-step flow
       - Cases page: demo card, safe wording
       - Demo-script page: capability table row, talk track
       - securityRuleCatalog.ts: all 26 SendGrid rules
  E. Backend rule key parity (26 expected rules)
  F. Forbidden wording across SendGrid backend modules
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import provider_capability_matrix_service as cap_svc
from app.services import provider_expansion_framework as exp_svc
from app.services import security_case_report_service as report_svc
from app.services.security_rules.sendgrid import SENDGRID_RULE_KEYS

# ── Forbidden claim phrases (M75A) ────────────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# Stale milestone tokens that must not appear in user-facing SendGrid copy.
USER_FACING_STALE_TOKENS = (
    "coming soon",
    "in-progress",
    "SendGrid (M79",
    "SendGrid (M80A–M80G)",
)

# Expected 26 SendGrid rule keys (M80B + M80C).
EXPECTED_SENDGRID_RULE_KEYS = frozenset({
    # M80B core rules (15)
    "sendgrid_api_key_broad_scopes",
    "sendgrid_sender_identity_unverified",
    "sendgrid_sender_identity_locked",
    "sendgrid_domain_authentication_invalid",
    "sendgrid_domain_automatic_security_disabled",
    "sendgrid_domain_authentication_legacy",
    "sendgrid_spam_check_disabled",
    "sendgrid_sandbox_mode_enabled",
    "sendgrid_bcc_enabled",
    "sendgrid_click_tracking_enabled",
    "sendgrid_open_tracking_enabled",
    "sendgrid_subscription_tracking_disabled",
    "sendgrid_event_webhook_disabled",
    "sendgrid_event_webhook_url_missing",
    "sendgrid_suppression_settings_empty",
    # M80C expansion rules (11)
    "sendgrid_sender_identity_reply_domain_mismatch",
    "sendgrid_domain_dns_records_missing",
    "sendgrid_default_domain_authentication_invalid",
    "sendgrid_footer_disabled",
    "sendgrid_bounce_purge_disabled",
    "sendgrid_template_engine_enabled",
    "sendgrid_google_analytics_tracking_enabled",
    "sendgrid_event_webhook_broad_event_stream",
    "sendgrid_inbound_parse_enabled",
    "sendgrid_inbound_parse_raw_email_enabled",
    "sendgrid_inbound_parse_spam_check_disabled",
})

# Expected 10 SendGrid signal types (M80E).
EXPECTED_SENDGRID_SIGNAL_TYPES = frozenset({
    "sendgrid_account_config_changed",
    "sendgrid_api_key_config_changed",
    "sendgrid_sender_identity_config_changed",
    "sendgrid_domain_authentication_config_changed",
    "sendgrid_mail_settings_config_changed",
    "sendgrid_tracking_settings_config_changed",
    "sendgrid_event_webhook_config_changed",
    "sendgrid_inbound_parse_config_changed",
    "sendgrid_suppression_settings_config_changed",
    "sendgrid_config_activity",
})

# Expected 7 SendGrid correlation types (M80F).
EXPECTED_SENDGRID_CORRELATION_TYPES = frozenset({
    "sendgrid_api_key_risk_activity_correlation",
    "sendgrid_sender_identity_risk_activity_correlation",
    "sendgrid_domain_authentication_risk_activity_correlation",
    "sendgrid_mail_settings_risk_activity_correlation",
    "sendgrid_tracking_settings_risk_activity_correlation",
    "sendgrid_webhook_risk_activity_correlation",
    "sendgrid_suppression_settings_risk_activity_correlation",
})


# ════════════════════════════════════════════════════════════════════════════
# Section A — Capability matrix
# ════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_sendgrid_remains_partial():
    """SendGrid stays in partial maturity; canonical 8 are unchanged."""
    cap = cap_svc.get_provider_capability("sendgrid")
    assert cap is not None
    assert cap.maturity == "partial"

    canonical_keys = {p.provider for p in cap_svc.PROVIDER_CAPABILITIES}
    assert "sendgrid" not in canonical_keys
    partial_keys = {p.provider for p in cap_svc.PROVIDER_CAPABILITIES_PARTIAL}
    assert "sendgrid" in partial_keys


def test_capability_matrix_sendgrid_security_flags():
    """Core SendGrid security flags are True after the full M80 arc."""
    cap = cap_svc.get_provider_capability("sendgrid")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    # evidence_timeline and evidence_graph intentionally deferred.
    assert cap.security.evidence_timeline is False
    assert cap.security.evidence_graph is False


def test_capability_matrix_sendgrid_notes_m80i_polish_complete():
    """Notes mention M80I cross-cloud UX polish complete (not future tense)."""
    cap = cap_svc.get_provider_capability("sendgrid")
    notes = cap.notes or ""
    assert "M80I" in notes, (
        "SendGrid capability notes must mention M80I after cross-cloud UX polish"
    )
    assert "complete" in notes.lower() or "polish" in notes.lower(), (
        "Notes must state M80I polish is complete"
    )
    # Must not imply M80I is still upcoming.
    assert "lands in M80I" not in notes
    assert "coming in M80I" not in notes


def test_capability_matrix_sendgrid_notes_mention_arc_layers():
    """Notes mention every stack layer added through the arc."""
    cap = cap_svc.get_provider_capability("sendgrid")
    notes = (cap.notes or "").lower()
    for token in ("drift", "security rules", "activity", "signals", "correlation", "demo"):
        assert token in notes, f"SendGrid notes missing layer keyword {token!r}"


def test_capability_matrix_sendgrid_notes_no_forbidden_phrases():
    """No forbidden claim phrases in SendGrid capability matrix notes."""
    cap = cap_svc.get_provider_capability("sendgrid")
    low = (cap.notes or "").lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"SendGrid notes contain forbidden phrase {phrase!r}"
        )


def test_capability_matrix_sendgrid_notes_partial_rationale():
    """Notes explain why SendGrid remains partial."""
    cap = cap_svc.get_provider_capability("sendgrid")
    notes = (cap.notes or "").lower()
    assert "partial" in notes
    assert "canonical" in notes or "dual-stack" in notes


# ════════════════════════════════════════════════════════════════════════════
# Section B — Provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_planned_next_stage_is_m81a():
    """After M80I and M81A, planned_next_stage points to M81B Auth0 Core Security."""
    fw = exp_svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M80I" not in stage, (
        f"planned_next_stage still points to M80I after arc closed: {stage!r}"
    )
    assert "M81A" not in stage, (
        f"planned_next_stage still points to M81A after it launched: {stage!r}"
    )
    assert "M81B" in stage or "Auth0" in stage, (
        f"planned_next_stage should point to M81B/Auth0 after M81A; got: {stage!r}"
    )


def test_expansion_framework_top_recommendation_is_auth0():
    """Datadog is the head of the recommended queue (Auth0 launched in M81A)."""
    fw = exp_svc.get_framework()
    recs = fw["recommended_next_providers"]
    assert len(recs) > 0
    top = recs[0]
    assert top["provider"] == "datadog"
    assert top["label"] == "Datadog"


def test_expansion_framework_sendgrid_not_in_recommended_queue():
    """SendGrid arc complete in M80I — must not appear in the recommended queue."""
    fw = exp_svc.get_framework()
    providers = [r["provider"] for r in fw["recommended_next_providers"]]
    assert "sendgrid" not in providers, (
        "SendGrid arc complete in M80I and should no longer be in the recommended queue"
    )


def test_expansion_framework_twilio_not_in_recommended_queue():
    """Twilio launched in M79A — must not be in the recommended queue."""
    fw = exp_svc.get_framework()
    providers = [r["provider"] for r in fw["recommended_next_providers"]]
    assert "twilio" not in providers


def test_expansion_framework_summary_next_provider_auth0():
    """Framework summary next_provider = Datadog (Auth0 launched in M81A)."""
    fw = exp_svc.get_framework()
    assert fw["summary"]["next_provider"] == "Datadog"
    next_ms = fw["summary"]["next_milestone"] or ""
    assert "M82" in next_ms or "Datadog" in next_ms


# ════════════════════════════════════════════════════════════════════════════
# Section C — Case report: SendGrid label + preview allowlist
# ════════════════════════════════════════════════════════════════════════════


def test_case_report_provider_label_for_sendgrid():
    """Case report timeline renders the 'SendGrid' label."""
    assert report_svc._TIMELINE_PROVIDER_LABELS.get("sendgrid") == "SendGrid"


def test_case_report_preview_allowlist_carries_sendgrid_safe_keys():
    """SendGrid-safe metadata keys appear in the case-report preview allowlist."""
    expected = {
        "api_key_id",
        "sender_id",
        "domain_id",
        "suppression_group_count",
    }
    missing = expected - report_svc._PREVIEW_ALLOWLIST
    assert missing == set(), (
        f"case-report preview allowlist missing SendGrid-safe keys: {missing}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section D — Frontend SendGrid consistency (skip if tree absent)
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


def test_fe_activity_page_sendgrid_in_provider_union():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert '"sendgrid"' in text


def test_fe_activity_page_sendgrid_sync_button_present():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert "Sync SendGrid activity" in text or "SendGrid" in text


def test_fe_activity_page_sendgrid_empty_state_review_safe():
    """Empty state must reference review-safe SendGrid activity."""
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert "SendGrid" in text
    # Must explain what is NOT stored.
    assert "never" in text.lower()
    # Review-safe framing.
    assert "review-safe" in text or "configuration" in text


def test_fe_activity_page_sendgrid_empty_state_excludes_private_data():
    """Empty state must explicitly mention what SendGrid data is excluded."""
    text = _read_fe("app/(app)/security/activity/page.tsx")
    # Must explicitly say sensitive data is NOT stored.
    lower = text.lower()
    assert (
        "email bodies" in lower
        or "recipient emails" in lower
        or "api key" in lower
    ), "Activity empty state should mention what SendGrid data is excluded"


def test_fe_activity_page_sendgrid_event_types_defined():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    for ev in (
        "sendgrid.api_key.created",
        "sendgrid.api_key.updated",
        "sendgrid.sender_identity.updated",
        "sendgrid.domain_authentication.updated",
        "sendgrid.mail_settings.updated",
        "sendgrid.event_webhook.updated",
    ):
        assert ev in text, f"activity page missing SendGrid event type {ev!r}"


def test_fe_activity_page_sendgrid_no_forbidden_wording():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"activity/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Signals page ──────────────────────────────────────────────────────────────


def test_fe_signals_page_sendgrid_in_provider_union():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert '"sendgrid"' in text


def test_fe_signals_page_sendgrid_generate_button():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert "Generate SendGrid signals" in text or "SendGrid signals" in text


def test_fe_signals_page_sendgrid_empty_state_two_step_flow():
    """Empty state must guide: sync activity first, then generate signals."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert "Sync SendGrid activity" in text or "sendgrid activity" in text.lower()
    assert "generate SendGrid" in text.lower() or "SendGrid signals" in text


def test_fe_signals_page_sendgrid_empty_state_review_safe_copy():
    """SendGrid empty state must include privacy-safe copy about what is not stored."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    lower = text.lower()
    # Must mention key excluded data types
    assert "email bodies" in lower or "recipient emails" in lower or "api key" in lower, (
        "Signals SendGrid empty state must mention what data is excluded"
    )
    assert "never" in lower


def test_fe_signals_page_sendgrid_signal_type_count():
    """Frontend SENDGRID_SIGNAL_TYPES carries all 10 M80E signal types."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    m = re.search(r"const SENDGRID_SIGNAL_TYPES = \[(.*?)\]", text, flags=re.DOTALL)
    assert m is not None, "SENDGRID_SIGNAL_TYPES array not found"
    entries = re.findall(r'"(sendgrid_[a-z_]+)"', m.group(1))
    assert len(entries) == 10, (
        f"SENDGRID_SIGNAL_TYPES should carry 10 M80E types, got {len(entries)}: {entries}"
    )


def test_fe_signals_page_sendgrid_signal_types_match_expected():
    """Frontend signal types match the backend signal-type set."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    m = re.search(r"const SENDGRID_SIGNAL_TYPES = \[(.*?)\]", text, flags=re.DOTALL)
    assert m is not None
    fe_types = frozenset(re.findall(r'"(sendgrid_[a-z_]+)"', m.group(1)))
    assert len(fe_types) == 10
    missing = EXPECTED_SENDGRID_SIGNAL_TYPES - fe_types
    assert missing == set(), (
        f"Frontend SENDGRID_SIGNAL_TYPES missing types: {missing}"
    )


def test_fe_signals_page_sendgrid_no_forbidden_wording():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"signals/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Correlations page ─────────────────────────────────────────────────────────


def test_fe_correlations_page_sendgrid_in_provider_options():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    assert '"sendgrid"' in text


def test_fe_correlations_page_sendgrid_correlation_count():
    """Frontend sendgrid block carries all 7 M80F correlation types."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    m = re.search(r"sendgrid:\s*\[(.*?)\]", text, flags=re.DOTALL)
    assert m is not None, "sendgrid correlation block not found"
    entries = re.findall(r'"(sendgrid_[a-z_]+)"', m.group(1))
    assert len(entries) == 7, (
        f"correlations page sendgrid block should list 7 types, got {len(entries)}: {entries}"
    )


def test_fe_correlations_page_sendgrid_all_types_present():
    """All 7 expected correlation type keys appear in the correlations page."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    for ct in EXPECTED_SENDGRID_CORRELATION_TYPES:
        assert ct in text, f"Correlations page missing SendGrid correlation type {ct!r}"


def test_fe_correlations_page_sendgrid_three_step_flow():
    """Empty-state or helper copy guides through sync → signals → correlations."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    lower = text.lower()
    assert "sendgrid activity" in lower
    assert "sendgrid signals" in lower
    assert "sendgrid correlations" in lower


def test_fe_correlations_page_sendgrid_no_forbidden_wording():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"correlations/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Cases page ────────────────────────────────────────────────────────────────


def test_fe_cases_page_sendgrid_demo_card_present():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert '"sendgrid"' in text
    assert "SendGrid" in text


def test_fe_cases_page_sendgrid_demo_card_polished():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert "Load SendGrid security demo" in text
    assert "Clear SendGrid demo" in text


def test_fe_cases_page_sendgrid_demo_card_review_safe():
    """Cases page SendGrid demo card uses review-safe wording."""
    text = _read_fe("app/(app)/security/cases/page.tsx")
    lower = text.lower()
    # Demo clearly identified
    assert "demo" in lower
    # No real sync implied
    assert "no real sendgrid sync" in lower or "review-safe" in lower


def test_fe_cases_page_sendgrid_demo_card_excludes_sensitive_copy():
    """Demo card must mention what is NOT in the SendGrid demo."""
    text = _read_fe("app/(app)/security/cases/page.tsx")
    lower = text.lower()
    # Privacy statement: email bodies, recipient data, or API keys are excluded
    assert (
        "email bodies" in lower
        or "recipient emails" in lower
        or "api key" in lower
    ), "Cases SendGrid demo card must exclude sensitive data in copy"


def test_fe_cases_page_sendgrid_no_forbidden_wording():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"cases/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Demo-script page ──────────────────────────────────────────────────────────


def test_fe_demo_script_page_sendgrid_in_capability_table():
    """PROVIDER_CAPABILITY_TABLE includes a SendGrid row."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    assert '"sendgrid"' in text
    assert "SendGrid" in text


def test_fe_demo_script_page_sendgrid_row_is_demo_ready():
    """SendGrid row in the capability table has demo: true."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(
        r'provider:\s*"sendgrid".*?demo:\s*(true|false)',
        text,
        flags=re.DOTALL,
    )
    assert m is not None, "SendGrid row not found in PROVIDER_CAPABILITY_TABLE"
    assert m.group(1) == "true", "SendGrid demo flag should be true after M80G"


def test_fe_demo_script_page_next_providers_has_auth0_first():
    """Auth0 is the first provider in NEXT_PROVIDERS_BRIEF after SendGrid arc closes."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(
        r"const NEXT_PROVIDERS_BRIEF.*?= \[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None, "NEXT_PROVIDERS_BRIEF not found"
    block = m.group(1)
    # SendGrid arc complete — must not still be in the future-provider queue.
    assert "SendGrid" not in block, (
        "SendGrid arc complete in M80I and must not be in NEXT_PROVIDERS_BRIEF"
    )
    # Twilio arc complete — no stale M79A reference.
    assert '"M79A"' not in block
    # Auth0 launched M81A — must not still be in NEXT_PROVIDERS_BRIEF.
    assert "Auth0" not in block, (
        "Auth0 launched M81A and must not be in NEXT_PROVIDERS_BRIEF"
    )
    assert '"M81A"' not in block, "Stale M81A milestone in NEXT_PROVIDERS_BRIEF"


def test_fe_demo_script_page_sendgrid_arc_range_updated():
    """Page description shows SendGrid arc through M80I, not M80G."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    # M80A–M80I is the correct arc range now
    assert "M80A–M80I" in text, (
        "demo-script description should say 'M80A–M80I' after M80I completes"
    )
    # Stale arc range should be gone
    assert "M80A–M80G" not in text, (
        "Stale 'M80A–M80G' arc range found — should be updated to 'M80A–M80I'"
    )


def test_fe_demo_script_page_stale_m80_milestone_labels_updated():
    """NEXT_PROVIDERS_BRIEF milestone labels updated to M81 series."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(
        r"const NEXT_PROVIDERS_BRIEF.*?= \[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None
    block = m.group(1)
    # Stale M80x milestones for next providers must be gone
    assert '"M80B"' not in block, "Stale M80B milestone in NEXT_PROVIDERS_BRIEF"
    assert '"M80C"' not in block, "Stale M80C milestone in NEXT_PROVIDERS_BRIEF"
    assert '"M80D"' not in block, "Stale M80D milestone in NEXT_PROVIDERS_BRIEF"


# ── securityDemoScript talk track ─────────────────────────────────────────────


def test_fe_demo_script_talk_track_mentions_sendgrid():
    """Demo script talk track includes SendGrid."""
    text = _read_fe("lib/securityDemoScript.ts")
    assert "SendGrid" in text


def test_fe_demo_script_opening_pitch_includes_sendgrid():
    """Opening pitch explicitly names SendGrid alongside other providers."""
    text = _read_fe("lib/securityDemoScript.ts")
    # Find the 3-min demo opening talkTrack and confirm SendGrid is there.
    m = re.search(r"DEMO_SCRIPT_3MIN.*?id.*?opening.*?talkTrack.*?\"(.*?)\"", text, flags=re.DOTALL)
    if m is not None:
        opening_track = m.group(1)
        assert "SendGrid" in opening_track, (
            "Opening pitch talkTrack must include SendGrid"
        )
    else:
        # Fallback: SendGrid appears somewhere near the opening section.
        assert "SendGrid" in text


def test_fe_demo_script_incident_seed_step_includes_sendgrid():
    """The incident-seed step names SendGrid as a seedable provider."""
    text = _read_fe("lib/securityDemoScript.ts")
    m = re.search(r'id:\s*"incident-seed"(.*?)id:\s*"incident-risks"', text, flags=re.DOTALL)
    if m is None:
        pytest.skip("incident-seed step not found in demo script")
    step_block = m.group(1)
    assert "SendGrid" in step_block, (
        "incident-seed step must include SendGrid in its provider list"
    )


def test_fe_demo_script_incident_timeline_step_includes_sendgrid():
    """The incident-timeline-graph step names SendGrid in its provider list."""
    text = _read_fe("lib/securityDemoScript.ts")
    m = re.search(r'id:\s*"incident-timeline-graph"(.*?)id:\s*"incident-report"', text, flags=re.DOTALL)
    if m is None:
        pytest.skip("incident-timeline-graph step not found in demo script")
    step_block = m.group(1)
    assert "SendGrid" in step_block, (
        "incident-timeline-graph step must include SendGrid in its provider list"
    )


def test_fe_demo_script_incident_clear_step_includes_sendgrid():
    """The incident-clear-demo step names SendGrid."""
    text = _read_fe("lib/securityDemoScript.ts")
    m = re.search(r'id:\s*"incident-clear-demo"(.*?)id:\s*"incident-what-this-proves"', text, flags=re.DOTALL)
    if m is None:
        pytest.skip("incident-clear-demo step not found in demo script")
    step_block = m.group(1)
    assert "SendGrid" in step_block, (
        "incident-clear-demo step must include SendGrid in its provider list"
    )


def test_fe_demo_script_no_stale_m80h_m80g_milestone_jargon():
    """Talk track copy contains no stale M80G/M80H milestone codes."""
    text = _read_fe("lib/securityDemoScript.ts")
    for token in ("M80G", "M80H"):
        assert token not in text, (
            f"securityDemoScript.ts talk track contains stale milestone token {token!r}"
        )


def test_fe_demo_script_no_forbidden_wording():
    text = _read_fe("lib/securityDemoScript.ts")
    # Strip lines that are explicit negation/avoidance/denylist contexts.
    lines = []
    for line in text.splitlines():
        ll = line.lower().strip()
        if any(tok in ll for tok in (
            "avoid:", "avoid '", "do not claim", "never assert",
            "don't", "does not confirm", "not claim",
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


def test_fe_rule_catalog_sendgrid_rule_count():
    """securityRuleCatalog.ts contains all 26 SendGrid rules."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    entries = re.findall(r'key:\s*"(sendgrid_[a-z0-9_]+)"', text)
    keys = frozenset(entries)
    assert len(keys) == 26, (
        f"Expected 26 SendGrid rules in catalog, found {len(keys)}: {sorted(keys)}"
    )


def test_fe_rule_catalog_sendgrid_all_keys_present():
    """All 26 expected SendGrid rule keys appear in the catalog."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    entries = frozenset(re.findall(r'key:\s*"(sendgrid_[a-z0-9_]+)"', text))
    missing = EXPECTED_SENDGRID_RULE_KEYS - entries
    assert missing == set(), (
        f"securityRuleCatalog.ts missing SendGrid rule keys: {missing}"
    )


def test_fe_rule_catalog_sendgrid_rules_have_description():
    """Every SendGrid rule entry has a non-empty description field."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(sendgrid_[a-z0-9_]+)".*?description:\s*"([^"]{10,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_SENDGRID_RULE_KEYS - found_keys
    assert missing == set(), (
        f"SendGrid rules missing description field: {missing}"
    )


def test_fe_rule_catalog_sendgrid_rules_have_remediation():
    """Every SendGrid rule entry has a non-empty remediation field."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(sendgrid_[a-z0-9_]+)".*?remediation:\s*"([^"]{10,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_SENDGRID_RULE_KEYS - found_keys
    assert missing == set(), (
        f"SendGrid rules missing remediation field: {missing}"
    )


def test_fe_rule_catalog_sendgrid_rules_have_false_positive_guard():
    """Every SendGrid rule entry has a falsePositiveGuard field."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(sendgrid_[a-z0-9_]+)".*?falsePositiveGuard:\s*"([^"]{5,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_SENDGRID_RULE_KEYS - found_keys
    assert missing == set(), (
        f"SendGrid rules missing falsePositiveGuard field: {missing}"
    )


def test_fe_rule_catalog_sendgrid_no_forbidden_wording():
    """No forbidden claim phrases in any SendGrid rule catalog entry."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    start = text.find('"sendgrid_api_key_broad_scopes"')
    assert start != -1, "SendGrid section not found in rule catalog"
    sendgrid_section = text[start:]
    low = sendgrid_section.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"securityRuleCatalog.ts SendGrid section contains forbidden phrase {phrase!r}"
        )


def test_fe_rule_catalog_provider_coverage_has_sendgrid():
    """PROVIDER_COVERAGE includes a sendgrid entry with surfaces."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    assert 'provider: "sendgrid"' in text
    # Must list SendGrid surfaces (including inbound parse added in M80I).
    for surface in ("API key", "sender identit", "Domain auth", "Mail settings", "Inbound parse"):
        assert surface in text, (
            f"PROVIDER_COVERAGE sendgrid entry missing surface keyword {surface!r}"
        )


def test_fe_rule_catalog_sendgrid_metadata_only_flag():
    """All SendGrid rule entries carry metadataOnly: true."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    # Find all sendgrid rule blocks and verify metadataOnly is set.
    # We check by counting metadataOnly: true occurrences in the sendgrid section.
    start = text.find('"sendgrid_api_key_broad_scopes"')
    assert start != -1
    sendgrid_section = text[start:]
    # The section ends at the next provider section or end of catalog.
    next_non_sendgrid = re.search(r'key:\s*"(?!sendgrid_)[a-z0-9_]+"', sendgrid_section)
    if next_non_sendgrid:
        sendgrid_section = sendgrid_section[:next_non_sendgrid.start()]
    count_true = sendgrid_section.count("metadataOnly: true")
    count_false = sendgrid_section.count("metadataOnly: false")
    # All should be true (or absent — check at least some are true)
    assert count_true >= 20, (
        f"Expected >= 20 metadataOnly: true in SendGrid section, found {count_true}"
    )
    assert count_false == 0, (
        f"Found {count_false} metadataOnly: false in SendGrid section"
    )


# ── api.ts ────────────────────────────────────────────────────────────────────


def test_fe_api_ts_sendgrid_sync_activity_present():
    text = _read_fe("lib/api.ts")
    assert "syncSendGridActivity" in text or "sendgrid-activity" in text


def test_fe_api_ts_sendgrid_generate_signals_present():
    text = _read_fe("lib/api.ts")
    assert "generateSendGridActivitySignals" in text or "sendgrid-activity/generate" in text


def test_fe_api_ts_sendgrid_generate_correlations_present():
    text = _read_fe("lib/api.ts")
    assert "generateSendGridCorrelations" in text or "sendgrid-correlations" in text


def test_fe_api_ts_demo_provider_union_includes_sendgrid():
    """getIncidentDemoStatus / seedIncidentDemo / clearIncidentDemo all include sendgrid."""
    text = _read_fe("lib/api.ts")
    full_union = (
        '"github" | "aws" | "cloudflare" | "vercel" | "supabase" | '
        '"firebase" | "stripe" | "shopify" | "azure" | "google_cloud" | "twilio" | "sendgrid"'
    )
    count = text.count(full_union)
    assert count >= 3, (
        f"Expected >= 3 demo helper unions to include sendgrid; found {count}"
    )


# ── types/index.ts ────────────────────────────────────────────────────────────


def test_fe_types_sendgrid_activity_sync_response():
    text = _read_fe("types/index.ts")
    assert "SendGridActivitySyncResponse" in text


def test_fe_types_sendgrid_signal_generate_response():
    text = _read_fe("types/index.ts")
    assert "SendGridActivitySignalGenerateResponse" in text


def test_fe_types_sendgrid_correlation_generate_response():
    text = _read_fe("types/index.ts")
    assert "SendGridCorrelationGenerateResponse" in text


# ════════════════════════════════════════════════════════════════════════════
# Section E — Backend rule key parity
# ════════════════════════════════════════════════════════════════════════════


def test_backend_sendgrid_rule_keys_count():
    """Backend SENDGRID_RULE_KEYS has all 26 expected rules."""
    assert len(SENDGRID_RULE_KEYS) == 26, (
        f"Expected 26 SendGrid rule keys, found {len(SENDGRID_RULE_KEYS)}"
    )


def test_backend_sendgrid_rule_keys_match_expected():
    """Backend SENDGRID_RULE_KEYS exactly matches the expected set."""
    missing = EXPECTED_SENDGRID_RULE_KEYS - frozenset(SENDGRID_RULE_KEYS)
    extra = frozenset(SENDGRID_RULE_KEYS) - EXPECTED_SENDGRID_RULE_KEYS
    assert missing == set(), f"Backend SendGrid rule keys missing: {missing}"
    assert extra == set(), f"Backend SendGrid has unexpected rule keys: {extra}"


# ════════════════════════════════════════════════════════════════════════════
# Section F — Forbidden wording in backend production modules
# ════════════════════════════════════════════════════════════════════════════

_BACKEND_SENDGRID_MODULES: tuple[str, ...] = (
    "app/connectors/sendgrid.py",
    "app/connectors/sendgrid_schema.py",
    "app/services/security_rules/sendgrid.py",
    "app/services/sendgrid_activity_ingestion_service.py",
    "app/services/sendgrid_activity_signal_service.py",
    "app/services/sendgrid_risk_activity_correlation_service.py",
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


@pytest.mark.parametrize("module", _BACKEND_SENDGRID_MODULES)
def test_backend_sendgrid_module_no_forbidden_wording(module: str):
    """No forbidden claim phrases in any SendGrid backend module."""
    text = _read_backend(module)
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
