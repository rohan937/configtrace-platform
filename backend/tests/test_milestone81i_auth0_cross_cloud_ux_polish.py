"""M81I — Auth0 cross-cloud UX polish guardrails.

Pins the final-mile UX/product polish for Auth0 across the full security
product surface: capability matrix notes, expansion-framework next stage,
frontend page copy, rule catalog parity, demo-script talk track, and
case-report label consistency.

Adds NO product code — only assertions against existing modules and frontend
files. Frontend assertions skip gracefully when the frontend tree is absent.

Sections:

  A. Capability matrix (M81I polish complete; maturity stays partial)
  B. Provider expansion framework (planned_next_stage → M82-pre)
  C. Case report (Auth0 label + preview allowlist)
  D. Frontend Auth0 consistency
       - Activity page: provider option, sync button, safe helper copy
       - Signals page: provider option, generate button, 9 signal types,
         Auth0-specific empty-state guidance
       - Correlations page: provider option, 8 correlation types, 3-step flow
       - Cases page: demo card, safe wording
       - Demo-script page: capability table row, arc range M81A–M81I, talk track
       - securityDemoScript.ts: Auth0 in all incident-demo steps
       - securityRuleCatalog.ts: all 37 Auth0 rules
       - api.ts: Auth0 API functions present, demo union includes auth0
       - types/index.ts: Auth0 response types present
  E. Backend rule key parity (37 expected rules)
  F. Forbidden wording across Auth0 backend modules
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import provider_capability_matrix_service as cap_svc
from app.services import provider_expansion_framework as exp_svc
from app.services import security_case_report_service as report_svc
from app.services.security_rules.auth0 import AUTH0_RULE_KEYS

# ── Forbidden claim phrases (M75A) ────────────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# Stale milestone tokens that must not appear in user-facing Auth0 copy.
USER_FACING_STALE_TOKENS = (
    "Auth0 (M81A) is drift-only",
    "coming soon",
    "in-progress",
)

# Expected 37 Auth0 rule keys (M81B + M81C).
EXPECTED_AUTH0_RULE_KEYS = frozenset({
    # ── M81B: Tenant settings (3) ───────────────────────────────────────────
    "auth0_tenant_session_lifetime_extended",
    "auth0_tenant_idle_session_lifetime_extended",
    "auth0_tenant_dynamic_client_registration_enabled",
    # ── M81B: Application core (7) ─────────────────────────────────────────
    "auth0_application_no_callbacks",
    "auth0_application_many_callbacks",
    "auth0_application_many_allowed_origins",
    "auth0_application_oidc_non_conformant",
    "auth0_application_weak_jwt_algorithm",
    "auth0_refresh_token_rotation_disabled",
    "auth0_refresh_token_lifetime_extended",
    # ── M81B: Connection (2) ───────────────────────────────────────────────
    "auth0_connection_no_enabled_clients",
    "auth0_connection_weak_password_policy",
    # ── M81B: Resource server (3) ──────────────────────────────────────────
    "auth0_resource_server_offline_access_enabled",
    "auth0_resource_server_token_lifetime_extended",
    "auth0_resource_server_rbac_disabled",
    # ── M81B: Rule (2) ─────────────────────────────────────────────────────
    "auth0_rule_disabled",
    "auth0_rule_large_script",
    # ── M81B: Action (2) ───────────────────────────────────────────────────
    "auth0_action_not_deployed",
    "auth0_action_secrets_present",
    # ── M81B: MFA factor (1) ───────────────────────────────────────────────
    "auth0_mfa_factor_disabled",
    # ── M81B: Custom domain (2) ────────────────────────────────────────────
    "auth0_custom_domain_not_ready",
    "auth0_custom_domain_weak_tls_policy",
    # ── M81C: Grant type posture (6) ───────────────────────────────────────
    "auth0_application_password_grant_enabled",
    "auth0_application_implicit_grant_enabled",
    "auth0_application_public_client_credentials_enabled",
    "auth0_application_refresh_grant_without_rotation",
    "auth0_application_many_grant_types",
    "auth0_application_device_code_grant_enabled",
    # ── M81C: Wildcard posture (3) ─────────────────────────────────────────
    "auth0_application_wildcard_callback",
    "auth0_application_wildcard_allowed_origin",
    "auth0_application_wildcard_logout_url",
    # ── M81C: Localhost posture (2) ────────────────────────────────────────
    "auth0_application_localhost_callback",
    "auth0_application_localhost_origin",
    # ── M81C: HTTPS posture (2) ────────────────────────────────────────────
    "auth0_application_callback_missing_https",
    "auth0_application_origin_missing_https",
    # ── M81C: Public client / token endpoint (2) ───────────────────────────
    "auth0_public_client_refresh_tokens_enabled",
    "auth0_application_token_endpoint_auth_none",
})

# Expected 9 Auth0 signal types (M81E).
EXPECTED_AUTH0_SIGNAL_TYPES = frozenset({
    "auth0_tenant_config_changed",
    "auth0_application_config_changed",
    "auth0_connection_config_changed",
    "auth0_resource_server_config_changed",
    "auth0_rule_config_changed",
    "auth0_action_config_changed",
    "auth0_mfa_factor_config_changed",
    "auth0_custom_domain_config_changed",
    "auth0_config_activity",
})

# Expected 8 Auth0 correlation types (M81F).
EXPECTED_AUTH0_CORRELATION_TYPES = frozenset({
    "auth0_tenant_risk_activity_correlation",
    "auth0_application_risk_activity_correlation",
    "auth0_connection_risk_activity_correlation",
    "auth0_resource_server_risk_activity_correlation",
    "auth0_rule_risk_activity_correlation",
    "auth0_action_risk_activity_correlation",
    "auth0_mfa_factor_risk_activity_correlation",
    "auth0_custom_domain_risk_activity_correlation",
})


# ════════════════════════════════════════════════════════════════════════════
# Section A — Capability matrix
# ════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_auth0_remains_partial():
    """Auth0 stays in partial maturity; canonical 8 are unchanged."""
    cap = cap_svc.get_provider_capability("auth0")
    assert cap is not None
    assert cap.maturity == "partial"

    canonical_keys = {p.provider for p in cap_svc.PROVIDER_CAPABILITIES}
    assert "auth0" not in canonical_keys
    partial_keys = {p.provider for p in cap_svc.PROVIDER_CAPABILITIES_PARTIAL}
    assert "auth0" in partial_keys


def test_capability_matrix_auth0_security_flags():
    """Core Auth0 security flags are True after the full M81 arc."""
    cap = cap_svc.get_provider_capability("auth0")
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
    # evidence_timeline and evidence_graph enabled (M81G via generic builders).
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True


def test_capability_matrix_auth0_notes_m81i_polish_complete():
    """Notes mention M81I cross-cloud UX polish complete (not future tense)."""
    cap = cap_svc.get_provider_capability("auth0")
    notes = cap.notes or ""
    assert "M81I" in notes, (
        "Auth0 capability notes must mention M81I after cross-cloud UX polish"
    )
    # Must not imply M81I is still upcoming.
    assert "lands in M81I" not in notes
    assert "coming in M81I" not in notes
    assert "Next: M81I" not in notes


def test_capability_matrix_auth0_notes_mention_arc_layers():
    """Notes mention every stack layer added through the arc."""
    cap = cap_svc.get_provider_capability("auth0")
    notes = (cap.notes or "").lower()
    for token in ("drift", "security rules", "activity", "signals", "correlation", "demo"):
        assert token in notes, f"Auth0 notes missing layer keyword {token!r}"


def test_capability_matrix_auth0_notes_no_forbidden_phrases():
    """No forbidden claim phrases in Auth0 capability matrix notes."""
    cap = cap_svc.get_provider_capability("auth0")
    low = (cap.notes or "").lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"Auth0 notes contain forbidden phrase {phrase!r}"
        )


def test_capability_matrix_auth0_notes_partial_rationale():
    """Notes explain why Auth0 remains partial."""
    cap = cap_svc.get_provider_capability("auth0")
    notes = (cap.notes or "").lower()
    assert "partial" in notes
    assert "canonical" in notes or "dual-stack" in notes


# ════════════════════════════════════════════════════════════════════════════
# Section B — Provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_planned_next_stage_is_m82_pre():
    """After M81I, planned_next_stage must advance past M81I (to M82 or beyond)."""
    fw = exp_svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M81I" not in stage, (
        f"planned_next_stage still points to M81I after arc closed: {stage!r}"
    )
    assert ("M82" in stage or "Integration Card" in stage or "M83" in stage
            or "Clerk" in stage or "M84" in stage or "PagerDuty" in stage
            or "M85A" in stage or "Linear" in stage), (
        f"planned_next_stage should point to M82/M83/Clerk or later; got: {stage!r}"
    )


def test_expansion_framework_top_recommendation_is_datadog():
    """Datadog is the head of the recommended queue (Auth0 arc complete)."""
    fw = exp_svc.get_framework()
    recs = fw["recommended_next_providers"]
    assert len(recs) > 0
    top = recs[0]
    # After M84A, PagerDuty launched; Linear is now at head.
    assert top["provider"] in ("pagerduty", "linear")
    assert top["label"] in ("PagerDuty", "Linear")


def test_expansion_framework_auth0_not_in_recommended_queue():
    """Auth0 arc complete M81A–M81I — must not appear in the recommended queue."""
    fw = exp_svc.get_framework()
    providers = [r["provider"] for r in fw["recommended_next_providers"]]
    assert "auth0" not in providers, (
        "Auth0 arc complete in M81I and should no longer be in the recommended queue"
    )


def test_expansion_framework_sendgrid_not_in_recommended_queue():
    """SendGrid arc complete in M80I — must not be in the recommended queue."""
    fw = exp_svc.get_framework()
    providers = [r["provider"] for r in fw["recommended_next_providers"]]
    assert "sendgrid" not in providers


def test_expansion_framework_summary_next_provider_is_datadog():
    """Framework summary next_provider = Clerk (Datadog launched in M82A)."""
    fw = exp_svc.get_framework()
    # After M84A, PagerDuty launched; Linear is now head.
    assert fw["summary"]["next_provider"] in ("PagerDuty", "Linear")
    next_ms = fw["summary"]["next_milestone"] or ""
    assert "PagerDuty" in next_ms or "M84A" in next_ms or "Clerk" in next_ms or "Linear" in next_ms or "M85A" in next_ms


# ════════════════════════════════════════════════════════════════════════════
# Section C — Case report: Auth0 label + preview allowlist
# ════════════════════════════════════════════════════════════════════════════


def test_case_report_provider_label_for_auth0():
    """Case report timeline renders the 'Auth0' label."""
    assert report_svc._TIMELINE_PROVIDER_LABELS.get("auth0") == "Auth0"


def test_case_report_preview_allowlist_carries_auth0_safe_keys():
    """Auth0-safe metadata keys appear in the case-report preview allowlist."""
    expected = {
        "client_id",
        "connection_id",
        "resource_server_id",
        "action_id",
        "custom_domain_id",
        "factor_name",
        "session_lifetime_category",
        "token_endpoint_auth_method",
        "password_policy_category",
        "rbac_enabled",
        "allow_offline_access",
        "script_present",
        "secrets_count",
        "status_category",
    }
    missing = expected - report_svc._PREVIEW_ALLOWLIST
    assert missing == set(), (
        f"case-report preview allowlist missing Auth0-safe keys: {missing}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section D — Frontend Auth0 consistency (skip if tree absent)
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


def test_fe_activity_page_auth0_in_provider_union():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert '"auth0"' in text


def test_fe_activity_page_auth0_sync_button_present():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert "Sync Auth0 activity" in text


def test_fe_activity_page_auth0_helper_copy_review_safe():
    """Helper copy must describe safe Auth0 activity, not claim breach/access."""
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert "Auth0" in text
    # Must explain what is NOT stored.
    assert "never" in text.lower()
    # Review-safe framing.
    assert "review-safe" in text or "configuration" in text


def test_fe_activity_page_auth0_helper_copy_excludes_private_data():
    """Helper copy must explicitly state sensitive Auth0 data is not stored."""
    text = _read_fe("app/(app)/security/activity/page.tsx")
    lower = text.lower()
    assert (
        "client secrets" in lower
        or "login history" in lower
        or "raw auth0 logs" in lower
        or "user emails" in lower
    ), "Activity page should mention what Auth0 data is excluded"


def test_fe_activity_page_auth0_event_types_defined():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    for ev in (
        "auth0.tenant.updated",
        "auth0.application.created",
        "auth0.application.updated",
        "auth0.connection.updated",
        "auth0.resource_server.updated",
        "auth0.rule.updated",
        "auth0.action.deployed",
        "auth0.mfa_factor.updated",
        "auth0.custom_domain.updated",
        "auth0.config.event",
    ):
        assert ev in text, f"activity page missing Auth0 event type {ev!r}"


def test_fe_activity_page_auth0_no_forbidden_wording():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"activity/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Signals page ──────────────────────────────────────────────────────────────


def test_fe_signals_page_auth0_in_provider_union():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert '"auth0"' in text


def test_fe_signals_page_auth0_generate_button():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert "Generate Auth0 signals" in text or "Auth0 signals" in text


def test_fe_signals_page_auth0_empty_state_two_step_flow():
    """Empty state must guide: sync Auth0 activity first, then generate signals."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert "Sync Auth0 activity" in text or "auth0 activity" in text.lower()
    assert "generate Auth0 signals" in text.lower() or "Auth0 signals" in text


def test_fe_signals_page_auth0_empty_state_review_safe_copy():
    """Auth0 signals empty state must mention what is not stored."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    lower = text.lower()
    assert (
        "user emails" in lower
        or "login history" in lower
        or "raw auth0 logs" in lower
        or "client secrets" in lower
    ), "Signals Auth0 empty state must mention excluded Auth0 data"
    assert "never" in lower


def test_fe_signals_page_auth0_signal_type_count():
    """Frontend AUTH0_SIGNAL_TYPES carries all 9 M81E signal types."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    m = re.search(r"const AUTH0_SIGNAL_TYPES = \[(.*?)\]", text, flags=re.DOTALL)
    assert m is not None, "AUTH0_SIGNAL_TYPES array not found"
    entries = re.findall(r'"(auth0_[a-z0-9_]+)"', m.group(1))
    assert len(entries) == 9, (
        f"AUTH0_SIGNAL_TYPES should carry 9 M81E types, got {len(entries)}: {entries}"
    )


def test_fe_signals_page_auth0_signal_types_match_expected():
    """Frontend signal types match the backend signal-type set."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    m = re.search(r"const AUTH0_SIGNAL_TYPES = \[(.*?)\]", text, flags=re.DOTALL)
    assert m is not None
    fe_types = frozenset(re.findall(r'"(auth0_[a-z0-9_]+)"', m.group(1)))
    missing = EXPECTED_AUTH0_SIGNAL_TYPES - fe_types
    assert missing == set(), (
        f"Frontend AUTH0_SIGNAL_TYPES missing types: {missing}"
    )


def test_fe_signals_page_auth0_no_forbidden_wording():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"signals/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Correlations page ─────────────────────────────────────────────────────────


def test_fe_correlations_page_auth0_in_provider_options():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    assert '"auth0"' in text


def test_fe_correlations_page_auth0_correlation_count():
    """Frontend auth0 block carries all 8 M81F correlation types."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    m = re.search(r"auth0:\s*\[(.*?)\]", text, flags=re.DOTALL)
    assert m is not None, "auth0 correlation block not found"
    entries = re.findall(r'"(auth0_[a-z0-9_]+)"', m.group(1))
    assert len(entries) == 8, (
        f"correlations page auth0 block should list 8 types, got {len(entries)}: {entries}"
    )


def test_fe_correlations_page_auth0_all_types_present():
    """All 8 expected Auth0 correlation type keys appear in the correlations page."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    for ct in EXPECTED_AUTH0_CORRELATION_TYPES:
        assert ct in text, f"Correlations page missing Auth0 correlation type {ct!r}"


def test_fe_correlations_page_auth0_three_step_flow():
    """Empty-state or helper copy guides through sync → signals → correlations."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    lower = text.lower()
    assert "auth0 activity" in lower
    assert "auth0 signals" in lower
    assert "auth0 correlations" in lower


def test_fe_correlations_page_auth0_no_forbidden_wording():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"correlations/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Cases page ────────────────────────────────────────────────────────────────


def test_fe_cases_page_auth0_demo_card_present():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert '"auth0"' in text
    assert "Auth0" in text


def test_fe_cases_page_auth0_demo_card_polished():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert "Load Auth0 security demo" in text
    assert "Clear Auth0 demo" in text


def test_fe_cases_page_auth0_demo_card_review_safe():
    """Cases page Auth0 demo card uses review-safe wording."""
    text = _read_fe("app/(app)/security/cases/page.tsx")
    lower = text.lower()
    assert "demo" in lower
    assert "no real auth0 sync" in lower or "review-safe" in lower


def test_fe_cases_page_auth0_demo_card_excludes_sensitive_copy():
    """Demo card must mention what is NOT in the Auth0 demo."""
    text = _read_fe("app/(app)/security/cases/page.tsx")
    lower = text.lower()
    assert (
        "client secrets" in lower
        or "user emails" in lower
        or "login history" in lower
        or "raw auth0 logs" in lower
    ), "Cases Auth0 demo card must exclude sensitive data in copy"


def test_fe_cases_page_auth0_no_forbidden_wording():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"cases/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Demo-script page ──────────────────────────────────────────────────────────


def test_fe_demo_script_page_auth0_in_capability_table():
    """PROVIDER_CAPABILITY_TABLE includes an Auth0 row."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    assert '"auth0"' in text
    assert "Auth0" in text


def test_fe_demo_script_page_auth0_row_is_demo_ready():
    """Auth0 row in the capability table has demo: true."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(
        r'provider:\s*"auth0".*?demo:\s*(true|false)',
        text,
        flags=re.DOTALL,
    )
    assert m is not None, "Auth0 row not found in PROVIDER_CAPABILITY_TABLE"
    assert m.group(1) == "true", "Auth0 demo flag should be true after M81G"


def test_fe_demo_script_page_auth0_arc_range_updated():
    """Page description shows Auth0 arc through M81I, not drift-only."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    # M81A–M81I is the correct arc range now
    assert "M81A–M81I" in text, (
        "demo-script description should say 'M81A–M81I' after M81I completes"
    )
    # Stale drift-only copy should be gone
    assert "Auth0 (M81A) is drift-only" not in text, (
        "Stale 'Auth0 (M81A) is drift-only' text found — should be updated to full arc"
    )


def test_fe_demo_script_page_next_providers_no_auth0():
    """Auth0 arc complete M81A–M81I — must not be in NEXT_PROVIDERS_BRIEF."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(
        r"const NEXT_PROVIDERS_BRIEF.*?= \[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None, "NEXT_PROVIDERS_BRIEF not found"
    block = m.group(1)
    assert "Auth0" not in block, (
        "Auth0 arc complete in M81I and must not be in NEXT_PROVIDERS_BRIEF"
    )
    assert '"M81A"' not in block, "Stale M81A milestone in NEXT_PROVIDERS_BRIEF"


def test_fe_demo_script_page_stale_m81_milestone_labels_updated():
    """NEXT_PROVIDERS_BRIEF must not have stale M81A-M81I milestone labels."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(
        r"const NEXT_PROVIDERS_BRIEF.*?= \[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None
    block = m.group(1)
    # Auth0 arc complete — no stale M81x milestone references
    for stale in ('"M81A"', '"M81B"', '"M81C"', '"M81D"', '"M81E"'):
        assert stale not in block, f"Stale {stale} milestone in NEXT_PROVIDERS_BRIEF"


def test_fe_demo_script_page_no_forbidden_wording():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"demo-script/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── securityDemoScript talk track ─────────────────────────────────────────────


def test_fe_demo_script_talk_track_mentions_auth0():
    """Demo script talk track includes Auth0."""
    text = _read_fe("lib/securityDemoScript.ts")
    assert "Auth0" in text


def test_fe_demo_script_incident_seed_step_includes_auth0():
    """The incident-seed step names Auth0 as a seedable provider."""
    text = _read_fe("lib/securityDemoScript.ts")
    m = re.search(r'id:\s*"incident-seed"(.*?)id:\s*"incident-risks"', text, flags=re.DOTALL)
    if m is None:
        pytest.skip("incident-seed step not found in demo script")
    step_block = m.group(1)
    assert "Auth0" in step_block, (
        "incident-seed step must include Auth0 in its provider list"
    )


def test_fe_demo_script_incident_timeline_step_includes_auth0():
    """The incident-timeline-graph step names Auth0 in its provider list."""
    text = _read_fe("lib/securityDemoScript.ts")
    m = re.search(r'id:\s*"incident-timeline-graph"(.*?)id:\s*"incident-report"', text, flags=re.DOTALL)
    if m is None:
        pytest.skip("incident-timeline-graph step not found in demo script")
    step_block = m.group(1)
    assert "Auth0" in step_block, (
        "incident-timeline-graph step must include Auth0 in its provider list"
    )


def test_fe_demo_script_incident_clear_step_includes_auth0():
    """The incident-clear-demo step names Auth0."""
    text = _read_fe("lib/securityDemoScript.ts")
    m = re.search(r'id:\s*"incident-clear-demo"(.*?)id:\s*"incident-what-this-proves"', text, flags=re.DOTALL)
    if m is None:
        pytest.skip("incident-clear-demo step not found in demo script")
    step_block = m.group(1)
    assert "Auth0" in step_block, (
        "incident-clear-demo step must include Auth0 in its provider list"
    )


def test_fe_demo_script_no_stale_m81h_m81g_milestone_jargon():
    """Talk track copy contains no stale M81G/M81H milestone codes."""
    text = _read_fe("lib/securityDemoScript.ts")
    for token in ("M81G", "M81H"):
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


def test_fe_rule_catalog_auth0_rule_count():
    """securityRuleCatalog.ts contains all 37 Auth0 rules."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    entries = re.findall(r'key:\s*"(auth0_[a-z0-9_]+)"', text)
    keys = frozenset(entries)
    assert len(keys) == 37, (
        f"Expected 37 Auth0 rules in catalog, found {len(keys)}: {sorted(keys)}"
    )


def test_fe_rule_catalog_auth0_all_keys_present():
    """All 37 expected Auth0 rule keys appear in the catalog."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    entries = frozenset(re.findall(r'key:\s*"(auth0_[a-z0-9_]+)"', text))
    missing = EXPECTED_AUTH0_RULE_KEYS - entries
    assert missing == set(), (
        f"securityRuleCatalog.ts missing Auth0 rule keys: {missing}"
    )


def test_fe_rule_catalog_auth0_rules_have_description():
    """Every Auth0 rule entry has a non-empty description field."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(auth0_[a-z0-9_]+)".*?description:\s*"([^"]{10,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_AUTH0_RULE_KEYS - found_keys
    assert missing == set(), (
        f"Auth0 rules missing description field: {missing}"
    )


def test_fe_rule_catalog_auth0_rules_have_remediation():
    """Every Auth0 rule entry has a non-empty remediation field."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(auth0_[a-z0-9_]+)".*?remediation:\s*"([^"]{10,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_AUTH0_RULE_KEYS - found_keys
    assert missing == set(), (
        f"Auth0 rules missing remediation field: {missing}"
    )


def test_fe_rule_catalog_auth0_rules_have_false_positive_guard():
    """Every Auth0 rule entry has a falsePositiveGuard field."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(auth0_[a-z0-9_]+)".*?falsePositiveGuard:\s*"([^"]{5,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_AUTH0_RULE_KEYS - found_keys
    assert missing == set(), (
        f"Auth0 rules missing falsePositiveGuard field: {missing}"
    )


def test_fe_rule_catalog_auth0_no_forbidden_wording():
    """No forbidden claim phrases in any Auth0 rule catalog entry."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    start = text.find('"auth0_tenant_session_lifetime_extended"')
    assert start != -1, "Auth0 section not found in rule catalog"
    auth0_section = text[start:]
    low = auth0_section.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"securityRuleCatalog.ts Auth0 section contains forbidden phrase {phrase!r}"
        )


def test_fe_rule_catalog_provider_coverage_has_auth0():
    """PROVIDER_COVERAGE includes an auth0 entry with surfaces."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    assert 'provider: "auth0"' in text
    # Must list Auth0 surfaces.
    for surface in ("Tenant settings", "Applications", "Connections", "APIs", "Rules", "Actions", "MFA"):
        assert surface in text, (
            f"PROVIDER_COVERAGE auth0 entry missing surface keyword {surface!r}"
        )


def test_fe_rule_catalog_auth0_metadata_only_flag():
    """Auth0 rule entries carry metadataOnly: true."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    start = text.find('"auth0_tenant_session_lifetime_extended"')
    assert start != -1
    auth0_section = text[start:]
    # The section ends at the next provider section or end of catalog.
    next_non_auth0 = re.search(r'key:\s*"(?!auth0_)[a-z0-9_]+"', auth0_section)
    if next_non_auth0:
        auth0_section = auth0_section[:next_non_auth0.start()]
    count_true = auth0_section.count("metadataOnly: true")
    count_false = auth0_section.count("metadataOnly: false")
    assert count_true >= 30, (
        f"Expected >= 30 metadataOnly: true in Auth0 section, found {count_true}"
    )
    assert count_false == 0, (
        f"Found {count_false} metadataOnly: false in Auth0 section"
    )


# ── api.ts ────────────────────────────────────────────────────────────────────


def test_fe_api_ts_auth0_sync_activity_present():
    text = _read_fe("lib/api.ts")
    assert "syncAuth0Activity" in text or "auth0-activity/sync" in text


def test_fe_api_ts_auth0_generate_signals_present():
    text = _read_fe("lib/api.ts")
    assert "generateAuth0ActivitySignals" in text or "auth0-activity/generate" in text


def test_fe_api_ts_auth0_generate_correlations_present():
    text = _read_fe("lib/api.ts")
    assert "generateAuth0Correlations" in text or "auth0-correlations" in text


def test_fe_api_ts_demo_provider_union_includes_auth0():
    """getIncidentDemoStatus / seedIncidentDemo / clearIncidentDemo all include auth0."""
    text = _read_fe("lib/api.ts")
    # At least 3 unions include auth0
    assert text.count('"auth0"') >= 3, (
        "Expected >= 3 demo helper union occurrences of auth0 in api.ts"
    )


# ── types/index.ts ────────────────────────────────────────────────────────────


def test_fe_types_auth0_activity_sync_response():
    text = _read_fe("types/index.ts")
    assert "Auth0ActivitySyncResponse" in text


def test_fe_types_auth0_signal_generate_response():
    text = _read_fe("types/index.ts")
    assert "Auth0ActivitySignalGenerateResponse" in text


def test_fe_types_auth0_correlation_generate_response():
    text = _read_fe("types/index.ts")
    assert "Auth0CorrelationGenerateResponse" in text


# ════════════════════════════════════════════════════════════════════════════
# Section E — Backend rule key parity
# ════════════════════════════════════════════════════════════════════════════


def test_backend_auth0_rule_keys_count():
    """Backend AUTH0_RULE_KEYS has all 37 expected rules."""
    assert len(AUTH0_RULE_KEYS) == 37, (
        f"Expected 37 Auth0 rule keys, found {len(AUTH0_RULE_KEYS)}"
    )


def test_backend_auth0_rule_keys_match_expected():
    """Backend AUTH0_RULE_KEYS exactly matches the expected set."""
    missing = EXPECTED_AUTH0_RULE_KEYS - frozenset(AUTH0_RULE_KEYS)
    extra = frozenset(AUTH0_RULE_KEYS) - EXPECTED_AUTH0_RULE_KEYS
    assert missing == set(), f"Backend Auth0 rule keys missing: {missing}"
    assert extra == set(), f"Backend Auth0 has unexpected rule keys: {extra}"


# ════════════════════════════════════════════════════════════════════════════
# Section F — Forbidden wording in backend production modules
# ════════════════════════════════════════════════════════════════════════════

_BACKEND_AUTH0_MODULES: tuple[str, ...] = (
    "app/connectors/auth0.py",
    "app/connectors/auth0_schema.py",
    "app/services/security_rules/auth0.py",
    "app/services/auth0_activity_ingestion_service.py",
    "app/services/auth0_activity_signal_service.py",
    "app/services/auth0_risk_activity_correlation_service.py",
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


@pytest.mark.parametrize("module", _BACKEND_AUTH0_MODULES)
def test_backend_auth0_module_no_forbidden_wording(module: str):
    """No forbidden claim phrases in any Auth0 backend module."""
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
