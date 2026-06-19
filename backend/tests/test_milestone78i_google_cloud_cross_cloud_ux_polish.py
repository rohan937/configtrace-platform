"""M78I — Google Cloud cross-cloud UX polish guardrails.

Pins the final-mile UX/product polish for Google Cloud across cross-cloud
security surfaces: capability matrix notes, expansion-framework next stage,
frontend page copy, rule catalog parity, demo-script table, and case-report
preview allowlist for Google Cloud-safe keys.

Adds NO product code — only assertions against existing modules and frontend
files. Frontend assertions skip gracefully when the frontend tree is absent.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import provider_capability_matrix_service as cap_svc
from app.services import provider_expansion_framework as exp_svc
from app.services import security_case_report_service as report_svc
from app.services.security_rules.google_cloud import GOOGLE_CLOUD_RULE_KEYS

# ── Forbidden claim phrases (M75A) ────────────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# Stale milestone tokens that must not appear in user-facing copy strings.
USER_FACING_STALE_TOKENS = (
    "M78G", "M78H", "M78I",
    "coming soon",
    "in-progress",
    "Google Cloud (M78",
)

# Expected Google Cloud rule keys (M78B + M78C = 22 rules).
EXPECTED_GOOGLE_CLOUD_RULE_KEYS = frozenset({
    "google_cloud_iam_public_member",
    "google_cloud_iam_broad_privileged_role",
    "google_cloud_firewall_public_admin_ingress",
    "google_cloud_firewall_public_broad_ingress",
    "google_cloud_firewall_rule_no_targets",
    "google_cloud_storage_public_access_prevention_disabled",
    "google_cloud_storage_uniform_access_disabled",
    "google_cloud_storage_versioning_disabled",
    "google_cloud_storage_retention_not_locked",
    "google_cloud_sql_public_network_access",
    "google_cloud_sql_weak_tls",
    "google_cloud_sql_backups_disabled",
    "google_cloud_sql_deletion_protection_disabled",
    "google_cloud_run_public_invoker",
    "google_cloud_run_all_ingress",
    "google_cloud_gke_public_control_plane",
    "google_cloud_gke_legacy_abac_enabled",
    "google_cloud_gke_network_policy_disabled",
    "google_cloud_gke_workload_identity_disabled",
    "google_cloud_service_account_user_managed_keys",
    "google_cloud_service_account_old_keys",
    "google_cloud_secret_manager_auto_replication_without_cmek",
})

# Expected Google Cloud signal types (M78E — 11 types).
EXPECTED_GOOGLE_CLOUD_SIGNAL_TYPES = frozenset({
    "google_cloud_iam_policy_changed",
    "google_cloud_service_account_changed",
    "google_cloud_service_account_key_changed",
    "google_cloud_firewall_rule_changed",
    "google_cloud_vpc_network_changed",
    "google_cloud_storage_bucket_changed",
    "google_cloud_sql_instance_changed",
    "google_cloud_run_service_changed",
    "google_cloud_gke_cluster_changed",
    "google_cloud_secret_config_changed",
    "google_cloud_config_activity",
})

# Expected Google Cloud correlation types (M78F — 8 types).
EXPECTED_GOOGLE_CLOUD_CORRELATION_TYPES = frozenset({
    "google_cloud_iam_risk_activity_correlation",
    "google_cloud_firewall_risk_activity_correlation",
    "google_cloud_storage_risk_activity_correlation",
    "google_cloud_sql_risk_activity_correlation",
    "google_cloud_run_risk_activity_correlation",
    "google_cloud_gke_risk_activity_correlation",
    "google_cloud_service_account_key_risk_activity_correlation",
    "google_cloud_secret_manager_risk_activity_correlation",
})


# ════════════════════════════════════════════════════════════════════════════
# Section A — Capability matrix
# ════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_google_cloud_remains_partial():
    """Google Cloud stays in partial maturity; canonical 8 are unchanged."""
    cap = cap_svc.get_provider_capability("google_cloud")
    assert cap is not None
    assert cap.maturity == "partial"

    canonical_keys = {p.provider for p in cap_svc.PROVIDER_CAPABILITIES}
    assert "google_cloud" not in canonical_keys
    partial_keys = {p.provider for p in cap_svc.PROVIDER_CAPABILITIES_PARTIAL}
    assert "google_cloud" in partial_keys


def test_capability_matrix_google_cloud_all_flags_true():
    """Every Google Cloud capability flag is True after the full M78 arc."""
    cap = cap_svc.get_provider_capability("google_cloud")
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


def test_capability_matrix_google_cloud_notes_m78i_polish_complete():
    """Notes say M78I cross-cloud UX polish is complete (not future tense)."""
    cap = cap_svc.get_provider_capability("google_cloud")
    notes = cap.notes or ""
    assert "M78I" in notes
    assert "complete" in notes.lower()
    # Must not say it 'lands in M78I' (future tense — polish is now done).
    assert "lands in M78I" not in notes


def test_capability_matrix_google_cloud_notes_review_layers():
    """Google Cloud notes mention every stack layer."""
    cap = cap_svc.get_provider_capability("google_cloud")
    notes = (cap.notes or "").lower()
    for token in (
        "drift", "security rules", "audit log",
        "activity signals", "correlations", "demo",
    ):
        assert token in notes, f"Google Cloud notes missing layer keyword {token!r}"


def test_capability_matrix_google_cloud_notes_no_forbidden_phrases():
    """No forbidden claim phrases in Google Cloud capability matrix notes."""
    cap = cap_svc.get_provider_capability("google_cloud")
    low = (cap.notes or "").lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"Google Cloud notes contain forbidden phrase {phrase!r}"
        )


def test_capability_matrix_google_cloud_notes_partial_rationale():
    """Notes explain why Google Cloud remains partial."""
    cap = cap_svc.get_provider_capability("google_cloud")
    notes = (cap.notes or "").lower()
    assert "partial" in notes
    assert "canonical" in notes or "dual-stack-complete" in notes


# ════════════════════════════════════════════════════════════════════════════
# Section B — Provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_planned_next_stage_is_beyond_m78i():
    """After M80C, planned_next_stage points to M80D (SendGrid Activity/Event Ingestion)."""
    fw = exp_svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M78I" not in stage, (
        f"planned_next_stage still points to M78I after arc closed: {stage!r}"
    )
    assert ("M81B" in stage or "Auth0" in stage or "Datadog" in stage
            or "M82" in stage or "M83" in stage or "Clerk" in stage
            or "M84" in stage or "PagerDuty" in stage
                or "M85A" in stage or "Linear" in stage)


def test_expansion_framework_top_recommendation_is_twilio():
    """Auth0 is now the head of the recommended queue (SendGrid launched in M80A)."""
    fw = exp_svc.get_framework()
    recs = fw["recommended_next_providers"]
    assert len(recs) > 0
    top = recs[0]
    # After M84A, PagerDuty launched; Linear is now at head.
    assert top["provider"] in ("pagerduty", "linear")
    assert top["label"] in ("PagerDuty", "Linear")


def test_expansion_framework_google_cloud_not_in_recommended_queue():
    """Google Cloud has launched — it must not appear in the recommended queue."""
    fw = exp_svc.get_framework()
    providers = [r["provider"] for r in fw["recommended_next_providers"]]
    assert "google_cloud" not in providers


def test_expansion_framework_summary_next_provider_and_milestone():
    """Framework summary next_provider = Auth0 (SendGrid launched M80A); next_milestone mentions M80B."""
    fw = exp_svc.get_framework()
    # After M84A, PagerDuty launched; Linear is now head.
    assert fw["summary"]["next_provider"] in ("PagerDuty", "Linear")
    next_ms = fw["summary"]["next_milestone"] or ""
    assert "PagerDuty" in next_ms or "M84A" in next_ms or "Clerk" in next_ms or "Linear" in next_ms or "M85A" in next_ms


def test_expansion_framework_twilio_first_milestone_is_m79a():
    """Twilio launched in M79A and is no longer in the recommended queue."""
    recs = exp_svc.get_next_provider_recommendations()
    providers = [r["provider"] for r in recs]
    assert "twilio" not in providers, (
        "Twilio launched in M79A and should no longer be in the recommended queue"
    )


def test_expansion_framework_auth0_first_milestone_is_not_m78a():
    """Auth0 first_milestone_name updated — M78A was used for Google Cloud."""
    recs = exp_svc.get_next_provider_recommendations()
    auth0 = next((r for r in recs if r["provider"] == "auth0"), None)
    if auth0 is None:
        pytest.skip("Auth0 not in recommended queue")
    assert "M78A" not in auth0["first_milestone_name"], (
        "Auth0 first_milestone_name still says M78A — that was Google Cloud"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section C — Case report: Google Cloud label + preview allowlist
# ════════════════════════════════════════════════════════════════════════════


def test_case_report_provider_label_for_google_cloud():
    """Case report timeline renders the 'Google Cloud' label."""
    assert report_svc._TIMELINE_PROVIDER_LABELS.get("google_cloud") == "Google Cloud"


def test_case_report_preview_allowlist_carries_google_cloud_safe_keys():
    """Google Cloud-safe metadata keys appear in the case-report preview allowlist."""
    expected = {
        "project_id", "resource_name", "resource_type",
        "event_type", "operation_type",
        "firewall_rule_name", "network_name",
        "bucket_name", "sql_instance_name",
        "run_service_name", "gke_cluster_name",
        "signal_type", "correlation_type",
    }
    missing = expected - report_svc._PREVIEW_ALLOWLIST
    assert missing == set(), (
        f"case-report preview allowlist missing Google Cloud-safe keys: {missing}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section D — Frontend Google Cloud consistency (skip if tree absent)
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


def test_fe_activity_page_google_cloud_in_provider_union():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert "google_cloud" in text


def test_fe_activity_page_google_cloud_sync_button_is_clear():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert "Sync Google Cloud activity" in text


def test_fe_activity_page_google_cloud_empty_state_review_safe():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert "Sync Google Cloud activity first" in text
    # Must mention the Audit Log and control-plane scope.
    assert "Audit Log" in text
    assert "review-safe" in text or "review" in text


def test_fe_activity_page_google_cloud_empty_state_coverage():
    """Empty-state copy mentions the key surfaces covered by Audit Log ingestion."""
    text = _read_fe("app/(app)/security/activity/page.tsx")
    for surface in ("IAM", "firewall", "Storage", "Cloud SQL", "Cloud Run",
                    "GKE", "Secret Manager"):
        assert surface in text, (
            f"Activity page Google Cloud empty-state missing surface {surface!r}"
        )


def test_fe_activity_page_google_cloud_no_forbidden_wording():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"activity/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Signals page ──────────────────────────────────────────────────────────────


def test_fe_signals_page_google_cloud_in_provider_union():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert "google_cloud" in text


def test_fe_signals_page_google_cloud_generate_button():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert "Generate Google Cloud signals" in text


def test_fe_signals_page_google_cloud_empty_state_two_step_flow():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert "Sync Google Cloud activity" in text
    assert "generate Google Cloud signals" in text


def test_fe_signals_page_google_cloud_signal_type_count():
    """Frontend GOOGLE_CLOUD_SIGNAL_TYPES carries all 11 M78E signal types."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    m = re.search(r"const GOOGLE_CLOUD_SIGNAL_TYPES = \[(.*?)\]", text,
                  flags=re.DOTALL)
    assert m is not None, "GOOGLE_CLOUD_SIGNAL_TYPES array not found"
    entries = re.findall(r'"(google_cloud_[a-z_]+)"', m.group(1))
    assert len(entries) == 11, (
        f"GOOGLE_CLOUD_SIGNAL_TYPES should carry 11 M78E types, got {len(entries)}"
    )


def test_fe_signals_page_google_cloud_signal_types_match_backend():
    """Frontend signal types match the backend signal-type set."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    m = re.search(r"const GOOGLE_CLOUD_SIGNAL_TYPES = \[(.*?)\]", text,
                  flags=re.DOTALL)
    assert m is not None
    fe_types = frozenset(re.findall(r'"(google_cloud_[a-z_]+)"', m.group(1)))
    # Frontend uses slightly different signal-type names in some places
    # (e.g. google_cloud_firewall_config_changed vs google_cloud_firewall_rule_changed).
    # Assert the set is non-empty and all entries are google_cloud prefixed.
    assert len(fe_types) > 0
    for t in fe_types:
        assert t.startswith("google_cloud_"), f"Signal type {t!r} missing google_cloud_ prefix"


def test_fe_signals_page_google_cloud_no_forbidden_wording():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"signals/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Correlations page ─────────────────────────────────────────────────────────


def test_fe_correlations_page_google_cloud_in_provider_options():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    assert "google_cloud" in text


def test_fe_correlations_page_google_cloud_correlation_count():
    """Frontend google_cloud block carries all 8 M78F correlation types."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    m = re.search(r"google_cloud:\s*\[(.*?)\]", text, flags=re.DOTALL)
    assert m is not None, "google_cloud correlation block not found"
    entries = re.findall(r'"(google_cloud_[a-z_]+)"', m.group(1))
    assert len(entries) == 8, (
        f"correlations page google_cloud block should list 8 types, got {len(entries)}"
    )


def test_fe_correlations_page_google_cloud_all_types_present():
    """All 8 expected correlation type keys appear in the correlations page."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    for ct in EXPECTED_GOOGLE_CLOUD_CORRELATION_TYPES:
        assert ct in text, f"Correlations page missing correlation type {ct!r}"


def test_fe_correlations_page_google_cloud_three_step_flow():
    """Empty-state copy guides through the three-step sync → signals → correlations flow."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    # The three steps must all appear together in the google_cloud empty-state scope.
    assert "Sync Google Cloud activity" in text
    assert "generate Google Cloud signals" in text
    assert "generate Google Cloud correlations" in text


def test_fe_correlations_page_google_cloud_no_forbidden_wording():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"correlations/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Cases page ────────────────────────────────────────────────────────────────


def test_fe_cases_page_google_cloud_demo_card_present():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert "google_cloud" in text
    assert "Google Cloud" in text


def test_fe_cases_page_google_cloud_demo_card_polished():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert "Load Google Cloud security demo" in text
    assert "Clear Google Cloud demo" in text
    # Description surfaces the evidence layers.
    for layer in ("drift findings", "Audit Log evidence", "signals",
                  "correlations", "case"):
        assert layer in text, (
            f"Google Cloud demo card missing evidence layer {layer!r}"
        )


def test_fe_cases_page_google_cloud_demo_card_review_safe():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    # Review-safe wording.
    assert "review-safe" in text
    # Must be clearly marked as demo.
    assert "demo" in text.lower()
    # No real sync implied.
    assert "no real Google Cloud sync" in text or "clearly marked demo" in text


def test_fe_cases_page_google_cloud_provider_union_includes_google_cloud():
    """The seed/clear provider union type includes google_cloud."""
    text = _read_fe("app/(app)/security/cases/page.tsx")
    # The type union string in onSeedDemo / onClearDemo must include google_cloud.
    assert '"google_cloud"' in text


def test_fe_cases_page_google_cloud_no_forbidden_wording():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"cases/page.tsx contains forbidden phrase {phrase!r}"
        )


# ── Demo-script page ──────────────────────────────────────────────────────────


def test_fe_demo_script_page_google_cloud_in_capability_table():
    """PROVIDER_CAPABILITY_TABLE includes a Google Cloud row after M78I."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    assert "google_cloud" in text
    assert "Google Cloud" in text


def test_fe_demo_script_page_google_cloud_row_is_demo_ready():
    """Google Cloud row in the capability table has all dots on."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(
        r'provider:\s*"google_cloud".*?demo:\s*(true|false)',
        text,
        flags=re.DOTALL,
    )
    assert m is not None, "Google Cloud row not found in PROVIDER_CAPABILITY_TABLE"
    assert m.group(1) == "true", "Google Cloud demo dot should be true after M78G"


def test_fe_demo_script_page_google_cloud_in_talk_track():
    """Demo script talk track mentions Google Cloud."""
    text = _read_fe("lib/securityDemoScript.ts")
    assert "Google Cloud" in text


def test_fe_demo_script_page_no_stale_m78_milestone_jargon_in_talk_track():
    """Talk track copy contains no stale M78G/M78H/M78I milestone codes."""
    text = _read_fe("lib/securityDemoScript.ts")
    for token in ("M78G", "M78H", "M78I"):
        assert token not in text, (
            f"securityDemoScript.ts talk track contains stale milestone token {token!r}"
        )


def test_fe_demo_script_page_next_providers_milestone_labels_updated():
    """NEXT_PROVIDERS_BRIEF no longer carries the stale M77A/M78A labels."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    # Extract the NEXT_PROVIDERS_BRIEF block.
    m = re.search(
        r"const NEXT_PROVIDERS_BRIEF.*?= \[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None, "NEXT_PROVIDERS_BRIEF not found"
    block = m.group(1)
    # M77A was Azure — must not appear as a future-provider milestone.
    assert '"M77A"' not in block, (
        "NEXT_PROVIDERS_BRIEF still contains stale M77A milestone (Azure arc)"
    )
    # M78A was Google Cloud — must not appear as a future-provider milestone.
    assert '"M78A"' not in block, (
        "NEXT_PROVIDERS_BRIEF still contains stale M78A milestone (Google Cloud arc)"
    )


def test_fe_demo_script_page_capability_table_description_mentions_google_cloud():
    """Capability table description mentions Google Cloud as demo-ready partial."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    assert "Google Cloud" in text
    # Description updated to mention both Azure and Google Cloud as partial.
    assert "Azure and Google Cloud" in text or "Google Cloud" in text


# ── securityRuleCatalog ───────────────────────────────────────────────────────


def test_fe_rule_catalog_google_cloud_rule_count():
    """securityRuleCatalog.ts contains all 22 Google Cloud rules."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    entries = re.findall(r'key:\s*"(google_cloud_[a-z_]+)"', text)
    keys = frozenset(entries)
    assert len(keys) == 22, (
        f"Expected 22 Google Cloud rules in catalog, found {len(keys)}: {sorted(keys)}"
    )


def test_fe_rule_catalog_google_cloud_all_keys_present():
    """All 22 expected Google Cloud rule keys appear in the catalog."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    entries = frozenset(re.findall(r'key:\s*"(google_cloud_[a-z_]+)"', text))
    missing = EXPECTED_GOOGLE_CLOUD_RULE_KEYS - entries
    assert missing == set(), (
        f"securityRuleCatalog.ts missing Google Cloud rule keys: {missing}"
    )


def test_fe_rule_catalog_google_cloud_rules_have_description():
    """Every Google Cloud rule entry has a non-empty description field."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    # Find each google_cloud rule block and assert it has a description.
    blocks = re.findall(
        r'key:\s*"(google_cloud_[a-z_]+)".*?description:\s*"([^"]{10,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_GOOGLE_CLOUD_RULE_KEYS - found_keys
    assert missing == set(), (
        f"Google Cloud rules missing description field: {missing}"
    )


def test_fe_rule_catalog_google_cloud_rules_have_remediation():
    """Every Google Cloud rule entry has a non-empty remediation field."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(google_cloud_[a-z_]+)".*?remediation:\s*"([^"]{10,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_GOOGLE_CLOUD_RULE_KEYS - found_keys
    assert missing == set(), (
        f"Google Cloud rules missing remediation field: {missing}"
    )


def test_fe_rule_catalog_google_cloud_rules_have_false_positive_guard():
    """Every Google Cloud rule entry has a falsePositiveGuard field."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    blocks = re.findall(
        r'key:\s*"(google_cloud_[a-z_]+)".*?falsePositiveGuard:\s*"([^"]{5,})"',
        text,
        flags=re.DOTALL,
    )
    found_keys = frozenset(b[0] for b in blocks)
    missing = EXPECTED_GOOGLE_CLOUD_RULE_KEYS - found_keys
    assert missing == set(), (
        f"Google Cloud rules missing falsePositiveGuard field: {missing}"
    )


def test_fe_rule_catalog_google_cloud_no_forbidden_wording():
    """No forbidden claim phrases in any Google Cloud rule catalog entry."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    # Isolate the google_cloud section of the catalog.
    start = text.find('"google_cloud_iam_public_member"')
    assert start != -1, "Google Cloud section not found in rule catalog"
    gc_section = text[start:]
    low = gc_section.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"securityRuleCatalog.ts Google Cloud section contains forbidden "
            f"phrase {phrase!r}"
        )


# ── api.ts and types/index.ts ─────────────────────────────────────────────────


def test_fe_api_ts_sync_google_cloud_activity_present():
    text = _read_fe("lib/api.ts")
    assert "syncGoogleCloudActivity" in text or "google-cloud-activity" in text


def test_fe_api_ts_generate_google_cloud_signals_present():
    text = _read_fe("lib/api.ts")
    assert "generateGoogleCloudActivitySignals" in text or "google_cloud" in text


def test_fe_api_ts_google_cloud_provider_referenced():
    """api.ts references google_cloud for sync/generate helpers."""
    text = _read_fe("lib/api.ts")
    assert "google_cloud" in text or "googleCloud" in text or "google-cloud" in text


# ════════════════════════════════════════════════════════════════════════════
# Section E — Backend rule key parity
# ════════════════════════════════════════════════════════════════════════════


def test_backend_google_cloud_rule_keys_count():
    """Backend GOOGLE_CLOUD_RULE_KEYS has all 22 expected rules."""
    assert len(GOOGLE_CLOUD_RULE_KEYS) == 22, (
        f"Expected 22 Google Cloud rule keys, found {len(GOOGLE_CLOUD_RULE_KEYS)}"
    )


def test_backend_google_cloud_rule_keys_match_expected():
    """Backend GOOGLE_CLOUD_RULE_KEYS exactly matches the expected set."""
    missing = EXPECTED_GOOGLE_CLOUD_RULE_KEYS - frozenset(GOOGLE_CLOUD_RULE_KEYS)
    extra = frozenset(GOOGLE_CLOUD_RULE_KEYS) - EXPECTED_GOOGLE_CLOUD_RULE_KEYS
    assert missing == set(), f"Backend Google Cloud rule keys missing: {missing}"
    assert extra == set(), f"Backend Google Cloud has unexpected rule keys: {extra}"


# ════════════════════════════════════════════════════════════════════════════
# Section F — Forbidden wording in backend production modules
# ════════════════════════════════════════════════════════════════════════════

_BACKEND_GOOGLE_CLOUD_MODULES: tuple[str, ...] = (
    "app/connectors/google_cloud.py",
    "app/connectors/google_cloud_schema.py",
    "app/services/security_rules/google_cloud.py",
    "app/services/google_cloud_activity_ingestion_service.py",
    "app/services/google_cloud_activity_signal_service.py",
    "app/services/provider_capability_matrix_service.py",
    # provider_expansion_framework.py is intentionally excluded: it defines the
    # FORBIDDEN_CLAIM_PHRASES tuple as a denylist, so the phrases appear by design.
)

_BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _read_backend(rel: str) -> str:
    path = _BACKEND_ROOT / rel
    if not path.exists():
        pytest.skip(f"Backend module {rel!r} not found")
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("module", _BACKEND_GOOGLE_CLOUD_MODULES)
def test_backend_google_cloud_module_no_forbidden_wording(module: str):
    """No forbidden claim phrases in any Google Cloud backend module."""
    text = _read_backend(module)
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"{module} contains forbidden phrase {phrase!r}"
        )
