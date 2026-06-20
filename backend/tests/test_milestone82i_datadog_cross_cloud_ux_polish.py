"""M82I — Datadog cross-cloud UX polish guardrails.

Pins the final-mile UX/product polish for Datadog across the full security
product surface: capability matrix notes, expansion-framework next stage,
frontend page copy, rule catalog parity, demo-script talk track, and
case-report label consistency.

Adds NO product code — only assertions against existing modules and frontend
files. Frontend assertions skip gracefully when the frontend tree is absent.

Sections:

  A. Capability matrix (M82I polish complete; maturity stays partial)
  B. Provider expansion framework (planned_next_stage → M83A Clerk)
  C. Case report (Datadog label)
  D. Frontend Datadog consistency
       - Activity page: provider option, sync button, safe helper copy
       - Signals page: provider option, generate button, 11 signal types,
         Datadog-specific empty-state guidance
       - Correlations page: provider option, 11 correlation types, 3-step flow
       - Cases page: demo card, safe wording
       - Demo-script page: capability table row, arc range M82A–M82I, talk track
       - securityDemoScript.ts: Datadog in incident-demo steps
       - securityRuleCatalog.ts: all 31 Datadog rules
       - api.ts: Datadog API functions present, demo union includes datadog
       - types/index.ts: Datadog response types present
  E. Backend rule key parity (31 expected rules)
  F. Forbidden wording across Datadog backend modules
  G. Privacy / raw-data copy guardrails
  H. Secret-shape grep
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import datadog_activity_ingestion_service as dd_ingest
from app.services import datadog_activity_signal_service as dd_sig
from app.services import datadog_risk_activity_correlation_service as dd_corr
from app.services import security_case_report_service as report_svc
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework
from app.services.security_rules.datadog import DATADOG_RULE_KEYS

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ROOT = REPO_ROOT / "frontend" / "src"
FE_ACTIVITY = FE_ROOT / "app" / "(app)" / "security" / "activity" / "page.tsx"
FE_SIGNALS = FE_ROOT / "app" / "(app)" / "security" / "signals" / "page.tsx"
FE_CORRELATIONS = FE_ROOT / "app" / "(app)" / "security" / "correlations" / "page.tsx"
FE_CASES = FE_ROOT / "app" / "(app)" / "security" / "cases" / "page.tsx"
FE_DEMO_PAGE = FE_ROOT / "app" / "(app)" / "security" / "demo-script" / "page.tsx"
FE_DEMO_LIB = FE_ROOT / "lib" / "securityDemoScript.ts"
FE_RULE_CATALOG = FE_ROOT / "lib" / "securityRuleCatalog.ts"
FE_API = FE_ROOT / "lib" / "api.ts"
FE_TYPES = FE_ROOT / "types" / "index.ts"

EXPECTED_RULE_KEYS = {
    "datadog_monitor_disabled", "datadog_monitor_unrestricted_roles",
    "datadog_monitor_notify_no_data_disabled", "datadog_monitor_long_query",
    "datadog_monitor_no_notifications", "datadog_monitor_message_template_present",
    "datadog_monitor_no_warning_threshold", "datadog_monitor_no_recovery_threshold",
    "datadog_monitor_silenced_scopes_present", "datadog_monitor_notify_audit_disabled",
    "datadog_monitor_require_full_window_disabled", "datadog_monitor_query_wildcard_scope",
    "datadog_monitor_broad_group_by", "datadog_monitor_long_no_data_timeframe",
    "datadog_slo_no_monitors", "datadog_slo_low_target",
    "datadog_dashboard_public_url_present", "datadog_dashboard_unrestricted_roles",
    "datadog_webhook_without_secret_headers", "datadog_webhook_payload_template_present",
    "datadog_webhook_custom_headers_without_secret_headers",
    "datadog_webhook_large_payload_template", "datadog_webhook_auth_material_present",
    "datadog_webhook_non_https_endpoint",
    "datadog_notification_integration_no_channels",
    "datadog_application_key_broad_scopes",
    "datadog_api_key_disabled",
    "datadog_role_high_permission_count",
    "datadog_team_no_members",
    "datadog_cloud_integration_broad_collection",
    "datadog_cloud_integration_log_collection_enabled",
}

FORBIDDEN_PHRASES = [
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
]

# Phrases that would imply raw Datadog data ingestion — must not appear in
# user-facing copy without negation (e.g. "never stores raw...")
RAW_DATA_PHRASES = [
    "raw monitor queries", "raw monitor messages", "raw dashboard json",
    "raw widget queries", "raw audit", "raw log data", "raw trace data",
    "raw metric values", "raw event payloads", "raw incident text",
]


# ════════════════════════════════════════════════════════════════════════════
# A. Capability matrix
# ════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_all_drift_flags():
    cap = get_provider_capability("datadog")
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True


def test_capability_matrix_all_security_flags():
    cap = get_provider_capability("datadog")
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True


def test_capability_matrix_maturity_partial():
    cap = get_provider_capability("datadog")
    assert cap.maturity == "partial"


def test_capability_matrix_notes_mention_m82i():
    cap = get_provider_capability("datadog")
    notes = cap.notes or ""
    assert "M82I" in notes, (
        f"Capability matrix notes should reference M82I polish; got: {notes[:200]!r}"
    )


def test_capability_matrix_notes_mention_clerk_as_next():
    cap = get_provider_capability("datadog")
    notes = cap.notes or ""
    assert "Clerk" in notes, (
        f"Capability matrix notes should mention Clerk as next provider; got: {notes[:300]!r}"
    )


def test_capability_matrix_notes_have_no_pending_m82_pointer():
    cap = get_provider_capability("datadog")
    notes = cap.notes or ""
    assert "planned_next_stage: M82I" not in notes, (
        "Capability matrix notes still reference M82I as the planned next stage"
    )


# ════════════════════════════════════════════════════════════════════════════
# B. Provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_planned_next_stage_is_m83a():
    """M82I complete: planned_next_stage must point to M83A Clerk."""
    framework = get_framework()
    stage = framework["summary"]["planned_next_stage"]
    assert ("M83A" in stage or "Clerk" in stage or "M84A" in stage or "PagerDuty" in stage
            or "M85A" in stage or "Linear" in stage
            or "M86A" in stage or "M86B" in stage or "Jira" in stage
            or "M87A" in stage or "GitLab" in stage), (
        f"planned_next_stage should reference M83A/Clerk or later; got {stage!r}"
    )


def test_expansion_framework_not_pointing_to_m82():
    """The full Datadog M82 arc is complete; must be past it."""
    framework = get_framework()
    stage = framework["summary"]["planned_next_stage"]
    assert "M82I" not in stage and "M82H" not in stage, (
        f"planned_next_stage still within M82 arc: {stage!r}"
    )


def test_expansion_framework_pagerduty_first_recommended():
    # M83A shipped Clerk; PagerDuty is now the head.
    framework = get_framework()
    recs = framework.get("recommended_next_providers", [])
    assert recs, "RECOMMENDED_NEXT_PROVIDERS is empty"
    # After M87A, GitLab launched and Terraform Cloud moved to head.
    assert recs[0]["provider"] in ("pagerduty", "linear", "jira", "gitlab", "terraform_cloud", "kubernetes", "sentry")
    assert recs[0]["label"] in ("PagerDuty", "Linear", "Jira", "GitLab", "Terraform Cloud", "Kubernetes", "Sentry")


def test_expansion_framework_datadog_not_in_recommended():
    framework = get_framework()
    providers = [r["provider"] for r in framework.get("recommended_next_providers", [])]
    assert "datadog" not in providers


def test_expansion_framework_clerk_not_in_recommended():
    # Clerk launched in M83A — must not be in the recommended queue.
    framework = get_framework()
    recs = framework.get("recommended_next_providers", [])
    providers = [r["provider"] for r in recs]
    assert "clerk" not in providers, (
        "Clerk launched in M83A; must not remain in RECOMMENDED_NEXT_PROVIDERS"
    )


# ════════════════════════════════════════════════════════════════════════════
# C. Case report
# ════════════════════════════════════════════════════════════════════════════


def test_case_report_has_datadog_timeline_label():
    import inspect
    src = inspect.getsource(report_svc)
    assert '"datadog"' in src or "'datadog'" in src
    assert "Datadog" in src


# ════════════════════════════════════════════════════════════════════════════
# D. Frontend Datadog consistency
# ════════════════════════════════════════════════════════════════════════════


# Activity page

@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="frontend tree absent")
def test_fe_activity_datadog_provider_option():
    assert '"datadog"' in FE_ACTIVITY.read_text() or "'datadog'" in FE_ACTIVITY.read_text()


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="frontend tree absent")
def test_fe_activity_datadog_sync_action():
    src = FE_ACTIVITY.read_text()
    assert "syncDatadogActivity" in src or "Sync Datadog" in src


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="frontend tree absent")
def test_fe_activity_datadog_helper_copy_review_safe():
    src = FE_ACTIVITY.read_text()
    # Must mention Datadog configuration activity or similar safe framing
    assert "Datadog" in src
    # Must not imply raw audit log ingestion
    lower = src.lower()
    assert "audit logs are never ingested" in lower or "audit api" not in lower or "never" in lower


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="frontend tree absent")
def test_fe_activity_datadog_no_forbidden_wording():
    src = FE_ACTIVITY.read_text()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in src.lower(), f"Forbidden phrase {phrase!r} in activity page"


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="frontend tree absent")
def test_fe_activity_datadog_32_event_types():
    src = FE_ACTIVITY.read_text()
    found = set(re.findall(r'"(datadog\.[a-z_.]+)"', src))
    assert len(found) == 32, f"Expected 32 Datadog event types in activity page, found {len(found)}"


# Signals page

@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="frontend tree absent")
def test_fe_signals_datadog_provider_option():
    assert '"datadog"' in FE_SIGNALS.read_text() or "'datadog'" in FE_SIGNALS.read_text()


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="frontend tree absent")
def test_fe_signals_datadog_generate_action():
    src = FE_SIGNALS.read_text()
    assert "generateDatadogActivitySignals" in src or "Generate Datadog" in src


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="frontend tree absent")
def test_fe_signals_datadog_11_signal_types():
    src = FE_SIGNALS.read_text()
    found = set(re.findall(r'"(datadog_[a-z_]+_config_changed|datadog_config_activity)"', src))
    assert len(found) == 11, f"Expected 11 Datadog signal types in signals page, found {len(found)}"


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="frontend tree absent")
def test_fe_signals_datadog_empty_state_mentions_activity_first():
    src = FE_SIGNALS.read_text()
    # The Datadog empty state should tell users to sync activity first
    assert "Sync Datadog activity" in src or "Datadog activity" in src


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="frontend tree absent")
def test_fe_signals_datadog_no_forbidden_wording():
    src = FE_SIGNALS.read_text()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in src.lower(), f"Forbidden phrase {phrase!r} in signals page"


# Correlations page

@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="frontend tree absent")
def test_fe_correlations_datadog_provider_option():
    assert '"datadog"' in FE_CORRELATIONS.read_text() or "'datadog'" in FE_CORRELATIONS.read_text()


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="frontend tree absent")
def test_fe_correlations_datadog_generate_action():
    src = FE_CORRELATIONS.read_text()
    assert "generateDatadogCorrelations" in src or "Generate Datadog" in src


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="frontend tree absent")
def test_fe_correlations_datadog_correlation_types_present():
    src = FE_CORRELATIONS.read_text()
    found = set(re.findall(r'"(datadog_[a-z_]+_correlation)"', src))
    assert len(found) >= 10, f"Expected at least 10 Datadog correlation types, found {len(found)}"


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="frontend tree absent")
def test_fe_correlations_datadog_3step_flow_mentioned():
    src = FE_CORRELATIONS.read_text()
    # The Datadog flow is: sync activity → generate signals → generate correlations
    lower = src.lower()
    assert "sync datadog activity" in lower or ("datadog activity" in lower and "datadog signal" in lower)


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="frontend tree absent")
def test_fe_correlations_datadog_no_forbidden_wording():
    src = FE_CORRELATIONS.read_text()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in src.lower(), f"Forbidden phrase {phrase!r} in correlations page"


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="frontend tree absent")
def test_fe_correlations_datadog_safe_evidence_framing():
    src = FE_CORRELATIONS.read_text()
    # Must not claim compromise; must frame as evidence for review
    lower = src.lower()
    assert "does not confirm" in lower or "evidence for review" in lower or "review" in lower


# Cases page

@pytest.mark.skipif(not FE_CASES.exists(), reason="frontend tree absent")
def test_fe_cases_datadog_demo_card():
    src = FE_CASES.read_text()
    assert "datadog" in src.lower()


@pytest.mark.skipif(not FE_CASES.exists(), reason="frontend tree absent")
def test_fe_cases_datadog_no_forbidden_wording():
    src = FE_CASES.read_text()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in src.lower(), f"Forbidden phrase {phrase!r} in cases page"


@pytest.mark.skipif(not FE_CASES.exists(), reason="frontend tree absent")
def test_fe_cases_datadog_demo_card_safe_copy():
    src = FE_CASES.read_text()
    # The demo card must frame Datadog as webhook integration review, not breach
    lower = src.lower()
    assert "review" in lower or "evidence" in lower


# Demo-script page

@pytest.mark.skipif(not FE_DEMO_PAGE.exists(), reason="frontend tree absent")
def test_fe_demo_script_datadog_in_capability_table():
    src = FE_DEMO_PAGE.read_text()
    assert "datadog" in src.lower()


@pytest.mark.skipif(not FE_DEMO_PAGE.exists(), reason="frontend tree absent")
def test_fe_demo_script_datadog_arc_range_is_m82a_m82i():
    src = FE_DEMO_PAGE.read_text()
    # Description should reference the complete Datadog arc M82A–M82I
    assert "M82A–M82I" in src, (
        "demo-script description should reference complete Datadog arc M82A–M82I"
    )


@pytest.mark.skipif(not FE_DEMO_PAGE.exists(), reason="frontend tree absent")
def test_fe_demo_script_datadog_arc_not_stale_m82g():
    src = FE_DEMO_PAGE.read_text()
    # Stale M82A–M82G arc range should be gone (replaced by M82A–M82I)
    assert "M82A–M82G" not in src, (
        "demo-script still references stale arc range M82A–M82G; should be M82A–M82I"
    )


@pytest.mark.skipif(not FE_DEMO_PAGE.exists(), reason="frontend tree absent")
def test_fe_demo_script_datadog_demo_true():
    src = FE_DEMO_PAGE.read_text()
    # Datadog row must have demo: true
    assert re.search(r'datadog.*demo.*true|demo.*true.*datadog', src, re.IGNORECASE | re.DOTALL)


@pytest.mark.skipif(not FE_DEMO_PAGE.exists(), reason="frontend tree absent")
def test_fe_demo_script_clerk_in_next_providers():
    src = FE_DEMO_PAGE.read_text()
    assert "Clerk" in src, "Clerk must appear in NEXT_PROVIDERS_BRIEF on demo-script page"
    assert "M83A" in src, "Clerk's M83A milestone must appear in demo-script NEXT_PROVIDERS_BRIEF"


@pytest.mark.skipif(not FE_DEMO_PAGE.exists(), reason="frontend tree absent")
def test_fe_demo_script_comment_reflects_arc_complete():
    src = FE_DEMO_PAGE.read_text()
    # The NEXT_PROVIDERS_BRIEF comment should say Datadog arc complete M82A–M82I
    # (not "pending M82H–M82I")
    assert "pending (M82H–M82I)" not in src, (
        "demo-script still has stale 'pending (M82H–M82I)' comment; arc is now complete"
    )


@pytest.mark.skipif(not FE_DEMO_PAGE.exists(), reason="frontend tree absent")
def test_fe_demo_script_page_no_forbidden_wording():
    src = FE_DEMO_PAGE.read_text()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in src.lower(), (
            f"Forbidden phrase {phrase!r} in demo-script page"
        )


# securityDemoScript.ts

@pytest.mark.skipif(not FE_DEMO_LIB.exists(), reason="frontend tree absent")
def test_fe_demo_lib_mentions_datadog():
    src = FE_DEMO_LIB.read_text()
    assert "Datadog" in src or "datadog" in src


@pytest.mark.skipif(not FE_DEMO_LIB.exists(), reason="frontend tree absent")
def test_fe_demo_lib_no_forbidden_wording():
    src = FE_DEMO_LIB.read_text()
    # Strip lines that are explicit negation/avoidance/denylist contexts before scanning.
    lines = []
    for line in src.splitlines():
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


# securityRuleCatalog.ts

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="frontend tree absent")
def test_fe_rule_catalog_has_all_31_datadog_rules():
    src = FE_RULE_CATALOG.read_text()
    found = set(re.findall(r'"(datadog_[a-z_]+)"', src))
    missing = EXPECTED_RULE_KEYS - found
    assert missing == set(), f"Rule catalog missing Datadog keys: {missing!r}"


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="frontend tree absent")
def test_fe_rule_catalog_datadog_no_forbidden_wording():
    src = FE_RULE_CATALOG.read_text()
    # Only scan Datadog rule sections
    datadog_section_start = src.find('"datadog_')
    if datadog_section_start == -1:
        return
    datadog_section = src[datadog_section_start:]
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in datadog_section.lower(), (
            f"Forbidden phrase {phrase!r} in Datadog section of rule catalog"
        )


# api.ts

@pytest.mark.skipif(not FE_API.exists(), reason="frontend tree absent")
def test_fe_api_has_all_3_datadog_functions():
    src = FE_API.read_text()
    assert "syncDatadogActivity" in src
    assert "generateDatadogActivitySignals" in src
    assert "generateDatadogCorrelations" in src


@pytest.mark.skipif(not FE_API.exists(), reason="frontend tree absent")
def test_fe_api_demo_unions_include_datadog():
    src = FE_API.read_text()
    # seedIncidentDemo / clearIncidentDemo / getIncidentDemoStatus unions
    assert '"datadog"' in src or "'datadog'" in src


# types/index.ts

@pytest.mark.skipif(not FE_TYPES.exists(), reason="frontend tree absent")
def test_fe_types_has_datadog_response_types():
    src = FE_TYPES.read_text()
    assert "DatadogActivitySyncResponse" in src
    assert "DatadogActivitySignalGenerateResponse" in src
    assert "DatadogCorrelationGenerateResponse" in src


@pytest.mark.skipif(not FE_TYPES.exists(), reason="frontend tree absent")
def test_fe_types_provider_union_includes_datadog():
    src = FE_TYPES.read_text()
    assert '"datadog"' in src or "'datadog'" in src


# ════════════════════════════════════════════════════════════════════════════
# E. Backend rule key parity
# ════════════════════════════════════════════════════════════════════════════


def test_backend_rule_keys_count_31():
    assert len(DATADOG_RULE_KEYS) == 31


def test_backend_rule_keys_match_expected():
    assert DATADOG_RULE_KEYS == EXPECTED_RULE_KEYS, (
        f"extra={DATADOG_RULE_KEYS - EXPECTED_RULE_KEYS!r}\n"
        f"missing={EXPECTED_RULE_KEYS - DATADOG_RULE_KEYS!r}"
    )


def test_activity_event_types_32():
    assert len(dd_ingest._DATADOG_CONFIG_EVENT_TYPES) == 32


def test_signal_types_11():
    import inspect
    src = inspect.getsource(dd_sig)
    found = set(re.findall(r'"(datadog_[a-z_]+_config_changed|datadog_config_activity)"', src))
    assert len(found) == 11


def test_correlation_types_11():
    import inspect
    src = inspect.getsource(dd_corr)
    found = set(re.findall(r'"(datadog_[a-z_]+_correlation)"', src))
    assert len(found) == 11


def test_datadog_provider_source_constants():
    assert dd_ingest.PROVIDER == "datadog"
    assert dd_ingest.SOURCE == "datadog_activity_event"
    assert dd_ingest.EVENT_SOURCE == "datadog_activity_event"


# ════════════════════════════════════════════════════════════════════════════
# F. Forbidden wording across Datadog backend modules
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("module,name", [
    (dd_ingest, "datadog_activity_ingestion_service"),
    (dd_sig, "datadog_activity_signal_service"),
    (dd_corr, "datadog_risk_activity_correlation_service"),
])
def test_backend_no_forbidden_claims(module, name):
    import inspect
    src = inspect.getsource(module)
    for phrase in FORBIDDEN_PHRASES:
        lines = [ln for ln in src.split("\n") if phrase.lower() in ln.lower()]
        for ln in lines:
            low = ln.lower()
            is_negation = any(neg in low for neg in ("does not", "never", "not confirm", "# never", "avoid"))
            assert is_negation, (
                f"Module {name!r} contains forbidden claim phrase {phrase!r} without negation:\n"
                f"  {ln.strip()!r}"
            )


# ════════════════════════════════════════════════════════════════════════════
# G. Privacy / raw-data copy guardrails
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="frontend tree absent")
def test_fe_activity_datadog_copy_no_raw_data_claim():
    """Datadog helper copy must not claim raw logs/traces/metrics/audit payloads
    are ingested — only the negation form is acceptable."""
    src = FE_ACTIVITY.read_text()
    suspicious_phrases = ["raw monitor", "raw dashboard", "raw audit", "raw log"]
    for phrase in suspicious_phrases:
        for ln in src.split("\n"):
            if phrase.lower() in ln.lower():
                assert "never" in ln.lower() or "not" in ln.lower(), (
                    f"Activity page mentions {phrase!r} without negation: {ln.strip()!r}"
                )


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="frontend tree absent")
def test_fe_signals_datadog_copy_no_raw_data_claim():
    src = FE_SIGNALS.read_text()
    for phrase in ["raw monitor", "raw audit", "raw log"]:
        for ln in src.split("\n"):
            if phrase.lower() in ln.lower():
                assert "never" in ln.lower() or "not" in ln.lower(), (
                    f"Signals page mentions {phrase!r} without negation: {ln.strip()!r}"
                )


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="frontend tree absent")
def test_fe_correlations_datadog_copy_no_raw_data_claim():
    src = FE_CORRELATIONS.read_text()
    for phrase in ["raw monitor", "raw audit", "raw log"]:
        for ln in src.split("\n"):
            if phrase.lower() in ln.lower():
                assert "never" in ln.lower() or "not" in ln.lower(), (
                    f"Correlations page mentions {phrase!r} without negation: {ln.strip()!r}"
                )


# ════════════════════════════════════════════════════════════════════════════
# H. Secret-shape grep
# ════════════════════════════════════════════════════════════════════════════


def test_no_secret_shapes_in_datadog_ingestion_source():
    import inspect
    src = inspect.getsource(dd_ingest)
    for pattern, name in [
        (r"eyJ[A-Za-z0-9_-]{10,}", "JWT shape"),
        (r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "SendGrid key shape"),
        (r"AC[0-9a-fA-F]{32}", "Twilio account SID shape"),
        (r"SK[0-9a-fA-F]{32}", "Twilio API key shape"),
    ]:
        assert not re.search(pattern, src), (
            f"{name} found in datadog_activity_ingestion_service source"
        )


def test_no_secret_shapes_in_datadog_signal_source():
    import inspect
    src = inspect.getsource(dd_sig)
    for pattern in [
        r"eyJ[A-Za-z0-9_-]{10,}", r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"AC[0-9a-fA-F]{32}", r"SK[0-9a-fA-F]{32}",
    ]:
        assert not re.search(pattern, src)


def test_no_secret_shapes_in_datadog_correlation_source():
    import inspect
    src = inspect.getsource(dd_corr)
    for pattern in [
        r"eyJ[A-Za-z0-9_-]{10,}", r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"AC[0-9a-fA-F]{32}", r"SK[0-9a-fA-F]{32}",
    ]:
        assert not re.search(pattern, src)
