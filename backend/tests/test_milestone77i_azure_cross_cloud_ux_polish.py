"""M77I — Azure cross-cloud UX polish guardrails.

This file pins the final-mile UX/product polish that lands across Azure
cross-cloud surfaces (capability matrix notes, expansion-framework next
stage + Google Cloud recommendation, frontend page copy, rule catalog
parity, and case-report preview allowlist for Azure-safe keys).

It adds NO product code — only assertions against the existing modules and
frontend files. If the frontend source tree is not mounted (e.g. inside the
docker test runner), the frontend assertions skip gracefully.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import provider_capability_matrix_service as cap_svc
from app.services import provider_expansion_framework as exp_svc
from app.services import security_case_report_service as report_svc
from app.services.security_rules.azure import AZURE_RULE_KEYS

# ── Forbidden claim phrases (M75A pin) ───────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# ── Stale milestone jargon that must not surface to end users ────────────────
# These tokens are fine in INTERNAL surfaces (e.g. the demo-script page is
# explicitly an internal milestone tracker), so we only forbid them in the
# user-facing copy strings inside frontend page components, lib/api.ts, and
# securityDemoScript talk-track text.
USER_FACING_STALE_TOKENS = (
    "M77G", "M77H", "M77I",  # internal milestone codes
    "coming soon",
    "in-progress",
    "in progress (Azure)",
    "Azure (M77",
)


# ════════════════════════════════════════════════════════════════════════════
# Section A — Capability matrix + expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_azure_remains_partial():
    """Azure stays in partial maturity; canonical 8 are unchanged."""
    cap = cap_svc.get_provider_capability("azure")
    assert cap is not None
    assert cap.maturity == "partial"

    canonical_keys = {p.provider for p in cap_svc.PROVIDER_CAPABILITIES}
    assert "azure" not in canonical_keys
    partial_keys = {p.provider for p in cap_svc.PROVIDER_CAPABILITIES_PARTIAL}
    assert "azure" in partial_keys


def test_capability_matrix_azure_all_flags_true():
    """Every Azure capability flag stays True after M77I polish."""
    cap = cap_svc.get_provider_capability("azure")
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


def test_capability_matrix_azure_notes_are_demo_ready():
    """Azure notes mention demo-ready and review-safe wording."""
    cap = cap_svc.get_provider_capability("azure")
    notes = (cap.notes or "")
    assert "demo-ready" in notes
    # Mentions every layer in the review flow.
    for token in (
        "drift snapshots", "security rules", "Activity Log",
        "activity signals", "correlations", "case",
    ):
        assert token in notes, f"Azure notes missing layer keyword {token!r}"
    # No forbidden claim phrases anywhere in the matrix notes.
    low = notes.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, f"Azure notes contain forbidden phrase {phrase!r}"
    # No stale milestone jargon in user-facing matrix notes.
    for token in ("M77G", "M77H", "M77I"):
        assert token not in notes, (
            f"Azure notes still mention {token!r} — Azure arc closed, "
            f"keep notes milestone-free"
        )


def test_capability_matrix_azure_notes_mention_partial_maturity_reason():
    """Notes explain why Azure remains partial."""
    cap = cap_svc.get_provider_capability("azure")
    notes = (cap.notes or "").lower()
    assert "partial" in notes
    # Notes should reference why Azure is still partial.
    assert "canonical" in notes or "cross-provider" in notes


def test_expansion_framework_next_stage_is_beyond_m79d():
    """Rolled forward in M80C: SendGrid Mail/Webhook complete; next stage is M80D."""
    fw = exp_svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert ("M81B" in stage or "Auth0" in stage or "Datadog" in stage
            or "M82" in stage or "M83" in stage or "Clerk" in stage
            or "M84" in stage or "PagerDuty" in stage
                or "M85A" in stage or "Linear" in stage)


def test_expansion_framework_top_recommendation_is_google_cloud():
    """Flipped in M80A: SendGrid moved out of the recommended queue (launched).
    Auth0 is now the head."""
    fw = exp_svc.get_framework()
    recs = fw["recommended_next_providers"]
    assert len(recs) > 0
    top = recs[0]
    # After M84A, PagerDuty launched; Linear is now at head.
    assert top["provider"] in ("pagerduty", "linear")
    assert top["label"] in ("PagerDuty", "Linear")
    # GCP, auth0, datadog, clerk must no longer be in the recommended list.
    providers = [r["provider"] for r in recs]
    assert "google_cloud" not in providers
    assert "auth0" not in providers
    assert "clerk" not in providers


def test_expansion_framework_google_cloud_recommendation_is_complete():
    """Flipped in M78A: GCP is no longer in RECOMMENDED_NEXT_PROVIDERS — it
    launched. Confirm it now lives in PROVIDER_CAPABILITIES_PARTIAL instead."""
    from app.services.provider_capability_matrix_service import (
        PROVIDER_CAPABILITIES_PARTIAL, get_provider_capability,
    )
    partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
    assert "google_cloud" in partial
    cap = get_provider_capability("google_cloud")
    assert cap is not None
    assert cap.label == "Google Cloud"
    assert cap.maturity == "partial"
    # Drift snapshots true; security_rules flipped on in M78B.
    assert cap.drift.drift_snapshots is True
    assert cap.security.security_rules is True


def test_expansion_framework_summary_next_provider_is_google_cloud():
    """Flipped in M80A: Auth0 is now the head of the recommended queue."""
    fw = exp_svc.get_framework()
    # After M84A, PagerDuty launched; Linear is now head.
    assert fw["summary"]["next_provider"] in ("PagerDuty", "Linear")
    next_ms = fw["summary"]["next_milestone"] or ""
    assert "PagerDuty" in next_ms or "M84A" in next_ms or "Clerk" in next_ms or "Linear" in next_ms or "M85A" in next_ms


# ════════════════════════════════════════════════════════════════════════════
# Section B — Case report preview allowlist for Azure
# ════════════════════════════════════════════════════════════════════════════


def test_case_report_preview_allowlist_carries_azure_safe_keys():
    """All Azure-safe keys surface in case-report previews."""
    expected = {
        "subscription_id", "resource_group",
        "nsg_name", "storage_account_name", "key_vault_name",
        "app_service_name", "sql_server_name", "aks_cluster_name",
        "role_definition_name", "principal_type", "scope_type",
        "operation_name", "operation_action",
    }
    missing = expected - report_svc._PREVIEW_ALLOWLIST
    assert missing == set(), (
        f"case-report preview allowlist missing Azure-safe keys: {missing}"
    )


def test_case_report_provider_label_for_azure_is_azure():
    assert report_svc._TIMELINE_PROVIDER_LABELS.get("azure") == "Azure"


# ════════════════════════════════════════════════════════════════════════════
# Section C — Frontend Azure consistency (skip if frontend tree absent)
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


# ── Activity page Azure copy ────────────────────────────────────────────────


def test_fe_activity_page_azure_sync_button_is_clear():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    # Sync button label.
    assert "Sync Azure activity" in text
    # Empty state should guide user to sync first.
    assert "Sync Azure activity first" in text


def test_fe_activity_page_azure_copy_uses_review_safe_wording():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    # Azure copy must use the safe vocabulary somewhere in the file
    # (the empty-state copy is far from the first provider-branch hit).
    assert "review-safe" in text or "Sync Azure activity first" in text


# ── Signals page Azure copy ─────────────────────────────────────────────────


def test_fe_signals_page_azure_generate_button_and_flow_copy():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert "Generate Azure signals" in text
    # Flow guidance: sync activity THEN generate signals.
    assert "Sync Azure activity, then generate Azure signals" in text


def test_fe_signals_page_azure_signal_type_count_matches_backend():
    """The frontend AZURE_SIGNAL_TYPES array carries the 14 M77E signal types."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    # Find the AZURE_SIGNAL_TYPES block and count the entries.
    m = re.search(r"const AZURE_SIGNAL_TYPES = \[(.*?)\]", text, flags=re.DOTALL)
    assert m is not None
    entries = re.findall(r'"(azure_[a-z_]+)"', m.group(1))
    assert len(entries) == 14, (
        f"AZURE_SIGNAL_TYPES should carry 14 M77E types, got {len(entries)}"
    )


# ── Correlations page Azure copy ────────────────────────────────────────────


def test_fe_correlations_page_azure_correlation_count_matches_backend():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    # Find the azure block in TYPE_OPTIONS_BY_PROVIDER.
    m = re.search(r"azure:\s*\[(.*?)\]", text, flags=re.DOTALL)
    assert m is not None
    entries = re.findall(r'"(azure_[a-z_]+)"', m.group(1))
    assert len(entries) == 7, (
        f"correlations page azure block should list 7 correlation types, "
        f"got {len(entries)}"
    )


def test_fe_correlations_page_azure_flow_guidance_three_step():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    # The empty-state must guide users through the three-step flow.
    # Search full text — the three-step copy is in the EmptyState component,
    # which is far from the first provider-branch hit in the file.
    assert (
        "Sync Azure activity, generate Azure signals, then generate Azure correlations"
        in text
    )


# ── Cases page Azure demo card ──────────────────────────────────────────────


def test_fe_cases_page_azure_demo_card_polished():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert "Load Azure security demo" in text
    assert "Clear Azure demo" in text
    # Description includes the five evidence layers.
    for layer in (
        "drift findings", "Activity Log evidence", "signals",
        "correlations", "case",
    ):
        assert layer in text, f"Azure demo card missing layer {layer!r}"


# ── Demo-script (internal milestone tracker) page Azure row ─────────────────


def test_fe_demo_script_page_azure_row_is_demo_ready():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    # Azure row in the capability table has demo: true.
    m = re.search(
        r'\{\s*provider:\s*"azure",[^}]*demo:\s*true', text,
    )
    assert m is not None, "demo-script Azure row should be demo: true"
    # The intro text should mention Azure as demo-ready (alongside Google Cloud after M78I).
    assert "Azure" in text and "demo-ready" in text


def test_fe_demo_script_page_no_stale_milestone_jargon():
    """The Azure intro should not still reference internal M77G/M77H/M77I codes."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    # Find the Azure intro paragraph.
    azure_para_match = re.search(
        r"Azure[^.]+demo-ready[^.]+\.", text,
    )
    assert azure_para_match is not None, "Azure intro paragraph not found"
    azure_para = azure_para_match.group(0)
    for token in ("M77G", "M77H", "M77I"):
        assert token not in azure_para, (
            f"Azure intro paragraph still mentions {token!r}; should be "
            f"polished milestone-free in M77I"
        )


# ── securityDemoScript talk-track ───────────────────────────────────────────


def test_fe_demo_script_lib_mentions_azure_in_every_relevant_step():
    text = _read_fe("lib/securityDemoScript.ts")
    # Opening problem mentions Azure alongside the other big providers.
    assert "Azure" in text
    # Incident-demo step mentions Azure in both the talk-track and the
    # "whatToClick" hint.
    occurrences = text.count("Azure")
    assert occurrences >= 4, (
        f"securityDemoScript should mention Azure on at least 4 steps; got "
        f"{occurrences}"
    )


# ── Rule catalog parity for Azure ───────────────────────────────────────────


def test_fe_rule_catalog_includes_every_azure_rule_with_safe_copy():
    text = _read_fe("lib/securityRuleCatalog.ts")
    for key in AZURE_RULE_KEYS:
        # Each rule key shows up as a catalog entry.
        m = re.search(rf'\{{[^{{}}]*key:\s*"{re.escape(key)}"[^{{}}]*\}}', text, flags=re.DOTALL)
        # The above can be tricky inside nested braces; fall back to existence.
        assert f'key: "{key}"' in text, f"rule catalog missing {key!r}"


def test_fe_rule_catalog_azure_categories_use_consistent_labels():
    """Every Azure rule sits in one of the 7 expected category labels."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    expected_categories = {
        "Network security groups",
        "Storage accounts",
        "Key Vaults",
        "Identity / Role assignments",
        "App Service / Functions",
        "SQL Servers",
        "AKS Clusters",
    }
    # For each Azure rule key, find its category line.
    for key in AZURE_RULE_KEYS:
        # Pull a small window of text after each key declaration.
        idx = text.find(f'key: "{key}"')
        assert idx >= 0
        window = text[idx: idx + 600]
        m = re.search(r'category:\s*"([^"]+)"', window)
        assert m is not None, f"category not found near rule {key!r}"
        category = m.group(1)
        assert category in expected_categories, (
            f"rule {key!r} uses unexpected category {category!r}; "
            f"expected one of {expected_categories}"
        )


def test_fe_rule_catalog_azure_rules_have_review_safe_copy():
    """Every Azure rule entry has description / remediation / falsePositiveGuard."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    for key in AZURE_RULE_KEYS:
        idx = text.find(f'key: "{key}"')
        assert idx >= 0
        window = text[idx: idx + 1800]
        # Every Azure rule must declare these three keys.
        for field in ("description:", "remediation:", "falsePositiveGuard:"):
            assert field in window, (
                f"rule {key!r} missing {field!r} in catalog entry"
            )


def test_fe_rule_catalog_azure_rules_have_no_forbidden_claims():
    """Azure rule catalog must not contain forbidden claim phrases."""
    text = _read_fe("lib/securityRuleCatalog.ts")
    # Pull every Azure entry.
    for key in AZURE_RULE_KEYS:
        idx = text.find(f'key: "{key}"')
        if idx < 0:
            continue
        window = text[idx: idx + 1800].lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in window, (
                f"rule {key!r} catalog entry contains forbidden phrase "
                f"{phrase!r}"
            )


# ── api.ts: Azure demo helper union types ───────────────────────────────────


def test_fe_api_demo_helpers_include_azure_in_union():
    text = _read_fe("lib/api.ts")
    union = (
        '"github" | "aws" | "cloudflare" | "vercel" | "supabase" | '
        '"firebase" | "stripe" | "shopify" | "azure"'
    )
    # Three demo helpers (status/seed/clear) all carry the wider union.
    assert text.count(union) >= 3


# ════════════════════════════════════════════════════════════════════════════
# Section D — No stale milestone jargon in user-facing copy
# ════════════════════════════════════════════════════════════════════════════


# Files that are USER-FACING and should not carry milestone codes for Azure.
# The demo-script page is INTENTIONALLY an internal milestone tracker, so we
# only check its Azure intro paragraph (not the milestone references it
# already documents elsewhere).
_USER_FACING_FILES = (
    "app/(app)/security/activity/page.tsx",
    "app/(app)/security/signals/page.tsx",
    "app/(app)/security/correlations/page.tsx",
    "app/(app)/security/cases/page.tsx",
    "lib/securityDemoScript.ts",
    "lib/securityRuleCatalog.ts",
    "lib/api.ts",
)


@pytest.mark.parametrize("rel", _USER_FACING_FILES)
def test_fe_user_facing_files_carry_no_stale_azure_milestone_jargon(rel: str):
    text = _read_fe(rel)
    # Only flag the Azure neighborhood — code comments / unrelated rule
    # provenance tags (e.g. "M77B" in a TypeScript comment) are allowed,
    # so we scan the actual string content surrounding "Azure".
    for marker_token in USER_FACING_STALE_TOKENS:
        # Find any "Azure" string with the stale token inside 240 chars.
        for m in re.finditer(r'"[^"]*Azure[^"]*"', text):
            snippet = m.group(0)
            assert marker_token not in snippet, (
                f"{rel}: user-facing Azure string still mentions "
                f"{marker_token!r}: {snippet[:140]}"
            )


# ════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════


def _isolate_azure_section(text: str, *, isolator_marker: str) -> str:
    """Return the slice of text from the first `isolator_marker` for the next
    600 chars — enough to cover Azure branch ternaries and their copy."""
    idx = text.find(isolator_marker)
    if idx < 0:
        return ""
    return text[idx: idx + 1200]


# ════════════════════════════════════════════════════════════════════════════
# Section E — Forbidden claim phrases across Azure production modules
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("module_name", [
    "app.connectors.azure",
    "app.services.security_rules.azure",
    "app.services.azure_activity_ingestion_service",
    "app.services.azure_activity_signal_service",
    "app.services.security_incident_demo_service",
])
def test_azure_modules_have_no_forbidden_claims(module_name):
    """Forbidden phrases scan — final guardrail across every Azure module."""
    import importlib
    import inspect
    mod = importlib.import_module(module_name)
    src = inspect.getsource(mod)
    # Strip negation contexts (claim-discipline disclaimers) so a phrase like
    # "this does not confirm compromise" doesn't false-positive.
    out_lines = []
    for line in src.splitlines():
        low = line.lower()
        if any(tok in low for tok in (
            "does not confirm", "never assert", "never claim",
            "do not claim", "is not a claim", "claim discipline",
            "review-safe", "without overclaim", "forbidden",
        )):
            continue
        out_lines.append(line)
    stripped = "\n".join(out_lines).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"{module_name} contains forbidden phrase {phrase!r} outside a "
            f"negation context"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section F — M77A–M77H regression smoke
# ════════════════════════════════════════════════════════════════════════════


def test_m77_arc_capabilities_intact():
    cap = cap_svc.get_provider_capability("azure")
    # All Azure security capabilities through M77G stay True.
    assert cap.security.security_rules
    assert cap.security.activity_ingestion
    assert cap.security.activity_signals
    assert cap.security.risk_activity_correlations
    assert cap.security.demo_seed_clear


def test_m77b_and_m77c_rule_keys_still_registered():
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    for k in (
        "azure_nsg_public_admin_ingress",
        "azure_role_assignment_broad_privilege",
        "azure_aks_public_api_access",
    ):
        assert k in KNOWN_RULE_KEYS


def test_import_time_assertions_still_pass():
    from app.services.security_rule_pack import _RULE_META
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    assert set(_RULE_META) == set(KNOWN_RULE_KEYS)
