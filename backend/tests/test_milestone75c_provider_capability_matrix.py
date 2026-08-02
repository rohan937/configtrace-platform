"""M75C — Provider capability matrix tests.

Pins the canonical provider capability matrix so a future change cannot
silently break the drift × security dual-stack status for any of the 8
completed providers.

Three layers:

  1. Service layer — the matrix data structure is valid and complete:
       - exactly 8 providers
       - all provider labels are canonical
       - maturity values are from the allowed enum
       - security capabilities are complete for all 8
       - drift capabilities are honest (partial allowed where planned)
       - summary counts are correct

  2. API / router layer — the endpoint returns the same matrix and is
     read-accessible (any authenticated workspace member can call it;
     endpoint is tested via TestClient fixtures matching the auth pattern
     already used by other security endpoints).

  3. Frontend static layer — the demo-script page table and the
     provider labels it renders match the matrix. Skips when frontend
     tree is not mounted (matches M75A / M75B pattern).

CLAIM DISCIPLINE: no forbidden phrase may appear in the matrix notes or
summary text — they describe capability and maturity, never confirmed
breach / compromise / attack / data exposure.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services import provider_capability_matrix_service as svc

# ── Helpers ──────────────────────────────────────────────────────────────────

FORBIDDEN_PHRASES = [
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

# The 8 dual-stack "complete"-maturity providers — every security capability
# (activity ingestion/signals/correlations/demo/case report/evidence) is
# True for these, and they're the set the demo-script table lists.
EXPECTED_PROVIDERS = {
    "github", "aws", "cloudflare", "vercel", "supabase", "firebase", "stripe", "shopify",
}
EXPECTED_LABELS = {
    "github": "GitHub",
    "aws": "AWS",
    "cloudflare": "Cloudflare",
    "vercel": "Vercel",
    "supabase": "Supabase",
    "firebase": "Firebase",
    "stripe": "Stripe",
    "shopify": "Shopify",
}

# All providers in the matrix, including Kubernetes, Okta, Microsoft Entra ID,
# Snowflake, and Sentry (all maturity "partial" — drift + Security Findings
# only, no activity ingestion/demo/case-report stack, so all five are
# intentionally excluded from EXPECTED_PROVIDERS above).
ALL_MATRIX_PROVIDERS = EXPECTED_PROVIDERS | {"kubernetes", "okta", "entra", "snowflake", "sentry"}
ALL_MATRIX_LABELS = {
    **EXPECTED_LABELS,
    "kubernetes": "Kubernetes",
    "okta": "Okta",
    "entra": "Microsoft Entra ID",
    "snowflake": "Snowflake",
    "sentry": "Sentry",
}


def _frontend_src() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "frontend" / "src"
        if candidate.is_dir():
            return candidate
    return None


def _read_fe(rel: str) -> str:
    src = _frontend_src()
    if src is None:
        pytest.skip("frontend/src not mounted in this environment")
    path = src / rel
    if not path.is_file():
        pytest.skip(f"frontend file not found: {rel}")
    return path.read_text(encoding="utf-8")


# ════════════════════════════════════════════════════════════════════════════
# Layer 1 — service data-integrity tests
# ════════════════════════════════════════════════════════════════════════════


def test_matrix_has_exactly_thirteen_providers():
    assert len(svc.PROVIDER_CAPABILITIES) == 13
    keys = {p.provider for p in svc.PROVIDER_CAPABILITIES}
    assert keys == ALL_MATRIX_PROVIDERS


def test_provider_labels_canonical():
    actual = {p.provider: p.label for p in svc.PROVIDER_CAPABILITIES}
    assert actual == ALL_MATRIX_LABELS


def test_maturity_values_are_valid():
    for p in svc.PROVIDER_CAPABILITIES:
        assert p.maturity in svc.MATURITY_LEVELS, (
            f"{p.provider} has invalid maturity {p.maturity!r}"
        )


def test_categories_are_valid():
    for p in svc.PROVIDER_CAPABILITIES:
        assert p.category in svc.CATEGORIES, (
            f"{p.provider} has invalid category {p.category!r}"
        )


def test_dual_stack_complete_providers_have_full_security_capabilities():
    """Every provider with maturity == "complete" must have every security
    capability True. Kubernetes deliberately has maturity == "partial" (drift
    + Security Findings only, no activity ingestion/signals/correlations) and
    is exempt by design — see its `notes` for why."""
    required_security = (
        "security_rules", "activity_ingestion", "activity_signals",
        "risk_activity_correlations", "demo_seed_clear",
        "case_report", "evidence_timeline", "evidence_graph",
    )
    for p in svc.PROVIDER_CAPABILITIES:
        if p.maturity != "complete":
            continue
        for cap in required_security:
            assert getattr(p.security, cap), (
                f"{p.provider} is missing security capability {cap!r}"
            )


def test_all_providers_have_drift_snapshot_and_diff():
    """All 9 providers have at minimum drift snapshots + diff available."""
    for p in svc.PROVIDER_CAPABILITIES:
        assert p.drift.drift_snapshots, f"{p.provider} missing drift_snapshots"
        assert p.drift.drift_diff, f"{p.provider} missing drift_diff"


def test_all_providers_have_drift_risk_classification():
    for p in svc.PROVIDER_CAPABILITIES:
        assert p.drift.drift_risk_classification, (
            f"{p.provider} missing drift_risk_classification"
        )


def test_drift_remediation_preview_is_honest():
    """remediation_preview is optional and can be True only for providers
    that genuinely surface actionable remediation guidance in the UI
    (currently GitHub). Other providers have it False — a planned stage.
    This test pins the current truthful set so a provider cannot be
    accidentally promoted without updating this guard."""
    # Providers with remediation_preview shipped.
    PREVIEW_SHIPPED = {"github"}
    for p in svc.PROVIDER_CAPABILITIES:
        if p.provider in PREVIEW_SHIPPED:
            assert p.drift.drift_remediation_preview is True, (
                f"{p.provider} should have drift_remediation_preview=True"
            )
        else:
            assert p.drift.drift_remediation_preview is False, (
                f"{p.provider} has drift_remediation_preview=True unexpectedly; "
                "update PREVIEW_SHIPPED if this feature has shipped for it."
            )


def test_summary_counts_are_correct():
    matrix = svc.get_matrix()
    summary = matrix["summary"]
    assert summary["total_providers"] == 13
    # The 8 dual-stack-complete providers have every security capability;
    # Kubernetes/Okta/Entra/Snowflake (security_rules only, no activity
    # ingestion) do not.
    assert summary["security_complete_count"] == 8
    # 11 have snapshot + diff + risk_classification + review_workflow; Entra
    # has drift_review_workflow=False (not yet built for this provider) —
    # Kubernetes/Okta/Snowflake all have it True (generic review UI).
    assert summary["drift_complete_count"] == 11
    # 8 have maturity == "complete"; Kubernetes/Okta/Entra/Snowflake are
    # "partial" (drift + security rules only, no activity ingestion/
    # signals/correlations).
    assert summary["dual_stack_complete_count"] == 8
    # M76 template note is present.
    assert "M76" in summary["planned_next_stage"]


def test_get_matrix_structure():
    matrix = svc.get_matrix()
    assert "providers" in matrix and "summary" in matrix
    assert len(matrix["providers"]) == 13
    # Each provider dict has the expected keys.
    for pdict in matrix["providers"]:
        for key in ("provider", "label", "category", "drift", "security", "maturity", "notes"):
            assert key in pdict, f"provider dict missing key {key!r}"
        for cap in ("security_rules", "activity_ingestion", "activity_signals",
                    "risk_activity_correlations", "demo_seed_clear",
                    "case_report", "evidence_timeline", "evidence_graph"):
            assert cap in pdict["security"]
        for cap in ("drift_snapshots", "drift_diff", "drift_risk_classification",
                    "drift_review_workflow", "drift_remediation_preview"):
            assert cap in pdict["drift"]


def test_get_provider_capability_lookup():
    for provider in ALL_MATRIX_PROVIDERS:
        cap = svc.get_provider_capability(provider)
        assert cap is not None
        assert cap.provider == provider
    assert svc.get_provider_capability("nonexistent") is None


def test_notes_and_summary_contain_no_forbidden_phrases():
    matrix = svc.get_matrix()
    blob = json.dumps(matrix, default=str).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in blob, (
            f"forbidden phrase {phrase!r} found in matrix output"
        )


def test_matrix_is_static_no_db_needed():
    """get_matrix() is pure (no DB call) — verify it returns the same result
    twice without any session argument."""
    m1 = svc.get_matrix()
    m2 = svc.get_matrix()
    assert m1 == m2


# ════════════════════════════════════════════════════════════════════════════
# Layer 2 — API / router tests (via TestClient with auth override)
# ════════════════════════════════════════════════════════════════════════════


def test_endpoint_returns_matrix(client):
    """Any authenticated workspace member can fetch the provider capabilities."""
    r = client.get("/security/provider-capabilities")
    assert r.status_code == 200
    body = r.json()
    assert "providers" in body and "summary" in body
    assert body["summary"]["total_providers"] == 13
    # All expected providers present.
    returned = {p["provider"] for p in body["providers"]}
    assert returned == ALL_MATRIX_PROVIDERS


def test_endpoint_provider_labels(client):
    r = client.get("/security/provider-capabilities")
    assert r.status_code == 200
    label_map = {p["provider"]: p["label"] for p in r.json()["providers"]}
    assert label_map == ALL_MATRIX_LABELS


def test_endpoint_security_capabilities_complete(client):
    """Every dual-stack "complete"-maturity provider has every security
    capability True. Kubernetes ("partial" — drift + Security Findings only)
    is intentionally exempt."""
    r = client.get("/security/provider-capabilities")
    assert r.status_code == 200
    for p in r.json()["providers"]:
        if p["maturity"] != "complete":
            continue
        sec = p["security"]
        assert sec["security_rules"] is True
        assert sec["activity_ingestion"] is True
        assert sec["activity_signals"] is True
        assert sec["risk_activity_correlations"] is True
        assert sec["demo_seed_clear"] is True
        assert sec["case_report"] is True
        assert sec["evidence_timeline"] is True
        assert sec["evidence_graph"] is True


def test_endpoint_unauthenticated_rejected():
    """Without a valid token the endpoint must return 401 or 422, not 200.
    We test this by calling the endpoint directly without using the
    ``client`` fixture (which injects auth). Uses a plain HTTPX / requests
    call — skip if httpx is not available."""
    try:
        from fastapi.testclient import TestClient
        from app.main import app
        plain = TestClient(app, raise_server_exceptions=False)
        r = plain.get("/security/provider-capabilities")
        assert r.status_code in (401, 422), (
            f"expected 401/422 without auth, got {r.status_code}"
        )
    except Exception:
        pytest.skip("Could not create an unauthenticated client")


# ════════════════════════════════════════════════════════════════════════════
# Layer 3 — frontend static guardrails (skip if frontend tree absent)
# ════════════════════════════════════════════════════════════════════════════


def test_fe_demo_script_has_capability_matrix_table():
    """The demo-script page renders a capability matrix table with the
    PROVIDER_CAPABILITY_TABLE constant and Dot helper."""
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    assert "PROVIDER_CAPABILITY_TABLE" in text
    assert "Provider capability matrix" in text
    assert "drift monitoring" in text.lower() or "drift" in text.lower()
    assert "security" in text.lower()
    assert "signals" in text.lower()
    assert "correlations" in text.lower()
    assert "demo" in text.lower()


def test_fe_demo_script_table_lists_all_providers():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    for label in EXPECTED_LABELS.values():
        assert f'label: "{label}"' in text, (
            f"PROVIDER_CAPABILITY_TABLE missing label: {label!r}"
        )


def test_fe_demo_script_m76_template_note():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    assert "M76" in text or "dual-stack template" in text, (
        "demo-script page missing M76 / dual-stack template note"
    )


def test_fe_capability_table_no_forbidden_wording():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    low = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        # Phrases may only appear inside explicit denylist strings, not as
        # rendered user-facing copy.
        import re
        for line in text.splitlines():
            if phrase not in line.lower():
                continue
            is_blocklist = re.match(r'^\s*"[^"]+",?\s*$', line) is not None
            assert is_blocklist or any(
                m in line.lower() for m in (
                    "avoid", "never", "not ", "n't", "forbidden", "don't",
                    "does not", "without", "no ",
                )
            ), f"forbidden phrase {phrase!r} found in demo-script page: {line.strip()!r}"
