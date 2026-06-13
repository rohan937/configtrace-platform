"""M69.8B — Cross-provider security regression guardrails.

Durable, deterministic guardrails so future provider work cannot silently break
the security investigation spine. Two layers:

  1. Backend provider-matrix: every provider demo (GitHub / AWS / Cloudflare) must
     seed a case, build a report + timeline + graph, carry the correct provider
     label and review-only claim language, and clear without touching non-demo
     evidence — and none of those payloads may contain forbidden breach/compromise
     claim wording.

  2. Frontend source guardrails: the cross-provider security pages and demo script
     must keep their GitHub/AWS/Cloudflare copy and the timeline/relationship-map/
     report-export/clear-demo narrative. These read source files and gracefully
     skip when the frontend tree is not mounted (e.g. backend-only CI container).

This file adds NO product code — it is a regression net only.
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

import pytest

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_case import SecurityCase
from app.models.security_finding import SecurityFinding
from app.models.user import User
from app.services import security_case_report_service as report_svc
from app.services import security_finding_service as finding_svc
from app.services import security_incident_demo_service as demo
from app.services import workspace_service

# ── Forbidden claim wording (exact phrases) ──────────────────────────────────
FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "token leaked",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
]

# ── Provider capability matrix (test-local; update when a provider is added) ─
EXPECTED_SURFACES = {
    "risks", "activity", "signals", "correlations", "cases", "reports",
    "timeline", "graph", "demo_seed", "demo_clear",
}
CAPABILITY_MATRIX = {
    "github": set(EXPECTED_SURFACES),
    "aws": set(EXPECTED_SURFACES),
    "cloudflare": set(EXPECTED_SURFACES),
}

# (provider, seed fn, clear fn, demo case source marker, expected label)
_PROVIDERS = [
    ("github", demo.seed, demo.clear, demo.DEMO_CASE_SOURCE, "GitHub"),
    ("aws", demo.seed_aws, demo.clear_aws, demo.AWS_DEMO_CASE_SOURCE, "AWS"),
    ("cloudflare", demo.seed_cloudflare, demo.clear_cloudflare,
     demo.CF_DEMO_CASE_SOURCE, "Cloudflare"),
]


# ── helpers ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.8B", db=db)


def _demo_case(db, ws_id, source):
    return db.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws_id,
        SecurityCase.case_metadata["source"].astext == source,
    ).first()


def _assert_no_forbidden(payload, where):
    low = json.dumps(payload, default=str).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, f"forbidden phrase {phrase!r} in {where}"


def _frontend_src() -> Path | None:
    """Locate <repo>/frontend/src by walking up from this test file. None if absent."""
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "frontend" / "src"
        if candidate.is_dir():
            return candidate
    return None


# ════════════════════════════════════════════════════════════════════════════
# Layer 1 — backend provider matrix
# ════════════════════════════════════════════════════════════════════════════

def test_capability_matrix_is_complete_and_backed():
    """Every expected provider declares every expected surface, and the demo_seed/
    demo_clear surfaces map to real callables (so the matrix stays honest)."""
    assert set(CAPABILITY_MATRIX) == {"github", "aws", "cloudflare"}
    for provider, surfaces in CAPABILITY_MATRIX.items():
        assert surfaces == EXPECTED_SURFACES, f"{provider} surface set drifted"
    # demo_seed / demo_clear are real and callable for each provider.
    for provider, seed_fn, clear_fn, _src, _label in _PROVIDERS:
        assert callable(seed_fn), f"{provider} seed not callable"
        assert callable(clear_fn), f"{provider} clear not callable"


@pytest.mark.parametrize("provider,seed_fn,clear_fn,source,label", _PROVIDERS)
def test_demo_seeds_case(provider, seed_fn, clear_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert res.get("seeded") or res.get("created") or res.get("case_id")
        case = _demo_case(db_session, ws.id, source)
        assert case is not None, f"{provider} demo case missing"
        assert (case.provider or "").lower() == provider
    finally:
        clear_fn(workspace_id=ws.id, db=db_session)


@pytest.mark.parametrize("provider,seed_fn,clear_fn,source,label", _PROVIDERS)
def test_report_timeline_graph_build_with_label_and_claim(
        provider, seed_fn, clear_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = _demo_case(db_session, ws.id, source)

        # Report builds, carries provider label + review-only claim note.
        rep = report_svc.build_case_report(case=case, db=db_session)
        assert label in rep["executive_summary"]
        assert "evidence for review" in rep["claim_note"].lower()
        assert "does not automatically confirm" in rep["claim_note"].lower()
        for key in ("evidence_timeline", "evidence_graph", "timeline",
                    "signals", "risks", "activity_events", "correlations",
                    "review_checklist", "limitations"):
            assert key in rep, f"{provider} report missing {key}"

        # Timeline builds with the four evidence kinds the demos seed.
        tl = report_svc.build_case_evidence_timeline(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        assert tl["provider"] == label
        assert tl["total"] >= 1
        cbt = tl["counts_by_type"]
        for kind in ("finding", "activity_event", "incident_signal", "correlation"):
            assert cbt.get(kind, 0) >= 1, f"{provider} timeline missing {kind}"
        ts = [it["timestamp"] for it in tl["timeline_items"] if it["timestamp"]]
        assert ts == sorted(ts), f"{provider} timeline not chronological"

        # Graph builds with a case node + case_contains edges to evidence.
        g = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        assert g["counts_by_node_type"].get("case", 0) == 1
        assert len(g["nodes"]) >= 2
        assert g["counts_by_edge_type"].get("case_contains", 0) >= 1
        node_ids = {n["id"] for n in g["nodes"]}
        for e in g["edges"]:
            assert e["source_node_id"] in node_ids and e["target_node_id"] in node_ids
        assert g["counts_by_provider"].get(provider, 0) >= 1
    finally:
        clear_fn(workspace_id=ws.id, db=db_session)


@pytest.mark.parametrize("provider,seed_fn,clear_fn,source,label", _PROVIDERS)
def test_no_forbidden_wording_in_outputs(
        provider, seed_fn, clear_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = _demo_case(db_session, ws.id, source)
        rep = report_svc.build_case_report(case=case, db=db_session)
        tl = report_svc.build_case_evidence_timeline(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        g = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        _assert_no_forbidden(rep, f"{provider} report")
        _assert_no_forbidden(tl, f"{provider} timeline")
        _assert_no_forbidden(g, f"{provider} graph")
    finally:
        clear_fn(workspace_id=ws.id, db=db_session)


@pytest.mark.parametrize("provider,seed_fn,clear_fn,source,label", _PROVIDERS)
def test_clear_removes_demo_preserves_non_demo(
        provider, seed_fn, clear_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
    # A real (non-demo) finding that must survive a demo clear.
    ct, iv = encrypt_credentials({"github_token": "x", "repo_owner": "real", "repo_name": "repo"})
    integ = Integration(user_id=test_user.id, workspace_id=ws.id, provider="github",
                        display_name="real", encrypted_credentials=ct,
                        credential_iv=iv, status="active")
    db_session.add(integ); db_session.commit(); db_session.refresh(integ)
    res = Resource(integration_id=integ.id, user_id=test_user.id,
                   provider_resource_type="github_repo", provider_resource_id="real/repo",
                   display_name="real/repo", is_active=True)
    db_session.add(res); db_session.commit(); db_session.refresh(res)
    real = finding_svc.upsert_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key=f"github_webhook_http:real/repo#{provider}", severity="high",
        title="Real webhook risk", resource_id=res.id, description="d",
        evidence={"rule": "github_webhook_http"}, remediation={"summary": "fix"})
    real_id = real.id
    try:
        seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert _demo_case(db_session, ws.id, source) is not None
        clear_fn(workspace_id=ws.id, db=db_session)
        assert _demo_case(db_session, ws.id, source) is None
        assert db_session.query(SecurityFinding).filter(
            SecurityFinding.id == real_id).first() is not None
    finally:
        try:
            clear_fn(workspace_id=ws.id, db=db_session)
        except Exception:
            db_session.rollback()
        db_session.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws.id).delete(synchronize_session=False)
        db_session.query(Resource).filter(Resource.integration_id == integ.id).delete(synchronize_session=False)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()


# ════════════════════════════════════════════════════════════════════════════
# Layer 2 — frontend source guardrails (skip when frontend tree is absent)
# ════════════════════════════════════════════════════════════════════════════

_SEC = "app/(app)/security"


def _read_fe(rel: str) -> str:
    src = _frontend_src()
    if src is None:
        pytest.skip("frontend/src not mounted in this environment")
    path = src / rel
    if not path.is_file():
        pytest.skip(f"frontend file not found: {rel}")
    return path.read_text(encoding="utf-8")


def test_fe_activity_mentions_all_three_providers():
    text = _read_fe(f"{_SEC}/activity/page.tsx")
    for token in ("GitHub", "AWS", "Cloudflare"):
        assert token in text, f"activity page missing {token}"


def test_fe_signals_has_all_three_provider_labels():
    text = _read_fe(f"{_SEC}/signals/page.tsx")
    for token in ("GitHub", "AWS", "Cloudflare"):
        assert token in text, f"signals page missing {token}"
    # Provider-specific generate copy exists for all three.
    assert "Cloudflare" in text and "AWS Incident Signals" in text


def test_fe_correlations_has_provider_specific_scope_copy():
    text = _read_fe(f"{_SEC}/correlations/page.tsx")
    assert "the same GitHub repository" in text
    assert "the same AWS resource" in text
    assert "the same Cloudflare zone" in text


def test_fe_cases_is_not_github_only():
    text = _read_fe(f"{_SEC}/cases/page.tsx")
    # The stale single-provider banner must be gone.
    assert ">GitHub beta<" not in text
    assert "GitHub · AWS · Cloudflare beta" in text


def test_fe_demo_script_covers_timeline_graph_export_clear():
    text = _read_fe("lib/securityDemoScript.ts")
    assert "relationship map" in text.lower()
    assert "chronological evidence timeline" in text.lower()
    assert "Case Evidence Report" in text
    assert "Clear demo data" in text


def test_fe_demo_script_forbidden_only_in_allowed_contexts():
    """Forbidden phrases may appear only in negated narration, 'avoid:' guidance,
    or the explicit blocklist constant — never as a customer-facing claim."""
    text = _read_fe("lib/securityDemoScript.ts")
    allowed_markers = ("avoid", "never", "not ", "n't", "forbidden", "don't")
    for phrase in FORBIDDEN_PHRASES:
        for line in text.splitlines():
            if phrase not in line.lower():
                continue
            low = line.lower()
            is_blocklist_entry = re.match(r'^\s*"[^"]+",?\s*$', line) is not None
            assert is_blocklist_entry or any(m in low for m in allowed_markers), (
                f"forbidden phrase {phrase!r} used as a claim: {line.strip()!r}")
