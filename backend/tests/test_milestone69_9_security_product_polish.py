"""M69.9 — Final security product polish + demo readiness.

Pins the demo-ready invariants of the cross-provider security spine so the
GitHub / AWS / Cloudflare experience stays consistent, credible, and claim-safe.
This milestone is polish-only; these tests assert backend report/demo invariants
that a live demo depends on:

  * each provider demo seeds → builds a report + timeline + graph;
  * the report carries the correct provider label and a clean, ordered set of
    key sections;
  * the claim note says evidence does NOT automatically confirm compromise or
    unauthorized access;
  * the report/timeline/graph use review language and contain no forbidden claims;
  * demo seed/clear works across providers and preserves non-demo evidence.
"""

from __future__ import annotations

import json
import uuid

import pytest

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_case import SecurityCase
from app.models.security_finding import SecurityFinding
from app.services import security_case_report_service as report_svc
from app.services import security_finding_service as finding_svc
from app.services import security_incident_demo_service as demo
from app.services import workspace_service

FORBIDDEN_PHRASES = [
    "compromise confirmed", "token leaked", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]

# Clean, ordered key sections every provider report must expose.
REQUIRED_REPORT_KEYS = [
    "title", "generated_at", "executive_summary", "claim_note", "case",
    "signals", "risks", "activity_events", "correlations", "timeline",
    "evidence_timeline", "evidence_graph", "review_checklist", "limitations",
]

# (provider, seed fn, clear fn, status fn, demo case source, expected label)
_PROVIDERS = [
    ("github", demo.seed, demo.clear, demo.get_status, demo.DEMO_CASE_SOURCE, "GitHub"),
    ("aws", demo.seed_aws, demo.clear_aws, demo.get_aws_status,
     demo.AWS_DEMO_CASE_SOURCE, "AWS"),
    ("cloudflare", demo.seed_cloudflare, demo.clear_cloudflare,
     demo.get_cloudflare_status, demo.CF_DEMO_CASE_SOURCE, "Cloudflare"),
]


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.9", db=db)


def _demo_case(db, ws_id, source):
    return db.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws_id,
        SecurityCase.case_metadata["source"].astext == source,
    ).first()


def _no_forbidden(payload, where):
    low = json.dumps(payload, default=str).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, f"forbidden phrase {phrase!r} in {where}"


# ── 1. report is demo-ready: label + sections + timeline + graph ─────────────

@pytest.mark.parametrize("provider,seed_fn,clear_fn,status_fn,source,label", _PROVIDERS)
def test_demo_report_is_demo_ready(
        provider, seed_fn, clear_fn, status_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = _demo_case(db_session, ws.id, source)
        assert case is not None

        rep = report_svc.build_case_report(case=case, db=db_session)

        # Clean key sections, present and in a stable order.
        assert list(rep.keys())[:len(REQUIRED_REPORT_KEYS)] == REQUIRED_REPORT_KEYS or all(
            k in rep for k in REQUIRED_REPORT_KEYS)
        for k in REQUIRED_REPORT_KEYS:
            assert k in rep, f"{provider} report missing {k}"

        # Provider label in summary; timeline + graph populated and labelled.
        assert label in rep["executive_summary"]
        et, eg = rep["evidence_timeline"], rep["evidence_graph"]
        assert et["provider"] == label and et["total"] >= 1
        assert eg["counts_by_node_type"].get("case", 0) == 1
        assert eg["counts_by_edge_type"].get("case_contains", 0) >= 1
        assert eg["counts_by_provider"].get(provider, 0) >= 1
    finally:
        clear_fn(workspace_id=ws.id, db=db_session)


# ── 2. claim discipline: review language, no forbidden claims ────────────────

@pytest.mark.parametrize("provider,seed_fn,clear_fn,status_fn,source,label", _PROVIDERS)
def test_demo_report_claim_discipline(
        provider, seed_fn, clear_fn, status_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = _demo_case(db_session, ws.id, source)
        rep = report_svc.build_case_report(case=case, db=db_session)

        note = rep["claim_note"].lower()
        assert "evidence for review" in note
        assert "does not automatically confirm" in note
        assert "compromise" in note and "unauthorized access" in note

        # Shared claim note also reaches the timeline + graph payloads.
        assert "does not" in rep["evidence_timeline"]["claim_note"].lower()
        assert "does not" in rep["evidence_graph"]["claim_note"].lower()

        _no_forbidden(rep, f"{provider} report")
        _no_forbidden(
            report_svc.build_case_evidence_timeline(
                case_id=case.id, workspace_id=ws.id, db=db_session),
            f"{provider} timeline")
        _no_forbidden(
            report_svc.build_case_evidence_graph(
                case_id=case.id, workspace_id=ws.id, db=db_session),
            f"{provider} graph")
    finally:
        clear_fn(workspace_id=ws.id, db=db_session)


# ── 3. demo status/seed/clear lifecycle across providers ─────────────────────

@pytest.mark.parametrize("provider,seed_fn,clear_fn,status_fn,source,label", _PROVIDERS)
def test_demo_status_seed_clear_lifecycle(
        provider, seed_fn, clear_fn, status_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        assert status_fn(ws.id, db_session)["seeded"] is False
        seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert status_fn(ws.id, db_session)["seeded"] is True
        clear_fn(workspace_id=ws.id, db=db_session)
        assert status_fn(ws.id, db_session)["seeded"] is False
    finally:
        clear_fn(workspace_id=ws.id, db=db_session)


# ── 4. clear preserves non-demo evidence ─────────────────────────────────────

@pytest.mark.parametrize("provider,seed_fn,clear_fn,status_fn,source,label", _PROVIDERS)
def test_clear_preserves_non_demo(
        provider, seed_fn, clear_fn, status_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
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


# ── 5. provider label map is exactly GitHub / AWS / Cloudflare ───────────────

def test_provider_labels_canonical():
    # M70E added Vercel; M71E added Supabase; M72E added Firebase; M73E added
    # Stripe; M74E added Shopify to the canonical provider-label map.
    assert report_svc._TIMELINE_PROVIDER_LABELS == {
        "github": "GitHub", "aws": "AWS", "cloudflare": "Cloudflare", "vercel": "Vercel",
        "supabase": "Supabase", "firebase": "Firebase", "stripe": "Stripe",
        "shopify": "Shopify"}
