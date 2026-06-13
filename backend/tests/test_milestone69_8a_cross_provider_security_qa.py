"""M69.8A — Cross-provider security QA hardening.

The security evidence experience must feel consistent and credible across GitHub,
AWS, and Cloudflare. Each provider's incident demo seeds a coherent case whose
evidence report, chronological timeline, and relationship graph all render with
the correct provider label and review-only language — and never with breach /
compromise claims. Clearing one provider's demo preserves unrelated evidence.

These tests are provider-parametrized so the three arcs stay in lockstep.
"""

from __future__ import annotations

import json
import uuid

import pytest

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.services import security_case_report_service as report_svc
from app.services import security_case_service as case_svc
from app.services import security_finding_service as finding_svc
from app.services import security_incident_demo_service as demo
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "token leaked", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]

# (provider, seed fn, clear fn, demo case source marker, expected label)
_PROVIDERS = [
    ("github", demo.seed, demo.clear, demo.DEMO_CASE_SOURCE, "GitHub"),
    ("aws", demo.seed_aws, demo.clear_aws, demo.AWS_DEMO_CASE_SOURCE, "AWS"),
    ("cloudflare", demo.seed_cloudflare, demo.clear_cloudflare,
     demo.CF_DEMO_CASE_SOURCE, "Cloudflare"),
]


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.8A", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _demo_case(db, ws_id, source):
    return db.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws_id,
        SecurityCase.case_metadata["source"].astext == source,
    ).first()


# ── 1. each provider demo case report carries timeline + graph + label ───────

@pytest.mark.parametrize("provider,seed_fn,clear_fn,source,label", _PROVIDERS)
def test_demo_report_has_timeline_graph_and_label(
    provider, seed_fn, clear_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = _demo_case(db_session, ws.id, source)
        assert case is not None, f"{provider} demo case not seeded"

        rep = report_svc.build_case_report(case=case, db=db_session)

        # Report embeds both the M69.7A timeline and the M69.7B graph.
        et = rep["evidence_timeline"]
        eg = rep["evidence_graph"]
        assert et is not None and et["total"] >= 1
        assert eg is not None and len(eg["nodes"]) >= 2  # case + >=1 evidence node
        assert eg["counts_by_edge_type"].get("case_contains", 0) >= 1

        # Provider label present in the executive summary.
        assert label in rep["executive_summary"]
        # Timeline + graph report dominant provider correctly.
        assert et["provider"] == label
        assert eg["counts_by_provider"].get(provider, 0) >= 1
    finally:
        clear_fn(workspace_id=ws.id, db=db_session)


# ── 2. review language present, forbidden claims absent ──────────────────────

@pytest.mark.parametrize("provider,seed_fn,clear_fn,source,label", _PROVIDERS)
def test_demo_report_review_language_no_forbidden_claims(
    provider, seed_fn, clear_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = _demo_case(db_session, ws.id, source)
        rep = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(rep, default=str)
        low = blob.lower()

        for phrase in _FORBIDDEN:
            assert phrase not in low, f"forbidden phrase {phrase!r} in {provider} report"

        # Review-only claim discipline.
        assert "evidence for review" in low
        assert "does not" in low and "confirm" in low
        assert "does not automatically confirm" in et_claim(rep).lower()
    finally:
        clear_fn(workspace_id=ws.id, db=db_session)


def et_claim(rep):
    # Both timeline and graph carry the shared claim note.
    return rep["evidence_graph"]["claim_note"]


# ── 3. standalone timeline + graph builders work per provider ────────────────

@pytest.mark.parametrize("provider,seed_fn,clear_fn,source,label", _PROVIDERS)
def test_demo_timeline_and_graph_builders(
    provider, seed_fn, clear_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = _demo_case(db_session, ws.id, source)

        tl = report_svc.build_case_evidence_timeline(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        assert tl["case_id"] == str(case.id)
        assert tl["total"] >= 1
        assert tl["provider"] == label
        # Items are chronologically non-decreasing on present timestamps.
        ts = [it["timestamp"] for it in tl["timeline_items"] if it["timestamp"]]
        assert ts == sorted(ts)

        g = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        assert g["case_id"] == str(case.id)
        node_types = {n["node_type"] for n in g["nodes"]}
        assert "case" in node_types
        # Every edge connects two real nodes.
        node_ids = {n["id"] for n in g["nodes"]}
        for e in g["edges"]:
            assert e["source_node_id"] in node_ids
            assert e["target_node_id"] in node_ids
        # Graph blob carries no forbidden claims.
        low = json.dumps(g, default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in low
    finally:
        clear_fn(workspace_id=ws.id, db=db_session)


# ── 4. provider label maps are exactly GitHub / AWS / Cloudflare ─────────────

def test_provider_label_maps_are_consistent():
    assert report_svc._TIMELINE_PROVIDER_LABELS == {
        "github": "GitHub", "aws": "AWS", "cloudflare": "Cloudflare"}
    # _provider_label resolves each known provider to the canonical label.
    assert report_svc._provider_label("github") == "GitHub"
    assert report_svc._provider_label("aws") == "AWS"
    assert report_svc._provider_label("cloudflare") == "Cloudflare"


# ── 5. report export payload keys present for every provider ─────────────────

@pytest.mark.parametrize("provider,seed_fn,clear_fn,source,label", _PROVIDERS)
def test_report_payload_keys(
    provider, seed_fn, clear_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = _demo_case(db_session, ws.id, source)
        rep = report_svc.build_case_report(case=case, db=db_session)
        for key in ("executive_summary", "claim_note", "signals", "risks",
                    "activity_events", "correlations", "timeline",
                    "evidence_timeline", "evidence_graph", "review_checklist",
                    "limitations"):
            assert key in rep, f"{key} missing from {provider} report"
    finally:
        clear_fn(workspace_id=ws.id, db=db_session)


# ── 6. clear preserves unrelated (non-demo) evidence ─────────────────────────

@pytest.mark.parametrize("provider,seed_fn,clear_fn,source,label", _PROVIDERS)
def test_clear_preserves_non_demo_evidence(
    provider, seed_fn, clear_fn, source, label, test_user, db_session):
    ws = _ws(test_user, db_session)
    # A real (non-demo) finding that must survive a demo clear.
    ct, iv = encrypt_credentials({"github_token": "x", "repo_owner": "real", "repo_name": "repo"})
    real_integ = Integration(user_id=test_user.id, workspace_id=ws.id, provider="github",
                             display_name="real", encrypted_credentials=ct,
                             credential_iv=iv, status="active")
    db_session.add(real_integ); db_session.commit(); db_session.refresh(real_integ)
    real_res = Resource(integration_id=real_integ.id, user_id=test_user.id,
                        provider_resource_type="github_repo", provider_resource_id="real/repo",
                        display_name="real/repo", is_active=True)
    db_session.add(real_res); db_session.commit(); db_session.refresh(real_res)
    real_finding = finding_svc.upsert_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=real_integ.id, provider="github",
        finding_key=f"github_webhook_http:real/repo#{provider}", severity="high",
        title="Real webhook risk", resource_id=real_res.id, description="d",
        evidence={"rule": "github_webhook_http"}, remediation={"summary": "fix"})
    real_fid = real_finding.id
    try:
        seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        clear_fn(workspace_id=ws.id, db=db_session)

        # Demo case gone; the real finding survives.
        assert _demo_case(db_session, ws.id, source) is None
        assert db_session.query(SecurityFinding).filter(
            SecurityFinding.id == real_fid).first() is not None
    finally:
        try:
            clear_fn(workspace_id=ws.id, db=db_session)
        except Exception:
            db_session.rollback()
        db_session.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws.id).delete(synchronize_session=False)
        db_session.query(Resource).filter(Resource.integration_id == real_integ.id).delete(synchronize_session=False)
        db_session.query(Integration).filter(Integration.id == real_integ.id).delete(synchronize_session=False)
        db_session.commit()
