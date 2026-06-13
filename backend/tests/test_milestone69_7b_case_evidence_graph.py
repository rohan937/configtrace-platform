"""M69.7B — Cross-provider evidence relationship graph foundation.

A case can render a computed relationship graph that connects its linked evidence
objects using EXPLICIT foreign keys only (the linked_*_id columns on correlations
and signals). It is a presentation layer, not a graph database, and never infers
attack paths. These tests assert:

  1. The graph has a case node plus one node per linked finding/activity/signal/
     correlation, and a case_contains edge to each.
  2. A correlation with linked_finding_id / linked_activity_event_id /
     linked_signal_id produces the matching explicit edges.
  3. A signal with linked_finding_id / linked_activity_event_id produces the
     matching explicit edges.
  4. counts_by_node_type / counts_by_edge_type / counts_by_provider are correct.
  5. A linked id pointing at evidence NOT in the case is skipped safely.
  6. The builder is workspace-scoped; the endpoint is 200 own / 404 cross-ws.
  7. Node previews leak no raw secrets/tokens/headers/code/paths/bodies; the
     response contains no forbidden breach/attacker/compromise claims.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase, SecurityCaseLink
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.services import security_activity_event_service as activity_svc
from app.services import security_case_report_service as report_svc
from app.services import security_case_service as case_svc
from app.services import security_finding_service as finding_svc
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "token leaked", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
REPO = "acme/repo"
RAW_IP = "203.0.113.9"
RAW_SECRET = "ghp_supersecrettoken12345"
_FORBIDDEN_KEYS = [
    "secret", "token", "credential", "authorization", "headers", "webhook_secret",
    "private_key", "oauth_secret", "raw_response", "code_snippet", "file_path",
    "manifest_path", "advisory_body", "patch", "request_body", "response_body",
]


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.7B", db=db)


def _integ(db, user, ws_id, provider="github"):
    ct, iv = encrypt_credentials({"github_token": "x", "repo_owner": "acme", "repo_name": "repo"})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider=provider,
                    display_name=provider, encrypted_credentials=ct, credential_iv=iv,
                    status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _repo(db, integ, user):
    r = Resource(integration_id=integ.id, user_id=user.id, provider_resource_type="github_repo",
                 provider_resource_id=REPO, display_name=REPO, is_active=True)
    db.add(r); db.commit(); db.refresh(r)
    return r


def _finding(db, ws, integ, res):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key=f"github_webhook_http:{uuid.uuid4().hex[:8]}", severity="high",
        title="webhook over HTTP", resource_id=res.id, description="d",
        evidence={
            "rule": "github_webhook_http", "repository": REPO,
            "secret_value": RAW_SECRET, "authorization": "Bearer x",
            "private_key": "-----BEGIN", "code_snippet": "os.system(...)",
            "file_path": "/etc/app/config.py", "patch": "@@ -1 +1 @@",
            "raw_response": {"k": "v"},
        },
        remediation={"summary": "fix"})


def _activity(db, ws_id, integ_id, *, provider="github", source="audit_log",
              event_type="github.webhook.updated", occurred_at=None, eid=None):
    norm = activity_svc.normalize_activity_event(
        provider=provider, source=source, event_type=event_type,
        occurred_at=occurred_at or datetime.now(timezone.utc),
        provider_event_id=eid or f"doc-{uuid.uuid4().hex[:8]}",
        actor_id="mallory", resource_type="repository", resource_id=REPO,
        source_ip=RAW_IP,
        metadata={"action": "hook.config_changed", "repository": REPO,
                  "authorization": "Bearer x", "secret": RAW_SECRET})
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _signal(db, ws_id, *, linked_finding_id=None, linked_activity_event_id=None,
            occurred_at=None):
    s = SecurityIncidentSignal(
        workspace_id=ws_id, provider="github", signal_key=uuid.uuid4().hex,
        signal_type="github_webhook_reconfigured", title="Webhook reconfigured",
        summary="A webhook was reconfigured.",
        severity="medium", status="open", confidence="medium", evidence_level="signal",
        linked_finding_id=linked_finding_id,
        linked_activity_event_id=linked_activity_event_id,
        first_seen_at=occurred_at or datetime.now(timezone.utc),
        last_seen_at=occurred_at or datetime.now(timezone.utc),
        signal_metadata={"repository": REPO, "action": "hook.config_changed",
                         "secret": RAW_SECRET, "private_key": "-----BEGIN"})
    db.add(s); db.commit(); db.refresh(s)
    return s


def _correlation(db, ws_id, *, linked_finding_id=None, linked_activity_event_id=None,
                 linked_signal_id=None, occurred_at=None):
    c = SecuritySignalCorrelation(
        workspace_id=ws_id, provider="github", correlation_key=uuid.uuid4().hex,
        correlation_type="github_config_audit", title="Config change near audit activity",
        summary="A config change occurred near audit activity.",
        severity="medium", status="open", confidence="high",
        linked_finding_id=linked_finding_id,
        linked_activity_event_id=linked_activity_event_id,
        linked_signal_id=linked_signal_id,
        first_seen_at=occurred_at or datetime.now(timezone.utc),
        last_seen_at=occurred_at or datetime.now(timezone.utc),
        correlation_metadata={"repository": REPO, "rule": "github_webhook_http",
                              "authorization": "Bearer x", "patch": "@@"})
    db.add(c); db.commit(); db.refresh(c)
    return c


def _link(db, case, user, otype, oid):
    case_svc.link_object_to_case(
        case=case, object_type=otype, object_id=oid, actor_user_id=user.id, db=db)


def _wired_case(db, user, *, miss_finding=False):
    """A case whose correlation+signal point at the linked finding/activity/signal."""
    ws = _ws(user, db)
    integ = _integ(db, user, ws.id)
    res = _repo(db, integ, user)
    t0 = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
    f = _finding(db, ws, integ, res)
    a = _activity(db, ws.id, integ.id, occurred_at=t0 + timedelta(hours=1))
    s = _signal(db, ws.id, linked_finding_id=f.id, linked_activity_event_id=a.id,
                occurred_at=t0 + timedelta(hours=2))
    # When miss_finding, point the correlation at a REAL finding that is NOT linked
    # to the case (FK is satisfied, but it has no graph node → edge is skipped).
    corr_fid = _finding(db, ws, integ, res).id if miss_finding else f.id
    c = _correlation(db, ws.id, linked_finding_id=corr_fid,
                     linked_activity_event_id=a.id, linked_signal_id=s.id,
                     occurred_at=t0 + timedelta(hours=3))
    case = case_svc.create_case(workspace_id=ws.id, user_id=user.id,
                                title="M69.7B case", provider="github", db=db)
    _link(db, case, user, "finding", f.id)
    _link(db, case, user, "activity_event", a.id)
    _link(db, case, user, "signal", s.id)
    _link(db, case, user, "correlation", c.id)
    return ws, case


def _cleanup(db, ws_id):
    db.query(SecurityCaseLink).filter(SecurityCaseLink.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityCase).filter(SecurityCase.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecuritySignalCorrelation).filter(SecuritySignalCorrelation.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityIncidentSignal).filter(SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    integ_ids = [i.id for i in db.query(Integration).filter(Integration.workspace_id == ws_id).all()]
    if integ_ids:
        db.query(Resource).filter(Resource.integration_id.in_(integ_ids)).delete(synchronize_session=False)
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(synchronize_session=False)
    db.commit()


def _edge_types(graph):
    return {e["edge_type"] for e in graph["edges"]}


def _node_types(graph):
    return {n["node_type"] for n in graph["nodes"]}


# ── 1. case + evidence nodes + case_contains edges ───────────────────────────

def test_graph_has_case_and_evidence_nodes(test_user, db_session):
    ws, case = _wired_case(db_session, test_user)
    try:
        g = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        assert _node_types(g) == {
            "case", "finding", "activity_event", "incident_signal", "correlation"}
        assert g["counts_by_node_type"]["case"] == 1
        # exactly one case node, and the rest are evidence nodes
        case_nodes = [n for n in g["nodes"] if n["node_type"] == "case"]
        assert len(case_nodes) == 1 and case_nodes[0]["id"] == f"case:{case.id}"

        # case_contains edge to every evidence node (4).
        contains = [e for e in g["edges"] if e["edge_type"] == "case_contains"]
        assert len(contains) == 4
        assert all(e["source_node_id"] == f"case:{case.id}" for e in contains)
    finally:
        _cleanup(db_session, ws.id)


# ── 2. explicit correlation edges ─────────────────────────────────────────────

def test_correlation_explicit_edges(test_user, db_session):
    ws, case = _wired_case(db_session, test_user)
    try:
        g = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        types = _edge_types(g)
        assert "correlation_links_finding" in types
        assert "correlation_links_activity" in types
        assert "correlation_created_signal" in types
        # Correlation edges carry the correlation's confidence.
        corr_edges = [e for e in g["edges"] if e["edge_type"].startswith("correlation_")]
        assert all(e["confidence"] == "high" for e in corr_edges)
        # Each edge's source is the correlation node, target is real and present.
        node_ids = {n["id"] for n in g["nodes"]}
        for e in corr_edges:
            assert e["source_node_id"].startswith("correlation:")
            assert e["target_node_id"] in node_ids
    finally:
        _cleanup(db_session, ws.id)


# ── 3. explicit signal edges (finding + activity; no correlation FK) ─────────

def test_signal_explicit_edges(test_user, db_session):
    ws, case = _wired_case(db_session, test_user)
    try:
        g = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        types = _edge_types(g)
        assert "signal_links_finding" in types
        assert "signal_links_activity" in types
        # The signal model has no linked_correlation_id, so no such edge exists.
        assert "signal_links_correlation" not in types
        sig_edges = [e for e in g["edges"] if e["edge_type"].startswith("signal_")]
        assert all(e["source_node_id"].startswith("incident_signal:") for e in sig_edges)
    finally:
        _cleanup(db_session, ws.id)


# ── 4. counts ─────────────────────────────────────────────────────────────────

def test_graph_counts(test_user, db_session):
    ws, case = _wired_case(db_session, test_user)
    try:
        g = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        assert g["counts_by_node_type"] == {
            "case": 1, "finding": 1, "activity_event": 1,
            "incident_signal": 1, "correlation": 1}
        assert g["counts_by_edge_type"]["case_contains"] == 4
        assert g["counts_by_edge_type"]["correlation_links_finding"] == 1
        assert g["counts_by_edge_type"]["correlation_links_activity"] == 1
        assert g["counts_by_edge_type"]["correlation_created_signal"] == 1
        assert g["counts_by_edge_type"]["signal_links_finding"] == 1
        assert g["counts_by_edge_type"]["signal_links_activity"] == 1
        # All evidence nodes are github; case node is github too.
        assert g["counts_by_provider"]["github"] == 5
        assert g["case_id"] == str(case.id)
    finally:
        _cleanup(db_session, ws.id)


# ── 5. dangling linked id is skipped safely ───────────────────────────────────

def test_missing_linked_evidence_skipped(test_user, db_session):
    ws, case = _wired_case(db_session, test_user, miss_finding=True)
    try:
        g = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        types = _edge_types(g)
        # correlation.linked_finding_id points at a finding NOT in the case → skipped.
        assert "correlation_links_finding" not in types
        # The other explicit correlation edges still resolve.
        assert "correlation_links_activity" in types
        assert "correlation_created_signal" in types
        # No edge ever references a non-existent node.
        node_ids = {n["id"] for n in g["nodes"]}
        for e in g["edges"]:
            assert e["source_node_id"] in node_ids
            assert e["target_node_id"] in node_ids
    finally:
        _cleanup(db_session, ws.id)


# ── 6. workspace scoping + endpoint ───────────────────────────────────────────

def test_graph_workspace_scoped_service(test_user, db_session):
    ws, case = _wired_case(db_session, test_user)
    other = _new_user(db_session, "other")
    ws_b = _ws(other, db_session)
    try:
        # Building case A's graph under workspace B yields no evidence nodes.
        g = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws_b.id, db=db_session)
        assert g["counts_by_node_type"].get("finding", 0) == 0
        assert g["counts_by_node_type"].get("correlation", 0) == 0
        assert all(e["edge_type"] == "case_contains" or False for e in g["edges"]) or g["edges"] == []
    finally:
        _cleanup(db_session, ws.id)
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


def test_graph_endpoint_ok(client, test_user, db_session):
    ws, case = _wired_case(db_session, test_user)
    try:
        resp = client.get(f"/security/cases/{case.id}/graph")
        assert resp.status_code == 200
        body = resp.json()
        assert body["case_id"] == str(case.id)
        assert len(body["nodes"]) == 5
        assert any(e["edge_type"] == "correlation_created_signal" for e in body["edges"])
    finally:
        _cleanup(db_session, ws.id)


def test_graph_endpoint_404_cross_workspace(client, test_user, db_session):
    other = _new_user(db_session, "other")
    ws_b, case_b = _wired_case(db_session, other)
    try:
        resp = client.get(f"/security/cases/{case_b.id}/graph")
        assert resp.status_code == 404
    finally:
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 7. privacy + claim discipline ─────────────────────────────────────────────

def test_graph_preview_is_sanitized(test_user, db_session):
    ws, case = _wired_case(db_session, test_user)
    try:
        g = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        blob = json.dumps(g, default=str)
        assert RAW_SECRET not in blob
        assert RAW_IP not in blob
        for n in g["nodes"]:
            preview = n["metadata_preview"]
            for k, v in preview.items():
                assert k in report_svc._PREVIEW_ALLOWLIST
                assert isinstance(v, (bool, int, float, str))
            for bad in _FORBIDDEN_KEYS:
                assert bad not in preview
    finally:
        _cleanup(db_session, ws.id)


def test_graph_has_no_forbidden_claims(test_user, db_session):
    ws, case = _wired_case(db_session, test_user)
    try:
        g = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        blob = json.dumps(g, default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
        assert "does not" in g["claim_note"].lower()
    finally:
        _cleanup(db_session, ws.id)
