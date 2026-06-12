"""M66.8 — Cases / Investigations workflow.

A case is a HUMAN-MANAGED investigation container. These tests assert
creation/listing/scoping/status/linking/idempotency/permissions and that NO
forbidden breach/attacker/compromise wording appears. Confirmation/dismissal are
human actions; ConfigTrace never auto-confirms.

  1. Model/table create via create_case.
  2. List cases is workspace-scoped.
  3. Get case 404 cross-workspace.
  4. Update status (investigating/dismissed/resolved) stamps fields.
  5. Confirm (confirmed_by_user) is admin-gated (permission helper) + sets confirmer.
  6. Link a signal to a case.
  7. Link a correlation to a case.
  8. Duplicate link is idempotent.
  9. Cross-workspace linked object is rejected (404).
 10. create-case-from-signal links the signal + its evidence.
 11. create-case-from-correlation links risk/activity/signal.
 12. No forbidden claim wording in generated case titles/summaries.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase, SecurityCaseLink
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_activity_event_service as activity_svc
from app.services import security_case_service as case_svc
from app.services import security_finding_service as finding_svc
from app.services import security_incident_signal_service as signal_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
]
REPO = "acme/repo"


# ── builders ──────────────────────────────────────────────────────────────────

def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M66.8", db=db
    )


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"github_token": "x", "repo_owner": "acme", "repo_name": "repo"})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="github", display_name="github",
                    encrypted_credentials=ct, credential_iv=iv, status="active")
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
        title="webhook risk", resource_id=res.id, description="d",
        evidence={"rule": "github_webhook_http"}, remediation={"summary": "fix"})


def _activity(db, ws_id, integ_id, event_type="github.webhook.updated"):
    norm = activity_svc.normalize_activity_event(
        provider="github", source="audit_log", event_type=event_type,
        occurred_at=datetime.now(timezone.utc), provider_event_id=uuid.uuid4().hex,
        actor_id="mallory", resource_type="repository", resource_id=REPO,
        metadata={"action": "hook.config_changed", "repository": REPO})
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _add_member(db, ws_id, user_id, role):
    m = WorkspaceMember(workspace_id=ws_id, user_id=user_id, role=role)
    db.add(m); db.commit(); db.refresh(m)
    return m


def _evidence(db, user):
    """Build a full evidence set: finding, activity, correlation(+signal), signal."""
    ws = _ws(user, db)
    integ = _integ(db, user, ws.id)
    res = _repo(db, integ, user)
    finding = _finding(db, ws, integ, res)
    activity = _activity(db, ws.id, integ.id)
    corr_svc.generate_github_correlations(workspace_id=ws.id, db=db)
    items, _ = corr_svc.list_correlations(workspace_id=ws.id, db=db)
    correlation = items[0]
    signal_svc.generate_github_incident_signals(workspace_id=ws.id, db=db)
    sigs, _ = signal_svc.list_incident_signals(workspace_id=ws.id, db=db)
    signal = sigs[0]
    return ws, finding, activity, correlation, signal


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


# ── 1. create + 2. list scope ─────────────────────────────────────────────────

def test_create_and_list_cases_scoped(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    resp = client.post("/security/cases", json={"title": "Repo review", "severity": "high"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "open"
    assert body["severity"] == "high"
    assert body["opened_by_user_id"] == str(test_user.id)

    lst = client.get("/security/cases")
    assert lst.status_code == 200
    assert lst.json()["total"] >= 1
    _cleanup(db_session, ws.id)


def test_list_is_workspace_scoped(client, test_user, db_session):
    other = _new_user(db_session, "other")
    ws_b = _ws(other, db_session)
    case_svc.create_case(workspace_id=ws_b.id, user_id=other.id, title="other case", db=db_session)
    try:
        resp = client.get("/security/cases")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0
    finally:
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 3. get 404 cross-workspace ────────────────────────────────────────────────

def test_get_case_404_cross_workspace(client, test_user, db_session):
    other = _new_user(db_session, "other")
    ws_b = _ws(other, db_session)
    case = case_svc.create_case(workspace_id=ws_b.id, user_id=other.id, title="x", db=db_session)
    try:
        resp = client.get(f"/security/cases/{case.id}")
        assert resp.status_code == 404
    finally:
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 4. status transitions ─────────────────────────────────────────────────────

def test_update_status_transitions(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    case = case_svc.create_case(workspace_id=ws.id, user_id=test_user.id, title="c", db=db_session)
    try:
        r1 = client.patch(f"/security/cases/{case.id}", json={"status": "investigating"})
        assert r1.json()["status"] == "investigating"
        r2 = client.patch(f"/security/cases/{case.id}", json={"status": "dismissed"})
        assert r2.json()["status"] == "dismissed"
        assert r2.json()["dismissed_by_user_id"] == str(test_user.id)
        r3 = client.patch(f"/security/cases/{case.id}", json={"status": "resolved"})
        assert r3.json()["status"] == "resolved"
        assert r3.json()["resolved_at"] is not None
    finally:
        _cleanup(db_session, ws.id)


# ── 5. confirm is admin-gated + sets confirmer ────────────────────────────────

def test_confirm_requires_admin_role(test_user, db_session):
    owner = _new_user(db_session, "owner")
    ws = _ws(owner, db_session)
    _add_member(db_session, ws.id, test_user.id, "member")
    try:
        with pytest.raises(HTTPException) as exc:
            workspace_permission_service.require_workspace_admin(ws.id, test_user.id, db_session)
        assert exc.value.status_code == 403
    finally:
        try:
            db_session.delete(owner); db_session.commit()
        except Exception:
            db_session.rollback()


def test_owner_can_confirm_case(client, test_user, db_session):
    ws = _ws(test_user, db_session)  # test_user is owner of own ws
    case = case_svc.create_case(workspace_id=ws.id, user_id=test_user.id, title="c", db=db_session)
    try:
        resp = client.patch(f"/security/cases/{case.id}", json={"status": "confirmed_by_user"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "confirmed_by_user"
        assert resp.json()["confirmed_by_user_id"] == str(test_user.id)
        assert resp.json()["confirmed_at"] is not None
    finally:
        _cleanup(db_session, ws.id)


# ── 6–9. linking ──────────────────────────────────────────────────────────────

def test_link_signal_and_correlation(client, test_user, db_session):
    ws, finding, activity, correlation, signal = _evidence(db_session, test_user)
    case = case_svc.create_case(workspace_id=ws.id, user_id=test_user.id, title="c", db=db_session)
    try:
        r1 = client.post(f"/security/cases/{case.id}/links",
                         json={"linked_object_type": "signal", "linked_object_id": str(signal.id)})
        assert r1.status_code == 201
        r2 = client.post(f"/security/cases/{case.id}/links",
                         json={"linked_object_type": "correlation", "linked_object_id": str(correlation.id)})
        assert r2.status_code == 201
        links = client.get(f"/security/cases/{case.id}/links").json()
        assert links["total"] == 2
    finally:
        _cleanup(db_session, ws.id)


def test_duplicate_link_is_idempotent(db_session, test_user):
    ws, finding, activity, correlation, signal = _evidence(db_session, test_user)
    case = case_svc.create_case(workspace_id=ws.id, user_id=test_user.id, title="c", db=db_session)
    try:
        o1, _ = case_svc.link_object_to_case(case=case, object_type="finding",
                                             object_id=finding.id, actor_user_id=test_user.id, db=db_session)
        o2, _ = case_svc.link_object_to_case(case=case, object_type="finding",
                                             object_id=finding.id, actor_user_id=test_user.id, db=db_session)
        assert o1 == "created" and o2 == "exists"
        assert case_svc.count_links(case.id, db_session) == 1
    finally:
        _cleanup(db_session, ws.id)


def test_cross_workspace_link_rejected(client, test_user, db_session):
    _ws(test_user, db_session)  # caller's own (owner) workspace
    other = _new_user(db_session, "other")
    ws_b, finding_b, *_ = _evidence(db_session, other)
    # Case in caller's own workspace.
    case = case_svc.create_case(
        workspace_id=_ws(test_user, db_session).id, user_id=test_user.id, title="c", db=db_session)
    try:
        resp = client.post(f"/security/cases/{case.id}/links",
                           json={"linked_object_type": "finding", "linked_object_id": str(finding_b.id)})
        assert resp.status_code == 404  # ws_b's finding is not in caller's workspace
    finally:
        _cleanup(db_session, _ws(test_user, db_session).id)
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 10–11. convenience endpoints ──────────────────────────────────────────────

def test_create_case_from_signal_endpoint(client, test_user, db_session):
    ws, finding, activity, correlation, signal = _evidence(db_session, test_user)
    try:
        resp = client.post(f"/security/signals/{signal.id}/create-case")
        assert resp.status_code == 201
        body = resp.json()
        assert body["link_count"] >= 1  # at least the signal itself
        case_id = body["id"]
        links = client.get(f"/security/cases/{case_id}/links").json()
        types = {ln["linked_object_type"] for ln in links["items"]}
        assert "signal" in types
    finally:
        _cleanup(db_session, ws.id)


def test_create_case_from_correlation_endpoint(client, test_user, db_session):
    ws, finding, activity, correlation, signal = _evidence(db_session, test_user)
    try:
        resp = client.post(f"/security/correlations/{correlation.id}/create-case")
        assert resp.status_code == 201
        case_id = resp.json()["id"]
        links = client.get(f"/security/cases/{case_id}/links").json()
        types = {ln["linked_object_type"] for ln in links["items"]}
        # correlation + finding + activity_event (+ signal) all linked
        assert "correlation" in types
        assert "finding" in types
        assert "activity_event" in types
    finally:
        _cleanup(db_session, ws.id)


# ── 12. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording_in_generated_cases(db_session, test_user):
    ws, finding, activity, correlation, signal = _evidence(db_session, test_user)
    try:
        c1 = case_svc.create_case_from_signal(
            workspace_id=ws.id, user_id=test_user.id, signal=signal, db=db_session)
        c2 = case_svc.create_case_from_correlation(
            workspace_id=ws.id, user_id=test_user.id, correlation=correlation, db=db_session)
        for c in (c1, c2):
            blob = f"{c.title}\n{c.summary}".lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob, f"forbidden phrase {phrase!r} in {blob!r}"
    finally:
        _cleanup(db_session, ws.id)
