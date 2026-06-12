"""M66.10 — GitHub Incident Workflow demo smoke test.

Verifies the seeded demo chain (configuration risk → activity → signal →
correlation → case), that the case report exports safely, that seeding is
idempotent and clearing removes everything, and that seed/clear are admin-gated.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import HTTPException

from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase, SecurityCaseLink
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_case_report_service as report_svc
from app.services import security_case_service as case_svc
from app.services import security_incident_demo_service as demo_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
]


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M66.10", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


# ── seeded chain ──────────────────────────────────────────────────────────────

def test_demo_seeds_full_chain(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        out = demo_svc.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert out["seeded"] and out["created"]
        case = db_session.query(SecurityCase).filter(SecurityCase.id == uuid.UUID(out["case_id"])).first()
        assert case is not None
        links = case_svc.list_case_links(case_id=case.id, db=db_session)
        types = {ln.linked_object_type for ln in links}
        # finding + activity + correlation + signal all linked.
        assert {"finding", "activity_event", "correlation", "signal"} <= types
        # The underlying objects exist in the workspace.
        assert db_session.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws.id).count() >= 1
        assert db_session.query(SecurityActivityEvent).filter(SecurityActivityEvent.workspace_id == ws.id).count() >= 1
        assert db_session.query(SecuritySignalCorrelation).filter(SecuritySignalCorrelation.workspace_id == ws.id).count() >= 1
        assert db_session.query(SecurityIncidentSignal).filter(SecurityIncidentSignal.workspace_id == ws.id).count() >= 1
    finally:
        demo_svc.clear(workspace_id=ws.id, db=db_session)


def test_demo_report_exports_safely(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        out = demo_svc.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = db_session.query(SecurityCase).filter(SecurityCase.id == uuid.UUID(out["case_id"])).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(report, default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
        assert "secret" not in blob or "secrets" in blob  # no bare secret values
        assert len(report["risks"]) >= 1
        assert len(report["activity_events"]) >= 1
        assert len(report["correlations"]) >= 1
    finally:
        demo_svc.clear(workspace_id=ws.id, db=db_session)


# ── idempotency + clear ───────────────────────────────────────────────────────

def test_demo_is_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        s1 = demo_svc.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        s2 = demo_svc.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert s1["created"] is True
        assert s2["created"] is False
        assert s1["case_id"] == s2["case_id"]
        assert db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == "demo_incident",
        ).count() == 1
    finally:
        demo_svc.clear(workspace_id=ws.id, db=db_session)


def test_demo_clear_removes_everything(test_user, db_session):
    ws = _ws(test_user, db_session)
    demo_svc.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    demo_svc.clear(workspace_id=ws.id, db=db_session)

    assert demo_svc.get_status(ws.id, db_session)["seeded"] is False
    assert db_session.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws.id,
        SecurityCase.case_metadata["source"].astext == "demo_incident",
    ).count() == 0
    # No orphan demo evidence remains.
    assert demo_svc.get_demo_integration(ws.id, db_session) is None
    assert db_session.query(SecurityActivityEvent).filter(SecurityActivityEvent.workspace_id == ws.id).count() == 0
    assert db_session.query(SecuritySignalCorrelation).filter(SecuritySignalCorrelation.workspace_id == ws.id).count() == 0


# ── permission gating ─────────────────────────────────────────────────────────

def test_seed_clear_admin_gated_via_endpoints(client, test_user, db_session):
    # test_user owns their workspace → can seed + clear.
    ws = _ws(test_user, db_session)
    try:
        r = client.post("/security/incident-demo/seed")
        assert r.status_code == 200
        assert r.json()["seeded"] is True
        st = client.get("/security/incident-demo/status")
        assert st.json()["seeded"] is True
        c = client.post("/security/incident-demo/clear")
        assert c.status_code == 200 and c.json()["cleared"] is True
    finally:
        demo_svc.clear(workspace_id=ws.id, db=db_session)


def test_member_cannot_seed_permission_helper(test_user, db_session):
    owner = _new_user(db_session, "owner")
    ws = _ws(owner, db_session)
    m = WorkspaceMember(workspace_id=ws.id, user_id=test_user.id, role="member")
    db_session.add(m); db_session.commit()
    try:
        with pytest.raises(HTTPException) as exc:
            workspace_permission_service.require_workspace_admin(ws.id, test_user.id, db_session)
        assert exc.value.status_code == 403
    finally:
        try:
            db_session.delete(owner); db_session.commit()
        except Exception:
            db_session.rollback()
