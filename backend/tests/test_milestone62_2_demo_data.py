"""M62.2 — Security Exposure demo data mode.

  1.  seed creates demo findings for the current workspace
  2.  seed is idempotent (no duplicate findings / integrations)
  3.  clear deletes only demo findings + their notes
  4.  clear does not delete real (non-demo) findings
  5.  demo findings have varied providers / statuses / severities
  6.  demo accepted_risk has accepted_until + acceptance_reason
  7.  demo snoozed findings have snoozed_until
  8.  demo notes are attached
  9.  demo endpoints are workspace-isolated
  10. seeding does not dispatch notifications (email/push/slack)
"""

from __future__ import annotations

import uuid

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_finding import SecurityFinding
from app.models.security_finding_note import SecurityFindingNote
from app.models.user import User
from app.services import email_service
from app.services import security_demo_data_service as demo
from app.services import security_finding_service as svc
from app.services import workspace_service


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M62.2", db=db
    )


def _real_integration(db, user, ws_id):
    ct, iv = encrypt_credentials({"credential_type": "github_app"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="github",
        display_name="real github", encrypted_credentials=ct, credential_iv=iv,
        status="active",
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _demo_findings(ws_id, db):
    integ = demo.get_demo_integration(ws_id, db)
    if integ is None:
        return []
    return (
        db.query(SecurityFinding)
        .filter(SecurityFinding.integration_id == integ.id)
        .all()
    )


# ── 1, 5, 6, 7, 8. Seed content ───────────────────────────────────────────────


def test_seed_creates_varied_demo_findings(test_user, db_session):
    ws = _ws(test_user, db_session)
    status = demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)

    assert status["exists"] is True
    assert status["finding_count"] >= 12
    assert status["active_count"] >= 1
    assert status["resolved_count"] >= 1
    assert status["accepted_count"] >= 1
    assert status["snoozed_count"] >= 1

    findings = _demo_findings(ws.id, db_session)
    providers = {f.provider for f in findings}
    severities = {f.severity for f in findings}
    statuses = {f.status for f in findings}
    assert len(providers) >= 5
    assert {"critical", "high", "medium"}.issubset(severities)
    assert {"active", "resolved", "accepted_risk", "snoozed"}.issubset(statuses)

    # Accepted risk has accepted_until + reason.
    accepted = [f for f in findings if f.status == "accepted_risk"]
    assert accepted and all(f.accepted_until is not None for f in accepted)
    assert all(f.acceptance_reason for f in accepted)

    # Snoozed has snoozed_until.
    snoozed = [f for f in findings if f.status == "snoozed"]
    assert snoozed and all(f.snoozed_until is not None for f in snoozed)

    # Notes attached.
    finding_ids = [f.id for f in findings]
    notes = (
        db_session.query(SecurityFindingNote)
        .filter(SecurityFindingNote.finding_id.in_(finding_ids))
        .all()
    )
    assert len(notes) >= 3

    # Evidence is demo-marked and metadata-only.
    for f in findings:
        assert f.evidence.get("demo") is True
        assert f.evidence.get("demo_dataset") == demo.DEMO_DATASET

    demo.clear(workspace_id=ws.id, db=db_session)


# ── 2. Idempotent seed ────────────────────────────────────────────────────────


def test_seed_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    s1 = demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    s2 = demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    assert s1["finding_count"] == s2["finding_count"]

    integs = (
        db_session.query(Integration)
        .filter(
            Integration.workspace_id == ws.id,
            Integration.provider == demo.DEMO_PROVIDER_TAG,
        )
        .all()
    )
    assert len(integs) == 1  # not duplicated
    demo.clear(workspace_id=ws.id, db=db_session)


# ── 3 & 4. Clear scoping ──────────────────────────────────────────────────────


def test_clear_only_removes_demo(test_user, db_session):
    ws = _ws(test_user, db_session)
    # A real, non-demo finding in the same workspace.
    integ = _real_integration(db_session, test_user, ws.id)
    real = svc.upsert_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key="github_webhook_http:real#1", severity="critical",
        title="Real finding", resource_id=None,
    )
    real_id = real.id

    demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    assert demo.get_status(ws.id, db_session)["exists"] is True

    res = demo.clear(workspace_id=ws.id, db=db_session)
    assert res["cleared"] is True
    assert res["findings_deleted"] >= 12
    assert res["notes_deleted"] >= 3

    # Demo gone; real finding survives.
    assert demo.get_status(ws.id, db_session)["exists"] is False
    assert demo.get_demo_integration(ws.id, db_session) is None
    surviving = db_session.get(SecurityFinding, real_id)
    assert surviving is not None and surviving.status == "active"

    db_session.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == ws.id
    ).delete()
    db_session.commit()


# ── 9. Workspace isolation ────────────────────────────────────────────────────


def test_workspace_isolation(test_user, db_session):
    ws = _ws(test_user, db_session)
    other = User(
        clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
        email=f"other_{uuid.uuid4().hex[:8]}@configtrace.test",
        display_name="Other",
    )
    db_session.add(other)
    db_session.commit()
    db_session.refresh(other)
    ows = _ws(other, db_session)

    demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    assert demo.get_status(ws.id, db_session)["exists"] is True
    assert demo.get_status(ows.id, db_session)["exists"] is False  # isolated

    # Clearing the other workspace does nothing to ours.
    demo.clear(workspace_id=ows.id, db=db_session)
    assert demo.get_status(ws.id, db_session)["exists"] is True

    demo.clear(workspace_id=ws.id, db=db_session)
    db_session.delete(other)
    db_session.commit()


# ── 10. No notifications dispatched ───────────────────────────────────────────


def test_seed_dispatches_no_notifications(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    sent = []
    monkeypatch.setattr(
        email_service, "send_email",
        lambda **kw: sent.append(kw) or {"id": "x"},
    )
    demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    assert sent == []  # demo seeding never emails
    demo.clear(workspace_id=ws.id, db=db_session)


# ── API-level: seed / status / clear round-trip ───────────────────────────────


def test_api_seed_status_clear(client, test_user, db_session):
    ws = _ws(test_user, db_session)

    seed = client.post("/security/demo-data/seed")
    assert seed.status_code == 200
    assert seed.json()["exists"] is True
    assert seed.json()["finding_count"] >= 12

    st = client.get("/security/demo-data/status")
    assert st.status_code == 200 and st.json()["exists"] is True

    # Seeded findings show up in the findings list.
    lst = client.get("/security/findings?status=active")
    assert lst.status_code == 200 and lst.json()["total"] >= 1

    clr = client.delete("/security/demo-data")
    assert clr.status_code == 200 and clr.json()["cleared"] is True

    st2 = client.get("/security/demo-data/status")
    assert st2.json()["exists"] is False

    db_session.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == ws.id
    ).delete()
    db_session.commit()
