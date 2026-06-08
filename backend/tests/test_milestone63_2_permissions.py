"""M63.2 — Admin/team permissions for Security Exposure actions.

Read-only access stays broad (any member). High-impact mutations
(accept risk / snooze / rule toggle / demo data) require admin or owner.
Acknowledge + add-note stay available to any member.

HTTP-level tests run as ``test_user`` (the `client` fixture) whose role in the
*finding's* workspace is varied. Cross-workspace stays 404; insufficient role
is 403. Rule-settings/demo endpoints resolve the actor's own (owned) workspace,
so their member-denial is covered at the permission-helper level.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_finding_service as svc
from app.services import workspace_permission_service as perms
from app.services import workspace_service


# ── builders ──────────────────────────────────────────────────────────────────


def _new_user(db, label="owner"):
    u = User(
        clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
        email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test",
        display_name=label,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M63.2", db=db
    )


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"credential_type": "github_app"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="github",
        display_name="github", encrypted_credentials=ct, credential_iv=iv,
        status="active",
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _res(db, integ, user):
    r = Resource(
        integration_id=integ.id, user_id=user.id,
        provider_resource_type="github_repo",
        provider_resource_id=f"acme/{uuid.uuid4().hex[:6]}",
        display_name="repo", is_active=True,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _finding(db, ws, integ, res):
    return svc.upsert_active_finding(
        db=db,
        workspace_id=ws.id,
        integration_id=integ.id,
        provider="github",
        finding_key=f"github_webhook_http:{uuid.uuid4().hex}",
        severity="critical",
        title="GitHub webhook uses plain HTTP",
        resource_id=res.id,
        description="desc",
        evidence={"rule": "github_webhook_http"},
        remediation={"summary": "Fix it"},
    )


def _add_member(db, ws_id, user_id, role):
    m = WorkspaceMember(workspace_id=ws_id, user_id=user_id, role=role)
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


def _setup(db, actor, role):
    """A workspace owned by a fresh user + a finding, with `actor` joined as `role`."""
    owner = _new_user(db, "owner")
    ws = _ws(owner, db)
    integ = _integ(db, owner, ws.id)
    res = _res(db, integ, owner)
    finding = _finding(db, ws, integ, res)
    _add_member(db, ws.id, actor.id, role)
    return owner, ws, finding


def _teardown(db, owner, ws):
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws.id).delete(
        synchronize_session=False
    )
    integ_ids = [
        i.id for i in db.query(Integration).filter(Integration.workspace_id == ws.id).all()
    ]
    if integ_ids:
        db.query(Resource).filter(Resource.integration_id.in_(integ_ids)).delete(
            synchronize_session=False
        )
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(
            synchronize_session=False
        )
    db.commit()
    try:
        db.delete(owner)  # cascade removes the workspace + memberships
        db.commit()
    except Exception:
        db.rollback()


# ── 1. Member can read a finding ──────────────────────────────────────────────


def test_member_can_read_finding(client, test_user, db_session):
    owner, ws, finding = _setup(db_session, test_user, "member")
    try:
        resp = client.get(f"/security/findings/{finding.id}")
        assert resp.status_code == 200
    finally:
        _teardown(db_session, owner, ws)


# ── 2 & 3. Member can acknowledge + add a note ────────────────────────────────


def test_member_can_acknowledge(client, test_user, db_session):
    owner, ws, finding = _setup(db_session, test_user, "member")
    try:
        resp = client.post(f"/security/findings/{finding.id}/acknowledge")
        assert resp.status_code == 200
    finally:
        _teardown(db_session, owner, ws)


def test_member_can_add_note(client, test_user, db_session):
    owner, ws, finding = _setup(db_session, test_user, "member")
    try:
        resp = client.post(
            f"/security/findings/{finding.id}/notes", json={"body": "Investigating this."}
        )
        assert resp.status_code == 201
    finally:
        _teardown(db_session, owner, ws)


# ── 4 & 5. Member cannot accept risk / snooze (403) ───────────────────────────


def test_member_cannot_accept_risk(client, test_user, db_session):
    owner, ws, finding = _setup(db_session, test_user, "member")
    try:
        resp = client.post(
            f"/security/findings/{finding.id}/accept-risk",
            json={"reason": "We accept this for now.", "accepted_until": "2099-01-01T00:00:00Z"},
        )
        assert resp.status_code == 403
    finally:
        _teardown(db_session, owner, ws)


def test_member_cannot_snooze(client, test_user, db_session):
    owner, ws, finding = _setup(db_session, test_user, "member")
    try:
        resp = client.post(
            f"/security/findings/{finding.id}/snooze",
            json={"snoozed_until": "2099-01-01T00:00:00Z"},
        )
        assert resp.status_code == 403
    finally:
        _teardown(db_session, owner, ws)


# ── 6 & 7. Member cannot manage rules / demo data (helper-level policy) ────────
# The rule-settings + demo endpoints resolve the actor's OWN (owned) workspace,
# so member-denial is enforced and verified through the permission helpers.


def test_member_cannot_manage_rules_or_demo(db_session):
    owner = _new_user(db_session, "owner")
    member = _new_user(db_session, "member")
    ws = _ws(owner, db_session)
    _add_member(db_session, ws.id, member.id, "member")
    try:
        assert perms.can_manage_security_rules(ws.id, member.id, db_session) is False
        assert perms.can_manage_demo_data(ws.id, member.id, db_session) is False
        with pytest.raises(Exception) as ei:
            perms.require_workspace_admin(ws.id, member.id, db_session)
        assert getattr(ei.value, "status_code", None) == 403
    finally:
        db_session.delete(owner)
        db_session.delete(member)
        db_session.commit()


# ── 8. Admin/owner can perform high-impact actions ────────────────────────────


def test_admin_can_accept_and_snooze(client, test_user, db_session):
    owner, ws, finding = _setup(db_session, test_user, "admin")
    try:
        acc = client.post(
            f"/security/findings/{finding.id}/accept-risk",
            json={"reason": "Accepted by an admin.", "accepted_until": "2099-01-01T00:00:00Z"},
        )
        assert acc.status_code == 200
    finally:
        _teardown(db_session, owner, ws)


def test_admin_can_snooze(client, test_user, db_session):
    owner, ws, finding = _setup(db_session, test_user, "admin")
    try:
        resp = client.post(
            f"/security/findings/{finding.id}/snooze",
            json={"snoozed_until": "2099-01-01T00:00:00Z"},
        )
        assert resp.status_code == 200
    finally:
        _teardown(db_session, owner, ws)


def test_owner_solo_flow_unbroken(client, test_user, db_session):
    """A solo user (owner of their own default workspace) keeps full access."""
    ws = _ws(test_user, db_session)
    # Rule toggle + demo seed/clear resolve test_user's own workspace (owner).
    r1 = client.patch(
        "/security/rules/settings/github_webhook_http", json={"enabled": False}
    )
    assert r1.status_code == 200
    seed = client.post("/security/demo-data/seed")
    assert seed.status_code == 200
    clear = client.delete("/security/demo-data")
    assert clear.status_code == 200
    # cleanup rule setting + demo rows
    db_session.execute(
        __import__("sqlalchemy").text(
            "DELETE FROM security_rule_settings WHERE workspace_id = :w"
        ),
        {"w": str(ws.id)},
    )
    db_session.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == ws.id
    ).delete(synchronize_session=False)
    db_session.commit()


# ── 9. Cross-workspace stays 404 ──────────────────────────────────────────────


def test_cross_workspace_still_404(client, test_user, db_session):
    # test_user is NOT a member of owner's workspace.
    owner = _new_user(db_session, "owner")
    ws = _ws(owner, db_session)
    integ = _integ(db_session, owner, ws.id)
    res = _res(db_session, integ, owner)
    finding = _finding(db_session, ws, integ, res)
    try:
        resp = client.post(
            f"/security/findings/{finding.id}/accept-risk",
            json={"reason": "x" * 12, "accepted_until": "2099-01-01T00:00:00Z"},
        )
        assert resp.status_code == 404  # never 403 — avoids leaking existence
    finally:
        _teardown(db_session, owner, ws)


# ── 10. Permission helpers: 404 vs 403 + role predicates ──────────────────────


def test_permission_helper_semantics(db_session):
    owner = _new_user(db_session, "owner")
    member = _new_user(db_session, "member")
    stranger = _new_user(db_session, "stranger")
    ws = _ws(owner, db_session)
    _add_member(db_session, ws.id, member.id, "member")
    try:
        # Non-member -> 404 from both member + admin gates.
        with pytest.raises(Exception) as e404:
            perms.require_workspace_member(ws.id, stranger.id, db_session)
        assert getattr(e404.value, "status_code", None) == 404

        # Member -> passes member gate, 403 on admin gate.
        assert perms.require_workspace_member(ws.id, member.id, db_session) is not None
        with pytest.raises(Exception) as e403:
            perms.require_workspace_admin(ws.id, member.id, db_session)
        assert getattr(e403.value, "status_code", None) == 403

        # Owner -> passes admin gate; predicates align with policy.
        assert perms.require_workspace_admin(ws.id, owner.id, db_session) is not None
        assert perms.can_acknowledge_security_finding(ws.id, member.id, db_session) is True
        assert perms.can_add_security_note(ws.id, member.id, db_session) is True
        assert perms.can_accept_risk(ws.id, member.id, db_session) is False
        assert perms.can_snooze(ws.id, member.id, db_session) is False
        assert perms.can_accept_risk(ws.id, owner.id, db_session) is True
    finally:
        db_session.delete(owner)
        db_session.delete(member)
        db_session.delete(stranger)
        db_session.commit()
