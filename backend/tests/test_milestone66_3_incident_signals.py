"""M66.3 — first GitHub Incident Signals from normalized audit activity.

Signals are REVIEW signals derived from control-plane audit activity. These tests
assert generation/severity/idempotency/scoping/privacy/permissions and that NO
forbidden breach/attacker/compromise wording appears — there is no breach
detection in this milestone.

  1. Model/table create via generation.
  2. Signal metadata sanitizer drops secrets/tokens/raw payloads.
  3. branch_protection.disabled → high-severity signal.
  4. deploy_key.added → high-severity signal.
  5. app.permissions_changed → high-severity signal.
  6. Unmapped activity event → no signal.
  7. Repeated generation is idempotent.
  8. List endpoint is workspace-scoped.
  9. Get endpoint returns 404 cross-workspace.
 10. Generate is admin/owner-gated (permission helper); member is not admin.
 11. Member can list (endpoint); owner can generate (endpoint).
 12. No forbidden claim wording in generated title/summary.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_activity_event_service as activity_svc
from app.services import security_incident_signal_service as sig_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected",
    "attacker found",
    "compromise confirmed",
    "someone has access",
    "unauthorized access confirmed",
    "attack detected",
]


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
        user_id=user.id, user_display_name=user.display_name or "M66.3", db=db
    )


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials(
        {"github_token": "x", "repo_owner": "acme", "repo_name": "repo"}
    )
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="github",
        display_name="github", encrypted_credentials=ct, credential_iv=iv,
        status="active",
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _add_member(db, ws_id, user_id, role):
    m = WorkspaceMember(workspace_id=ws_id, user_id=user_id, role=role)
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


def _activity(db, ws_id, integ_id, event_type, *, doc_id=None, actor="mallory",
              repo="acme/repo", metadata=None):
    norm = activity_svc.normalize_activity_event(
        provider="github",
        source="audit_log",
        event_type=event_type,
        occurred_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        provider_event_id=doc_id or uuid.uuid4().hex,
        actor_id=actor,
        resource_type="repository",
        resource_id=repo,
        metadata=metadata or {"action": "x", "repository": repo},
    )
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db
    )
    return row


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id
    ).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id
    ).delete(synchronize_session=False)
    integ_ids = [
        i.id for i in db.query(Integration).filter(
            Integration.workspace_id == ws_id
        ).all()
    ]
    if integ_ids:
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(
            synchronize_session=False
        )
    db.commit()


def _gen(db, ws_id):
    return sig_svc.generate_github_incident_signals(workspace_id=ws_id, db=db)


def _signals(db, ws_id):
    items, _ = sig_svc.list_incident_signals(workspace_id=ws_id, db=db)
    return items


# ── 1. model/table + generation ───────────────────────────────────────────────

def test_generate_creates_signal_row(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    _activity(db_session, ws.id, integ.id, "github.branch_protection.disabled")
    summary = _gen(db_session, ws.id)
    assert summary["signals_created"] == 1
    rows = _signals(db_session, ws.id)
    assert len(rows) == 1
    assert rows[0].id is not None
    _cleanup(db_session, ws.id)


# ── 2. sanitizer ──────────────────────────────────────────────────────────────

def test_signal_sanitizer_drops_secrets_and_nested():
    raw = {
        "action": "deploy_key.create",     # allowlisted → kept
        "github_token": "ghp_secret",       # dropped
        "password": "hunter2",              # dropped
        "payload": {"raw": "blob"},         # nested → dropped
        "ips": ["203.0.113.7"],             # list → dropped
    }
    clean = sig_svc.sanitize_signal_metadata(raw)
    assert clean == {"action": "deploy_key.create"}
    assert "github_token" not in clean and "payload" not in clean and "ips" not in clean


# ── 3–5. severity rules ───────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "event_type,expected_sev,expected_key",
    [
        ("github.branch_protection.disabled", "high", "github_branch_protection_disabled"),
        ("github.deploy_key.added", "high", "github_deploy_key_added"),
        ("github.app.permissions_changed", "high", "github_app_permissions_changed"),
        ("github.branch_protection.updated", "medium", "github_branch_protection_updated"),
        ("github.app.installed", "medium", "github_app_installed"),
    ],
)
def test_signal_severity_rules(test_user, db_session, event_type, expected_sev, expected_key):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    _activity(db_session, ws.id, integ.id, event_type)
    _gen(db_session, ws.id)
    rows = _signals(db_session, ws.id)
    assert len(rows) == 1
    assert rows[0].severity == expected_sev
    assert rows[0].signal_key == expected_key
    assert rows[0].evidence_level == "activity"  # never confirmed_breach
    assert rows[0].confidence == "high"
    _cleanup(db_session, ws.id)


# ── 6. unmapped event → no signal ─────────────────────────────────────────────

def test_unmapped_activity_makes_no_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    # secret_scanning_alert.resolved and deploy_key.removed are intentionally
    # NOT signal-producing categories.
    _activity(db_session, ws.id, integ.id, "github.deploy_key.removed")
    summary = _gen(db_session, ws.id)
    assert summary["signals_created"] == 0
    assert _signals(db_session, ws.id) == []
    _cleanup(db_session, ws.id)


# ── 7. idempotency ────────────────────────────────────────────────────────────

def test_generation_is_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    _activity(db_session, ws.id, integ.id, "github.deploy_key.added", doc_id="dk1")
    s1 = _gen(db_session, ws.id)
    s2 = _gen(db_session, ws.id)
    assert s1["signals_created"] == 1
    assert s2["signals_created"] == 0
    assert s2["signals_skipped"] == 1
    assert len(_signals(db_session, ws.id)) == 1
    _cleanup(db_session, ws.id)


# ── 12. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording_in_output(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    for et in (
        "github.branch_protection.disabled",
        "github.deploy_key.added",
        "github.app.permissions_changed",
        "github.collaborator.added",
    ):
        _activity(db_session, ws.id, integ.id, et, doc_id=uuid.uuid4().hex)
    _gen(db_session, ws.id)
    for s in _signals(db_session, ws.id):
        blob = f"{s.title}\n{s.summary}".lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob, f"forbidden phrase {phrase!r} in: {blob!r}"
        # Positive: calibrated review wording is present.
        assert "may require review" in s.summary.lower()
    _cleanup(db_session, ws.id)


# ── 8 & 9. endpoint scoping ───────────────────────────────────────────────────

def test_list_endpoint_workspace_scoped(client, test_user, db_session):
    # Seed a signal in ANOTHER workspace; caller must not see it.
    other = _new_user(db_session, "other")
    ws_b = _ws(other, db_session)
    integ_b = _integ(db_session, other, ws_b.id)
    _activity(db_session, ws_b.id, integ_b.id, "github.branch_protection.disabled")
    _gen(db_session, ws_b.id)
    try:
        resp = client.get("/security/signals")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0  # caller's own (empty) workspace
        assert body["items"] == []
    finally:
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other)
            db_session.commit()
        except Exception:
            db_session.rollback()


def test_get_endpoint_404_cross_workspace(client, test_user, db_session):
    other = _new_user(db_session, "other")
    ws_b = _ws(other, db_session)
    integ_b = _integ(db_session, other, ws_b.id)
    _activity(db_session, ws_b.id, integ_b.id, "github.deploy_key.added")
    _gen(db_session, ws_b.id)
    sig = _signals(db_session, ws_b.id)[0]
    try:
        resp = client.get(f"/security/signals/{sig.id}")
        assert resp.status_code == 404  # never leaks existence cross-workspace
    finally:
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other)
            db_session.commit()
        except Exception:
            db_session.rollback()


# ── 10 & 11. permissions ──────────────────────────────────────────────────────

def test_generate_requires_admin_role(test_user, db_session):
    # Generation is gated by require_workspace_admin. A member of a workspace is
    # not an admin → 403; a member can still read (member gate passes).
    owner = _new_user(db_session, "owner")
    ws = _ws(owner, db_session)
    _add_member(db_session, ws.id, test_user.id, "member")
    try:
        with pytest.raises(HTTPException) as exc:
            workspace_permission_service.require_workspace_admin(
                ws.id, test_user.id, db_session
            )
        assert exc.value.status_code == 403
        # Member read gate passes (can list).
        member = workspace_permission_service.require_workspace_member(
            ws.id, test_user.id, db_session
        )
        assert member is not None
    finally:
        try:
            db_session.delete(owner)  # cascade removes ws + membership
            db_session.commit()
        except Exception:
            db_session.rollback()


def test_owner_can_generate_and_member_can_list_via_endpoints(client, test_user, db_session):
    # test_user owns their default workspace → can generate AND list.
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    _activity(db_session, ws.id, integ.id, "github.app.permissions_changed")
    try:
        gen = client.post("/security/signals/generate", json={})
        assert gen.status_code == 200
        assert gen.json()["signals_created"] == 1

        lst = client.get("/security/signals?severity=high")
        assert lst.status_code == 200
        body = lst.json()
        assert body["total"] == 1
        assert body["items"][0]["signal_type"] == "app_permissions_change"
        assert body["items"][0]["evidence_level"] == "activity"
    finally:
        _cleanup(db_session, ws.id)
