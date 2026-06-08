"""M61.7 — Security rule enable/disable controls.

  1.  GET settings returns all known rules enabled by default (no rows)
  2.  disabling a valid rule persists; GET returns enabled=false
  3.  re-enabling returns enabled=true
  4.  unknown rule key is rejected (404)
  5.  workspace isolation: one workspace's override does not affect another
  6.  evaluator does not create a finding for a disabled rule
  7.  evaluator does not refresh an existing active finding for a disabled rule
  8.  evaluator does not auto-resolve an active finding merely because disabled
  9.  re-enabling resumes normal create/refresh/resolve behavior
"""

from __future__ import annotations

import uuid

from app.connectors.github_schema import GITHUB_WEBHOOK
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.security_rule_setting import SecurityRuleSetting
from app.models.user import User
from app.services import security_finding_evaluator as evaluator
from app.services import security_finding_service as svc
from app.services import security_rule_settings_service as rulesvc
from app.services import workspace_service
from app.services.security_rule_registry import KNOWN_RULE_KEYS

RULE = "github_webhook_http"


# ── builders ──────────────────────────────────────────────────────────────────


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M61.7", db=db
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


def _res(db, integ, user, rid="acme/widgets"):
    r = Resource(
        integration_id=integ.id, user_id=user.id,
        provider_resource_type="github_repo", provider_resource_id=rid,
        display_name=rid, is_active=True,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _http_webhook(hook_id=1):
    return {
        "record_id": f"acme/widgets#webhook#{hook_id}",
        "record_type": GITHUB_WEBHOOK,
        "name": f"hook #{hook_id}",
        "url": "http://example.com/github-webhook",
        "active": True,
    }


def _https_webhook(hook_id=1):
    r = _http_webhook(hook_id)
    r["url"] = "https://api.example.com/github-webhook"
    return r


def _snap(db, res, integ, user, state):
    from app.models.snapshot import Snapshot

    s = Snapshot(
        resource_id=res.id, integration_id=integ.id, user_id=user.id,
        state=state, content_hash=uuid.uuid4().hex, triggered_by="manual",
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _evaluate(db, ws, integ, res, state):
    snap = _snap(db, res, integ, user=_user_of(integ), state=state)
    return evaluator.evaluate_security_findings_for_resource(
        db=db, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap,
    )


def _user_of(integ):
    class _U:
        id = integ.user_id
    return _U()


def _active(db, ws_id, res_id):
    return (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == ws_id,
            SecurityFinding.resource_id == res_id,
            SecurityFinding.status == "active",
        )
        .all()
    )


def _cleanup(db, ws_id):
    db.query(SecurityRuleSetting).filter(SecurityRuleSetting.workspace_id == ws_id).delete()
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete()
    db.commit()


# ── 1-3. Settings service: defaults, disable, re-enable ───────────────────────


def test_defaults_all_enabled(test_user, db_session):
    ws = _ws(test_user, db_session)
    items = rulesvc.list_effective_settings(ws.id, db_session)
    assert len(items) == len(KNOWN_RULE_KEYS)
    assert all(it["enabled"] for it in items)
    assert all(it["explicit_setting"] is False for it in items)
    _cleanup(db_session, ws.id)


def test_disable_then_reenable(test_user, db_session):
    ws = _ws(test_user, db_session)
    rulesvc.set_rule_enabled(
        workspace_id=ws.id, rule_key=RULE, enabled=False,
        actor_user_id=test_user.id, db=db_session,
    )
    assert RULE in rulesvc.get_disabled_rule_keys(ws.id, db_session)
    eff = rulesvc.get_effective_setting(ws.id, RULE, db_session)
    assert eff["enabled"] is False and eff["explicit_setting"] is True

    rulesvc.set_rule_enabled(
        workspace_id=ws.id, rule_key=RULE, enabled=True,
        actor_user_id=test_user.id, db=db_session,
    )
    assert RULE not in rulesvc.get_disabled_rule_keys(ws.id, db_session)
    assert rulesvc.get_effective_setting(ws.id, RULE, db_session)["enabled"] is True
    _cleanup(db_session, ws.id)


def test_unknown_rule_rejected_service(test_user, db_session):
    ws = _ws(test_user, db_session)
    import pytest

    with pytest.raises(ValueError):
        rulesvc.set_rule_enabled(
            workspace_id=ws.id, rule_key="not_a_real_rule", enabled=False,
            actor_user_id=test_user.id, db=db_session,
        )
    _cleanup(db_session, ws.id)


# ── 5. Workspace isolation ────────────────────────────────────────────────────


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

    rulesvc.set_rule_enabled(
        workspace_id=ws.id, rule_key=RULE, enabled=False,
        actor_user_id=test_user.id, db=db_session,
    )
    assert RULE in rulesvc.get_disabled_rule_keys(ws.id, db_session)
    assert RULE not in rulesvc.get_disabled_rule_keys(ows.id, db_session)  # isolated

    _cleanup(db_session, ws.id)
    _cleanup(db_session, ows.id)
    db_session.delete(other)
    db_session.commit()


# ── 6. Disabled rule creates no finding ───────────────────────────────────────


def test_disabled_rule_creates_no_finding(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    rulesvc.set_rule_enabled(
        workspace_id=ws.id, rule_key=RULE, enabled=False,
        actor_user_id=test_user.id, db=db_session,
    )

    summary = _evaluate(db_session, ws, integ, res, [_http_webhook(1)])
    assert _active(db_session, ws.id, res.id) == []
    assert summary["events"] == []
    _cleanup(db_session, ws.id)


# ── 7 & 8. Existing active finding: not refreshed, not auto-resolved ──────────


def test_disabled_rule_does_not_refresh_or_resolve(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    # Create an active finding while the rule is ENABLED.
    _evaluate(db_session, ws, integ, res, [_http_webhook(1)])
    actives = _active(db_session, ws.id, res.id)
    assert len(actives) == 1
    fid = actives[0].id
    last_seen_before = actives[0].last_seen_at

    # Disable the rule, then evaluate again with the SAME risky state present.
    rulesvc.set_rule_enabled(
        workspace_id=ws.id, rule_key=RULE, enabled=False,
        actor_user_id=test_user.id, db=db_session,
    )
    _evaluate(db_session, ws, integ, res, [_http_webhook(1)])

    still = db_session.get(SecurityFinding, fid)
    assert still is not None
    assert still.status == "active"  # (8) not auto-resolved
    assert still.last_seen_at == last_seen_before  # (7) not refreshed
    assert still.resolved_at is None
    _cleanup(db_session, ws.id)


# ── 9. Re-enabling resumes normal behavior ────────────────────────────────────


def test_reenable_resumes_creation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    rulesvc.set_rule_enabled(
        workspace_id=ws.id, rule_key=RULE, enabled=False,
        actor_user_id=test_user.id, db=db_session,
    )
    _evaluate(db_session, ws, integ, res, [_http_webhook(1)])
    assert _active(db_session, ws.id, res.id) == []

    rulesvc.set_rule_enabled(
        workspace_id=ws.id, rule_key=RULE, enabled=True,
        actor_user_id=test_user.id, db=db_session,
    )
    _evaluate(db_session, ws, integ, res, [_http_webhook(1)])
    assert len(_active(db_session, ws.id, res.id)) == 1
    _cleanup(db_session, ws.id)


# ── API-level: defaults, disable/enable, unknown 404, isolation ───────────────


def test_api_settings_defaults_and_patch(client, test_user, db_session):
    ws = _ws(test_user, db_session)

    resp = client.get("/security/rules/settings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == len(KNOWN_RULE_KEYS)
    assert all(it["enabled"] for it in body["items"])

    patch = client.patch(f"/security/rules/settings/{RULE}", json={"enabled": False})
    assert patch.status_code == 200
    assert patch.json()["enabled"] is False
    assert patch.json()["explicit_setting"] is True

    # Reflected in the list.
    again = client.get("/security/rules/settings")
    row = next(i for i in again.json()["items"] if i["rule_key"] == RULE)
    assert row["enabled"] is False

    # Re-enable.
    patch2 = client.patch(f"/security/rules/settings/{RULE}", json={"enabled": True})
    assert patch2.status_code == 200 and patch2.json()["enabled"] is True
    _cleanup(db_session, ws.id)


def test_api_unknown_rule_404(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    resp = client.patch("/security/rules/settings/not_a_real_rule", json={"enabled": False})
    assert resp.status_code == 404
    _cleanup(db_session, ws.id)
