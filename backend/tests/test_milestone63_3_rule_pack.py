"""M63.3 — Security Rule pack / versioning.

  1.  pack registry covers exactly the known rule keys.
  2.  GET /security/rules/pack returns version + rule_count + providers + rules.
  3.  finding create persists rule_pack_name/version/rule_version.
  4.  active refresh keeps/updates rule pack metadata.
  5.  demo findings include pack metadata.
  6.  API finding response includes the new fields.
  7.  migration upgrade works (columns exist / queryable).
"""

from __future__ import annotations

import uuid

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.services import security_demo_data_service as demo
from app.services import security_finding_service as svc
from app.services import security_rule_pack as pack
from app.services import workspace_service
from app.services.security_rule_registry import KNOWN_RULE_KEYS


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M63.3", db=db
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


def _cleanup(db, ws_id):
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete(
        synchronize_session=False
    )
    db.commit()


# ── 1. Registry covers all known rule keys ────────────────────────────────────


def test_pack_covers_known_rule_keys():
    rules = pack.list_pack_rules()
    keys = {r["rule_key"] for r in rules}
    assert keys == set(KNOWN_RULE_KEYS)
    # Every rule carries the required manifest fields.
    for r in rules:
        assert r["provider"]
        assert r["rule_version"] == pack.DEFAULT_RULE_VERSION
        assert r["introduced_in"] == pack.DEFAULT_INTRODUCED_IN
        assert r["status"] == "active"
        assert r["confidence"] in {"high", "medium", "low"}
        assert r["severity"]
        assert r["category"]


# ── 2. GET /security/rules/pack ───────────────────────────────────────────────


def test_get_rule_pack_endpoint(client):
    resp = client.get("/security/rules/pack")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == pack.SECURITY_RULE_PACK_NAME
    assert body["version"] == pack.SECURITY_RULE_PACK_VERSION
    assert body["rule_count"] == len(KNOWN_RULE_KEYS)
    assert len(body["rules"]) == len(KNOWN_RULE_KEYS)
    assert "github" in body["providers"]
    assert body["released_at"] == pack.SECURITY_RULE_PACK_RELEASED_AT


# ── 3 & 4. Finding create + refresh persist pack metadata ─────────────────────


def test_create_and_refresh_persist_pack(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    created = svc.upsert_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=integ.id,
        provider="github", finding_key="github_webhook_http:acme/x#webhook#1",
        severity="critical", title="GitHub webhook uses plain HTTP",
        resource_id=res.id,
    )
    assert created.rule_pack_name == pack.SECURITY_RULE_PACK_NAME
    assert created.rule_pack_version == pack.SECURITY_RULE_PACK_VERSION
    assert created.rule_version == pack.DEFAULT_RULE_VERSION

    # Refresh the same active finding — metadata stays stamped.
    refreshed = svc.upsert_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=integ.id,
        provider="github", finding_key="github_webhook_http:acme/x#webhook#1",
        severity="high", title="GitHub webhook uses plain HTTP",
        resource_id=res.id,
    )
    assert refreshed.id == created.id  # same row (refresh, not create)
    assert refreshed.rule_pack_name == pack.SECURITY_RULE_PACK_NAME
    assert refreshed.rule_pack_version == pack.SECURITY_RULE_PACK_VERSION
    assert refreshed.rule_version == pack.DEFAULT_RULE_VERSION
    _cleanup(db_session, ws.id)


# ── 5. Demo findings include pack metadata ────────────────────────────────────


def test_demo_findings_have_pack_metadata(test_user, db_session):
    ws = _ws(test_user, db_session)
    demo.clear(workspace_id=ws.id, db=db_session)
    demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    rows = (
        db_session.query(SecurityFinding)
        .filter(SecurityFinding.workspace_id == ws.id)
        .all()
    )
    assert rows, "demo seed should create findings"
    for f in rows:
        assert f.rule_pack_name == pack.SECURITY_RULE_PACK_NAME
        assert f.rule_pack_version == pack.SECURITY_RULE_PACK_VERSION
        assert f.rule_version == pack.DEFAULT_RULE_VERSION
    demo.clear(workspace_id=ws.id, db=db_session)


# ── 6 & 7. API response includes fields (columns exist post-migration) ────────


def test_api_finding_includes_pack_fields(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = svc.upsert_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=integ.id,
        provider="github", finding_key="github_webhook_http:acme/y#webhook#1",
        severity="critical", title="GitHub webhook uses plain HTTP",
        resource_id=res.id,
    )
    resp = client.get(f"/security/findings/{f.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule_pack_name"] == pack.SECURITY_RULE_PACK_NAME
    assert body["rule_pack_version"] == pack.SECURITY_RULE_PACK_VERSION
    assert body["rule_version"] == pack.DEFAULT_RULE_VERSION
    _cleanup(db_session, ws.id)
