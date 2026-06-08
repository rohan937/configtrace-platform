"""M62.3 — Security Exposure coverage quality.

  1.  no integrations → every provider not_connected
  2.  connected but unsynced → not_synced
  3.  snapshot with all expected record types → good coverage
  4.  snapshot missing some expected record types → limited coverage
  5.  disabled rule count reflected per provider
  6.  workspace isolation
  7.  coverage reads stored snapshots only (observed == stored state)
  8.  deleted integrations are ignored
"""

from __future__ import annotations

import uuid

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.models.user import User
from app.services import security_coverage_service as cov
from app.services import security_rule_settings_service as rulesvc
from app.services import workspace_service


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M62.3", db=db
    )


def _integ(db, user, ws_id, provider="github", status="active"):
    ct, iv = encrypt_credentials({"credential_type": "x"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider=provider,
        display_name=provider, encrypted_credentials=ct, credential_iv=iv,
        status=status, last_synced_at=None,
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _snapshot(db, integ, user, record_types):
    res = Resource(
        integration_id=integ.id, user_id=user.id,
        provider_resource_type=f"{integ.provider}_resource",
        provider_resource_id=f"r-{uuid.uuid4().hex[:8]}",
        display_name="res", is_active=True,
    )
    db.add(res)
    db.commit()
    db.refresh(res)
    snap = Snapshot(
        resource_id=res.id, integration_id=integ.id, user_id=user.id,
        state=[{"record_type": rt} for rt in record_types],
        content_hash=uuid.uuid4().hex, triggered_by="manual",
    )
    db.add(snap)
    db.commit()
    return res, snap


def _provider(report, name):
    return next(p for p in report["providers"] if p["provider"] == name)


def _cleanup(db, ws_id):
    integ_ids = [
        i.id for i in db.query(Integration).filter(Integration.workspace_id == ws_id).all()
    ]
    if integ_ids:
        res_ids = [
            r.id for r in db.query(Resource).filter(Resource.integration_id.in_(integ_ids)).all()
        ]
        if res_ids:
            db.query(Snapshot).filter(Snapshot.resource_id.in_(res_ids)).delete(synchronize_session=False)
            db.query(Resource).filter(Resource.id.in_(res_ids)).delete(synchronize_session=False)
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(synchronize_session=False)
    db.commit()


# ── 1. No integrations ────────────────────────────────────────────────────────


def test_no_integrations_all_not_connected(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    report = cov.get_coverage(ws.id, db_session)
    assert len(report["providers"]) == len(cov.PROVIDERS)
    assert all(p["coverage_status"] == "not_connected" for p in report["providers"])
    assert report["summary"]["connected_providers"] == 0
    assert report["summary"]["not_connected"] == len(cov.PROVIDERS)


# ── 2. Connected but unsynced ─────────────────────────────────────────────────


def test_connected_unsynced(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    _integ(db_session, test_user, ws.id, "github")
    report = cov.get_coverage(ws.id, db_session)
    gh = _provider(report, "github")
    assert gh["connected"] is True
    assert gh["coverage_status"] == "not_synced"
    assert report["summary"]["connected_providers"] == 1
    _cleanup(db_session, ws.id)


# ── 3 & 7. Good coverage (all expected observed) ──────────────────────────────


def test_good_coverage(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    integ = _integ(db_session, test_user, ws.id, "github")
    expected = sorted(cov._expected_record_types("github"))
    _snapshot(db_session, integ, test_user, expected)
    report = cov.get_coverage(ws.id, db_session)
    gh = _provider(report, "github")
    assert gh["coverage_status"] == "good"
    # Reads stored snapshot only — observed equals the stored state record types.
    assert set(expected).issubset(set(gh["observed_record_types"]))
    assert gh["missing_record_types"] == []
    assert all(r["supported"] for r in gh["rules"])
    assert report["summary"]["good_coverage"] == 1
    _cleanup(db_session, ws.id)


# ── 4. Limited coverage (some expected missing) ───────────────────────────────


def test_limited_coverage(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    integ = _integ(db_session, test_user, ws.id, "github")
    _snapshot(db_session, integ, test_user, ["github_webhook"])  # only one surface
    report = cov.get_coverage(ws.id, db_session)
    gh = _provider(report, "github")
    assert gh["coverage_status"] == "limited"
    assert "github_webhook" in gh["observed_record_types"]
    assert len(gh["missing_record_types"]) > 0
    # The webhook rule is supported; branch-protection rules are not.
    supported = {r["rule_key"]: r["supported"] for r in gh["rules"]}
    assert supported["github_webhook_http"] is True
    assert supported["github_branch_protection_missing"] is False
    assert report["summary"]["limited_coverage"] == 1
    _cleanup(db_session, ws.id)


# ── 5. Disabled rule count reflected ──────────────────────────────────────────


def test_disabled_rule_count(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    _integ(db_session, test_user, ws.id, "github")
    rulesvc.set_rule_enabled(
        workspace_id=ws.id, rule_key="github_webhook_http", enabled=False,
        actor_user_id=test_user.id, db=db_session,
    )
    report = cov.get_coverage(ws.id, db_session)
    gh = _provider(report, "github")
    assert gh["disabled_rules"] == 1
    assert gh["active_rules"] == gh["supported_rules"] - 1
    assert report["summary"]["disabled_rules"] >= 1
    disabled = {r["rule_key"]: r["enabled"] for r in gh["rules"]}
    assert disabled["github_webhook_http"] is False
    db_session.execute(
        __import__("sqlalchemy").text(
            "DELETE FROM security_rule_settings WHERE workspace_id = :w"
        ),
        {"w": str(ws.id)},
    )
    db_session.commit()
    _cleanup(db_session, ws.id)


# ── 6. Workspace isolation ────────────────────────────────────────────────────


def test_workspace_isolation(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    integ = _integ(db_session, test_user, ws.id, "github")
    _snapshot(db_session, integ, test_user, sorted(cov._expected_record_types("github")))

    other = User(
        clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
        email=f"other_{uuid.uuid4().hex[:8]}@configtrace.test",
        display_name="Other",
    )
    db_session.add(other)
    db_session.commit()
    db_session.refresh(other)
    ows = _ws(other, db_session)

    rep_other = cov.get_coverage(ows.id, db_session)
    assert _provider(rep_other, "github")["coverage_status"] == "not_connected"

    _cleanup(db_session, ws.id)
    db_session.delete(other)
    db_session.commit()


# ── 8. Deleted integrations ignored ───────────────────────────────────────────


def test_deleted_integration_ignored(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    integ = _integ(db_session, test_user, ws.id, "github", status="deleted")
    _snapshot(db_session, integ, test_user, sorted(cov._expected_record_types("github")))
    report = cov.get_coverage(ws.id, db_session)
    gh = _provider(report, "github")
    assert gh["connected"] is False
    assert gh["coverage_status"] == "not_connected"
    _cleanup(db_session, ws.id)


# ── API-level ─────────────────────────────────────────────────────────────────


def test_api_coverage(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    resp = client.get("/security/coverage")
    assert resp.status_code == 200
    body = resp.json()
    assert "providers" in body and "summary" in body
    assert len(body["providers"]) == len(cov.PROVIDERS)
    _cleanup(db_session, ws.id)
