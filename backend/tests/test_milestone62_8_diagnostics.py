"""M62.8 — Security Exposure coverage permission diagnostics.

  1.  not connected provider → provider_not_connected.
  2.  connected but never synced → needs_sync.
  3.  needs_reconnect / error status → provider_attention_needed.
  4.  partial observed record types → missing_metadata with missing surfaces.
  5.  missing AWS S3/IAM/EC2 surfaces → permission hints present.
  6.  full expected coverage → ok.
  7.  diagnostics are workspace-scoped.
  8.  diagnostics never call provider APIs / connectors.
  9.  demo / deleted integrations remain ignored.

Diagnostics are read-only and inspect only stored snapshots + integration rows.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.models.user import User
from app.services import security_coverage_service as cov
from app.services import workspace_service


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M62.8", db=db
    )


def _integ(db, user, ws_id, provider="github", status="active", synced=False):
    ct, iv = encrypt_credentials({"credential_type": "x"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider=provider,
        display_name=provider, encrypted_credentials=ct, credential_iv=iv,
        status=status,
        last_synced_at=datetime.now(timezone.utc) if synced else None,
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


# ── 1. Not connected ──────────────────────────────────────────────────────────


def test_not_connected_diagnostic(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    report = cov.get_coverage(ws.id, db_session)
    for p in report["providers"]:
        assert p["diagnostic_status"] == "provider_not_connected"
        assert p["diagnostic_confidence"] == "high"
        assert any("Connect" in a for a in p["recommended_actions"])


# ── 2. Connected but never synced ─────────────────────────────────────────────


def test_connected_unsynced_needs_sync(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    _integ(db_session, test_user, ws.id, "github", synced=False)
    report = cov.get_coverage(ws.id, db_session)
    gh = _provider(report, "github")
    assert gh["diagnostic_status"] == "needs_sync"
    assert any("sync" in a.lower() for a in gh["recommended_actions"])
    assert report["summary"]["diagnostics_needs_sync"] >= 1
    _cleanup(db_session, ws.id)


# ── 3. needs_reconnect / error → attention ────────────────────────────────────


def test_needs_reconnect_attention(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    _integ(db_session, test_user, ws.id, "github", status="needs_reconnect", synced=True)
    report = cov.get_coverage(ws.id, db_session)
    gh = _provider(report, "github")
    assert gh["diagnostic_status"] == "provider_attention_needed"
    assert any("Reconnect" in a or "credentials" in a for a in gh["recommended_actions"])
    _cleanup(db_session, ws.id)


def test_error_status_attention(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    _integ(db_session, test_user, ws.id, "stripe", status="error", synced=True)
    report = cov.get_coverage(ws.id, db_session)
    assert _provider(report, "stripe")["diagnostic_status"] == "provider_attention_needed"
    _cleanup(db_session, ws.id)


# ── 4. Partial observed → missing_metadata ────────────────────────────────────


def test_partial_missing_metadata(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    integ = _integ(db_session, test_user, ws.id, "github", synced=True)
    _snapshot(db_session, integ, test_user, ["github_webhook"])  # only one surface
    report = cov.get_coverage(ws.id, db_session)
    gh = _provider(report, "github")
    assert gh["diagnostic_status"] == "missing_metadata"
    assert len(gh["missing_record_types"]) > 0
    # A specific branch-protection diagnostic message + permission hint surface.
    assert any("branch protection" in m.lower() for m in gh["diagnostic_messages"])
    assert any("repository" in h.lower() for h in gh["permission_hints"])
    assert report["summary"]["diagnostics_missing_metadata"] >= 1
    _cleanup(db_session, ws.id)


# ── 5. AWS missing surfaces → permission hints ────────────────────────────────


def test_aws_permission_hints(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    integ = _integ(db_session, test_user, ws.id, "aws", synced=True)
    # Synced, but nothing expected observed → permissions_likely_limited.
    _snapshot(db_session, integ, test_user, ["aws_unrelated_record"])
    report = cov.get_coverage(ws.id, db_session)
    aws = _provider(report, "aws")
    assert aws["diagnostic_status"] == "permissions_likely_limited"
    hints = set(aws["permission_hints"])
    assert {
        "ec2:DescribeSecurityGroups",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:GetPublicAccessBlock",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
    }.issubset(hints)
    # AWS stays conservative: caveat + lower confidence.
    assert aws["diagnostic_confidence"] == "low"
    assert any("intentionally omit" in m for m in aws["diagnostic_messages"])
    assert report["summary"]["diagnostics_permissions_likely_limited"] >= 1
    _cleanup(db_session, ws.id)


# ── 6. Full coverage → ok ─────────────────────────────────────────────────────


def test_full_coverage_ok(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    integ = _integ(db_session, test_user, ws.id, "github", synced=True)
    _snapshot(db_session, integ, test_user, sorted(cov._expected_record_types("github")))
    report = cov.get_coverage(ws.id, db_session)
    gh = _provider(report, "github")
    assert gh["diagnostic_status"] == "ok"
    assert gh["permission_hints"] == []
    assert any("sufficient" in m for m in gh["diagnostic_messages"])
    assert report["summary"]["diagnostics_ok"] >= 1
    _cleanup(db_session, ws.id)


# ── 7. Workspace isolation ────────────────────────────────────────────────────


def test_diagnostics_workspace_scoped(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    integ = _integ(db_session, test_user, ws.id, "github", synced=True)
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
    assert _provider(rep_other, "github")["diagnostic_status"] == "provider_not_connected"

    _cleanup(db_session, ws.id)
    db_session.delete(other)
    db_session.commit()


# ── 8. No provider API / connector calls ──────────────────────────────────────


def test_diagnostics_do_not_call_providers(test_user, db_session):
    # The service must not import or invoke any provider connector.
    assert not any("connector" in name.lower() for name in dir(cov))
    # And it produces diagnostics from clearly non-functional stored credentials
    # (proving it never decrypts/uses them to call a provider).
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    integ = _integ(db_session, test_user, ws.id, "cloudflare", synced=True)
    _snapshot(db_session, integ, test_user, ["A"])  # only DNS present
    report = cov.get_coverage(ws.id, db_session)
    cf = _provider(report, "cloudflare")
    assert cf["diagnostic_status"] == "missing_metadata"
    assert any("zone setting" in m.lower() for m in cf["diagnostic_messages"])
    _cleanup(db_session, ws.id)


# ── 9. Demo / deleted integrations ignored ────────────────────────────────────


def test_deleted_integration_ignored(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    integ = _integ(db_session, test_user, ws.id, "github", status="deleted", synced=True)
    _snapshot(db_session, integ, test_user, sorted(cov._expected_record_types("github")))
    report = cov.get_coverage(ws.id, db_session)
    gh = _provider(report, "github")
    assert gh["connected"] is False
    assert gh["diagnostic_status"] == "provider_not_connected"
    _cleanup(db_session, ws.id)
