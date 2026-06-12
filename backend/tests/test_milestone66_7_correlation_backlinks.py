"""M66.7 — correlation evidence backlinks (filter correlations by linked object).

Verifies the new ``linked_signal_id`` / ``linked_finding_id`` /
``linked_activity_event_id`` filters on the correlation list — the backbone of
the cross-page evidence backlinks (Signal ↔ Risk ↔ Activity ↔ Correlation).

  1. Filter by linked_signal_id returns the matching correlation.
  2. Filter by linked_finding_id works.
  3. Filter by linked_activity_event_id works.
  4. Cross-workspace correlations are never leaked through the filters.
  5. An invalid UUID filter returns 422.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.services import security_activity_event_service as activity_svc
from app.services import security_finding_service as finding_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services import workspace_service

REPO = "acme/repo"


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
        user_id=user.id, user_display_name=user.display_name or "M66.7", db=db
    )


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"github_token": "x", "repo_owner": "acme", "repo_name": "repo"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="github", display_name="github",
        encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _repo(db, integ, user, slug=REPO):
    r = Resource(
        integration_id=integ.id, user_id=user.id, provider_resource_type="github_repo",
        provider_resource_id=slug, display_name=slug, is_active=True,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _finding(db, ws, integ, res):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key=f"github_webhook_http:{uuid.uuid4().hex[:8]}", severity="high",
        title="webhook risk", resource_id=res.id, description="d",
        evidence={"rule": "github_webhook_http"}, remediation={"summary": "fix"},
    )


def _activity(db, ws_id, integ_id):
    norm = activity_svc.normalize_activity_event(
        provider="github", source="audit_log", event_type="github.webhook.updated",
        occurred_at=datetime.now(timezone.utc), provider_event_id=uuid.uuid4().hex,
        actor_id="mallory", resource_type="repository", resource_id=REPO,
        metadata={"action": "hook.config_changed", "repository": REPO},
    )
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db
    )
    return row


def _seed_correlation(db, user):
    ws = _ws(user, db)
    integ = _integ(db, user, ws.id)
    res = _repo(db, integ, user)
    _finding(db, ws, integ, res)
    _activity(db, ws.id, integ.id)
    corr_svc.generate_github_correlations(workspace_id=ws.id, db=db)
    items, _ = corr_svc.list_correlations(workspace_id=ws.id, db=db)
    return ws, items[0]


def _cleanup(db, ws_id):
    db.query(SecuritySignalCorrelation).filter(SecuritySignalCorrelation.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityIncidentSignal).filter(SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    integ_ids = [i.id for i in db.query(Integration).filter(Integration.workspace_id == ws_id).all()]
    if integ_ids:
        db.query(Resource).filter(Resource.integration_id.in_(integ_ids)).delete(synchronize_session=False)
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(synchronize_session=False)
    db.commit()


# ── 1–3. filters return the matching correlation ──────────────────────────────

def test_filter_by_linked_signal_id(test_user, db_session):
    ws, corr = _seed_correlation(db_session, test_user)
    try:
        items, total = corr_svc.list_correlations(
            workspace_id=ws.id, db=db_session, linked_signal_id=corr.linked_signal_id
        )
        assert total == 1
        assert items[0].id == corr.id
    finally:
        _cleanup(db_session, ws.id)


def test_filter_by_linked_finding_id(test_user, db_session):
    ws, corr = _seed_correlation(db_session, test_user)
    try:
        items, total = corr_svc.list_correlations(
            workspace_id=ws.id, db=db_session, linked_finding_id=corr.linked_finding_id
        )
        assert total == 1
        assert items[0].id == corr.id
    finally:
        _cleanup(db_session, ws.id)


def test_filter_by_linked_activity_event_id(test_user, db_session):
    ws, corr = _seed_correlation(db_session, test_user)
    try:
        items, total = corr_svc.list_correlations(
            workspace_id=ws.id, db=db_session,
            linked_activity_event_id=corr.linked_activity_event_id,
        )
        assert total == 1
        assert items[0].id == corr.id
    finally:
        _cleanup(db_session, ws.id)


# ── 4. cross-workspace is never leaked through a filter ───────────────────────

def test_filter_does_not_leak_cross_workspace(client, test_user, db_session):
    # Another workspace owns the correlation + its linked finding.
    other = _new_user(db_session, "other")
    ws_b, corr_b = _seed_correlation(db_session, other)
    try:
        # Caller is test_user (their own, empty default workspace). Filtering by
        # ws_b's linked finding must NOT return ws_b's correlation.
        resp = client.get(f"/security/correlations?linked_finding_id={corr_b.linked_finding_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["items"] == []

        # Same for signal + activity filters.
        r2 = client.get(f"/security/correlations?linked_signal_id={corr_b.linked_signal_id}")
        assert r2.json()["total"] == 0
        r3 = client.get(
            f"/security/correlations?linked_activity_event_id={corr_b.linked_activity_event_id}"
        )
        assert r3.json()["total"] == 0
    finally:
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other)
            db_session.commit()
        except Exception:
            db_session.rollback()


# ── 5. invalid UUID → 422 ─────────────────────────────────────────────────────

def test_invalid_uuid_filter_returns_422(client, test_user, db_session):
    resp = client.get("/security/correlations?linked_signal_id=not-a-uuid")
    assert resp.status_code == 422


# ── happy-path endpoint backlink ──────────────────────────────────────────────

def test_endpoint_filter_returns_own_correlation(client, test_user, db_session):
    ws, corr = _seed_correlation(db_session, test_user)
    try:
        resp = client.get(f"/security/correlations?linked_finding_id={corr.linked_finding_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["id"] == str(corr.id)
        assert body["items"][0]["linked_activity_event_id"] is not None
    finally:
        _cleanup(db_session, ws.id)
