"""M66.2 — GitHub audit-log ingestion foundation (security_activity_events).

Covers the activity-event data spine for the FUTURE Incident Signals product.
These tests assert storage/normalization/privacy/idempotency/scoping only — there
is NO breach/attacker/compromise detection in this milestone.

  1. Model/table create + query.
  2. Metadata sanitizer drops secrets/tokens/raw payloads/nested values.
  3. Idempotent upsert (same provider_event_id → skipped).
  4. Deterministic fingerprint fallback when provider_event_id is missing.
  5. GitHub audit-log permission failure is non-fatal (→ permission_limited).
  6. Event normalization maps GitHub actions → stable event_type; unknown skipped.
  7. Workspace scoping (service list never crosses workspaces).
  8. GET /security/activity/events does not leak across workspaces.
  9. Source IP is stored only as a hash; the raw IP never appears.
 10. POST /security/activity/sync permission gating + non-fatal summary.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import github_activity_ingestion_service as ingest
from app.services import security_activity_event_service as activity_svc
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
        user_id=user.id, user_display_name=user.display_name or "M66.2", db=db
    )


def _integ_pat(db, user, ws_id):
    """A PAT-style GitHub integration whose creds resolve without minting."""
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


def _cleanup(db, ws_id):
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


def _norm(**over):
    """Build a normalized event dict via the service for upsert tests."""
    base = dict(
        provider="github",
        source="audit_log",
        event_type="github.branch_protection.disabled",
        occurred_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        provider_event_id="doc-1",
        actor_id="alice",
        resource_type="repository",
        resource_id="acme/repo",
        metadata={"action": "protected_branch.destroy"},
    )
    base.update(over)
    return activity_svc.normalize_activity_event(**base)


# ── 1. model/table ────────────────────────────────────────────────────────────

def test_model_create_and_query(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ_pat(db_session, test_user, ws.id)
    outcome, row = activity_svc.upsert_activity_event(
        workspace_id=ws.id, integration_id=integ.id, normalized=_norm(), db=db_session
    )
    assert outcome == "inserted"
    assert row.id is not None
    fetched = db_session.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.id == row.id
    ).first()
    assert fetched.event_type == "github.branch_protection.disabled"
    assert fetched.provider == "github"
    _cleanup(db_session, ws.id)


# ── 2. sanitizer ──────────────────────────────────────────────────────────────

def test_sanitizer_drops_secrets_and_nested():
    raw = {
        "action": "hook.create",       # allowlisted scalar → kept
        "github_token": "ghp_supersecret",   # not allowlisted → dropped
        "password": "hunter2",               # not allowlisted → dropped
        "payload": {"body": "raw"},          # not allowlisted + nested → dropped
        "nested": {"k": "v"},                # not allowlisted + nested → dropped
        "headers": ["Authorization: Bearer x"],  # not allowlisted + list → dropped
    }
    clean = activity_svc.sanitize_activity_metadata(raw)
    assert clean == {"action": "hook.create"}
    assert "github_token" not in clean and "password" not in clean
    assert "payload" not in clean and "headers" not in clean


def test_sanitizer_truncates_long_strings():
    clean = activity_svc.sanitize_activity_metadata({"action": "a" * 5000})
    assert len(clean["action"]) == activity_svc.MAX_STR_LEN


# ── 3. idempotency ────────────────────────────────────────────────────────────

def test_upsert_is_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ_pat(db_session, test_user, ws.id)
    o1, r1 = activity_svc.upsert_activity_event(
        workspace_id=ws.id, integration_id=integ.id, normalized=_norm(), db=db_session
    )
    o2, r2 = activity_svc.upsert_activity_event(
        workspace_id=ws.id, integration_id=integ.id, normalized=_norm(), db=db_session
    )
    assert o1 == "inserted"
    assert o2 == "skipped"
    assert r1.id == r2.id
    count = db_session.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws.id
    ).count()
    assert count == 1
    _cleanup(db_session, ws.id)


# ── 4. fingerprint fallback ───────────────────────────────────────────────────

def test_fingerprint_when_no_provider_event_id(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ_pat(db_session, test_user, ws.id)
    n = _norm(provider_event_id=None)
    assert n["provider_event_id"].startswith("fp:")
    # Same inputs → same fingerprint → idempotent.
    o1, _ = activity_svc.upsert_activity_event(
        workspace_id=ws.id, integration_id=integ.id, normalized=n, db=db_session
    )
    o2, _ = activity_svc.upsert_activity_event(
        workspace_id=ws.id, integration_id=integ.id, normalized=_norm(provider_event_id=None), db=db_session
    )
    assert (o1, o2) == ("inserted", "skipped")
    _cleanup(db_session, ws.id)


# ── 5. permission failure is non-fatal ────────────────────────────────────────

def test_ingestion_permission_denied_is_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _integ_pat(db_session, test_user, ws.id)

    def _raise(self, credentials, **kw):
        raise AuthenticationError("no audit access", status_code=403)

    monkeypatch.setattr(
        "app.services.github_activity_ingestion_service.GitHubConnector.list_audit_log_events",
        _raise,
    )
    summary = ingest.ingest_github_activity(
        integration=integ, workspace_id=ws.id, db=db_session
    )
    assert summary["attempted"] is True
    assert summary["permission_limited"] is True
    assert summary["events_inserted"] == 0
    _cleanup(db_session, ws.id)


def test_ingestion_404_is_permission_limited(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _integ_pat(db_session, test_user, ws.id)

    def _raise(self, credentials, **kw):
        raise ConnectorError("no org audit log", status_code=404)

    monkeypatch.setattr(
        "app.services.github_activity_ingestion_service.GitHubConnector.list_audit_log_events",
        _raise,
    )
    summary = ingest.ingest_github_activity(
        integration=integ, workspace_id=ws.id, db=db_session
    )
    assert summary["permission_limited"] is True
    _cleanup(db_session, ws.id)


# ── 6. normalization + happy-path ingestion ───────────────────────────────────

_AUDIT_ITEMS = [
    {
        "_document_id": "d1",
        "action": "protected_branch.destroy",
        "actor": "mallory",
        "repo": "acme/repo",
        "@timestamp": 1_780_000_000_000,
        "actor_ip": "203.0.113.7",
    },
    {
        "_document_id": "d2",
        "action": "deploy_key.create",
        "actor": "alice",
        "repo": "acme/repo",
        "@timestamp": 1_780_000_100_000,
    },
    {
        "_document_id": "d3",
        "action": "some.unmapped.action",   # not allowlisted → skipped
        "actor": "bob",
        "repo": "acme/repo",
    },
]


def test_normalize_maps_known_actions_and_skips_unknown():
    n1 = ingest.normalize_github_audit_item(_AUDIT_ITEMS[0])
    assert n1["event_type"] == "github.branch_protection.disabled"
    assert n1["actor_id"] == "mallory"
    assert n1["resource_id"] == "acme/repo"
    n3 = ingest.normalize_github_audit_item(_AUDIT_ITEMS[2])
    assert n3 is None  # unmapped action is skipped


def test_ingestion_happy_path_and_idempotent(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _integ_pat(db_session, test_user, ws.id)

    def _items(self, credentials, **kw):
        return list(_AUDIT_ITEMS)

    monkeypatch.setattr(
        "app.services.github_activity_ingestion_service.GitHubConnector.list_audit_log_events",
        _items,
    )
    s1 = ingest.ingest_github_activity(integration=integ, workspace_id=ws.id, db=db_session)
    assert s1["succeeded"] is True
    assert s1["events_seen"] == 3
    assert s1["events_inserted"] == 2          # only the 2 allowlisted actions
    assert s1["events_updated_or_skipped"] == 0

    # Re-run → all skipped (idempotent).
    s2 = ingest.ingest_github_activity(integration=integ, workspace_id=ws.id, db=db_session)
    assert s2["events_inserted"] == 0
    assert s2["events_updated_or_skipped"] == 2
    _cleanup(db_session, ws.id)


# ── 9. source IP is hashed, never raw ─────────────────────────────────────────

def test_source_ip_is_hashed_never_raw(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _integ_pat(db_session, test_user, ws.id)

    def _items(self, credentials, **kw):
        return [_AUDIT_ITEMS[0]]   # has actor_ip 203.0.113.7

    monkeypatch.setattr(
        "app.services.github_activity_ingestion_service.GitHubConnector.list_audit_log_events",
        _items,
    )
    ingest.ingest_github_activity(integration=integ, workspace_id=ws.id, db=db_session)
    row = db_session.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws.id
    ).first()
    assert row.source_ip_hash is not None
    assert row.source_ip_hash != "203.0.113.7"
    # The raw IP must not appear anywhere in the stored row.
    blob = "|".join(
        str(x) for x in [row.source_ip_hash, row.actor_id, row.resource_id, row.event_metadata, row.raw_ref]
    )
    assert "203.0.113.7" not in blob
    _cleanup(db_session, ws.id)


# ── 7. workspace scoping (service) ────────────────────────────────────────────

def test_list_is_workspace_scoped(test_user, db_session):
    # test_user's workspace gets an event…
    ws_a = _ws(test_user, db_session)
    integ_a = _integ_pat(db_session, test_user, ws_a.id)
    activity_svc.upsert_activity_event(
        workspace_id=ws_a.id, integration_id=integ_a.id, normalized=_norm(), db=db_session
    )
    # …a different user's workspace gets its own event.
    other = _new_user(db_session, "other")
    ws_b = _ws(other, db_session)
    integ_b = _integ_pat(db_session, other, ws_b.id)
    activity_svc.upsert_activity_event(
        workspace_id=ws_b.id, integration_id=integ_b.id,
        normalized=_norm(provider_event_id="doc-b"), db=db_session
    )

    items_a, total_a = activity_svc.list_activity_events(workspace_id=ws_a.id, db=db_session)
    assert total_a == 1
    assert all(ev.workspace_id == ws_a.id for ev in items_a)

    _cleanup(db_session, ws_a.id)
    _cleanup(db_session, ws_b.id)
    try:
        db_session.delete(other)
        db_session.commit()
    except Exception:
        db_session.rollback()


# ── 8 & 10. endpoints: scoping + permission gating ────────────────────────────

def test_get_events_endpoint_scoped_to_caller(client, test_user, db_session):
    # Seed an event in ANOTHER workspace; caller must not see it.
    other = _new_user(db_session, "other")
    ws_b = _ws(other, db_session)
    integ_b = _integ_pat(db_session, other, ws_b.id)
    activity_svc.upsert_activity_event(
        workspace_id=ws_b.id, integration_id=integ_b.id, normalized=_norm(), db=db_session
    )
    try:
        resp = client.get("/security/activity/events")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0   # caller's own (empty) workspace, not ws_b
        assert body["items"] == []
    finally:
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other)
            db_session.commit()
        except Exception:
            db_session.rollback()


def test_sync_endpoint_no_integration_returns_summary(client, test_user, db_session):
    # Caller is owner of their default workspace; no GitHub integration exists.
    resp = client.post("/security/activity/sync", json={})
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "github"
    assert body["attempted"] is False
    assert body["succeeded"] is False
    assert "No active GitHub integration" in (body["error_message"] or "")
