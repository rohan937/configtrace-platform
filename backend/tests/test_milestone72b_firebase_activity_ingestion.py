"""M72B — Firebase activity/audit ingestion foundation.

Firebase control-plane change activity (Google Cloud Audit Logs) is normalized
into the shared ``security_activity_events`` spine (provider=firebase,
source=audit_log) as evidence for review. Activity ingestion ONLY — no
signals/correlations/demo. These tests assert normalization + event-type mapping,
idempotency, non-fatal permission/unavailable handling, malformed-event skipping,
privacy (no documents, DB data, storage objects, auth users, emails, private
keys, tokens, headers, raw payloads, raw rule source), endpoint admin gating,
workspace scoping, and claim discipline.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import HTTPException

from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.connectors.firebase import FirebaseConnector
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import firebase_activity_ingestion_service as fb_ingest
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "secret leaked", "data leaked", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected",
]
PRIVATE_KEY = "private_key_should_never_store"
ACTOR_EMAIL = "deployer@example.com"
RAW_RULES = "service cloud.firestore { allow read, write: if true; }"


def _entry(insert_id, service, method, *, resource_name="", with_secrets=True, labels=None):
    """Build a raw Cloud Audit Log entry in the shape the normalizer expects."""
    proto = {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "serviceName": service,
        "methodName": method,
        "resourceName": resource_name,
        "authenticationInfo": {"principalEmail": ACTOR_EMAIL},
    }
    if with_secrets:
        # None of these must be traversed/stored by the allowlist gate.
        proto["request"] = {"source": RAW_RULES, "private_key": PRIVATE_KEY}
        proto["response"] = {"rules": RAW_RULES}
    return {
        "insertId": insert_id,
        "timestamp": "2026-06-14T10:00:00Z",
        "resource": {"type": "audited_resource", "labels": labels or {"project_id": "demo-fb"}},
        "protoPayload": proto,
    }


def _patch(monkeypatch, entries=None, *, raise_exc=None):
    def _fake(self, credentials, *, project_id=None, max_events=100, lookback_hours=24):
        if raise_exc is not None:
            raise raise_exc
        return entries or []
    monkeypatch.setattr(FirebaseConnector, "list_activity_events", _fake)


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M72B", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _fb_integ(db, user, ws_id):
    ct, iv = encrypt_credentials({
        "type": "service_account", "project_id": "demo-fb",
        "private_key_id": "x", "private_key": PRIVATE_KEY, "client_email": "x@x.iam",
    })
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="firebase",
                    display_name="firebase", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _rows(db, ws_id):
    return db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id,
        SecurityActivityEvent.provider == "firebase",
        SecurityActivityEvent.source == "audit_log",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _ingest(integ, ws_id, db):
    return fb_ingest.ingest_firebase_activity(integration=integ, workspace_id=ws_id, db=db)


# ── 1. normalize + event-type mapping ─────────────────────────────────────────

def test_normalizes_and_maps_event_types(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _fb_integ(db_session, test_user, ws.id)
    entries = [
        _entry("e1", "firebaserules.googleapis.com", "google.firebase.rules.v1.UpdateRelease",
               resource_name="projects/demo-fb/releases/cloud.firestore"),
        _entry("e2", "firebasedatabase.googleapis.com", "UpdateDatabaseRules",
               resource_name="projects/demo-fb/instances/demo-default"),
        _entry("e3", "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/firebase.storage/demo.appspot.com"),
        _entry("e4", "identitytoolkit.googleapis.com", "UpdateConfig",
               resource_name="projects/demo-fb/config"),
        _entry("e5", "cloudfunctions.googleapis.com", "CreateFunction",
               resource_name="projects/demo-fb/locations/us-central1/functions/api"),
        _entry("e6", "cloudfunctions.googleapis.com", "DeleteFunction",
               resource_name="projects/demo-fb/locations/us-central1/functions/old"),
        _entry("e7", "firebasehosting.googleapis.com", "CreateRelease",
               resource_name="projects/demo-fb/sites/demo/releases/r1"),
        _entry("e8", "firebase.googleapis.com", "CreateWebApp",
               resource_name="projects/demo-fb/webApps/app1"),
        _entry("e9", "mystery.googleapis.com", "DoThing"),  # → project.event fallback
    ]
    _patch(monkeypatch, entries)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "audit_log"
        assert summary["events_inserted"] == 9
        types = {r.event_type for r in _rows(db_session, ws.id)}
        assert {
            "firebase.firestore_rules.updated", "firebase.database_rules.updated",
            "firebase.storage_rules.updated", "firebase.auth_config.updated",
            "firebase.function.created", "firebase.function.deleted",
            "firebase.hosting.updated", "firebase.app.updated",
            "firebase.project.event",
        } <= types
        fn = next(r for r in _rows(db_session, ws.id)
                  if r.event_type == "firebase.function.created")
        assert fn.event_metadata.get("function_name") == "api"
        assert fn.event_metadata.get("service_name") == "cloudfunctions.googleapis.com"
        assert fn.actor_id is None  # principalEmail never stored as actor_id
    finally:
        _cleanup(db_session, ws.id)


# ── 2. malformed events are skipped safely ────────────────────────────────────

def test_malformed_events_skipped(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _fb_integ(db_session, test_user, ws.id)
    entries = [
        _entry("ok1", "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/cloud.firestore"),
        "not-a-dict",                       # not a dict → skip
        {"insertId": "x"},                  # no protoPayload service/method → skip
        {"protoPayload": {}},               # empty proto → skip
        None,                               # None → skip
    ]
    _patch(monkeypatch, entries)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["events_seen"] == 5
        assert summary["events_inserted"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 3. permission / unavailable failures are non-fatal ────────────────────────

def test_permission_failure_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _fb_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, raise_exc=AuthenticationError("denied"))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["attempted"] is True
    assert summary["permission_limited"] is True
    assert summary["succeeded"] is True
    assert summary["events_inserted"] == 0


def test_unavailable_endpoint_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _fb_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, raise_exc=ConnectorError("no logging access", status_code=403))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["succeeded"] is True
    assert summary["permission_limited"] is True
    assert _rows(db_session, ws.id) == []
    assert summary["error_message"] and "limited" in summary["error_message"].lower()


# ── 4. idempotency ────────────────────────────────────────────────────────────

def test_idempotent_ingestion(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _fb_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_entry("dupe", "firebaserules.googleapis.com", "UpdateRelease",
                                resource_name="projects/demo-fb/releases/cloud.firestore")])
    try:
        s1 = _ingest(integ, ws.id, db_session)
        s2 = _ingest(integ, ws.id, db_session)
        assert s1["events_inserted"] == 1
        assert s2["events_inserted"] == 0
        assert s2["events_skipped"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


def test_idempotent_without_id_via_fingerprint(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _fb_integ(db_session, test_user, ws.id)
    e = _entry(None, "firebasehosting.googleapis.com", "CreateRelease",
               resource_name="projects/demo-fb/sites/demo/releases/r1")
    e.pop("insertId", None)
    _patch(monkeypatch, [dict(e), dict(e)])
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["events_inserted"] == 1
        assert len(_rows(db_session, ws.id)) == 1
        assert _rows(db_session, ws.id)[0].provider_event_id.startswith("fp:")
    finally:
        _cleanup(db_session, ws.id)


# ── 5. privacy: no secrets / emails / raw rules / bodies ─────────────────────

def test_no_secrets_emails_or_raw_payloads(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _fb_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [
        _entry("p1", "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/cloud.firestore"),
        _entry("p2", "cloudfunctions.googleapis.com", "UpdateFunction",
               resource_name="projects/demo-fb/locations/us-central1/functions/api"),
    ])
    try:
        _ingest(integ, ws.id, db_session)
        rows = _rows(db_session, ws.id)
        blob = json.dumps([{
            "event_type": r.event_type, "actor_id": r.actor_id,
            "actor_type": r.actor_type, "resource_id": r.resource_id,
            "metadata": r.event_metadata, "raw_ref": r.raw_ref,
        } for r in rows], default=str)
        assert PRIVATE_KEY not in blob
        assert ACTOR_EMAIL not in blob
        assert RAW_RULES not in blob
        for bad in ("private_key", "principalemail", "authorization", "bearer ",
                    "request", "response", "@example.com"):
            assert bad not in blob.lower()
        for r in rows:
            for forbidden_key in ("private_key", "request", "response", "source",
                                  "principalEmail", "payload", "headers"):
                assert forbidden_key not in r.event_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 6. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session, monkeypatch):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _fb_integ(db_session, test_user, ws_a.id)
    _patch(monkeypatch, [_entry("sc1", "firebase.googleapis.com", "UpdateProject")])
    try:
        _ingest(integ_a, ws_a.id, db_session)
        assert len(_rows(db_session, ws_a.id)) == 1
        assert len(_rows(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 7. claim discipline ───────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _fb_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [
        _entry("c1", "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/cloud.firestore"),
        _entry("c2", "identitytoolkit.googleapis.com", "UpdateConfig"),
    ])
    try:
        _ingest(integ, ws.id, db_session)
        blob = json.dumps(
            [{"t": r.event_type, "m": r.event_metadata} for r in _rows(db_session, ws.id)],
            default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 8. endpoint admin gating + member read ────────────────────────────────────

def test_member_cannot_sync(test_user, db_session):
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


def test_owner_can_sync_and_member_can_read_via_endpoint(client, test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _fb_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_entry("ep1", "firebaserules.googleapis.com", "UpdateRelease",
                                resource_name="projects/demo-fb/releases/cloud.firestore")])
    try:
        r = client.post("/security/firebase-activity/sync")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "firebase" and body["source"] == "audit_log"
        assert body["events_inserted"] == 1
        lst = client.get("/security/activity/events?provider=firebase")
        assert lst.status_code == 200
        assert lst.json()["total"] >= 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()


def test_no_active_integration_returns_clean_summary(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    r = client.post("/security/firebase-activity/sync")
    assert r.status_code == 200
    body = r.json()
    assert body["attempted"] is False and body["provider"] == "firebase"
    assert body["error_message"]
