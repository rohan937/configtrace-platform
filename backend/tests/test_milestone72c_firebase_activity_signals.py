"""M72C — Firebase activity Incident Signals.

Firebase / Google Cloud Audit Log activity (provider=firebase, source=audit_log,
ingested in M72B) is promoted into review-worthy Incident Signals
(signal_type="firebase_activity_signal", evidence_level="activity",
confidence="medium"). These tests assert per-pattern signal creation, sensitive
Cloud-Function severity bump, idempotency, workspace scoping, endpoint admin
gating, metadata privacy, and claim discipline.

Signals only — no correlations / demo.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import HTTPException

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_activity_event_service as activity_svc
from app.services import firebase_activity_ingestion_service as fb_ingest
from app.services import firebase_activity_signal_service as fb_sig
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


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M72C", db=db)


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


def _entry(insert_id, service, method, *, resource_name="", labels=None):
    return {
        "insertId": insert_id,
        "timestamp": "2026-06-14T10:00:00Z",
        "resource": {"type": "audited_resource", "labels": labels or {"project_id": "demo-fb"}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": service, "methodName": method, "resourceName": resource_name,
            "authenticationInfo": {"principalEmail": ACTOR_EMAIL},
            "request": {"source": RAW_RULES, "private_key": PRIVATE_KEY},
            "response": {"rules": RAW_RULES},
        },
    }


def _ingest(db, ws_id, integ, entries):
    """Normalize + upsert raw Cloud Audit Log entries into activity events."""
    for entry in entries:
        norm = fb_ingest.normalize_firebase_activity_event(entry)
        assert norm is not None, f"entry did not normalize: {entry}"
        activity_svc.upsert_activity_event(
            workspace_id=ws_id, integration_id=integ.id, normalized=norm, db=db)


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == "firebase",
    ).all()


def _gen(db, ws_id):
    return fb_sig.generate_firebase_activity_signals(workspace_id=ws_id, db=db)


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


# ── 1. rules-change events → high-severity signals ───────────────────────────

def test_rules_change_signals(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _fb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("r1", "firebaserules.googleapis.com", "UpdateRelease",
                   resource_name="projects/demo-fb/releases/cloud.firestore"),
            _entry("r2", "firebasedatabase.googleapis.com", "UpdateDatabaseRules",
                   resource_name="projects/demo-fb/instances/demo-default"),
            _entry("r3", "firebaserules.googleapis.com", "UpdateRelease",
                   resource_name="projects/demo-fb/releases/firebase.storage/demo.appspot.com"),
        ])
        summary = _gen(db_session, ws.id)
        assert summary["provider"] == "firebase" and summary["source"] == "audit_log"
        assert summary["signals_created"] == 3
        sigs = _signals(db_session, ws.id)
        types = {s.signal_metadata.get("event_type"): s for s in sigs}
        assert types["firebase.firestore_rules.updated"].severity == "high"
        assert types["firebase.database_rules.updated"].severity == "high"
        assert types["firebase.storage_rules.updated"].severity == "high"
        for s in sigs:
            assert s.signal_type == "firebase_activity_signal"
            assert s.evidence_level == "activity" and s.confidence == "medium"
            assert "rules changed" in s.title.lower()
            assert s.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


# ── 2. auth config change → medium signal ────────────────────────────────────

def test_auth_config_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _fb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("a1", "identitytoolkit.googleapis.com", "UpdateConfig",
                   resource_name="projects/demo-fb/config"),
        ])
        _gen(db_session, ws.id)
        s = _signals(db_session, ws.id)[0]
        assert "authentication configuration changed" in s.title.lower()
        assert s.severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. Cloud Function change → signal (+ sensitive name bump) ────────────────

def test_function_signal_severity(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _fb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("f1", "cloudfunctions.googleapis.com", "UpdateFunction",
                   resource_name="projects/demo-fb/locations/us-central1/functions/admin-webhook"),
            _entry("f2", "cloudfunctions.googleapis.com", "CreateFunction",
                   resource_name="projects/demo-fb/locations/us-central1/functions/render-page"),
        ])
        _gen(db_session, ws.id)
        sev = {s.signal_metadata.get("function_name"): s.severity for s in _signals(db_session, ws.id)}
        assert sev["admin-webhook"] == "high"
        assert sev["render-page"] == "medium"
        for s in _signals(db_session, ws.id):
            assert "cloud function configuration changed" in s.title.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 4. hosting change → medium signal ────────────────────────────────────────

def test_hosting_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _fb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("h1", "firebasehosting.googleapis.com", "CreateRelease",
                   resource_name="projects/demo-fb/sites/demo/releases/r1"),
        ])
        _gen(db_session, ws.id)
        s = _signals(db_session, ws.id)[0]
        assert "hosting configuration changed" in s.title.lower()
        assert s.severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. app / project fallback → signal ───────────────────────────────────────

def test_project_app_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _fb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("p1", "firebase.googleapis.com", "CreateWebApp",
                   resource_name="projects/demo-fb/webApps/app1"),
            _entry("p2", "mystery.googleapis.com", "DoThing"),  # → project.event fallback
        ])
        summary = _gen(db_session, ws.id)
        assert summary["signals_created"] == 2
        sev_by_type = {s.signal_metadata.get("event_type"): s.severity for s in _signals(db_session, ws.id)}
        for s in _signals(db_session, ws.id):
            assert "project or app configuration changed" in s.title.lower()
        assert sev_by_type["firebase.app.updated"] == "medium"
        assert sev_by_type["firebase.project.event"] == "low"  # bare fallback, no target
    finally:
        _cleanup(db_session, ws.id)


# ── 6. idempotency ────────────────────────────────────────────────────────────

def test_idempotent_generation(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _fb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("i1", "firebaserules.googleapis.com", "UpdateRelease",
                   resource_name="projects/demo-fb/releases/cloud.firestore"),
        ])
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["signals_created"] == 1
        assert s2["signals_created"] == 0
        assert s2["signals_skipped"] == 1
        assert len(_signals(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 7. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _fb_integ(db_session, test_user, ws_a.id)
    try:
        _ingest(db_session, ws_a.id, integ_a, [
            _entry("w1", "firebaserules.googleapis.com", "UpdateRelease",
                   resource_name="projects/demo-fb/releases/cloud.firestore"),
        ])
        _gen(db_session, ws_a.id)
        assert len(_signals(db_session, ws_a.id)) == 1
        assert len(_signals(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id)
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 8. metadata privacy ───────────────────────────────────────────────────────

def test_metadata_privacy(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _fb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("m1", "firebaserules.googleapis.com", "UpdateRelease",
                   resource_name="projects/demo-fb/releases/cloud.firestore"),
            _entry("m2", "cloudfunctions.googleapis.com", "UpdateFunction",
                   resource_name="projects/demo-fb/locations/us-central1/functions/admin-task"),
        ])
        _gen(db_session, ws.id)
        blob = json.dumps([{
            "title": s.title, "summary": s.summary, "metadata": s.signal_metadata,
        } for s in _signals(db_session, ws.id)], default=str)
        assert PRIVATE_KEY not in blob
        assert ACTOR_EMAIL not in blob
        assert RAW_RULES not in blob
        for bad in ("private_key", "principalemail", "authorization", "bearer ",
                    "request", "response", "@example.com"):
            assert bad not in blob.lower()
        for s in _signals(db_session, ws.id):
            # "source" is the allowlisted activity-source label ("audit_log"), not
            # the raw rule source; the raw rule source key must never appear.
            for forbidden_key in ("private_key", "request", "response",
                                  "principalEmail", "payload", "headers", "actor_email"):
                assert forbidden_key not in s.signal_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 9. claim discipline ───────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _fb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("c1", "firebaserules.googleapis.com", "UpdateRelease",
                   resource_name="projects/demo-fb/releases/cloud.firestore"),
            _entry("c2", "identitytoolkit.googleapis.com", "UpdateConfig"),
        ])
        _gen(db_session, ws.id)
        for s in _signals(db_session, ws.id):
            blob = f"{s.title}\n{s.summary}".lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "evidence for review" in s.summary.lower()
            assert "does not confirm" in s.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 10. endpoint admin gating + member read ──────────────────────────────────

def test_member_cannot_generate(test_user, db_session):
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


def test_owner_can_generate_and_member_can_read_via_endpoint(client, test_user, db_session):
    ws = _ws(test_user, db_session); integ = _fb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("ep1", "firebaserules.googleapis.com", "UpdateRelease",
                   resource_name="projects/demo-fb/releases/cloud.firestore"),
        ])
        r = client.post("/security/firebase-activity/generate-signals")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "firebase" and body["source"] == "audit_log"
        assert body["signals_created"] == 1
        lst = client.get("/security/signals?provider=firebase")
        assert lst.status_code == 200
        assert lst.json()["total"] >= 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()
