"""M72D — Firebase configuration-risk × activity correlations.

Correlates an ACTIVE Firebase configuration-risk finding with Firebase audit
activity (source="audit_log") for the SAME project, when an aligned event falls
inside the finding's review window (first_detected_at - 24h .. last_seen_at + 24h).
Project identity is the finding's Resource.provider_resource_id (or evidence
project_id) matched against the event's metadata project_id; when the finding's
evidence carries a narrower resource identity (ruleset/database/bucket name) the
event must match it too. Correlations only — no demo.

These tests assert per-rule correlation creation, project-scoped matching
(different project / different DB identity / provider-only / out-of-window all
skip), function-rule deferral, idempotency, linked correlation Incident Signal
creation, list/generate endpoints, metadata privacy, and claim discipline.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_activity_event_service as activity_svc
from app.services import security_finding_service as finding_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services import firebase_activity_ingestion_service as fb_ingest
from app.services import workspace_permission_service
from app.services import workspace_service
from app.services.security_rule_registry import KNOWN_RULE_KEYS

_FORBIDDEN = [
    "compromise confirmed", "secret leaked", "data leaked", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected",
]
PRIVATE_KEY = "private_key_should_never_store"
ACTOR_EMAIL = "deployer@example.com"
RAW_RULES = "service cloud.firestore { allow read, write: if true; }"
PROJECT = "demo-fb"
_NOW = datetime.now(timezone.utc).replace(microsecond=0)


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M72D", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({
        "type": "service_account", "project_id": PROJECT,
        "private_key_id": "x", "private_key": PRIVATE_KEY, "client_email": "x@x.iam",
    })
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="firebase",
                    display_name="firebase", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _res(db, integ, user, project=PROJECT):
    r = Resource(integration_id=integ.id, user_id=user.id,
                 provider_resource_type="firebase_project", provider_resource_id=project,
                 display_name=project, is_active=True)
    db.add(r); db.commit(); db.refresh(r)
    return r


def _finding(db, ws, integ, res, rule, *, severity="high", evidence=None):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="firebase",
        finding_key=f"{rule}:{uuid.uuid4().hex[:8]}", severity=severity,
        title=f"{rule} risk", resource_id=res.id, description="d",
        evidence=evidence or {"rule": rule}, remediation={"summary": "fix"})


def _event(db, ws_id, integ, service, method, *, resource_name="", occurred=None, labels=None):
    when = occurred if occurred is not None else _NOW
    entry = {
        "insertId": f"ev-{uuid.uuid4().hex[:10]}",
        "timestamp": when.isoformat(),
        "resource": {"type": "audited_resource", "labels": labels if labels is not None else {"project_id": PROJECT}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": service, "methodName": method, "resourceName": resource_name,
            "authenticationInfo": {"principalEmail": ACTOR_EMAIL},
            "request": {"source": RAW_RULES, "private_key": PRIVATE_KEY},
            "response": {"rules": RAW_RULES},
        },
    }
    norm = fb_ingest.normalize_firebase_activity_event(entry)
    assert norm is not None
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ.id, normalized=norm, db=db)
    return row


def _gen(db, ws_id):
    return corr_svc.generate_firebase_correlations(workspace_id=ws_id, db=db)


def _corrs(db, ws_id):
    return db.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == ws_id,
        SecuritySignalCorrelation.provider == "firebase",
    ).all()


def _cleanup(db, ws_id):
    from app.models.security_activity_event import SecurityActivityEvent
    from app.models.security_finding import SecurityFinding
    db.query(SecuritySignalCorrelation).filter(SecuritySignalCorrelation.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityIncidentSignal).filter(SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _setup(db, user):
    ws = _ws(user, db); integ = _integ(db, user, ws.id); res = _res(db, integ, user)
    return ws, integ, res


# ── 1. Firestore public rules risk × rules activity ──────────────────────────

def test_firestore_rules_risk_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_rules_public",
                 evidence={"rule": "firebase_rules_public", "release": "cloud.firestore"})
        _event(db_session, ws.id, integ, "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/cloud.firestore")
        s = _gen(db_session, ws.id)
        assert s["provider"] == "firebase" and s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "firebase_firestore_rules_risk_activity"
        assert c.severity == "high" and c.confidence == "medium"
        assert c.linked_finding_id and c.linked_activity_event_id
    finally:
        _cleanup(db_session, ws.id)


# ── 2. Realtime Database public read/write risk × database rules activity ────

def test_database_rules_risk_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_database_public_read",
                 evidence={"rule": "firebase_database_public_read", "service": "realtime_database"})
        _finding(db_session, ws, integ, res, "firebase_database_public_write", severity="critical",
                 evidence={"rule": "firebase_database_public_write", "service": "realtime_database"})
        _event(db_session, ws.id, integ, "firebasedatabase.googleapis.com", "UpdateDatabaseRules",
               resource_name="projects/demo-fb/instances/demo-default")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 2
        assert all(c.correlation_type == "firebase_database_rules_risk_activity"
                   for c in _corrs(db_session, ws.id))
    finally:
        _cleanup(db_session, ws.id)


# ── 3. Storage public rules risk × storage rules activity ────────────────────

def test_storage_rules_risk_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_storage_rules_public",
                 evidence={"rule": "firebase_storage_rules_public", "release": "firebase.storage"})
        _event(db_session, ws.id, integ, "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/firebase.storage/demo.appspot.com")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        assert _corrs(db_session, ws.id)[0].correlation_type == "firebase_storage_rules_risk_activity"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. anonymous auth risk × auth config activity ────────────────────────────

def test_anonymous_auth_risk_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_anonymous_auth_enabled", severity="medium",
                 evidence={"rule": "firebase_anonymous_auth_enabled", "project_id": PROJECT, "anonymous_enabled": True})
        _event(db_session, ws.id, integ, "identitytoolkit.googleapis.com", "UpdateConfig",
               resource_name="projects/demo-fb/config")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "firebase_anonymous_auth_risk_activity"
        assert c.severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. auth protection risk × auth config activity ───────────────────────────

def test_auth_protection_risk_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_auth_protection_missing", severity="medium",
                 evidence={"rule": "firebase_auth_protection_missing", "project_id": PROJECT, "mfa_enabled": False})
        _event(db_session, ws.id, integ, "identitytoolkit.googleapis.com", "UpdateConfig",
               resource_name="projects/demo-fb/config")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        assert _corrs(db_session, ws.id)[0].correlation_type == "firebase_auth_protection_risk_activity"
    finally:
        _cleanup(db_session, ws.id)


# ── 6. function correlation is deferred (rule does not exist) ─────────────────

def test_function_correlation_deferred():
    assert "firebase_public_https_function" not in KNOWN_RULE_KEYS
    types = {r["correlation_type"] for r in corr_svc.FIREBASE_CORRELATION_RULES.values()}
    assert "firebase_function_risk_activity" not in types
    assert "firebase_public_https_function" not in corr_svc.FIREBASE_CORRELATION_RULES


# ── 7. different project does not correlate ──────────────────────────────────

def test_different_project_no_correlation(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_rules_public",
                 evidence={"rule": "firebase_rules_public", "release": "cloud.firestore"})
        _event(db_session, ws.id, integ, "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/other-fb/releases/cloud.firestore",
               labels={"project_id": "other-fb"})
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 8. different database identity does not correlate (when available) ───────

def test_different_database_identity_no_correlation(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        # The finding's evidence carries a narrower database_instance identity.
        _finding(db_session, ws, integ, res, "firebase_database_public_read",
                 evidence={"rule": "firebase_database_public_read", "database_instance": "inst-a"})
        _event(db_session, ws.id, integ, "firebasedatabase.googleapis.com", "UpdateDatabaseRules",
               labels={"project_id": PROJECT, "database_id": "inst-b"})
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 9. provider-only match (no project on event) does not correlate ──────────

def test_provider_only_no_correlation(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_rules_public",
                 evidence={"rule": "firebase_rules_public", "release": "cloud.firestore"})
        # Aligned event_type but no project_id on the event metadata.
        _event(db_session, ws.id, integ, "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/cloud.firestore", labels={})
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 10. event outside review window does not correlate ───────────────────────

def test_out_of_window_no_correlation(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_rules_public",
                 evidence={"rule": "firebase_rules_public", "release": "cloud.firestore"})
        _event(db_session, ws.id, integ, "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/cloud.firestore",
               occurred=_NOW - timedelta(days=3))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 11. idempotency ───────────────────────────────────────────────────────────

def test_idempotent(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_rules_public",
                 evidence={"rule": "firebase_rules_public", "release": "cloud.firestore"})
        _event(db_session, ws.id, integ, "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/cloud.firestore")
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["correlations_created"] == 1
        assert s2["correlations_created"] == 0
        assert s2["correlations_skipped"] == 1
        assert len(_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 12. linked correlation Incident Signal created ───────────────────────────

def test_linked_correlation_signal(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_rules_public",
                 evidence={"rule": "firebase_rules_public", "release": "cloud.firestore"})
        _event(db_session, ws.id, integ, "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/cloud.firestore")
        _gen(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        assert c.linked_signal_id is not None
        sig = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.id == c.linked_signal_id).first()
        assert sig is not None
        assert sig.evidence_level == "correlation"
        assert sig.signal_type == "firebase_firestore_rules_risk_activity"
        assert sig.linked_finding_id == c.linked_finding_id
        assert sig.linked_activity_event_id == c.linked_activity_event_id
    finally:
        _cleanup(db_session, ws.id)


# ── 13. metadata privacy ──────────────────────────────────────────────────────

def test_metadata_privacy(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_rules_public",
                 evidence={"rule": "firebase_rules_public", "release": "cloud.firestore"})
        _event(db_session, ws.id, integ, "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/cloud.firestore")
        _gen(db_session, ws.id)
        cs = _corrs(db_session, ws.id)
        assert cs
        blob = json.dumps([{"t": c.title, "s": c.summary, "m": c.correlation_metadata}
                           for c in cs], default=str)
        assert PRIVATE_KEY not in blob
        assert ACTOR_EMAIL not in blob
        assert RAW_RULES not in blob
        for bad in ("private_key", "principalemail", "authorization", "bearer ",
                    "request", "response", "@example.com"):
            assert bad not in blob.lower()
        for c in cs:
            for forbidden_key in ("private_key", "request", "response",
                                  "principalEmail", "payload", "headers", "actor_email"):
                assert forbidden_key not in c.correlation_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 14. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_rules_public",
                 evidence={"rule": "firebase_rules_public", "release": "cloud.firestore"})
        _event(db_session, ws.id, integ, "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/cloud.firestore")
        _gen(db_session, ws.id)
        for c in _corrs(db_session, ws.id):
            blob = f"{c.title}\n{c.summary}".lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "does not confirm" in c.summary.lower()
            assert "review" in c.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 15. list + generate endpoints ────────────────────────────────────────────

def test_list_and_generate_endpoints(client, test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "firebase_rules_public",
                 evidence={"rule": "firebase_rules_public", "release": "cloud.firestore"})
        _event(db_session, ws.id, integ, "firebaserules.googleapis.com", "UpdateRelease",
               resource_name="projects/demo-fb/releases/cloud.firestore")
        r = client.post("/security/correlations/generate", json={"provider": "firebase"})
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "firebase" and body["correlations_created"] == 1

        lst = client.get("/security/correlations?provider=firebase&correlation_type=firebase_firestore_rules_risk_activity")
        assert lst.status_code == 200
        data = lst.json()
        assert data["total"] >= 1
        assert all(it["correlation_type"] == "firebase_firestore_rules_risk_activity" for it in data["items"])
        none = client.get("/security/correlations?provider=firebase&correlation_type=firebase_storage_rules_risk_activity")
        assert none.json()["total"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 16. generate endpoint admin gating ───────────────────────────────────────

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
