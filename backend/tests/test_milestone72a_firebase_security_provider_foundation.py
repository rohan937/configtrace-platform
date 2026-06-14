"""M72A — Firebase security provider foundation (configuration-risk only).

Expands the existing Firebase config-risk provider with a safe Realtime Database
ruleset surface and three NEW data-backed rules over metadata-only fields:

  * firebase_database_public_read  — RTDB rules allow unauthenticated read;
  * firebase_database_public_write — RTDB rules allow unauthenticated write;
  * firebase_auth_protection_missing — multi-factor auth is not enabled.

The existing coarse Firestore/Storage public-access rules and the anonymous-auth
rule are unchanged (and verified still firing). The per-operation Firestore/Storage
read/write split and the public-HTTPS-function rule are deferred (documented).
These tests assert RTDB rules-metadata analysis (no raw rules JSON / secrets), the
new + existing rules, idempotency, fail-soft connector behavior, evidence privacy,
claim discipline, deferral, and registry/confidence/rule-pack parity.
"""

from __future__ import annotations

import json
import uuid

from app.connectors.firebase import (
    _analyze_rtdb_rules,
    _normalize_database_ruleset,
)
from app.connectors.firebase_schema import (
    FIREBASE_AUTH_CONFIG,
    FIREBASE_DATABASE_RULESET,
    FIREBASE_FIRESTORE_RULESET,
    FIREBASE_STORAGE_RULESET,
)
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.services import security_finding_evaluator as evaluator
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "secret leaked", "data leaked", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected",
]
RAW_SECRET = "private_key_should_never_appear"

_NEW_RULE_KEYS = {
    "firebase_database_public_read",
    "firebase_database_public_write",
    "firebase_auth_protection_missing",
}
_DEFERRED_RULE_KEYS = {
    "firebase_firestore_public_read",
    "firebase_firestore_public_write",
    "firebase_storage_public_read",
    "firebase_storage_public_write",
    "firebase_public_https_function",
}


# ── fixtures / helpers ────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M72A", db=db)


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({
        "type": "service_account", "project_id": "demo-fb",
        "private_key_id": "x", "private_key": RAW_SECRET, "client_email": "x@x.iam",
    })
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="firebase",
                    display_name="firebase", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _res(db, integ, user):
    r = Resource(integration_id=integ.id, user_id=user.id,
                 provider_resource_type="firebase_project", provider_resource_id="demo-fb",
                 display_name="demo-fb", is_active=True)
    db.add(r); db.commit(); db.refresh(r)
    return r


def _snap(db, res, integ, user, state):
    s = Snapshot(resource_id=res.id, integration_id=integ.id, user_id=user.id,
                 state=state, content_hash=uuid.uuid4().hex, triggered_by="manual")
    db.add(s); db.commit(); db.refresh(s)
    return s


def _active(db, ws_id, res_id):
    return (
        db.query(SecurityFinding)
        .filter(SecurityFinding.workspace_id == ws_id,
                SecurityFinding.resource_id == res_id,
                SecurityFinding.status == "active")
        .all()
    )


def _cleanup(db, ws_id):
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _evaluate(db, ws, integ, res, user, state):
    snap = _snap(db, res, integ, user, state)
    return evaluator.evaluate_security_findings_for_resource(
        db=db, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap)


def _db_ruleset(instance, *, read=False, write=False, confidence="high"):
    return {
        "record_type": FIREBASE_DATABASE_RULESET,
        "record_id": f"demo-fb/database/{instance}",
        "name": instance, "project_id": "demo-fb", "service": "realtime_database",
        "instance_name_hash": "abc123", "rules_hash": "deadbeef",
        "public_read_detected": read, "public_write_detected": write,
        "authenticated_only_detected": False, "parser_confidence": confidence,
        "rule_summary": "demo",
    }


def _auth(**kw):
    rec = {"record_type": FIREBASE_AUTH_CONFIG, "record_id": "demo-fb/auth_config",
           "project_id": "demo-fb"}
    rec.update(kw)
    return rec


# ── 1. RTDB rules analysis is metadata-only (no raw rules / secrets) ─────────

def test_rtdb_rules_analysis_metadata_only():
    rules = {"rules": {".read": True, ".write": "auth != null",
                       "secret_path": {".read": "true", "token": RAW_SECRET}}}
    out = _analyze_rtdb_rules(rules)
    blob = json.dumps(out)
    assert RAW_SECRET not in blob
    assert out["public_read_detected"] is True
    assert out["public_write_detected"] is False  # auth-guarded write is not public
    assert out["rules_hash"] and out["rules_hash"] != RAW_SECRET
    # Only safe derived keys are returned.
    assert set(out) == {
        "rules_hash", "public_read_detected", "public_write_detected",
        "authenticated_only_detected", "rule_summary", "parser_confidence",
    }

    # The normalized record carries names/hashes/booleans only — never raw rules.
    rec = _normalize_database_ruleset(
        project_id="demo-fb", instance_name="demo-default", rules_obj=rules)
    recblob = json.dumps(rec)
    assert RAW_SECRET not in recblob
    assert rec["record_type"] == FIREBASE_DATABASE_RULESET
    assert rec["public_read_detected"] is True


# ── 2. RTDB public read ───────────────────────────────────────────────────────

def test_database_public_read(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _db_ruleset("inst-read", read=True),
        ])
        findings = _active(db_session, ws.id, res.id)
        keys = {f.finding_key.split(":", 1)[0] for f in findings}
        assert "firebase_database_public_read" in keys
        assert "firebase_database_public_write" not in keys
        sev = {f.finding_key.split(":", 1)[0]: f.severity for f in findings}
        assert sev["firebase_database_public_read"] == "high"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. RTDB public write (+ read+write both fire) ─────────────────────────────

def test_database_public_write(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _db_ruleset("inst-rw", read=True, write=True),
        ])
        findings = _active(db_session, ws.id, res.id)
        sev = {f.finding_key.split(":", 1)[0]: f.severity for f in findings}
        assert sev.get("firebase_database_public_read") == "high"
        assert sev.get("firebase_database_public_write") == "critical"
    finally:
        _cleanup(db_session, ws.id)


def test_database_low_confidence_skipped(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _db_ruleset("inst-low", read=True, write=True, confidence="low"),
        ])
        assert _active(db_session, ws.id, res.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 4. auth protection missing (MFA off) ─────────────────────────────────────

def test_auth_protection_missing(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _auth(mfa_enabled=False, anonymous_enabled=False),
        ])
        keys = {f.finding_key.split(":", 1)[0] for f in _active(db_session, ws.id, res.id)}
        assert "firebase_auth_protection_missing" in keys
        assert "firebase_anonymous_auth_enabled" not in keys
    finally:
        _cleanup(db_session, ws.id)


def test_auth_mfa_on_is_clean(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _auth(mfa_enabled=True, anonymous_enabled=False),
        ])
        assert _active(db_session, ws.id, res.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 5. existing coarse rules still fire (Firestore/Storage public + anon) ────

def test_existing_firebase_rules_still_fire(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            {"record_type": FIREBASE_FIRESTORE_RULESET, "record_id": "demo-fb/firestore/r1",
             "release_name": "r1", "public_read_detected": True, "public_write_detected": False,
             "parser_confidence": "high"},
            {"record_type": FIREBASE_STORAGE_RULESET, "record_id": "demo-fb/storage/r2",
             "release_name": "r2", "public_read_detected": False, "public_write_detected": True,
             "parser_confidence": "high"},
            _auth(anonymous_enabled=True, mfa_enabled=True),
        ])
        keys = {f.finding_key.split(":", 1)[0] for f in _active(db_session, ws.id, res.id)}
        assert "firebase_rules_public" in keys           # Firestore (existing)
        assert "firebase_storage_rules_public" in keys   # Storage (existing)
        assert "firebase_anonymous_auth_enabled" in keys  # anon (existing)
    finally:
        _cleanup(db_session, ws.id)


# ── 6. deferred rules are not registered ─────────────────────────────────────

def test_deferred_rules_not_registered():
    for key in _DEFERRED_RULE_KEYS:
        assert key not in KNOWN_RULE_KEYS, f"{key} should be deferred"


# ── 7. idempotent re-evaluation ──────────────────────────────────────────────

def test_idempotent_reevaluation(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    state = [
        _db_ruleset("inst-rw", read=True, write=True),
        _auth(mfa_enabled=False, anonymous_enabled=True),
    ]
    try:
        _evaluate(db_session, ws, integ, res, test_user, state)
        ids = {f.id for f in _active(db_session, ws.id, res.id)}
        _evaluate(db_session, ws, integ, res, test_user, state)
        assert {f.id for f in _active(db_session, ws.id, res.id)} == ids
    finally:
        _cleanup(db_session, ws.id)


# ── 8. connector fails soft when the RTDB list is unavailable ────────────────

def test_connector_database_fetch_fails_soft(monkeypatch):
    from app.connectors.exceptions import ConnectorError
    from app.connectors.firebase import FirebaseConnector

    conn = FirebaseConnector()

    def boom(token, url, *a, **k):
        raise ConnectorError("no rtdb", status_code=403)

    monkeypatch.setattr(conn, "_get", boom)
    warnings: list[str] = []
    assert conn._fetch_database_rules("tok", "demo-fb", warnings) == []
    assert warnings  # a fail-soft warning is recorded, never raised


# ── 9. evidence privacy + claim discipline ───────────────────────────────────

def test_evidence_and_wording_are_safe(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _db_ruleset("inst-rw", read=True, write=True),
            _auth(mfa_enabled=False, anonymous_enabled=False),
        ])
        findings = _active(db_session, ws.id, res.id)
        assert findings
        blob = json.dumps(
            [{"t": f.title, "d": f.description, "e": f.evidence, "r": f.remediation}
             for f in findings], default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
        for bad in ("private_key", "service_account", "client_email", "access_token",
                    "bearer ", "authorization:", RAW_SECRET.lower()):
            assert bad not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 10. registry / confidence / pack parity for new keys ─────────────────────

def test_new_keys_registered_everywhere():
    for key in _NEW_RULE_KEYS:
        assert key in KNOWN_RULE_KEYS, f"{key} missing from KNOWN_RULE_KEYS"
        assert key in RULE_CONFIDENCE, f"{key} missing from RULE_CONFIDENCE"
        assert key in _RULE_META, f"{key} missing from _RULE_META"
        assert _RULE_META[key][0] == "firebase"
    assert KNOWN_RULE_KEYS == set(RULE_CONFIDENCE)
    assert set(_RULE_META) == set(KNOWN_RULE_KEYS)
