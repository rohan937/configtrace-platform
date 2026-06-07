"""M60.4.4 — Supabase + Firebase security exposure rules.

Unit tests per rule (risky fires / safe does not / malformed ignored / evidence
metadata-only) plus DB-backed evaluator tests for lifecycle (dedupe + resolve)
and multi-record separate findings.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy.orm import Session

from app.connectors.firebase_schema import (
    FIREBASE_AUTH_CONFIG,
    FIREBASE_FIRESTORE_RULESET,
    FIREBASE_STORAGE_RULESET,
)
from app.connectors.supabase_schema import (
    SUPABASE_AUTH_CONFIG,
    SUPABASE_RLS_STATUS,
)
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.models.user import User
from app.services import security_finding_evaluator as evaluator
from app.services.security_rules import firebase as fb
from app.services.security_rules import supabase as sb

_SECRET_RE = re.compile(
    r"secret|token|password|api_?key|access_?key|private_?key|client_secret", re.I
)


def _safe(cands):
    for c in cands:
        for k in c.evidence.keys():
            assert not _SECRET_RE.search(k), f"sensitive evidence key: {k}"
        # raw rule text / hashes / summaries must never appear
        assert "rules_hash" not in c.evidence
        assert "rule_summary" not in c.evidence


# ── builders ─────────────────────────────────────────────────────────────────


def _rls(**over) -> dict:
    rec = {
        "record_type": SUPABASE_RLS_STATUS,
        "record_id": "proj/public/users",
        "table_name": "users",
        "schema_name": "public",
        "rls_enabled": False,
    }
    rec.update(over)
    return rec


def _sb_auth(**over) -> dict:
    rec = {
        "record_type": SUPABASE_AUTH_CONFIG,
        "record_id": "auth_config",
        "anonymous_enabled": False,
        "jwt_exp": 3600,
        "email_enabled": True,
    }
    rec.update(over)
    return rec


def _fs(**over) -> dict:
    rec = {
        "record_type": FIREBASE_FIRESTORE_RULESET,
        "record_id": "proj/firestore/cloud.firestore",
        "release_name": "cloud.firestore",
        "public_read_detected": False,
        "public_write_detected": False,
        "authenticated_only_detected": True,
        "parser_confidence": "high",
    }
    rec.update(over)
    return rec


def _storage(**over) -> dict:
    rec = {
        "record_type": FIREBASE_STORAGE_RULESET,
        "record_id": "proj/storage/firebase.storage",
        "release_name": "firebase.storage",
        "public_read_detected": False,
        "public_write_detected": False,
        "authenticated_only_detected": True,
        "parser_confidence": "high",
    }
    rec.update(over)
    return rec


def _fb_auth(**over) -> dict:
    rec = {
        "record_type": FIREBASE_AUTH_CONFIG,
        "record_id": "proj/auth_config",
        "project_id": "proj",
        "anonymous_enabled": False,
    }
    rec.update(over)
    return rec


# ── Supabase: RLS (regression) ───────────────────────────────────────────────


def test_rls_disabled_fires_high():
    out = sb.evaluate(_rls(rls_enabled=False))
    assert len(out) == 1 and out[0].rule_key == "supabase_rls_disabled"
    assert out[0].severity == "high"
    _safe(out)


def test_rls_enabled_safe():
    assert sb.evaluate(_rls(rls_enabled=True)) == []


def test_rls_missing_flag_ignored():
    rec = _rls()
    del rec["rls_enabled"]
    assert sb.evaluate(rec) == []


# ── Supabase: auth config ────────────────────────────────────────────────────


def test_supabase_anonymous_enabled_medium():
    out = sb.evaluate(_sb_auth(anonymous_enabled=True))
    assert any(c.rule_key == "supabase_anonymous_access_enabled" for c in out)
    assert next(c for c in out if c.rule_key == "supabase_anonymous_access_enabled").severity == "medium"
    _safe(out)


def test_supabase_anonymous_disabled_safe():
    out = sb.evaluate(_sb_auth(anonymous_enabled=False))
    assert all(c.rule_key != "supabase_anonymous_access_enabled" for c in out)


def test_supabase_jwt_long_fires():
    out = sb.evaluate(_sb_auth(jwt_exp=172800))  # 2 days
    assert any(c.rule_key == "supabase_jwt_expiry_long" for c in out)


def test_supabase_jwt_default_safe():
    assert sb.evaluate(_sb_auth(jwt_exp=3600)) == []


def test_supabase_jwt_non_int_ignored():
    assert sb.evaluate(_sb_auth(jwt_exp=None)) == []
    assert sb.evaluate(_sb_auth(jwt_exp="long")) == []
    # bool must not be treated as int
    assert sb.evaluate(_sb_auth(jwt_exp=True)) == []


def test_supabase_unknown_record_ignored():
    assert sb.evaluate({"record_type": "supabase_project"}) == []
    assert sb.evaluate({"weird": "x"}) == []


# ── Firebase: Firestore ──────────────────────────────────────────────────────


def test_firestore_public_write_critical():
    out = fb.evaluate(_fs(public_write_detected=True))
    assert out and out[0].rule_key == "firebase_rules_public"
    assert out[0].severity == "critical"
    _safe(out)


def test_firestore_public_read_high():
    out = fb.evaluate(_fs(public_read_detected=True))
    assert out and out[0].severity == "high"


def test_firestore_authenticated_only_safe():
    assert fb.evaluate(_fs()) == []


def test_firestore_low_confidence_not_flagged():
    # Even with public detected, a low-confidence parse is not flagged.
    assert fb.evaluate(_fs(public_read_detected=True, parser_confidence="low")) == []


def test_firestore_old_is_public_field_no_longer_used():
    # The legacy 'is_public' field is gone; a record with only is_public must
    # NOT fire (proves the M60.4 latent bug is fixed to the real fields).
    rec = {
        "record_type": FIREBASE_FIRESTORE_RULESET,
        "record_id": "proj/firestore/x",
        "is_public": True,
    }
    assert fb.evaluate(rec) == []


# ── Firebase: Storage ────────────────────────────────────────────────────────


def test_storage_public_write_critical():
    out = fb.evaluate(_storage(public_write_detected=True))
    assert out and out[0].rule_key == "firebase_storage_rules_public"
    assert out[0].severity == "critical"


def test_storage_public_read_high():
    out = fb.evaluate(_storage(public_read_detected=True))
    assert out and out[0].severity == "high"


def test_storage_safe():
    assert fb.evaluate(_storage()) == []


# ── Firebase: auth ───────────────────────────────────────────────────────────


def test_firebase_anonymous_auth_medium():
    out = fb.evaluate(_fb_auth(anonymous_enabled=True))
    assert out and out[0].rule_key == "firebase_anonymous_auth_enabled"
    assert out[0].severity == "medium"
    _safe(out)


def test_firebase_anonymous_disabled_safe():
    assert fb.evaluate(_fb_auth(anonymous_enabled=False)) == []


def test_firebase_unknown_record_ignored():
    assert fb.evaluate({"record_type": "firebase_project"}) == []
    assert fb.evaluate({"weird": "x"}) == []


# ════════════════════════════════════════════════════════════════════════════
# DB-backed evaluator: lifecycle + multi-record
# ════════════════════════════════════════════════════════════════════════════


def _ws(user, db):
    from app.services import workspace_service

    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M60.4.4", db=db
    )


def _integ(db, user, ws_id, provider):
    ct, iv = encrypt_credentials({"k": "v"})
    i = Integration(
        user_id=user.id,
        workspace_id=ws_id,
        provider=provider,
        display_name=provider,
        encrypted_credentials=ct,
        credential_iv=iv,
        status="active",
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _res(db, integ, user, rtype):
    r = Resource(
        integration_id=integ.id,
        user_id=user.id,
        provider_resource_type=rtype,
        provider_resource_id="proj-1",
        display_name="proj",
        is_active=True,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _snap(db, res, integ, user, state):
    s = Snapshot(
        resource_id=res.id,
        integration_id=integ.id,
        user_id=user.id,
        state=state,
        content_hash=uuid.uuid4().hex,
        triggered_by="manual",
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


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
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete()
    db.commit()


def test_supabase_multi_record_and_lifecycle(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id, "supabase")
    res = _res(db_session, integ, test_user, "supabase_project")

    state = [
        _rls(record_id="proj/public/users", table_name="users", rls_enabled=False),
        _rls(record_id="proj/public/orders", table_name="orders", rls_enabled=False),
        _sb_auth(anonymous_enabled=True, jwt_exp=200000),
        _rls(record_id="proj/public/safe", table_name="safe", rls_enabled=True),
    ]
    snap = _snap(db_session, res, integ, test_user, state)
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap
    )
    findings = _active(db_session, ws.id, res.id)
    keys = {f.finding_key for f in findings}
    # 2 RLS + anon + jwt = 4
    assert len(findings) == 4
    assert sum(k.startswith("supabase_rls_disabled") for k in keys) == 2
    assert any(k.startswith("supabase_anonymous_access_enabled") for k in keys)
    assert any(k.startswith("supabase_jwt_expiry_long") for k in keys)

    first_seen = {f.finding_key: f.last_seen_at for f in findings}
    # Re-evaluate same state → dedupe + refresh.
    snap2 = _snap(db_session, res, integ, test_user, state)
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap2
    )
    again = _active(db_session, ws.id, res.id)
    assert len(again) == 4
    for f in again:
        assert f.last_seen_at >= first_seen[f.finding_key]

    # One table fixed (RLS enabled) → that finding resolves.
    fixed = [
        _rls(record_id="proj/public/users", table_name="users", rls_enabled=True),
        _rls(record_id="proj/public/orders", table_name="orders", rls_enabled=False),
        _sb_auth(anonymous_enabled=True, jwt_exp=200000),
    ]
    snap3 = _snap(db_session, res, integ, test_user, fixed)
    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap3
    )
    assert summary["resolved"] == 1
    assert len(_active(db_session, ws.id, res.id)) == 3

    _cleanup(db_session, ws.id)


def test_firebase_multi_record_and_resolve(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id, "firebase")
    res = _res(db_session, integ, test_user, "firebase_project")

    state = [
        _fs(public_write_detected=True),
        _storage(public_read_detected=True),
        _fb_auth(anonymous_enabled=True),
    ]
    snap = _snap(db_session, res, integ, test_user, state)
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap
    )
    findings = _active(db_session, ws.id, res.id)
    keys = {f.finding_key for f in findings}
    assert len(findings) == 3
    assert any(k.startswith("firebase_rules_public") for k in keys)
    assert any(k.startswith("firebase_storage_rules_public") for k in keys)
    assert any(k.startswith("firebase_anonymous_auth_enabled") for k in keys)

    # Firestore rules tightened → that finding resolves.
    state2 = [
        _fs(),  # safe now
        _storage(public_read_detected=True),
        _fb_auth(anonymous_enabled=True),
    ]
    snap2 = _snap(db_session, res, integ, test_user, state2)
    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap2
    )
    assert summary["resolved"] == 1
    assert len(_active(db_session, ws.id, res.id)) == 2

    _cleanup(db_session, ws.id)
