"""M71A — Supabase security provider foundation (configuration-risk only).

Extends the existing Supabase config-risk provider with four NEW data-backed
rules over safe Management-API metadata:

  * supabase_public_select_sensitive_table — a public/anon SELECT policy on an
    RLS-enabled, sensitively-named table (derived from pg_policies METADATA only);
  * supabase_public_write_policy — a public/anon insert/update/delete policy on
    an RLS-enabled table;
  * supabase_edge_function_jwt_disabled — an Edge Function with verify_jwt=false;
  * supabase_auth_protection_missing — leaked-password protection disabled.

These tests assert connector policy-metadata normalization (no row data / policy
expressions), each rule's trigger + idempotency, privacy of evidence, claim
discipline, deferral of the storage-bucket / redirect-URL rules, and
registry/confidence/rule-pack/coverage parity. Configuration-risk only.
"""

from __future__ import annotations

import json
import uuid

from app.connectors.supabase import _normalize_policy_rows
from app.connectors.supabase_schema import (
    SUPABASE_AUTH_CONFIG,
    SUPABASE_EDGE_FUNCTION,
    SUPABASE_RLS_STATUS,
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
RAW_SECRET = "service_role_key_should_never_appear"

_NEW_RULE_KEYS = {
    "supabase_public_select_sensitive_table",
    "supabase_public_write_policy",
    "supabase_edge_function_jwt_disabled",
    "supabase_auth_protection_missing",
}


# ── fixtures / helpers ────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M71A", db=db)


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"access_token": "sbp_x", "project_ref": "demoref0000000000000"})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="supabase",
                    display_name="supabase", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _res(db, integ, user):
    r = Resource(integration_id=integ.id, user_id=user.id,
                 provider_resource_type="supabase_project", provider_resource_id="demoref",
                 display_name="demo-project", is_active=True)
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


def _rls(table, *, schema="public", rls_enabled=True, **flags):
    rec = {
        "record_type": SUPABASE_RLS_STATUS,
        "record_id": f"supabase_rls_status:demoref:{schema}.{table}",
        "table_name": table, "schema_name": schema, "rls_enabled": rls_enabled,
    }
    rec.update(flags)
    return rec


def _fn(name, verify_jwt):
    return {
        "record_type": SUPABASE_EDGE_FUNCTION,
        "record_id": f"supabase_edge_function:demoref:{name}",
        "function_name": name, "slug": name, "verify_jwt": verify_jwt,
    }


def _auth(**kw):
    rec = {"record_type": SUPABASE_AUTH_CONFIG, "record_id": "supabase_auth_config:demoref"}
    rec.update(kw)
    return rec


# ── 1. connector policy normalization stores no row data / expressions ───────

def test_connector_policy_normalization_metadata_only():
    rows = [
        {"schemaname": "public", "tablename": "users", "cmd": "SELECT", "roles": ["anon"]},
        {"schemaname": "public", "tablename": "users", "cmd": "ALL", "roles": "{public}"},
        {"schemaname": "public", "tablename": "logs", "cmd": "INSERT", "roles": ["authenticated"]},
        # A row carrying secret-looking extra fields must never be reflected back.
        {"schemaname": "public", "tablename": "x", "cmd": "DELETE", "roles": ["anon"],
         "qual": RAW_SECRET, "with_check": RAW_SECRET},
    ]
    out = _normalize_policy_rows(rows)
    blob = json.dumps(out)
    assert RAW_SECRET not in blob
    # Only the derived safe flags + count appear (never qual/with_check/roles).
    for tbl in out.values():
        assert set(tbl) <= {
            "policy_count", "has_public_select_policy", "has_public_insert_policy",
            "has_public_update_policy", "has_public_delete_policy", "exposed_to_anon",
        }
    users = out["public.users"]
    assert users["has_public_select_policy"] is True
    assert users["has_public_insert_policy"] is True  # via ALL
    assert users["exposed_to_anon"] is True
    assert users["policy_count"] == 2
    # authenticated-only policy is not a public exposure.
    assert out["public.logs"]["exposed_to_anon"] is False
    assert out["public.logs"]["has_public_insert_policy"] is False
    assert out["public.x"]["has_public_delete_policy"] is True


# ── 2. public SELECT on sensitive-looking table ──────────────────────────────

def test_public_select_sensitive_table(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _rls("customers", rls_enabled=True, has_public_select_policy=True, policy_count=1),
            _rls("widgets", rls_enabled=True, has_public_select_policy=True, policy_count=1),  # not sensitive
        ])
        keys = {f.finding_key for f in _active(db_session, ws.id, res.id)}
        assert any(k.startswith("supabase_public_select_sensitive_table") and "customers" in k for k in keys)
        # Non-sensitive table name does not fire B.
        assert not any("widgets" in k and "public_select" in k for k in keys)
    finally:
        _cleanup(db_session, ws.id)


def test_public_select_skipped_when_rls_off(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        # RLS off → the disabled-RLS rule fires; the policy rule does NOT (avoids
        # double-flagging — policies are inactive when RLS is off).
        _evaluate(db_session, ws, integ, res, test_user, [
            _rls("users", rls_enabled=False, has_public_select_policy=True, policy_count=1),
        ])
        keys = {f.finding_key for f in _active(db_session, ws.id, res.id)}
        assert any(k.startswith("supabase_rls_disabled") for k in keys)
        assert not any(k.startswith("supabase_public_select_sensitive_table") for k in keys)
    finally:
        _cleanup(db_session, ws.id)


# ── 3. public write policy ────────────────────────────────────────────────────

def test_public_write_policy(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _rls("comments", rls_enabled=True, has_public_update_policy=True, policy_count=1),
        ])
        keys = {f.finding_key for f in _active(db_session, ws.id, res.id)}
        assert any(k.startswith("supabase_public_write_policy") for k in keys)
    finally:
        _cleanup(db_session, ws.id)


# ── 4. Edge Function JWT disabled (+ severity bump) ──────────────────────────

def test_edge_function_jwt_disabled(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _fn("admin-webhook", verify_jwt=False),   # sensitive → high
            _fn("public-health", verify_jwt=False),    # not sensitive → medium
            _fn("secure-task", verify_jwt=True),        # enabled → no finding
        ])
        findings = _active(db_session, ws.id, res.id)
        sev = {f.finding_key: f.severity for f in findings
               if f.finding_key.startswith("supabase_edge_function_jwt_disabled")}
        assert any("admin-webhook" in k and v == "high" for k, v in sev.items())
        assert any("public-health" in k and v == "medium" for k, v in sev.items())
        assert not any("secure-task" in k for k in sev)
    finally:
        _cleanup(db_session, ws.id)


# ── 5. auth leaked-password protection missing ───────────────────────────────

def test_auth_protection_missing(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _auth(leaked_password_protection_enabled=False, mfa_totp_enabled=False),
        ])
        keys = {f.finding_key for f in _active(db_session, ws.id, res.id)}
        assert any(k.startswith("supabase_auth_protection_missing") for k in keys)
    finally:
        _cleanup(db_session, ws.id)


def test_auth_protection_enabled_is_clean(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _auth(leaked_password_protection_enabled=True, mfa_totp_enabled=True),
        ])
        assert _active(db_session, ws.id, res.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 6. deferred rules are not registered ─────────────────────────────────────

def test_deferred_rules_not_registered():
    # Storage bucket + redirect-URL rules are deferred (unsafe/unavailable data).
    assert "supabase_public_storage_bucket" not in KNOWN_RULE_KEYS
    assert "supabase_auth_redirect_url_broad" not in KNOWN_RULE_KEYS
    # The public-schema RLS-disabled scenario is covered by the existing rule.
    assert "supabase_rls_disabled" in KNOWN_RULE_KEYS
    assert "supabase_rls_disabled_public_table" not in KNOWN_RULE_KEYS


# ── 7. idempotent re-evaluation ──────────────────────────────────────────────

def test_idempotent_reevaluation(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    state = [
        _rls("accounts", rls_enabled=True, has_public_select_policy=True, policy_count=1),
        _fn("admin-task", verify_jwt=False),
        _auth(leaked_password_protection_enabled=False, mfa_totp_enabled=False),
    ]
    try:
        _evaluate(db_session, ws, integ, res, test_user, state)
        ids = {f.id for f in _active(db_session, ws.id, res.id)}
        _evaluate(db_session, ws, integ, res, test_user, state)
        assert {f.id for f in _active(db_session, ws.id, res.id)} == ids
    finally:
        _cleanup(db_session, ws.id)


# ── 8. connector fails soft when the policy query is unavailable ─────────────

def test_connector_policy_fetch_fails_soft(monkeypatch):
    from app.connectors.exceptions import ConnectorError
    from app.connectors.supabase import SupabaseConnector

    conn = SupabaseConnector()

    def boom(*a, **k):
        raise ConnectorError("query disabled", status_code=403)

    monkeypatch.setattr(conn, "_run_query", boom)
    # Fail-soft → empty policy map (RLS records simply carry no policy flags).
    assert conn._fetch_database_policies("sbp_x", "demoref") == {}


# ── 9. evidence privacy + claim discipline ───────────────────────────────────

def test_evidence_and_wording_are_safe(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    state = [
        _rls("user_secrets", rls_enabled=True, has_public_select_policy=True,
             has_public_delete_policy=True, policy_count=2),
        _fn("admin-delete", verify_jwt=False),
        _auth(leaked_password_protection_enabled=False, mfa_totp_enabled=False),
    ]
    try:
        _evaluate(db_session, ws, integ, res, test_user, state)
        findings = _active(db_session, ws.id, res.id)
        assert findings
        blob = json.dumps(
            [{"t": f.title, "d": f.description, "e": f.evidence, "r": f.remediation}
             for f in findings], default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
        # No secret material / raw artifacts / user data / request headers.
        for bad in ("access_token", "service_role", "anon_key", "password=",
                    "authorization:", "authorization\":", "bearer ", "sbp_",
                    "with_check", "@example", "@"):
            assert bad not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 10. registry / confidence / pack parity for new keys ─────────────────────

def test_new_keys_registered_everywhere():
    for key in _NEW_RULE_KEYS:
        assert key in KNOWN_RULE_KEYS, f"{key} missing from KNOWN_RULE_KEYS"
        assert key in RULE_CONFIDENCE, f"{key} missing from RULE_CONFIDENCE"
        assert key in _RULE_META, f"{key} missing from _RULE_META"
        assert _RULE_META[key][0] == "supabase"
    assert KNOWN_RULE_KEYS == set(RULE_CONFIDENCE)
    assert set(_RULE_META) == set(KNOWN_RULE_KEYS)
