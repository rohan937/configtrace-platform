"""M68.1 — Cloudflare security/audit activity ingestion + signals.

Cloudflare account audit-log activity is normalized into the shared
``security_activity_events`` spine (provider=cloudflare, source=audit_log) as
evidence for review, and optionally promoted to Cloudflare Incident Signals
(evidence_level="activity"). These tests assert normalization + event-type
mapping, idempotency, non-fatal permission/unavailable handling, privacy (no raw
IPs/secrets/headers/JSON), signal generation + idempotency, endpoint admin
gating, workspace scoping, and claim discipline.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import HTTPException

from app.connectors.cloudflare import CloudflareConnector
from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import cloudflare_security_activity_ingestion_service as cf_ingest
from app.services import security_incident_signal_service as signal_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
]
RAW_IP = "203.0.113.88"
SECRET_VAL = "ghp_or_token_SECRETVALUE_should_never_store"


def _entry(event_id, *, rtype="dns_record", atype="edit", result="success",
           zone_name="example.com", with_secrets=True):
    e = {
        "id": event_id,
        "action": {"type": atype, "result": result},
        "actor": {"email": "admin@example.com", "id": "u-1", "ip": RAW_IP, "type": "user"},
        "interface": "API",
        "resource": {"id": "res-1", "type": rtype},
        "owner": {"id": "acct-1"},
        "zone": {"id": "zone-1", "name": zone_name},
        "when": "2026-06-12T10:00:00Z",
    }
    if with_secrets:
        # These blobs must never be traversed/stored.
        e["newValue"] = SECRET_VAL
        e["oldValue"] = "OLDSECRET"
        e["metadata"] = {"headers": {"Cookie": "session=abc"}, "token": SECRET_VAL}
    return e


# ── fake connector plumbing ───────────────────────────────────────────────────

def _patch_audit(monkeypatch, entries=None, *, raise_exc=None):
    def _fake(self, credentials, *, max_events=100, account_id=None):
        if raise_exc is not None:
            raise raise_exc
        return entries or []
    monkeypatch.setattr(CloudflareConnector, "list_audit_events", _fake)


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M68.1", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _cf_integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"api_token": "x", "zone_id": "zone-1", "account_id": "acct-1"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="cloudflare",
        display_name="cloudflare", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i); db.commit(); db.refresh(i)
    return i


def _rows(db, ws_id):
    return db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id,
        SecurityActivityEvent.provider == "cloudflare",
        SecurityActivityEvent.source == "audit_log",
    ).all()


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == "cloudflare",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _ingest(integ, ws_id, db):
    return cf_ingest.ingest_cloudflare_security_activity(
        integration=integ, workspace_id=ws_id, db=db)


# ── 1. normalize + event-type mapping ─────────────────────────────────────────

def test_normalizes_and_maps_event_types(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    entries = [
        _entry("e1", rtype="dns_record"),
        _entry("e2", rtype="firewall_rule"),
        _entry("e3", rtype="setting", atype="ssl"),
        _entry("e4", rtype="access_app"),
        _entry("e5", rtype="api_token"),
        _entry("e6", rtype="zone", atype="edit"),
        _entry("e7", rtype="mystery_thing", atype="poke"),
    ]
    _patch_audit(monkeypatch, entries)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "audit_log"
        assert summary["events_inserted"] == 7
        types = {r.event_type for r in _rows(db_session, ws.id)}
        assert {
            "cloudflare.dns_record.changed", "cloudflare.waf_rule.changed",
            "cloudflare.ssl_tls.changed", "cloudflare.access_policy.changed",
            "cloudflare.api_token.activity", "cloudflare.zone_setting.changed",
            "cloudflare.audit_event",
        } <= types
        dns = next(r for r in _rows(db_session, ws.id) if r.event_type == "cloudflare.dns_record.changed")
        assert dns.event_metadata.get("zone_name") == "example.com"
        assert dns.event_metadata.get("outcome") == "success"
        assert dns.actor_id == "admin@example.com"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. idempotency ────────────────────────────────────────────────────────────

def test_idempotent_ingestion(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [_entry("dupe")])
    try:
        s1 = _ingest(integ, ws.id, db_session)
        s2 = _ingest(integ, ws.id, db_session)
        assert s1["events_inserted"] == 1
        assert s2["events_inserted"] == 0
        assert s2["events_skipped"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 3. permission failure is non-fatal ────────────────────────────────────────

def test_permission_failure_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, raise_exc=AuthenticationError("denied", status_code=403))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["attempted"] is True
    assert summary["permission_limited"] is True
    assert summary["succeeded"] is True
    assert summary["events_inserted"] == 0


def test_unavailable_endpoint_non_fatal(test_user, db_session, monkeypatch):
    # 404/422 (account context unavailable / plan-gated) → permission_limited.
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, raise_exc=ConnectorError("unavailable", status_code=404))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["succeeded"] is True
    assert summary["permission_limited"] is True
    assert _rows(db_session, ws.id) == []


# ── 4. privacy: no raw IP / secrets / headers / JSON ──────────────────────────

def test_no_raw_secrets_ip_or_json(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [_entry("p1")])
    try:
        _ingest(integ, ws.id, db_session)
        row = _rows(db_session, ws.id)[0]
        blob = json.dumps({
            "event_type": row.event_type, "actor_id": row.actor_id,
            "resource_id": row.resource_id, "metadata": row.event_metadata,
            "source_ip_hash": row.source_ip_hash, "raw_ref": row.raw_ref,
        }, default=str)
        assert RAW_IP not in blob
        assert SECRET_VAL not in blob
        assert row.source_ip_hash is not None  # IP hashed, never raw
        for bad in ("newValue", "oldValue", "Cookie", "headers", "token", "session=abc"):
            assert bad not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 5. signal generation + idempotency ────────────────────────────────────────

def test_signal_generation_and_idempotency(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [
        _entry("s1", rtype="firewall_rule"),       # → waf_rule signal (high)
        _entry("s2", rtype="setting", atype="ssl"),  # → ssl_tls signal (high)
        _entry("s3", rtype="mystery", atype="x"),  # audit_event → NO signal
    ])
    try:
        _ingest(integ, ws.id, db_session)
        g1 = signal_svc.generate_cloudflare_signals(workspace_id=ws.id, db=db_session)
        g2 = signal_svc.generate_cloudflare_signals(workspace_id=ws.id, db=db_session)
        assert g1["signals_created"] == 2  # waf + ssl; audit_event produces none
        assert g2["signals_created"] == 0
        assert g2["signals_skipped"] == 2
        keys = {s.signal_key for s in _signals(db_session, ws.id)}
        assert "cloudflare_waf_rule_changed" in keys
        assert "cloudflare_ssl_tls_changed" in keys
        for s in _signals(db_session, ws.id):
            assert s.evidence_level == "activity"
            assert s.signal_type == "cloudflare_audit_activity"
    finally:
        _cleanup(db_session, ws.id)


# ── 6. claim discipline ───────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [_entry("c1", rtype="firewall_rule")])
    try:
        _ingest(integ, ws.id, db_session)
        signal_svc.generate_cloudflare_signals(workspace_id=ws.id, db=db_session)
        for s in _signals(db_session, ws.id):
            blob = f"{s.title}\n{s.summary}".lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "evidence for review" in s.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 7. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session, monkeypatch):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _cf_integ(db_session, test_user, ws_a.id)
    _patch_audit(monkeypatch, [_entry("sc1")])
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


# ── 8. endpoint admin gating ──────────────────────────────────────────────────

def test_member_cannot_sync_or_generate(test_user, db_session):
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


def test_owner_can_sync_and_generate_via_endpoints(client, test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [_entry("ep1", rtype="firewall_rule")])
    try:
        r = client.post("/security/cloudflare-activity/sync")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "cloudflare" and body["source"] == "audit_log"
        assert body["events_inserted"] == 1

        g = client.post("/security/cloudflare-activity/generate-signals")
        assert g.status_code == 200
        assert g.json()["signals_created"] == 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()
