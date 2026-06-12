"""M68.4 — Cloudflare WAF / security-event ingestion.

Cloudflare WAF/firewall security events (the GraphQL ``firewallEventsAdaptive``
dataset) are normalized into the shared ``security_activity_events`` spine
(provider=cloudflare, source=waf_security_event) as evidence for review — blocked
/ challenged / logged requests, never confirmed attacks. These tests assert
action mapping, privacy (no raw IP/URL/query/path/headers/secrets), the parser on
mocked GraphQL-shaped events, malformed-event safety, fail-soft permission/plan
handling, idempotency, workspace scoping, endpoint admin gating, and claim
discipline.
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
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import cloudflare_waf_event_ingestion_service as waf
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
    "exploit confirmed",
]
RAW_IP = "203.0.113.200"
SECRET_PATH = "/admin/api?token=SUPERSECRET&session=abc123"


def _event(ray, action, *, path=SECRET_PATH, ip=RAW_IP, country="US"):
    return {
        "action": action, "source": "waf",
        "ruleId": "rule-1", "rulesetId": "rs-1",
        "datetime": "2026-06-12T10:00:00Z", "rayName": ray,
        "clientCountryName": country, "clientRequestHTTPMethodName": "POST",
        "clientRequestHTTPHost": "app.example.com", "clientRequestPath": path,
        "clientIP": ip, "description": "SQLi managed rule",
        "_zone_id": "zone-1",
    }


# ── fake connector plumbing ───────────────────────────────────────────────────

def _patch(monkeypatch, events=None, *, raise_exc=None):
    def _fake(self, credentials, *, lookback_hours=24, max_events=200):
        if raise_exc is not None:
            raise raise_exc
        return events or []
    monkeypatch.setattr(CloudflareConnector, "list_waf_security_events", _fake)


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M68.4", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _cf_integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"api_token": "x", "zone_id": "zone-1",
                                  "zone_name": "example.com", "account_id": "acct-1"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="cloudflare",
        display_name="cf", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i); db.commit(); db.refresh(i)
    return i


def _rows(db, ws_id):
    return db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id,
        SecurityActivityEvent.provider == "cloudflare",
        SecurityActivityEvent.source == "waf_security_event",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _ingest(integ, ws_id, db):
    return waf.ingest_cloudflare_waf_events(integration=integ, workspace_id=ws_id, db=db)


# ── 1. action mapping ─────────────────────────────────────────────────────────

def test_action_mapping(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    events = [
        _event("r1", "block"), _event("r2", "challenge"),
        _event("r3", "managed_challenge"), _event("r4", "jschallenge"),
        _event("r5", "log"), _event("r6", "skip"), _event("r7", "allow"),
        _event("r8", "weird_action"),
    ]
    _patch(monkeypatch, events)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "waf_security_event"
        assert summary["events_inserted"] == 8
        types = {r.event_type for r in _rows(db_session, ws.id)}
        assert {
            "cloudflare.waf_event.block", "cloudflare.waf_event.challenge",
            "cloudflare.waf_event.managed_challenge", "cloudflare.waf_event.js_challenge",
            "cloudflare.waf_event.log", "cloudflare.waf_event.skip",
            "cloudflare.waf_event.allow", "cloudflare.waf_event.event",
        } <= types
    finally:
        _cleanup(db_session, ws.id)


# ── 2. privacy: no raw IP / URL / query / path / secrets ──────────────────────

def test_no_raw_ip_url_or_secrets(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_event("ray1", "block")])
    try:
        _ingest(integ, ws.id, db_session)
        row = _rows(db_session, ws.id)[0]
        blob = json.dumps({
            "event_type": row.event_type, "resource_id": row.resource_id,
            "metadata": row.event_metadata, "source_ip_hash": row.source_ip_hash,
        }, default=str)
        # Raw IP never stored — only a hash.
        assert RAW_IP not in blob
        assert row.source_ip_hash is not None
        # Raw URL / query / path never stored — only a hash + safe prefix.
        assert "token=SUPERSECRET" not in blob and "SUPERSECRET" not in blob
        assert "session=abc123" not in blob and "/admin/api" not in blob
        assert row.event_metadata.get("path_hash") is not None
        assert row.event_metadata.get("path_prefix") == "admin"  # safe leading segment
        # Safe fields ARE present.
        assert row.event_metadata.get("client_country") == "US"
        assert row.event_metadata.get("method") == "POST"
        assert row.event_metadata.get("host") == "app.example.com"
        for bad in ("clientIP", "clientRequestPath", "clientRequestQuery", "cookie",
                    "header", "session"):
            assert bad not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 3. parser on mocked GraphQL-shaped event (no DB) ──────────────────────────

def test_normalize_parser_direct():
    n = waf.normalize_waf_event(_event("ray-x", "block"), zone_name="example.com")
    assert n["event_type"] == "cloudflare.waf_event.block"
    assert n["actor_id"] is None  # never infer an actor from a request
    assert n["metadata"]["ray_id"] == "ray-x"
    assert n["metadata"]["rule_id"] == "rule-1"
    assert n["metadata"]["zone_name"] == "example.com"
    # deterministic fingerprint
    assert n["provider_event_id"] == waf.normalize_waf_event(_event("ray-x", "block"))["provider_event_id"]


# ── 4. malformed events skipped safely ────────────────────────────────────────

def test_malformed_events_skipped(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, ["not-a-dict", None, _event("good", "block"), 42])
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["succeeded"] is True
        assert summary["events_seen"] == 4
        assert summary["events_inserted"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 5. permission/plan failure is non-fatal ───────────────────────────────────

def test_permission_failure_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, raise_exc=AuthenticationError("denied", status_code=403))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["attempted"] is True
    assert summary["permission_limited"] is True
    assert summary["succeeded"] is True
    assert summary["events_inserted"] == 0


def test_plan_unavailable_non_fatal(test_user, db_session, monkeypatch):
    # GraphQL dataset unavailable (errors → ConnectorError 403) → permission_limited.
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, raise_exc=ConnectorError("plan", status_code=403))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["succeeded"] is True
    assert summary["permission_limited"] is True
    assert _rows(db_session, ws.id) == []


# ── 6. idempotency ────────────────────────────────────────────────────────────

def test_idempotency(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_event("dupe", "block")])
    try:
        s1 = _ingest(integ, ws.id, db_session)
        s2 = _ingest(integ, ws.id, db_session)
        assert s1["events_inserted"] == 1
        assert s2["events_inserted"] == 0
        assert s2["events_skipped"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 7. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session, monkeypatch):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _cf_integ(db_session, test_user, ws_a.id)
    _patch(monkeypatch, [_event("sc1", "block")])
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


# ── 8. claim discipline ───────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_event("c1", "block")])
    try:
        _ingest(integ, ws.id, db_session)
        for r in _rows(db_session, ws.id):
            blob = json.dumps({"t": r.event_type, "m": r.event_metadata}, default=str).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 9. endpoint admin gating ──────────────────────────────────────────────────

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


def test_owner_can_sync_via_endpoint(client, test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_event("ep1", "block")])
    try:
        resp = client.post("/security/cloudflare-waf-events/sync")
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "cloudflare" and body["source"] == "waf_security_event"
        assert body["events_inserted"] == 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()
