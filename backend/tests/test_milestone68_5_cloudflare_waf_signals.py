"""M68.5 — Cloudflare WAF / security-event Incident Signals.

Groups normalized Cloudflare WAF/security activity events (provider=cloudflare,
source=waf_security_event, ingested in M68.4) and surfaces review-worthy patterns
as Incident Signals (signal_type="cloudflare_waf_activity_signal",
evidence_level="activity", confidence="medium"). A single blocked/challenged
request is just a WAF event; a burst, sensitive-path activity, repeated-rule
activity, or skip/allow activity is worth a human's review.

These tests assert: the five patterns (block volume, challenge volume,
sensitive-path activity, repeated-rule activity, skip/allow), deterministic anchor
selection + idempotency, safe aggregate-only metadata (no raw IP / URL / path /
secrets), threshold gating, workspace scoping, endpoint admin gating, response
shape, and claim discipline (never asserts an attack / exploit / unauthorized
access).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import cloudflare_waf_signal_service as waf_sig
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
    "exploit confirmed",
]
RAW_IP = "203.0.113.200"
SECRET = "token=SUPERSECRET&session=abc123"

PROVIDER = "cloudflare"
SOURCE = "waf_security_event"


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M68.5", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _evt(db, ws_id, *, event_type, host="app.example.com", zone_id="zone-1",
         zone_name="example.com", rule_id="rule-1", rule_name="SQLi managed rule",
         ruleset_id="rs-1", path_prefix=None, action=None, country="US",
         minutes_ago=5, ray=None):
    md = {
        "zone_id": zone_id, "zone_name": zone_name, "host": host,
        "rule_id": rule_id, "rule_name": rule_name, "ruleset_id": ruleset_id,
        "client_country": country, "method": "POST", "service": "waf",
        "event_source": "cloudflare_waf",
        # Privacy-safe substitutes for raw values (M68.4 hashes these):
        "path_hash": "sha256:deadbeef", "ray_id": ray or uuid.uuid4().hex[:12],
    }
    if path_prefix is not None:
        md["path_prefix"] = path_prefix
    if action is not None:
        md["action"] = action
    row = SecurityActivityEvent(
        workspace_id=ws_id, provider=PROVIDER, source=SOURCE,
        provider_event_id=f"cfwaf:{uuid.uuid4().hex}",
        event_type=event_type, actor_id=None,
        resource_type="cloudflare_zone", resource_id=zone_id,
        source_ip_hash="sha256:" + uuid.uuid4().hex,
        occurred_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        event_metadata=md,
    )
    db.add(row)
    return row


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == PROVIDER,
        SecurityIncidentSignal.signal_type == "cloudflare_waf_activity_signal",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _gen(ws_id, db, **kw):
    return waf_sig.generate_cloudflare_waf_signals(workspace_id=ws_id, db=db, **kw)


# ── 1. high block volume ──────────────────────────────────────────────────────

def test_high_block_volume(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        for i in range(12):
            _evt(db_session, ws.id, event_type="cloudflare.waf_event.block",
                 action="block", ray=f"b{i}")
        db_session.commit()
        summary = _gen(ws.id, db_session, block_threshold=10)
        assert summary["provider"] == PROVIDER and summary["source"] == SOURCE
        assert summary["events_scanned"] == 12
        assert summary["signals_created"] >= 1
        keys = {s.signal_key for s in _signals(db_session, ws.id)}
        assert "cloudflare.waf.high_block_volume" in keys
        sig = next(s for s in _signals(db_session, ws.id)
                   if s.signal_key == "cloudflare.waf.high_block_volume")
        assert sig.evidence_level == "activity" and sig.confidence == "medium"
        assert sig.linked_activity_event_id is not None
        assert sig.signal_metadata.get("event_count") == 12
        assert sig.signal_metadata.get("pattern") == "high_block_volume"
    finally:
        _cleanup(db_session, ws.id)


def test_block_below_threshold_no_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        for i in range(4):
            _evt(db_session, ws.id, event_type="cloudflare.waf_event.block",
                 action="block", ray=f"b{i}")
        db_session.commit()
        summary = _gen(ws.id, db_session, block_threshold=10)
        assert summary["signals_created"] == 0
        assert _signals(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 2. high challenge volume ──────────────────────────────────────────────────

def test_high_challenge_volume(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        types = ["cloudflare.waf_event.challenge",
                 "cloudflare.waf_event.managed_challenge",
                 "cloudflare.waf_event.js_challenge"]
        for i in range(12):
            _evt(db_session, ws.id, event_type=types[i % 3],
                 action="challenge", ray=f"c{i}")
        db_session.commit()
        _gen(ws.id, db_session, challenge_threshold=10)
        keys = {s.signal_key for s in _signals(db_session, ws.id)}
        assert "cloudflare.waf.high_challenge_volume" in keys
    finally:
        _cleanup(db_session, ws.id)


# ── 3. sensitive-path activity ────────────────────────────────────────────────

def test_sensitive_path_activity(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        for i in range(6):
            _evt(db_session, ws.id, event_type="cloudflare.waf_event.block",
                 action="block", path_prefix="admin", ray=f"s{i}")
        db_session.commit()
        _gen(ws.id, db_session, block_threshold=999, sensitive_path_threshold=5)
        sigs = _signals(db_session, ws.id)
        keys = {s.signal_key for s in sigs}
        assert "cloudflare.waf.sensitive_path_activity" in keys
        sig = next(s for s in sigs
                   if s.signal_key == "cloudflare.waf.sensitive_path_activity")
        # Discipline: must not infer access.
        assert "does not infer that any endpoint was accessed" in sig.summary.lower()
        assert sig.signal_metadata.get("path_prefix") == "admin"
    finally:
        _cleanup(db_session, ws.id)


def test_nonsensitive_path_no_sensitive_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        for i in range(6):
            _evt(db_session, ws.id, event_type="cloudflare.waf_event.block",
                 action="block", path_prefix="images", ray=f"n{i}")
        db_session.commit()
        _gen(ws.id, db_session, block_threshold=999, sensitive_path_threshold=5)
        keys = {s.signal_key for s in _signals(db_session, ws.id)}
        assert "cloudflare.waf.sensitive_path_activity" not in keys
    finally:
        _cleanup(db_session, ws.id)


# ── 4. repeated WAF rule activity ─────────────────────────────────────────────

def test_repeated_rule_activity(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        # Spread across distinct hosts so block-volume (zone,host) does not fire,
        # but the (zone, rule_id) grouping accumulates.
        for i in range(12):
            _evt(db_session, ws.id, event_type="cloudflare.waf_event.log",
                 action="log", rule_id="rule-9", host=f"h{i}.example.com", ray=f"r{i}")
        db_session.commit()
        _gen(ws.id, db_session, rule_trigger_threshold=10)
        sigs = _signals(db_session, ws.id)
        keys = {s.signal_key for s in sigs}
        assert "cloudflare.waf.repeated_rule_activity" in keys
        sig = next(s for s in sigs
                   if s.signal_key == "cloudflare.waf.repeated_rule_activity")
        assert sig.signal_metadata.get("rule_id") == "rule-9"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. skip/allow activity ────────────────────────────────────────────────────

def test_skip_allow_activity(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        for i in range(6):
            _evt(db_session, ws.id,
                 event_type="cloudflare.waf_event.skip" if i % 2 else "cloudflare.waf_event.allow",
                 action="skip" if i % 2 else "allow", ray=f"sa{i}")
        db_session.commit()
        _gen(ws.id, db_session, skip_allow_threshold=5)
        sigs = _signals(db_session, ws.id)
        keys = {s.signal_key for s in sigs}
        assert "cloudflare.waf.skip_allow_activity" in keys
        sig = next(s for s in sigs if s.signal_key == "cloudflare.waf.skip_allow_activity")
        # Skip/allow is treated cautiously — never high.
        assert sig.severity in ("low", "medium")
        assert "can be legitimate" in sig.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 6. deterministic anchor + idempotency ─────────────────────────────────────

def test_idempotent_regeneration(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        for i in range(12):
            _evt(db_session, ws.id, event_type="cloudflare.waf_event.block",
                 action="block", ray=f"b{i}")
        db_session.commit()
        s1 = _gen(ws.id, db_session, block_threshold=10)
        n_after_first = len(_signals(db_session, ws.id))
        s2 = _gen(ws.id, db_session, block_threshold=10)
        assert s1["signals_created"] >= 1
        assert s2["signals_created"] == 0
        assert s2["signals_skipped"] >= 1
        assert len(_signals(db_session, ws.id)) == n_after_first
    finally:
        _cleanup(db_session, ws.id)


def test_anchor_prefers_block_over_log(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        # Same (zone, rule) group: many logs + one block. Anchor should be the block.
        for i in range(11):
            _evt(db_session, ws.id, event_type="cloudflare.waf_event.log",
                 action="log", rule_id="rule-7", host=f"h{i}.example.com", ray=f"l{i}")
        block = _evt(db_session, ws.id, event_type="cloudflare.waf_event.block",
                     action="block", rule_id="rule-7", host="hb.example.com", ray="theblock")
        db_session.commit()
        block_id = block.id
        _gen(ws.id, db_session, rule_trigger_threshold=10, block_threshold=999)
        sig = next(s for s in _signals(db_session, ws.id)
                   if s.signal_key == "cloudflare.waf.repeated_rule_activity")
        assert sig.linked_activity_event_id == block_id
    finally:
        _cleanup(db_session, ws.id)


# ── 7. privacy: aggregate-only metadata ───────────────────────────────────────

def test_metadata_is_safe_aggregate_only(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        for i in range(12):
            _evt(db_session, ws.id, event_type="cloudflare.waf_event.block",
                 action="block", path_prefix="login", ray=f"p{i}")
        db_session.commit()
        _gen(ws.id, db_session, block_threshold=10)
        for sig in _signals(db_session, ws.id):
            blob = json.dumps(sig.signal_metadata, default=str)
            assert RAW_IP not in blob and "SUPERSECRET" not in blob
            assert SECRET not in blob
            for bad in ("path_hash", "source_ip_hash", "clientIP",
                        "clientRequestPath", "ray_id", "cookie", "header"):
                assert bad not in sig.signal_metadata
            # Only aggregate-safe keys present.
            assert isinstance(sig.signal_metadata.get("event_count"), int)
            assert "client_country_count" in sig.signal_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 8. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    try:
        for i in range(12):
            _evt(db_session, ws_a.id, event_type="cloudflare.waf_event.block",
                 action="block", ray=f"a{i}")
        db_session.commit()
        _gen(ws_a.id, db_session, block_threshold=10)
        assert len(_signals(db_session, ws_a.id)) >= 1
        assert _signals(db_session, ws_b.id) == []
    finally:
        _cleanup(db_session, ws_a.id)
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 9. claim discipline ───────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        for i in range(12):
            _evt(db_session, ws.id, event_type="cloudflare.waf_event.block",
                 action="block", path_prefix="admin", ray=f"f{i}")
        db_session.commit()
        _gen(ws.id, db_session, block_threshold=10, sensitive_path_threshold=5)
        for sig in _signals(db_session, ws.id):
            blob = json.dumps({
                "title": sig.title, "summary": sig.summary,
                "metadata": sig.signal_metadata,
            }, default=str).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "does not confirm an attack, exploit, or unauthorized access" in sig.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 10. endpoint admin gating + response shape ────────────────────────────────

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


def test_owner_can_generate_via_endpoint(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        for i in range(12):
            _evt(db_session, ws.id, event_type="cloudflare.waf_event.block",
                 action="block", ray=f"e{i}")
        db_session.commit()
        resp = client.post("/security/cloudflare-waf-events/generate-signals",
                           json={"block_threshold": 10})
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == PROVIDER and body["source"] == SOURCE
        assert body["events_scanned"] == 12
        assert body["signals_created"] >= 1
        assert "groups_scanned" in body and "signals_skipped" in body
    finally:
        _cleanup(db_session, ws.id)
