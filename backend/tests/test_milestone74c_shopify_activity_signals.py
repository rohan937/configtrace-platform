"""M74C — Shopify activity Incident Signals.

Shopify configuration-change activity (provider=shopify, source=shopify_events,
ingested in M74B) is promoted into review-worthy Incident Signals
(signal_type="shopify_activity_signal", evidence_level="activity",
confidence="medium"). These tests assert per-pattern signal creation, severity
bumps for webhook deletion / http delivery / domain deletion, deferred /
no-op behavior for app_scopes / policy / config.event patterns the M74B
ingestion path does not emit, idempotency, workspace scoping, endpoint admin
gating, metadata privacy, and claim discipline.

Signals only — no correlations / demo.
"""

from __future__ import annotations

import json
import time
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
from app.services import shopify_activity_ingestion_service as sh_ingest
from app.services import shopify_activity_signal_service as sh_sig
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
]
RAW_TOKEN = "shpat_must_never_appear"
RAW_WHSEC = "whsec_must_never_appear_shopify"
RAW_EMAIL = "customer@example.com"
RAW_CARD_LAST4 = "4242"
RAW_ORDER_ID = "5544332211"
RAW_STAFF_NAME = "Jane Operator"


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M74C", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test",
             display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _sh_integ(db, user, ws_id):
    ct, iv = encrypt_credentials({
        "shop_domain": "demo-store.myshopify.com",
        "access_token": RAW_TOKEN,
    })
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="shopify",
                    display_name="shopify", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _now_epoch() -> int:
    return int(time.time())


def _now_iso(offset_seconds: int = -60) -> str:
    """Recent ISO-8601 timestamp so events fall inside the 168-hour window."""
    return time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(_now_epoch() + offset_seconds))


def _raw_event(event_id, subject_type, verb, *,
               subject_id=None, created_at=None, shop_domain="demo.example.com",
               myshopify_domain="demo-store.myshopify.com",
               metadata=None, livemode=True, inject_pii=True):
    """Build a raw Shopify event the M74B normalizer accepts. PII is salted to
    confirm the allowlist gate keeps it out of the signal."""
    evt = {
        "id": event_id,
        "subject_id": subject_id if subject_id is not None else 1000,
        "subject_type": subject_type,
        "verb": verb,
        "created_at": created_at or _now_iso(),
        "shop_domain": shop_domain,
        "myshopify_domain": myshopify_domain,
        "livemode": livemode,
    }
    if metadata is not None:
        evt["metadata"] = metadata
    if inject_pii:
        evt["arguments"] = [
            "order_number: " + RAW_ORDER_ID,
            "email: " + RAW_EMAIL,
            "card_last4: " + RAW_CARD_LAST4,
            "token: " + RAW_TOKEN,
            "signing_secret: " + RAW_WHSEC,
        ]
        evt["message"] = (
            f"{RAW_STAFF_NAME} updated order {RAW_ORDER_ID} "
            f"for customer {RAW_EMAIL}"
        )
        evt["path"] = f"/admin/orders/{RAW_ORDER_ID}"
        evt["author"] = RAW_STAFF_NAME
        evt["body"] = f"raw payload with {RAW_WHSEC}"
    return evt


def _ingest(db, ws_id, integ, entries):
    """Normalize + upsert raw Shopify events into activity events."""
    for entry in entries:
        norm = sh_ingest.normalize_shopify_activity_event(entry)
        assert norm is not None, f"entry did not normalize: {entry}"
        activity_svc.upsert_activity_event(
            workspace_id=ws_id, integration_id=integ.id, normalized=norm, db=db)


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == "shopify",
    ).all()


def _gen(db, ws_id):
    # Use the max lookback so events always fall inside the window.
    return sh_sig.generate_shopify_activity_signals(
        workspace_id=ws_id, db=db, lookback_hours=168)


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


# ── 1. webhook subscription change → medium signal (https) ───────────────────

def test_webhook_subscription_signal_medium(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sh_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event(1001, "Webhook", "update", subject_id=11,
                       metadata={"topic": "products/update",
                                 "address": "https://example.com/wh"}),
        ])
        summary = _gen(db_session, ws.id)
        assert summary["provider"] == "shopify"
        assert summary["source"] == "shopify_events"
        assert summary["signals_created"] == 1
        s = _signals(db_session, ws.id)[0]
        assert s.signal_type == "shopify_activity_signal"
        assert s.evidence_level == "activity" and s.confidence == "medium"
        assert s.severity == "medium"
        assert "shopify webhook subscription changed" in s.title.lower()
        assert s.linked_activity_event_id is not None
        md = s.signal_metadata
        assert md.get("pattern") == "webhook_subscription_changed"
        assert md.get("webhook_id") == "11"
        assert md.get("webhook_endpoint_domain") == "example.com"
        assert md.get("webhook_endpoint_scheme") == "https"
        assert md.get("webhook_topic") == "products/update"
        assert md.get("shop_domain") == "demo.example.com"
        assert md.get("myshopify_domain") == "demo-store.myshopify.com"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. webhook severity bump on deletion + http scheme ───────────────────────

def test_webhook_severity_bump(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sh_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event(2001, "Webhook", "destroy", subject_id=21,
                       metadata={"topic": "products/update",
                                 "address": "https://gone.example.com/wh"}),
            _raw_event(2002, "Webhook", "update", subject_id=22,
                       metadata={"topic": "products/update",
                                 "address": "http://insecure.example.com/wh"}),
        ])
        _gen(db_session, ws.id)
        sev_by_id = {
            s.signal_metadata.get("webhook_id"): s.severity
            for s in _signals(db_session, ws.id)
        }
        assert sev_by_id.get("21") == "high"  # deletion → high
        assert sev_by_id.get("22") == "high"  # plain-http delivery → high
    finally:
        _cleanup(db_session, ws.id)


# ── 3. domain configuration change → medium signal ──────────────────────────

def test_domain_signal_medium(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sh_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event(3001, "Domain", "update", subject_id=31,
                       metadata={"host": "store.example.com"}),
        ])
        _gen(db_session, ws.id)
        s = _signals(db_session, ws.id)[0]
        assert "shopify domain configuration changed" in s.title.lower()
        assert s.severity == "medium"
        md = s.signal_metadata
        assert md.get("pattern") == "domain_configuration_changed"
        assert md.get("domain_id") == "31"
        assert md.get("domain_host") == "store.example.com"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. domain deletion severity bump ─────────────────────────────────────────

def test_domain_deletion_severity_bump(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sh_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event(4001, "Domain", "destroy", subject_id=41,
                       metadata={"host": "old.example.com"}),
        ])
        _gen(db_session, ws.id)
        s = _signals(db_session, ws.id)[0]
        assert s.severity == "high"
        assert s.signal_metadata.get("domain_id") == "41"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. shop settings change → medium signal ─────────────────────────────────

def test_shop_settings_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sh_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event(5001, "Shop", "update", subject_id=901),
        ])
        _gen(db_session, ws.id)
        s = _signals(db_session, ws.id)[0]
        assert "shop settings changed" in s.title.lower()
        assert s.severity == "medium"
        assert s.signal_metadata.get("pattern") == "shop_settings_changed"
        assert s.signal_metadata.get("object_type") == "Shop"
    finally:
        _cleanup(db_session, ws.id)


# ── 6. app-scopes pattern is DEFERRED until ingestion emits it ──────────────

def test_app_scopes_pattern_deferred(test_user, db_session):
    """M74B's ingestion path does not emit shopify.app_scopes.updated under
    any normal Shopify Events response (no AppScope subject_type is requested,
    and the normalizer never invents one). The signal service must therefore
    not fabricate app-scope signals. This pins the deferred behavior so a
    future change must update the test deliberately."""
    assert "shopify.app_scopes.updated" not in sh_sig._EVENT_PATTERNS


# ── 7. policy pattern is DEFERRED until ingestion emits it ──────────────────

def test_policy_pattern_deferred(test_user, db_session):
    """Same rationale as test_app_scopes_pattern_deferred — M74B's Shopify
    Events ingestion does not emit shopify.policy.* (no Policy subject_type
    is requested), so the signal service must not synthesize those signals."""
    for et in ("shopify.policy.created", "shopify.policy.updated",
               "shopify.policy.deleted"):
        assert et not in sh_sig._EVENT_PATTERNS


# ── 8. safe fallback pattern is DEFERRED until ingestion emits it ──────────

def test_config_fallback_pattern_deferred(test_user, db_session):
    """M74B's ingestion does not emit a shopify.config.event fallback. Pin
    the deferral so the signal service does not fabricate fallback signals."""
    assert "shopify.config.event" not in sh_sig._EVENT_PATTERNS


# ── 9. idempotency ───────────────────────────────────────────────────────────

def test_idempotent_generation(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sh_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event(9001, "Webhook", "update", subject_id=91,
                       metadata={"topic": "products/update",
                                 "address": "https://example.com/wh"}),
        ])
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["signals_created"] == 1
        assert s2["signals_created"] == 0
        assert s2["signals_skipped"] == 1
        assert len(_signals(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 10. grouping: multiple events on the same target dedupe into one signal ─

def test_grouping_deduplicates(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sh_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event(10001, "Webhook", "update", subject_id=101,
                       metadata={"topic": "products/update",
                                 "address": "https://example.com/wh"},
                       created_at=_now_iso(-1200)),
            _raw_event(10002, "Webhook", "update", subject_id=101,
                       metadata={"topic": "products/update",
                                 "address": "https://example.com/wh"},
                       created_at=_now_iso(-300)),
        ])
        _gen(db_session, ws.id)
        sigs = _signals(db_session, ws.id)
        assert len(sigs) == 1
        assert sigs[0].signal_metadata.get("event_count") == 2
    finally:
        _cleanup(db_session, ws.id)


# ── 11. workspace scoping ────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other_sh_sig")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _sh_integ(db_session, test_user, ws_a.id)
    try:
        _ingest(db_session, ws_a.id, integ_a, [
            _raw_event(11001, "Shop", "update", subject_id=911),
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


# ── 12. metadata privacy ─────────────────────────────────────────────────────

def test_metadata_privacy(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sh_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event(12001, "Webhook", "update", subject_id=121,
                       metadata={"topic": "products/update",
                                 "address": "https://api.example.com/h?token=" + RAW_TOKEN}),
            _raw_event(12002, "Shop", "update", subject_id=122),
            _raw_event(12003, "Domain", "update", subject_id=123,
                       metadata={"host": "store.example.com"}),
        ])
        _gen(db_session, ws.id)
        blob = json.dumps([{
            "title": s.title, "summary": s.summary,
            "metadata": s.signal_metadata,
        } for s in _signals(db_session, ws.id)], default=str)
        # Secrets, tokens, customer PII, orders, card data, staff names must
        # never appear in any signal text or metadata.
        assert RAW_TOKEN not in blob
        assert RAW_WHSEC not in blob
        assert RAW_EMAIL not in blob
        assert RAW_CARD_LAST4 not in blob
        assert RAW_ORDER_ID not in blob
        assert RAW_STAFF_NAME not in blob
        for bad in ("shpat_", "shpss_", "shpca_", "shpapp_", "whsec_",
                    "bearer ", "authorization", "customer_email",
                    "card number", "4242", "?token=", "?secret=",
                    "?session_id", "?cart_token="):
            assert bad not in blob.lower()
        for s in _signals(db_session, ws.id):
            for forbidden_key in (
                "arguments", "message", "path", "author", "body",
                "description", "secret", "signing_secret", "access_token",
                "token", "customer", "customer_email", "email", "card",
                "order", "checkout", "cart", "payment", "payload",
                "headers", "request", "response", "raw", "url",
            ):
                assert forbidden_key not in s.signal_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 13. claim discipline ─────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sh_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event(13001, "Webhook", "destroy", subject_id=131,
                       metadata={"topic": "products/update",
                                 "address": "https://example.com/wh"}),
            _raw_event(13002, "Domain", "destroy", subject_id=132,
                       metadata={"host": "store.example.com"}),
            _raw_event(13003, "Shop", "update", subject_id=133),
        ])
        _gen(db_session, ws.id)
        for s in _signals(db_session, ws.id):
            blob = f"{s.title}\n{s.summary}".lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert ("evidence for review" in s.summary.lower()
                    or "may require review" in s.summary.lower())
            assert "does not confirm" in s.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 14. endpoint admin gating: member cannot generate ───────────────────────

def test_member_cannot_generate(test_user, db_session):
    owner = _new_user(db_session, "owner_sh_sig")
    ws = _ws(owner, db_session)
    m = WorkspaceMember(workspace_id=ws.id, user_id=test_user.id, role="member")
    db_session.add(m); db_session.commit()
    try:
        with pytest.raises(HTTPException) as exc:
            workspace_permission_service.require_workspace_admin(
                ws.id, test_user.id, db_session)
        assert exc.value.status_code == 403
    finally:
        try:
            db_session.delete(owner); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 15. owner can generate + member can read via endpoint ───────────────────

def test_owner_can_generate_and_member_can_read_via_endpoint(
        client, test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sh_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event(15001, "Webhook", "update", subject_id=151,
                       metadata={"topic": "products/update",
                                 "address": "https://example.com/wh"}),
        ])
        r = client.post("/security/shopify-activity/generate-signals")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "shopify"
        assert body["source"] == "shopify_events"
        assert body["signals_created"] == 1
        lst = client.get("/security/signals?provider=shopify")
        assert lst.status_code == 200
        assert lst.json()["total"] >= 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(
            Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()
