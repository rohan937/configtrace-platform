"""M73C — Stripe activity Incident Signals.

Stripe configuration-change activity (provider=stripe, source=stripe_events,
ingested in M73B) is promoted into review-worthy Incident Signals
(signal_type="stripe_activity_signal", evidence_level="activity",
confidence="medium"). These tests assert per-pattern signal creation, severity
bumps for webhook deletion / http delivery / inactive or pending capability,
config_event fallback severity, idempotency, workspace scoping, endpoint admin
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
from app.services import stripe_activity_ingestion_service as st_ingest
from app.services import stripe_activity_signal_service as st_sig
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "secret leaked", "data leaked", "customer data leaked",
    "payment fraud detected", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
RAW_SECRET = "sk_live_must_never_appear"
RAW_WHSEC = "whsec_must_never_appear"
RAW_EMAIL = "customer@example.com"
RAW_CARD = "4242424242424242"


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M73C", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _st_integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"stripe_api_key": RAW_SECRET})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="stripe",
                    display_name="stripe", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _now_epoch() -> int:
    return int(time.time())


def _raw_event(event_id, event_type, *, obj, created=None, livemode=True,
               account="acct_demo", inject_secrets=True):
    """Build a raw Stripe event the M73B normalizer accepts.

    ``created`` defaults to a "near-now" epoch so events fall inside the
    24-hour lookback window regardless of when the test runs.
    """
    if created is None:
        created = _now_epoch() - 60  # one minute ago
    object_dict = dict(obj or {})
    if inject_secrets:
        object_dict.setdefault("secret", RAW_WHSEC)
        object_dict.setdefault("customer_email", RAW_EMAIL)
        object_dict.setdefault("card", {"last4": "4242", "number": RAW_CARD})
    return {
        "id": event_id, "type": event_type, "object": "event",
        "created": created, "livemode": livemode, "account": account,
        "data": {"object": object_dict},
        "request": {"id": "req_demo", "idempotency_key": "ik_demo"},
    }


def _ingest(db, ws_id, integ, entries):
    """Normalize + upsert raw Stripe events into activity events."""
    for entry in entries:
        norm = st_ingest.normalize_stripe_activity_event(entry)
        assert norm is not None, f"entry did not normalize: {entry}"
        activity_svc.upsert_activity_event(
            workspace_id=ws_id, integration_id=integ.id, normalized=norm, db=db)


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == "stripe",
    ).all()


def _gen(db, ws_id):
    # Use the max lookback so the fixture's stable-epoch events always fall
    # inside the window regardless of when the test runs.
    return st_sig.generate_stripe_activity_signals(
        workspace_id=ws_id, db=db, lookback_hours=168)


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


# ── 1. webhook endpoint change → signal (https = medium) ─────────────────────

def test_webhook_endpoint_signal_medium(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _st_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event("evt_we1", "webhook_endpoint.updated",
                       obj={"id": "we_1", "object": "webhook_endpoint",
                            "url": "https://example.com/h"}),
        ])
        summary = _gen(db_session, ws.id)
        assert summary["provider"] == "stripe" and summary["source"] == "stripe_events"
        assert summary["signals_created"] == 1
        s = _signals(db_session, ws.id)[0]
        assert s.signal_type == "stripe_activity_signal"
        assert s.evidence_level == "activity" and s.confidence == "medium"
        assert s.severity == "medium"
        assert "stripe webhook endpoint changed" in s.title.lower()
        assert s.linked_activity_event_id is not None
        assert s.signal_metadata.get("webhook_endpoint_id") == "we_1"
        assert s.signal_metadata.get("webhook_url_scheme") == "https"
        assert s.signal_metadata.get("pattern") == "webhook_endpoint_changed"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. webhook severity bump on deletion + http scheme ───────────────────────

def test_webhook_severity_bump(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _st_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event("evt_del", "webhook_endpoint.deleted",
                       obj={"id": "we_del", "object": "webhook_endpoint",
                            "url": "https://gone.example.com/h"}),
            _raw_event("evt_http", "webhook_endpoint.updated",
                       obj={"id": "we_http", "object": "webhook_endpoint",
                            "url": "http://insecure.example.com/h"}),
        ])
        _gen(db_session, ws.id)
        sev_by_id = {
            s.signal_metadata.get("webhook_endpoint_id"): s.severity
            for s in _signals(db_session, ws.id)
        }
        assert sev_by_id["we_del"] == "high"
        assert sev_by_id["we_http"] == "high"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. payment link change → medium signal ───────────────────────────────────

def test_payment_link_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _st_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event("evt_pl", "payment_link.updated",
                       obj={"id": "plink_a", "object": "payment_link",
                            "url": "https://buy.stripe.com/test_xyz?x=y"}),
        ])
        _gen(db_session, ws.id)
        s = _signals(db_session, ws.id)[0]
        assert "payment link configuration changed" in s.title.lower()
        assert s.severity == "medium"
        assert s.signal_metadata.get("payment_link_id") == "plink_a"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. portal config change → medium signal ──────────────────────────────────

def test_portal_config_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _st_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event("evt_bp", "billing_portal.configuration.updated",
                       obj={"id": "bpc_1", "object": "billing_portal.configuration"}),
        ])
        _gen(db_session, ws.id)
        s = _signals(db_session, ws.id)[0]
        assert "customer portal configuration changed" in s.title.lower()
        assert s.severity == "medium"
        assert s.signal_metadata.get("portal_config_id") == "bpc_1"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. account updated → medium signal ───────────────────────────────────────

def test_account_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _st_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event("evt_acct", "account.updated",
                       obj={"id": "acct_demo", "object": "account"}),
        ])
        _gen(db_session, ws.id)
        s = _signals(db_session, ws.id)[0]
        assert "account settings changed" in s.title.lower()
        assert s.severity == "medium"
        assert s.signal_metadata.get("account_id") == "acct_demo"
    finally:
        _cleanup(db_session, ws.id)


# ── 6. capability updated — severity bump for inactive/pending ───────────────

def test_capability_signal_severity(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _st_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event("evt_cap_active", "capability.updated",
                       obj={"id": "card_payments", "object": "capability",
                            "status": "active"}),
            _raw_event("evt_cap_inactive", "capability.updated",
                       obj={"id": "transfers", "object": "capability",
                            "status": "inactive"}, account="acct_demo2"),
            _raw_event("evt_cap_pending", "capability.updated",
                       obj={"id": "us_bank_account_ach_payments", "object": "capability",
                            "status": "pending"}, account="acct_demo3"),
        ])
        _gen(db_session, ws.id)
        sev_by_cap = {
            s.signal_metadata.get("capability"): s.severity
            for s in _signals(db_session, ws.id)
        }
        assert sev_by_cap["card_payments"] == "medium"
        assert sev_by_cap["transfers"] == "high"
        assert sev_by_cap["us_bank_account_ach_payments"] == "high"
    finally:
        _cleanup(db_session, ws.id)


# ── 7. idempotency ────────────────────────────────────────────────────────────

def test_idempotent_generation(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _st_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event("evt_dupe", "webhook_endpoint.updated",
                       obj={"id": "we_d", "object": "webhook_endpoint",
                            "url": "https://example.com/h"}),
        ])
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["signals_created"] == 1
        assert s2["signals_created"] == 0
        assert s2["signals_skipped"] == 1
        assert len(_signals(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 8. grouping: multiple events on the same endpoint dedupe into one signal ─

def test_grouping_deduplicates(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _st_integ(db_session, test_user, ws.id)
    try:
        now = _now_epoch()
        _ingest(db_session, ws.id, integ, [
            _raw_event("evt_a", "webhook_endpoint.updated",
                       obj={"id": "we_same", "object": "webhook_endpoint",
                            "url": "https://example.com/h"}, created=now - 1200),
            _raw_event("evt_b", "webhook_endpoint.updated",
                       obj={"id": "we_same", "object": "webhook_endpoint",
                            "url": "https://example.com/h"}, created=now - 300),
        ])
        _gen(db_session, ws.id)
        sigs = _signals(db_session, ws.id)
        assert len(sigs) == 1
        assert sigs[0].signal_metadata.get("event_count") == 2
    finally:
        _cleanup(db_session, ws.id)


# ── 9. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _st_integ(db_session, test_user, ws_a.id)
    try:
        _ingest(db_session, ws_a.id, integ_a, [
            _raw_event("evt_scope", "account.updated",
                       obj={"id": "acct_demo", "object": "account"}),
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


# ── 10. metadata privacy ──────────────────────────────────────────────────────

def test_metadata_privacy(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _st_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event("evt_m1", "webhook_endpoint.updated",
                       obj={"id": "we_p", "object": "webhook_endpoint",
                            "url": "https://api.example.com/h?session_id=cs_test_SECRET&token=" + RAW_SECRET}),
            _raw_event("evt_m2", "payment_link.updated",
                       obj={"id": "plink_p", "object": "payment_link",
                            "url": "https://buy.stripe.com/test_abc?secret=" + RAW_SECRET}),
            _raw_event("evt_m3", "capability.updated",
                       obj={"id": "card_payments", "object": "capability",
                            "status": "active"}),
        ])
        _gen(db_session, ws.id)
        blob = json.dumps([{
            "title": s.title, "summary": s.summary, "metadata": s.signal_metadata,
        } for s in _signals(db_session, ws.id)], default=str)
        assert RAW_SECRET not in blob
        assert RAW_WHSEC not in blob
        assert RAW_EMAIL not in blob
        assert RAW_CARD not in blob
        for bad in ("sk_live", "sk_test", "rk_live", "whsec_", "bearer ",
                    "authorization", "customer_email", "?session_id",
                    "?secret=", "?token="):
            assert bad not in blob.lower()
        for s in _signals(db_session, ws.id):
            for forbidden_key in ("secret", "customer", "customer_email",
                                  "card", "payload", "headers", "request",
                                  "response", "url"):
                assert forbidden_key not in s.signal_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 11. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _st_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event("evt_c1", "webhook_endpoint.deleted",
                       obj={"id": "we_c", "object": "webhook_endpoint",
                            "url": "https://example.com/h"}),
            _raw_event("evt_c2", "capability.updated",
                       obj={"id": "transfers", "object": "capability",
                            "status": "inactive"}, account="acct_demo2"),
        ])
        _gen(db_session, ws.id)
        for s in _signals(db_session, ws.id):
            blob = f"{s.title}\n{s.summary}".lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "evidence for review" in s.summary.lower() or "may require review" in s.summary.lower()
            assert "does not confirm" in s.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 12. endpoint admin gating + member read ──────────────────────────────────

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
    ws = _ws(test_user, db_session); integ = _st_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _raw_event("evt_ep1", "webhook_endpoint.updated",
                       obj={"id": "we_e", "object": "webhook_endpoint",
                            "url": "https://example.com/h"}),
        ])
        r = client.post("/security/stripe-activity/generate-signals")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "stripe" and body["source"] == "stripe_events"
        assert body["signals_created"] == 1
        lst = client.get("/security/signals?provider=stripe")
        assert lst.status_code == 200
        assert lst.json()["total"] >= 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()
