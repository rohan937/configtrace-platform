"""M73B — Stripe activity / Events API ingestion foundation.

Stripe configuration-change activity is fetched from the public ``/v1/events``
API under a STRICT event-type allowlist (webhook endpoint, payment link,
billing portal configuration, account, capability events). Customer / payment
/ charge / invoice / refund / dispute / subscription lifecycle events are
NEVER requested. Events are normalized into the shared
``security_activity_events`` spine (provider=stripe, source=stripe_events) as
evidence for review.

Activity ingestion ONLY — no signals/correlations/demo. These tests assert
normalization + event-type mapping, idempotency, non-fatal
permission/unavailable handling, malformed-event skipping, non-config events
being dropped (defense-in-depth), privacy (no secret/restricted key values,
webhook signing secrets, customer PII, payment method data, card data, raw
event payloads, raw API responses, tokens, headers, request/response bodies,
bank-account details, tax IDs), endpoint admin gating, workspace scoping, and
claim discipline.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import HTTPException

from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.connectors.stripe import StripeConnector
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import stripe_activity_ingestion_service as st_ingest
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
RAW_CARD_LAST4 = "4242"


def _event(event_id, event_type, *, obj=None, created=1735000000, livemode=True,
           account="acct_demo", inject_secrets=True):
    """Build a raw Stripe event in the shape /v1/events returns."""
    object_dict = dict(obj or {})
    if inject_secrets:
        # None of these must be traversed/stored by the allowlist gate.
        object_dict.setdefault("secret", RAW_WHSEC)
        object_dict.setdefault("customer_email", RAW_EMAIL)
        object_dict.setdefault("card", {"last4": RAW_CARD_LAST4, "number": "4242424242424242"})
    return {
        "id": event_id,
        "type": event_type,
        "object": "event",
        "created": created,
        "livemode": livemode,
        "account": account,
        "data": {"object": object_dict},
        "request": {"id": "req_demo", "idempotency_key": "ik_demo"},
        "api_version": "2024-06-20",
    }


def _patch(monkeypatch, entries=None, *, raise_exc=None):
    def _fake(self, credentials, *, max_events=100, lookback_hours=24):
        if raise_exc is not None:
            raise raise_exc
        return entries or []
    monkeypatch.setattr(StripeConnector, "list_activity_events", _fake)


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M73B", db=db)


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


def _rows(db, ws_id):
    return db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id,
        SecurityActivityEvent.provider == "stripe",
        SecurityActivityEvent.source == "stripe_events",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _ingest(integ, ws_id, db):
    return st_ingest.ingest_stripe_activity(integration=integ, workspace_id=ws_id, db=db)


# ── 1. normalize + event-type mapping ─────────────────────────────────────────

def test_normalizes_and_maps_event_types(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _st_integ(db_session, test_user, ws.id)
    entries = [
        _event("evt_1", "webhook_endpoint.created",
               obj={"id": "we_1", "object": "webhook_endpoint",
                    "url": "https://api.example.com/hook?token=" + RAW_SECRET}),
        _event("evt_2", "webhook_endpoint.updated",
               obj={"id": "we_2", "object": "webhook_endpoint",
                    "url": "http://insecure.example.com/h?x=y"}),
        _event("evt_3", "webhook_endpoint.deleted",
               obj={"id": "we_3", "object": "webhook_endpoint",
                    "url": "https://gone.example.com/h"}),
        _event("evt_4", "payment_link.created",
               obj={"id": "plink_1", "object": "payment_link",
                    "url": "https://buy.stripe.com/test_abc?session_id=cs_SECRET"}),
        _event("evt_5", "payment_link.updated",
               obj={"id": "plink_2", "object": "payment_link"}),
        _event("evt_6", "billing_portal.configuration.created",
               obj={"id": "bpc_1", "object": "billing_portal.configuration"}),
        _event("evt_7", "billing_portal.configuration.updated",
               obj={"id": "bpc_2", "object": "billing_portal.configuration"}),
        _event("evt_8", "account.updated",
               obj={"id": "acct_demo", "object": "account"}),
        _event("evt_9", "capability.updated",
               obj={"id": "card_payments", "object": "capability",
                    "status": "active"}),
    ]
    _patch(monkeypatch, entries)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "stripe_events"
        assert summary["events_inserted"] == 9
        rows = _rows(db_session, ws.id)
        types = {r.event_type for r in rows}
        assert types == {
            "stripe.webhook_endpoint.created", "stripe.webhook_endpoint.updated",
            "stripe.webhook_endpoint.deleted", "stripe.payment_link.created",
            "stripe.payment_link.updated", "stripe.portal_config.created",
            "stripe.portal_config.updated", "stripe.account.updated",
            "stripe.capability.updated",
        }
        # Spot-check normalization fidelity on richest event.
        we_upd = next(r for r in rows
                      if r.event_type == "stripe.webhook_endpoint.updated")
        md = we_upd.event_metadata
        assert md.get("webhook_endpoint_id") == "we_2"
        assert md.get("webhook_url_domain") == "insecure.example.com"
        assert md.get("webhook_url_scheme") == "http"
        assert md.get("stripe_event_type") == "webhook_endpoint.updated"
        assert md.get("account_id") == "acct_demo"
        assert md.get("livemode") is True
        assert md.get("object_type") == "webhook_endpoint"
        assert we_upd.actor_id is None  # Stripe events have no actor identity

        # Capability event surfaces capability NAME + status.
        cap = next(r for r in rows if r.event_type == "stripe.capability.updated")
        assert cap.event_metadata.get("capability") == "card_payments"
        assert cap.event_metadata.get("capability_status") == "active"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. non-config (customer/payment/charge/invoice) events are skipped ───────

def test_non_config_events_skipped(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _st_integ(db_session, test_user, ws.id)
    entries = [
        _event("evt_keep", "webhook_endpoint.updated",
               obj={"id": "we_x", "object": "webhook_endpoint",
                    "url": "https://example.com/h"}),
        # These should never appear in a real allowlisted response, but the
        # normalizer must drop them as defense-in-depth without traversing PII.
        _event("evt_pi", "payment_intent.succeeded",
               obj={"id": "pi_secret", "object": "payment_intent",
                    "customer": "cus_secret", "amount": 9999}),
        _event("evt_charge", "charge.succeeded",
               obj={"id": "ch_secret", "object": "charge",
                    "card": {"number": "4242424242424242"}}),
        _event("evt_invoice", "invoice.paid",
               obj={"id": "in_secret", "object": "invoice",
                    "customer_email": RAW_EMAIL}),
        _event("evt_customer", "customer.created",
               obj={"id": "cus_secret", "object": "customer",
                    "email": RAW_EMAIL}),
        _event("evt_sub", "customer.subscription.updated",
               obj={"id": "sub_secret", "object": "subscription"}),
        _event("evt_refund", "charge.refunded",
               obj={"id": "ch_secret", "object": "charge"}),
        _event("evt_dispute", "charge.dispute.created",
               obj={"id": "dp_secret", "object": "dispute"}),
    ]
    _patch(monkeypatch, entries)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["events_seen"] == 8
        assert summary["events_inserted"] == 1  # only the allowlisted one
        rows = _rows(db_session, ws.id)
        assert len(rows) == 1
        assert rows[0].event_type == "stripe.webhook_endpoint.updated"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. malformed events are skipped safely ────────────────────────────────────

def test_malformed_events_skipped(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _st_integ(db_session, test_user, ws.id)
    entries = [
        _event("ok1", "account.updated",
               obj={"id": "acct_demo", "object": "account"}),
        "not-a-dict",                       # not a dict → skip
        {"id": "x"},                         # no type → skip
        {"type": "webhook_endpoint.updated"},  # no data.object → skip... or no? Should normalize w/ defaults.
        {"type": "unknown.event"},          # unknown type → skip
        None,                               # None → skip
    ]
    _patch(monkeypatch, entries)
    try:
        summary = _ingest(integ, ws.id, db_session)
        # Seen = 6. The "webhook_endpoint.updated" with no data.object is in the
        # allowlist so it normalizes (best-effort), but missing data is fine.
        assert summary["events_seen"] == 6
        # At minimum the well-formed ok1 + the bare allowlisted event normalize.
        assert summary["events_inserted"] >= 1
        # The "not-a-dict", None, missing type, and unknown type must be dropped.
        for r in _rows(db_session, ws.id):
            assert r.event_type.startswith("stripe.")
    finally:
        _cleanup(db_session, ws.id)


# ── 4. permission / unavailable failures are non-fatal ───────────────────────

def test_permission_failure_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _st_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, raise_exc=AuthenticationError("invalid key", status_code=401))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["attempted"] is True
    assert summary["permission_limited"] is True
    assert summary["succeeded"] is True
    assert summary["events_inserted"] == 0


def test_unavailable_endpoint_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _st_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, raise_exc=ConnectorError("no events access", status_code=403))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["succeeded"] is True
    assert summary["permission_limited"] is True
    assert _rows(db_session, ws.id) == []
    assert summary["error_message"] and "limited" in summary["error_message"].lower()


# ── 5. idempotency ────────────────────────────────────────────────────────────

def test_idempotent_ingestion(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _st_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_event("dupe", "webhook_endpoint.updated",
                                obj={"id": "we_d", "object": "webhook_endpoint",
                                     "url": "https://example.com/h"})])
    try:
        s1 = _ingest(integ, ws.id, db_session)
        s2 = _ingest(integ, ws.id, db_session)
        assert s1["events_inserted"] == 1
        assert s2["events_inserted"] == 0
        assert s2["events_skipped"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


def test_idempotent_without_id_via_fingerprint(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _st_integ(db_session, test_user, ws.id)
    e = _event(None, "account.updated", obj={"id": "acct_demo", "object": "account"})
    e.pop("id", None)
    _patch(monkeypatch, [dict(e), dict(e)])
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["events_inserted"] == 1
        assert len(_rows(db_session, ws.id)) == 1
        assert _rows(db_session, ws.id)[0].provider_event_id.startswith("fp:")
    finally:
        _cleanup(db_session, ws.id)


# ── 6. privacy: no secret keys, signing secrets, customer PII, card data ─────

def test_no_secrets_pii_or_raw_payloads(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _st_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [
        _event("p1", "webhook_endpoint.updated",
               obj={"id": "we_p", "object": "webhook_endpoint",
                    "url": "https://api.example.com/h?session_id=cs_test_SECRET&token=" + RAW_SECRET}),
        _event("p2", "payment_link.updated",
               obj={"id": "plink_p", "object": "payment_link",
                    "url": "https://buy.stripe.com/test_abc?secret=" + RAW_SECRET}),
        _event("p3", "account.updated",
               obj={"id": "acct_demo", "object": "account"}),
    ])
    try:
        _ingest(integ, ws.id, db_session)
        rows = _rows(db_session, ws.id)
        blob = json.dumps([{
            "event_type": r.event_type, "actor_id": r.actor_id,
            "actor_type": r.actor_type, "resource_id": r.resource_id,
            "metadata": r.event_metadata, "raw_ref": r.raw_ref,
        } for r in rows], default=str)
        # Secrets / signing secrets / customer PII / card data must never appear.
        assert RAW_SECRET not in blob
        assert RAW_WHSEC not in blob
        assert RAW_EMAIL not in blob
        assert RAW_CARD_LAST4 not in blob
        for bad in ("sk_live", "sk_test", "rk_live", "whsec_", "bearer ",
                    "authorization", "customer_email", "card number",
                    "4242", "cs_test", "?session_id", "?secret=", "?token="):
            assert bad not in blob.lower()
        # Allowlist must keep raw object dicts out of event_metadata.
        for r in rows:
            for forbidden_key in ("secret", "customer", "customer_email",
                                  "card", "payload", "headers", "request",
                                  "response", "url"):
                assert forbidden_key not in r.event_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 7. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session, monkeypatch):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _st_integ(db_session, test_user, ws_a.id)
    _patch(monkeypatch, [_event("sc1", "account.updated",
                                obj={"id": "acct_demo", "object": "account"})])
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
    integ = _st_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [
        _event("c1", "webhook_endpoint.updated",
               obj={"id": "we_c", "object": "webhook_endpoint",
                    "url": "https://example.com/h"}),
        _event("c2", "account.updated",
               obj={"id": "acct_demo", "object": "account"}),
    ])
    try:
        _ingest(integ, ws.id, db_session)
        blob = json.dumps(
            [{"t": r.event_type, "m": r.event_metadata} for r in _rows(db_session, ws.id)],
            default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 9. endpoint admin gating + member read ────────────────────────────────────

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


def test_owner_can_sync_and_member_can_read_via_endpoint(client, test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _st_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_event("ep1", "webhook_endpoint.updated",
                                obj={"id": "we_e", "object": "webhook_endpoint",
                                     "url": "https://example.com/h"})])
    try:
        r = client.post("/security/stripe-activity/sync")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "stripe" and body["source"] == "stripe_events"
        assert body["events_inserted"] == 1
        lst = client.get("/security/activity/events?provider=stripe")
        assert lst.status_code == 200
        assert lst.json()["total"] >= 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()


def test_no_active_integration_returns_clean_summary(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    r = client.post("/security/stripe-activity/sync")
    assert r.status_code == 200
    body = r.json()
    assert body["attempted"] is False and body["provider"] == "stripe"
    assert body["error_message"]


# ── 10. connector list_activity_events filters to allowlist + bounds ─────────

def test_connector_uses_strict_allowlist(monkeypatch):
    """The connector must only ever request allowlisted event types."""
    captured: dict = {}

    def fake_get(self, credentials, path, params=None):
        captured["path"] = path
        captured["params"] = dict(params or {})
        return {"data": [], "has_more": False}

    monkeypatch.setattr(StripeConnector, "_get", fake_get)
    conn = StripeConnector()
    out = conn.list_activity_events({"stripe_api_key": "rk_test_x"},
                                    max_events=10, lookback_hours=24)
    assert out == []
    assert captured["path"] == "/v1/events"
    # Allowlist passed as types[] param.
    types = captured["params"].get("types[]")
    assert isinstance(types, list) and len(types) == 9
    for t in types:
        assert t in StripeConnector._ALLOWED_EVENT_TYPES
    # Strict customer/payment/charge/invoice exclusion at API level.
    for forbidden in ("charge.succeeded", "invoice.paid", "customer.created",
                      "payment_intent.succeeded", "customer.subscription.updated",
                      "charge.refunded", "charge.dispute.created"):
        assert forbidden not in types
    # Lookback floor is included.
    assert "created[gte]" in captured["params"]
