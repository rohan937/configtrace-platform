"""M74B — Shopify activity / Events API ingestion foundation.

Shopify configuration-change activity is fetched from the public
``/admin/api/{version}/events.json`` REST API under a STRICT ``subject_type``
allowlist (``Webhook``, ``Shop``, ``Domain``). Customer / order / checkout /
cart / payment / fulfillment / refund / inventory / staff subject types are
NEVER requested. Events are normalized into the shared
``security_activity_events`` spine (provider=shopify, source=shopify_events) as
evidence for review.

Activity ingestion ONLY — no signals/correlations/demo. These tests assert
normalization + event-type mapping, idempotency, non-fatal
permission/unavailable handling, malformed-event skipping, non-config events
being dropped (defense-in-depth), privacy (no Admin API tokens, OAuth tokens,
webhook signing secrets, customer PII, order details, card data, raw event
``arguments`` / ``message`` / ``path`` / ``author``, raw API responses, auth
headers, request/response bodies, bank-account details, tax IDs, staff
names/emails), endpoint admin gating, workspace scoping, and claim discipline.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import HTTPException

from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.connectors.shopify import ShopifyConnector
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import shopify_activity_ingestion_service as sh_ingest
from app.services import workspace_permission_service
from app.services import workspace_service

# Forbidden claim wording (M74B set). These must never appear in normalized
# event metadata or response bodies — the system describes "evidence for
# review", not confirmed compromise / breach / attack / leakage.
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


def _event(event_id, subject_type, verb, *, subject_id=None,
           created_at="2026-06-14T10:00:00Z", shop_domain="demo.example.com",
           myshopify_domain="demo-store.myshopify.com",
           inject_pii=True, metadata=None, livemode=True):
    """Build a raw Shopify event in the shape /admin/api/{ver}/events.json returns.

    inject_pii=True salts the event with strings the normalizer must NEVER
    traverse or surface (raw arguments, message, path, author).
    """
    evt = {
        "id": event_id,
        "subject_id": subject_id if subject_id is not None else 1000,
        "subject_type": subject_type,
        "verb": verb,
        "created_at": created_at,
        "shop_domain": shop_domain,
        "myshopify_domain": myshopify_domain,
        "livemode": livemode,
    }
    if metadata is not None:
        evt["metadata"] = metadata
    if inject_pii:
        # None of these fields must be traversed/stored by the allowlist gate.
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
        evt["description"] = f"customer {RAW_EMAIL} card {RAW_CARD_LAST4}"
    return evt


def _patch(monkeypatch, entries=None, *, raise_exc=None):
    def _fake(self, credentials, *, max_events=100, lookback_hours=24):
        if raise_exc is not None:
            raise raise_exc
        return entries or []
    monkeypatch.setattr(ShopifyConnector, "list_activity_events", _fake)


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M74B", db=db)


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


def _rows(db, ws_id):
    return db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id,
        SecurityActivityEvent.provider == "shopify",
        SecurityActivityEvent.source == "shopify_events",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(
            synchronize_session=False)
    db.commit()


def _ingest(integ, ws_id, db):
    return sh_ingest.ingest_shopify_activity(
        integration=integ, workspace_id=ws_id, db=db)


# ── 1. normalize + event-type mapping ─────────────────────────────────────────

def test_normalizes_and_maps_event_types(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sh_integ(db_session, test_user, ws.id)
    entries = [
        _event(101, "Webhook", "create", subject_id=11,
               metadata={"topic": "products/update",
                         "address": "https://hooks.example.com/wh"}),
        _event(102, "Webhook", "update", subject_id=12,
               metadata={"topic": "products/update",
                         "address": "http://insecure.example.com/wh"}),
        _event(103, "Webhook", "destroy", subject_id=13,
               metadata={"topic": "products/update",
                         "address": "https://gone.example.com/wh"}),
        _event(201, "Shop", "update", subject_id=901),
        _event(301, "Domain", "create", subject_id=31,
               metadata={"host": "store.example.com"}),
        _event(302, "Domain", "update", subject_id=32,
               metadata={"host": "store.example.com"}),
        _event(303, "Domain", "destroy", subject_id=33,
               metadata={"host": "old.example.com"}),
    ]
    _patch(monkeypatch, entries)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "shopify_events"
        assert summary["provider"] == "shopify"
        assert summary["events_inserted"] == 7
        rows = _rows(db_session, ws.id)
        types = {r.event_type for r in rows}
        assert types == {
            "shopify.webhook.created", "shopify.webhook.updated",
            "shopify.webhook.deleted", "shopify.shop.updated",
            "shopify.domain.created", "shopify.domain.updated",
            "shopify.domain.deleted",
        }
        # Spot-check the richest case: webhook update preserves NAME-only
        # fields and never the raw event payload / arguments / message.
        wh_upd = next(r for r in rows
                      if r.event_type == "shopify.webhook.updated")
        md = wh_upd.event_metadata
        assert md.get("webhook_id") == "12"
        assert md.get("webhook_endpoint_domain") == "insecure.example.com"
        assert md.get("webhook_endpoint_scheme") == "http"
        assert md.get("webhook_topic") == "products/update"
        assert md.get("shopify_event_type") == "Webhook/update"
        assert md.get("event_action") == "update"
        assert md.get("shop_domain") == "demo.example.com"
        assert md.get("myshopify_domain") == "demo-store.myshopify.com"
        assert md.get("object_type") == "Webhook"
        assert md.get("livemode") is True
        # No actor identity — Shopify ``author`` is intentionally not stored.
        assert wh_upd.actor_id is None
        assert wh_upd.actor_type is None

        # Domain event surfaces domain_id + host NAME only.
        dom = next(r for r in rows if r.event_type == "shopify.domain.created")
        assert dom.event_metadata.get("domain_id") == "31"
        assert dom.event_metadata.get("domain_host") == "store.example.com"

        # Shop update has the shop domain present but no webhook/domain fields.
        shop = next(r for r in rows if r.event_type == "shopify.shop.updated")
        assert shop.event_metadata.get("object_type") == "Shop"
        assert "webhook_id" not in shop.event_metadata
        assert "domain_id" not in shop.event_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 2. non-config (customer/order/cart/payment/etc.) events are skipped ──────

def test_non_config_events_skipped(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sh_integ(db_session, test_user, ws.id)
    entries = [
        _event(1000, "Webhook", "update", subject_id=99,
               metadata={"topic": "products/update",
                         "address": "https://example.com/wh"}),
        # These should never appear in a real allowlisted response, but the
        # normalizer must drop them as defense-in-depth without traversing
        # arguments / message / path. Each carries customer/order/payment data
        # that absolutely must not surface in event_metadata.
        _event(1001, "Order", "create", subject_id=int(RAW_ORDER_ID),
               metadata={"order_number": RAW_ORDER_ID,
                         "customer_email": RAW_EMAIL}),
        _event(1002, "Customer", "create", subject_id=12345,
               metadata={"email": RAW_EMAIL}),
        _event(1003, "Checkout", "update", subject_id=22222,
               metadata={"cart_token": "ct_secret"}),
        _event(1004, "Cart", "create", subject_id=33333),
        _event(1005, "Refund", "create", subject_id=44444),
        _event(1006, "Fulfillment", "update", subject_id=55555),
        _event(1007, "InventoryItem", "update", subject_id=66666),
        _event(1008, "Article", "create", subject_id=77777),
    ]
    _patch(monkeypatch, entries)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["events_seen"] == 9
        assert summary["events_inserted"] == 1  # only the allowlisted one
        rows = _rows(db_session, ws.id)
        assert len(rows) == 1
        assert rows[0].event_type == "shopify.webhook.updated"
        # Defense-in-depth check: the kept row must not reference any of the
        # dropped events' identifiers or PII.
        md = rows[0].event_metadata
        assert md.get("object_type") == "Webhook"
        blob = json.dumps(md, default=str)
        assert RAW_ORDER_ID not in blob
        assert RAW_EMAIL not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 3. malformed events are skipped safely ────────────────────────────────────

def test_malformed_events_skipped(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sh_integ(db_session, test_user, ws.id)
    entries = [
        _event(2001, "Shop", "update", subject_id=701),
        "not-a-dict",                                # not a dict → skip
        {"id": 1},                                    # no subject_type/verb → skip
        {"subject_type": "Webhook"},                  # no verb → skip
        {"subject_type": "Webhook", "verb": "weird"},  # unknown verb → skip
        {"subject_type": "Unknown", "verb": "create"},  # unknown subject → skip
        None,                                         # None → skip
    ]
    _patch(monkeypatch, entries)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["events_seen"] == 7
        # Only the well-formed Shop/update normalizes.
        assert summary["events_inserted"] == 1
        rows = _rows(db_session, ws.id)
        assert len(rows) == 1
        assert rows[0].event_type == "shopify.shop.updated"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. permission / unavailable failures are non-fatal ───────────────────────

def test_permission_failure_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch,
           raise_exc=AuthenticationError("invalid token", status_code=401))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["attempted"] is True
    assert summary["permission_limited"] is True
    assert summary["succeeded"] is True
    assert summary["events_inserted"] == 0


def test_unavailable_endpoint_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch,
           raise_exc=ConnectorError("no events scope", status_code=403))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["succeeded"] is True
    assert summary["permission_limited"] is True
    assert _rows(db_session, ws.id) == []
    assert summary["error_message"] and "limited" in summary["error_message"].lower()


# ── 5. idempotency ────────────────────────────────────────────────────────────

def test_idempotent_ingestion(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_event(3001, "Webhook", "update", subject_id=801,
                                metadata={"topic": "products/update",
                                          "address": "https://example.com/wh"})])
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
    integ = _sh_integ(db_session, test_user, ws.id)
    e = _event(None, "Shop", "update", subject_id=901)
    e.pop("id", None)
    _patch(monkeypatch, [dict(e), dict(e)])
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["events_inserted"] == 1
        assert len(_rows(db_session, ws.id)) == 1
        assert _rows(db_session, ws.id)[0].provider_event_id.startswith("fp:")
    finally:
        _cleanup(db_session, ws.id)


# ── 6. privacy: no tokens, signing secrets, customer PII, orders, card data ──

def test_no_secrets_pii_or_raw_payloads(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [
        _event(4001, "Webhook", "update", subject_id=11,
               metadata={"topic": "products/update",
                         "address": "https://api.example.com/h?token=" + RAW_TOKEN}),
        _event(4002, "Shop", "update", subject_id=12),
        _event(4003, "Domain", "update", subject_id=13,
               metadata={"host": "store.example.com"}),
    ])
    try:
        _ingest(integ, ws.id, db_session)
        rows = _rows(db_session, ws.id)
        blob = json.dumps([{
            "event_type": r.event_type, "actor_id": r.actor_id,
            "actor_type": r.actor_type, "resource_id": r.resource_id,
            "metadata": r.event_metadata, "raw_ref": r.raw_ref,
        } for r in rows], default=str)
        # Secrets / tokens / customer PII / card / order data must never appear.
        assert RAW_TOKEN not in blob
        assert RAW_WHSEC not in blob
        assert RAW_EMAIL not in blob
        assert RAW_CARD_LAST4 not in blob
        assert RAW_ORDER_ID not in blob
        assert RAW_STAFF_NAME not in blob
        for bad in ("shpat_", "shpss_", "shpca_", "shpapp_", "whsec_",
                    "bearer ", "authorization", "customer_email",
                    "card number", "4242", "?token=", "?session_id",
                    "?secret=", "arguments", "?cart_token="):
            assert bad not in blob.lower()
        # Allowlist must keep raw event/object dicts out of event_metadata.
        for r in rows:
            for forbidden_key in (
                "arguments", "message", "path", "author", "body",
                "description", "secret", "signing_secret", "access_token",
                "token", "customer", "customer_email", "email", "card",
                "order", "checkout", "cart", "payment", "payload",
                "headers", "request", "response", "raw",
            ):
                assert forbidden_key not in r.event_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 7. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session, monkeypatch):
    other = _new_user(db_session, "other_sh")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _sh_integ(db_session, test_user, ws_a.id)
    _patch(monkeypatch, [_event(5001, "Shop", "update", subject_id=901)])
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
    integ = _sh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [
        _event(6001, "Webhook", "update", subject_id=11,
               metadata={"topic": "products/update",
                         "address": "https://example.com/wh"}),
        _event(6002, "Shop", "update", subject_id=12),
    ])
    try:
        summary = _ingest(integ, ws.id, db_session)
        blob = json.dumps([
            {"t": r.event_type, "m": r.event_metadata}
            for r in _rows(db_session, ws.id)
        ], default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
        for phrase in _FORBIDDEN:
            assert phrase not in json.dumps(summary, default=str).lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 9. endpoint admin gating + member read ────────────────────────────────────

def test_member_cannot_sync(test_user, db_session):
    owner = _new_user(db_session, "owner_sh")
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


def test_owner_can_sync_and_member_can_read_via_endpoint(
        client, test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_event(7001, "Webhook", "update", subject_id=701,
                                metadata={"topic": "products/update",
                                          "address": "https://example.com/wh"})])
    try:
        r = client.post("/security/shopify-activity/sync")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "shopify"
        assert body["source"] == "shopify_events"
        assert body["events_inserted"] == 1
        # Member read via the shared activity endpoint.
        lst = client.get("/security/activity/events?provider=shopify")
        assert lst.status_code == 200
        assert lst.json()["total"] >= 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(
            Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()


def test_no_active_integration_returns_clean_summary(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    r = client.post("/security/shopify-activity/sync")
    assert r.status_code == 200
    body = r.json()
    assert body["attempted"] is False
    assert body["provider"] == "shopify"
    assert body["source"] == "shopify_events"
    assert body["error_message"]


# ── 10. connector list_activity_events filters to strict subject_type allowlist

def test_connector_uses_strict_subject_type_allowlist(monkeypatch):
    """The connector must request ONLY Webhook/Shop/Domain subject types.

    Customer / order / checkout / cart / payment / fulfillment / refund /
    inventory / staff subject types must not appear in any outgoing API call.
    """
    captured: list[dict] = []

    def fake_get(self, credentials, path, params=None):
        captured.append({"path": path, "params": dict(params or {})})
        return {"events": []}

    monkeypatch.setattr(ShopifyConnector, "_get", fake_get)
    conn = ShopifyConnector()
    out = conn.list_activity_events(
        {"shop_domain": "demo.myshopify.com", "access_token": "shpat_x"},
        max_events=10, lookback_hours=24)
    assert out == []
    assert captured, "connector must call _get at least once"
    first = captured[0]
    assert first["path"] == "/events.json"
    params = first["params"]
    # ``filter`` is the API-level subject-type allowlist.
    filt = params.get("filter", "")
    assert isinstance(filt, str)
    allowed = {s.strip() for s in filt.split(",") if s.strip()}
    assert allowed == {"Webhook", "Shop", "Domain"}
    for forbidden in ("Order", "Customer", "Checkout", "Cart", "Payment",
                      "Fulfillment", "Refund", "InventoryItem",
                      "InventoryLevel", "Article", "Blog", "Staff"):
        assert forbidden not in allowed
        assert forbidden not in filt
    # Lookback floor is included.
    assert "created_at_min" in params
    # Per-page cap is bounded.
    assert int(params.get("limit", 0)) <= 250
