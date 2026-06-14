"""M74D — Shopify configuration-risk × activity correlations.

Correlates an ACTIVE Shopify configuration-risk finding with Shopify
configuration activity (source="shopify_events") for the SAME Shopify object
(webhook id or shop-domain id), when an aligned event falls inside the
finding's review window (first_detected_at - 24h .. last_seen_at + 24h).
Object identity is the finding's Resource.provider_resource_id (or
finding_key-suffix fallback) matched against the event's narrow-key metadata
(webhook_id / domain_id) — never provider-only, never different objects,
never customer / order / checkout / cart / payment / refund / fulfillment
lifecycle events. Correlations only — no demo.

These tests assert per-rule correlation creation, narrow object-id matching
(different webhook / different domain / provider-only / out-of-window all
skip), deferred behavior for app-scope / policy correlations (M74B does not
emit those activity event types), idempotency, linked correlation Incident
Signal creation, list / generate endpoints, metadata privacy, and claim
discipline.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_activity_event_service as activity_svc
from app.services import security_finding_service as finding_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services import shopify_activity_ingestion_service as sh_ingest
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

SHOP_A = "demo-store.myshopify.com"
SHOP_B = "rival-store.myshopify.com"


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M74D", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test",
             display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({
        "shop_domain": SHOP_A, "access_token": RAW_TOKEN,
    })
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="shopify",
                    display_name="shopify", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _res(db, integ, user, *, kind, oid):
    """Create one Resource per Shopify object."""
    r = Resource(integration_id=integ.id, user_id=user.id,
                 provider_resource_type=kind, provider_resource_id=oid,
                 display_name=oid, is_active=True)
    db.add(r); db.commit(); db.refresh(r)
    return r


def _finding(db, ws, integ, res, rule, *, severity="high", evidence=None):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="shopify",
        finding_key=f"{rule}:{res.provider_resource_id}", severity=severity,
        title=f"{rule} risk", resource_id=res.id, description="d",
        evidence=evidence or {"rule": rule}, remediation={"summary": "fix"})


def _raw_event(event_id, subject_type, verb, *, subject_id, metadata=None,
               shop_domain=SHOP_A, myshopify_domain=SHOP_A,
               occurred_offset_seconds=-60, inject_pii=True, livemode=True):
    """Build a raw Shopify event near "now" so it falls inside the review window."""
    when_iso = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(int(time.time()) + occurred_offset_seconds))
    evt = {
        "id": event_id, "subject_id": subject_id,
        "subject_type": subject_type, "verb": verb,
        "created_at": when_iso,
        "shop_domain": shop_domain,
        "myshopify_domain": myshopify_domain,
        "livemode": livemode,
    }
    if metadata is not None:
        evt["metadata"] = metadata
    if inject_pii:
        # Defense-in-depth: forbidden bytes must never survive normalization.
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


def _event(db, ws_id, integ, raw):
    norm = sh_ingest.normalize_shopify_activity_event(raw)
    assert norm is not None, f"event did not normalize: {raw}"
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ.id, normalized=norm, db=db)
    return row


def _gen(db, ws_id):
    return corr_svc.generate_shopify_correlations(workspace_id=ws_id, db=db)


def _corrs(db, ws_id):
    return db.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == ws_id,
        SecuritySignalCorrelation.provider == "shopify",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _setup(db, user):
    ws = _ws(user, db); integ = _integ(db, user, ws.id)
    return ws, integ


# ── 1. HTTP webhook risk × webhook activity ─────────────────────────────────

def test_webhook_insecure_risk_activity(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_webhook", oid="11")
    try:
        _finding(db_session, ws, integ, res, "shopify_webhook_http",
                 severity="critical")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_w1", "Webhook", "update", subject_id=11,
            metadata={"topic": "products/update",
                      "address": "http://insecure.example.com/wh"}))
        s = _gen(db_session, ws.id)
        assert s["provider"] == "shopify" and s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "shopify_webhook_insecure_risk_activity"
        assert c.severity == "critical" and c.confidence == "medium"
        assert c.linked_finding_id and c.linked_activity_event_id
        assert "webhook \"11\"" in c.title
        md = c.correlation_metadata
        assert md.get("webhook_id") == "11"
        assert md.get("webhook_endpoint_scheme") == "http"
        assert md.get("webhook_topic") == "products/update"
        assert md.get("finding_rule") == "shopify_webhook_http"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. high-risk webhook topic × webhook activity ───────────────────────────

def test_webhook_topic_risk_activity(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_webhook", oid="21")
    try:
        _finding(db_session, ws, integ, res, "shopify_webhook_high_risk_topic",
                 severity="medium")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_w2", "Webhook", "update", subject_id=21,
            metadata={"topic": "orders/create",
                      "address": "https://hooks.example.com/wh"}))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "shopify_webhook_topic_risk_activity"
        assert c.severity == "medium"
        assert c.correlation_metadata.get("webhook_topic") == "orders/create"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. domain SSL missing × domain activity ─────────────────────────────────

def test_domain_ssl_risk_activity(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_domain", oid="31")
    try:
        _finding(db_session, ws, integ, res, "shopify_domain_ssl_missing",
                 severity="high")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_d1", "Domain", "update", subject_id=31,
            metadata={"host": "store.example.com"}))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "shopify_domain_ssl_risk_activity"
        assert c.severity == "high"
        assert c.correlation_metadata.get("domain_id") == "31"
        assert c.correlation_metadata.get("domain_host") == "store.example.com"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. domain unverified × domain activity ──────────────────────────────────

def test_domain_verification_risk_activity(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_domain", oid="41")
    try:
        _finding(db_session, ws, integ, res, "shopify_domain_unverified",
                 severity="medium")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_d2", "Domain", "update", subject_id=41,
            metadata={"host": "store.example.com"}))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "shopify_domain_verification_risk_activity"
        assert c.severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. app-scope correlations are DEFERRED (no shopify.app_scopes event yet) ─

def test_app_scope_correlations_deferred(test_user, db_session):
    """M74B does not emit ``shopify.app_scopes.updated`` (no AppScope subject
    type is requested at the API level), so the correlation service must NOT
    synthesize a shopify_app_scope_risk_activity / shopify_customer_scope_risk_
    activity. A finding of either app-scope rule must produce zero correlations
    even when a stray webhook event happens to be present in the workspace."""
    # Pin in the rules map for forward safety.
    assert "shopify_app_broad_write_scopes" \
        in corr_svc._SHOPIFY_DEFERRED_FINDING_RULES
    assert "shopify_app_customer_data_scope" \
        in corr_svc._SHOPIFY_DEFERRED_FINDING_RULES
    assert "shopify_app_broad_write_scopes" \
        not in corr_svc.SHOPIFY_CORRELATION_RULES
    assert "shopify_app_customer_data_scope" \
        not in corr_svc.SHOPIFY_CORRELATION_RULES

    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user,
               kind="shopify_app_scope_summary", oid="app_main")
    try:
        _finding(db_session, ws, integ, res,
                 "shopify_app_broad_write_scopes", severity="high")
        _finding(db_session, ws, integ, res,
                 "shopify_app_customer_data_scope", severity="high")
        # An unrelated (and inadmissible) Webhook event in the same workspace
        # must not produce app-scope correlations.
        _event(db_session, ws.id, integ, _raw_event(
            "evt_x", "Webhook", "update", subject_id=999,
            metadata={"topic": "products/update",
                      "address": "https://example.com/wh"}))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 6. policy correlations are DEFERRED (no shopify.policy.* event yet) ─────

def test_policy_correlations_deferred(test_user, db_session):
    assert "shopify_policy_missing" \
        in corr_svc._SHOPIFY_DEFERRED_FINDING_RULES
    assert "shopify_policy_missing" \
        not in corr_svc.SHOPIFY_CORRELATION_RULES

    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user,
               kind="shopify_store_policy", oid="refund_policy")
    try:
        _finding(db_session, ws, integ, res,
                 "shopify_policy_missing", severity="low")
        # An unrelated (and inadmissible) Webhook event in the same workspace
        # must not produce a policy correlation.
        _event(db_session, ws.id, integ, _raw_event(
            "evt_y", "Webhook", "update", subject_id=999,
            metadata={"topic": "products/update",
                      "address": "https://example.com/wh"}))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 7. different webhook does not correlate ─────────────────────────────────

def test_different_webhook_does_not_correlate(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_webhook", oid="71")
    try:
        _finding(db_session, ws, integ, res, "shopify_webhook_http",
                 severity="critical")
        # Same provider + same event family but a DIFFERENT webhook id.
        _event(db_session, ws.id, integ, _raw_event(
            "evt_other_w", "Webhook", "update", subject_id=72,
            metadata={"topic": "products/update",
                      "address": "http://insecure.example.com/wh"}))
        assert _gen(db_session, ws.id)["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 8. different domain does not correlate ──────────────────────────────────

def test_different_domain_does_not_correlate(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_domain", oid="81")
    try:
        _finding(db_session, ws, integ, res, "shopify_domain_ssl_missing",
                 severity="high")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_other_d", "Domain", "update", subject_id=82,
            metadata={"host": "other.example.com"}))
        assert _gen(db_session, ws.id)["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 9. different shop does not correlate ────────────────────────────────────

def test_different_shop_does_not_correlate(test_user, db_session):
    """The finding's webhook id matches the event's narrow webhook_id, but the
    event was emitted on a DIFFERENT shop. The finding's Resource is set to
    expose the shop identity, so the shop-identity guard rejects the match."""
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_webhook", oid="91")
    # Annotate the Resource with a shop identity so the shop-guard fires.
    setattr(res, "myshopify_domain", SHOP_A)
    db_session.commit()
    try:
        _finding(db_session, ws, integ, res, "shopify_webhook_http",
                 severity="critical")
        # Same webhook id but rival shop on the event.
        _event(db_session, ws.id, integ, _raw_event(
            "evt_other_shop", "Webhook", "update", subject_id=91,
            metadata={"topic": "products/update",
                      "address": "http://insecure.example.com/wh"},
            shop_domain=SHOP_B, myshopify_domain=SHOP_B))
        assert _gen(db_session, ws.id)["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 10. provider-only match never correlates ────────────────────────────────

def test_provider_only_does_not_correlate(test_user, db_session):
    """Two Shopify objects (different kinds) must NEVER correlate just because
    the provider matches."""
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_webhook", oid="101")
    try:
        _finding(db_session, ws, integ, res, "shopify_webhook_http",
                 severity="critical")
        # Domain.update event must not correlate to a webhook finding.
        _event(db_session, ws.id, integ, _raw_event(
            "evt_d_only", "Domain", "update", subject_id=101,
            metadata={"host": "store.example.com"}))
        assert _gen(db_session, ws.id)["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 11. event outside review window does not correlate ──────────────────────

def test_out_of_window_does_not_correlate(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_webhook", oid="111")
    try:
        f = _finding(db_session, ws, integ, res, "shopify_webhook_http",
                     severity="critical")
        # Push the finding's active window way into the future so a "now"
        # event sits well outside [first - 24h, last + 24h].
        future = datetime.now(timezone.utc).replace(microsecond=0)
        f.first_detected_at = future.replace(year=future.year + 1)
        f.last_seen_at = f.first_detected_at
        db_session.commit()
        _event(db_session, ws.id, integ, _raw_event(
            "evt_old", "Webhook", "update", subject_id=111,
            metadata={"topic": "products/update",
                      "address": "http://x.example.com/wh"}))
        assert _gen(db_session, ws.id)["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 12. idempotency ─────────────────────────────────────────────────────────

def test_idempotent_generation(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_webhook", oid="121")
    try:
        _finding(db_session, ws, integ, res, "shopify_webhook_http",
                 severity="critical")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_id", "Webhook", "update", subject_id=121,
            metadata={"topic": "products/update",
                      "address": "http://x.example.com/wh"}))
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["correlations_created"] == 1
        assert s2["correlations_created"] == 0
        assert s2["correlations_skipped"] == 1
        assert len(_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 13. linked correlation Incident Signal is created ───────────────────────

def test_linked_correlation_signal_created(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_webhook", oid="131")
    try:
        _finding(db_session, ws, integ, res, "shopify_webhook_http",
                 severity="critical")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_s", "Webhook", "update", subject_id=131,
            metadata={"topic": "products/update",
                      "address": "http://x.example.com/wh"}))
        _gen(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        assert c.linked_signal_id is not None
        sig = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.id == c.linked_signal_id).first()
        assert sig is not None
        assert sig.evidence_level == "correlation"
        assert sig.signal_type == "shopify_webhook_insecure_risk_activity"
        assert sig.linked_finding_id == c.linked_finding_id
    finally:
        _cleanup(db_session, ws.id)


# ── 14. metadata privacy + claim discipline ─────────────────────────────────

def test_metadata_privacy_and_wording(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_webhook", oid="141")
    try:
        _finding(db_session, ws, integ, res, "shopify_webhook_http",
                 severity="critical")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_p", "Webhook", "update", subject_id=141,
            metadata={"topic": "products/update",
                      "address": "http://x.example.com/h?token=" + RAW_TOKEN}))
        _gen(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        blob = json.dumps({
            "title": c.title, "summary": c.summary,
            "metadata": c.correlation_metadata,
        }, default=str)
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
        # Forbidden claim wording must never appear in any text.
        lower = (c.title + "\n" + c.summary).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in lower
        assert "does not confirm" in c.summary.lower()
        # Allowlist keeps raw event keys out of metadata.
        for forbidden_key in (
            "arguments", "message", "path", "author", "body", "description",
            "secret", "signing_secret", "access_token", "token", "customer",
            "customer_email", "email", "card", "order", "checkout", "cart",
            "payment", "payload", "headers", "request", "response", "raw",
            "url",
        ):
            assert forbidden_key not in c.correlation_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 15. list endpoint filters provider=shopify + correlation_type ───────────

def test_list_endpoint_filters(client, test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="shopify_webhook", oid="151")
    try:
        _finding(db_session, ws, integ, res, "shopify_webhook_http",
                 severity="critical")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_l", "Webhook", "update", subject_id=151,
            metadata={"topic": "products/update",
                      "address": "http://x.example.com/wh"}))
        r = client.post("/security/correlations/generate",
                        json={"provider": "shopify"})
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "shopify"
        assert body["correlations_created"] == 1

        lst = client.get("/security/correlations?provider=shopify")
        assert lst.status_code == 200 and lst.json()["total"] >= 1

        ft = client.get(
            "/security/correlations?provider=shopify"
            "&correlation_type=shopify_webhook_insecure_risk_activity")
        assert ft.status_code == 200 and ft.json()["total"] >= 1

        # An unrelated type yields zero.
        empty = client.get(
            "/security/correlations?provider=shopify"
            "&correlation_type=shopify_domain_ssl_risk_activity")
        assert empty.status_code == 200 and empty.json()["total"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 16. endpoint admin gating: member cannot generate ───────────────────────

def test_member_cannot_generate(test_user, db_session):
    owner = _new_user(db_session, "owner_sh_corr")
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
