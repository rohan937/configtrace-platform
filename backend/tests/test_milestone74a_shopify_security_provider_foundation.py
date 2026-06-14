"""M74A — Shopify security provider foundation (configuration-risk only).

Expands the existing Shopify config-risk provider (which already had
``shopify_webhook_http``) with a safe SHOPIFY_DOMAIN surface and SIX NEW
data-backed, business-critical configuration rules over metadata-only fields:

  * shopify_webhook_high_risk_topic   — orders/customers/checkouts/etc.
  * shopify_app_broad_write_scopes    — 3+ curated high-risk write scopes
  * shopify_app_customer_data_scope   — exact read_/write_customers grant
  * shopify_domain_ssl_missing        — primary domain ssl_enabled=false
  * shopify_domain_unverified         — primary domain verified=false
  * shopify_policy_missing            — canonical store policy not present

The webhook-disabled and per-scope-presence rules are deferred (documented).
These tests assert: Shopify connector normalization without secrets/PII,
each new + existing rule, idempotency, fail-soft connector behavior,
evidence privacy, claim discipline, deferral, and
registry/confidence/rule-pack/coverage parity.
"""

from __future__ import annotations

import json
import uuid

from app.connectors.shopify import ShopifyConnector
from app.connectors.shopify_schema import (
    SHOPIFY_APP_SCOPE_SUMMARY,
    SHOPIFY_DOMAIN,
    SHOPIFY_RECORD_TYPES,
    SHOPIFY_SHOP_METADATA,
    SHOPIFY_STANDARD_POLICY_TYPES,
    SHOPIFY_STORE_POLICY,
    SHOPIFY_WEBHOOK_SUBSCRIPTION,
)
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.services import security_finding_evaluator as evaluator
from app.services.security_coverage_service import RULE_RECORD_TYPES
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "secret leaked", "data leaked", "customer data leaked",
    "payment fraud detected", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
    "orders exposed", "card data exposed",
]
RAW_TOKEN = "shpat_must_never_appear"
RAW_CUSTOMER_EMAIL = "shopper@example.com"
RAW_ORDER_NOTE = "Customer ordered 2 items"
RAW_POLICY_BODY = "By placing an order you agree to ..."
RAW_WEBHOOK_PATH = "/incoming/hmac/SECRET-PATH-token-" + RAW_TOKEN

_NEW_RULE_KEYS = {
    "shopify_webhook_high_risk_topic",
    "shopify_app_broad_write_scopes",
    "shopify_app_customer_data_scope",
    "shopify_domain_ssl_missing",
    "shopify_domain_unverified",
    "shopify_policy_missing",
}
_DEFERRED_RULE_KEYS = {
    "shopify_webhook_insecure_url",   # superseded by shopify_webhook_http
    "shopify_webhook_disabled",        # no enabled/disabled field on records
    "shopify_app_any_scope",           # raw any-scope-presence rule
    "shopify_app_payment_scope",       # too low-signal; use broad_write rule
}


# ── fixtures / helpers ────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M74A", db=db)


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({
        "shop_domain": "demo-shop.myshopify.com",
        "shopify_access_token": RAW_TOKEN,
    })
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="shopify",
                    display_name="shopify", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _res(db, integ, user):
    r = Resource(integration_id=integ.id, user_id=user.id,
                 provider_resource_type="shopify_shop",
                 provider_resource_id="demo-shop.myshopify.com",
                 display_name="demo-shop.myshopify.com", is_active=True)
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


def _webhook(rid, *, topic="orders/create", scheme="https",
             domain="hooks.example.com"):
    return {
        "record_type": SHOPIFY_WEBHOOK_SUBSCRIPTION,
        "record_id": rid, "name": f"{topic} -> {domain}",
        "webhook_id_hash": rid, "topic": topic,
        "endpoint_domain": domain, "endpoint_scheme": scheme,
        "endpoint_path_hash": "abc123", "endpoint_path_length": 12,
        "is_https": scheme == "https",
        "format": "json", "api_version": "2024-01",
    }


def _scope_summary(rid="demo-shop.myshopify.com:app_scopes", *, scopes=()):
    scope_names = sorted(scopes)
    return {
        "record_type": SHOPIFY_APP_SCOPE_SUMMARY,
        "record_id": rid, "name": f"app scopes ({rid})",
        "scope_count": len(scope_names),
        "write_scope_count": sum(1 for s in scope_names if s.startswith("write_")),
        "sensitive_scope_count": 0,
        "customer_scope_present": any("customer" in s for s in scope_names),
        "order_scope_present": any("order" in s for s in scope_names),
        "payment_scope_present": False,
        "scope_hash": "abc",
        "scope_names": scope_names,
    }


def _domain(rid, *, host="demo.example.com", primary=True,
            ssl_enabled=True, verified=True):
    return {
        "record_type": SHOPIFY_DOMAIN,
        "record_id": rid, "name": host,
        "domain_id_hash": "h1", "host": host,
        "ssl_enabled": ssl_enabled, "primary": primary,
        "verified": verified,
    }


def _policy(rid, *, policy_type="refund_policy", present=False):
    return {
        "record_type": SHOPIFY_STORE_POLICY,
        "record_id": rid, "name": f"{policy_type} policy",
        "policy_type": policy_type, "present": present,
        "body_hash": None, "body_length": 0,
    }


# ── 1. connector normalizes webhook/shop/policy/scope/domain safely ──────────

def test_connector_decompose_webhook_url_safe():
    parts = ShopifyConnector._decompose_webhook_url(
        f"https://hooks.example.com{RAW_WEBHOOK_PATH}?token={RAW_TOKEN}"
    )
    blob = json.dumps(parts)
    # The raw URL, path, and token must never survive normalization.
    assert RAW_TOKEN not in blob
    assert "SECRET-PATH" not in blob
    assert parts["endpoint_domain"] == "hooks.example.com"
    assert parts["endpoint_scheme"] == "https"
    assert parts["is_https"] is True


def test_connector_emits_policy_baseline_when_api_missing_some(monkeypatch):
    """When the policies API returns 0 policies, the connector emits a
    ``present=False`` baseline record for each canonical policy type so the
    M74A policy-missing rule can fire deterministically."""
    conn = ShopifyConnector()

    def _get(creds, path, params=None):
        if path == "/policies.json":
            return {"policies": []}
        # The connector only calls _fetch_store_policies inside this test.
        raise AssertionError(f"unexpected path: {path}")

    monkeypatch.setattr(conn, "_get", _get)
    out = conn._fetch_store_policies({"shop_domain": "demo-shop.myshopify.com"})
    types = {r.get("policy_type") for r in out}
    assert set(SHOPIFY_STANDARD_POLICY_TYPES) <= types
    # All baseline records assert absence and store no secret bytes.
    blob = json.dumps(out)
    for bad in (RAW_POLICY_BODY, RAW_CUSTOMER_EMAIL, RAW_ORDER_NOTE, RAW_TOKEN):
        assert bad not in blob
    for r in out:
        if r["policy_type"] in SHOPIFY_STANDARD_POLICY_TYPES:
            assert r["present"] is False
            # The connector NEVER stores raw policy bodies.
            assert "body" not in r and "raw_body" not in r


def test_connector_fetch_domains_normalization(monkeypatch):
    conn = ShopifyConnector()
    raw = {"domains": [
        {"id": 100, "host": "demo-shop.example.com", "ssl_enabled": False,
         "primary": True, "verified": False, "managed_by_shopify": True,
         # Forbidden bytes that must not survive allowlisting:
         "owner_email": RAW_CUSTOMER_EMAIL, "raw_dns": ["A 1.2.3.4"]},
        {"id": 101, "host": "alias.example.com", "ssl_enabled": True,
         "primary": False, "verified": True},
    ]}

    def _get(creds, path, params=None):
        assert path == "/shop/domains.json"
        return raw

    monkeypatch.setattr(conn, "_get", _get)
    out = conn._fetch_domains({"shop_domain": "demo-shop.myshopify.com"})
    assert len(out) == 2
    blob = json.dumps(out)
    assert RAW_CUSTOMER_EMAIL not in blob
    assert "1.2.3.4" not in blob
    primary = next(r for r in out if r["primary"] is True)
    assert primary["host"] == "demo-shop.example.com"
    assert primary["ssl_enabled"] is False
    assert primary["verified"] is False
    for r in out:
        assert r["record_type"] == SHOPIFY_DOMAIN
        for forbidden in ("owner_email", "raw_dns", "raw_url"):
            assert forbidden not in r


# ── 2. plain-HTTP webhook fires (existing rule, unchanged) ───────────────────

def test_webhook_http_existing(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_webhook("we_http", scheme="http", topic="products/update")])
        keys = {f.finding_key.split(":", 1)[0] for f in _active(db_session, ws.id, res.id)}
        assert "shopify_webhook_http" in keys
    finally:
        _cleanup(db_session, ws.id)


# ── 3. high-risk webhook topic ────────────────────────────────────────────────

def test_webhook_high_risk_topic_orders(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_webhook("we_orders", topic="orders/create")])
        keys = {f.finding_key.split(":", 1)[0] for f in _active(db_session, ws.id, res.id)}
        assert "shopify_webhook_high_risk_topic" in keys
        # HTTPS endpoint → no http rule.
        assert "shopify_webhook_http" not in keys
    finally:
        _cleanup(db_session, ws.id)


def test_webhook_high_risk_topic_app_uninstalled(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_webhook("we_app", topic="app/uninstalled")])
        keys = {f.finding_key.split(":", 1)[0] for f in _active(db_session, ws.id, res.id)}
        assert "shopify_webhook_high_risk_topic" in keys
    finally:
        _cleanup(db_session, ws.id)


def test_webhook_normal_topic_clean(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_webhook("we_ok", topic="products/update")])
        assert _active(db_session, ws.id, res.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 4. broad high-risk write scopes ───────────────────────────────────────────

def test_app_broad_write_scopes_medium(test_user, db_session):
    """3 high-risk write scopes → medium."""
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_scope_summary(scopes=["write_orders", "write_products", "write_inventory"])])
        findings = _active(db_session, ws.id, res.id)
        by_rule = {f.finding_key.split(":", 1)[0]: f for f in findings}
        assert by_rule["shopify_app_broad_write_scopes"].severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


def test_app_broad_write_scopes_high(test_user, db_session):
    """4 high-risk write scopes → high."""
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _scope_summary(scopes=[
                "write_orders", "write_products", "write_inventory",
                "write_fulfillments", "read_themes",
            ]),
        ])
        findings = _active(db_session, ws.id, res.id)
        by_rule = {f.finding_key.split(":", 1)[0]: f for f in findings}
        assert by_rule["shopify_app_broad_write_scopes"].severity == "high"
    finally:
        _cleanup(db_session, ws.id)


def test_app_broad_write_scopes_below_threshold(test_user, db_session):
    """Only 2 high-risk write scopes — does not fire."""
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_scope_summary(scopes=["write_orders", "write_themes"])])
        keys = {f.finding_key.split(":", 1)[0] for f in _active(db_session, ws.id, res.id)}
        assert "shopify_app_broad_write_scopes" not in keys
    finally:
        _cleanup(db_session, ws.id)


# ── 5. customer-data scope ────────────────────────────────────────────────────

def test_app_customer_data_scope_read(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_scope_summary(scopes=["read_customers", "read_themes"])])
        keys = {f.finding_key.split(":", 1)[0] for f in _active(db_session, ws.id, res.id)}
        assert "shopify_app_customer_data_scope" in keys
    finally:
        _cleanup(db_session, ws.id)


def test_app_customer_substring_scope_does_not_fire(test_user, db_session):
    """A broader customer-substring scope (e.g. customer_payment_methods) must
    NOT trigger the customer-data rule — only the exact read/write_customers
    handles do."""
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_scope_summary(scopes=["read_customer_payment_methods"])])
        keys = {f.finding_key.split(":", 1)[0] for f in _active(db_session, ws.id, res.id)}
        assert "shopify_app_customer_data_scope" not in keys
    finally:
        _cleanup(db_session, ws.id)


# ── 6. domain rules ───────────────────────────────────────────────────────────

def test_domain_ssl_missing(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _domain("d_primary", host="store.example.com", primary=True,
                    ssl_enabled=False, verified=True),
        ])
        keys = {f.finding_key.split(":", 1)[0] for f in _active(db_session, ws.id, res.id)}
        assert "shopify_domain_ssl_missing" in keys
    finally:
        _cleanup(db_session, ws.id)


def test_domain_unverified(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _domain("d_primary", host="store.example.com", primary=True,
                    ssl_enabled=True, verified=False),
        ])
        keys = {f.finding_key.split(":", 1)[0] for f in _active(db_session, ws.id, res.id)}
        assert "shopify_domain_unverified" in keys
    finally:
        _cleanup(db_session, ws.id)


def test_domain_non_primary_clean(test_user, db_session):
    """An alias (non-primary) domain with missing SSL must not fire — the rule
    is scoped to the primary domain."""
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _domain("d_alias", host="alias.example.com", primary=False,
                    ssl_enabled=False, verified=False),
        ])
        assert _active(db_session, ws.id, res.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 7. policy missing ────────────────────────────────────────────────────────

def test_policy_missing(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _policy("p_refund", policy_type="refund_policy", present=False),
            _policy("p_privacy", policy_type="privacy_policy", present=True),
        ])
        findings = _active(db_session, ws.id, res.id)
        by_rule = {f.finding_key.split(":", 1)[0]: f for f in findings}
        assert "shopify_policy_missing" in by_rule
        # The present=True policy does not fire.
        assert by_rule["shopify_policy_missing"].evidence.get("policy_type") == "refund_policy"
    finally:
        _cleanup(db_session, ws.id)


# ── 8. idempotent re-evaluation ──────────────────────────────────────────────

def test_idempotent_reevaluation(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    state = [
        _webhook("we_orders", topic="orders/create"),
        _scope_summary(scopes=["write_orders", "write_products", "write_inventory",
                               "write_fulfillments", "read_customers"]),
        _domain("d_primary", host="store.example.com", primary=True,
                ssl_enabled=False, verified=False),
        _policy("p_refund", policy_type="refund_policy", present=False),
    ]
    try:
        _evaluate(db_session, ws, integ, res, test_user, state)
        ids = {f.id for f in _active(db_session, ws.id, res.id)}
        assert ids
        _evaluate(db_session, ws, integ, res, test_user, state)
        assert {f.id for f in _active(db_session, ws.id, res.id)} == ids
    finally:
        _cleanup(db_session, ws.id)


# ── 9. connector fail-soft (no domains accessible) ───────────────────────────

def test_connector_fetch_domains_fails_soft(monkeypatch):
    from app.connectors.exceptions import ConnectorError

    conn = ShopifyConnector()

    def _get(creds, path, params=None):
        raise ConnectorError("forbidden", status_code=403)

    monkeypatch.setattr(conn, "_get", _get)
    # Fail-soft: empty list instead of raising.
    assert conn._fetch_domains({"shop_domain": "demo-shop.myshopify.com"}) == []


# ── 10. evidence privacy + claim discipline ──────────────────────────────────

def test_evidence_and_wording_are_safe(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _webhook("we_http", topic="orders/create", scheme="http"),
            _scope_summary(scopes=["write_orders", "write_products", "write_inventory",
                                   "write_fulfillments", "read_customers", "write_customers"]),
            _domain("d_primary", host="store.example.com", primary=True,
                    ssl_enabled=False, verified=False),
            _policy("p_refund", policy_type="refund_policy", present=False),
        ])
        findings = _active(db_session, ws.id, res.id)
        assert findings
        blob = json.dumps(
            [{"t": f.title, "d": f.description, "e": f.evidence, "r": f.remediation}
             for f in findings], default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
        for bad in ("shpat_", "shppa_", "bearer ", "x-shopify-access-token",
                    RAW_TOKEN.lower(), RAW_CUSTOMER_EMAIL.lower(),
                    RAW_ORDER_NOTE.lower(), RAW_POLICY_BODY.lower(),
                    "secret-path"):
            assert bad not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 11. deferred rules are not registered ────────────────────────────────────

def test_deferred_rules_not_registered():
    for key in _DEFERRED_RULE_KEYS:
        assert key not in KNOWN_RULE_KEYS, f"{key} should be deferred"


# ── 12. registry / confidence / pack / coverage parity ───────────────────────

def test_new_keys_registered_everywhere():
    for key in _NEW_RULE_KEYS:
        assert key in KNOWN_RULE_KEYS, f"{key} missing from KNOWN_RULE_KEYS"
        assert key in RULE_CONFIDENCE, f"{key} missing from RULE_CONFIDENCE"
        assert key in _RULE_META, f"{key} missing from _RULE_META"
        assert key in RULE_RECORD_TYPES, f"{key} missing from RULE_RECORD_TYPES"
        assert _RULE_META[key][0] == "shopify"
    # Global parity invariants stay intact.
    assert KNOWN_RULE_KEYS == set(RULE_CONFIDENCE)
    assert set(_RULE_META) == set(KNOWN_RULE_KEYS)
    # New SHOPIFY_DOMAIN record type is in the schema's record-type set.
    assert SHOPIFY_DOMAIN in SHOPIFY_RECORD_TYPES
