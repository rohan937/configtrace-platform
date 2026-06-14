"""M73A — Stripe security provider foundation (configuration-risk only).

Expands the existing Stripe config-risk provider (which already had
``stripe_webhook_http``) with a safe Payment Links surface and seven NEW
data-backed, business-critical configuration rules over metadata-only fields:

  * stripe_webhook_disabled                  — endpoint status disabled
  * stripe_webhook_broad_events              — wildcard '*' / very large event set
  * stripe_payment_link_tax_disabled         — active link, automatic tax off
  * stripe_payment_link_promo_codes_enabled  — active link allows promo codes
  * stripe_portal_subscription_cancel_enabled — portal self-serve cancellation on
  * stripe_portal_login_enabled              — portal hosted login page on
  * stripe_account_capability_incomplete     — charges/payouts/details not done

The insecure-URL duplicate, restricted-key/live-mode, and standalone tax-settings
rules are deferred (documented). These tests assert connector normalization with
no secret/customer/payment data, each new + existing rule, idempotency, fail-soft
connector behavior, evidence privacy, claim discipline, deferral, and
registry/confidence/rule-pack/coverage parity.
"""

from __future__ import annotations

import json
import uuid

from app.connectors.stripe import StripeConnector, _url_origin
from app.connectors.stripe_schema import (
    STRIPE_ACCOUNT_SETTINGS,
    STRIPE_BILLING_PORTAL_CONFIG,
    STRIPE_PAYMENT_LINK,
    STRIPE_WEBHOOK_ENDPOINT,
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
    "money stolen", "card data exposed",
]
RAW_SECRET = "sk_live_should_never_appear"

_NEW_RULE_KEYS = {
    "stripe_webhook_disabled",
    "stripe_webhook_broad_events",
    "stripe_payment_link_tax_disabled",
    "stripe_payment_link_promo_codes_enabled",
    "stripe_portal_subscription_cancel_enabled",
    "stripe_portal_login_enabled",
    "stripe_account_capability_incomplete",
}
_DEFERRED_RULE_KEYS = {
    "stripe_webhook_insecure_url",
    "stripe_restricted_key_broad_scope",
    "stripe_tax_disabled",
    "stripe_live_mode_webhook_http",
}


# ── fixtures / helpers ────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M73A", db=db)


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"stripe_api_key": RAW_SECRET})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="stripe",
                    display_name="stripe", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _res(db, integ, user):
    r = Resource(integration_id=integ.id, user_id=user.id,
                 provider_resource_type="stripe_account", provider_resource_id="acct_demo",
                 display_name="acct_demo", is_active=True)
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


def _keys(db, ws_id, res_id):
    return {f.finding_key.split(":", 1)[0] for f in _active(db, ws_id, res_id)}


def _webhook(rid, *, url="https://example.com/hook", status="enabled", events=None):
    return {
        "record_type": STRIPE_WEBHOOK_ENDPOINT, "record_id": rid, "name": url,
        "endpoint_id": rid, "url": url, "status": status,
        "enabled_events": events if events is not None else ["charge.succeeded"],
    }


def _payment_link(rid, *, active=True, tax=True, promo=False):
    return {
        "record_type": STRIPE_PAYMENT_LINK, "record_id": rid, "name": rid,
        "active": active, "automatic_tax_enabled": tax,
        "allow_promotion_codes": promo, "livemode": True,
    }


def _portal(rid, *, active=True, cancel=False, login=False):
    return {
        "record_type": STRIPE_BILLING_PORTAL_CONFIG, "record_id": rid, "name": rid,
        "config_id": rid, "active": active,
        "subscription_cancel_enabled": cancel, "login_page_enabled": login,
    }


def _account(rid="acct_demo", *, charges=True, payouts=True, details=True):
    return {
        "record_type": STRIPE_ACCOUNT_SETTINGS, "record_id": rid, "name": rid,
        "account_id": rid, "charges_enabled": charges,
        "payouts_enabled": payouts, "details_submitted": details,
    }


# ── 1. connector normalizes payment-link metadata without secrets/PII ────────

def test_payment_link_normalization_is_safe():
    conn = StripeConnector()
    raw = [{
        "id": "plink_1", "active": True, "allow_promotion_codes": True,
        "automatic_tax": {"enabled": False},
        "after_completion": {"type": "redirect", "redirect": {"url": "https://shop.example.com/thanks?session_id=cs_test_SECRET&token=" + RAW_SECRET}},
        "url": "https://buy.stripe.com/test_abc?secret=" + RAW_SECRET,
        "payment_method_types": ["card", "link"],
        "metadata": {"k1": "v1", "k2": "v2"},
        "livemode": True,
        # Fields that must NOT be carried through:
        "customer": "cus_SECRET", "line_items": [{"price": {"unit_amount": 999}}],
    }]
    conn._get_list = lambda creds, path, limit=100: raw  # type: ignore
    out = conn._fetch_payment_links({"stripe_api_key": RAW_SECRET})
    assert len(out) == 1
    rec = out[0]
    blob = json.dumps(rec)
    # No secrets, tokens, query strings, customer ids, or amounts leak.
    assert RAW_SECRET not in blob
    assert "cs_test" not in blob
    assert "cus_SECRET" not in blob
    assert "999" not in blob
    assert "?" not in blob  # query strings stripped (origins only)
    assert rec["record_type"] == STRIPE_PAYMENT_LINK
    assert rec["active"] is True and rec["automatic_tax_enabled"] is False
    assert rec["allow_promotion_codes"] is True
    assert rec["payment_method_types_count"] == 2
    assert rec["after_completion_redirect_origin"] == "https://shop.example.com"
    assert rec["success_url_origin"] == "https://buy.stripe.com"


def test_url_origin_strips_path_and_query():
    assert _url_origin("https://a.example.com/p/x?y=z#frag") == "https://a.example.com"
    assert _url_origin("") is None
    assert _url_origin(None) is None


# ── 2. webhook rules: http (existing), disabled, broad events ────────────────

def test_webhook_http_existing(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_webhook("we_http", url="http://insecure.example.com/h")])
        assert "stripe_webhook_http" in _keys(db_session, ws.id, res.id)
    finally:
        _cleanup(db_session, ws.id)


def test_webhook_disabled(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_webhook("we_dis", status="disabled")])
        keys = _keys(db_session, ws.id, res.id)
        assert "stripe_webhook_disabled" in keys
        # A disabled HTTPS endpoint is not an http exposure.
        assert "stripe_webhook_http" not in keys
    finally:
        _cleanup(db_session, ws.id)


def test_webhook_broad_events_wildcard(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_webhook("we_star", events=["*"])])
        assert "stripe_webhook_broad_events" in _keys(db_session, ws.id, res.id)
    finally:
        _cleanup(db_session, ws.id)


def test_webhook_normal_events_clean(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_webhook("we_ok", events=["charge.succeeded", "invoice.paid"])])
        assert _active(db_session, ws.id, res.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 3. payment-link rules: tax disabled, promo codes ─────────────────────────

def test_payment_link_tax_disabled(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_payment_link("plink_tax", active=True, tax=False)])
        assert "stripe_payment_link_tax_disabled" in _keys(db_session, ws.id, res.id)
    finally:
        _cleanup(db_session, ws.id)


def test_payment_link_promo_codes(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_payment_link("plink_promo", active=True, tax=True, promo=True)])
        keys = _keys(db_session, ws.id, res.id)
        assert "stripe_payment_link_promo_codes_enabled" in keys
        assert "stripe_payment_link_tax_disabled" not in keys
    finally:
        _cleanup(db_session, ws.id)


def test_inactive_payment_link_clean(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_payment_link("plink_off", active=False, tax=False, promo=True)])
        assert _active(db_session, ws.id, res.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 4. customer-portal rules: cancellation, login page ───────────────────────

def test_portal_subscription_cancel_enabled(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_portal("bpc_cancel", active=True, cancel=True)])
        assert "stripe_portal_subscription_cancel_enabled" in _keys(db_session, ws.id, res.id)
    finally:
        _cleanup(db_session, ws.id)


def test_portal_login_enabled(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_portal("bpc_login", active=True, login=True)])
        assert "stripe_portal_login_enabled" in _keys(db_session, ws.id, res.id)
    finally:
        _cleanup(db_session, ws.id)


def test_inactive_portal_clean(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_portal("bpc_off", active=False, cancel=True, login=True)])
        assert _active(db_session, ws.id, res.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 5. account-capability rule ───────────────────────────────────────────────

def test_account_capability_incomplete(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_account(charges=False, payouts=True, details=False)])
        assert "stripe_account_capability_incomplete" in _keys(db_session, ws.id, res.id)
    finally:
        _cleanup(db_session, ws.id)


def test_account_fully_enabled_clean(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_account(charges=True, payouts=True, details=True)])
        assert _active(db_session, ws.id, res.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 6. idempotent re-evaluation ──────────────────────────────────────────────

def test_idempotent_reevaluation(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    state = [
        _webhook("we_dis", status="disabled"),
        _payment_link("plink_tax", active=True, tax=False, promo=True),
        _portal("bpc_login", active=True, cancel=True, login=True),
        _account(charges=False, payouts=False, details=False),
    ]
    try:
        _evaluate(db_session, ws, integ, res, test_user, state)
        ids = {f.id for f in _active(db_session, ws.id, res.id)}
        assert ids
        _evaluate(db_session, ws, integ, res, test_user, state)
        assert {f.id for f in _active(db_session, ws.id, res.id)} == ids
    finally:
        _cleanup(db_session, ws.id)


# ── 7. connector fails soft when a surface is unavailable ────────────────────

def test_connector_payment_links_fails_soft():
    from app.connectors.exceptions import ConnectorError

    conn = StripeConnector()

    def boom(creds, path, limit=100):
        raise ConnectorError("forbidden", status_code=403)

    conn._get_list = boom  # type: ignore
    # Fail-soft: returns [] instead of raising.
    assert conn._fetch_payment_links({"stripe_api_key": RAW_SECRET}) == []


def test_connector_payment_links_propagates_auth_error():
    from app.connectors.exceptions import AuthenticationError

    conn = StripeConnector()

    def boom(creds, path, limit=100):
        raise AuthenticationError("bad key", status_code=401)

    conn._get_list = boom  # type: ignore
    raised = False
    try:
        conn._fetch_payment_links({"stripe_api_key": RAW_SECRET})
    except AuthenticationError:
        raised = True
    assert raised  # an invalid key is surfaced, not swallowed


# ── 8. evidence privacy + claim discipline ───────────────────────────────────

def test_evidence_and_wording_are_safe(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [
            _webhook("we_http", url="http://insecure.example.com/h"),
            _webhook("we_dis", status="disabled"),
            _webhook("we_star", events=["*"]),
            _payment_link("plink_tax", active=True, tax=False, promo=True),
            _portal("bpc_login", active=True, cancel=True, login=True),
            _account(charges=False, payouts=False, details=False),
        ])
        findings = _active(db_session, ws.id, res.id)
        assert findings
        blob = json.dumps(
            [{"t": f.title, "d": f.description, "e": f.evidence, "r": f.remediation}
             for f in findings], default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
        for bad in ("sk_live", "sk_test", "rk_live", "whsec_", "bearer ",
                    "authorization:", "card number", RAW_SECRET.lower()):
            assert bad not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 9. deferred rules are not registered ─────────────────────────────────────

def test_deferred_rules_not_registered():
    for key in _DEFERRED_RULE_KEYS:
        assert key not in KNOWN_RULE_KEYS, f"{key} should be deferred"


# ── 10. registry / confidence / pack / coverage parity for new keys ──────────

def test_new_keys_registered_everywhere():
    for key in _NEW_RULE_KEYS:
        assert key in KNOWN_RULE_KEYS, f"{key} missing from KNOWN_RULE_KEYS"
        assert key in RULE_CONFIDENCE, f"{key} missing from RULE_CONFIDENCE"
        assert key in _RULE_META, f"{key} missing from _RULE_META"
        assert key in RULE_RECORD_TYPES, f"{key} missing from RULE_RECORD_TYPES"
        assert _RULE_META[key][0] == "stripe"
    # Global parity invariants stay intact.
    assert KNOWN_RULE_KEYS == set(RULE_CONFIDENCE)
    assert set(_RULE_META) == set(KNOWN_RULE_KEYS)
    assert _NEW_RULE_KEYS <= set(RULE_RECORD_TYPES)
