"""M60.4.5 — Stripe / Vercel / Shopify security exposure rules.

Unit tests per rule (risky fires / safe does not / malformed ignored / evidence
metadata-only) plus DB-backed evaluator tests for lifecycle (dedupe + resolve)
and multi-record separate findings.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy.orm import Session

from app.connectors.shopify_schema import SHOPIFY_WEBHOOK_SUBSCRIPTION
from app.connectors.stripe_schema import STRIPE_WEBHOOK_ENDPOINT
from app.connectors.vercel_schema import VERCEL_DEPLOYMENT_PROTECTION
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.models.user import User
from app.services import security_finding_evaluator as evaluator
from app.services.security_rules import shopify as sh
from app.services.security_rules import stripe as st
from app.services.security_rules import vercel as ve

_SECRET_RE = re.compile(
    r"secret|token|password|api_?key|access_?key|private_?key|client_secret", re.I
)


def _safe(cands):
    for c in cands:
        for k in c.evidence.keys():
            assert not _SECRET_RE.search(k), f"sensitive evidence key: {k}"
        assert "endpoint_path_hash" not in c.evidence
        assert "trusted_ips_cidr_hash" not in c.evidence


# ── builders ─────────────────────────────────────────────────────────────────


def _stripe_wh(**over) -> dict:
    rec = {
        "record_type": STRIPE_WEBHOOK_ENDPOINT,
        "record_id": "we_1",
        "name": "https://api.example.com/stripe",
        "url": "https://api.example.com/stripe",
        "status": "enabled",
    }
    rec.update(over)
    return rec


def _vercel_prot(**over) -> dict:
    rec = {
        "record_type": VERCEL_DEPLOYMENT_PROTECTION,
        "record_id": "prj_1",
        "name": "my-app",
        "sso_enabled": False,
        "password_enabled": False,
        "preview_deployments_protected": False,
        "preview_comments_public": False,
    }
    rec.update(over)
    return rec


def _shopify_wh(**over) -> dict:
    rec = {
        "record_type": SHOPIFY_WEBHOOK_SUBSCRIPTION,
        "record_id": "wh_1",
        "name": "orders/create → hooks.example.com",
        "topic": "orders/create",
        "endpoint_domain": "hooks.example.com",
        "endpoint_scheme": "https",
        "is_https": True,
    }
    rec.update(over)
    return rec


# ── Stripe (regression: existing rule preserved) ─────────────────────────────


def test_stripe_http_fires_critical():
    out = st.evaluate(_stripe_wh(url="http://api.example.com/stripe"))
    assert out and out[0].rule_key == "stripe_webhook_http"
    assert out[0].severity == "critical"
    _safe(out)


def test_stripe_https_safe():
    assert st.evaluate(_stripe_wh(url="https://api.example.com/stripe")) == []


def test_stripe_disabled_http_not_flagged():
    # disabled endpoint is not flagged (existing behavior).
    assert st.evaluate(_stripe_wh(url="http://x", status="disabled")) == []


# ── Vercel ───────────────────────────────────────────────────────────────────


def test_vercel_preview_unprotected_medium():
    out = ve.evaluate(_vercel_prot())
    assert out and out[0].rule_key == "vercel_preview_unprotected"
    assert out[0].severity == "medium"
    _safe(out)


def test_vercel_preview_protected_safe():
    assert ve.evaluate(_vercel_prot(preview_deployments_protected=True)) == []


def test_vercel_sso_or_password_safe():
    assert ve.evaluate(_vercel_prot(sso_enabled=True)) == []
    assert ve.evaluate(_vercel_prot(password_enabled=True)) == []


def test_vercel_malformed_ignored():
    assert ve.evaluate({"record_type": VERCEL_DEPLOYMENT_PROTECTION, "name": "x"}) == []


def test_vercel_unknown_record_ignored():
    assert ve.evaluate({"record_type": "vercel_domain", "name": "x"}) == []


# ── Shopify ──────────────────────────────────────────────────────────────────


def test_shopify_http_fires_critical():
    out = sh.evaluate(_shopify_wh(endpoint_scheme="http", is_https=False))
    assert out and out[0].rule_key == "shopify_webhook_http"
    assert out[0].severity == "critical"
    assert out[0].evidence["topic"] == "orders/create"
    _safe(out)


def test_shopify_https_safe():
    assert sh.evaluate(_shopify_wh(endpoint_scheme="https", is_https=True)) == []


def test_shopify_non_http_transport_ignored():
    # EventBridge / Pub-Sub style delivery (scheme not "http") is not flagged.
    assert sh.evaluate(_shopify_wh(endpoint_scheme="", is_https=False)) == []
    assert sh.evaluate(_shopify_wh(endpoint_scheme="pubsub", is_https=False)) == []


def test_shopify_unknown_record_ignored():
    assert sh.evaluate({"record_type": "shopify_store_policy"}) == []
    assert sh.evaluate({"weird": "x"}) == []


# ════════════════════════════════════════════════════════════════════════════
# DB-backed evaluator: lifecycle + multi-record
# ════════════════════════════════════════════════════════════════════════════


def _ws(user, db):
    from app.services import workspace_service

    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M60.4.5", db=db
    )


def _integ(db, user, ws_id, provider):
    ct, iv = encrypt_credentials({"k": "v"})
    i = Integration(
        user_id=user.id,
        workspace_id=ws_id,
        provider=provider,
        display_name=provider,
        encrypted_credentials=ct,
        credential_iv=iv,
        status="active",
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _res(db, integ, user, rtype):
    r = Resource(
        integration_id=integ.id,
        user_id=user.id,
        provider_resource_type=rtype,
        provider_resource_id="r-1",
        display_name="r",
        is_active=True,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _snap(db, res, integ, user, state):
    s = Snapshot(
        resource_id=res.id,
        integration_id=integ.id,
        user_id=user.id,
        state=state,
        content_hash=uuid.uuid4().hex,
        triggered_by="manual",
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _active(db, ws_id, res_id):
    return (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == ws_id,
            SecurityFinding.resource_id == res_id,
            SecurityFinding.status == "active",
        )
        .all()
    )


def _cleanup(db, ws_id):
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete()
    db.commit()


def test_shopify_multi_webhook_and_lifecycle(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id, "shopify")
    res = _res(db_session, integ, test_user, "shopify_shop")

    state = [
        _shopify_wh(record_id="wh_a", topic="orders/create", endpoint_scheme="http", is_https=False),
        _shopify_wh(record_id="wh_b", topic="app/uninstalled", endpoint_scheme="http", is_https=False),
        _shopify_wh(record_id="wh_safe", topic="products/update", endpoint_scheme="https", is_https=True),
    ]
    snap = _snap(db_session, res, integ, test_user, state)
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap
    )
    findings = _active(db_session, ws.id, res.id)
    assert len(findings) == 2  # two HTTP webhooks, safe one excluded
    first_seen = {f.finding_key: f.last_seen_at for f in findings}

    # Re-evaluate → dedupe + refresh.
    snap2 = _snap(db_session, res, integ, test_user, state)
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap2
    )
    again = _active(db_session, ws.id, res.id)
    assert len(again) == 2
    for f in again:
        assert f.last_seen_at >= first_seen[f.finding_key]

    # One webhook fixed to HTTPS → that finding resolves.
    fixed = [
        _shopify_wh(record_id="wh_a", topic="orders/create", endpoint_scheme="https", is_https=True),
        _shopify_wh(record_id="wh_b", topic="app/uninstalled", endpoint_scheme="http", is_https=False),
    ]
    snap3 = _snap(db_session, res, integ, test_user, fixed)
    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap3
    )
    assert summary["resolved"] == 1
    assert len(_active(db_session, ws.id, res.id)) == 1

    _cleanup(db_session, ws.id)


def test_vercel_lifecycle_resolve(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id, "vercel")
    res = _res(db_session, integ, test_user, "vercel_project")

    s1 = _snap(db_session, res, integ, test_user, [_vercel_prot()])
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=s1
    )
    assert len(_active(db_session, ws.id, res.id)) == 1

    # Protection enabled → finding resolves.
    s2 = _snap(db_session, res, integ, test_user, [_vercel_prot(sso_enabled=True)])
    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=s2
    )
    assert summary["resolved"] == 1
    assert _active(db_session, ws.id, res.id) == []

    _cleanup(db_session, ws.id)
