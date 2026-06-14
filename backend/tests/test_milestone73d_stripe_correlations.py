"""M73D — Stripe configuration-risk × activity correlations.

Correlates an ACTIVE Stripe configuration-risk finding with Stripe configuration
activity (source="stripe_events") for the SAME Stripe object, when an aligned
event falls inside the finding's review window
(first_detected_at - 24h .. last_seen_at + 24h). Object identity is the
finding's Resource.provider_resource_id (or finding_key suffix fallback)
matched against the event's narrow-key metadata (webhook_endpoint_id /
payment_link_id / portal_config_id / account_id) — never provider-only,
never different objects, never customer/payment lifecycle events. Correlations
only — no demo.

These tests assert per-rule correlation creation, narrow object-id matching
(different object / different account / provider-only / out-of-window all
skip), idempotency, linked correlation Incident Signal creation, list /
generate endpoints, metadata privacy, and claim discipline.
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
RAW_CARD = "4242424242424242"
ACCOUNT = "acct_demo"


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M73D", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"stripe_api_key": RAW_SECRET})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="stripe",
                    display_name="stripe", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _res(db, integ, user, *, kind, oid):
    """Create one Resource per Stripe object."""
    r = Resource(integration_id=integ.id, user_id=user.id,
                 provider_resource_type=kind, provider_resource_id=oid,
                 display_name=oid, is_active=True)
    db.add(r); db.commit(); db.refresh(r)
    return r


def _finding(db, ws, integ, res, rule, *, severity="high", evidence=None):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="stripe",
        finding_key=f"{rule}:{res.provider_resource_id}", severity=severity,
        title=f"{rule} risk", resource_id=res.id, description="d",
        evidence=evidence or {"rule": rule}, remediation={"summary": "fix"})


def _raw_event(event_id, event_type, *, obj, livemode=True, account=ACCOUNT,
               occurred_offset_seconds=-60, inject_secrets=True):
    """Build a raw Stripe event near "now" so it falls inside the review window."""
    object_dict = dict(obj or {})
    if inject_secrets:
        # Defense-in-depth: forbidden bytes must never survive normalization.
        object_dict.setdefault("secret", RAW_WHSEC)
        object_dict.setdefault("customer_email", RAW_EMAIL)
        object_dict.setdefault("card", {"last4": "4242", "number": RAW_CARD})
    return {
        "id": event_id, "type": event_type, "object": "event",
        "created": int(time.time()) + occurred_offset_seconds,
        "livemode": livemode, "account": account,
        "data": {"object": object_dict},
    }


def _event(db, ws_id, integ, raw):
    norm = st_ingest.normalize_stripe_activity_event(raw)
    assert norm is not None
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ.id, normalized=norm, db=db)
    return row


def _gen(db, ws_id):
    return corr_svc.generate_stripe_correlations(workspace_id=ws_id, db=db)


def _corrs(db, ws_id):
    return db.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == ws_id,
        SecuritySignalCorrelation.provider == "stripe",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecuritySignalCorrelation).filter(SecuritySignalCorrelation.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityIncidentSignal).filter(SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _setup(db, user):
    ws = _ws(user, db); integ = _integ(db, user, ws.id)
    return ws, integ


# ── 1. insecure webhook risk × webhook activity ──────────────────────────────

def test_webhook_insecure_risk_activity(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_webhook_endpoint", oid="we_secure_1")
    try:
        _finding(db_session, ws, integ, res, "stripe_webhook_http", severity="critical")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_w_http", "stripe.webhook_endpoint.updated"  # already normalized type
            if False else "webhook_endpoint.updated",
            obj={"id": "we_secure_1", "object": "webhook_endpoint",
                 "url": "http://insecure.example.com/h"},
        ))
        s = _gen(db_session, ws.id)
        assert s["provider"] == "stripe" and s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "stripe_webhook_insecure_risk_activity"
        assert c.severity == "critical" and c.confidence == "medium"
        assert c.linked_finding_id and c.linked_activity_event_id
        assert "endpoint \"we_secure_1\"" in c.title
        assert c.correlation_metadata.get("webhook_endpoint_id") == "we_secure_1"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. disabled webhook risk × webhook activity ──────────────────────────────

def test_webhook_disabled_risk_activity(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_webhook_endpoint", oid="we_dis_1")
    try:
        _finding(db_session, ws, integ, res, "stripe_webhook_disabled", severity="medium")
        # An event TYPE in the disabled-rule allowlist (deleted) for the same id.
        _event(db_session, ws.id, integ, _raw_event(
            "evt_w_dis", "webhook_endpoint.deleted",
            obj={"id": "we_dis_1", "object": "webhook_endpoint",
                 "url": "https://gone.example.com/h"},
        ))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "stripe_webhook_disabled_risk_activity"
        assert c.severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. broad-events webhook risk × webhook activity ──────────────────────────

def test_webhook_broad_events_risk_activity(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_webhook_endpoint", oid="we_broad_1")
    try:
        _finding(db_session, ws, integ, res, "stripe_webhook_broad_events", severity="medium")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_w_broad", "webhook_endpoint.updated",
            obj={"id": "we_broad_1", "object": "webhook_endpoint",
                 "url": "https://example.com/h"},
        ))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "stripe_webhook_broad_events_risk_activity"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. payment link tax risk × payment link activity ─────────────────────────

def test_payment_link_tax_risk_activity(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_payment_link", oid="plink_tax_1")
    try:
        _finding(db_session, ws, integ, res, "stripe_payment_link_tax_disabled",
                 severity="medium")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_plink_tax", "payment_link.updated",
            obj={"id": "plink_tax_1", "object": "payment_link"},
        ))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "stripe_payment_link_tax_risk_activity"
        assert c.correlation_metadata.get("payment_link_id") == "plink_tax_1"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. payment link promo risk × payment link activity ───────────────────────

def test_payment_link_promo_risk_activity(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_payment_link", oid="plink_promo_1")
    try:
        _finding(db_session, ws, integ, res,
                 "stripe_payment_link_promo_codes_enabled", severity="low")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_plink_promo", "payment_link.created",
            obj={"id": "plink_promo_1", "object": "payment_link"},
        ))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "stripe_payment_link_promo_risk_activity"
    finally:
        _cleanup(db_session, ws.id)


# ── 6. portal cancellation risk × portal config activity ─────────────────────

def test_portal_cancel_risk_activity(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user,
               kind="stripe_billing_portal_config", oid="bpc_cancel_1")
    try:
        _finding(db_session, ws, integ, res,
                 "stripe_portal_subscription_cancel_enabled", severity="low")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_bpc_cancel", "billing_portal.configuration.updated",
            obj={"id": "bpc_cancel_1", "object": "billing_portal.configuration"},
        ))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "stripe_portal_cancel_risk_activity"
        assert c.correlation_metadata.get("portal_config_id") == "bpc_cancel_1"
    finally:
        _cleanup(db_session, ws.id)


# ── 7. portal login risk × portal config activity ────────────────────────────

def test_portal_login_risk_activity(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user,
               kind="stripe_billing_portal_config", oid="bpc_login_1")
    try:
        _finding(db_session, ws, integ, res,
                 "stripe_portal_login_enabled", severity="medium")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_bpc_login", "billing_portal.configuration.updated",
            obj={"id": "bpc_login_1", "object": "billing_portal.configuration"},
        ))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "stripe_portal_login_risk_activity"
    finally:
        _cleanup(db_session, ws.id)


# ── 8. account capability risk × account/capability activity ─────────────────

def test_account_capability_risk_activity(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_account", oid=ACCOUNT)
    try:
        _finding(db_session, ws, integ, res,
                 "stripe_account_capability_incomplete", severity="medium")
        # Two aligned events — same account: account.updated and capability.updated.
        _event(db_session, ws.id, integ, _raw_event(
            "evt_acct_upd", "account.updated",
            obj={"id": ACCOUNT, "object": "account"}, account=ACCOUNT,
        ))
        _event(db_session, ws.id, integ, _raw_event(
            "evt_cap_upd", "capability.updated",
            obj={"id": "card_payments", "object": "capability", "status": "inactive"},
            account=ACCOUNT,
        ))
        s = _gen(db_session, ws.id)
        # Both events match → two correlations on the same correlation_key but
        # different linked_activity_event_id (the unique tuple).
        assert s["correlations_created"] == 2
        types = {c.correlation_type for c in _corrs(db_session, ws.id)}
        assert types == {"stripe_account_capability_risk_activity"}
    finally:
        _cleanup(db_session, ws.id)


# ── 9. different object → no correlation ─────────────────────────────────────

def test_different_object_does_not_correlate(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_webhook_endpoint", oid="we_a")
    try:
        _finding(db_session, ws, integ, res, "stripe_webhook_http", severity="critical")
        # Same provider, same event family, but a DIFFERENT webhook endpoint id.
        _event(db_session, ws.id, integ, _raw_event(
            "evt_other_w", "webhook_endpoint.updated",
            obj={"id": "we_OTHER", "object": "webhook_endpoint",
                 "url": "http://something.example.com/h"},
        ))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


def test_different_payment_link_does_not_correlate(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_payment_link", oid="plink_a")
    try:
        _finding(db_session, ws, integ, res,
                 "stripe_payment_link_tax_disabled", severity="medium")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_pl_other", "payment_link.updated",
            obj={"id": "plink_OTHER", "object": "payment_link"},
        ))
        assert _gen(db_session, ws.id)["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_different_portal_config_does_not_correlate(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user,
               kind="stripe_billing_portal_config", oid="bpc_a")
    try:
        _finding(db_session, ws, integ, res,
                 "stripe_portal_login_enabled", severity="medium")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_bpc_other", "billing_portal.configuration.updated",
            obj={"id": "bpc_OTHER", "object": "billing_portal.configuration"},
        ))
        assert _gen(db_session, ws.id)["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_different_account_does_not_correlate(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_account", oid="acct_REAL")
    try:
        _finding(db_session, ws, integ, res,
                 "stripe_account_capability_incomplete", severity="medium")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_acct_other", "account.updated",
            obj={"id": "acct_OTHER", "object": "account"}, account="acct_OTHER",
        ))
        assert _gen(db_session, ws.id)["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 10. provider-only match never correlates ─────────────────────────────────

def test_provider_only_does_not_correlate(test_user, db_session):
    """Two Stripe objects (different ids) must NEVER correlate just because the
    provider matches."""
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_webhook_endpoint", oid="we_x")
    try:
        _finding(db_session, ws, integ, res, "stripe_webhook_http", severity="critical")
        # Even a payment_link.updated event in the same workspace must not
        # correlate to a webhook finding — event type mismatch + id mismatch.
        _event(db_session, ws.id, integ, _raw_event(
            "evt_pl_z", "payment_link.updated",
            obj={"id": "plink_z", "object": "payment_link"},
        ))
        assert _gen(db_session, ws.id)["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 11. event outside review window does not correlate ───────────────────────

def test_out_of_window_does_not_correlate(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_webhook_endpoint", oid="we_old")
    try:
        f = _finding(db_session, ws, integ, res, "stripe_webhook_http", severity="critical")
        # Shrink the finding's active window to a small slice in the future so
        # the event (now - 60s) falls well outside [first - 24h, last + 24h].
        future = datetime.now(timezone.utc).replace(microsecond=0)
        f.first_detected_at = future.replace(year=future.year + 1)
        f.last_seen_at = f.first_detected_at
        db_session.commit()
        _event(db_session, ws.id, integ, _raw_event(
            "evt_old", "webhook_endpoint.updated",
            obj={"id": "we_old", "object": "webhook_endpoint",
                 "url": "http://x.example.com/h"},
        ))
        assert _gen(db_session, ws.id)["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 12. idempotency ──────────────────────────────────────────────────────────

def test_idempotent_generation(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_webhook_endpoint", oid="we_d")
    try:
        _finding(db_session, ws, integ, res, "stripe_webhook_http", severity="critical")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_d", "webhook_endpoint.updated",
            obj={"id": "we_d", "object": "webhook_endpoint",
                 "url": "http://x.example.com/h"},
        ))
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["correlations_created"] == 1
        assert s2["correlations_created"] == 0
        assert s2["correlations_skipped"] == 1
        assert len(_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 13. linked correlation Incident Signal is created ────────────────────────

def test_linked_correlation_signal_created(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_webhook_endpoint", oid="we_s")
    try:
        _finding(db_session, ws, integ, res, "stripe_webhook_http", severity="critical")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_s", "webhook_endpoint.updated",
            obj={"id": "we_s", "object": "webhook_endpoint",
                 "url": "http://x.example.com/h"},
        ))
        _gen(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        assert c.linked_signal_id is not None
        sig = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.id == c.linked_signal_id).first()
        assert sig is not None
        assert sig.evidence_level == "correlation"
        assert sig.signal_type == "stripe_webhook_insecure_risk_activity"
        assert sig.linked_finding_id == c.linked_finding_id
    finally:
        _cleanup(db_session, ws.id)


# ── 14. metadata privacy + claim discipline ──────────────────────────────────

def test_metadata_privacy_and_wording(test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_webhook_endpoint", oid="we_p")
    try:
        _finding(db_session, ws, integ, res, "stripe_webhook_http", severity="critical")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_p", "webhook_endpoint.updated",
            obj={"id": "we_p", "object": "webhook_endpoint",
                 "url": "http://x.example.com/h?session_id=cs_test_SECRET&token=" + RAW_SECRET},
        ))
        _gen(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        blob = json.dumps({
            "title": c.title, "summary": c.summary,
            "metadata": c.correlation_metadata,
        }, default=str)
        assert RAW_SECRET not in blob
        assert RAW_WHSEC not in blob
        assert RAW_EMAIL not in blob
        assert RAW_CARD not in blob
        for bad in ("sk_live", "sk_test", "rk_live", "whsec_", "bearer ",
                    "authorization", "customer_email", "?session_id",
                    "?secret=", "?token="):
            assert bad not in blob.lower()
        # Forbidden claim wording must never appear.
        lower = (c.title + "\n" + c.summary).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in lower
        assert "does not confirm" in c.summary.lower()
        # Allowlist must keep raw object dicts and secrets out of metadata.
        for forbidden_key in ("secret", "customer", "customer_email", "card",
                              "payload", "headers", "request", "response", "url"):
            assert forbidden_key not in c.correlation_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 15. list endpoint filters provider=stripe + correlation_type ─────────────

def test_list_endpoint_filters(client, test_user, db_session):
    ws, integ = _setup(db_session, test_user)
    res = _res(db_session, integ, test_user, kind="stripe_webhook_endpoint", oid="we_l")
    try:
        _finding(db_session, ws, integ, res, "stripe_webhook_http", severity="critical")
        _event(db_session, ws.id, integ, _raw_event(
            "evt_l", "webhook_endpoint.updated",
            obj={"id": "we_l", "object": "webhook_endpoint",
                 "url": "http://x.example.com/h"},
        ))
        r = client.post("/security/correlations/generate", json={"provider": "stripe"})
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "stripe"
        assert body["correlations_created"] == 1

        lst = client.get("/security/correlations?provider=stripe")
        assert lst.status_code == 200 and lst.json()["total"] >= 1

        ft = client.get(
            "/security/correlations?provider=stripe"
            "&correlation_type=stripe_webhook_insecure_risk_activity"
        )
        assert ft.status_code == 200 and ft.json()["total"] >= 1

        # An unrelated type yields zero.
        empty = client.get(
            "/security/correlations?provider=stripe"
            "&correlation_type=stripe_payment_link_tax_risk_activity"
        )
        assert empty.status_code == 200 and empty.json()["total"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 16. endpoint admin gating ────────────────────────────────────────────────

def test_member_cannot_generate(test_user, db_session):
    owner = _new_user(db_session, "owner")
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
