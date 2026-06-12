"""M68.2 — Cloudflare Configuration Risk × Audit Activity correlations.

A Cloudflare config-risk finding is correlated with Cloudflare audit activity
ONLY when they share the SAME zone (same zone-scoped integration) AND the SAME
logical risk area (DNS / WAF / TLS) within the finding's review window. These
tests assert each implemented rule, the risk-area gate, the zone gate, the time
window, idempotency, linked correlation-evidence signal, list filtering,
workspace scoping, permissions, privacy, and claim discipline.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_activity_event_service as activity_svc
from app.services import security_finding_service as finding_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
]
_ALLOWED_CORR_META = {
    "finding_rule", "finding_severity", "event_type", "action", "actor",
    "zone_id", "zone_name", "resource_type", "resource_id", "account_id",
    "window_hours",
}
ZONE = "example.com"


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M68.2", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _cf_integ(db, user, ws_id, zone="zone-1"):
    ct, iv = encrypt_credentials({"api_token": "x", "zone_id": zone, "account_id": "acct-1"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="cloudflare",
        display_name=f"cloudflare-{zone}", encrypted_credentials=ct, credential_iv=iv,
        status="active",
    )
    db.add(i); db.commit(); db.refresh(i)
    return i


def _finding(db, ws, integ, base_rule, *, severity="high"):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="cloudflare",
        finding_key=f"{base_rule}:{uuid.uuid4().hex[:8]}", severity=severity,
        title=f"{base_rule} risk", resource_id=None, description="desc",
        evidence={"rule": base_rule}, remediation={"summary": "fix"},
    )


def _cf_event(db, ws_id, integ_id, event_type, *, occurred=None, zone_id="zone-1",
              zone_name=ZONE):
    norm = activity_svc.normalize_activity_event(
        provider="cloudflare", source="audit_log", event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id=f"cf-{uuid.uuid4().hex[:12]}",
        actor_id="admin@example.com", actor_type="user",
        resource_type="dns_record", resource_id="res-1",
        metadata={"zone_id": zone_id, "zone_name": zone_name, "action": "edit",
                  "actor": "admin@example.com", "outcome": "success", "account_id": "acct-1"},
    )
    _o, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _gen(db, ws_id):
    return corr_svc.generate_cloudflare_correlations(workspace_id=ws_id, db=db)


def _corrs(db, ws_id):
    items, _ = corr_svc.list_correlations(workspace_id=ws_id, db=db, provider="cloudflare")
    return items


def _cleanup(db, ws_id):
    db.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    integ_ids = [i.id for i in db.query(Integration).filter(Integration.workspace_id == ws_id).all()]
    if integ_ids:
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(synchronize_session=False)
    db.commit()


# ── 1–3. each implemented rule correlates ─────────────────────────────────────

def test_dns_risk_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_dns_private_origin")
    _cf_event(db_session, ws.id, integ.id, "cloudflare.dns_record.changed")
    try:
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.provider == "cloudflare"
        assert c.correlation_type == "cloudflare_dns_change"
        assert c.confidence == "medium"
    finally:
        _cleanup(db_session, ws.id)


def test_waf_risk_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_waf_rule_disabled")
    _cf_event(db_session, ws.id, integ.id, "cloudflare.waf_rule.changed")
    try:
        _gen(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "cloudflare_waf_change"
        assert c.severity == "high"
    finally:
        _cleanup(db_session, ws.id)


def test_tls_risk_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_ssl_mode_weak")
    _cf_event(db_session, ws.id, integ.id, "cloudflare.ssl_tls.changed")
    try:
        _gen(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "cloudflare_tls_change"
        assert c.correlation_metadata.get("zone_name") == ZONE
    finally:
        _cleanup(db_session, ws.id)


# ── 4. risk-area gate: unrelated event does not correlate ─────────────────────

def test_unrelated_area_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    # TLS finding but only a DNS event present → no correlation (area gate).
    _finding(db_session, ws, integ, "cloudflare_ssl_mode_weak")
    _cf_event(db_session, ws.id, integ.id, "cloudflare.dns_record.changed")
    try:
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 5. unmatched zone (different integration) does not correlate ──────────────

def test_unmatched_zone_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ_a = _cf_integ(db_session, test_user, ws.id, zone="zone-A")
    integ_b = _cf_integ(db_session, test_user, ws.id, zone="zone-B")
    _finding(db_session, ws, integ_a, "cloudflare_waf_rule_disabled")
    # WAF event under a DIFFERENT zone-scoped integration → different zone.
    _cf_event(db_session, ws.id, integ_b.id, "cloudflare.waf_rule.changed")
    try:
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 6. event outside the time window does not correlate ───────────────────────

def test_outside_window_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_ssl_mode_weak")
    old = datetime.now(timezone.utc) - timedelta(hours=48)
    _cf_event(db_session, ws.id, integ.id, "cloudflare.ssl_tls.changed", occurred=old)
    try:
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 7. idempotency ────────────────────────────────────────────────────────────

def test_generation_is_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_waf_rule_disabled")
    _cf_event(db_session, ws.id, integ.id, "cloudflare.waf_rule.changed")
    try:
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["correlations_created"] == 1
        assert s2["correlations_created"] == 0
        assert s2["correlations_skipped"] == 1
        assert len(_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 8. linked correlation-evidence signal ─────────────────────────────────────

def test_correlation_creates_linked_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    finding = _finding(db_session, ws, integ, "cloudflare_ssl_mode_weak")
    _cf_event(db_session, ws.id, integ.id, "cloudflare.ssl_tls.changed")
    try:
        _gen(db_session, ws.id)
        corr = _corrs(db_session, ws.id)[0]
        assert corr.linked_signal_id is not None
        sig = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.id == corr.linked_signal_id).first()
        assert sig is not None
        assert sig.provider == "cloudflare"
        assert sig.evidence_level == "correlation"
        assert sig.linked_finding_id == finding.id
    finally:
        _cleanup(db_session, ws.id)


# ── 9. list filter + workspace scoping ────────────────────────────────────────

def test_list_filter_and_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ = _cf_integ(db_session, test_user, ws_a.id)
    _finding(db_session, ws_a, integ, "cloudflare_dns_private_origin")
    _cf_event(db_session, ws_a.id, integ.id, "cloudflare.dns_record.changed")
    try:
        _gen(db_session, ws_a.id)
        assert len(_corrs(db_session, ws_a.id)) == 1
        assert len(_corrs(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 10. privacy + claim discipline ────────────────────────────────────────────

def test_metadata_privacy_and_claims(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_waf_rule_disabled")
    _cf_event(db_session, ws.id, integ.id, "cloudflare.waf_rule.changed")
    try:
        _gen(db_session, ws.id)
        for c in _corrs(db_session, ws.id):
            blob = json.dumps({"t": c.title, "s": c.summary, "m": c.correlation_metadata}, default=str)
            low = blob.lower()
            for phrase in _FORBIDDEN:
                assert phrase not in low, f"forbidden {phrase!r}"
            assert "may require review" in c.summary.lower()
            assert set(c.correlation_metadata.keys()) <= _ALLOWED_CORR_META
            for bad in ("newvalue", "oldvalue", "token", "secret", "cookie",
                        "headers", "source_ip"):
                assert bad not in low
    finally:
        _cleanup(db_session, ws.id)


# ── 11. endpoint admin gating ─────────────────────────────────────────────────

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


def test_owner_can_generate_and_list_via_endpoint(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_ssl_mode_weak")
    _cf_event(db_session, ws.id, integ.id, "cloudflare.ssl_tls.changed")
    try:
        gen = client.post("/security/correlations/generate", json={"provider": "cloudflare"})
        assert gen.status_code == 200
        body = gen.json()
        assert body["provider"] == "cloudflare"
        assert body["correlations_created"] == 1

        lst = client.get("/security/correlations?provider=cloudflare")
        assert lst.status_code == 200
        lb = lst.json()
        assert lb["total"] == 1
        assert lb["items"][0]["correlation_type"] == "cloudflare_tls_change"
    finally:
        _cleanup(db_session, ws.id)
