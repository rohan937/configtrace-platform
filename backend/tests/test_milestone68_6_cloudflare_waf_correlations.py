"""M68.6 — Cloudflare Configuration Risk × WAF/security-event correlations.

A Cloudflare config-risk finding is correlated with Cloudflare WAF/security
activity (provider=cloudflare, source=waf_security_event, ingested in M68.4) ONLY
when they share the SAME zone (same zone-scoped integration) AND a relevant,
non-vague join key for the finding's risk area, within the review window:

  * WAF rule disabled            → same zone + WAF/security activity
  * zone security setting risk   → same zone + event carries host evidence
  * DNS private-origin risk      → event host == finding hostname (never zone-only)
  * Access policy risk           → same zone + sensitive path_prefix
  * TLS/HTTPS setting risk        → same zone + host evidence (confidence low)

These tests assert each rule, the join-key gates (no vague same-zone matching),
the time window, idempotency, the linked correlation-evidence signal, the combined
provider=cloudflare endpoint (audit + WAF), list filtering, workspace scoping,
permissions, privacy (no raw IP / URL / path / query / secrets), and claim
discipline (never asserts an attack / exploit / unauthorized access).
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
    "exploit confirmed",
]
_ALLOWED_CORR_META = {
    "source", "finding_rule", "finding_severity", "event_type", "action",
    "zone_id", "zone_name", "host", "rule_id", "rule_name", "path_prefix",
    "event_count", "window_hours",
}
ZONE = "example.com"
RAW_IP = "203.0.113.55"


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M68.6", db=db)


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


def _finding(db, ws, integ, base_rule, *, severity="high", evidence=None):
    ev = {"rule": base_rule}
    if evidence:
        ev.update(evidence)
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="cloudflare",
        finding_key=f"{base_rule}:{uuid.uuid4().hex[:8]}", severity=severity,
        title=f"{base_rule} risk", resource_id=None, description="desc",
        evidence=ev, remediation={"summary": "fix"},
    )


def _waf_event(db, ws_id, integ_id, event_type, *, host="app.example.com",
               path_prefix=None, rule_id="rule-1", ruleset_id="rs-1",
               zone_id="zone-1", zone_name=ZONE, action="block", occurred=None):
    md = {
        "action": action, "rule_id": rule_id, "rule_name": "SQLi managed rule",
        "ruleset_id": ruleset_id, "client_country": "US", "method": "POST",
        "host": host, "path_hash": "sha256:deadbeef", "path_prefix": path_prefix,
        "ray_id": uuid.uuid4().hex[:12], "service": "waf", "outcome": action,
        "event_source": "cloudflare_waf", "zone_id": zone_id, "zone_name": zone_name,
    }
    norm = activity_svc.normalize_activity_event(
        provider="cloudflare", source="waf_security_event", event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id=f"cfwaf-{uuid.uuid4().hex[:12]}",
        actor_id=None, actor_type="waf_event",
        resource_type="cloudflare_zone", resource_id=zone_id,
        metadata=md,
    )
    _o, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _audit_event(db, ws_id, integ_id, event_type, *, occurred=None):
    norm = activity_svc.normalize_activity_event(
        provider="cloudflare", source="audit_log", event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id=f"cf-{uuid.uuid4().hex[:12]}",
        actor_id="admin@example.com", actor_type="user",
        resource_type="zone", resource_id="res-1",
        metadata={"zone_id": "zone-1", "zone_name": ZONE, "action": "edit",
                  "actor": "admin@example.com", "outcome": "success"},
    )
    _o, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _gen_waf(db, ws_id):
    return corr_svc.generate_cloudflare_waf_correlations(workspace_id=ws_id, db=db)


def _gen_all(db, ws_id):
    return corr_svc.generate_cloudflare_correlations(workspace_id=ws_id, db=db)


def _corrs(db, ws_id, ctype=None):
    items, _ = corr_svc.list_correlations(
        workspace_id=ws_id, db=db, provider="cloudflare", correlation_type=ctype)
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


# ── A. WAF rule disabled + WAF event ──────────────────────────────────────────

def test_waf_disabled_risk_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_waf_rule_disabled",
             evidence={"ruleset_id": "rs-1"})
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block")
    try:
        s = _gen_waf(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "cloudflare_waf_risk_activity"
        assert c.severity == "high"  # block event raises review priority
        # ruleset alignment raises confidence.
        assert c.confidence == "high"
        assert c.correlation_metadata.get("event_count") == 1
        assert c.linked_finding_id is not None
        assert c.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


def test_waf_disabled_confidence_medium_without_ruleset_match(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_waf_rule_disabled",
             evidence={"ruleset_id": "rs-OTHER"}, severity="medium")
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.challenge",
               action="challenge", ruleset_id="rs-1")
    try:
        _gen_waf(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        assert c.confidence == "medium"
        assert c.severity == "high"  # challenge is a security event
    finally:
        _cleanup(db_session, ws.id)


# ── B. zone security setting + WAF event (host required) ──────────────────────

def test_zone_security_correlates_with_host(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_security_level_low", severity="medium")
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block",
               host="app.example.com")
    try:
        _gen_waf(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "cloudflare_zone_security_activity"
        assert c.correlation_metadata.get("host") == "app.example.com"
    finally:
        _cleanup(db_session, ws.id)


def test_zone_security_no_correlation_without_host(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_development_mode_on", severity="medium")
    # Event carries NO host → would be vague → must not correlate.
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block", host=None)
    try:
        s = _gen_waf(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── C. DNS private origin + WAF event (host match required) ───────────────────

def test_dns_origin_correlates_on_host_match(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_dns_private_origin",
             evidence={"name": "App.Example.com"})  # case-insensitive match
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block",
               host="app.example.com")
    try:
        s = _gen_waf(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "cloudflare_dns_origin_activity"
    finally:
        _cleanup(db_session, ws.id)


def test_dns_origin_no_correlation_without_host_match(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_dns_private_origin",
             evidence={"name": "app.example.com"})
    # Same zone, but a DIFFERENT host → must NOT correlate (no zone-only match).
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block",
               host="other.example.com")
    try:
        s = _gen_waf(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


def test_dns_origin_no_correlation_without_finding_hostname(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    # DNS finding with no hostname in evidence → nothing to match on.
    _finding(db_session, ws, integ, "cloudflare_dns_private_origin")
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block",
               host="app.example.com")
    try:
        s = _gen_waf(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_dns_origin_event_type_gate(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_dns_private_origin",
             evidence={"name": "app.example.com"})
    # 'skip' is not a security/log event → outside the DNS rule's event set.
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.skip",
               host="app.example.com", action="skip")
    try:
        s = _gen_waf(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── D. Access policy + sensitive-path WAF event ───────────────────────────────

def test_access_policy_correlates_on_sensitive_path(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_access_policy_bypass")
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.challenge",
               action="challenge", path_prefix="admin")
    try:
        _gen_waf(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "cloudflare_access_policy_activity"
        assert c.correlation_metadata.get("path_prefix") == "admin"
        low = c.summary.lower()
        assert "sensitive path" in low
        assert "does not indicate that any endpoint was accessed" in low
    finally:
        _cleanup(db_session, ws.id)


def test_access_policy_no_correlation_on_nonsensitive_path(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_access_policy_disabled", severity="medium")
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block",
               path_prefix="images")
    try:
        s = _gen_waf(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── E. TLS/HTTPS weak + WAF event (conservative confidence) ───────────────────

def test_tls_risk_correlates_with_low_confidence(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_ssl_mode_weak")
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block",
               host="app.example.com")
    try:
        _gen_waf(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "cloudflare_tls_activity"
        assert c.confidence == "low"  # weakest evidence
    finally:
        _cleanup(db_session, ws.id)


# ── negatives: unrelated, wrong zone, window ──────────────────────────────────

def test_unrelated_finding_no_waf_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    # WAF-disabled finding, but only an AUDIT event present (no WAF event).
    _finding(db_session, ws, integ, "cloudflare_waf_rule_disabled")
    _audit_event(db_session, ws.id, integ.id, "cloudflare.waf_rule.changed")
    try:
        s = _gen_waf(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


def test_wrong_zone_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ_a = _cf_integ(db_session, test_user, ws.id, zone="zone-A")
    integ_b = _cf_integ(db_session, test_user, ws.id, zone="zone-B")
    _finding(db_session, ws, integ_a, "cloudflare_waf_rule_disabled")
    # WAF event under a DIFFERENT zone-scoped integration → different zone.
    _waf_event(db_session, ws.id, integ_b.id, "cloudflare.waf_event.block")
    try:
        s = _gen_waf(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_outside_window_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_waf_rule_disabled")
    old = datetime.now(timezone.utc) - timedelta(hours=48)
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block", occurred=old)
    try:
        s = _gen_waf(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── idempotency + linked signal ───────────────────────────────────────────────

def test_idempotent_regeneration(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_waf_rule_disabled")
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block")
    try:
        s1 = _gen_waf(db_session, ws.id)
        s2 = _gen_waf(db_session, ws.id)
        assert s1["correlations_created"] == 1
        assert s2["correlations_created"] == 0
        assert s2["correlations_skipped"] == 1
        assert len(_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


def test_correlation_creates_linked_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    finding = _finding(db_session, ws, integ, "cloudflare_access_policy_bypass")
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.challenge",
               action="challenge", path_prefix="login")
    try:
        _gen_waf(db_session, ws.id)
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


# ── combined endpoint generates BOTH audit and WAF correlations ───────────────

def test_combined_provider_cloudflare_generates_waf(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    # Audit side (M68.2): TLS finding + audit ssl_tls event.
    _finding(db_session, ws, integ, "cloudflare_ssl_mode_weak")
    _audit_event(db_session, ws.id, integ.id, "cloudflare.ssl_tls.changed")
    # WAF side (M68.6): WAF-disabled finding + WAF block event.
    _finding(db_session, ws, integ, "cloudflare_waf_rule_disabled")
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block")
    try:
        s = _gen_all(db_session, ws.id)
        assert s["correlations_created"] == 3  # tls audit + tls waf + waf waf
        types = {c.correlation_type for c in _corrs(db_session, ws.id)}
        assert "cloudflare_tls_change" in types          # audit
        assert "cloudflare_waf_risk_activity" in types    # waf
        assert "cloudflare_tls_activity" in types         # waf (ssl finding)
    finally:
        _cleanup(db_session, ws.id)


# ── list filter + workspace scoping ───────────────────────────────────────────

def test_list_filter_and_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ = _cf_integ(db_session, test_user, ws_a.id)
    _finding(db_session, ws_a, integ, "cloudflare_waf_rule_disabled")
    _waf_event(db_session, ws_a.id, integ.id, "cloudflare.waf_event.block")
    try:
        _gen_waf(db_session, ws_a.id)
        assert len(_corrs(db_session, ws_a.id, ctype="cloudflare_waf_risk_activity")) == 1
        assert _corrs(db_session, ws_b.id) == []
    finally:
        _cleanup(db_session, ws_a.id)
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── privacy + claim discipline ────────────────────────────────────────────────

def test_metadata_privacy_and_claims(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_access_policy_bypass")
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block",
               path_prefix="admin")
    try:
        _gen_waf(db_session, ws.id)
        for c in _corrs(db_session, ws.id):
            blob = json.dumps({"t": c.title, "s": c.summary, "m": c.correlation_metadata},
                              default=str)
            low = blob.lower()
            for phrase in _FORBIDDEN:
                assert phrase not in low, f"forbidden {phrase!r}"
            assert "may require review" in c.summary.lower()
            assert set(c.correlation_metadata.keys()) <= _ALLOWED_CORR_META
            assert RAW_IP not in blob
            for bad in ("path_hash", "ray_id", "source_ip", "newvalue", "oldvalue",
                        "token", "secret", "cookie", "headers", "query"):
                assert bad not in low
    finally:
        _cleanup(db_session, ws.id)


# ── endpoint admin gating ─────────────────────────────────────────────────────

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
    _finding(db_session, ws, integ, "cloudflare_waf_rule_disabled")
    _waf_event(db_session, ws.id, integ.id, "cloudflare.waf_event.block")
    try:
        gen = client.post("/security/correlations/generate", json={"provider": "cloudflare"})
        assert gen.status_code == 200
        body = gen.json()
        assert body["provider"] == "cloudflare"
        assert body["correlations_created"] == 1

        lst = client.get(
            "/security/correlations?provider=cloudflare"
            "&correlation_type=cloudflare_waf_risk_activity")
        assert lst.status_code == 200
        lb = lst.json()
        assert lb["total"] == 1
        assert lb["items"][0]["correlation_type"] == "cloudflare_waf_risk_activity"
    finally:
        _cleanup(db_session, ws.id)
