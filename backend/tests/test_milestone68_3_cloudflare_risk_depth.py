"""M68.3 — deeper Cloudflare config-risk coverage + new correlations.

Adds Cloudflare Access-policy config-risk rules (bypass / disabled — data-backed
from decision + enabled, counts only) and unlocks two new correlation areas:
Access-policy (Candidate D) and exact zone-setting (HSTS / security_level /
development_mode, gated on an exact setting-name match). These tests assert the
new rules fire only from supported metadata, never store raw lists, that audit
normalization preserves a safe setting/policy name, and that the new
correlations fire only on exact matches.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.services import cloudflare_security_activity_ingestion_service as cf_ingest
from app.services import security_activity_event_service as activity_svc
from app.services import security_finding_service as finding_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services.security_rules import cloudflare as cf_rules
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
]


# ── pure rule-evaluator tests (no DB) ─────────────────────────────────────────

def test_access_bypass_policy_produces_high_finding():
    out = cf_rules.evaluate({
        "record_type": "cloudflare_access_policy", "record_id": "p1",
        "name": "open-bypass", "decision": "bypass", "enabled": True,
        "application_id": "app1",
    })
    assert len(out) == 1
    assert out[0].rule_key == "cloudflare_access_policy_bypass"
    assert out[0].severity == "high"


def test_access_disabled_policy_produces_finding():
    out = cf_rules.evaluate({
        "record_type": "cloudflare_access_policy", "record_id": "p2",
        "name": "x", "decision": "allow", "enabled": False, "application_id": "app1",
    })
    assert len(out) == 1
    assert out[0].rule_key == "cloudflare_access_policy_disabled"
    assert out[0].severity == "medium"


def test_clean_access_policy_no_false_positive():
    # A normal enabled allow policy must NOT produce a finding.
    out = cf_rules.evaluate({
        "record_type": "cloudflare_access_policy", "record_id": "p3",
        "name": "ok", "decision": "allow", "enabled": True,
    })
    assert out == []


def test_access_finding_evidence_has_no_raw_lists():
    out = cf_rules.evaluate({
        "record_type": "cloudflare_access_policy", "record_id": "p1",
        "name": "open", "decision": "bypass", "enabled": True,
        # Even if a raw include list were present on the record, the rule must
        # not copy it — only decision/name/app id are used.
        "include": [{"email": {"email": "a@x.com"}}],
    })
    blob = json.dumps(out[0].evidence)
    assert "include" not in blob and "a@x.com" not in blob and "email" not in blob


# ── audit normalization preserves a safe setting name ─────────────────────────

def test_audit_normalization_preserves_setting_name():
    n = cf_ingest.normalize_audit_event({
        "id": "e1", "action": {"type": "security_level", "result": "success"},
        "actor": {"email": "admin@x.com"}, "resource": {"id": "security_level", "type": "setting"},
        "owner": {"id": "acct"}, "when": "2026-06-12T10:00:00Z",
        "newValue": "off", "oldValue": "medium",
    })
    assert n["event_type"] == "cloudflare.zone_setting.changed"
    assert n["metadata"].get("setting_name") == "security_level"
    blob = json.dumps(n, default=str)
    assert "newValue" not in blob and "oldValue" not in blob and "off" not in blob


def test_audit_normalization_access_policy_name():
    n = cf_ingest.normalize_audit_event({
        "id": "e2", "action": {"type": "access_policy.update", "result": "success"},
        "actor": {"email": "admin@x.com"},
        "resource": {"id": "pol-1", "type": "access_policy", "name": "Prod Access"},
        "owner": {"id": "acct"}, "when": "2026-06-12T10:00:00Z",
    })
    assert n["event_type"] == "cloudflare.access_policy.changed"
    assert n["metadata"].get("policy_name") == "Prod Access"


# ── DB correlation fixtures ───────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M68.3", db=db)


def _cf_integ(db, user, ws_id, zone="zone-1"):
    ct, iv = encrypt_credentials({"api_token": "x", "zone_id": zone, "account_id": "acct-1"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="cloudflare",
        display_name=f"cf-{zone}", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i); db.commit(); db.refresh(i)
    return i


def _finding(db, ws, integ, base_rule, *, severity="high", setting=None):
    evidence = {"rule": base_rule}
    if setting:
        evidence["setting"] = setting
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="cloudflare",
        finding_key=f"{base_rule}:{uuid.uuid4().hex[:8]}", severity=severity,
        title=f"{base_rule} risk", resource_id=None, description="d",
        evidence=evidence, remediation={"summary": "fix"})


def _event(db, ws_id, integ_id, event_type, *, occurred=None, metadata=None):
    norm = activity_svc.normalize_activity_event(
        provider="cloudflare", source="audit_log", event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id=f"cf-{uuid.uuid4().hex[:12]}",
        actor_id="admin@x.com", actor_type="user",
        resource_type="setting", resource_id="r1",
        metadata={"zone_id": "zone-1", "zone_name": "example.com", **(metadata or {})})
    _o, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _gen(db, ws_id):
    return corr_svc.generate_cloudflare_correlations(workspace_id=ws_id, db=db)


def _corrs(db, ws_id):
    items, _ = corr_svc.list_correlations(workspace_id=ws_id, db=db, provider="cloudflare")
    return items


def _cleanup(db, ws_id):
    for m in (SecuritySignalCorrelation, SecurityIncidentSignal, SecurityFinding, SecurityActivityEvent):
        db.query(m).filter(m.workspace_id == ws_id).delete(synchronize_session=False)
    ids = [i.id for i in db.query(Integration).filter(Integration.workspace_id == ws_id).all()]
    if ids:
        db.query(Integration).filter(Integration.id.in_(ids)).delete(synchronize_session=False)
    db.commit()


# ── Access-policy correlation (Candidate D, unlocked) ─────────────────────────

def test_access_policy_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_access_policy_bypass")
    _event(db_session, ws.id, integ.id, "cloudflare.access_policy.changed",
           metadata={"policy_name": "Prod Access"})
    try:
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "cloudflare_access_policy_change"
    finally:
        _cleanup(db_session, ws.id)


# ── exact zone-setting correlation ────────────────────────────────────────────

def test_zone_setting_correlation_exact_match(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_security_level_low",
             severity="medium", setting="security_level")
    _event(db_session, ws.id, integ.id, "cloudflare.zone_setting.changed",
           metadata={"setting_name": "security_level"})
    try:
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "cloudflare_zone_setting_change"
        assert c.correlation_metadata.get("setting_name") == "security_level"
    finally:
        _cleanup(db_session, ws.id)


def test_zone_setting_no_correlation_on_setting_mismatch(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    # security_level finding but the audit event changed a DIFFERENT setting.
    _finding(db_session, ws, integ, "cloudflare_security_level_low",
             severity="medium", setting="security_level")
    _event(db_session, ws.id, integ.id, "cloudflare.zone_setting.changed",
           metadata={"setting_name": "development_mode"})
    try:
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


def test_zone_setting_no_correlation_without_setting_name(test_user, db_session):
    # A generic zone_setting.changed with no setting_name must NOT correlate.
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_hsts_disabled",
             severity="medium", setting="security_header")
    _event(db_session, ws.id, integ.id, "cloudflare.zone_setting.changed")
    try:
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── gates: wrong area, outside window, idempotency, claims ─────────────────────

def test_wrong_area_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_access_policy_bypass")
    # Access finding but only a zone-setting event present → no correlation.
    _event(db_session, ws.id, integ.id, "cloudflare.zone_setting.changed",
           metadata={"setting_name": "security_level"})
    try:
        assert _gen(db_session, ws.id)["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


def test_outside_window_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_access_policy_disabled", severity="medium")
    old = datetime.now(timezone.utc) - timedelta(hours=48)
    _event(db_session, ws.id, integ.id, "cloudflare.access_policy.changed", occurred=old,
           metadata={"policy_name": "x"})
    try:
        assert _gen(db_session, ws.id)["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_idempotent_generation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_access_policy_bypass")
    _event(db_session, ws.id, integ.id, "cloudflare.access_policy.changed",
           metadata={"policy_name": "Prod"})
    try:
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["correlations_created"] == 1
        assert s2["correlations_created"] == 0
        assert s2["correlations_skipped"] == 1
    finally:
        _cleanup(db_session, ws.id)


def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _cf_integ(db_session, test_user, ws.id)
    _finding(db_session, ws, integ, "cloudflare_security_level_low",
             severity="medium", setting="security_level")
    _event(db_session, ws.id, integ.id, "cloudflare.zone_setting.changed",
           metadata={"setting_name": "security_level"})
    try:
        _gen(db_session, ws.id)
        for c in _corrs(db_session, ws.id):
            blob = f"{c.title}\n{c.summary}".lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "may require review" in c.summary.lower()
    finally:
        _cleanup(db_session, ws.id)
