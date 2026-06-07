"""M60.4.3 — Cloudflare security exposure rules.

Unit tests per rule (risky fires / safe + normal records do not / malformed
ignored / evidence metadata-only) plus DB-backed evaluator tests for lifecycle
(dedupe + resolve) and multi-record separate findings.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy.orm import Session

from app.connectors.cloudflare_schema import (
    CLOUDFLARE_WAF_RULE,
    CLOUDFLARE_ZONE_SETTING,
)
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.models.user import User
from app.services import security_finding_evaluator as evaluator
from app.services.security_rules import cloudflare as cf

_SECRET_RE = re.compile(
    r"secret|token|password|api_?key|access_?key|private_?key|client_secret", re.I
)


def _setting(setting_id: str, value, **over) -> dict:
    rec = {
        "record_type": CLOUDFLARE_ZONE_SETTING,
        "record_id": setting_id,
        "setting_id": setting_id,
        "value": value,
        "editable": True,
        "modified_on": None,
    }
    rec.update(over)
    return rec


def _waf(**over) -> dict:
    rec = {
        "record_type": CLOUDFLARE_WAF_RULE,
        "record_id": "rule-1",
        "ruleset_id": "rs-1",
        "description": "block SQLi",
        "action": "block",
        "enabled": True,
        "expression_hash": "abc",
        "modified_on": None,
    }
    rec.update(over)
    return rec


def _dns(content: str, **over) -> dict:
    rec = {
        "record_id": "dns-1",
        "record_type": "A",
        "name": "api.example.com",
        "content": content,
        "ttl": 1,
        "proxied": False,
        "priority": None,
        "comment": None,
        "modified_on": "",
    }
    rec.update(over)
    return rec


def _safe(cands):
    for c in cands:
        for k in c.evidence.keys():
            assert not _SECRET_RE.search(k), f"sensitive evidence key: {k}"


# ── Zone settings ────────────────────────────────────────────────────────────


def test_ssl_flexible_high():
    out = cf.evaluate(_setting("ssl", "flexible"))
    assert len(out) == 1 and out[0].rule_key == "cloudflare_ssl_mode_weak"
    assert out[0].severity == "high"
    _safe(out)


def test_ssl_off_high():
    out = cf.evaluate(_setting("ssl", "off"))
    assert out and out[0].severity == "high"


def test_ssl_strict_safe():
    assert cf.evaluate(_setting("ssl", "strict")) == []
    assert cf.evaluate(_setting("ssl", "full")) == []


def test_always_https_off_medium():
    out = cf.evaluate(_setting("always_use_https", "off"))
    assert out and out[0].rule_key == "cloudflare_always_https_off"
    assert out[0].severity == "medium"


def test_always_https_on_safe():
    assert cf.evaluate(_setting("always_use_https", "on")) == []


def test_min_tls_weak():
    assert cf.evaluate(_setting("min_tls_version", "1.0"))[0].rule_key == "cloudflare_min_tls_weak"
    assert cf.evaluate(_setting("min_tls_version", "1.1"))
    assert cf.evaluate(_setting("min_tls_version", "1.2")) == []


def test_security_level_off():
    assert cf.evaluate(_setting("security_level", "off"))[0].rule_key == "cloudflare_security_level_low"
    assert cf.evaluate(_setting("security_level", "essentially_off"))
    # 'medium'/'high'/'low' are normal — not flagged.
    assert cf.evaluate(_setting("security_level", "medium")) == []
    assert cf.evaluate(_setting("security_level", "low")) == []


def test_development_mode_on():
    assert cf.evaluate(_setting("development_mode", "on"))[0].rule_key == "cloudflare_development_mode_on"
    assert cf.evaluate(_setting("development_mode", "off")) == []


def test_hsts_disabled_nested():
    # Cloudflare's real nested shape.
    val = {"strict_transport_security": {"enabled": False, "max_age": 0}}
    out = cf.evaluate(_setting("security_header", val))
    assert out and out[0].rule_key == "cloudflare_hsts_disabled"
    _safe(out)


def test_hsts_enabled_safe():
    val = {"strict_transport_security": {"enabled": True, "max_age": 31536000}}
    assert cf.evaluate(_setting("security_header", val)) == []


def test_hsts_unknown_shape_not_flagged():
    # Indeterminate value must NOT be flagged.
    assert cf.evaluate(_setting("security_header", None)) == []
    assert cf.evaluate(_setting("security_header", "weird")) == []


def test_unmonitored_setting_ignored():
    assert cf.evaluate(_setting("automatic_https_rewrites", "off")) == []
    assert cf.evaluate(_setting("browser_check", "off")) == []


# ── WAF rule ─────────────────────────────────────────────────────────────────


def test_disabled_block_rule_high():
    out = cf.evaluate(_waf(enabled=False, action="block"))
    assert out and out[0].rule_key == "cloudflare_waf_rule_disabled"
    assert out[0].severity == "high"
    _safe(out)
    # expression hash must never be in evidence
    assert "expression_hash" not in out[0].evidence


def test_disabled_challenge_rule_medium():
    out = cf.evaluate(_waf(enabled=False, action="js_challenge"))
    assert out and out[0].severity == "medium"


def test_enabled_rule_safe():
    assert cf.evaluate(_waf(enabled=True, action="block")) == []


def test_disabled_log_rule_not_flagged():
    # A disabled log/skip rule is not a protection loss.
    assert cf.evaluate(_waf(enabled=False, action="log")) == []
    assert cf.evaluate(_waf(enabled=False, action="skip")) == []


def test_waf_malformed_ignored():
    assert cf.evaluate({"record_type": CLOUDFLARE_WAF_RULE, "action": "block"}) == []


# ── DNS private/reserved origin ──────────────────────────────────────────────


def test_dns_private_ip_high():
    out = cf.evaluate(_dns("10.0.0.5"))
    assert out and out[0].rule_key == "cloudflare_dns_private_origin"
    assert out[0].severity == "high"
    assert out[0].evidence["address_kind"] == "private"
    _safe(out)


def test_dns_loopback():
    out = cf.evaluate(_dns("127.0.0.1"))
    assert out and out[0].evidence["address_kind"] == "loopback"


def test_dns_public_ip_safe():
    assert cf.evaluate(_dns("93.184.216.34")) == []


def test_dns_cname_ignored():
    # CNAME content is a hostname, not an IP → ignored (no hostname guessing).
    assert cf.evaluate(_dns("origin.example.net", record_type="CNAME")) == []


def test_dns_non_ip_content_ignored():
    assert cf.evaluate(_dns("not-an-ip")) == []


def test_unknown_record_ignored():
    assert cf.evaluate({"record_type": "cloudflare_page_rule", "name": "x"}) == []
    assert cf.evaluate({"weird": "shape"}) == []


# ════════════════════════════════════════════════════════════════════════════
# DB-backed evaluator: lifecycle + multi-record
# ════════════════════════════════════════════════════════════════════════════


def _ws(user, db):
    from app.services import workspace_service

    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M60.4.3", db=db
    )


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"cloudflare_api_token": "x"})
    i = Integration(
        user_id=user.id,
        workspace_id=ws_id,
        provider="cloudflare",
        display_name="cloudflare",
        encrypted_credentials=ct,
        credential_iv=iv,
        status="active",
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _res(db, integ, user):
    r = Resource(
        integration_id=integ.id,
        user_id=user.id,
        provider_resource_type="cloudflare_zone",
        provider_resource_id="zone-1",
        display_name="example.com",
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


def test_multiple_cloudflare_records_separate_findings(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    state = [
        _setting("ssl", "flexible"),
        _setting("development_mode", "on"),
        _waf(record_id="rule-9", enabled=False, action="block"),
        _dns("10.1.2.3", record_id="dns-9"),
        # safe rows:
        _setting("min_tls_version", "1.3"),
        _dns("93.184.216.34", record_id="dns-safe"),
    ]
    snap = _snap(db_session, res, integ, test_user, state)

    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap
    )
    findings = _active(db_session, ws.id, res.id)
    keys = {f.finding_key for f in findings}
    assert len(findings) == 4
    assert any(k.startswith("cloudflare_ssl_mode_weak") for k in keys)
    assert any(k.startswith("cloudflare_development_mode_on") for k in keys)
    assert any(k.startswith("cloudflare_waf_rule_disabled") for k in keys)
    assert any(k.startswith("cloudflare_dns_private_origin") for k in keys)

    _cleanup(db_session, ws.id)


def test_cloudflare_lifecycle_dedupe_and_resolve(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    risky = [_setting("ssl", "flexible")]
    s1 = _snap(db_session, res, integ, test_user, risky)
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=s1
    )
    f1 = _active(db_session, ws.id, res.id)
    assert len(f1) == 1
    first_seen = f1[0].last_seen_at

    s2 = _snap(db_session, res, integ, test_user, risky)
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=s2
    )
    f2 = _active(db_session, ws.id, res.id)
    assert len(f2) == 1 and f2[0].id == f1[0].id
    assert f2[0].last_seen_at >= first_seen

    # SSL set to strict → finding resolves.
    s3 = _snap(db_session, res, integ, test_user, [_setting("ssl", "strict")])
    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=s3
    )
    assert summary["resolved"] == 1
    assert _active(db_session, ws.id, res.id) == []

    _cleanup(db_session, ws.id)
