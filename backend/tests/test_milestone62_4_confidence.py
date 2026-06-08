"""M62.4 — rule confidence + false-positive safeguards.

  1.  confidence registry covers every known rule (FindingCandidate-equivalent)
  2.  no emitted rule is low confidence
  3.  created finding persists confidence + reason + guard
  4.  refreshing an active finding keeps confidence metadata current
  5.  confidence is rule-derived (medium rule → medium; high rule → high)
  6.  confidence_for handles unknown keys (defaults high, no guard)
  7.  API response includes confidence metadata
  8.  demo findings carry confidence metadata
  9.  existing lifecycle (resolve) preserves confidence
"""

from __future__ import annotations

import uuid

from app.connectors.github_schema import GITHUB_WEBHOOK
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.user import User
from app.services import security_finding_service as svc
from app.services import security_demo_data_service as demo
from app.services import workspace_service
from app.services.security_rule_confidence import (
    HIGH,
    MEDIUM,
    RULE_CONFIDENCE,
    confidence_for,
)
from app.services.security_rule_registry import KNOWN_RULE_KEYS


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M62.4", db=db
    )


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"credential_type": "github_app"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="github",
        display_name="gh", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _res(db, integ, user):
    r = Resource(
        integration_id=integ.id, user_id=user.id,
        provider_resource_type="github_repo", provider_resource_id="acme/widgets",
        display_name="acme/widgets", is_active=True,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _cleanup(db, ws_id):
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete()
    db.commit()


# ── 1 & 2. Registry coverage + no-low ─────────────────────────────────────────


def test_registry_covers_all_rules_no_low():
    assert KNOWN_RULE_KEYS == set(RULE_CONFIDENCE)
    assert all(conf in (HIGH, MEDIUM) for conf, _ in RULE_CONFIDENCE.values())


# ── 5 & 6. confidence_for ─────────────────────────────────────────────────────


def test_confidence_for_known_and_unknown():
    conf, reason, guard = confidence_for("github_webhook_http:acme#1")
    assert conf == HIGH and reason and guard
    # A medium rule.
    mconf, _, _ = confidence_for("vercel_preview_unprotected:proj")
    assert mconf == MEDIUM
    # Unknown rule → safe default high, no guard.
    uconf, ureason, uguard = confidence_for("totally_unknown:x")
    assert uconf == HIGH and ureason and uguard == ""


# ── 3 & 5. Persisted on create ────────────────────────────────────────────────


def test_create_persists_confidence(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = svc.upsert_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key="github_webhook_http:acme/widgets#webhook#1", severity="critical",
        title="GitHub webhook uses plain HTTP", resource_id=res.id,
    )
    assert f.confidence == HIGH
    assert f.confidence_reason
    assert f.false_positive_guard
    _cleanup(db_session, ws.id)


# ── 4. Refresh keeps confidence ───────────────────────────────────────────────


def test_refresh_keeps_confidence(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    kw = dict(
        db=db_session, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key="github_webhook_http:acme/widgets#webhook#1", severity="critical",
        title="GitHub webhook uses plain HTTP", resource_id=res.id,
    )
    svc.upsert_active_finding(**kw)
    f2 = svc.upsert_active_finding(**kw)  # refresh path
    assert f2.confidence == HIGH and f2.false_positive_guard
    _cleanup(db_session, ws.id)


# ── 9. Resolve preserves confidence ───────────────────────────────────────────


def test_resolve_preserves_confidence(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = svc.upsert_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key="github_webhook_http:acme/widgets#webhook#1", severity="critical",
        title="GitHub webhook uses plain HTTP", resource_id=res.id,
    )
    conf = f.confidence
    svc.resolve_finding(db=db_session, finding=f)
    db_session.refresh(f)
    assert f.status == "resolved" and f.confidence == conf and f.false_positive_guard
    _cleanup(db_session, ws.id)


# ── 8. Demo findings carry confidence ─────────────────────────────────────────


def test_demo_findings_have_confidence(test_user, db_session):
    ws = _ws(test_user, db_session)
    demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    integ = demo.get_demo_integration(ws.id, db_session)
    findings = (
        db_session.query(SecurityFinding)
        .filter(SecurityFinding.integration_id == integ.id)
        .all()
    )
    assert findings
    assert all(f.confidence in (HIGH, MEDIUM) for f in findings)
    assert all(f.confidence_reason for f in findings)
    demo.clear(workspace_id=ws.id, db=db_session)


# ── 7. API response includes confidence ───────────────────────────────────────


def test_api_response_includes_confidence(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = svc.upsert_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key="github_webhook_http:acme/widgets#webhook#1", severity="critical",
        title="GitHub webhook uses plain HTTP", resource_id=res.id,
    )
    resp = client.get(f"/security/findings/{f.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["confidence"] == HIGH
    assert body["confidence_reason"]
    assert body["false_positive_guard"]
    _cleanup(db_session, ws.id)
