"""M69.4F — GitHub Configuration Risk × code-scanning alert correlations.

Correlations are EVIDENCE FOR REVIEW that link a GitHub Configuration Risk finding
to GitHub code-scanning (SAST) ALERT evidence (security_activity_events,
provider=github, source=code_scanning_alert — M69.4D) on the SAME repository within
the review window. Only OPEN/REOPENED alerts correlate (fixed/dismissed never do).
These tests assert matching/window/idempotency/scoping/privacy/permissions and that
NO forbidden exploitation/compromise/breach/attack wording appears.

  1. Repository protection risk + open alert → github_repo_protection_code_alert.
  2. Repository protection risk + reopened alert → correlation.
  3. High/critical alert raises severity (environment family medium → high).
  4. Automation (deploy-key/webhook) risk + alert → github_automation_code_alert.
  5. Environment protection risk + alert → github_environment_code_alert.
  6. Generic fallback (github_repo_risk_code_alert) → DEFERRED / no-op.
  7. Different repository → no correlation.
  8. Same org only (different repo) → no correlation.
  9. Fixed-only / dismissed-only alert → no correlation.
 10. Alert outside the review window → no correlation.
 11. Repeated generation is idempotent.
 12. A linked correlation-evidence incident signal is created.
 13. List endpoint filters provider=github + the new correlation types.
 14. Workspace scoping prevents leakage.
 15. Generate is admin/owner-gated; member cannot generate.
 16. No raw code/SARIF/locations/path/URL in correlation metadata.
 17. No forbidden claim wording in correlation title/summary.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

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
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "vulnerability exploitation confirmed",
    "exploit confirmed",
    "compromise confirmed",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
]

REPO = "acme/repo"
_OPEN = "github.code_scanning.alert.open"
_REOPENED = "github.code_scanning.alert.reopened"
_FIXED = "github.code_scanning.alert.fixed"
_DISMISSED = "github.code_scanning.alert.dismissed"

_PROTECTION_TYPE = "github_repo_protection_code_alert"
_AUTOMATION_TYPE = "github_automation_code_alert"
_ENVIRONMENT_TYPE = "github_environment_code_alert"
_GENERIC_TYPE = "github_repo_risk_code_alert"


# ── builders ──────────────────────────────────────────────────────────────────

def _new_user(db, label="owner"):
    u = User(
        clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
        email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test",
        display_name=label,
    )
    db.add(u); db.commit(); db.refresh(u)
    return u


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.4F", db=db
    )


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"github_token": "x", "repo_owner": "acme", "repo_name": "repo"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="github",
        display_name="github", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i); db.commit(); db.refresh(i)
    return i


def _repo(db, integ, user, slug=REPO):
    r = Resource(
        integration_id=integ.id, user_id=user.id,
        provider_resource_type="github_repo", provider_resource_id=slug,
        display_name=slug, is_active=True,
    )
    db.add(r); db.commit(); db.refresh(r)
    return r


def _finding(db, ws, integ, res, base_rule, severity="high"):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key=f"{base_rule}:{uuid.uuid4().hex[:8]}", severity=severity,
        title=f"{base_rule} risk", resource_id=res.id, description="desc",
        evidence={"rule": base_rule}, remediation={"summary": "fix"},
    )


def _cs_event(
    db, ws_id, integ_id, *, event_type=_OPEN, repo=REPO, occurred=None,
    alert_number=4, state="open", rule_id="js/sql-injection", tool_name="CodeQL",
    security_severity_level="high",
):
    """Insert a normalized code-scanning ALERT activity event.

    Includes raw-ish fields the activity sanitizer MUST drop so the correlation
    can never carry them downstream.
    """
    norm = activity_svc.normalize_activity_event(
        provider="github", source="code_scanning_alert", event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id="ghcs:" + uuid.uuid4().hex, actor_id=None,
        resource_type="repository", resource_id=repo,
        metadata={
            "repository": repo,
            "repository_full_name": repo,
            "alert_number": alert_number,
            "state": state,
            "rule_id": rule_id,
            "rule_name": "Database query built from user-controlled sources",
            "tool_name": tool_name,
            "severity": "error",
            "security_severity_level": security_severity_level,
            "instances_count": 2,
            # MUST be dropped by the activity allowlist:
            "html_url": f"https://github.com/{repo}/security/code-scanning/{alert_number}?token=ghp_RAW",
            "path": "src/db/query.js",
            "message": "SELECT * FROM users WHERE id = req.params.id",
        },
    )
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db
    )
    return row


def _add_member(db, ws_id, user_id, role):
    m = WorkspaceMember(workspace_id=ws_id, user_id=user_id, role=role)
    db.add(m); db.commit(); db.refresh(m)
    return m


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
        db.query(Resource).filter(Resource.integration_id.in_(integ_ids)).delete(synchronize_session=False)
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(synchronize_session=False)
    db.commit()


def _gen(db, ws_id):
    return corr_svc.generate_github_correlations(workspace_id=ws_id, db=db)


def _cs_corrs(db, ws_id):
    items, _ = corr_svc.list_correlations(workspace_id=ws_id, db=db)
    cs_types = {_PROTECTION_TYPE, _AUTOMATION_TYPE, _ENVIRONMENT_TYPE, _GENERIC_TYPE}
    return [c for c in items if c.correlation_type in cs_types]


# ── 1. protection risk + open alert → protection correlation ──────────────────

def test_protection_risk_open_alert_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN)
    try:
        summary = _gen(db_session, ws.id)
        assert summary["correlations_created"] >= 1
        corrs = _cs_corrs(db_session, ws.id)
        assert len(corrs) == 1
        c = corrs[0]
        assert c.correlation_type == _PROTECTION_TYPE
        assert c.provider == "github"
        assert c.severity == "high"
        assert c.linked_finding_id is not None
        assert c.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


# ── 2. protection risk + reopened alert → correlation ─────────────────────────

def test_protection_risk_reopened_alert_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_force_pushes_allowed")
    _cs_event(db_session, ws.id, integ.id, event_type=_REOPENED, state="open")
    try:
        _gen(db_session, ws.id)
        corrs = _cs_corrs(db_session, ws.id)
        assert len(corrs) == 1
        assert corrs[0].correlation_type == _PROTECTION_TYPE
    finally:
        _cleanup(db_session, ws.id)


# ── 3. high/critical raises severity (environment family medium → high) ───────

def test_environment_severity_bump_on_critical(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_env_protection_missing", severity="medium")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN, security_severity_level="critical")
    try:
        _gen(db_session, ws.id)
        corrs = _cs_corrs(db_session, ws.id)
        assert len(corrs) == 1
        c = corrs[0]
        assert c.correlation_type == _ENVIRONMENT_TYPE
        assert c.severity == "high"  # bumped from medium by critical alert
        assert c.correlation_metadata.get("security_severity_level") == "critical"
    finally:
        _cleanup(db_session, ws.id)


def test_environment_stays_medium_on_low_severity(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_env_protection_missing", severity="medium")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN, security_severity_level="low")
    try:
        _gen(db_session, ws.id)
        corrs = _cs_corrs(db_session, ws.id)
        assert len(corrs) == 1
        assert corrs[0].severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. automation risk + alert → automation correlation ───────────────────────

def test_automation_risk_alert_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_deploy_key_write_access")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN)
    try:
        _gen(db_session, ws.id)
        corrs = _cs_corrs(db_session, ws.id)
        assert len(corrs) == 1
        assert corrs[0].correlation_type == _AUTOMATION_TYPE
    finally:
        _cleanup(db_session, ws.id)


# ── 5. environment protection risk + alert → environment correlation ──────────

def test_environment_risk_alert_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_env_protection_missing", severity="medium")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN, security_severity_level="medium")
    try:
        _gen(db_session, ws.id)
        corrs = _cs_corrs(db_session, ws.id)
        assert len(corrs) == 1
        assert corrs[0].correlation_type == _ENVIRONMENT_TYPE
        assert corrs[0].severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 6. generic fallback is deferred (no-op) ───────────────────────────────────

def test_generic_fallback_deferred(test_user, db_session):
    # No GitHub repo-scoped finding rule maps to the generic type, so it never
    # fires. Confirm the constant exists but produces no correlation rows.
    assert corr_svc._CS_GENERIC_TYPE == _GENERIC_TYPE
    assert _GENERIC_TYPE not in {
        r["correlation_type"] for r in corr_svc.CODE_SCANNING_CORRELATION_RULES.values()
    }


# ── 7. different repository → no correlation ──────────────────────────────────

def test_different_repository_does_not_correlate(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user, slug="acme/repo")
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN, repo="acme/other-repo")
    try:
        _gen(db_session, ws.id)
        assert _cs_corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 8. fixed-only / dismissed-only alert → no correlation ─────────────────────

@pytest.mark.parametrize("event_type,state", [
    (_FIXED, "fixed"),
    (_DISMISSED, "dismissed"),
])
def test_fixed_or_dismissed_alert_does_not_correlate(test_user, db_session, event_type, state):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _cs_event(db_session, ws.id, integ.id, event_type=event_type, state=state)
    try:
        _gen(db_session, ws.id)
        assert _cs_corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 9. alert outside the review window → no correlation ───────────────────────

def test_alert_outside_window_does_not_correlate(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN,
              occurred=datetime.now(timezone.utc) - timedelta(days=10))
    try:
        _gen(db_session, ws.id)
        assert _cs_corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 10. idempotency ───────────────────────────────────────────────────────────

def test_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN)
    try:
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["correlations_created"] == 1
        assert s2["correlations_created"] == 0
        assert s2["correlations_skipped"] >= 1
        assert len(_cs_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 11. linked correlation-evidence incident signal is created ────────────────

def test_creates_linked_correlation_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN)
    try:
        _gen(db_session, ws.id)
        c = _cs_corrs(db_session, ws.id)[0]
        assert c.linked_signal_id is not None
        sig = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.id == c.linked_signal_id).first()
        assert sig is not None
        assert sig.evidence_level == "correlation"
        assert sig.provider == "github"
        assert sig.signal_type == _PROTECTION_TYPE
    finally:
        _cleanup(db_session, ws.id)


# ── 12. list endpoint filters provider=github + new correlation types ─────────

def test_list_filters_provider_and_type(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN)
    try:
        _gen(db_session, ws.id)
        items, total = corr_svc.list_correlations(
            workspace_id=ws.id, db=db_session, provider="github",
            correlation_type=_PROTECTION_TYPE,
        )
        assert total == 1
        assert all(c.provider == "github" for c in items)
        assert all(c.correlation_type == _PROTECTION_TYPE for c in items)
    finally:
        _cleanup(db_session, ws.id)


# ── 13. workspace scoping ─────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ = _integ(db_session, test_user, ws_a.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws_a, integ, res, "github_branch_protection_missing")
    _cs_event(db_session, ws_a.id, integ.id, event_type=_OPEN)
    try:
        _gen(db_session, ws_a.id)
        assert len(_cs_corrs(db_session, ws_a.id)) == 1
        assert len(_cs_corrs(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id)
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 14. admin/owner gating; member cannot generate ───────────────────────────

def test_generate_requires_admin_role(test_user, db_session):
    owner = _new_user(db_session, "owner")
    ws = _ws(owner, db_session)
    _add_member(db_session, ws.id, test_user.id, "member")
    try:
        with pytest.raises(HTTPException) as exc:
            workspace_permission_service.require_workspace_admin(ws.id, test_user.id, db_session)
        assert exc.value.status_code == 403
        member = workspace_permission_service.require_workspace_member(
            ws.id, test_user.id, db_session)
        assert member is not None
    finally:
        try:
            db_session.delete(owner); db_session.commit()
        except Exception:
            db_session.rollback()


def test_owner_can_generate_via_endpoint(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN)
    try:
        resp = client.post("/security/correlations/generate", json={"provider": "github"})
        assert resp.status_code == 200
        assert resp.json()["correlations_created"] >= 1
        assert len(_cs_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 15. privacy: no raw code / SARIF / locations / path / URL in metadata ─────

def test_no_raw_code_in_correlation_metadata(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN, security_severity_level="critical")
    try:
        _gen(db_session, ws.id)
        for c in _cs_corrs(db_session, ws.id):
            blob = json.dumps({
                "title": c.title, "summary": c.summary, "metadata": c.correlation_metadata,
            }, default=str)
            assert "ghp_" not in blob
            assert "token=" not in blob
            assert "SELECT" not in blob
            assert "query.js" not in blob
            for bad in ("html_url", "path", "message", "snippet", "code", "sarif",
                        "locations", "patch"):
                assert bad not in c.correlation_metadata
            # safe context fields ARE present.
            assert c.correlation_metadata.get("rule_id") == "js/sql-injection"
            assert c.correlation_metadata.get("tool_name") == "CodeQL"
            assert c.correlation_metadata.get("repository_full_name") == REPO
    finally:
        _cleanup(db_session, ws.id)


# ── 16. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _cs_event(db_session, ws.id, integ.id, event_type=_OPEN, security_severity_level="critical")
    try:
        _gen(db_session, ws.id)
        for c in _cs_corrs(db_session, ws.id):
            blob = json.dumps({"t": c.title, "s": c.summary, "m": c.correlation_metadata},
                              default=str).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "does not confirm" in c.summary.lower()
    finally:
        _cleanup(db_session, ws.id)
