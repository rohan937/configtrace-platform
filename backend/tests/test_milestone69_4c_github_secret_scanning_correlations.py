"""M69.4C — GitHub Configuration Risk × secret-scanning alert correlations.

Correlations are EVIDENCE FOR REVIEW that link a GitHub Configuration Risk finding
to GitHub secret-scanning ALERT evidence (security_activity_events, provider=github,
source=secret_scanning_alert — M69.4A) on the SAME repository within the review
window. Only OPEN alerts correlate (resolved/revoked/false_positive/used_in_tests
never do). These tests assert matching/window/idempotency/scoping/privacy/permissions
and that NO forbidden secret-leakage/compromise/breach/attack wording appears.

  1. Repository protection risk + open alert → github_repo_protection_secret_alert.
  2. Automation (deploy-key/webhook) risk + open alert → github_automation_secret_alert.
  3. Public visibility risk + publicly_leaked alert → DEFERRED (no rule exists today).
  4. Generic repo-scoped risk + publicly_leaked alert → high github_repo_risk_secret_alert.
  5. Different repository → no correlation.
  6. Same org only (different repo) → no correlation.
  7. Resolved / false_positive / used_in_tests alert → no correlation.
  8. Alert outside the review window → no correlation.
  9. Repeated generation is idempotent.
 10. A linked correlation-evidence incident signal is created.
 11. List endpoint filters provider=github + the new correlation types.
 12. Workspace scoping prevents leakage.
 13. Generate is admin/owner-gated (permission helper); member cannot generate.
 14. No raw secret/token/URL/locations in correlation metadata.
 15. No forbidden claim wording in correlation title/summary.
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
    "secret leakage confirmed",
    "compromise confirmed",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
]

RAW_SECRET = "ghp_SUPERSECRETTOKENVALUE1234567890"
REPO = "acme/repo"
_OPEN = "github.secret_scanning.alert.open"
_RESOLVED = "github.secret_scanning.alert.resolved"
_FALSE_POSITIVE = "github.secret_scanning.alert.false_positive"
_USED_IN_TESTS = "github.secret_scanning.alert.used_in_tests"

_PROTECTION_TYPE = "github_repo_protection_secret_alert"
_AUTOMATION_TYPE = "github_automation_secret_alert"
_GENERIC_TYPE = "github_repo_risk_secret_alert"


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
        user_id=user.id, user_display_name=user.display_name or "M69.4C", db=db
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


def _ss_event(
    db, ws_id, integ_id, *, event_type=_OPEN, repo=REPO, occurred=None,
    alert_number=7, state="open", resolution=None, secret_type="github_personal_access_token",
    validity="active", publicly_leaked=False,
):
    """Insert a normalized secret-scanning ALERT activity event.

    Includes raw-ish fields (``secret``/``html_url``) that the activity-event
    sanitizer MUST drop so the correlation can never carry them downstream.
    """
    norm = activity_svc.normalize_activity_event(
        provider="github", source="secret_scanning_alert", event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id="ghss:" + uuid.uuid4().hex, actor_id=None,
        resource_type="secret_scanning_alert", resource_id=repo,
        metadata={
            "repository": repo,
            "repository_full_name": repo,
            "alert_number": alert_number,
            "state": state,
            "resolution": resolution,
            "secret_type": secret_type,
            "secret_type_display_name": "GitHub Personal Access Token",
            "validity": validity,
            "publicly_leaked": publicly_leaked,
            "location_count": 2,
            # These MUST be dropped by the activity allowlist:
            "secret": RAW_SECRET,
            "html_url": f"https://github.com/{repo}/security/secret-scanning/{alert_number}?token={RAW_SECRET}",
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


def _ss_corrs(db, ws_id):
    items, _ = corr_svc.list_correlations(workspace_id=ws_id, db=db)
    ss_types = {_PROTECTION_TYPE, _AUTOMATION_TYPE, _GENERIC_TYPE}
    return [c for c in items if c.correlation_type in ss_types]


# ── 1. repository protection risk + open alert → protection correlation ───────

def test_protection_risk_open_alert_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _ss_event(db_session, ws.id, integ.id, event_type=_OPEN, validity="active")
    try:
        summary = _gen(db_session, ws.id)
        assert summary["correlations_created"] >= 1
        corrs = _ss_corrs(db_session, ws.id)
        assert len(corrs) == 1
        c = corrs[0]
        assert c.correlation_type == _PROTECTION_TYPE
        assert c.provider == "github"
        assert c.severity == "high"
        assert c.linked_finding_id is not None
        assert c.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


# ── 2. automation/deploy-key/webhook risk + open alert → automation correlation ─

def test_automation_risk_open_alert_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_deploy_key_write_access")
    _ss_event(db_session, ws.id, integ.id, event_type=_OPEN)
    try:
        _gen(db_session, ws.id)
        corrs = _ss_corrs(db_session, ws.id)
        assert len(corrs) == 1
        assert corrs[0].correlation_type == _AUTOMATION_TYPE
    finally:
        _cleanup(db_session, ws.id)


def test_webhook_risk_also_correlates_to_secret_alert(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_webhook_http", severity="high")
    _ss_event(db_session, ws.id, integ.id, event_type=_OPEN)
    try:
        _gen(db_session, ws.id)
        corrs = _ss_corrs(db_session, ws.id)
        assert len(corrs) == 1
        assert corrs[0].correlation_type == _AUTOMATION_TYPE
    finally:
        _cleanup(db_session, ws.id)


# ── 3. generic repo-scoped risk + publicly_leaked alert → high generic ─────────

def test_generic_repo_risk_publicly_leaked_high(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    # github_env_protection_missing is a medium-severity generic-fallback rule.
    _finding(db_session, ws, integ, res, "github_env_protection_missing", severity="medium")
    _ss_event(db_session, ws.id, integ.id, event_type=_OPEN,
              validity="inactive", publicly_leaked=True)
    try:
        _gen(db_session, ws.id)
        corrs = _ss_corrs(db_session, ws.id)
        assert len(corrs) == 1
        c = corrs[0]
        assert c.correlation_type == _GENERIC_TYPE
        # Raised to high because GitHub marked the alert publicly leaked.
        assert c.severity == "high"
        assert c.correlation_metadata.get("publicly_leaked") is True
    finally:
        _cleanup(db_session, ws.id)


# ── 4. different repository → no correlation ──────────────────────────────────

def test_different_repository_does_not_correlate(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user, slug="acme/repo")
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    # Alert on a DIFFERENT repo in the same org.
    _ss_event(db_session, ws.id, integ.id, event_type=_OPEN, repo="acme/other-repo")
    try:
        _gen(db_session, ws.id)
        assert _ss_corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 5. resolved / false-positive / used-in-tests alert → no correlation ───────

@pytest.mark.parametrize("event_type,resolution,state", [
    (_RESOLVED, "resolved", "resolved"),
    (_FALSE_POSITIVE, "false_positive", "resolved"),
    (_USED_IN_TESTS, "used_in_tests", "resolved"),
])
def test_non_open_alert_does_not_correlate(test_user, db_session, event_type, resolution, state):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _ss_event(db_session, ws.id, integ.id, event_type=event_type,
              resolution=resolution, state=state)
    try:
        _gen(db_session, ws.id)
        assert _ss_corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 6. alert outside the review window → no correlation ───────────────────────

def test_alert_outside_window_does_not_correlate(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    # 10 days before the finding's first_detected_at — well outside the 24h window.
    _ss_event(db_session, ws.id, integ.id, event_type=_OPEN,
              occurred=datetime.now(timezone.utc) - timedelta(days=10))
    try:
        _gen(db_session, ws.id)
        assert _ss_corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 7. idempotency ────────────────────────────────────────────────────────────

def test_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _ss_event(db_session, ws.id, integ.id, event_type=_OPEN)
    try:
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["correlations_created"] == 1
        assert s2["correlations_created"] == 0
        assert s2["correlations_skipped"] >= 1
        assert len(_ss_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 8. linked correlation-evidence incident signal is created ─────────────────

def test_creates_linked_correlation_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _ss_event(db_session, ws.id, integ.id, event_type=_OPEN)
    try:
        _gen(db_session, ws.id)
        c = _ss_corrs(db_session, ws.id)[0]
        assert c.linked_signal_id is not None
        sig = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.id == c.linked_signal_id).first()
        assert sig is not None
        assert sig.evidence_level == "correlation"
        assert sig.provider == "github"
        assert sig.signal_type == _PROTECTION_TYPE
    finally:
        _cleanup(db_session, ws.id)


# ── 9. list endpoint filters provider=github + new correlation types ──────────

def test_list_filters_provider_and_type(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _ss_event(db_session, ws.id, integ.id, event_type=_OPEN)
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


# ── 10. workspace scoping ─────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ = _integ(db_session, test_user, ws_a.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws_a, integ, res, "github_branch_protection_missing")
    _ss_event(db_session, ws_a.id, integ.id, event_type=_OPEN)
    try:
        _gen(db_session, ws_a.id)
        assert len(_ss_corrs(db_session, ws_a.id)) == 1
        assert len(_ss_corrs(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id)
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 11. admin/owner gating; member cannot generate ───────────────────────────

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
    _ss_event(db_session, ws.id, integ.id, event_type=_OPEN)
    try:
        resp = client.post("/security/correlations/generate", json={"provider": "github"})
        assert resp.status_code == 200
        assert resp.json()["correlations_created"] >= 1
        assert len(_ss_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 12. privacy: no raw secret / token / URL / locations in metadata ──────────

def test_no_raw_secret_in_correlation_metadata(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _ss_event(db_session, ws.id, integ.id, event_type=_OPEN, publicly_leaked=True)
    try:
        _gen(db_session, ws.id)
        for c in _ss_corrs(db_session, ws.id):
            blob = json.dumps({
                "title": c.title, "summary": c.summary, "metadata": c.correlation_metadata,
            }, default=str)
            assert RAW_SECRET not in blob
            assert "ghp_" not in blob
            assert "token=" not in blob
            assert "html_url" not in c.correlation_metadata
            assert "secret" not in c.correlation_metadata
            assert "locations" not in c.correlation_metadata
            # safe context fields ARE present.
            assert c.correlation_metadata.get("secret_type") == "github_personal_access_token"
            assert c.correlation_metadata.get("repository_full_name") == REPO
    finally:
        _cleanup(db_session, ws.id)


# ── 13. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "github_branch_protection_missing")
    _ss_event(db_session, ws.id, integ.id, event_type=_OPEN, publicly_leaked=True)
    try:
        _gen(db_session, ws.id)
        for c in _ss_corrs(db_session, ws.id):
            blob = json.dumps({"t": c.title, "s": c.summary, "m": c.correlation_metadata},
                              default=str).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "does not confirm" in c.summary.lower()
    finally:
        _cleanup(db_session, ws.id)
