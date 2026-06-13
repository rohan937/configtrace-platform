"""M69.5C — GitHub ruleset / automation-permission risk × evidence correlations.

Correlate the M69.5A ruleset findings and M69.5B automation-permission findings
with existing GitHub evidence on the SAME repository within the review window:
  * repository-protection / automation AUDIT activity (source=audit_log), and
  * OPEN/REOPENED security-alert evidence (secret / code / Dependabot).

These tests assert matching/window/idempotency/scoping/privacy/permissions and
that NO forbidden compromise/token-leak/attacker wording appears.
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
    "compromise confirmed", "token leaked", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
REPO = "acme/repo"

_RULESET_TYPES = {"github_ruleset_risk_activity", "github_ruleset_risk_security_alert"}
_AUTO_TYPES = {"github_automation_permission_activity",
               "github_automation_permission_security_alert"}
_ALL_5C_TYPES = _RULESET_TYPES | _AUTO_TYPES


# ── builders ──────────────────────────────────────────────────────────────────

def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.5C", db=db)


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"github_token": "x", "repo_owner": "acme", "repo_name": "repo"})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="github",
                    display_name="github", encrypted_credentials=ct, credential_iv=iv,
                    status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _repo(db, integ, user, slug=REPO):
    r = Resource(integration_id=integ.id, user_id=user.id,
                 provider_resource_type="github_repo", provider_resource_id=slug,
                 display_name=slug, is_active=True)
    db.add(r); db.commit(); db.refresh(r)
    return r


def _ruleset_finding(db, ws, integ, res, base_rule="github_ruleset_not_enforced", severity="high"):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key=f"{base_rule}:{uuid.uuid4().hex[:8]}", severity=severity,
        title=f"{base_rule} risk", resource_id=res.id, description="desc",
        evidence={
            "rule": base_rule, "ruleset_name": "Protect main", "enforcement": "disabled",
            "target": "branch", "targets_protected_branch": True,
            "bypass_actor_count": 2, "required_status_checks_count": 0,
            # decoys that must never leak into correlation metadata:
            "bypass_actor_login": "octocat", "token": "ghp_RAWTOKEN",
        },
        remediation={"summary": "fix"},
    )


def _automation_finding(db, ws, integ, res, base_rule="github_automation_admin_permission",
                        severity="high"):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key=f"{base_rule}:{uuid.uuid4().hex[:8]}", severity=severity,
        title=f"{base_rule} risk", resource_id=res.id, description="desc",
        evidence={
            "rule": base_rule, "credential_type": "github_token",
            "broad_permission_count": 2, "token_scope_count": 5,
            "broad_scope_names": ["repo", "workflow"],
            # decoys:
            "authorization": "Bearer ghp_RAWTOKEN", "private_key": "-----BEGIN-----",
        },
        remediation={"summary": "fix"},
    )


def _audit_event(db, ws_id, integ_id, event_type, *, repo=REPO, occurred=None):
    norm = activity_svc.normalize_activity_event(
        provider="github", source="audit_log", event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id=uuid.uuid4().hex, actor_id="mallory",
        resource_type="repository", resource_id=repo,
        metadata={"action": "x", "repository": repo},
    )
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _alert_event(db, ws_id, integ_id, *, source, event_type, repo=REPO, occurred=None,
                 metadata=None):
    md = {"repository": repo, "repository_full_name": repo, "alert_number": 4, "state": "open"}
    md.update(metadata or {})
    # decoys that the activity sanitizer must drop at ingestion:
    md.update({"secret": "ghp_RAWSECRET", "html_url": f"https://x/{repo}?token=ghp_RAW",
               "manifest_path": "services/internal/package-lock.json"})
    norm = activity_svc.normalize_activity_event(
        provider="github", source=source, event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id="alrt:" + uuid.uuid4().hex, actor_id=None,
        resource_type="repository", resource_id=repo, metadata=md,
    )
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
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


def _corrs(db, ws_id, types=_ALL_5C_TYPES):
    items, _ = corr_svc.list_correlations(workspace_id=ws_id, db=db)
    return [c for c in items if c.correlation_type in types]


# ── A. ruleset risk × repository-protection audit activity ───────────────────

def test_ruleset_risk_activity(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _ruleset_finding(db_session, ws, integ, res)
    _audit_event(db_session, ws.id, integ.id, "github.ruleset.changed")
    try:
        _gen(db_session, ws.id)
        corrs = _corrs(db_session, ws.id, {"github_ruleset_risk_activity"})
        assert len(corrs) == 1
        c = corrs[0]
        assert c.severity == "high"
        assert c.correlation_metadata.get("ruleset_name") == "Protect main"
        assert c.correlation_metadata.get("enforcement") == "disabled"
        assert c.linked_finding_id is not None and c.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


# ── B. ruleset risk × security-alert evidence ────────────────────────────────

def test_ruleset_risk_security_alert(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _ruleset_finding(db_session, ws, integ, res)
    _alert_event(db_session, ws.id, integ.id, source="secret_scanning_alert",
                 event_type="github.secret_scanning.alert.open",
                 metadata={"secret_type": "github_pat", "publicly_leaked": True})
    try:
        _gen(db_session, ws.id)
        corrs = _corrs(db_session, ws.id, {"github_ruleset_risk_security_alert"})
        assert len(corrs) == 1
        assert corrs[0].severity == "high"  # publicly leaked → high
        assert corrs[0].correlation_metadata.get("secret_type") == "github_pat"
    finally:
        _cleanup(db_session, ws.id)


# ── C. automation permission risk × automation audit activity ────────────────

def test_automation_permission_activity(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _automation_finding(db_session, ws, integ, res)
    _audit_event(db_session, ws.id, integ.id, "github.deploy_key.added")
    try:
        _gen(db_session, ws.id)
        corrs = _corrs(db_session, ws.id, {"github_automation_permission_activity"})
        assert len(corrs) == 1
        assert corrs[0].correlation_metadata.get("credential_type") == "github_token"
        assert corrs[0].correlation_metadata.get("broad_permission_count") == 2
    finally:
        _cleanup(db_session, ws.id)


# ── D. automation permission risk × security-alert evidence ──────────────────

def test_automation_permission_security_alert(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _automation_finding(db_session, ws, integ, res)
    _alert_event(db_session, ws.id, integ.id, source="code_scanning_alert",
                 event_type="github.code_scanning.alert.open",
                 metadata={"rule_id": "js/x", "tool_name": "CodeQL",
                           "security_severity_level": "high"})
    try:
        _gen(db_session, ws.id)
        corrs = _corrs(db_session, ws.id, {"github_automation_permission_security_alert"})
        assert len(corrs) == 1
        assert corrs[0].severity == "high"  # high security severity
        assert corrs[0].correlation_metadata.get("tool_name") == "CodeQL"
    finally:
        _cleanup(db_session, ws.id)


# ── different repository → no correlation ────────────────────────────────────

def test_different_repository_does_not_correlate(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user, slug="acme/repo")
    _ruleset_finding(db_session, ws, integ, res)
    _audit_event(db_session, ws.id, integ.id, "github.ruleset.changed", repo="acme/other")
    try:
        _gen(db_session, ws.id)
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── fixed/dismissed-only alert → no urgent security-alert correlation ────────

@pytest.mark.parametrize("event_type", [
    "github.code_scanning.alert.fixed",
    "github.code_scanning.alert.dismissed",
    "github.dependabot.alert.fixed",
])
def test_fixed_or_dismissed_alert_does_not_correlate(test_user, db_session, event_type):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _ruleset_finding(db_session, ws, integ, res)
    src = "dependabot_alert" if "dependabot" in event_type else "code_scanning_alert"
    _alert_event(db_session, ws.id, integ.id, source=src, event_type=event_type)
    try:
        _gen(db_session, ws.id)
        assert _corrs(db_session, ws.id, {"github_ruleset_risk_security_alert"}) == []
    finally:
        _cleanup(db_session, ws.id)


# ── outside window → no correlation ──────────────────────────────────────────

def test_outside_window_does_not_correlate(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _ruleset_finding(db_session, ws, integ, res)
    _audit_event(db_session, ws.id, integ.id, "github.ruleset.changed",
                 occurred=datetime.now(timezone.utc) - timedelta(days=10))
    try:
        _gen(db_session, ws.id)
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── unrelated audit event type → no correlation ─────────────────────────────

def test_unrelated_activity_does_not_correlate(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _ruleset_finding(db_session, ws, integ, res)
    # A collaborator event is not in the ruleset-protection activity set.
    _audit_event(db_session, ws.id, integ.id, "github.collaborator.added")
    try:
        _gen(db_session, ws.id)
        assert _corrs(db_session, ws.id, {"github_ruleset_risk_activity"}) == []
    finally:
        _cleanup(db_session, ws.id)


# ── idempotency ──────────────────────────────────────────────────────────────

def test_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _ruleset_finding(db_session, ws, integ, res)
    _audit_event(db_session, ws.id, integ.id, "github.ruleset.changed")
    try:
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["correlations_created"] == 1
        assert s2["correlations_created"] == 0
        assert s2["correlations_skipped"] >= 1
        assert len(_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── linked correlation-evidence signal ───────────────────────────────────────

def test_creates_linked_correlation_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _ruleset_finding(db_session, ws, integ, res)
    _audit_event(db_session, ws.id, integ.id, "github.ruleset.changed")
    try:
        _gen(db_session, ws.id)
        c = _corrs(db_session, ws.id, {"github_ruleset_risk_activity"})[0]
        assert c.linked_signal_id is not None
        sig = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.id == c.linked_signal_id).first()
        assert sig is not None
        assert sig.evidence_level == "correlation"
        assert sig.signal_type == "github_ruleset_risk_activity"
    finally:
        _cleanup(db_session, ws.id)


# ── list filter + workspace scoping ──────────────────────────────────────────

def test_list_filter_and_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session); ws_b = _ws(other, db_session)
    integ = _integ(db_session, test_user, ws_a.id)
    res = _repo(db_session, integ, test_user)
    _automation_finding(db_session, ws_a, integ, res)
    _audit_event(db_session, ws_a.id, integ.id, "github.webhook.created")
    try:
        _gen(db_session, ws_a.id)
        items, total = corr_svc.list_correlations(
            workspace_id=ws_a.id, db=db_session, provider="github",
            correlation_type="github_automation_permission_activity")
        assert total == 1
        assert all(c.correlation_type == "github_automation_permission_activity" for c in items)
        assert len(_corrs(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id); _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── admin gating; member cannot generate ─────────────────────────────────────

def test_generate_requires_admin_role(test_user, db_session):
    owner = _new_user(db_session, "owner")
    ws = _ws(owner, db_session)
    _add_member(db_session, ws.id, test_user.id, "member")
    try:
        with pytest.raises(HTTPException) as exc:
            workspace_permission_service.require_workspace_admin(ws.id, test_user.id, db_session)
        assert exc.value.status_code == 403
    finally:
        try:
            db_session.delete(owner); db_session.commit()
        except Exception:
            db_session.rollback()


def test_owner_can_generate_via_endpoint(client, test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _ruleset_finding(db_session, ws, integ, res)
    _audit_event(db_session, ws.id, integ.id, "github.ruleset.changed")
    try:
        resp = client.post("/security/correlations/generate", json={"provider": "github"})
        assert resp.status_code == 200
        assert resp.json()["correlations_created"] >= 1
        assert len(_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── privacy: no token / header / secret / private key / raw paths ────────────

def test_no_sensitive_data_in_metadata(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _ruleset_finding(db_session, ws, integ, res)        # evidence has token + actor login decoys
    _automation_finding(db_session, ws, integ, res)     # evidence has authorization + private_key decoys
    _alert_event(db_session, ws.id, integ.id, source="secret_scanning_alert",
                 event_type="github.secret_scanning.alert.open",
                 metadata={"secret_type": "github_pat"})
    _audit_event(db_session, ws.id, integ.id, "github.deploy_key.added")
    try:
        _gen(db_session, ws.id)
        for c in _corrs(db_session, ws.id):
            blob = json.dumps({"t": c.title, "s": c.summary, "m": c.correlation_metadata},
                              default=str)
            assert "ghp_RAWTOKEN" not in blob
            assert "ghp_RAWSECRET" not in blob
            assert "Bearer" not in blob
            assert "BEGIN" not in blob
            assert "package-lock.json" not in blob
            assert "token=" not in blob
            md = c.correlation_metadata
            for bad in ("token", "authorization", "private_key", "bypass_actor_login",
                        "secret", "html_url", "manifest_path", "broad_scope_names"):
                assert bad not in md
    finally:
        _cleanup(db_session, ws.id)


# ── claim discipline ─────────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _repo(db_session, integ, test_user)
    _ruleset_finding(db_session, ws, integ, res)
    _automation_finding(db_session, ws, integ, res)
    _audit_event(db_session, ws.id, integ.id, "github.ruleset.changed")
    _audit_event(db_session, ws.id, integ.id, "github.deploy_key.added")
    _alert_event(db_session, ws.id, integ.id, source="dependabot_alert",
                 event_type="github.dependabot.alert.open",
                 metadata={"advisory_severity": "high", "dependency_package_name": "lodash"})
    try:
        _gen(db_session, ws.id)
        corrs = _corrs(db_session, ws.id)
        assert len(corrs) >= 3
        for c in corrs:
            blob = json.dumps({"t": c.title, "s": c.summary, "m": c.correlation_metadata},
                              default=str).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "does not confirm" in c.summary.lower()
    finally:
        _cleanup(db_session, ws.id)
