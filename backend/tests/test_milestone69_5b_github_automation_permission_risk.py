"""M69.5B — GitHub App / token permission risk coverage.

Surfaces broad automation blast radius from SAFE metadata only: the authenticated
credential's repository permission level (from ``GET /repos`` ``permissions``),
classic-PAT OAuth scope NAMES (from the ``X-OAuth-Scopes`` header), and the
presence of a webhook signing secret. The connector stores no token, headers, or
secret values; the rules read only counts / booleans / scope-name strings.

Covers: admin / write / broad-scope / webhook-secret rules; connector
normalization + fail-soft; deploy-key rule unchanged and not duplicated;
idempotency; privacy (no token/header/secret/private-key/email/raw payload);
claim discipline.
"""

from __future__ import annotations

import json
import uuid

from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.connectors.github import GitHubConnector
from app.connectors.github_schema import (
    GITHUB_AUTOMATION_PERMISSIONS,
    GITHUB_DEPLOY_KEY,
    GITHUB_WEBHOOK,
)
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.models.user import User
from app.services import security_finding_evaluator as evaluator
from app.services.security_rules import github as github_rules

_FORBIDDEN = [
    "compromise confirmed", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
    "token leaked",
]
SLUG = "acme/widgets"


# ── record builders ───────────────────────────────────────────────────────────

def _perms(
    *, admin=False, maintain=False, push=False, triage=True, pull=True,
    permissions_present=True, credential_type="github_token",
    token_scope_names=None, token_broad_scopes=False, broad_scope_names=None,
):
    broad_perm_count = sum(1 for v in (admin, maintain, push) if v)
    names = token_scope_names or []
    return {
        "record_id": f"{SLUG}#automation_permissions",
        "record_type": GITHUB_AUTOMATION_PERMISSIONS,
        "name": SLUG,
        "credential_type": credential_type,
        "permissions_present": permissions_present,
        "repository_permission_admin": admin,
        "repository_permission_maintain": maintain,
        "repository_permission_push": push,
        "repository_permission_triage": triage,
        "repository_permission_pull": pull,
        "broad_permission_count": broad_perm_count,
        "token_scope_names": names,
        "token_scope_count": len(names),
        "token_broad_scopes": token_broad_scopes,
        "broad_scope_names": broad_scope_names or [],
    }


def _keys(cands):
    return {c.rule_key for c in cands}


# ── 1. admin permission ───────────────────────────────────────────────────────

def test_admin_permission_creates_finding():
    cands = github_rules.evaluate(_perms(admin=True, push=True))
    assert "github_automation_admin_permission" in _keys(cands)
    a = [c for c in cands if c.rule_key == "github_automation_admin_permission"][0]
    assert a.severity == "high"
    assert a.evidence["repository_permission_admin"] is True
    # admin supersedes write — the write rule must NOT also fire.
    assert "github_automation_write_permission" not in _keys(cands)


# ── 2. write/push permission ──────────────────────────────────────────────────

def test_write_permission_creates_finding():
    cands = github_rules.evaluate(_perms(push=True))
    assert "github_automation_write_permission" in _keys(cands)
    w = [c for c in cands if c.rule_key == "github_automation_write_permission"][0]
    assert w.severity == "medium"
    assert w.evidence["repository_permission_push"] is True


def test_maintain_permission_creates_write_finding():
    cands = github_rules.evaluate(_perms(maintain=True))
    assert "github_automation_write_permission" in _keys(cands)


# ── 3. broad token scopes ─────────────────────────────────────────────────────

def test_broad_token_scopes_creates_finding():
    cands = github_rules.evaluate(_perms(
        pull=True, permissions_present=True,
        token_scope_names=["repo", "workflow", "read:org"],
        token_broad_scopes=True, broad_scope_names=["repo", "workflow"],
    ))
    assert "github_token_broad_scopes" in _keys(cands)
    c = [x for x in cands if x.rule_key == "github_token_broad_scopes"][0]
    assert c.severity == "high"
    assert c.evidence["broad_scope_names"] == ["repo", "workflow"]
    assert c.evidence["token_scope_count"] == 3


# ── 4. read-only credential with no broad scopes → no finding ─────────────────

def test_read_only_no_findings():
    assert github_rules.evaluate(_perms(pull=True, triage=True)) == []


# ── 5. permission metadata absent → fail soft (no finding) ────────────────────

def test_permissions_absent_fails_soft():
    rec = _perms(admin=True, push=True, permissions_present=False)
    # With no permissions object observed, A/B do not fire.
    keys = _keys(github_rules.evaluate(rec))
    assert "github_automation_admin_permission" not in keys
    assert "github_automation_write_permission" not in keys


# ── 6. webhook secret missing ─────────────────────────────────────────────────

def _webhook(*, url="https://hooks.example.com/gh", active=True, secret_configured):
    return {
        "record_id": f"{SLUG}#webhook#1",
        "record_type": GITHUB_WEBHOOK,
        "name": "hook #1",
        "hook_id": 1,
        "url": url,
        "active": active,
        "events": ["push"],
        "content_type": "json",
        "webhook_secret_configured": secret_configured,
    }


def test_webhook_secret_missing_creates_finding():
    cands = github_rules.evaluate(_webhook(secret_configured=False))
    assert "github_webhook_secret_missing" in _keys(cands)
    s = [c for c in cands if c.rule_key == "github_webhook_secret_missing"][0]
    assert s.severity == "high"
    # Only the presence boolean is stored — never a secret value.
    assert s.evidence.get("webhook_secret_configured") is False
    assert set(s.evidence.keys()) == {"rule", "webhook_secret_configured"}


def test_webhook_with_secret_no_finding():
    cands = github_rules.evaluate(_webhook(secret_configured=True))
    assert "github_webhook_secret_missing" not in _keys(cands)


def test_webhook_http_and_secret_missing_both_fire():
    cands = github_rules.evaluate(_webhook(url="http://hooks.example.com/gh", secret_configured=False))
    keys = _keys(cands)
    assert "github_webhook_http" in keys
    assert "github_webhook_secret_missing" in keys


def test_webhook_secret_field_absent_is_ignored():
    # Old/partial record without the boolean → no secret finding (fail soft).
    rec = _webhook(secret_configured=True)
    del rec["webhook_secret_configured"]
    assert "github_webhook_secret_missing" not in _keys(github_rules.evaluate(rec))


# ── 7. existing deploy-key write rule unchanged + not duplicated ──────────────

def test_deploy_key_write_rule_unchanged():
    rec = {
        "record_id": f"{SLUG}#deploy_key#9",
        "record_type": GITHUB_DEPLOY_KEY,
        "name": "ci key",
        "key_id": 9,
        "title": "ci key",
        "read_only": False,
        "verified": True,
    }
    cands = github_rules.evaluate(rec)
    assert _keys(cands) == {"github_deploy_key_write_access"}
    assert len(cands) == 1  # not duplicated


# ── 8. claim discipline ───────────────────────────────────────────────────────

def test_no_forbidden_wording():
    samples = [
        _perms(admin=True),
        _perms(push=True),
        _perms(token_scope_names=["repo"], token_broad_scopes=True, broad_scope_names=["repo"]),
        _webhook(secret_configured=False),
    ]
    for rec in samples:
        for c in github_rules.evaluate(rec):
            blob = json.dumps(
                {"t": c.title, "d": c.description, "e": c.evidence, "r": c.remediation},
                default=str,
            ).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "does not confirm" in c.description.lower()


# ── 9. connector: normalization (safe aggregate, no token/headers/secret) ─────

class _Resp:
    def __init__(self, status_code, payload, headers=None):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def json(self):
        return self._payload


def test_connector_automation_permissions_normalization(monkeypatch):
    payload = {
        "permissions": {"admin": True, "maintain": False, "push": True,
                        "triage": True, "pull": True},
        # Decoy sensitive-looking fields that must never be persisted.
        "owner": {"login": "octocat", "email": "octocat@secret.example"},
    }
    headers = {"X-OAuth-Scopes": "repo, workflow, read:org",
               "Authorization": "Bearer ghp_RAWTOKEN"}

    def _fake_get(self, client, url, headers_, params=None, *, allow_404=False):
        return _Resp(200, payload, headers)

    monkeypatch.setattr(GitHubConnector, "_get", _fake_get)
    out = GitHubConnector()._fetch_automation_permissions(
        None, {}, "acme", "widgets", SLUG, credential_type="github_token")
    assert len(out) == 1
    rec = out[0]
    assert rec["record_type"] == GITHUB_AUTOMATION_PERMISSIONS
    assert rec["record_id"] == f"{SLUG}#automation_permissions"
    assert rec["repository_permission_admin"] is True
    assert rec["repository_permission_push"] is True
    assert rec["broad_permission_count"] == 2
    assert rec["token_scope_names"] == ["read:org", "repo", "workflow"]
    assert rec["token_scope_count"] == 3
    assert rec["token_broad_scopes"] is True
    assert rec["broad_scope_names"] == ["repo", "workflow"]
    assert rec["permissions_present"] is True
    # Privacy: no token value, Authorization/raw header, or owner email/login.
    # (The decoy owner object and headers from the API response must be dropped.)
    blob = json.dumps(rec, default=str)
    for bad in ("ghp_RAWTOKEN", "Bearer", "Authorization", "X-OAuth-Scopes",
                "octocat", "secret.example", "email"):
        assert bad not in blob


def test_connector_automation_permissions_no_scope_header(monkeypatch):
    # GitHub App / fine-grained tokens expose no X-OAuth-Scopes header.
    def _fake_get(self, client, url, headers_, params=None, *, allow_404=False):
        return _Resp(200, {"permissions": {"pull": True}}, {})
    monkeypatch.setattr(GitHubConnector, "_get", _fake_get)
    rec = GitHubConnector()._fetch_automation_permissions(
        None, {}, "acme", "widgets", SLUG, credential_type="github_app")[0]
    assert rec["token_broad_scopes"] is False
    assert rec["token_scope_names"] == []
    assert rec["broad_permission_count"] == 0


# ── 10. connector fail-soft on 403 / 404 ─────────────────────────────────────

def test_connector_automation_permissions_fail_soft_403(monkeypatch):
    def _fake_get(self, client, url, headers_, params=None, *, allow_404=False):
        raise AuthenticationError("denied", status_code=403)
    monkeypatch.setattr(GitHubConnector, "_get", _fake_get)
    assert GitHubConnector()._fetch_automation_permissions(
        None, {}, "acme", "widgets", SLUG, credential_type="github_token") == []


def test_connector_automation_permissions_fail_soft_404(monkeypatch):
    def _fake_get(self, client, url, headers_, params=None, *, allow_404=False):
        return _Resp(404, {})
    monkeypatch.setattr(GitHubConnector, "_get", _fake_get)
    assert GitHubConnector()._fetch_automation_permissions(
        None, {}, "acme", "widgets", SLUG, credential_type="github_token") == []


def test_connector_automation_permissions_fail_soft_connector_error(monkeypatch):
    def _fake_get(self, client, url, headers_, params=None, *, allow_404=False):
        raise ConnectorError("boom", status_code=500)
    monkeypatch.setattr(GitHubConnector, "_get", _fake_get)
    assert GitHubConnector()._fetch_automation_permissions(
        None, {}, "acme", "widgets", SLUG, credential_type="github_token") == []


# ── 11. end-to-end persist + idempotent + deploy-key coexists ─────────────────

def _make_workspace(user, db):
    from app.services import workspace_service
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.5B", db=db)


def _make_integration(db, user, ws_id):
    ct, iv = encrypt_credentials({"credential_type": "github_app"})
    integ = Integration(
        user_id=user.id, workspace_id=ws_id, provider="github",
        display_name="github", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(integ); db.commit(); db.refresh(integ)
    return integ


def _make_resource(db, integ, user):
    res = Resource(
        integration_id=integ.id, user_id=user.id,
        provider_resource_type="github_repo", provider_resource_id=SLUG,
        display_name=SLUG, is_active=True,
    )
    db.add(res); db.commit(); db.refresh(res)
    return res


def _make_snapshot(db, res, integ, user, state):
    snap = Snapshot(
        resource_id=res.id, integration_id=integ.id, user_id=user.id,
        state=state, content_hash=uuid.uuid4().hex, triggered_by="manual",
    )
    db.add(snap); db.commit(); db.refresh(snap)
    return snap


def _active(db, ws_id, res_id):
    return db.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == ws_id,
        SecurityFinding.resource_id == res_id,
        SecurityFinding.status == "active",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete()
    db.commit()


def test_end_to_end_persist_idempotent_and_deploy_key_coexists(test_user, db_session):
    ws = _make_workspace(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id)
    res = _make_resource(db_session, integ, test_user)

    deploy_key = {
        "record_id": f"{SLUG}#deploy_key#9",
        "record_type": GITHUB_DEPLOY_KEY,
        "name": "ci key", "key_id": 9, "title": "ci key",
        "read_only": False, "verified": True,
    }
    state = [_perms(admin=True, push=True), deploy_key]
    snap = _make_snapshot(db_session, res, integ, test_user, state)
    try:
        evaluator.evaluate_security_findings_for_resource(
            db=db_session, workspace_id=ws.id, integration=integ,
            resource=res, snapshot=snap, linked_changes=[],
        )
        keys = {f.finding_key.split(":", 1)[0] for f in _active(db_session, ws.id, res.id)}
        assert "github_automation_admin_permission" in keys
        assert "github_deploy_key_write_access" in keys
        n1 = len(_active(db_session, ws.id, res.id))

        evaluator.evaluate_security_findings_for_resource(
            db=db_session, workspace_id=ws.id, integration=integ,
            resource=res, snapshot=snap, linked_changes=[],
        )
        assert len(_active(db_session, ws.id, res.id)) == n1  # idempotent
    finally:
        _cleanup(db_session, ws.id)
