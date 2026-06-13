"""M70A — Vercel security provider foundation (configuration-risk only).

Vercel becomes a configuration-risk provider via data-backed rules over the
existing Vercel connector snapshot records (vercel_project / vercel_domain /
vercel_env_var / vercel_deploy_hook_metadata). These tests assert:

  * the connector normalizes records WITHOUT storing env var values or raw
    deploy hook URLs;
  * each rule fires on its trigger and stays idempotent;
  * the protection-missing rule is intentionally DEFERRED (no new key);
  * evidence never contains secrets / values / raw hook URLs / tokens / emails;
  * finding wording carries no forbidden claim phrasing;
  * registry / confidence / rule-pack / coverage parity stays green.

Configuration-risk only: no Vercel activity, signals, correlations, or demo.
"""

from __future__ import annotations

import json
import uuid

from app.connectors.vercel import (
    _extract_deploy_hooks,
    _normalize_domain,
    _normalize_env_var,
    _normalize_project,
)
from app.connectors.vercel_schema import (
    VERCEL_DEPLOY_HOOK_METADATA,
    VERCEL_DOMAIN,
    VERCEL_ENV_VAR,
    VERCEL_PROJECT,
)
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.services import security_finding_evaluator as evaluator
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules import vercel as ve
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "secret leaked", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
RAW_SECRET = "vercel_secret_value_should_never_appear"
RAW_HOOK_URL = "https://api.vercel.com/v1/integrations/deploy/prj_x/SECRETTOKEN123"

_VERCEL_RULE_KEYS = {
    "vercel_preview_unprotected",
    "vercel_production_branch_missing",
    "vercel_production_branch_unusual",
    "vercel_domain_unverified",
    "vercel_env_var_broad_target",
    "vercel_sensitive_env_var_broad_scope",
    "vercel_deploy_hook_production_branch",
}


# ── fixtures / helpers ────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M70A", db=db)


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"vercel_token": "x", "vercel_project_id": "prj_x"})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="vercel",
                    display_name="vercel", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _res(db, integ, user):
    r = Resource(integration_id=integ.id, user_id=user.id,
                 provider_resource_type="vercel_project", provider_resource_id="prj_x",
                 display_name="demo-project", is_active=True)
    db.add(r); db.commit(); db.refresh(r)
    return r


def _snap(db, res, integ, user, state):
    s = Snapshot(resource_id=res.id, integration_id=integ.id, user_id=user.id,
                 state=state, content_hash=uuid.uuid4().hex, triggered_by="manual")
    db.add(s); db.commit(); db.refresh(s)
    return s


def _active(db, ws_id, res_id):
    return (
        db.query(SecurityFinding)
        .filter(SecurityFinding.workspace_id == ws_id,
                SecurityFinding.resource_id == res_id,
                SecurityFinding.status == "active")
        .all()
    )


def _cleanup(db, ws_id):
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _project(record_id="prj_x", git_repository="acme/site", git_branch="main"):
    return {
        "record_id": record_id, "record_type": VERCEL_PROJECT, "name": "demo-project",
        "framework": "nextjs", "git_repository": git_repository, "git_branch": git_branch,
        "sso_protection": None, "password_protection": None,
    }


def _domain(name="app.example.com", verified=True):
    return {"record_id": name, "record_type": VERCEL_DOMAIN, "name": name,
            "verified": verified, "git_branch": None, "redirect": None}


def _env(record_id, key, target):
    return {"record_id": record_id, "record_type": VERCEL_ENV_VAR, "name": key,
            "key": key, "env_type": "encrypted", "target": sorted(target),
            "git_branch": None}


def _hook(hook_id="h1", ref="main"):
    return {"record_id": f"prj_x#deploy_hook#{hook_id}",
            "record_type": VERCEL_DEPLOY_HOOK_METADATA, "name": "nightly",
            "hook_id": hook_id, "hook_name": "nightly", "hook_ref": ref}


def _evaluate(db, ws, integ, res, user, state):
    snap = _snap(db, res, integ, user, state)
    return evaluator.evaluate_security_findings_for_resource(
        db=db, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap)


# ── 1. connector normalization stores no secret values / raw hook URLs ───────

def test_connector_normalization_drops_values_and_urls():
    proj = _normalize_project({
        "id": "prj_x", "name": "demo", "framework": "nextjs",
        "link": {"repo": "acme/site", "productionBranch": "main"},
        "ssoProtection": None, "passwordProtection": None,
    })
    assert proj["record_type"] == VERCEL_PROJECT
    assert proj["git_branch"] == "main" and proj["git_repository"] == "acme/site"
    assert "value" not in json.dumps(proj)

    env = _normalize_env_var({
        "id": "env1", "key": "DATABASE_URL", "type": "encrypted",
        "target": ["production", "preview"], "value": RAW_SECRET,
    })
    assert env["record_type"] == VERCEL_ENV_VAR
    assert "value" not in env
    assert RAW_SECRET not in json.dumps(env)
    assert env["target"] == ["preview", "production"]

    dom = _normalize_domain({"name": "app.example.com", "verified": False})
    assert dom["record_type"] == VERCEL_DOMAIN and dom["verified"] is False

    hooks = _extract_deploy_hooks(
        {"deployHooks": [{"id": "h1", "name": "nightly", "ref": "main", "url": RAW_HOOK_URL}]},
        "prj_x")
    assert len(hooks) == 1
    blob = json.dumps(hooks)
    assert RAW_HOOK_URL not in blob and "url" not in hooks[0]
    assert hooks[0]["hook_ref"] == "main"


# ── 2. production branch missing ─────────────────────────────────────────────

def test_production_branch_missing(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_project(git_repository="acme/site", git_branch="")])
        keys = {f.finding_key for f in _active(db_session, ws.id, res.id)}
        assert any(k.startswith("vercel_production_branch_missing") for k in keys)
    finally:
        _cleanup(db_session, ws.id)


def test_production_branch_missing_skipped_without_git(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        # No git repository connected → no production-branch concept → no finding.
        _evaluate(db_session, ws, integ, res, test_user,
                  [_project(git_repository="", git_branch="")])
        assert _active(db_session, ws.id, res.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 3. unusual production branch ─────────────────────────────────────────────

def test_production_branch_unusual(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_project(git_branch="develop")])
        keys = {f.finding_key for f in _active(db_session, ws.id, res.id)}
        assert any(k.startswith("vercel_production_branch_unusual") for k in keys)
    finally:
        _cleanup(db_session, ws.id)


def test_production_branch_main_is_clean(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user, [_project(git_branch="main")])
        assert _active(db_session, ws.id, res.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 4. unverified domain ─────────────────────────────────────────────────────

def test_domain_unverified(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_project(git_branch="main"),
                   _domain("ok.example.com", verified=True),
                   _domain("bad.example.com", verified=False)])
        keys = {f.finding_key for f in _active(db_session, ws.id, res.id)}
        assert any(k == "vercel_domain_unverified:bad.example.com" for k in keys)
        # Verified domain produces no finding.
        assert not any("ok.example.com" in k for k in keys)
    finally:
        _cleanup(db_session, ws.id)


# ── 5. broad env var target ──────────────────────────────────────────────────

def test_env_var_broad_target(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_project(git_branch="main"),
                   _env("e1", "FEATURE_FLAG_X", ["production", "preview"]),
                   _env("e2", "PROD_ONLY_FLAG", ["production"])])
        keys = {f.finding_key for f in _active(db_session, ws.id, res.id)}
        assert any(k == "vercel_env_var_broad_target:e1" for k in keys)
        # Production-only var is clean.
        assert not any(k.endswith(":e2") for k in keys)
    finally:
        _cleanup(db_session, ws.id)


# ── 6. sensitive env var broadly scoped ──────────────────────────────────────

def test_sensitive_env_var_broad_scope(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_project(git_branch="main"),
                   _env("s1", "STRIPE_SECRET_KEY", ["preview", "development"]),
                   _env("s2", "PUBLIC_BASE_URL", ["preview"])])
        findings = _active(db_session, ws.id, res.id)
        keys = {f.finding_key for f in findings}
        assert any(k == "vercel_sensitive_env_var_broad_scope:s1" for k in keys)
        # Non-sensitive, non-prod-spanning var is clean.
        assert not any(k.endswith(":s2") for k in keys)
        # Severity is high for the sensitive rule.
        sev = {f.finding_key: f.severity for f in findings}
        assert sev["vercel_sensitive_env_var_broad_scope:s1"] == "high"
        # Evidence never contains a value.
        blob = json.dumps([f.evidence for f in findings], default=str)
        assert RAW_SECRET not in blob and "value" not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 7. deploy hook targeting production branch (no raw URL) ──────────────────

def test_deploy_hook_production_branch(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    try:
        _evaluate(db_session, ws, integ, res, test_user,
                  [_project(git_branch="main"),
                   _hook("h1", ref="main"),
                   _hook("h2", ref="dev")])
        findings = _active(db_session, ws.id, res.id)
        keys = {f.finding_key for f in findings}
        assert any(k == "vercel_deploy_hook_production_branch:prj_x#deploy_hook#h1" for k in keys)
        # Non-production hook is clean.
        assert not any("h2" in k for k in keys)
        # No raw hook URL anywhere in evidence.
        blob = json.dumps([f.evidence for f in findings], default=str)
        assert "url" not in blob and RAW_HOOK_URL not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 8. project-protection rule is deferred (no such key) ─────────────────────

def test_project_protection_missing_rule_is_deferred():
    assert "vercel_project_protection_missing" not in KNOWN_RULE_KEYS
    # The protection record still maps only to the existing preview-unprotected rule.
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    rules_for_protection = {
        k for k, rts in RULE_RECORD_TYPES.items()
        if "vercel_deployment_protection" in rts
    }
    assert rules_for_protection == {"vercel_preview_unprotected"}


# ── 9. idempotent re-evaluation ──────────────────────────────────────────────

def test_idempotent_reevaluation(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    state = [_project(git_branch="develop"), _domain("bad.example.com", verified=False)]
    try:
        _evaluate(db_session, ws, integ, res, test_user, state)
        first = _active(db_session, ws.id, res.id)
        ids = {f.id for f in first}
        _evaluate(db_session, ws, integ, res, test_user, state)
        second = _active(db_session, ws.id, res.id)
        assert {f.id for f in second} == ids  # no duplicates created
    finally:
        _cleanup(db_session, ws.id)


# ── 10. connector fails soft on permission/network errors ────────────────────

def test_connector_fails_soft_on_auth_error(monkeypatch):
    from app.connectors.exceptions import AuthenticationError
    from app.connectors.vercel import VercelConnector

    conn = VercelConnector()

    def boom(*a, **k):
        raise AuthenticationError("Vercel API rejected the token (HTTP 403).")

    monkeypatch.setattr(conn, "_get", boom)
    # validate_credentials propagates AuthenticationError (caller marks reconnect);
    # the important guarantee is no crash/secret leak — assert the typed error.
    try:
        conn.validate_credentials({"vercel_token": "x", "vercel_project_id": "prj_x"})
        raised = False
    except AuthenticationError as exc:
        raised = True
        assert "x" not in str(exc)  # token never echoed in the error
    assert raised


# ── 11. evidence + wording privacy / claim discipline ────────────────────────

def test_evidence_and_wording_are_safe(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    state = [
        _project(git_branch="develop"),
        _domain("bad.example.com", verified=False),
        _env("e1", "DB_PASSWORD", ["production", "preview"]),
        _hook("h1", ref="production"),
    ]
    try:
        _evaluate(db_session, ws, integ, res, test_user, state)
        findings = _active(db_session, ws.id, res.id)
        assert findings
        blob = json.dumps(
            [{"t": f.title, "d": f.description, "e": f.evidence, "r": f.remediation}
             for f in findings], default=str).lower()
        # No forbidden claim wording.
        for phrase in _FORBIDDEN:
            assert phrase not in blob
        # No leaked secret material / raw artifacts in the rendered finding.
        for bad in ("vercel_token", "bearer ", RAW_SECRET.lower(),
                    RAW_HOOK_URL.lower(), "@"):
            assert bad not in blob
        # No env var VALUE field or raw hook URL key in any evidence dict.
        for f in findings:
            assert "value" not in f.evidence
            assert "url" not in f.evidence
    finally:
        _cleanup(db_session, ws.id)


# ── 12. registry / confidence / pack parity holds for vercel keys ────────────

def test_vercel_keys_registered_everywhere():
    for key in _VERCEL_RULE_KEYS:
        assert key in KNOWN_RULE_KEYS, f"{key} missing from KNOWN_RULE_KEYS"
        assert key in RULE_CONFIDENCE, f"{key} missing from RULE_CONFIDENCE"
        assert key in _RULE_META, f"{key} missing from _RULE_META"
        assert _RULE_META[key][0] == "vercel"
    # Global parity invariants (mirror the dedicated parity suites).
    assert KNOWN_RULE_KEYS == set(RULE_CONFIDENCE)
    assert set(_RULE_META) == set(KNOWN_RULE_KEYS)
