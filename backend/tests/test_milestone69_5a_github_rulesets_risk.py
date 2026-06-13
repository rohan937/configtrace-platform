"""M69.5A — GitHub Rulesets configuration-risk coverage.

GitHub rulesets (modern branch protection) are fetched by the connector into
``github_ruleset`` snapshot records (safe aggregate fields only) and evaluated by
the GitHub risk rules into SEPARATE, clearly-named findings that never collide
with the legacy branch-protection findings.

These tests cover:
  * the rule logic for each ruleset finding (not-enforced / force-push / PR-review
    / status-checks / bypass-actors / weak-target),
  * connector fail-soft on 403/404 and safe (counts-only) normalization,
  * end-to-end persistence + idempotency via the evaluator,
  * legacy branch-protection findings still work alongside rulesets,
  * privacy (no raw actor identities / API response / tokens / secrets),
  * claim discipline (no forbidden breach/attacker/compromise wording).
"""

from __future__ import annotations

import json
import uuid

from sqlalchemy.orm import Session

from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.connectors.github import GitHubConnector
from app.connectors.github_schema import (
    GITHUB_BRANCH_PROTECTION,
    GITHUB_RULESET,
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
]
SLUG = "acme/widgets"


# ── record builders ───────────────────────────────────────────────────────────

def _ruleset(
    *, rid="7", name="Protect main", target="branch", enforcement="active",
    targets_protected_branch=True, restrict_force_pushes=True,
    required_pr_reviews_required=True, required_status_checks_count=1,
    bypass_actor_count=0,
):
    return {
        "record_id": f"{SLUG}#ruleset#{rid}",
        "record_type": GITHUB_RULESET,
        "name": name,
        "ruleset_id": rid,
        "target": target,
        "enforcement": enforcement,
        "branch_patterns_count": 1,
        "targets_protected_branch": targets_protected_branch,
        "bypass_actor_count": bypass_actor_count,
        "required_status_checks_count": required_status_checks_count,
        "restrict_force_pushes": restrict_force_pushes,
        "restrict_deletions": True,
        "required_pr_reviews_required": required_pr_reviews_required,
        "require_signed_commits": False,
        "requires_linear_history": False,
        "requires_code_scanning": False,
    }


def _rule_keys(cands):
    return {c.rule_key for c in cands}


# ── 1. ruleset not enforced ─────────────────────────────────────────────────

def test_ruleset_not_enforced_creates_finding():
    cands = github_rules.evaluate(_ruleset(enforcement="disabled"))
    keys = _rule_keys(cands)
    assert "github_ruleset_not_enforced" in keys
    # Non-enforced → ONLY the not-enforced finding (weakening sub-rules are moot).
    assert keys == {"github_ruleset_not_enforced"}
    f = cands[0]
    assert f.severity == "high"  # targets a protected branch
    assert f.evidence["enforcement"] == "disabled"
    # 'evaluate' enforcement is also not active.
    assert "github_ruleset_not_enforced" in _rule_keys(
        github_rules.evaluate(_ruleset(enforcement="evaluate", targets_protected_branch=False))
    )


# ── 2. ruleset allows force pushes ───────────────────────────────────────────

def test_ruleset_force_push_allowed_creates_finding():
    cands = github_rules.evaluate(_ruleset(restrict_force_pushes=False))
    keys = _rule_keys(cands)
    assert "github_ruleset_force_push_allowed" in keys
    fp = [c for c in cands if c.rule_key == "github_ruleset_force_push_allowed"][0]
    assert fp.severity == "high"
    assert fp.evidence["force_pushes_allowed"] is True


# ── 3. ruleset missing PR review ─────────────────────────────────────────────

def test_ruleset_pr_review_missing_creates_finding():
    cands = github_rules.evaluate(_ruleset(required_pr_reviews_required=False))
    assert "github_ruleset_pr_review_missing" in _rule_keys(cands)


# ── 4. ruleset missing status checks ─────────────────────────────────────────

def test_ruleset_status_checks_missing_creates_finding():
    cands = github_rules.evaluate(_ruleset(required_status_checks_count=0))
    assert "github_ruleset_status_checks_missing" in _rule_keys(cands)


# ── 5. bypass actors present (counts only) ───────────────────────────────────

def test_ruleset_bypass_actors_present_counts_only():
    cands = github_rules.evaluate(_ruleset(bypass_actor_count=3))
    by = [c for c in cands if c.rule_key == "github_ruleset_bypass_actors_present"]
    assert len(by) == 1
    assert by[0].severity == "medium"
    assert by[0].evidence["bypass_actor_count"] == 3
    # No raw actor identities anywhere in the candidate.
    blob = json.dumps({"e": by[0].evidence, "d": by[0].description}, default=str)
    for bad in ("actor_id", "actor_type", "login", "team", "slug"):
        assert bad not in blob.lower()


# ── 6. weak target coverage ──────────────────────────────────────────────────

def test_ruleset_weak_target_coverage_creates_finding():
    cands = github_rules.evaluate(_ruleset(targets_protected_branch=False))
    keys = _rule_keys(cands)
    assert "github_ruleset_weak_target_coverage" in keys
    # When the branch target is not protected, PR-review/status-checks rules
    # (which require a protected target) must NOT fire.
    assert "github_ruleset_pr_review_missing" not in keys
    assert "github_ruleset_status_checks_missing" not in keys


# ── 7. a healthy, fully-protective ruleset produces no findings ──────────────

def test_healthy_ruleset_produces_no_findings():
    assert github_rules.evaluate(_ruleset()) == []


# ── 8. malformed / partial ruleset record is ignored ─────────────────────────

def test_malformed_ruleset_ignored():
    assert github_rules.evaluate({"record_type": GITHUB_RULESET, "name": "x"}) == []
    assert github_rules.evaluate({"record_type": GITHUB_RULESET}) == []


# ── 9. tag rulesets skip branch-only rules ───────────────────────────────────

def test_tag_ruleset_skips_branch_rules():
    cands = github_rules.evaluate(_ruleset(target="tag", restrict_force_pushes=False,
                                           required_pr_reviews_required=False,
                                           required_status_checks_count=0))
    keys = _rule_keys(cands)
    assert "github_ruleset_force_push_allowed" not in keys
    assert "github_ruleset_pr_review_missing" not in keys
    assert "github_ruleset_weak_target_coverage" not in keys


# ── 10. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording():
    samples = [
        _ruleset(enforcement="disabled"),
        _ruleset(restrict_force_pushes=False),
        _ruleset(required_pr_reviews_required=False),
        _ruleset(required_status_checks_count=0),
        _ruleset(bypass_actor_count=2),
        _ruleset(targets_protected_branch=False),
    ]
    for rec in samples:
        for c in github_rules.evaluate(rec):
            blob = json.dumps(
                {"t": c.title, "d": c.description, "e": c.evidence,
                 "r": c.remediation}, default=str,
            ).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "does not confirm" in c.description.lower()


# ── 11. connector fails soft on 403 / 404 ────────────────────────────────────

class _Resp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_connector_rulesets_fail_soft_403(monkeypatch):
    def _fake_get(self, client, url, headers, params=None, *, allow_404=False):
        raise AuthenticationError("denied", status_code=403)
    monkeypatch.setattr(GitHubConnector, "_get", _fake_get)
    out = GitHubConnector()._fetch_rulesets(None, {}, "acme", "widgets", SLUG)
    assert out == []


def test_connector_rulesets_fail_soft_404(monkeypatch):
    def _fake_get(self, client, url, headers, params=None, *, allow_404=False):
        return _Resp(404, {})
    monkeypatch.setattr(GitHubConnector, "_get", _fake_get)
    out = GitHubConnector()._fetch_rulesets(None, {}, "acme", "widgets", SLUG)
    assert out == []


def test_connector_rulesets_fail_soft_connector_error(monkeypatch):
    def _fake_get(self, client, url, headers, params=None, *, allow_404=False):
        raise ConnectorError("boom", status_code=500)
    monkeypatch.setattr(GitHubConnector, "_get", _fake_get)
    out = GitHubConnector()._fetch_rulesets(None, {}, "acme", "widgets", SLUG)
    assert out == []


# ── 12. connector normalizes to safe aggregate fields (counts only) ──────────

def test_connector_rulesets_normalization_counts_only(monkeypatch):
    list_payload = [{"id": 7, "name": "Protect main", "target": "branch",
                     "enforcement": "active"}]
    detail_payload = {
        "id": 7,
        "name": "Protect main",
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "rules": [
            {"type": "pull_request"},
            {"type": "required_status_checks",
             "parameters": {"required_status_checks": [{"context": "ci"}, {"context": "lint"}]}},
            {"type": "non_fast_forward"},
            {"type": "deletion"},
        ],
        # Raw actor identities — MUST be reduced to a count, never stored.
        "bypass_actors": [
            {"actor_id": 111, "actor_type": "Team", "bypass_mode": "always"},
            {"actor_id": 222, "actor_type": "Integration", "bypass_mode": "pull_request"},
        ],
    }

    def _fake_get(self, client, url, headers, params=None, *, allow_404=False):
        if url.rstrip("/").endswith("/rulesets"):
            return _Resp(200, list_payload)
        return _Resp(200, detail_payload)  # detail endpoint

    monkeypatch.setattr(GitHubConnector, "_get", _fake_get)
    out = GitHubConnector()._fetch_rulesets(None, {}, "acme", "widgets", SLUG)
    assert len(out) == 1
    rec = out[0]
    assert rec["record_type"] == GITHUB_RULESET
    assert rec["record_id"] == f"{SLUG}#ruleset#7"
    assert rec["enforcement"] == "active"
    assert rec["target"] == "branch"
    assert rec["targets_protected_branch"] is True
    assert rec["bypass_actor_count"] == 2
    assert rec["required_status_checks_count"] == 2
    assert rec["required_pr_reviews_required"] is True
    assert rec["restrict_force_pushes"] is True   # non_fast_forward present
    assert rec["restrict_deletions"] is True
    # Privacy: no raw actor identities / globs / API containers anywhere.
    blob = json.dumps(rec, default=str)
    for bad in ("actor_id", "actor_type", "bypass_mode", "111", "222",
                "Integration", "conditions", "ref_name", "refs/heads",
                "bypass_actors", "parameters"):
        assert bad not in blob
    assert "Team" not in blob


# ── 13. end-to-end: findings persist + idempotent + legacy BP coexists ───────

def _make_workspace(user, db):
    from app.services import workspace_service
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.5A", db=db)


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


def test_end_to_end_persist_idempotent_and_legacy_coexists(test_user, db_session):
    ws = _make_workspace(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id)
    res = _make_resource(db_session, integ, test_user)

    # A disabled ruleset (→ not_enforced) PLUS a legacy branch-protection record
    # that is missing protection (→ github_branch_protection_missing).
    legacy_bp = {
        "record_id": f"{SLUG}#branch_protection#main",
        "record_type": GITHUB_BRANCH_PROTECTION,
        "name": "main branch",
        "branch": "main",
        "protection_enabled": False,
    }
    state = [_ruleset(enforcement="disabled"), legacy_bp]
    snap = _make_snapshot(db_session, res, integ, test_user, state)
    try:
        s1 = evaluator.evaluate_security_findings_for_resource(
            db=db_session, workspace_id=ws.id, integration=integ,
            resource=res, snapshot=snap, linked_changes=[],
        )
        keys1 = {f.finding_key.split(":", 1)[0] for f in _active(db_session, ws.id, res.id)}
        # Both the ruleset finding AND the legacy branch-protection finding exist.
        assert "github_ruleset_not_enforced" in keys1
        assert "github_branch_protection_missing" in keys1
        n1 = len(_active(db_session, ws.id, res.id))

        # Re-running the evaluation must NOT create duplicate findings.
        evaluator.evaluate_security_findings_for_resource(
            db=db_session, workspace_id=ws.id, integration=integ,
            resource=res, snapshot=snap, linked_changes=[],
        )
        assert len(_active(db_session, ws.id, res.id)) == n1
    finally:
        _cleanup(db_session, ws.id)
