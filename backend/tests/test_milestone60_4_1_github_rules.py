"""M60.4.1 — expanded GitHub security exposure rules.

Unit tests for each new GitHub rule (risky fires / safe does not / malformed
ignored / evidence is metadata-only) plus integration tests through the
evaluator for lifecycle (dedupe + resolve) and multi-record findings.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy.orm import Session

from app.connectors.github_schema import (
    GITHUB_BRANCH_PROTECTION,
    GITHUB_DEPLOY_KEY,
    GITHUB_ENVIRONMENT_PROTECTION,
    GITHUB_WEBHOOK,
)
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.models.user import User
from app.services import security_finding_evaluator as evaluator
from app.services.security_rules import github as gh

_SECRET_RE = re.compile(
    r"secret|token|password|api_?key|access_?key|private_?key|client_secret", re.I
)


# ── record builders ──────────────────────────────────────────────────────────


def _bp_record(**over) -> dict:
    rec = {
        "record_id": "acme/widgets#branch_protection#main",
        "record_type": GITHUB_BRANCH_PROTECTION,
        "name": "main branch",
        "branch": "main",
        "protection_enabled": True,
        "required_status_checks_enabled": True,
        "required_pull_request_reviews_enabled": True,
        "required_approving_review_count": 1,
        "dismiss_stale_reviews": True,
        "enforce_admins": True,
        "required_linear_history": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
    }
    rec.update(over)
    return rec


def _deploy_key(**over) -> dict:
    rec = {
        "record_id": "acme/widgets#deploy_key#5",
        "record_type": GITHUB_DEPLOY_KEY,
        "name": "ci key",
        "key_id": 5,
        "title": "ci key",
        "read_only": True,
        "verified": True,
    }
    rec.update(over)
    return rec


def _env_record(**over) -> dict:
    rec = {
        "record_id": "acme/widgets#environment#production",
        "record_type": GITHUB_ENVIRONMENT_PROTECTION,
        "name": "production",
        "environment_name": "production",
        "wait_timer": 0,
        "reviewers_count": 0,
        "prevent_self_review": False,
        "protected_branches": None,
        "custom_branch_policies": None,
    }
    rec.update(over)
    return rec


def _assert_evidence_safe(cands):
    for c in cands:
        for k in c.evidence.keys():
            assert not _SECRET_RE.search(k), f"evidence key looks sensitive: {k}"


# ── Branch protection ────────────────────────────────────────────────────────


def test_branch_protection_missing_fires():
    out = gh.evaluate(_bp_record(protection_enabled=False))
    assert len(out) == 1
    assert out[0].rule_key == "github_branch_protection_missing"
    assert out[0].severity == "high"
    _assert_evidence_safe(out)


def test_full_protection_produces_no_finding():
    assert gh.evaluate(_bp_record()) == []


def test_missing_protection_does_not_also_emit_subrules():
    # When protection is off, only the single "missing" finding is emitted.
    out = gh.evaluate(_bp_record(protection_enabled=False))
    keys = {c.rule_key for c in out}
    assert keys == {"github_branch_protection_missing"}


def test_force_pushes_allowed_fires():
    out = gh.evaluate(_bp_record(allow_force_pushes=True))
    assert any(c.rule_key == "github_force_pushes_allowed" for c in out)
    _assert_evidence_safe(out)


def test_branch_deletion_allowed_fires():
    out = gh.evaluate(_bp_record(allow_deletions=True))
    assert any(c.rule_key == "github_branch_deletion_allowed" for c in out)


def test_pr_review_not_required_fires():
    out = gh.evaluate(
        _bp_record(
            required_pull_request_reviews_enabled=False,
            required_approving_review_count=None,
        )
    )
    assert any(c.rule_key == "github_pr_review_not_required" for c in out)

    # Zero approving reviews also counts as "not required".
    out2 = gh.evaluate(_bp_record(required_approving_review_count=0))
    assert any(c.rule_key == "github_pr_review_not_required" for c in out2)


def test_status_checks_not_required_fires():
    out = gh.evaluate(_bp_record(required_status_checks_enabled=False))
    assert any(c.rule_key == "github_status_checks_not_required" for c in out)
    assert next(
        c for c in out if c.rule_key == "github_status_checks_not_required"
    ).severity == "medium"


def test_branch_protection_malformed_ignored():
    # No protection_enabled key → ignored safely.
    assert gh.evaluate({"record_type": GITHUB_BRANCH_PROTECTION, "branch": "main"}) == []


# ── Deploy keys ──────────────────────────────────────────────────────────────


def test_deploy_key_write_access_fires():
    out = gh.evaluate(_deploy_key(read_only=False))
    assert len(out) == 1
    assert out[0].rule_key == "github_deploy_key_write_access"
    assert out[0].severity == "high"
    assert out[0].evidence.get("key_title") == "ci key"
    _assert_evidence_safe(out)


def test_deploy_key_readonly_safe():
    assert gh.evaluate(_deploy_key(read_only=True)) == []


def test_deploy_key_malformed_ignored():
    # Missing read_only → ignored (connector defaults missing to read-only).
    assert gh.evaluate({"record_type": GITHUB_DEPLOY_KEY, "title": "x"}) == []


# ── Environments ─────────────────────────────────────────────────────────────


def test_production_env_unprotected_fires():
    out = gh.evaluate(_env_record())
    assert len(out) == 1
    assert out[0].rule_key == "github_env_protection_missing"
    assert out[0].severity == "medium"
    _assert_evidence_safe(out)


def test_production_env_with_reviewers_safe():
    assert gh.evaluate(_env_record(reviewers_count=1)) == []


def test_non_production_env_ignored():
    assert gh.evaluate(_env_record(name="staging", environment_name="staging")) == []


def test_env_malformed_ignored():
    assert gh.evaluate(
        {"record_type": GITHUB_ENVIRONMENT_PROTECTION, "environment_name": "production"}
    ) == []


# ── Unknown record ───────────────────────────────────────────────────────────


def test_unknown_record_ignored():
    assert gh.evaluate({"record_type": "github_repo_settings", "name": "x"}) == []
    assert gh.evaluate({"weird": "shape"}) == []


# ════════════════════════════════════════════════════════════════════════════
# Integration tests through the evaluator (DB-backed): lifecycle + multi-record
# ════════════════════════════════════════════════════════════════════════════


def _make_workspace_for(user: User, db: Session):
    from app.services import workspace_service

    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M60.4.1", db=db
    )


def _make_integration(db: Session, user: User, workspace_id: uuid.UUID) -> Integration:
    ciphertext, iv = encrypt_credentials({"credential_type": "github_app"})
    integ = Integration(
        user_id=user.id,
        workspace_id=workspace_id,
        provider="github",
        display_name="github",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db.add(integ)
    db.commit()
    db.refresh(integ)
    return integ


def _make_resource(db: Session, integ: Integration, user: User) -> Resource:
    res = Resource(
        integration_id=integ.id,
        user_id=user.id,
        provider_resource_type="github_repo",
        provider_resource_id="acme/widgets",
        display_name="acme/widgets",
        is_active=True,
    )
    db.add(res)
    db.commit()
    db.refresh(res)
    return res


def _snapshot(db, res, integ, user, state) -> Snapshot:
    snap = Snapshot(
        resource_id=res.id,
        integration_id=integ.id,
        user_id=user.id,
        state=state,
        content_hash=uuid.uuid4().hex,
        triggered_by="manual",
    )
    db.add(snap)
    db.commit()
    db.refresh(snap)
    return snap


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


def test_multiple_records_produce_separate_findings(test_user, db_session):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id)
    res = _make_resource(db_session, integ, test_user)
    state = [
        {
            "record_id": "acme/widgets#webhook#1",
            "record_type": GITHUB_WEBHOOK,
            "name": "hook #1",
            "url": "http://example.com/hook",
            "active": True,
        },
        _bp_record(protection_enabled=False),
        _deploy_key(record_id="acme/widgets#deploy_key#5", key_id=5, read_only=False),
        _deploy_key(record_id="acme/widgets#deploy_key#6", key_id=6, read_only=False),
        _env_record(),
    ]
    snap = _snapshot(db_session, res, integ, test_user, state)

    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap
    )

    findings = _active(db_session, ws.id, res.id)
    keys = sorted(f.finding_key for f in findings)
    # webhook + bp_missing + 2 deploy keys + env = 5 distinct findings
    assert len(findings) == 5
    assert any(k.startswith("github_webhook_http") for k in keys)
    assert any(k.startswith("github_branch_protection_missing") for k in keys)
    assert sum(k.startswith("github_deploy_key_write_access") for k in keys) == 2
    assert any(k.startswith("github_env_protection_missing") for k in keys)

    _cleanup(db_session, ws.id)


def test_lifecycle_dedupe_and_resolve(test_user, db_session):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id)
    res = _make_resource(db_session, integ, test_user)

    risky = [_bp_record(protection_enabled=False)]
    snap1 = _snapshot(db_session, res, integ, test_user, risky)
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap1
    )
    f1 = _active(db_session, ws.id, res.id)
    assert len(f1) == 1
    first_seen = f1[0].last_seen_at

    # Same risky state again → dedupe, last_seen refreshes.
    snap2 = _snapshot(db_session, res, integ, test_user, risky)
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap2
    )
    f2 = _active(db_session, ws.id, res.id)
    assert len(f2) == 1
    assert f2[0].id == f1[0].id
    assert f2[0].last_seen_at >= first_seen

    # Protection enabled (safe) → finding resolves.
    snap3 = _snapshot(db_session, res, integ, test_user, [_bp_record()])
    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap3
    )
    assert summary["resolved"] == 1
    assert _active(db_session, ws.id, res.id) == []

    _cleanup(db_session, ws.id)
