"""M60.4 — security findings evaluation engine.

Covers the evaluator that turns the latest normalized snapshot into live
security_findings:

  1. Creates an active finding for a risky GitHub webhook (HTTP).
  2. Does NOT create a finding for a safe HTTPS webhook.
  3. Dedupes the same active finding across repeated evaluations.
  4. Resolves a finding when the risky state disappears.
  5. Updates last_seen_at when the risky state remains active.
  6. Reconciles per resource (a focused service-level pass; full Celery sync is
     not driven here to avoid heavy mocking).
  7. Ignores unsupported/unknown records safely.
  8. Workspace/integration/resource scoping is correct.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.connectors.github_schema import GITHUB_WEBHOOK
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.models.user import User
from app.services import security_finding_evaluator as evaluator


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_workspace_for(user: User, db: Session):
    from app.services import workspace_service

    return workspace_service.get_or_create_default_workspace(
        user_id=user.id,
        user_display_name=user.display_name or "M60.4 Test",
        db=db,
    )


def _make_integration(
    db: Session, user: User, workspace_id: uuid.UUID, provider: str = "github"
) -> Integration:
    ciphertext, iv = encrypt_credentials({"credential_type": "github_app"})
    integ = Integration(
        user_id=user.id,
        workspace_id=workspace_id,
        provider=provider,
        display_name=f"{provider} integration",
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


def _make_snapshot(
    db: Session, res: Resource, integ: Integration, user: User, state: list[dict]
) -> Snapshot:
    snap = Snapshot(
        resource_id=res.id,
        integration_id=integ.id,
        user_id=user.id,
        state=state,
        content_hash=uuid.uuid4().hex,  # uniqueness not important for the test
        triggered_by="manual",
    )
    db.add(snap)
    db.commit()
    db.refresh(snap)
    return snap


def _http_webhook(hook_id: int = 1) -> dict:
    return {
        "record_id": f"acme/widgets#webhook#{hook_id}",
        "record_type": GITHUB_WEBHOOK,
        "name": f"hook #{hook_id}",
        "hook_id": hook_id,
        "url": "http://example.com/github-webhook",
        "active": True,
        "events": ["push"],
        "content_type": "json",
    }


def _https_webhook(hook_id: int = 1) -> dict:
    rec = _http_webhook(hook_id)
    rec["url"] = "https://api.example.com/github-webhook"
    return rec


def _active_findings(db: Session, workspace_id, resource_id) -> list[SecurityFinding]:
    return (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.resource_id == resource_id,
            SecurityFinding.status == "active",
        )
        .all()
    )


def _cleanup(db: Session, workspace_id):
    db.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == workspace_id
    ).delete()
    db.commit()


# ── 1. Creates active finding for risky GitHub webhook ────────────────────────


def test_creates_active_finding_for_http_webhook(test_user, db_session):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id, "github")
    res = _make_resource(db_session, integ, test_user)
    snap = _make_snapshot(db_session, res, integ, test_user, [_http_webhook()])

    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session,
        workspace_id=ws.id,
        integration=integ,
        resource=res,
        snapshot=snap,
        linked_changes=[],
    )

    assert summary["upserted"] == 1
    findings = _active_findings(db_session, ws.id, res.id)
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_key.startswith("github_webhook_http")
    # Stale expectation from before the critical -> high severity
    # recalibration (confirmed consistent across evaluator, rule pack,
    # confidence, coverage, and frontend catalog in the GitHub detection-QA
    # pass, commit 49955d9). This test was missed by that pass; fixed here.
    assert f.severity == "high"
    assert f.title == "GitHub webhook uses plain HTTP"
    # Stale key: evidence stores only the URL scheme/host (never the full
    # URL, matching the sensitive-data minimization convention), not "url".
    assert f.evidence["url_scheme"] == "http"
    assert f.evidence["url_host"] == "example.com"
    assert f.evidence["uses_http"] is True
    assert f.provider == "github"

    _cleanup(db_session, ws.id)


# ── 2. No finding for safe HTTPS webhook ──────────────────────────────────────


def test_no_finding_for_https_webhook(test_user, db_session):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id, "github")
    res = _make_resource(db_session, integ, test_user)
    snap = _make_snapshot(db_session, res, integ, test_user, [_https_webhook()])

    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session,
        workspace_id=ws.id,
        integration=integ,
        resource=res,
        snapshot=snap,
    )

    assert summary["upserted"] == 0
    assert _active_findings(db_session, ws.id, res.id) == []
    _cleanup(db_session, ws.id)


# ── 3 & 5. Dedupe + last_seen_at refresh across repeated evaluations ──────────


def test_dedupes_and_updates_last_seen(test_user, db_session):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id, "github")
    res = _make_resource(db_session, integ, test_user)
    snap1 = _make_snapshot(db_session, res, integ, test_user, [_http_webhook()])

    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap1
    )
    findings = _active_findings(db_session, ws.id, res.id)
    assert len(findings) == 1
    first_seen = findings[0].last_seen_at

    # Second evaluation with the SAME risky state — no duplicate, last_seen moves.
    snap2 = _make_snapshot(db_session, res, integ, test_user, [_http_webhook()])
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap2
    )
    findings2 = _active_findings(db_session, ws.id, res.id)
    assert len(findings2) == 1  # deduped
    assert findings2[0].id == findings[0].id
    assert findings2[0].last_seen_at >= first_seen

    _cleanup(db_session, ws.id)


# ── 4. Resolves finding when risky state disappears ───────────────────────────


def test_resolves_when_risky_state_gone(test_user, db_session):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id, "github")
    res = _make_resource(db_session, integ, test_user)

    snap_risky = _make_snapshot(db_session, res, integ, test_user, [_http_webhook()])
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap_risky
    )
    assert len(_active_findings(db_session, ws.id, res.id)) == 1

    # Webhook flipped back to HTTPS — risky state gone.
    snap_safe = _make_snapshot(db_session, res, integ, test_user, [_https_webhook()])
    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap_safe
    )

    assert summary["resolved"] == 1
    assert _active_findings(db_session, ws.id, res.id) == []
    resolved = (
        db_session.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == ws.id,
            SecurityFinding.resource_id == res.id,
            SecurityFinding.status == "resolved",
        )
        .all()
    )
    assert len(resolved) == 1
    assert resolved[0].resolved_at is not None

    _cleanup(db_session, ws.id)


# ── 6. Per-resource reconciliation + linked_change attachment ─────────────────


def test_links_change_when_available(test_user, db_session):
    """A real change whose provider_metadata.record_id matches the risky record
    is linked to the finding (best-effort). Uses a persisted Change so the
    finding's linked_change_id FK is satisfied (as in the real sync flow)."""
    from app.models.change import Change

    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id, "github")
    res = _make_resource(db_session, integ, test_user)
    rec = _http_webhook(hook_id=7)
    snap = _make_snapshot(db_session, res, integ, test_user, [rec])

    # A real Change row carrying the matching record_id in provider_metadata.
    change = Change(
        resource_id=res.id,
        integration_id=integ.id,
        user_id=test_user.id,
        prev_snapshot_id=snap.id,
        new_snapshot_id=snap.id,
        change_type="modified",
        record_identifier=rec["record_id"],
        field_path="url",
        risk_level="critical",
        provider_metadata={"record_id": rec["record_id"]},
    )
    db_session.add(change)
    db_session.commit()
    db_session.refresh(change)

    evaluator.evaluate_security_findings_for_resource(
        db=db_session,
        workspace_id=ws.id,
        integration=integ,
        resource=res,
        snapshot=snap,
        linked_changes=[change],
    )

    findings = _active_findings(db_session, ws.id, res.id)
    assert len(findings) == 1
    assert findings[0].linked_change_id == change.id

    # cleanup: findings first (FK), then the change
    db_session.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == ws.id
    ).delete()
    db_session.commit()
    db_session.delete(change)
    db_session.commit()


# ── 7. Unknown / unsupported records are ignored safely ───────────────────────


def test_unknown_records_ignored(test_user, db_session):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id, "github")
    res = _make_resource(db_session, integ, test_user)
    state = [
        {"record_type": "github_repo", "record_id": "acme/widgets", "name": "repo"},
        {"weird": "shape"},  # malformed, no record_type
        {"record_type": "totally_unknown", "record_id": "x"},
    ]
    snap = _make_snapshot(db_session, res, integ, test_user, state)

    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap
    )
    assert summary["upserted"] == 0
    assert _active_findings(db_session, ws.id, res.id) == []
    _cleanup(db_session, ws.id)


# ── 8. Scoping: workspace_id/integration_id/resource_id set correctly + skip ──


def test_scoping_and_skip_without_workspace(test_user, db_session):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id, "github")
    res = _make_resource(db_session, integ, test_user)
    snap = _make_snapshot(db_session, res, integ, test_user, [_http_webhook()])

    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap
    )
    f = _active_findings(db_session, ws.id, res.id)[0]
    assert f.workspace_id == ws.id
    assert f.integration_id == integ.id
    assert f.resource_id == res.id

    # No workspace → skip cleanly, no rows written.
    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session,
        workspace_id=None,
        integration=integ,
        resource=res,
        snapshot=snap,
    )
    assert summary["skipped"] is True

    _cleanup(db_session, ws.id)


# ── evaluate_record dispatch (provider-agnostic safety) ───────────────────────


def test_evaluate_record_dispatch():
    # Supported risky record → 1 candidate.
    out = evaluator.evaluate_record(_http_webhook(), "github")
    assert len(out) == 1
    assert out[0].rule_key == "github_webhook_http"

    # Unknown provider → nothing.
    assert evaluator.evaluate_record(_http_webhook(), "nonexistent") == []
    # Non-dict record → nothing, no raise.
    assert evaluator.evaluate_record("not-a-dict", "github") == []  # type: ignore[arg-type]
