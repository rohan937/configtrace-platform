"""M60.3 — security_findings data model + read-only API.

Covers the data foundation for Security Exposure findings:

  1. An active finding can be created.
  2. A duplicate ACTIVE finding for the same logical issue is prevented
     (partial unique index), and the idempotent upsert dedupes instead.
  3. A RESOLVED finding does not block a new active finding for the same issue.
  4. GET /security/findings returns the current user's workspace findings.
  5. GET /security/findings/{id} returns full detail.
  6. Workspace isolation: a user cannot read another workspace's findings.

No evaluation engine is exercised — these test persistence + access scoping
only (M60.3 is the data foundation).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_finding import SecurityFinding
from app.models.user import User
from app.services import security_finding_service


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_workspace_for(user: User, db: Session):
    from app.services import workspace_service

    return workspace_service.get_or_create_default_workspace(
        user_id=user.id,
        user_display_name=user.display_name or "M60.3 Test",
        db=db,
    )


def _make_integration(db: Session, user: User, workspace_id: uuid.UUID) -> Integration:
    creds = {"credential_type": "github_app", "installation_id": 4242}
    ciphertext, iv = encrypt_credentials(creds)
    integ = Integration(
        user_id=user.id,
        workspace_id=workspace_id,
        provider="github",
        display_name="acme/widgets",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db.add(integ)
    db.commit()
    db.refresh(integ)
    return integ


def _make_user(db: Session) -> User:
    uid = uuid.uuid4().hex[:12]
    user = User(
        clerk_id=f"test_clerk_{uid}",
        email=f"test_{uid}@configtrace.test",
        display_name="Other User",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ── 1. Create active finding ──────────────────────────────────────────────────


def test_create_active_finding(test_user, db_session):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id)

    finding = security_finding_service.create_finding(
        db=db_session,
        workspace_id=ws.id,
        integration_id=integ.id,
        provider="github",
        finding_key="github_webhook_http",
        severity="critical",
        title="GitHub webhook uses HTTP",
        description="Webhook delivery URL is plain http://.",
        evidence={"url": "http://example.com/github-webhook"},
        remediation={"steps": ["Restore HTTPS"]},
    )

    assert finding.id is not None
    assert finding.status == "active"
    assert finding.severity == "critical"
    assert finding.first_detected_at is not None
    assert finding.last_seen_at is not None

    # cleanup (workspace/integration cascade from user teardown; finding too)
    db_session.delete(finding)
    db_session.commit()


# ── 2. Duplicate active finding prevented + upsert dedupes ─────────────────────


def test_duplicate_active_finding_is_prevented(test_user, db_session):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id)

    common = dict(
        db=db_session,
        workspace_id=ws.id,
        integration_id=integ.id,
        provider="github",
        finding_key="github_webhook_http",
        severity="critical",
        title="GitHub webhook uses HTTP",
    )

    first = security_finding_service.create_finding(**common)

    # Second plain insert for the same logical (active) issue must violate the
    # partial unique index.
    with pytest.raises(IntegrityError):
        security_finding_service.create_finding(**common)
    db_session.rollback()

    # The idempotent path dedupes instead of erroring: same row, refreshed.
    upserted = security_finding_service.upsert_active_finding(**common)
    assert upserted.id == first.id

    count = (
        db_session.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == ws.id,
            SecurityFinding.finding_key == "github_webhook_http",
        )
        .count()
    )
    assert count == 1

    db_session.delete(first)
    db_session.commit()


# ── 3. Resolved finding does not block a new active finding ────────────────────


def test_resolved_finding_does_not_block_new_active(test_user, db_session):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id)

    common = dict(
        db=db_session,
        workspace_id=ws.id,
        integration_id=integ.id,
        provider="github",
        finding_key="github_webhook_http",
        severity="high",
        title="GitHub webhook uses HTTP",
    )

    first = security_finding_service.create_finding(**common)

    # Resolve it.
    from datetime import datetime, timezone

    first.status = "resolved"
    first.resolved_at = datetime.now(timezone.utc)
    db_session.add(first)
    db_session.commit()

    # A new active finding for the same logical issue should now be allowed.
    second = security_finding_service.create_finding(**common)
    assert second.id != first.id
    assert second.status == "active"

    rows = (
        db_session.query(SecurityFinding)
        .filter(SecurityFinding.finding_key == "github_webhook_http", SecurityFinding.workspace_id == ws.id)
        .all()
    )
    statuses = sorted(r.status for r in rows)
    assert statuses == ["active", "resolved"]

    for r in rows:
        db_session.delete(r)
    db_session.commit()


# ── 4. List endpoint returns the user's workspace findings ────────────────────


def test_list_findings_returns_workspace_findings(test_user, db_session, client):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id)
    finding = security_finding_service.create_finding(
        db=db_session,
        workspace_id=ws.id,
        integration_id=integ.id,
        provider="github",
        finding_key="github_webhook_http",
        severity="critical",
        title="GitHub webhook uses HTTP",
    )

    resp = client.get("/security/findings")
    assert resp.status_code == 200
    body = resp.json()
    ids = [item["id"] for item in body["items"]]
    assert str(finding.id) in ids

    # status filter narrows correctly.
    resp_resolved = client.get("/security/findings?status=resolved")
    assert resp_resolved.status_code == 200
    assert str(finding.id) not in [i["id"] for i in resp_resolved.json()["items"]]

    db_session.delete(finding)
    db_session.commit()


# ── 5. Detail endpoint returns full finding ───────────────────────────────────


def test_detail_returns_finding(test_user, db_session, client):
    ws = _make_workspace_for(test_user, db_session)
    integ = _make_integration(db_session, test_user, ws.id)
    finding = security_finding_service.create_finding(
        db=db_session,
        workspace_id=ws.id,
        integration_id=integ.id,
        provider="github",
        finding_key="github_webhook_http",
        severity="critical",
        title="GitHub webhook uses HTTP",
        evidence={"url": "http://x"},
    )

    resp = client.get(f"/security/findings/{finding.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == str(finding.id)
    assert body["finding_key"] == "github_webhook_http"
    assert body["severity"] == "critical"
    assert body["evidence"] == {"url": "http://x"}

    db_session.delete(finding)
    db_session.commit()


# ── 6. Workspace isolation ────────────────────────────────────────────────────


def test_workspace_isolation(test_user, db_session, client):
    # Findings belonging to test_user's own workspace (visible).
    own_ws = _make_workspace_for(test_user, db_session)
    own_integ = _make_integration(db_session, test_user, own_ws.id)
    own_finding = security_finding_service.create_finding(
        db=db_session,
        workspace_id=own_ws.id,
        integration_id=own_integ.id,
        provider="github",
        finding_key="github_webhook_http",
        severity="high",
        title="Own finding",
    )

    # A second user with their own workspace + finding (must NOT be visible).
    other_user = _make_user(db_session)
    other_ws = _make_workspace_for(other_user, db_session)
    other_integ = _make_integration(db_session, other_user, other_ws.id)
    other_finding = security_finding_service.create_finding(
        db=db_session,
        workspace_id=other_ws.id,
        integration_id=other_integ.id,
        provider="aws",
        finding_key="aws_open_admin_port",
        severity="critical",
        title="Other workspace finding",
    )

    # List: only the requester's finding appears.
    resp = client.get("/security/findings")
    assert resp.status_code == 200
    ids = [i["id"] for i in resp.json()["items"]]
    assert str(own_finding.id) in ids
    assert str(other_finding.id) not in ids

    # Detail: another workspace's finding is 404 (existence not leaked).
    resp_detail = client.get(f"/security/findings/{other_finding.id}")
    assert resp_detail.status_code == 404

    # cleanup
    db_session.delete(own_finding)
    db_session.delete(other_finding)
    db_session.commit()
    db_session.delete(other_integ)
    db_session.commit()
    # other_user's workspace + user
    from app.models.workspace import Workspace, WorkspaceMember

    db_session.query(WorkspaceMember).filter(
        WorkspaceMember.workspace_id == other_ws.id
    ).delete()
    db_session.query(Workspace).filter(Workspace.id == other_ws.id).delete()
    db_session.delete(other_user)
    db_session.commit()
