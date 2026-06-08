"""M63.1 — Security Exposure beta usage instrumentation.

  1.  valid event creates a row.
  2.  unknown event_name is rejected (422 / ValueError).
  3.  unknown metadata keys are stripped.
  4.  metadata string values are truncated.
  5.  workspace isolation.
  6.  forbidden keys (evidence/token/secret/remediation/...) are never stored.
  7.  endpoint requires authentication (get_current_user in dependency graph).
  8.  migration head present — table exists / insert works.

First-party, metadata-only, allowlisted instrumentation.
"""

from __future__ import annotations

import uuid

from app.core.auth import get_current_user
from app.main import app
from app.models.security_beta_event import SecurityBetaEvent
from app.models.user import User
from app.services import security_beta_event_service as svc
from app.services import workspace_service


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M63.1", db=db
    )


def _cleanup(db, ws_id):
    db.query(SecurityBetaEvent).filter(
        SecurityBetaEvent.workspace_id == ws_id
    ).delete(synchronize_session=False)
    db.commit()


# ── 1. Valid event creates a row ──────────────────────────────────────────────


def test_valid_event_creates_row(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    ev = svc.record_event(
        workspace_id=ws.id,
        user_id=test_user.id,
        event_name="security_page_viewed",
        page_path="/security",
        metadata={"route_group": "overview"},
        db=db_session,
    )
    assert ev.id is not None
    assert ev.event_name == "security_page_viewed"
    assert ev.event_category == "security_beta"
    assert ev.page_path == "/security"
    assert ev.event_metadata == {"route_group": "overview"}
    _cleanup(db_session, ws.id)


# ── 2. Unknown event_name rejected ────────────────────────────────────────────


def test_unknown_event_name_rejected(test_user, db_session):
    ws = _ws(test_user, db_session)
    import pytest

    with pytest.raises(ValueError):
        svc.record_event(
            workspace_id=ws.id,
            user_id=test_user.id,
            event_name="totally_made_up_event",
            page_path=None,
            metadata=None,
            db=db_session,
        )


def test_api_unknown_event_name_422(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    resp = client.post(
        "/security/beta-events",
        json={"event_name": "not_allowed"},
    )
    assert resp.status_code == 422
    _cleanup(db_session, ws.id)


# ── 3 & 6. Unknown / forbidden metadata keys stripped ─────────────────────────


def test_unknown_and_forbidden_keys_stripped(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    ev = svc.record_event(
        workspace_id=ws.id,
        user_id=test_user.id,
        event_name="security_exposure_opened",
        page_path="/security/exposures/[id]",
        metadata={
            # allowed
            "provider": "github",
            "severity": "high",
            "finding_id": "abc-123",
            # forbidden / unknown — must be dropped
            "evidence": {"secret": "leak"},
            "remediation": "do x",
            "token": "ghp_xxx",
            "secret": "s3cr3t",
            "payload": {"k": "v"},
            "note_body": "private note",
            "acceptance_reason": "we accept",
            "raw_rule": {"json": True},
            "random_key": "nope",
        },
        db=db_session,
    )
    md = ev.event_metadata
    assert md == {"provider": "github", "severity": "high", "finding_id": "abc-123"}
    for forbidden in ("evidence", "remediation", "token", "secret", "payload", "note_body", "acceptance_reason", "raw_rule", "random_key"):
        assert forbidden not in md
    _cleanup(db_session, ws.id)


# ── 4. String values truncated ────────────────────────────────────────────────


def test_string_values_truncated(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    long = "x" * 5000
    ev = svc.record_event(
        workspace_id=ws.id,
        user_id=test_user.id,
        event_name="security_report_exported",
        page_path="y" * 5000,
        metadata={"report_type": long, "demo_loaded": True},
        db=db_session,
    )
    assert len(ev.event_metadata["report_type"]) == svc.MAX_STR_LEN
    assert ev.event_metadata["demo_loaded"] is True
    assert len(ev.page_path) == svc.MAX_PAGE_PATH_LEN
    _cleanup(db_session, ws.id)


# ── 5. Workspace isolation ────────────────────────────────────────────────────


def test_workspace_isolation(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    svc.record_event(
        workspace_id=ws.id, user_id=test_user.id,
        event_name="security_coverage_viewed", page_path="/security/coverage",
        metadata=None, db=db_session,
    )

    other = User(
        clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
        email=f"other_{uuid.uuid4().hex[:8]}@configtrace.test",
        display_name="Other",
    )
    db_session.add(other)
    db_session.commit()
    db_session.refresh(other)
    ows = _ws(other, db_session)

    mine = db_session.query(SecurityBetaEvent).filter(
        SecurityBetaEvent.workspace_id == ws.id
    ).count()
    theirs = db_session.query(SecurityBetaEvent).filter(
        SecurityBetaEvent.workspace_id == ows.id
    ).count()
    assert mine == 1
    assert theirs == 0

    _cleanup(db_session, ws.id)
    db_session.delete(other)
    db_session.commit()


# ── 7. Endpoint requires auth ─────────────────────────────────────────────────


def test_endpoint_requires_auth():
    """The POST /security/beta-events route depends on get_current_user."""
    route = next(
        r
        for r in app.routes
        if getattr(r, "path", None) == "/security/beta-events"
        and "POST" in getattr(r, "methods", set())
    )

    def _calls(dependant):
        found = dependant.call is get_current_user
        for sub in dependant.dependencies:
            found = found or _calls(sub)
        return found

    assert _calls(route.dependant)


# ── 8. API happy-path (table exists post-migration) ───────────────────────────


def test_api_valid_event_201(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    resp = client.post(
        "/security/beta-events",
        json={
            "event_name": "security_walkthrough_opened",
            "page_path": "/security",
            "metadata": {"action": "open", "demo_loaded": False},
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["ok"] is True
    assert body["id"]
    row = db_session.query(SecurityBetaEvent).filter(
        SecurityBetaEvent.workspace_id == ws.id,
        SecurityBetaEvent.event_name == "security_walkthrough_opened",
    ).one()
    assert row.event_metadata == {"action": "open", "demo_loaded": False}
    _cleanup(db_session, ws.id)
