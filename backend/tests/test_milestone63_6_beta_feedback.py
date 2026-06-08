"""M63.6 — beta feedback after Security Report export.

  1.  valid report_export feedback creates a row.
  2.  invalid rating rejected (422).
  3.  invalid feedback_type rejected (422).
  4.  comment truncated to 500 chars.
  5.  unknown context keys stripped.
  6.  forbidden context keys stripped (report contents/secrets never stored).
  7.  workspace isolation.
  8.  endpoint requires auth (get_current_user dependency).
  9.  feedback never stores report contents.
"""

from __future__ import annotations

import uuid

from app.core.auth import get_current_user
from app.main import app
from app.models.security_beta_feedback import SecurityBetaFeedback
from app.models.user import User
from app.services import security_beta_feedback_service as svc
from app.services import workspace_service


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M63.6", db=db
    )


def _cleanup(db, ws_id):
    db.query(SecurityBetaFeedback).filter(
        SecurityBetaFeedback.workspace_id == ws_id
    ).delete(synchronize_session=False)
    db.commit()


# ── 1. Valid feedback (HTTP) ──────────────────────────────────────────────────


def test_valid_feedback_creates_row(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    resp = client.post(
        "/security/beta-feedback",
        json={
            "feedback_type": "report_export",
            "rating": "useful",
            "comment": "Clear and concise.",
            "context": {"report_type": "review_packet", "export_format": "markdown_download", "finding_count": 12},
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["ok"] is True and body["id"]
    row = db_session.query(SecurityBetaFeedback).filter(
        SecurityBetaFeedback.workspace_id == ws.id
    ).one()
    assert row.rating == "useful"
    assert row.comment == "Clear and concise."
    assert row.context == {"report_type": "review_packet", "export_format": "markdown_download", "finding_count": 12}
    _cleanup(db_session, ws.id)


# ── 2 & 3. Invalid rating / feedback_type ─────────────────────────────────────


def test_invalid_rating_rejected(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    resp = client.post("/security/beta-feedback", json={"rating": "amazing"})
    assert resp.status_code == 422
    _cleanup(db_session, ws.id)


def test_invalid_feedback_type_rejected(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    resp = client.post(
        "/security/beta-feedback",
        json={"feedback_type": "nps_survey", "rating": "useful"},
    )
    assert resp.status_code == 422
    _cleanup(db_session, ws.id)


# ── 4. Comment truncation ─────────────────────────────────────────────────────


def test_comment_truncated(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    fb = svc.record_feedback(
        workspace_id=ws.id, user_id=test_user.id, feedback_type="report_export",
        rating="somewhat", comment="x" * 2000, context=None, db=db_session,
    )
    assert len(fb.comment) == svc.MAX_COMMENT_LEN
    _cleanup(db_session, ws.id)


# ── 5 & 6 & 9. Context allowlist + no report contents ─────────────────────────


def test_context_allowlist_and_no_report_contents(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    fb = svc.record_feedback(
        workspace_id=ws.id, user_id=test_user.id, feedback_type="report_export",
        rating="useful", comment=None,
        context={
            # allowed
            "report_type": "summary",
            "finding_count": 3,
            "critical_count": 1,
            "demo_loaded": True,
            # forbidden / unknown — must be dropped
            "report_markdown": "# secret report body",
            "report_json": "{...}",
            "csv": "a,b,c",
            "evidence": {"x": 1},
            "remediation": "do x",
            "note_body": "private",
            "acceptance_reason": "we accept",
            "token": "ghp_xxx",
            "secret": "s3cr3t",
            "random": "nope",
        },
        db=db_session,
    )
    assert fb.context == {
        "report_type": "summary",
        "finding_count": 3,
        "critical_count": 1,
        "demo_loaded": True,
    }
    for forbidden in ("report_markdown", "report_json", "csv", "evidence", "remediation", "note_body", "acceptance_reason", "token", "secret", "random"):
        assert forbidden not in fb.context
    _cleanup(db_session, ws.id)


# ── 7. Workspace isolation ────────────────────────────────────────────────────


def test_workspace_isolation(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    other = User(
        clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
        email=f"other_{uuid.uuid4().hex[:8]}@configtrace.test",
        display_name="Other",
    )
    db_session.add(other)
    db_session.commit()
    db_session.refresh(other)
    ows = _ws(other, db_session)
    _cleanup(db_session, ows.id)

    svc.record_feedback(
        workspace_id=ws.id, user_id=test_user.id, feedback_type="report_export",
        rating="useful", comment=None, context=None, db=db_session,
    )
    assert db_session.query(SecurityBetaFeedback).filter(
        SecurityBetaFeedback.workspace_id == ws.id
    ).count() == 1
    assert db_session.query(SecurityBetaFeedback).filter(
        SecurityBetaFeedback.workspace_id == ows.id
    ).count() == 0

    _cleanup(db_session, ws.id)
    db_session.delete(other)
    db_session.commit()


# ── 8. Requires auth ──────────────────────────────────────────────────────────


def test_endpoint_requires_auth():
    route = next(
        r
        for r in app.routes
        if getattr(r, "path", None) == "/security/beta-feedback"
        and "POST" in getattr(r, "methods", set())
    )

    def _calls(dep):
        found = dep.call is get_current_user
        for sub in dep.dependencies:
            found = found or _calls(sub)
        return found

    assert _calls(route.dependant)
