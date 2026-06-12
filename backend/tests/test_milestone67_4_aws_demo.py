"""M67.4 — AWS Incident Workflow demo smoke test + QA hardening.

Verifies the seeded AWS demo chain (S3 public-policy configuration risk →
Access Analyzer provider alert → AWS Incident Signal → AWS correlation → case),
that the case report exports AWS summaries safely (metadata-only, no raw
secrets/IPs/payloads), that seeding is idempotent and clearing removes exactly
the AWS demo objects, that the AWS demo is isolated from the GitHub demo, and
that seed/clear are admin-gated. No forbidden breach/attacker/compromise wording.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import HTTPException

from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_case_report_service as report_svc
from app.services import security_case_service as case_svc
from app.services import security_incident_demo_service as demo_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
]

# Raw-evidence leak guards: things that must NEVER appear in an exported report.
_FORBIDDEN_RAW = [
    "aws_secret_access_key", "aws_access_key_id", "akia", "secretaccesskey",
    "password", "private_key",
]

AWS_SOURCE = "demo_aws_incident"


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M67.4", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _aws_cases(db, ws_id):
    return db.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws_id,
        SecurityCase.case_metadata["source"].astext == AWS_SOURCE,
    ).count()


# ── seeded chain ────────────────────────────────────────────────────────────────

def test_aws_demo_seeds_full_chain(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        out = demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert out["seeded"] and out["created"]
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(out["case_id"])
        ).first()
        assert case is not None
        assert case.provider == "aws"
        links = case_svc.list_case_links(case_id=case.id, db=db_session)
        types = {ln.linked_object_type for ln in links}
        # finding + activity + correlation + signal all linked.
        assert {"finding", "activity_event", "correlation", "signal"} <= types

        # The underlying AWS objects exist in the workspace.
        finding = db_session.query(SecurityFinding).filter(
            SecurityFinding.workspace_id == ws.id, SecurityFinding.provider == "aws"
        ).first()
        assert finding is not None
        assert finding.finding_key.startswith("aws_s3_public_policy")

        alert = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.workspace_id == ws.id,
            SecurityActivityEvent.provider == "aws",
            SecurityActivityEvent.source == "security_alert",
        ).first()
        assert alert is not None
        assert alert.event_type == "aws.access_analyzer.finding"

        corr = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "aws",
        ).first()
        assert corr is not None
        assert corr.correlation_type == "aws_s3_public_access_alert"

        sig = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "aws",
            SecurityIncidentSignal.evidence_level == "provider_alert",
        ).first()
        assert sig is not None
    finally:
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)


def test_aws_demo_report_includes_aws_summaries_safely(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        out = demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(out["case_id"])
        ).first()
        report = report_svc.build_case_report(case=case, db=db_session)

        # AWS summaries present.
        assert len(report["risks"]) >= 1
        assert len(report["activity_events"]) >= 1
        assert len(report["correlations"]) >= 1
        assert len(report["signals"]) >= 1
        assert "AWS" in report["executive_summary"]

        blob = json.dumps(report, default=str).lower()
        # No forbidden claim wording.
        for phrase in _FORBIDDEN:
            assert phrase not in blob, f"forbidden claim {phrase!r} in report"
        # No raw secrets / credentials / payloads.
        for raw in _FORBIDDEN_RAW:
            assert raw not in blob, f"raw secret marker {raw!r} leaked into report"

        # Activity events carry only a hashed IP (or none) — never a raw IP field.
        for ev in report["activity_events"]:
            assert "source_ip" not in ev  # only source_ip_hash is allowed
    finally:
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)


# ── idempotency + clear ───────────────────────────────────────────────────────

def test_aws_demo_is_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        s1 = demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        s2 = demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert s1["created"] is True
        assert s2["created"] is False
        assert s1["case_id"] == s2["case_id"]
        assert _aws_cases(db_session, ws.id) == 1
    finally:
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)


def test_aws_demo_clear_removes_only_aws_demo(test_user, db_session):
    ws = _ws(test_user, db_session)
    demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    demo_svc.clear_aws(workspace_id=ws.id, db=db_session)

    assert demo_svc.get_aws_status(ws.id, db_session)["seeded"] is False
    assert _aws_cases(db_session, ws.id) == 0
    # No orphan AWS demo evidence remains.
    assert demo_svc.get_aws_demo_integration(ws.id, db_session) is None
    assert db_session.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws.id
    ).count() == 0
    assert db_session.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == ws.id
    ).count() == 0
    assert db_session.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == ws.id
    ).count() == 0


def test_aws_and_github_demos_are_isolated(test_user, db_session):
    """Clearing the AWS demo must not remove the GitHub demo (and vice-versa)."""
    ws = _ws(test_user, db_session)
    try:
        gh = demo_svc.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        aws = demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert gh["case_id"] != aws["case_id"]
        # Two distinct hidden demo integrations.
        assert demo_svc.get_demo_integration(ws.id, db_session) is not None
        assert demo_svc.get_aws_demo_integration(ws.id, db_session) is not None

        # Clearing AWS leaves the GitHub demo intact.
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)
        assert demo_svc.get_aws_status(ws.id, db_session)["seeded"] is False
        assert demo_svc.get_status(ws.id, db_session)["seeded"] is True
        assert demo_svc.get_demo_integration(ws.id, db_session) is not None
    finally:
        demo_svc.clear(workspace_id=ws.id, db=db_session)
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)


# ── permission gating (endpoints) ─────────────────────────────────────────────

def test_admin_can_seed_clear_aws_via_endpoints(client, test_user, db_session):
    # test_user owns their workspace → can seed + clear.
    ws = _ws(test_user, db_session)
    try:
        r = client.post("/security/incident-demo/seed?provider=aws")
        assert r.status_code == 200
        assert r.json()["seeded"] is True
        st = client.get("/security/incident-demo/status?provider=aws")
        assert st.json()["seeded"] is True
        c = client.post("/security/incident-demo/clear?provider=aws")
        assert c.status_code == 200 and c.json()["cleared"] is True
    finally:
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)


def test_member_cannot_seed_clear_aws_permission_helper(test_user, db_session):
    owner = _new_user(db_session, "owner")
    ws = _ws(owner, db_session)
    m = WorkspaceMember(workspace_id=ws.id, user_id=test_user.id, role="member")
    db_session.add(m); db_session.commit()
    try:
        with pytest.raises(HTTPException) as exc:
            workspace_permission_service.require_workspace_admin(ws.id, test_user.id, db_session)
        assert exc.value.status_code == 403
    finally:
        try:
            db_session.delete(owner); db_session.commit()
        except Exception:
            db_session.rollback()


# ── claim discipline on generated titles/summaries ────────────────────────────

def test_no_forbidden_wording_in_seeded_objects(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        blobs = []
        for case in db_session.query(SecurityCase).filter(SecurityCase.workspace_id == ws.id).all():
            blobs.append(f"{case.title}\n{case.summary}")
        for corr in db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id
        ).all():
            blobs.append(f"{corr.title}\n{corr.summary}")
        for sig in db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id
        ).all():
            blobs.append(f"{sig.title}\n{sig.summary}")
        text = "\n".join(blobs).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in text, f"forbidden phrase {phrase!r} in seeded objects"
    finally:
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)
