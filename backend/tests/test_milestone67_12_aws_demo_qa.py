"""M67.12 — Final AWS Security Demo + QA hardening.

Verifies the enhanced AWS demo seeds ONE coherent case spanning every AWS layer
(configuration risk, provider alert + Security Hub findings, CloudTrail/IAM
behavior, S3 data events + spike signal, VPC Flow Logs + flow signal), that the
chain is idempotent, that clear removes only AWS demo evidence (GitHub demo
stays isolated), that the case report exports AWS summaries with no raw leaks,
that member cannot seed/clear, and that no forbidden claim wording appears.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import HTTPException

from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase
from app.models.security_incident_signal import SecurityIncidentSignal
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
    "data exfiltration confirmed", "network intrusion confirmed",
]
_FORBIDDEN_RAW = [
    "aws_secret_access_key", "secretaccesskey", "sessiontoken",
    "requestparameters", "responseelements", "sourceipaddress", "cloudtrailevent",
]
AWS_SOURCE = "demo_aws_incident"


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M67.12", db=db)


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


# ── 1. full chain ─────────────────────────────────────────────────────────────

def test_aws_demo_seeds_full_chain(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        out = demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert out["seeded"] and out["created"]
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(out["case_id"])).first()
        assert case is not None and case.provider == "aws"

        links = case_svc.list_case_links(case_id=case.id, db=db_session)
        types = {ln.linked_object_type for ln in links}
        assert {"finding", "activity_event", "correlation", "signal"} <= types

        # Representative activity events from each AWS source are present.
        sources = {
            r.source for r in db_session.query(SecurityActivityEvent).filter(
                SecurityActivityEvent.workspace_id == ws.id,
                SecurityActivityEvent.provider == "aws",
            ).all()
        }
        assert {"security_alert", "security_hub", "cloudtrail",
                "s3_data_event", "vpc_flow_log"} <= sources

        # Signals from each derived AWS layer are present.
        sig_types = {
            s.signal_type for s in db_session.query(SecurityIncidentSignal).filter(
                SecurityIncidentSignal.workspace_id == ws.id,
                SecurityIncidentSignal.provider == "aws",
            ).all()
        }
        assert "aws_security_hub_finding" in sig_types
        assert "iam_behavior_timeline" in sig_types
        assert "s3_object_access_spike" in sig_types
        assert "vpc_flow_activity_signal" in sig_types
    finally:
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)


# ── 2. idempotency ────────────────────────────────────────────────────────────

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


# ── 3. clear removes only AWS demo evidence ───────────────────────────────────

def test_clear_removes_all_aws_demo_evidence(test_user, db_session):
    ws = _ws(test_user, db_session)
    demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    demo_svc.clear_aws(workspace_id=ws.id, db=db_session)

    assert demo_svc.get_aws_status(ws.id, db_session)["seeded"] is False
    assert _aws_cases(db_session, ws.id) == 0
    assert demo_svc.get_aws_demo_integration(ws.id, db_session) is None
    assert db_session.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws.id).count() == 0
    assert db_session.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws.id).count() == 0


# ── 4. GitHub demo stays isolated ─────────────────────────────────────────────

def test_github_demo_isolated_from_aws(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        gh = demo_svc.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        aws = demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert gh["case_id"] != aws["case_id"]
        # Clearing AWS leaves the GitHub demo intact.
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)
        assert demo_svc.get_aws_status(ws.id, db_session)["seeded"] is False
        assert demo_svc.get_status(ws.id, db_session)["seeded"] is True
        assert demo_svc.get_demo_integration(ws.id, db_session) is not None
    finally:
        demo_svc.clear(workspace_id=ws.id, db=db_session)
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)


# ── 5. report exports AWS summaries with no raw leaks ─────────────────────────

def test_report_exports_aws_summaries_safely(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        out = demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(out["case_id"])).first()
        report = report_svc.build_case_report(case=case, db=db_session)

        assert "AWS" in report["executive_summary"]
        assert len(report["risks"]) >= 1
        assert len(report["signals"]) >= 4  # provider-alert + sh + iam + s3 + vpc
        # Activity section spans the AWS sources.
        report_sources = {e["source"] for e in report["activity_events"]}
        assert {"security_alert", "security_hub", "cloudtrail",
                "s3_data_event", "vpc_flow_log"} <= report_sources
        # Evidence levels render.
        levels = {s["evidence_level"] for s in report["signals"]}
        assert "provider_alert" in levels and "activity" in levels

        blob = json.dumps(report, default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob, f"forbidden claim {phrase!r}"
        for raw in _FORBIDDEN_RAW:
            assert raw not in blob, f"raw marker {raw!r} leaked"
        # No raw object key / no source_ip raw field.
        for ev in report["activity_events"]:
            assert "source_ip" not in ev  # only source_ip_hash allowed
            assert "object_key" not in {k for k in (ev.get("metadata") or {})
                                        if k not in ("object_key_hash", "object_key_prefix")}
    finally:
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)


# ── 6. claim discipline across all seeded objects ─────────────────────────────

def test_no_forbidden_wording_in_seeded_objects(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        blobs = []
        for c in db_session.query(SecurityCase).filter(SecurityCase.workspace_id == ws.id).all():
            blobs.append(f"{c.title}\n{c.summary}")
        for s in db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id).all():
            blobs.append(f"{s.title}\n{s.summary}")
        text = "\n".join(blobs).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in text, f"forbidden phrase {phrase!r}"
    finally:
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)


# ── 7. member cannot seed/clear ───────────────────────────────────────────────

def test_member_cannot_seed_or_clear(test_user, db_session):
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


def test_admin_can_seed_clear_via_endpoints(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        r = client.post("/security/incident-demo/seed?provider=aws")
        assert r.status_code == 200 and r.json()["seeded"] is True
        st = client.get("/security/incident-demo/status?provider=aws")
        assert st.json()["seeded"] is True
        c = client.post("/security/incident-demo/clear?provider=aws")
        assert c.status_code == 200 and c.json()["cleared"] is True
    finally:
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)
