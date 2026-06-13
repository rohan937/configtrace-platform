"""M69.7A — Cross-provider case evidence timeline foundation.

A case can render a single chronological "evidence timeline" across its linked
findings, activity events, incident signals, and correlations. These tests assert:

  1. The timeline normalizes all four evidence kinds into a common item shape and
     sorts ascending by timestamp with a stable item-type/id tie-breaker.
  2. counts_by_type / counts_by_provider / dominant provider label are correct.
  3. It works cross-provider (GitHub + AWS evidence on one case).
  4. metadata_preview is scalar-allowlisted — it never leaks raw secrets/tokens/
     headers/webhook secrets/private keys/raw payloads/code/file paths/patches.
  5. The endpoint is workspace-scoped (own case → 200, cross-workspace → 404).
  6. No forbidden breach/attacker/compromise claims appear anywhere.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase, SecurityCaseLink
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.services import security_activity_event_service as activity_svc
from app.services import security_case_report_service as report_svc
from app.services import security_case_service as case_svc
from app.services import security_finding_service as finding_svc
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "token leaked", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
REPO = "acme/repo"
RAW_IP = "203.0.113.9"
RAW_SECRET = "ghp_supersecrettoken12345"

# Raw fields that must NEVER appear inside any metadata_preview.
_FORBIDDEN_KEYS = [
    "secret", "token", "credential", "authorization", "headers", "webhook_secret",
    "private_key", "oauth_secret", "raw_response", "code_snippet", "file_path",
    "manifest_path", "advisory_body", "patch", "request_body", "response_body",
]


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.7A", db=db)


def _integ(db, user, ws_id, provider="github"):
    ct, iv = encrypt_credentials({"github_token": "x", "repo_owner": "acme", "repo_name": "repo"})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider=provider,
                    display_name=provider, encrypted_credentials=ct, credential_iv=iv,
                    status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _repo(db, integ, user):
    r = Resource(integration_id=integ.id, user_id=user.id, provider_resource_type="github_repo",
                 provider_resource_id=REPO, display_name=REPO, is_active=True)
    db.add(r); db.commit(); db.refresh(r)
    return r


def _finding(db, ws, integ, res):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key=f"github_webhook_http:{uuid.uuid4().hex[:8]}", severity="high",
        title="webhook over HTTP", resource_id=res.id, description="d",
        evidence={
            "rule": "github_webhook_http", "repository": REPO,
            # forbidden raw fields that must be dropped from the preview
            "secret_value": RAW_SECRET, "authorization": "Bearer x",
            "private_key": "-----BEGIN", "code_snippet": "os.system(...)",
            "file_path": "/etc/app/config.py", "patch": "@@ -1 +1 @@",
            "raw_response": {"k": "v"},
        },
        remediation={"summary": "fix"})


def _activity(db, ws_id, integ_id, *, provider="github", source="audit_log",
              event_type="github.webhook.updated", occurred_at=None, eid=None):
    norm = activity_svc.normalize_activity_event(
        provider=provider, source=source, event_type=event_type,
        occurred_at=occurred_at or datetime.now(timezone.utc),
        provider_event_id=eid or f"doc-{uuid.uuid4().hex[:8]}",
        actor_id="mallory", resource_type="repository", resource_id=REPO,
        source_ip=RAW_IP,
        metadata={"action": "hook.config_changed", "repository": REPO,
                  "authorization": "Bearer x", "secret": RAW_SECRET})
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _signal(db, ws_id, *, occurred_at=None):
    s = SecurityIncidentSignal(
        workspace_id=ws_id, provider="github", signal_key=uuid.uuid4().hex,
        signal_type="github_webhook_reconfigured", title="Webhook reconfigured",
        summary="A webhook was reconfigured.",
        severity="medium", status="open", confidence="medium", evidence_level="signal",
        first_seen_at=occurred_at or datetime.now(timezone.utc),
        last_seen_at=occurred_at or datetime.now(timezone.utc),
        signal_metadata={"repository": REPO, "action": "hook.config_changed",
                         "secret": RAW_SECRET, "private_key": "-----BEGIN"})
    db.add(s); db.commit(); db.refresh(s)
    return s


def _correlation(db, ws_id, *, occurred_at=None):
    c = SecuritySignalCorrelation(
        workspace_id=ws_id, provider="github", correlation_key=uuid.uuid4().hex,
        correlation_type="github_config_audit", title="Config change near audit activity",
        summary="A config change occurred near audit activity.",
        severity="medium", status="open", confidence="medium",
        first_seen_at=occurred_at or datetime.now(timezone.utc),
        last_seen_at=occurred_at or datetime.now(timezone.utc),
        correlation_metadata={"repository": REPO, "rule": "github_webhook_http",
                              "authorization": "Bearer x", "patch": "@@"})
    db.add(c); db.commit(); db.refresh(c)
    return c


def _link(db, case, user, otype, oid):
    case_svc.link_object_to_case(
        case=case, object_type=otype, object_id=oid, actor_user_id=user.id, db=db)


def _full_case(db, user, *, provider="github"):
    """A case linking one of each evidence kind, with staggered timestamps."""
    ws = _ws(user, db)
    integ = _integ(db, user, ws.id)
    res = _repo(db, integ, user)
    t0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    f = _finding(db, ws, integ, res)
    a = _activity(db, ws.id, integ.id, occurred_at=t0 + timedelta(hours=1))
    s = _signal(db, ws.id, occurred_at=t0 + timedelta(hours=2))
    c = _correlation(db, ws.id, occurred_at=t0 + timedelta(hours=3))
    case = case_svc.create_case(workspace_id=ws.id, user_id=user.id,
                                title="M69.7A case", provider=provider, db=db)
    _link(db, case, user, "finding", f.id)
    _link(db, case, user, "activity_event", a.id)
    _link(db, case, user, "signal", s.id)
    _link(db, case, user, "correlation", c.id)
    return ws, case


def _cleanup(db, ws_id):
    db.query(SecurityCaseLink).filter(SecurityCaseLink.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityCase).filter(SecurityCase.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecuritySignalCorrelation).filter(SecuritySignalCorrelation.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityIncidentSignal).filter(SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    integ_ids = [i.id for i in db.query(Integration).filter(Integration.workspace_id == ws_id).all()]
    if integ_ids:
        db.query(Resource).filter(Resource.integration_id.in_(integ_ids)).delete(synchronize_session=False)
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(synchronize_session=False)
    db.commit()


# ── 1. normalized shape + ascending sort ─────────────────────────────────────

def test_timeline_normalizes_and_sorts(test_user, db_session):
    ws, case = _full_case(db_session, test_user)
    try:
        tl = report_svc.build_case_evidence_timeline(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        items = tl["timeline_items"]
        assert tl["total"] == 4 and len(items) == 4

        # Every item carries the common normalized shape.
        for it in items:
            assert it["item_type"] in {
                "finding", "activity_event", "incident_signal", "correlation"}
            for key in ("id", "provider", "title", "summary", "source",
                        "linked_object_id", "metadata_preview"):
                assert key in it
            assert it["linked_object_id"] == it["id"]

        # Ascending by timestamp (finding has no explicit ts → created_at now,
        # so order is asserted on the explicitly-staggered three).
        staggered = [it for it in items if it["item_type"] != "finding"]
        ts = [it["timestamp"] for it in staggered]
        assert ts == sorted(ts)
        # The discriminator field is set per type.
        by_type = {it["item_type"]: it for it in items}
        assert by_type["finding"]["rule_key"] == "github_webhook_http"
        assert by_type["activity_event"]["event_type"] == "github.webhook.updated"
        assert by_type["incident_signal"]["signal_type"] == "github_webhook_reconfigured"
        assert by_type["correlation"]["correlation_type"] == "github_config_audit"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. counts + provider label ───────────────────────────────────────────────

def test_timeline_counts_and_provider(test_user, db_session):
    ws, case = _full_case(db_session, test_user)
    try:
        tl = report_svc.build_case_evidence_timeline(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        assert tl["counts_by_type"] == {
            "finding": 1, "activity_event": 1, "incident_signal": 1, "correlation": 1}
        assert tl["counts_by_provider"]["github"] == 4
        assert tl["provider"] == "GitHub"
        assert tl["case_id"] == str(case.id)
    finally:
        _cleanup(db_session, ws.id)


# ── 3. cross-provider ─────────────────────────────────────────────────────────

def test_timeline_cross_provider(test_user, db_session):
    ws = _ws(test_user, db_session)
    gh = _integ(db_session, test_user, ws.id, provider="github")
    aws = _integ(db_session, test_user, ws.id, provider="aws")
    t0 = datetime(2026, 2, 1, 9, 0, tzinfo=timezone.utc)
    a_gh = _activity(db_session, ws.id, gh.id, provider="github",
                     occurred_at=t0, eid="gh-1")
    a_aws1 = _activity(db_session, ws.id, aws.id, provider="aws", source="cloudtrail",
                       event_type="aws.iam.policy_changed", occurred_at=t0 + timedelta(minutes=5),
                       eid="aws-1")
    a_aws2 = _activity(db_session, ws.id, aws.id, provider="aws", source="cloudtrail",
                       event_type="aws.s3.policy_changed", occurred_at=t0 + timedelta(minutes=10),
                       eid="aws-2")
    case = case_svc.create_case(workspace_id=ws.id, user_id=test_user.id,
                                title="cross", db=db_session)
    for a in (a_gh, a_aws1, a_aws2):
        _link(db_session, case, test_user, "activity_event", a.id)
    try:
        tl = report_svc.build_case_evidence_timeline(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        assert tl["counts_by_provider"] == {"github": 1, "aws": 2}
        assert tl["provider"] == "AWS"  # dominant provider label
        # Chronological order across providers.
        order = [it["event_type"] for it in tl["timeline_items"]]
        assert order == ["github.webhook.updated", "aws.iam.policy_changed",
                         "aws.s3.policy_changed"]
    finally:
        _cleanup(db_session, ws.id)


# ── 4. privacy: scalar-allowlisted metadata preview ──────────────────────────

def test_timeline_preview_is_scalar_allowlisted(test_user, db_session):
    ws, case = _full_case(db_session, test_user)
    try:
        tl = report_svc.build_case_evidence_timeline(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        blob = json.dumps(tl, default=str)
        # Raw secret / IP never appear anywhere.
        assert RAW_SECRET not in blob
        assert RAW_IP not in blob
        # No forbidden raw key surfaces in any preview, and every preview value
        # is a flat scalar (no nested dicts/lists).
        for it in tl["timeline_items"]:
            preview = it["metadata_preview"]
            for k, v in preview.items():
                assert k in report_svc._PREVIEW_ALLOWLIST
                assert isinstance(v, (bool, int, float, str))
            for bad in _FORBIDDEN_KEYS:
                assert bad not in preview
        # The safe allowlisted field still made it through.
        previews = [it["metadata_preview"] for it in tl["timeline_items"]]
        assert any(p.get("repository") == REPO for p in previews)
    finally:
        _cleanup(db_session, ws.id)


# ── 5. endpoint scoping ───────────────────────────────────────────────────────

def test_timeline_endpoint_ok(client, test_user, db_session):
    ws, case = _full_case(db_session, test_user)
    try:
        resp = client.get(f"/security/cases/{case.id}/timeline")
        assert resp.status_code == 200
        body = resp.json()
        assert body["case_id"] == str(case.id)
        assert body["total"] == 4
        assert len(body["timeline_items"]) == 4
        assert body["provider"] == "GitHub"
    finally:
        _cleanup(db_session, ws.id)


def test_timeline_endpoint_404_cross_workspace(client, test_user, db_session):
    other = _new_user(db_session, "other")
    ws_b, case_b = _full_case(db_session, other)
    try:
        resp = client.get(f"/security/cases/{case_b.id}/timeline")
        assert resp.status_code == 404
    finally:
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 6. report embeds the evidence timeline + no forbidden claims ─────────────

def test_report_embeds_timeline_and_no_forbidden_claims(test_user, db_session):
    ws, case = _full_case(db_session, test_user)
    try:
        rep = report_svc.build_case_report(case=case, db=db_session)
        et = rep["evidence_timeline"]
        assert et is not None
        assert et["total"] == 4
        assert et["case_id"] == str(case.id)
        # Claim discipline across the whole report payload.
        blob = json.dumps(rep, default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
        assert "does not automatically confirm" in et["claim_note"].lower()
    finally:
        _cleanup(db_session, ws.id)
