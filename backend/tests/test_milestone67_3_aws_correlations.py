"""M67.3 — AWS Configuration Risk × AWS provider-alert correlation.

AWS correlations are EVIDENCE FOR REVIEW that link an AWS Configuration Risk
finding (``security_findings`` provider=aws) to an AWS provider-reported
security alert (``security_activity_events`` provider=aws, source=
"security_alert" — GuardDuty / Access Analyzer) for the SAME concrete resource
(an S3 bucket name or an IAM principal / user name) within a review window.

Matching is conservative and resource-driven — never account-wide. These tests
assert:
  1. S3 public-policy risk + GuardDuty S3 alert (bucket name) → correlation.
  2. S3 risk + Access Analyzer alert (bucket ARN) → matched via ARN→name.
  3. IAM admin risk + GuardDuty AccessKey alert (user name) → correlation.
  4. IAM unused-key risk + GuardDuty AccessKey alert → correlation.
  5. Different resource (bucket A vs alert B) → NO correlation.
  6. Security-group risk is DEFERRED — never correlated to an instance alert.
  7. Activity outside the time window → no correlation.
  8. Repeated generation is idempotent.
  9. A "critical" provider alert raises the correlation severity to critical.
 10. No forbidden breach/attacker/compromise wording; "may require review".
 11. Correlation creates a linked AWS correlation-evidence incident signal.
 12. Provider isolation — AWS generate ignores GitHub data and vice-versa.
 13. _norm_resource reduces ARNs to a bare comparable name.
 14. Endpoints: generate(provider=aws) + list(provider=aws) (owner).
 15. Metadata sanitizer keeps allowlisted AWS keys, drops secrets.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.services import security_activity_event_service as activity_svc
from app.services import security_finding_service as finding_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected",
    "attacker found",
    "compromise confirmed",
    "someone has access",
    "unauthorized access confirmed",
    "attack detected",
]

BUCKET = "acme-prod-bucket"
IAM_USER = "deploy-bot"


# ── builders ──────────────────────────────────────────────────────────────────

def _new_user(db, label="owner"):
    u = User(
        clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
        email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test",
        display_name=label,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M67.3", db=db
    )


def _integ(db, user, ws_id, provider="aws"):
    ct, iv = encrypt_credentials(
        {"aws_access_key_id": "AKIA", "aws_secret_access_key": "x"}
        if provider == "aws"
        else {"github_token": "x", "repo_owner": "acme", "repo_name": "repo"}
    )
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider=provider,
        display_name=provider, encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _resource(db, integ, user, rtype="aws_s3_bucket", rid=BUCKET):
    r = Resource(
        integration_id=integ.id, user_id=user.id,
        provider_resource_type=rtype, provider_resource_id=rid,
        display_name=rid, is_active=True,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _finding(db, ws, integ, res, base_rule, evidence, *, provider="aws", severity="high"):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider=provider,
        finding_key=f"{base_rule}:{uuid.uuid4().hex[:8]}", severity=severity,
        title=f"{base_rule} risk", resource_id=res.id, description="desc",
        evidence=evidence, remediation={"summary": "fix"},
    )


def _alert(db, ws_id, integ_id, event_type, resource_id, *,
           occurred=None, severity_label="high", region="us-east-1",
           account_id="123456789012"):
    norm = activity_svc.normalize_activity_event(
        provider="aws", source="security_alert", event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id=uuid.uuid4().hex, actor_id=None,
        resource_type="aws_resource", resource_id=resource_id,
        metadata={
            "severity_label": severity_label, "region": region,
            "account_id": account_id, "finding_type": event_type,
        },
    )
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db
    )
    return row


def _gh_activity(db, ws_id, integ_id, event_type, repo="acme/repo", occurred=None):
    norm = activity_svc.normalize_activity_event(
        provider="github", source="audit_log", event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id=uuid.uuid4().hex, actor_id="mallory",
        resource_type="repository", resource_id=repo,
        metadata={"repository": repo},
    )
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db
    )
    return row


def _cleanup(db, ws_id):
    db.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == ws_id
    ).delete(synchronize_session=False)
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id
    ).delete(synchronize_session=False)
    db.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == ws_id
    ).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id
    ).delete(synchronize_session=False)
    integ_ids = [
        i.id for i in db.query(Integration).filter(Integration.workspace_id == ws_id).all()
    ]
    if integ_ids:
        db.query(Resource).filter(Resource.integration_id.in_(integ_ids)).delete(
            synchronize_session=False
        )
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(
            synchronize_session=False
        )
    db.commit()


def _gen(db, ws_id):
    return corr_svc.generate_aws_correlations(workspace_id=ws_id, db=db)


def _corrs(db, ws_id):
    items, _ = corr_svc.list_correlations(workspace_id=ws_id, db=db)
    return items


# ── 1. S3 risk + GuardDuty S3 alert (bucket name) ─────────────────────────────

def test_s3_risk_guardduty_bucket_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "aws_s3_public_policy", {"rule": "aws_s3_public_policy", "bucket": BUCKET})
    _alert(db_session, ws.id, integ.id, "aws.guardduty.unauthorized_access", BUCKET)
    summary = _gen(db_session, ws.id)
    assert summary["provider"] == "aws"
    assert summary["correlations_created"] == 1
    rows = _corrs(db_session, ws.id)
    assert len(rows) == 1
    assert rows[0].provider == "aws"
    assert rows[0].correlation_type == "aws_s3_public_access_alert"
    assert rows[0].confidence == "high"
    assert BUCKET in rows[0].title
    _cleanup(db_session, ws.id)


# ── 2. S3 risk + Access Analyzer alert (bucket ARN) ───────────────────────────

def test_s3_risk_access_analyzer_arn_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "aws_s3_public_acl", {"rule": "aws_s3_public_acl", "bucket": BUCKET})
    _alert(db_session, ws.id, integ.id, "aws.access_analyzer.finding", f"arn:aws:s3:::{BUCKET}")
    summary = _gen(db_session, ws.id)
    assert summary["correlations_created"] == 1
    assert _corrs(db_session, ws.id)[0].correlation_type == "aws_s3_public_access_alert"
    _cleanup(db_session, ws.id)


# ── 3. IAM admin risk + GuardDuty AccessKey alert (user name) ─────────────────

def test_iam_admin_risk_guardduty_accesskey_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user, rtype="aws_iam_user", rid=IAM_USER)
    _finding(db_session, ws, integ, res, "aws_iam_admin_policy_attached",
             {"rule": "aws_iam_admin_policy_attached", "principal_name": IAM_USER, "principal_type": "user"})
    _alert(db_session, ws.id, integ.id, "aws.guardduty.unauthorized_access", IAM_USER)
    summary = _gen(db_session, ws.id)
    assert summary["correlations_created"] == 1
    assert _corrs(db_session, ws.id)[0].correlation_type == "aws_iam_credential_alert"
    _cleanup(db_session, ws.id)


# ── 4. IAM unused-key risk + GuardDuty AccessKey alert ────────────────────────

def test_iam_unused_key_risk_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user, rtype="aws_iam_user", rid=IAM_USER)
    _finding(db_session, ws, integ, res, "aws_access_key_unused",
             {"rule": "aws_access_key_unused", "username": IAM_USER})
    _alert(db_session, ws.id, integ.id, "aws.guardduty.unauthorized_access", IAM_USER)
    summary = _gen(db_session, ws.id)
    assert summary["correlations_created"] == 1
    assert _corrs(db_session, ws.id)[0].correlation_key == "aws_iam_credential_alert"
    _cleanup(db_session, ws.id)


# ── 5. different resource → no correlation ────────────────────────────────────

def test_different_resource_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "aws_s3_public_policy", {"rule": "aws_s3_public_policy", "bucket": BUCKET})
    _alert(db_session, ws.id, integ.id, "aws.guardduty.unauthorized_access", "some-other-bucket")
    summary = _gen(db_session, ws.id)
    assert summary["correlations_created"] == 0
    assert _corrs(db_session, ws.id) == []
    _cleanup(db_session, ws.id)


# ── 6. security-group risk is DEFERRED (never correlated to an instance) ───────

def test_security_group_risk_is_deferred(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user, rtype="aws_security_group_rule", rid="sg-123")
    # An SG finding has no safe join key to an instance — must be ignored.
    _finding(db_session, ws, integ, res, "aws_public_admin_port",
             {"rule": "aws_public_admin_port", "group_id": "sg-123", "port": 22})
    _alert(db_session, ws.id, integ.id, "aws.guardduty.unauthorized_access", "i-0abc123")
    summary = _gen(db_session, ws.id)
    assert summary["findings_scanned"] == 0  # SG finding filtered out as non-correlatable
    assert summary["correlations_created"] == 0
    assert _corrs(db_session, ws.id) == []
    # Defensive: the SG base rule is intentionally absent from the ruleset.
    assert "aws_public_admin_port" not in corr_svc.AWS_CORRELATION_RULES
    _cleanup(db_session, ws.id)


# ── 7. outside the time window → no correlation ───────────────────────────────

def test_outside_window_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "aws_s3_public_policy", {"rule": "aws_s3_public_policy", "bucket": BUCKET})
    old = datetime.now(timezone.utc) - timedelta(hours=48)
    _alert(db_session, ws.id, integ.id, "aws.guardduty.unauthorized_access", BUCKET, occurred=old)
    summary = _gen(db_session, ws.id)
    assert summary["correlations_created"] == 0
    assert _corrs(db_session, ws.id) == []
    _cleanup(db_session, ws.id)


# ── 8. idempotency ────────────────────────────────────────────────────────────

def test_generation_is_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "aws_s3_public_policy", {"rule": "aws_s3_public_policy", "bucket": BUCKET})
    _alert(db_session, ws.id, integ.id, "aws.guardduty.unauthorized_access", BUCKET)
    s1 = _gen(db_session, ws.id)
    s2 = _gen(db_session, ws.id)
    assert s1["correlations_created"] == 1
    assert s2["correlations_created"] == 0
    assert s2["correlations_skipped"] == 1
    assert len(_corrs(db_session, ws.id)) == 1
    _cleanup(db_session, ws.id)


# ── 9. critical alert raises severity ─────────────────────────────────────────

def test_critical_alert_raises_severity(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "aws_s3_public_policy", {"rule": "aws_s3_public_policy", "bucket": BUCKET})
    _alert(db_session, ws.id, integ.id, "aws.guardduty.unauthorized_access", BUCKET, severity_label="critical")
    _gen(db_session, ws.id)
    assert _corrs(db_session, ws.id)[0].severity == "critical"
    _cleanup(db_session, ws.id)


# ── 10. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "aws_s3_public_policy", {"rule": "aws_s3_public_policy", "bucket": BUCKET})
    _alert(db_session, ws.id, integ.id, "aws.guardduty.unauthorized_access", BUCKET)
    _gen(db_session, ws.id)
    for c in _corrs(db_session, ws.id):
        blob = f"{c.title}\n{c.summary}".lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob, f"forbidden phrase {phrase!r} in {blob!r}"
        assert "may require review" in c.summary.lower()
    _cleanup(db_session, ws.id)


# ── 11. linked AWS correlation-evidence signal ────────────────────────────────

def test_correlation_creates_linked_aws_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    finding = _finding(db_session, ws, integ, res, "aws_s3_public_policy", {"rule": "aws_s3_public_policy", "bucket": BUCKET})
    _alert(db_session, ws.id, integ.id, "aws.guardduty.unauthorized_access", BUCKET)
    _gen(db_session, ws.id)
    corr = _corrs(db_session, ws.id)[0]
    assert corr.linked_signal_id is not None
    sig = db_session.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.id == corr.linked_signal_id
    ).first()
    assert sig is not None
    assert sig.provider == "aws"
    assert sig.evidence_level == "correlation"
    assert sig.linked_finding_id == finding.id
    _cleanup(db_session, ws.id)


# ── 12. provider isolation ────────────────────────────────────────────────────

def test_provider_isolation(test_user, db_session):
    ws = _ws(test_user, db_session)
    gh = _integ(db_session, test_user, ws.id, provider="github")
    gh_res = _resource(db_session, gh, test_user, rtype="github_repo", rid="acme/repo")
    _finding(db_session, ws, gh, gh_res, "github_webhook_http", {"rule": "github_webhook_http"}, provider="github")
    _gh_activity(db_session, ws.id, gh.id, "github.webhook.updated")
    # AWS generation must not touch GitHub data.
    summary = _gen(db_session, ws.id)
    assert summary["findings_scanned"] == 0
    assert summary["correlations_created"] == 0
    # GitHub generation must not touch AWS data either (none here → 0 cleanly).
    gh_summary = corr_svc.generate_github_correlations(workspace_id=ws.id, db=db_session)
    assert gh_summary["correlations_created"] == 1  # the GitHub pair correlates
    assert all(c.provider == "github" for c in _corrs(db_session, ws.id))
    _cleanup(db_session, ws.id)


# ── 13. _norm_resource ────────────────────────────────────────────────────────

def test_norm_resource_reduces_arns():
    assert corr_svc._norm_resource("arn:aws:s3:::My-Bucket") == "my-bucket"
    assert corr_svc._norm_resource("arn:aws:iam::123456789012:user/Deploy-Bot") == "deploy-bot"
    assert corr_svc._norm_resource("plain-bucket") == "plain-bucket"
    assert corr_svc._norm_resource("  ") is None
    assert corr_svc._norm_resource(None) is None


# ── 14. endpoints (owner) ─────────────────────────────────────────────────────

def test_generate_and_list_endpoints_aws(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "aws_s3_public_policy", {"rule": "aws_s3_public_policy", "bucket": BUCKET})
    _alert(db_session, ws.id, integ.id, "aws.guardduty.unauthorized_access", BUCKET)
    try:
        gen = client.post("/security/correlations/generate", json={"provider": "aws"})
        assert gen.status_code == 200
        body = gen.json()
        assert body["provider"] == "aws"
        assert body["correlations_created"] == 1

        lst = client.get("/security/correlations?provider=aws")
        assert lst.status_code == 200
        lb = lst.json()
        assert lb["total"] == 1
        assert lb["items"][0]["provider"] == "aws"
        assert lb["items"][0]["correlation_type"] == "aws_s3_public_access_alert"
    finally:
        _cleanup(db_session, ws.id)


# ── 15. metadata sanitizer ────────────────────────────────────────────────────

def test_sanitizer_keeps_aws_keys_drops_secrets():
    raw = {
        "resource": BUCKET,                 # allowlisted (M67.3)
        "region": "us-east-1",              # allowlisted
        "account_id": "123456789012",       # allowlisted
        "finding_rule": "aws_s3_public_policy",
        "aws_secret_access_key": "shh",     # dropped
        "payload": {"raw": "blob"},         # nested → dropped
    }
    clean = corr_svc.sanitize_correlation_metadata(raw)
    assert clean["resource"] == BUCKET
    assert clean["region"] == "us-east-1"
    assert clean["account_id"] == "123456789012"
    assert "aws_secret_access_key" not in clean
    assert "payload" not in clean
