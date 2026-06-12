"""GitHub Incident Workflow demo seed (M66.10).

Seeds a clearly-labelled, demo-only end-to-end GitHub incident chain so the
workflow is easy to demo:

    Configuration Risk → Activity Event → Incident Signal → Correlation → Case

Separate from the M62.2 configuration-risk demo (lower risk, self-contained).

Rules (honored):
  * Clearly marked demo: a hidden ``provider="demo"`` integration (status
    "deleted", never scheduled) anchors the data; the case carries
    ``metadata.source = "demo_incident"``.
  * No notifications, no real provider sync (rows inserted directly).
  * Does not touch real findings/activity (correlation is built directly for the
    demo objects, not by scanning the workspace).
  * Idempotent: re-seeding returns the existing demo case.
  * ``clear`` removes exactly the demo objects and nothing else.

CLAIM DISCIPLINE: the demo presents evidence for review. It never asserts a
breach/attacker/compromise.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase, SecurityCaseLink
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.services import security_activity_event_service as activity_svc
from app.services import security_case_service as case_svc
from app.services import security_finding_service as finding_svc
from app.services import security_incident_signal_service as signal_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services import aws_iam_behavior_service as behavior_svc
from app.services import aws_s3_access_signal_service as s3_spike_svc
from app.services import aws_vpc_flow_signal_service as vpc_flow_svc

logger = logging.getLogger(__name__)

DEMO_PROVIDER_TAG = "demo"
DEMO_INTEGRATION_NAME = "ConfigTrace incident demo (sample data)"
DEMO_REPO = "configtrace-demo/incident-repo"
DEMO_CASE_SOURCE = "demo_incident"

# ── AWS incident demo (M67.4) — a SEPARATE hidden demo integration + case source
# so "Clear AWS demo" removes only AWS demo objects and never touches the GitHub
# demo (and vice-versa). Same safety rules: clearly marked demo, no real sync, no
# notifications, never touches a real AWS integration, idempotent.
AWS_DEMO_INTEGRATION_NAME = "ConfigTrace AWS incident demo (sample data)"
AWS_DEMO_BUCKET = "configtrace-demo-public-bucket"
AWS_DEMO_CASE_SOURCE = "demo_aws_incident"
AWS_DEMO_REGION = "us-east-1"
AWS_DEMO_ACCOUNT_ID = "000000000000"  # RFC-style placeholder, not a real account
AWS_DEMO_PRINCIPAL = "configtrace-demo-deploy"  # sample IAM principal name
AWS_DEMO_ENI = "eni-0configtracedemo"           # sample network interface id


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_demo_integration(workspace_id: uuid.UUID, db: Session) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_demo_case(workspace_id: uuid.UUID, db: Session) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed(*, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Seed the demo incident chain (idempotent). No notifications, no real sync."""
    existing = _existing_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" → never shown / never synced).
    integ = get_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({"demo": True, "dataset": "incident_demo_v1"})
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    # 2. Demo repo resource.
    resource = Resource(
        integration_id=integ.id,
        user_id=actor_user_id,
        provider_resource_type="github_repo",
        provider_resource_id=DEMO_REPO,
        display_name=DEMO_REPO,
        is_active=True,
    )
    db.add(resource)
    db.flush()

    # 3. Configuration Risk finding (demo-tagged in evidence).
    finding = finding_svc.upsert_active_finding(
        db=db,
        workspace_id=workspace_id,
        integration_id=integ.id,
        provider="github",
        finding_key=f"github_webhook_http:{DEMO_REPO}#demo",
        severity="high",
        title="Demo: GitHub webhook delivered over plain HTTP",
        resource_id=resource.id,
        description="Sample configuration risk for the incident-workflow demo.",
        evidence={"rule": "github_webhook_http", "demo": True, "repository": DEMO_REPO},
        remediation={"summary": "Switch the webhook to HTTPS."},
    )

    # 4. Activity Event (control-plane: webhook changed) on the same repo.
    normalized = activity_svc.normalize_activity_event(
        provider="github",
        source="audit_log",
        event_type="github.webhook.updated",
        occurred_at=_utcnow(),
        provider_event_id=f"demo-doc-{uuid.uuid4().hex[:8]}",
        actor_id="demo-admin",
        actor_type="user",
        resource_type="repository",
        resource_id=DEMO_REPO,
        metadata={"action": "hook.config_changed", "repository": DEMO_REPO},
    )
    _outcome, activity = activity_svc.upsert_activity_event(
        workspace_id=workspace_id, integration_id=integ.id, normalized=normalized, db=db
    )

    # 5. Incident Signal from the activity event.
    sig = signal_svc.build_signal_from_activity_event(activity)
    if sig is not None:
        signal_svc.upsert_incident_signal(workspace_id=workspace_id, signal=sig, db=db)

    # 6. Correlation (built directly for the demo objects — never scans real data).
    rule = corr_svc.CORRELATION_RULES["github_webhook_http"]
    corr_dict = corr_svc.build_correlation(
        finding=finding, event=activity, repo=DEMO_REPO, rule=rule
    )
    _o, correlation = corr_svc.upsert_correlation(
        workspace_id=workspace_id, correlation=corr_dict, db=db
    )

    # 7. Case linking all the evidence (marked demo via metadata.source).
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="[Demo] GitHub incident investigation",
        summary=(
            "Demo investigation case. A configuration risk on a GitHub repository "
            "was accompanied by control-plane audit activity on the same repo. "
            "This is a human-reviewed case presenting evidence for review — "
            "ConfigTrace does not automatically confirm compromise or unauthorized "
            "access."
        ),
        severity=correlation.severity,
        provider="github",
        metadata={"source": DEMO_CASE_SOURCE, "repository": DEMO_REPO},
        db=db,
    )
    case_svc.link_object_to_case(case=case, object_type="correlation", object_id=correlation.id, actor_user_id=actor_user_id, db=db)
    case_svc.link_object_to_case(case=case, object_type="finding", object_id=finding.id, actor_user_id=actor_user_id, db=db)
    case_svc.link_object_to_case(case=case, object_type="activity_event", object_id=activity.id, actor_user_id=actor_user_id, db=db)
    if correlation.linked_signal_id is not None:
        case_svc.link_object_to_case(case=case, object_type="signal", object_id=correlation.linked_signal_id, actor_user_id=actor_user_id, db=db)

    logger.info("incident_demo: seeded workspace=%s case=%s", workspace_id, case.id)
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the demo incident objects (and nothing else)."""
    # 1. Demo cases (+ their links).
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == DEMO_CASE_SOURCE,
        )
        .all()
    )
    case_ids = [c.id for c in demo_cases]
    if case_ids:
        db.query(SecurityCaseLink).filter(
            SecurityCaseLink.case_id.in_(case_ids)
        ).delete(synchronize_session=False)
        db.query(SecurityCase).filter(
            SecurityCase.id.in_(case_ids)
        ).delete(synchronize_session=False)

    # 2. Demo evidence anchored on the hidden demo integration.
    integ = get_demo_integration(workspace_id, db)
    if integ is not None:
        finding_ids = [
            f.id for f in db.query(SecurityFinding).filter(
                SecurityFinding.integration_id == integ.id
            ).all()
        ]
        activity_ids = [
            a.id for a in db.query(SecurityActivityEvent).filter(
                SecurityActivityEvent.integration_id == integ.id
            ).all()
        ]
        # Correlations referencing the demo finding/activity.
        corr_conds = []
        if finding_ids:
            corr_conds.append(SecuritySignalCorrelation.linked_finding_id.in_(finding_ids))
        if activity_ids:
            corr_conds.append(SecuritySignalCorrelation.linked_activity_event_id.in_(activity_ids))
        if corr_conds:
            db.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                or_(*corr_conds),
            ).delete(synchronize_session=False)
        # Signals tied to the demo integration or its activity events.
        sig_conds = [SecurityIncidentSignal.integration_id == integ.id]
        if activity_ids:
            sig_conds.append(SecurityIncidentSignal.linked_activity_event_id.in_(activity_ids))
        db.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == workspace_id,
            or_(*sig_conds),
        ).delete(synchronize_session=False)
        db.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id
        ).delete(synchronize_session=False)
        db.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id
        ).delete(synchronize_session=False)
        db.query(Resource).filter(
            Resource.integration_id == integ.id
        ).delete(synchronize_session=False)
        # Bulk delete (not ORM db.delete) to avoid a relationship-cascade re-delete
        # of the already-removed resources.
        db.query(Integration).filter(
            Integration.id == integ.id
        ).delete(synchronize_session=False)

    db.commit()
    return {"cleared": True}


# ───────────────────────────────────────────────────────────────────────────────
# AWS incident demo (M67.4)
# ───────────────────────────────────────────────────────────────────────────────


def get_aws_demo_integration(workspace_id: uuid.UUID, db: Session) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == AWS_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_aws_demo_case(workspace_id: uuid.UUID, db: Session) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == AWS_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_aws_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_aws_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_aws(*, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Seed the AWS demo incident chain (idempotent). No notifications, no real sync.

    Chain: S3 public-policy Configuration Risk → Access Analyzer provider alert
    (security_alert activity) → AWS Incident Signal → AWS correlation → Case.
    """
    existing = _existing_aws_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" → never shown / never synced).
    integ = get_aws_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({"demo": True, "dataset": "aws_incident_demo_v1"})
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=AWS_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    # 2. Demo S3 bucket resource.
    resource = Resource(
        integration_id=integ.id,
        user_id=actor_user_id,
        provider_resource_type="aws_s3_bucket",
        provider_resource_id=AWS_DEMO_BUCKET,
        display_name=AWS_DEMO_BUCKET,
        is_active=True,
    )
    db.add(resource)
    db.flush()

    # 3. Configuration Risk finding: S3 bucket policy allows public access.
    finding = finding_svc.upsert_active_finding(
        db=db,
        workspace_id=workspace_id,
        integration_id=integ.id,
        provider="aws",
        finding_key=f"aws_s3_public_policy:{AWS_DEMO_BUCKET}#demo",
        severity="high",
        title="Demo: S3 bucket policy allows public access",
        resource_id=resource.id,
        description="Sample AWS configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "aws_s3_public_policy",
            "demo": True,
            "bucket": AWS_DEMO_BUCKET,
            "policy_status_is_public": True,
        },
        remediation={"summary": "Restrict the bucket policy and enable Block Public Access."},
    )

    # 4. Provider alert: an Access Analyzer finding for the SAME bucket.
    normalized = activity_svc.normalize_activity_event(
        provider="aws",
        source="security_alert",
        event_type="aws.access_analyzer.finding",
        occurred_at=_utcnow(),
        provider_event_id=f"demo-aws-doc-{uuid.uuid4().hex[:8]}",
        actor_id=None,
        actor_type=None,
        resource_type="aws_s3_bucket",
        resource_id=f"arn:aws:s3:::{AWS_DEMO_BUCKET}",
        metadata={
            "finding_type": "ExternalAccess:S3/BucketPublic",
            "severity_label": "high",
            "region": AWS_DEMO_REGION,
            "account_id": AWS_DEMO_ACCOUNT_ID,
            "service_name": "access-analyzer",
        },
    )
    _outcome, activity = activity_svc.upsert_activity_event(
        workspace_id=workspace_id, integration_id=integ.id, normalized=normalized, db=db
    )

    # 5. AWS Incident Signal from the provider alert (evidence_level="provider_alert").
    aws_signal = None
    sig_dict = signal_svc.build_aws_signal_from_activity_event(activity)
    if sig_dict is not None:
        _so, aws_signal = signal_svc.upsert_incident_signal(
            workspace_id=workspace_id, signal=sig_dict, db=db
        )

    # 6. AWS correlation (built directly for the demo objects — never scans real data).
    rule_desc, _evidence_key = corr_svc.AWS_CORRELATION_RULES["aws_s3_public_policy"]
    resource_key = corr_svc._aws_finding_resource_key(finding)
    corr_dict = corr_svc.build_aws_correlation(
        finding=finding, event=activity, resource_key=resource_key, rule=rule_desc
    )
    _o, correlation = corr_svc.upsert_correlation(
        workspace_id=workspace_id, correlation=corr_dict, db=db
    )

    # ── Richer AWS evidence layers (M67.12) — ONE coherent case, a representative
    # sample from each AWS source (not noise). All are anchored on the hidden demo
    # integration, so ``clear_aws`` removes them too.

    def _demo_activity(*, source, event_type, metadata, resource_type=None,
                       resource_id=None, actor_id=None, actor_type=None):
        norm = activity_svc.normalize_activity_event(
            provider="aws", source=source, event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=f"demo-aws-{uuid.uuid4().hex[:12]}",
            actor_id=actor_id, actor_type=actor_type,
            resource_type=resource_type, resource_id=resource_id,
            metadata=metadata,
        )
        _o2, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id, normalized=norm, db=db
        )
        return row

    extra_signals: list[Any] = []
    extra_activity: list[Any] = []

    # (a) Security Hub finding (provider-reported) → Security Hub signal.
    sh_activity = _demo_activity(
        source="security_hub", event_type="aws.security_hub.s3_finding",
        resource_type="AwsS3Bucket", resource_id=f"arn:aws:s3:::{AWS_DEMO_BUCKET}",
        actor_type="provider_finding",
        metadata={
            "finding_type": "Software and Configuration Checks/AWS Security Best Practices",
            "finding_title": "S3 Block Public Access setting should be enabled",
            "severity_label": "high", "product_name": "Security Hub",
            "company_name": "AWS", "account_id": AWS_DEMO_ACCOUNT_ID,
            "region": AWS_DEMO_REGION, "compliance_status": "FAILED",
            "workflow_status": "NEW",
        },
    )
    extra_activity.append(sh_activity)
    sh_dict = signal_svc.build_aws_security_hub_signal_from_activity_event(sh_activity)
    if sh_dict is not None:
        _o3, sh_signal = signal_svc.upsert_incident_signal(
            workspace_id=workspace_id, signal=sh_dict, db=db)
        extra_signals.append(sh_signal)

    # (b) CloudTrail IAM management activity → IAM behavior signal.
    ct_events = [
        _demo_activity(
            source="cloudtrail", event_type="aws.iam.create_access_key",
            resource_type="aws_iam", resource_id=AWS_DEMO_PRINCIPAL,
            actor_id=AWS_DEMO_PRINCIPAL, actor_type="IAMUser",
            metadata={"event_name": "CreateAccessKey", "event_source": "iam.amazonaws.com",
                      "aws_region": AWS_DEMO_REGION, "account_id": AWS_DEMO_ACCOUNT_ID,
                      "user_name": AWS_DEMO_PRINCIPAL},
        ),
        _demo_activity(
            source="cloudtrail", event_type="aws.iam.attach_user_policy",
            resource_type="aws_iam", resource_id=AWS_DEMO_PRINCIPAL,
            actor_id=AWS_DEMO_PRINCIPAL, actor_type="IAMUser",
            metadata={"event_name": "AttachUserPolicy", "event_source": "iam.amazonaws.com",
                      "aws_region": AWS_DEMO_REGION, "account_id": AWS_DEMO_ACCOUNT_ID,
                      "user_name": AWS_DEMO_PRINCIPAL, "resource_name": "AdministratorAccess"},
        ),
    ]
    extra_activity.append(ct_events[-1])
    iam_dict = behavior_svc.build_iam_behavior_signal(events=ct_events, match={
        "signal_key": "aws.iam_behavior.access_key_policy_chain",
        "severity": "high",
        "phrase": "IAM access key creation followed by policy change",
        "summary_core": (
            "CloudTrail shows an IAM access key event and a policy change for the "
            "same principal/resource in the review window."
        ),
        "trigger_events": ct_events,
    })
    if iam_dict is not None:
        _o4, iam_signal = signal_svc.upsert_incident_signal(
            workspace_id=workspace_id, signal=iam_dict, db=db)
        extra_signals.append(iam_signal)

    # (c) S3 object-level data events → S3 object-access spike signal.
    s3_events = [
        _demo_activity(
            source="s3_data_event", event_type="aws.s3.data.get_object",
            resource_type="aws_s3_bucket", resource_id=AWS_DEMO_BUCKET,
            actor_id=AWS_DEMO_PRINCIPAL, actor_type="IAMUser",
            metadata={"bucket_name": AWS_DEMO_BUCKET, "object_key_hash": f"demohash{i}",
                      "object_key_prefix": "exports", "event_name": "GetObject"},
        )
        for i in range(6)
    ]
    extra_activity.append(s3_events[0])
    s3_dict = s3_spike_svc.build_s3_access_signal(events=s3_events, match={
        "pattern": "high_read_volume",
        "signal_key": "aws.s3_access.high_read_volume",
        "severity": "high",
        "phrase": "High S3 object read volume by principal",
        "summary_core": (
            "CloudTrail S3 data events show elevated object-read activity for one "
            "principal and bucket."
        ),
        "trigger_events": s3_events,
    })
    if s3_dict is not None:
        _o5, s3_signal = signal_svc.upsert_incident_signal(
            workspace_id=workspace_id, signal=s3_dict, db=db)
        extra_signals.append(s3_signal)

    # (d) VPC Flow Log network activity → VPC flow signal.
    vpc_events = [
        _demo_activity(
            source="vpc_flow_log", event_type="aws.vpc.flow.accept",
            resource_type="aws_network_interface", resource_id=AWS_DEMO_ENI,
            actor_type="network_flow",
            metadata={"interface_id": AWS_DEMO_ENI, "dst_port": 22, "protocol": 6,
                      "bytes": 4096, "packets": 12, "action": "ACCEPT",
                      "aws_region": AWS_DEMO_REGION},
        )
        for _ in range(3)
    ]
    extra_activity.append(vpc_events[0])
    vpc_dict = vpc_flow_svc.build_vpc_flow_signal(events=vpc_events, match={
        "pattern": "sensitive_port_accept",
        "signal_key": "aws.vpc_flow.sensitive_port_accept",
        "severity": "high",
        "phrase": "Accepted network flow to sensitive port",
        "summary_core": (
            "VPC Flow Logs show accepted network flow activity to a sensitive "
            "destination port."
        ),
        "trigger_events": vpc_events,
    })
    if vpc_dict is not None:
        _o6, vpc_signal = signal_svc.upsert_incident_signal(
            workspace_id=workspace_id, signal=vpc_dict, db=db)
        extra_signals.append(vpc_signal)

    # 7. Case linking all the evidence (marked demo via metadata.source).
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="[Demo] AWS incident investigation",
        summary=(
            "Demo investigation case. It groups AWS security evidence across a "
            "configuration risk, provider-reported findings (Access Analyzer and "
            "Security Hub), CloudTrail management activity, S3 object-level activity, "
            "and VPC network-flow activity into review signals. This is a "
            "human-reviewed case presenting evidence for review — ConfigTrace does "
            "not read raw customer data and does not automatically confirm "
            "compromise, exfiltration, or intrusion."
        ),
        severity=correlation.severity,
        provider="aws",
        metadata={"source": AWS_DEMO_CASE_SOURCE, "bucket": AWS_DEMO_BUCKET},
        db=db,
    )
    case_svc.link_object_to_case(case=case, object_type="correlation", object_id=correlation.id, actor_user_id=actor_user_id, db=db)
    case_svc.link_object_to_case(case=case, object_type="finding", object_id=finding.id, actor_user_id=actor_user_id, db=db)
    case_svc.link_object_to_case(case=case, object_type="activity_event", object_id=activity.id, actor_user_id=actor_user_id, db=db)
    if aws_signal is not None:
        case_svc.link_object_to_case(case=case, object_type="signal", object_id=aws_signal.id, actor_user_id=actor_user_id, db=db)
    # Link the richer AWS evidence (one representative activity event per source +
    # each derived review signal) so the case + report span every AWS layer.
    for sig in extra_signals:
        case_svc.link_object_to_case(case=case, object_type="signal", object_id=sig.id, actor_user_id=actor_user_id, db=db)
    for ev in extra_activity:
        case_svc.link_object_to_case(case=case, object_type="activity_event", object_id=ev.id, actor_user_id=actor_user_id, db=db)

    logger.info("aws_incident_demo: seeded workspace=%s case=%s", workspace_id, case.id)
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_aws(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the AWS demo incident objects (and nothing else)."""
    # 1. AWS demo cases (+ their links).
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == AWS_DEMO_CASE_SOURCE,
        )
        .all()
    )
    case_ids = [c.id for c in demo_cases]
    if case_ids:
        db.query(SecurityCaseLink).filter(
            SecurityCaseLink.case_id.in_(case_ids)
        ).delete(synchronize_session=False)
        db.query(SecurityCase).filter(
            SecurityCase.id.in_(case_ids)
        ).delete(synchronize_session=False)

    # 2. AWS demo evidence anchored on the hidden AWS demo integration.
    integ = get_aws_demo_integration(workspace_id, db)
    if integ is not None:
        finding_ids = [
            f.id for f in db.query(SecurityFinding).filter(
                SecurityFinding.integration_id == integ.id
            ).all()
        ]
        activity_ids = [
            a.id for a in db.query(SecurityActivityEvent).filter(
                SecurityActivityEvent.integration_id == integ.id
            ).all()
        ]
        corr_conds = []
        if finding_ids:
            corr_conds.append(SecuritySignalCorrelation.linked_finding_id.in_(finding_ids))
        if activity_ids:
            corr_conds.append(SecuritySignalCorrelation.linked_activity_event_id.in_(activity_ids))
        if corr_conds:
            db.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                or_(*corr_conds),
            ).delete(synchronize_session=False)
        sig_conds = [SecurityIncidentSignal.integration_id == integ.id]
        if activity_ids:
            sig_conds.append(SecurityIncidentSignal.linked_activity_event_id.in_(activity_ids))
        db.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == workspace_id,
            or_(*sig_conds),
        ).delete(synchronize_session=False)
        db.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id
        ).delete(synchronize_session=False)
        db.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id
        ).delete(synchronize_session=False)
        db.query(Resource).filter(
            Resource.integration_id == integ.id
        ).delete(synchronize_session=False)
        db.query(Integration).filter(
            Integration.id == integ.id
        ).delete(synchronize_session=False)

    db.commit()
    return {"cleared": True}
