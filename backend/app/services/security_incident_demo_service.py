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
from app.services import cloudflare_waf_signal_service as cf_waf_signal_svc
from app.services import vercel_activity_signal_service as ve_sig
from app.services import supabase_activity_signal_service as sb_sig
from app.services import firebase_activity_signal_service as fb_sig
from app.services import stripe_activity_signal_service as st_sig
from app.services import shopify_activity_signal_service as sh_sig
from app.services import azure_activity_signal_service as az_sig
from app.services import google_cloud_activity_signal_service as gcp_sig
from app.services import twilio_activity_signal_service as twilio_sig
from app.services import twilio_risk_activity_correlation_service as twilio_corr_svc
from app.services import sendgrid_activity_signal_service as sg_sig
from app.services import sendgrid_risk_activity_correlation_service as sg_corr_svc
from app.services import auth0_activity_signal_service as auth0_sig
from app.services import auth0_risk_activity_correlation_service as auth0_corr_svc
from app.services import datadog_activity_signal_service as dd_sig
from app.services import datadog_risk_activity_correlation_service as dd_corr_svc
from app.services import clerk_activity_signal_service as clerk_sig
from app.services import clerk_risk_activity_correlation_service as clerk_corr_svc
from app.services import pagerduty_activity_signal_service as pd_sig
from app.services import pagerduty_risk_activity_correlation_service as pd_corr_svc
from app.services import linear_activity_signal_service as linear_sig
from app.services import linear_risk_activity_correlation_service as linear_corr_svc
from app.services import jira_activity_signal_service as jira_sig
from app.services import jira_risk_activity_correlation_service as jira_corr_svc

logger = logging.getLogger(__name__)

DEMO_PROVIDER_TAG = "demo"
DEMO_INTEGRATION_NAME = "ConfigTrace incident demo (sample data)"
DEMO_REPO = "configtrace-demo/incident-repo"
DEMO_CASE_SOURCE = "demo_incident"
# Synthetic, clearly demo-only advisory / rule identifiers for the expanded
# GitHub story (M69.6). None reference a real secret, token, or advisory.
DEMO_GHSA_ID = "GHSA-demo-0000-0000"
DEMO_CVE_ID = "CVE-0000-00000"

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

# ── Cloudflare incident demo (M68.7) — a SEPARATE hidden demo integration + case
# source so "Clear Cloudflare demo" removes only Cloudflare demo objects and never
# touches the GitHub or AWS demos. Same safety rules: clearly marked demo, no real
# sync, no notifications, never touches a real Cloudflare integration, idempotent.
# The chain is one coherent Cloudflare story anchored on a disabled WAF rule:
#   Config risk (WAF rule disabled) → audit activity (waf_rule.changed) → WAF
#   security activity (waf_event.block) → audit-activity signal + WAF-activity
#   signal → audit correlation (cloudflare_waf_change) + WAF correlation
#   (cloudflare_waf_risk_activity) → human-reviewed case → report.
CF_DEMO_INTEGRATION_NAME = "ConfigTrace Cloudflare incident demo (sample data)"
CF_DEMO_CASE_SOURCE = "demo_cloudflare_incident"
CF_DEMO_ZONE_ID = "configtrace-demo-zone"             # sample zone id (not real)
CF_DEMO_ZONE_NAME = "demo.configtrace.test"           # sample zone (RFC test TLD)
CF_DEMO_HOST = "app.demo.configtrace.test"            # sample request host
CF_DEMO_RULE_ID = "configtrace-demo-waf-rule"         # sample WAF rule id
CF_DEMO_RULE_NAME = "Block SQL injection (demo)"      # sample WAF rule name
CF_DEMO_RULESET_ID = "configtrace-demo-ruleset"       # sample ruleset id


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

    # ── Helper: build + upsert a demo activity/alert event on the demo repo. ──
    def _mk_event(source: str, event_type: str, *, actor=None, metadata):
        meta = {"repository": DEMO_REPO, "repository_full_name": DEMO_REPO}
        meta.update(metadata)
        norm = activity_svc.normalize_activity_event(
            provider="github", source=source, event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=f"demo-{uuid.uuid4().hex[:10]}",
            actor_id=actor, actor_type="user" if actor else None,
            resource_type="repository", resource_id=DEMO_REPO, metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id, normalized=norm, db=db
        )
        return row

    # ── Helper: upsert a correlation dict + link it (and its signal) to a case. ─
    correlations: list = []

    def _add_correlation(corr_dict: dict):
        _o, c = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=corr_dict, db=db
        )
        correlations.append(c)
        return c

    # 3. Configuration-risk findings (demo-tagged) — repo / ruleset / automation.
    webhook_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="github",
        finding_key=f"github_webhook_http:{DEMO_REPO}#demo", severity="high",
        title="Demo: GitHub webhook delivered over plain HTTP", resource_id=resource.id,
        description="Sample repository configuration risk for the incident-workflow demo.",
        evidence={"rule": "github_webhook_http", "demo": True, "repository": DEMO_REPO},
        remediation={"summary": "Switch the webhook to HTTPS."},
    )
    ruleset_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="github",
        finding_key=f"github_ruleset_not_enforced:{DEMO_REPO}#demo", severity="high",
        title="Demo: GitHub ruleset is not actively enforced", resource_id=resource.id,
        description="Sample ruleset posture risk for the incident-workflow demo.",
        evidence={"rule": "github_ruleset_not_enforced", "demo": True,
                  "ruleset_name": "Protect main (demo)", "enforcement": "disabled",
                  "target": "branch", "targets_protected_branch": True},
        remediation={"summary": "Set the ruleset enforcement status to 'Active'."},
    )
    automation_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="github",
        finding_key=f"github_automation_admin_permission:{DEMO_REPO}#demo", severity="high",
        title="Demo: GitHub automation credential has admin repository permission",
        resource_id=resource.id,
        description="Sample automation permission risk for the incident-workflow demo.",
        evidence={"rule": "github_automation_admin_permission", "demo": True,
                  "credential_type": "github_token", "broad_permission_count": 2},
        remediation={"summary": "Reduce the automation credential to least privilege."},
    )

    # 4. Evidence events on the same repo: audit activity + security alerts.
    webhook_activity = _mk_event(
        "audit_log", "github.webhook.updated", actor="demo-admin",
        metadata={"action": "hook.config_changed"})
    ruleset_activity = _mk_event(
        "audit_log", "github.ruleset.changed", actor="demo-admin",
        metadata={"action": "ruleset.updated"})
    deploy_key_activity = _mk_event(
        "audit_log", "github.deploy_key.added", actor="demo-admin",
        metadata={"action": "deploy_key.create"})
    secret_alert = _mk_event(
        "secret_scanning_alert", "github.secret_scanning.alert.open",
        metadata={"alert_number": 1, "state": "open",
                  "secret_type": "github_personal_access_token",
                  "secret_type_display_name": "GitHub Personal Access Token (demo)",
                  "validity": "unknown", "publicly_leaked": False})
    code_alert = _mk_event(
        "code_scanning_alert", "github.code_scanning.alert.open",
        metadata={"alert_number": 2, "state": "open", "rule_id": "demo/sql-injection",
                  "rule_name": "Database query from user input (demo)",
                  "tool_name": "CodeQL", "security_severity_level": "high"})
    dependabot_alert = _mk_event(
        "dependabot_alert", "github.dependabot.alert.open",
        metadata={"alert_number": 3, "state": "open",
                  "dependency_package_name": "demo-lib", "dependency_ecosystem": "npm",
                  "advisory_ghsa_id": DEMO_GHSA_ID, "advisory_cve_id": DEMO_CVE_ID,
                  "advisory_severity": "high"})

    # 5. Incident signals from the audit activity events.
    audit_signals = []
    for ev in (webhook_activity, ruleset_activity, deploy_key_activity):
        s = signal_svc.build_signal_from_activity_event(ev)
        if s is not None:
            _o, srow = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=s, db=db)
            audit_signals.append(srow)

    # 6. Correlations (built directly for the demo objects — never scans real data).
    #    Each upsert_correlation also creates a correlation-evidence signal.
    _add_correlation(corr_svc.build_correlation(
        finding=webhook_finding, event=webhook_activity, repo=DEMO_REPO,
        rule=corr_svc.CORRELATION_RULES["github_webhook_http"]))
    _add_correlation(corr_svc.build_secret_scanning_correlation(
        finding=webhook_finding, event=secret_alert, repo=DEMO_REPO,
        rule=corr_svc.SECRET_SCANNING_CORRELATION_RULES["github_webhook_http"]))
    _add_correlation(corr_svc.build_code_scanning_correlation(
        finding=webhook_finding, event=code_alert, repo=DEMO_REPO,
        rule=corr_svc.CODE_SCANNING_CORRELATION_RULES["github_webhook_http"]))
    _add_correlation(corr_svc.build_dependabot_correlation(
        finding=webhook_finding, event=dependabot_alert, repo=DEMO_REPO,
        rule=corr_svc.DEPENDABOT_CORRELATION_RULES["github_webhook_http"]))
    _add_correlation(corr_svc.build_ruleset_activity_correlation(
        finding=ruleset_finding, event=ruleset_activity, repo=DEMO_REPO))
    _add_correlation(corr_svc.build_automation_security_alert_correlation(
        finding=automation_finding, event=code_alert, repo=DEMO_REPO))

    top_severity = "high"

    # 7. Case linking all the evidence (marked demo via metadata.source).
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="[Demo] GitHub incident investigation",
        summary=(
            "Demo investigation case. Repository protection and automation posture "
            "risks on a GitHub repository align with security-alert evidence "
            "(secret-scanning, code-scanning, Dependabot) and control-plane audit "
            "activity on the same repo. This is a human-reviewed case presenting "
            "evidence for review — ConfigTrace does not automatically confirm "
            "compromise or unauthorized access."
        ),
        severity=top_severity,
        provider="github",
        metadata={"source": DEMO_CASE_SOURCE, "repository": DEMO_REPO},
        db=db,
    )
    for f in (webhook_finding, ruleset_finding, automation_finding):
        case_svc.link_object_to_case(case=case, object_type="finding", object_id=f.id,
                                     actor_user_id=actor_user_id, db=db)
    for ev in (webhook_activity, ruleset_activity, deploy_key_activity,
               secret_alert, code_alert, dependabot_alert):
        case_svc.link_object_to_case(case=case, object_type="activity_event",
                                     object_id=ev.id, actor_user_id=actor_user_id, db=db)
    linked_signal_ids: set = set()
    for s in audit_signals:
        linked_signal_ids.add(s.id)
    for c in correlations:
        case_svc.link_object_to_case(case=case, object_type="correlation",
                                     object_id=c.id, actor_user_id=actor_user_id, db=db)
        if c.linked_signal_id is not None:
            linked_signal_ids.add(c.linked_signal_id)
    for sid in linked_signal_ids:
        case_svc.link_object_to_case(case=case, object_type="signal", object_id=sid,
                                     actor_user_id=actor_user_id, db=db)

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
# Cloudflare incident demo (M68.7)
# ───────────────────────────────────────────────────────────────────────────────


def get_cloudflare_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == CF_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_cf_demo_case(workspace_id: uuid.UUID, db: Session) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == CF_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_cloudflare_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_cf_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_cloudflare(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Cloudflare demo incident chain (idempotent). No real sync.

    One coherent Cloudflare story anchored on a disabled protective WAF rule:
      Configuration Risk (WAF rule disabled) → Cloudflare audit activity
      (cloudflare.waf_rule.changed) → Cloudflare WAF/security activity
      (cloudflare.waf_event.block) → Cloudflare audit-activity Incident Signal +
      Cloudflare WAF/security Incident Signal → Cloudflare risk × audit-activity
      correlation + Cloudflare risk × WAF/security-activity correlation → Case.

    All objects are anchored on a hidden demo integration so ``clear_cloudflare``
    removes them and nothing else. Evidence is built directly for the demo objects
    (never by scanning the real workspace).
    """
    existing = _existing_cf_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" → never shown / never synced).
    integ = get_cloudflare_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({"demo": True, "dataset": "cloudflare_incident_demo_v1"})
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=CF_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    # 2. Demo Cloudflare zone resource.
    resource = Resource(
        integration_id=integ.id,
        user_id=actor_user_id,
        provider_resource_type="cloudflare_zone",
        provider_resource_id=CF_DEMO_ZONE_ID,
        display_name=CF_DEMO_ZONE_NAME,
        is_active=True,
    )
    db.add(resource)
    db.flush()

    # 3. Configuration Risk finding: a protective WAF rule is disabled.
    finding = finding_svc.upsert_active_finding(
        db=db,
        workspace_id=workspace_id,
        integration_id=integ.id,
        provider="cloudflare",
        finding_key=f"cloudflare_waf_rule_disabled:{CF_DEMO_ZONE_ID}#demo",
        severity="high",
        title="Demo: Cloudflare WAF rule is disabled",
        resource_id=resource.id,
        description="Sample Cloudflare configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "cloudflare_waf_rule_disabled",
            "demo": True,
            "description": CF_DEMO_RULE_NAME,
            "action": "block",
            "enabled": False,
            "ruleset_id": CF_DEMO_RULESET_ID,
        },
        remediation={"summary": "Re-enable the protective WAF rule if it should be active."},
    )

    # 4. Cloudflare audit activity: the WAF rule was changed (control-plane).
    audit_norm = activity_svc.normalize_activity_event(
        provider="cloudflare",
        source="audit_log",
        event_type="cloudflare.waf_rule.changed",
        occurred_at=_utcnow(),
        provider_event_id=f"demo-cf-audit-{uuid.uuid4().hex[:8]}",
        actor_id="demo-admin@configtrace.test",
        actor_type="user",
        resource_type="cloudflare_zone",
        resource_id=CF_DEMO_ZONE_ID,
        metadata={
            "zone_id": CF_DEMO_ZONE_ID,
            "zone_name": CF_DEMO_ZONE_NAME,
            "rule_id": CF_DEMO_RULE_ID,
            "rule_name": CF_DEMO_RULE_NAME,
            "ruleset_id": CF_DEMO_RULESET_ID,
            "action": "disable",
            "actor": "demo-admin@configtrace.test",
            "outcome": "success",
        },
    )
    _ao, audit_event = activity_svc.upsert_activity_event(
        workspace_id=workspace_id, integration_id=integ.id, normalized=audit_norm, db=db
    )

    # 5. Cloudflare audit-activity Incident Signal from the audit event.
    audit_signal = None
    audit_sig_dict = signal_svc.build_cloudflare_signal_from_activity_event(audit_event)
    if audit_sig_dict is not None:
        _aso, audit_signal = signal_svc.upsert_incident_signal(
            workspace_id=workspace_id, signal=audit_sig_dict, db=db
        )

    # 6. Cloudflare WAF/security activity: a burst of blocked requests for the same
    #    rule/host (a small representative set — not noise).
    def _waf_event(idx: int):
        norm = activity_svc.normalize_activity_event(
            provider="cloudflare",
            source="waf_security_event",
            event_type="cloudflare.waf_event.block",
            occurred_at=_utcnow(),
            provider_event_id=f"demo-cfwaf-{uuid.uuid4().hex[:12]}",
            actor_id=None,
            actor_type="waf_event",
            resource_type="cloudflare_zone",
            resource_id=CF_DEMO_ZONE_ID,
            metadata={
                "action": "block",
                "rule_id": CF_DEMO_RULE_ID,
                "rule_name": CF_DEMO_RULE_NAME,
                "ruleset_id": CF_DEMO_RULESET_ID,
                "host": CF_DEMO_HOST,
                "path_prefix": "login",
                "method": "POST",
                "client_country": "US",
                "service": "waf",
                "outcome": "block",
                "event_source": "cloudflare_waf",
                "zone_id": CF_DEMO_ZONE_ID,
                "zone_name": CF_DEMO_ZONE_NAME,
            },
        )
        _wo, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id, normalized=norm, db=db
        )
        return row

    waf_events = [_waf_event(i) for i in range(6)]

    # 7. Cloudflare WAF/security-activity Incident Signal (built directly).
    waf_signal = None
    waf_sig_dict = cf_waf_signal_svc.build_waf_signal(match={
        "pattern": "repeated_rule_activity",
        "signal_key": "cloudflare.waf.repeated_rule_activity",
        "severity": "medium",
        "phrase": "Repeated Cloudflare WAF rule activity",
        "summary_core": (
            "Cloudflare WAF events show repeated blocked-request activity for one "
            "WAF rule."
        ),
        "trigger_events": waf_events,
    })
    if waf_sig_dict is not None:
        _wso, waf_signal = signal_svc.upsert_incident_signal(
            workspace_id=workspace_id, signal=waf_sig_dict, db=db
        )

    # 8. Cloudflare risk × audit-activity correlation (M68.2).
    audit_rule = corr_svc.CLOUDFLARE_CORRELATION_RULES["cloudflare_waf_rule_disabled"]
    audit_corr_dict = corr_svc.build_cloudflare_correlation(
        finding=finding, event=audit_event, rule=audit_rule
    )
    _aco, audit_corr = corr_svc.upsert_correlation(
        workspace_id=workspace_id, correlation=audit_corr_dict, db=db
    )

    # 9. Cloudflare risk × WAF/security-activity correlation (M68.6).
    waf_rule = corr_svc.CLOUDFLARE_WAF_CORRELATION_RULES["cloudflare_waf_rule_disabled"]
    waf_corr_dict = corr_svc.build_cloudflare_waf_correlation(
        finding=finding, anchor=waf_events[0], matched=waf_events, rule=waf_rule
    )
    _wco, waf_corr = corr_svc.upsert_correlation(
        workspace_id=workspace_id, correlation=waf_corr_dict, db=db
    )

    # 10. Case linking all the evidence (marked demo via metadata.source).
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="[Demo] Cloudflare incident investigation",
        summary=(
            "Demo investigation case. It groups Cloudflare security evidence: a "
            "configuration risk (a disabled protective WAF rule), Cloudflare account "
            "audit activity showing the control-plane change, and Cloudflare "
            "WAF/security activity (blocked requests) for the same zone and rule — "
            "turned into review signals and correlations. This is a human-reviewed "
            "case presenting evidence for review — ConfigTrace does not automatically "
            "confirm compromise, unauthorized access, an attack, or an exploit."
        ),
        severity=waf_corr.severity,
        provider="cloudflare",
        metadata={"source": CF_DEMO_CASE_SOURCE, "repository": CF_DEMO_ZONE_NAME},
        db=db,
    )
    case_svc.link_object_to_case(case=case, object_type="correlation", object_id=audit_corr.id, actor_user_id=actor_user_id, db=db)
    case_svc.link_object_to_case(case=case, object_type="correlation", object_id=waf_corr.id, actor_user_id=actor_user_id, db=db)
    case_svc.link_object_to_case(case=case, object_type="finding", object_id=finding.id, actor_user_id=actor_user_id, db=db)
    case_svc.link_object_to_case(case=case, object_type="activity_event", object_id=audit_event.id, actor_user_id=actor_user_id, db=db)
    case_svc.link_object_to_case(case=case, object_type="activity_event", object_id=waf_events[0].id, actor_user_id=actor_user_id, db=db)
    if audit_signal is not None:
        case_svc.link_object_to_case(case=case, object_type="signal", object_id=audit_signal.id, actor_user_id=actor_user_id, db=db)
    if waf_signal is not None:
        case_svc.link_object_to_case(case=case, object_type="signal", object_id=waf_signal.id, actor_user_id=actor_user_id, db=db)
    # Correlation-evidence signals (auto-created by upsert_correlation) complete the
    # signal layer (evidence_level="correlation").
    for corr in (audit_corr, waf_corr):
        if corr.linked_signal_id is not None:
            case_svc.link_object_to_case(case=case, object_type="signal", object_id=corr.linked_signal_id, actor_user_id=actor_user_id, db=db)

    logger.info("cloudflare_incident_demo: seeded workspace=%s case=%s", workspace_id, case.id)
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_cloudflare(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the Cloudflare demo incident objects (and nothing else)."""
    # 1. Cloudflare demo cases (+ their links).
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == CF_DEMO_CASE_SOURCE,
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

    # 2. Cloudflare demo evidence anchored on the hidden Cloudflare demo integration.
    integ = get_cloudflare_demo_integration(workspace_id, db)
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


# ───────────────────────────────────────────────────────────────────────────────
# Vercel incident demo (M70E)
# ───────────────────────────────────────────────────────────────────────────────
#
# A SEPARATE hidden demo integration + case source so "Clear Vercel demo" removes
# only Vercel demo objects and never touches the GitHub / AWS / Cloudflare demos
# or any real evidence. Same safety rules: clearly marked demo, no real sync, no
# notifications, never touches a real Vercel integration, idempotent. One coherent
# Vercel story anchored on the same project:
#   Config risks (production branch unusual + sensitive env var broadly scoped +
#   deploy hook targets production) -> Vercel audit activity (project.updated +
#   env_var.updated + deploy_hook.created) -> Vercel activity Incident Signals ->
#   Vercel risk x activity correlations -> human-reviewed case -> report.

VERCEL_DEMO_INTEGRATION_NAME = "ConfigTrace Vercel incident demo (sample data)"
VERCEL_DEMO_CASE_SOURCE = "demo_vercel_incident"
VERCEL_DEMO_PROJECT_ID = "prj_configtrace_demo"        # sample Vercel project id
VERCEL_DEMO_PROJECT_NAME = "configtrace-demo-app"      # sample project slug
VERCEL_DEMO_BRANCH = "develop"                          # non-production branch
VERCEL_DEMO_ENV_KEY = "DEMO_DATABASE_PASSWORD"         # secret-suggestive KEY NAME only
VERCEL_DEMO_HOOK_NAME = "demo-nightly-production"      # deploy hook name (never the URL)


def get_vercel_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == VERCEL_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_vercel_demo_case(workspace_id: uuid.UUID, db: Session) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == VERCEL_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_vercel_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_vercel_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_vercel(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Vercel demo incident chain (idempotent). No real sync.

    One coherent Vercel story anchored on the same demo project:
      Configuration Risks (production branch looks non-production + a
      secret-suggestive env var broadly scoped + a deploy hook targeting the
      production branch) -> Vercel audit activity (project.updated + env_var.updated
      + deploy_hook.created) -> Vercel activity Incident Signals -> Vercel risk x
      activity correlations -> Case.

    All objects are anchored on a hidden demo integration so ``clear_vercel``
    removes them and nothing else. Evidence is built directly for the demo
    objects (never by scanning the real workspace). NEVER stores env var values,
    deploy hook URLs, tokens, headers, raw payloads, or actor emails.
    """
    existing = _existing_vercel_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" -> never shown / never synced).
    integ = get_vercel_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({"demo": True, "dataset": "vercel_incident_demo_v1"})
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=VERCEL_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    # 2. Demo Vercel project resource (provider_resource_id == project id).
    resource = Resource(
        integration_id=integ.id,
        user_id=actor_user_id,
        provider_resource_type="vercel_project",
        provider_resource_id=VERCEL_DEMO_PROJECT_ID,
        display_name=VERCEL_DEMO_PROJECT_NAME,
        is_active=True,
    )
    db.add(resource)
    db.flush()

    # 3. Configuration Risk findings on the same project.
    branch_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="vercel",
        finding_key=f"vercel_production_branch_unusual:{VERCEL_DEMO_PROJECT_ID}#demo",
        severity="medium", title="Demo: Vercel production branch looks non-production",
        resource_id=resource.id,
        description="Sample Vercel configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "vercel_production_branch_unusual", "demo": True,
            "project": VERCEL_DEMO_PROJECT_NAME, "production_branch": VERCEL_DEMO_BRANCH,
        },
        remediation={"summary": "Confirm the production branch is intentional."},
    )
    env_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="vercel",
        finding_key=f"vercel_sensitive_env_var_broad_scope:{VERCEL_DEMO_PROJECT_ID}#demo",
        severity="high", title="Demo: Sensitive-looking Vercel env var is broadly scoped",
        resource_id=resource.id,
        description="Sample Vercel configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "vercel_sensitive_env_var_broad_scope", "demo": True,
            "env_var_name": VERCEL_DEMO_ENV_KEY, "target": ["preview", "production"],
        },
        remediation={"summary": "Scope sensitive env vars to production only."},
    )
    hook_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="vercel",
        finding_key=f"vercel_deploy_hook_production_branch:{VERCEL_DEMO_PROJECT_ID}#deploy_hook#demo",
        severity="medium", title="Demo: Vercel deploy hook targets the production branch",
        resource_id=resource.id,
        description="Sample Vercel configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "vercel_deploy_hook_production_branch", "demo": True,
            "hook_name": VERCEL_DEMO_HOOK_NAME, "hook_ref": "main",
        },
        remediation={"summary": "Confirm production deploy hooks are intended."},
    )

    # 4. Vercel audit activity (control-plane changes) for the same project.
    def _mk_event(event_type, action, **md):
        meta = {
            "project_id": VERCEL_DEMO_PROJECT_ID,
            "project_name": VERCEL_DEMO_PROJECT_NAME,
            "team_id": "team_configtrace_demo",
            "event_action": action,
            "event_source": "vercel_audit_log",
        }
        meta.update(md)
        norm = activity_svc.normalize_activity_event(
            provider="vercel", source="audit_log", event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=f"demo-vercel-{uuid.uuid4().hex[:10]}",
            actor_id=None, actor_type="user",
            resource_type=md.get("target_type") or "project",
            resource_id=md.get("target_id") or VERCEL_DEMO_PROJECT_ID,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id, normalized=norm, db=db
        )
        return row

    project_event = _mk_event(
        "vercel.project.updated", "project.update",
        target_type="project", target_id=VERCEL_DEMO_PROJECT_ID,
        target_name=VERCEL_DEMO_PROJECT_NAME, branch=VERCEL_DEMO_BRANCH,
    )
    env_event = _mk_event(
        "vercel.env_var.updated", "env.update",
        target_type="env", env_var_key=VERCEL_DEMO_ENV_KEY,
    )
    hook_event = _mk_event(
        "vercel.deploy_hook.created", "deployHook.create",
        target_type="deploy_hook", deploy_hook_name=VERCEL_DEMO_HOOK_NAME, branch="main",
    )

    # 5. Vercel activity Incident Signals (built directly from each event).
    signals = []
    for ev in (project_event, env_event, hook_event):
        sig_dict = ve_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db
            )
            signals.append(sig)

    # 6. Vercel risk x activity correlations (M70D), built directly.
    def _add_correlation(finding, event):
        rule = corr_svc.VERCEL_CORRELATION_RULES[corr_svc._base_rule(finding.finding_key)]
        cdict = corr_svc.build_vercel_correlation(
            finding=finding, event=event, project_key=VERCEL_DEMO_PROJECT_ID, rule=rule
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db
        )
        return corr

    branch_corr = _add_correlation(branch_finding, project_event)
    env_corr = _add_correlation(env_finding, env_event)
    hook_corr = _add_correlation(hook_finding, hook_event)

    # 7. Case linking all the evidence (marked demo via metadata.source).
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="[Demo] Vercel incident investigation",
        summary=(
            "Demo investigation case. It groups Vercel security evidence: "
            "configuration risks (a non-production production branch, a "
            "secret-suggestive environment variable scoped beyond production, and "
            "a deploy hook targeting the production branch), and Vercel audit "
            "activity (project, environment-variable, and deploy-hook changes) for "
            "the same project - turned into review signals and correlations. This "
            "is a human-reviewed case presenting evidence for review and may "
            "require review. ConfigTrace does not confirm compromise or "
            "unauthorized access."
        ),
        severity=env_corr.severity,
        provider="vercel",
        metadata={"source": VERCEL_DEMO_CASE_SOURCE, "repository": VERCEL_DEMO_PROJECT_NAME},
        db=db,
    )
    for corr in (branch_corr, env_corr, hook_corr):
        case_svc.link_object_to_case(case=case, object_type="correlation", object_id=corr.id, actor_user_id=actor_user_id, db=db)
    for finding in (branch_finding, env_finding, hook_finding):
        case_svc.link_object_to_case(case=case, object_type="finding", object_id=finding.id, actor_user_id=actor_user_id, db=db)
    for ev in (project_event, env_event, hook_event):
        case_svc.link_object_to_case(case=case, object_type="activity_event", object_id=ev.id, actor_user_id=actor_user_id, db=db)
    for sig in signals:
        case_svc.link_object_to_case(case=case, object_type="signal", object_id=sig.id, actor_user_id=actor_user_id, db=db)
    # Correlation-evidence signals (auto-created by upsert_correlation).
    for corr in (branch_corr, env_corr, hook_corr):
        if corr.linked_signal_id is not None:
            case_svc.link_object_to_case(case=case, object_type="signal", object_id=corr.linked_signal_id, actor_user_id=actor_user_id, db=db)

    logger.info("vercel_incident_demo: seeded workspace=%s case=%s", workspace_id, case.id)
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_vercel(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the Vercel demo incident objects (and nothing else)."""
    # 1. Vercel demo cases (+ their links).
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == VERCEL_DEMO_CASE_SOURCE,
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

    # 2. Vercel demo evidence anchored on the hidden Vercel demo integration.
    integ = get_vercel_demo_integration(workspace_id, db)
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


# ── Supabase incident demo (M71E) ─────────────────────────────────────────────

SUPABASE_DEMO_INTEGRATION_NAME = "ConfigTrace Supabase incident demo (sample data)"
SUPABASE_DEMO_CASE_SOURCE = "demo_supabase_incident"
SUPABASE_DEMO_PROJECT_REF = "demoref_configtrace00"   # sample project ref (not real)
SUPABASE_DEMO_PROJECT_NAME = "configtrace-demo-db"    # sample project name
SUPABASE_DEMO_SCHEMA = "public"
SUPABASE_DEMO_TABLE_CUSTOMERS = "customers"           # sensitive-looking table NAME only
SUPABASE_DEMO_TABLE_ORDERS = "orders"                 # table NAME only (never row data)
SUPABASE_DEMO_FUNCTION = "admin-webhook"              # Edge Function NAME only (never source/env)


def get_supabase_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == SUPABASE_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_supabase_demo_case(workspace_id: uuid.UUID, db: Session) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == SUPABASE_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_supabase_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_supabase_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_supabase(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Supabase demo incident chain (idempotent). No real sync.

    One coherent Supabase story anchored on the same demo project:
      Configuration Risks (RLS disabled on a sensitive table + a public/anon
      SELECT policy on it + a public write policy on another table + an Edge
      Function with JWT verification disabled + leaked-password protection off)
      -> Supabase audit activity (rls / policy / edge-function / auth-config
      changes) for the same table/function/project -> Supabase activity Incident
      Signals -> Supabase risk x activity correlations -> Case.

    All objects are anchored on a hidden demo integration so ``clear_supabase``
    removes them and nothing else. Evidence is built directly for the demo
    objects (never by scanning the real workspace). Metadata is NAMES only —
    NEVER database row data, SQL result rows, auth users, emails, JWT secrets,
    service-role/anon keys, db passwords, tokens, headers, raw API responses,
    policy expressions, or Edge Function env var values.
    """
    existing = _existing_supabase_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" -> never shown / never synced).
    integ = get_supabase_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({"demo": True, "dataset": "supabase_incident_demo_v1"})
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=SUPABASE_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    # 2. Demo Supabase project resource (provider_resource_id == project ref).
    resource = Resource(
        integration_id=integ.id,
        user_id=actor_user_id,
        provider_resource_type="supabase_project",
        provider_resource_id=SUPABASE_DEMO_PROJECT_REF,
        display_name=SUPABASE_DEMO_PROJECT_NAME,
        is_active=True,
    )
    db.add(resource)
    db.flush()

    # 3. Configuration Risk findings on the same project (names/booleans only).
    rls_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="supabase",
        finding_key=f"supabase_rls_disabled:{SUPABASE_DEMO_PROJECT_REF}#{SUPABASE_DEMO_TABLE_CUSTOMERS}#demo",
        severity="high", title="Demo: Supabase table has Row Level Security disabled",
        resource_id=resource.id,
        description="Sample Supabase configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "supabase_rls_disabled", "demo": True,
            "schema": SUPABASE_DEMO_SCHEMA, "table": SUPABASE_DEMO_TABLE_CUSTOMERS,
        },
        remediation={"summary": "Enable Row Level Security and add explicit policies."},
    )
    select_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="supabase",
        finding_key=f"supabase_public_select_sensitive_table:{SUPABASE_DEMO_PROJECT_REF}#{SUPABASE_DEMO_TABLE_CUSTOMERS}#demo",
        severity="high", title="Demo: Supabase public read policy on a sensitive-looking table",
        resource_id=resource.id,
        description="Sample Supabase configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "supabase_public_select_sensitive_table", "demo": True,
            "schema": SUPABASE_DEMO_SCHEMA, "table": SUPABASE_DEMO_TABLE_CUSTOMERS,
            "policy_count": 2,
        },
        remediation={"summary": "Scope read access away from the public/anon role."},
    )
    write_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="supabase",
        finding_key=f"supabase_public_write_policy:{SUPABASE_DEMO_PROJECT_REF}#{SUPABASE_DEMO_TABLE_ORDERS}#demo",
        severity="high", title="Demo: Supabase public write policy on a table",
        resource_id=resource.id,
        description="Sample Supabase configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "supabase_public_write_policy", "demo": True,
            "schema": SUPABASE_DEMO_SCHEMA, "table": SUPABASE_DEMO_TABLE_ORDERS,
            "policy_count": 1,
        },
        remediation={"summary": "Restrict write access away from the public/anon role."},
    )
    fn_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="supabase",
        finding_key=f"supabase_edge_function_jwt_disabled:{SUPABASE_DEMO_PROJECT_REF}#{SUPABASE_DEMO_FUNCTION}#demo",
        severity="high", title="Demo: Supabase Edge Function has JWT verification disabled",
        resource_id=resource.id,
        description="Sample Supabase configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "supabase_edge_function_jwt_disabled", "demo": True,
            "function_name": SUPABASE_DEMO_FUNCTION, "verify_jwt": False,
        },
        remediation={"summary": "Enable JWT verification unless the function is intentionally public."},
    )
    auth_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="supabase",
        finding_key=f"supabase_auth_protection_missing:{SUPABASE_DEMO_PROJECT_REF}#auth#demo",
        severity="medium", title="Demo: Supabase leaked-password protection is disabled",
        resource_id=resource.id,
        description="Sample Supabase configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "supabase_auth_protection_missing", "demo": True,
            "leaked_password_protection_enabled": False, "mfa_totp_enabled": False,
        },
        remediation={"summary": "Enable leaked-password protection (and consider MFA)."},
    )

    # 4. Supabase audit activity (control-plane changes) for the same project.
    def _mk_event(event_type, action, **md):
        meta = {
            "project_ref": SUPABASE_DEMO_PROJECT_REF,
            "project_name": SUPABASE_DEMO_PROJECT_NAME,
            "organization_id": "org_configtrace_demo",
            "event_action": action,
            "event_source": "supabase_audit_log",
        }
        meta.update(md)
        norm = activity_svc.normalize_activity_event(
            provider="supabase", source="audit_log", event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=f"demo-supabase-{uuid.uuid4().hex[:10]}",
            actor_id=None, actor_type="user",
            resource_type=md.get("target_type") or "project",
            resource_id=md.get("table_name") or md.get("edge_function_name") or SUPABASE_DEMO_PROJECT_REF,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id, normalized=norm, db=db
        )
        return row

    rls_event = _mk_event(
        "supabase.rls.updated", "rls.update",
        target_type="table", schema_name=SUPABASE_DEMO_SCHEMA, table_name=SUPABASE_DEMO_TABLE_CUSTOMERS,
    )
    policy_select_event = _mk_event(
        "supabase.policy.updated", "policy.update",
        target_type="policy", schema_name=SUPABASE_DEMO_SCHEMA, table_name=SUPABASE_DEMO_TABLE_CUSTOMERS,
        policy_name="public_read", policy_command="SELECT",
    )
    policy_write_event = _mk_event(
        "supabase.policy.created", "policy.create",
        target_type="policy", schema_name=SUPABASE_DEMO_SCHEMA, table_name=SUPABASE_DEMO_TABLE_ORDERS,
        policy_name="public_write", policy_command="INSERT",
    )
    fn_event = _mk_event(
        "supabase.edge_function.updated", "function.update",
        target_type="edge_function", edge_function_name=SUPABASE_DEMO_FUNCTION,
    )
    auth_event = _mk_event(
        "supabase.auth_config.updated", "auth.config.update",
        target_type="auth_config", auth_setting_name="leaked_password_protection",
    )

    # 5. Supabase activity Incident Signals (built directly from each event).
    signals = []
    for ev in (rls_event, policy_select_event, policy_write_event, fn_event, auth_event):
        sig_dict = sb_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db
            )
            signals.append(sig)

    # 6. Supabase risk x activity correlations (M71D), built directly.
    def _add_correlation(finding, event):
        rule = corr_svc.SUPABASE_CORRELATION_RULES[corr_svc._base_rule(finding.finding_key)]
        cdict = corr_svc.build_supabase_correlation(
            finding=finding, event=event,
            project_label=f'project "{SUPABASE_DEMO_PROJECT_NAME}"', rule=rule,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db
        )
        return corr

    rls_corr = _add_correlation(rls_finding, rls_event)
    select_corr = _add_correlation(select_finding, policy_select_event)
    write_corr = _add_correlation(write_finding, policy_write_event)
    fn_corr = _add_correlation(fn_finding, fn_event)
    auth_corr = _add_correlation(auth_finding, auth_event)

    correlations = [rls_corr, select_corr, write_corr, fn_corr, auth_corr]
    findings = [rls_finding, select_finding, write_finding, fn_finding, auth_finding]
    events = [rls_event, policy_select_event, policy_write_event, fn_event, auth_event]

    # 7. Case linking all the evidence (marked demo via metadata.source).
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="[Demo] Supabase incident investigation",
        summary=(
            "Demo investigation case. It groups Supabase security evidence: "
            "configuration risks (Row Level Security disabled on a sensitive "
            "table, a public read policy on it, a public write policy on another "
            "table, an Edge Function with JWT verification disabled, and "
            "leaked-password protection disabled), and Supabase audit activity "
            "(table/RLS, access-policy, Edge Function, and auth-configuration "
            "changes) for the same project - turned into review signals and "
            "correlations. This is a human-reviewed case presenting evidence for "
            "review and may require review. ConfigTrace does not confirm data "
            "exposure, unauthorized access, or compromise."
        ),
        severity=rls_corr.severity,
        provider="supabase",
        metadata={"source": SUPABASE_DEMO_CASE_SOURCE, "repository": SUPABASE_DEMO_PROJECT_NAME},
        db=db,
    )
    for corr in correlations:
        case_svc.link_object_to_case(case=case, object_type="correlation", object_id=corr.id, actor_user_id=actor_user_id, db=db)
    for finding in findings:
        case_svc.link_object_to_case(case=case, object_type="finding", object_id=finding.id, actor_user_id=actor_user_id, db=db)
    for ev in events:
        case_svc.link_object_to_case(case=case, object_type="activity_event", object_id=ev.id, actor_user_id=actor_user_id, db=db)
    for sig in signals:
        case_svc.link_object_to_case(case=case, object_type="signal", object_id=sig.id, actor_user_id=actor_user_id, db=db)
    # Correlation-evidence signals (auto-created by upsert_correlation).
    for corr in correlations:
        if corr.linked_signal_id is not None:
            case_svc.link_object_to_case(case=case, object_type="signal", object_id=corr.linked_signal_id, actor_user_id=actor_user_id, db=db)

    logger.info("supabase_incident_demo: seeded workspace=%s case=%s", workspace_id, case.id)
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_supabase(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the Supabase demo incident objects (and nothing else)."""
    # 1. Supabase demo cases (+ their links).
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == SUPABASE_DEMO_CASE_SOURCE,
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

    # 2. Supabase demo evidence anchored on the hidden Supabase demo integration.
    integ = get_supabase_demo_integration(workspace_id, db)
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


# ── Firebase incident demo (M72E) ─────────────────────────────────────────────

FIREBASE_DEMO_INTEGRATION_NAME = "ConfigTrace Firebase incident demo (sample data)"
FIREBASE_DEMO_CASE_SOURCE = "demo_firebase_incident"
FIREBASE_DEMO_PROJECT_ID = "configtrace-demo-fb"       # sample Firebase project id
FIREBASE_DEMO_PROJECT_NAME = "configtrace-demo-fb"     # sample project name
FIREBASE_DEMO_DB_INSTANCE = "configtrace-demo-default"  # RTDB instance NAME only
FIREBASE_DEMO_BUCKET = "configtrace-demo.appspot.com"  # storage bucket NAME only


def get_firebase_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == FIREBASE_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_firebase_demo_case(workspace_id: uuid.UUID, db: Session) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == FIREBASE_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_firebase_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_firebase_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_firebase(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Firebase demo incident chain (idempotent). No real sync.

    One coherent Firebase story anchored on the same demo project:
      Configuration Risks (Firestore rules public, Realtime Database rules public
      write, Storage rules public, anonymous auth enabled, and MFA not enabled)
      -> Firebase audit activity (Firestore/Realtime Database/Storage rules and
      auth-config changes) for the same project -> Firebase activity Incident
      Signals -> Firebase risk x activity correlations -> Case.

    All objects are anchored on a hidden demo integration so ``clear_firebase``
    removes them and nothing else. Evidence is built directly for the demo
    objects (never by scanning the real workspace). Metadata is NAMES only —
    NEVER Firestore documents, Realtime Database data, storage object contents,
    auth users, emails, private keys, service-account JSON secrets, tokens,
    headers, raw API responses, raw rule source, or Cloud Function env var values.
    """
    existing = _existing_firebase_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" -> never shown / never synced).
    integ = get_firebase_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({"demo": True, "dataset": "firebase_incident_demo_v1"})
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=FIREBASE_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    # 2. Demo Firebase project resource (provider_resource_id == project id).
    resource = Resource(
        integration_id=integ.id,
        user_id=actor_user_id,
        provider_resource_type="firebase_project",
        provider_resource_id=FIREBASE_DEMO_PROJECT_ID,
        display_name=FIREBASE_DEMO_PROJECT_NAME,
        is_active=True,
    )
    db.add(resource)
    db.flush()

    # 3. Configuration Risk findings on the same project (names/booleans only).
    firestore_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="firebase",
        finding_key=f"firebase_rules_public:{FIREBASE_DEMO_PROJECT_ID}#firestore#demo",
        severity="high", title="Demo: Firebase Firestore rules allow public access",
        resource_id=resource.id,
        description="Sample Firebase configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "firebase_rules_public", "demo": True,
            "release": "cloud.firestore", "public_read_detected": True,
            "public_write_detected": False, "parser_confidence": "high",
        },
        remediation={"summary": "Tighten Firestore security rules to require auth."},
    )
    database_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="firebase",
        finding_key=f"firebase_database_public_write:{FIREBASE_DEMO_PROJECT_ID}#database#demo",
        severity="critical", title="Demo: Firebase Realtime Database rules allow public write",
        resource_id=resource.id,
        description="Sample Firebase configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "firebase_database_public_write", "demo": True,
            "service": "realtime_database", "database_instance": FIREBASE_DEMO_DB_INSTANCE,
            "public_write_detected": True, "parser_confidence": "high",
        },
        remediation={"summary": "Require authentication in the Realtime Database rules."},
    )
    storage_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="firebase",
        finding_key=f"firebase_storage_rules_public:{FIREBASE_DEMO_PROJECT_ID}#storage#demo",
        severity="high", title="Demo: Firebase Storage rules allow public access",
        resource_id=resource.id,
        description="Sample Firebase configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "firebase_storage_rules_public", "demo": True,
            "release": "firebase.storage", "public_read_detected": True,
            "parser_confidence": "high",
        },
        remediation={"summary": "Tighten Storage security rules to require auth."},
    )
    anon_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="firebase",
        finding_key=f"firebase_anonymous_auth_enabled:{FIREBASE_DEMO_PROJECT_ID}#auth#demo",
        severity="medium", title="Demo: Firebase anonymous authentication is enabled",
        resource_id=resource.id,
        description="Sample Firebase configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "firebase_anonymous_auth_enabled", "demo": True,
            "project_id": FIREBASE_DEMO_PROJECT_ID, "anonymous_enabled": True,
        },
        remediation={"summary": "Disable anonymous auth if not required."},
    )
    authprot_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="firebase",
        finding_key=f"firebase_auth_protection_missing:{FIREBASE_DEMO_PROJECT_ID}#mfa#demo",
        severity="medium", title="Demo: Firebase multi-factor authentication is not enabled",
        resource_id=resource.id,
        description="Sample Firebase configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "firebase_auth_protection_missing", "demo": True,
            "project_id": FIREBASE_DEMO_PROJECT_ID, "mfa_enabled": False,
        },
        remediation={"summary": "Enable multi-factor authentication for Firebase Auth."},
    )

    # 4. Firebase audit activity (control-plane changes) for the same project.
    def _mk_event(event_type, service, method, **md):
        meta = {
            "project_id": FIREBASE_DEMO_PROJECT_ID,
            "event_action": method,
            "event_source": "firebase_audit_log",
            "service_name": service,
            "method_name": method,
        }
        meta.update(md)
        norm = activity_svc.normalize_activity_event(
            provider="firebase", source="audit_log", event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=f"demo-firebase-{uuid.uuid4().hex[:10]}",
            actor_id=None, actor_type="user",
            resource_type=md.get("target_type") or "project",
            resource_id=md.get("target_name") or FIREBASE_DEMO_PROJECT_ID,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id, normalized=norm, db=db
        )
        return row

    firestore_event = _mk_event(
        "firebase.firestore_rules.updated", "firebaserules.googleapis.com", "UpdateRelease",
        target_type="release", ruleset_name="cloud.firestore", target_name="cloud.firestore",
    )
    database_event = _mk_event(
        "firebase.database_rules.updated", "firebasedatabase.googleapis.com", "UpdateDatabaseRules",
        target_type="database", database_instance=FIREBASE_DEMO_DB_INSTANCE,
        target_name=FIREBASE_DEMO_DB_INSTANCE,
    )
    storage_event = _mk_event(
        "firebase.storage_rules.updated", "firebaserules.googleapis.com", "UpdateRelease",
        target_type="release", ruleset_name="firebase.storage",
        storage_bucket_name=FIREBASE_DEMO_BUCKET, target_name="firebase.storage",
    )
    auth_event = _mk_event(
        "firebase.auth_config.updated", "identitytoolkit.googleapis.com", "UpdateConfig",
        target_type="auth_config", auth_setting_name="mfa",
    )

    # 5. Firebase activity Incident Signals (built directly from each event).
    signals = []
    for ev in (firestore_event, database_event, storage_event, auth_event):
        sig_dict = fb_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db
            )
            signals.append(sig)

    # 6. Firebase risk x activity correlations (M72D), built directly.
    def _add_correlation(finding, event):
        rule = corr_svc.FIREBASE_CORRELATION_RULES[corr_svc._base_rule(finding.finding_key)]
        cdict = corr_svc.build_firebase_correlation(
            finding=finding, event=event,
            project_label=f'project "{FIREBASE_DEMO_PROJECT_NAME}"', rule=rule,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db
        )
        return corr

    firestore_corr = _add_correlation(firestore_finding, firestore_event)
    database_corr = _add_correlation(database_finding, database_event)
    storage_corr = _add_correlation(storage_finding, storage_event)
    anon_corr = _add_correlation(anon_finding, auth_event)
    authprot_corr = _add_correlation(authprot_finding, auth_event)

    correlations = [firestore_corr, database_corr, storage_corr, anon_corr, authprot_corr]
    findings = [firestore_finding, database_finding, storage_finding, anon_finding, authprot_finding]
    events = [firestore_event, database_event, storage_event, auth_event]

    # 7. Case linking all the evidence (marked demo via metadata.source).
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="[Demo] Firebase incident investigation",
        summary=(
            "Demo investigation case. It groups Firebase security evidence: "
            "configuration risks (Firestore rules allowing public access, "
            "Realtime Database rules allowing public write, Storage rules "
            "allowing public access, anonymous authentication enabled, and "
            "multi-factor authentication not enabled), and Firebase audit "
            "activity (Firestore/Realtime Database/Storage rules and "
            "auth-configuration changes) for the same project - turned into "
            "review signals and correlations. This is a human-reviewed case "
            "presenting evidence for review and may require review. ConfigTrace "
            "does not confirm data exposure, unauthorized access, or compromise."
        ),
        severity=database_corr.severity,
        provider="firebase",
        metadata={"source": FIREBASE_DEMO_CASE_SOURCE, "repository": FIREBASE_DEMO_PROJECT_NAME},
        db=db,
    )
    for corr in correlations:
        case_svc.link_object_to_case(case=case, object_type="correlation", object_id=corr.id, actor_user_id=actor_user_id, db=db)
    for finding in findings:
        case_svc.link_object_to_case(case=case, object_type="finding", object_id=finding.id, actor_user_id=actor_user_id, db=db)
    for ev in events:
        case_svc.link_object_to_case(case=case, object_type="activity_event", object_id=ev.id, actor_user_id=actor_user_id, db=db)
    for sig in signals:
        case_svc.link_object_to_case(case=case, object_type="signal", object_id=sig.id, actor_user_id=actor_user_id, db=db)
    # Correlation-evidence signals (auto-created by upsert_correlation).
    seen_signal_ids = {s.id for s in signals}
    for corr in correlations:
        if corr.linked_signal_id is not None and corr.linked_signal_id not in seen_signal_ids:
            seen_signal_ids.add(corr.linked_signal_id)
            case_svc.link_object_to_case(case=case, object_type="signal", object_id=corr.linked_signal_id, actor_user_id=actor_user_id, db=db)

    logger.info("firebase_incident_demo: seeded workspace=%s case=%s", workspace_id, case.id)
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_firebase(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the Firebase demo incident objects (and nothing else)."""
    # 1. Firebase demo cases (+ their links).
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == FIREBASE_DEMO_CASE_SOURCE,
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

    # 2. Firebase demo evidence anchored on the hidden Firebase demo integration.
    integ = get_firebase_demo_integration(workspace_id, db)
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


# ── Stripe incident demo (M73E) ───────────────────────────────────────────────

STRIPE_DEMO_INTEGRATION_NAME = "ConfigTrace Stripe incident demo (sample data)"
STRIPE_DEMO_CASE_SOURCE = "demo_stripe_incident"
STRIPE_DEMO_ACCOUNT_ID = "acct_configtrace_demo"     # sample Stripe account id
STRIPE_DEMO_WEBHOOK_ID = "we_configtrace_demo_001"   # sample webhook endpoint id
STRIPE_DEMO_PAYMENT_LINK_ID = "plink_configtrace_demo"  # sample payment link id
STRIPE_DEMO_PORTAL_CONFIG_ID = "bpc_configtrace_demo"   # sample billing-portal config id


def get_stripe_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == STRIPE_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_stripe_demo_case(workspace_id: uuid.UUID, db: Session) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == STRIPE_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_stripe_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_stripe_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_stripe(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Stripe demo incident chain (idempotent). No real sync.

    One coherent Stripe story anchored on the same demo account/objects:
      Configuration Risks (insecure webhook, broad webhook event set, payment
      link with automatic tax off and promotion codes allowed, customer portal
      with hosted login page on, and account not fully enabled for payments)
      -> Stripe configuration activity (webhook endpoint / payment link / portal
      configuration / account / capability changes) for the same objects ->
      Stripe activity Incident Signals -> Stripe risk x activity correlations
      -> Case.

    All objects are anchored on a hidden demo integration so ``clear_stripe``
    removes them and nothing else. Evidence is built directly for the demo
    objects (never by scanning the real workspace). Metadata is NAMES/booleans
    only — NEVER secret API keys, restricted key values, webhook signing
    secrets, raw webhook/event payloads, raw API responses, customer PII /
    emails, payment method data, card data, charges/payment intents/invoices/
    customer records, OAuth tokens, authorization headers, request/response
    bodies, bank-account details, or tax IDs.
    """
    existing = _existing_stripe_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" -> never shown / never synced).
    integ = get_stripe_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({"demo": True, "dataset": "stripe_incident_demo_v1"})
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=STRIPE_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    # 2. One Resource per Stripe object kind, so each finding's
    #    Resource.provider_resource_id is the canonical Stripe object id
    #    (we_*/plink_*/bpc_*/acct_*) the M73D correlation join expects.
    def _mk_resource(kind: str, oid: str) -> Resource:
        r = Resource(
            integration_id=integ.id, user_id=actor_user_id,
            provider_resource_type=kind, provider_resource_id=oid,
            display_name=oid, is_active=True,
        )
        db.add(r); db.flush()
        return r

    webhook_resource = _mk_resource("stripe_webhook_endpoint", STRIPE_DEMO_WEBHOOK_ID)
    payment_link_resource = _mk_resource("stripe_payment_link", STRIPE_DEMO_PAYMENT_LINK_ID)
    portal_resource = _mk_resource("stripe_billing_portal_config", STRIPE_DEMO_PORTAL_CONFIG_ID)
    account_resource = _mk_resource("stripe_account", STRIPE_DEMO_ACCOUNT_ID)

    # 3. Configuration Risk findings (booleans/names only).
    webhook_http_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="stripe",
        finding_key=f"stripe_webhook_http:{STRIPE_DEMO_WEBHOOK_ID}",
        severity="critical", title="Demo: Stripe webhook uses plain HTTP",
        resource_id=webhook_resource.id,
        description="Sample Stripe configuration risk for the incident-workflow demo.",
        evidence={"rule": "stripe_webhook_http", "demo": True,
                  "url": "http://insecure.example.com/stripe/hook"},
        remediation={"summary": "Restore HTTPS on the webhook endpoint."},
    )
    webhook_broad_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="stripe",
        finding_key=f"stripe_webhook_broad_events:{STRIPE_DEMO_WEBHOOK_ID}",
        severity="medium",
        title="Demo: Stripe webhook subscribes to a very broad set of events",
        resource_id=webhook_resource.id,
        description="Sample Stripe configuration risk for the incident-workflow demo.",
        evidence={"rule": "stripe_webhook_broad_events", "demo": True,
                  "enabled_events_count": 60, "subscribes_to_all_events": True},
        remediation={"summary": "Scope the webhook to the events the integration needs."},
    )
    payment_link_tax_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="stripe",
        finding_key=f"stripe_payment_link_tax_disabled:{STRIPE_DEMO_PAYMENT_LINK_ID}",
        severity="medium", title="Demo: Stripe payment link has automatic tax disabled",
        resource_id=payment_link_resource.id,
        description="Sample Stripe configuration risk for the incident-workflow demo.",
        evidence={"rule": "stripe_payment_link_tax_disabled", "demo": True,
                  "active": True, "automatic_tax_enabled": False},
        remediation={"summary": "Enable automatic tax on the payment link if expected."},
    )
    payment_link_promo_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="stripe",
        finding_key=f"stripe_payment_link_promo_codes_enabled:{STRIPE_DEMO_PAYMENT_LINK_ID}",
        severity="low", title="Demo: Stripe payment link allows promotion codes",
        resource_id=payment_link_resource.id,
        description="Sample Stripe configuration risk for the incident-workflow demo.",
        evidence={"rule": "stripe_payment_link_promo_codes_enabled", "demo": True,
                  "active": True, "allow_promotion_codes": True},
        remediation={"summary": "Disable promotion codes on the link if not intended."},
    )
    portal_login_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="stripe",
        finding_key=f"stripe_portal_login_enabled:{STRIPE_DEMO_PORTAL_CONFIG_ID}",
        severity="medium",
        title="Demo: Stripe customer portal login page is enabled",
        resource_id=portal_resource.id,
        description="Sample Stripe configuration risk for the incident-workflow demo.",
        evidence={"rule": "stripe_portal_login_enabled", "demo": True,
                  "active": True, "login_page_enabled": True},
        remediation={"summary": "Disable the hosted portal login page if not intended."},
    )
    account_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="stripe",
        finding_key=f"stripe_account_capability_incomplete:{STRIPE_DEMO_ACCOUNT_ID}",
        severity="medium", title="Demo: Stripe account is not fully enabled for payments",
        resource_id=account_resource.id,
        description="Sample Stripe configuration risk for the incident-workflow demo.",
        evidence={"rule": "stripe_account_capability_incomplete", "demo": True,
                  "charges_enabled": False, "payouts_enabled": True,
                  "details_submitted": False},
        remediation={"summary": "Complete the account's required-information onboarding."},
    )

    # 4. Stripe configuration activity events for the same demo objects.
    def _mk_event(event_type: str, *, object_type: str, object_id: str, extras: dict | None = None) -> Any:
        meta: dict[str, Any] = {
            "stripe_event_type": event_type.removeprefix("stripe."),
            "event_action": event_type.removeprefix("stripe."),
            "event_source": "stripe_events_api",
            "account_id": STRIPE_DEMO_ACCOUNT_ID,
            "object_type": object_type,
            "object_id": object_id,
            "livemode": True,
        }
        if extras:
            meta.update(extras)
        norm = activity_svc.normalize_activity_event(
            provider="stripe", source="stripe_events", event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=f"demo-stripe-{uuid.uuid4().hex[:10]}",
            actor_id=None, actor_type=None,
            resource_type=object_type, resource_id=object_id, metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id, normalized=norm, db=db
        )
        return row

    webhook_event = _mk_event(
        "stripe.webhook_endpoint.updated",
        object_type="webhook_endpoint", object_id=STRIPE_DEMO_WEBHOOK_ID,
        extras={
            "webhook_endpoint_id": STRIPE_DEMO_WEBHOOK_ID,
            "webhook_url_domain": "insecure.example.com",
            "webhook_url_scheme": "http",
        },
    )
    payment_link_event = _mk_event(
        "stripe.payment_link.updated",
        object_type="payment_link", object_id=STRIPE_DEMO_PAYMENT_LINK_ID,
        extras={"payment_link_id": STRIPE_DEMO_PAYMENT_LINK_ID},
    )
    portal_event = _mk_event(
        "stripe.portal_config.updated",
        object_type="billing_portal.configuration", object_id=STRIPE_DEMO_PORTAL_CONFIG_ID,
        extras={"portal_config_id": STRIPE_DEMO_PORTAL_CONFIG_ID},
    )
    account_event = _mk_event(
        "stripe.account.updated",
        object_type="account", object_id=STRIPE_DEMO_ACCOUNT_ID,
    )
    capability_event = _mk_event(
        "stripe.capability.updated",
        object_type="capability", object_id="card_payments",
        extras={"capability": "card_payments", "capability_status": "inactive"},
    )

    # 5. Stripe activity Incident Signals (built directly from each event).
    signals = []
    for ev in (webhook_event, payment_link_event, portal_event, account_event, capability_event):
        sig_dict = st_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db
            )
            signals.append(sig)

    # 6. Stripe risk x activity correlations (M73D), built directly.
    def _add_correlation(finding, event, *, object_kind: str, object_id: str):
        rule = corr_svc.STRIPE_CORRELATION_RULES[corr_svc._base_rule(finding.finding_key)]
        cdict = corr_svc.build_stripe_correlation(
            finding=finding, event=event,
            object_label=f'{object_kind} "{object_id}"', rule=rule,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db
        )
        return corr

    webhook_http_corr = _add_correlation(
        webhook_http_finding, webhook_event,
        object_kind="webhook endpoint", object_id=STRIPE_DEMO_WEBHOOK_ID,
    )
    webhook_broad_corr = _add_correlation(
        webhook_broad_finding, webhook_event,
        object_kind="webhook endpoint", object_id=STRIPE_DEMO_WEBHOOK_ID,
    )
    payment_link_tax_corr = _add_correlation(
        payment_link_tax_finding, payment_link_event,
        object_kind="payment link", object_id=STRIPE_DEMO_PAYMENT_LINK_ID,
    )
    payment_link_promo_corr = _add_correlation(
        payment_link_promo_finding, payment_link_event,
        object_kind="payment link", object_id=STRIPE_DEMO_PAYMENT_LINK_ID,
    )
    portal_login_corr = _add_correlation(
        portal_login_finding, portal_event,
        object_kind="portal configuration", object_id=STRIPE_DEMO_PORTAL_CONFIG_ID,
    )
    account_corr = _add_correlation(
        account_finding, account_event,
        object_kind="account", object_id=STRIPE_DEMO_ACCOUNT_ID,
    )

    correlations = [
        webhook_http_corr, webhook_broad_corr,
        payment_link_tax_corr, payment_link_promo_corr,
        portal_login_corr, account_corr,
    ]
    findings = [
        webhook_http_finding, webhook_broad_finding,
        payment_link_tax_finding, payment_link_promo_finding,
        portal_login_finding, account_finding,
    ]
    events = [webhook_event, payment_link_event, portal_event, account_event, capability_event]

    # 7. Case linking all the evidence (marked demo via metadata.source).
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="[Demo] Stripe incident investigation",
        summary=(
            "Demo investigation case. It groups Stripe security evidence: "
            "configuration risks (insecure webhook, broad webhook event set, "
            "payment link with automatic tax off and promotion codes allowed, "
            "customer portal with hosted login page on, and an account not "
            "fully enabled for payments), and Stripe configuration activity "
            "(webhook endpoint, payment link, portal configuration, account, "
            "and capability changes) for the same account/objects - turned "
            "into review signals and correlations. This is a human-reviewed "
            "case presenting evidence for review and may require review. "
            "ConfigTrace does not confirm fraud, compromise, unauthorized "
            "access, or data exposure."
        ),
        severity=webhook_http_corr.severity,
        provider="stripe",
        metadata={"source": STRIPE_DEMO_CASE_SOURCE,
                  "repository": STRIPE_DEMO_ACCOUNT_ID},
        db=db,
    )
    for corr in correlations:
        case_svc.link_object_to_case(case=case, object_type="correlation", object_id=corr.id, actor_user_id=actor_user_id, db=db)
    for finding in findings:
        case_svc.link_object_to_case(case=case, object_type="finding", object_id=finding.id, actor_user_id=actor_user_id, db=db)
    for ev in events:
        case_svc.link_object_to_case(case=case, object_type="activity_event", object_id=ev.id, actor_user_id=actor_user_id, db=db)
    for sig in signals:
        case_svc.link_object_to_case(case=case, object_type="signal", object_id=sig.id, actor_user_id=actor_user_id, db=db)
    # Correlation-evidence signals (auto-created by upsert_correlation).
    seen_signal_ids = {s.id for s in signals}
    for corr in correlations:
        if corr.linked_signal_id is not None and corr.linked_signal_id not in seen_signal_ids:
            seen_signal_ids.add(corr.linked_signal_id)
            case_svc.link_object_to_case(case=case, object_type="signal", object_id=corr.linked_signal_id, actor_user_id=actor_user_id, db=db)

    logger.info("stripe_incident_demo: seeded workspace=%s case=%s", workspace_id, case.id)
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_stripe(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the Stripe demo incident objects (and nothing else)."""
    # 1. Stripe demo cases (+ their links).
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == STRIPE_DEMO_CASE_SOURCE,
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

    # 2. Stripe demo evidence anchored on the hidden Stripe demo integration.
    integ = get_stripe_demo_integration(workspace_id, db)
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


# ── Shopify incident demo (M74E) ──────────────────────────────────────────────

SHOPIFY_DEMO_INTEGRATION_NAME = "ConfigTrace Shopify incident demo (sample data)"
SHOPIFY_DEMO_CASE_SOURCE = "demo_shopify_incident"
SHOPIFY_DEMO_SHOP_DOMAIN = "configtrace-demo.example.com"
SHOPIFY_DEMO_MYSHOPIFY_DOMAIN = "configtrace-demo.myshopify.com"
SHOPIFY_DEMO_WEBHOOK_ID = "9000000001"
SHOPIFY_DEMO_HIGH_RISK_WEBHOOK_ID = "9000000002"
SHOPIFY_DEMO_DOMAIN_ID = "9100000001"
SHOPIFY_DEMO_APP_SCOPE_SUMMARY_ID = "app_scope_summary_demo"
SHOPIFY_DEMO_POLICY_ID = "refund_policy"


def get_shopify_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == SHOPIFY_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_shopify_demo_case(workspace_id: uuid.UUID, db: Session) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == SHOPIFY_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_shopify_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_shopify_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_shopify(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Shopify demo incident chain (idempotent). No real sync.

    One coherent Shopify story anchored on the same demo shop/objects:
      Shopify configuration risks (insecure webhook over HTTP, high-risk
      webhook topic, primary domain without SSL, primary domain unverified,
      plus a broad-write-scopes app risk and a missing-policy risk that
      remain uncorrelated because M74B ingestion does not emit app-scope or
      policy activity yet) -> Shopify configuration activity
      (shopify.webhook.updated for both webhooks, shopify.domain.updated,
      and shopify.shop.updated) -> Shopify activity Incident Signals ->
      Shopify risk x activity correlations (webhook insecure, webhook
      high-risk topic, domain SSL, domain verification) -> Case.

    All objects are anchored on a hidden demo integration so
    ``clear_shopify`` removes them and nothing else. Evidence is built
    directly for the demo objects (never by scanning the real workspace).
    Metadata is NAMES/booleans only - NEVER Admin API access tokens, OAuth
    tokens, private app secrets, webhook signing secrets, raw webhook
    payloads, raw event payloads, raw API responses, customer PII / emails,
    orders, carts / checkouts with buyer data, payment method data, card
    data, refunds, fulfillments with customer/order data, authorization
    headers, request/response bodies, bank-account details, tax IDs, or
    staff names/emails.
    """
    existing = _existing_shopify_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    integ = get_shopify_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({"demo": True, "dataset": "shopify_incident_demo_v1"})
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=SHOPIFY_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    def _mk_resource(kind: str, oid: str) -> Resource:
        r = Resource(
            integration_id=integ.id, user_id=actor_user_id,
            provider_resource_type=kind, provider_resource_id=oid,
            display_name=oid, is_active=True,
        )
        db.add(r); db.flush()
        return r

    webhook_resource = _mk_resource("shopify_webhook", SHOPIFY_DEMO_WEBHOOK_ID)
    high_risk_webhook_resource = _mk_resource(
        "shopify_webhook", SHOPIFY_DEMO_HIGH_RISK_WEBHOOK_ID)
    domain_resource = _mk_resource("shopify_domain", SHOPIFY_DEMO_DOMAIN_ID)
    app_scope_resource = _mk_resource(
        "shopify_app_scope_summary", SHOPIFY_DEMO_APP_SCOPE_SUMMARY_ID)
    policy_resource = _mk_resource("shopify_store_policy", SHOPIFY_DEMO_POLICY_ID)

    webhook_http_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="shopify",
        finding_key=f"shopify_webhook_http:{SHOPIFY_DEMO_WEBHOOK_ID}",
        severity="critical",
        title="Demo: Shopify webhook uses plain HTTP",
        resource_id=webhook_resource.id,
        description="Sample Shopify configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "shopify_webhook_http", "demo": True,
            "topic": "products/update", "endpoint_domain": "insecure.example.com",
            "endpoint_scheme": "http",
        },
        remediation={"summary": "Switch the webhook endpoint to HTTPS."},
    )
    webhook_topic_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="shopify",
        finding_key=f"shopify_webhook_high_risk_topic:{SHOPIFY_DEMO_HIGH_RISK_WEBHOOK_ID}",
        severity="medium",
        title="Demo: Shopify webhook subscribes to a high-risk topic",
        resource_id=high_risk_webhook_resource.id,
        description="Sample Shopify configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "shopify_webhook_high_risk_topic", "demo": True,
            "topic": "orders/create", "topic_family": "orders",
            "endpoint_domain": "hooks.example.com",
        },
        remediation={"summary": "Confirm the receiving system is intended and trusted."},
    )
    domain_ssl_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="shopify",
        finding_key=f"shopify_domain_ssl_missing:{SHOPIFY_DEMO_DOMAIN_ID}",
        severity="high",
        title="Demo: Shopify primary domain does not have SSL enabled",
        resource_id=domain_resource.id,
        description="Sample Shopify configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "shopify_domain_ssl_missing", "demo": True,
            "host": "store.example.com", "primary": True, "ssl_enabled": False,
        },
        remediation={"summary": "Enable SSL on the primary domain."},
    )
    domain_verified_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="shopify",
        finding_key=f"shopify_domain_unverified:{SHOPIFY_DEMO_DOMAIN_ID}",
        severity="medium",
        title="Demo: Shopify primary domain is unverified",
        resource_id=domain_resource.id,
        description="Sample Shopify configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "shopify_domain_unverified", "demo": True,
            "host": "store.example.com", "primary": True, "verified": False,
        },
        remediation={"summary": "Verify the primary domain in the Shopify admin."},
    )
    app_scope_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="shopify",
        finding_key=f"shopify_app_broad_write_scopes:{SHOPIFY_DEMO_APP_SCOPE_SUMMARY_ID}",
        severity="medium",
        title="Demo: Shopify app has broad high-risk write scopes",
        resource_id=app_scope_resource.id,
        description="Sample Shopify configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "shopify_app_broad_write_scopes", "demo": True,
            "high_risk_write_scope_count": 3,
            "high_risk_write_scopes": "write_customers,write_orders,write_products",
        },
        remediation={"summary": "Reduce the app's grant to least privilege."},
    )
    policy_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="shopify",
        finding_key=f"shopify_policy_missing:{SHOPIFY_DEMO_POLICY_ID}",
        severity="low",
        title="Demo: Shopify 'refund_policy' policy is missing",
        resource_id=policy_resource.id,
        description="Sample Shopify configuration risk for the incident-workflow demo.",
        evidence={
            "rule": "shopify_policy_missing", "demo": True,
            "policy_type": "refund_policy", "present": False,
        },
        remediation={"summary": "Add the refund_policy policy in the Shopify admin."},
    )

    def _mk_event(event_type: str, *, object_type: str, object_id: str,
                  extras: Optional[dict] = None) -> Any:
        meta: dict[str, Any] = {
            "shopify_event_type": (
                event_type.removeprefix("shopify.").replace(".", "/")
            ),
            "event_action": event_type.removeprefix("shopify.").split(".")[-1],
            "event_source": "shopify_events_api",
            "shop_domain": SHOPIFY_DEMO_SHOP_DOMAIN,
            "myshopify_domain": SHOPIFY_DEMO_MYSHOPIFY_DOMAIN,
            "object_type": object_type,
            "object_id": object_id,
            "livemode": True,
        }
        if extras:
            meta.update(extras)
        norm = activity_svc.normalize_activity_event(
            provider="shopify", source="shopify_events", event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=f"demo-shopify-{uuid.uuid4().hex[:10]}",
            actor_id=None, actor_type=None,
            resource_type=object_type, resource_id=object_id, metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id, normalized=norm, db=db
        )
        return row

    webhook_event = _mk_event(
        "shopify.webhook.updated",
        object_type="Webhook", object_id=SHOPIFY_DEMO_WEBHOOK_ID,
        extras={
            "webhook_id": SHOPIFY_DEMO_WEBHOOK_ID,
            "webhook_topic": "products/update",
            "webhook_endpoint_domain": "insecure.example.com",
            "webhook_endpoint_scheme": "http",
        },
    )
    high_risk_webhook_event = _mk_event(
        "shopify.webhook.updated",
        object_type="Webhook", object_id=SHOPIFY_DEMO_HIGH_RISK_WEBHOOK_ID,
        extras={
            "webhook_id": SHOPIFY_DEMO_HIGH_RISK_WEBHOOK_ID,
            "webhook_topic": "orders/create",
            "webhook_endpoint_domain": "hooks.example.com",
            "webhook_endpoint_scheme": "https",
        },
    )
    domain_event = _mk_event(
        "shopify.domain.updated",
        object_type="Domain", object_id=SHOPIFY_DEMO_DOMAIN_ID,
        extras={
            "domain_id": SHOPIFY_DEMO_DOMAIN_ID,
            "domain_host": "store.example.com",
        },
    )
    shop_event = _mk_event(
        "shopify.shop.updated",
        object_type="Shop", object_id=SHOPIFY_DEMO_MYSHOPIFY_DOMAIN,
    )

    signals = []
    for ev in (webhook_event, high_risk_webhook_event, domain_event, shop_event):
        sig_dict = sh_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db
            )
            signals.append(sig)

    def _add_correlation(finding, event, *, object_kind: str, object_id: str):
        rule = corr_svc.SHOPIFY_CORRELATION_RULES[
            corr_svc._base_rule(finding.finding_key)
        ]
        cdict = corr_svc.build_shopify_correlation(
            finding=finding, event=event,
            object_label=f'{object_kind} "{object_id}"', rule=rule,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db
        )
        return corr

    webhook_http_corr = _add_correlation(
        webhook_http_finding, webhook_event,
        object_kind="webhook", object_id=SHOPIFY_DEMO_WEBHOOK_ID,
    )
    webhook_topic_corr = _add_correlation(
        webhook_topic_finding, high_risk_webhook_event,
        object_kind="webhook", object_id=SHOPIFY_DEMO_HIGH_RISK_WEBHOOK_ID,
    )
    domain_ssl_corr = _add_correlation(
        domain_ssl_finding, domain_event,
        object_kind="domain", object_id=SHOPIFY_DEMO_DOMAIN_ID,
    )
    domain_verified_corr = _add_correlation(
        domain_verified_finding, domain_event,
        object_kind="domain", object_id=SHOPIFY_DEMO_DOMAIN_ID,
    )

    correlations = [
        webhook_http_corr, webhook_topic_corr,
        domain_ssl_corr, domain_verified_corr,
    ]
    findings = [
        webhook_http_finding, webhook_topic_finding,
        domain_ssl_finding, domain_verified_finding,
        app_scope_finding, policy_finding,
    ]
    events = [webhook_event, high_risk_webhook_event, domain_event, shop_event]

    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="[Demo] Shopify incident investigation",
        summary=(
            "Demo investigation case. It groups Shopify security evidence: "
            "configuration risks (insecure webhook, high-risk webhook topic, "
            "primary domain without SSL, primary domain unverified, broad "
            "app write scopes, and a missing standard policy), and Shopify "
            "configuration activity (webhook subscription, shop-domain, and "
            "shop setting changes) for the same shop/objects - turned into "
            "review signals and correlations. This is a human-reviewed case "
            "presenting evidence for review and may require review. "
            "ConfigTrace does not confirm fraud, compromise, unauthorized "
            "access, or data exposure."
        ),
        severity=webhook_http_corr.severity,
        provider="shopify",
        metadata={
            "source": SHOPIFY_DEMO_CASE_SOURCE,
            "repository": SHOPIFY_DEMO_MYSHOPIFY_DOMAIN,
        },
        db=db,
    )
    for corr in correlations:
        case_svc.link_object_to_case(
            case=case, object_type="correlation", object_id=corr.id,
            actor_user_id=actor_user_id, db=db)
    for finding in findings:
        case_svc.link_object_to_case(
            case=case, object_type="finding", object_id=finding.id,
            actor_user_id=actor_user_id, db=db)
    for ev in events:
        case_svc.link_object_to_case(
            case=case, object_type="activity_event", object_id=ev.id,
            actor_user_id=actor_user_id, db=db)
    for sig in signals:
        case_svc.link_object_to_case(
            case=case, object_type="signal", object_id=sig.id,
            actor_user_id=actor_user_id, db=db)
    seen_signal_ids = {s.id for s in signals}
    for corr in correlations:
        if corr.linked_signal_id is not None and corr.linked_signal_id not in seen_signal_ids:
            seen_signal_ids.add(corr.linked_signal_id)
            case_svc.link_object_to_case(
                case=case, object_type="signal", object_id=corr.linked_signal_id,
                actor_user_id=actor_user_id, db=db)

    logger.info("shopify_incident_demo: seeded workspace=%s case=%s", workspace_id, case.id)
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_shopify(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the Shopify demo incident objects (and nothing else)."""
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == SHOPIFY_DEMO_CASE_SOURCE,
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

    integ = get_shopify_demo_integration(workspace_id, db)
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



# ── Azure incident demo (M77G) ────────────────────────────────────────────────
# A SEPARATE hidden demo integration + case source so "Clear Azure demo"
# removes only Azure demo objects and never touches any other provider's
# demo (or any real Azure integration). Same safety rules as every other
# provider demo: clearly marked demo, no real sync, no notifications, never
# touches a real Azure integration, idempotent.
#
# The chain is one coherent Azure story anchored on a hidden demo subscription
# + resource group, with risky configuration evidence on four Azure resources
# (NSG, Storage account, Key Vault, and one broad role assignment), four
# matching Azure Activity Log management events, the four corresponding
# review signals, and four risk x activity correlations linking each finding
# to its same-resource activity event:
#
#   Azure configuration risks (NSG public admin ingress, Storage public blob,
#   Key Vault public network access, broad Owner role assignment at the
#   subscription) -> Azure Activity Log activity (azure.nsg_rule.updated,
#   azure.storage_account.updated, azure.key_vault.updated,
#   azure.role_assignment.created) -> Azure activity signals -> Azure risk x
#   activity correlations -> Case.
#
# All resource identifiers are RFC-style synthetic placeholders. No real
# subscription, no real tenant, no real principal IDs / emails / UPNs, no
# raw correlationId, no claims, no authorization, no properties payload, no
# storage keys, no SAS tokens, no connection strings, no Key Vault secret
# names/values, no certificate material, no key material, no app setting
# names/values, no env var values, no database contents, no VM user data,
# no customer/workload data, no PII.

AZURE_DEMO_INTEGRATION_NAME = "ConfigTrace Azure incident demo (sample data)"
AZURE_DEMO_CASE_SOURCE = "demo_azure_incident"
AZURE_DEMO_DATASET = "azure_incident_demo_v1"

AZURE_DEMO_SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
AZURE_DEMO_RESOURCE_GROUP = "configtrace-demo-rg"
AZURE_DEMO_LOCATION = "eastus"
AZURE_DEMO_NSG_NAME = "configtrace-demo-nsg"
AZURE_DEMO_STORAGE_NAME = "configtracedemoacct"
AZURE_DEMO_VAULT_NAME = "configtrace-demo-kv"
AZURE_DEMO_ROLE_ASSIGNMENT_ID = "11111111-1111-1111-1111-111111111111"


def _az_arm_path(*, kind: str, name: str) -> str:
    """Build a synthetic ARM resource id for demo resources."""
    return (
        f"/subscriptions/{AZURE_DEMO_SUBSCRIPTION_ID}"
        f"/resourceGroups/{AZURE_DEMO_RESOURCE_GROUP}"
        f"/providers/{kind}/{name}"
    )


def get_azure_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == AZURE_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_azure_demo_case(
    workspace_id: uuid.UUID, db: Session
) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == AZURE_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_azure_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_azure_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_azure(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Azure demo incident chain (idempotent). No real Azure sync.

    Builds one coherent Azure story anchored on the same demo subscription
    + resource group:
      Azure configuration risks (NSG public admin ingress, Storage public blob,
      Key Vault public network access, broad Owner role assignment) -> Azure
      Activity Log activity (azure.nsg_rule.updated, azure.storage_account.
      updated, azure.key_vault.updated, azure.role_assignment.created) ->
      Azure activity signals -> Azure risk x activity correlations -> Case.

    All objects are anchored on a hidden demo integration so ``clear_azure``
    removes them and nothing else. Evidence is built directly for the demo
    objects (never by scanning the real workspace). Metadata is allowlisted
    NAMES / booleans / categories only - NEVER caller email/UPN/name,
    principal IDs, raw correlationId, claims, authorization, properties
    payload, httpRequest body, tenantId, storage keys, SAS tokens, connection
    strings, Key Vault secret names/values, certificate material, key
    material, app setting names/values, env var values, customer/workload
    data, or PII.
    """
    existing = _existing_azure_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    integ = get_azure_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({"demo": True, "dataset": AZURE_DEMO_DATASET})
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=AZURE_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    def _mk_resource(kind: str, arm_id: str, display: str) -> Resource:
        r = Resource(
            integration_id=integ.id, user_id=actor_user_id,
            provider_resource_type=kind, provider_resource_id=arm_id,
            display_name=display, is_active=True,
        )
        db.add(r); db.flush()
        return r

    nsg_arm = _az_arm_path(
        kind="Microsoft.Network/networkSecurityGroups", name=AZURE_DEMO_NSG_NAME
    )
    storage_arm = _az_arm_path(
        kind="Microsoft.Storage/storageAccounts", name=AZURE_DEMO_STORAGE_NAME
    )
    kv_arm = _az_arm_path(
        kind="Microsoft.KeyVault/vaults", name=AZURE_DEMO_VAULT_NAME
    )
    role_arm = (
        f"/subscriptions/{AZURE_DEMO_SUBSCRIPTION_ID}"
        f"/providers/Microsoft.Authorization/roleAssignments/"
        f"{AZURE_DEMO_ROLE_ASSIGNMENT_ID}"
    )

    nsg_resource = _mk_resource(
        "azure_network_security_group", nsg_arm, AZURE_DEMO_NSG_NAME
    )
    storage_resource = _mk_resource(
        "azure_storage_account", storage_arm, AZURE_DEMO_STORAGE_NAME
    )
    kv_resource = _mk_resource(
        "azure_key_vault", kv_arm, AZURE_DEMO_VAULT_NAME
    )
    role_resource = _mk_resource(
        "azure_role_assignment", role_arm, "Owner @ subscription"
    )

    nsg_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="azure",
        finding_key=f"azure_nsg_public_admin_ingress:{nsg_arm}",
        severity="critical",
        title="Demo: Azure NSG allows public inbound on an administrative port",
        resource_id=nsg_resource.id,
        description=(
            "Sample Azure NSG configuration risk for the incident-workflow demo. "
            "This is evidence for review and does not confirm compromise, "
            "unauthorized access, or data exposure."
        ),
        evidence={
            "rule": "azure_nsg_public_admin_ingress", "demo": True,
            "nsg_name": AZURE_DEMO_NSG_NAME,
            "resource_group": AZURE_DEMO_RESOURCE_GROUP,
            "location": AZURE_DEMO_LOCATION,
            "admin_port": 3389,
            "source_address_prefix": "*",
            "destination_port_range": "3389",
            "protocol": "Tcp",
            "public_source": True,
        },
        remediation={
            "summary": "Restrict the NSG source range or remove the rule.",
        },
    )
    storage_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="azure",
        finding_key=f"azure_storage_public_blob_access:{storage_arm}",
        severity="high",
        title="Demo: Azure Storage account permits public blob access",
        resource_id=storage_resource.id,
        description=(
            "Sample Azure Storage configuration risk for the incident-workflow "
            "demo. This is evidence for review and does not confirm data exposure."
        ),
        evidence={
            "rule": "azure_storage_public_blob_access", "demo": True,
            "account_name": AZURE_DEMO_STORAGE_NAME,
            "resource_group": AZURE_DEMO_RESOURCE_GROUP,
            "location": AZURE_DEMO_LOCATION,
            "allow_blob_public_access": True,
        },
        remediation={
            "summary": "Disable Allow Blob public access on the storage account.",
        },
    )
    kv_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="azure",
        finding_key=f"azure_key_vault_public_network_access:{kv_arm}",
        severity="high",
        title="Demo: Azure Key Vault allows public network access",
        resource_id=kv_resource.id,
        description=(
            "Sample Azure Key Vault configuration risk for the incident-workflow "
            "demo. This is evidence for review and does not confirm secret "
            "exposure or unauthorized access."
        ),
        evidence={
            "rule": "azure_key_vault_public_network_access", "demo": True,
            "vault_name": AZURE_DEMO_VAULT_NAME,
            "resource_group": AZURE_DEMO_RESOURCE_GROUP,
            "location": AZURE_DEMO_LOCATION,
            "public_network_access": "Enabled",
            "network_default_action": "Allow",
        },
        remediation={
            "summary": "Restrict to selected networks or disable public access.",
        },
    )
    role_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id, provider="azure",
        finding_key=f"azure_role_assignment_broad_privilege:{role_arm}",
        severity="high",
        title="Demo: Azure role assignment grants 'Owner' at subscription scope",
        resource_id=role_resource.id,
        description=(
            "Sample Azure access-governance risk for the incident-workflow demo. "
            "This is evidence for review and does not confirm compromise or "
            "unauthorized access. Principal ID/email/name is never stored."
        ),
        evidence={
            "rule": "azure_role_assignment_broad_privilege", "demo": True,
            "assignment_id": AZURE_DEMO_ROLE_ASSIGNMENT_ID,
            "scope_type": "subscription",
            "resource_group": "",
            "role_definition_name": "Owner",
            "principal_type": "ServicePrincipal",
        },
        remediation={
            "summary": (
                "Replace with a narrower built-in role or restrict scope/condition."
            ),
        },
    )

    def _mk_event(
        *, event_type: str, resource_arm: str, resource_type: str,
        extra: dict,
    ) -> SecurityActivityEvent:
        meta: dict[str, Any] = {
            "event_source": "azure_activity_log",
            "subscription_id": AZURE_DEMO_SUBSCRIPTION_ID,
            "resource_group": AZURE_DEMO_RESOURCE_GROUP,
            "resource_id": resource_arm,
            "resource_type": resource_type,
            "status": "Succeeded",
            "category": "Administrative",
            "azure_event_id": f"demo-az-{uuid.uuid4().hex[:10]}",
            "azure_correlation_id_hash": ("d" * 32),
        }
        meta.update(extra)
        norm = activity_svc.normalize_activity_event(
            provider="azure", source="azure_activity_log",
            event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=meta["azure_event_id"],
            actor_id=None, actor_type=None,
            resource_type=resource_type, resource_id=resource_arm,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id,
            normalized=norm, db=db,
        )
        return row

    nsg_event = _mk_event(
        event_type="azure.nsg_rule.updated",
        resource_arm=nsg_arm,
        resource_type="Microsoft.Network/networkSecurityGroups",
        extra={
            "operation_name": (
                "Microsoft.Network/networkSecurityGroups/securityRules/write"
            ),
            "operation_family": (
                "Microsoft.Network/networkSecurityGroups/securityRules"
            ),
            "operation_action": "write",
            "nsg_name": AZURE_DEMO_NSG_NAME,
            "nsg_rule_name": "allow-rdp",
        },
    )
    storage_event = _mk_event(
        event_type="azure.storage_account.updated",
        resource_arm=storage_arm,
        resource_type="Microsoft.Storage/storageAccounts",
        extra={
            "operation_name": "Microsoft.Storage/storageAccounts/write",
            "operation_family": "Microsoft.Storage/storageAccounts",
            "operation_action": "write",
            "storage_account_name": AZURE_DEMO_STORAGE_NAME,
        },
    )
    kv_event = _mk_event(
        event_type="azure.key_vault.updated",
        resource_arm=kv_arm,
        resource_type="Microsoft.KeyVault/vaults",
        extra={
            "operation_name": "Microsoft.KeyVault/vaults/write",
            "operation_family": "Microsoft.KeyVault/vaults",
            "operation_action": "write",
            "key_vault_name": AZURE_DEMO_VAULT_NAME,
        },
    )
    role_event = _mk_event(
        event_type="azure.role_assignment.created",
        resource_arm=role_arm,
        resource_type="Microsoft.Authorization/roleAssignments",
        extra={
            "operation_name": "Microsoft.Authorization/roleAssignments/write",
            "operation_family": "Microsoft.Authorization/roleAssignments",
            "operation_action": "write",
            "role_definition_name": "Owner",
            "scope_type": "subscription",
            "principal_type": "ServicePrincipal",
        },
    )

    signals: list[SecurityIncidentSignal] = []
    for ev in (nsg_event, storage_event, kv_event, role_event):
        sig_dict = az_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db
            )
            signals.append(sig)

    def _add_correlation(
        *, finding: SecurityFinding, event: SecurityActivityEvent,
        matched_on: str, resource_label: str,
    ) -> SecuritySignalCorrelation:
        rule = corr_svc.AZURE_CORRELATION_RULES[
            corr_svc._base_rule(finding.finding_key)
        ]
        cdict = corr_svc.build_azure_correlation(
            finding=finding, event=event, rule=rule,
            matched_on=matched_on, resource_label=resource_label,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db,
        )
        return corr

    nsg_corr = _add_correlation(
        finding=nsg_finding, event=nsg_event,
        matched_on="nsg_name+resource_group",
        resource_label=f'NSG "{AZURE_DEMO_NSG_NAME}"',
    )
    storage_corr = _add_correlation(
        finding=storage_finding, event=storage_event,
        matched_on="storage_account_name+resource_group",
        resource_label=f'Storage account "{AZURE_DEMO_STORAGE_NAME}"',
    )
    kv_corr = _add_correlation(
        finding=kv_finding, event=kv_event,
        matched_on="key_vault_name+resource_group",
        resource_label=f'Key Vault "{AZURE_DEMO_VAULT_NAME}"',
    )
    role_corr = _add_correlation(
        finding=role_finding, event=role_event,
        matched_on="role_definition_name+scope_type",
        resource_label='role assignment "Owner"',
    )

    correlations = [nsg_corr, storage_corr, kv_corr, role_corr]
    findings = [nsg_finding, storage_finding, kv_finding, role_finding]
    events = [nsg_event, storage_event, kv_event, role_event]

    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="[Demo] Azure configuration review",
        summary=(
            "Demo Azure exposure and access-governance review. It groups Azure "
            "security evidence: configuration risks (NSG public admin ingress, "
            "Storage public blob access, Key Vault public network access, and a "
            "broad Owner role assignment at subscription scope), and Azure "
            "Activity Log control-plane activity (NSG rule, storage account, "
            "Key Vault, and role assignment changes) for the same resources - "
            "turned into review signals and risk x activity correlations. This "
            "is a human-reviewed case presenting evidence for review and may "
            "require review. ConfigTrace does not confirm compromise, "
            "unauthorized access, or data exposure."
        ),
        severity=nsg_corr.severity,
        provider="azure",
        metadata={
            "source": AZURE_DEMO_CASE_SOURCE,
            "repository": AZURE_DEMO_RESOURCE_GROUP,
        },
        db=db,
    )
    for corr in correlations:
        case_svc.link_object_to_case(
            case=case, object_type="correlation", object_id=corr.id,
            actor_user_id=actor_user_id, db=db,
        )
    for finding in findings:
        case_svc.link_object_to_case(
            case=case, object_type="finding", object_id=finding.id,
            actor_user_id=actor_user_id, db=db,
        )
    for ev in events:
        case_svc.link_object_to_case(
            case=case, object_type="activity_event", object_id=ev.id,
            actor_user_id=actor_user_id, db=db,
        )
    for sig in signals:
        case_svc.link_object_to_case(
            case=case, object_type="signal", object_id=sig.id,
            actor_user_id=actor_user_id, db=db,
        )
    seen_signal_ids = {s.id for s in signals}
    for corr in correlations:
        if corr.linked_signal_id is not None and corr.linked_signal_id not in seen_signal_ids:
            seen_signal_ids.add(corr.linked_signal_id)
            case_svc.link_object_to_case(
                case=case, object_type="signal", object_id=corr.linked_signal_id,
                actor_user_id=actor_user_id, db=db,
            )

    logger.info(
        "azure_incident_demo: seeded workspace=%s case=%s", workspace_id, case.id
    )
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_azure(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the Azure demo incident objects (and nothing else)."""
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == AZURE_DEMO_CASE_SOURCE,
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

    integ = get_azure_demo_integration(workspace_id, db)
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
            corr_conds.append(
                SecuritySignalCorrelation.linked_finding_id.in_(finding_ids)
            )
        if activity_ids:
            corr_conds.append(
                SecuritySignalCorrelation.linked_activity_event_id.in_(activity_ids)
            )
        if corr_conds:
            db.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                or_(*corr_conds),
            ).delete(synchronize_session=False)
        sig_conds = [SecurityIncidentSignal.integration_id == integ.id]
        if activity_ids:
            sig_conds.append(
                SecurityIncidentSignal.linked_activity_event_id.in_(activity_ids)
            )
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


# ─────────────────────────────────────────────────────────────────────────────
# Google Cloud incident demo (M78G) — a SEPARATE hidden demo integration + case
# source so "Clear Google Cloud demo" removes only Google Cloud demo objects
# and never touches the GitHub / AWS / Cloudflare / Vercel / Supabase / Firebase
# / Stripe / Shopify / Azure demos (and vice-versa). Same safety rules:
#   - clearly marked demo, no real Google Cloud sync, no notifications
#   - never touches a real Google Cloud integration
#   - idempotent
#
# Forbidden in demo evidence: service account private keys / private_key_id,
# access tokens, refresh tokens, signed JWTs, authorization headers, raw Cloud
# Logging entries, protoPayload raw object, request/response objects,
# authenticationInfo, authorizationInfo, principal emails / IDs, service
# account emails, user names, group names, full IAM bindings, database
# names/users/passwords, connection strings, query data, env var names/values,
# secret names/values, secret payloads, container args, kubeconfig, certs,
# node names, workload data, pod specs, logs, customer data, raw caller IPs,
# userAgent, PII.

GOOGLE_CLOUD_DEMO_INTEGRATION_NAME = (
    "ConfigTrace Google Cloud incident demo (sample data)"
)
GOOGLE_CLOUD_DEMO_CASE_SOURCE = "demo_google_cloud_incident"
GOOGLE_CLOUD_DEMO_DATASET = "google_cloud_incident_demo_v1"

# Safe synthetic identifiers (RFC-style placeholders). No real project, no real
# resource names, no real principals, no real keys.
GOOGLE_CLOUD_DEMO_PROJECT_ID = "demo-gcp-project"
GOOGLE_CLOUD_DEMO_FIREWALL_NAME = "demo-admin-firewall"
GOOGLE_CLOUD_DEMO_NETWORK_NAME = "demo-vpc"
GOOGLE_CLOUD_DEMO_BUCKET_NAME = "demo-storage-bucket"
GOOGLE_CLOUD_DEMO_SQL_INSTANCE_NAME = "demo-sql-instance"
GOOGLE_CLOUD_DEMO_RUN_SERVICE_NAME = "demo-run-service"
GOOGLE_CLOUD_DEMO_GKE_CLUSTER_NAME = "demo-gke-cluster"
GOOGLE_CLOUD_DEMO_SAKEY_SUMMARY_ID = "demo-service-account-key-summary"
GOOGLE_CLOUD_DEMO_SECRET_SUMMARY_ID = "demo-secret-manager-summary"
GOOGLE_CLOUD_DEMO_IAM_SUMMARY_ID = "demo-iam-policy-summary"


def _gcp_resource_name(*, kind: str, name: str) -> str:
    """Build a synthetic Google Cloud resource path for demo resources."""
    return f"projects/{GOOGLE_CLOUD_DEMO_PROJECT_ID}/{kind}/{name}"


# ── Twilio incident demo (M79G) — a SEPARATE hidden demo integration + case
# source so "Clear Twilio demo" removes only Twilio demo objects and never
# touches any other provider demo. Same safety rules:
#   - clearly marked demo, no real Twilio sync, no notifications
#   - never touches a real Twilio integration
#   - idempotent
#
# Forbidden in demo evidence: auth tokens, API key secrets, full account SIDs
# (strings matching AC[0-9a-fA-F]{32} or SK[0-9a-fA-F]{32}), full E.164 phone
# numbers, message bodies, call transcripts, raw webhook URLs, raw API response
# dicts, recording data, or any customer PII.
TWILIO_DEMO_INTEGRATION_NAME = "ConfigTrace Twilio incident demo (sample data)"
TWILIO_DEMO_CASE_SOURCE = "demo_twilio_incident"
TWILIO_DEMO_DATASET = "twilio_incident_demo_v1"

# Safe synthetic identifiers — plain-English placeholders, NOT Twilio SID
# format patterns (no AC/SK hex sequences, no real E.164 phone numbers).
TWILIO_DEMO_PHONE_RESOURCE = "TWILIO_DEMO_PHONE_RESOURCE"
TWILIO_DEMO_MESSAGING_SERVICE = "TWILIO_DEMO_MESSAGING_SERVICE"
TWILIO_DEMO_VERIFY_SERVICE = "TWILIO_DEMO_VERIFY_SERVICE"
TWILIO_DEMO_API_KEY_ID = "TWILIO_DEMO_API_KEY_ID"


def get_google_cloud_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == GOOGLE_CLOUD_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_google_cloud_demo_case(
    workspace_id: uuid.UUID, db: Session
) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == GOOGLE_CLOUD_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_google_cloud_status(
    workspace_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    case = _existing_google_cloud_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_google_cloud(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Google Cloud demo incident chain (idempotent). No real GCP sync.

    All objects are anchored on a hidden demo integration so
    ``clear_google_cloud`` removes them and nothing else. Evidence is built
    directly for the demo objects (never by scanning the real workspace).
    Metadata is allowlisted via ``security_activity_event_service.
    sanitize_activity_metadata`` — anything not on the allowlist is silently
    dropped (defense-in-depth on top of the explicit safe shape used here).
    """
    existing = _existing_google_cloud_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    integ = get_google_cloud_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({
            "demo": True, "dataset": GOOGLE_CLOUD_DEMO_DATASET,
        })
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=GOOGLE_CLOUD_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    def _mk_resource(kind: str, gcp_path: str, display: str) -> Resource:
        r = Resource(
            integration_id=integ.id, user_id=actor_user_id,
            provider_resource_type=kind, provider_resource_id=gcp_path,
            display_name=display, is_active=True,
        )
        db.add(r); db.flush()
        return r

    # Synthetic resource paths — same shape as real Google APIs use.
    iam_path = _gcp_resource_name(
        kind="iam_policy_summary", name=GOOGLE_CLOUD_DEMO_IAM_SUMMARY_ID
    )
    fw_path = _gcp_resource_name(
        kind="firewall_rules", name=GOOGLE_CLOUD_DEMO_FIREWALL_NAME
    )
    bucket_path = f"projects/_/buckets/{GOOGLE_CLOUD_DEMO_BUCKET_NAME}"
    sql_path = _gcp_resource_name(
        kind="sql_instances", name=GOOGLE_CLOUD_DEMO_SQL_INSTANCE_NAME
    )
    run_path = _gcp_resource_name(
        kind="locations/us-central1/services",
        name=GOOGLE_CLOUD_DEMO_RUN_SERVICE_NAME,
    )
    gke_path = _gcp_resource_name(
        kind="locations/us-central1/clusters",
        name=GOOGLE_CLOUD_DEMO_GKE_CLUSTER_NAME,
    )
    sa_key_path = _gcp_resource_name(
        kind="service_account_key_summary",
        name=GOOGLE_CLOUD_DEMO_SAKEY_SUMMARY_ID,
    )
    secret_path = _gcp_resource_name(
        kind="secret_manager_summary",
        name=GOOGLE_CLOUD_DEMO_SECRET_SUMMARY_ID,
    )

    iam_res = _mk_resource(
        "google_cloud_iam_policy_summary", iam_path,
        f"IAM policy ({GOOGLE_CLOUD_DEMO_PROJECT_ID})",
    )
    fw_res = _mk_resource(
        "google_cloud_firewall_rule", fw_path, GOOGLE_CLOUD_DEMO_FIREWALL_NAME,
    )
    bucket_res = _mk_resource(
        "google_cloud_storage_bucket", bucket_path,
        GOOGLE_CLOUD_DEMO_BUCKET_NAME,
    )
    sql_res = _mk_resource(
        "google_cloud_sql_instance", sql_path,
        GOOGLE_CLOUD_DEMO_SQL_INSTANCE_NAME,
    )
    run_res = _mk_resource(
        "google_cloud_run_service", run_path,
        GOOGLE_CLOUD_DEMO_RUN_SERVICE_NAME,
    )
    gke_res = _mk_resource(
        "google_cloud_gke_cluster", gke_path,
        GOOGLE_CLOUD_DEMO_GKE_CLUSTER_NAME,
    )
    sa_key_res = _mk_resource(
        "google_cloud_service_account_key_summary", sa_key_path,
        "Service account key summary (demo project)",
    )
    secret_res = _mk_resource(
        "google_cloud_secret_manager_summary", secret_path,
        "Secret Manager summary (demo project)",
    )

    common_disclaimer = (
        "This is evidence for review and does not confirm compromise, "
        "unauthorized access, or data exposure."
    )

    iam_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="google_cloud",
        finding_key=f"google_cloud_iam_public_member:{iam_path}",
        severity="high",
        title="Demo: Google Cloud IAM policy includes a public member",
        resource_id=iam_res.id,
        description=(
            "Sample Google Cloud IAM configuration risk for the incident-"
            "workflow demo. The project IAM policy is shown including the "
            f"allUsers sentinel. {common_disclaimer}"
        ),
        evidence={
            "rule": "google_cloud_iam_public_member", "demo": True,
            "project_id": GOOGLE_CLOUD_DEMO_PROJECT_ID,
            "allusers_binding_present": True,
            "allauthenticatedusers_binding_present": False,
            "binding_count": 4,
        },
        remediation={
            "summary": (
                "Remove the allUsers / allAuthenticatedUsers binding from "
                "the project IAM policy."
            ),
        },
    )

    fw_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="google_cloud",
        finding_key=f"google_cloud_firewall_public_admin_ingress:{fw_path}",
        severity="critical",
        title="Demo: Google Cloud firewall rule allows public inbound on RDP",
        resource_id=fw_res.id,
        description=(
            "Sample Google Cloud firewall configuration risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "google_cloud_firewall_public_admin_ingress", "demo": True,
            "firewall_rule_name": GOOGLE_CLOUD_DEMO_FIREWALL_NAME,
            "network_name": GOOGLE_CLOUD_DEMO_NETWORK_NAME,
            "project_id": GOOGLE_CLOUD_DEMO_PROJECT_ID,
            "direction": "INGRESS",
            "admin_port": 3389,
            "public_source": True,
        },
        remediation={
            "summary": (
                "Restrict the source range to known IPs or remove the rule."
            ),
        },
    )

    bucket_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="google_cloud",
        finding_key=(
            f"google_cloud_storage_public_access_prevention_disabled:{bucket_path}"
        ),
        severity="high",
        title=(
            "Demo: Google Cloud Storage bucket does not enforce public "
            "access prevention"
        ),
        resource_id=bucket_res.id,
        description=(
            "Sample Google Cloud Storage posture risk for the incident-"
            f"workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "google_cloud_storage_public_access_prevention_disabled",
            "demo": True,
            "bucket_name": GOOGLE_CLOUD_DEMO_BUCKET_NAME,
            "location": "US",
            "storage_class": "STANDARD",
            "public_access_prevention": "inherited",
            "uniform_bucket_level_access_enabled": False,
        },
        remediation={
            "summary": (
                "Set publicAccessPrevention to 'enforced' and enable uniform "
                "bucket-level access."
            ),
        },
    )

    sql_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="google_cloud",
        finding_key=f"google_cloud_sql_public_network_access:{sql_path}",
        severity="high",
        title="Demo: Google Cloud SQL instance permits public network access",
        resource_id=sql_res.id,
        description=(
            "Sample Google Cloud SQL configuration risk for the incident-"
            f"workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "google_cloud_sql_public_network_access", "demo": True,
            "sql_instance_name": GOOGLE_CLOUD_DEMO_SQL_INSTANCE_NAME,
            "project_id": GOOGLE_CLOUD_DEMO_PROJECT_ID,
            "ipv4_enabled": True,
            "authorized_network_count": 0,
            "require_ssl": False,
        },
        remediation={
            "summary": (
                "Disable public IPv4 or restrict authorizedNetworks to "
                "known ranges; require SSL."
            ),
        },
    )

    run_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="google_cloud",
        finding_key=f"google_cloud_run_public_invoker:{run_path}",
        severity="high",
        title=(
            "Demo: Google Cloud Run service allows public unauthenticated "
            "invocation"
        ),
        resource_id=run_res.id,
        description=(
            "Sample Google Cloud Run configuration risk for the incident-"
            f"workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "google_cloud_run_public_invoker", "demo": True,
            "run_service_name": GOOGLE_CLOUD_DEMO_RUN_SERVICE_NAME,
            "project_id": GOOGLE_CLOUD_DEMO_PROJECT_ID,
            "allusers_invoker_present": True,
            "ingress": "all",
        },
        remediation={
            "summary": (
                "Remove allUsers from the run.invoker role and restrict "
                "ingress to internal traffic."
            ),
        },
    )

    gke_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="google_cloud",
        finding_key=f"google_cloud_gke_public_control_plane:{gke_path}",
        severity="high",
        title="Demo: Google Cloud GKE cluster has a public control plane",
        resource_id=gke_res.id,
        description=(
            "Sample Google Kubernetes Engine configuration risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "google_cloud_gke_public_control_plane", "demo": True,
            "gke_cluster_name": GOOGLE_CLOUD_DEMO_GKE_CLUSTER_NAME,
            "project_id": GOOGLE_CLOUD_DEMO_PROJECT_ID,
            "private_cluster": False,
            "master_authorized_networks_count": 0,
        },
        remediation={
            "summary": (
                "Enable private cluster or configure masterAuthorizedNetworks "
                "to known ranges."
            ),
        },
    )

    sa_key_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="google_cloud",
        finding_key=f"google_cloud_service_account_old_keys:{sa_key_path}",
        severity="medium",
        title=(
            "Demo: Google Cloud service account has long-lived user-managed "
            "keys"
        ),
        resource_id=sa_key_res.id,
        description=(
            "Sample Google Cloud service-account-key hygiene risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "google_cloud_service_account_old_keys", "demo": True,
            "project_id": GOOGLE_CLOUD_DEMO_PROJECT_ID,
            "user_managed_key_count": 2,
            "user_managed_key_old_count": 1,
            "user_managed_key_max_age_days": 420,
        },
        remediation={
            "summary": (
                "Rotate or delete user-managed service account keys older "
                "than 90 days; prefer Workload Identity."
            ),
        },
    )

    secret_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="google_cloud",
        finding_key=(
            "google_cloud_secret_manager_auto_replication_without_cmek:"
            f"{secret_path}"
        ),
        severity="medium",
        title=(
            "Demo: Google Cloud Secret Manager uses automatic replication "
            "without CMEK"
        ),
        resource_id=secret_res.id,
        description=(
            "Sample Google Cloud Secret Manager posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": (
                "google_cloud_secret_manager_auto_replication_without_cmek"
            ),
            "demo": True,
            "project_id": GOOGLE_CLOUD_DEMO_PROJECT_ID,
            "auto_replicated_secret_count": 3,
            "auto_replicated_without_cmek_count": 3,
        },
        remediation={
            "summary": (
                "Use user-managed replication with a Cloud KMS key (CMEK) "
                "for sensitive secrets."
            ),
        },
    )

    # ── Activity events ────────────────────────────────────────────────────
    # Each event uses provider="google_cloud" + source="google_cloud_audit_log"
    # so the M78E signal generator and M78F correlator both treat them just
    # like real Cloud Logging entries. Metadata uses only allowlisted keys.
    SOURCE = "google_cloud_audit_log"

    def _mk_event(
        *, event_type: str, resource_path: str, resource_type: str,
        extra: dict,
    ) -> SecurityActivityEvent:
        meta: dict[str, Any] = {
            "event_source": SOURCE,
            "project_id": GOOGLE_CLOUD_DEMO_PROJECT_ID,
            "google_cloud_event_id": f"demo-gcp-{uuid.uuid4().hex[:12]}",
            "resource_name": resource_path,
            "resource_type": resource_type,
            "status_code": 0,
        }
        meta.update(extra)
        norm = activity_svc.normalize_activity_event(
            provider="google_cloud", source=SOURCE,
            event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=meta["google_cloud_event_id"],
            actor_id=None, actor_type=None,
            resource_type=resource_type, resource_id=resource_path,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id,
            normalized=norm, db=db,
        )
        return row

    iam_event = _mk_event(
        event_type="google_cloud.iam_policy.updated",
        resource_path=f"projects/{GOOGLE_CLOUD_DEMO_PROJECT_ID}",
        resource_type="cloudresourcemanager.googleapis.com/Project",
        extra={
            "method_name": "SetIamPolicy",
            "service_name": "cloudresourcemanager.googleapis.com",
            "operation_name": "SetIamPolicy",
            "operation_family": "iam",
            "operation_action": "update",
        },
    )
    fw_event = _mk_event(
        event_type="google_cloud.firewall_rule.updated",
        resource_path=fw_path,
        resource_type="compute.googleapis.com/Firewall",
        extra={
            "method_name": "v1.compute.firewalls.patch",
            "service_name": "compute.googleapis.com",
            "operation_name": "v1.compute.firewalls.patch",
            "operation_family": "compute.firewalls",
            "operation_action": "patch",
            "firewall_rule_name": GOOGLE_CLOUD_DEMO_FIREWALL_NAME,
            "network_name": GOOGLE_CLOUD_DEMO_NETWORK_NAME,
        },
    )
    bucket_event = _mk_event(
        event_type="google_cloud.storage_bucket.updated",
        resource_path=bucket_path,
        resource_type="storage.googleapis.com/Bucket",
        extra={
            "method_name": "storage.buckets.update",
            "service_name": "storage.googleapis.com",
            "operation_name": "storage.buckets.update",
            "operation_family": "storage.buckets",
            "operation_action": "update",
            "bucket_name": GOOGLE_CLOUD_DEMO_BUCKET_NAME,
        },
    )
    sql_event = _mk_event(
        event_type="google_cloud.sql_instance.updated",
        resource_path=sql_path,
        resource_type="sqladmin.googleapis.com/Instance",
        extra={
            "method_name": "cloudsql.instances.update",
            "service_name": "sqladmin.googleapis.com",
            "operation_name": "cloudsql.instances.update",
            "operation_family": "cloudsql.instances",
            "operation_action": "update",
            "sql_instance_name": GOOGLE_CLOUD_DEMO_SQL_INSTANCE_NAME,
        },
    )
    run_event = _mk_event(
        event_type="google_cloud.run_service.updated",
        resource_path=run_path,
        resource_type="run.googleapis.com/Service",
        extra={
            "method_name": "google.cloud.run.v2.Services.UpdateService",
            "service_name": "run.googleapis.com",
            "operation_name": "google.cloud.run.v2.Services.UpdateService",
            "operation_family": "run.services",
            "operation_action": "update",
            "run_service_name": GOOGLE_CLOUD_DEMO_RUN_SERVICE_NAME,
        },
    )
    gke_event = _mk_event(
        event_type="google_cloud.gke_cluster.updated",
        resource_path=gke_path,
        resource_type="container.googleapis.com/Cluster",
        extra={
            "method_name": (
                "google.container.v1.ClusterManager.UpdateCluster"
            ),
            "service_name": "container.googleapis.com",
            "operation_name": (
                "google.container.v1.ClusterManager.UpdateCluster"
            ),
            "operation_family": "container.clusters",
            "operation_action": "update",
            "gke_cluster_name": GOOGLE_CLOUD_DEMO_GKE_CLUSTER_NAME,
        },
    )
    sa_key_event = _mk_event(
        event_type="google_cloud.service_account_key.created",
        resource_path=sa_key_path,
        resource_type="iam.googleapis.com/ServiceAccountKey",
        extra={
            "method_name": (
                "google.iam.admin.v1.CreateServiceAccountKey"
            ),
            "service_name": "iam.googleapis.com",
            "operation_name": (
                "google.iam.admin.v1.CreateServiceAccountKey"
            ),
            "operation_family": "iam.service_account_keys",
            "operation_action": "create",
        },
    )
    secret_event = _mk_event(
        event_type="google_cloud.secret.updated",
        resource_path=secret_path,
        resource_type="secretmanager.googleapis.com/Secret",
        extra={
            "method_name": "google.cloud.secretmanager.v1.UpdateSecret",
            "service_name": "secretmanager.googleapis.com",
            "operation_name": (
                "google.cloud.secretmanager.v1.UpdateSecret"
            ),
            "operation_family": "secretmanager.secrets",
            "operation_action": "update",
        },
    )

    events = [
        iam_event, fw_event, bucket_event, sql_event, run_event, gke_event,
        sa_key_event, secret_event,
    ]

    # ── Signals via the real M78E generator ────────────────────────────────
    signals: list[SecurityIncidentSignal] = []
    for ev in events:
        sig_dict = gcp_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db,
            )
            signals.append(sig)

    # ── Correlations via the real M78F builder ─────────────────────────────
    def _add_correlation(
        *, finding: SecurityFinding, event: SecurityActivityEvent,
        matched_on: str, resource_label: str,
    ) -> SecuritySignalCorrelation:
        rule = corr_svc.GOOGLE_CLOUD_CORRELATION_RULES[
            corr_svc._base_rule(finding.finding_key)
        ]
        cdict = corr_svc.build_google_cloud_correlation(
            finding=finding, event=event, rule=rule,
            matched_on=matched_on, resource_label=resource_label,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db,
        )
        return corr

    iam_corr = _add_correlation(
        finding=iam_finding, event=iam_event,
        matched_on="project_id+family",
        resource_label=f"IAM policy in project '{GOOGLE_CLOUD_DEMO_PROJECT_ID}'",
    )
    fw_corr = _add_correlation(
        finding=fw_finding, event=fw_event,
        matched_on="firewall_rule_name+project_id",
        resource_label=f'firewall rule "{GOOGLE_CLOUD_DEMO_FIREWALL_NAME}"',
    )
    bucket_corr = _add_correlation(
        finding=bucket_finding, event=bucket_event,
        matched_on="bucket_name",
        resource_label=f'Cloud Storage bucket "{GOOGLE_CLOUD_DEMO_BUCKET_NAME}"',
    )
    sql_corr = _add_correlation(
        finding=sql_finding, event=sql_event,
        matched_on="sql_instance_name+project_id",
        resource_label=(
            f'Cloud SQL instance "{GOOGLE_CLOUD_DEMO_SQL_INSTANCE_NAME}"'
        ),
    )
    run_corr = _add_correlation(
        finding=run_finding, event=run_event,
        matched_on="run_service_name+project_id",
        resource_label=(
            f'Cloud Run service "{GOOGLE_CLOUD_DEMO_RUN_SERVICE_NAME}"'
        ),
    )
    gke_corr = _add_correlation(
        finding=gke_finding, event=gke_event,
        matched_on="gke_cluster_name+project_id",
        resource_label=f'GKE cluster "{GOOGLE_CLOUD_DEMO_GKE_CLUSTER_NAME}"',
    )
    sa_key_corr = _add_correlation(
        finding=sa_key_finding, event=sa_key_event,
        matched_on="project_id+family",
        resource_label=(
            "service-account-key hygiene in project "
            f"'{GOOGLE_CLOUD_DEMO_PROJECT_ID}'"
        ),
    )
    secret_corr = _add_correlation(
        finding=secret_finding, event=secret_event,
        matched_on="project_id+family",
        resource_label=(
            "Secret Manager posture in project "
            f"'{GOOGLE_CLOUD_DEMO_PROJECT_ID}'"
        ),
    )

    correlations = [
        iam_corr, fw_corr, bucket_corr, sql_corr, run_corr, gke_corr,
        sa_key_corr, secret_corr,
    ]
    findings = [
        iam_finding, fw_finding, bucket_finding, sql_finding, run_finding,
        gke_finding, sa_key_finding, secret_finding,
    ]

    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="[Demo] Google Cloud configuration review",
        summary=(
            "Demo Google Cloud security review. It groups Google Cloud "
            "configuration findings (IAM public member, firewall public "
            "admin ingress, Cloud Storage public-access-prevention disabled, "
            "Cloud SQL public network access, Cloud Run public invoker, GKE "
            "public control plane, long-lived user-managed service account "
            "keys, and Secret Manager auto-replication without CMEK) with "
            "Google Cloud Audit Log control-plane activity for the same "
            "resources, plus the matching activity signals and risk x "
            "activity correlations. This is a human-reviewed case "
            "presenting evidence for review and may require review. "
            "ConfigTrace does not confirm compromise, unauthorized access, "
            "or data exposure."
        ),
        severity=fw_corr.severity,  # critical (firewall admin port)
        provider="google_cloud",
        metadata={
            "source": GOOGLE_CLOUD_DEMO_CASE_SOURCE,
            "repository": GOOGLE_CLOUD_DEMO_PROJECT_ID,
        },
        db=db,
    )
    for corr in correlations:
        case_svc.link_object_to_case(
            case=case, object_type="correlation", object_id=corr.id,
            actor_user_id=actor_user_id, db=db,
        )
    for finding in findings:
        case_svc.link_object_to_case(
            case=case, object_type="finding", object_id=finding.id,
            actor_user_id=actor_user_id, db=db,
        )
    for ev in events:
        case_svc.link_object_to_case(
            case=case, object_type="activity_event", object_id=ev.id,
            actor_user_id=actor_user_id, db=db,
        )
    for sig in signals:
        case_svc.link_object_to_case(
            case=case, object_type="signal", object_id=sig.id,
            actor_user_id=actor_user_id, db=db,
        )
    seen_signal_ids = {s.id for s in signals}
    for corr in correlations:
        if (
            corr.linked_signal_id is not None
            and corr.linked_signal_id not in seen_signal_ids
        ):
            seen_signal_ids.add(corr.linked_signal_id)
            case_svc.link_object_to_case(
                case=case, object_type="signal",
                object_id=corr.linked_signal_id,
                actor_user_id=actor_user_id, db=db,
            )

    logger.info(
        "google_cloud_incident_demo: seeded workspace=%s case=%s",
        workspace_id, case.id,
    )
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_google_cloud(
    *, workspace_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Remove exactly the Google Cloud demo incident objects (and nothing else)."""
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == GOOGLE_CLOUD_DEMO_CASE_SOURCE,
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

    integ = get_google_cloud_demo_integration(workspace_id, db)
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
            corr_conds.append(
                SecuritySignalCorrelation.linked_finding_id.in_(finding_ids)
            )
        if activity_ids:
            corr_conds.append(
                SecuritySignalCorrelation.linked_activity_event_id.in_(activity_ids)
            )
        if corr_conds:
            db.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                or_(*corr_conds),
            ).delete(synchronize_session=False)
        sig_conds = [SecurityIncidentSignal.integration_id == integ.id]
        if activity_ids:
            sig_conds.append(
                SecurityIncidentSignal.linked_activity_event_id.in_(activity_ids)
            )
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


# ───────────────────────────────────────────────────────────────────────────────
# Twilio incident demo (M79G)
# ───────────────────────────────────────────────────────────────────────────────


def get_twilio_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == TWILIO_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_twilio_demo_case(
    workspace_id: uuid.UUID, db: Session
) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == TWILIO_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_twilio_status(
    workspace_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    case = _existing_twilio_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_twilio(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Twilio demo incident chain (idempotent). No real Twilio sync.

    All objects are anchored on a hidden demo integration so ``clear_twilio``
    removes them and nothing else. Evidence is built directly for the demo
    objects (never by scanning the real workspace).

    PRIVACY: no auth tokens, API key secrets, full account SIDs matching
    AC/SK hex patterns, full E.164 phone numbers, message bodies, call logs,
    recordings, raw webhook URLs, or customer data are ever included. Only
    the last-4 digits of a phone number are used (phone_number_last4).
    """
    existing = _existing_twilio_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" → never shown / never synced).
    integ = get_twilio_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({
            "demo": True, "dataset": TWILIO_DEMO_DATASET,
        })
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=TWILIO_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    common_disclaimer = (
        "This is evidence for review and does not confirm compromise, "
        "unauthorized access, or data exposure."
    )

    # 2. Security findings using real Twilio rule keys (M79B/M79C).
    phone_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="twilio",
        finding_key=f"twilio_phone_number_sms_webhook_missing:{TWILIO_DEMO_PHONE_RESOURCE}",
        severity="high",
        title="Demo: Twilio incoming phone number has no SMS webhook configured",
        resource_id=None,
        description=(
            "Sample Twilio phone number configuration risk for the incident-"
            f"workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "twilio_phone_number_sms_webhook_missing", "demo": True,
            "phone_number_sid": TWILIO_DEMO_PHONE_RESOURCE,
            "phone_number_last4": "0429",
            "iso_country": "US",
            "capability_sms": True,
            "sms_url_configured": False,
        },
        remediation={
            "summary": (
                "Configure an SMS webhook URL for this incoming phone number "
                "to ensure SMS delivery events are observable."
            ),
        },
    )

    messaging_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="twilio",
        finding_key=(
            f"twilio_messaging_service_observability_gap:{TWILIO_DEMO_MESSAGING_SERVICE}"
        ),
        severity="high",
        title="Demo: Twilio messaging service has no fallback or status callback URL",
        resource_id=None,
        description=(
            "Sample Twilio messaging service observability-gap risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "twilio_messaging_service_observability_gap", "demo": True,
            "messaging_service_sid": TWILIO_DEMO_MESSAGING_SERVICE,
            "fallback_url_configured": False,
            "status_callback_url_configured": False,
        },
        remediation={
            "summary": (
                "Configure a fallback URL and status callback URL for the "
                "messaging service to enable full delivery observability."
            ),
        },
    )

    verify_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="twilio",
        finding_key=(
            f"twilio_verify_short_code_length:{TWILIO_DEMO_VERIFY_SERVICE}"
        ),
        severity="medium",
        title="Demo: Twilio Verify service uses a short verification code (4 digits)",
        resource_id=None,
        description=(
            "Sample Twilio Verify service posture risk for the incident-"
            f"workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "twilio_verify_short_code_length", "demo": True,
            "verify_service_sid": TWILIO_DEMO_VERIFY_SERVICE,
            "code_length": 4,
        },
        remediation={
            "summary": (
                "Increase the verification code length to 6 or more digits "
                "to reduce brute-force risk."
            ),
        },
    )

    api_key_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="twilio",
        finding_key=f"twilio_api_key_stale:{TWILIO_DEMO_API_KEY_ID}",
        severity="high",
        title="Demo: Twilio API key has not been rotated in over 180 days",
        resource_id=None,
        description=(
            "Sample Twilio API key staleness risk for the incident-workflow "
            f"demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "twilio_api_key_stale", "demo": True,
            "api_key_sid": TWILIO_DEMO_API_KEY_ID,
            "date_created": "2023-01-01T00:00:00Z",
            "date_updated": "2023-06-01T00:00:00Z",
        },
        remediation={
            "summary": (
                "Rotate this API key and update any services that depend on it. "
                "Establish a regular key-rotation schedule."
            ),
        },
    )

    findings = [phone_finding, messaging_finding, verify_finding, api_key_finding]

    # 3. Activity events (provider="twilio", source="twilio_activity_event").
    TWILIO_ACTIVITY_SOURCE = "twilio_activity_event"

    def _mk_twilio_event(
        *, event_type: str, resource_type: str, provider_event_id: str,
        extra: dict,
    ) -> SecurityActivityEvent:
        meta: dict[str, Any] = {
            "resource_type": resource_type,
            "event_action": event_type,
        }
        meta.update(extra)
        norm = activity_svc.normalize_activity_event(
            provider="twilio", source=TWILIO_ACTIVITY_SOURCE,
            event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=provider_event_id,
            actor_id=None, actor_type=None,
            resource_type=resource_type, resource_id=provider_event_id,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id,
            normalized=norm, db=db,
        )
        return row

    phone_event = _mk_twilio_event(
        event_type="twilio.phone_number.updated",
        resource_type="incoming-phone-number",
        provider_event_id="TWILIO_DEMO_EVT_PHONE_001",
        extra={
            "twilio_resource_sid_prefix": "TWILIO_D",
            "phone_number_last4": "0429",
        },
    )
    msg_event = _mk_twilio_event(
        event_type="twilio.messaging_service.updated",
        resource_type="messaging-service",
        provider_event_id="TWILIO_DEMO_EVT_MSG_001",
        extra={
            "twilio_resource_sid_prefix": "TWILIO_D",
            "messaging_service_sid": TWILIO_DEMO_MESSAGING_SERVICE,
        },
    )
    pool_event = _mk_twilio_event(
        event_type="twilio.messaging_service.sender_pool.updated",
        resource_type="messaging-service",
        provider_event_id="TWILIO_DEMO_EVT_POOL_001",
        extra={
            "twilio_resource_sid_prefix": "TWILIO_D",
            "messaging_service_sid": TWILIO_DEMO_MESSAGING_SERVICE,
        },
    )
    verify_event = _mk_twilio_event(
        event_type="twilio.verify_service.updated",
        resource_type="verify-service",
        provider_event_id="TWILIO_DEMO_EVT_VERIFY_001",
        extra={
            "twilio_resource_sid_prefix": "TWILIO_D",
            "verify_service_sid": TWILIO_DEMO_VERIFY_SERVICE,
        },
    )
    api_key_event = _mk_twilio_event(
        event_type="twilio.api_key.updated",
        resource_type="api-key",
        provider_event_id="TWILIO_DEMO_EVT_APIKEY_001",
        extra={
            "twilio_resource_sid_prefix": "TWILIO_D",
            "api_key_sid": TWILIO_DEMO_API_KEY_ID,
        },
    )

    events = [phone_event, msg_event, pool_event, verify_event, api_key_event]

    # 4. Activity signals via the real M79E signal builder.
    signals: list[SecurityIncidentSignal] = []
    for ev in events:
        sig_dict = twilio_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db,
            )
            signals.append(sig)

    # 5. Correlations via the real M79F builder.
    #    Each correlation joins a finding to a signal (not directly to an event).
    twilio_correlations: list[SecuritySignalCorrelation] = []

    def _add_twilio_correlation(
        *,
        finding: SecurityFinding,
        signal: SecurityIncidentSignal,
        correlation_type: str,
        match_reason: str,
    ) -> SecuritySignalCorrelation:
        rule = twilio_corr_svc.TWILIO_CORRELATION_RULES[correlation_type]
        cdict = twilio_corr_svc._build_correlation(
            finding=finding, signal=signal,
            correlation_type=correlation_type, rule=rule,
            match_reason=match_reason,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db,
        )
        twilio_correlations.append(corr)
        return corr

    # Map signal types to signal objects.
    signals_by_type: dict[str, SecurityIncidentSignal] = {
        s.signal_type: s for s in signals
    }

    phone_signal = signals_by_type.get("twilio_phone_number_config_changed")
    msg_signal = signals_by_type.get("twilio_messaging_service_config_changed")
    verify_signal = signals_by_type.get("twilio_verify_service_config_changed")
    api_key_signal = signals_by_type.get("twilio_api_key_config_changed")

    if phone_signal is not None:
        _add_twilio_correlation(
            finding=phone_finding,
            signal=phone_signal,
            correlation_type="twilio_phone_number_risk_activity_correlation",
            match_reason="phone_number_family",
        )
    if msg_signal is not None:
        _add_twilio_correlation(
            finding=messaging_finding,
            signal=msg_signal,
            correlation_type="twilio_messaging_service_risk_activity_correlation",
            match_reason="messaging_service_sid_match",
        )
    if verify_signal is not None:
        _add_twilio_correlation(
            finding=verify_finding,
            signal=verify_signal,
            correlation_type="twilio_verify_service_risk_activity_correlation",
            match_reason="verify_service_sid_match",
        )
    if api_key_signal is not None:
        _add_twilio_correlation(
            finding=api_key_finding,
            signal=api_key_signal,
            correlation_type="twilio_api_key_risk_activity_correlation",
            match_reason="api_key_sid_match",
        )

    # 6. Case — links 4 findings, 5 events, up to 4 signals, up to 4 correlations.
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title=(
            "[Demo] Twilio configuration review: webhook, Verify, and API key posture"
        ),
        summary=(
            "Review-safe Twilio demo case linking configuration risks to "
            "control-plane activity evidence. Groups Twilio configuration "
            "findings (phone number SMS webhook missing, messaging service "
            "observability gap, Verify service short code length, and stale "
            "API key) with Twilio Monitor-style control-plane activity events "
            "for the same resources, plus the matching activity signals and "
            "risk x activity correlations. Marked demo — no real Twilio sync, "
            "no message bodies, no call logs, no recordings, no customer data. "
            "Evidence for review. Does not confirm compromise or unauthorized "
            "access."
        ),
        severity="high",
        provider="twilio",
        metadata={
            "source": TWILIO_DEMO_CASE_SOURCE,
        },
        db=db,
    )

    for finding in findings:
        case_svc.link_object_to_case(
            case=case, object_type="finding", object_id=finding.id,
            actor_user_id=actor_user_id, db=db,
        )
    for ev in events:
        case_svc.link_object_to_case(
            case=case, object_type="activity_event", object_id=ev.id,
            actor_user_id=actor_user_id, db=db,
        )
    seen_signal_ids: set = set()
    for sig in signals:
        seen_signal_ids.add(sig.id)
        case_svc.link_object_to_case(
            case=case, object_type="signal", object_id=sig.id,
            actor_user_id=actor_user_id, db=db,
        )
    for corr in twilio_correlations:
        case_svc.link_object_to_case(
            case=case, object_type="correlation", object_id=corr.id,
            actor_user_id=actor_user_id, db=db,
        )
        if (
            corr.linked_signal_id is not None
            and corr.linked_signal_id not in seen_signal_ids
        ):
            seen_signal_ids.add(corr.linked_signal_id)
            case_svc.link_object_to_case(
                case=case, object_type="signal",
                object_id=corr.linked_signal_id,
                actor_user_id=actor_user_id, db=db,
            )

    logger.info(
        "twilio_incident_demo: seeded workspace=%s case=%s",
        workspace_id, case.id,
    )
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_twilio(
    *, workspace_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Remove exactly the Twilio demo incident objects (and nothing else)."""
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == TWILIO_DEMO_CASE_SOURCE,
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

    integ = get_twilio_demo_integration(workspace_id, db)
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
            corr_conds.append(
                SecuritySignalCorrelation.linked_finding_id.in_(finding_ids)
            )
        if activity_ids:
            corr_conds.append(
                SecuritySignalCorrelation.linked_activity_event_id.in_(activity_ids)
            )
        if corr_conds:
            db.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                or_(*corr_conds),
            ).delete(synchronize_session=False)
        sig_conds = [SecurityIncidentSignal.integration_id == integ.id]
        if activity_ids:
            sig_conds.append(
                SecurityIncidentSignal.linked_activity_event_id.in_(activity_ids)
            )
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


# ── SendGrid incident demo (M80G) — a SEPARATE hidden demo integration + case
# source so "Clear SendGrid demo" removes only SendGrid demo objects and never
# touches any other provider demo. Same safety rules:
#   - clearly marked demo, no real SendGrid sync, no notifications
#   - never touches a real SendGrid integration
#   - idempotent
#
# Forbidden in demo evidence: API key values, bearer tokens, authorization
# headers, email bodies, subject lines, recipient emails, sender personal
# emails (full), suppression recipient emails, template HTML/plaintext,
# dynamic template content, raw webhook URLs, raw inbound parse hostnames,
# marketing contact data, mail event payloads (bounce/click/open/delivered/
# dropped/spamreport/unsubscribe), message IDs, DNS token values, DKIM keys,
# customer data, or PII.
#
# Strings must NEVER match SG.[A-Za-z0-9_-]{10,}.[A-Za-z0-9_-]{10,}.
SENDGRID_DEMO_INTEGRATION_NAME = "ConfigTrace SendGrid incident demo (sample data)"
SENDGRID_DEMO_CASE_SOURCE = "demo_sendgrid_incident"
SENDGRID_DEMO_DATASET = "sendgrid_incident_demo_v1"

# Safe synthetic identifiers — plain-English placeholders only.
# NEVER real SendGrid SID/key format patterns.
SENDGRID_DEMO_API_KEY_ID = "SENDGRID_DEMO_API_KEY_ID"
SENDGRID_DEMO_SENDER_ID = "SENDGRID_DEMO_SENDER_ID"
SENDGRID_DEMO_DOMAIN_ID = "SENDGRID_DEMO_DOMAIN_ID"


def get_sendgrid_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == SENDGRID_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_sendgrid_demo_case(
    workspace_id: uuid.UUID, db: Session
) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == SENDGRID_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_sendgrid_status(
    workspace_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    case = _existing_sendgrid_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_sendgrid(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the SendGrid demo incident chain (idempotent). No real SendGrid sync.

    All objects are anchored on a hidden demo integration so ``clear_sendgrid``
    removes them and nothing else. Evidence is built directly for the demo
    objects (never by scanning the real workspace).

    PRIVACY: no API key values, bearer tokens, authorization headers, email
    bodies, subject lines, recipient emails, sender personal emails, suppression
    recipient emails, template content, raw webhook URLs, raw inbound parse
    hostnames, mail event payloads, message IDs, DNS token values, customer
    data, or PII are ever included. Only safe booleans, counts, opaque IDs,
    and domain names are used.

    SECURITY: no strings matching SG.[A-Za-z0-9_-]{10,}.[A-Za-z0-9_-]{10,}
    are used. Placeholders are plain-English strings.
    """
    existing = _existing_sendgrid_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" → never shown / never synced).
    integ = get_sendgrid_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({
            "demo": True, "dataset": SENDGRID_DEMO_DATASET,
        })
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=SENDGRID_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    common_disclaimer = (
        "This is evidence for review and does not confirm compromise, "
        "unauthorized access, or data exposure."
    )

    # 2. Security findings using real SendGrid rule keys (M80B/M80C).
    #    Evidence uses only safe booleans, counts, and opaque IDs.
    api_key_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="sendgrid",
        finding_key=(
            f"sendgrid_api_key_broad_scopes:{SENDGRID_DEMO_API_KEY_ID}"
        ),
        severity="high",
        title="Demo: SendGrid API key is configured with broad access scopes",
        resource_id=None,
        description=(
            "Sample SendGrid API key broad-scope risk for the incident-workflow "
            f"demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "sendgrid_api_key_broad_scopes", "demo": True,
            "api_key_id": SENDGRID_DEMO_API_KEY_ID,
            "name": "Demo broad-scope key",
            "scopes_count": 12,
            "has_full_access": True,
        },
        remediation={
            "summary": (
                "Review API key scopes and restrict to least-privilege — "
                "create a new key scoped only to its required operations."
            ),
        },
    )

    sender_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="sendgrid",
        finding_key=(
            f"sendgrid_sender_identity_unverified:{SENDGRID_DEMO_SENDER_ID}"
        ),
        severity="medium",
        title="Demo: SendGrid sender identity has not been verified",
        resource_id=None,
        description=(
            "Sample SendGrid sender identity verification risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "sendgrid_sender_identity_unverified", "demo": True,
            "sender_id": SENDGRID_DEMO_SENDER_ID,
            "nickname": "Demo Sender",
            "from_email_domain": "demo-domain.example",
            "verified": False,
        },
        remediation={
            "summary": (
                "Complete sender identity verification in SendGrid Console "
                "under Settings > Sender Authentication."
            ),
        },
    )

    domain_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="sendgrid",
        finding_key=(
            f"sendgrid_domain_authentication_invalid:{SENDGRID_DEMO_DOMAIN_ID}"
        ),
        severity="medium",
        title="Demo: SendGrid domain authentication is not passing DNS validation",
        resource_id=None,
        description=(
            "Sample SendGrid domain authentication posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "sendgrid_domain_authentication_invalid", "demo": True,
            "domain_id": SENDGRID_DEMO_DOMAIN_ID,
            "domain": "mail.demo-domain.example",
            "valid": False,
            "dns_record_count": 0,
        },
        remediation={
            "summary": (
                "Fix the failing DNS records for this domain authentication "
                "in SendGrid Console under Settings > Sender Authentication."
            ),
        },
    )

    mail_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="sendgrid",
        finding_key="sendgrid_spam_check_disabled:sendgrid_mail_settings_main",
        severity="medium",
        title="Demo: SendGrid spam check is disabled",
        resource_id=None,
        description=(
            "Sample SendGrid mail settings risk for the incident-workflow "
            f"demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "sendgrid_spam_check_disabled", "demo": True,
            "spam_check_enabled": False,
        },
        remediation={
            "summary": (
                "Enable the spam check mail setting in SendGrid Console "
                "under Settings > Mail Settings."
            ),
        },
    )

    tracking_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="sendgrid",
        finding_key=(
            "sendgrid_subscription_tracking_disabled:sendgrid_tracking_settings_main"
        ),
        severity="medium",
        title="Demo: SendGrid subscription (unsubscribe) tracking is disabled",
        resource_id=None,
        description=(
            "Sample SendGrid tracking settings risk for the incident-workflow "
            f"demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "sendgrid_subscription_tracking_disabled", "demo": True,
            "subscription_tracking_enabled": False,
        },
        remediation={
            "summary": (
                "Enable subscription tracking in SendGrid Console under "
                "Settings > Tracking to ensure compliance with unsubscribe requirements."
            ),
        },
    )

    webhook_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="sendgrid",
        finding_key=(
            "sendgrid_inbound_parse_spam_check_disabled:sendgrid_webhook_settings_main"
        ),
        severity="medium",
        title="Demo: SendGrid inbound parse spam check is disabled",
        resource_id=None,
        description=(
            "Sample SendGrid inbound parse posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "sendgrid_inbound_parse_spam_check_disabled", "demo": True,
            "inbound_parse_enabled": True,
            "inbound_parse_spam_check_enabled": False,
        },
        remediation={
            "summary": (
                "Enable spam check for the inbound parse configuration in "
                "SendGrid Console under Settings > Inbound Parse."
            ),
        },
    )

    suppression_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="sendgrid",
        finding_key=(
            "sendgrid_suppression_settings_empty:sendgrid_suppression_settings_main"
        ),
        severity="low",
        title="Demo: SendGrid has no suppression groups configured",
        resource_id=None,
        description=(
            "Sample SendGrid suppression settings risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "sendgrid_suppression_settings_empty", "demo": True,
            "suppression_group_count": 0,
        },
        remediation={
            "summary": (
                "Create suppression groups for email categories in SendGrid "
                "Console under Marketing > Suppressions > Unsubscribe Groups."
            ),
        },
    )

    findings = [
        api_key_finding, sender_finding, domain_finding,
        mail_finding, tracking_finding, webhook_finding, suppression_finding,
    ]

    # 3. Activity events (provider="sendgrid", source="sendgrid_activity_event").
    SENDGRID_ACTIVITY_SOURCE = "sendgrid_activity_event"

    def _mk_sg_event(
        *, event_type: str, resource_type: str, provider_event_id: str,
        extra: dict,
    ) -> SecurityActivityEvent:
        meta: dict[str, Any] = {
            "resource_type": resource_type,
            "event_action": event_type,
            "event_source": SENDGRID_ACTIVITY_SOURCE,
            "status": "observed",
            "category": resource_type,
        }
        meta.update(extra)
        norm = activity_svc.normalize_activity_event(
            provider="sendgrid", source=SENDGRID_ACTIVITY_SOURCE,
            event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=provider_event_id,
            actor_id=None, actor_type=None,
            resource_type=resource_type, resource_id=provider_event_id,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id,
            normalized=norm, db=db,
        )
        return row

    api_key_event = _mk_sg_event(
        event_type="sendgrid.api_key.updated",
        resource_type="api_key",
        provider_event_id="SENDGRID_DEMO_EVT_APIKEY_001",
        extra={
            "api_key_id": SENDGRID_DEMO_API_KEY_ID,
            "resource_id": SENDGRID_DEMO_API_KEY_ID,
            "resource_name": "Demo broad-scope key",
        },
    )
    sender_event = _mk_sg_event(
        event_type="sendgrid.sender_identity.updated",
        resource_type="sender_identity",
        provider_event_id="SENDGRID_DEMO_EVT_SENDER_001",
        extra={
            "sender_id": SENDGRID_DEMO_SENDER_ID,
            "resource_id": SENDGRID_DEMO_SENDER_ID,
            "sender_verified": False,
            "sender_locked": False,
        },
    )
    domain_event = _mk_sg_event(
        event_type="sendgrid.domain_authentication.updated",
        resource_type="domain_authentication",
        provider_event_id="SENDGRID_DEMO_EVT_DOMAIN_001",
        extra={
            "domain_id": SENDGRID_DEMO_DOMAIN_ID,
            "resource_id": SENDGRID_DEMO_DOMAIN_ID,
            "domain_valid": False,
            "automatic_security": False,
            "dns_record_count": 0,
        },
    )
    mail_event = _mk_sg_event(
        event_type="sendgrid.mail_settings.updated",
        resource_type="mail_settings",
        provider_event_id="SENDGRID_DEMO_EVT_MAIL_001",
        extra={
            "mail_setting_name": "mail_settings_config",
        },
    )
    tracking_event = _mk_sg_event(
        event_type="sendgrid.tracking_settings.updated",
        resource_type="tracking_settings",
        provider_event_id="SENDGRID_DEMO_EVT_TRACKING_001",
        extra={
            "tracking_setting_name": "tracking_settings_config",
        },
    )
    webhook_event = _mk_sg_event(
        event_type="sendgrid.event_webhook.updated",
        resource_type="event_webhook",
        provider_event_id="SENDGRID_DEMO_EVT_WEBHOOK_001",
        extra={
            "event_webhook_enabled": True,
            "event_webhook_has_url": False,
            "inbound_parse_enabled": True,
            "inbound_parse_spam_check_enabled": False,
        },
    )
    inbound_parse_event = _mk_sg_event(
        event_type="sendgrid.inbound_parse.updated",
        resource_type="event_webhook",
        provider_event_id="SENDGRID_DEMO_EVT_INBOUND_001",
        extra={
            "inbound_parse_enabled": True,
            "inbound_parse_send_raw_enabled": False,
            "inbound_parse_spam_check_enabled": False,
        },
    )
    suppression_event = _mk_sg_event(
        event_type="sendgrid.suppression_settings.updated",
        resource_type="suppression_settings",
        provider_event_id="SENDGRID_DEMO_EVT_SUPPRESSION_001",
        extra={
            "suppression_group_count": 0,
        },
    )

    events = [
        api_key_event, sender_event, domain_event, mail_event,
        tracking_event, webhook_event, inbound_parse_event, suppression_event,
    ]

    # 4. Activity signals via the real M80E signal builder.
    signals: list[SecurityIncidentSignal] = []
    for ev in events:
        sig_dict = sg_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db,
            )
            signals.append(sig)

    # 5. Correlations via the real M80F builder.
    sg_correlations: list[SecuritySignalCorrelation] = []
    signals_by_type: dict[str, SecurityIncidentSignal] = {
        s.signal_type: s for s in signals
    }

    def _add_sg_correlation(
        *,
        finding: SecurityFinding,
        signal: SecurityIncidentSignal,
        correlation_type: str,
        match_reason: str,
    ) -> SecuritySignalCorrelation:
        rule = sg_corr_svc.SENDGRID_CORRELATION_RULES[correlation_type]
        cdict = sg_corr_svc._build_correlation(
            finding=finding, signal=signal,
            correlation_type=correlation_type, rule=rule,
            match_reason=match_reason,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db,
        )
        sg_correlations.append(corr)
        return corr

    api_key_signal = signals_by_type.get("sendgrid_api_key_config_changed")
    sender_signal = signals_by_type.get("sendgrid_sender_identity_config_changed")
    domain_signal = signals_by_type.get("sendgrid_domain_authentication_config_changed")
    mail_signal = signals_by_type.get("sendgrid_mail_settings_config_changed")
    tracking_signal = signals_by_type.get("sendgrid_tracking_settings_config_changed")
    webhook_signal = signals_by_type.get("sendgrid_event_webhook_config_changed")
    inbound_signal = signals_by_type.get("sendgrid_inbound_parse_config_changed")
    suppression_signal = signals_by_type.get("sendgrid_suppression_settings_config_changed")

    if api_key_signal is not None:
        _add_sg_correlation(
            finding=api_key_finding,
            signal=api_key_signal,
            correlation_type="sendgrid_api_key_risk_activity_correlation",
            match_reason="api_key_id_match",
        )
    if sender_signal is not None:
        _add_sg_correlation(
            finding=sender_finding,
            signal=sender_signal,
            correlation_type="sendgrid_sender_identity_risk_activity_correlation",
            match_reason="sender_id_match",
        )
    if domain_signal is not None:
        _add_sg_correlation(
            finding=domain_finding,
            signal=domain_signal,
            correlation_type="sendgrid_domain_authentication_risk_activity_correlation",
            match_reason="domain_id_match",
        )
    if mail_signal is not None:
        _add_sg_correlation(
            finding=mail_finding,
            signal=mail_signal,
            correlation_type="sendgrid_mail_settings_risk_activity_correlation",
            match_reason="mail_settings_family",
        )
    if tracking_signal is not None:
        _add_sg_correlation(
            finding=tracking_finding,
            signal=tracking_signal,
            correlation_type="sendgrid_tracking_settings_risk_activity_correlation",
            match_reason="tracking_settings_family",
        )
    # Use whichever webhook signal was created first
    wh_signal = webhook_signal or inbound_signal
    if wh_signal is not None:
        _add_sg_correlation(
            finding=webhook_finding,
            signal=wh_signal,
            correlation_type="sendgrid_webhook_risk_activity_correlation",
            match_reason="webhook_family",
        )
    if suppression_signal is not None:
        _add_sg_correlation(
            finding=suppression_finding,
            signal=suppression_signal,
            correlation_type="sendgrid_suppression_settings_risk_activity_correlation",
            match_reason="suppression_settings_family",
        )

    # 6. Case linking 7 findings, 8 events, signals, and correlations.
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title=(
            "[Demo] SendGrid configuration review: API key, sender identity, "
            "domain authentication, and mail/webhook posture"
        ),
        summary=(
            "Review-safe SendGrid demo case linking configuration risks to "
            "control-plane activity evidence. Groups SendGrid configuration "
            "findings (API key broad-scope, sender identity unverified, "
            "domain authentication invalid, spam check disabled, subscription "
            "tracking disabled, inbound parse spam check disabled, suppression "
            "settings empty) with SendGrid configuration-state activity events "
            "for the same surfaces, plus the matching activity signals and "
            "risk x activity correlations. Marked demo — no real SendGrid sync, "
            "no email bodies, no subject lines, no recipient emails, no sender "
            "personal emails, no template content, no raw webhook URLs, no API "
            "key values, no customer data. Evidence for review. Does not "
            "confirm compromise or unauthorized access."
        ),
        severity="high",
        provider="sendgrid",
        metadata={
            "source": SENDGRID_DEMO_CASE_SOURCE,
        },
        db=db,
    )

    for finding in findings:
        case_svc.link_object_to_case(
            case=case, object_type="finding", object_id=finding.id,
            actor_user_id=actor_user_id, db=db,
        )
    for ev in events:
        case_svc.link_object_to_case(
            case=case, object_type="activity_event", object_id=ev.id,
            actor_user_id=actor_user_id, db=db,
        )
    seen_signal_ids: set = set()
    for sig in signals:
        seen_signal_ids.add(sig.id)
        case_svc.link_object_to_case(
            case=case, object_type="signal", object_id=sig.id,
            actor_user_id=actor_user_id, db=db,
        )
    for corr in sg_correlations:
        case_svc.link_object_to_case(
            case=case, object_type="correlation", object_id=corr.id,
            actor_user_id=actor_user_id, db=db,
        )
        if (
            corr.linked_signal_id is not None
            and corr.linked_signal_id not in seen_signal_ids
        ):
            seen_signal_ids.add(corr.linked_signal_id)
            case_svc.link_object_to_case(
                case=case, object_type="signal",
                object_id=corr.linked_signal_id,
                actor_user_id=actor_user_id, db=db,
            )

    logger.info(
        "sendgrid_incident_demo: seeded workspace=%s case=%s",
        workspace_id, case.id,
    )
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_sendgrid(
    *, workspace_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Remove exactly the SendGrid demo incident objects (and nothing else)."""
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == SENDGRID_DEMO_CASE_SOURCE,
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

    integ = get_sendgrid_demo_integration(workspace_id, db)
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
            corr_conds.append(
                SecuritySignalCorrelation.linked_finding_id.in_(finding_ids)
            )
        if activity_ids:
            corr_conds.append(
                SecuritySignalCorrelation.linked_activity_event_id.in_(activity_ids)
            )
        if corr_conds:
            db.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                or_(*corr_conds),
            ).delete(synchronize_session=False)
        sig_conds = [SecurityIncidentSignal.integration_id == integ.id]
        if activity_ids:
            sig_conds.append(
                SecurityIncidentSignal.linked_activity_event_id.in_(activity_ids)
            )
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


# ── Auth0 incident demo (M81G) ────────────────────────────────────────────────
#
# A SEPARATE hidden demo integration + case source so "Clear Auth0 demo" removes
# only Auth0 demo objects and never touches any other provider's demo or real
# evidence. Same safety rules: clearly marked demo, no real Auth0 sync, no
# notifications, no client secrets, no management tokens, no JWTs, no raw
# callback/logout/origin URLs, no raw Auth0 logs, no rule/action code, no user
# emails, no user IDs, no IP addresses, no session data, no customer data or PII.
#
# Chain (one coherent story per resource type):
#   Auth0 configuration risks (tenant, application, connection, resource_server,
#   rule, action, mfa_factor, custom_domain) -> Auth0 config-state activity events
#   (auth0.tenant.updated, auth0.application.updated, auth0.connection.updated,
#   auth0.resource_server.updated, auth0.rule.updated, auth0.action.deployed,
#   auth0.mfa_factor.updated, auth0.custom_domain.updated) -> Auth0 activity
#   signals -> Auth0 risk x activity correlations -> case.

AUTH0_DEMO_INTEGRATION_NAME = "ConfigTrace Auth0 incident demo (sample data)"
AUTH0_DEMO_CASE_SOURCE = "demo_auth0_incident"
AUTH0_DEMO_DATASET = "auth0_incident_demo_v1"

# Safe placeholder IDs (no real-looking Auth0 values, no JWTs, no secrets).
_AUTH0_DEMO_TENANT_ID = "AUTH0_DEMO_TENANT_ID"
_AUTH0_DEMO_CLIENT_ID = "AUTH0_DEMO_CLIENT_ID"
_AUTH0_DEMO_CONNECTION_ID = "AUTH0_DEMO_CONNECTION_ID"
_AUTH0_DEMO_RESOURCE_SERVER_ID = "AUTH0_DEMO_RESOURCE_SERVER_ID"
_AUTH0_DEMO_RULE_ID = "AUTH0_DEMO_RULE_ID"
_AUTH0_DEMO_ACTION_ID = "AUTH0_DEMO_ACTION_ID"
_AUTH0_DEMO_FACTOR_NAME = "otp"
_AUTH0_DEMO_CUSTOM_DOMAIN_ID = "AUTH0_DEMO_CUSTOM_DOMAIN_ID"


def get_auth0_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == AUTH0_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_auth0_demo_case(
    workspace_id: uuid.UUID, db: Session
) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == AUTH0_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_auth0_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_auth0_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_auth0(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Auth0 demo incident chain (idempotent). No real Auth0 sync.

    One coherent Auth0 story per resource type:
      Configuration risks (tenant, application, connection, resource_server,
      rule, action, mfa_factor, custom_domain) -> Auth0 config-state activity
      events -> Auth0 activity signals -> Auth0 risk x activity correlations
      -> case.

    All objects are anchored on a hidden demo integration so ``clear_auth0``
    removes them and nothing else. Evidence is built directly for the demo
    objects (never by scanning the real workspace).

    PRIVACY: no client secrets, management API tokens, access tokens, refresh
    tokens, ID tokens, JWTs, JWKS private material, signing private keys,
    authorization headers, raw Auth0 API responses, raw callback/logout/origin
    URLs, user emails, user names, user IDs, login history, IP addresses,
    session data, MFA recovery codes, connection credentials, rule/action code,
    raw Auth0 logs, or customer data are ever included.

    SECURITY: no strings matching eyJ[A-Za-z0-9_-]{10,} are used. Placeholders
    are uppercase ASCII sentinel strings only.
    """
    existing = _existing_auth0_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" → never shown / never synced).
    integ = get_auth0_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({
            "demo": True, "dataset": AUTH0_DEMO_DATASET,
        })
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=AUTH0_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    common_disclaimer = (
        "This is evidence for review and does not confirm compromise, "
        "unauthorized access, or data exposure."
    )

    # 2. Security findings using real Auth0 rule keys (M81B/M81C).
    #    Evidence uses only safe booleans, counts, opaque IDs, and category
    #    labels — never client_secret, management tokens, JWTs, raw URLs,
    #    rule/action code, user emails, IP addresses, or credentials.

    tenant_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="auth0",
        finding_key=(
            f"auth0_tenant_session_lifetime_extended:{_AUTH0_DEMO_TENANT_ID}#demo"
        ),
        severity="medium",
        title="Demo: Auth0 tenant has an extended session lifetime",
        resource_id=None,
        description=(
            "Sample Auth0 tenant session posture risk for the incident-workflow "
            f"demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "auth0_tenant_session_lifetime_extended", "demo": True,
            "session_lifetime_category": "extended",
        },
        remediation={
            "summary": (
                "Review the Auth0 tenant session lifetime and reduce it to the "
                "minimum value needed for your application users."
            ),
        },
    )

    application_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="auth0",
        finding_key=(
            f"auth0_application_token_endpoint_auth_none:{_AUTH0_DEMO_CLIENT_ID}#demo"
        ),
        severity="high",
        title="Demo: Auth0 application uses no token endpoint authentication",
        resource_id=None,
        description=(
            "Sample Auth0 application OAuth posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "auth0_application_token_endpoint_auth_none", "demo": True,
            "client_id": _AUTH0_DEMO_CLIENT_ID,
            "token_endpoint_auth_method": "none",
            "app_type": "regular_web",
            "callbacks_count": 12,
            "allowed_origins_count": 6,
        },
        remediation={
            "summary": (
                "Configure a token endpoint authentication method "
                "(client_secret_post or private_key_jwt) for this application."
            ),
        },
    )

    connection_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="auth0",
        finding_key=(
            f"auth0_connection_weak_password_policy:{_AUTH0_DEMO_CONNECTION_ID}#demo"
        ),
        severity="high",
        title="Demo: Auth0 connection has a weak password policy",
        resource_id=None,
        description=(
            "Sample Auth0 connection password policy risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "auth0_connection_weak_password_policy", "demo": True,
            "connection_id": _AUTH0_DEMO_CONNECTION_ID,
            "password_policy_category": "weak",
            "enabled_clients_count": 0,
        },
        remediation={
            "summary": (
                "Upgrade the database connection password policy to at least "
                "'good' strength."
            ),
        },
    )

    resource_server_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="auth0",
        finding_key=(
            f"auth0_resource_server_rbac_disabled:{_AUTH0_DEMO_RESOURCE_SERVER_ID}#demo"
        ),
        severity="medium",
        title="Demo: Auth0 resource server has RBAC disabled",
        resource_id=None,
        description=(
            "Sample Auth0 resource server / API posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "auth0_resource_server_rbac_disabled", "demo": True,
            "resource_server_id": _AUTH0_DEMO_RESOURCE_SERVER_ID,
            "rbac_enabled": False,
            "allow_offline_access": True,
        },
        remediation={
            "summary": (
                "Enable RBAC on the Auth0 resource server and define "
                "explicit permission scopes."
            ),
        },
    )

    rule_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="auth0",
        finding_key=(
            f"auth0_rule_disabled:{_AUTH0_DEMO_RULE_ID}#demo"
        ),
        severity="medium",
        title="Demo: Auth0 auth-pipeline rule is disabled",
        resource_id=None,
        description=(
            "Sample Auth0 auth-pipeline rule posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "auth0_rule_disabled", "demo": True,
            "rule_id": _AUTH0_DEMO_RULE_ID,
            "enabled": False,
            "script_present": True,
            "script_length_category": "large",
        },
        remediation={
            "summary": (
                "Review whether the disabled auth-pipeline rule should be "
                "re-enabled or removed."
            ),
        },
    )

    action_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="auth0",
        finding_key=(
            f"auth0_action_secrets_present:{_AUTH0_DEMO_ACTION_ID}#demo"
        ),
        severity="medium",
        title="Demo: Auth0 auth-pipeline action has secrets configured",
        resource_id=None,
        description=(
            "Sample Auth0 auth-pipeline action posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "auth0_action_secrets_present", "demo": True,
            "action_id": _AUTH0_DEMO_ACTION_ID,
            "secrets_count": 2,
            "code_present": True,
            "code_length_category": "large",
        },
        remediation={
            "summary": (
                "Review the action secrets and confirm they are rotated and "
                "scoped to minimum required access."
            ),
        },
    )

    mfa_factor_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="auth0",
        finding_key=(
            f"auth0_mfa_factor_disabled:{_AUTH0_DEMO_FACTOR_NAME}#demo"
        ),
        severity="medium",
        title="Demo: Auth0 MFA / Guardian factor is disabled",
        resource_id=None,
        description=(
            "Sample Auth0 MFA factor posture risk for the incident-workflow "
            f"demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "auth0_mfa_factor_disabled", "demo": True,
            "factor_name": _AUTH0_DEMO_FACTOR_NAME,
            "enabled": False,
        },
        remediation={
            "summary": (
                "Enable the Auth0 MFA / Guardian OTP factor to require "
                "a second authentication factor for users."
            ),
        },
    )

    custom_domain_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="auth0",
        finding_key=(
            f"auth0_custom_domain_not_ready:{_AUTH0_DEMO_CUSTOM_DOMAIN_ID}#demo"
        ),
        severity="low",
        title="Demo: Auth0 custom domain is not yet provisioned",
        resource_id=None,
        description=(
            "Sample Auth0 custom domain posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "auth0_custom_domain_not_ready", "demo": True,
            "custom_domain_id": _AUTH0_DEMO_CUSTOM_DOMAIN_ID,
            "status_category": "not_ready",
        },
        remediation={
            "summary": (
                "Complete the Auth0 custom domain DNS provisioning or "
                "remove the pending domain record."
            ),
        },
    )

    auth0_findings = [
        tenant_finding, application_finding, connection_finding,
        resource_server_finding, rule_finding, action_finding,
        mfa_factor_finding, custom_domain_finding,
    ]

    # 3. Activity events (provider="auth0", source="auth0_activity_event").
    AUTH0_ACTIVITY_SOURCE = "auth0_activity_event"

    def _mk_auth0_event(
        *, event_type: str, resource_type: str, provider_event_id: str,
        resource_id: str, extra: dict,
    ) -> SecurityActivityEvent:
        meta: dict[str, Any] = {
            "resource_type": resource_type,
            "event_action": event_type,
            "event_source": AUTH0_ACTIVITY_SOURCE,
            "status": "observed",
            "category": resource_type,
        }
        meta.update(extra)
        norm = activity_svc.normalize_activity_event(
            provider="auth0", source=AUTH0_ACTIVITY_SOURCE,
            event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=provider_event_id,
            actor_id=None, actor_type=None,
            resource_type=resource_type, resource_id=resource_id,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id,
            normalized=norm, db=db,
        )
        return row

    tenant_event = _mk_auth0_event(
        event_type="auth0.tenant.updated",
        resource_type="tenant_settings",
        provider_event_id="AUTH0_DEMO_EVT_TENANT_001",
        resource_id=_AUTH0_DEMO_TENANT_ID,
        extra={
            "operation_family": "tenant",
            "operation_action": "update",
        },
    )
    application_event = _mk_auth0_event(
        event_type="auth0.application.updated",
        resource_type="application",
        provider_event_id="AUTH0_DEMO_EVT_APP_001",
        resource_id=_AUTH0_DEMO_CLIENT_ID,
        extra={
            "client_id": _AUTH0_DEMO_CLIENT_ID,
            "operation_family": "application",
            "operation_action": "update",
            "app_type": "regular_web",
            "token_endpoint_auth_method": "none",
            "callbacks_count": 12,
            "allowed_origins_count": 6,
        },
    )
    connection_event = _mk_auth0_event(
        event_type="auth0.connection.updated",
        resource_type="connection",
        provider_event_id="AUTH0_DEMO_EVT_CONN_001",
        resource_id=_AUTH0_DEMO_CONNECTION_ID,
        extra={
            "connection_id": _AUTH0_DEMO_CONNECTION_ID,
            "operation_family": "connection",
            "operation_action": "update",
            "password_policy_category": "weak",
            "enabled_clients_count": 0,
        },
    )
    resource_server_event = _mk_auth0_event(
        event_type="auth0.resource_server.updated",
        resource_type="resource_server",
        provider_event_id="AUTH0_DEMO_EVT_RS_001",
        resource_id=_AUTH0_DEMO_RESOURCE_SERVER_ID,
        extra={
            "resource_server_id": _AUTH0_DEMO_RESOURCE_SERVER_ID,
            "operation_family": "resource_server",
            "operation_action": "update",
            "rbac_enabled": False,
            "allow_offline_access": True,
        },
    )
    rule_event = _mk_auth0_event(
        event_type="auth0.rule.updated",
        resource_type="rule",
        provider_event_id="AUTH0_DEMO_EVT_RULE_001",
        resource_id=_AUTH0_DEMO_RULE_ID,
        extra={
            "rule_id": _AUTH0_DEMO_RULE_ID,
            "operation_family": "rule",
            "operation_action": "update",
            "enabled": False,
            "script_present": True,
        },
    )
    action_event = _mk_auth0_event(
        event_type="auth0.action.deployed",
        resource_type="action",
        provider_event_id="AUTH0_DEMO_EVT_ACTION_001",
        resource_id=_AUTH0_DEMO_ACTION_ID,
        extra={
            "action_id": _AUTH0_DEMO_ACTION_ID,
            "operation_family": "action",
            "operation_action": "deploy",
            "secrets_count": 2,
            "code_present": True,
        },
    )
    mfa_factor_event = _mk_auth0_event(
        event_type="auth0.mfa_factor.updated",
        resource_type="mfa_factor",
        provider_event_id="AUTH0_DEMO_EVT_MFA_001",
        resource_id=_AUTH0_DEMO_FACTOR_NAME,
        extra={
            "factor_name": _AUTH0_DEMO_FACTOR_NAME,
            "operation_family": "mfa_factor",
            "operation_action": "update",
            "enabled": False,
        },
    )
    custom_domain_event = _mk_auth0_event(
        event_type="auth0.custom_domain.updated",
        resource_type="custom_domain",
        provider_event_id="AUTH0_DEMO_EVT_CD_001",
        resource_id=_AUTH0_DEMO_CUSTOM_DOMAIN_ID,
        extra={
            "custom_domain_id": _AUTH0_DEMO_CUSTOM_DOMAIN_ID,
            "operation_family": "custom_domain",
            "operation_action": "update",
            "status_category": "not_ready",
        },
    )

    auth0_events = [
        tenant_event, application_event, connection_event,
        resource_server_event, rule_event, action_event,
        mfa_factor_event, custom_domain_event,
    ]

    # 4. Activity signals via the real M81E signal builder.
    auth0_signals: list[SecurityIncidentSignal] = []
    for ev in auth0_events:
        sig_dict = auth0_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db,
            )
            auth0_signals.append(sig)

    # 5. Correlations via the real M81F builder.
    auth0_correlations: list[SecuritySignalCorrelation] = []
    signals_by_type_a0: dict[str, SecurityIncidentSignal] = {
        s.signal_type: s for s in auth0_signals
    }

    def _add_auth0_correlation(
        *,
        finding: SecurityFinding,
        signal: SecurityIncidentSignal,
        correlation_type: str,
        match_reason: str,
    ) -> SecuritySignalCorrelation:
        rule = auth0_corr_svc.AUTH0_CORRELATION_RULES[correlation_type]
        cdict = auth0_corr_svc._build_correlation(
            finding=finding, signal=signal,
            correlation_type=correlation_type, rule=rule,
            match_reason=match_reason,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db,
        )
        auth0_correlations.append(corr)
        return corr

    tenant_signal = signals_by_type_a0.get("auth0_tenant_config_changed")
    application_signal = signals_by_type_a0.get("auth0_application_config_changed")
    connection_signal = signals_by_type_a0.get("auth0_connection_config_changed")
    rs_signal = signals_by_type_a0.get("auth0_resource_server_config_changed")
    rule_signal_a0 = signals_by_type_a0.get("auth0_rule_config_changed")
    action_signal = signals_by_type_a0.get("auth0_action_config_changed")
    mfa_signal = signals_by_type_a0.get("auth0_mfa_factor_config_changed")
    cd_signal = signals_by_type_a0.get("auth0_custom_domain_config_changed")

    if tenant_signal is not None:
        _add_auth0_correlation(
            finding=tenant_finding, signal=tenant_signal,
            correlation_type="auth0_tenant_risk_activity_correlation",
            match_reason="tenant_level",
        )
    if application_signal is not None:
        _add_auth0_correlation(
            finding=application_finding, signal=application_signal,
            correlation_type="auth0_application_risk_activity_correlation",
            match_reason="client_id_match",
        )
    if connection_signal is not None:
        _add_auth0_correlation(
            finding=connection_finding, signal=connection_signal,
            correlation_type="auth0_connection_risk_activity_correlation",
            match_reason="connection_id_match",
        )
    if rs_signal is not None:
        _add_auth0_correlation(
            finding=resource_server_finding, signal=rs_signal,
            correlation_type="auth0_resource_server_risk_activity_correlation",
            match_reason="resource_server_id_match",
        )
    if rule_signal_a0 is not None:
        _add_auth0_correlation(
            finding=rule_finding, signal=rule_signal_a0,
            correlation_type="auth0_rule_risk_activity_correlation",
            match_reason="rule_id_match",
        )
    if action_signal is not None:
        _add_auth0_correlation(
            finding=action_finding, signal=action_signal,
            correlation_type="auth0_action_risk_activity_correlation",
            match_reason="action_id_match",
        )
    if mfa_signal is not None:
        _add_auth0_correlation(
            finding=mfa_factor_finding, signal=mfa_signal,
            correlation_type="auth0_mfa_factor_risk_activity_correlation",
            match_reason="factor_name_match",
        )
    if cd_signal is not None:
        _add_auth0_correlation(
            finding=custom_domain_finding, signal=cd_signal,
            correlation_type="auth0_custom_domain_risk_activity_correlation",
            match_reason="custom_domain_id_match",
        )

    # 6. Case linking 8 findings, 8 events, signals, and correlations.
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title=(
            "[Demo] Auth0 configuration review: tenant, application, connection, "
            "resource server, rule, action, MFA factor, and custom domain posture"
        ),
        summary=(
            "Review-safe Auth0 demo case linking configuration risks to "
            "control-plane activity evidence. Groups Auth0 configuration "
            "findings (extended tenant session lifetime, application token "
            "endpoint auth none, connection weak password policy, resource "
            "server RBAC disabled, auth-pipeline rule disabled, action secrets "
            "present, MFA factor disabled, custom domain not ready) with Auth0 "
            "configuration-state activity events for the same surfaces, plus "
            "the matching activity signals and risk x activity correlations. "
            "Marked demo — no real Auth0 sync, no client secrets, no management "
            "tokens, no JWTs, no raw callback URLs, no logout URLs, no raw "
            "origins, no rule/action code, no user emails, no user IDs, no "
            "login history, no IP addresses, no raw Auth0 logs, no customer "
            "data. Evidence for review. Does not confirm compromise, "
            "unauthorized access, or data exposure."
        ),
        severity="high",
        provider="auth0",
        metadata={
            "source": AUTH0_DEMO_CASE_SOURCE,
        },
        db=db,
    )

    for f in auth0_findings:
        case_svc.link_object_to_case(
            case=case, object_type="finding", object_id=f.id,
            actor_user_id=actor_user_id, db=db,
        )
    for ev in auth0_events:
        case_svc.link_object_to_case(
            case=case, object_type="activity_event", object_id=ev.id,
            actor_user_id=actor_user_id, db=db,
        )
    seen_signal_ids: set = set()
    for sig in auth0_signals:
        seen_signal_ids.add(sig.id)
        case_svc.link_object_to_case(
            case=case, object_type="signal", object_id=sig.id,
            actor_user_id=actor_user_id, db=db,
        )
    for corr in auth0_correlations:
        case_svc.link_object_to_case(
            case=case, object_type="correlation", object_id=corr.id,
            actor_user_id=actor_user_id, db=db,
        )
        if (
            corr.linked_signal_id is not None
            and corr.linked_signal_id not in seen_signal_ids
        ):
            seen_signal_ids.add(corr.linked_signal_id)
            case_svc.link_object_to_case(
                case=case, object_type="signal",
                object_id=corr.linked_signal_id,
                actor_user_id=actor_user_id, db=db,
            )

    logger.info(
        "auth0_incident_demo: seeded workspace=%s case=%s",
        workspace_id, case.id,
    )
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_auth0(
    *, workspace_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Remove exactly the Auth0 demo incident objects (and nothing else)."""
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == AUTH0_DEMO_CASE_SOURCE,
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

    integ = get_auth0_demo_integration(workspace_id, db)
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
            corr_conds.append(
                SecuritySignalCorrelation.linked_finding_id.in_(finding_ids)
            )
        if activity_ids:
            corr_conds.append(
                SecuritySignalCorrelation.linked_activity_event_id.in_(activity_ids)
            )
        if corr_conds:
            db.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                or_(*corr_conds),
            ).delete(synchronize_session=False)
        sig_conds = [SecurityIncidentSignal.integration_id == integ.id]
        if activity_ids:
            sig_conds.append(
                SecurityIncidentSignal.linked_activity_event_id.in_(activity_ids)
            )
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


# ── Datadog incident demo (M82G) ──────────────────────────────────────────────
#
# Story: A Datadog webhook integration has outbound posture findings (missing
# secret headers, non-HTTPS endpoint, auth material in custom headers).
# Evidence chain: webhook configuration risk finding → Datadog activity event
# (datadog.webhook_integration.updated) → Datadog activity signal
# (datadog_webhook_integration_config_changed) → risk × activity correlation
# (datadog_webhook_risk_activity_correlation) → case.
#
# PRIVACY: no API key values, application key values, OAuth tokens, bearer
# tokens, webhook secrets, raw monitor queries, raw monitor messages, raw
# dashboard JSON, webhook URLs, custom header names/values, payload templates,
# notification handles, Slack channel names, PagerDuty service IDs, email
# addresses, user IDs, team member identities, IP addresses, user agents,
# raw Datadog audit payloads, raw API responses, customer data, or PII.
# No strings matching eyJ[A-Za-z0-9_-]{10,} are used.

DATADOG_DEMO_INTEGRATION_NAME = "ConfigTrace Datadog incident demo (sample data)"
DATADOG_DEMO_CASE_SOURCE = "demo_datadog_incident"
DATADOG_DEMO_DATASET = "datadog_incident_demo_v1"

# Safe placeholder — no real Datadog values, no API keys, no webhook URLs.
_DATADOG_DEMO_WEBHOOK_ID = "demo_datadog_webhook_001"


def get_datadog_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == DATADOG_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_datadog_demo_case(
    workspace_id: uuid.UUID, db: Session
) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == DATADOG_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_datadog_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_datadog_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_datadog(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Datadog demo incident chain (idempotent). No real Datadog sync.

    One coherent Datadog webhook integration story:
      Webhook posture risks (missing secret headers, non-HTTPS endpoint, auth
      material in custom headers) → Datadog config-state activity event →
      Datadog activity signal → Datadog risk × activity correlation → case.

    All objects are anchored on a hidden demo integration so ``clear_datadog``
    removes them and nothing else. Evidence is built directly for the demo
    objects (never by scanning the real workspace).

    PRIVACY: no API key values, application key values, OAuth tokens, bearer
    tokens, webhook secrets, raw monitor queries/messages, raw dashboard JSON,
    webhook URLs, custom header names/values, payload templates, notification
    handles, Slack channel names, PagerDuty service IDs, email addresses, user
    IDs, team member identities, IP addresses, user agents, raw Datadog audit
    payloads, raw API responses, or customer data. Only safe booleans, counts,
    opaque IDs, and category labels.

    SECURITY: no strings matching eyJ[A-Za-z0-9_-]{10,} are used.
    """
    existing = _existing_datadog_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" → never shown / never synced).
    integ = get_datadog_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({
            "demo": True, "dataset": DATADOG_DEMO_DATASET,
        })
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=DATADOG_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    common_disclaimer = (
        "This is evidence for review and does not confirm compromise, "
        "unauthorized access, or data exposure."
    )

    # 2. Security findings using real Datadog rule keys (M82B/M82C).
    #    Evidence uses only safe booleans, counts, opaque IDs, and category
    #    labels — never webhook URLs, header names/values, payload content,
    #    secrets, raw queries, notification handles, email addresses, or PII.

    webhook_finding_1 = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="datadog",
        finding_key=(
            f"datadog_webhook_without_secret_headers:{_DATADOG_DEMO_WEBHOOK_ID}#demo"
        ),
        severity="high",
        title="Demo: Datadog webhook integration has no secret headers configured",
        resource_id=None,  # Findings use evidence.record_id; resource_id is a UUID FK we leave null for demo
        description=(
            "Sample Datadog webhook integration posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "datadog_webhook_without_secret_headers", "demo": True,
            "record_id": _DATADOG_DEMO_WEBHOOK_ID,
            "record_type": "datadog_webhook_integration",
            "resource_name": "Datadog webhook integration review",
            "url_present": True,
            "url_scheme_category": "http",
            "url_host_present": True,
            "secret_headers_present": False,
            "secret_headers_count": 0,
        },
        remediation={
            "summary": (
                "Configure HMAC secret headers on the Datadog webhook "
                "integration to allow receivers to verify request authenticity."
            ),
        },
    )

    webhook_finding_2 = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="datadog",
        finding_key=(
            f"datadog_webhook_non_https_endpoint:{_DATADOG_DEMO_WEBHOOK_ID}#demo"
        ),
        severity="high",
        title="Demo: Datadog webhook integration uses a non-HTTPS endpoint",
        resource_id=None,  # Findings use evidence.record_id; resource_id is a UUID FK we leave null for demo
        description=(
            "Sample Datadog webhook non-HTTPS endpoint posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "datadog_webhook_non_https_endpoint", "demo": True,
            "record_id": _DATADOG_DEMO_WEBHOOK_ID,
            "record_type": "datadog_webhook_integration",
            "resource_name": "Datadog webhook integration review",
            "url_present": True,
            "url_scheme_category": "http",
        },
        remediation={
            "summary": (
                "Update the Datadog webhook integration to use an HTTPS endpoint "
                "to protect data in transit."
            ),
        },
    )

    webhook_finding_3 = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="datadog",
        finding_key=(
            f"datadog_webhook_auth_material_present:{_DATADOG_DEMO_WEBHOOK_ID}#demo"
        ),
        severity="medium",
        title="Demo: Datadog webhook integration has auth material in custom headers",
        resource_id=None,  # Findings use evidence.record_id; resource_id is a UUID FK we leave null for demo
        description=(
            "Sample Datadog webhook auth material posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "datadog_webhook_auth_material_present", "demo": True,
            "record_id": _DATADOG_DEMO_WEBHOOK_ID,
            "record_type": "datadog_webhook_integration",
            "resource_name": "Datadog webhook integration review",
            "custom_headers_present": True,
            "custom_header_count": 2,
            "auth_material_present": True,
            "auth_material_count": 1,
            "secret_headers_present": False,
        },
        remediation={
            "summary": (
                "Move authentication material from custom headers to Datadog's "
                "dedicated secret_headers field, and remove auth credentials "
                "from unprotected custom_headers."
            ),
        },
    )

    datadog_findings = [webhook_finding_1, webhook_finding_2, webhook_finding_3]

    # 3. Activity event (provider="datadog", source="datadog_activity_event").
    DATADOG_ACTIVITY_SOURCE = "datadog_activity_event"

    def _mk_dd_event(
        *, event_type: str, resource_type: str, provider_event_id: str,
        resource_id: str, extra: dict,
    ) -> SecurityActivityEvent:
        meta: dict[str, Any] = {
            "resource_type": resource_type,
            "event_action": event_type,
            "event_source": DATADOG_ACTIVITY_SOURCE,
            "status": "observed",
            "category": "datadog_configuration",
            "status_category": "observed",
            "operation_family": f"datadog.{resource_type}",
            "operation_action": "observe",
        }
        meta.update(extra)
        norm = activity_svc.normalize_activity_event(
            provider="datadog", source=DATADOG_ACTIVITY_SOURCE,
            event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=provider_event_id,
            actor_id=None, actor_type=None,
            resource_type=resource_type, resource_id=resource_id,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id,
            normalized=norm, db=db,
        )
        return row

    webhook_event = _mk_dd_event(
        event_type="datadog.webhook_integration.updated",
        resource_type="webhook_integration",
        provider_event_id="DATADOG_DEMO_EVT_WEBHOOK_001",
        resource_id=_DATADOG_DEMO_WEBHOOK_ID,
        extra={
            "webhook_id": _DATADOG_DEMO_WEBHOOK_ID,
            "resource_name": "Datadog webhook integration review",
            "url_present": True,
            "url_scheme_category": "http",
            "url_host_present": True,
            "custom_headers_present": True,
            "custom_header_count": 2,
            "secret_headers_present": False,
            "secret_headers_count": 0,
            "payload_template_present": True,
            "payload_template_length_category": "long",
            "encode_as_category": "json",
            "auth_material_present": True,
            "auth_material_count": 1,
        },
    )

    datadog_events = [webhook_event]

    # 4. Activity signals via the real M82E signal builder.
    datadog_signals: list[SecurityIncidentSignal] = []
    for ev in datadog_events:
        sig_dict = dd_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db,
            )
            datadog_signals.append(sig)

    # 5. Correlation via the real M82F builder.
    datadog_correlations: list[SecuritySignalCorrelation] = []
    signals_by_type_dd: dict[str, SecurityIncidentSignal] = {
        s.signal_type: s for s in datadog_signals
    }

    def _add_dd_correlation(
        *,
        finding: SecurityFinding,
        signal: SecurityIncidentSignal,
        correlation_type: str,
        match_reason: str,
        confidence: str = "medium",
    ) -> SecuritySignalCorrelation:
        rule = dd_corr_svc.DATADOG_CORRELATION_RULES[correlation_type]
        cdict = dd_corr_svc._build_correlation(
            finding=finding, signal=signal,
            correlation_type=correlation_type, rule=rule,
            match_reason=match_reason, confidence=confidence,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db,
        )
        datadog_correlations.append(corr)
        return corr

    webhook_signal = signals_by_type_dd.get("datadog_webhook_integration_config_changed")
    if webhook_signal is not None:
        _add_dd_correlation(
            finding=webhook_finding_1,
            signal=webhook_signal,
            correlation_type="datadog_webhook_risk_activity_correlation",
            match_reason="webhook_id_id_match",
            confidence="medium",
        )

    # 6. Case linking 3 findings, 1 event, signals, and correlations.
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title=(
            "[Demo] Datadog webhook integration review: outbound posture and "
            "configuration activity"
        ),
        summary=(
            "Review-safe Datadog demo case linking webhook configuration risks "
            "to control-plane activity evidence. Groups Datadog webhook "
            "integration findings (missing secret headers, non-HTTPS endpoint, "
            "auth material in custom headers) with a Datadog configuration-state "
            "activity event for the same webhook, plus the matching activity "
            "signal and risk x activity correlation. "
            "Marked demo — no real Datadog sync, no API key values, no "
            "application key values, no webhook URLs, no header names or values, "
            "no payload templates, no notification handles, no email addresses, "
            "no user IDs, no IP addresses, no raw Datadog audit payloads, no "
            "customer data. Evidence for review. Does not confirm compromise, "
            "unauthorized access, or data exposure."
        ),
        severity="high",
        provider="datadog",
        metadata={
            "source": DATADOG_DEMO_CASE_SOURCE,
        },
        db=db,
    )

    for f in datadog_findings:
        case_svc.link_object_to_case(
            case=case, object_type="finding", object_id=f.id,
            actor_user_id=actor_user_id, db=db,
        )
    for ev in datadog_events:
        case_svc.link_object_to_case(
            case=case, object_type="activity_event", object_id=ev.id,
            actor_user_id=actor_user_id, db=db,
        )
    seen_signal_ids_dd: set = set()
    for sig in datadog_signals:
        seen_signal_ids_dd.add(sig.id)
        case_svc.link_object_to_case(
            case=case, object_type="signal", object_id=sig.id,
            actor_user_id=actor_user_id, db=db,
        )
    for corr in datadog_correlations:
        case_svc.link_object_to_case(
            case=case, object_type="correlation", object_id=corr.id,
            actor_user_id=actor_user_id, db=db,
        )
        if (
            corr.linked_signal_id is not None
            and corr.linked_signal_id not in seen_signal_ids_dd
        ):
            seen_signal_ids_dd.add(corr.linked_signal_id)
            case_svc.link_object_to_case(
                case=case, object_type="signal",
                object_id=corr.linked_signal_id,
                actor_user_id=actor_user_id, db=db,
            )

    logger.info(
        "datadog_incident_demo: seeded workspace=%s case=%s",
        workspace_id, case.id,
    )
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_datadog(
    *, workspace_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Remove exactly the Datadog demo incident objects (and nothing else)."""
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == DATADOG_DEMO_CASE_SOURCE,
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

    integ = get_datadog_demo_integration(workspace_id, db)
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
            corr_conds.append(
                SecuritySignalCorrelation.linked_finding_id.in_(finding_ids)
            )
        if activity_ids:
            corr_conds.append(
                SecuritySignalCorrelation.linked_activity_event_id.in_(activity_ids)
            )
        if corr_conds:
            db.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                or_(*corr_conds),
            ).delete(synchronize_session=False)
        sig_conds = [SecurityIncidentSignal.integration_id == integ.id]
        if activity_ids:
            sig_conds.append(
                SecurityIncidentSignal.linked_activity_event_id.in_(activity_ids)
            )
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


# ── Clerk demo ────────────────────────────────────────────────────────────────

CLERK_DEMO_INTEGRATION_NAME = "ConfigTrace Clerk incident demo (sample data)"
CLERK_DEMO_CASE_SOURCE = "demo_clerk_incident"
CLERK_DEMO_DATASET = "clerk_incident_demo_v1"

# Safe placeholder -- no real Clerk values, no secret keys, no JWT tokens.
_CLERK_DEMO_SESSION_POLICY_ID = "CLERK_DEMO_SESSION_POLICY_ID"


def _get_clerk_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == CLERK_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_clerk_demo_case(
    workspace_id: uuid.UUID, db: Session
) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == CLERK_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_clerk_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_clerk_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_clerk(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Clerk demo incident chain (idempotent). No real Clerk sync.

    One coherent Clerk session-policy story:
      Session policy posture risks (extended lifetime, token rotation disabled,
      reverification disabled) -> Clerk session-policy activity event ->
      Clerk activity signal -> Clerk risk x activity correlation -> case.

    All objects are anchored on a hidden demo integration so clear_clerk
    removes them and nothing else. Evidence is built directly for the demo
    objects (never by scanning the real workspace).

    PRIVACY: no secret key values, publishable key values, JWT tokens, webhook
    secrets, application IDs, user IDs, email addresses, IP addresses, raw Clerk
    audit log payloads, raw API responses, or customer data. Only safe booleans,
    counts, opaque IDs, and category labels.

    SECURITY: no strings matching eyJ[A-Za-z0-9_-]{10,} are used.
    """
    existing = _existing_clerk_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" -> never shown / never synced).
    integ = _get_clerk_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({
            "demo": True, "dataset": CLERK_DEMO_DATASET,
        })
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=CLERK_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    common_disclaimer = (
        "This is evidence for review and does not confirm compromise, "
        "unauthorized access, or data exposure."
    )

    # 2. Security findings using real Clerk session-policy rule keys (M83B).
    session_finding_1 = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="clerk",
        finding_key=(
            f"clerk_session_lifetime_extended:{_CLERK_DEMO_SESSION_POLICY_ID}#demo"
        ),
        severity="high",
        title="Demo: Clerk session lifetime is set to an extended duration",
        resource_id=None,
        description=(
            "Sample Clerk session lifetime posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "clerk_session_lifetime_extended", "demo": True,
            "record_id": _CLERK_DEMO_SESSION_POLICY_ID,
            "record_type": "clerk_session_policy",
            "resource_name": "Clerk session policy review",
            "lifetime_category": "extended",
            "lifetime_hours_category": "long",
        },
        remediation={
            "summary": (
                "Reduce the Clerk session lifetime to the recommended default "
                "to limit the window of exposure for stolen session tokens."
            ),
        },
    )

    session_finding_2 = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="clerk",
        finding_key=(
            f"clerk_session_token_rotation_disabled:{_CLERK_DEMO_SESSION_POLICY_ID}#demo"
        ),
        severity="high",
        title="Demo: Clerk session token rotation is disabled",
        resource_id=None,
        description=(
            "Sample Clerk token rotation posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "clerk_session_token_rotation_disabled", "demo": True,
            "record_id": _CLERK_DEMO_SESSION_POLICY_ID,
            "record_type": "clerk_session_policy",
            "resource_name": "Clerk session policy review",
            "token_rotation_enabled": False,
        },
        remediation={
            "summary": (
                "Enable session token rotation in the Clerk session policy "
                "to reduce the risk from long-lived session tokens."
            ),
        },
    )

    session_finding_3 = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="clerk",
        finding_key=(
            f"clerk_session_reverification_disabled:{_CLERK_DEMO_SESSION_POLICY_ID}#demo"
        ),
        severity="medium",
        title="Demo: Clerk session reverification is disabled",
        resource_id=None,
        description=(
            "Sample Clerk reverification posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "clerk_session_reverification_disabled", "demo": True,
            "record_id": _CLERK_DEMO_SESSION_POLICY_ID,
            "record_type": "clerk_session_policy",
            "resource_name": "Clerk session policy review",
            "reverification_enabled": False,
        },
        remediation={
            "summary": (
                "Enable reverification in the Clerk session policy for "
                "sensitive operations to require re-authentication."
            ),
        },
    )

    clerk_findings = [session_finding_1, session_finding_2, session_finding_3]

    # 3. Activity event (provider="clerk", source="clerk_activity_event").
    CLERK_ACTIVITY_SOURCE = "clerk_activity_event"

    def _mk_clerk_event(
        *, event_type: str, resource_type: str, provider_event_id: str,
        resource_id: str, extra: dict,
    ) -> SecurityActivityEvent:
        meta: dict[str, Any] = {
            "resource_type": resource_type,
            "event_action": event_type,
            "event_source": CLERK_ACTIVITY_SOURCE,
            "status": "observed",
            "category": "clerk_configuration",
            "status_category": "observed",
            "operation_family": f"clerk.{resource_type}",
            "operation_action": "observe",
        }
        meta.update(extra)
        norm = activity_svc.normalize_activity_event(
            provider="clerk", source=CLERK_ACTIVITY_SOURCE,
            event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=provider_event_id,
            actor_id=None, actor_type=None,
            resource_type=resource_type, resource_id=resource_id,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id,
            normalized=norm, db=db,
        )
        return row

    session_event = _mk_clerk_event(
        event_type="clerk.session_policy.updated",
        resource_type="session_policy",
        provider_event_id="CLERK_DEMO_EVT_SESSION_POLICY_001",
        resource_id=_CLERK_DEMO_SESSION_POLICY_ID,
        extra={
            "session_policy_id": _CLERK_DEMO_SESSION_POLICY_ID,
            "resource_name": "Clerk session policy review",
            "lifetime_category": "extended",
            "token_rotation_enabled": False,
            "reverification_enabled": False,
            "single_session_enabled": True,
            "device_tracking_enabled": True,
            "inactivity_timeout_category": "standard",
        },
    )

    clerk_events = [session_event]

    # 4. Activity signals via the real M83E signal builder.
    clerk_signals: list[SecurityIncidentSignal] = []
    for ev in clerk_events:
        sig_dict = clerk_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db,
            )
            clerk_signals.append(sig)

    # 5. Correlation via the real M83F builder.
    clerk_correlations: list[SecuritySignalCorrelation] = []
    signals_by_type_clerk: dict[str, SecurityIncidentSignal] = {
        s.signal_type: s for s in clerk_signals
    }

    def _add_clerk_correlation(
        *,
        finding: SecurityFinding,
        signal: SecurityIncidentSignal,
        correlation_type: str,
        match_reason: str,
        confidence: str = "medium",
    ) -> SecuritySignalCorrelation:
        rule = clerk_corr_svc.CLERK_CORRELATION_RULES[correlation_type]
        cdict = clerk_corr_svc._build_correlation(
            finding=finding, signal=signal,
            correlation_type=correlation_type, rule=rule,
            match_reason=match_reason, confidence=confidence,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db,
        )
        clerk_correlations.append(corr)
        return corr

    session_signal = signals_by_type_clerk.get("clerk_session_policy_config_changed")
    if session_signal is not None:
        _add_clerk_correlation(
            finding=session_finding_1,
            signal=session_signal,
            correlation_type="clerk_session_policy_risk_activity_correlation",
            match_reason="session_policy_id_match",
            confidence="medium",
        )

    # 6. Case linking 3 findings, 1 event, signals, and correlations.
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title=(
            "[Demo] Clerk session policy review: posture risks and "
            "configuration activity"
        ),
        summary=(
            "Review-safe Clerk demo case linking session policy configuration "
            "risks to control-plane activity evidence. Groups Clerk session "
            "policy findings (extended lifetime, token rotation disabled, "
            "reverification disabled) with a Clerk configuration-state "
            "activity event for the same policy, plus the matching activity "
            "signal and risk x activity correlation. "
            "Marked demo -- no real Clerk sync, no secret key values, no "
            "publishable key values, no JWT tokens, no user IDs, no email "
            "addresses, no IP addresses, no raw Clerk audit log payloads, no "
            "customer data. Evidence for review. Does not confirm compromise, "
            "unauthorized access, or data exposure."
        ),
        severity="high",
        provider="clerk",
        metadata={
            "source": CLERK_DEMO_CASE_SOURCE,
        },
        db=db,
    )
    db.flush()

    # Link findings.
    for f in clerk_findings:
        case_svc.add_link(
            case_id=case.id,
            link_type="finding",
            linked_finding_id=f.id,
            db=db,
        )

    # Link activity events.
    for ev in clerk_events:
        case_svc.add_link(
            case_id=case.id,
            link_type="activity_event",
            linked_activity_event_id=ev.id,
            db=db,
        )

    # Link signals.
    for sig in clerk_signals:
        case_svc.add_link(
            case_id=case.id,
            link_type="signal",
            linked_signal_id=sig.id,
            db=db,
        )

    # Link correlations.
    for corr in clerk_correlations:
        case_svc.add_link(
            case_id=case.id,
            link_type="correlation",
            linked_correlation_id=corr.id,
            db=db,
        )

    db.commit()
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_clerk(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the Clerk demo incident objects (and nothing else)."""
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == CLERK_DEMO_CASE_SOURCE,
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

    integ = _get_clerk_demo_integration(workspace_id, db)
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
            corr_conds.append(
                SecuritySignalCorrelation.linked_finding_id.in_(finding_ids)
            )
        if activity_ids:
            corr_conds.append(
                SecuritySignalCorrelation.linked_activity_event_id.in_(activity_ids)
            )
        if corr_conds:
            db.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                or_(*corr_conds),
            ).delete(synchronize_session=False)
        sig_conds = [SecurityIncidentSignal.integration_id == integ.id]
        if activity_ids:
            sig_conds.append(
                SecurityIncidentSignal.linked_activity_event_id.in_(activity_ids)
            )
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


# ── PagerDuty demo ────────────────────────────────────────────────────────────
#
# M84G: review-safe PagerDuty webhook subscription story.
# A PagerDuty incident-response configuration has webhook posture that may
# require review. ConfigTrace shows related PagerDuty configuration activity
# near the finding. Evidence for review. Does not confirm compromise,
# unauthorized access, or data exposure.
#
# PRIVACY: no PagerDuty API tokens, routing keys, integration keys, webhook
# secrets, delivery URLs, custom header names/values, user emails, user names,
# phone numbers, contact methods, on-call user identities, responder identities,
# subscriber identities, incident payloads, alert payloads, conference phone
# numbers, raw routing expressions, IP addresses, user agents, raw audit
# payloads, raw API response dicts, or customer PII are seeded.
# Only safe opaque placeholder IDs, booleans, counts, and category labels.
#
# SECURITY: no strings matching eyJ[A-Za-z0-9_-]{10,} are used.

PAGERDUTY_DEMO_INTEGRATION_NAME = "ConfigTrace PagerDuty incident demo (sample data)"
PAGERDUTY_DEMO_CASE_SOURCE = "demo_pagerduty_incident"
PAGERDUTY_DEMO_DATASET = "pagerduty_incident_demo_v1"

# Safe placeholder -- no real PagerDuty values, no API tokens, no webhook URLs.
_PAGERDUTY_DEMO_WEBHOOK_ID = "PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID"


def _get_pagerduty_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == PAGERDUTY_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_pagerduty_demo_case(
    workspace_id: uuid.UUID, db: Session
) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == PAGERDUTY_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_pagerduty_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_pagerduty_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_pagerduty(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the PagerDuty demo incident chain (idempotent). No real PagerDuty sync.

    One coherent PagerDuty webhook subscription story:
      Webhook posture risks (non-HTTPS delivery, broad event scope, secret not
      indicated) -> PagerDuty webhook config-state activity event -> PagerDuty
      activity signal -> PagerDuty risk x activity correlation -> case.

    All objects are anchored on a hidden demo integration so clear_pagerduty
    removes them and nothing else. Evidence is built directly for the demo
    objects (never by scanning the real workspace).

    PRIVACY: no PagerDuty API tokens, routing keys, integration keys, webhook
    secrets, delivery URLs, custom header names/values, user emails, user names,
    phone numbers, contact methods, on-call user identities, responder identities,
    subscriber identities, incident payloads, alert payloads, conference phone
    numbers, raw routing expressions, IP addresses, user agents, raw audit
    payloads, raw API response dicts, or customer PII. Only safe booleans,
    counts, opaque placeholder IDs, and category labels.

    SECURITY: no strings matching eyJ[A-Za-z0-9_-]{10,} are used.
    """
    existing = _existing_pagerduty_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" -- never shown / never synced).
    integ = _get_pagerduty_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({
            "demo": True, "dataset": PAGERDUTY_DEMO_DATASET,
        })
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=PAGERDUTY_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    common_disclaimer = (
        "This is evidence for review and does not confirm compromise, "
        "unauthorized access, or data exposure."
    )

    # 2. Security findings using real PagerDuty rule keys (M84B/M84C).
    #    Evidence uses only safe booleans, counts, opaque placeholder IDs, and
    #    category labels -- never webhook URLs, delivery endpoints, routing keys,
    #    integration keys, webhook secrets, user emails, or PII.

    webhook_finding_1 = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="pagerduty",
        finding_key=(
            f"pagerduty_webhook_subscription_non_https:{_PAGERDUTY_DEMO_WEBHOOK_ID}#demo"
        ),
        severity="high",
        title="Demo: PagerDuty webhook subscription uses a non-HTTPS delivery endpoint",
        resource_id=None,
        description=(
            "Sample PagerDuty webhook subscription non-HTTPS delivery posture risk "
            f"for the incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "pagerduty_webhook_subscription_non_https", "demo": True,
            "record_id": _PAGERDUTY_DEMO_WEBHOOK_ID,
            "record_type": "pagerduty_webhook_subscription",
            "resource_name": "PagerDuty webhook subscription review",
            "active": True,
            "enabled": True,
            "url_present": True,
            "url_scheme_category": "non_https",
            "https_delivery": False,
        },
        remediation={
            "summary": (
                "Update the PagerDuty webhook subscription to deliver events "
                "only to HTTPS endpoints to protect data in transit."
            ),
        },
    )

    webhook_finding_2 = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="pagerduty",
        finding_key=(
            f"pagerduty_webhook_subscription_broad_event_scope:{_PAGERDUTY_DEMO_WEBHOOK_ID}#demo"
        ),
        severity="medium",
        title="Demo: PagerDuty webhook subscription has a broad event scope",
        resource_id=None,
        description=(
            "Sample PagerDuty webhook subscription broad-scope posture risk "
            f"for the incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "pagerduty_webhook_subscription_broad_event_scope", "demo": True,
            "record_id": _PAGERDUTY_DEMO_WEBHOOK_ID,
            "record_type": "pagerduty_webhook_subscription",
            "resource_name": "PagerDuty webhook subscription review",
            "active": True,
            "event_count": 20,
            "subscribed_event_count": 20,
            "event_scope_category": "broad",
        },
        remediation={
            "summary": (
                "Narrow the PagerDuty webhook subscription to only the specific "
                "event types required rather than subscribing to all events."
            ),
        },
    )

    webhook_finding_3 = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="pagerduty",
        finding_key=(
            f"pagerduty_webhook_subscription_secret_not_indicated:{_PAGERDUTY_DEMO_WEBHOOK_ID}#demo"
        ),
        severity="medium",
        title="Demo: PagerDuty webhook subscription has no secret indicated",
        resource_id=None,
        description=(
            "Sample PagerDuty webhook subscription missing-secret posture risk "
            f"for the incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "pagerduty_webhook_subscription_secret_not_indicated", "demo": True,
            "record_id": _PAGERDUTY_DEMO_WEBHOOK_ID,
            "record_type": "pagerduty_webhook_subscription",
            "resource_name": "PagerDuty webhook subscription review",
            "active": True,
            "secret_present": False,
            "description_present": True,
        },
        remediation={
            "summary": (
                "Configure a shared secret for the PagerDuty webhook subscription "
                "to allow receivers to verify event authenticity."
            ),
        },
    )

    pagerduty_findings = [webhook_finding_1, webhook_finding_2, webhook_finding_3]

    # 3. Activity event (provider="pagerduty", source="pagerduty_activity_event").
    PAGERDUTY_ACTIVITY_SOURCE = "pagerduty_activity_event"

    def _mk_pd_event(
        *, event_type: str, resource_type: str, provider_event_id: str,
        resource_id: str, extra: dict,
    ) -> SecurityActivityEvent:
        meta: dict[str, Any] = {
            "resource_type": resource_type,
            "event_action": event_type,
            "event_source": PAGERDUTY_ACTIVITY_SOURCE,
            "status": "observed",
            "category": "pagerduty_configuration",
            "status_category": "observed",
            "operation_family": f"pagerduty.{resource_type}",
            "operation_action": "observe",
        }
        meta.update(extra)
        norm = activity_svc.normalize_activity_event(
            provider="pagerduty", source=PAGERDUTY_ACTIVITY_SOURCE,
            event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=provider_event_id,
            actor_id=None, actor_type=None,
            resource_type=resource_type, resource_id=resource_id,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id,
            normalized=norm, db=db,
        )
        return row

    webhook_event = _mk_pd_event(
        event_type="pagerduty.webhook_subscription.updated",
        resource_type="webhook_subscription",
        provider_event_id="PAGERDUTY_TEST_ACTIVITY_EVENT_ID",
        resource_id=_PAGERDUTY_DEMO_WEBHOOK_ID,
        extra={
            "resource_id": _PAGERDUTY_DEMO_WEBHOOK_ID,
            "resource_name": "PagerDuty webhook subscription review",
            "active": True,
            "enabled": True,
            "url_present": True,
            "url_scheme_category": "non_https",
            "https_delivery": False,
            "event_count": 20,
            "subscribed_event_count": 20,
            "event_scope_category": "broad",
            "secret_present": False,
            "description_present": True,
            "has_custom_headers": False,
        },
    )

    pagerduty_events = [webhook_event]

    # 4. Activity signals via the real M84E signal builder.
    pagerduty_signals: list[SecurityIncidentSignal] = []
    for ev in pagerduty_events:
        sig_dict = pd_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db,
            )
            pagerduty_signals.append(sig)

    # 5. Correlation via the real M84F builder.
    pagerduty_correlations: list[SecuritySignalCorrelation] = []
    signals_by_type_pd: dict[str, SecurityIncidentSignal] = {
        s.signal_type: s for s in pagerduty_signals
    }

    def _add_pd_correlation(
        *,
        finding: SecurityFinding,
        signal: SecurityIncidentSignal,
        correlation_type: str,
        match_reason: str,
    ) -> SecuritySignalCorrelation:
        rule = pd_corr_svc.PAGERDUTY_CORRELATION_RULES[correlation_type]
        cdict = pd_corr_svc._build_correlation(
            finding=finding, signal=signal,
            correlation_type=correlation_type, rule=rule,
            match_reason=match_reason,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db,
        )
        pagerduty_correlations.append(corr)
        return corr

    webhook_signal = signals_by_type_pd.get("pagerduty_webhook_subscription_config_changed")
    if webhook_signal is not None:
        _add_pd_correlation(
            finding=webhook_finding_1,
            signal=webhook_signal,
            correlation_type="pagerduty_webhook_subscription_risk_activity_correlation",
            match_reason="resource_id_match",
        )

    # 6. Case linking 3 findings, 1 event, signals, and correlations.
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title=(
            "[Demo] PagerDuty incident-response configuration review: "
            "webhook posture and configuration activity"
        ),
        summary=(
            "Review-safe PagerDuty demo case linking webhook subscription "
            "configuration risks to control-plane activity evidence. Groups "
            "PagerDuty webhook subscription findings (non-HTTPS delivery, broad "
            "event scope, secret not indicated) with a PagerDuty configuration-state "
            "activity event for the same webhook subscription, plus the matching "
            "activity signal and risk x activity correlation. "
            "Marked demo -- no real PagerDuty sync, no API tokens, no routing keys, "
            "no integration keys, no webhook secrets, no delivery URLs, no user "
            "emails, no user names, no phone numbers, no contact methods, no "
            "on-call identities, no incident payloads, no alert payloads, no "
            "IP addresses, no user agents, no raw audit payloads, no customer data. "
            "Evidence for review. Does not confirm compromise, unauthorized access, "
            "or data exposure."
        ),
        severity="high",
        provider="pagerduty",
        metadata={
            "source": PAGERDUTY_DEMO_CASE_SOURCE,
        },
        db=db,
    )
    db.flush()

    for f in pagerduty_findings:
        case_svc.add_link(
            case_id=case.id,
            link_type="finding",
            linked_finding_id=f.id,
            db=db,
        )

    for ev in pagerduty_events:
        case_svc.add_link(
            case_id=case.id,
            link_type="activity_event",
            linked_activity_event_id=ev.id,
            db=db,
        )

    seen_signal_ids_pd: set = set()
    for sig in pagerduty_signals:
        seen_signal_ids_pd.add(sig.id)
        case_svc.add_link(
            case_id=case.id,
            link_type="signal",
            linked_signal_id=sig.id,
            db=db,
        )

    for corr in pagerduty_correlations:
        case_svc.add_link(
            case_id=case.id,
            link_type="correlation",
            linked_correlation_id=corr.id,
            db=db,
        )
        if (
            corr.linked_signal_id is not None
            and corr.linked_signal_id not in seen_signal_ids_pd
        ):
            seen_signal_ids_pd.add(corr.linked_signal_id)
            case_svc.add_link(
                case_id=case.id,
                link_type="signal",
                linked_signal_id=corr.linked_signal_id,
                db=db,
            )

    db.commit()
    logger.info(
        "pagerduty_incident_demo: seeded workspace=%s case=%s",
        workspace_id, case.id,
    )
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_pagerduty(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the PagerDuty demo incident objects (and nothing else)."""
    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == PAGERDUTY_DEMO_CASE_SOURCE,
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

    integ = _get_pagerduty_demo_integration(workspace_id, db)
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
            corr_conds.append(
                SecuritySignalCorrelation.linked_finding_id.in_(finding_ids)
            )
        if activity_ids:
            corr_conds.append(
                SecuritySignalCorrelation.linked_activity_event_id.in_(activity_ids)
            )
        if corr_conds:
            db.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                or_(*corr_conds),
            ).delete(synchronize_session=False)
        sig_conds = [SecurityIncidentSignal.integration_id == integ.id]
        if activity_ids:
            sig_conds.append(
                SecurityIncidentSignal.linked_activity_event_id.in_(activity_ids)
            )
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


# ─ Linear incident demo (M85G) ─────────────────────────────────────────────
# A separate hidden demo integration + case source so "Clear Linear demo"
# removes only Linear demo objects. Same safety rules: clearly marked demo,
# no real sync, no notifications, never touches a real Linear integration,
# idempotent. Evidence chain: webhook posture risk -> activity event -> signal
# -> risk x activity correlation -> case.
#
# PRIVACY: no Linear API keys, OAuth tokens, webhook secrets, raw webhook URLs,
# issue titles, issue descriptions, comment bodies, attachment content, user
# emails, user names, member identities, customer names, IP addresses, user
# agents, raw audit payloads, raw API response dicts, or PII.
# Only safe opaque placeholder IDs, booleans, counts, and category labels.
#
# SECURITY: no strings matching eyJ[A-Za-z0-9_-]{10,} are used.

LINEAR_DEMO_INTEGRATION_NAME = "ConfigTrace Linear incident demo (sample data)"
LINEAR_DEMO_CASE_SOURCE = "demo_linear_incident"
LINEAR_DEMO_DATASET = "linear_incident_demo_v1"

# Safe placeholder -- no real Linear values, no API keys, no webhook URLs.
_LINEAR_DEMO_WEBHOOK_ID = "LINEAR_DEMO_WEBHOOK_ID"


def _get_linear_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == LINEAR_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_linear_demo_case(
    workspace_id: uuid.UUID, db: Session
) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == LINEAR_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_linear_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_linear_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_linear(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Linear demo incident chain (idempotent). No real Linear sync.

    One coherent Linear webhook story:
      Webhook posture risks (secret not indicated, non-HTTPS delivery, broad
      resource scope) -> Linear webhook config-state activity event -> Linear
      activity signal -> Linear risk x activity correlation -> case.

    All objects are anchored on a hidden demo integration so clear_linear
    removes them and nothing else. Evidence is built directly for the demo
    objects (never by scanning the real workspace).

    PRIVACY: no Linear API keys, OAuth tokens, webhook secrets, raw webhook
    URLs, issue titles, issue descriptions, comment bodies, attachment content,
    user emails, user names, member identities, customer names, IP addresses,
    user agents, raw audit payloads, raw API response dicts, or PII. Only safe
    booleans, counts, opaque placeholder IDs, and category labels.

    SECURITY: no strings matching eyJ[A-Za-z0-9_-]{10,} are used.
    """
    existing = _existing_linear_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" -- never shown / never synced).
    integ = _get_linear_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({
            "demo": True, "dataset": LINEAR_DEMO_DATASET,
        })
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=LINEAR_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    common_disclaimer = (
        "This is evidence for review and does not confirm compromise, "
        "unauthorized access, or data exposure."
    )

    # 2. Security findings using real Linear webhook rule keys (M85B).
    #    Evidence uses only safe booleans, counts, opaque placeholder IDs, and
    #    category labels -- never webhook URLs, delivery endpoints, webhook
    #    secrets, signing keys, user emails, issue content, or PII.

    webhook_finding_1 = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="linear",
        finding_key=(
            f"linear_webhook_no_secret_indicator:{_LINEAR_DEMO_WEBHOOK_ID}#demo"
        ),
        severity="high",
        title="Demo: Linear webhook has no secret indicated",
        resource_id=None,
        description=(
            "Sample Linear webhook missing-secret posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "linear_webhook_no_secret_indicator", "demo": True,
            "record_id": _LINEAR_DEMO_WEBHOOK_ID,
            "record_type": "linear_webhook",
            "resource_name": "Linear webhook review",
            "active": True,
            "webhook_secret_present": False,
            "webhook_enabled": True,
            "webhook_url_present": True,
            "webhook_url_scheme_category": "non_https",
            "webhook_resource_types_count": 6,
        },
        remediation={
            "summary": (
                "Configure a signing secret for the Linear webhook so receivers "
                "can verify event authenticity."
            ),
        },
    )

    webhook_finding_2 = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="linear",
        finding_key=(
            f"linear_webhook_non_https:{_LINEAR_DEMO_WEBHOOK_ID}#demo"
        ),
        severity="high",
        title="Demo: Linear webhook uses a non-HTTPS delivery endpoint",
        resource_id=None,
        description=(
            "Sample Linear webhook non-HTTPS delivery posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "linear_webhook_non_https", "demo": True,
            "record_id": _LINEAR_DEMO_WEBHOOK_ID,
            "record_type": "linear_webhook",
            "resource_name": "Linear webhook review",
            "active": True,
            "webhook_secret_present": False,
            "webhook_enabled": True,
            "webhook_url_present": True,
            "webhook_url_scheme_category": "non_https",
            "webhook_resource_types_count": 6,
        },
        remediation={
            "summary": (
                "Update the Linear webhook to deliver events only to HTTPS "
                "endpoints to protect data in transit."
            ),
        },
    )

    webhook_finding_3 = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="linear",
        finding_key=(
            f"linear_webhook_broad_resource_scope:{_LINEAR_DEMO_WEBHOOK_ID}#demo"
        ),
        severity="medium",
        title="Demo: Linear webhook has a broad resource scope",
        resource_id=None,
        description=(
            "Sample Linear webhook broad-scope posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "linear_webhook_broad_resource_scope", "demo": True,
            "record_id": _LINEAR_DEMO_WEBHOOK_ID,
            "record_type": "linear_webhook",
            "resource_name": "Linear webhook review",
            "active": True,
            "webhook_secret_present": False,
            "webhook_enabled": True,
            "webhook_url_present": True,
            "webhook_url_scheme_category": "non_https",
            "webhook_resource_types_count": 6,
        },
        remediation={
            "summary": (
                "Narrow the Linear webhook to only the specific resource types "
                "required rather than subscribing to all resource types."
            ),
        },
    )

    linear_findings = [webhook_finding_1, webhook_finding_2, webhook_finding_3]

    # 3. Activity event (provider="linear", source="linear_activity_event").
    LINEAR_ACTIVITY_SOURCE = "linear_activity_event"

    def _mk_linear_event(
        *, event_type: str, resource_type: str, provider_event_id: str,
        resource_id: str, extra: dict,
    ) -> SecurityActivityEvent:
        meta: dict[str, Any] = {
            "resource_type": resource_type,
            "event_action": event_type,
            "event_source": LINEAR_ACTIVITY_SOURCE,
            "status": "observed",
            "category": "linear_configuration",
            "status_category": "observed",
            "operation_family": "linear.webhook",
            "operation_action": "updated",
        }
        meta.update(extra)
        norm = activity_svc.normalize_activity_event(
            provider="linear", source=LINEAR_ACTIVITY_SOURCE,
            event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=provider_event_id,
            actor_id=None, actor_type=None,
            resource_type=resource_type, resource_id=resource_id,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id,
            normalized=norm, db=db,
        )
        return row

    webhook_event = _mk_linear_event(
        event_type="linear.webhook.updated",
        resource_type="linear_webhook",
        provider_event_id="LINEAR_DEMO_ACTIVITY_EVENT_ID",
        resource_id=_LINEAR_DEMO_WEBHOOK_ID,
        extra={
            "resource_id": _LINEAR_DEMO_WEBHOOK_ID,
            "resource_name": "Linear webhook review",
            "webhook_enabled": True,
            "webhook_secret_present": False,
            "webhook_url_present": True,
            "webhook_url_scheme_category": "non_https",
            "webhook_resource_types_count": 6,
            "webhook_has_comment_type": True,
            "webhook_has_attachment_type": True,
            "operation_family": "linear.webhook",
            "operation_action": "updated",
        },
    )

    linear_events = [webhook_event]

    # 4. Activity signals via the real M85E signal builder.
    linear_signals: list[SecurityIncidentSignal] = []
    for ev in linear_events:
        sig_dict = linear_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db,
            )
            linear_signals.append(sig)

    # 5. Correlation via the real M85F builder.
    linear_correlations: list[SecuritySignalCorrelation] = []
    signals_by_type_linear: dict[str, SecurityIncidentSignal] = {
        s.signal_type: s for s in linear_signals
    }

    def _add_linear_correlation(
        *,
        finding: SecurityFinding,
        signal: SecurityIncidentSignal,
        correlation_type: str,
        match_reason: str,
    ) -> SecuritySignalCorrelation:
        rule = linear_corr_svc.LINEAR_CORRELATION_RULES[correlation_type]
        cdict = linear_corr_svc._build_correlation(
            finding=finding, signal=signal,
            correlation_type=correlation_type, rule=rule,
            match_reason=match_reason,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db,
        )
        linear_correlations.append(corr)
        return corr

    webhook_signal = signals_by_type_linear.get("linear_webhook_config_changed")
    if webhook_signal is not None:
        _add_linear_correlation(
            finding=webhook_finding_1,
            signal=webhook_signal,
            correlation_type="linear_webhook_risk_activity_correlation",
            match_reason="resource_id_match",
        )

    # 6. Case linking 3 findings, 1 event, signals, and correlations.
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="[Demo] Linear webhook configuration review",
        summary=(
            "Linear webhook configuration review shows webhook posture findings "
            "with related Linear configuration activity, signal, and correlation. "
            "Evidence for review. Does not confirm compromise, unauthorized access, "
            "or data exposure. No Linear API keys, OAuth tokens, webhook secrets, "
            "raw URLs, issue content, user identities, or PII."
        ),
        severity="high",
        provider="linear",
        metadata={
            "source": LINEAR_DEMO_CASE_SOURCE,
        },
        db=db,
    )
    db.flush()

    for f in linear_findings:
        case_svc.add_link(
            case_id=case.id,
            link_type="finding",
            linked_finding_id=f.id,
            db=db,
        )

    for ev in linear_events:
        case_svc.add_link(
            case_id=case.id,
            link_type="activity_event",
            linked_activity_event_id=ev.id,
            db=db,
        )

    seen_signal_ids_linear: set = set()
    for sig in linear_signals:
        seen_signal_ids_linear.add(sig.id)
        case_svc.add_link(
            case_id=case.id,
            link_type="signal",
            linked_signal_id=sig.id,
            db=db,
        )

    for corr in linear_correlations:
        case_svc.add_link(
            case_id=case.id,
            link_type="correlation",
            linked_correlation_id=corr.id,
            db=db,
        )
        if (
            corr.linked_signal_id is not None
            and corr.linked_signal_id not in seen_signal_ids_linear
        ):
            seen_signal_ids_linear.add(corr.linked_signal_id)
            case_svc.add_link(
                case_id=case.id,
                link_type="signal",
                linked_signal_id=corr.linked_signal_id,
                db=db,
            )

    db.commit()
    logger.info(
        "linear_incident_demo: seeded workspace=%s case=%s",
        workspace_id, case.id,
    )
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_linear(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the Linear demo incident objects (and nothing else)."""
    objects_removed = 0

    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == LINEAR_DEMO_CASE_SOURCE,
        )
        .all()
    )
    case_ids = [c.id for c in demo_cases]
    if case_ids:
        objects_removed += db.query(SecurityCaseLink).filter(
            SecurityCaseLink.case_id.in_(case_ids)
        ).delete(synchronize_session=False)
        objects_removed += db.query(SecurityCase).filter(
            SecurityCase.id.in_(case_ids)
        ).delete(synchronize_session=False)

    integ = _get_linear_demo_integration(workspace_id, db)
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
            corr_conds.append(
                SecuritySignalCorrelation.linked_finding_id.in_(finding_ids)
            )
        if activity_ids:
            corr_conds.append(
                SecuritySignalCorrelation.linked_activity_event_id.in_(activity_ids)
            )
        if corr_conds:
            objects_removed += db.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                or_(*corr_conds),
            ).delete(synchronize_session=False)
        sig_conds = [SecurityIncidentSignal.integration_id == integ.id]
        if activity_ids:
            sig_conds.append(
                SecurityIncidentSignal.linked_activity_event_id.in_(activity_ids)
            )
        objects_removed += db.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == workspace_id,
            or_(*sig_conds),
        ).delete(synchronize_session=False)
        objects_removed += db.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id
        ).delete(synchronize_session=False)
        objects_removed += db.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id
        ).delete(synchronize_session=False)
        objects_removed += db.query(Resource).filter(
            Resource.integration_id == integ.id
        ).delete(synchronize_session=False)
        objects_removed += db.query(Integration).filter(
            Integration.id == integ.id
        ).delete(synchronize_session=False)

    db.commit()
    return {"cleared": True, "objects_removed": objects_removed}


# ── Jira incident demo (M86G) — a SEPARATE hidden demo integration + case source
# so "Clear Jira demo" removes only Jira demo objects and never touches any other
# provider's demo (or any real Jira integration). Same safety rules: clearly
# marked demo, no real sync, no notifications, idempotent.
#
# DEMO STORY: "Jira permission scheme review". One coherent Jira configuration
# story:
#   Permission scheme broad-access risk + webhook no-secret risk + automation
#   external-action risk -> Jira permission-scheme config-state activity event
#   (+ webhook config-state activity event) -> Jira permission scheme activity
#   signal -> Jira permission scheme risk x activity correlation -> human-reviewed
#   case -> report.
#
# All objects are anchored on a hidden demo integration so clear_jira removes
# them and nothing else. Evidence is built directly for the demo objects (never
# by scanning a real workspace).
#
# PRIVACY: no Jira API tokens, OAuth tokens, webhook secrets, integration secrets,
# raw webhook/delivery URLs, site base URLs, JQL, filter expressions, issue keys,
# issue titles, issue descriptions, comment bodies, attachment content, customer
# names, user emails, user names, account IDs, member/grant-holder identities, IP
# addresses, user agents, request/response payloads, raw audit payloads, or PII.
# Only safe opaque placeholder IDs, booleans, counts, and category labels.
#
# SECURITY: no strings matching eyJ[A-Za-z0-9_-]{10,} are used.

JIRA_DEMO_INTEGRATION_NAME = "ConfigTrace Jira incident demo (sample data)"
JIRA_DEMO_CASE_SOURCE = "demo_jira_incident"
JIRA_DEMO_DATASET = "jira_incident_demo_v1"

# Safe placeholders -- no real Jira values, no API tokens, no webhook URLs.
JIRA_DEMO_PERMISSION_SCHEME_ID = "JIRA_DEMO_PERMISSION_SCHEME_ID"
JIRA_DEMO_WEBHOOK_ID = "JIRA_DEMO_WEBHOOK_ID"
JIRA_DEMO_AUTOMATION_RULE_ID = "JIRA_DEMO_AUTOMATION_RULE_ID"
JIRA_DEMO_WORKFLOW_ID = "JIRA_DEMO_WORKFLOW_ID"
JIRA_DEMO_PROJECT_ID = "JIRA_DEMO_PROJECT_ID"
JIRA_DEMO_SITE_ID = "JIRA_DEMO_SITE_ID"


def _get_jira_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.display_name == JIRA_DEMO_INTEGRATION_NAME,
        )
        .first()
    )


def _existing_jira_demo_case(
    workspace_id: uuid.UUID, db: Session
) -> Optional[SecurityCase]:
    return (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == JIRA_DEMO_CASE_SOURCE,
        )
        .first()
    )


def get_jira_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    case = _existing_jira_demo_case(workspace_id, db)
    if case is None:
        return {"seeded": False, "case_id": None, "link_count": 0}
    return {
        "seeded": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def seed_jira(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the Jira demo incident chain (idempotent). No real Jira sync.

    "Jira permission scheme review" story:
      Permission scheme broad-access risk + webhook no-secret risk + automation
      external-action risk -> Jira permission-scheme config-state activity event
      (+ webhook config-state activity event) -> Jira permission scheme activity
      signal -> Jira permission scheme risk x activity correlation -> case.

    All objects are anchored on a hidden demo integration so clear_jira removes
    them and nothing else. Evidence is built directly for the demo objects
    (never by scanning the real workspace).

    PRIVACY: no Jira API tokens, OAuth tokens, webhook secrets, raw webhook/
    delivery URLs, site base URLs, JQL, issue keys, issue titles, issue
    descriptions, comment bodies, attachment content, user emails, user names,
    account IDs, grant-holder identities, IP addresses, user agents, raw audit
    payloads, raw API response dicts, or PII. Only safe booleans, counts, opaque
    placeholder IDs, and category labels.

    SECURITY: no strings matching eyJ[A-Za-z0-9_-]{10,} are used.
    """
    existing = _existing_jira_demo_case(workspace_id, db)
    if existing is not None:
        return {
            "seeded": True,
            "created": False,
            "case_id": str(existing.id),
            "link_count": case_svc.count_links(existing.id, db),
        }

    # 1. Hidden demo integration (status="deleted" -- never shown / never synced).
    integ = _get_jira_demo_integration(workspace_id, db)
    if integ is None:
        ct, iv = encrypt_credentials({
            "demo": True, "dataset": JIRA_DEMO_DATASET,
        })
        integ = Integration(
            user_id=actor_user_id,
            workspace_id=workspace_id,
            provider=DEMO_PROVIDER_TAG,
            display_name=JIRA_DEMO_INTEGRATION_NAME,
            encrypted_credentials=ct,
            credential_iv=iv,
            status="deleted",
            scheduled_sync_enabled=False,
        )
        db.add(integ)
        db.flush()

    common_disclaimer = (
        "This is Jira configuration evidence for review and does not confirm "
        "compromise, unauthorized access, or data exposure."
    )

    # 2. Security findings using real Jira rule keys (M86B/M86C).
    #    Evidence uses only safe booleans, counts, opaque placeholder IDs, and
    #    category labels -- never permission grant holders, webhook URLs/secrets,
    #    automation action targets, user identities, issue content, or PII.

    permission_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="jira",
        finding_key=(
            f"jira_permission_scheme_public_administer_projects:"
            f"{JIRA_DEMO_PERMISSION_SCHEME_ID}#demo"
        ),
        severity="high",
        title="Demo: Jira permission scheme grants broad administer access",
        resource_id=None,
        description=(
            "Jira configuration evidence indicates the permission scheme may "
            "require review. Sample Jira permission scheme broad-access posture "
            f"risk for the incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "jira_permission_scheme_public_administer_projects",
            "demo": True,
            "record_id": JIRA_DEMO_PERMISSION_SCHEME_ID,
            "record_type": "jira_permission_scheme",
            "permission_scheme_id": JIRA_DEMO_PERMISSION_SCHEME_ID,
            "resource_type": "permission_scheme",
            "resource_name": "Jira permission scheme review",
            "active": True,
            "permission_public_administer_projects": True,
            "permission_grant_count": 24,
        },
        remediation={
            "summary": (
                "Review the Jira permission scheme and remove broad public "
                "administer-projects grants so only intended roles retain "
                "administrative access."
            ),
        },
    )

    webhook_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="jira",
        finding_key=(
            f"jira_webhook_no_secret_indicator:{JIRA_DEMO_WEBHOOK_ID}#demo"
        ),
        severity="high",
        title="Demo: Jira webhook has no secret indicated",
        resource_id=None,
        description=(
            "Jira configuration evidence indicates the webhook may require "
            "review. Sample Jira webhook missing-secret posture risk for the "
            f"incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "jira_webhook_no_secret_indicator",
            "demo": True,
            "record_id": JIRA_DEMO_WEBHOOK_ID,
            "record_type": "jira_webhook",
            "webhook_id": JIRA_DEMO_WEBHOOK_ID,
            "resource_type": "webhook",
            "resource_name": "Jira webhook review",
            "active": True,
            "webhook_secret_present": False,
            "webhook_event_count": 12,
        },
        remediation={
            "summary": (
                "Configure a signing secret for the Jira webhook so receivers "
                "can verify event authenticity."
            ),
        },
    )

    automation_finding = finding_svc.upsert_active_finding(
        db=db, workspace_id=workspace_id, integration_id=integ.id,
        provider="jira",
        finding_key=(
            f"jira_automation_rule_external_action:{JIRA_DEMO_AUTOMATION_RULE_ID}#demo"
        ),
        severity="high",
        title="Demo: Jira automation rule performs an external action",
        resource_id=None,
        description=(
            "Jira configuration evidence indicates the automation rule may "
            "require review. Sample Jira automation external-action posture "
            f"risk for the incident-workflow demo. {common_disclaimer}"
        ),
        evidence={
            "rule": "jira_automation_rule_external_action",
            "demo": True,
            "record_id": JIRA_DEMO_AUTOMATION_RULE_ID,
            "record_type": "jira_automation_rule",
            "automation_rule_id": JIRA_DEMO_AUTOMATION_RULE_ID,
            "resource_type": "automation_rule",
            "resource_name": "Jira automation rule review",
            "active": True,
            "automation_has_external_action": True,
            "automation_scope_category": "global",
        },
        remediation={
            "summary": (
                "Review the Jira automation rule and confirm whether the "
                "external action is intended and appropriately scoped."
            ),
        },
    )

    jira_findings = [permission_finding, webhook_finding, automation_finding]

    # 3. Activity events (provider="jira", source="jira_activity_event").
    JIRA_ACTIVITY_SOURCE = "jira_activity_event"

    def _mk_jira_event(
        *, event_type: str, resource_type: str, provider_event_id: str,
        resource_id: str, extra: dict,
    ) -> SecurityActivityEvent:
        meta: dict[str, Any] = {
            "resource_type": resource_type,
            "event_action": event_type,
            "event_source": JIRA_ACTIVITY_SOURCE,
            "status": "observed",
            "category": "jira_configuration",
            "status_category": "observed",
            "operation_family": "jira_configuration",
            "operation_action": "configuration_updated",
        }
        meta.update(extra)
        norm = activity_svc.normalize_activity_event(
            provider="jira", source=JIRA_ACTIVITY_SOURCE,
            event_type=event_type,
            occurred_at=_utcnow(),
            provider_event_id=provider_event_id,
            actor_id=None, actor_type=None,
            resource_type=resource_type, resource_id=resource_id,
            metadata=meta,
        )
        _o, row = activity_svc.upsert_activity_event(
            workspace_id=workspace_id, integration_id=integ.id,
            normalized=norm, db=db,
        )
        return row

    permission_event = _mk_jira_event(
        event_type="jira.permission_scheme.updated",
        resource_type="jira_permission_scheme",
        provider_event_id="JIRA_DEMO_PERMISSION_ACTIVITY_EVENT_ID",
        resource_id=JIRA_DEMO_PERMISSION_SCHEME_ID,
        extra={
            "resource_id": JIRA_DEMO_PERMISSION_SCHEME_ID,
            "permission_scheme_id": JIRA_DEMO_PERMISSION_SCHEME_ID,
            "resource_name": "Jira permission scheme review",
            "permission_grant_count": 24,
            "permission_public_administer_projects": True,
        },
    )

    webhook_event = _mk_jira_event(
        event_type="jira.webhook.updated",
        resource_type="jira_webhook",
        provider_event_id="JIRA_DEMO_WEBHOOK_ACTIVITY_EVENT_ID",
        resource_id=JIRA_DEMO_WEBHOOK_ID,
        extra={
            "resource_id": JIRA_DEMO_WEBHOOK_ID,
            "webhook_id": JIRA_DEMO_WEBHOOK_ID,
            "resource_name": "Jira webhook review",
            "webhook_enabled": True,
            "webhook_event_count": 12,
        },
    )

    jira_events = [permission_event, webhook_event]

    # 4. Activity signals via the real M86E signal builder. One signal per
    #    (signal_type, resource); the permission-scheme event yields the
    #    jira_permission_scheme_config_changed signal used by the correlation.
    jira_signals: list[SecurityIncidentSignal] = []
    for ev in jira_events:
        sig_dict = jira_sig._build_signal([ev])
        if sig_dict is not None:
            _so, sig = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=sig_dict, db=db,
            )
            jira_signals.append(sig)

    # 5. Correlation via the real M86F builder.
    jira_correlations: list[SecuritySignalCorrelation] = []
    signals_by_type_jira: dict[str, SecurityIncidentSignal] = {
        s.signal_type: s for s in jira_signals
    }

    def _add_jira_correlation(
        *,
        finding: SecurityFinding,
        signal: SecurityIncidentSignal,
        correlation_type: str,
        match_reason: str,
    ) -> SecuritySignalCorrelation:
        rule = jira_corr_svc.JIRA_CORRELATION_RULES[correlation_type]
        cdict = jira_corr_svc._build_correlation(
            finding=finding, signal=signal,
            correlation_type=correlation_type, rule=rule,
            match_reason=match_reason,
        )
        _co, corr = corr_svc.upsert_correlation(
            workspace_id=workspace_id, correlation=cdict, db=db,
        )
        jira_correlations.append(corr)
        return corr

    permission_signal = signals_by_type_jira.get(
        "jira_permission_scheme_config_changed"
    )
    if permission_signal is not None:
        _add_jira_correlation(
            finding=permission_finding,
            signal=permission_signal,
            correlation_type="jira_permission_scheme_risk_with_activity",
            match_reason="resource_id_match",
        )

    # 6. Case linking 3 findings, 2 events, signals, and correlations.
    case = case_svc.create_case(
        workspace_id=workspace_id,
        user_id=actor_user_id,
        title="Jira Permission Scheme Configuration Review",
        summary=(
            "Jira configuration evidence indicates permission scheme posture may require review."
            " This does not confirm compromise, unauthorized access, or data exposure."
            " This Jira permission scheme review groups configuration findings"
            " (permission scheme, webhook, automation) with related Jira configuration"
            " activity, signal, and correlation. Evidence for review. No Jira API tokens,"
            " OAuth tokens, webhook secrets, raw URLs, JQL, issue content, grant-holder"
            " identities, or PII."
        ),
        severity="high",
        provider="jira",
        metadata={
            "source": JIRA_DEMO_CASE_SOURCE,
        },
        db=db,
    )
    db.flush()

    for f in jira_findings:
        case_svc.link_object_to_case(
            case=case, object_type="finding", object_id=f.id,
            actor_user_id=actor_user_id, db=db,
        )

    for ev in jira_events:
        case_svc.link_object_to_case(
            case=case, object_type="activity_event", object_id=ev.id,
            actor_user_id=actor_user_id, db=db,
        )

    seen_signal_ids_jira: set = set()
    for sig in jira_signals:
        seen_signal_ids_jira.add(sig.id)
        case_svc.link_object_to_case(
            case=case, object_type="signal", object_id=sig.id,
            actor_user_id=actor_user_id, db=db,
        )

    for corr in jira_correlations:
        case_svc.link_object_to_case(
            case=case, object_type="correlation", object_id=corr.id,
            actor_user_id=actor_user_id, db=db,
        )
        if (
            corr.linked_signal_id is not None
            and corr.linked_signal_id not in seen_signal_ids_jira
        ):
            seen_signal_ids_jira.add(corr.linked_signal_id)
            case_svc.link_object_to_case(
                case=case, object_type="signal",
                object_id=corr.linked_signal_id,
                actor_user_id=actor_user_id, db=db,
            )

    db.commit()
    logger.info(
        "jira_incident_demo: seeded workspace=%s case=%s",
        workspace_id, case.id,
    )
    return {
        "seeded": True,
        "created": True,
        "case_id": str(case.id),
        "link_count": case_svc.count_links(case.id, db),
    }


def clear_jira(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove exactly the Jira demo incident objects (and nothing else)."""
    objects_removed = 0

    demo_cases = (
        db.query(SecurityCase)
        .filter(
            SecurityCase.workspace_id == workspace_id,
            SecurityCase.case_metadata["source"].astext == JIRA_DEMO_CASE_SOURCE,
        )
        .all()
    )
    case_ids = [c.id for c in demo_cases]
    if case_ids:
        objects_removed += db.query(SecurityCaseLink).filter(
            SecurityCaseLink.case_id.in_(case_ids)
        ).delete(synchronize_session=False)
        objects_removed += db.query(SecurityCase).filter(
            SecurityCase.id.in_(case_ids)
        ).delete(synchronize_session=False)

    integ = _get_jira_demo_integration(workspace_id, db)
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
            corr_conds.append(
                SecuritySignalCorrelation.linked_finding_id.in_(finding_ids)
            )
        if activity_ids:
            corr_conds.append(
                SecuritySignalCorrelation.linked_activity_event_id.in_(activity_ids)
            )
        if corr_conds:
            objects_removed += db.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                or_(*corr_conds),
            ).delete(synchronize_session=False)
        sig_conds = [SecurityIncidentSignal.integration_id == integ.id]
        if activity_ids:
            sig_conds.append(
                SecurityIncidentSignal.linked_activity_event_id.in_(activity_ids)
            )
        objects_removed += db.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == workspace_id,
            or_(*sig_conds),
        ).delete(synchronize_session=False)
        objects_removed += db.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id
        ).delete(synchronize_session=False)
        objects_removed += db.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id
        ).delete(synchronize_session=False)
        objects_removed += db.query(Resource).filter(
            Resource.integration_id == integ.id
        ).delete(synchronize_session=False)
        objects_removed += db.query(Integration).filter(
            Integration.id == integ.id
        ).delete(synchronize_session=False)

    db.commit()
    return {"cleared": True, "objects_removed": objects_removed}
