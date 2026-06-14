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
