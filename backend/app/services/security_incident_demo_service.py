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
