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

logger = logging.getLogger(__name__)

DEMO_PROVIDER_TAG = "demo"
DEMO_INTEGRATION_NAME = "ConfigTrace incident demo (sample data)"
DEMO_REPO = "configtrace-demo/incident-repo"
DEMO_CASE_SOURCE = "demo_incident"


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
