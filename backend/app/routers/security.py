"""Security Exposure router — M60.3 (read-only foundation).

Routes
------
GET /security/findings        — paginated, filtered list of security findings
GET /security/findings/{id}   — full detail for a single finding

Scope & security
----------------
Findings are workspace-scoped. Every result is restricted to workspaces the
authenticated user is a member of. The detail endpoint returns HTTP 404 (never
403) for findings the user cannot see, to avoid leaking existence — matching
the Changes endpoints.

Mutation actions (accept risk / snooze / review) are intentionally NOT included
in this milestone; they arrive alongside the evaluation engine work.

Naming: this is "security exposure findings" — security-relevant configuration
exposure. It is not breach or threat detection.
"""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import UUID4
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.database import get_db
from app.models.security_finding import (
    VALID_FINDING_SEVERITIES,
    VALID_FINDING_STATUSES,
)
from app.models.user import User
from app.schemas.security_finding import (
    AcceptRiskRequest,
    SecurityFindingListResponse,
    SecurityFindingResponse,
    SnoozeRequest,
)
from app.schemas.security_finding_note import (
    SecurityFindingActivityItem,
    SecurityFindingActivityResponse,
    SecurityFindingNoteCreate,
    SecurityFindingNoteListResponse,
    SecurityFindingNoteResponse,
)
from app.schemas.security_rule_setting import (
    RuleSettingUpdateRequest,
    SecurityRuleSettingItem,
    SecurityRuleSettingsListResponse,
)
from app.schemas.security_demo_data import (
    SecurityDemoClearResponse,
    SecurityDemoDataStatus,
)
from app.schemas.security_coverage import SecurityCoverageResponse
from app.schemas.security_beta_event import (
    SecurityBetaEventCreate,
    SecurityBetaEventResponse,
    SecurityBetaSummaryResponse,
)
from app.schemas.security_rule_pack import (
    SecurityRulePackResponse,
    SecurityRulePackRule,
)
from app.schemas.security_beta_feedback import (
    SecurityBetaFeedbackCreate,
    SecurityBetaFeedbackResponse,
)
from app.schemas.security_activity_event import (
    SecurityActivityEventListResponse,
    SecurityActivityEventResponse,
    SecurityActivitySyncRequest,
    SecurityActivitySyncResponse,
)
from app.schemas.security_incident_signal import (
    SecurityIncidentSignalListResponse,
    SecurityIncidentSignalResponse,
    SecuritySignalGenerateRequest,
    SecuritySignalGenerateResponse,
)
from app.schemas.security_signal_correlation import (
    SecuritySignalCorrelationListResponse,
    SecuritySignalCorrelationResponse,
    SecurityCorrelationGenerateRequest,
    SecurityCorrelationGenerateResponse,
)
from app.schemas.security_case import (
    SecurityCaseCreate,
    SecurityCaseUpdate,
    SecurityCaseResponse,
    SecurityCaseListResponse,
    SecurityCaseDetailResponse,
    SecurityCaseLinkCreate,
    SecurityCaseLinkResponse,
    SecurityCaseLinkListResponse,
)
from app.schemas.security_case_report import SecurityCaseReportResponse
from app.schemas.security_incident_demo import (
    IncidentDemoStatusResponse,
    IncidentDemoSeedResponse,
    IncidentDemoClearResponse,
)
from app.schemas.security_aws_alerts import (
    AwsAlertSyncRequest,
    AwsAlertSyncResponse,
    AwsSignalGenerateResponse,
)
from app.models.integration import Integration
from app.services import security_finding_service
from app.services import security_finding_note_service
from app.services import security_rule_settings_service
from app.services import security_demo_data_service
from app.services import security_coverage_service
from app.services import security_beta_event_service
from app.services import security_beta_feedback_service
from app.services import security_rule_pack
from app.services import security_activity_event_service
from app.services import github_activity_ingestion_service
from app.services import security_incident_signal_service
from app.services import security_signal_correlation_service
from app.services import security_case_service
from app.services import security_case_report_service
from app.services import security_incident_demo_service
from app.services import aws_security_alert_ingestion_service
from app.services import workspace_service
from app.services import workspace_permission_service
from app.services.security_rule_registry import is_known_rule_key

router = APIRouter(prefix="/security", tags=["security"])


@router.get("/findings", response_model=SecurityFindingListResponse)
def list_security_findings(
    status: Optional[str] = Query(
        None, description="Filter by lifecycle status (active/resolved/accepted_risk/snoozed)."
    ),
    severity: Optional[str] = Query(
        None, description="Filter by severity (critical/high/medium/low/info)."
    ),
    provider: Optional[str] = Query(None, description="Filter by provider."),
    integration_id: Optional[UUID4] = Query(None),
    resource_id: Optional[UUID4] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingListResponse:
    """Return a paginated, filtered list of the user's security findings.

    Results are restricted to the authenticated user's workspaces and ordered
    by ``last_seen_at DESC``. All filters are optional and combined with AND.
    """
    if status is not None and status not in VALID_FINDING_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status: {status!r}")
    if severity is not None and severity not in VALID_FINDING_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"Invalid severity: {severity!r}")

    items, total = security_finding_service.list_findings(
        user_id=current_user.id,
        db=db,
        status=status,
        severity=severity,
        provider=provider,
        integration_id=integration_id,
        resource_id=resource_id,
        page=page,
        page_size=page_size,
    )

    return SecurityFindingListResponse(
        items=[SecurityFindingResponse.model_validate(f) for f in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/findings/{finding_id}", response_model=SecurityFindingResponse)
def get_security_finding(
    finding_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingResponse:
    """Return full detail for a single security finding.

    Returns HTTP 404 whether the finding does not exist OR belongs to a
    workspace the user is not a member of.
    """
    finding = security_finding_service.get_finding_for_user(
        finding_id=finding_id,
        user_id=current_user.id,
        db=db,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found.")
    return SecurityFindingResponse.model_validate(finding)


@router.post(
    "/findings/{finding_id}/accept-risk",
    response_model=SecurityFindingResponse,
)
def accept_security_finding_risk(
    finding_id: UUID4,
    body: AcceptRiskRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingResponse:
    """Mark an active security finding as accepted risk (M61.1).

    Accepting risk records that the team is intentionally carrying a known
    exposure until ``accepted_until`` — for the stated reason. It does NOT mark
    the exposure resolved or fixed, and it sends no notifications.

    * 404 — finding does not exist, or belongs to a workspace the user is not a
      member of (never 403, to avoid leaking existence).
    * 400 — the finding cannot be accepted (e.g. it is already resolved).
    * 422 — the request body is invalid (missing reason, past expiry).

    Re-accepting an already ``accepted_risk`` finding updates its reason and
    expiry without re-subscribing it as a new exposure.
    """
    finding = security_finding_service.get_finding_for_user(
        finding_id=finding_id,
        user_id=current_user.id,
        db=db,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found.")

    # M63.2 — accepting risk is a higher-impact action: admin/owner only.
    workspace_permission_service.require_workspace_admin(
        finding.workspace_id, current_user.id, db
    )

    try:
        updated = security_finding_service.accept_finding_risk(
            db=db,
            finding=finding,
            actor_user_id=current_user.id,
            reason=body.reason,
            accepted_until=body.accepted_until,
        )
    except security_finding_service.FindingNotAcceptableError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return SecurityFindingResponse.model_validate(updated)


@router.post(
    "/findings/{finding_id}/acknowledge",
    response_model=SecurityFindingResponse,
)
def acknowledge_security_finding(
    finding_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingResponse:
    """Acknowledge an active security finding (M61.2).

    Records that the team has reviewed the exposure and is tracking it. The
    finding stays ACTIVE — acknowledging does NOT mark it fixed or resolved, and
    it sends no notifications.

    * 404 — finding not found, or not in the user's workspace (never 403).
    * 400 — the finding cannot be acknowledged (resolved, accepted risk, or
      snoozed — those are already explicit review states).
    """
    finding = security_finding_service.get_finding_for_user(
        finding_id=finding_id,
        user_id=current_user.id,
        db=db,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found.")

    # M63.2 — acknowledge is a collaborative review action: any member or above.
    workspace_permission_service.require_workspace_member(
        finding.workspace_id, current_user.id, db
    )

    try:
        updated = security_finding_service.acknowledge_finding(
            db=db,
            finding=finding,
            actor_user_id=current_user.id,
        )
    except security_finding_service.FindingNotAcceptableError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return SecurityFindingResponse.model_validate(updated)


@router.post(
    "/findings/{finding_id}/snooze",
    response_model=SecurityFindingResponse,
)
def snooze_security_finding(
    finding_id: UUID4,
    body: SnoozeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingResponse:
    """Snooze an active security finding until ``snoozed_until`` (M61.2).

    Snoozing pauses active attention on the exposure temporarily. It does NOT
    accept the risk and does NOT mark the exposure fixed or resolved, and it
    sends no notifications. While snoozed, the evaluator will not re-open an
    active duplicate; once the snooze expires and the risky state persists, a
    fresh active finding opens.

    * 404 — finding not found, or not in the user's workspace (never 403).
    * 400 — the finding cannot be snoozed (resolved, or accepted risk).
    * 422 — the request body is invalid (missing or past ``snoozed_until``).
    """
    finding = security_finding_service.get_finding_for_user(
        finding_id=finding_id,
        user_id=current_user.id,
        db=db,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found.")

    # M63.2 — snoozing is a higher-impact action: admin/owner only.
    workspace_permission_service.require_workspace_admin(
        finding.workspace_id, current_user.id, db
    )

    try:
        updated = security_finding_service.snooze_finding(
            db=db,
            finding=finding,
            actor_user_id=current_user.id,
            snoozed_until=body.snoozed_until,
        )
    except security_finding_service.FindingNotAcceptableError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return SecurityFindingResponse.model_validate(updated)


# ── Review notes + activity feed (M61.3) ──────────────────────────────────────


def _require_finding(finding_id, current_user, db):
    """Load a finding scoped to the user's workspace, or raise 404."""
    finding = security_finding_service.get_finding_for_user(
        finding_id=finding_id, user_id=current_user.id, db=db,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found.")
    return finding


@router.get(
    "/findings/{finding_id}/notes",
    response_model=SecurityFindingNoteListResponse,
)
def list_security_finding_notes(
    finding_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingNoteListResponse:
    """Return all review notes for a finding, oldest first (M61.3).

    Only members of the finding's workspace may view notes; others get 404.
    """
    _require_finding(finding_id, current_user, db)
    notes = security_finding_note_service.list_notes(finding_id=finding_id, db=db)
    return SecurityFindingNoteListResponse(
        items=[SecurityFindingNoteResponse.model_validate(n) for n in notes],
        total=len(notes),
    )


@router.post(
    "/findings/{finding_id}/notes",
    response_model=SecurityFindingNoteResponse,
    status_code=201,
)
def create_security_finding_note(
    finding_id: UUID4,
    body: SecurityFindingNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingNoteResponse:
    """Add a review note to a finding (M61.3).

    Notes capture investigation context, owner handoff, or follow-up. A note
    NEVER changes the finding's status and sends no notifications.

    * 404 — finding not found, or not in the user's workspace.
    * 422 — note body is empty / too short / too long.
    """
    finding = _require_finding(finding_id, current_user, db)
    # M63.2 — adding a review note is collaborative: any member or above.
    workspace_permission_service.require_workspace_member(
        finding.workspace_id, current_user.id, db
    )
    try:
        note = security_finding_note_service.create_note(
            finding_id=finding_id,
            workspace_id=finding.workspace_id,
            author_user_id=current_user.id,
            body=body.body,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return SecurityFindingNoteResponse.model_validate(note)


@router.get(
    "/findings/{finding_id}/activity",
    response_model=SecurityFindingActivityResponse,
)
def get_security_finding_activity(
    finding_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingActivityResponse:
    """Return a combined, derived activity feed for a finding (M61.3).

    Combines lifecycle actions (exposure opened, acknowledged, snoozed, risk
    accepted, resolved) derived from the finding's own fields with note_added
    entries. Read-only and metadata-only; emits nothing.

    Only members of the finding's workspace may view activity; others get 404.
    """
    finding = _require_finding(finding_id, current_user, db)
    notes = security_finding_note_service.list_notes(finding_id=finding_id, db=db)
    items = security_finding_note_service.build_activity(finding=finding, notes=notes)
    return SecurityFindingActivityResponse(
        items=[SecurityFindingActivityItem(**it) for it in items],
        total=len(items),
    )


# ── Rule enable/disable settings (M61.7) ──────────────────────────────────────


def _current_workspace_id(current_user: User, db: Session):
    """Resolve the workspace for rule settings (the user's default workspace).

    Rule settings are workspace-scoped; we use the same default-workspace helper
    other non-/workspaces/{id} surfaces use, so a single workspace is targeted.
    """
    ws = workspace_service.get_or_create_default_workspace(
        user_id=current_user.id,
        user_display_name=getattr(current_user, "display_name", None),
        db=db,
    )
    return ws.id


@router.get("/rules/pack", response_model=SecurityRulePackResponse)
def get_security_rule_pack(
    current_user: User = Depends(get_current_user),
) -> SecurityRulePackResponse:
    """Return the active Security Exposure rule pack + per-rule version (M63.3).

    Read-only and workspace-independent: the rule pack is a static manifest of
    which rules ship in the current pack version. Authenticated like every other
    security endpoint.
    """
    summary = security_rule_pack.pack_summary()
    return SecurityRulePackResponse(
        name=summary["name"],
        version=summary["version"],
        released_at=summary["released_at"],
        description=summary["description"],
        rule_count=summary["rule_count"],
        providers=summary["providers"],
        rules=[SecurityRulePackRule(**r) for r in summary["rules"]],
    )


@router.get("/rules/settings", response_model=SecurityRuleSettingsListResponse)
def list_security_rule_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityRuleSettingsListResponse:
    """Return every known security rule with its effective enabled state (M61.7).

    Scoped to the current user's workspace. Rules with no override report
    ``enabled=true`` / ``explicit_setting=false``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    items = security_rule_settings_service.list_effective_settings(workspace_id, db)
    return SecurityRuleSettingsListResponse(
        items=[SecurityRuleSettingItem(**it) for it in items],
        total=len(items),
    )


@router.patch(
    "/rules/settings/{rule_key}",
    response_model=SecurityRuleSettingItem,
)
def update_security_rule_setting(
    rule_key: str,
    body: RuleSettingUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityRuleSettingItem:
    """Enable or disable a security rule for the current workspace (M61.7).

    Disabling a rule stops FUTURE findings from that rule. It does not mark
    existing findings resolved, delete them, or send notifications.

    * 404 — unknown rule key.
    """
    if not is_known_rule_key(rule_key):
        raise HTTPException(status_code=404, detail="Unknown security rule key.")

    workspace_id = _current_workspace_id(current_user, db)
    # M63.2 — changing rule settings is admin/owner only.
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    try:
        item = security_rule_settings_service.set_rule_enabled(
            workspace_id=workspace_id,
            rule_key=rule_key,
            enabled=body.enabled,
            actor_user_id=current_user.id,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return SecurityRuleSettingItem(**item)


# ── Demo data (M62.2) ─────────────────────────────────────────────────────────


@router.get("/demo-data/status", response_model=SecurityDemoDataStatus)
def get_security_demo_data_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityDemoDataStatus:
    """Return whether Security Exposure demo data exists for the workspace."""
    workspace_id = _current_workspace_id(current_user, db)
    return SecurityDemoDataStatus(
        **security_demo_data_service.get_status(workspace_id, db)
    )


@router.post("/demo-data/seed", response_model=SecurityDemoDataStatus)
def seed_security_demo_data(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityDemoDataStatus:
    """Seed a safe Security Exposure demo dataset for the current workspace.

    Opt-in and idempotent: if demo data already exists, the current counts are
    returned without duplicating. Inserts rows directly — no evaluator run and
    no Slack/email/push notifications.
    """
    workspace_id = _current_workspace_id(current_user, db)
    # M63.2 — seeding demo data mutates workspace data: admin/owner only.
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    return SecurityDemoDataStatus(
        **security_demo_data_service.seed(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    )


@router.delete("/demo-data", response_model=SecurityDemoClearResponse)
def clear_security_demo_data(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityDemoClearResponse:
    """Remove only the demo-created Security Exposure rows for the workspace."""
    workspace_id = _current_workspace_id(current_user, db)
    # M63.2 — clearing demo data mutates workspace data: admin/owner only.
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    return SecurityDemoClearResponse(
        **security_demo_data_service.clear(workspace_id=workspace_id, db=db)
    )


# ── Coverage quality (M62.3) ──────────────────────────────────────────────────


@router.get("/coverage", response_model=SecurityCoverageResponse)
def get_security_coverage(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCoverageResponse:
    """Report Security Exposure coverage quality per provider (read-only, M62.3).

    Inspects stored snapshots only — never calls provider APIs. Reports which
    surfaces are monitored and which rules have enough data to run. Demo and
    deleted integrations are ignored. Good coverage does not mean no risk exists.
    """
    workspace_id = _current_workspace_id(current_user, db)
    return SecurityCoverageResponse(
        **security_coverage_service.get_coverage(workspace_id, db)
    )


# ── Beta usage instrumentation (M63.1) ────────────────────────────────────────


@router.post("/beta-events", response_model=SecurityBetaEventResponse, status_code=201)
def create_security_beta_event(
    body: SecurityBetaEventCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityBetaEventResponse:
    """Record a lightweight, workspace-scoped Security Exposure beta usage event.

    First-party only. ``event_name`` is validated against a fixed allowlist
    (422 on unknown names); ``metadata`` keys are allowlisted, type-checked, and
    truncated server-side — evidence/remediation/secrets/payloads/note bodies
    can never be stored. Intended for beta learning, not surveillance.
    """
    workspace_id = _current_workspace_id(current_user, db)
    try:
        event = security_beta_event_service.record_event(
            workspace_id=workspace_id,
            user_id=current_user.id,
            event_name=body.event_name,
            page_path=body.page_path,
            metadata=body.metadata,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return SecurityBetaEventResponse(id=str(event.id), ok=True)


@router.get("/beta-events/summary", response_model=SecurityBetaSummaryResponse)
def get_security_beta_events_summary(
    days: int = Query(7, description="Window length in days (1, 7, 30, or 90)."),
    event_name: Optional[str] = Query(None, description="Filter to a single event name."),
    route_group: Optional[str] = Query(None, description="Filter to a single route group."),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityBetaSummaryResponse:
    """Read-only, workspace-scoped beta usage analytics (M63.4).

    Admin/owner only (a member of the workspace gets 403). First-party and
    metadata-only — reuses the already-sanitized security_beta_events rows and
    never exposes other workspaces.
    """
    if days not in security_beta_event_service.ALLOWED_SUMMARY_DAYS:
        raise HTTPException(status_code=422, detail="days must be one of 1, 7, 30, 90.")
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    data = security_beta_event_service.summarize(
        workspace_id=workspace_id,
        days=days,
        event_name=event_name,
        route_group=route_group,
        db=db,
    )
    return SecurityBetaSummaryResponse(**data)


@router.post("/beta-feedback", response_model=SecurityBetaFeedbackResponse, status_code=201)
def create_security_beta_feedback(
    body: SecurityBetaFeedbackCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityBetaFeedbackResponse:
    """Record optional qualitative feedback after a report export (M63.6).

    First-party + workspace-scoped. ``rating`` and ``feedback_type`` are
    validated against fixed allowlists (422 on bad values); ``comment`` is
    truncated; ``context`` keys are allowlisted + scalar-only — report contents,
    evidence/remediation, notes, secrets, tokens, and payloads can never be
    stored. Any authenticated workspace member may submit feedback.
    """
    workspace_id = _current_workspace_id(current_user, db)
    try:
        feedback = security_beta_feedback_service.record_feedback(
            workspace_id=workspace_id,
            user_id=current_user.id,
            feedback_type=body.feedback_type,
            rating=body.rating,
            comment=body.comment,
            context=body.context,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return SecurityBetaFeedbackResponse(id=str(feedback.id), ok=True)


# ── Activity ingestion (M66.2) ────────────────────────────────────────────────
#
# Foundation for the FUTURE Incident Signals product. These endpoints ingest and
# list normalized GitHub control-plane *activity* events. They do NOT detect
# breaches, identify attackers, or confirm compromise — correlation that turns
# activity + configuration risk into incident signals is a later milestone.


@router.post("/activity/sync", response_model=SecurityActivitySyncResponse)
def sync_security_activity(
    body: Optional[SecurityActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityActivitySyncResponse:
    """Attempt GitHub audit-log activity ingestion for a workspace integration.

    Admin/owner only — this pulls organization audit logs. Non-fatal: permission
    or availability limits are reported in the summary, never raised. Ingests
    control-plane activity only; makes no breach/attacker/compromise claims.
    """
    workspace_id = _current_workspace_id(current_user, db)
    # Higher-impact action (pulls org audit logs) → admin/owner only.
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "github",
    )
    requested_id = body.integration_id if body else None
    if requested_id:
        try:
            iid = uuid.UUID(str(requested_id))
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(status_code=422, detail="Invalid integration_id.")
        integration = q.filter(Integration.id == iid).first()
        if integration is None:
            raise HTTPException(status_code=404, detail="GitHub integration not found.")
    else:
        integration = (
            q.filter(Integration.status == "active")
            .order_by(Integration.created_at.asc())
            .first()
        )
        if integration is None:
            return SecurityActivitySyncResponse(
                attempted=False,
                succeeded=False,
                provider="github",
                error_message="No active GitHub integration found.",
            )

    summary = github_activity_ingestion_service.ingest_github_activity(
        integration=integration,
        workspace_id=workspace_id,
        db=db,
    )
    return SecurityActivitySyncResponse(**summary)


@router.get("/activity/events", response_model=SecurityActivityEventListResponse)
def list_security_activity_events(
    provider: Optional[str] = Query(None, description="Filter by provider."),
    event_type: Optional[str] = Query(
        None, description="Filter by normalized event_type."
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityActivityEventListResponse:
    """List recent normalized activity events for the user's workspace (M66.2).

    Strictly workspace-scoped — never returns another workspace's events. Safe,
    metadata-only fields; control-plane activity, not incident detection.
    """
    workspace_id = _current_workspace_id(current_user, db)
    items, total = security_activity_event_service.list_activity_events(
        workspace_id=workspace_id,
        db=db,
        provider=provider,
        event_type=event_type,
        page=page,
        page_size=page_size,
    )
    return SecurityActivityEventListResponse(
        items=[SecurityActivityEventResponse.from_model(ev) for ev in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/activity/events/{event_id}", response_model=SecurityActivityEventResponse
)
def get_security_activity_event(
    event_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityActivityEventResponse:
    """Return a single workspace-scoped normalized activity event (M66.5).

    Authenticated member access. Cross-workspace access returns 404 (never leaks
    existence). Safe, metadata-only fields; control-plane activity, not detection.
    """
    workspace_id = _current_workspace_id(current_user, db)
    ev = security_activity_event_service.get_activity_event(
        event_id=event_id, workspace_id=workspace_id, db=db
    )
    if ev is None:
        raise HTTPException(status_code=404, detail="Activity event not found.")
    return SecurityActivityEventResponse.from_model(ev)


# ── Incident Signals (M66.3) ──────────────────────────────────────────────────
#
# First control-plane Incident Signal layer, generated from normalized GitHub
# audit activity (M66.2). Signals are REVIEW signals — they do NOT confirm a
# breach, identify an attacker, or confirm compromise/access. Severity reflects
# review priority; evidence_level is "activity". Exposure×activity correlation is
# a later milestone.

VALID_SIGNAL_STATUSES = {"open", "acknowledged", "dismissed", "resolved"}
VALID_SIGNAL_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@router.post("/signals/generate", response_model=SecuritySignalGenerateResponse)
def generate_security_signals(
    body: Optional[SecuritySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecuritySignalGenerateResponse:
    """Generate incident signals from recent activity events (M66.3).

    Admin/owner only. GitHub-only for now; an unsupported provider yields an empty
    summary (no error). Idempotent — re-running creates no duplicates.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    provider = (body.provider if body and body.provider else "github").lower()
    if provider != "github":
        # Only GitHub signal rules exist this milestone — return an empty summary.
        return SecuritySignalGenerateResponse(
            provider=provider,
            activity_events_scanned=0,
            signals_created=0,
            signals_skipped=0,
        )

    summary = security_incident_signal_service.generate_github_incident_signals(
        workspace_id=workspace_id, db=db
    )
    return SecuritySignalGenerateResponse(**summary)


@router.get("/signals", response_model=SecurityIncidentSignalListResponse)
def list_security_signals(
    provider: Optional[str] = Query(None, description="Filter by provider."),
    status: Optional[str] = Query(None, description="Filter by status."),
    severity: Optional[str] = Query(None, description="Filter by severity."),
    signal_type: Optional[str] = Query(None, description="Filter by signal_type."),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityIncidentSignalListResponse:
    """List incident signals for the user's workspace (M66.3).

    Authenticated member access. Strictly workspace-scoped — never returns another
    workspace's signals.
    """
    if status is not None and status not in VALID_SIGNAL_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status: {status!r}")
    if severity is not None and severity not in VALID_SIGNAL_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"Invalid severity: {severity!r}")

    workspace_id = _current_workspace_id(current_user, db)
    items, total = security_incident_signal_service.list_incident_signals(
        workspace_id=workspace_id,
        db=db,
        provider=provider,
        status=status,
        severity=severity,
        signal_type=signal_type,
        page=page,
        page_size=page_size,
    )
    return SecurityIncidentSignalListResponse(
        items=[SecurityIncidentSignalResponse.from_model(s) for s in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/signals/{signal_id}", response_model=SecurityIncidentSignalResponse)
def get_security_signal(
    signal_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityIncidentSignalResponse:
    """Return a single workspace-scoped incident signal (M66.3).

    Cross-workspace access returns 404 (never leaks existence).
    """
    workspace_id = _current_workspace_id(current_user, db)
    signal = security_incident_signal_service.get_incident_signal(
        signal_id=signal_id, workspace_id=workspace_id, db=db
    )
    if signal is None:
        raise HTTPException(status_code=404, detail="Incident signal not found.")
    return SecurityIncidentSignalResponse.from_model(signal)


# ── Correlations (M66.6) ──────────────────────────────────────────────────────
#
# Configuration Risk × audit-activity correlation — the core differentiator. A
# correlation links a GitHub Configuration Risk finding to GitHub audit activity
# on the same repository within a review window. Correlations are EVIDENCE FOR
# REVIEW — they do NOT confirm a breach, attacker, compromise, or unauthorized
# access.


@router.post("/correlations/generate", response_model=SecurityCorrelationGenerateResponse)
def generate_security_correlations(
    body: Optional[SecurityCorrelationGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCorrelationGenerateResponse:
    """Generate risk×activity correlations. Admin/owner.

    M66.6 (github): Configuration Risk × GitHub audit activity.
    M67.3 (aws): AWS Configuration Risk × AWS provider alerts (GuardDuty /
    Access Analyzer), matched on the SAME bucket / IAM principal name.

    Idempotent — re-running creates no duplicates. An unsupported provider yields
    an empty summary.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    provider = (body.provider if body and body.provider else "github").lower()
    if provider == "github":
        summary = security_signal_correlation_service.generate_github_correlations(
            workspace_id=workspace_id, db=db
        )
    elif provider == "aws":
        summary = security_signal_correlation_service.generate_aws_correlations(
            workspace_id=workspace_id, db=db
        )
    else:
        return SecurityCorrelationGenerateResponse(provider=provider)

    return SecurityCorrelationGenerateResponse(**summary)


@router.get("/correlations", response_model=SecuritySignalCorrelationListResponse)
def list_security_correlations(
    provider: Optional[str] = Query(None, description="Filter by provider."),
    status: Optional[str] = Query(None, description="Filter by status."),
    severity: Optional[str] = Query(None, description="Filter by severity."),
    correlation_type: Optional[str] = Query(None, description="Filter by correlation_type."),
    linked_signal_id: Optional[UUID4] = Query(
        None, description="Only correlations linked to this incident signal (M66.7)."
    ),
    linked_finding_id: Optional[UUID4] = Query(
        None, description="Only correlations linked to this configuration risk (M66.7)."
    ),
    linked_activity_event_id: Optional[UUID4] = Query(
        None, description="Only correlations linked to this activity event (M66.7)."
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecuritySignalCorrelationListResponse:
    """List correlations for the user's workspace (M66.6/M66.7). Member access.

    Strictly workspace-scoped — never returns another workspace's correlations,
    even when a ``linked_*`` filter references another workspace's object.
    """
    if status is not None and status not in VALID_SIGNAL_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status: {status!r}")
    if severity is not None and severity not in VALID_SIGNAL_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"Invalid severity: {severity!r}")

    workspace_id = _current_workspace_id(current_user, db)
    items, total = security_signal_correlation_service.list_correlations(
        workspace_id=workspace_id,
        db=db,
        provider=provider,
        status=status,
        severity=severity,
        correlation_type=correlation_type,
        linked_signal_id=linked_signal_id,
        linked_finding_id=linked_finding_id,
        linked_activity_event_id=linked_activity_event_id,
        page=page,
        page_size=page_size,
    )
    return SecuritySignalCorrelationListResponse(
        items=[SecuritySignalCorrelationResponse.from_model(c) for c in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/correlations/{correlation_id}",
    response_model=SecuritySignalCorrelationResponse,
)
def get_security_correlation(
    correlation_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecuritySignalCorrelationResponse:
    """Return a single workspace-scoped correlation (M66.6).

    Cross-workspace access returns 404 (never leaks existence).
    """
    workspace_id = _current_workspace_id(current_user, db)
    corr = security_signal_correlation_service.get_correlation(
        correlation_id=correlation_id, workspace_id=workspace_id, db=db
    )
    if corr is None:
        raise HTTPException(status_code=404, detail="Correlation not found.")
    return SecuritySignalCorrelationResponse.from_model(corr)


# ── Cases / Investigations (M66.8) ────────────────────────────────────────────
#
# A case is a HUMAN-MANAGED investigation container grouping incident evidence
# (signals, correlations, configuration risks, activity events). ConfigTrace does
# NOT automatically confirm breaches/attackers/compromise — confirmation and
# dismissal are human actions. ``confirmed_by_user`` requires admin/owner.


def _case_or_404(case_id, current_user, db):
    workspace_id = _current_workspace_id(current_user, db)
    case = security_case_service.get_case(
        case_id=case_id, workspace_id=workspace_id, db=db
    )
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return workspace_id, case


@router.post("/cases", response_model=SecurityCaseResponse, status_code=201)
def create_security_case(
    body: SecurityCaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCaseResponse:
    """Create an investigation case (M66.8). Any workspace member may create one."""
    workspace_id = _current_workspace_id(current_user, db)
    try:
        case = security_case_service.create_case(
            workspace_id=workspace_id, user_id=current_user.id,
            title=body.title, summary=body.summary, severity=body.severity,
            provider=body.provider, db=db,
        )
    except security_case_service.CaseValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return SecurityCaseResponse.from_model(case, link_count=0)


@router.get("/cases", response_model=SecurityCaseListResponse)
def list_security_cases(
    status: Optional[str] = Query(None, description="Filter by status."),
    provider: Optional[str] = Query(None, description="Filter by provider."),
    severity: Optional[str] = Query(None, description="Filter by severity."),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCaseListResponse:
    """List investigation cases for the user's workspace (M66.8). Member access."""
    workspace_id = _current_workspace_id(current_user, db)
    items, total = security_case_service.list_cases(
        workspace_id=workspace_id, db=db, status=status, provider=provider,
        severity=severity, page=page, page_size=page_size,
    )
    return SecurityCaseListResponse(
        items=[
            SecurityCaseResponse.from_model(
                c, link_count=security_case_service.count_links(c.id, db)
            )
            for c in items
        ],
        total=total, page=page, page_size=page_size,
    )


@router.get("/cases/{case_id}", response_model=SecurityCaseDetailResponse)
def get_security_case(
    case_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCaseDetailResponse:
    """Return a case + its links (M66.8). 404 cross-workspace."""
    _ws, case = _case_or_404(case_id, current_user, db)
    links = security_case_service.list_case_links(case_id=case.id, db=db)
    return SecurityCaseDetailResponse(
        case=SecurityCaseResponse.from_model(case, link_count=len(links)),
        links=[SecurityCaseLinkResponse.from_model(ln) for ln in links],
    )


@router.patch("/cases/{case_id}", response_model=SecurityCaseResponse)
def update_security_case(
    case_id: UUID4,
    body: SecurityCaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCaseResponse:
    """Update case fields / lifecycle (M66.8).

    Members may edit title/summary/severity/confidence and move a case to
    investigating / dismissed / resolved. Marking a case ``confirmed_by_user``
    requires admin/owner — confirmation is a higher-trust human action.
    """
    workspace_id, case = _case_or_404(case_id, current_user, db)
    if body.status == "confirmed_by_user":
        workspace_permission_service.require_workspace_admin(
            workspace_id, current_user.id, db
        )
    try:
        updated = security_case_service.update_case(
            case=case, actor_user_id=current_user.id, db=db,
            title=body.title, summary=body.summary, severity=body.severity,
            confidence=body.confidence, status=body.status,
        )
    except security_case_service.CaseValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return SecurityCaseResponse.from_model(
        updated, link_count=security_case_service.count_links(updated.id, db)
    )


@router.get("/cases/{case_id}/links", response_model=SecurityCaseLinkListResponse)
def list_security_case_links(
    case_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCaseLinkListResponse:
    """List the evidence links attached to a case (M66.8)."""
    _ws, case = _case_or_404(case_id, current_user, db)
    links = security_case_service.list_case_links(case_id=case.id, db=db)
    return SecurityCaseLinkListResponse(
        items=[SecurityCaseLinkResponse.from_model(ln) for ln in links],
        total=len(links),
    )


@router.post("/cases/{case_id}/links", response_model=SecurityCaseLinkResponse, status_code=201)
def add_security_case_link(
    case_id: UUID4,
    body: SecurityCaseLinkCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCaseLinkResponse:
    """Attach an evidence object to a case (M66.8). Cross-workspace objects → 404."""
    _ws, case = _case_or_404(case_id, current_user, db)
    try:
        object_id = uuid.UUID(str(body.linked_object_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=422, detail="Invalid linked_object_id.")
    try:
        _outcome, link = security_case_service.link_object_to_case(
            case=case, object_type=body.linked_object_type, object_id=object_id,
            actor_user_id=current_user.id, db=db,
        )
    except security_case_service.CaseValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except security_case_service.CrossWorkspaceLinkError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return SecurityCaseLinkResponse.from_model(link)


@router.delete("/cases/{case_id}/links/{link_id}")
def delete_security_case_link(
    case_id: UUID4,
    link_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Detach an evidence object from a case (M66.8)."""
    _ws, case = _case_or_404(case_id, current_user, db)
    removed = security_case_service.unlink_object_from_case(
        case=case, link_id=link_id, db=db
    )
    if not removed:
        raise HTTPException(status_code=404, detail="Case link not found.")
    return {"ok": True}


@router.post("/signals/{signal_id}/create-case", response_model=SecurityCaseResponse, status_code=201)
def create_case_from_signal_endpoint(
    signal_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCaseResponse:
    """Create a case from an incident signal, linking its evidence (M66.8)."""
    workspace_id = _current_workspace_id(current_user, db)
    signal = security_incident_signal_service.get_incident_signal(
        signal_id=signal_id, workspace_id=workspace_id, db=db
    )
    if signal is None:
        raise HTTPException(status_code=404, detail="Incident signal not found.")
    case = security_case_service.create_case_from_signal(
        workspace_id=workspace_id, user_id=current_user.id, signal=signal, db=db
    )
    return SecurityCaseResponse.from_model(
        case, link_count=security_case_service.count_links(case.id, db)
    )


@router.post("/correlations/{correlation_id}/create-case", response_model=SecurityCaseResponse, status_code=201)
def create_case_from_correlation_endpoint(
    correlation_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCaseResponse:
    """Create a case from a correlation, linking risk/activity/signal (M66.8)."""
    workspace_id = _current_workspace_id(current_user, db)
    corr = security_signal_correlation_service.get_correlation(
        correlation_id=correlation_id, workspace_id=workspace_id, db=db
    )
    if corr is None:
        raise HTTPException(status_code=404, detail="Correlation not found.")
    case = security_case_service.create_case_from_correlation(
        workspace_id=workspace_id, user_id=current_user.id, correlation=corr, db=db
    )
    return SecurityCaseResponse.from_model(
        case, link_count=security_case_service.count_links(case.id, db)
    )


@router.get("/cases/{case_id}/report", response_model=SecurityCaseReportResponse)
def get_security_case_report(
    case_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCaseReportResponse:
    """Return a metadata-only Case Evidence Report (M66.9). Member; 404 cross-ws.

    Structured packet (not a file) — the frontend formats it as Markdown/JSON.
    Only allowlisted safe fields are emitted; no raw payloads/IPs/secrets/tokens.
    """
    _ws, case = _case_or_404(case_id, current_user, db)
    report = security_case_report_service.build_case_report(case=case, db=db)
    return SecurityCaseReportResponse(**report)


# ── GitHub Incident Workflow demo (M66.10) ────────────────────────────────────
#
# Seeds/clears a clearly-labelled, demo-only end-to-end chain (configuration risk
# → activity event → incident signal → correlation → case) so the workflow is
# easy to demo. Demo data never notifies, never syncs real providers, and never
# touches real findings. Seed/clear are admin/owner only.


@router.get("/incident-demo/status", response_model=IncidentDemoStatusResponse)
def incident_demo_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentDemoStatusResponse:
    """Whether the GitHub incident-workflow demo is seeded (M66.10)."""
    workspace_id = _current_workspace_id(current_user, db)
    return IncidentDemoStatusResponse(
        **security_incident_demo_service.get_status(workspace_id, db)
    )


@router.post("/incident-demo/seed", response_model=IncidentDemoSeedResponse)
def incident_demo_seed(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentDemoSeedResponse:
    """Seed the GitHub incident-workflow demo chain (M66.10). Admin/owner only."""
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    summary = security_incident_demo_service.seed(
        workspace_id=workspace_id, actor_user_id=current_user.id, db=db
    )
    return IncidentDemoSeedResponse(**summary)


@router.post("/incident-demo/clear", response_model=IncidentDemoClearResponse)
def incident_demo_clear(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentDemoClearResponse:
    """Remove the GitHub incident-workflow demo chain (M66.10). Admin/owner only."""
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    return IncidentDemoClearResponse(
        **security_incident_demo_service.clear(workspace_id=workspace_id, db=db)
    )


# ── AWS security alerts (M67.1) ───────────────────────────────────────────────
#
# Ingests provider-ADJUDICATED AWS security findings (GuardDuty / Access Analyzer)
# into activity events, and generates AWS Incident Signals from them. This
# surfaces provider-reported findings as evidence for review — it does NOT confirm
# a breach, attacker, or unauthorized access. AWS-specific endpoints (rather than
# extending the GitHub-coupled /activity/sync + /signals/generate) keep each
# provider's ingestion/generation independent and testable.


@router.post("/aws-alerts/sync", response_model=AwsAlertSyncResponse)
def sync_aws_security_alerts(
    body: Optional[AwsAlertSyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AwsAlertSyncResponse:
    """Ingest GuardDuty/Access Analyzer findings for an AWS integration (M67.1).

    Admin/owner only. Non-fatal: permission/availability limits are reported in
    the summary, never raised.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "aws",
    )
    requested_id = body.integration_id if body else None
    if requested_id:
        try:
            iid = uuid.UUID(str(requested_id))
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(status_code=422, detail="Invalid integration_id.")
        integration = q.filter(Integration.id == iid).first()
        if integration is None:
            raise HTTPException(status_code=404, detail="AWS integration not found.")
    else:
        integration = (
            q.filter(Integration.status == "active")
            .order_by(Integration.created_at.asc())
            .first()
        )
        if integration is None:
            return AwsAlertSyncResponse(
                attempted=False, succeeded=False, provider="aws",
                source="security_alert",
                error_message="No active AWS integration found.",
            )

    summary = aws_security_alert_ingestion_service.ingest_aws_security_alerts(
        integration=integration, workspace_id=workspace_id, db=db
    )
    return AwsAlertSyncResponse(**summary)


@router.post("/aws-alerts/generate-signals", response_model=AwsSignalGenerateResponse)
def generate_aws_security_signals(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AwsSignalGenerateResponse:
    """Generate AWS Incident Signals from AWS security-alert events (M67.1).

    Admin/owner only. Idempotent — re-running creates no duplicates.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    summary = security_incident_signal_service.generate_aws_incident_signals(
        workspace_id=workspace_id, db=db
    )
    return AwsSignalGenerateResponse(**summary)
