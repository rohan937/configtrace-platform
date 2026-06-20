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
from typing import Any, Optional

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
from app.services import provider_capability_matrix_service as capability_svc
from app.services import provider_expansion_framework as expansion_svc
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
    GitHubSecretScanningSyncRequest,
    GitHubSecretScanningSyncResponse,
    GitHubSecretScanningSignalGenerateRequest,
    GitHubSecretScanningSignalGenerateResponse,
    GitHubCodeScanningSyncRequest,
    GitHubCodeScanningSyncResponse,
    GitHubCodeScanningSignalGenerateRequest,
    GitHubCodeScanningSignalGenerateResponse,
    GitHubDependabotSyncRequest,
    GitHubDependabotSyncResponse,
    GitHubDependabotSignalGenerateRequest,
    GitHubDependabotSignalGenerateResponse,
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
from app.schemas.security_case_report import (
    SecurityCaseGraphResponse,
    SecurityCaseReportResponse,
    SecurityCaseTimelineResponse,
)
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
from app.schemas.security_aws_cloudtrail import (
    AwsCloudTrailSyncRequest,
    AwsCloudTrailSyncResponse,
    AwsBehaviorSignalGenerateRequest,
    AwsBehaviorSignalGenerateResponse,
    AwsIamChainSignalGenerateRequest,
    AwsIamChainSignalGenerateResponse,
)
from app.schemas.security_aws_security_hub import (
    AwsSecurityHubSyncRequest,
    AwsSecurityHubSyncResponse,
    AwsSecurityHubSignalGenerateResponse,
)
from app.schemas.security_aws_s3_data_events import (
    AwsS3DataEventSyncRequest,
    AwsS3DataEventSyncResponse,
    AwsS3AccessSignalGenerateRequest,
    AwsS3AccessSignalGenerateResponse,
)
from app.schemas.security_aws_vpc_flow_logs import (
    AwsVpcFlowLogSyncRequest,
    AwsVpcFlowLogSyncResponse,
    AwsVpcFlowSignalGenerateRequest,
    AwsVpcFlowSignalGenerateResponse,
)
from app.schemas.security_cloudflare_activity import (
    CloudflareActivitySyncRequest,
    CloudflareActivitySyncResponse,
    CloudflareSignalGenerateResponse,
    CloudflareWafEventSyncRequest,
    CloudflareWafEventSyncResponse,
    CloudflareWafSignalGenerateRequest,
    CloudflareWafSignalGenerateResponse,
)
from app.schemas.security_vercel_activity import (
    VercelActivitySyncRequest,
    VercelActivitySyncResponse,
    VercelActivitySignalGenerateRequest,
    VercelActivitySignalGenerateResponse,
)
from app.schemas.security_firebase_activity import (
    FirebaseActivitySyncRequest,
    FirebaseActivitySyncResponse,
    FirebaseActivitySignalGenerateRequest,
    FirebaseActivitySignalGenerateResponse,
)
from app.schemas.security_supabase_activity import (
    SupabaseActivitySyncRequest,
    SupabaseActivitySyncResponse,
    SupabaseActivitySignalGenerateRequest,
    SupabaseActivitySignalGenerateResponse,
)
from app.schemas.security_stripe_activity import (
    StripeActivitySyncRequest,
    StripeActivitySyncResponse,
    StripeActivitySignalGenerateRequest,
    StripeActivitySignalGenerateResponse,
)
from app.schemas.security_shopify_activity import (
    ShopifyActivitySyncRequest,
    ShopifyActivitySyncResponse,
    ShopifyActivitySignalGenerateRequest,
    ShopifyActivitySignalGenerateResponse,
)
from app.schemas.security_azure_activity import (
    AzureActivitySyncRequest,
    AzureActivitySyncResponse,
    AzureActivitySignalGenerateRequest,
    AzureActivitySignalGenerateResponse,
)
from app.schemas.security_google_cloud_activity import (
    GoogleCloudActivitySyncRequest,
    GoogleCloudActivitySyncResponse,
    GoogleCloudActivitySignalGenerateRequest,
    GoogleCloudActivitySignalGenerateResponse,
)
from app.schemas.security_twilio_activity import (
    TwilioActivitySyncRequest,
    TwilioActivitySyncResponse,
    TwilioActivitySignalGenerateRequest,
    TwilioActivitySignalGenerateResponse,
    TwilioCorrelationGenerateRequest,
    TwilioCorrelationGenerateResponse,
)
from app.schemas.security_auth0_activity import (
    Auth0ActivitySyncRequest,
    Auth0ActivitySyncResponse,
    Auth0ActivitySignalGenerateRequest,
    Auth0ActivitySignalGenerateResponse,
    Auth0CorrelationGenerateRequest,
    Auth0CorrelationGenerateResponse,
)
from app.schemas.security_datadog_activity import (
    DatadogActivitySyncRequest,
    DatadogActivitySyncResponse,
    DatadogActivitySignalGenerateRequest,
    DatadogActivitySignalGenerateResponse,
    DatadogCorrelationGenerateRequest,
    DatadogCorrelationGenerateResponse,
)
from app.schemas.security_sendgrid_activity import (
    SendGridActivitySyncRequest,
    SendGridActivitySyncResponse,
    SendGridActivitySignalGenerateRequest,
    SendGridActivitySignalGenerateResponse,
    SendGridCorrelationGenerateRequest,
    SendGridCorrelationGenerateResponse,
)
from app.schemas.security_clerk_activity import (
    ClerkActivitySyncRequest,
    ClerkActivitySyncResponse,
    ClerkActivitySignalGenerateRequest,
    ClerkActivitySignalGenerateResponse,
    ClerkCorrelationGenerateRequest,
    ClerkCorrelationGenerateResponse,
)
from app.schemas.security_pagerduty_activity import (
    PagerDutyActivitySyncRequest,
    PagerDutyActivitySyncResponse,
    PagerDutyActivitySignalGenerateRequest,
    PagerDutyActivitySignalGenerateResponse,
    PagerDutyCorrelationGenerateRequest,
    PagerDutyCorrelationGenerateResponse,
)
from app.schemas.security_linear_activity import (
    LinearActivitySyncRequest,
    LinearActivitySyncResponse,
    LinearActivitySignalGenerateRequest,
    LinearActivitySignalGenerateResponse,
    LinearCorrelationGenerateRequest,
    LinearCorrelationGenerateResponse,
)
from app.schemas.security_jira_activity import (
    JiraActivitySyncRequest,
    JiraActivitySyncResponse,
    JiraActivitySignalGenerateRequest,
    JiraActivitySignalGenerateResponse,
)
from app.services import clerk_activity_ingestion_service
from app.services import clerk_activity_signal_service
from app.services import pagerduty_activity_ingestion_service
from app.services import pagerduty_activity_signal_service
from app.services import linear_activity_ingestion_service
from app.services import linear_activity_signal_service
from app.services import linear_risk_activity_correlation_service
from app.services import jira_activity_ingestion_service
from app.services import jira_activity_signal_service
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
from app.services import github_secret_scanning_ingestion_service
from app.services import github_secret_scanning_signal_service
from app.services import github_code_scanning_ingestion_service
from app.services import github_code_scanning_signal_service
from app.services import github_dependabot_ingestion_service
from app.services import github_dependabot_signal_service
from app.services import security_incident_signal_service
from app.services import security_signal_correlation_service
from app.services import security_case_service
from app.services import security_case_report_service
from app.services import security_incident_demo_service
from app.services import aws_security_alert_ingestion_service
from app.services import aws_cloudtrail_ingestion_service
from app.services import aws_iam_behavior_service
from app.services import aws_iam_chain_signal_service
from app.services import aws_security_hub_ingestion_service
from app.services import aws_s3_data_event_ingestion_service
from app.services import aws_s3_access_signal_service
from app.services import aws_vpc_flow_log_ingestion_service
from app.services import aws_vpc_flow_signal_service
from app.services import cloudflare_security_activity_ingestion_service
from app.services import cloudflare_waf_event_ingestion_service
from app.services import vercel_activity_ingestion_service
from app.services import vercel_activity_signal_service
from app.services import supabase_activity_ingestion_service
from app.services import firebase_activity_ingestion_service
from app.services import stripe_activity_ingestion_service
from app.services import stripe_activity_signal_service
from app.services import shopify_activity_ingestion_service
from app.services import shopify_activity_signal_service
from app.services import azure_activity_ingestion_service
from app.services import azure_activity_signal_service
from app.services import google_cloud_activity_ingestion_service
from app.services import google_cloud_activity_signal_service
from app.services import twilio_activity_ingestion_service
from app.services import auth0_activity_ingestion_service
from app.services import auth0_activity_signal_service
from app.services import datadog_activity_ingestion_service
from app.services import datadog_activity_signal_service
from app.services import sendgrid_activity_ingestion_service
from app.services import sendgrid_activity_signal_service
from app.services import twilio_activity_signal_service
from app.services import firebase_activity_signal_service
from app.services import supabase_activity_signal_service
from app.services import cloudflare_waf_signal_service
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


@router.get("/provider-capabilities")
def get_provider_capabilities(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return the canonical provider capability matrix (M75C).

    Read-only — any authenticated workspace member may call this. Returns
    which providers support drift monitoring, security rules, activity
    ingestion, incident signals, risk × activity correlations, demo
    seed/clear, case/report, evidence timeline, and evidence graph.

    This is static metadata only — it never evaluates live provider state,
    never calls external APIs, and never changes DB records.
    """
    _current_workspace_id(current_user, db)  # authenticate workspace membership
    return capability_svc.get_matrix()


@router.get("/provider-expansion-framework")
def get_provider_expansion_framework(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return the dual-stack provider expansion framework (M76).

    Read-only — any authenticated workspace member may call this. Returns
    the 6-stage provider expansion template, the recommended next-provider
    queue (starting with Twilio), and claim-discipline / privacy requirements
    every future provider must satisfy.

    This is static metadata only — it never evaluates live provider state,
    never calls external APIs, and never changes DB records.
    """
    _current_workspace_id(current_user, db)  # authenticate workspace membership
    return expansion_svc.get_framework()


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


@router.post(
    "/github-secret-scanning/sync",
    response_model=GitHubSecretScanningSyncResponse,
)
def sync_github_secret_scanning(
    body: Optional[GitHubSecretScanningSyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GitHubSecretScanningSyncResponse:
    """Ingest GitHub secret-scanning alerts for a workspace integration (M69.4A).

    Admin/owner only. Repo-scoped secret-scanning ALERT evidence. Non-fatal:
    GitHub Advanced Security disabled / missing scope / unavailable repo are
    reported as ``permission_limited``, never raised. Never stores raw secrets.
    Members can view the resulting events via
    ``GET /security/activity/events?provider=github``.
    """
    workspace_id = _current_workspace_id(current_user, db)
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
            return GitHubSecretScanningSyncResponse(
                attempted=False, succeeded=False, provider="github",
                source="secret_scanning_alert",
                error_message="No active GitHub integration found.",
            )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_alerts = min(body.max_alerts, 1000) if body and body.max_alerts else 1000
    summary = github_secret_scanning_ingestion_service.ingest_github_secret_scanning_alerts(
        integration=integration, workspace_id=workspace_id, db=db,
        lookback_hours=lookback_hours, max_alerts=max_alerts,
    )
    return GitHubSecretScanningSyncResponse(**summary)


@router.post(
    "/github-code-scanning/sync",
    response_model=GitHubCodeScanningSyncResponse,
)
def sync_github_code_scanning(
    body: Optional[GitHubCodeScanningSyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GitHubCodeScanningSyncResponse:
    """Ingest GitHub code-scanning alerts for a workspace integration (M69.4D).

    Admin/owner only. Repo-scoped code-scanning (SAST) ALERT evidence. Non-fatal:
    GitHub Advanced Security / code scanning disabled, missing scope, or an
    unavailable repo are reported as ``permission_limited``, never raised. Never
    stores raw SARIF, code snippets, file contents, or raw locations. Members can
    view the resulting events via ``GET /security/activity/events?provider=github``.
    """
    workspace_id = _current_workspace_id(current_user, db)
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
            return GitHubCodeScanningSyncResponse(
                attempted=False, succeeded=False, provider="github",
                source="code_scanning_alert",
                error_message="No active GitHub integration found.",
            )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_alerts = min(body.max_alerts, 1000) if body and body.max_alerts else 1000
    summary = github_code_scanning_ingestion_service.ingest_github_code_scanning_alerts(
        integration=integration, workspace_id=workspace_id, db=db,
        lookback_hours=lookback_hours, max_alerts=max_alerts,
    )
    return GitHubCodeScanningSyncResponse(**summary)


@router.post(
    "/github-dependabot/sync",
    response_model=GitHubDependabotSyncResponse,
)
def sync_github_dependabot(
    body: Optional[GitHubDependabotSyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GitHubDependabotSyncResponse:
    """Ingest GitHub Dependabot alerts for a workspace integration (M69.4G).

    Admin/owner only. Repo-scoped Dependabot (vulnerable-dependency) ALERT
    evidence. Non-fatal: Dependabot disabled, missing scope, or an unavailable
    repo are reported as ``permission_limited``, never raised. Never stores raw
    advisory bodies, raw manifest/file paths, or the raw dependency-graph
    response. Members can view the resulting events via
    ``GET /security/activity/events?provider=github``.
    """
    workspace_id = _current_workspace_id(current_user, db)
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
            return GitHubDependabotSyncResponse(
                attempted=False, succeeded=False, provider="github",
                source="dependabot_alert",
                error_message="No active GitHub integration found.",
            )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_alerts = min(body.max_alerts, 1000) if body and body.max_alerts else 1000
    summary = github_dependabot_ingestion_service.ingest_github_dependabot_alerts(
        integration=integration, workspace_id=workspace_id, db=db,
        lookback_hours=lookback_hours, max_alerts=max_alerts,
    )
    return GitHubDependabotSyncResponse(**summary)


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
    M68.2/68.3/68.6 (cloudflare): Configuration Risk × BOTH Cloudflare audit
    activity AND Cloudflare WAF/security-event activity, matched on the same
    zone + risk-area join key (host / sensitive path / setting).

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
    elif provider == "cloudflare":
        summary = security_signal_correlation_service.generate_cloudflare_correlations(
            workspace_id=workspace_id, db=db
        )
    elif provider == "vercel":
        summary = security_signal_correlation_service.generate_vercel_correlations(
            workspace_id=workspace_id, db=db
        )
    elif provider == "supabase":
        summary = security_signal_correlation_service.generate_supabase_correlations(
            workspace_id=workspace_id, db=db
        )
    elif provider == "firebase":
        summary = security_signal_correlation_service.generate_firebase_correlations(
            workspace_id=workspace_id, db=db
        )
    elif provider == "stripe":
        summary = security_signal_correlation_service.generate_stripe_correlations(
            workspace_id=workspace_id, db=db
        )
    elif provider == "shopify":
        summary = security_signal_correlation_service.generate_shopify_correlations(
            workspace_id=workspace_id, db=db
        )
    elif provider == "azure":
        summary = security_signal_correlation_service.generate_azure_correlations(
            workspace_id=workspace_id, db=db
        )
    elif provider == "google_cloud":
        summary = security_signal_correlation_service.generate_google_cloud_correlations(
            workspace_id=workspace_id, db=db
        )
    elif provider == "linear":
        summary = linear_risk_activity_correlation_service.generate_linear_correlations(
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


@router.get("/cases/{case_id}/timeline", response_model=SecurityCaseTimelineResponse)
def get_security_case_timeline(
    case_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCaseTimelineResponse:
    """Return a normalized chronological evidence timeline for a case (M69.7A).

    Member-readable; 404 cross-workspace. Joins the case's linked findings,
    activity events, incident signals, and correlations into a single ascending
    timeline for review. Metadata previews are scalar-allowlisted — no raw
    secrets/tokens/headers/payloads. This correlates evidence for review and does
    NOT confirm compromise or unauthorized access.
    """
    _ws, case = _case_or_404(case_id, current_user, db)
    timeline = security_case_report_service.build_case_evidence_timeline(
        case_id=case.id, workspace_id=case.workspace_id, db=db
    )
    return SecurityCaseTimelineResponse(**timeline)


@router.get("/cases/{case_id}/graph", response_model=SecurityCaseGraphResponse)
def get_security_case_graph(
    case_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityCaseGraphResponse:
    """Return a metadata-only evidence relationship graph for a case (M69.7B).

    Member-readable; 404 cross-workspace. Connects the case's linked findings,
    activity events, incident signals, and correlations using their explicit
    foreign keys only — no inferred attack paths. Node previews are
    scalar-allowlisted. This correlates evidence for review and does NOT confirm
    compromise or unauthorized access.
    """
    _ws, case = _case_or_404(case_id, current_user, db)
    graph = security_case_report_service.build_case_evidence_graph(
        case_id=case.id, workspace_id=case.workspace_id, db=db
    )
    return SecurityCaseGraphResponse(**graph)


# ── GitHub Incident Workflow demo (M66.10) ────────────────────────────────────
#
# Seeds/clears a clearly-labelled, demo-only end-to-end chain (configuration risk
# → activity event → incident signal → correlation → case) so the workflow is
# easy to demo. Demo data never notifies, never syncs real providers, and never
# touches real findings. Seed/clear are admin/owner only.


@router.get("/incident-demo/status", response_model=IncidentDemoStatusResponse)
def incident_demo_status(
    provider: str = "github",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentDemoStatusResponse:
    """Whether the incident-workflow demo is seeded.

    M66.10 github / M67.4 aws / M68.7 cloudflare.
    """
    workspace_id = _current_workspace_id(current_user, db)
    prov = (provider or "github").lower()
    if prov == "aws":
        status = security_incident_demo_service.get_aws_status(workspace_id, db)
    elif prov == "cloudflare":
        status = security_incident_demo_service.get_cloudflare_status(workspace_id, db)
    elif prov == "vercel":
        status = security_incident_demo_service.get_vercel_status(workspace_id, db)
    elif prov == "supabase":
        status = security_incident_demo_service.get_supabase_status(workspace_id, db)
    elif prov == "firebase":
        status = security_incident_demo_service.get_firebase_status(workspace_id, db)
    elif prov == "stripe":
        status = security_incident_demo_service.get_stripe_status(workspace_id, db)
    elif prov == "shopify":
        status = security_incident_demo_service.get_shopify_status(workspace_id, db)
    elif prov == "azure":
        status = security_incident_demo_service.get_azure_status(workspace_id, db)
    elif prov == "google_cloud":
        status = security_incident_demo_service.get_google_cloud_status(workspace_id, db)
    elif prov == "twilio":
        status = security_incident_demo_service.get_twilio_status(workspace_id, db)
    elif prov == "sendgrid":
        status = security_incident_demo_service.get_sendgrid_status(workspace_id, db)
    elif prov == "auth0":
        status = security_incident_demo_service.get_auth0_status(workspace_id, db)
    elif prov == "datadog":
        status = security_incident_demo_service.get_datadog_status(workspace_id, db)
    elif prov == "clerk":
        status = security_incident_demo_service.get_clerk_status(workspace_id, db)
    elif prov == "pagerduty":
        status = security_incident_demo_service.get_pagerduty_status(workspace_id, db)
    elif prov == "linear":
        status = security_incident_demo_service.get_linear_status(workspace_id, db)
    else:
        status = security_incident_demo_service.get_status(workspace_id, db)
    return IncidentDemoStatusResponse(**status)


@router.post("/incident-demo/seed", response_model=IncidentDemoSeedResponse)
def incident_demo_seed(
    provider: str = "github",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentDemoSeedResponse:
    """Seed the incident-workflow demo chain. Admin/owner only.

    provider=github (M66.10): Configuration Risk × GitHub audit activity.
    provider=aws (M67.4): S3 public-policy risk × Access Analyzer provider alert.
    provider=cloudflare (M68.7): WAF-rule-disabled risk × Cloudflare audit +
    WAF/security activity.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    prov = (provider or "github").lower()
    if prov == "aws":
        summary = security_incident_demo_service.seed_aws(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "cloudflare":
        summary = security_incident_demo_service.seed_cloudflare(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "vercel":
        summary = security_incident_demo_service.seed_vercel(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "supabase":
        summary = security_incident_demo_service.seed_supabase(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "firebase":
        summary = security_incident_demo_service.seed_firebase(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "stripe":
        summary = security_incident_demo_service.seed_stripe(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "shopify":
        summary = security_incident_demo_service.seed_shopify(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "azure":
        summary = security_incident_demo_service.seed_azure(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "google_cloud":
        summary = security_incident_demo_service.seed_google_cloud(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "twilio":
        summary = security_incident_demo_service.seed_twilio(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "sendgrid":
        summary = security_incident_demo_service.seed_sendgrid(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "auth0":
        summary = security_incident_demo_service.seed_auth0(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "datadog":
        summary = security_incident_demo_service.seed_datadog(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "clerk":
        summary = security_incident_demo_service.seed_clerk(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "pagerduty":
        summary = security_incident_demo_service.seed_pagerduty(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    elif prov == "linear":
        summary = security_incident_demo_service.seed_linear(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    else:
        summary = security_incident_demo_service.seed(
            workspace_id=workspace_id, actor_user_id=current_user.id, db=db
        )
    return IncidentDemoSeedResponse(**summary)


@router.post("/incident-demo/clear", response_model=IncidentDemoClearResponse)
def incident_demo_clear(
    provider: str = "github",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentDemoClearResponse:
    """Remove the incident-workflow demo chain. Admin/owner only.

    Scoped per provider — clearing one provider's demo removes only that
    provider's demo objects (github / aws / cloudflare are isolated).
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    prov = (provider or "github").lower()
    if prov == "aws":
        result = security_incident_demo_service.clear_aws(workspace_id=workspace_id, db=db)
    elif prov == "cloudflare":
        result = security_incident_demo_service.clear_cloudflare(workspace_id=workspace_id, db=db)
    elif prov == "vercel":
        result = security_incident_demo_service.clear_vercel(workspace_id=workspace_id, db=db)
    elif prov == "supabase":
        result = security_incident_demo_service.clear_supabase(workspace_id=workspace_id, db=db)
    elif prov == "firebase":
        result = security_incident_demo_service.clear_firebase(workspace_id=workspace_id, db=db)
    elif prov == "stripe":
        result = security_incident_demo_service.clear_stripe(workspace_id=workspace_id, db=db)
    elif prov == "shopify":
        result = security_incident_demo_service.clear_shopify(workspace_id=workspace_id, db=db)
    elif prov == "azure":
        result = security_incident_demo_service.clear_azure(workspace_id=workspace_id, db=db)
    elif prov == "google_cloud":
        result = security_incident_demo_service.clear_google_cloud(workspace_id=workspace_id, db=db)
    elif prov == "twilio":
        result = security_incident_demo_service.clear_twilio(workspace_id=workspace_id, db=db)
    elif prov == "sendgrid":
        result = security_incident_demo_service.clear_sendgrid(workspace_id=workspace_id, db=db)
    elif prov == "auth0":
        result = security_incident_demo_service.clear_auth0(workspace_id=workspace_id, db=db)
    elif prov == "datadog":
        result = security_incident_demo_service.clear_datadog(workspace_id=workspace_id, db=db)
    elif prov == "clerk":
        result = security_incident_demo_service.clear_clerk(workspace_id=workspace_id, db=db)
    elif prov == "pagerduty":
        result = security_incident_demo_service.clear_pagerduty(workspace_id=workspace_id, db=db)
    elif prov == "linear":
        result = security_incident_demo_service.clear_linear(workspace_id=workspace_id, db=db)
    else:
        result = security_incident_demo_service.clear(workspace_id=workspace_id, db=db)
    return IncidentDemoClearResponse(**result)


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


@router.post("/aws-cloudtrail/sync", response_model=AwsCloudTrailSyncResponse)
def sync_aws_cloudtrail_events(
    body: Optional[AwsCloudTrailSyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AwsCloudTrailSyncResponse:
    """Ingest CloudTrail management events for an AWS integration (M67.5).

    Admin/owner only. Non-fatal: permission/availability limits are reported in
    the summary, never raised. Members can view the resulting events via
    ``GET /security/activity/events?provider=aws``.
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
            return AwsCloudTrailSyncResponse(
                attempted=False, succeeded=False, provider="aws",
                source="cloudtrail",
                error_message="No active AWS integration found.",
            )

    # Bound the work regardless of what the client requested.
    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_pages = min(body.max_pages, 10) if body and body.max_pages else 2

    summary = aws_cloudtrail_ingestion_service.ingest_aws_cloudtrail_events(
        integration=integration, workspace_id=workspace_id, db=db,
        lookback_hours=lookback_hours, max_pages=max_pages,
    )
    return AwsCloudTrailSyncResponse(**summary)


@router.post(
    "/aws-cloudtrail/generate-behavior-signals",
    response_model=AwsBehaviorSignalGenerateResponse,
)
def generate_aws_iam_behavior_signals(
    body: Optional[AwsBehaviorSignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AwsBehaviorSignalGenerateResponse:
    """Generate IAM behavior-timeline signals from CloudTrail activity (M67.6).

    Admin/owner only. Groups CloudTrail IAM/KMS/S3 management events by principal
    and surfaces review-worthy behavior chains as Incident Signals. Idempotent —
    re-running creates no duplicates. Members can view the resulting signals via
    ``GET /security/signals?provider=aws``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 72
    max_signals = min(body.max_signals, 1000) if body and body.max_signals else 200

    summary = aws_iam_behavior_service.generate_aws_iam_behavior_signals(
        workspace_id=workspace_id, db=db,
        lookback_hours=lookback_hours, max_signals=max_signals,
    )
    return AwsBehaviorSignalGenerateResponse(**summary)


@router.post(
    "/aws-iam-chains/generate-signals",
    response_model=AwsIamChainSignalGenerateResponse,
)
def generate_aws_iam_chain_signals(
    body: Optional[AwsIamChainSignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AwsIamChainSignalGenerateResponse:
    """Generate AWS IAM privilege-chain signals from CloudTrail activity (M69.3A).

    Admin/owner only. Detects ordered IAM privilege-escalation sequences (user/role
    creation followed by policy grants, policy grants followed by access-key
    creation) targeting the SAME IAM entity within a configurable chain window.
    Idempotent — re-running creates no duplicates. These are review signals; they
    do not confirm compromise or unauthorized access.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
        if body.chain_window_minutes is not None:
            kwargs["chain_window_minutes"] = body.chain_window_minutes
    summary = aws_iam_chain_signal_service.generate_aws_iam_chain_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return AwsIamChainSignalGenerateResponse(**summary)


@router.post("/aws-security-hub/sync", response_model=AwsSecurityHubSyncResponse)
def sync_aws_security_hub(
    body: Optional[AwsSecurityHubSyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AwsSecurityHubSyncResponse:
    """Ingest AWS Security Hub findings for an AWS integration (M67.7).

    Admin/owner only. Non-fatal: permission/availability limits are reported in
    the summary, never raised. Members can view the resulting events via
    ``GET /security/activity/events?provider=aws``.
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
            return AwsSecurityHubSyncResponse(
                attempted=False, succeeded=False, provider="aws",
                source="security_hub",
                error_message="No active AWS integration found.",
            )

    max_pages = min(body.max_pages, 5) if body and body.max_pages else 2

    summary = aws_security_hub_ingestion_service.ingest_aws_security_hub_findings(
        integration=integration, workspace_id=workspace_id, db=db, max_pages=max_pages
    )
    return AwsSecurityHubSyncResponse(**summary)


@router.post(
    "/aws-security-hub/generate-signals",
    response_model=AwsSecurityHubSignalGenerateResponse,
)
def generate_aws_security_hub_signals(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AwsSecurityHubSignalGenerateResponse:
    """Generate AWS Incident Signals from Security Hub findings (M67.7).

    Admin/owner only. Idempotent — re-running creates no duplicates.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    summary = security_incident_signal_service.generate_aws_security_hub_signals(
        workspace_id=workspace_id, db=db
    )
    return AwsSecurityHubSignalGenerateResponse(**summary)


@router.post("/aws-s3-data-events/sync", response_model=AwsS3DataEventSyncResponse)
def sync_aws_s3_data_events(
    body: AwsS3DataEventSyncRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AwsS3DataEventSyncResponse:
    """Ingest S3 object-level data events from bounded CloudTrail trail logs (M67.8).

    Admin/owner only. ``trail_bucket`` is required — CloudTrail S3 data events are
    only available from a configured trail's delivery bucket. Non-fatal:
    permission/availability limits are reported in the summary, never raised.
    Members can view the resulting events via
    ``GET /security/activity/events?provider=aws``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "aws",
    )
    requested_id = body.integration_id
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
            return AwsS3DataEventSyncResponse(
                attempted=False, succeeded=False, provider="aws",
                source="s3_data_event",
                error_message="No active AWS integration found.",
            )

    max_files = min(body.max_files, 200) if body.max_files else 20
    max_events = min(body.max_events, 20000) if body.max_events else 1000

    summary = aws_s3_data_event_ingestion_service.ingest_aws_s3_data_events(
        integration=integration, workspace_id=workspace_id, db=db,
        trail_bucket=body.trail_bucket, trail_prefix=body.trail_prefix,
        max_files=max_files, max_events=max_events,
    )
    return AwsS3DataEventSyncResponse(**summary)


@router.post(
    "/aws-s3-data-events/generate-signals",
    response_model=AwsS3AccessSignalGenerateResponse,
)
def generate_aws_s3_access_signals(
    body: Optional[AwsS3AccessSignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AwsS3AccessSignalGenerateResponse:
    """Generate S3 object-access-spike signals from S3 data events (M67.9).

    Admin/owner only. Groups S3 object-level activity by principal + bucket and
    surfaces review-worthy access spikes as Incident Signals. Idempotent —
    re-running creates no duplicates. Members can view results via
    ``GET /security/signals?provider=aws``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_signals = min(body.max_signals, 1000) if body and body.max_signals else 200
    read_threshold = (
        min(body.read_threshold, 100000) if body and body.read_threshold
        else aws_s3_access_signal_service.DEFAULT_READ_THRESHOLD
    )

    summary = aws_s3_access_signal_service.generate_aws_s3_access_signals(
        workspace_id=workspace_id, db=db,
        lookback_hours=lookback_hours, max_signals=max_signals,
        read_threshold=read_threshold,
    )
    return AwsS3AccessSignalGenerateResponse(**summary)


@router.post("/aws-vpc-flow-logs/sync", response_model=AwsVpcFlowLogSyncResponse)
def sync_aws_vpc_flow_logs(
    body: AwsVpcFlowLogSyncRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AwsVpcFlowLogSyncResponse:
    """Ingest VPC Flow Logs from bounded S3 objects (M67.10).

    Admin/owner only. ``flow_log_bucket`` is required. Non-fatal: permission/
    availability limits are reported in the summary, never raised. Members can
    view the resulting events via ``GET /security/activity/events?provider=aws``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "aws",
    )
    requested_id = body.integration_id
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
            return AwsVpcFlowLogSyncResponse(
                attempted=False, succeeded=False, provider="aws",
                source="vpc_flow_log",
                error_message="No active AWS integration found.",
            )

    max_files = min(body.max_files, 200) if body.max_files else 20
    max_events = min(body.max_events, 50000) if body.max_events else 2000

    summary = aws_vpc_flow_log_ingestion_service.ingest_aws_vpc_flow_logs(
        integration=integration, workspace_id=workspace_id, db=db,
        flow_log_bucket=body.flow_log_bucket, flow_log_prefix=body.flow_log_prefix,
        max_files=max_files, max_events=max_events,
    )
    return AwsVpcFlowLogSyncResponse(**summary)


@router.post(
    "/aws-vpc-flow-logs/generate-signals",
    response_model=AwsVpcFlowSignalGenerateResponse,
)
def generate_aws_vpc_flow_signals(
    body: Optional[AwsVpcFlowSignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AwsVpcFlowSignalGenerateResponse:
    """Generate network-activity signals from VPC Flow Logs (M67.11).

    Admin/owner only. Groups VPC Flow Log activity by interface + destination port
    and surfaces review-worthy network patterns as Incident Signals. Idempotent —
    re-running creates no duplicates. Members can view results via
    ``GET /security/signals?provider=aws``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_signals = min(body.max_signals, 1000) if body and body.max_signals else 200
    kwargs: dict = {"lookback_hours": lookback_hours, "max_signals": max_signals}
    if body and body.rejected_threshold:
        kwargs["rejected_threshold"] = body.rejected_threshold
    if body and body.sensitive_port_threshold:
        kwargs["sensitive_port_threshold"] = body.sensitive_port_threshold
    if body and body.bytes_threshold:
        kwargs["bytes_threshold"] = body.bytes_threshold

    summary = aws_vpc_flow_signal_service.generate_aws_vpc_flow_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return AwsVpcFlowSignalGenerateResponse(**summary)


@router.post("/cloudflare-activity/sync", response_model=CloudflareActivitySyncResponse)
def sync_cloudflare_security_activity(
    body: Optional[CloudflareActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CloudflareActivitySyncResponse:
    """Ingest Cloudflare account audit activity (M68.1).

    Admin/owner only. Non-fatal: permission/availability limits are reported in
    the summary, never raised. Members can view the resulting events via
    ``GET /security/activity/events?provider=cloudflare``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "cloudflare",
    )
    requested_id = body.integration_id if body else None
    if requested_id:
        try:
            iid = uuid.UUID(str(requested_id))
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(status_code=422, detail="Invalid integration_id.")
        integration = q.filter(Integration.id == iid).first()
        if integration is None:
            raise HTTPException(status_code=404, detail="Cloudflare integration not found.")
    else:
        integration = (
            q.filter(Integration.status == "active")
            .order_by(Integration.created_at.asc())
            .first()
        )
        if integration is None:
            return CloudflareActivitySyncResponse(
                attempted=False, succeeded=False, provider="cloudflare",
                source="audit_log",
                error_message="No active Cloudflare integration found.",
            )

    max_events = min(body.max_events, 1000) if body and body.max_events else 100
    summary = cloudflare_security_activity_ingestion_service.ingest_cloudflare_security_activity(
        integration=integration, workspace_id=workspace_id, db=db, max_events=max_events
    )
    return CloudflareActivitySyncResponse(**summary)


@router.post("/vercel-activity/sync", response_model=VercelActivitySyncResponse)
def sync_vercel_activity(
    body: Optional[VercelActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> VercelActivitySyncResponse:
    """Ingest Vercel team audit activity (M70B).

    Admin/owner only. Non-fatal: permission/availability limits are reported in
    the summary, never raised — Vercel audit logs need a team id and audit-log
    read access (typically Enterprise). Members can view the resulting events via
    ``GET /security/activity/events?provider=vercel``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "vercel",
    )
    requested_id = body.integration_id if body else None
    if requested_id:
        try:
            iid = uuid.UUID(str(requested_id))
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(status_code=422, detail="Invalid integration_id.")
        integration = q.filter(Integration.id == iid).first()
        if integration is None:
            raise HTTPException(status_code=404, detail="Vercel integration not found.")
    else:
        integration = (
            q.filter(Integration.status == "active")
            .order_by(Integration.created_at.asc())
            .first()
        )
        if integration is None:
            return VercelActivitySyncResponse(
                attempted=False, succeeded=False, provider="vercel",
                source="audit_log",
                error_message="No active Vercel integration found.",
            )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100
    summary = vercel_activity_ingestion_service.ingest_vercel_activity(
        integration=integration, workspace_id=workspace_id, db=db,
        lookback_hours=lookback_hours, max_events=max_events,
    )
    return VercelActivitySyncResponse(**summary)


@router.post("/supabase-activity/sync", response_model=SupabaseActivitySyncResponse)
def sync_supabase_activity(
    body: Optional[SupabaseActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SupabaseActivitySyncResponse:
    """Ingest Supabase organization audit activity (M71B).

    Admin/owner only. Non-fatal: permission/availability limits are reported in
    the summary, never raised — Supabase audit logs need an organization slug and
    a token with audit-log read access (a project-scoped token alone cannot read
    them). Members can view the resulting events via
    ``GET /security/activity/events?provider=supabase``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "supabase",
    )
    requested_id = body.integration_id if body else None
    if requested_id:
        try:
            iid = uuid.UUID(str(requested_id))
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(status_code=422, detail="Invalid integration_id.")
        integration = q.filter(Integration.id == iid).first()
        if integration is None:
            raise HTTPException(status_code=404, detail="Supabase integration not found.")
    else:
        integration = (
            q.filter(Integration.status == "active")
            .order_by(Integration.created_at.asc())
            .first()
        )
        if integration is None:
            return SupabaseActivitySyncResponse(
                attempted=False, succeeded=False, provider="supabase",
                source="audit_log",
                error_message="No active Supabase integration found.",
            )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100
    summary = supabase_activity_ingestion_service.ingest_supabase_activity(
        integration=integration, workspace_id=workspace_id, db=db,
        lookback_hours=lookback_hours, max_events=max_events,
    )
    return SupabaseActivitySyncResponse(**summary)


@router.post("/firebase-activity/sync", response_model=FirebaseActivitySyncResponse)
def sync_firebase_activity(
    body: Optional[FirebaseActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FirebaseActivitySyncResponse:
    """Ingest Firebase / Google Cloud Audit Log activity (M72B).

    Admin/owner only. Non-fatal: permission/availability limits are reported in
    the summary, never raised — Firebase audit logs are read from Cloud Logging
    and need an IAM role with audit-log read access (the read-only config-sync
    service account commonly lacks it). Members can view the resulting events via
    ``GET /security/activity/events?provider=firebase``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "firebase",
    )
    requested_id = body.integration_id if body else None
    if requested_id:
        try:
            iid = uuid.UUID(str(requested_id))
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(status_code=422, detail="Invalid integration_id.")
        integration = q.filter(Integration.id == iid).first()
        if integration is None:
            raise HTTPException(status_code=404, detail="Firebase integration not found.")
    else:
        integration = (
            q.filter(Integration.status == "active")
            .order_by(Integration.created_at.asc())
            .first()
        )
        if integration is None:
            return FirebaseActivitySyncResponse(
                attempted=False, succeeded=False, provider="firebase",
                source="audit_log",
                error_message="No active Firebase integration found.",
            )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100
    summary = firebase_activity_ingestion_service.ingest_firebase_activity(
        integration=integration, workspace_id=workspace_id, db=db,
        lookback_hours=lookback_hours, max_events=max_events,
    )
    return FirebaseActivitySyncResponse(**summary)


@router.post("/stripe-activity/sync", response_model=StripeActivitySyncResponse)
def sync_stripe_activity(
    body: Optional[StripeActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> StripeActivitySyncResponse:
    """Ingest Stripe configuration-change activity from the Events API (M73B).

    Admin/owner only. Non-fatal: permission/availability limits are reported in
    the summary, never raised — Stripe Events API access requires the key to
    grant the Events permission (a restricted key without it cannot read them).
    Members can view the resulting events via
    ``GET /security/activity/events?provider=stripe``.

    Strict configuration-event allowlist applied at the API level: webhook
    endpoint, payment link, billing portal configuration, account, and
    capability events only. Customer / payment / charge / invoice / subscription
    lifecycle events are NEVER requested.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "stripe",
    )
    requested_id = body.integration_id if body else None
    if requested_id:
        try:
            iid = uuid.UUID(str(requested_id))
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(status_code=422, detail="Invalid integration_id.")
        integration = q.filter(Integration.id == iid).first()
        if integration is None:
            raise HTTPException(status_code=404, detail="Stripe integration not found.")
    else:
        integration = (
            q.filter(Integration.status == "active")
            .order_by(Integration.created_at.asc())
            .first()
        )
        if integration is None:
            return StripeActivitySyncResponse(
                attempted=False, succeeded=False, provider="stripe",
                source="stripe_events",
                error_message="No active Stripe integration found.",
            )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100
    summary = stripe_activity_ingestion_service.ingest_stripe_activity(
        integration=integration, workspace_id=workspace_id, db=db,
        lookback_hours=lookback_hours, max_events=max_events,
    )
    return StripeActivitySyncResponse(**summary)


@router.post("/shopify-activity/sync", response_model=ShopifyActivitySyncResponse)
def sync_shopify_activity(
    body: Optional[ShopifyActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ShopifyActivitySyncResponse:
    """Ingest Shopify configuration-change activity from the Events API (M74B).

    Admin/owner only. Non-fatal: permission/availability limits are reported in
    the summary, never raised — Shopify Events API access requires the Admin API
    token to grant the appropriate read scopes (a restricted token without them
    cannot read these events). Members can view the resulting events via
    ``GET /security/activity/events?provider=shopify``.

    Strict configuration-event allowlist applied at the API level via the
    Shopify ``filter`` parameter: ``Webhook``, ``Shop``, and ``Domain`` subject
    types only. Customer / order / checkout / cart / payment / fulfillment /
    refund / inventory / staff subject types are NEVER requested.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "shopify",
    )
    requested_id = body.integration_id if body else None
    if requested_id:
        try:
            iid = uuid.UUID(str(requested_id))
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(status_code=422, detail="Invalid integration_id.")
        integration = q.filter(Integration.id == iid).first()
        if integration is None:
            raise HTTPException(status_code=404, detail="Shopify integration not found.")
    else:
        integration = (
            q.filter(Integration.status == "active")
            .order_by(Integration.created_at.asc())
            .first()
        )
        if integration is None:
            return ShopifyActivitySyncResponse(
                attempted=False, succeeded=False, provider="shopify",
                source="shopify_events",
                error_message="No active Shopify integration found.",
            )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100
    summary = shopify_activity_ingestion_service.ingest_shopify_activity(
        integration=integration, workspace_id=workspace_id, db=db,
        lookback_hours=lookback_hours, max_events=max_events,
    )
    return ShopifyActivitySyncResponse(**summary)


@router.post(
    "/supabase-activity/generate-signals",
    response_model=SupabaseActivitySignalGenerateResponse,
)
def generate_supabase_activity_signals(
    body: Optional[SupabaseActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SupabaseActivitySignalGenerateResponse:
    """Generate Supabase activity Incident Signals (M71C).

    Admin/owner only. Promotes Supabase organization audit activity (table/RLS,
    policy, storage-bucket, Edge Function, auth-config, and project changes) into
    review-worthy signals. Idempotent — re-running creates no duplicates. These
    are review signals; they do not confirm data exposure, unauthorized access,
    or compromise. Members can view the resulting signals via
    ``GET /security/signals?provider=supabase``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = supabase_activity_signal_service.generate_supabase_activity_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return SupabaseActivitySignalGenerateResponse(**summary)


@router.post(
    "/firebase-activity/generate-signals",
    response_model=FirebaseActivitySignalGenerateResponse,
)
def generate_firebase_activity_signals(
    body: Optional[FirebaseActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FirebaseActivitySignalGenerateResponse:
    """Generate Firebase activity Incident Signals (M72C).

    Admin/owner only. Promotes Firebase audit activity (Firestore/Realtime
    Database/Storage rules, auth-config, Cloud Function, Hosting, and project/app
    changes) into review-worthy signals. Idempotent — re-running creates no
    duplicates. These are review signals; they do not confirm data exposure,
    unauthorized access, or compromise. Members can view the resulting signals via
    ``GET /security/signals?provider=firebase``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = firebase_activity_signal_service.generate_firebase_activity_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return FirebaseActivitySignalGenerateResponse(**summary)


@router.post(
    "/stripe-activity/generate-signals",
    response_model=StripeActivitySignalGenerateResponse,
)
def generate_stripe_activity_signals(
    body: Optional[StripeActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> StripeActivitySignalGenerateResponse:
    """Generate Stripe activity Incident Signals (M73C).

    Admin/owner only. Promotes Stripe configuration-change activity (webhook
    endpoint / payment link / customer portal / account / capability changes)
    into review-worthy signals. Idempotent — re-running creates no duplicates.
    These are review signals; they do not confirm fraud, compromise,
    unauthorized access, or data exposure. Members can view the resulting
    signals via ``GET /security/signals?provider=stripe``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = stripe_activity_signal_service.generate_stripe_activity_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return StripeActivitySignalGenerateResponse(**summary)


@router.post(
    "/shopify-activity/generate-signals",
    response_model=ShopifyActivitySignalGenerateResponse,
)
def generate_shopify_activity_signals(
    body: Optional[ShopifyActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ShopifyActivitySignalGenerateResponse:
    """Generate Shopify activity Incident Signals (M74C).

    Admin/owner only. Promotes Shopify configuration-change activity (webhook
    subscription / shop settings / shop-domain changes) into review-worthy
    signals. Idempotent — re-running creates no duplicates. These are review
    signals; they do not confirm fraud, compromise, unauthorized access, or
    customer-data / order / card-data exposure. Members can view the resulting
    signals via ``GET /security/signals?provider=shopify``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = shopify_activity_signal_service.generate_shopify_activity_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return ShopifyActivitySignalGenerateResponse(**summary)


@router.post(
    "/vercel-activity/generate-signals",
    response_model=VercelActivitySignalGenerateResponse,
)
def generate_vercel_activity_signals(
    body: Optional[VercelActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> VercelActivitySignalGenerateResponse:
    """Generate Vercel activity Incident Signals (M70C).

    Admin/owner only. Promotes Vercel team audit activity (project / domain /
    env-var / deploy-hook / deployment changes) into review-worthy signals.
    Idempotent — re-running creates no duplicates. These are review signals; they
    do not confirm unauthorized access or compromise. Members can view the
    resulting signals via ``GET /security/signals?provider=vercel``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = vercel_activity_signal_service.generate_vercel_activity_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return VercelActivitySignalGenerateResponse(**summary)


@router.post(
    "/cloudflare-activity/generate-signals",
    response_model=CloudflareSignalGenerateResponse,
)
def generate_cloudflare_signals(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CloudflareSignalGenerateResponse:
    """Generate Cloudflare Incident Signals from audit activity (M68.1).

    Admin/owner only. Idempotent — re-running creates no duplicates.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    summary = security_incident_signal_service.generate_cloudflare_signals(
        workspace_id=workspace_id, db=db
    )
    return CloudflareSignalGenerateResponse(**summary)


@router.post("/cloudflare-waf-events/sync", response_model=CloudflareWafEventSyncResponse)
def sync_cloudflare_waf_events(
    body: Optional[CloudflareWafEventSyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CloudflareWafEventSyncResponse:
    """Ingest Cloudflare WAF/security events (M68.4).

    Admin/owner only. Reads the GraphQL ``firewallEventsAdaptive`` dataset; non-
    fatal: missing GraphQL access / unsupported plan / ineligible zone are
    reported as ``permission_limited``, never raised. Members can view the
    resulting events via ``GET /security/activity/events?provider=cloudflare``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "cloudflare",
    )
    requested_id = body.integration_id if body else None
    if requested_id:
        try:
            iid = uuid.UUID(str(requested_id))
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(status_code=422, detail="Invalid integration_id.")
        integration = q.filter(Integration.id == iid).first()
        if integration is None:
            raise HTTPException(status_code=404, detail="Cloudflare integration not found.")
    else:
        integration = (
            q.filter(Integration.status == "active")
            .order_by(Integration.created_at.asc())
            .first()
        )
        if integration is None:
            return CloudflareWafEventSyncResponse(
                attempted=False, succeeded=False, provider="cloudflare",
                source="waf_security_event",
                error_message="No active Cloudflare integration found.",
            )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 200
    summary = cloudflare_waf_event_ingestion_service.ingest_cloudflare_waf_events(
        integration=integration, workspace_id=workspace_id, db=db,
        lookback_hours=lookback_hours, max_events=max_events,
    )
    return CloudflareWafEventSyncResponse(**summary)


@router.post(
    "/cloudflare-waf-events/generate-signals",
    response_model=CloudflareWafSignalGenerateResponse,
)
def generate_cloudflare_waf_signals(
    body: Optional[CloudflareWafSignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CloudflareWafSignalGenerateResponse:
    """Generate Cloudflare WAF/security-event Incident Signals (M68.5).

    Admin/owner only. Surfaces review-worthy WAF activity patterns (block /
    challenge bursts, sensitive-path activity, repeated-rule activity, skip/allow)
    as activity-level signals. Idempotent — re-running creates no duplicates.
    These are review signals; they do not confirm an attack, exploit, or
    unauthorized access.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
        if body.block_threshold is not None:
            kwargs["block_threshold"] = body.block_threshold
        if body.challenge_threshold is not None:
            kwargs["challenge_threshold"] = body.challenge_threshold
        if body.sensitive_path_threshold is not None:
            kwargs["sensitive_path_threshold"] = body.sensitive_path_threshold
        if body.rule_trigger_threshold is not None:
            kwargs["rule_trigger_threshold"] = body.rule_trigger_threshold
        if body.skip_allow_threshold is not None:
            kwargs["skip_allow_threshold"] = body.skip_allow_threshold
    summary = cloudflare_waf_signal_service.generate_cloudflare_waf_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return CloudflareWafSignalGenerateResponse(**summary)


@router.post(
    "/github-secret-scanning/generate-signals",
    response_model=GitHubSecretScanningSignalGenerateResponse,
)
def generate_github_secret_scanning_signals(
    body: Optional[GitHubSecretScanningSignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GitHubSecretScanningSignalGenerateResponse:
    """Generate GitHub secret-scanning alert Incident Signals (M69.4B).

    Admin/owner only. Surfaces review-worthy secret-scanning alert evidence
    (open / publicly-leaked / active-validity / resolved-or-revoked /
    non-actionable) as activity-level signals. Idempotent — re-running creates no
    duplicates. These are review signals; they do not confirm secret misuse,
    compromise, or unauthorized access.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = github_secret_scanning_signal_service.generate_github_secret_scanning_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return GitHubSecretScanningSignalGenerateResponse(**summary)


@router.post(
    "/github-code-scanning/generate-signals",
    response_model=GitHubCodeScanningSignalGenerateResponse,
)
def generate_github_code_scanning_signals(
    body: Optional[GitHubCodeScanningSignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GitHubCodeScanningSignalGenerateResponse:
    """Generate GitHub code-scanning alert Incident Signals (M69.4E).

    Admin/owner only. Surfaces review-worthy code-scanning (SAST) alert evidence
    (open / high-severity / reopened / fixed / dismissed) as activity-level
    signals. Idempotent — re-running creates no duplicates. These are review
    signals; they do not confirm exploitation, compromise, or unauthorized access.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = github_code_scanning_signal_service.generate_github_code_scanning_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return GitHubCodeScanningSignalGenerateResponse(**summary)


@router.post(
    "/github-dependabot/generate-signals",
    response_model=GitHubDependabotSignalGenerateResponse,
)
def generate_github_dependabot_signals(
    body: Optional[GitHubDependabotSignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GitHubDependabotSignalGenerateResponse:
    """Generate GitHub Dependabot alert Incident Signals (M69.4H).

    Admin/owner only. Surfaces review-worthy Dependabot (vulnerable-dependency)
    alert evidence (open / high-severity / reopened / fixed / dismissed) as
    activity-level signals. Idempotent — re-running creates no duplicates. These
    are review signals; they do not confirm exploitation, compromise, or
    unauthorized access.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = github_dependabot_signal_service.generate_github_dependabot_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return GitHubDependabotSignalGenerateResponse(**summary)


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


@router.post("/azure-activity/sync", response_model=AzureActivitySyncResponse)
def sync_azure_activity(
    body: Optional[AzureActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AzureActivitySyncResponse:
    """Ingest Azure Activity Log management events (M77D).

    Admin/owner only. Non-fatal: permission/availability limits are reported in
    the summary, never raised. The service principal must have the Reader role
    on the subscription for Activity Log access.

    Strict operation-name allowlist applied client-side: only WRITE/DELETE
    operations on NSGs, Storage Accounts, Key Vaults, role assignments, App
    Services, SQL Servers, and AKS clusters are ingested. READ/LIST operations,
    data-plane access, diagnostic logs, VM logs, and application logs are
    deliberately excluded.

    Members can view the resulting events via
    ``GET /security/activity/events?provider=azure``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "azure",
    )
    requested_id = body.integration_id if body else None
    if requested_id:
        try:
            iid = uuid.UUID(str(requested_id))
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(status_code=422, detail="Invalid integration_id.")
        integration = q.filter(Integration.id == iid).first()
        if integration is None:
            raise HTTPException(status_code=404, detail="Azure integration not found.")
    else:
        integration = (
            q.filter(Integration.status == "active")
            .order_by(Integration.created_at.asc())
            .first()
        )
        if integration is None:
            return AzureActivitySyncResponse(
                attempted=False,
                succeeded=False,
                provider="azure",
                source="azure_activity_log",
                error_message="No active Azure integration found.",
            )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100
    summary = azure_activity_ingestion_service.ingest_azure_activity(
        integration=integration,
        workspace_id=workspace_id,
        db=db,
        lookback_hours=lookback_hours,
        max_events=max_events,
    )
    return AzureActivitySyncResponse(**summary)


@router.post(
    "/google-cloud-activity/sync",
    response_model=GoogleCloudActivitySyncResponse,
)
def sync_google_cloud_activity(
    body: Optional[GoogleCloudActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GoogleCloudActivitySyncResponse:
    """Ingest Google Cloud Admin Activity audit log entries (M78D).

    Admin/owner only. Non-fatal: permission/availability limits are reported in
    the summary, never raised. The service account must have the
    roles/logging.viewer role (or logging.logEntries.list permission) on the
    project for Cloud Logging access.

    Strict methodName allowlist applied client-side: only CREATE/UPDATE/DELETE
    operations on IAM, firewall rules, VPC networks, Cloud Storage buckets,
    Cloud SQL instances, Cloud Run services, GKE clusters, and Secret Manager
    secrets are ingested. READ/LIST operations, data-plane access (Cloud SQL
    query logs, secret access events, storage object reads), VM logs, Kubernetes
    workload logs, and application logs are deliberately excluded.

    Members can view the resulting events via
    ``GET /security/activity/events?provider=google_cloud``.

    Evidence is configuration-change metadata only. Does not confirm breach,
    compromise, unauthorized access, or data exposure.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    q = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.provider == "google_cloud",
    )
    requested_id = body.integration_id if body else None
    if requested_id:
        try:
            iid = uuid.UUID(str(requested_id))
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(status_code=422, detail="Invalid integration_id.")
        integration = q.filter(Integration.id == iid).first()
        if integration is None:
            raise HTTPException(
                status_code=404, detail="Google Cloud integration not found."
            )
    else:
        integration = (
            q.filter(Integration.status == "active")
            .order_by(Integration.created_at.asc())
            .first()
        )
        if integration is None:
            return GoogleCloudActivitySyncResponse(
                attempted=False,
                succeeded=False,
                provider="google_cloud",
                source="google_cloud_audit_log",
                error_message="No active Google Cloud integration found.",
            )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100
    summary = google_cloud_activity_ingestion_service.ingest_google_cloud_activity(
        integration=integration,
        workspace_id=workspace_id,
        db=db,
        lookback_hours=lookback_hours,
        max_events=max_events,
    )
    return GoogleCloudActivitySyncResponse(**summary)


@router.post(
    "/twilio-activity/sync",
    response_model=TwilioActivitySyncResponse,
)
def sync_twilio_activity_events(
    body: Optional[TwilioActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TwilioActivitySyncResponse:
    """Sync review-safe Twilio configuration activity events (M79D).

    Admin/owner only. Ingests control-plane configuration-change events from
    the Twilio Monitor API. Only account/phone-number/messaging-service/
    Verify-service/API-key create/update/delete events are ingested.

    Message bodies, call logs, recordings, media, SMS/MMS content, customer
    communication data, full phone numbers, webhook URL strings, auth tokens,
    API secrets, and customer PII are never stored.

    Non-fatal: permission/availability limits are reported in the summary,
    never raised. Members can view the resulting events via
    ``GET /security/activity/events?provider=twilio``.

    Evidence is configuration-change metadata only. Does not confirm breach,
    compromise, unauthorized access, or data exposure.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    integration_id = body.integration_id if body else None
    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100

    summary = twilio_activity_ingestion_service.sync_twilio_activity(
        workspace_id=workspace_id,
        integration_id=integration_id,
        lookback_hours=lookback_hours,
        max_events=max_events,
        db=db,
    )
    return TwilioActivitySyncResponse(**summary)


@router.post(
    "/sendgrid-activity/sync",
    response_model=SendGridActivitySyncResponse,
)
def sync_sendgrid_activity_events(
    body: Optional[SendGridActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SendGridActivitySyncResponse:
    """Sync review-safe SendGrid configuration activity events (M80D).

    Admin/owner only. Synthesizes configuration-state events from safe
    SendGrid configuration surfaces. Only account, API key, sender identity,
    domain authentication, mail settings, tracking settings, event webhook,
    inbound parse, and suppression configuration metadata are ingested.

    Email bodies, subject lines, recipient emails, sender personal emails,
    suppression recipient emails, template content, mail event payloads,
    click/open/bounce/unsubscribe events, raw webhook URLs, API key values,
    bearer tokens, authorization headers, and customer data are NEVER stored.

    Evidence is configuration-state metadata only. Does not confirm breach,
    compromise, unauthorized access, or data exposure.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(workspace_id, current_user.id, db)

    integration_id = body.integration_id if body else None
    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100

    summary = sendgrid_activity_ingestion_service.sync_sendgrid_activity(
        workspace_id=workspace_id,
        integration_id=integration_id,
        lookback_hours=lookback_hours,
        max_events=max_events,
        db=db,
    )
    return SendGridActivitySyncResponse(**summary)


@router.post(
    "/auth0-activity/sync",
    response_model=Auth0ActivitySyncResponse,
)
def sync_auth0_activity_events(
    body: Optional[Auth0ActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Auth0ActivitySyncResponse:
    """Sync review-safe Auth0 configuration activity events (M81D).

    Admin/owner only. Synthesizes configuration-state events from safe
    Auth0 Management API surfaces: tenant settings, applications, connections,
    resource servers, rules, actions, MFA/Guardian factors, and custom domains.

    Auth0 Management API logs (/api/v2/logs) are NEVER ingested — they
    contain user_id, email, IP address, and device data in every entry.
    Events are synthesized from the same safe configuration surfaces the
    drift connector already reads.

    Login, authentication, session, token-exchange, password-reset,
    MFA-enrollment, user profile, and organization-member events are
    NEVER stored. Client secrets, management tokens, access tokens, JWTs,
    raw callback/logout/origin URLs, audience URIs, custom domain names,
    rule/action script content, action secret values, user emails, user IDs,
    IP addresses, session data, connection credentials, SAML certificates,
    and raw Auth0 API response dicts are NEVER stored.

    Evidence is configuration-state metadata only. Does not confirm breach,
    compromise, unauthorized access, or data exposure.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    integration_id = body.integration_id if body else None
    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100

    summary = auth0_activity_ingestion_service.sync_auth0_activity(
        workspace_id=workspace_id,
        integration_id=integration_id,
        lookback_hours=lookback_hours,
        max_events=max_events,
        db=db,
    )
    return Auth0ActivitySyncResponse(**summary)


@router.post(
    "/clerk-activity/sync",
    response_model=ClerkActivitySyncResponse,
)
def sync_clerk_activity_events(
    body: Optional[ClerkActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ClerkActivitySyncResponse:
    """Sync review-safe Clerk configuration activity events (M83D).

    Admin/owner only. Synthesizes config-state events from safe Clerk
    API surfaces (instance settings, auth strategy, org settings, session
    policy, email/SMS, domains, redirect URL configs, JWT templates,
    webhook endpoints). Auth/session/user events are NEVER ingested.
    PII and credentials are NEVER stored.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    integration_id = body.integration_id if body else None
    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100

    summary = clerk_activity_ingestion_service.sync_clerk_activity(
        workspace_id=workspace_id,
        integration_id=integration_id,
        lookback_hours=lookback_hours,
        max_events=max_events,
        db=db,
    )
    return ClerkActivitySyncResponse(**summary)


@router.post(
    "/pagerduty-activity/sync",
    response_model=PagerDutyActivitySyncResponse,
)
def sync_pagerduty_activity_events(
    body: Optional[PagerDutyActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PagerDutyActivitySyncResponse:
    """Sync review-safe PagerDuty configuration activity events (M84D).

    Admin/owner only. Synthesizes config-state events from safe PagerDuty
    API surfaces (services, escalation policies, schedules, service
    integrations, webhook subscriptions, event orchestrations, business
    services, response plays). Raw PagerDuty audit logs, actor identities,
    incident content, alert data, and operational payloads are NEVER ingested.

    PagerDuty API tokens, routing keys, integration keys, webhook secrets,
    delivery URLs, custom header values, user emails, user names, phone numbers,
    contact methods, on-call user identities, responder identities, subscriber
    identities, incident payloads, alert payloads, conference phone numbers,
    raw routing expressions, IP addresses, user agents, raw audit payloads,
    and customer PII are NEVER stored.

    Evidence is configuration-state metadata only. Does not confirm breach,
    compromise, unauthorized access, or data exposure.

    Members can read ingested events via
    GET /security/activity/events?provider=pagerduty.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    integration_id = body.integration_id if body else None
    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100

    summary = pagerduty_activity_ingestion_service.sync_pagerduty_activity(
        workspace_id=workspace_id,
        integration_id=integration_id,
        lookback_hours=lookback_hours,
        max_events=max_events,
        db=db,
    )
    return PagerDutyActivitySyncResponse(**summary)


@router.post(
    "/linear-activity/sync",
    response_model=LinearActivitySyncResponse,
)
def sync_linear_activity_events(
    body: Optional[LinearActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> LinearActivitySyncResponse:
    """Sync review-safe Linear configuration activity events (M85D).

    Admin/owner only. Synthesizes config-state events from safe Linear
    API surfaces (workspace, teams, projects, workflow states, labels,
    webhook subscriptions, custom views, active cycles, and integrations).
    Linear's audit API is NEVER used — it contains actor emails, user IDs,
    IP addresses, and user agents in every entry.

    Linear API keys, OAuth tokens, webhook secrets, raw webhook URLs, issue
    titles, issue descriptions, comment bodies, attachment content, user
    emails, user names, member identities, customer names, IP addresses,
    user agents, raw audit payloads, and PII are NEVER stored.

    Evidence is configuration-state metadata only. Does not confirm breach,
    compromise, unauthorized access, or data exposure.

    Members can read ingested events via
    GET /security/activity/events?provider=linear.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    integration_id = body.integration_id if body else None
    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100

    summary = linear_activity_ingestion_service.sync_linear_activity(
        workspace_id=workspace_id,
        integration_id=integration_id,
        lookback_hours=lookback_hours,
        max_events=max_events,
        db=db,
    )
    return LinearActivitySyncResponse(**summary)


@router.post(
    "/jira-activity/sync",
    response_model=JiraActivitySyncResponse,
)
def sync_jira_activity_events(
    body: Optional[JiraActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> JiraActivitySyncResponse:
    """Sync review-safe Jira configuration activity events (M86D).

    Admin/owner only. Synthesizes config-state events from the same safe Jira
    configuration posture summaries the drift connector already stores (site,
    projects, boards, workflows, workflow schemes, permission schemes,
    notification schemes, issue type schemes, field configuration schemes,
    screen schemes, webhooks, and automation rules). Jira's audit log / issue /
    user activity APIs are NEVER used — they contain actor account IDs, actor
    emails, IP addresses, user agents, and issue content in every entry.

    Jira API tokens, OAuth tokens, webhook secrets, raw webhook/delivery URLs,
    site base URLs, JQL, filter expressions, issue keys, issue titles, issue
    descriptions, comment bodies, attachment content, customer names, user
    emails, user names, account IDs, IP addresses, user agents, raw audit
    payloads, and PII are NEVER stored.

    Evidence is configuration-state metadata only. Does not confirm breach,
    compromise, unauthorized access, or data exposure.

    Members can read ingested events via
    GET /security/activity/events?provider=jira.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    integration_id = body.integration_id if body else None
    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100

    summary = jira_activity_ingestion_service.sync_jira_activity(
        workspace_id=workspace_id,
        integration_id=integration_id,
        lookback_hours=lookback_hours,
        max_events=max_events,
        db=db,
    )
    return JiraActivitySyncResponse(**summary)


@router.post(
    "/jira-activity/generate-signals",
    response_model=JiraActivitySignalGenerateResponse,
)
def generate_jira_activity_signals_endpoint(
    body: Optional[JiraActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> JiraActivitySignalGenerateResponse:
    """Generate Incident Signals from safe Jira configuration activity events (M86E).

    Admin/owner only. Promotes ingested jira/jira_activity_event config-state
    events into review-priority Incident Signals grouped by resource identity.
    Idempotent — re-running creates no duplicates. Review signals only; does not
    confirm breach, compromise, unauthorized access, or data exposure.

    Jira API tokens, OAuth tokens, webhook secrets, raw webhook/delivery URLs,
    site base URLs, JQL, filter expressions, issue keys, issue titles, issue
    descriptions, comment bodies, attachment content, customer names, user
    emails, user names, account IDs, IP addresses, user agents, raw audit
    payloads, and PII are NEVER stored. Members can read signals via
    GET /security/signals?provider=jira.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_signals = min(body.max_signals, 1000) if body and body.max_signals else 100
    summary = jira_activity_signal_service.generate_jira_activity_signals(
        workspace_id=workspace_id,
        db=db,
        lookback_hours=lookback_hours,
        max_signals=max_signals,
    )
    return JiraActivitySignalGenerateResponse(**summary)


@router.post(
    "/linear-activity/generate-signals",
    response_model=LinearActivitySignalGenerateResponse,
)
def generate_linear_activity_signals_endpoint(
    body: Optional[LinearActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> LinearActivitySignalGenerateResponse:
    """Generate Linear configuration review signals from M85D activity events.

    Admin/owner only. Reads linear/linear_activity_event events and promotes
    config-state activity into Incident Signals. Idempotent — re-running creates
    no duplicates. Never confirms breach, compromise, or unauthorized access.
    Members can read signals via GET /security/signals?provider=linear.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_signals = min(body.max_signals, 1000) if body and body.max_signals else 100
    summary = linear_activity_signal_service.generate_linear_activity_signals(
        workspace_id=workspace_id,
        db=db,
        lookback_hours=lookback_hours,
        max_signals=max_signals,
    )
    return LinearActivitySignalGenerateResponse(**summary)


@router.post(
    "/linear-correlations/generate",
    response_model=LinearCorrelationGenerateResponse,
)
def generate_linear_risk_activity_correlations(
    body: Optional[LinearCorrelationGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> LinearCorrelationGenerateResponse:
    """Generate Linear Risk x Activity correlations for a workspace.

    Admin/owner only. Joins active Linear configuration-risk findings with
    Linear activity signals on the same resource. Idempotent. Never confirms
    breach, compromise, or unauthorized access. Members can read correlations
    via GET /security/correlations?provider=linear.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_correlations = min(body.max_correlations, 1000) if body and body.max_correlations else 100
    summary = linear_risk_activity_correlation_service.generate_linear_correlations(
        workspace_id=workspace_id,
        db=db,
        lookback_hours=lookback_hours,
        max_correlations=max_correlations,
    )
    return LinearCorrelationGenerateResponse(**summary)


@router.post(
    "/pagerduty-activity/generate-signals",
    response_model=PagerDutyActivitySignalGenerateResponse,
)
def generate_pagerduty_activity_signals_endpoint(
    body: Optional[PagerDutyActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PagerDutyActivitySignalGenerateResponse:
    """Generate Incident Signals from safe PagerDuty configuration activity events (M84E).

    Admin/owner only. Promotes ingested PagerDuty config-state events into
    review-priority Incident Signals grouped by resource identity.
    Idempotent — re-running creates no duplicates. Review signals only;
    does not confirm compromise, unauthorized access, or data exposure.

    PagerDuty API tokens, routing keys, integration keys, webhook secrets,
    delivery URLs, custom header values, user emails, user names, phone numbers,
    contact methods, on-call user identities, responder identities, subscriber
    identities, incident payloads, alert payloads, conference phone numbers,
    raw routing expressions, IP addresses, user agents, raw audit payloads,
    and customer PII are NEVER stored.

    Members can read signals via GET /security/signals?provider=pagerduty.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_signals = min(body.max_signals, 1000) if body and body.max_signals else 100

    summary = pagerduty_activity_signal_service.generate_pagerduty_activity_signals(
        workspace_id=workspace_id,
        lookback_hours=lookback_hours,
        max_signals=max_signals,
        db=db,
    )
    return PagerDutyActivitySignalGenerateResponse(**summary)


@router.post(
    "/pagerduty-correlations/generate",
    response_model=PagerDutyCorrelationGenerateResponse,
)
def generate_pagerduty_risk_activity_correlations(
    body: Optional[PagerDutyCorrelationGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PagerDutyCorrelationGenerateResponse:
    """Generate PagerDuty Risk × Activity correlations (M84F).

    Admin/owner only. Joins active PagerDuty configuration-risk findings with
    PagerDuty activity signals on the same safe opaque resource_id within a
    review window. Covers eight correlation families: service, escalation_policy,
    schedule, service_integration, webhook_subscription, event_orchestration,
    business_service, and response_play.

    PagerDuty API tokens, routing keys, integration keys, webhook secrets,
    delivery URLs, user emails, user names, phone numbers, contact methods,
    on-call user identities, responder identities, subscriber identities,
    incident payloads, alert payloads, IP addresses, user agents, raw audit
    payloads, and PII are never used or stored.
    Does not confirm compromise, unauthorized access, or data exposure.
    Idempotent — re-running creates no duplicates.

    Members can view the resulting correlations via
    GET /security/correlations?provider=pagerduty.
    """
    from app.services.pagerduty_risk_activity_correlation_service import (
        generate_pagerduty_correlations,
    )

    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_correlations is not None:
            kwargs["max_correlations"] = body.max_correlations
    result = generate_pagerduty_correlations(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return PagerDutyCorrelationGenerateResponse(**result)


@router.post(
    "/clerk-activity/generate-signals",
    response_model=ClerkActivitySignalGenerateResponse,
)
def generate_clerk_activity_signals_endpoint(
    body: Optional[ClerkActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ClerkActivitySignalGenerateResponse:
    """Generate Incident Signals from safe Clerk configuration activity events (M83E).

    Admin/owner only. Promotes ingested Clerk config-state events into
    review-priority Incident Signals grouped by resource identity.
    Idempotent — re-running creates no duplicates. Review signals only;
    does not confirm compromise, unauthorized access, or data exposure.
    No secrets, tokens, PII, or raw URLs are stored.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_signals = min(body.max_signals, 1000) if body and body.max_signals else 100

    summary = clerk_activity_signal_service.generate_clerk_activity_signals(
        workspace_id=workspace_id,
        lookback_hours=lookback_hours,
        max_signals=max_signals,
        db=db,
    )
    return ClerkActivitySignalGenerateResponse(**summary)


@router.post(
    "/auth0-activity/generate-signals",
    response_model=Auth0ActivitySignalGenerateResponse,
)
def generate_auth0_activity_signals_endpoint(
    body: Optional[Auth0ActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Auth0ActivitySignalGenerateResponse:
    """Generate Incident Signals from safe Auth0 configuration activity events (M81E).

    Admin/owner only. Promotes ingested Auth0 config-state events (tenant
    settings, applications, connections, resource servers, rules, actions,
    MFA factors, and custom domains) into review-priority Incident Signals.
    Groups events by resource identity within the lookback window.
    Idempotent — re-running creates no duplicates.

    Client secrets, management tokens, access tokens, JWTs, raw URLs,
    callback/logout/origin URLs, audience URIs, custom domain name strings,
    rule/action script content, action secret values, user emails, user IDs,
    IP addresses, session data, connection credentials, and raw Auth0 API
    responses are never stored.
    These are review signals; they do not confirm compromise, unauthorized
    access, leaked credentials, or data exposure.

    Members can view the resulting signals via
    GET /security/signals?provider=auth0.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = auth0_activity_signal_service.generate_auth0_activity_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return Auth0ActivitySignalGenerateResponse(**summary)


@router.post(
    "/datadog-activity/sync",
    response_model=DatadogActivitySyncResponse,
)
def sync_datadog_activity_events(
    body: Optional[DatadogActivitySyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DatadogActivitySyncResponse:
    """Sync review-safe Datadog configuration activity events (M82D).

    Admin/owner only. Synthesizes configuration-state events from safe
    Datadog API surfaces: monitors, SLOs, dashboards, webhook integrations,
    notification integrations, API key metadata, application key metadata,
    roles, teams, and cloud integrations.

    Datadog's audit/audit-trail API is NEVER used — it contains actor email,
    actor UUID, and IP-level request metadata in every entry. Events are
    synthesized from the same safe configuration surfaces the drift connector
    already reads.

    Raw audit payloads, actor identities, IP addresses, user agents, raw
    monitor queries, raw monitor messages, raw dashboard JSON, webhook URLs,
    webhook headers, webhook payload templates, webhook secrets, notification
    handles, Slack channel names, PagerDuty service IDs, email addresses,
    user IDs, team member identities, logs, traces, metric values, incident
    content, API key values, application key values, OAuth tokens, bearer
    tokens, and raw Datadog API response dicts are NEVER stored.

    Evidence is configuration-state metadata only. Does not confirm breach,
    compromise, unauthorized access, or data exposure.

    Members can read ingested events via
    GET /security/activity/events?provider=datadog.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )

    integration_id = body.integration_id if body else None
    lookback_hours = min(body.lookback_hours, 168) if body and body.lookback_hours else 24
    max_events = min(body.max_events, 1000) if body and body.max_events else 100

    summary = datadog_activity_ingestion_service.sync_datadog_activity(
        workspace_id=workspace_id,
        integration_id=integration_id,
        lookback_hours=lookback_hours,
        max_events=max_events,
        db=db,
    )
    return DatadogActivitySyncResponse(**summary)


@router.post(
    "/datadog-activity/generate-signals",
    response_model=DatadogActivitySignalGenerateResponse,
)
def generate_datadog_activity_signals_endpoint(
    body: Optional[DatadogActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DatadogActivitySignalGenerateResponse:
    """Generate Incident Signals from safe Datadog configuration activity events (M82E).

    Admin/owner only. Promotes ingested Datadog config-state events (monitors,
    SLOs, dashboards, webhook integrations, notification integrations, API key
    metadata, application key metadata, roles, teams, and cloud integrations)
    into review-priority Incident Signals. Groups events by resource identity
    within the lookback window. Idempotent — re-running creates no duplicates.

    Datadog's audit/audit-trail API is never used. Events are synthesized from
    the same safe configuration surfaces the drift connector already reads.

    API key values, application key values, OAuth tokens, bearer tokens,
    webhook secrets, raw monitor queries, raw monitor messages, raw dashboard
    JSON, webhook URLs, headers, payload templates, notification handles, Slack
    channel names, PagerDuty service IDs, email addresses, user IDs, team
    member identities, IP addresses, user agents, raw Datadog audit payloads,
    and raw API response dicts are never stored.
    These are review signals; they do not confirm compromise, unauthorized
    access, leaked credentials, or data exposure.

    Members can view the resulting signals via
    GET /security/signals?provider=datadog.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = datadog_activity_signal_service.generate_datadog_activity_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return DatadogActivitySignalGenerateResponse(**summary)


@router.post(
    "/sendgrid-activity/generate-signals",
    response_model=SendGridActivitySignalGenerateResponse,
)
def generate_sendgrid_activity_signals_endpoint(
    body: Optional[SendGridActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SendGridActivitySignalGenerateResponse:
    """Generate Incident Signals from safe SendGrid configuration activity events (M80E).

    Admin/owner only. Promotes ingested SendGrid config-state events (account,
    API key, sender identity, domain authentication, mail/tracking settings,
    event webhook, inbound parse, and suppression configuration changes) into
    review-priority Incident Signals. Groups events by resource identity within
    the lookback window. Idempotent — re-running creates no duplicates.

    API key values, email bodies, subject lines, recipient emails, template
    content, raw webhook URLs, raw inbound parse hostnames, mail event payloads
    (bounce/click/open/delivered/dropped/spamreport/unsubscribe/processed),
    and customer data are never stored.
    These are review signals; they do not confirm compromise, unauthorized
    access, leaked credentials, or data exposure.

    Members can view the resulting signals via
    GET /security/signals?provider=sendgrid.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = sendgrid_activity_signal_service.generate_sendgrid_activity_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return SendGridActivitySignalGenerateResponse(**summary)


@router.post(
    "/twilio-activity/generate-signals",
    response_model=TwilioActivitySignalGenerateResponse,
)
def generate_twilio_activity_signals_endpoint(
    body: Optional[TwilioActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TwilioActivitySignalGenerateResponse:
    """Generate Incident Signals from safe Twilio configuration activity events (M79E).

    Admin/owner only. Promotes ingested Twilio Monitor config-change events
    (phone number, messaging service, Verify service, API key, and account
    configuration changes) into review-priority Incident Signals. Groups events
    by resource identity within the lookback window. Idempotent — re-running
    creates no duplicates.

    Message bodies, call logs, recordings, media, full phone numbers, auth
    tokens, API secrets, webhook URL strings, and customer PII are never stored.
    These are review signals; they do not confirm compromise, unauthorized
    access, leaked credentials, or data exposure.

    Members can view the resulting signals via
    ``GET /security/signals?provider=twilio``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = twilio_activity_signal_service.generate_twilio_activity_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return TwilioActivitySignalGenerateResponse(**summary)


@router.post(
    "/sendgrid-correlations/generate",
    response_model=SendGridCorrelationGenerateResponse,
)
def generate_sendgrid_risk_activity_correlations(
    body: Optional[SendGridCorrelationGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SendGridCorrelationGenerateResponse:
    """Generate SendGrid Risk × Activity correlations (M80F).

    Admin/owner only. Joins active SendGrid configuration-risk findings with
    SendGrid activity signals using safe resource identifiers (api_key_id,
    sender_id, domain_id) or provider+family aggregate matching for account-level
    surfaces (mail settings, tracking settings, webhook, suppression settings).

    Covers seven correlation families: api_key, sender_identity,
    domain_authentication, mail_settings, tracking_settings, webhook,
    and suppression_settings.

    API key values, email bodies, subject lines, recipient emails, template
    content, raw webhook URLs, raw inbound parse hostnames, mail event payloads
    (bounce/click/open/delivered/dropped/spamreport/unsubscribe/processed),
    message IDs, and customer data are never used or stored. Does not confirm
    compromise, unauthorized access, or data exposure. Idempotent — re-running
    creates no duplicates.

    Members can view the resulting correlations via
    GET /security/correlations?provider=sendgrid.
    """
    from app.services.sendgrid_risk_activity_correlation_service import (
        generate_sendgrid_correlations,
    )

    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs_sg: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs_sg["lookback_hours"] = body.lookback_hours
        if body.max_correlations is not None:
            kwargs_sg["max_correlations"] = body.max_correlations
    result = generate_sendgrid_correlations(
        workspace_id=workspace_id, db=db, **kwargs_sg
    )
    return SendGridCorrelationGenerateResponse(**result)


@router.post(
    "/twilio-correlations/generate",
    response_model=TwilioCorrelationGenerateResponse,
)
def generate_twilio_risk_activity_correlations(
    body: Optional[TwilioCorrelationGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TwilioCorrelationGenerateResponse:
    """Generate Twilio Risk × Activity correlations (M79F).

    Admin/owner only. Joins active Twilio configuration-risk findings with
    Twilio activity signals using safe resource identifiers (phone_number_last4,
    messaging_service_sid, verify_service_sid, api_key_sid) or provider+family
    aggregate matching when no per-resource identity is available.

    Covers five correlation families: phone_number, messaging_service,
    verify_service, api_key, and account.

    Message bodies, call logs, recordings, media, full phone numbers, auth
    tokens, API key secrets, webhook URL strings, and customer communication
    data are never used or stored. Does not confirm compromise, unauthorized
    access, or data exposure. Idempotent — re-running creates no duplicates.

    Members can view the resulting correlations via
    ``GET /security/correlations?provider=twilio``.
    """
    from app.services.twilio_risk_activity_correlation_service import (
        generate_twilio_correlations,
    )

    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs2: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs2["lookback_hours"] = body.lookback_hours
        if body.max_correlations is not None:
            kwargs2["max_correlations"] = body.max_correlations
    result = generate_twilio_correlations(
        workspace_id=workspace_id, db=db, **kwargs2
    )
    return TwilioCorrelationGenerateResponse(**result)


@router.post(
    "/auth0-correlations/generate",
    response_model=Auth0CorrelationGenerateResponse,
)
def generate_auth0_risk_activity_correlations(
    body: Optional[Auth0CorrelationGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Auth0CorrelationGenerateResponse:
    """Generate Auth0 Risk × Activity correlations (M81F).

    Admin/owner only. Joins active Auth0 configuration-risk findings with
    Auth0 activity signals using safe resource identifiers (client_id,
    connection_id, resource_server_id, rule_id, action_id, factor_name,
    custom_domain_id) or provider+family aggregate matching when no
    per-resource identity is available.

    Covers eight correlation families: tenant, application, connection,
    resource_server, rule, action, mfa_factor, and custom_domain.

    Client secrets, management tokens, access tokens, JWTs, raw URLs,
    callback/logout/origin URLs, audience URIs, custom domain name strings,
    rule/action script content, action secret values, user emails, user IDs,
    IP addresses, session data, connection credentials, and raw Auth0 API
    responses are never used or stored. Does not confirm compromise,
    unauthorized access, or data exposure. Idempotent — re-running creates
    no duplicates.

    Members can view the resulting correlations via
    GET /security/correlations?provider=auth0.
    """
    from app.services.auth0_risk_activity_correlation_service import (
        generate_auth0_correlations,
    )

    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs_auth0: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs_auth0["lookback_hours"] = body.lookback_hours
        if body.max_correlations is not None:
            kwargs_auth0["max_correlations"] = body.max_correlations
    result = generate_auth0_correlations(
        workspace_id=workspace_id, db=db, **kwargs_auth0
    )
    return Auth0CorrelationGenerateResponse(**result)


@router.post(
    "/datadog-correlations/generate",
    response_model=DatadogCorrelationGenerateResponse,
)
def generate_datadog_risk_activity_correlations(
    body: Optional[DatadogCorrelationGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DatadogCorrelationGenerateResponse:
    """Generate Datadog Risk × Activity correlations (M82F).

    Admin/owner only. Joins active Datadog configuration-risk findings with
    Datadog activity signals using safe resource identifiers (monitor_id,
    slo_id, dashboard_id, webhook_id, notification_integration_id, api_key_id,
    application_key_id, role_id, team_id, cloud_integration_id) or resource
    family aggregate matching when no per-resource identity is available.

    Covers ten correlation families: monitor, SLO, dashboard, webhook,
    notification integration, API key, application key, role, team, and
    cloud integration, plus a generic resource_type/resource_id fallback.

    API key values, application key values, OAuth tokens, bearer tokens,
    webhook secrets, raw monitor queries, raw monitor messages, raw dashboard
    JSON, webhook URLs, headers, payload templates, notification handles, Slack
    channel names, PagerDuty service IDs, email addresses, user IDs, team
    member identities, IP addresses, user agents, raw Datadog audit payloads,
    and raw API response dicts are never used or stored.
    Does not confirm compromise, unauthorized access, or data exposure.
    Idempotent — re-running creates no duplicates.

    Members can view the resulting correlations via
    GET /security/correlations?provider=datadog.
    """
    from app.services.datadog_risk_activity_correlation_service import (
        generate_datadog_correlations,
    )

    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs_dd: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs_dd["lookback_hours"] = body.lookback_hours
        if body.max_correlations is not None:
            kwargs_dd["max_correlations"] = body.max_correlations
    result = generate_datadog_correlations(
        workspace_id=workspace_id, db=db, **kwargs_dd
    )
    return DatadogCorrelationGenerateResponse(**result)


@router.post(
    "/clerk-correlations/generate",
    response_model=ClerkCorrelationGenerateResponse,
)
def generate_clerk_risk_activity_correlations(
    body: Optional[ClerkCorrelationGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ClerkCorrelationGenerateResponse:
    """Generate Clerk Risk × Activity correlations (M83F).

    Admin/owner only. Joins active Clerk configuration-risk findings with
    Clerk activity signals using safe resource identifiers (instance_id,
    application_id, domain_id, redirect_url_config_id, jwt_template_id,
    webhook_endpoint_id, auth_strategy_id, organization_settings_id,
    session_policy_id) or family aggregate matching for singleton resources.

    Clerk secret key values, publishable key values, session tokens, JWTs,
    OAuth tokens, webhook secrets, raw redirect URLs, raw domain names,
    JWT template bodies, user emails, user IDs, phone numbers, member
    identities, session history, IP addresses, user agents, raw audit
    payloads, and PII are never used or stored.
    Does not confirm compromise, unauthorized access, or data exposure.
    Idempotent — re-running creates no duplicates.

    Members can view the resulting correlations via
    GET /security/correlations?provider=clerk.
    """
    from app.services.clerk_risk_activity_correlation_service import (
        generate_clerk_correlations,
    )

    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_correlations is not None:
            kwargs["max_correlations"] = body.max_correlations
    result = generate_clerk_correlations(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return ClerkCorrelationGenerateResponse(**result)


@router.post(
    "/google-cloud-activity/generate-signals",
    response_model=GoogleCloudActivitySignalGenerateResponse,
)
def generate_google_cloud_activity_signals(
    body: Optional[GoogleCloudActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GoogleCloudActivitySignalGenerateResponse:
    """Generate Google Cloud Audit Log Incident Signals (M78E).

    Admin/owner only. Promotes Google Cloud Admin Activity audit log events
    (IAM policy changes, service account changes, firewall rule changes, VPC
    network changes, Cloud Storage changes, Cloud SQL changes, Cloud Run
    changes, GKE cluster changes, and Secret Manager changes) into
    review-worthy signals. Idempotent — re-running creates no duplicates.

    These are review signals; they do not confirm compromise, unauthorized
    access, leaked secrets, or data exposure. Members can view the resulting
    signals via ``GET /security/signals?provider=google_cloud``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = google_cloud_activity_signal_service.generate_google_cloud_activity_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return GoogleCloudActivitySignalGenerateResponse(**summary)


@router.post(
    "/azure-activity/generate-signals",
    response_model=AzureActivitySignalGenerateResponse,
)
def generate_azure_activity_signals(
    body: Optional[AzureActivitySignalGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AzureActivitySignalGenerateResponse:
    """Generate Azure Activity Log Incident Signals (M77E).

    Admin/owner only. Promotes Azure Activity Log management events (NSG,
    Storage, Key Vault, role assignment, App Service, SQL, AKS configuration
    changes) into review-worthy signals. Idempotent — re-running creates no
    duplicates. These are review signals; they do not confirm compromise,
    unauthorized access, leaked secrets, or data exposure. Members can view
    the resulting signals via ``GET /security/signals?provider=azure``.
    """
    workspace_id = _current_workspace_id(current_user, db)
    workspace_permission_service.require_workspace_admin(
        workspace_id, current_user.id, db
    )
    kwargs: dict[str, Any] = {}
    if body:
        if body.lookback_hours is not None:
            kwargs["lookback_hours"] = body.lookback_hours
        if body.max_signals is not None:
            kwargs["max_signals"] = body.max_signals
    summary = azure_activity_signal_service.generate_azure_activity_signals(
        workspace_id=workspace_id, db=db, **kwargs
    )
    return AzureActivitySignalGenerateResponse(**summary)
