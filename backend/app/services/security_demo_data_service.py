"""Security Exposure demo-data service — M62.2.

Seeds a workspace with a realistic, SAFE demo dataset so a new user or prospect
can experience the full Security Exposure product (findings, assets, timeline,
review workflows, reports) without connecting real provider accounts.

Design / safety
---------------
* Opt-in only — created by an explicit API call, never automatically.
* All demo rows are anchored to a HIDDEN demo Integration (provider="demo",
  status="deleted") so they never appear in the integrations UI and are never
  picked up by the scheduler (it only syncs status=="active"). Findings still
  carry the REAL provider id in ``finding.provider`` for correct badges/grouping.
* Findings are also tagged in ``evidence`` (demo / demo_dataset / generated_by)
  for transparency.
* Rows are inserted directly — the evaluator and all notification dispatch
  (Slack/email/push) are bypassed entirely, so demo data never sends a message.
* Metadata-only: titles/evidence/remediation contain no secrets, tokens,
  payloads, or customer data, and avoid breach/attack/compromise wording.
* Idempotent seed: if demo data already exists it returns current counts
  without duplicating. Clear removes only the demo rows (by the demo anchor).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_finding import SecurityFinding
from app.models.security_finding_note import SecurityFindingNote

logger = logging.getLogger(__name__)

DEMO_DATASET = "security_exposure_demo_v1"
DEMO_PROVIDER_TAG = "demo"  # Integration.provider value for the hidden anchor.
DEMO_INTEGRATION_NAME = "ConfigTrace security demo (sample data)"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _evidence(detail: str) -> dict[str, Any]:
    return {
        "demo": True,
        "demo_dataset": DEMO_DATASET,
        "generated_by": "configtrace_demo_data",
        "detail": detail,
    }


def _remediation(summary: str) -> dict[str, Any]:
    return {"summary": summary, "demo": True}


def get_demo_integration(
    workspace_id: uuid.UUID, db: Session
) -> Optional[Integration]:
    """Return the hidden demo Integration for this workspace, if it exists."""
    return (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.provider == DEMO_PROVIDER_TAG,
            Integration.status == "deleted",
        )
        .first()
    )


def _demo_findings(workspace_id: uuid.UUID, integ_id: uuid.UUID, actor_user_id):
    """Build the demo finding ORM rows (not yet persisted)."""
    now = _utcnow()

    def mins(n):
        return now - timedelta(minutes=n)

    def hours(n):
        return now - timedelta(hours=n)

    def days(n):
        return now - timedelta(days=n)

    # (rule_key, record, provider, severity, status, title, remediation, extra)
    # status-specific timestamps applied below.
    rows: list[SecurityFinding] = []

    from app.services.security_rule_confidence import confidence_for

    def add(rule, record, provider, severity, status, title, remediation, *,
            opened, last_seen=None, resolved_at=None, accepted_until=None,
            snoozed_until=None, reviewed_at=None, acceptance_reason=None):
        finding_key = f"{rule}:{record}"
        conf, conf_reason, guard = confidence_for(finding_key)
        rows.append(
            SecurityFinding(
                workspace_id=workspace_id,
                integration_id=integ_id,
                resource_id=None,
                linked_change_id=None,
                provider=provider,
                finding_key=finding_key,
                severity=severity,
                status=status,
                title=title,
                description=title,
                evidence=_evidence(title),
                remediation=_remediation(remediation),
                first_detected_at=opened,
                last_seen_at=last_seen or opened,
                resolved_at=resolved_at,
                accepted_until=accepted_until,
                snoozed_until=snoozed_until,
                reviewed_by_user_id=actor_user_id if reviewed_at else None,
                reviewed_at=reviewed_at,
                acceptance_reason=acceptance_reason,
                confidence=conf,
                confidence_reason=conf_reason,
                false_positive_guard=guard or None,
            )
        )

    # ── Active critical / high ────────────────────────────────────────────────
    add("github_webhook_http", "acme/api#webhook#1", "github", "critical", "active",
        "GitHub webhook uses plain HTTP",
        "Switch the webhook delivery URL to HTTPS.",
        opened=hours(2), last_seen=mins(10))
    add("aws_public_database_port", "sg-0a1b2c#5432", "aws", "critical", "active",
        "Security group exposes a database port to the internet",
        "Restrict the ingress rule to known internal ranges.",
        opened=days(1), last_seen=mins(15))
    add("cloudflare_ssl_mode_weak", "zone:acme.com", "cloudflare", "high", "active",
        "Cloudflare SSL mode is set to Flexible",
        "Set SSL/TLS mode to Full (strict).",
        opened=days(3), last_seen=mins(20))
    add("firebase_rules_public", "ruleset:firestore", "firebase", "critical", "active",
        "Firestore security rules allow public access",
        "Replace public allow rules with authenticated access checks.",
        opened=hours(2), last_seen=mins(12))
    add("shopify_webhook_http", "webhook:orders/create", "shopify", "high", "active",
        "Shopify webhook uses plain HTTP",
        "Update the webhook endpoint to use HTTPS.",
        opened=days(1), last_seen=mins(18))

    # ── Medium active ─────────────────────────────────────────────────────────
    add("vercel_preview_unprotected", "project:acme-web", "vercel", "medium", "active",
        "Vercel preview deployments are publicly accessible",
        "Enable deployment protection for preview environments.",
        opened=days(3), last_seen=mins(25))
    add("supabase_anonymous_access_enabled", "project:acme", "supabase", "medium", "active",
        "Supabase anonymous access is enabled",
        "Disable anonymous sign-in if it is not required.",
        opened=days(1), last_seen=mins(30))

    # ── Acknowledged active (reviewed_at set, still active) ────────────────────
    add("cloudflare_always_https_off", "zone:acme.com", "cloudflare", "high", "active",
        "Always Use HTTPS is disabled",
        "Enable Always Use HTTPS to redirect HTTP traffic.",
        opened=days(2), last_seen=mins(22), reviewed_at=hours(3))

    # ── Resolved ──────────────────────────────────────────────────────────────
    add("stripe_webhook_http", "webhook:we_123", "stripe", "high", "resolved",
        "Stripe webhook uses plain HTTP",
        "Use an HTTPS webhook endpoint.",
        opened=days(3), last_seen=mins(30), resolved_at=mins(30))
    add("cloudflare_development_mode_on", "zone:acme.com", "cloudflare", "medium", "resolved",
        "Cloudflare development mode is on",
        "Turn off development mode to restore caching and protections.",
        opened=days(2), last_seen=hours(1), resolved_at=hours(1))

    # ── Accepted risk (future accepted_until + reason) ────────────────────────
    add("aws_public_admin_port", "sg-0a1b2c#22", "aws", "high", "accepted_risk",
        "Security group exposes an admin port to the internet",
        "Restrict SSH/RDP ingress to a bastion or VPN range.",
        opened=days(5), last_seen=hours(4), reviewed_at=hours(4),
        accepted_until=now + timedelta(days=30),
        acceptance_reason="Staging only; access is restricted at the network layer. Revisit after the Q3 migration.")
    add("github_status_checks_not_required", "acme/api#main", "github", "medium", "accepted_risk",
        "Required status checks are not enforced",
        "Require passing status checks before merge on protected branches.",
        opened=days(6), last_seen=hours(5), reviewed_at=hours(5),
        accepted_until=now + timedelta(days=14),
        acceptance_reason="Tracked in JIRA-481; enabling after the CI pipeline is stabilized.")

    # ── Snoozed (future snoozed_until) ────────────────────────────────────────
    add("aws_access_key_unused", "iam:deploy-bot#k4", "aws", "medium", "snoozed",
        "IAM access key has been unused for 90+ days",
        "Rotate or remove the unused access key.",
        opened=days(4), last_seen=hours(6), reviewed_at=hours(6),
        snoozed_until=now + timedelta(days=7))
    add("supabase_jwt_expiry_long", "project:acme", "supabase", "low", "snoozed",
        "Supabase JWT expiry is set very long",
        "Shorten the JWT expiry to reduce token lifetime.",
        opened=days(4), last_seen=hours(6), reviewed_at=hours(6),
        snoozed_until=now + timedelta(days=3))

    return rows


# Notes keyed by finding_key (added to a few demo findings).
_DEMO_NOTES = {
    "aws_public_admin_port:sg-0a1b2c#22": "Owner confirmed this belongs to staging. Follow-up scheduled.",
    "aws_public_database_port:sg-0a1b2c#5432": "Waiting on infra to restrict ingress.",
    "shopify_webhook_http:webhook:orders/create": "Need to verify webhook endpoint ownership.",
}


def _counts(findings: list[SecurityFinding]) -> dict[str, int]:
    by_status = {"active": 0, "resolved": 0, "accepted_risk": 0, "snoozed": 0}
    for f in findings:
        if f.status in by_status:
            by_status[f.status] += 1
    return {
        "exists": len(findings) > 0,
        "finding_count": len(findings),
        "active_count": by_status["active"],
        "resolved_count": by_status["resolved"],
        "accepted_count": by_status["accepted_risk"],
        "snoozed_count": by_status["snoozed"],
    }


def _demo_findings_in_workspace(
    workspace_id: uuid.UUID, integ: Optional[Integration], db: Session
) -> list[SecurityFinding]:
    if integ is None:
        return []
    return (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.integration_id == integ.id,
        )
        .all()
    )


def get_status(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Return whether demo data exists in the workspace + status counts."""
    integ = get_demo_integration(workspace_id, db)
    findings = _demo_findings_in_workspace(workspace_id, integ, db)
    return _counts(findings)


def seed(
    *, workspace_id: uuid.UUID, actor_user_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Seed the demo dataset (idempotent).

    If demo data already exists, returns the current counts without
    duplicating. Inserts rows directly — no evaluator, no notifications.
    """
    existing = get_demo_integration(workspace_id, db)
    if existing is not None:
        # Idempotent: demo data already present.
        return get_status(workspace_id, db)

    ct, iv = encrypt_credentials({"demo": True, "dataset": DEMO_DATASET})
    integ = Integration(
        user_id=actor_user_id,
        workspace_id=workspace_id,
        provider=DEMO_PROVIDER_TAG,
        display_name=DEMO_INTEGRATION_NAME,
        encrypted_credentials=ct,
        credential_iv=iv,
        status="deleted",  # hidden from the integrations UI; never scheduled
        scheduled_sync_enabled=False,
    )
    db.add(integ)
    db.flush()  # assign integ.id

    findings = _demo_findings(workspace_id, integ.id, actor_user_id)
    db.add_all(findings)
    db.flush()  # assign finding ids

    by_key = {f.finding_key: f for f in findings}
    for key, body in _DEMO_NOTES.items():
        f = by_key.get(key)
        if f is None:
            continue
        db.add(
            SecurityFindingNote(
                finding_id=f.id,
                workspace_id=workspace_id,
                author_user_id=actor_user_id,
                body=body,
            )
        )

    db.commit()
    logger.info(
        "security_demo_data: seeded workspace=%s findings=%d notes=%d",
        workspace_id, len(findings), len(_DEMO_NOTES),
    )
    return get_status(workspace_id, db)


def clear(*, workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Remove only demo-created security rows for the workspace.

    Deletes the demo findings' notes, the demo findings, and the hidden demo
    Integration. Real (non-demo) findings are never touched — they belong to
    real integrations.
    """
    integ = get_demo_integration(workspace_id, db)
    if integ is None:
        return {"cleared": False, "findings_deleted": 0, "notes_deleted": 0}

    findings = _demo_findings_in_workspace(workspace_id, integ, db)
    finding_ids = [f.id for f in findings]

    notes_deleted = 0
    if finding_ids:
        notes_deleted = (
            db.query(SecurityFindingNote)
            .filter(SecurityFindingNote.finding_id.in_(finding_ids))
            .delete(synchronize_session=False)
        )
    findings_deleted = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.integration_id == integ.id,
        )
        .delete(synchronize_session=False)
    )
    db.delete(integ)
    db.commit()
    logger.info(
        "security_demo_data: cleared workspace=%s findings=%d notes=%d",
        workspace_id, findings_deleted, notes_deleted,
    )
    return {
        "cleared": True,
        "findings_deleted": int(findings_deleted),
        "notes_deleted": int(notes_deleted),
    }
