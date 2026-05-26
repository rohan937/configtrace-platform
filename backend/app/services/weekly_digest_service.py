"""Weekly digest service — M58.15.

Computes, renders, and dispatches the weekly workspace drift report.

Architecture:
  - compute_digest(): assembles the WeeklyDigest object from DB + policy engine.
  - render_digest_email_body(): produces the plain-text email body.
  - send_digest_email(): sends to all workspace admin/owner members via email_service.
  - get_digest_settings() / update_digest_settings(): manage schedule config.
  - send_due_weekly_digests(now, db): scheduler entry point — call from a cron job.

Safety rules (permanent):
  - No raw prev_value / new_value string content in any digest output.
  - No credential values, tokens, or secrets.
  - No customer data (order IDs, payment info, email addresses of non-admins).
  - Language: "detected", "needs review", "policy violation" — never "breach".
  - Evidence: metadata-derived facts only.
  - send_digest_email() never raises — email failures are logged, not re-raised.

Scheduler integration:
  send_due_weekly_digests(now, db) is the intended entry point for an external
  cron job or scheduled worker (e.g. Celery beat, APScheduler, Lambda schedule).
  It is NOT automatically called by any HTTP handler — it must be wired up by
  the deployment operator.  A simple approach:

      # In a cron worker that runs every hour:
      from datetime import datetime, timezone
      from app.database import SessionLocal
      from app.services.weekly_digest_service import send_due_weekly_digests
      with SessionLocal() as db:
          send_due_weekly_digests(datetime.now(timezone.utc), db)
"""
from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.config import settings as app_settings
from app.schemas.weekly_digest import (
    WeeklyDigest,
    WeeklyDigestPolicyViolationEntry,
    WeeklyDigestPolicyViolations,
    WeeklyDigestProviderActivity,
    WeeklyDigestReviewCounts,
    WeeklyDigestRiskCounts,
    WeeklyDigestSettings,
    WeeklyDigestSettingsUpdateRequest,
    WeeklyDigestStaleIntegration,
    WeeklyDigestTestResponse,
    WeeklyDigestTopRisk,
)

logger = logging.getLogger(__name__)

# How many top-risk changes to include in the digest.
_TOP_RISKS_LIMIT = 5

# How many policy-violation changes to evaluate.  Capped to bound CPU cost.
_POLICY_EVAL_LIMIT = 50

# Integration staleness threshold (hours without a successful sync).
_STALE_HOURS = 48

# Minimum gap between digests (prevents double-sends within the same week).
_MIN_SEND_GAP_DAYS = 6

# Placeholder email patterns (Clerk dev users) — never send to these.
_PLACEHOLDER_PATTERNS = ("@clerk.user", "+clerk_test", "example.com")


# ── Record-type → provider mapping (mirrors riskAssistant._deriveProvider) ───

def _provider_from_record_type(rt: str) -> str:
    rt = (rt or "").lower()
    if rt.startswith("aws_"):       return "aws"
    if rt.startswith("github_"):    return "github"
    if rt.startswith("vercel_"):    return "vercel"
    if rt.startswith("stripe_"):    return "stripe"
    if rt.startswith("firebase_"):  return "firebase"
    if rt.startswith("supabase_"):  return "supabase"
    if rt.startswith("shopify_"):   return "shopify"
    if rt != "":                    return "cloudflare"
    return "unknown"


def _safe_title(change) -> str:
    """Build a safe plain-English change title from structural metadata only.

    Never interpolates raw prev_value / new_value strings.
    """
    rt = ((change.provider_metadata or {}).get("record_type") or "").lower()
    provider = _provider_from_record_type(rt)
    ct = (change.change_type or "modified").lower()
    record_id = change.record_identifier or "resource"

    ct_label = {"added": "added", "removed": "removed"}.get(ct, "modified")

    # Use provider + record type for the resource label
    if rt:
        resource_label = rt.replace("_", " ").title()
    else:
        resource_label = provider.title() + " resource"

    return f"{resource_label} {ct_label} — {record_id}"


def _is_placeholder_email(email: str) -> bool:
    return any(p in email.lower() for p in _PLACEHOLDER_PATTERNS)


# ── Settings CRUD ─────────────────────────────────────────────────────────────


def get_digest_settings(
    workspace_id: uuid.UUID,
    db: Session,
) -> WeeklyDigestSettings:
    """Return the weekly digest settings for a workspace.

    Creates a default notification-settings row (with digest disabled) if none exists.
    """
    from app.services.notification_service import get_or_create_notification_settings

    row = get_or_create_notification_settings(workspace_id, db)
    return _row_to_settings(workspace_id, row)


def update_digest_settings(
    workspace_id: uuid.UUID,
    body: WeeklyDigestSettingsUpdateRequest,
    db: Session,
) -> WeeklyDigestSettings:
    """Upsert weekly digest settings.  Caller owns db.commit()."""
    from app.services.notification_service import get_or_create_notification_settings

    row = get_or_create_notification_settings(workspace_id, db)

    if body.weekly_digest_enabled is not None:
        if body.weekly_digest_enabled not in (True, False):
            raise ValueError("weekly_digest_enabled must be a boolean.")
        row.weekly_digest_enabled = body.weekly_digest_enabled

    if body.weekly_digest_day is not None:
        if not (0 <= body.weekly_digest_day <= 6):
            raise ValueError("weekly_digest_day must be 0–6 (Monday–Sunday).")
        row.weekly_digest_day = body.weekly_digest_day

    if body.weekly_digest_hour is not None:
        if not (0 <= body.weekly_digest_hour <= 23):
            raise ValueError("weekly_digest_hour must be 0–23.")
        row.weekly_digest_hour = body.weekly_digest_hour

    if body.weekly_digest_timezone is not None:
        # Store as-is; validation is the caller's responsibility.
        # Null string → clear field.
        row.weekly_digest_timezone = body.weekly_digest_timezone or None

    db.add(row)
    db.flush()
    return _row_to_settings(workspace_id, row)


def _row_to_settings(workspace_id: uuid.UUID, row) -> WeeklyDigestSettings:
    return WeeklyDigestSettings(
        workspace_id=str(workspace_id),
        weekly_digest_enabled=bool(getattr(row, "weekly_digest_enabled", False)),
        weekly_digest_day=int(getattr(row, "weekly_digest_day", 0)),
        weekly_digest_hour=int(getattr(row, "weekly_digest_hour", 9)),
        weekly_digest_timezone=getattr(row, "weekly_digest_timezone", None),
        weekly_digest_last_sent_at=getattr(row, "weekly_digest_last_sent_at", None),
    )


# ── Digest computation ────────────────────────────────────────────────────────


def compute_digest(
    workspace_id: uuid.UUID,
    db: Session,
    *,
    period_start: Optional[datetime] = None,
    period_end: Optional[datetime] = None,
) -> WeeklyDigest:
    """Compute the full weekly digest for a workspace.

    Args:
        workspace_id:  Target workspace.
        db:            Active SQLAlchemy session.
        period_start:  Start of analysis window (inclusive). Default: now − 7d.
        period_end:    End of analysis window (inclusive). Default: now.

    Returns:
        WeeklyDigest with all sections populated.
    """
    from app.models.change import Change
    from app.models.change_review import ChangeReview
    from app.models.integration import Integration
    from app.models.workspace import Workspace, WorkspaceMember
    from app.models.user import User

    now = datetime.now(timezone.utc)
    if period_end is None:
        period_end = now
    if period_start is None:
        period_start = period_end - timedelta(days=7)

    # ── Workspace name ────────────────────────────────────────────────────────
    workspace = db.get(Workspace, workspace_id)
    workspace_name = workspace.name if workspace else str(workspace_id)

    # ── Load changes in window ────────────────────────────────────────────────
    rows = (
        db.query(Change, Integration)
        .join(Integration, Change.integration_id == Integration.id)
        .filter(
            Integration.workspace_id == workspace_id,
            Change.created_at >= period_start,
            Change.created_at <= period_end,
        )
        .all()
    )
    changes = [c for c, _ in rows]
    integration_map: dict[uuid.UUID, Integration] = {}
    for _, integ in rows:
        integration_map[integ.id] = integ

    total_changes = len(changes)

    # ── Risk counts ───────────────────────────────────────────────────────────
    risk_counter: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for c in changes:
        lvl = (c.risk_level or "low").lower()
        if lvl in risk_counter:
            risk_counter[lvl] += 1
    risk_counts = WeeklyDigestRiskCounts(**risk_counter)

    # ── Review counts ─────────────────────────────────────────────────────────
    review_map: dict[uuid.UUID, str] = {}
    if changes:
        change_ids = [c.id for c in changes]
        reviews = (
            db.query(ChangeReview)
            .filter(ChangeReview.change_id.in_(change_ids))
            .all()
        )
        review_map = {r.change_id: r.review_status for r in reviews}

    status_counter: dict[str, int] = {
        "needs_review": 0, "acknowledged": 0, "expected": 0, "snoozed": 0
    }
    for c in changes:
        status = review_map.get(c.id, "needs_review")
        if status in status_counter:
            status_counter[status] += 1
        else:
            status_counter["needs_review"] += 1
    review_counts = WeeklyDigestReviewCounts(**status_counter)

    # Review completion rate: % of changes that are NOT needs_review
    reviewed = total_changes - status_counter["needs_review"]
    review_completion_rate = (reviewed / total_changes) if total_changes > 0 else 1.0

    # ── Provider activity ─────────────────────────────────────────────────────
    provider_change_count: dict[str, int] = defaultdict(int)
    provider_high_count: dict[str, int] = defaultdict(int)
    for c, integ in rows:
        provider = integ.provider or _provider_from_record_type(
            (c.provider_metadata or {}).get("record_type", "")
        )
        provider_change_count[provider] += 1
        if (c.risk_level or "").lower() in ("high", "critical"):
            provider_high_count[provider] += 1

    provider_activity = [
        WeeklyDigestProviderActivity(
            provider=p,
            change_count=cnt,
            high_or_critical_count=provider_high_count[p],
        )
        for p, cnt in sorted(provider_change_count.items(), key=lambda x: -x[1])
    ]

    # ── Policy violations ─────────────────────────────────────────────────────
    policy_violations = _compute_policy_violations(workspace_id, changes, db)

    # ── Top risks ─────────────────────────────────────────────────────────────
    base_url = app_settings.APP_BASE_URL.rstrip("/")
    top_risks = _compute_top_risks(
        changes, review_map, base_url, limit=_TOP_RISKS_LIMIT
    )

    # ── Stale integrations ────────────────────────────────────────────────────
    workspace_integrations = (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.status != "deleted",
        )
        .all()
    )
    stale_integrations = _find_stale_integrations(workspace_integrations, now)

    # ── Recommended actions ───────────────────────────────────────────────────
    recommended_actions = _build_recommended_actions(
        review_counts=review_counts,
        policy_violations=policy_violations,
        stale_integrations=stale_integrations,
    )

    return WeeklyDigest(
        workspace_id=str(workspace_id),
        workspace_name=workspace_name,
        period_start=period_start,
        period_end=period_end,
        generated_at=now,
        total_changes=total_changes,
        risk_counts=risk_counts,
        review_counts=review_counts,
        review_completion_rate=round(review_completion_rate, 4),
        policy_violations=policy_violations,
        provider_activity=provider_activity,
        top_risks=top_risks,
        stale_integrations=stale_integrations,
        recommended_actions=recommended_actions,
    )


def _compute_policy_violations(
    workspace_id: uuid.UUID,
    changes: list,
    db: Session,
) -> WeeklyDigestPolicyViolations:
    """Evaluate policy engine against the top N changes and aggregate results."""
    from app.services.policy_engine_service import (
        BUILT_IN_POLICIES,
        evaluate_change,
        _get_workspace_overrides,
    )

    # Build enabled key set
    overrides = _get_workspace_overrides(workspace_id, db)
    enabled_keys: set[str] = {
        p.key for p in BUILT_IN_POLICIES
        if overrides.get(p.key, p.enabled_by_default)
    }

    # Evaluate only high/critical + up to limit total to bound CPU
    priority = [c for c in changes if (c.risk_level or "").lower() in ("high", "critical")]
    others = [c for c in changes if c not in set(priority)]
    eval_changes = (priority + others)[:_POLICY_EVAL_LIMIT]

    policy_count: dict[str, int] = defaultdict(int)
    policy_meta: dict[str, tuple[str, str]] = {}  # key → (name, severity)
    total = 0

    for change in eval_changes:
        violations = evaluate_change(change, enabled_keys)
        for v in violations:
            policy_count[v.policy_key] += 1
            policy_meta[v.policy_key] = (v.name, v.severity)
            total += 1

    top_policies = [
        WeeklyDigestPolicyViolationEntry(
            policy_key=k,
            name=policy_meta[k][0],
            count=cnt,
            severity=policy_meta[k][1],
        )
        for k, cnt in sorted(policy_count.items(), key=lambda x: -x[1])
    ][:5]

    return WeeklyDigestPolicyViolations(total=total, top_policies=top_policies)


def _compute_top_risks(
    changes: list,
    review_map: dict,
    base_url: str,
    *,
    limit: int,
) -> list[WeeklyDigestTopRisk]:
    """Return top N changes sorted by criticality + review status."""

    def _sort_key(c):
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        status_order = {"needs_review": 0, "snoozed": 1, "acknowledged": 2, "expected": 3}
        lvl = risk_order.get((c.risk_level or "").lower(), 3)
        status = review_map.get(c.id, "needs_review")
        sts = status_order.get(status, 4)
        # Newer changes before older ones within the same bucket
        ts = c.created_at.timestamp() if c.created_at else 0
        return (lvl, sts, -ts)

    sorted_changes = sorted(changes, key=_sort_key)[:limit]

    result = []
    for c in sorted_changes:
        status = review_map.get(c.id, "needs_review")
        result.append(
            WeeklyDigestTopRisk(
                change_id=str(c.id),
                title=_safe_title(c),
                provider=_provider_from_record_type(
                    (c.provider_metadata or {}).get("record_type", "")
                ),
                risk_level=(c.risk_level or "").lower(),
                status=status,
                url=f"{base_url}/changes/{c.id}",
            )
        )
    return result


def _find_stale_integrations(
    integrations: list,
    now: datetime,
) -> list[WeeklyDigestStaleIntegration]:
    """Return integrations that appear to be stale or unhealthy."""
    stale = []
    cutoff = now - timedelta(hours=_STALE_HOURS)
    for i in integrations:
        is_stale = (
            i.last_synced_at is None
            or i.last_synced_at < cutoff
            or (i.consecutive_failure_count or 0) >= 2
        )
        if is_stale:
            stale.append(
                WeeklyDigestStaleIntegration(
                    integration_id=str(i.id),
                    provider=i.provider or "unknown",
                    name=i.display_name or i.provider or "Unknown",
                    last_synced_at=i.last_synced_at,
                    consecutive_failure_count=i.consecutive_failure_count or 0,
                )
            )
    return stale


def _build_recommended_actions(
    *,
    review_counts: WeeklyDigestReviewCounts,
    policy_violations: WeeklyDigestPolicyViolations,
    stale_integrations: list[WeeklyDigestStaleIntegration],
) -> list[str]:
    """Generate deterministic recommended action strings.

    Never includes commands, credentials, or customer data.
    """
    actions: list[str] = []

    unreviewed = review_counts.needs_review
    if unreviewed > 0:
        s = "" if unreviewed == 1 else "s"
        actions.append(
            f"Review {unreviewed} unacknowledged change{s} that still "
            "need{s} attention.".replace("{s}", s)
        )

    if policy_violations.total > 0:
        for entry in policy_violations.top_policies[:2]:
            actions.append(
                f"Resolve policy violation: {entry.name} "
                f"({entry.count} change{'s' if entry.count != 1 else ''} affected)."
            )
        if policy_violations.total > 2 and len(policy_violations.top_policies) > 2:
            remaining = policy_violations.total - sum(
                e.count for e in policy_violations.top_policies[:2]
            )
            if remaining > 0:
                actions.append(
                    f"Investigate {remaining} additional policy violation"
                    f"{'s' if remaining != 1 else ''} in the Policy Violations panel."
                )

    if stale_integrations:
        n = len(stale_integrations)
        s = "" if n == 1 else "s"
        names = ", ".join(i.name for i in stale_integrations[:3])
        suffix = f" and {n - 3} more" if n > 3 else ""
        actions.append(
            f"Reconnect or investigate {n} stale integration{s}: "
            f"{names}{suffix}."
        )

    if review_counts.snoozed > 0:
        s = "" if review_counts.snoozed == 1 else "s"
        actions.append(
            f"Review {review_counts.snoozed} snoozed change{s} — "
            f"confirm they are still deferred intentionally."
        )

    if not actions:
        actions.append(
            "No immediate actions required. All changes are reviewed and "
            "integrations are healthy."
        )

    return actions


# ── Email render ──────────────────────────────────────────────────────────────


def render_digest_email_body(digest: WeeklyDigest) -> str:
    """Render the digest as a plain-text email body.

    Safety rules:
      - No raw prev_value / new_value.
      - No credentials, tokens, or secret values.
      - No customer data.
      - Uses "detected", "needs review", "policy violation" language.
    """
    lines: list[str] = []

    def _line(text: str = "") -> None:
        lines.append(text)

    def _hr() -> None:
        lines.append("─" * 60)

    period_start = digest.period_start.strftime("%b %-d")
    period_end = digest.period_end.strftime("%b %-d, %Y")

    _line(f"ConfigTrace Weekly Drift Report — {digest.workspace_name}")
    _line(f"Period: {period_start} – {period_end}")
    _line()
    _hr()

    # ── Executive summary ─────────────────────────────────────────────────────
    _line("SUMMARY")
    _line()
    _line(f"  {digest.total_changes} configuration changes detected")
    rc = digest.risk_counts
    if rc.critical > 0:
        _line(f"  {rc.critical} critical-risk change{'s' if rc.critical != 1 else ''}")
    if rc.high > 0:
        _line(f"  {rc.high} high-risk change{'s' if rc.high != 1 else ''}")
    if rc.medium > 0:
        _line(f"  {rc.medium} medium-risk change{'s' if rc.medium != 1 else ''}")
    _line(f"  {digest.policy_violations.total} policy violation{'s' if digest.policy_violations.total != 1 else ''} detected")
    _line(f"  {digest.review_counts.needs_review} change{'s' if digest.review_counts.needs_review != 1 else ''} still needs review")
    _line(f"  Review completion rate: {round(digest.review_completion_rate * 100)}%")
    _line()

    # ── Provider activity ─────────────────────────────────────────────────────
    if digest.provider_activity:
        _hr()
        _line("PROVIDER ACTIVITY")
        _line()
        for p in digest.provider_activity[:6]:
            high_note = (
                f"  ({p.high_or_critical_count} high/critical)"
                if p.high_or_critical_count > 0 else ""
            )
            _line(f"  {p.provider.upper():12s}  {p.change_count} change{'s' if p.change_count != 1 else ''}{high_note}")
        _line()

    # ── Policy violations ─────────────────────────────────────────────────────
    if digest.policy_violations.total > 0:
        _hr()
        _line("POLICY VIOLATIONS")
        _line()
        _line(f"  {digest.policy_violations.total} violation{'s' if digest.policy_violations.total != 1 else ''} detected in this period.")
        _line()
        for entry in digest.policy_violations.top_policies:
            _line(f"  [{entry.severity.upper()}]  {entry.name} — {entry.count} change{'s' if entry.count != 1 else ''}")
        _line()

    # ── Changes needing review ────────────────────────────────────────────────
    if digest.review_counts.needs_review > 0:
        _hr()
        _line("NEEDS REVIEW")
        _line()
        _line(f"  {digest.review_counts.needs_review} change{'s' if digest.review_counts.needs_review != 1 else ''} need attention.")
        _line()

    # ── Top risks ─────────────────────────────────────────────────────────────
    if digest.top_risks:
        _hr()
        _line("TOP RISKS")
        _line()
        for risk in digest.top_risks:
            status_label = {
                "needs_review": "Needs review",
                "acknowledged": "Acknowledged",
                "expected":     "Expected",
                "snoozed":      "Snoozed",
            }.get(risk.status, risk.status.replace("_", " ").title())
            _line(f"  [{risk.risk_level.upper()}]  {risk.title}")
            _line(f"           Status: {status_label}")
            _line(f"           URL:    {risk.url}")
            _line()

    # ── Stale integrations ────────────────────────────────────────────────────
    if digest.stale_integrations:
        _hr()
        _line("STALE INTEGRATIONS")
        _line()
        for si in digest.stale_integrations:
            last = (
                si.last_synced_at.strftime("%b %-d, %Y %H:%M UTC")
                if si.last_synced_at else "Never synced"
            )
            _line(f"  {si.name} ({si.provider}) — last sync: {last}")
        _line()

    # ── Recommended actions ───────────────────────────────────────────────────
    _hr()
    _line("RECOMMENDED ACTIONS")
    _line()
    for i, action in enumerate(digest.recommended_actions, 1):
        _line(f"  {i}. {action}")
    _line()

    # ── CTAs ──────────────────────────────────────────────────────────────────
    base_url = app_settings.APP_BASE_URL.rstrip("/")
    _hr()
    _line("NEXT STEPS")
    _line()
    _line(f"  Open dashboard:    {base_url}/dashboard")
    _line(f"  Open needs review: {base_url}/changes?review=needs_review")
    _line()
    _hr()
    _line()
    _line(
        "This digest is generated from configuration metadata detected by "
        "ConfigTrace. It does not contain customer data, credentials, raw "
        "configuration values, or compliance determinations."
    )
    _line(
        "To unsubscribe, disable weekly digest in: "
        f"{base_url}/settings/workspace/notifications"
    )

    return "\n".join(lines)


# ── Email dispatch ────────────────────────────────────────────────────────────


def _get_admin_emails(workspace_id: uuid.UUID, db: Session) -> list[str]:
    """Return non-placeholder email addresses of workspace admin/owner members."""
    from app.models.workspace import WorkspaceMember
    from app.models.user import User

    members = (
        db.query(WorkspaceMember)
        .filter(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.role.in_(["admin", "owner"]),
        )
        .all()
    )

    emails: list[str] = []
    for m in members:
        user = db.get(User, m.user_id)
        if user and user.email and not _is_placeholder_email(user.email):
            emails.append(user.email)
    return list(set(emails))  # deduplicate


def send_digest_email(
    workspace_id: uuid.UUID,
    db: Session,
    *,
    digest: Optional[WeeklyDigest] = None,
    recipient_override: Optional[str] = None,
) -> dict:
    """Send the weekly digest to workspace admins (or recipient_override).

    Never raises — failures are logged.

    Returns:
        {"sent": int, "failed": int, "skipped": int, "body": str}
    """
    from app.services.email_service import EmailNotConfigured, EmailSendError
    from app.services import email_service

    if digest is None:
        digest = compute_digest(workspace_id, db)

    body = render_digest_email_body(digest)
    subject = f"ConfigTrace Weekly Drift Report — {digest.workspace_name}"

    if recipient_override:
        recipients = [recipient_override]
    else:
        recipients = _get_admin_emails(workspace_id, db)

    result = {"sent": 0, "failed": 0, "skipped": 0, "body": body}

    if not recipients:
        logger.info(
            "weekly_digest: no deliverable admin recipients for workspace=%s — skipping",
            workspace_id,
        )
        result["skipped"] = 1
        return result

    for email in recipients:
        try:
            email_service.send_email(to=email, subject=subject, body=body)
            result["sent"] += 1
            logger.info(
                "weekly_digest: sent  workspace=%s  recipient=****",
                workspace_id,
            )
        except EmailNotConfigured:
            logger.info(
                "weekly_digest: email not configured — skipping workspace=%s",
                workspace_id,
            )
            result["skipped"] += 1
            break  # Don't try remaining recipients if service isn't configured
        except EmailSendError as exc:
            logger.error(
                "weekly_digest: send failed  workspace=%s  error=%r",
                workspace_id, exc,
            )
            result["failed"] += 1
        except Exception as exc:
            logger.error(
                "weekly_digest: unexpected error  workspace=%s  error=%r",
                workspace_id, exc,
            )
            result["failed"] += 1

    return result


def send_and_record_digest(
    workspace_id: uuid.UUID,
    db: Session,
    *,
    settings_row,
) -> dict:
    """Send the digest and update weekly_digest_last_sent_at on success.

    Caller must commit after calling this function.
    """
    result = send_digest_email(workspace_id, db)
    if result["sent"] > 0:
        settings_row.weekly_digest_last_sent_at = datetime.now(timezone.utc)
        db.add(settings_row)
        db.flush()
    return result


# ── Test send helper ──────────────────────────────────────────────────────────


def test_send_digest(
    workspace_id: uuid.UUID,
    requesting_user_id: uuid.UUID,
    db: Session,
) -> WeeklyDigestTestResponse:
    """Send a test digest to the requesting user's email (admin).

    If email is not configured, returns the rendered body without sending.
    """
    from app.models.user import User
    from app.services.email_service import EmailNotConfigured, EmailSendError
    from app.services import email_service

    digest = compute_digest(workspace_id, db)
    body = render_digest_email_body(digest)
    subject = f"[TEST] ConfigTrace Weekly Drift Report — {digest.workspace_name}"

    # Resolve recipient — use requesting user's email
    user = db.get(User, requesting_user_id)
    recipient = user.email if user and user.email else None
    email_configured = bool(email_service.settings.is_email_alerting_configured)

    if not email_configured:
        return WeeklyDigestTestResponse(
            sent=False,
            recipient=None,
            email_configured=False,
            preview_body=body,
            error="Email alerting is not configured (RESEND_API_KEY / ALERTS_FROM_EMAIL missing).",
        )

    if not recipient or _is_placeholder_email(recipient):
        return WeeklyDigestTestResponse(
            sent=False,
            recipient=None,
            email_configured=True,
            preview_body=body,
            error="No deliverable email address found for your user account.",
        )

    try:
        email_service.send_email(to=recipient, subject=subject, body=body)
        # Mask recipient for response
        masked = _mask_email(recipient)
        return WeeklyDigestTestResponse(
            sent=True,
            recipient=masked,
            email_configured=True,
            preview_body=body,
            error=None,
        )
    except (EmailNotConfigured, EmailSendError) as exc:
        return WeeklyDigestTestResponse(
            sent=False,
            recipient=_mask_email(recipient),
            email_configured=True,
            preview_body=body,
            error=str(exc),
        )


def _mask_email(email: str) -> str:
    """Mask an email address: 'user@example.com' → 'use****@example.com'."""
    if "@" not in email:
        return "****"
    local, domain = email.split("@", 1)
    masked_local = local[:3] + "****" if len(local) > 3 else "****"
    return f"{masked_local}@{domain}"


# ── Scheduler entry point ─────────────────────────────────────────────────────


def send_due_weekly_digests(
    now: datetime,
    db: Session,
) -> dict:
    """Check all workspaces for due weekly digests and send them.

    This function is the intended entry point for a scheduled cron job.
    Call it once per hour at minimum; it is idempotent within a given day/hour.

    Returns:
        {"checked": int, "sent": int, "skipped": int, "failed": int}
    """
    from app.models.notification_settings import WorkspaceNotificationSettings

    result = {"checked": 0, "sent": 0, "skipped": 0, "failed": 0}

    enabled_rows = (
        db.query(WorkspaceNotificationSettings)
        .filter(WorkspaceNotificationSettings.weekly_digest_enabled.is_(True))
        .all()
    )

    for row in enabled_rows:
        result["checked"] += 1
        try:
            if not _is_due(row, now):
                result["skipped"] += 1
                continue

            workspace_id = row.workspace_id
            send_result = send_and_record_digest(
                workspace_id,
                db,
                settings_row=row,
            )
            if send_result["sent"] > 0:
                result["sent"] += 1
                db.commit()
                logger.info(
                    "weekly_digest: sent for workspace=%s", workspace_id
                )
            elif send_result["failed"] > 0:
                result["failed"] += 1
            else:
                result["skipped"] += 1

        except Exception as exc:
            result["failed"] += 1
            logger.error(
                "weekly_digest: scheduler error workspace=%s error=%r",
                getattr(row, "workspace_id", "?"), exc,
            )

    return result


def _is_due(row, now: datetime) -> bool:
    """Return True if the digest is due to be sent right now.

    Due when:
      1. today's weekday matches weekly_digest_day (0=Monday)
      2. current hour matches weekly_digest_hour
      3. no digest sent in the last _MIN_SEND_GAP_DAYS days
    """
    # Weekday check (Python weekday(): Monday=0)
    if now.weekday() != int(getattr(row, "weekly_digest_day", 0)):
        return False

    # Hour check (UTC)
    if now.hour != int(getattr(row, "weekly_digest_hour", 9)):
        return False

    # Gap check — don't double-send in same week
    last_sent = getattr(row, "weekly_digest_last_sent_at", None)
    if last_sent is not None:
        gap = now - last_sent
        if gap.days < _MIN_SEND_GAP_DAYS:
            return False

    return True
