"""Drift Control Score service — M58.17.

Computes a deterministic, on-demand Drift Control Score (0–100) for a
workspace.  The score measures how well the team controls risky
configuration drift — it is NOT a compliance score, security rating,
or breach-risk indicator.

Architecture
------------
``compute_drift_score(workspace_id, db)``
  Main entry point.  Calls ``_fetch_inputs`` to gather all raw data from the
  DB, then delegates to ``_compute_score_from_inputs`` for pure logic.

``_ScoreInputs``
  Dataclass holding all pre-fetched metrics.  Decouples DB I/O from scoring
  so the scoring function is directly unit-testable without a live database.

``_compute_score_from_inputs(inputs)``
  Pure function: ``_ScoreInputs → DriftScoreResponse``.  All test cases target
  this function.

Scoring model (start from 100, subtract penalties)
---------------------------------------------------
Penalty factor                  | Per-item | Cap
--------------------------------|----------|-----
Unreviewed critical change      | -12      | -30
Unreviewed high change          | -8       | -24
Policy violation (last 7d)      | -10      | -30
Stale / failing integration     | -8       | -20
No alert channels at all        | -15      | n/a
Push-only (no Slack/webhook)    | -5       | n/a
No policies enabled             | -8       | n/a
Review completion rate < 50%    | -15      | n/a
Review completion rate < 75%    | -8       | n/a
No providers connected          | score cap = 40

Final score is clamped to [0, 100].

Grade thresholds
----------------
90–100 → strong
75–89  → good
55–74  → needs_attention
0–54   → weak

Safety rules (permanent)
------------------------
* No raw prev_value / new_value content in any output.
* No credential values, tokens, or secrets.
* No customer data (email addresses of non-admins, order IDs, etc.).
* Language: "detected", "needs review", "drift control" — never
  "breach", "compliance grade", "SOC2 score", "security rating".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.change import Change
from app.models.change_review import ChangeReview
from app.models.expected_change_window import ExpectedChangeWindow
from app.models.integration import Integration
from app.models.notification_settings import WorkspaceNotificationSettings
from app.models.push_subscription import WorkspacePushSubscription
from app.models.workspace_policy import WorkspacePolicy
from app.schemas.drift_score import (
    DriftScoreFactor,
    DriftScoreMetrics,
    DriftScoreResponse,
)

# ── Constants ─────────────────────────────────────────────────────────────────

_PERIOD_DAYS = 7
_STALE_HOURS = 48           # same definition as weekly_digest_service
_STALE_FAILURES = 2         # consecutive_failure_count ≥ this → stale
_POLICY_EVAL_LIMIT = 30     # evaluate policy violations on top N high-risk changes


# ── Score inputs dataclass ─────────────────────────────────────────────────────


@dataclass
class _ScoreInputs:
    """All metrics needed to compute the score — no DB session required."""

    # Integrations
    providers_connected: int
    stale_integration_count: int

    # Changes
    total_changes_7d: int
    high_critical_changes_7d: int
    unreviewed_critical_count: int
    unreviewed_high_count: int

    # Review quality
    review_completion_rate: float   # 0.0–1.0

    # Policy engine
    policy_violations_7d: int
    any_policies_enabled: bool      # False if all built-in policies are disabled

    # Alert channels
    slack_app_configured: bool
    legacy_slack_configured: bool
    webhook_configured: bool
    push_configured: bool
    weekly_digest_enabled: bool

    # Expected change windows
    approved_window_count: int


# ── Public entry point ────────────────────────────────────────────────────────


def compute_drift_score(workspace_id: uuid.UUID, db: Session) -> DriftScoreResponse:
    """Compute and return the Drift Control Score for *workspace_id*.

    Args:
        workspace_id: UUID of the workspace to score.
        db:           Active SQLAlchemy session.

    Returns:
        A :class:`DriftScoreResponse` with score, grade, factors, and metrics.
    """
    inputs = _fetch_inputs(workspace_id, db)
    return _compute_score_from_inputs(inputs)


# ── Data collection ───────────────────────────────────────────────────────────


def _fetch_inputs(workspace_id: uuid.UUID, db: Session) -> _ScoreInputs:
    """Load all data needed for scoring in a minimal number of DB queries."""
    now = datetime.now(timezone.utc)
    since_7d = now - timedelta(days=_PERIOD_DAYS)
    stale_cutoff = now - timedelta(hours=_STALE_HOURS)

    # ── 1. Integrations ──────────────────────────────────────────────────────
    integrations = (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.status != "deleted",
        )
        .all()
    )
    providers_connected = len(integrations)

    stale_integrations = [
        i for i in integrations
        if _is_stale_integration(i, stale_cutoff)
    ]
    stale_integration_count = len(stale_integrations)

    integration_ids = [i.id for i in integrations]

    # ── 2. Changes (last 7 days) ─────────────────────────────────────────────
    if not integration_ids:
        recent_changes: list[Change] = []
        total_changes_7d = 0
        high_critical_changes_7d = 0
    else:
        recent_changes = (
            db.query(Change)
            .filter(
                Change.integration_id.in_(integration_ids),
                Change.created_at >= since_7d,
            )
            .all()
        )
        total_changes_7d = len(recent_changes)
        high_critical_changes_7d = sum(
            1 for c in recent_changes if c.risk_level in ("high", "critical")
        )

    # ── 3. Review states ─────────────────────────────────────────────────────
    unreviewed_critical = 0
    unreviewed_high = 0
    reviewed_high_critical = 0

    if recent_changes:
        change_ids = [c.id for c in recent_changes]
        review_rows = (
            db.query(ChangeReview)
            .filter(ChangeReview.change_id.in_(change_ids))
            .all()
        )
        review_map = {r.change_id: r for r in review_rows}

        for c in recent_changes:
            if c.risk_level not in ("high", "critical"):
                continue
            r = review_map.get(c.id)
            status = r.review_status if r else "needs_review"
            if status in ("acknowledged", "expected"):
                reviewed_high_critical += 1
            else:
                # needs_review, snoozed, or no row → unreviewed
                if c.risk_level == "critical":
                    unreviewed_critical += 1
                else:
                    unreviewed_high += 1

    review_completion_rate = (
        reviewed_high_critical / high_critical_changes_7d
        if high_critical_changes_7d > 0
        else 1.0
    )

    # ── 4. Policy violations ─────────────────────────────────────────────────
    policy_violations_7d = 0
    any_policies_enabled = True

    if recent_changes:
        # Load workspace policy overrides
        disabled_policy_rows = (
            db.query(WorkspacePolicy)
            .filter(
                WorkspacePolicy.workspace_id == workspace_id,
                WorkspacePolicy.enabled.is_(False),
            )
            .all()
        )
        disabled_keys = {row.policy_key for row in disabled_policy_rows}

        # Check if all policies have been disabled (unusual edge case)
        from app.services.policy_engine_service import get_catalog, evaluate_change
        all_keys = {p.key for p in get_catalog()}
        enabled_keys = all_keys - disabled_keys
        any_policies_enabled = bool(enabled_keys)

        if any_policies_enabled and enabled_keys:
            # Evaluate top N high/critical changes to count violations
            top_changes = sorted(
                [c for c in recent_changes if c.risk_level in ("high", "critical")],
                key=lambda c: (0 if c.risk_level == "critical" else 1, -c.created_at.timestamp()),
            )[:_POLICY_EVAL_LIMIT]

            violation_set: set[str] = set()  # policy keys violated
            for c in top_changes:
                violations = evaluate_change(c, enabled_keys)
                for v in violations:
                    violation_set.add(v.policy_key)
            policy_violations_7d = len(violation_set)

    # ── 5. Notification settings ─────────────────────────────────────────────
    notif = (
        db.query(WorkspaceNotificationSettings)
        .filter(WorkspaceNotificationSettings.workspace_id == workspace_id)
        .first()
    )

    slack_app_configured = bool(
        notif
        and notif.slack_app_enabled
        and notif.slack_bot_token_encrypted is not None
        and notif.slack_channel_id is not None
    )
    legacy_slack_configured = bool(
        notif
        and notif.slack_enabled
        and notif.slack_webhook_url_encrypted is not None
    )
    webhook_configured = bool(
        notif
        and notif.webhook_enabled
        and notif.webhook_url_encrypted is not None
    )
    weekly_digest_enabled = bool(notif and notif.weekly_digest_enabled)

    # ── 6. Push subscriptions ────────────────────────────────────────────────
    push_count = (
        db.query(func.count(WorkspacePushSubscription.id))
        .filter(
            WorkspacePushSubscription.workspace_id == workspace_id,
            WorkspacePushSubscription.enabled.is_(True),
        )
        .scalar()
    ) or 0
    push_configured = push_count > 0

    # ── 7. Expected change windows ───────────────────────────────────────────
    approved_window_count = (
        db.query(func.count(ExpectedChangeWindow.id))
        .filter(
            ExpectedChangeWindow.workspace_id == workspace_id,
            ExpectedChangeWindow.status == "approved",
        )
        .scalar()
    ) or 0

    return _ScoreInputs(
        providers_connected=providers_connected,
        stale_integration_count=stale_integration_count,
        total_changes_7d=total_changes_7d,
        high_critical_changes_7d=high_critical_changes_7d,
        unreviewed_critical_count=unreviewed_critical,
        unreviewed_high_count=unreviewed_high,
        review_completion_rate=review_completion_rate,
        policy_violations_7d=policy_violations_7d,
        any_policies_enabled=any_policies_enabled,
        slack_app_configured=slack_app_configured,
        legacy_slack_configured=legacy_slack_configured,
        webhook_configured=webhook_configured,
        push_configured=push_configured,
        weekly_digest_enabled=weekly_digest_enabled,
        approved_window_count=approved_window_count,
    )


# ── Scoring logic (pure function — directly unit-testable) ────────────────────


def _compute_score_from_inputs(inputs: _ScoreInputs) -> DriftScoreResponse:
    """Compute score, grade, factors, and recommendations from pre-fetched inputs.

    This function contains no DB calls — it is safe to test directly by
    constructing a ``_ScoreInputs`` dataclass.
    """
    score = 100
    factors: list[DriftScoreFactor] = []
    positive_signals: list[str] = []
    recommended_actions: list[str] = []
    no_providers = inputs.providers_connected == 0

    # ── No providers connected → hard cap ────────────────────────────────────
    if no_providers:
        # Cap enforced at the end; record the factor now.
        factors.append(DriftScoreFactor(
            key="no_providers",
            label="No providers connected",
            impact=-60,
            status="critical",
            detail=(
                "No integrations are connected. "
                "Connect a provider to start monitoring configuration drift."
            ),
            action_label="Connect integration",
            action_href="/integrations",
        ))
        recommended_actions.append(
            "Connect at least one provider integration to begin monitoring drift."
        )

    # ── Unreviewed critical changes ───────────────────────────────────────────
    if inputs.unreviewed_critical_count > 0:
        n = inputs.unreviewed_critical_count
        penalty = min(n * 12, 30)
        score -= penalty
        factors.append(DriftScoreFactor(
            key="unreviewed_critical",
            label="Unreviewed critical changes",
            impact=-penalty,
            status="critical",
            detail=(
                f"{n} critical change{'s' if n != 1 else ''} "
                f"still need{'s' if n == 1 else ''} review."
            ),
            action_label="Open Needs Review",
            action_href="/needs-review",
        ))
        recommended_actions.append(
            f"Review {n} critical change{'s' if n != 1 else ''}."
        )

    # ── Unreviewed high-risk changes ──────────────────────────────────────────
    if inputs.unreviewed_high_count > 0:
        n = inputs.unreviewed_high_count
        penalty = min(n * 8, 24)
        score -= penalty
        factors.append(DriftScoreFactor(
            key="unreviewed_high",
            label="Unreviewed high-risk changes",
            impact=-penalty,
            status="needs_attention",
            detail=(
                f"{n} high-risk change{'s' if n != 1 else ''} "
                f"still need{'s' if n == 1 else ''} review."
            ),
            action_label="Open Needs Review",
            action_href="/needs-review",
        ))
        recommended_actions.append(
            f"Review {n} high-risk change{'s' if n != 1 else ''}."
        )

    # ── Policy violations ─────────────────────────────────────────────────────
    if inputs.policy_violations_7d > 0:
        n = inputs.policy_violations_7d
        penalty = min(n * 10, 30)
        score -= penalty
        factors.append(DriftScoreFactor(
            key="policy_violations",
            label="Policy violations detected",
            impact=-penalty,
            status="needs_attention",
            detail=(
                f"{n} distinct policy violation{'s' if n != 1 else ''} "
                f"found in the last {_PERIOD_DAYS} days."
            ),
            action_label="Review changes",
            action_href="/timeline",
        ))
        recommended_actions.append(
            f"Address {n} policy violation{'s' if n != 1 else ''}."
        )
    elif inputs.any_policies_enabled:
        positive_signals.append("Policy engine enabled — no violations detected")

    # ── Stale / failing integrations ──────────────────────────────────────────
    if inputs.stale_integration_count > 0:
        n = inputs.stale_integration_count
        penalty = min(n * 8, 20)
        score -= penalty
        plural = "s" if n != 1 else ""
        have = "have" if n != 1 else "has"
        factors.append(DriftScoreFactor(
            key="stale_integrations",
            label="Stale or failing integrations",
            impact=-penalty,
            status="needs_attention",
            detail=(
                f"{n} integration{plural} {have} not synced recently "
                f"or {have} repeated failures."
            ),
            action_label="View integrations",
            action_href="/integrations",
        ))
        recommended_actions.append(
            f"Reconnect {n} stale integration{plural}."
        )
    elif inputs.providers_connected > 0:
        positive_signals.append("All integrations are healthy")

    # ── Alert channels ────────────────────────────────────────────────────────
    has_proactive = (
        inputs.slack_app_configured
        or inputs.legacy_slack_configured
        or inputs.webhook_configured
    )
    has_any_alert = has_proactive or inputs.push_configured

    if not has_any_alert:
        score -= 15
        factors.append(DriftScoreFactor(
            key="no_alert_channels",
            label="No alert channels configured",
            impact=-15,
            status="needs_attention",
            detail=(
                "No Slack, webhook, or browser push notification channels "
                "are configured. You may miss critical drift events."
            ),
            action_label="Configure alerts",
            action_href="/settings/workspace/notifications",
        ))
        recommended_actions.append(
            "Configure at least one alert channel (Slack App, webhook, or browser push)."
        )
    elif not has_proactive:
        # Push only — no persistent team channel
        score -= 5
        factors.append(DriftScoreFactor(
            key="limited_alert_channels",
            label="Limited alert channels",
            impact=-5,
            status="needs_attention",
            detail=(
                "Only browser push notifications are configured. "
                "Consider adding a Slack channel or webhook for reliable team alerts."
            ),
            action_label="Configure alerts",
            action_href="/settings/workspace/notifications",
        ))
    else:
        if inputs.slack_app_configured:
            positive_signals.append("Slack App alerts enabled")
        elif inputs.legacy_slack_configured:
            positive_signals.append("Slack webhook alerts enabled")
        if inputs.webhook_configured:
            positive_signals.append("Webhook alerts enabled")

    if inputs.push_configured:
        positive_signals.append("Browser push notifications enabled")

    if inputs.weekly_digest_enabled:
        positive_signals.append("Weekly security digest enabled")

    # ── Review completion rate ────────────────────────────────────────────────
    if inputs.high_critical_changes_7d > 0:
        rate = inputs.review_completion_rate
        rate_pct = int(rate * 100)
        if rate < 0.50:
            score -= 15
            factors.append(DriftScoreFactor(
                key="low_review_rate",
                label="Low review completion rate",
                impact=-15,
                status="critical",
                detail=(
                    f"Only {rate_pct}% of high/critical changes from the last "
                    f"{_PERIOD_DAYS} days have been reviewed."
                ),
                action_label="Open Needs Review",
                action_href="/needs-review",
            ))
        elif rate < 0.75:
            score -= 8
            factors.append(DriftScoreFactor(
                key="low_review_rate",
                label="Review completion rate below 75%",
                impact=-8,
                status="needs_attention",
                detail=(
                    f"{rate_pct}% of high/critical changes from the last "
                    f"{_PERIOD_DAYS} days have been reviewed."
                ),
                action_label="Open Needs Review",
                action_href="/needs-review",
            ))
        else:
            positive_signals.append(
                f"Strong review completion rate ({rate_pct}% of "
                f"high/critical changes reviewed)"
            )

    # ── Policies not enabled ──────────────────────────────────────────────────
    if not inputs.any_policies_enabled:
        score -= 8
        factors.append(DriftScoreFactor(
            key="no_policies",
            label="Policy engine disabled",
            impact=-8,
            status="needs_attention",
            detail=(
                "All built-in policies are disabled for this workspace. "
                "Enable policies to detect known risky drift patterns."
            ),
            action_label="Configure policies",
            action_href="/settings/workspace/policies",
        ))
        recommended_actions.append(
            "Enable built-in policies to automatically flag risky configuration patterns."
        )

    # ── Expected change windows ───────────────────────────────────────────────
    if inputs.approved_window_count > 0:
        positive_signals.append("Expected change windows used for planned work")
    elif inputs.providers_connected > 0:
        recommended_actions.append(
            "Use expected change windows to mark planned deployments "
            "and reduce alert noise."
        )

    # ── Apply no-providers cap ────────────────────────────────────────────────
    if no_providers:
        score = min(score, 40)

    # ── Clamp ─────────────────────────────────────────────────────────────────
    score = max(0, min(100, score))

    grade = _grade(score)
    summary = _build_summary(score, grade, inputs)

    metrics = DriftScoreMetrics(
        providers_connected=inputs.providers_connected,
        total_changes_7d=inputs.total_changes_7d,
        high_critical_changes_7d=inputs.high_critical_changes_7d,
        unreviewed_high_critical=(
            inputs.unreviewed_critical_count + inputs.unreviewed_high_count
        ),
        policy_violations_7d=inputs.policy_violations_7d,
        stale_integrations=inputs.stale_integration_count,
        review_completion_rate=round(inputs.review_completion_rate, 3),
        alerts_configured=has_proactive,
    )

    return DriftScoreResponse(
        score=score,
        grade=grade,
        trend="unknown",   # no score history table in M58.17 MVP
        summary=summary,
        period_days=_PERIOD_DAYS,
        factors=factors,
        positive_signals=positive_signals,
        recommended_actions=recommended_actions,
        metrics=metrics,
    )


# ── Private helpers ───────────────────────────────────────────────────────────


def _is_stale_integration(integ: Integration, stale_cutoff: datetime) -> bool:
    """Return True when an integration is considered stale.

    Stale = has not successfully synced in 48 h, OR has ≥2 consecutive failures.
    """
    if (integ.consecutive_failure_count or 0) >= _STALE_FAILURES:
        return True
    if integ.last_synced_at is None:
        return False
    last = integ.last_synced_at
    if last.tzinfo is None:
        from datetime import timezone as _tz
        last = last.replace(tzinfo=_tz.utc)
    return last < stale_cutoff


def _grade(score: int) -> str:
    """Return the grade label for a given score."""
    if score >= 90:
        return "strong"
    if score >= 75:
        return "good"
    if score >= 55:
        return "needs_attention"
    return "weak"


def _build_summary(score: int, grade: str, inputs: _ScoreInputs) -> str:
    """Build a one-sentence advisory summary."""
    unreviewed = inputs.unreviewed_critical_count + inputs.unreviewed_high_count
    if inputs.providers_connected == 0:
        return (
            "No providers are connected. "
            "Connect an integration to start monitoring configuration drift."
        )
    if grade == "strong":
        return (
            "Your workspace has strong drift control. "
            "Keep reviewing changes and maintaining alert coverage."
        )
    if grade == "good":
        tail = (
            f" {unreviewed} high-risk change{'s' if unreviewed != 1 else ''} still "
            f"need{'s' if unreviewed == 1 else ''} review."
            if unreviewed > 0
            else " Continue reviewing new changes promptly."
        )
        return f"Your workspace has good drift control.{tail}"
    if grade == "needs_attention":
        parts = []
        if unreviewed > 0:
            parts.append(
                f"{unreviewed} high-risk change{'s' if unreviewed != 1 else ''} need review"
            )
        if inputs.stale_integration_count > 0:
            parts.append(
                f"{inputs.stale_integration_count} stale integration"
                f"{'s' if inputs.stale_integration_count != 1 else ''}"
            )
        if inputs.policy_violations_7d > 0:
            parts.append(f"{inputs.policy_violations_7d} policy violation{'s' if inputs.policy_violations_7d != 1 else ''}")
        detail = ("; ".join(parts) + ".") if parts else "Review the factors below."
        return f"Drift control needs attention: {detail}"
    # weak
    return (
        "Drift control is weak. "
        "Review unacknowledged changes and configure alert channels to improve."
    )
