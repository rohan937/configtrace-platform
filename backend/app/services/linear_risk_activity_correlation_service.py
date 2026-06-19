"""Linear Risk × Activity Correlations (M85F).

Joins active Linear configuration-risk findings (provider=linear, from
M85B/M85C) with Linear activity signals (provider=linear, from M85E) on
the same resource within a review window. Produces SecuritySignalCorrelation
rows with evidence_level="correlation".

CORRELATION STRATEGY
--------------------
Nine specialized correlation families:

  workspace        — workspace findings matched to workspace activity
                     (match on resource_id — opaque Linear workspace ID)
  team             — team findings matched to team activity
                     (match on resource_id — opaque Linear team ID)
  project          — project findings matched to project activity
                     (match on resource_id — opaque Linear project ID)
  workflow_state   — workflow state findings matched to workflow state activity
                     (match on resource_id — opaque Linear workflow state ID)
  label            — label findings matched to label activity
                     (match on resource_id — opaque Linear label ID)
  webhook          — webhook findings matched to webhook activity
                     (match on resource_id — opaque Linear webhook ID)
  view             — view findings matched to view activity
                     (match on resource_id — opaque Linear view ID)
  cycle            — cycle findings matched to cycle activity
                     (match on resource_id — opaque Linear cycle ID)
  integration      — integration findings matched to integration activity
                     (match on resource_id — opaque Linear integration ID)

Each family also matches against the generic linear_config_activity signal
type (lower confidence) when no resource-specific signal is available.

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They never assert
that a breach, compromise, unauthorized access, or data exposure has occurred
or been confirmed. Severity = review priority only. Confidence = "medium"
(circumstantial co-occurrence, not proof).

PRIVACY: metadata is allowlisted + flat. NEVER stored:
  Linear API tokens, OAuth tokens, webhook secrets, webhook signing keys,
  delivery URLs, custom header values, user emails, user names, display names,
  avatar URLs, member identities, lead identities, subscriber identities,
  issue payloads, comment payloads, attachment payloads, raw integration
  configs, IP addresses, user agents, raw audit payloads, raw API response
  dicts, or customer PII.
Only safe opaque identifiers, booleans, counts, and category labels.

Idempotent — re-running over the same data creates no duplicate correlation
rows.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.services import security_signal_correlation_service as corr_svc

_log = logging.getLogger(__name__)

PROVIDER = "linear"

_WINDOW = timedelta(hours=24)

_REVIEW_NOTE = (
    "Linear configuration risk correlated with configuration activity evidence "
    "on the same resource. Evidence for review. Does not confirm compromise, "
    "unauthorized access, or data exposure."
)

# ── Correlation rule definitions ──────────────────────────────────────────────

LINEAR_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "linear_workspace_risk_activity_correlation": {
        "rule_keys": {
            "linear_workspace_missing_url_key",
            "linear_workspace_missing_logo",
            "linear_workspace_low_team_count",
            "linear_workspace_no_webhooks",
            "linear_workspace_no_integrations",
        },
        "signal_types": {
            "linear_workspace_config_changed",
            "linear_config_activity",
        },
        "match_key": "workspace",
        "severity": "medium",
        "title_phrase": "Linear workspace risk aligned with workspace configuration activity",
        "subject_phrase": "Linear workspace configuration posture risk",
    },
    "linear_team_risk_activity_correlation": {
        "rule_keys": {
            "linear_team_private",
            "linear_team_low_member_count",
            "linear_team_no_projects",
            "linear_team_auto_archive_disabled",
            "linear_team_cycles_disabled",
            "linear_team_long_cycle_duration",
            "linear_team_no_backlog_state",
            "linear_team_no_started_state",
            "linear_team_no_completed_state",
            "linear_team_no_canceled_state",
            "linear_team_low_workflow_state_count",
            "linear_team_no_labels",
            "linear_team_no_webhooks",
        },
        "signal_types": {
            "linear_team_config_changed",
            "linear_config_activity",
        },
        "match_key": "team",
        "severity": "medium",
        "title_phrase": "Linear team risk aligned with team configuration activity",
        "subject_phrase": "Linear team configuration / workflow posture risk",
    },
    "linear_project_risk_activity_correlation": {
        "rule_keys": {
            "linear_project_no_lead",
            "linear_project_no_members",
            "linear_project_high_issue_count",
            "linear_project_unhealthy",
            "linear_project_unknown_status",
            "linear_project_no_team_scope",
        },
        "signal_types": {
            "linear_project_config_changed",
            "linear_config_activity",
        },
        "match_key": "project",
        "severity": "low",
        "title_phrase": "Linear project risk aligned with project configuration activity",
        "subject_phrase": "Linear project ownership / health posture risk",
    },
    "linear_workflow_state_risk_activity_correlation": {
        "rule_keys": {
            "linear_workflow_state_unknown_type",
        },
        "signal_types": {
            "linear_workflow_state_config_changed",
            "linear_config_activity",
        },
        "match_key": "workflow_state",
        "severity": "low",
        "title_phrase": "Linear workflow state risk aligned with workflow state configuration activity",
        "subject_phrase": "Linear workflow state configuration posture risk",
    },
    "linear_label_risk_activity_correlation": {
        "rule_keys": {
            "linear_label_missing_team_scope",
        },
        "signal_types": {
            "linear_label_config_changed",
            "linear_config_activity",
        },
        "match_key": "label",
        "severity": "low",
        "title_phrase": "Linear label risk aligned with label configuration activity",
        "subject_phrase": "Linear label scoping posture risk",
    },
    "linear_webhook_risk_activity_correlation": {
        "rule_keys": {
            "linear_webhook_disabled",
            "linear_webhook_no_secret_indicator",
            "linear_webhook_non_https",
            "linear_webhook_no_events",
            "linear_webhook_broad_resource_scope",
            "linear_webhook_issue_comment_scope",
            "linear_webhook_attachment_scope",
        },
        "signal_types": {
            "linear_webhook_config_changed",
            "linear_config_activity",
        },
        "match_key": "webhook",
        "severity": "high",
        "title_phrase": "Linear webhook risk aligned with webhook configuration activity",
        "subject_phrase": "Linear webhook transport / authentication posture risk",
    },
    "linear_view_risk_activity_correlation": {
        "rule_keys": {
            "linear_view_shared",
            "linear_view_shared_without_team_scope",
        },
        "signal_types": {
            "linear_view_config_changed",
            "linear_config_activity",
        },
        "match_key": "view",
        "severity": "low",
        "title_phrase": "Linear view risk aligned with view configuration activity",
        "subject_phrase": "Linear view sharing / scoping posture risk",
    },
    "linear_cycle_risk_activity_correlation": {
        "rule_keys": {
            "linear_cycle_high_issue_count",
        },
        "signal_types": {
            "linear_cycle_config_changed",
            "linear_config_activity",
        },
        "match_key": "cycle",
        "severity": "low",
        "title_phrase": "Linear cycle risk aligned with cycle configuration activity",
        "subject_phrase": "Linear cycle load posture risk",
    },
    "linear_integration_risk_activity_correlation": {
        "rule_keys": {
            "linear_integration_disabled",
            "linear_integration_unknown_type",
            "linear_integration_workspace_scoped",
        },
        "signal_types": {
            "linear_integration_config_changed",
            "linear_config_activity",
        },
        "match_key": "integration",
        "severity": "medium",
        "title_phrase": "Linear integration risk aligned with integration configuration activity",
        "subject_phrase": "Linear integration configuration / scope posture risk",
    },
}

LINEAR_CORRELATION_TYPES: frozenset[str] = frozenset(
    LINEAR_CORRELATION_RULES.keys()
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _fmd(finding: SecurityFinding, key: str) -> Optional[str]:
    """Read a string from finding.evidence (never raises).

    PRIVACY: never returns Linear API tokens, OAuth tokens, webhook secrets,
    webhook signing keys, delivery URLs, user emails, user names, display
    names, avatar URLs, member identities, issue payloads, comment payloads,
    attachment payloads, IP addresses, or PII.
    """
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    v = ev.get(key)
    if isinstance(v, str) and v.strip():
        return v
    return None


def _smd(signal: SecurityIncidentSignal, key: str) -> Optional[str]:
    """Read a string from signal.signal_metadata (never raises)."""
    md = signal.signal_metadata if isinstance(signal.signal_metadata, dict) else {}
    v = md.get(key)
    if isinstance(v, str) and v.strip():
        return v
    return None


def _smdint(signal: SecurityIncidentSignal, key: str) -> Optional[int]:
    """Read an int from signal.signal_metadata (never raises)."""
    md = signal.signal_metadata if isinstance(signal.signal_metadata, dict) else {}
    v = md.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _base_rule_key(finding_key: str) -> str:
    """Strip any ':resource_id' suffix to get the base rule key."""
    return finding_key.split(":", 1)[0] if finding_key else ""


def _resource_id_from_finding(finding: SecurityFinding) -> Optional[str]:
    """Extract the safe resource identifier from a finding.

    Uses finding.resource_id first, then falls back to evidence record_id.
    NEVER uses user emails, API tokens, OAuth tokens, webhook secrets, or PII.
    """
    return finding.resource_id or _fmd(finding, "record_id")


def _resource_id_from_signal(signal: SecurityIncidentSignal) -> Optional[str]:
    """Extract the safe resource identifier from a signal's metadata."""
    return _smd(signal, "resource_id")


def _match_pair(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
) -> Optional[str]:
    """Attempt to match a finding to a signal by resource_id.

    Returns a match_reason string or None if no match.

    Match requires the same safe opaque resource_id on both sides. If either
    side lacks a resource_id, we do not produce a correlation (no vague
    cross-resource matching).

    PRIVACY: never matches on user emails, user IDs, display names, member
    identities, lead identities, subscriber identities, webhook secrets,
    delivery URLs, issue payloads, comment payloads, attachment payloads, or
    any credential/PII.
    """
    f_rid = _resource_id_from_finding(finding)
    s_rid = _resource_id_from_signal(signal)
    if not f_rid or not s_rid:
        return None
    if f_rid != s_rid:
        return None
    return "resource_id_match"


def _match_strength(match_reason: str, signal_type: str, finding_integration_id: Any, signal_integration_id: Any) -> str:
    """Return confidence level for the match."""
    if match_reason != "resource_id_match":
        return "low"
    if "config_activity" in signal_type:
        # Generic signal — medium confidence
        return "medium"
    # Specific signal type matched
    if (finding_integration_id and signal_integration_id
            and str(finding_integration_id) == str(signal_integration_id)):
        return "high"
    return "medium"


def _correlation_key(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
    correlation_type: str,
) -> str:
    """Deterministic correlation key — one correlation per (type, finding, signal)."""
    return "|".join([
        "linear.correlation",
        correlation_type,
        str(finding.id),
        str(signal.id),
    ])


def _build_correlation(
    *,
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
    correlation_type: str,
    rule: dict[str, Any],
    match_reason: str,
) -> dict[str, Any]:
    """Build a correlation dict (not yet persisted).

    PRIVACY: metadata uses only safe opaque identifiers, booleans, counts,
    and category labels. NEVER Linear API tokens, OAuth tokens, webhook
    secrets, webhook signing keys, delivery URLs, custom header values, user
    emails, user names, display names, avatar URLs, member identities, lead
    identities, subscriber identities, issue payloads, comment payloads,
    attachment payloads, raw integration configs, IP addresses, user agents,
    raw audit payloads, or customer PII.
    """
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    s_first = _aware(signal.first_seen_at)
    s_last = _aware(signal.last_seen_at)

    times = [t for t in [f_start, f_end, s_first, s_last] if t is not None]
    window_start = min(times) if times else _utcnow() - _WINDOW
    window_end = max(times) if times else _utcnow()

    match_strength = _match_strength(
        match_reason,
        signal.signal_type,
        finding.integration_id,
        signal.integration_id,
    )
    confidence = match_strength  # "high" | "medium" | "low"

    title = f"{rule['title_phrase']} ({match_reason})"[:240]
    summary = (
        f"{rule['subject_phrase']} correlated with {signal.signal_type} "
        f"evidence ({match_reason}). {_REVIEW_NOTE}"
    )

    rule_key = _base_rule_key(finding.finding_key)

    # Safe resource identifiers from both sides.
    resource_id = _resource_id_from_finding(finding) or _resource_id_from_signal(signal)
    resource_type = _fmd(finding, "resource_type") or _smd(signal, "resource_type")

    metadata = corr_svc.sanitize_correlation_metadata({
        "source": "linear_activity_event",
        "rule_key": rule_key,
        "signal_type": signal.signal_type,
        "resource_type": resource_type or rule["match_key"],
        "resource_id": resource_id,
        "match_reason": match_reason,
        "match_strength": match_strength,
        "finding_severity": finding.severity,
        "risk_family": rule["match_key"],
        "activity_family": rule["match_key"],
        "event_types": _smd(signal, "event_types"),
        "event_count": _smdint(signal, "event_count"),
        "correlation_reason": f"linear_{rule['match_key']}_risk_activity",
        "correlation_strength": match_strength,
        "window_start": window_start.isoformat() if window_start else None,
        "window_end": window_end.isoformat() if window_end else None,
    })

    return {
        "provider": PROVIDER,
        "correlation_key": _correlation_key(finding, signal, correlation_type),
        "correlation_type": correlation_type,
        "severity": rule["severity"],
        "confidence": confidence,
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": signal.linked_activity_event_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": window_start,
        "last_seen_at": window_end,
        "metadata": metadata,
    }


def _in_window(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
) -> bool:
    """True if the signal's time range overlaps with the finding's review window."""
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    if f_start is None or f_end is None:
        return True

    s_time = _aware(signal.last_seen_at) or _aware(signal.first_seen_at)
    if s_time is None:
        return True

    window_open = f_start - _WINDOW
    window_close = f_end + _WINDOW
    return window_open <= s_time <= window_close


# ── Main function ─────────────────────────────────────────────────────────────


def generate_linear_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_correlations: int = 100,
) -> dict[str, Any]:
    """Generate Linear Risk × Activity correlations for a workspace.

    Joins active Linear configuration-risk findings with Linear activity
    signals on the same safe opaque resource_id within a review window.

    Covers nine correlation families: workspace, team, project, workflow_state,
    label, webhook, view, cycle, and integration. Each family also correlates
    against generic linear_config_activity signals when a resource-specific
    signal is unavailable.

    Linear API tokens, OAuth tokens, webhook secrets, webhook signing keys,
    delivery URLs, custom header values, user emails, user names, display
    names, avatar URLs, member identities, lead identities, subscriber
    identities, issue payloads, comment payloads, attachment payloads, raw
    integration configs, IP addresses, user agents, raw audit payloads, and
    PII are never used or stored.
    Does not confirm compromise, unauthorized access, or data exposure.
    Idempotent — re-running creates no duplicates.

    Args:
        workspace_id:      Workspace UUID for data scoping.
        db:                Database session.
        lookback_hours:    Lookback window for signal recency (1–168 hours).
        max_correlations:  Maximum correlations to create (1–1000).

    Returns:
        Summary dict with provider/findings_scanned/signals_scanned/
        candidate_pairs/correlations_created/correlations_skipped fields.
    """
    hours = max(1, min(int(lookback_hours or 24), 168))
    cap = max(1, min(int(max_correlations or 100), 1000))
    cutoff = _utcnow() - timedelta(hours=hours)

    # ── Load active Linear findings ───────────────────────────────────────────
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER,
            SecurityFinding.status == "active",
        )
        .order_by(SecurityFinding.last_seen_at.desc().nullslast())
        .limit(2000)
        .all()
    )

    # ── Load recent Linear activity signals ───────────────────────────────────
    all_signal_types: set[str] = set()
    for rule in LINEAR_CORRELATION_RULES.values():
        all_signal_types.update(rule["signal_types"])

    signals = (
        db.query(SecurityIncidentSignal)
        .filter(
            SecurityIncidentSignal.workspace_id == workspace_id,
            SecurityIncidentSignal.provider == PROVIDER,
            SecurityIncidentSignal.signal_type.in_(all_signal_types),
            SecurityIncidentSignal.last_seen_at >= cutoff,
        )
        .order_by(SecurityIncidentSignal.last_seen_at.desc().nullslast())
        .limit(2000)
        .all()
    )

    findings_by_rule: dict[str, list[SecurityFinding]] = {}
    for f in findings:
        rk = _base_rule_key(f.finding_key)
        findings_by_rule.setdefault(rk, []).append(f)

    signals_by_type: dict[str, list[SecurityIncidentSignal]] = {}
    for s in signals:
        signals_by_type.setdefault(s.signal_type, []).append(s)

    created = skipped = candidate_pairs = 0

    for correlation_type, rule in LINEAR_CORRELATION_RULES.items():
        if created >= cap:
            break

        candidate_findings: list[SecurityFinding] = []
        for rk in rule["rule_keys"]:
            candidate_findings.extend(findings_by_rule.get(rk, []))

        if not candidate_findings:
            continue

        candidate_signals: list[SecurityIncidentSignal] = []
        for st in rule["signal_types"]:
            candidate_signals.extend(signals_by_type.get(st, []))

        if not candidate_signals:
            continue

        for finding in candidate_findings:
            if created >= cap:
                break
            for signal in candidate_signals:
                if created >= cap:
                    break
                if not _in_window(finding, signal):
                    continue
                match_reason = _match_pair(finding, signal)
                if match_reason is None:
                    continue
                candidate_pairs += 1
                try:
                    correlation = _build_correlation(
                        finding=finding,
                        signal=signal,
                        correlation_type=correlation_type,
                        rule=rule,
                        match_reason=match_reason,
                    )
                    outcome, _row = corr_svc.upsert_correlation(
                        workspace_id=workspace_id,
                        correlation=correlation,
                        db=db,
                    )
                    if outcome == "created":
                        created += 1
                    else:
                        skipped += 1
                except Exception:  # noqa: BLE001
                    _log.warning(
                        "linear_correlations: failed to upsert one pair; continuing"
                    )
                    continue

    return {
        "provider": PROVIDER,
        "findings_scanned": len(findings),
        "signals_scanned": len(signals),
        "candidate_pairs": candidate_pairs,
        "correlations_created": created,
        "correlations_skipped": skipped,
    }
