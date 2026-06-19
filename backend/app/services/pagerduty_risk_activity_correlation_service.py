"""PagerDuty Risk × Activity Correlations (M84F).

Joins active PagerDuty configuration-risk findings (provider=pagerduty, from
M84B/M84C) with PagerDuty activity signals (provider=pagerduty, from M84E) on
the same resource within a review window. Produces SecuritySignalCorrelation
rows with evidence_level="correlation".

CORRELATION STRATEGY
--------------------
Eight specialized correlation families:

  service              — service findings matched to service activity
                         (match on resource_id — opaque PagerDuty service ID)
  escalation_policy    — escalation policy findings matched to EP activity
                         (match on resource_id — opaque EP ID)
  schedule             — schedule findings matched to schedule activity
                         (match on resource_id — opaque schedule ID)
  service_integration  — integration findings matched to integration activity
                         (match on resource_id — opaque integration ID)
  webhook_subscription — webhook findings matched to webhook activity
                         (match on resource_id — opaque webhook subscription ID)
  event_orchestration  — orchestration findings matched to orchestration activity
                         (match on resource_id — opaque orchestration ID)
  business_service     — business service findings matched to BS activity
                         (match on resource_id — opaque business service ID)
  response_play        — response play findings matched to RP activity
                         (match on resource_id — opaque response play ID)

Each family also matches against the generic pagerduty_config_activity signal
type (lower confidence) when no resource-specific signal is available.

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They never assert
that a breach, compromise, unauthorized access, or data exposure has occurred
or been confirmed. Severity = review priority only. Confidence = "medium"
(circumstantial co-occurrence, not proof).

PRIVACY: metadata is allowlisted + flat. NEVER stored:
  PagerDuty API tokens, routing keys, integration keys, webhook secrets,
  delivery URLs, custom header values, user emails, user names, phone numbers,
  contact methods, on-call user identities, responder identities, subscriber
  identities, incident payloads, alert payloads, conference phone numbers,
  raw routing expressions, IP addresses, user agents, raw audit payloads,
  raw API response dicts, or customer PII.
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

PROVIDER = "pagerduty"

_WINDOW = timedelta(hours=24)

_REVIEW_NOTE = (
    "PagerDuty incident-response configuration risk correlated with configuration "
    "activity evidence on the same resource. Evidence for review. Does not confirm "
    "compromise, unauthorized access, or data exposure."
)

# ── Correlation rule definitions ──────────────────────────────────────────────

PAGERDUTY_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "pagerduty_service_risk_activity_correlation": {
        "rule_keys": {
            "pagerduty_service_no_escalation_policy",
            "pagerduty_service_no_integrations",
            "pagerduty_service_ack_timeout_disabled",
            "pagerduty_service_auto_resolve_disabled",
            "pagerduty_service_alert_creation_limited",
            "pagerduty_service_no_teams",
        },
        "signal_types": {
            "pagerduty_service_config_changed",
            "pagerduty_config_activity",
        },
        "match_key": "service",
        "severity": "medium",
        "title_phrase": "PagerDuty service risk aligned with service configuration activity",
        "subject_phrase": "PagerDuty service incident-response configuration posture risk",
    },
    "pagerduty_escalation_policy_risk_activity_correlation": {
        "rule_keys": {
            "pagerduty_escalation_policy_no_rules",
            "pagerduty_escalation_policy_single_level",
            "pagerduty_escalation_policy_no_targets",
            "pagerduty_escalation_policy_low_target_count",
            "pagerduty_escalation_policy_no_schedule_targets",
            "pagerduty_escalation_policy_no_team_targets",
        },
        "signal_types": {
            "pagerduty_escalation_policy_config_changed",
            "pagerduty_config_activity",
        },
        "match_key": "escalation_policy",
        "severity": "high",
        "title_phrase": "PagerDuty escalation policy risk aligned with escalation policy activity",
        "subject_phrase": "PagerDuty escalation policy routing / coverage posture risk",
    },
    "pagerduty_schedule_risk_activity_correlation": {
        "rule_keys": {
            "pagerduty_schedule_no_layers",
            "pagerduty_schedule_no_teams",
            "pagerduty_schedule_no_targets",
            "pagerduty_schedule_no_restrictions",
            "pagerduty_schedule_single_layer",
            "pagerduty_schedule_low_target_count",
        },
        "signal_types": {
            "pagerduty_schedule_config_changed",
            "pagerduty_config_activity",
        },
        "match_key": "schedule",
        "severity": "medium",
        "title_phrase": "PagerDuty schedule risk aligned with schedule configuration activity",
        "subject_phrase": "PagerDuty on-call schedule coverage posture risk",
    },
    "pagerduty_service_integration_risk_activity_correlation": {
        "rule_keys": {
            "pagerduty_service_integration_missing_key_indicator",
            "pagerduty_service_integration_email_type",
            "pagerduty_service_integration_routing_key_missing",
            "pagerduty_service_integration_unknown_type",
        },
        "signal_types": {
            "pagerduty_service_integration_config_changed",
            "pagerduty_config_activity",
        },
        "match_key": "service_integration",
        "severity": "medium",
        "title_phrase": "PagerDuty integration risk aligned with integration configuration activity",
        "subject_phrase": "PagerDuty service integration posture risk",
    },
    "pagerduty_webhook_subscription_risk_activity_correlation": {
        "rule_keys": {
            "pagerduty_webhook_subscription_inactive",
            "pagerduty_webhook_subscription_non_https",
            "pagerduty_webhook_subscription_broad_event_scope",
            "pagerduty_webhook_subscription_no_events",
            "pagerduty_webhook_subscription_secret_not_indicated",
            "pagerduty_webhook_subscription_broad_scope_high",
            "pagerduty_webhook_subscription_account_scope",
        },
        "signal_types": {
            "pagerduty_webhook_subscription_config_changed",
            "pagerduty_config_activity",
        },
        "match_key": "webhook_subscription",
        "severity": "high",
        "title_phrase": "PagerDuty webhook risk aligned with webhook subscription configuration activity",
        "subject_phrase": "PagerDuty webhook subscription transport / authentication posture risk",
    },
    "pagerduty_event_orchestration_risk_activity_correlation": {
        "rule_keys": {
            "pagerduty_event_orchestration_no_routes",
            "pagerduty_event_orchestration_no_team",
            "pagerduty_event_orchestration_low_route_count",
        },
        "signal_types": {
            "pagerduty_event_orchestration_config_changed",
            "pagerduty_config_activity",
        },
        "match_key": "event_orchestration",
        "severity": "medium",
        "title_phrase": "PagerDuty orchestration risk aligned with orchestration configuration activity",
        "subject_phrase": "PagerDuty event orchestration routing posture risk",
    },
    "pagerduty_business_service_risk_activity_correlation": {
        "rule_keys": {
            "pagerduty_business_service_no_team",
            "pagerduty_business_service_no_contact",
        },
        "signal_types": {
            "pagerduty_business_service_config_changed",
            "pagerduty_config_activity",
        },
        "match_key": "business_service",
        "severity": "low",
        "title_phrase": "PagerDuty business service risk aligned with business service configuration activity",
        "subject_phrase": "PagerDuty business service ownership / contact posture risk",
    },
    "pagerduty_response_play_risk_activity_correlation": {
        "rule_keys": {
            "pagerduty_response_play_no_responders",
            "pagerduty_response_play_not_runnable",
            "pagerduty_response_play_no_subscribers",
            "pagerduty_response_play_low_responder_count",
            "pagerduty_response_play_no_team",
            "pagerduty_response_play_manual_only",
        },
        "signal_types": {
            "pagerduty_response_play_config_changed",
            "pagerduty_config_activity",
        },
        "match_key": "response_play",
        "severity": "medium",
        "title_phrase": "PagerDuty response play risk aligned with response play configuration activity",
        "subject_phrase": "PagerDuty response play responder / runnability posture risk",
    },
}

PAGERDUTY_CORRELATION_TYPES: frozenset[str] = frozenset(
    PAGERDUTY_CORRELATION_RULES.keys()
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

    PRIVACY: never returns PagerDuty API tokens, routing keys, integration keys,
    webhook secrets, delivery URLs, user emails, user names, phone numbers,
    contact methods, IP addresses, incident payloads, alert payloads, or PII.
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
    NEVER uses user emails, API tokens, routing keys, or PII.
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

    PRIVACY: never matches on user emails, user IDs, phone numbers, contact
    methods, IP addresses, routing keys, integration keys, webhook secrets,
    incident payloads, alert payloads, or any credential/PII.
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
        "pagerduty.correlation",
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
    and category labels. NEVER PagerDuty API tokens, routing keys, integration
    keys, webhook secrets, delivery URLs, user emails, user names, phone
    numbers, contact methods, on-call user identities, responder identities,
    subscriber identities, incident payloads, alert payloads, conference phone
    numbers, raw routing expressions, IP addresses, user agents, raw audit
    payloads, or customer PII.
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
        "source": "pagerduty_activity_event",
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
        "correlation_reason": f"pagerduty_{rule['match_key']}_risk_activity",
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


def generate_pagerduty_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_correlations: int = 100,
) -> dict[str, Any]:
    """Generate PagerDuty Risk × Activity correlations for a workspace.

    Joins active PagerDuty configuration-risk findings with PagerDuty activity
    signals on the same safe opaque resource_id within a review window.

    Covers eight correlation families: service, escalation_policy, schedule,
    service_integration, webhook_subscription, event_orchestration,
    business_service, and response_play. Each family also correlates against
    generic pagerduty_config_activity signals when a resource-specific signal
    is unavailable.

    PagerDuty API tokens, routing keys, integration keys, webhook secrets,
    delivery URLs, custom header values, user emails, user names, phone numbers,
    contact methods, on-call user identities, responder identities, subscriber
    identities, incident payloads, alert payloads, conference phone numbers,
    raw routing expressions, IP addresses, user agents, raw audit payloads,
    and PII are never used or stored.
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

    # ── Load active PagerDuty findings ────────────────────────────────────────
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

    # ── Load recent PagerDuty activity signals ────────────────────────────────
    all_signal_types: set[str] = set()
    for rule in PAGERDUTY_CORRELATION_RULES.values():
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

    for correlation_type, rule in PAGERDUTY_CORRELATION_RULES.items():
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
                        "pagerduty_correlations: failed to upsert one pair; continuing"
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
