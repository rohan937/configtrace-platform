"""Datadog Risk × Activity Correlations (M82F).

Joins active Datadog configuration-risk findings (provider=datadog) with Datadog
activity signals (provider=datadog, from M82E) on the same resource family
within a review window. Produces SecuritySignalCorrelation rows with
evidence_level="correlation".

CORRELATION STRATEGY
--------------------
Ten focused correlation families + one generic fallback:

  monitor                  — monitor_id exact match; else monitor family.
  slo                      — slo_id exact match; else SLO family.
  dashboard                — dashboard_id exact match; else dashboard family.
  webhook                  — webhook_id exact match; else webhook family.
  notification_integration — notification_integration_id exact match; else family.
  api_key                  — api_key_id exact match; else API-key family.
  application_key          — application_key_id exact match; else app-key family.
  role                     — role_id exact match; else role family.
  team                     — team_id exact match; else team family.
  cloud_integration        — cloud_integration_id exact match; else cloud family.
  generic                  — same resource_type + resource_id (low-confidence fallback).

CONFIDENCE LEVELS
-----------------
  high   — exact specific resource-ID match + same integration_id
  medium — exact specific resource-ID match (different or missing integration)
  low    — family aggregate or generic resource_type/resource_id fallback

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They never assert
that a breach, compromise, unauthorized access, or data exposure has occurred
or been confirmed. Severity = review priority only.

PRIVACY: metadata is allowlisted + flat. NEVER stored:
  API key values, application key values, OAuth tokens, bearer tokens,
  webhook secrets, raw monitor queries/messages, raw dashboard JSON,
  webhook URLs/headers/payload templates, notification handles, Slack
  channel names, PagerDuty service IDs, email addresses, user IDs,
  team member identities, IP addresses, user agents, raw Datadog audit
  payloads, raw API response dicts, customer data, or PII.

Idempotent — re-running over the same data creates no duplicate rows.
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

PROVIDER = "datadog"

_WINDOW = timedelta(hours=24)

_REVIEW_NOTE = (
    "Datadog configuration risk correlated with related Datadog configuration "
    "activity evidence on the same resource. Evidence for review. Does not "
    "confirm compromise, unauthorized access, or data exposure."
)

# ── Correlation rule definitions ──────────────────────────────────────────────
#
# Each entry maps a correlation_type (output label) to:
#   rule_keys       — finding rule keys that trigger this family
#   signal_types    — signal types that can match
#   id_key          — finding evidence key for the specific resource ID
#   signal_id_key   — signal metadata key for the specific resource ID
#   severity        — review-priority severity for the correlation
#   title_phrase    — short phrase for the correlation title
#   subject_phrase  — what the finding risk concerns

DATADOG_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "datadog_monitor_risk_activity_correlation": {
        "rule_keys": {
            "datadog_monitor_disabled",
            "datadog_monitor_unrestricted_roles",
            "datadog_monitor_notify_no_data_disabled",
            "datadog_monitor_long_query",
            "datadog_monitor_no_notifications",
            "datadog_monitor_message_template_present",
            "datadog_monitor_no_warning_threshold",
            "datadog_monitor_no_recovery_threshold",
            "datadog_monitor_silenced_scopes_present",
            "datadog_monitor_notify_audit_disabled",
            "datadog_monitor_require_full_window_disabled",
            "datadog_monitor_query_wildcard_scope",
            "datadog_monitor_broad_group_by",
            "datadog_monitor_long_no_data_timeframe",
        },
        "signal_types": {
            "datadog_monitor_config_changed",
            "datadog_config_activity",
        },
        "id_key": "record_id",       # finding evidence key
        "signal_id_key": "monitor_id",  # signal metadata key
        "metadata_id_key": "monitor_id",  # key to store in correlation metadata
        "severity": "medium",
        "title_phrase": "Datadog monitor risk aligned with monitor configuration activity",
        "subject_phrase": "Datadog monitor configuration posture risk",
    },
    "datadog_slo_risk_activity_correlation": {
        "rule_keys": {
            "datadog_slo_no_monitors",
            "datadog_slo_low_target",
        },
        "signal_types": {
            "datadog_slo_config_changed",
            "datadog_config_activity",
        },
        "id_key": "record_id",
        "signal_id_key": "slo_id",
        "metadata_id_key": "slo_id",
        "severity": "medium",
        "title_phrase": "Datadog SLO risk aligned with SLO configuration activity",
        "subject_phrase": "Datadog SLO configuration posture risk",
    },
    "datadog_dashboard_risk_activity_correlation": {
        "rule_keys": {
            "datadog_dashboard_public_url_present",
            "datadog_dashboard_unrestricted_roles",
        },
        "signal_types": {
            "datadog_dashboard_config_changed",
            "datadog_config_activity",
        },
        "id_key": "record_id",
        "signal_id_key": "dashboard_id",
        "metadata_id_key": "dashboard_id",
        "severity": "medium",
        "title_phrase": "Datadog dashboard risk aligned with dashboard configuration activity",
        "subject_phrase": "Datadog dashboard configuration posture risk",
    },
    "datadog_webhook_risk_activity_correlation": {
        "rule_keys": {
            "datadog_webhook_without_secret_headers",
            "datadog_webhook_payload_template_present",
            "datadog_webhook_non_https_endpoint",
            "datadog_webhook_custom_headers_without_secret_headers",
            "datadog_webhook_large_payload_template",
            "datadog_webhook_auth_material_present",
        },
        "signal_types": {
            "datadog_webhook_integration_config_changed",
            "datadog_config_activity",
        },
        "id_key": "record_id",
        "signal_id_key": "webhook_id",
        "metadata_id_key": "webhook_id",
        "severity": "high",
        "title_phrase": "Datadog webhook risk aligned with webhook configuration activity",
        "subject_phrase": "Datadog webhook integration security posture risk",
    },
    "datadog_notification_integration_risk_activity_correlation": {
        "rule_keys": {
            "datadog_notification_integration_no_channels",
        },
        "signal_types": {
            "datadog_notification_integration_config_changed",
            "datadog_config_activity",
        },
        "id_key": "record_id",
        "signal_id_key": "notification_integration_id",
        "metadata_id_key": "notification_integration_id",
        "severity": "low",
        "title_phrase": (
            "Datadog notification integration risk aligned with "
            "notification integration configuration activity"
        ),
        "subject_phrase": "Datadog notification integration posture risk",
    },
    "datadog_api_key_risk_activity_correlation": {
        "rule_keys": {
            "datadog_api_key_disabled",
        },
        "signal_types": {
            "datadog_api_key_metadata_config_changed",
            "datadog_config_activity",
        },
        "id_key": "record_id",
        "signal_id_key": "api_key_id",
        "metadata_id_key": "api_key_id",
        "severity": "medium",
        "title_phrase": "Datadog API key risk aligned with API key configuration activity",
        "subject_phrase": "Datadog API key metadata posture risk",
    },
    "datadog_application_key_risk_activity_correlation": {
        "rule_keys": {
            "datadog_application_key_broad_scopes",
        },
        "signal_types": {
            "datadog_application_key_metadata_config_changed",
            "datadog_config_activity",
        },
        "id_key": "record_id",
        "signal_id_key": "application_key_id",
        "metadata_id_key": "application_key_id",
        "severity": "medium",
        "title_phrase": (
            "Datadog application key risk aligned with "
            "application key configuration activity"
        ),
        "subject_phrase": "Datadog application key metadata posture risk",
    },
    "datadog_role_risk_activity_correlation": {
        "rule_keys": {
            "datadog_role_high_permission_count",
        },
        "signal_types": {
            "datadog_role_config_changed",
            "datadog_config_activity",
        },
        "id_key": "record_id",
        "signal_id_key": "role_id",
        "metadata_id_key": "role_id",
        "severity": "high",
        "title_phrase": "Datadog role risk aligned with role configuration activity",
        "subject_phrase": "Datadog role / IAM posture risk",
    },
    "datadog_team_risk_activity_correlation": {
        "rule_keys": {
            "datadog_team_no_members",
        },
        "signal_types": {
            "datadog_team_config_changed",
            "datadog_config_activity",
        },
        "id_key": "record_id",
        "signal_id_key": "team_id",
        "metadata_id_key": "team_id",
        "severity": "low",
        "title_phrase": "Datadog team risk aligned with team configuration activity",
        "subject_phrase": "Datadog team configuration posture risk",
    },
    "datadog_cloud_integration_risk_activity_correlation": {
        "rule_keys": {
            "datadog_cloud_integration_broad_collection",
            "datadog_cloud_integration_log_collection_enabled",
        },
        "signal_types": {
            "datadog_cloud_integration_config_changed",
            "datadog_config_activity",
        },
        "id_key": "record_id",
        "signal_id_key": "cloud_integration_id",
        "metadata_id_key": "cloud_integration_id",
        "severity": "medium",
        "title_phrase": (
            "Datadog cloud integration risk aligned with "
            "cloud integration configuration activity"
        ),
        "subject_phrase": "Datadog cloud integration posture risk",
    },
}

DATADOG_CORRELATION_TYPES: frozenset[str] = frozenset(
    DATADOG_CORRELATION_RULES.keys()
)
# Generic fallback type.
_GENERIC_CORRELATION_TYPE = "datadog_config_activity_correlation"


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _fmd(finding: SecurityFinding, key: str) -> Optional[str]:
    """Read a string from finding.evidence (never raises).

    PRIVACY: never returns API key values, application key values, OAuth tokens,
    bearer tokens, webhook secrets, raw monitor queries/messages, raw dashboard
    JSON, webhook URLs, notification handles, email addresses, user IDs, team
    member identities, IP addresses, user agents, or any credential material.
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
    """Strip any ':instance' suffix to get the base rule key."""
    return finding_key.split(":", 1)[0] if finding_key else ""


def _match_pair(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
    rule: dict[str, Any],
) -> Optional[tuple[str, str]]:
    """Attempt to match a finding to a signal.

    Returns (match_reason, confidence) or None if no match.

    Match strategy:
      Exact ID: both sides have the specific resource ID and they are equal
                → ('{type}_id_match', 'high' if same integration else 'medium')
      Family:   one or both sides lack the specific ID
                → ('{type}_family', 'low')
      No match: both sides have different specific IDs → None

    PRIVACY: never matches on API key values, application key values, raw
    monitor queries, raw monitor messages, webhook URLs, notification handles,
    email addresses, user IDs, team member identities, IP addresses, or any
    credential material.
    """
    id_key = rule["id_key"]         # finding evidence key (always "record_id")
    signal_id_key = rule["signal_id_key"]   # signal metadata key
    family_label = rule.get("metadata_id_key", "resource")

    f_rid = _fmd(finding, id_key)
    s_rid = _smd(signal, signal_id_key) or _smd(signal, "resource_id")

    if f_rid and s_rid:
        if f_rid == s_rid:
            # Exact match — confidence depends on integration context
            f_iid = str(finding.integration_id) if finding.integration_id else None
            s_iid = str(signal.integration_id) if signal.integration_id else None
            if f_iid and s_iid and f_iid == s_iid:
                confidence = "high"
            else:
                confidence = "medium"
            return f"{family_label}_id_match", confidence
        # Both have IDs but they differ → different resources, no correlation.
        return None

    # One or both sides lack the specific ID — use family aggregate.
    return f"{family_label}_family", "low"


def _in_window(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
) -> bool:
    """True when the signal's time range overlaps with the finding's review window."""
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    if f_start is None or f_end is None:
        return True  # conservative — allow when timestamps are missing

    s_time = _aware(signal.last_seen_at) or _aware(signal.first_seen_at)
    if s_time is None:
        return True

    window_open = f_start - _WINDOW
    window_close = f_end + _WINDOW
    return window_open <= s_time <= window_close


def _correlation_key(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
    correlation_type: str,
) -> str:
    """Deterministic key — one correlation per (type, finding, signal)."""
    return "|".join([
        "datadog.correlation",
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
    confidence: str,
) -> dict[str, Any]:
    """Build a correlation dict (not yet persisted).

    PRIVACY: metadata uses only safe opaque identifiers, booleans, counts,
    and category labels from the allowed list. NEVER API key values,
    application key values, OAuth tokens, bearer tokens, webhook secrets,
    raw monitor queries/messages, raw dashboard JSON, webhook URLs/headers/
    payload templates, notification handles, email addresses, user IDs,
    team member identities, IP addresses, user agents, raw Datadog audit
    payloads, raw API response dicts, customer data, or PII.
    """
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    s_first = _aware(signal.first_seen_at)
    s_last = _aware(signal.last_seen_at)

    times = [t for t in [f_start, f_end, s_first, s_last] if t is not None]
    window_start = min(times) if times else _utcnow() - _WINDOW
    window_end = max(times) if times else _utcnow()

    rule_key = _base_rule_key(finding.finding_key)
    match_strength = "high" if match_reason.endswith("_id_match") else "low"

    title = (
        f"{rule['title_phrase']} ({match_reason})"
    )[:240]
    summary = (
        f"{rule['subject_phrase']} correlated with {signal.signal_type} evidence "
        f"({match_reason}). {_REVIEW_NOTE}"
    )

    # Gather safe resource identifiers from both sides.
    # PRIVACY: NEVER API key values, application key values, OAuth tokens,
    # bearer tokens, webhook secrets, raw queries/messages, webhook URLs/headers,
    # payload templates, notification handles, email addresses, user IDs,
    # team member identities, IP addresses, user agents, or raw Datadog payloads.
    f_record_id = _fmd(finding, "record_id")
    s_resource_id = (
        _smd(signal, rule.get("signal_id_key", "resource_id"))
        or _smd(signal, "resource_id")
    )
    metadata_id_key = rule.get("metadata_id_key")

    md_raw: dict[str, Any] = {
        "source": "datadog_activity_event",
        "rule_key": rule_key,
        "signal_type": signal.signal_type,
        "resource_type": _fmd(finding, "record_type") or finding.resource_type or "datadog",
        "resource_id": f_record_id or s_resource_id,
        "resource_name": _fmd(finding, "resource_name") or _smd(signal, "resource_name"),
        "match_reason": match_reason,
        "match_strength": match_strength,
        "finding_severity": finding.severity,
        "event_types": _smd(signal, "event_types"),
        "event_count": _smdint(signal, "event_count"),
        "risk_family": rule.get("metadata_id_key", "configuration"),
        "activity_family": rule.get("metadata_id_key", "configuration"),
        "category": "datadog_configuration",
    }

    # Add the specific resource ID under its proper key.
    if metadata_id_key and (f_record_id or s_resource_id):
        md_raw[metadata_id_key] = f_record_id or s_resource_id

    metadata = corr_svc.sanitize_correlation_metadata(md_raw)

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


def _build_generic_correlation(
    *,
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
) -> Optional[dict[str, Any]]:
    """Build a generic fallback correlation for same resource_type + resource_id.

    Only used when no specialized mapping matched but the finding and signal
    share the same resource_type and resource_id. Low confidence only.

    PRIVACY: same constraints as _build_correlation — never raw queries,
    messages, URLs, handles, credentials, PII, or raw Datadog payloads.
    """
    f_rt = (
        _fmd(finding, "record_type")
        or finding.resource_type
        or "configuration"
    )
    s_rt = (
        signal.signal_metadata.get("resource_type")
        if isinstance(signal.signal_metadata, dict)
        else None
    ) or "configuration"

    f_rid = _fmd(finding, "record_id") or finding.resource_id
    s_rid = signal.resource_id

    if not f_rid or not s_rid or f_rid != s_rid:
        return None
    if f_rt != s_rt:
        return None

    rule_key = _base_rule_key(finding.finding_key)
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    s_first = _aware(signal.first_seen_at)
    s_last = _aware(signal.last_seen_at)

    times = [t for t in [f_start, f_end, s_first, s_last] if t is not None]
    window_start = min(times) if times else _utcnow() - _WINDOW
    window_end = max(times) if times else _utcnow()

    title = (
        f"Datadog {f_rt} configuration risk aligned with related "
        f"Datadog {f_rt} configuration activity"
    )[:240]
    summary = (
        f"Datadog {f_rt} configuration risk ({rule_key}) correlated with "
        f"{signal.signal_type} evidence on the same resource. {_REVIEW_NOTE}"
    )

    metadata = corr_svc.sanitize_correlation_metadata({
        "source": "datadog_activity_event",
        "rule_key": rule_key,
        "signal_type": signal.signal_type,
        "resource_type": f_rt,
        "resource_id": f_rid,
        "resource_name": (
            _fmd(finding, "resource_name") or _smd(signal, "resource_name")
        ),
        "match_reason": "generic_resource_id_match",
        "match_strength": "low",
        "finding_severity": finding.severity,
        "event_types": (
            signal.signal_metadata.get("event_types")
            if isinstance(signal.signal_metadata, dict) else None
        ),
        "risk_family": f_rt,
        "activity_family": f_rt,
        "category": "datadog_configuration",
    })

    return {
        "provider": PROVIDER,
        "correlation_key": _correlation_key(finding, signal, _GENERIC_CORRELATION_TYPE),
        "correlation_type": _GENERIC_CORRELATION_TYPE,
        "severity": finding.severity or "low",
        "confidence": "low",
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


# ── Main function ─────────────────────────────────────────────────────────────


def generate_datadog_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_correlations: int = 100,
) -> dict[str, Any]:
    """Generate Datadog Risk × Activity correlations for a workspace.

    Joins active Datadog configuration-risk findings with Datadog activity
    signals using safe resource identifiers (monitor_id, slo_id, dashboard_id,
    webhook_id, notification_integration_id, api_key_id, application_key_id,
    role_id, team_id, cloud_integration_id) or resource family aggregate
    matching when no per-resource identity is available.

    Covers ten correlation families: monitor, SLO, dashboard, webhook,
    notification integration, API key, application key, role, team, and
    cloud integration, plus a generic resource_type/resource_id fallback.

    API key values, application key values, OAuth tokens, bearer tokens,
    webhook secrets, raw monitor queries/messages, raw dashboard JSON,
    webhook URLs/headers/payload templates, notification handles, email
    addresses, user IDs, team member identities, IP addresses, user agents,
    and raw Datadog audit payloads are never used or stored.
    Does not confirm compromise, unauthorized access, or data exposure.
    Idempotent — re-running creates no duplicates.

    Args:
        workspace_id:     Workspace UUID for data scoping.
        db:               Database session.
        lookback_hours:   Lookback window for signal recency (1–168 hours).
        max_correlations: Maximum correlations to create (1–1000).

    Returns:
        Summary dict with provider/findings_scanned/signals_scanned/
        candidate_pairs/correlations_created/correlations_skipped fields.
    """
    hours = max(1, min(int(lookback_hours or 24), 168))
    cap = max(1, min(int(max_correlations or 100), 1000))
    cutoff = _utcnow() - timedelta(hours=hours)

    # ── Load active Datadog findings ──────────────────────────────────────────
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

    # ── Load recent Datadog activity signals ──────────────────────────────────
    all_signal_types: set[str] = set()
    for rule in DATADOG_CORRELATION_RULES.values():
        all_signal_types.update(rule["signal_types"])
    all_signal_types.add("datadog_config_activity")

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

    # Build lookup tables for efficient cross-product.
    findings_by_rule: dict[str, list[SecurityFinding]] = {}
    for f in findings:
        rk = _base_rule_key(f.finding_key)
        findings_by_rule.setdefault(rk, []).append(f)

    signals_by_type: dict[str, list[SecurityIncidentSignal]] = {}
    for s in signals:
        signals_by_type.setdefault(s.signal_type, []).append(s)

    created = skipped = candidate_pairs = 0

    # ── Specialized correlation families ──────────────────────────────────────
    for correlation_type, rule in DATADOG_CORRELATION_RULES.items():
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
                pair_result = _match_pair(finding, signal, rule)
                if pair_result is None:
                    continue
                match_reason, confidence = pair_result
                candidate_pairs += 1
                try:
                    correlation = _build_correlation(
                        finding=finding,
                        signal=signal,
                        correlation_type=correlation_type,
                        rule=rule,
                        match_reason=match_reason,
                        confidence=confidence,
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
                        "datadog_correlations: failed to upsert one pair; continuing"
                    )
                    continue

    # ── Generic fallback: same resource_type + resource_id ────────────────────
    # Only fires for findings NOT matched by a specialized rule above.
    # Skips any finding already matched by a specialized rule to avoid
    # creating noisy duplicate generic correlations.
    matched_rule_keys: set[str] = set()
    for rule in DATADOG_CORRELATION_RULES.values():
        matched_rule_keys.update(rule["rule_keys"])

    if created < cap and signals:
        for finding in findings:
            if created >= cap:
                break
            rk = _base_rule_key(finding.finding_key)
            if rk in matched_rule_keys:
                continue  # already handled by a specialized rule
            for signal in signals:
                if created >= cap:
                    break
                if not _in_window(finding, signal):
                    continue
                try:
                    generic = _build_generic_correlation(finding=finding, signal=signal)
                    if generic is None:
                        continue
                    candidate_pairs += 1
                    outcome, _row = corr_svc.upsert_correlation(
                        workspace_id=workspace_id,
                        correlation=generic,
                        db=db,
                    )
                    if outcome == "created":
                        created += 1
                    else:
                        skipped += 1
                except Exception:  # noqa: BLE001
                    _log.warning(
                        "datadog_correlations: failed to upsert generic pair; continuing"
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
