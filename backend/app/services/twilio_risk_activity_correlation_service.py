"""Twilio Risk × Activity Correlations (M79F).

Joins active Twilio configuration-risk findings (provider=twilio) with Twilio
activity signals (provider=twilio, from M79E) on the same resource family
within a review window. Produces SecuritySignalCorrelation rows with
evidence_level="correlation".

CORRELATION STRATEGY
--------------------
Five correlation families, each matching findings to signals by resource
identity:

  phone_number         — phone_number_last4 exact match, OR provider+family
                         aggregate if no per-number identity is available.
  messaging_service    — messaging_service_sid exact match, OR provider+family.
  verify_service       — verify_service_sid exact match, OR provider+family.
  api_key              — api_key_sid exact match, OR provider+family.
  account              — account-level match (provider+workspace).

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They never assert that
a breach, compromise, unauthorized access, or data exposure has occurred or has
been confirmed. Severity = review priority only. Confidence = "medium"
(circumstantial co-occurrence, not proof).

PRIVACY: metadata is allowlisted + flat. NEVER auth tokens, API key secrets,
full account SIDs, full phone number strings, webhook/callback URL strings,
message bodies, call SIDs, call legs, recording data, customer PII (caller
name, verification payloads), raw Twilio API response dicts, raw HTTP request
or response bodies, or any value that could re-identify a customer or expose a
credential. Only the last-4 digits of a phone number (phone_number_last4) are
permitted — never full numbers.

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

PROVIDER = "twilio"

# Default review window around a finding's active period.
_WINDOW = timedelta(hours=24)

_REVIEW_NOTE = (
    "Twilio configuration risk correlated with configuration activity evidence "
    "on the same resource family. Evidence for review. Does not confirm "
    "compromise or unauthorized access."
)

# ── Correlation rule definitions ──────────────────────────────────────────────
#
# Each entry maps a correlation_type (the output label) to:
#   rule_keys       — set of finding rule keys that trigger this correlation
#   signal_types    — set of signal types that can match
#   match_key       — resource family label used for matching logic
#   severity        — review-priority severity for the correlation
#   title_phrase    — short phrase for the correlation title
#   subject_phrase  — what the finding risk concerns

TWILIO_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "twilio_phone_number_risk_activity_correlation": {
        "rule_keys": {
            "twilio_phone_number_sms_webhook_missing",
            "twilio_phone_number_voice_webhook_missing",
            "twilio_phone_number_status_callback_missing",
            "twilio_phone_number_messaging_observability_gap",
            "twilio_phone_number_voice_observability_gap",
            "twilio_webhook_uses_http",
        },
        "signal_types": {
            "twilio_phone_number_config_changed",
            "twilio_config_activity",
        },
        "match_key": "phone_number",
        "severity": "high",
        "title_phrase": "Twilio phone-number risk aligned with phone-number activity",
        "subject_phrase": "Twilio phone-number webhook / observability risk",
    },
    "twilio_messaging_service_risk_activity_correlation": {
        "rule_keys": {
            "twilio_messaging_service_inbound_webhook_missing",
            "twilio_messaging_service_fallback_missing",
            "twilio_messaging_service_status_callback_missing",
            "twilio_messaging_service_observability_gap",
            "twilio_messaging_service_number_level_inbound_webhook",
            "twilio_messaging_service_long_validity_period",
            "twilio_webhook_uses_http",
        },
        "signal_types": {
            "twilio_messaging_service_config_changed",
            "twilio_messaging_sender_pool_changed",
            "twilio_config_activity",
        },
        "match_key": "messaging_service",
        "severity": "high",
        "title_phrase": "Twilio messaging-service risk aligned with messaging-service activity",
        "subject_phrase": "Twilio messaging-service webhook / observability risk",
    },
    "twilio_verify_service_risk_activity_correlation": {
        "rule_keys": {
            "twilio_verify_short_code_length",
            "twilio_verify_lookup_disabled",
            "twilio_verify_psd2_disabled",
            "twilio_verify_sms_to_landlines_allowed",
        },
        "signal_types": {
            "twilio_verify_service_config_changed",
            "twilio_config_activity",
        },
        "match_key": "verify_service",
        "severity": "medium",
        "title_phrase": "Twilio Verify-service risk aligned with Verify-service activity",
        "subject_phrase": "Twilio Verify-service posture risk",
    },
    "twilio_api_key_risk_activity_correlation": {
        "rule_keys": {
            "twilio_api_key_stale",
        },
        "signal_types": {
            "twilio_api_key_config_changed",
            "twilio_config_activity",
        },
        "match_key": "api_key",
        "severity": "high",
        "title_phrase": "Twilio API-key staleness risk aligned with API-key activity",
        "subject_phrase": "Twilio API-key staleness risk",
    },
    "twilio_account_risk_activity_correlation": {
        "rule_keys": {
            "twilio_account_suspended",
        },
        "signal_types": {
            "twilio_account_config_changed",
            "twilio_config_activity",
        },
        "match_key": "account",
        "severity": "high",
        "title_phrase": "Twilio account risk aligned with account configuration activity",
        "subject_phrase": "Twilio account status risk",
    },
}

TWILIO_CORRELATION_TYPES: frozenset[str] = frozenset(TWILIO_CORRELATION_RULES.keys())


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _fmd(finding: SecurityFinding, key: str) -> Optional[str]:
    """Read a string from finding.evidence (never raises)."""
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


def _base_rule_key(finding_key: str) -> str:
    """Strip any ':instance' suffix to get the base rule key."""
    return finding_key.split(":", 1)[0] if finding_key else ""


def _match_pair(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
    match_key: str,
) -> Optional[str]:
    """Attempt to match a finding to a signal. Returns match_reason or None.

    Match strategy by resource family:
      phone_number      — phone_number_last4 exact match if both sides have it;
                          else provider+family aggregate (never cross-resource).
      messaging_service — messaging_service_sid exact match if both have it;
                          else provider+family aggregate.
      verify_service    — verify_service_sid exact match if both have it;
                          else provider+family aggregate.
      api_key           — api_key_sid exact match if both have it;
                          else provider+family aggregate.
      account           — always matches at provider+workspace level.

    Returns a short safe match_reason string, or None if no match.
    """
    if match_key == "phone_number":
        f_last4 = _fmd(finding, "phone_number_last4")
        s_last4 = _smd(signal, "phone_number_last4")
        if f_last4 and s_last4:
            if f_last4 == s_last4:
                return "phone_number_last4_match"
            # Different phone numbers — no cross-number correlation.
            return None
        # Neither side has per-number identity → aggregate on family.
        return "phone_number_family"

    if match_key == "messaging_service":
        f_sid = _fmd(finding, "messaging_service_sid")
        s_sid = _smd(signal, "messaging_service_sid")
        if f_sid and s_sid:
            if f_sid == s_sid:
                return "messaging_service_sid_match"
            return None
        return "messaging_service_family"

    if match_key == "verify_service":
        f_sid = _fmd(finding, "verify_service_sid")
        s_sid = _smd(signal, "verify_service_sid")
        if f_sid and s_sid:
            if f_sid == s_sid:
                return "verify_service_sid_match"
            return None
        return "verify_service_family"

    if match_key == "api_key":
        f_sid = _fmd(finding, "api_key_sid")
        s_sid = _smd(signal, "api_key_sid")
        if f_sid and s_sid:
            if f_sid == s_sid:
                return "api_key_sid_match"
            return None
        return "api_key_family"

    if match_key == "account":
        return "account_level"

    return None


def _match_strength(match_reason: str) -> str:
    """Return 'high' for exact-SID matches; 'medium' for family aggregates."""
    if match_reason.endswith("_match"):
        return "high"
    return "medium"


def _correlation_key(
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
    correlation_type: str,
) -> str:
    """Deterministic correlation key — one correlation per (type, finding, signal)."""
    return "|".join([
        "twilio.correlation",
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
    """Build a correlation dict (not yet persisted)."""
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    s_first = _aware(signal.first_seen_at)
    s_last = _aware(signal.last_seen_at)

    times = [t for t in [f_start, f_end, s_first, s_last] if t is not None]
    window_start = min(times) if times else _utcnow() - _WINDOW
    window_end = max(times) if times else _utcnow()

    title = f"{rule['title_phrase']} ({match_reason})"[:240]
    summary = (
        f"{rule['subject_phrase']} correlated with {signal.signal_type} evidence "
        f"({match_reason}). {_REVIEW_NOTE}"
    )

    rule_key = _base_rule_key(finding.finding_key)
    match_strength = _match_strength(match_reason)

    metadata = corr_svc.sanitize_correlation_metadata({
        "source": "twilio_activity_event",
        "rule_key": rule_key,
        "signal_type": signal.signal_type,
        "resource_type": rule["match_key"],
        "match_reason": match_reason,
        "match_strength": match_strength,
        "finding_severity": finding.severity,
        # Safe per-resource identifiers (never full phone number, never secrets)
        "phone_number_last4": (
            _fmd(finding, "phone_number_last4")
            or _smd(signal, "phone_number_last4")
        ),
        "messaging_service_sid": (
            _fmd(finding, "messaging_service_sid")
            or _smd(signal, "messaging_service_sid")
        ),
        "verify_service_sid": (
            _fmd(finding, "verify_service_sid")
            or _smd(signal, "verify_service_sid")
        ),
        "api_key_sid": (
            _fmd(finding, "api_key_sid")
            or _smd(signal, "api_key_sid")
        ),
        "twilio_resource_sid_prefix": (
            _smd(signal, "twilio_resource_sid_prefix")
        ),
        "event_types": _smd(signal, "event_types"),
        "event_count": (
            signal.signal_metadata.get("event_count")
            if isinstance(signal.signal_metadata, dict)
            else None
        ),
        "window_start": window_start.isoformat() if window_start else None,
        "window_end": window_end.isoformat() if window_end else None,
    })

    return {
        "provider": PROVIDER,
        "correlation_key": _correlation_key(finding, signal, correlation_type),
        "correlation_type": correlation_type,
        "severity": rule["severity"],
        "confidence": "medium",
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
        return True  # conservative — allow match if timestamps are missing

    s_time = _aware(signal.last_seen_at) or _aware(signal.first_seen_at)
    if s_time is None:
        return True

    window_open = f_start - _WINDOW
    window_close = f_end + _WINDOW
    return window_open <= s_time <= window_close


# ── Main function ─────────────────────────────────────────────────────────────


def generate_twilio_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_correlations: int = 100,
) -> dict[str, Any]:
    """Generate Twilio Risk × Activity correlations for a workspace.

    Joins active Twilio configuration-risk findings with Twilio activity
    signals using safe resource identifiers. Idempotent — re-running creates
    no duplicates.

    Message bodies, call logs, recordings, media, full phone numbers, auth
    tokens, API key secrets, and customer communication data are never used
    or stored. Does not confirm compromise, unauthorized access, or data
    exposure.

    Args:
        workspace_id:     Workspace UUID for data scoping.
        db:               Database session.
        lookback_hours:   Lookback window for signal recency (1–168 hours).
        max_correlations: Maximum correlations to create (1–1000).

    Returns:
        Summary dict with provider/findings_scanned/signals_scanned/
        correlations_created/correlations_skipped fields.
    """
    hours = max(1, min(int(lookback_hours or 24), 168))
    cap = max(1, min(int(max_correlations or 100), 1000))
    cutoff = _utcnow() - timedelta(hours=hours)

    # ── Load active Twilio findings ───────────────────────────────────────────
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

    # ── Load recent Twilio activity signals ───────────────────────────────────
    # All signal_types across all correlation rules.
    all_signal_types = set()
    for rule in TWILIO_CORRELATION_RULES.values():
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

    # Build lookup: rule_key → list[SecurityFinding]
    # and signal_type → list[SecurityIncidentSignal]
    findings_by_rule: dict[str, list[SecurityFinding]] = {}
    for f in findings:
        rk = _base_rule_key(f.finding_key)
        findings_by_rule.setdefault(rk, []).append(f)

    signals_by_type: dict[str, list[SecurityIncidentSignal]] = {}
    for s in signals:
        signals_by_type.setdefault(s.signal_type, []).append(s)

    created = skipped = 0

    for correlation_type, rule in TWILIO_CORRELATION_RULES.items():
        if created >= cap:
            break

        # Gather candidate findings for this correlation rule.
        candidate_findings: list[SecurityFinding] = []
        for rk in rule["rule_keys"]:
            candidate_findings.extend(findings_by_rule.get(rk, []))

        if not candidate_findings:
            continue

        # Gather candidate signals for this correlation rule.
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
                match_reason = _match_pair(finding, signal, rule["match_key"])
                if match_reason is None:
                    continue
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
                        "twilio_correlations: failed to upsert one pair; continuing"
                    )
                    continue

    return {
        "provider": PROVIDER,
        "findings_scanned": len(findings),
        "signals_scanned": len(signals),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }
