"""SendGrid Risk × Activity Correlations (M80F).

Joins active SendGrid configuration-risk findings (provider=sendgrid) with
SendGrid activity signals (provider=sendgrid, from M80E) on the same
resource family within a review window. Produces SecuritySignalCorrelation
rows with evidence_level="correlation".

CORRELATION STRATEGY
--------------------
Eight correlation families, each matching findings to signals by resource
identity or configuration surface:

  api_key              — api_key_id exact match, OR provider+family aggregate.
  sender_identity      — sender_id exact match, OR provider+family aggregate.
  domain_authentication — domain_id exact match, OR provider+family aggregate.
  mail_settings        — account-level surface: provider+family aggregate.
  tracking_settings    — account-level surface: provider+family aggregate.
  webhook              — account-level surface: provider+family aggregate.
  suppression_settings — account-level surface: provider+family aggregate.
  config               — (not used; skipped to avoid noisy provider-only matches)

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They never assert that
a breach, compromise, unauthorized access, or data exposure has occurred or has
been confirmed. Severity = review priority only. Confidence = "medium"
(circumstantial co-occurrence, not proof).

PRIVACY: metadata is allowlisted + flat. NEVER API key values, bearer tokens,
authorization headers, email bodies, subject lines, recipient emails, sender
personal emails, suppression recipient emails, template content, raw webhook
URLs, raw inbound parse hostnames, mail event payloads (bounce/click/open/
delivered/dropped/spamreport/unsubscribe/processed), message IDs, raw SendGrid
API response dicts, raw HTTP request/response bodies, customer data, or PII.
Only safe booleans, counts, opaque identifiers, and configuration labels.

Idempotent — re-running over the same data creates no duplicate correlation rows.
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

PROVIDER = "sendgrid"

# Default review window around a finding's active period.
_WINDOW = timedelta(hours=24)

_REVIEW_NOTE = (
    "SendGrid configuration risk correlated with configuration activity evidence "
    "on the same resource family. Evidence for review. Does not confirm "
    "compromise, unauthorized access, or data exposure."
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

SENDGRID_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "sendgrid_api_key_risk_activity_correlation": {
        "rule_keys": {
            "sendgrid_api_key_broad_scopes",
        },
        "signal_types": {
            "sendgrid_api_key_config_changed",
            "sendgrid_config_activity",
        },
        "match_key": "api_key",
        "severity": "high",
        "title_phrase": "SendGrid API-key risk aligned with API-key configuration activity",
        "subject_phrase": "SendGrid API-key broad-scope risk",
    },
    "sendgrid_sender_identity_risk_activity_correlation": {
        "rule_keys": {
            "sendgrid_sender_identity_unverified",
            "sendgrid_sender_identity_locked",
            "sendgrid_sender_identity_reply_domain_mismatch",
        },
        "signal_types": {
            "sendgrid_sender_identity_config_changed",
            "sendgrid_config_activity",
        },
        "match_key": "sender_identity",
        "severity": "medium",
        "title_phrase": "SendGrid sender-identity risk aligned with sender-identity activity",
        "subject_phrase": "SendGrid sender-identity posture risk",
    },
    "sendgrid_domain_authentication_risk_activity_correlation": {
        "rule_keys": {
            "sendgrid_domain_authentication_invalid",
            "sendgrid_domain_automatic_security_disabled",
            "sendgrid_domain_authentication_legacy",
            "sendgrid_domain_dns_records_missing",
            "sendgrid_default_domain_authentication_invalid",
        },
        "signal_types": {
            "sendgrid_domain_authentication_config_changed",
            "sendgrid_config_activity",
        },
        "match_key": "domain_authentication",
        "severity": "high",
        "title_phrase": "SendGrid domain-authentication risk aligned with domain activity",
        "subject_phrase": "SendGrid domain authentication posture risk",
    },
    "sendgrid_mail_settings_risk_activity_correlation": {
        "rule_keys": {
            "sendgrid_spam_check_disabled",
            "sendgrid_sandbox_mode_enabled",
            "sendgrid_bcc_enabled",
            "sendgrid_footer_disabled",
            "sendgrid_bounce_purge_disabled",
            "sendgrid_template_engine_enabled",
        },
        "signal_types": {
            "sendgrid_mail_settings_config_changed",
            "sendgrid_config_activity",
        },
        "match_key": "mail_settings",
        "severity": "medium",
        "title_phrase": "SendGrid mail-settings risk aligned with mail-settings activity",
        "subject_phrase": "SendGrid mail settings posture risk",
    },
    "sendgrid_tracking_settings_risk_activity_correlation": {
        "rule_keys": {
            "sendgrid_click_tracking_enabled",
            "sendgrid_open_tracking_enabled",
            "sendgrid_subscription_tracking_disabled",
            "sendgrid_google_analytics_tracking_enabled",
        },
        "signal_types": {
            "sendgrid_tracking_settings_config_changed",
            "sendgrid_config_activity",
        },
        "match_key": "tracking_settings",
        "severity": "low",
        "title_phrase": "SendGrid tracking-settings risk aligned with tracking-settings activity",
        "subject_phrase": "SendGrid tracking settings posture risk",
    },
    "sendgrid_webhook_risk_activity_correlation": {
        "rule_keys": {
            "sendgrid_event_webhook_disabled",
            "sendgrid_event_webhook_url_missing",
            "sendgrid_event_webhook_not_signed",
            "sendgrid_event_webhook_broad_event_stream",
            "sendgrid_inbound_parse_enabled",
            "sendgrid_inbound_parse_raw_email_enabled",
            "sendgrid_inbound_parse_spam_check_disabled",
        },
        "signal_types": {
            "sendgrid_event_webhook_config_changed",
            "sendgrid_inbound_parse_config_changed",
            "sendgrid_config_activity",
        },
        "match_key": "webhook",
        "severity": "medium",
        "title_phrase": "SendGrid webhook/inbound-parse risk aligned with webhook activity",
        "subject_phrase": "SendGrid event webhook and inbound parse posture risk",
    },
    "sendgrid_suppression_settings_risk_activity_correlation": {
        "rule_keys": {
            "sendgrid_suppression_settings_empty",
        },
        "signal_types": {
            "sendgrid_suppression_settings_config_changed",
            "sendgrid_config_activity",
        },
        "match_key": "suppression_settings",
        "severity": "low",
        "title_phrase": "SendGrid suppression-settings risk aligned with suppression-settings activity",
        "subject_phrase": "SendGrid suppression settings posture risk",
    },
}

SENDGRID_CORRELATION_TYPES: frozenset[str] = frozenset(SENDGRID_CORRELATION_RULES.keys())


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


def _smdbool(signal: SecurityIncidentSignal, key: str) -> Optional[bool]:
    """Read a bool from signal.signal_metadata (never raises)."""
    md = signal.signal_metadata if isinstance(signal.signal_metadata, dict) else {}
    v = md.get(key)
    return v if isinstance(v, bool) else None


def _smdint(signal: SecurityIncidentSignal, key: str) -> Optional[int]:
    """Read an int from signal.signal_metadata (never raises)."""
    md = signal.signal_metadata if isinstance(signal.signal_metadata, dict) else {}
    v = md.get(key)
    return v if isinstance(v, int) else None


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
      api_key              — api_key_id exact match if both have it; else family.
      sender_identity      — sender_id exact match if both have it; else family.
      domain_authentication — domain_id exact match if both have it; else family.
      mail_settings        — account-level: always match at family level.
      tracking_settings    — account-level: always match at family level.
      webhook              — account-level: always match at family level.
      suppression_settings — account-level: always match at family level.

    Returns a short safe match_reason string, or None if no match.
    PRIVACY: never matches on email addresses, webhook URLs, hostnames,
    raw payloads, or any customer data.
    """
    if match_key == "api_key":
        f_key_id = _fmd(finding, "api_key_id")
        s_key_id = _smd(signal, "api_key_id")
        if f_key_id and s_key_id:
            if f_key_id == s_key_id:
                return "api_key_id_match"
            # Different API keys — no cross-key correlation.
            return None
        return "api_key_family"

    if match_key == "sender_identity":
        f_sender_id = _fmd(finding, "sender_id")
        s_sender_id = _smd(signal, "sender_id")
        if f_sender_id and s_sender_id:
            if f_sender_id == s_sender_id:
                return "sender_id_match"
            return None
        return "sender_identity_family"

    if match_key == "domain_authentication":
        f_domain_id = _fmd(finding, "domain_id")
        s_domain_id = _smd(signal, "domain_id")
        if f_domain_id and s_domain_id:
            if f_domain_id == s_domain_id:
                return "domain_id_match"
            return None
        return "domain_authentication_family"

    # Account-level surfaces: mail_settings, tracking_settings, webhook,
    # suppression_settings — one per account, so family-level match is correct.
    if match_key in ("mail_settings", "tracking_settings", "webhook", "suppression_settings"):
        return f"{match_key}_family"

    return None


def _match_strength(match_reason: str) -> str:
    """Return 'high' for exact-ID matches; 'medium' for family aggregates."""
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
        "sendgrid.correlation",
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

    # Collect safe resource identifiers for metadata.
    # PRIVACY: NEVER api_key values, email addresses, webhook URLs, hostnames,
    # raw payloads, or any customer data.
    api_key_id = _fmd(finding, "api_key_id") or _smd(signal, "api_key_id")
    sender_id = _fmd(finding, "sender_id") or _smd(signal, "sender_id")
    domain_id_val = _fmd(finding, "domain_id") or _smd(signal, "domain_id")

    metadata = corr_svc.sanitize_correlation_metadata({
        "source": "sendgrid_activity_event",
        "rule_key": rule_key,
        "signal_type": signal.signal_type,
        "resource_type": rule["match_key"],
        "match_reason": match_reason,
        "match_strength": match_strength,
        "finding_severity": finding.severity,
        "api_key_id": api_key_id,
        "sender_id": sender_id,
        "domain_id": domain_id_val,
        "event_types": _smd(signal, "event_types"),
        "event_count": (
            signal.signal_metadata.get("event_count")
            if isinstance(signal.signal_metadata, dict)
            else None
        ),
        "risk_family": rule["match_key"],
        "activity_family": rule["match_key"],
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


def generate_sendgrid_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_correlations: int = 100,
) -> dict[str, Any]:
    """Generate SendGrid Risk × Activity correlations for a workspace.

    Joins active SendGrid configuration-risk findings with SendGrid activity
    signals using safe resource identifiers. Idempotent — re-running creates
    no duplicates.

    API key values, email bodies, subject lines, recipient emails, template
    content, raw webhook URLs, raw inbound parse hostnames, mail event payloads
    (bounce/click/open/delivered/dropped/spamreport/unsubscribe/processed),
    message IDs, and customer data are never used or stored. Does not confirm
    compromise, unauthorized access, or data exposure.

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

    # ── Load active SendGrid findings ─────────────────────────────────────────
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

    # ── Load recent SendGrid activity signals ─────────────────────────────────
    all_signal_types: set[str] = set()
    for rule in SENDGRID_CORRELATION_RULES.values():
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

    for correlation_type, rule in SENDGRID_CORRELATION_RULES.items():
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
                        "sendgrid_correlations: failed to upsert one pair; continuing"
                    )
                    continue

    return {
        "provider": PROVIDER,
        "findings_scanned": len(findings),
        "signals_scanned": len(signals),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }
