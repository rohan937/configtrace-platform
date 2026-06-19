"""Clerk Risk × Activity Correlations (M83F).

Joins active Clerk configuration-risk findings (provider=clerk, from M83B/M83C)
with Clerk activity signals (provider=clerk, from M83E) on the same resource
family within a review window. Produces SecuritySignalCorrelation rows with
evidence_level="correlation".

CORRELATION STRATEGY
--------------------
Ten specialized correlation families plus a generic fallback:

  instance_settings   — instance-level findings matched to instance activity
                        (match on instance_id or resource_id, else family).
  application         — application-level findings matched to application
                        activity (match on application_id or resource_id, else
                        family).
  domain              — domain findings matched to domain activity (match on
                        domain_id or resource_id, else family).
  redirect_url_config — redirect URL findings matched to redirect URL activity
                        (match on redirect_url_config_id or resource_id).
  jwt_template        — JWT template findings matched to JWT template activity
                        (match on jwt_template_id or resource_id).
  webhook_endpoint    — webhook endpoint findings matched to webhook activity
                        (match on webhook_endpoint_id or resource_id).
  email_sms_settings  — email/SMS findings matched to email/SMS activity
                        (match on email_sms_settings_id or resource_id).
  auth_strategy       — auth strategy findings matched to auth strategy activity
                        (match on auth_strategy_id or resource_id, else family).
  organization_settings — org settings findings matched to org settings activity
                        (match on organization_settings_id or resource_id).
  session_policy      — session policy findings matched to session policy
                        activity (match on session_policy_id or resource_id).

No generic provider-only fallback is created to avoid noisy cross-resource
correlations.

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They never assert
that a breach, compromise, unauthorized access, or data exposure has occurred
or been confirmed. Severity = review priority only. Confidence = "medium"
(circumstantial co-occurrence, not proof).

PRIVACY: metadata is allowlisted + flat. NEVER stored: Clerk secret key
values, publishable key values, session tokens, JWTs, OAuth tokens, bearer
tokens, webhook secrets, raw webhook URLs, raw redirect URLs, raw domain names,
JWT template bodies, custom claims, audience URIs, issuer URIs, user emails,
user IDs, phone numbers, names, organization member identities, session
history, login history, IP addresses, user agents, raw audit payloads, or PII.
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

PROVIDER = "clerk"

_WINDOW = timedelta(hours=24)

_REVIEW_NOTE = (
    "Clerk configuration risk correlated with configuration activity evidence "
    "on the same resource family. Evidence for review. Does not confirm "
    "compromise, unauthorized access, or data exposure."
)

# ── Correlation rule definitions ──────────────────────────────────────────────

CLERK_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "clerk_instance_settings_risk_activity_correlation": {
        "rule_keys": {
            "clerk_instance_mfa_disabled",
            "clerk_instance_password_without_mfa",
            "clerk_instance_sign_up_enabled",
        },
        "signal_types": {
            "clerk_instance_settings_config_changed",
            "clerk_config_activity",
        },
        "match_key": "instance_settings",
        "severity": "medium",
        "title_phrase": "Clerk instance risk aligned with instance settings activity",
        "subject_phrase": "Clerk instance MFA / sign-up posture risk",
    },
    "clerk_application_risk_activity_correlation": {
        "rule_keys": {
            "clerk_application_mfa_not_required",
            "clerk_application_sign_up_enabled",
            "clerk_application_password_without_mfa",
            "clerk_application_oauth_without_mfa",
            "clerk_application_saml_without_mfa",
            "clerk_application_many_redirect_urls",
            "clerk_application_many_allowed_origins",
        },
        "signal_types": {
            "clerk_application_config_changed",
            "clerk_config_activity",
        },
        "match_key": "application",
        "severity": "medium",
        "title_phrase": "Clerk application risk aligned with application configuration activity",
        "subject_phrase": "Clerk application / authentication posture risk",
    },
    "clerk_domain_risk_activity_correlation": {
        "rule_keys": {
            "clerk_domain_unverified",
            "clerk_domain_ssl_disabled",
        },
        "signal_types": {
            "clerk_domain_config_changed",
            "clerk_config_activity",
        },
        "match_key": "domain",
        "severity": "medium",
        "title_phrase": "Clerk domain risk aligned with domain configuration activity",
        "subject_phrase": "Clerk domain verification / SSL posture risk",
    },
    "clerk_redirect_url_risk_activity_correlation": {
        "rule_keys": {
            "clerk_redirect_url_non_https",
            "clerk_redirect_url_wildcard_present",
            "clerk_redirect_url_localhost_present",
            "clerk_redirect_url_custom_scheme_present",
        },
        "signal_types": {
            "clerk_redirect_url_config_changed",
            "clerk_config_activity",
        },
        "match_key": "redirect_url_config",
        "severity": "medium",
        "title_phrase": "Clerk redirect URL risk aligned with redirect URL configuration activity",
        "subject_phrase": "Clerk redirect URL posture risk",
    },
    "clerk_jwt_template_risk_activity_correlation": {
        "rule_keys": {
            "clerk_jwt_template_custom_claims_present",
            "clerk_jwt_template_long_lifetime",
            "clerk_jwt_template_audience_missing",
            "clerk_jwt_template_issuer_missing",
            "clerk_jwt_template_many_claims",
        },
        "signal_types": {
            "clerk_jwt_template_config_changed",
            "clerk_config_activity",
        },
        "match_key": "jwt_template",
        "severity": "medium",
        "title_phrase": "Clerk JWT template risk aligned with JWT template configuration activity",
        "subject_phrase": "Clerk JWT template posture risk",
    },
    "clerk_webhook_endpoint_risk_activity_correlation": {
        "rule_keys": {
            "clerk_webhook_endpoint_disabled",
            "clerk_webhook_without_signing",
            "clerk_webhook_non_https",
            "clerk_webhook_broad_event_scope",
        },
        "signal_types": {
            "clerk_webhook_endpoint_config_changed",
            "clerk_config_activity",
        },
        "match_key": "webhook_endpoint",
        "severity": "high",
        "title_phrase": "Clerk webhook risk aligned with webhook endpoint configuration activity",
        "subject_phrase": "Clerk webhook endpoint signing / HTTPS posture risk",
    },
    "clerk_email_sms_settings_risk_activity_correlation": {
        "rule_keys": {
            "clerk_email_sms_custom_sender_present",
        },
        "signal_types": {
            "clerk_email_sms_settings_config_changed",
            "clerk_config_activity",
        },
        "match_key": "email_sms_settings",
        "severity": "low",
        "title_phrase": "Clerk email/SMS settings risk aligned with email/SMS configuration activity",
        "subject_phrase": "Clerk email/SMS custom-sender posture risk",
    },
    "clerk_auth_strategy_risk_activity_correlation": {
        "rule_keys": {
            "clerk_auth_strategy_mfa_not_required",
            "clerk_auth_strategy_password_without_mfa",
        },
        "signal_types": {
            "clerk_auth_strategy_config_changed",
            "clerk_config_activity",
        },
        "match_key": "auth_strategy",
        "severity": "medium",
        "title_phrase": "Clerk auth strategy risk aligned with auth strategy configuration activity",
        "subject_phrase": "Clerk authentication strategy MFA posture risk",
    },
    "clerk_organization_settings_risk_activity_correlation": {
        "rule_keys": {
            "clerk_org_verified_domains_not_required",
            "clerk_org_invitations_enabled",
            "clerk_org_admin_role_missing",
            "clerk_org_high_role_count",
            "clerk_org_high_permission_count",
        },
        "signal_types": {
            "clerk_organization_settings_config_changed",
            "clerk_config_activity",
        },
        "match_key": "organization_settings",
        "severity": "medium",
        "title_phrase": "Clerk organization settings risk aligned with organization configuration activity",
        "subject_phrase": "Clerk organization domain / role / permission posture risk",
    },
    "clerk_session_policy_risk_activity_correlation": {
        "rule_keys": {
            "clerk_session_lifetime_extended",
            "clerk_session_inactivity_timeout_extended",
            "clerk_session_single_session_disabled",
            "clerk_session_token_rotation_disabled",
            "clerk_session_device_tracking_disabled",
            "clerk_session_reverification_disabled",
            "clerk_session_long_lifetime_without_single_session",
        },
        "signal_types": {
            "clerk_session_policy_config_changed",
            "clerk_config_activity",
        },
        "match_key": "session_policy",
        "severity": "medium",
        "title_phrase": "Clerk session policy risk aligned with session policy configuration activity",
        "subject_phrase": "Clerk session lifetime / reverification / rotation posture risk",
    },
}

CLERK_CORRELATION_TYPES: frozenset[str] = frozenset(CLERK_CORRELATION_RULES.keys())


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _fmd(finding: SecurityFinding, key: str) -> Optional[str]:
    """Read a string from finding.evidence (never raises).

    PRIVACY: never returns Clerk secret keys, publishable keys, session tokens,
    JWTs, raw URLs, domain names, JWT template bodies, user emails, user IDs,
    phone numbers, member identities, IP addresses, or any credential/PII.
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
    match_key: str,
) -> Optional[str]:
    """Attempt to match a finding to a signal. Returns match_reason or None.

    Match strategy by resource family:
      instance_settings     — instance_id exact match if both have it; else family.
      application           — application_id exact match if both have it; else family.
      domain                — domain_id exact match if both have it; else family.
      redirect_url_config   — redirect_url_config_id exact match if both have it;
                              else no match (redirect URL entries are per-URL).
      jwt_template          — jwt_template_id exact match if both have it; else family.
      webhook_endpoint      — webhook_endpoint_id exact match if both have it; else family.
      email_sms_settings    — email_sms_settings_id or resource_id; always family
                              (singleton per instance).
      auth_strategy         — auth_strategy_id or resource_id; always family
                              (singleton per instance).
      organization_settings — organization_settings_id or resource_id; always
                              family (singleton per instance).
      session_policy        — session_policy_id or resource_id; always family
                              (singleton per instance).

    Returns a short safe match_reason string, or None if no match.
    PRIVACY: never matches on user emails, user IDs, phone numbers, member
    identities, IP addresses, session data, tokens, JWTs, raw URLs, domain
    names, or any credential/PII material.
    """
    # Singleton surfaces — one per instance, always match at family level.
    _SINGLETON_KEYS = frozenset({
        "instance_settings",
        "email_sms_settings",
        "auth_strategy",
        "organization_settings",
        "session_policy",
    })

    if match_key in _SINGLETON_KEYS:
        return f"{match_key}_family"

    if match_key == "application":
        f_aid = _fmd(finding, "application_id") or finding.resource_id
        s_aid = _smd(signal, "application_id") or _smd(signal, "resource_id")
        if f_aid and s_aid:
            if f_aid == s_aid:
                return "application_id_match"
            return None  # Different application — no cross-app correlation
        return "application_family"

    if match_key == "domain":
        f_did = _fmd(finding, "domain_id") or finding.resource_id
        s_did = _smd(signal, "domain_id") or _smd(signal, "resource_id")
        if f_did and s_did:
            if f_did == s_did:
                return "domain_id_match"
            return None
        return "domain_family"

    if match_key == "redirect_url_config":
        f_rid = _fmd(finding, "redirect_url_config_id") or finding.resource_id
        s_rid = _smd(signal, "redirect_url_config_id") or _smd(signal, "resource_id")
        if f_rid and s_rid:
            if f_rid == s_rid:
                return "redirect_url_config_id_match"
            return None  # Per-URL records — no cross-URL correlation
        return "redirect_url_family"

    if match_key == "jwt_template":
        f_jid = _fmd(finding, "jwt_template_id") or finding.resource_id
        s_jid = _smd(signal, "jwt_template_id") or _smd(signal, "resource_id")
        if f_jid and s_jid:
            if f_jid == s_jid:
                return "jwt_template_id_match"
            return None
        return "jwt_template_family"

    if match_key == "webhook_endpoint":
        f_wid = _fmd(finding, "webhook_endpoint_id") or finding.resource_id
        s_wid = _smd(signal, "webhook_endpoint_id") or _smd(signal, "resource_id")
        if f_wid and s_wid:
            if f_wid == s_wid:
                return "webhook_endpoint_id_match"
            return None
        return "webhook_endpoint_family"

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
        "clerk.correlation",
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
    and category labels. NEVER Clerk secret keys, publishable keys, session
    tokens, JWTs, raw URLs, domain names, JWT template bodies, user emails,
    user IDs, phone numbers, member identities, IP addresses, user agents,
    raw audit payloads, or any PII.
    """
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

    # Gather safe resource identifiers from both sides.
    instance_id = _fmd(finding, "instance_id") or _smd(signal, "instance_id")
    application_id = (
        _fmd(finding, "application_id") or _smd(signal, "application_id")
        or finding.resource_id or _smd(signal, "resource_id")
    )
    domain_id = _fmd(finding, "domain_id") or _smd(signal, "domain_id")
    redirect_url_config_id = (
        _fmd(finding, "redirect_url_config_id") or _smd(signal, "redirect_url_config_id")
    )
    jwt_template_id = _fmd(finding, "jwt_template_id") or _smd(signal, "jwt_template_id")
    webhook_endpoint_id = (
        _fmd(finding, "webhook_endpoint_id") or _smd(signal, "webhook_endpoint_id")
    )
    auth_strategy_id = _fmd(finding, "auth_strategy_id") or _smd(signal, "auth_strategy_id")
    organization_settings_id = (
        _fmd(finding, "organization_settings_id") or _smd(signal, "organization_settings_id")
    )
    session_policy_id = (
        _fmd(finding, "session_policy_id") or _smd(signal, "session_policy_id")
    )

    metadata = corr_svc.sanitize_correlation_metadata({
        "source": "clerk_activity_event",
        "rule_key": rule_key,
        "signal_type": signal.signal_type,
        "resource_type": rule["match_key"],
        "match_reason": match_reason,
        "match_strength": match_strength,
        "finding_severity": finding.severity,
        "instance_id": instance_id,
        "application_id": application_id if rule["match_key"] == "application" else None,
        "domain_id": domain_id if rule["match_key"] == "domain" else None,
        "redirect_url_config_id": redirect_url_config_id if rule["match_key"] == "redirect_url_config" else None,
        "jwt_template_id": jwt_template_id if rule["match_key"] == "jwt_template" else None,
        "webhook_endpoint_id": webhook_endpoint_id if rule["match_key"] == "webhook_endpoint" else None,
        "auth_strategy_id": auth_strategy_id if rule["match_key"] == "auth_strategy" else None,
        "organization_settings_id": organization_settings_id if rule["match_key"] == "organization_settings" else None,
        "session_policy_id": session_policy_id if rule["match_key"] == "session_policy" else None,
        "event_types": _smd(signal, "event_types"),
        "event_count": _smdint(signal, "event_count"),
        "risk_family": rule["match_key"],
        "activity_family": rule["match_key"],
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
        return True

    s_time = _aware(signal.last_seen_at) or _aware(signal.first_seen_at)
    if s_time is None:
        return True

    window_open = f_start - _WINDOW
    window_close = f_end + _WINDOW
    return window_open <= s_time <= window_close


# ── Main function ─────────────────────────────────────────────────────────────


def generate_clerk_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_correlations: int = 100,
) -> dict[str, Any]:
    """Generate Clerk Risk × Activity correlations for a workspace.

    Joins active Clerk configuration-risk findings with Clerk activity signals
    using safe resource identifiers (instance_id, application_id, domain_id,
    redirect_url_config_id, jwt_template_id, webhook_endpoint_id,
    auth_strategy_id, organization_settings_id, session_policy_id) or
    provider+family aggregate matching when no per-resource identity is
    available for singleton resources.

    Covers ten correlation families: instance_settings, application, domain,
    redirect_url_config, jwt_template, webhook_endpoint, email_sms_settings,
    auth_strategy, organization_settings, and session_policy.

    Clerk secret key values, publishable key values, session tokens, JWTs,
    OAuth tokens, bearer tokens, webhook secrets, raw webhook URLs, raw redirect
    URLs, raw domain names, JWT template bodies, custom claims, audience URIs,
    issuer URIs, user emails, user IDs, phone numbers, names, member identities,
    session history, login history, IP addresses, user agents, raw audit
    payloads, and PII are never used or stored.
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

    # ── Load active Clerk findings ────────────────────────────────────────────
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

    # ── Load recent Clerk activity signals ────────────────────────────────────
    all_signal_types: set[str] = set()
    for rule in CLERK_CORRELATION_RULES.values():
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

    for correlation_type, rule in CLERK_CORRELATION_RULES.items():
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
                match_reason = _match_pair(finding, signal, rule["match_key"])
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
                        "clerk_correlations: failed to upsert one pair; continuing"
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
