"""Auth0 Risk × Activity Correlations (M81F).

Joins active Auth0 configuration-risk findings (provider=auth0) with Auth0
activity signals (provider=auth0, from M81E) on the same resource family
within a review window. Produces SecuritySignalCorrelation rows with
evidence_level="correlation".

CORRELATION STRATEGY
--------------------
Eight correlation families, each matching findings to signals by resource
identity:

  tenant           — tenant-level (no per-resource ID); always matches at
                     provider+family level.
  application      — client_id exact match if both sides have it; else
                     provider+family aggregate.
  connection       — connection_id exact match if both have it; else
                     provider+family aggregate.
  resource_server  — resource_server_id exact match if both have it; else
                     provider+family aggregate.
  rule             — rule_id exact match if both have it; else
                     provider+family aggregate.
  action           — action_id exact match if both have it; else
                     provider+family aggregate.
  mfa_factor       — factor_name exact match if both have it; else
                     provider+family aggregate.
  custom_domain    — custom_domain_id exact match if both have it; else
                     provider+family aggregate.

Generic auth0_config_risk_activity_correlation is omitted to avoid noisy
provider-only matches for resource-bearing findings.

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They never assert
that a breach, compromise, unauthorized access, or data exposure has occurred
or been confirmed. Severity = review priority only. Confidence = "medium"
(circumstantial co-occurrence, not proof).

PRIVACY: metadata is allowlisted + flat. NEVER client_secret, management
API token, access/refresh/ID tokens, JWTs, JWKS, private keys, authorization
headers, raw Auth0 API responses, raw log entries, raw callback/logout/origin
URLs, audience URIs, custom domain name strings, rule/action script content,
action secret values, user emails, user IDs, user names, profile data, IP
addresses, device fingerprints, session data, MFA recovery codes, connection
credentials, social provider secrets, SAML certificates, or any PII.
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

PROVIDER = "auth0"

# Default review window around a finding's active period.
_WINDOW = timedelta(hours=24)

_REVIEW_NOTE = (
    "Auth0 configuration risk correlated with configuration activity evidence "
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

AUTH0_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "auth0_tenant_risk_activity_correlation": {
        "rule_keys": {
            "auth0_tenant_session_lifetime_extended",
            "auth0_tenant_idle_session_lifetime_extended",
            "auth0_tenant_dynamic_client_registration_enabled",
        },
        "signal_types": {
            "auth0_tenant_config_changed",
            "auth0_config_activity",
        },
        "match_key": "tenant",
        "severity": "medium",
        "title_phrase": "Auth0 tenant risk aligned with tenant configuration activity",
        "subject_phrase": "Auth0 tenant session / dynamic-registration posture risk",
    },
    "auth0_application_risk_activity_correlation": {
        "rule_keys": {
            "auth0_application_no_callbacks",
            "auth0_application_many_callbacks",
            "auth0_application_many_allowed_origins",
            "auth0_application_oidc_non_conformant",
            "auth0_application_weak_jwt_algorithm",
            "auth0_refresh_token_rotation_disabled",
            "auth0_refresh_token_lifetime_extended",
            "auth0_application_password_grant_enabled",
            "auth0_application_implicit_grant_enabled",
            "auth0_application_public_client_credentials_enabled",
            "auth0_application_refresh_grant_without_rotation",
            "auth0_application_many_grant_types",
            "auth0_application_wildcard_callback",
            "auth0_application_wildcard_allowed_origin",
            "auth0_application_wildcard_logout_url",
            "auth0_application_localhost_callback",
            "auth0_application_localhost_origin",
            "auth0_application_callback_missing_https",
            "auth0_application_origin_missing_https",
            "auth0_public_client_refresh_tokens_enabled",
            "auth0_application_token_endpoint_auth_none",
            "auth0_application_device_code_grant_enabled",
        },
        "signal_types": {
            "auth0_application_config_changed",
            "auth0_config_activity",
        },
        "match_key": "application",
        "severity": "high",
        "title_phrase": "Auth0 application risk aligned with application configuration activity",
        "subject_phrase": "Auth0 application / OAuth grant-type posture risk",
    },
    "auth0_connection_risk_activity_correlation": {
        "rule_keys": {
            "auth0_connection_no_enabled_clients",
            "auth0_connection_weak_password_policy",
            "auth0_connection_mfa_disabled",
        },
        "signal_types": {
            "auth0_connection_config_changed",
            "auth0_config_activity",
        },
        "match_key": "connection",
        "severity": "high",
        "title_phrase": "Auth0 connection risk aligned with connection configuration activity",
        "subject_phrase": "Auth0 connection posture risk",
    },
    "auth0_resource_server_risk_activity_correlation": {
        "rule_keys": {
            "auth0_resource_server_offline_access_enabled",
            "auth0_resource_server_token_lifetime_extended",
            "auth0_resource_server_rbac_disabled",
            "auth0_resource_server_weak_signing_algorithm",
        },
        "signal_types": {
            "auth0_resource_server_config_changed",
            "auth0_config_activity",
        },
        "match_key": "resource_server",
        "severity": "medium",
        "title_phrase": "Auth0 API/resource-server risk aligned with resource-server activity",
        "subject_phrase": "Auth0 resource server / API posture risk",
    },
    "auth0_rule_risk_activity_correlation": {
        "rule_keys": {
            "auth0_rule_disabled",
            "auth0_rule_large_script",
        },
        "signal_types": {
            "auth0_rule_config_changed",
            "auth0_config_activity",
        },
        "match_key": "rule",
        "severity": "medium",
        "title_phrase": "Auth0 rule risk aligned with rule configuration activity",
        "subject_phrase": "Auth0 auth-pipeline rule posture risk",
    },
    "auth0_action_risk_activity_correlation": {
        "rule_keys": {
            "auth0_action_not_deployed",
            "auth0_action_secrets_present",
        },
        "signal_types": {
            "auth0_action_config_changed",
            "auth0_config_activity",
        },
        "match_key": "action",
        "severity": "medium",
        "title_phrase": "Auth0 action risk aligned with action configuration activity",
        "subject_phrase": "Auth0 auth-pipeline action posture risk",
    },
    "auth0_mfa_factor_risk_activity_correlation": {
        "rule_keys": {
            "auth0_mfa_factor_disabled",
        },
        "signal_types": {
            "auth0_mfa_factor_config_changed",
            "auth0_config_activity",
        },
        "match_key": "mfa_factor",
        "severity": "medium",
        "title_phrase": "Auth0 MFA factor risk aligned with MFA factor configuration activity",
        "subject_phrase": "Auth0 MFA / Guardian factor posture risk",
    },
    "auth0_custom_domain_risk_activity_correlation": {
        "rule_keys": {
            "auth0_custom_domain_not_ready",
            "auth0_custom_domain_weak_tls_policy",
        },
        "signal_types": {
            "auth0_custom_domain_config_changed",
            "auth0_config_activity",
        },
        "match_key": "custom_domain",
        "severity": "low",
        "title_phrase": "Auth0 custom-domain risk aligned with custom-domain configuration activity",
        "subject_phrase": "Auth0 custom domain posture risk",
    },
}

AUTH0_CORRELATION_TYPES: frozenset[str] = frozenset(AUTH0_CORRELATION_RULES.keys())


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _fmd(finding: SecurityFinding, key: str) -> Optional[str]:
    """Read a string from finding.evidence (never raises).

    PRIVACY: never returns client_secret, management tokens, JWTs, raw URLs,
    user emails, user IDs, IP addresses, or any credential material.
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


def _smdbool(signal: SecurityIncidentSignal, key: str) -> Optional[bool]:
    """Read a bool from signal.signal_metadata (never raises)."""
    md = signal.signal_metadata if isinstance(signal.signal_metadata, dict) else {}
    v = md.get(key)
    return v if isinstance(v, bool) else None


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
      tenant          — always matches at provider+family level.
      application     — client_id exact match if both have it; else family.
      connection      — connection_id exact match if both have it; else family.
      resource_server — resource_server_id exact match if both have it; else family.
      rule            — rule_id exact match if both have it; else family.
      action          — action_id exact match if both have it; else family.
      mfa_factor      — factor_name exact match if both have it; else family.
      custom_domain   — custom_domain_id exact match if both have it; else family.

    Returns a short safe match_reason string, or None if no match.
    PRIVACY: never matches on user emails, user IDs, IP addresses, session
    data, tokens, JWTs, raw URLs, domain names, or any credential material.
    """
    if match_key == "tenant":
        # Tenant-level: one per workspace, always matches at family level.
        return "tenant_level"

    if match_key == "application":
        f_cid = _fmd(finding, "client_id")
        s_cid = _smd(signal, "client_id")
        if f_cid and s_cid:
            if f_cid == s_cid:
                return "client_id_match"
            # Different application — no cross-application correlation.
            return None
        return "application_family"

    if match_key == "connection":
        f_cid = _fmd(finding, "connection_id")
        s_cid = _smd(signal, "connection_id")
        if f_cid and s_cid:
            if f_cid == s_cid:
                return "connection_id_match"
            return None
        return "connection_family"

    if match_key == "resource_server":
        f_rsid = _fmd(finding, "resource_server_id")
        s_rsid = _smd(signal, "resource_server_id")
        if f_rsid and s_rsid:
            if f_rsid == s_rsid:
                return "resource_server_id_match"
            return None
        return "resource_server_family"

    if match_key == "rule":
        f_rid = _fmd(finding, "rule_id")
        s_rid = _smd(signal, "rule_id")
        if f_rid and s_rid:
            if f_rid == s_rid:
                return "rule_id_match"
            return None
        return "rule_family"

    if match_key == "action":
        f_aid = _fmd(finding, "action_id")
        s_aid = _smd(signal, "action_id")
        if f_aid and s_aid:
            if f_aid == s_aid:
                return "action_id_match"
            return None
        return "action_family"

    if match_key == "mfa_factor":
        f_fn = _fmd(finding, "factor_name")
        s_fn = _smd(signal, "factor_name")
        if f_fn and s_fn:
            if f_fn == s_fn:
                return "factor_name_match"
            return None
        return "mfa_factor_family"

    if match_key == "custom_domain":
        f_did = _fmd(finding, "custom_domain_id")
        s_did = _smd(signal, "custom_domain_id")
        if f_did and s_did:
            if f_did == s_did:
                return "custom_domain_id_match"
            return None
        return "custom_domain_family"

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
        "auth0.correlation",
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
    and category labels. NEVER client_secret, tokens, JWTs, raw URLs, user
    emails, user IDs, IP addresses, or any credential material.
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
    # PRIVACY: NEVER client_secret, management token, JWT, raw URL, email,
    # user ID, IP address, script content, action secret, domain name, or PII.
    client_id = _fmd(finding, "client_id") or _smd(signal, "client_id")
    connection_id = _fmd(finding, "connection_id") or _smd(signal, "connection_id")
    resource_server_id = (
        _fmd(finding, "resource_server_id") or _smd(signal, "resource_server_id")
    )
    rule_id = _fmd(finding, "rule_id") or _smd(signal, "rule_id")
    action_id = _fmd(finding, "action_id") or _smd(signal, "action_id")
    factor_name = _fmd(finding, "factor_name") or _smd(signal, "factor_name")
    custom_domain_id = (
        _fmd(finding, "custom_domain_id") or _smd(signal, "custom_domain_id")
    )

    metadata = corr_svc.sanitize_correlation_metadata({
        "source": "auth0_activity_event",
        "rule_key": rule_key,
        "signal_type": signal.signal_type,
        "resource_type": rule["match_key"],
        "match_reason": match_reason,
        "match_strength": match_strength,
        "finding_severity": finding.severity,
        "client_id": client_id,
        "connection_id": connection_id,
        "resource_server_id": resource_server_id,
        "rule_id": rule_id,
        "action_id": action_id,
        "factor_name": factor_name,
        "custom_domain_id": custom_domain_id,
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
        return True  # conservative — allow match if timestamps are missing

    s_time = _aware(signal.last_seen_at) or _aware(signal.first_seen_at)
    if s_time is None:
        return True

    window_open = f_start - _WINDOW
    window_close = f_end + _WINDOW
    return window_open <= s_time <= window_close


# ── Main function ─────────────────────────────────────────────────────────────


def generate_auth0_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_correlations: int = 100,
) -> dict[str, Any]:
    """Generate Auth0 Risk × Activity correlations for a workspace.

    Joins active Auth0 configuration-risk findings with Auth0 activity signals
    using safe resource identifiers (client_id, connection_id, resource_server_id,
    rule_id, action_id, factor_name, custom_domain_id) or provider+family
    aggregate matching when no per-resource identity is available.

    Covers eight correlation families: tenant, application, connection,
    resource_server, rule, action, mfa_factor, and custom_domain.

    Client secrets, management tokens, access tokens, JWTs, raw URLs, user
    emails, user IDs, IP addresses, session data, script content, action
    secrets, and raw Auth0 API responses are never used or stored.
    Does not confirm compromise, unauthorized access, or data exposure.
    Idempotent — re-running creates no duplicates.

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

    # ── Load active Auth0 findings ────────────────────────────────────────────
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

    # ── Load recent Auth0 activity signals ────────────────────────────────────
    all_signal_types: set[str] = set()
    for rule in AUTH0_CORRELATION_RULES.values():
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

    for correlation_type, rule in AUTH0_CORRELATION_RULES.items():
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
                        "auth0_correlations: failed to upsert one pair; continuing"
                    )
                    continue

    return {
        "provider": PROVIDER,
        "findings_scanned": len(findings),
        "signals_scanned": len(signals),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }
