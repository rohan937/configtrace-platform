"""Clerk Configuration Activity Incident Signals (M83E).

Promotes Clerk configuration-state activity events (provider=clerk,
source=clerk_activity_event, synthesized in M83D) into review-worthy Incident
Signals covering instance settings, application, domain, redirect URL config,
JWT template, webhook endpoint, email/SMS settings, auth strategy, organization
settings, and session policy configuration changes.

Conservative + deterministic + idempotent: events are grouped by
(signal_type, resource_identity); each group yields one signal anchored on
the group's latest event, with a deterministic signal_key so re-running
creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration review signals.
They NEVER assert that a breach, compromise, unauthorized access, leaked
secret, exposed data, or attacker presence has been confirmed. Severity
reflects review priority only.

PRIVACY: signal metadata is allowlisted + flat. NEVER stored:
- Clerk secret key values, publishable key values
- Session tokens, JWTs, OAuth tokens, bearer tokens
- Webhook secrets, webhook URLs, webhook signing keys
- Raw redirect URLs, raw callback URLs, raw allowed origins
- Raw domain name strings
- JWT template bodies, custom claims, audience URIs, issuer URIs
- User emails, user IDs, user names, phone numbers
- Organization names (customer-identifying), member identities
- Session history, login history, login events, authentication events
- IP addresses, user agents, device fingerprints
- Raw Clerk API response dicts, raw audit payloads, PII of any kind
Only safe opaque identifiers, booleans, counts, and category labels.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "clerk"
SOURCE = "clerk_activity_event"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is evidence for review and may require review. ConfigTrace does not "
    "confirm compromise, unauthorized access, or data exposure."
)

# ── Event type → signal_type ──────────────────────────────────────────────────
CLERK_EVENT_TYPE_TO_SIGNAL_TYPE: dict[str, str] = {
    "clerk.instance_settings.updated": "clerk_instance_settings_config_changed",
    "clerk.domain.created": "clerk_domain_config_changed",
    "clerk.domain.updated": "clerk_domain_config_changed",
    "clerk.domain.deleted": "clerk_domain_config_changed",
    "clerk.redirect_url_config.created": "clerk_redirect_url_config_changed",
    "clerk.redirect_url_config.updated": "clerk_redirect_url_config_changed",
    "clerk.redirect_url_config.deleted": "clerk_redirect_url_config_changed",
    "clerk.jwt_template.created": "clerk_jwt_template_config_changed",
    "clerk.jwt_template.updated": "clerk_jwt_template_config_changed",
    "clerk.jwt_template.deleted": "clerk_jwt_template_config_changed",
    "clerk.webhook_endpoint.created": "clerk_webhook_endpoint_config_changed",
    "clerk.webhook_endpoint.updated": "clerk_webhook_endpoint_config_changed",
    "clerk.webhook_endpoint.deleted": "clerk_webhook_endpoint_config_changed",
    "clerk.email_sms_settings.updated": "clerk_email_sms_settings_config_changed",
    "clerk.auth_strategy.updated": "clerk_auth_strategy_config_changed",
    "clerk.organization_settings.updated": "clerk_organization_settings_config_changed",
    "clerk.session_policy.updated": "clerk_session_policy_config_changed",
    "clerk.config.event": "clerk_config_activity",
}

CLERK_SIGNAL_TYPES: frozenset[str] = frozenset(
    CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.values()
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> datetime:
    if not isinstance(dt, datetime):
        return datetime.min.replace(tzinfo=timezone.utc)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _when(ev: SecurityActivityEvent) -> datetime:
    return _aware(ev.occurred_at or ev.ingested_at or ev.created_at)


def _md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    """Read a string metadata field from the activity event (never raises)."""
    data = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = data.get(key)
    return v if isinstance(v, str) and v.strip() else None


def _mdbool(ev: SecurityActivityEvent, key: str) -> Optional[bool]:
    """Read a bool metadata field from the activity event (never raises)."""
    data = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = data.get(key)
    return v if isinstance(v, bool) else None


def _mdint(ev: SecurityActivityEvent, key: str) -> Optional[int]:
    """Read an int metadata field from the activity event (never raises)."""
    data = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = data.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _resource_key(ev: SecurityActivityEvent) -> str:
    """Pick the most specific safe resource identifier for grouping.

    Uses safe opaque identifiers only — never Clerk secret key values,
    publishable keys, session tokens, JWTs, raw redirect URLs, raw webhook
    URLs, raw domain names, JWT template bodies, user emails, user IDs,
    phone numbers, member identities, IP addresses, or any credential/PII.
    """
    return (
        _md(ev, "instance_id")
        or _md(ev, "domain_id")
        or _md(ev, "redirect_url_config_id")
        or _md(ev, "jwt_template_id")
        or _md(ev, "webhook_endpoint_id")
        or _md(ev, "email_sms_settings_id")
        or _md(ev, "auth_strategy_id")
        or _md(ev, "organization_settings_id")
        or _md(ev, "session_policy_id")
        or _md(ev, "application_id")
        or _md(ev, "resource_id")
        or ev.resource_id
        or "global"
    )


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    """Deterministic group key — one signal per (signal_type, resource)."""
    signal_type = CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.get(ev.event_type)
    if signal_type is None:
        return None
    rkey = _resource_key(ev)
    return "|".join(["clerk.activity", signal_type, rkey])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id)."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(signal_type: str) -> str:
    """Conservative review-priority severity. Never asserts confirmed impact."""
    if signal_type in (
        "clerk_instance_settings_config_changed",
        "clerk_auth_strategy_config_changed",
        "clerk_session_policy_config_changed",
        "clerk_organization_settings_config_changed",
        "clerk_jwt_template_config_changed",
        "clerk_webhook_endpoint_config_changed",
    ):
        return "medium"
    # Application, domain, redirect URL, email/SMS, and generic config events
    # are lower review priority.
    return "low"


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    signal_type = CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.get(anchor.event_type)
    if signal_type is None:
        return None

    # Collect unique event types in this group (sorted for determinism).
    unique_event_types = sorted({ev.event_type for ev in group})
    event_types_str = ", ".join(unique_event_types)

    resource_type = _md(anchor, "resource_type") or anchor.resource_type or "configuration"

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    title = (
        f"Clerk {resource_type} activity: {len(group)} "
        f"{signal_type.replace('_', ' ')} event(s)"
    )
    summary = (
        f"Review-worthy Clerk configuration activity detected on {resource_type}. "
        f"{len(group)} event(s) recorded in the review window. "
        f"Does not confirm compromise or unauthorized access — evidence for review. "
        f"{_REVIEW_NOTE}"
    ).strip()

    gk = _group_key(anchor)

    # Gather safe metadata fields from anchor event.
    # PRIVACY: NEVER include Clerk secret keys, publishable keys, session tokens,
    # JWTs, raw redirect URLs, webhook URLs, raw domain names, JWT template bodies,
    # custom claims, audience URIs, issuer URIs, user emails, user IDs, phone numbers,
    # names, member identities, session history, login history, IP addresses, user agents,
    # raw audit payloads, or any PII.
    md_raw: dict[str, Any] = {
        "source": SOURCE,
        "event_types": event_types_str,
        "event_count": len(group),
        "resource_type": resource_type,
        "resource_id": _md(anchor, "resource_id"),
        "instance_id": _md(anchor, "instance_id"),
        "application_id": _md(anchor, "application_id"),
        "domain_id": _md(anchor, "domain_id"),
        "redirect_url_config_id": _md(anchor, "redirect_url_config_id"),
        "jwt_template_id": _md(anchor, "jwt_template_id"),
        "webhook_endpoint_id": _md(anchor, "webhook_endpoint_id"),
        "email_sms_settings_id": _md(anchor, "email_sms_settings_id"),
        "auth_strategy_id": _md(anchor, "auth_strategy_id"),
        "organization_settings_id": _md(anchor, "organization_settings_id"),
        "session_policy_id": _md(anchor, "session_policy_id"),
        "operation_family": _md(anchor, "operation_family"),
        "operation_action": _md(anchor, "operation_action"),
        "category": _md(anchor, "category"),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        # Safe instance config fields
        "environment_type": _md(anchor, "environment_type"),
        "sign_up_enabled": _mdbool(anchor, "sign_up_enabled"),
        "sign_in_enabled": _mdbool(anchor, "sign_in_enabled"),
        "password_enabled": _mdbool(anchor, "password_enabled"),
        "email_enabled": _mdbool(anchor, "email_enabled"),
        "phone_enabled": _mdbool(anchor, "phone_enabled"),
        "username_enabled": _mdbool(anchor, "username_enabled"),
        "social_provider_count": _mdint(anchor, "social_provider_count"),
        "mfa_enabled": _mdbool(anchor, "mfa_enabled"),
        "mfa_factor_count": _mdint(anchor, "mfa_factor_count"),
        "mfa_required": _mdbool(anchor, "mfa_required"),
        "domain_count": _mdint(anchor, "domain_count"),
        "webhook_count": _mdint(anchor, "webhook_count"),
        # Safe auth strategy fields
        "oauth_enabled": _mdbool(anchor, "oauth_enabled"),
        "oauth_provider_count": _mdint(anchor, "oauth_provider_count"),
        "saml_enabled": _mdbool(anchor, "saml_enabled"),
        "passkey_enabled": _mdbool(anchor, "passkey_enabled"),
        "magic_link_enabled": _mdbool(anchor, "magic_link_enabled"),
        # Safe session policy fields
        "session_lifetime_category": _md(anchor, "session_lifetime_category"),
        "inactivity_timeout_category": _md(anchor, "inactivity_timeout_category"),
        "single_session_enabled": _mdbool(anchor, "single_session_enabled"),
        "device_tracking_enabled": _mdbool(anchor, "device_tracking_enabled"),
        "reverification_required": _mdbool(anchor, "reverification_required"),
        "token_rotation_enabled": _mdbool(anchor, "token_rotation_enabled"),
        # Safe organization settings fields
        "organizations_enabled": _mdbool(anchor, "organizations_enabled"),
        "verified_domains_required": _mdbool(anchor, "verified_domains_required"),
        "invitation_enabled": _mdbool(anchor, "invitation_enabled"),
        "admin_role_present": _mdbool(anchor, "admin_role_present"),
        "role_count": _mdint(anchor, "role_count"),
        "permission_count": _mdint(anchor, "permission_count"),
        # Safe domain fields
        "domain_type": _md(anchor, "domain_type"),
        "verified": _mdbool(anchor, "verified"),
        "primary": _mdbool(anchor, "primary"),
        "ssl_enabled": _mdbool(anchor, "ssl_enabled"),
        "dns_status_category": _md(anchor, "dns_status_category"),
        # Safe redirect URL fields
        "url_scheme_category": _md(anchor, "url_scheme_category"),
        "wildcard_present": _mdbool(anchor, "wildcard_present"),
        "localhost_present": _mdbool(anchor, "localhost_present"),
        "custom_scheme_present": _mdbool(anchor, "custom_scheme_present"),
        # Safe JWT template fields
        "name": _md(anchor, "name"),
        "enabled": _mdbool(anchor, "enabled"),
        "claims_count": _mdint(anchor, "claims_count"),
        "custom_claims_present": _mdbool(anchor, "custom_claims_present"),
        "audience_present": _mdbool(anchor, "audience_present"),
        "issuer_present": _mdbool(anchor, "issuer_present"),
        "lifetime_category": _md(anchor, "lifetime_category"),
        "algorithm": _md(anchor, "algorithm"),
        # Safe webhook endpoint fields
        "url_present": _mdbool(anchor, "url_present"),
        "webhook_subscribed_event_count": _mdint(anchor, "event_count"),
        "secret_present": _mdbool(anchor, "secret_present"),
        # Safe email/SMS settings fields
        "sms_enabled": _mdbool(anchor, "sms_enabled"),
        "custom_sender_present": _mdbool(anchor, "custom_sender_present"),
        "template_customization_present": _mdbool(anchor, "template_customization_present"),
    }

    metadata = signal_svc.sanitize_signal_metadata(md_raw)

    return {
        "provider": PROVIDER,
        "integration_id": anchor.integration_id,
        "signal_key": gk,
        "signal_type": signal_type,
        "severity": _severity(signal_type),
        "status": "open",
        "title": title[:240],
        "summary": summary,
        "evidence_level": EVIDENCE_LEVEL,
        "confidence": CONFIDENCE,
        "first_seen_at": window_start,
        "last_seen_at": window_end,
        "linked_activity_event_id": anchor.id,
        "metadata": metadata,
    }


def generate_clerk_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Clerk configuration review signals for a workspace.

    Reads normalized clerk / clerk_activity_event activity events (M83D) and
    promotes selected config-state events into Incident Signals. Idempotent —
    re-running creates no duplicates. Never raises.

    PRIVACY: only safe, allowlisted fields are stored in signal metadata.
    Clerk secret key values, publishable key values, session tokens, JWTs,
    OAuth tokens, bearer tokens, webhook secrets, raw redirect URLs, raw
    webhook URLs, raw domain names, JWT template bodies, custom claims,
    audience URIs, issuer URIs, user emails, user IDs, phone numbers, names,
    member identities, session history, login history, IP addresses, user
    agents, raw audit payloads, and customer PII are never stored.

    Args:
        workspace_id:   Workspace UUID for data scoping.
        db:             Database session.
        lookback_hours: Lookback window (1–168 hours; capped internally).
        max_signals:    Maximum signals to create (1–1000; capped internally).
        scan_limit:     Maximum activity events to scan.

    Returns:
        Summary dict with provider/source/events_scanned/groups_scanned/
        signals_created/signals_skipped fields.
    """
    hours = max(1, min(int(lookback_hours or 24), 168))
    cap = max(1, min(int(max_signals or 100), 1000))
    cutoff = _utcnow() - timedelta(hours=hours)

    raw = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER,
            SecurityActivityEvent.source == SOURCE,
        )
        .order_by(
            SecurityActivityEvent.occurred_at.desc().nullslast(),
            SecurityActivityEvent.created_at.desc(),
        )
        .limit(scan_limit)
        .all()
    )
    events = [e for e in raw if _when(e) >= cutoff]

    groups: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        gk = _group_key(ev)
        if gk is None:
            continue
        groups.setdefault(gk, []).append(ev)

    created = skipped = 0
    for _gk, group in groups.items():
        if created >= cap:
            break
        try:
            signal = _build_signal(group)
            if signal is None:
                continue
            outcome, _row = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=signal, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1
        except Exception:  # noqa: BLE001
            import logging
            logging.getLogger(__name__).warning(
                "clerk_signals: failed to build or upsert one group; continuing"
            )
            continue

    return {
        "provider": PROVIDER,
        "source": SOURCE,
        "events_scanned": len(events),
        "groups_scanned": len(groups),
        "signals_created": created,
        "signals_skipped": skipped,
    }
