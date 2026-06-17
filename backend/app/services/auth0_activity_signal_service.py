"""Auth0 Configuration Activity Incident Signals (M81E).

Promotes Auth0 configuration-state activity events (provider=auth0,
source=auth0_activity_event, synthesized in M81D) into review-worthy Incident
Signals covering tenant settings, application, connection, resource server,
rule, action, MFA factor, and custom domain configuration changes.

Conservative + deterministic + idempotent: events are grouped by
(signal_type, resource_identity); each group yields one signal anchored on
the group's latest event, with a deterministic signal_key so re-running
creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration review signals.
They NEVER assert that a breach, compromise, unauthorized access, leaked
secret, exposed data, or attacker presence has been confirmed. Severity
reflects review priority only.

PRIVACY: signal metadata is allowlisted + flat. NEVER client_secret,
management_api_token, access tokens, refresh tokens, ID tokens, JWTs,
JWKS, private keys, authorization headers, raw Auth0 API responses, raw
log entries, raw callback/logout/origin URLs, audience URIs, custom domain
name strings, rule/action script content, action secret values, user
emails, user IDs, user names, profile data, IP addresses, device
fingerprints, session data, MFA enrollment/recovery data, connection
credentials, social provider secrets, SAML certificates, or any customer
PII. Only safe opaque identifiers, booleans, counts, and category labels.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "auth0"
SOURCE = "auth0_activity_event"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is evidence for review and may require review. ConfigTrace does not "
    "confirm compromise, unauthorized access, or data exposure."
)

# ── Event type → signal_type ──────────────────────────────────────────────────
AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE: dict[str, str] = {
    "auth0.tenant.updated": "auth0_tenant_config_changed",
    "auth0.application.created": "auth0_application_config_changed",
    "auth0.application.updated": "auth0_application_config_changed",
    "auth0.application.deleted": "auth0_application_config_changed",
    "auth0.connection.created": "auth0_connection_config_changed",
    "auth0.connection.updated": "auth0_connection_config_changed",
    "auth0.connection.deleted": "auth0_connection_config_changed",
    "auth0.resource_server.created": "auth0_resource_server_config_changed",
    "auth0.resource_server.updated": "auth0_resource_server_config_changed",
    "auth0.resource_server.deleted": "auth0_resource_server_config_changed",
    "auth0.rule.created": "auth0_rule_config_changed",
    "auth0.rule.updated": "auth0_rule_config_changed",
    "auth0.rule.deleted": "auth0_rule_config_changed",
    "auth0.action.created": "auth0_action_config_changed",
    "auth0.action.updated": "auth0_action_config_changed",
    "auth0.action.deployed": "auth0_action_config_changed",
    "auth0.action.deleted": "auth0_action_config_changed",
    "auth0.mfa_factor.updated": "auth0_mfa_factor_config_changed",
    "auth0.custom_domain.created": "auth0_custom_domain_config_changed",
    "auth0.custom_domain.updated": "auth0_custom_domain_config_changed",
    "auth0.custom_domain.verified": "auth0_custom_domain_config_changed",
    "auth0.custom_domain.deleted": "auth0_custom_domain_config_changed",
    "auth0.config.event": "auth0_config_activity",
}

AUTH0_SIGNAL_TYPES: frozenset[str] = frozenset(
    AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE.values()
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

    Uses safe opaque identifiers only — never client_secret, management tokens,
    raw URLs, callback URLs, domain names, user emails, or any credential.
    """
    return (
        _md(ev, "client_id")
        or _md(ev, "connection_id")
        or _md(ev, "resource_server_id")
        or _md(ev, "rule_id")
        or _md(ev, "action_id")
        or _md(ev, "custom_domain_id")
        or _md(ev, "factor_name")
        or _md(ev, "resource_id")
        or ev.resource_id
        or "global"
    )


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    """Deterministic group key — one signal per (signal_type, resource)."""
    signal_type = AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE.get(ev.event_type)
    if signal_type is None:
        return None
    rkey = _resource_key(ev)
    return "|".join(["auth0.activity", signal_type, rkey])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id)."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(signal_type: str) -> str:
    """Conservative review-priority severity. Never asserts confirmed impact."""
    if signal_type in (
        "auth0_application_config_changed",
        "auth0_connection_config_changed",
        "auth0_resource_server_config_changed",
        "auth0_rule_config_changed",
        "auth0_action_config_changed",
        "auth0_mfa_factor_config_changed",
        "auth0_tenant_config_changed",
    ):
        return "medium"
    # custom domain and generic config events are lower review priority.
    return "low"


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    signal_type = AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE.get(anchor.event_type)
    if signal_type is None:
        return None

    # Collect unique event types in this group (sorted for determinism).
    unique_event_types = sorted({ev.event_type for ev in group})
    event_types_str = ", ".join(unique_event_types)

    resource_type = _md(anchor, "resource_type") or anchor.resource_type or "configuration"

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    title = (
        f"Auth0 {resource_type} activity: {len(group)} "
        f"{signal_type.replace('_', ' ')} event(s)"
    )
    summary = (
        f"Review-worthy Auth0 configuration activity detected on {resource_type}. "
        f"{len(group)} event(s) recorded in the review window. "
        f"Does not confirm compromise or unauthorized access — evidence for review. "
        f"{_REVIEW_NOTE}"
    ).strip()

    gk = _group_key(anchor)

    # Gather safe metadata fields from anchor event.
    # PRIVACY: NEVER include client_secret, management_api_token, access tokens,
    # JWTs, raw URLs, callback/logout/origin URLs, domain names, user emails,
    # user IDs, IP addresses, script content, action secrets, or PII.
    md_raw: dict[str, Any] = {
        "source": SOURCE,
        "event_types": event_types_str,
        "event_count": len(group),
        "resource_type": resource_type,
        "resource_id": _md(anchor, "resource_id"),
        "resource_name": _md(anchor, "resource_name"),
        "client_id": _md(anchor, "client_id"),
        "connection_id": _md(anchor, "connection_id"),
        "resource_server_id": _md(anchor, "resource_server_id"),
        "rule_id": _md(anchor, "rule_id"),
        "action_id": _md(anchor, "action_id"),
        "factor_name": _md(anchor, "factor_name"),
        "custom_domain_id": _md(anchor, "custom_domain_id"),
        "operation_family": _md(anchor, "operation_family"),
        "operation_action": _md(anchor, "operation_action"),
        "category": _md(anchor, "category"),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        # Safe boolean/int application config fields (never raw URLs or secrets).
        "app_type": _md(anchor, "app_type"),
        "is_first_party": _mdbool(anchor, "is_first_party"),
        "jwt_alg": _md(anchor, "jwt_alg"),
        "oidc_conformant": _mdbool(anchor, "oidc_conformant"),
        "token_endpoint_auth_method": _md(anchor, "token_endpoint_auth_method"),
        "refresh_token_rotation_enabled": _mdbool(anchor, "refresh_token_rotation_enabled"),
        "refresh_token_lifetime_category": _md(anchor, "refresh_token_lifetime_category"),
        "grant_types_count": _mdint(anchor, "grant_types_count"),
        "callbacks_count": _mdint(anchor, "callbacks_count"),
        "allowed_logout_urls_count": _mdint(anchor, "allowed_logout_urls_count"),
        "allowed_origins_count": _mdint(anchor, "allowed_origins_count"),
        "web_origins_count": _mdint(anchor, "web_origins_count"),
        # Safe connection config fields.
        "enabled_clients_count": _mdint(anchor, "enabled_clients_count"),
        "password_policy_category": _md(anchor, "password_policy_category"),
        # Safe resource server config fields.
        "signing_alg": _md(anchor, "signing_alg"),
        "token_lifetime_category": _md(anchor, "token_lifetime_category"),
        "allow_offline_access": _mdbool(anchor, "allow_offline_access"),
        "rbac_enabled": _mdbool(anchor, "rbac_enabled"),
        # Safe rule/action config fields.
        "script_present": _mdbool(anchor, "script_present"),
        "script_length_category": _md(anchor, "script_length_category"),
        "code_present": _mdbool(anchor, "code_present"),
        "code_length_category": _md(anchor, "code_length_category"),
        "secrets_count": _mdint(anchor, "secrets_count"),
        "enabled": _mdbool(anchor, "enabled"),
        # Safe custom domain / MFA factor config fields.
        "status_category": _md(anchor, "status_category"),
        "tls_policy_category": _md(anchor, "tls_policy_category"),
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


def generate_auth0_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Auth0 configuration review signals for a workspace.

    Reads normalized auth0 / auth0_activity_event activity events (M81D) and
    promotes selected config-state events into Incident Signals. Idempotent —
    re-running creates no duplicates. Never raises.

    PRIVACY: only safe, allowlisted fields are stored in signal metadata.
    Client secrets, management tokens, access tokens, JWTs, raw URLs,
    callback/logout/origin URLs, audience URIs, domain name strings, script
    content, action secrets, user emails, user IDs, IP addresses, session data,
    connection credentials, and raw Auth0 API responses are never stored.

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
                "auth0_signals: failed to build or upsert one group; continuing"
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
