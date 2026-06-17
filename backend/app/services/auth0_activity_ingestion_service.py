"""Auth0 configuration activity ingestion (M81D).

Auth0 Management API logs (/api/v2/logs) are highly user-centric: every
entry includes user_id, email, IP address, and device data. ConfigTrace
NEVER ingests from that endpoint. Instead, this service ingests config-state
observation events synthesized by the connector's ``list_activity_events``
method from the same safe configuration surfaces the drift connector reads.

INGESTION SCOPE (deliberate):
  Only tenant settings, applications, connections, resource servers, rules,
  actions, MFA/Guardian factors, and custom domains. Login, authentication,
  session, token-exchange, password-reset, MFA-enrollment, user profile, and
  organization-member events are NEVER fetched, ingested, or stored.

CLAIM DISCIPLINE: events are configuration-state evidence for review. This
service does NOT confirm a breach, attacker, compromise, unauthorized access,
data exposure, or leaked credential.

NON-FATAL BY DESIGN: missing permission / unavailable endpoint / throttling /
network failures are captured in the returned summary, never raised.

PRIVACY: only allowlisted, flat, safe fields are stored — opaque IDs,
safe booleans, counts, and category labels. NEVER stored: client_secret,
management API token, access/refresh/ID tokens, JWTs, JWKS, private keys,
authorization headers, raw callback/logout/origin URLs, audience URIs,
custom domain name strings, rule/action script content, action secret
values, user emails, user IDs, user names, profile data, IP addresses,
device data, session data, MFA enrollment data, recovery codes, connection
credentials, social provider secrets, SAML certificates, raw Auth0 API
response dicts, raw log entries, or any customer PII.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.connectors.auth0 import _AUTH0_CONFIG_EVENT_TYPES, Auth0Connector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "auth0"
SOURCE = "auth0_activity_event"
EVENT_SOURCE = "auth0_activity_event"


def normalize_auth0_activity_event(
    entry: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Map one connector config-state event → a normalized activity event.

    The ``entry`` dict is produced by Auth0Connector.list_activity_events()
    and contains only safe flat fields: event_type, provider, source,
    event_source, provider_event_id, metadata.

    Returns None for:
      * malformed entries missing required fields, OR
      * ANY event_type not in the Auth0 config-event allowlist.

    This is a hard privacy gate: login/auth/session/token/profile/org-member
    event types are NEVER in the allowlist and can NEVER be normalized or
    stored, even if a caller passes them.

    NEVER touches raw Auth0 API payloads, log entries, user emails, user IDs,
    IP addresses, session data, or any credential material.
    """
    if not isinstance(entry, dict):
        return None

    event_type = entry.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        return None

    # Hard allowlist gate — drop any non-config event type.
    if event_type not in _AUTH0_CONFIG_EVENT_TYPES:
        return None

    provider_event_id: Optional[str] = entry.get("provider_event_id") or None
    if isinstance(provider_event_id, str) and not provider_event_id.strip():
        provider_event_id = None

    metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}

    resource_type = metadata.get("resource_type") or None
    resource_id = (
        metadata.get("resource_id")
        or metadata.get("client_id")
        or metadata.get("connection_id")
        or metadata.get("resource_server_id")
        or metadata.get("rule_id")
        or metadata.get("action_id")
        or metadata.get("custom_domain_id")
        or metadata.get("factor_name")
        or None
    )

    # Compute deterministic fingerprint fallback if no stable provider_event_id.
    if not provider_event_id:
        provider_event_id = activity_svc.compute_event_fingerprint(
            provider=PROVIDER,
            source=SOURCE,
            event_type=event_type,
            actor_id=None,
            resource_id=resource_id,
            occurred_at=None,
        )

    metadata_with_source = dict(metadata)
    metadata_with_source["event_source"] = EVENT_SOURCE

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        occurred_at=None,
        provider_event_id=provider_event_id,
        # Auth0 config-state events surface no actor identity — we intentionally
        # store no actor to avoid any risk of ingesting PII.
        actor_id=None,
        actor_type=None,
        resource_type=resource_type,
        resource_id=resource_id,
        source_ip=None,
        metadata=metadata_with_source,
        raw_ref=entry.get("provider_event_id") or None,
    )


def _empty_summary(integration_id: Optional[uuid.UUID]) -> dict[str, Any]:
    return {
        "attempted": False,
        "succeeded": False,
        "provider": PROVIDER,
        "integration_id": str(integration_id) if integration_id else None,
        "source": SOURCE,
        "events_seen": 0,
        "events_inserted": 0,
        "events_skipped": 0,
        "permission_limited": False,
        "error_message": None,
    }


def ingest_auth0_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Ingest Auth0 configuration-state activity events for one integration.

    Never raises. All errors are captured in the returned summary dict.

    Args:
        integration:    An ``auth0`` Integration model row.
        workspace_id:   Workspace UUID for storage scoping.
        db:             Database session.
        lookback_hours: Lookback window (1–168 hours; capped internally).
        max_events:     Maximum events to ingest (1–1000; capped internally).

    Returns:
        Summary dict with attempted/succeeded/events_seen/events_inserted/
        events_skipped/permission_limited/error_message fields.
    """
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not an Auth0 integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("auth0_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve Auth0 credentials."
        return summary

    connector = Auth0Connector()
    hard_error: Optional[str] = None
    events: list[dict] = []

    try:
        events = connector.list_activity_events(
            credentials,
            max_events=max_events,
            lookback_hours=lookback_hours,
        )
    except AuthenticationError:
        summary["permission_limited"] = True
    except RateLimitError:
        hard_error = "Auth0 rate limit reached; try again later."
    except NetworkError:
        hard_error = "Network error reaching Auth0."
    except ConnectorError as exc:
        code = getattr(exc, "status_code", None)
        if code in (401, 403, 404, 422):
            summary["permission_limited"] = True
        else:
            hard_error = "Auth0 Management API request failed."
    except Exception:  # noqa: BLE001
        logger.exception("auth0_activity: unexpected error")
        hard_error = "Unexpected error ingesting Auth0 configuration activity."

    seen = inserted = skipped = 0
    for entry in events:
        seen += 1
        normalized = normalize_auth0_activity_event(entry)
        if normalized is None:
            continue
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id,
                integration_id=integration.id,
                normalized=normalized,
                db=db,
            )
        except Exception:  # noqa: BLE001
            logger.warning("auth0_activity: failed to upsert one event; continuing")
            continue
        if outcome == "inserted":
            inserted += 1
        else:
            skipped += 1

    summary["events_seen"] = seen
    summary["events_inserted"] = inserted
    summary["events_skipped"] = skipped

    if hard_error is not None:
        summary["error_message"] = hard_error
        summary["succeeded"] = False
    else:
        summary["succeeded"] = True
        if summary["permission_limited"] and seen == 0:
            summary["error_message"] = (
                "Auth0 Management API access is limited for these credentials. "
                "Ensure the credentials have read access to tenant settings, "
                "applications, connections, resource servers, rules, actions, "
                "Guardian factors, and custom domains."
            )

    return summary


def sync_auth0_activity(
    *,
    workspace_id: uuid.UUID,
    integration_id: Optional[str],
    lookback_hours: int = 24,
    max_events: int = 100,
    db: Session,
) -> dict[str, Any]:
    """Look up the Auth0 integration and delegate to ingest_auth0_activity.

    Convenience wrapper used by the router endpoint. Never raises — all errors
    are captured in the returned summary dict.

    Args:
        workspace_id:   Workspace UUID for storage scoping.
        integration_id: Optional integration UUID string to target a specific
                        integration; when None the first active Auth0
                        integration for the workspace is used.
        lookback_hours: Lookback window (1–168 hours; capped internally).
        max_events:     Maximum events to ingest (1–1000; capped internally).
        db:             Database session.

    Returns:
        Summary dict compatible with Auth0ActivitySyncResponse.
    """
    empty: dict[str, Any] = {
        "attempted": False,
        "succeeded": False,
        "provider": PROVIDER,
        "integration_id": integration_id,
        "source": SOURCE,
        "events_seen": 0,
        "events_inserted": 0,
        "events_skipped": 0,
        "permission_limited": False,
        "error_message": None,
    }

    try:
        q = db.query(Integration).filter(Integration.provider == PROVIDER)

        if integration_id:
            try:
                iid = uuid.UUID(str(integration_id))
            except (ValueError, AttributeError, TypeError):
                empty["error_message"] = "Invalid integration_id."
                return empty
            integration = q.filter(Integration.id == iid).first()
            if integration is None:
                empty["error_message"] = "Auth0 integration not found."
                return empty
        else:
            integration = (
                q.filter(Integration.status == "active")
                .order_by(Integration.created_at.asc())
                .first()
            )
            if integration is None:
                empty["error_message"] = "No active Auth0 integration found."
                return empty

        return ingest_auth0_activity(
            integration=integration,
            workspace_id=workspace_id,
            db=db,
            lookback_hours=lookback_hours,
            max_events=max_events,
        )
    except Exception:  # noqa: BLE001
        logger.exception("auth0_activity: unexpected error in sync_auth0_activity")
        empty["error_message"] = "Unexpected error during Auth0 activity sync."
        return empty
