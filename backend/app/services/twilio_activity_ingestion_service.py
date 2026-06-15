"""Twilio Monitor activity ingestion (M79D).

Ingests Twilio configuration-change events — surfaced through the Twilio
Monitor Events API (``https://monitor.twilio.com/v1/Events``) — into the shared
``security_activity_events`` table (``provider="twilio"``,
``source="twilio_activity_event"``).

INGESTION SCOPE (deliberate):
  Only account/subaccount updates, incoming phone number create/update/delete,
  messaging service create/update/delete, Verify service create/update/delete,
  API key create/update/delete, and application create/update/delete events are
  ingested. Message bodies, call logs, recordings, media, SMS/MMS content,
  customer communication data, and customer PII are explicitly excluded at both
  the connector and here.

CLAIM DISCIPLINE: events are configuration-change evidence for review. This
service does NOT confirm a breach, attacker, compromise, unauthorized access,
data exposure, or leaked secret.

NON-FATAL BY DESIGN: missing permission / unavailable endpoint / throttling /
network failures are captured in the returned summary, never raised. Existing
Twilio drift sync is never interrupted by Monitor ingestion failures.

PRIVACY: only allowlisted, flat, safe fields are stored:
  twilio_event_id (Monitor event SID — opaque), twilio_resource_sid_prefix
  (first 8 chars only), resource_type, event_action, account_sid_prefix
  (first 8 chars only), operation_name (truncated description), event_time.

NEVER stored: auth_token, API key secrets, full account SID, full phone number
strings, webhook / callback URL strings, message bodies, call SIDs, call legs,
recording data, customer PII (caller name, verification payloads), raw Twilio
API response dicts, raw HTTP request or response bodies, or any value that could
re-identify a customer or expose a credential.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.twilio import TwilioConnector
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "twilio"
SOURCE = "twilio_activity_event"
EVENT_SOURCE = "twilio_activity_event"


def _ts(raw: Any) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp → UTC-aware datetime."""
    if raw is None:
        return None
    try:
        if isinstance(raw, datetime):
            return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        if isinstance(raw, str):
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        return None
    return None


def normalize_twilio_activity_event(
    entry: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Map one pre-normalized Twilio Monitor event → a normalized activity event.

    The ``entry`` dict is already normalized by the connector's
    ``_normalize_monitor_event`` method and contains only safe flat fields:
    event_type, provider, source, event_source, provider_event_id, metadata.

    Returns None for malformed entries missing required fields.

    NEVER touches raw Twilio API response payloads, message bodies, call logs,
    phone numbers, auth tokens, or customer data.
    """
    if not isinstance(entry, dict):
        return None

    event_type = entry.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        return None

    provider_event_id: Optional[str] = entry.get("provider_event_id") or None
    if isinstance(provider_event_id, str) and not provider_event_id.strip():
        provider_event_id = None

    metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}

    # Parse event_time from metadata for occurred_at
    occurred_at = _ts(metadata.get("event_time"))

    # resource_type and resource_id from safe metadata fields
    resource_type = metadata.get("resource_type") or None
    resource_id = metadata.get("twilio_resource_sid_prefix") or None

    # Compute fingerprint fallback if no stable provider_event_id
    if not provider_event_id:
        provider_event_id = activity_svc.compute_event_fingerprint(
            provider=PROVIDER,
            source=SOURCE,
            event_type=event_type,
            actor_id=None,
            resource_id=resource_id,
            occurred_at=occurred_at,
        )

    # Ensure event_source is present in metadata
    metadata_with_source = dict(metadata)
    metadata_with_source["event_source"] = EVENT_SOURCE

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        occurred_at=occurred_at,
        provider_event_id=provider_event_id,
        # Twilio Monitor events surface an actor_sid — we intentionally store
        # no actor identity (actor email / SID could be PII).
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


def ingest_twilio_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Ingest Twilio Monitor configuration-change events for one integration.

    Never raises. All errors are captured in the returned summary dict. The
    existing Twilio drift sync is never interrupted by failures here.

    Args:
        integration:    A ``twilio`` Integration model row.
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
        summary["error_message"] = "Not a Twilio integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("twilio_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve Twilio credentials."
        return summary

    connector = TwilioConnector()
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
    except ConnectorError as exc:
        code = getattr(exc, "status_code", None)
        if code in (401, 403, 404, 422):
            summary["permission_limited"] = True
        else:
            hard_error = "Twilio Monitor API request failed."
    except RateLimitError:
        hard_error = "Twilio rate limit reached; try again later."
    except NetworkError:
        hard_error = "Network error reaching Twilio."
    except Exception:  # noqa: BLE001
        logger.exception("twilio_activity: unexpected error")
        hard_error = "Unexpected error ingesting Twilio Monitor activity."

    seen = inserted = skipped = 0
    for entry in events:
        seen += 1
        normalized = normalize_twilio_activity_event(entry)
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
            logger.warning("twilio_activity: failed to upsert one event; continuing")
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
                "Twilio Monitor API access is limited for these credentials. "
                "Ensure the account has access to the Twilio Monitor API and that "
                "the auth token is valid. The Monitor API may not be available on "
                "all Twilio plans."
            )

    return summary


def sync_twilio_activity(
    *,
    workspace_id: uuid.UUID,
    integration_id: Optional[str],
    lookback_hours: int = 24,
    max_events: int = 100,
    db: Session,
) -> dict[str, Any]:
    """Look up the Twilio integration and delegate to ingest_twilio_activity.

    Convenience wrapper used by the router endpoint. Never raises — all errors
    are captured in the returned summary dict.

    Args:
        workspace_id:   Workspace UUID for storage scoping.
        integration_id: Optional integration UUID string to target a specific
                        integration; when None the first active Twilio integration
                        for the workspace is used.
        lookback_hours: Lookback window (1–168 hours; capped internally).
        max_events:     Maximum events to ingest (1–1000; capped internally).
        db:             Database session.

    Returns:
        Summary dict compatible with TwilioActivitySyncResponse.
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
                empty["error_message"] = "Twilio integration not found."
                return empty
        else:
            integration = (
                q.filter(Integration.status == "active")
                .order_by(Integration.created_at.asc())
                .first()
            )
            if integration is None:
                empty["error_message"] = "No active Twilio integration found."
                return empty

        return ingest_twilio_activity(
            integration=integration,
            workspace_id=workspace_id,
            db=db,
            lookback_hours=lookback_hours,
            max_events=max_events,
        )
    except Exception:  # noqa: BLE001
        logger.exception("twilio_activity: unexpected error in sync_twilio_activity")
        empty["error_message"] = "Unexpected error during Twilio activity sync."
        return empty
