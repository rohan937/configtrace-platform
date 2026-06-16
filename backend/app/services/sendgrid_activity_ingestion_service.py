"""SendGrid configuration activity ingestion (M80D).

SendGrid does NOT have a native audit/event API for configuration changes.
This service ingests config-state observation events synthesized by the
connector's ``list_activity_events`` method (the same safe HTTP calls the
drift connector already makes) into the shared ``security_activity_events``
table (``provider="sendgrid"``, ``source="sendgrid_activity_event"``).

INGESTION SCOPE (deliberate):
  Only safe configuration/control-plane surfaces are ingested: account,
  API key metadata, sender identity, domain authentication, mail settings,
  tracking settings, event webhook, inbound parse, and suppression settings.
  Mail-delivery events (bounce, delivered, deferred, dropped, click, open,
  spamreport, unsubscribe, group_unsubscribe, processed) are NEVER ingested —
  they are filtered at both the connector and the normalizer here.

CLAIM DISCIPLINE: events are configuration-state evidence for review. This
service does NOT confirm a breach, attacker, compromise, unauthorized access,
data exposure, or leaked secret.

NON-FATAL BY DESIGN: missing permission / unavailable endpoint / throttling /
network failures are captured in the returned summary, never raised. Existing
SendGrid drift sync is never interrupted by activity ingestion failures.

PRIVACY: only allowlisted, flat, safe fields are stored — safe booleans, counts,
opaque IDs (api_key_id, sender_id, domain_id), domain names, and configuration
flags. NEVER stored: API key values, bearer tokens, authorization headers,
email bodies, subject lines, recipient emails, sender personal emails,
suppression recipient emails, template content, raw webhook URLs, raw inbound
parse hostnames, message IDs, mail event payloads, raw DNS values, raw SendGrid
API response dicts, raw HTTP request/response bodies, customer data, or PII.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.sendgrid import (
    _SENDGRID_CONFIG_EVENT_TYPES,
    SendGridConnector,
)
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "sendgrid"
SOURCE = "sendgrid_activity_event"
EVENT_SOURCE = "sendgrid_activity_event"


def normalize_sendgrid_activity_event(
    entry: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Map one connector config-state event → a normalized activity event.

    The ``entry`` dict is produced by the connector's ``list_activity_events``
    method and contains only safe flat fields: event_type, provider, source,
    event_source, provider_event_id, metadata.

    Returns None for:
      * malformed entries missing required fields, OR
      * ANY event_type not in the SENDGRID config-event allowlist.

    This is a hard privacy gate: mail-delivery event types (bounce, delivered,
    deferred, dropped, click, open, spamreport, unsubscribe, group_unsubscribe,
    processed) are NEVER in the allowlist, so they can never be normalized or
    stored even if a caller passes them.

    NEVER touches raw SendGrid API payloads, email bodies, subject lines,
    recipient emails, template content, API key values, or customer data.
    """
    if not isinstance(entry, dict):
        return None

    event_type = entry.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        return None

    # Hard allowlist gate — drop any non-config (mail-delivery) event type.
    if event_type not in _SENDGRID_CONFIG_EVENT_TYPES:
        return None

    provider_event_id: Optional[str] = entry.get("provider_event_id") or None
    if isinstance(provider_event_id, str) and not provider_event_id.strip():
        provider_event_id = None

    metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}

    resource_type = metadata.get("resource_type") or None
    resource_id = (
        metadata.get("resource_id")
        or metadata.get("api_key_id")
        or metadata.get("sender_id")
        or metadata.get("domain_id")
        or None
    )

    # Compute fingerprint fallback if no stable provider_event_id.
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
        # SendGrid config-state events surface no actor identity (and an actor
        # email would be PII) — we intentionally store no actor.
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


def ingest_sendgrid_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Ingest SendGrid configuration-state activity events for one integration.

    Never raises. All errors are captured in the returned summary dict. The
    existing SendGrid drift sync is never interrupted by failures here.

    Args:
        integration:    A ``sendgrid`` Integration model row.
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
        summary["error_message"] = "Not a SendGrid integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("sendgrid_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve SendGrid credentials."
        return summary

    connector = SendGridConnector()
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
            hard_error = "SendGrid API request failed."
    except RateLimitError:
        hard_error = "SendGrid rate limit reached; try again later."
    except NetworkError:
        hard_error = "Network error reaching SendGrid."
    except Exception:  # noqa: BLE001
        logger.exception("sendgrid_activity: unexpected error")
        hard_error = "Unexpected error ingesting SendGrid configuration activity."

    seen = inserted = skipped = 0
    for entry in events:
        seen += 1
        normalized = normalize_sendgrid_activity_event(entry)
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
            logger.warning("sendgrid_activity: failed to upsert one event; continuing")
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
                "SendGrid configuration access is limited for these credentials. "
                "Ensure the API key has read access to account, API key, sender "
                "identity, domain authentication, mail/tracking settings, event "
                "webhook, and suppression configuration surfaces."
            )

    return summary


def sync_sendgrid_activity(
    *,
    workspace_id: uuid.UUID,
    integration_id: Optional[str],
    lookback_hours: int = 24,
    max_events: int = 100,
    db: Session,
) -> dict[str, Any]:
    """Look up the SendGrid integration and delegate to ingest_sendgrid_activity.

    Convenience wrapper used by the router endpoint. Never raises — all errors
    are captured in the returned summary dict.

    Args:
        workspace_id:   Workspace UUID for storage scoping.
        integration_id: Optional integration UUID string to target a specific
                        integration; when None the first active SendGrid
                        integration for the workspace is used.
        lookback_hours: Lookback window (1–168 hours; capped internally).
        max_events:     Maximum events to ingest (1–1000; capped internally).
        db:             Database session.

    Returns:
        Summary dict compatible with SendGridActivitySyncResponse.
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
                empty["error_message"] = "SendGrid integration not found."
                return empty
        else:
            integration = (
                q.filter(Integration.status == "active")
                .order_by(Integration.created_at.asc())
                .first()
            )
            if integration is None:
                empty["error_message"] = "No active SendGrid integration found."
                return empty

        return ingest_sendgrid_activity(
            integration=integration,
            workspace_id=workspace_id,
            db=db,
            lookback_hours=lookback_hours,
            max_events=max_events,
        )
    except Exception:  # noqa: BLE001
        logger.exception("sendgrid_activity: unexpected error in sync_sendgrid_activity")
        empty["error_message"] = "Unexpected error during SendGrid activity sync."
        return empty
