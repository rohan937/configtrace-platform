"""PagerDuty configuration activity ingestion (M84D).

PagerDuty's audit trail API includes actor emails, user IDs, IP addresses,
and user agents in every entry — ingesting those would violate ConfigTrace's
privacy contract. This service ingests config-state observation events
synthesized by the connector's list_activity_events method from the same safe
configuration surfaces the drift connector reads (M84A–M84C): services,
escalation policies, schedules, service integrations, webhook subscriptions,
event orchestrations, business services, and response plays.

INGESTION SCOPE (deliberate):
  Only service configuration posture, escalation policy structure, schedule
  coverage, service integration type/key presence, webhook subscription
  active/event/scheme posture, event orchestration route/team posture,
  business service team/contact posture, and response play
  responder/subscriber/runnability posture.
  Raw PagerDuty audit logs, actor identity, incident content, alert data,
  and operational payloads are NEVER fetched, ingested, or stored.

CLAIM DISCIPLINE: events are configuration-state evidence for review. This
service does NOT confirm a breach, attacker, compromise, unauthorized access,
data exposure, or leaked credential.

NON-FATAL BY DESIGN: missing permission / unavailable endpoint / throttling /
network failures are captured in the returned summary, never raised.

PRIVACY: only allowlisted, flat, safe fields are stored — opaque IDs,
safe booleans, counts, and category labels. NEVER stored:
- PagerDuty API token values, routing keys, integration keys
- Webhook secrets, delivery URLs, custom header names/values
- User emails, user names, phone numbers, contact methods
- On-call user identities, responder identities, subscriber identities
- Incident payloads, alert payloads, conference phone numbers
- Raw routing expressions, IP addresses, user agents
- Raw PagerDuty audit payloads, raw API response dicts
- Customer data, PII
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.connectors.pagerduty import PagerDutyConnector
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

PROVIDER = "pagerduty"
SOURCE = "pagerduty_activity_event"
EVENT_SOURCE = "pagerduty_activity_event"

# Hard allowlist of PagerDuty config-state event types. Only these may be
# normalized and stored. Raw audit/incident/alert/user event types are NEVER
# in this set and can NEVER be stored, even if a caller passes them.
_PAGERDUTY_CONFIG_EVENT_TYPES: frozenset[str] = frozenset({
    "pagerduty.service.updated",
    "pagerduty.escalation_policy.updated",
    "pagerduty.schedule.updated",
    "pagerduty.service_integration.updated",
    "pagerduty.webhook_subscription.updated",
    "pagerduty.event_orchestration.updated",
    "pagerduty.business_service.updated",
    "pagerduty.response_play.updated",
    "pagerduty.config.event",
})

# Expose the allowlist so tests and the router can import it.
PAGERDUTY_CONFIG_EVENT_TYPES = _PAGERDUTY_CONFIG_EVENT_TYPES


def normalize_pagerduty_activity_event(
    entry: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Map one connector config-state event → a normalized activity event.

    The entry dict is produced by PagerDutyConnector.list_activity_events()
    and contains only safe flat fields: event_type, provider, source,
    event_source, provider_event_id, metadata.

    Returns None for:
      * malformed entries missing required fields, OR
      * ANY event_type not in the PagerDuty config-event allowlist.

    This is a hard privacy gate: incident/audit/alert/user event types are
    NEVER in the allowlist and can NEVER be normalized or stored, even if a
    caller passes them.

    NEVER touches raw PagerDuty API payloads, routing keys, integration keys,
    webhook secrets, user emails, user IDs, IP addresses, or any
    credential/PII material.
    """
    if not isinstance(entry, dict):
        return None

    event_type = entry.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        return None

    # Hard allowlist gate — drop any non-config event type.
    if event_type not in _PAGERDUTY_CONFIG_EVENT_TYPES:
        return None

    provider_event_id: Optional[str] = entry.get("provider_event_id") or None
    if isinstance(provider_event_id, str) and not provider_event_id.strip():
        provider_event_id = None

    metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}

    resource_type = metadata.get("resource_type") or None
    resource_id = (
        metadata.get("resource_id")
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
        # PagerDuty config-state events surface no actor identity — we
        # intentionally store no actor to avoid any risk of ingesting PII.
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


def ingest_pagerduty_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Ingest PagerDuty configuration-state activity events for one integration.

    Never raises. All errors are captured in the returned summary dict.

    Args:
        integration:    A pagerduty Integration model row.
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
        summary["error_message"] = "Not a PagerDuty integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("pagerduty_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve PagerDuty credentials."
        return summary

    connector = PagerDutyConnector()
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
        hard_error = "PagerDuty rate limit reached; try again later."
    except NetworkError:
        hard_error = "Network error reaching PagerDuty."
    except ConnectorError as exc:
        code = getattr(exc, "status_code", None)
        if code in (401, 403, 404, 422):
            summary["permission_limited"] = True
        else:
            hard_error = "PagerDuty API request failed."
    except Exception:  # noqa: BLE001
        logger.exception("pagerduty_activity: unexpected error")
        hard_error = "Unexpected error ingesting PagerDuty configuration activity."

    seen = inserted = skipped = 0
    for entry in events:
        seen += 1
        normalized = normalize_pagerduty_activity_event(entry)
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
            logger.warning(
                "pagerduty_activity: failed to upsert one event; continuing"
            )
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
                "PagerDuty API access is limited for these credentials. "
                "Ensure the PagerDuty API token has read access to services, "
                "escalation policies, schedules, and webhook subscriptions."
            )

    return summary


def sync_pagerduty_activity(
    *,
    workspace_id: uuid.UUID,
    integration_id: Optional[str],
    lookback_hours: int = 24,
    max_events: int = 100,
    db: Session,
) -> dict[str, Any]:
    """Look up the PagerDuty integration and delegate to ingest_pagerduty_activity.

    Convenience wrapper used by the router endpoint. Never raises — all errors
    are captured in the returned summary dict.

    Args:
        workspace_id:   Workspace UUID for storage scoping.
        integration_id: Optional integration UUID string to target a specific
                        integration; when None the first active PagerDuty
                        integration for the workspace is used.
        lookback_hours: Lookback window (1–168 hours; capped internally).
        max_events:     Maximum events to ingest (1–1000; capped internally).
        db:             Database session.

    Returns:
        Summary dict compatible with PagerDutyActivitySyncResponse.
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
                empty["error_message"] = "PagerDuty integration not found."
                return empty
        else:
            integration = (
                q.filter(Integration.status == "active")
                .order_by(Integration.created_at.asc())
                .first()
            )
            if integration is None:
                empty["error_message"] = "No active PagerDuty integration found."
                return empty

        return ingest_pagerduty_activity(
            integration=integration,
            workspace_id=workspace_id,
            db=db,
            lookback_hours=lookback_hours,
            max_events=max_events,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "pagerduty_activity: unexpected error in sync_pagerduty_activity"
        )
        empty["error_message"] = (
            "Unexpected error during PagerDuty activity sync."
        )
        return empty
