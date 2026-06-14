"""Stripe activity/Events ingestion (M73B).

Ingests Stripe configuration-change activity — surfaced through the public
``/v1/events`` Stripe Events API — into the shared ``security_activity_events``
table (``provider="stripe"``, ``source="stripe_events"``). The connector applies
a STRICT event-type allowlist at the API level: webhook endpoint, payment link,
billing portal configuration, account, and capability changes only. Customer /
payment / charge / invoice / refund / dispute / dispute / subscription lifecycle
events are deliberately NEVER requested.

INGESTION SOURCE (deliberate): reading the Events API requires that the Stripe
API key (a secret or restricted key) grant the "Events" permission. When that
access is not granted, ingestion fails soft and reports ``permission_limited``
— it NEVER breaks the existing Stripe configuration-risk sync, and it never
scrapes or infers events from other surfaces.

CLAIM DISCIPLINE: this ingests provider configuration-change activity. It does
NOT confirm a breach, payment fraud, compromise, unauthorized access, data
exposure, attacker presence, or a leaked secret. Events are "evidence for
review".

NON-FATAL BY DESIGN: missing permission / unavailable endpoint / throttling /
network failures are captured in the returned summary, never raised.

PRIVACY: only allowlisted, flat, safe fields are stored (account id, Stripe
object id + type NAME, webhook endpoint id + URL scheme + URL host only,
payment link id, portal config id, capability NAME + status, ``livemode``,
event timestamp). NEVER customer PII / emails, payment method data, card data,
charges/payment intents/invoices/customer records, raw event payloads, raw API
responses, OAuth tokens, signing secrets (``webhook_endpoint.secret``),
authorization headers, request/response bodies, bank-account details, or tax
IDs.
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
from app.connectors.stripe import StripeConnector, _url_origin
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "stripe"
SOURCE = "stripe_events"
EVENT_SOURCE = "stripe_events_api"


# Map a raw Stripe event type → a normalized ``stripe.<surface>.<action>`` type.
# A change here must be reflected in StripeConnector._ALLOWED_EVENT_TYPES so the
# connector and normalizer stay aligned.
_EVENT_TYPE_MAP: dict[str, str] = {
    "webhook_endpoint.created": "stripe.webhook_endpoint.created",
    "webhook_endpoint.updated": "stripe.webhook_endpoint.updated",
    "webhook_endpoint.deleted": "stripe.webhook_endpoint.deleted",
    "payment_link.created": "stripe.payment_link.created",
    "payment_link.updated": "stripe.payment_link.updated",
    "billing_portal.configuration.created": "stripe.portal_config.created",
    "billing_portal.configuration.updated": "stripe.portal_config.updated",
    "account.updated": "stripe.account.updated",
    "capability.updated": "stripe.capability.updated",
}


def _safe_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value.strip() else None


def _safe_bool(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _ts(raw: Any) -> Optional[datetime]:
    """Stripe ``created`` is a Unix epoch in seconds. Be defensive."""
    if raw is None:
        return None
    try:
        if isinstance(raw, datetime):
            return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        if isinstance(raw, (int, float)):
            ts = float(raw)
            if ts > 1e12:  # accidental ms → seconds
                ts /= 1000.0
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(raw, str):
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        return None
    return None


def _url_host(url: Any) -> Optional[str]:
    """Return the host portion of a URL or None — never query strings / paths."""
    origin = _url_origin(url) if isinstance(url, str) and url.strip() else None
    if not origin:
        return None
    try:
        from urllib.parse import urlparse

        parsed = urlparse(origin)
        return parsed.netloc or None
    except Exception:
        return None


def _url_scheme(url: Any) -> Optional[str]:
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return (parsed.scheme or None) if parsed.scheme in {"http", "https"} else None
    except Exception:
        return None


def normalize_stripe_activity_event(entry: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map one raw Stripe event dict → a normalized activity dict.

    Returns ``None`` for malformed entries or for any event type NOT in the
    configuration allowlist (defense-in-depth even though the connector already
    filters at the API level). Only safe, flat, allowlisted fields are
    extracted. Customer / payment / charge / invoice / subscription /
    dispute / refund / setup_intent / source / payout / transfer / topup
    lifecycle events are skipped; their PII / payment data is never traversed.
    """
    if not isinstance(entry, dict):
        return None

    raw_type = _safe_str(entry.get("type"))
    if not raw_type or raw_type not in _EVENT_TYPE_MAP:
        # Defense-in-depth: a customer/payment/charge/invoice/etc. event makes
        # it past the connector → drop it silently. Its PII / payment data is
        # never traversed.
        return None
    event_type = _EVENT_TYPE_MAP[raw_type]

    data = entry.get("data") if isinstance(entry.get("data"), dict) else {}
    obj = data.get("object") if isinstance(data.get("object"), dict) else {}

    # Stripe ``account`` field on the event itself names the connected account
    # (or, when absent, the platform account context).
    account_id = _safe_str(entry.get("account"))
    livemode = _safe_bool(entry.get("livemode"))

    object_type = _safe_str(obj.get("object"))
    object_id = _safe_str(obj.get("id"))
    occurred_at = _ts(entry.get("created"))

    # Surface-specific NAME extraction (NEVER signing secrets, customer PII,
    # payment method data, or raw URLs with query strings).
    webhook_endpoint_id = None
    webhook_url_domain = None
    webhook_url_scheme = None
    payment_link_id = None
    portal_config_id = None
    capability = None
    capability_status = None

    if raw_type.startswith("webhook_endpoint."):
        webhook_endpoint_id = object_id
        webhook_url_domain = _url_host(obj.get("url"))
        webhook_url_scheme = _url_scheme(obj.get("url"))
    elif raw_type.startswith("payment_link."):
        payment_link_id = object_id
    elif raw_type.startswith("billing_portal.configuration."):
        portal_config_id = object_id
    elif raw_type == "capability.updated":
        # Object NAME is the capability key (e.g. "card_payments"); status is
        # the lifecycle state (active/pending/inactive/unrequested).
        capability = _safe_str(obj.get("id"))
        capability_status = _safe_str(obj.get("status"))

    metadata = {
        "stripe_event_type": raw_type,
        "event_action": raw_type,
        "event_source": EVENT_SOURCE,
        "account_id": account_id,
        "object_type": object_type,
        "object_id": object_id,
        "webhook_endpoint_id": webhook_endpoint_id,
        "webhook_url_domain": webhook_url_domain,
        "webhook_url_scheme": webhook_url_scheme,
        "payment_link_id": payment_link_id,
        "portal_config_id": portal_config_id,
        "capability": capability,
        "capability_status": capability_status,
        "livemode": livemode,
        "event_time": occurred_at.isoformat() if occurred_at else None,
    }

    resource_type = object_type or "account"
    resource_id = (
        webhook_endpoint_id or payment_link_id or portal_config_id or object_id or account_id
    )
    event_id = _safe_str(entry.get("id"))

    provider_event_id = event_id or activity_svc.compute_event_fingerprint(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        actor_id=None,
        resource_id=resource_id,
        occurred_at=occurred_at,
    )

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        occurred_at=occurred_at,
        provider_event_id=provider_event_id,
        # Stripe events do not expose a per-event actor for config changes
        # (dashboard or API). We intentionally store no actor identity.
        actor_id=None,
        actor_type=None,
        resource_type=resource_type,
        resource_id=resource_id,
        source_ip=None,
        metadata=metadata,
        raw_ref=event_id,
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


def ingest_stripe_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Ingest Stripe configuration-change activity for one integration. Never raises."""
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not a Stripe integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("stripe_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve Stripe credentials."
        return summary

    connector = StripeConnector()
    hard_error: Optional[str] = None

    try:
        events = connector.list_activity_events(
            credentials, max_events=max_events, lookback_hours=lookback_hours
        )
    except AuthenticationError:
        # Invalid/revoked key → don't claim success, but also don't break the
        # caller. Mark permission-limited so the UI shows a soft warning.
        events = []
        summary["permission_limited"] = True
    except ConnectorError as exc:
        events = []
        code = getattr(exc, "status_code", None)
        if code in (401, 403, 404, 422):
            summary["permission_limited"] = True
        elif code == 503:
            hard_error = "Stripe is temporarily unavailable."
        else:
            hard_error = "Stripe events request failed."
    except RateLimitError:
        events = []
        hard_error = "Stripe rate limit reached; try again later."
    except NetworkError:
        events = []
        hard_error = "Network error reaching Stripe."
    except Exception:  # noqa: BLE001
        logger.exception("stripe_activity: unexpected error")
        events = []
        hard_error = "Unexpected error ingesting Stripe activity."

    seen = inserted = skipped = 0
    for entry in events:
        seen += 1
        normalized = normalize_stripe_activity_event(entry)
        if normalized is None:
            continue  # malformed / non-allowlisted entry → skip safely
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id, integration_id=integration.id,
                normalized=normalized, db=db,
            )
        except Exception:  # noqa: BLE001 — one bad row never fails the batch
            logger.warning("stripe_activity: failed to upsert one event; continuing")
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
                "Stripe Events API access is limited for this key "
                "(a key with the Events read permission is required)."
            )
    return summary
