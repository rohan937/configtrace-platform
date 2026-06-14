"""Shopify activity/Events ingestion (M74B).

Ingests Shopify configuration-change activity — surfaced through the public
``/admin/api/{version}/events.json`` Shopify Events REST API — into the shared
``security_activity_events`` table (``provider="shopify"``, ``source="shopify_events"``).
The connector applies a STRICT ``subject_type`` allowlist at the API level
(``Webhook``, ``Shop``, ``Domain`` only). Customer / order / checkout / cart /
payment / fulfillment / inventory / refund / staff subject types are
deliberately NEVER requested.

INGESTION SOURCE (deliberate): reading the Shopify Events API requires that the
Admin API access token grant the appropriate read scope for the surface
involved (e.g. ``read_shop`` / ``read_themes`` and the bundled events scope).
When that access is not granted, ingestion fails soft and reports
``permission_limited`` — it NEVER breaks the existing Shopify
configuration-risk sync, and it never scrapes or infers events from other
surfaces.

CLAIM DISCIPLINE: this ingests provider configuration-change activity. It does
NOT confirm a breach, attack, payment fraud, compromise, unauthorized access,
exposure of order details, exposure of customer records, exposure of card
data, attacker presence, or a leaked secret. Events are "evidence for review".

NON-FATAL BY DESIGN: missing permission / unavailable endpoint / throttling /
network failures are captured in the returned summary, never raised.

PRIVACY: only allowlisted, flat, safe fields are stored (shop domain,
canonical .myshopify.com domain, subject_type/verb NAMES, webhook id +
endpoint URL host + scheme + topic NAME, app scope COUNT + sanitized scope
NAME sample, shop-domain id + host NAME, store policy_type NAME, ``livemode``,
event timestamp). NEVER customer PII / emails, orders, carts/checkouts,
payment method data, card data, refunds, fulfillments, raw event payloads,
raw API responses, the event ``arguments`` / ``message`` / ``path`` /
``author`` fields, OAuth access tokens, webhook signing secrets, Admin API
tokens, authorization headers, request/response bodies, bank-account details,
tax IDs, or staff names/emails.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.shopify import ShopifyConnector
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "shopify"
SOURCE = "shopify_events"
EVENT_SOURCE = "shopify_events_api"


# Map a raw (subject_type, verb) pair → a normalized ``shopify.<surface>.<action>``
# event type. A change here must be reflected in
# ``ShopifyConnector._ALLOWED_EVENT_SUBJECT_TYPES`` so the connector and the
# normalizer stay aligned. Customer / order / payment / checkout / cart /
# fulfillment / inventory / refund / staff subject types are intentionally
# absent — the connector never requests them, and this map drops them silently
# if they ever slipped through (defense-in-depth).
_EVENT_TYPE_MAP: dict[tuple[str, str], str] = {
    ("Webhook", "create"): "shopify.webhook.created",
    ("Webhook", "update"): "shopify.webhook.updated",
    ("Webhook", "destroy"): "shopify.webhook.deleted",
    ("Shop", "update"): "shopify.shop.updated",
    ("Domain", "create"): "shopify.domain.created",
    ("Domain", "update"): "shopify.domain.updated",
    ("Domain", "destroy"): "shopify.domain.deleted",
}


def _safe_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value.strip() else None


def _safe_bool(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _ts(raw: Any) -> Optional[datetime]:
    """Shopify ``created_at`` is an ISO-8601 string. Be defensive."""
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
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        parsed = urlparse(url)
        return parsed.netloc or None
    except Exception:
        return None


def _url_scheme(url: Any) -> Optional[str]:
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        parsed = urlparse(url)
        return (parsed.scheme or None) if parsed.scheme in {"http", "https"} else None
    except Exception:
        return None


def normalize_shopify_activity_event(entry: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map one raw Shopify event dict → a normalized activity dict.

    Returns ``None`` for malformed entries or for any (subject_type, verb)
    pair NOT in the configuration allowlist (defense-in-depth even though the
    connector already filters at the API level). Only safe, flat, allowlisted
    fields are extracted. The raw ``arguments``, ``message``, ``path``, and
    ``author`` fields are NEVER traversed — they can contain customer PII,
    order details, or staff names.
    """
    if not isinstance(entry, dict):
        return None

    subject_type = _safe_str(entry.get("subject_type"))
    verb = _safe_str(entry.get("verb"))
    if not subject_type or not verb:
        return None

    key = (subject_type, verb.lower())
    if key not in _EVENT_TYPE_MAP:
        # Defense-in-depth: a customer/order/payment/etc. subject_type that
        # somehow leaked past the connector's API-level allowlist is dropped
        # silently. Its arguments / message / path are never traversed.
        return None
    event_type = _EVENT_TYPE_MAP[key]

    subject_id_raw = entry.get("subject_id")
    object_id: Optional[str] = None
    if isinstance(subject_id_raw, (int, float)):
        try:
            object_id = str(int(subject_id_raw))
        except (ValueError, TypeError):
            object_id = None
    elif isinstance(subject_id_raw, str) and subject_id_raw.strip():
        object_id = subject_id_raw.strip()

    occurred_at = _ts(entry.get("created_at"))

    # Surface-specific allowlisted NAME extraction. The connector intentionally
    # does NOT expose webhook URLs / topics on the Events endpoint (Shopify's
    # /events.json response does not include them either); these fields stay
    # None on this code path. They are reserved for a future enrichment that
    # would re-query the safe Webhook config endpoint, never the payload.
    webhook_id: Optional[str] = None
    webhook_topic: Optional[str] = None
    webhook_endpoint_domain: Optional[str] = None
    webhook_endpoint_scheme: Optional[str] = None
    domain_id: Optional[str] = None
    domain_host: Optional[str] = None
    policy_type: Optional[str] = None

    if subject_type == "Webhook":
        webhook_id = object_id
        # If the connector ever surfaces an enrichment dict (e.g. via a separate
        # safe Webhook config fetch), extract NAME-only fields. Never traverse
        # arbitrary keys — only the allowlisted ones below.
        meta = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else None
        if meta is not None:
            webhook_topic = _safe_str(meta.get("topic"))
            webhook_endpoint_domain = _url_host(meta.get("address")) or _safe_str(
                meta.get("endpoint_domain")
            )
            webhook_endpoint_scheme = _url_scheme(meta.get("address")) or _safe_str(
                meta.get("endpoint_scheme")
            )
    elif subject_type == "Domain":
        domain_id = object_id
        meta = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else None
        if meta is not None:
            domain_host = _safe_str(meta.get("host"))

    # Shop-scope identifiers — present on every event regardless of subject.
    shop_domain = _safe_str(entry.get("shop_domain"))
    myshopify_domain = _safe_str(entry.get("myshopify_domain"))

    livemode = _safe_bool(entry.get("livemode"))

    metadata = {
        "shopify_event_type": f"{subject_type}/{verb.lower()}",
        "event_action": verb.lower(),
        "event_source": EVENT_SOURCE,
        "shop_domain": shop_domain,
        "myshopify_domain": myshopify_domain,
        "object_type": subject_type,
        "object_id": object_id,
        "webhook_id": webhook_id,
        "webhook_topic": webhook_topic,
        "webhook_endpoint_domain": webhook_endpoint_domain,
        "webhook_endpoint_scheme": webhook_endpoint_scheme,
        "domain_id": domain_id,
        "domain_host": domain_host,
        "policy_type": policy_type,
        "livemode": livemode,
        "event_time": occurred_at.isoformat() if occurred_at else None,
    }

    resource_type = subject_type
    resource_id = object_id or myshopify_domain or shop_domain
    event_id_raw = entry.get("id")
    event_id: Optional[str] = None
    if isinstance(event_id_raw, (int, float)):
        try:
            event_id = str(int(event_id_raw))
        except (ValueError, TypeError):
            event_id = None
    elif isinstance(event_id_raw, str) and event_id_raw.strip():
        event_id = event_id_raw.strip()

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
        # Shopify Events surface an ``author`` field that can be a staff name
        # or email — we intentionally store no actor identity.
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


def ingest_shopify_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Ingest Shopify configuration-change activity for one integration. Never raises."""
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not a Shopify integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("shopify_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve Shopify credentials."
        return summary

    connector = ShopifyConnector()
    hard_error: Optional[str] = None

    try:
        events = connector.list_activity_events(
            credentials, max_events=max_events, lookback_hours=lookback_hours
        )
    except AuthenticationError:
        # Invalid/revoked token → don't claim success, but also don't break the
        # caller. Mark permission-limited so the UI shows a soft warning.
        events = []
        summary["permission_limited"] = True
    except ConnectorError as exc:
        events = []
        code = getattr(exc, "status_code", None)
        if code in (401, 403, 404, 422):
            summary["permission_limited"] = True
        elif code == 503:
            hard_error = "Shopify is temporarily unavailable."
        else:
            hard_error = "Shopify events request failed."
    except RateLimitError:
        events = []
        hard_error = "Shopify rate limit reached; try again later."
    except NetworkError:
        events = []
        hard_error = "Network error reaching Shopify."
    except Exception:  # noqa: BLE001
        logger.exception("shopify_activity: unexpected error")
        events = []
        hard_error = "Unexpected error ingesting Shopify activity."

    seen = inserted = skipped = 0
    for entry in events:
        seen += 1
        normalized = normalize_shopify_activity_event(entry)
        if normalized is None:
            continue  # malformed / non-allowlisted entry → skip safely
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id,
                integration_id=integration.id,
                normalized=normalized,
                db=db,
            )
        except Exception:  # noqa: BLE001 — one bad row never fails the batch
            logger.warning("shopify_activity: failed to upsert one event; continuing")
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
                "Shopify Events API access is limited for this token "
                "(a token with the required Events read scope is required)."
            )
    return summary
