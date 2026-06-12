"""Cloudflare WAF / security-event ingestion (M68.4).

Ingests Cloudflare per-request WAF / firewall / security events (the
``firewallEventsAdaptive`` GraphQL dataset) into the shared
``security_activity_events`` table (``provider="cloudflare"``,
``source="waf_security_event"``) — the "what security-relevant traffic did
Cloudflare observe?" layer that complements M68.1 audit-log activity ("who
changed Cloudflare settings?").

CLAIM DISCIPLINE: these are WAF / SECURITY EVENTS for review (blocked / challenged
/ logged requests). They are NOT confirmed attacks, breaches, exploits, or
unauthorized access — only evidence for review. Actor identity is never inferred
from an IP.

INGESTION SOURCE: Cloudflare GraphQL Analytics (``firewallEventsAdaptive``),
which requires an analytics-capable token and an eligible plan/zone. Live-API
validation is DEFERRED (no eligible test token); the connector is small and
mockable. Everything fails soft — missing GraphQL access / unsupported plan /
no permission / ineligible zone / rate limit / malformed response never breaks
the normal Cloudflare sync.

PRIVACY: only allowlisted, flat, safe fields are stored. NEVER the raw client IP
(hashed only), the raw URL / query string, the raw path (hashed; an optional
sanitized prefix only), cookies, headers, request bodies, payloads, tokens,
secrets, session ids, or the raw GraphQL event JSON.
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.connectors.cloudflare import CloudflareConnector
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

PROVIDER = "cloudflare"
SOURCE = "waf_security_event"
EVENT_SOURCE = "cloudflare_waf"

# Cloudflare firewall action → normalized event type.
_ACTION_MAP: dict[str, str] = {
    "block": "cloudflare.waf_event.block",
    "challenge": "cloudflare.waf_event.challenge",
    "managed_challenge": "cloudflare.waf_event.managed_challenge",
    "jschallenge": "cloudflare.waf_event.js_challenge",
    "js_challenge": "cloudflare.waf_event.js_challenge",
    "log": "cloudflare.waf_event.log",
    "skip": "cloudflare.waf_event.skip",
    "allow": "cloudflare.waf_event.allow",
}
_FALLBACK_EVENT_TYPE = "cloudflare.waf_event.event"

_SAFE_PREFIX_RE = re.compile(r"^[A-Za-z0-9._\-]{1,40}$")


def _event_type(action: Any) -> str:
    if not isinstance(action, str) or not action:
        return _FALLBACK_EVENT_TYPE
    return _ACTION_MAP.get(action.lower(), _FALLBACK_EVENT_TYPE)


def _safe_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value.strip() else None


def _path_hash(path: Any) -> Optional[str]:
    """Salted, truncated hash of the request path. Never stores the raw path."""
    if not isinstance(path, str) or not path.strip():
        return None
    # Strip any query string defensively before hashing.
    p = path.split("?", 1)[0]
    key = getattr(settings, "ENCRYPTION_KEY", "") or ""
    salt = ("cf_waf_path_v1:" + str(key)).encode("utf-8")
    return hashlib.sha256(salt + p.encode("utf-8")).hexdigest()[:32]


def _path_prefix(path: Any) -> Optional[str]:
    """Return a sanitized leading path segment, or None.

    Only the first segment after the leading '/', kept ONLY if it matches a short
    safe charset — so a path containing sensitive values never round-trips.
    """
    if not isinstance(path, str) or not path.strip():
        return None
    head = path.split("?", 1)[0].lstrip("/").split("/", 1)[0]
    return head if _SAFE_PREFIX_RE.match(head) else None


def _parse_ts(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    try:
        if isinstance(raw, datetime):
            return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        if isinstance(raw, (int, float)):
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        if isinstance(raw, str):
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        return None
    return None


def _fingerprint(parts: list[Optional[str]]) -> str:
    basis = "|".join(p or "" for p in parts)
    return "cfwaf:" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:40]


def normalize_waf_event(
    event: dict[str, Any], *, zone_name: Optional[str] = None
) -> Optional[dict[str, Any]]:
    """Map one raw firewallEventsAdaptive event → a normalized activity dict."""
    if not isinstance(event, dict):
        return None

    action = event.get("action")
    event_type = _event_type(action)

    ray = _safe_str(event.get("rayName"))
    rule_id = _safe_str(event.get("ruleId"))
    ruleset_id = _safe_str(event.get("rulesetId"))
    path = event.get("clientRequestPath")
    occurred = _parse_ts(event.get("datetime"))
    zone_id = _safe_str(event.get("_zone_id")) or _safe_str(event.get("zoneTag"))

    # Deterministic fingerprint from non-raw-able fields (idempotency). A ray id
    # can carry multiple events, so include rule/action/path-hash/time.
    pe_id = _fingerprint([
        ray, rule_id, ruleset_id,
        _safe_str(action), _path_hash(path),
        _safe_str(event.get("datetime")),
    ])

    metadata = {
        "action": _safe_str(action),
        "rule_id": rule_id,
        "rule_name": _safe_str(event.get("description")),
        "ruleset_id": ruleset_id,
        "client_country": _safe_str(event.get("clientCountryName")),
        "method": _safe_str(event.get("clientRequestHTTPMethodName")),
        "host": _safe_str(event.get("clientRequestHTTPHost")),
        "path_hash": _path_hash(path),
        "path_prefix": _path_prefix(path),
        "ray_id": ray,
        "service": _safe_str(event.get("source")),
        "outcome": _safe_str(action),
        "event_source": EVENT_SOURCE,
        "zone_id": zone_id,
        "zone_name": _safe_str(zone_name),
    }

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        occurred_at=occurred,
        provider_event_id=pe_id,
        actor_id=None,  # never infer an actor from a request/IP
        actor_type="waf_event",
        resource_type="cloudflare_zone" if zone_id else None,
        resource_id=zone_id,
        # Hashed to source_ip_hash by normalize_activity_event — raw IP never stored.
        source_ip=_safe_str(event.get("clientIP")),
        metadata=metadata,
        raw_ref=ray,
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


def ingest_cloudflare_waf_events(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 200,
) -> dict[str, Any]:
    """Ingest Cloudflare WAF/security events for one integration. Never raises."""
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not a Cloudflare integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("cloudflare_waf: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve Cloudflare credentials."
        return summary

    zone_name = _safe_str(credentials.get("zone_name"))
    connector = CloudflareConnector()
    hard_error: Optional[str] = None

    try:
        events = connector.list_waf_security_events(
            credentials, lookback_hours=lookback_hours, max_events=max_events
        )
    except AuthenticationError:
        summary["permission_limited"] = True
        events = []
    except ConnectorError as exc:
        events = []
        code = getattr(exc, "status_code", None)
        if code in (401, 403, 404, 422):
            summary["permission_limited"] = True
        elif code == 503:
            hard_error = "Cloudflare is temporarily unavailable."
        else:
            hard_error = "Cloudflare WAF/security-event request failed."
    except RateLimitError:
        events = []
        hard_error = "Cloudflare rate limit reached; try again later."
    except NetworkError:
        events = []
        hard_error = "Network error reaching Cloudflare."
    except Exception:  # noqa: BLE001
        logger.exception("cloudflare_waf: unexpected error")
        events = []
        hard_error = "Unexpected error ingesting Cloudflare WAF events."

    seen = inserted = skipped = 0
    for event in events:
        seen += 1
        normalized = normalize_waf_event(event, zone_name=zone_name)
        if normalized is None:
            continue  # malformed event — skipped safely
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id, integration_id=integration.id,
                normalized=normalized, db=db,
            )
        except Exception:  # noqa: BLE001 — one bad row never fails the batch
            logger.warning("cloudflare_waf: failed to upsert one event; continuing")
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
                "Cloudflare WAF/security events are unavailable for this token/plan "
                "(GraphQL Analytics access and an eligible plan are required)."
            )
    return summary
