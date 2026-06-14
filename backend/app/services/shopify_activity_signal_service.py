"""Shopify activity Incident Signals (M74C).

Promotes Shopify configuration-change activity (provider=shopify,
source=shopify_events, ingested in M74B) into review-worthy Incident Signals
(signal_type="shopify_activity_signal", evidence_level="activity",
confidence="medium").

Conservative + deterministic + idempotent: events are grouped by
(shop_domain / myshopify_domain, pattern, event_type, object identity), each
group yields one signal anchored on the group's latest event, with a
deterministic signal_key so re-running creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration-change review signals.
They NEVER assert that a breach, fraud, attacker, compromise, unauthorized
access, or customer-data / order / card-data exposure occurred. Severity
reflects review priority only.

PRIVACY: metadata is allowlisted + flat. NEVER Admin API tokens, OAuth tokens,
private app secrets, webhook signing secrets, raw webhook payloads, raw event
payloads, raw API responses, customer PII / emails, orders, carts /
checkouts with buyer data, payment method data, card data, refunds,
fulfillments with customer/order data, authorization headers, request /
response bodies, bank-account details, tax IDs, or staff names/emails (none
of those are present on the M74B activity events — they are filtered at the
allowlist + connector level).

DEFERRED PATTERNS (M74B does not currently emit these event types and the
M74C ingestion path does not produce them, so this signal service must not
fabricate them):
  - shopify.app_scopes.updated     — deferred until ingestion emits it.
  - shopify.policy.created/.updated/.deleted — deferred until ingestion emits.
  - shopify.config.event           — deferred until ingestion emits the fallback.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "shopify"
SOURCE = "shopify_events"
SIGNAL_TYPE = "shopify_activity_signal"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is evidence for review and may require review. ConfigTrace does not "
    "confirm fraud, compromise, unauthorized access, or data exposure."
)

# event_type → (pattern, title-phrase). Only event types M74B actually emits
# are mapped; the others (app_scopes/policy/config_event) are deferred above.
_EVENT_PATTERNS: dict[str, tuple[str, str]] = {
    "shopify.webhook.created":  ("webhook_subscription_changed", "Shopify webhook subscription changed"),
    "shopify.webhook.updated":  ("webhook_subscription_changed", "Shopify webhook subscription changed"),
    "shopify.webhook.deleted":  ("webhook_subscription_changed", "Shopify webhook subscription changed"),
    "shopify.shop.updated":     ("shop_settings_changed",        "Shopify shop settings changed"),
    "shopify.domain.created":   ("domain_configuration_changed", "Shopify domain configuration changed"),
    "shopify.domain.updated":   ("domain_configuration_changed", "Shopify domain configuration changed"),
    "shopify.domain.deleted":   ("domain_configuration_changed", "Shopify domain configuration changed"),
}

# Per-pattern review-safe summary core.
_PATTERN_SUMMARY: dict[str, str] = {
    "webhook_subscription_changed": (
        "A Shopify webhook subscription configuration changed, observed in "
        "Shopify configuration activity. Only the webhook id, topic NAME, and "
        "endpoint URL host/scheme are recorded — never the webhook signing "
        "secret, URL query strings, customer records, order details, or raw "
        "event payloads. This may affect store operations and may require "
        "review."
    ),
    "shop_settings_changed": (
        "Shopify shop settings changed, observed in Shopify configuration "
        "activity. Only the shop domain and a safe setting NAME (when "
        "available) are recorded — never customer records, payment data, or "
        "raw event payloads. This may affect store operations and may "
        "require review."
    ),
    "domain_configuration_changed": (
        "A Shopify shop-domain configuration changed, observed in Shopify "
        "configuration activity. Only the domain id and host NAME are "
        "recorded — never DNS records, customer records, or raw event "
        "payloads. This may affect store operations and may require review."
    ),
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> datetime:
    if not isinstance(dt, datetime):
        return datetime.min.replace(tzinfo=timezone.utc)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _when(ev: SecurityActivityEvent) -> datetime:
    return _aware(ev.occurred_at or ev.ingested_at or ev.created_at)


def _md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get(key)
    return v if isinstance(v, str) and v.strip() else None


def _mdb(ev: SecurityActivityEvent, key: str) -> Optional[bool]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get(key)
    return v if isinstance(v, bool) else None


def _target_ident(ev: SecurityActivityEvent) -> str:
    """Pick a stable target identifier for the group key (NEVER a secret)."""
    return (
        _md(ev, "webhook_id")
        or _md(ev, "domain_id")
        or _md(ev, "object_id")
        or ""
    )


def _shop_ident(ev: SecurityActivityEvent) -> str:
    """Stable shop identifier — prefer .myshopify.com canonical, fall back to
    the storefront shop_domain, then any raw object identifier."""
    return _md(ev, "myshopify_domain") or _md(ev, "shop_domain") or ""


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    pattern_title = _EVENT_PATTERNS.get(ev.event_type)
    if pattern_title is None:
        return None
    pattern = pattern_title[0]
    shop = _shop_ident(ev)
    object_type = _md(ev, "object_type") or ""
    livemode = _mdb(ev, "livemode")
    livemode_part = "live" if livemode is True else "test" if livemode is False else ""
    return "|".join([
        "shopify.activity", pattern, shop, ev.event_type,
        object_type, _target_ident(ev), livemode_part,
    ])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id) for stable selection."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(pattern: str, anchor: SecurityActivityEvent) -> str:
    """Conservative severity. Never asserts impact — review priority only."""
    if pattern == "webhook_subscription_changed":
        # Webhook deletion (delivery stops) or plain-http delivery widen review
        # priority. Otherwise the change is treated as routine config activity.
        if anchor.event_type == "shopify.webhook.deleted":
            return "high"
        if _md(anchor, "webhook_endpoint_scheme") == "http":
            return "high"
        return "medium"
    if pattern == "domain_configuration_changed":
        # Domain deletion widens review priority — store reachability /
        # customer-facing impact is plausible.
        if anchor.event_type == "shopify.domain.deleted":
            return "high"
        return "medium"
    if pattern == "shop_settings_changed":
        return "medium"
    return "medium"


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    pattern_title = _EVENT_PATTERNS.get(anchor.event_type)
    if pattern_title is None:
        return None
    pattern, title_phrase = pattern_title

    shop = _shop_ident(anchor)
    target = _target_ident(anchor)
    where = f" on {shop}" if shop else ""
    if target:
        where = f"{where} ({target})" if shop else f" ({target})"
    title = f"{title_phrase}{where}"

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    summary = f"{_PATTERN_SUMMARY[pattern]} {_REVIEW_NOTE}"

    metadata = signal_svc.sanitize_signal_metadata({
        "source": SOURCE,
        "pattern": pattern,
        "event_type": anchor.event_type,
        "shopify_event_type": _md(anchor, "shopify_event_type"),
        "event_action": _md(anchor, "event_action"),
        "event_source": _md(anchor, "event_source"),
        "shop_domain": _md(anchor, "shop_domain"),
        "myshopify_domain": _md(anchor, "myshopify_domain"),
        "object_type": _md(anchor, "object_type"),
        "object_id": _md(anchor, "object_id"),
        "webhook_id": _md(anchor, "webhook_id"),
        "webhook_topic": _md(anchor, "webhook_topic"),
        "webhook_endpoint_domain": _md(anchor, "webhook_endpoint_domain"),
        "webhook_endpoint_scheme": _md(anchor, "webhook_endpoint_scheme"),
        "domain_id": _md(anchor, "domain_id"),
        "domain_host": _md(anchor, "domain_host"),
        "policy_type": _md(anchor, "policy_type"),
        "setting_name": _md(anchor, "setting_name"),
        "livemode": _mdb(anchor, "livemode"),
        "event_count": len(group),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
    })

    return {
        "provider": PROVIDER,
        "integration_id": anchor.integration_id,
        "signal_key": _group_key(anchor),
        "signal_type": SIGNAL_TYPE,
        "severity": _severity(pattern, anchor),
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


def generate_shopify_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Shopify activity review signals for a workspace. Never raises."""
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

    return {
        "provider": PROVIDER,
        "source": SOURCE,
        "events_scanned": len(events),
        "groups_scanned": len(groups),
        "signals_created": created,
        "signals_skipped": skipped,
    }
