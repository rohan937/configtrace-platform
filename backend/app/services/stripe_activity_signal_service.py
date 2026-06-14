"""Stripe activity Incident Signals (M73C).

Promotes Stripe configuration-change activity (provider=stripe,
source=stripe_events, ingested in M73B) into review-worthy Incident Signals
(signal_type="stripe_activity_signal", evidence_level="activity",
confidence="medium").

Conservative + deterministic + idempotent: events are grouped by
(account, pattern, event_type, object identity, capability+status, livemode),
each group yields one signal anchored on the group's latest event, with a
deterministic signal_key so re-running creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration-change review signals.
They NEVER assert that a breach, fraud, attacker, compromise, unauthorized
access, or customer-data exposure occurred. Severity reflects review priority
only.

PRIVACY: metadata is allowlisted + flat. NEVER customer PII / emails, payment
method data, card data, charges/payment intents/invoices/customer records, raw
event payloads, raw API responses, OAuth tokens, signing secrets, authorization
headers, request/response bodies, bank-account details, or tax IDs (none of
those are even present on the M73B activity events — they are filtered at the
allowlist + connector level).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "stripe"
SOURCE = "stripe_events"
SIGNAL_TYPE = "stripe_activity_signal"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is evidence for review and may require review. ConfigTrace does not "
    "confirm fraud, compromise, unauthorized access, or data exposure."
)

# event_type → (pattern, title-phrase). Every M73B Stripe activity event type is
# promotable. ``stripe.config.event`` is a safe fallback for any future
# allowlisted but un-mapped Stripe event type.
_EVENT_PATTERNS: dict[str, tuple[str, str]] = {
    "stripe.webhook_endpoint.created": ("webhook_endpoint_changed", "Stripe webhook endpoint changed"),
    "stripe.webhook_endpoint.updated": ("webhook_endpoint_changed", "Stripe webhook endpoint changed"),
    "stripe.webhook_endpoint.deleted": ("webhook_endpoint_changed", "Stripe webhook endpoint changed"),
    "stripe.payment_link.created":   ("payment_link_changed",      "Stripe payment link configuration changed"),
    "stripe.payment_link.updated":   ("payment_link_changed",      "Stripe payment link configuration changed"),
    "stripe.portal_config.created":  ("portal_config_changed",     "Stripe customer portal configuration changed"),
    "stripe.portal_config.updated":  ("portal_config_changed",     "Stripe customer portal configuration changed"),
    "stripe.account.updated":        ("account_updated",           "Stripe account settings changed"),
    "stripe.capability.updated":     ("capability_updated",        "Stripe account capability changed"),
    "stripe.config.event":           ("config_event",              "Stripe configuration event observed"),
}

# Per-pattern review-safe summary core.
_PATTERN_SUMMARY: dict[str, str] = {
    "webhook_endpoint_changed": (
        "A Stripe webhook endpoint configuration changed, observed in Stripe "
        "configuration activity. Only the endpoint id and URL host/scheme are "
        "recorded — never the signing secret, URL query strings, or raw event "
        "payloads. This may affect payment or webhook operations and may "
        "require review."
    ),
    "payment_link_changed": (
        "A Stripe payment link configuration changed, observed in Stripe "
        "configuration activity. Only the payment link id is recorded — never "
        "customer records, charges, or raw event payloads. This may affect "
        "payment or billing operations and may require review."
    ),
    "portal_config_changed": (
        "A Stripe customer portal configuration changed, observed in Stripe "
        "configuration activity. Only the portal configuration id is recorded "
        "— never customer records or raw event payloads. This may affect "
        "self-service billing operations and may require review."
    ),
    "account_updated": (
        "Stripe account settings changed, observed in Stripe configuration "
        "activity. Only the Stripe account id is recorded — never customer or "
        "payment data. This may affect billing or payment operations and may "
        "require review."
    ),
    "capability_updated": (
        "A Stripe account capability changed, observed in Stripe configuration "
        "activity. Only the capability name and status are recorded — never "
        "payment or customer data. This may affect payment operations and may "
        "require review."
    ),
    "config_event": (
        "A Stripe configuration event was observed in Stripe configuration "
        "activity. Only safe identifiers and the event type are recorded — "
        "never customer or payment data. This may require review."
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
        _md(ev, "webhook_endpoint_id")
        or _md(ev, "payment_link_id")
        or _md(ev, "portal_config_id")
        or _md(ev, "object_id")
        or ""
    )


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    pattern_title = _EVENT_PATTERNS.get(ev.event_type)
    if pattern_title is None:
        return None
    pattern = pattern_title[0]
    account = _md(ev, "account_id") or ""
    capability = _md(ev, "capability") or ""
    capability_status = _md(ev, "capability_status") or ""
    object_type = _md(ev, "object_type") or ""
    livemode = _mdb(ev, "livemode")
    livemode_part = "live" if livemode is True else "test" if livemode is False else ""
    return "|".join([
        "stripe.activity", pattern, account, ev.event_type,
        object_type, _target_ident(ev),
        capability, capability_status, livemode_part,
    ])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id) for stable selection."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(pattern: str, anchor: SecurityActivityEvent) -> str:
    """Conservative severity. Never asserts impact — review priority only."""
    if pattern == "webhook_endpoint_changed":
        # Webhook deletion (delivery stops) or plain-http delivery widen review
        # priority. Otherwise the change is treated as routine config activity.
        if anchor.event_type == "stripe.webhook_endpoint.deleted":
            return "high"
        if _md(anchor, "webhook_url_scheme") == "http":
            return "high"
        return "medium"
    if pattern == "capability_updated":
        # An inactive or pending capability may affect ongoing payment
        # operations — review priority is elevated.
        status = _md(anchor, "capability_status")
        if status in ("inactive", "pending", "unrequested", "disabled"):
            return "high"
        return "medium"
    if pattern == "config_event":
        # Bare fallback with no specific object identity is the lowest signal.
        has_identifier = bool(_target_ident(anchor) or _md(anchor, "object_type"))
        return "medium" if has_identifier else "low"
    # payment_link_changed, portal_config_changed, account_updated
    return "medium"


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    pattern_title = _EVENT_PATTERNS.get(anchor.event_type)
    if pattern_title is None:
        return None
    pattern, title_phrase = pattern_title

    account = _md(anchor, "account_id")
    target = _target_ident(anchor)
    where = f" on {account}" if account else ""
    if target:
        where = f"{where} ({target})" if account else f" ({target})"
    title = f"{title_phrase}{where}"

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    summary = f"{_PATTERN_SUMMARY[pattern]} {_REVIEW_NOTE}"

    metadata = signal_svc.sanitize_signal_metadata({
        "source": SOURCE,
        "pattern": pattern,
        "event_type": anchor.event_type,
        "stripe_event_type": _md(anchor, "stripe_event_type"),
        "event_action": _md(anchor, "event_action"),
        "event_source": _md(anchor, "event_source"),
        "account_id": _md(anchor, "account_id"),
        "object_type": _md(anchor, "object_type"),
        "object_id": _md(anchor, "object_id"),
        "webhook_endpoint_id": _md(anchor, "webhook_endpoint_id"),
        "webhook_url_domain": _md(anchor, "webhook_url_domain"),
        "webhook_url_scheme": _md(anchor, "webhook_url_scheme"),
        "payment_link_id": _md(anchor, "payment_link_id"),
        "portal_config_id": _md(anchor, "portal_config_id"),
        "capability": _md(anchor, "capability"),
        "capability_status": _md(anchor, "capability_status"),
        "tax_setting_name": _md(anchor, "tax_setting_name"),
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


def generate_stripe_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Stripe activity review signals for a workspace. Never raises."""
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
