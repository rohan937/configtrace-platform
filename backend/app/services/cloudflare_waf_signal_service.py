"""Cloudflare WAF / security-event Incident Signals (M68.5).

Groups normalized Cloudflare WAF/security activity (``security_activity_events``,
provider=cloudflare, source=waf_security_event — ingested in M68.4) by zone /
host / rule / path-prefix and surfaces review-worthy patterns as Incident Signals
(``security_incident_signals``, signal_type="cloudflare_waf_activity_signal",
evidence_level="activity", confidence="medium").

Core idea: a single blocked/challenged request is just a WAF event. A pattern — a
burst of blocks, a challenge burst, repeated security activity on a sensitive path
prefix, repeated triggering of one WAF rule, or skip/allow activity — is worth a
human's review.

CLAIM DISCIPLINE: these are WAF / SECURITY-EVENT review signals built from
request-defense activity. They never assert an attack, exploit, breach, attacker,
compromise, or unauthorized access — only "evidence for review". The raw path / IP
are never used (only the hashed path's safe prefix and aggregate counts).

PRIVACY: only allowlisted, flat, safe AGGREGATE fields are stored (zone, host,
rule id/name, ruleset id, path_prefix, counts, action list, country count,
window). The source events were already sanitized in M68.4 (raw IP hashed, raw
path hashed) and the signal metadata is re-sanitized through the signal allowlist
— NEVER raw IPs, raw URLs/paths/query strings, headers, cookies, bodies, tokens,
secrets, session ids, or raw GraphQL JSON.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

logger = logging.getLogger(__name__)

PROVIDER = "cloudflare"
SOURCE = "waf_security_event"
SIGNAL_TYPE = "cloudflare_waf_activity_signal"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_BLOCK = "cloudflare.waf_event.block"
_CHALLENGE = {
    "cloudflare.waf_event.challenge",
    "cloudflare.waf_event.managed_challenge",
    "cloudflare.waf_event.js_challenge",
}
_LOG = "cloudflare.waf_event.log"
_SKIP_ALLOW = {"cloudflare.waf_event.skip", "cloudflare.waf_event.allow"}
_SECURITY_ACTIONS = {_BLOCK} | _CHALLENGE  # block + any challenge
_RULE_TRIGGER_TYPES = {_BLOCK} | _CHALLENGE | {_LOG}

_SENSITIVE_PREFIXES = {
    "admin", "login", "wp-admin", "api", "dashboard", "account", "auth",
}

# Conservative production-safe defaults; the endpoint can override (capped).
DEFAULT_BLOCK_THRESHOLD = 10
DEFAULT_CHALLENGE_THRESHOLD = 10
DEFAULT_SENSITIVE_PATH_THRESHOLD = 5
DEFAULT_RULE_TRIGGER_THRESHOLD = 10
DEFAULT_SKIP_ALLOW_THRESHOLD = 5

_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm an attack, exploit, or "
    "unauthorized access."
)

# Deterministic anchor rank — block first, then challenges, then log, then skip/allow.
_EVENT_RANK: dict[str, int] = {
    _BLOCK: 60,
    "cloudflare.waf_event.managed_challenge": 52,
    "cloudflare.waf_event.challenge": 50,
    "cloudflare.waf_event.js_challenge": 48,
    _LOG: 40,
    "cloudflare.waf_event.skip": 30,
    "cloudflare.waf_event.allow": 28,
    "cloudflare.waf_event.event": 20,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _meta(ev: SecurityActivityEvent) -> dict[str, Any]:
    return ev.event_metadata if isinstance(ev.event_metadata, dict) else {}


def _when(ev: SecurityActivityEvent) -> datetime:
    return ev.occurred_at or ev.ingested_at or _utcnow()


def _zone(ev: SecurityActivityEvent) -> Optional[str]:
    md = _meta(ev)
    z = md.get("zone_id")
    if isinstance(z, str) and z:
        return z
    return ev.resource_id if isinstance(ev.resource_id, str) and ev.resource_id else None


def _str_md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    v = _meta(ev).get(key)
    return v if isinstance(v, str) and v else None


def _pick_anchor(events: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    return max(
        events,
        key=lambda e: (
            _EVENT_RANK.get(e.event_type, 0),
            _when(e),
            str(e.provider_event_id or ""),
        ),
    )


def _country_count(events: list[SecurityActivityEvent]) -> int:
    return len({c for c in (_str_md(e, "client_country") for e in events) if c})


def _grouped(
    events: list[SecurityActivityEvent], key_fn
) -> dict[tuple, list[SecurityActivityEvent]]:
    groups: dict[tuple, list[SecurityActivityEvent]] = {}
    for ev in events:
        k = key_fn(ev)
        if k is None:
            continue
        groups.setdefault(k, []).append(ev)
    for k in groups:
        groups[k].sort(key=lambda e: (_when(e), str(e.provider_event_id or "")))
    return groups


def _detect(
    events: list[SecurityActivityEvent],
    *,
    block_threshold: int,
    challenge_threshold: int,
    sensitive_path_threshold: int,
    rule_trigger_threshold: int,
    skip_allow_threshold: int,
) -> list[dict[str, Any]]:
    """Return matched WAF patterns across all groupings."""
    matches: list[dict[str, Any]] = []

    # A — high blocked-request volume (by zone, host).
    for (_z, _h), grp in _grouped(events, lambda e: (_zone(e), _str_md(e, "host"))).items():
        blocks = [e for e in grp if e.event_type == _BLOCK]
        if len(blocks) >= block_threshold:
            matches.append({
                "pattern": "high_block_volume",
                "signal_key": "cloudflare.waf.high_block_volume",
                "severity": "high" if len(blocks) >= 2 * block_threshold else "medium",
                "phrase": "High Cloudflare WAF block volume",
                "summary_core": (
                    "Cloudflare WAF events show a burst of blocked request activity."
                ),
                "trigger_events": blocks,
            })
        challenges = [e for e in grp if e.event_type in _CHALLENGE]
        if len(challenges) >= challenge_threshold:
            matches.append({
                "pattern": "high_challenge_volume",
                "signal_key": "cloudflare.waf.high_challenge_volume",
                "severity": "medium",
                "phrase": "High Cloudflare challenge volume",
                "summary_core": (
                    "Cloudflare WAF events show a burst of challenged request activity."
                ),
                "trigger_events": challenges,
            })
        skip_allow = [e for e in grp if e.event_type in _SKIP_ALLOW]
        if len(skip_allow) >= skip_allow_threshold:
            matches.append({
                "pattern": "skip_allow_activity",
                "signal_key": "cloudflare.waf.skip_allow_activity",
                # Skip/allow can be legitimate — never high without strong metadata.
                "severity": "low" if len(skip_allow) < 2 * skip_allow_threshold else "medium",
                "phrase": "Cloudflare WAF skip/allow activity observed",
                "summary_core": (
                    "Cloudflare WAF events show skip/allow activity. Skip/allow can be "
                    "legitimate (an explicit allowlist or exception)."
                ),
                "trigger_events": skip_allow,
            })

    # C — repeated security activity on a sensitive path prefix (zone, host, prefix).
    def _sensitive_key(e):
        p = _str_md(e, "path_prefix")
        if p and p.lower() in _SENSITIVE_PREFIXES and e.event_type in _SECURITY_ACTIONS:
            return (_zone(e), _str_md(e, "host"), p.lower())
        return None

    for (_z, _h, _p), grp in _grouped(events, _sensitive_key).items():
        if len(grp) >= sensitive_path_threshold:
            matches.append({
                "pattern": "sensitive_path_activity",
                "signal_key": "cloudflare.waf.sensitive_path_activity",
                "severity": "high" if len(grp) >= 2 * sensitive_path_threshold else "medium",
                "phrase": "Cloudflare security activity on sensitive path prefix",
                "summary_core": (
                    "Cloudflare WAF events show repeated security activity on a "
                    "sensitive path prefix. ConfigTrace does not infer that any "
                    "endpoint was accessed."
                ),
                "trigger_events": grp,
            })

    # D — repeated WAF rule activity (zone, rule_id).
    def _rule_key(e):
        rid = _str_md(e, "rule_id")
        if rid and e.event_type in _RULE_TRIGGER_TYPES:
            return (_zone(e), rid)
        return None

    for (_z, _rid), grp in _grouped(events, _rule_key).items():
        if len(grp) >= rule_trigger_threshold:
            matches.append({
                "pattern": "repeated_rule_activity",
                "signal_key": "cloudflare.waf.repeated_rule_activity",
                "severity": "medium",
                "phrase": "Repeated Cloudflare WAF rule activity",
                "summary_core": (
                    "Cloudflare WAF events show repeated activity for one WAF rule."
                ),
                "trigger_events": grp,
            })

    return matches


def build_waf_signal(
    *, match: dict[str, Any]
) -> Optional[dict[str, Any]]:
    """Build one Cloudflare WAF review-signal dict from a matched pattern."""
    trig = match.get("trigger_events") or []
    if not trig:
        return None
    anchor = _pick_anchor(trig)
    host = _str_md(anchor, "host")
    zone_name = _str_md(anchor, "zone_name")

    times = [_when(e) for e in trig]
    window_start = min(times)
    window_end = max(times)
    trigger_types = sorted({e.event_type for e in trig})
    actions = sorted({a for a in (_str_md(e, "action") for e in trig) if a})

    label = host or zone_name or _zone(anchor) or "a Cloudflare zone"
    title = f"{match['phrase']} on {label}"
    summary = f"{match['summary_core']} {_REVIEW_NOTE}"

    metadata = signal_svc.sanitize_signal_metadata({
        "source": SOURCE,
        "pattern": match["pattern"],
        "zone_id": _zone(anchor),
        "zone_name": zone_name,
        "host": host,
        "rule_id": _str_md(anchor, "rule_id"),
        "rule_name": _str_md(anchor, "rule_name"),
        "ruleset_id": _str_md(anchor, "ruleset_id"),
        "path_prefix": _str_md(anchor, "path_prefix"),
        "event_count": len(trig),
        "event_types": ",".join(trigger_types),
        "actions": ",".join(actions),
        "client_country_count": _country_count(trig),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
    })

    return {
        "provider": PROVIDER,
        "integration_id": anchor.integration_id,
        "signal_key": match["signal_key"],
        "signal_type": SIGNAL_TYPE,
        "severity": match["severity"],
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


def generate_cloudflare_waf_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 200,
    block_threshold: int = DEFAULT_BLOCK_THRESHOLD,
    challenge_threshold: int = DEFAULT_CHALLENGE_THRESHOLD,
    sensitive_path_threshold: int = DEFAULT_SENSITIVE_PATH_THRESHOLD,
    rule_trigger_threshold: int = DEFAULT_RULE_TRIGGER_THRESHOLD,
    skip_allow_threshold: int = DEFAULT_SKIP_ALLOW_THRESHOLD,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Cloudflare WAF/security-event review signals for a workspace.

    Conservative + deterministic + idempotent: re-running over the same events
    produces the same anchors and creates no duplicates. Returns a summary.
    """
    hours = max(1, min(int(lookback_hours or 24), 168))
    cap = max(1, min(int(max_signals or 200), 1000))
    block_t = max(2, min(int(block_threshold or DEFAULT_BLOCK_THRESHOLD), 1_000_000))
    chal_t = max(2, min(int(challenge_threshold or DEFAULT_CHALLENGE_THRESHOLD), 1_000_000))
    path_t = max(2, min(int(sensitive_path_threshold or DEFAULT_SENSITIVE_PATH_THRESHOLD), 1_000_000))
    rule_t = max(2, min(int(rule_trigger_threshold or DEFAULT_RULE_TRIGGER_THRESHOLD), 1_000_000))
    sa_t = max(2, min(int(skip_allow_threshold or DEFAULT_SKIP_ALLOW_THRESHOLD), 1_000_000))
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

    matches = _detect(
        events, block_threshold=block_t, challenge_threshold=chal_t,
        sensitive_path_threshold=path_t, rule_trigger_threshold=rule_t,
        skip_allow_threshold=sa_t,
    )
    # Count distinct groups scanned (zone, host) — a stable denominator.
    groups = {(_zone(e), _str_md(e, "host")) for e in events if _zone(e)}

    created = 0
    skipped = 0
    for match in matches:
        if created >= cap:
            break
        signal = build_waf_signal(match=match)
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
