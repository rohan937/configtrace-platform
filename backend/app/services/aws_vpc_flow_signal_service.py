"""AWS VPC Flow Log network-activity signals (M67.11).

Groups normalized VPC Flow Log activity (``security_activity_events``,
provider=aws, source=vpc_flow_log — ingested in M67.10) by network interface +
destination port and surfaces review-worthy NETWORK patterns as Incident Signals
(``security_incident_signals``, signal_type="vpc_flow_activity_signal",
evidence_level="activity", confidence="medium").

Core idea: a single accepted flow is just an accepted flow. A pattern — "accepted
traffic to a sensitive port", "a high volume of rejected flows", "a high outbound
byte volume", "repeated admin-port activity", "a database-port burst" — is worth
a human's review.

CLAIM DISCIPLINE: these are NETWORK ACTIVITY / REVIEW signals built from flow-log
activity. They never assert a network intrusion, breach, attacker, compromise, or
unauthorized access — only "evidence for review". Because raw IPs are never
stored, ConfigTrace never claims any external destination identity.

PRIVACY: only allowlisted, flat, safe AGGREGATE fields are stored (interface,
port, protocol, counts, byte/packet totals, window, pattern). The source events
were already sanitized in M67.10 (IPs hashed, raw lines dropped) and the signal
metadata is re-sanitized through the signal allowlist — NEVER raw IPs, raw log
lines, payloads, tokens, or secrets.

Scope note (M67.11): VPC Flow Log network signals only. NOT Cloudflare, NOT new
providers.
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

PROVIDER = "aws"
SOURCE = "vpc_flow_log"
SIGNAL_TYPE = "vpc_flow_activity_signal"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_ACCEPT = "aws.vpc.flow.accept"
_REJECT = "aws.vpc.flow.reject"

# Sensitive destination ports (admin + datastore). Conservative, well-known set.
_ADMIN_PORTS = {22, 3389, 5985, 5986}
_DB_PORTS = {3306, 5432, 6379, 27017, 9200, 1433}
_SENSITIVE_PORTS = _ADMIN_PORTS | _DB_PORTS

# Conservative production-safe defaults; the endpoint can override (capped).
DEFAULT_REJECTED_THRESHOLD = 20
DEFAULT_SENSITIVE_PORT_THRESHOLD = 1
DEFAULT_BYTES_THRESHOLD = 100_000_000  # 100 MB
DEFAULT_PORT_ACTIVITY_THRESHOLD = 5

_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm intrusion or "
    "unauthorized access."
)

_EVENT_RANK = {_ACCEPT: 42, _REJECT: 40, "aws.vpc.flow.event": 38}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _meta(ev: SecurityActivityEvent) -> dict[str, Any]:
    return ev.event_metadata if isinstance(ev.event_metadata, dict) else {}


def _when(ev: SecurityActivityEvent) -> datetime:
    return ev.occurred_at or ev.ingested_at or _utcnow()


def _interface(ev: SecurityActivityEvent) -> Optional[str]:
    md = _meta(ev)
    v = md.get("interface_id")
    if isinstance(v, str) and v.strip():
        return v.strip()
    if isinstance(ev.resource_id, str) and ev.resource_id.strip():
        return ev.resource_id.strip()
    return None


def _dst_port(ev: SecurityActivityEvent) -> Optional[int]:
    v = _meta(ev).get("dst_port")
    return v if isinstance(v, int) else None


def _protocol(ev: SecurityActivityEvent) -> Optional[int]:
    v = _meta(ev).get("protocol")
    return v if isinstance(v, int) else None


def _int_metric(ev: SecurityActivityEvent, key: str) -> int:
    v = _meta(ev).get(key)
    return v if isinstance(v, int) else 0


def _pick_anchor(events: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    return max(
        events,
        key=lambda e: (
            _EVENT_RANK.get(e.event_type, 0),
            _when(e),
            str(e.provider_event_id or ""),
        ),
    )


def _flow_action(events: list[SecurityActivityEvent]) -> str:
    actions = {_meta(e).get("action") for e in events if _meta(e).get("action")}
    if len(actions) == 1:
        return next(iter(actions))
    return "mixed"


def group_by_interface_port(
    events: list[SecurityActivityEvent],
) -> dict[tuple[str, int], list[SecurityActivityEvent]]:
    """Group flow events by (interface_id, dst_port). Events missing either drop."""
    groups: dict[tuple[str, int], list[SecurityActivityEvent]] = {}
    for ev in events:
        if ev.provider != PROVIDER or ev.source != SOURCE:
            continue
        iface = _interface(ev)
        port = _dst_port(ev)
        if not iface or port is None:
            continue
        groups.setdefault((iface, port), []).append(ev)
    for key in groups:
        groups[key].sort(key=lambda e: (_when(e), str(e.provider_event_id or "")))
    return groups


def group_by_interface(
    events: list[SecurityActivityEvent],
) -> dict[str, list[SecurityActivityEvent]]:
    groups: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        if ev.provider != PROVIDER or ev.source != SOURCE:
            continue
        iface = _interface(ev)
        if not iface:
            continue
        groups.setdefault(iface, []).append(ev)
    for key in groups:
        groups[key].sort(key=lambda e: (_when(e), str(e.provider_event_id or "")))
    return groups


def _detect_port_patterns(
    events: list[SecurityActivityEvent],
    *,
    port: int,
    rejected_threshold: int,
    sensitive_port_threshold: int,
    port_activity_threshold: int,
) -> list[dict[str, Any]]:
    """Patterns A, B, D, E for one (interface, dst_port) group."""
    accepts = [e for e in events if e.event_type == _ACCEPT]
    rejects = [e for e in events if e.event_type == _REJECT]
    matches: list[dict[str, Any]] = []

    # Pattern A — accepted traffic to a sensitive destination port.
    if port in _SENSITIVE_PORTS and len(accepts) >= sensitive_port_threshold:
        matches.append({
            "pattern": "sensitive_port_accept",
            "signal_key": "aws.vpc_flow.sensitive_port_accept",
            "severity": "high" if port in _ADMIN_PORTS else "medium",
            "phrase": "Accepted network flow to sensitive port",
            "summary_core": (
                "VPC Flow Logs show accepted network flow activity to a sensitive "
                "destination port."
            ),
            "trigger_events": accepts,
        })

    # Pattern B — high rejected-flow volume.
    if len(rejects) >= rejected_threshold:
        matches.append({
            "pattern": "rejected_volume",
            "signal_key": "aws.vpc_flow.rejected_volume",
            "severity": "medium",
            "phrase": "High rejected network-flow volume",
            "summary_core": (
                "VPC Flow Logs show a high volume of rejected network flows for one "
                "interface and port."
            ),
            "trigger_events": rejects,
        })

    # Pattern D — repeated admin-port activity (accept or reject).
    if port in _ADMIN_PORTS and len(events) >= port_activity_threshold:
        matches.append({
            "pattern": "admin_port_activity",
            "signal_key": "aws.vpc_flow.admin_port_activity",
            "severity": "high",
            "phrase": "Repeated admin-port network activity",
            "summary_core": (
                "VPC Flow Logs show repeated admin-port (SSH / RDP / WinRM) network "
                "activity for one interface and port."
            ),
            "trigger_events": list(events),
        })

    # Pattern E — database/cache/search-port activity burst (accept or reject).
    if port in _DB_PORTS and len(events) >= port_activity_threshold:
        matches.append({
            "pattern": "db_port_activity",
            "signal_key": "aws.vpc_flow.db_port_activity",
            "severity": "high" if len(events) >= 2 * port_activity_threshold else "medium",
            "phrase": "Database-port network activity burst",
            "summary_core": (
                "VPC Flow Logs show a burst of database / cache / search-port network "
                "activity for one interface and port."
            ),
            "trigger_events": list(events),
        })

    return matches


def _detect_interface_patterns(
    events: list[SecurityActivityEvent], *, bytes_threshold: int
) -> list[dict[str, Any]]:
    """Pattern C for one interface group."""
    accepts = [e for e in events if e.event_type == _ACCEPT]
    total_bytes = sum(_int_metric(e, "bytes") for e in accepts)
    matches: list[dict[str, Any]] = []
    if accepts and total_bytes >= bytes_threshold:
        matches.append({
            "pattern": "high_byte_volume",
            "signal_key": "aws.vpc_flow.high_byte_volume",
            "severity": "high" if total_bytes >= 2 * bytes_threshold else "medium",
            "phrase": "High outbound network byte volume",
            "summary_core": (
                "VPC Flow Logs show a high outbound byte volume for one network "
                "interface. ConfigTrace does not identify the external destination."
            ),
            "trigger_events": accepts,
        })
    return matches


def build_vpc_flow_signal(
    *,
    events: list[SecurityActivityEvent],
    match: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Build one VPC-flow network signal dict from a matched pattern."""
    trig = match.get("trigger_events") or []
    if not trig:
        return None
    anchor = _pick_anchor(trig)
    interface = _interface(anchor) or "a network interface"
    port = _dst_port(anchor)

    times = [_when(e) for e in trig]
    window_start = min(times)
    window_end = max(times)
    trigger_types = sorted({e.event_type for e in trig})

    title = f"{match['phrase']} on {interface}"
    if port is not None and match["pattern"] != "high_byte_volume":
        title = f"{match['phrase']} (port {port}) on {interface}"
    summary = f"{match['summary_core']} {_REVIEW_NOTE}"

    metadata = signal_svc.sanitize_signal_metadata({
        "source": SOURCE,
        "pattern": match["pattern"],
        "interface_id": _interface(anchor),
        "dst_port": _dst_port(anchor),
        "protocol": _protocol(anchor),
        "flow_action": _flow_action(trig),
        "event_count": len(trig),
        "bytes_total": sum(_int_metric(e, "bytes") for e in trig),
        "packets_total": sum(_int_metric(e, "packets") for e in trig),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "event_types": ",".join(trigger_types),
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


def generate_aws_vpc_flow_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 200,
    rejected_threshold: int = DEFAULT_REJECTED_THRESHOLD,
    sensitive_port_threshold: int = DEFAULT_SENSITIVE_PORT_THRESHOLD,
    bytes_threshold: int = DEFAULT_BYTES_THRESHOLD,
    port_activity_threshold: int = DEFAULT_PORT_ACTIVITY_THRESHOLD,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate VPC Flow Log network-activity signals for a workspace.

    Conservative + deterministic + idempotent: re-running over the same events
    produces the same anchors and creates no duplicates. Returns a summary.
    """
    hours = max(1, min(int(lookback_hours or 24), 168))
    cap = max(1, min(int(max_signals or 200), 1000))
    rej_t = max(1, min(int(rejected_threshold or DEFAULT_REJECTED_THRESHOLD), 1_000_000))
    sens_t = max(1, min(int(sensitive_port_threshold or DEFAULT_SENSITIVE_PORT_THRESHOLD), 1_000_000))
    bytes_t = max(1, min(int(bytes_threshold or DEFAULT_BYTES_THRESHOLD), 1_000_000_000_000))
    port_t = max(2, min(int(port_activity_threshold or DEFAULT_PORT_ACTIVITY_THRESHOLD), 1_000_000))
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

    port_groups = group_by_interface_port(events)
    iface_groups = group_by_interface(events)
    interfaces = set(iface_groups.keys())

    created = 0
    skipped = 0

    def _emit(grp, match):
        nonlocal created, skipped
        signal = build_vpc_flow_signal(events=grp, match=match)
        if signal is None:
            return
        outcome, _row = signal_svc.upsert_incident_signal(
            workspace_id=workspace_id, signal=signal, db=db
        )
        if outcome == "created":
            created += 1
        else:
            skipped += 1

    for (_iface, port), grp in port_groups.items():
        for match in _detect_port_patterns(
            grp, port=port, rejected_threshold=rej_t,
            sensitive_port_threshold=sens_t, port_activity_threshold=port_t,
        ):
            if created >= cap:
                break
            _emit(grp, match)

    for _iface, grp in iface_groups.items():
        for match in _detect_interface_patterns(grp, bytes_threshold=bytes_t):
            if created >= cap:
                break
            _emit(grp, match)

    return {
        "provider": PROVIDER,
        "events_scanned": len(events),
        "interfaces_scanned": len(interfaces),
        "signals_created": created,
        "signals_skipped": skipped,
    }
