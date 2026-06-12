"""AWS S3 object-access spike signals from CloudTrail data events (M67.9).

Groups normalized S3 object-level activity (``security_activity_events``,
provider=aws, source=s3_data_event — ingested in M67.8) by IAM principal +
bucket and surfaces review-worthy access SPIKES as Incident Signals
(``security_incident_signals``, signal_type="s3_object_access_spike",
evidence_level="activity", confidence="medium").

Core idea: a single GetObject is just activity. A spike — "this principal read an
unusually high number of objects / many unique objects / listed then read in a
burst / deleted many objects" — is a chain worth a human's review.

CLAIM DISCIPLINE: these are object-access SPIKE / REVIEW signals built from
control-plane data-event activity. They never assert data exfiltration, a breach,
an attacker, a compromise, or unauthorized access — only "evidence for review".

PRIVACY: only allowlisted, flat, safe AGGREGATE fields are stored (bucket name,
actor, counts, window, sanitized prefix, pattern). The source events were already
sanitized in M67.8 (object keys hashed, IPs hashed) and the signal metadata is
re-sanitized through the signal allowlist — NEVER raw object keys, raw IPs,
requestParameters/responseElements, raw CloudTrail JSON, tokens, or secrets.

Scope note (M67.9): S3 object-access spike signals only. NOT VPC Flow Logs, NOT
Cloudflare, NOT new providers.
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
SOURCE = "s3_data_event"
SIGNAL_TYPE = "s3_object_access_spike"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

# Conservative production-safe default; the endpoint can override (capped).
DEFAULT_READ_THRESHOLD = 50

_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm data exfiltration or "
    "unauthorized access."
)

_GET = "aws.s3.data.get_object"
_PUT = "aws.s3.data.put_object"
_DELETE = "aws.s3.data.delete_object"
_LIST = "aws.s3.data.list_bucket"
_ACL = "aws.s3.data.put_object_acl"
_COPY = "aws.s3.data.copy_object"
_HEAD = "aws.s3.data.head_object"

_OBJECT_ACCESS_TYPES = {_GET, _PUT, _DELETE, _COPY, _HEAD}

# Deterministic anchor rank — higher = preferred "most important" linked event.
_EVENT_RANK: dict[str, int] = {
    _ACL: 60,
    _DELETE: 58,
    _PUT: 50,
    _COPY: 48,
    _GET: 40,
    _LIST: 38,
    _HEAD: 36,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _meta(ev: SecurityActivityEvent) -> dict[str, Any]:
    return ev.event_metadata if isinstance(ev.event_metadata, dict) else {}


def _when(ev: SecurityActivityEvent) -> datetime:
    return ev.occurred_at or ev.ingested_at or _utcnow()


def _bucket(ev: SecurityActivityEvent) -> Optional[str]:
    md = _meta(ev)
    b = md.get("bucket_name")
    if isinstance(b, str) and b.strip():
        return b.strip()
    if isinstance(ev.resource_id, str) and ev.resource_id.strip():
        return ev.resource_id.strip()
    return None


def _actor(ev: SecurityActivityEvent) -> Optional[str]:
    if isinstance(ev.actor_id, str) and ev.actor_id.strip():
        return ev.actor_id.strip()
    md = _meta(ev)
    for k in ("user_name", "role_name"):
        v = md.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def group_events_by_actor_bucket(
    events: list[SecurityActivityEvent],
) -> dict[tuple[str, str], list[SecurityActivityEvent]]:
    """Group S3 data events by (actor, bucket). Events missing both are dropped."""
    groups: dict[tuple[str, str], list[SecurityActivityEvent]] = {}
    for ev in events:
        if ev.provider != PROVIDER or ev.source != SOURCE:
            continue
        actor = _actor(ev)
        bucket = _bucket(ev)
        if not actor and not bucket:
            continue
        key = ((actor or "").lower(), (bucket or "").lower())
        groups.setdefault(key, []).append(ev)
    for key in groups:
        groups[key].sort(key=lambda e: (_when(e), str(e.provider_event_id or "")))
    return groups


def _pick_anchor(events: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    return max(
        events,
        key=lambda e: (
            _EVENT_RANK.get(e.event_type, 0),
            _when(e),
            str(e.provider_event_id or ""),
        ),
    )


def _unique_object_count(events: list[SecurityActivityEvent]) -> int:
    hashes = set()
    for e in events:
        h = _meta(e).get("object_key_hash")
        if isinstance(h, str) and h:
            hashes.add(h)
    return len(hashes)


def _detect_patterns(
    events: list[SecurityActivityEvent], *, threshold: int
) -> list[dict[str, Any]]:
    """Return matched spike patterns for one (actor, bucket) group."""
    by_type: dict[str, list[SecurityActivityEvent]] = {}
    for e in events:
        by_type.setdefault(e.event_type, []).append(e)
    gets = by_type.get(_GET, [])
    deletes = by_type.get(_DELETE, [])
    lists = by_type.get(_LIST, [])
    acls = by_type.get(_ACL, [])

    matches: list[dict[str, Any]] = []

    # Pattern A — high GetObject volume.
    if len(gets) >= threshold:
        matches.append({
            "pattern": "high_read_volume",
            "signal_key": "aws.s3_access.high_read_volume",
            "severity": "high" if len(gets) >= 2 * threshold else "medium",
            "phrase": "High S3 object read volume by principal",
            "summary_core": (
                "CloudTrail S3 data events show elevated object-read activity for "
                "one principal and bucket."
            ),
            "trigger_events": gets,
        })

    # Pattern B — many UNIQUE objects read.
    uniq = _unique_object_count(gets)
    if uniq >= threshold:
        matches.append({
            "pattern": "unique_objects_read",
            "signal_key": "aws.s3_access.unique_objects_read",
            "severity": "high",
            "phrase": "Many unique S3 objects read",
            "summary_core": (
                "CloudTrail S3 data events show many unique objects read from one "
                "bucket by one principal."
            ),
            "trigger_events": gets,
            "unique_object_count": uniq,
        })

    # Pattern C — ListBucket followed by a GetObject burst.
    if lists and gets:
        earliest_list = min(_when(e) for e in lists)
        reads_after = [e for e in gets if _when(e) >= earliest_list]
        if len(reads_after) >= threshold:
            matches.append({
                "pattern": "list_then_read_burst",
                "signal_key": "aws.s3_access.list_then_read_burst",
                "severity": "high",
                "phrase": "S3 list followed by object-read burst",
                "summary_core": (
                    "CloudTrail S3 data events show a bucket listing followed by an "
                    "object-read burst for one principal."
                ),
                "trigger_events": lists + reads_after,
            })

    # Pattern D — object ACL changed near other object activity.
    if acls:
        nearby = [e for e in events if e.event_type in _OBJECT_ACCESS_TYPES]
        if nearby:
            matches.append({
                "pattern": "acl_changed_near_activity",
                "signal_key": "aws.s3_access.acl_changed_near_activity",
                "severity": "medium",
                "phrase": "S3 object ACL changed near object activity",
                "summary_core": (
                    "CloudTrail S3 data events show an object ACL change near other "
                    "object activity for one bucket and principal."
                ),
                "trigger_events": acls + nearby,
            })

    # Pattern E — DeleteObject burst.
    if len(deletes) >= threshold:
        matches.append({
            "pattern": "delete_burst",
            "signal_key": "aws.s3_access.delete_burst",
            "severity": "high",
            "phrase": "Multiple S3 object deletions",
            "summary_core": (
                "CloudTrail S3 data events show multiple object deletions for one "
                "principal and bucket."
            ),
            "trigger_events": deletes,
        })

    return matches


def build_s3_access_signal(
    *,
    events: list[SecurityActivityEvent],
    match: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Build one S3 object-access-spike signal dict from a matched pattern."""
    trig = match.get("trigger_events") or []
    if not trig:
        return None
    anchor = _pick_anchor(trig)
    bucket = _bucket(anchor) or "an S3 bucket"
    principal = _actor(anchor) or "a principal"

    times = [_when(e) for e in trig]
    window_start = min(times)
    window_end = max(times)
    trigger_types = sorted({e.event_type for e in trig})
    anchor_md = _meta(anchor)

    title = f"{match['phrase']} on {bucket}"
    summary = f"{match['summary_core']} {_REVIEW_NOTE}"

    metadata = signal_svc.sanitize_signal_metadata({
        "source": SOURCE,
        "pattern": match["pattern"],
        "bucket_name": _bucket(anchor),
        "actor_id": anchor.actor_id if isinstance(anchor.actor_id, str) else principal,
        "event_count": len(trig),
        "unique_object_count": match.get("unique_object_count", _unique_object_count(trig)),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "object_key_prefix": anchor_md.get("object_key_prefix"),
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


def generate_aws_s3_access_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 200,
    read_threshold: int = DEFAULT_READ_THRESHOLD,
    scan_limit: int = 5000,
) -> dict[str, Any]:
    """Generate S3 object-access-spike signals for a workspace.

    Conservative + deterministic + idempotent: re-running over the same events
    produces the same anchors and therefore creates no duplicates. Returns a
    generation summary.
    """
    hours = max(1, min(int(lookback_hours or 24), 168))
    cap = max(1, min(int(max_signals or 200), 1000))
    threshold = max(2, min(int(read_threshold or DEFAULT_READ_THRESHOLD), 100000))
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

    groups = group_events_by_actor_bucket(events)
    buckets = {b for (_a, b) in groups if b}
    actors = {a for (a, _b) in groups if a}

    created = 0
    skipped = 0
    for _key, grp in groups.items():
        for match in _detect_patterns(grp, threshold=threshold):
            if created >= cap:
                break
            signal = build_s3_access_signal(events=grp, match=match)
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
        "events_scanned": len(events),
        "buckets_scanned": len(buckets),
        "actors_scanned": len(actors),
        "signals_created": created,
        "signals_skipped": skipped,
    }
