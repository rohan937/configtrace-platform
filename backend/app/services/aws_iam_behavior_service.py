"""AWS IAM behavior timelines from CloudTrail management events (M67.6).

Groups normalized CloudTrail management activity (``security_activity_events``,
provider=aws, source=cloudtrail — ingested in M67.5) by IAM principal / resource
and surfaces review-worthy BEHAVIOR CHAINS as Incident Signals
(``security_incident_signals``, signal_type="iam_behavior_timeline",
evidence_level="activity", confidence="medium").

Core idea: a single CloudTrail event ("AttachUserPolicy happened") is just an
event. A behavior timeline is "this principal had an access key created, then a
policy attached, in the same review window" — a chain worth a human's review.

CLAIM DISCIPLINE: these are BEHAVIOR / REVIEW signals built from control-plane
activity. They never assert a breach, attacker, compromise, or unauthorized
access, and never infer that any data was accessed.

PRIVACY: only allowlisted, flat, safe summary fields are stored (event types,
principal identity, counts, window, safe resource/policy hints, salted principal
hash). NEVER raw CloudTrail JSON, requestParameters/responseElements, raw IPs,
secrets, or tokens — the source events were already sanitized in M67.5 and the
signal metadata is re-sanitized through the signal allowlist.

Scope note (M67.6): IAM/KMS/S3 control-plane behavior chains only. NOT Security
Hub, NOT VPC Flow Logs, NOT S3 data events, NOT object-access-spike detection.
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
SOURCE = "cloudtrail"
SIGNAL_TYPE = "iam_behavior_timeline"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm compromise or "
    "unauthorized access."
)

# Normalized CloudTrail event-type groups used by the patterns.
_ACCESS_KEY_TYPES = {"aws.iam.create_access_key"}
_POLICY_CHANGE_TYPES = {
    "aws.iam.attach_user_policy",
    "aws.iam.attach_role_policy",
    "aws.iam.put_user_policy",
    "aws.iam.put_role_policy",
}
_TRUST_POLICY_TYPES = {"aws.iam.update_assume_role_policy"}
_KMS_TYPES = {"aws.kms.disable_key", "aws.kms.schedule_key_deletion"}
_S3_TYPES = {
    "aws.s3.put_bucket_policy",
    "aws.s3.put_public_access_block",
    "aws.s3.put_bucket_acl",
}

# Anchor selection rank — higher = preferred deterministic "most important" event
# to link the signal to. Ties broken by (occurred time, provider_event_id).
_EVENT_RANK: dict[str, int] = {
    "aws.iam.update_assume_role_policy": 60,
    "aws.kms.schedule_key_deletion": 58,
    "aws.kms.disable_key": 56,
    "aws.iam.attach_user_policy": 50,
    "aws.iam.attach_role_policy": 50,
    "aws.iam.put_user_policy": 48,
    "aws.iam.put_role_policy": 48,
    "aws.s3.put_public_access_block": 44,
    "aws.s3.put_bucket_policy": 42,
    "aws.s3.put_bucket_acl": 40,
    "aws.iam.create_access_key": 38,
}

_ADMIN_TOKENS = ("administratoraccess", "admin", "*")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _meta(ev: SecurityActivityEvent) -> dict[str, Any]:
    return ev.event_metadata if isinstance(ev.event_metadata, dict) else {}


def _when(ev: SecurityActivityEvent) -> datetime:
    return ev.occurred_at or ev.ingested_at or _utcnow()


def _principal_key(ev: SecurityActivityEvent) -> Optional[str]:
    """A stable grouping key for an event: actor → resource → metadata identity."""
    if isinstance(ev.actor_id, str) and ev.actor_id.strip():
        return ev.actor_id.strip().lower()
    if isinstance(ev.resource_id, str) and ev.resource_id.strip():
        return ev.resource_id.strip().lower()
    md = _meta(ev)
    for k in ("user_name", "role_name", "resource_name"):
        v = md.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
    return None


def _display_principal(events: list[SecurityActivityEvent]) -> str:
    """A human label for the principal (not lowercased), best-effort."""
    for ev in events:
        if isinstance(ev.actor_id, str) and ev.actor_id.strip():
            return ev.actor_id.strip()
    for ev in events:
        md = _meta(ev)
        for k in ("user_name", "role_name", "resource_name"):
            v = md.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        if isinstance(ev.resource_id, str) and ev.resource_id.strip():
            return ev.resource_id.strip()
    return "this principal"


def group_cloudtrail_events_by_principal(
    events: list[SecurityActivityEvent],
) -> dict[str, list[SecurityActivityEvent]]:
    """Group CloudTrail events by IAM principal / resource key.

    Events with no resolvable principal key are dropped (cannot be timelined).
    Each group is time-ordered ascending.
    """
    groups: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        if ev.provider != PROVIDER or ev.source != SOURCE:
            continue
        key = _principal_key(ev)
        if not key:
            continue
        groups.setdefault(key, []).append(ev)
    for key in groups:
        groups[key].sort(key=lambda e: (_when(e), str(e.provider_event_id or "")))
    return groups


def _has_admin_hint(events: list[SecurityActivityEvent]) -> Optional[str]:
    """Return a safe policy hint if any policy-change event looks admin-like."""
    for ev in events:
        if ev.event_type not in _POLICY_CHANGE_TYPES:
            continue
        md = _meta(ev)
        candidates = [
            md.get("policy_name"),
            md.get("resource_name"),
            md.get("resource_arn"),
        ]
        for c in candidates:
            if isinstance(c, str) and c:
                low = c.lower()
                if any(tok in low for tok in _ADMIN_TOKENS):
                    # Prefer a clean "AdministratorAccess" label when present.
                    if "administratoraccess" in low:
                        return "AdministratorAccess"
                    return c[:120]
    return None


def _pick_anchor(events: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Deterministic "most important" event: rank, then latest, then id."""
    return max(
        events,
        key=lambda e: (
            _EVENT_RANK.get(e.event_type, 0),
            _when(e),
            str(e.provider_event_id or ""),
        ),
    )


def _detect_patterns(
    events: list[SecurityActivityEvent],
) -> list[dict[str, Any]]:
    """Return matched behavior patterns for one principal's events.

    Each match: {signal_key, severity, phrase, summary_core, trigger_events,
    policy_name?}.
    """
    types = {e.event_type for e in events}
    matches: list[dict[str, Any]] = []

    # Pattern A — access key created + policy change for the same principal.
    if (types & _ACCESS_KEY_TYPES) and (types & _POLICY_CHANGE_TYPES):
        trig = [e for e in events if e.event_type in (_ACCESS_KEY_TYPES | _POLICY_CHANGE_TYPES)]
        matches.append({
            "signal_key": "aws.iam_behavior.access_key_policy_chain",
            "severity": "high",
            "phrase": "IAM access key creation followed by policy change",
            "summary_core": (
                "CloudTrail shows an IAM access key event and a policy change for "
                "the same principal/resource in the review window."
            ),
            "trigger_events": trig,
        })

    # Pattern B — admin-like IAM policy change.
    admin_hint = _has_admin_hint(events)
    if admin_hint is not None:
        trig = [e for e in events if e.event_type in _POLICY_CHANGE_TYPES]
        matches.append({
            "signal_key": "aws.iam_behavior.admin_policy_change",
            "severity": "high",
            "phrase": "Admin-like IAM policy change",
            "summary_core": (
                "CloudTrail shows an admin-like IAM policy change for this "
                "principal in the review window."
            ),
            "trigger_events": trig,
            "policy_name": admin_hint,
        })

    # Pattern C — IAM role trust (assume-role) policy changed.
    if types & _TRUST_POLICY_TYPES:
        trig = [e for e in events if e.event_type in _TRUST_POLICY_TYPES]
        matches.append({
            "signal_key": "aws.iam_behavior.role_trust_policy_change",
            "severity": "high",
            "phrase": "IAM role trust policy changed",
            "summary_core": (
                "CloudTrail shows an IAM role trust (assume-role) policy change "
                "in the review window."
            ),
            "trigger_events": trig,
        })

    # Pattern D — KMS key protection changed (disable / schedule deletion).
    if types & _KMS_TYPES:
        trig = [e for e in events if e.event_type in _KMS_TYPES]
        matches.append({
            "signal_key": "aws.kms_behavior.key_protection_changed",
            "severity": "high",
            "phrase": "KMS key protection changed",
            "summary_core": (
                "CloudTrail shows a KMS key protection change (key disabled or "
                "scheduled for deletion) in the review window."
            ),
            "trigger_events": trig,
        })

    # Pattern E — S3 access control changed (policy / ACL / public access block).
    if types & _S3_TYPES:
        trig = [e for e in events if e.event_type in _S3_TYPES]
        matches.append({
            "signal_key": "aws.s3_behavior.access_control_changed",
            "severity": "medium",
            "phrase": "S3 access control changed",
            "summary_core": (
                "CloudTrail shows an S3 access-control change (bucket policy, ACL, "
                "or public access block) in the review window. ConfigTrace does "
                "not infer or claim that any data was accessed."
            ),
            "trigger_events": trig,
        })

    return matches


def build_iam_behavior_signal(
    *,
    events: list[SecurityActivityEvent],
    match: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Build one behavior-timeline signal dict from a matched pattern."""
    trig = match.get("trigger_events") or []
    if not trig:
        return None
    anchor = _pick_anchor(trig)
    principal = _display_principal(events)

    times = [_when(e) for e in trig]
    window_start = min(times)
    window_end = max(times)

    trigger_types = sorted({e.event_type for e in trig})
    anchor_md = _meta(anchor)

    title = f"{match['phrase']} for {principal}"
    summary = f"{match['summary_core']} {_REVIEW_NOTE}"

    metadata = signal_svc.sanitize_signal_metadata({
        "event_types": ",".join(trigger_types),
        "actor_id": anchor.actor_id if isinstance(anchor.actor_id, str) else None,
        "resource_id": anchor.resource_id if isinstance(anchor.resource_id, str) else None,
        "event_count": len(trig),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "principal_hash": anchor_md.get("principal_id_hash"),
        "policy_name": match.get("policy_name"),
        "resource_name": anchor_md.get("resource_name"),
        "event_type": anchor.event_type,
    })

    return {
        "provider": PROVIDER,
        "integration_id": anchor.integration_id,
        "signal_key": match["signal_key"],
        "signal_type": SIGNAL_TYPE,
        "severity": match["severity"],
        "status": "open",
        "title": title,
        "summary": summary,
        "evidence_level": EVIDENCE_LEVEL,
        "confidence": CONFIDENCE,
        "first_seen_at": window_start,
        "last_seen_at": window_end,
        "linked_activity_event_id": anchor.id,
        "metadata": metadata,
    }


def generate_aws_iam_behavior_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 72,
    max_signals: int = 200,
    scan_limit: int = 2000,
) -> dict[str, Any]:
    """Generate IAM behavior-timeline signals for a workspace.

    Conservative + deterministic + idempotent: re-running over the same events
    produces the same anchors and therefore creates no duplicates. Returns a
    generation summary.
    """
    hours = max(1, min(int(lookback_hours or 72), 168))
    cap = max(1, min(int(max_signals or 200), 1000))
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
    # Keep events inside the lookback window (by occurred_at, else ingested_at).
    events = [e for e in raw if _when(e) >= cutoff]

    groups = group_cloudtrail_events_by_principal(events)

    created = 0
    skipped = 0
    for _key, grp in groups.items():
        for match in _detect_patterns(grp):
            if created >= cap:
                break
            signal = build_iam_behavior_signal(events=grp, match=match)
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
        "principals_scanned": len(groups),
        "signals_created": created,
        "signals_skipped": skipped,
    }
