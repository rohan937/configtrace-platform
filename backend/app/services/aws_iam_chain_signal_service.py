"""AWS IAM privilege-escalation chain detection (M69.3A).

Groups normalized CloudTrail management activity (``security_activity_events``,
provider=aws, source=cloudtrail — ingested in M67.5) by target IAM entity
(the user/role being created/modified) and detects ORDERED privilege-escalation
SEQUENCE patterns within a configurable chain window, surfacing them as Incident
Signals (``security_incident_signals``, signal_type="aws_iam_privilege_chain",
evidence_level="activity", confidence="medium").

WHY THIS IS DIFFERENT FROM M67.6:
M67.6 (``aws_iam_behavior_service.py``) detects unordered per-ACTOR patterns
("this actor did policy-change and access-key-creation in any order"). M69.3A
detects ordered per-TARGET-ENTITY sequences: "user X was created, THEN user X
was granted a policy, THEN user X got an access key" — a privilege-escalation
progression targeting the same IAM entity within a tight time window.

PATTERNS IMPLEMENTED:
  A. CreateUser → AttachUserPolicy / PutUserPolicy     (same target user)
     Signal: "AWS IAM user creation followed by privilege grant"
  B. CreateRole → AttachRolePolicy / PutRolePolicy     (same target role)
     Signal: "AWS IAM role creation followed by privilege grant"
  C. AttachUserPolicy / PutUserPolicy → CreateAccessKey (same target user)
     Signal: "AWS IAM privilege grant followed by access-key creation"

PATTERNS DEFERRED:
  D. UpdateAssumeRolePolicy → AssumeRole: AssumeRole is NOT currently ingested
     (not in _EVENT_NAME_MAP in aws_cloudtrail_ingestion_service.py). Deferred.
  E. AddUserToGroup → CreateAccessKey: AddUserToGroup is NOT currently ingested.
     Deferred.

GROUPING KEY:
Events are grouped by (integration_id, normalized target_entity) where
target_entity = resource_id (the IAM user/role name the event acts ON, stored
during ingestion). Events without a resource_id are not chain-able.

CLAIM DISCIPLINE: these are ordered CloudTrail activity chain patterns for
review. They NEVER assert a breach, attacker, compromise, unauthorized access,
or privilege escalation that succeeded — only "evidence for review". ConfigTrace
cannot determine whether any action was authorized.

PRIVACY: only allowlisted, flat, safe summary fields are stored (pattern,
entity names, event types, counts, window). NEVER raw CloudTrail JSON,
requestParameters/responseElements, raw IPs, secrets, tokens, access key
values, session tokens, or request bodies.
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
SIGNAL_TYPE = "aws_iam_privilege_chain"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

# CloudTrail event types used in chain patterns.
_CREATE_USER = "aws.iam.create_user"
_CREATE_ROLE = "aws.iam.create_role"
_ATTACH_USER_POLICY = "aws.iam.attach_user_policy"
_PUT_USER_POLICY = "aws.iam.put_user_policy"
_ATTACH_ROLE_POLICY = "aws.iam.attach_role_policy"
_PUT_ROLE_POLICY = "aws.iam.put_role_policy"
_CREATE_ACCESS_KEY = "aws.iam.create_access_key"

_GRANT_USER = frozenset({_ATTACH_USER_POLICY, _PUT_USER_POLICY})
_GRANT_ROLE = frozenset({_ATTACH_ROLE_POLICY, _PUT_ROLE_POLICY})

# All event types involved in any chain pattern (pre-filter load).
_CHAIN_RELEVANT_TYPES = frozenset({
    _CREATE_USER, _CREATE_ROLE,
    _ATTACH_USER_POLICY, _PUT_USER_POLICY,
    _ATTACH_ROLE_POLICY, _PUT_ROLE_POLICY,
    _CREATE_ACCESS_KEY,
})

# Deterministic anchor rank — higher = preferred "most important" anchor event.
_CHAIN_ANCHOR_RANK: dict[str, int] = {
    _CREATE_ACCESS_KEY: 70,
    _ATTACH_USER_POLICY: 60,
    _ATTACH_ROLE_POLICY: 60,
    _PUT_USER_POLICY: 58,
    _PUT_ROLE_POLICY: 58,
    _CREATE_USER: 40,
    _CREATE_ROLE: 40,
}

_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm compromise or "
    "unauthorized access."
)

DEFAULT_LOOKBACK_HOURS = 24
DEFAULT_CHAIN_WINDOW_MINUTES = 60
DEFAULT_MAX_SIGNALS = 100


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _meta(ev: SecurityActivityEvent) -> dict[str, Any]:
    return ev.event_metadata if isinstance(ev.event_metadata, dict) else {}


def _when(ev: SecurityActivityEvent) -> datetime:
    return ev.occurred_at or ev.ingested_at or _utcnow()


def _norm_entity(value: Any) -> Optional[str]:
    """Normalize a resource_id / entity name to a comparable bare name.

    Reduces ARNs to their final segment and lower-cases. Returns None for
    empty/non-string values so empty keys never match.
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if "arn:aws:" in s:
        if "/" in s:
            s = s.rsplit("/", 1)[-1]
        else:
            s = s.rsplit(":", 1)[-1]
    return s.lower().strip() or None


def _pick_anchor(events: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Deterministic most-important event: rank, then latest time, then id."""
    return max(
        events,
        key=lambda e: (
            _CHAIN_ANCHOR_RANK.get(e.event_type, 0),
            _when(e),
            str(e.provider_event_id or ""),
        ),
    )


def _actor(ev: SecurityActivityEvent) -> Optional[str]:
    if isinstance(ev.actor_id, str) and ev.actor_id.strip():
        return ev.actor_id.strip()
    md = _meta(ev)
    for k in ("user_name", "role_name"):
        v = md.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _policy_hint(ev: SecurityActivityEvent) -> Optional[str]:
    md = _meta(ev)
    for k in ("policy_name", "resource_name", "resource_arn"):
        v = md.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()[:120]
    return None


def detect_iam_chains(
    events: list[SecurityActivityEvent],
    chain_window: timedelta,
) -> list[dict[str, Any]]:
    """Detect ordered IAM privilege-escalation chains for one target entity's events.

    Returns a list of matched chain dicts, each with:
    ``{chain_pattern, signal_key, severity, phrase, summary_core,
       chain_events, anchor}``.
    """
    if not events:
        return []

    # Sort ascending by time (deterministic across multiple calls).
    evs = sorted(events, key=lambda e: (_when(e), str(e.provider_event_id or "")))
    seen_chain_ids: set[tuple] = set()
    chains: list[dict[str, Any]] = []

    # ── Pattern A: CreateUser → UserPolicyGrant ────────────────────────────────
    create_users = [e for e in evs if e.event_type == _CREATE_USER]
    for cu in create_users:
        for pg in evs:
            if pg.event_type not in _GRANT_USER:
                continue
            if _when(pg) <= _when(cu):
                continue
            if _when(pg) - _when(cu) > chain_window:
                continue
            chain_id = ("A", cu.id, pg.id)
            if chain_id in seen_chain_ids:
                continue
            seen_chain_ids.add(chain_id)
            chains.append({
                "chain_pattern": "user_create_privilege_grant",
                "signal_key": "aws.iam_chain.user_create_privilege_grant",
                "severity": "high",
                "phrase": "AWS IAM user creation followed by privilege grant",
                "summary_core": (
                    "AWS CloudTrail activity shows IAM user creation followed by "
                    "a permission-granting IAM action for the same target user "
                    "within the chain review window."
                ),
                "chain_events": [cu, pg],
                "anchor": pg,
            })

    # ── Pattern B: CreateRole → RolePolicyGrant ────────────────────────────────
    create_roles = [e for e in evs if e.event_type == _CREATE_ROLE]
    for cr in create_roles:
        for pg in evs:
            if pg.event_type not in _GRANT_ROLE:
                continue
            if _when(pg) <= _when(cr):
                continue
            if _when(pg) - _when(cr) > chain_window:
                continue
            chain_id = ("B", cr.id, pg.id)
            if chain_id in seen_chain_ids:
                continue
            seen_chain_ids.add(chain_id)
            chains.append({
                "chain_pattern": "role_create_privilege_grant",
                "signal_key": "aws.iam_chain.role_create_privilege_grant",
                "severity": "high",
                "phrase": "AWS IAM role creation followed by privilege grant",
                "summary_core": (
                    "AWS CloudTrail activity shows IAM role creation followed by "
                    "a permission-granting IAM action for the same target role "
                    "within the chain review window."
                ),
                "chain_events": [cr, pg],
                "anchor": pg,
            })

    # ── Pattern C: UserPolicyGrant → CreateAccessKey ───────────────────────────
    for pg in evs:
        if pg.event_type not in _GRANT_USER:
            continue
        for ak in evs:
            if ak.event_type != _CREATE_ACCESS_KEY:
                continue
            if _when(ak) <= _when(pg):
                continue
            if _when(ak) - _when(pg) > chain_window:
                continue
            chain_id = ("C", pg.id, ak.id)
            if chain_id in seen_chain_ids:
                continue
            seen_chain_ids.add(chain_id)
            chains.append({
                "chain_pattern": "privilege_grant_access_key",
                "signal_key": "aws.iam_chain.privilege_grant_access_key",
                "severity": "high",
                "phrase": "AWS IAM privilege grant followed by access-key creation",
                "summary_core": (
                    "AWS CloudTrail activity shows an IAM permission-granting "
                    "action followed by access-key creation for the same target "
                    "user within the chain review window."
                ),
                "chain_events": [pg, ak],
                "anchor": ak,
            })

    return chains


def build_iam_chain_signal(
    *,
    chain: dict[str, Any],
    chain_window_minutes: int,
) -> Optional[dict[str, Any]]:
    """Build one IAM chain signal dict from a matched pattern."""
    chain_evs = chain.get("chain_events") or []
    if not chain_evs:
        return None
    anchor = chain.get("anchor") or _pick_anchor(chain_evs)

    times = [_when(e) for e in chain_evs]
    first_at = min(times)
    last_at = max(times)

    # Best-effort safe entity label (never an ARN, just a bare name).
    entity = _norm_entity(anchor.resource_id)
    actor = _actor(anchor)

    label = entity or actor or "an IAM entity"
    title = f"{chain['phrase']} ({label})"
    summary = f"{chain['summary_core']} {_REVIEW_NOTE}"

    # Determine whether target is user or role from chain_pattern.
    pattern = chain.get("chain_pattern", "")
    target_user = entity if "user" in pattern else None
    target_role = entity if "role" in pattern else None

    # Safe policy hint — never raw ARN, just name-like label.
    p_hint = None
    for ev in chain_evs:
        if ev.event_type in (_GRANT_USER | _GRANT_ROLE):
            p_hint = _policy_hint(ev)
            break

    event_types = sorted({e.event_type for e in chain_evs})
    anchor_md = _meta(anchor)

    metadata = signal_svc.sanitize_signal_metadata({
        "source": SOURCE,
        "chain_pattern": pattern,
        "event_types": ",".join(event_types),
        "actor_id": actor,
        "resource_name": entity,
        "target_user": target_user,
        "target_role": target_role,
        "policy_arn": p_hint,
        "chain_steps": len(chain_evs),
        "event_count": len(chain_evs),
        "chain_window_minutes": chain_window_minutes,
        "window_start": first_at.isoformat(),
        "window_end": last_at.isoformat(),
    })

    return {
        "provider": PROVIDER,
        "integration_id": anchor.integration_id,
        "signal_key": chain["signal_key"],
        "signal_type": SIGNAL_TYPE,
        "severity": chain["severity"],
        "status": "open",
        "title": title[:240],
        "summary": summary,
        "evidence_level": EVIDENCE_LEVEL,
        "confidence": CONFIDENCE,
        "first_seen_at": first_at,
        "last_seen_at": last_at,
        "linked_activity_event_id": anchor.id,
        "metadata": metadata,
    }


def generate_aws_iam_chain_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
    max_signals: int = DEFAULT_MAX_SIGNALS,
    chain_window_minutes: int = DEFAULT_CHAIN_WINDOW_MINUTES,
    scan_limit: int = 5000,
) -> dict[str, Any]:
    """Generate AWS IAM privilege-chain signals for a workspace.

    Detects ordered sequences (CreateUser→grant, CreateRole→grant, grant→key)
    where both steps target the SAME IAM entity within ``chain_window_minutes``.
    Deterministic + idempotent: same anchor event → same signal → no duplicate.
    """
    hours = max(1, min(int(lookback_hours or DEFAULT_LOOKBACK_HOURS), 168))
    cap = max(1, min(int(max_signals or DEFAULT_MAX_SIGNALS), 1000))
    win_min = max(1, min(int(chain_window_minutes or DEFAULT_CHAIN_WINDOW_MINUTES), 1440))
    chain_window = timedelta(minutes=win_min)
    cutoff = _utcnow() - timedelta(hours=hours)

    raw = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER,
            SecurityActivityEvent.source == SOURCE,
            SecurityActivityEvent.event_type.in_(tuple(_CHAIN_RELEVANT_TYPES)),
        )
        .order_by(
            SecurityActivityEvent.occurred_at.desc().nullslast(),
            SecurityActivityEvent.created_at.desc(),
        )
        .limit(scan_limit)
        .all()
    )
    events = [e for e in raw if (_when(e) >= cutoff) and _norm_entity(e.resource_id)]

    # Group by (integration_id, normalized_target_entity). Events without both
    # integration_id and resource_id cannot be safely chained.
    groups: dict[tuple, list[SecurityActivityEvent]] = {}
    for ev in events:
        entity = _norm_entity(ev.resource_id)
        if not entity:
            continue
        key = (ev.integration_id, entity)
        groups.setdefault(key, []).append(ev)

    created = 0
    skipped = 0
    for _key, grp in groups.items():
        chains = detect_iam_chains(grp, chain_window)
        for chain in chains:
            if created >= cap:
                break
            signal = build_iam_chain_signal(chain=chain, chain_window_minutes=win_min)
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
        "chains_scanned": len(groups),
        "signals_created": created,
        "signals_skipped": skipped,
    }
