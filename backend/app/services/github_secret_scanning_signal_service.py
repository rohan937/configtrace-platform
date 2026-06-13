"""GitHub secret-scanning alert Incident Signals (M69.4B).

Groups normalized GitHub secret-scanning activity (``security_activity_events``,
provider=github, source=secret_scanning_alert — ingested in M69.4A) by
repository / alert number / secret type and surfaces review-worthy patterns as
Incident Signals (``security_incident_signals``,
signal_type="github_secret_scanning_alert", evidence_level="activity",
confidence="medium").

Core idea: a secret-scanning alert is EVIDENCE that GitHub detected a pattern
matching a known secret type in the repository. That is review-worthy — but it
is not, on its own, proof that a secret was leaked, abused, or that anyone gained
access. Open / publicly-leaked / active-validity alerts are higher review
priority; resolved/revoked alerts are lower; false-positive / used-in-tests
alerts are context only.

CLAIM DISCIPLINE: these are SECRET-SCANNING review signals built from alert
evidence. They never assert that a secret was leaked-and-confirmed, abused,
compromised, that an attacker was found, that someone has access, that access was
unauthorized, or that a breach/attack occurred — only "evidence for review" and,
where GitHub itself set the flag, "marked publicly leaked" / "marked active".

PRIVACY: only allowlisted, flat, safe fields are stored (repository, alert
number, state, resolution, secret type, validity, publicly_leaked flag, location
COUNT, counts, window). The source events were already sanitized in M69.4A (raw
secret never read, raw alert URL salted-hashed, raw locations reduced to a count)
and signal metadata is re-sanitized through the signal allowlist — NEVER the raw
secret, token, credential value, raw alert URL, raw API response, raw locations,
file contents, patch, headers, or request body.
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

PROVIDER = "github"
SOURCE = "secret_scanning_alert"
SIGNAL_TYPE = "github_secret_scanning_alert"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

# Normalized event types (from M69.4A ingestion).
_OPEN = "github.secret_scanning.alert.open"
_RESOLVED = "github.secret_scanning.alert.resolved"
_REVOKED = "github.secret_scanning.alert.revoked"
_FALSE_POSITIVE = "github.secret_scanning.alert.false_positive"
_USED_IN_TESTS = "github.secret_scanning.alert.used_in_tests"
_EVENT = "github.secret_scanning.alert.event"

_RESOLVED_OR_REVOKED = {_RESOLVED, _REVOKED}
_NON_ACTIONABLE = {_FALSE_POSITIVE, _USED_IN_TESTS}

# Deterministic anchor rank within an alert group. Open evidence outranks
# resolved/revoked, which outranks non-actionable, which outranks the fallback.
_EVENT_RANK: dict[str, int] = {
    _OPEN: 60,
    _REVOKED: 52,
    _RESOLVED: 50,
    _FALSE_POSITIVE: 30,
    _USED_IN_TESTS: 28,
    _EVENT: 20,
}

# Calibrated note appended to every secret-scanning signal summary.
_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm secret misuse, "
    "compromise, or unauthorized access."
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _meta(ev: SecurityActivityEvent) -> dict[str, Any]:
    return ev.event_metadata if isinstance(ev.event_metadata, dict) else {}


def _when(ev: SecurityActivityEvent) -> datetime:
    return ev.occurred_at or ev.ingested_at or _utcnow()


def _str_md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    v = _meta(ev).get(key)
    return v if isinstance(v, str) and v else None


def _repo(ev: SecurityActivityEvent) -> Optional[str]:
    return (
        _str_md(ev, "repository_full_name")
        or _str_md(ev, "repository")
        or (ev.resource_id if isinstance(ev.resource_id, str) and ev.resource_id else None)
    )


def _alert_number(ev: SecurityActivityEvent) -> Optional[int]:
    v = _meta(ev).get("alert_number")
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _is_public(ev: SecurityActivityEvent) -> bool:
    return _meta(ev).get("publicly_leaked") is True


def _is_active(ev: SecurityActivityEvent) -> bool:
    v = _meta(ev).get("validity")
    return isinstance(v, str) and v.strip().lower() == "active"


def _pick_anchor(events: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Deterministic anchor — highest rank, then latest, then stable id."""
    return max(
        events,
        key=lambda e: (
            _EVENT_RANK.get(e.event_type, 0),
            _when(e),
            str(e.provider_event_id or ""),
        ),
    )


def _pick_anchor_of_type(
    events: list[SecurityActivityEvent], types: set[str]
) -> Optional[SecurityActivityEvent]:
    subset = [e for e in events if e.event_type in types]
    if not subset:
        return None
    return _pick_anchor(subset)


def _group_key(ev: SecurityActivityEvent) -> Optional[tuple]:
    repo = _repo(ev)
    if not repo:
        return None
    return (repo, _alert_number(ev), _str_md(ev, "secret_type"))


def _grouped(events: list[SecurityActivityEvent]) -> dict[tuple, list[SecurityActivityEvent]]:
    groups: dict[tuple, list[SecurityActivityEvent]] = {}
    for ev in events:
        k = _group_key(ev)
        if k is None:
            continue
        groups.setdefault(k, []).append(ev)
    for k in groups:
        groups[k].sort(key=lambda e: (_when(e), str(e.provider_event_id or "")))
    return groups


def _signal_key(pattern: str, anchor: SecurityActivityEvent) -> str:
    repo = _repo(anchor) or ""
    num = _alert_number(anchor)
    secret_type = _str_md(anchor, "secret_type") or ""
    state = _str_md(anchor, "state") or ""
    resolution = _str_md(anchor, "resolution") or ""
    parts = [
        "github.secret_scanning",
        pattern,
        repo,
        str(num) if num is not None else "",
        secret_type,
        state,
        resolution,
    ]
    return "|".join(parts)


def _label(anchor: SecurityActivityEvent) -> str:
    repo = _repo(anchor)
    num = _alert_number(anchor)
    if repo and num is not None:
        return f"{repo} (alert #{num})"
    if repo:
        return repo
    return "a GitHub repository"


def _build_signal(
    *,
    pattern: str,
    severity: str,
    phrase: str,
    summary_core: str,
    anchor: SecurityActivityEvent,
    group: list[SecurityActivityEvent],
) -> dict[str, Any]:
    times = [_when(e) for e in group]
    window_start = min(times)
    window_end = max(times)

    title = f"{phrase} on {_label(anchor)}"
    summary = f"{summary_core} {_REVIEW_NOTE}"

    metadata = signal_svc.sanitize_signal_metadata({
        "source": SOURCE,
        "pattern": pattern,
        "repository": _repo(anchor),
        "repository_full_name": _str_md(anchor, "repository_full_name") or _repo(anchor),
        "alert_number": _alert_number(anchor),
        "state": _str_md(anchor, "state"),
        "resolution": _str_md(anchor, "resolution"),
        "secret_type": _str_md(anchor, "secret_type"),
        "secret_type_display_name": _str_md(anchor, "secret_type_display_name"),
        "validity": _str_md(anchor, "validity"),
        "publicly_leaked": _is_public(anchor),
        "location_count": _meta(anchor).get("location_count"),
        "event_count": len(group),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
    })

    return {
        "provider": PROVIDER,
        "integration_id": anchor.integration_id,
        "signal_key": _signal_key(pattern, anchor),
        "signal_type": SIGNAL_TYPE,
        "severity": severity,
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


def _detect_group(group: list[SecurityActivityEvent]) -> list[dict[str, Any]]:
    """Return the signal dicts for one alert group (repo, alert#, secret_type)."""
    signals: list[dict[str, Any]] = []
    open_anchor = _pick_anchor_of_type(group, {_OPEN})

    if open_anchor is not None:
        public = _is_public(open_anchor)
        active = _is_active(open_anchor)

        # Pattern A — open secret-scanning alert (always fires for an open alert).
        signals.append(_build_signal(
            pattern="open_alert",
            severity="high" if (public or active) else "medium",
            phrase="GitHub secret-scanning alert opened",
            summary_core=(
                "GitHub secret-scanning alert evidence was observed for this "
                "repository."
            ),
            anchor=open_anchor,
            group=group,
        ))

        # Pattern B — open alert GitHub marked publicly leaked.
        if public:
            signals.append(_build_signal(
                pattern="publicly_leaked",
                severity="high",
                phrase="GitHub secret-scanning alert marked publicly leaked",
                summary_core=(
                    "GitHub marked this secret-scanning alert as publicly leaked. "
                    "This reflects GitHub's alert metadata only."
                ),
                anchor=open_anchor,
                group=group,
            ))

        # Pattern C — open alert GitHub reported as active validity.
        if active:
            signals.append(_build_signal(
                pattern="active_validity",
                severity="high",
                phrase="GitHub secret-scanning alert marked active",
                summary_core=(
                    "GitHub reported this secret-scanning alert as having active "
                    "validity. This reflects GitHub's alert metadata only."
                ),
                anchor=open_anchor,
                group=group,
            ))

    # Pattern D — resolved or revoked alert (lower urgency).
    rr_anchor = _pick_anchor_of_type(group, _RESOLVED_OR_REVOKED)
    if rr_anchor is not None:
        revoked = rr_anchor.event_type == _REVOKED
        signals.append(_build_signal(
            pattern="resolved_or_revoked",
            severity="medium" if revoked else "low",
            phrase="GitHub secret-scanning alert resolved or revoked",
            summary_core=(
                "A GitHub secret-scanning alert for this repository was resolved or "
                "revoked. This is useful evidence and is usually lower urgency than "
                "an open alert."
            ),
            anchor=rr_anchor,
            group=group,
        ))

    # Pattern E — false positive / used in tests (context only).
    na_anchor = _pick_anchor_of_type(group, _NON_ACTIONABLE)
    if na_anchor is not None:
        signals.append(_build_signal(
            pattern="non_actionable",
            severity="low",
            phrase="GitHub secret-scanning alert marked non-actionable",
            summary_core=(
                "A GitHub secret-scanning alert for this repository was marked "
                "non-actionable (false positive or used in tests). Treat as context."
            ),
            anchor=na_anchor,
            group=group,
        ))

    return signals


def generate_github_secret_scanning_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate GitHub secret-scanning review signals for a workspace.

    Conservative + deterministic + idempotent: re-running over the same activity
    events picks the same anchors and creates no duplicates. Returns a summary.
    """
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

    groups = _grouped(events)

    created = 0
    skipped = 0
    for _key, group in groups.items():
        for signal in _detect_group(group):
            if created >= cap:
                break
            outcome, _row = signal_svc.upsert_incident_signal(
                workspace_id=workspace_id, signal=signal, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1
        if created >= cap:
            break

    return {
        "provider": PROVIDER,
        "source": SOURCE,
        "events_scanned": len(events),
        "groups_scanned": len(groups),
        "signals_created": created,
        "signals_skipped": skipped,
    }
