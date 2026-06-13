"""GitHub code-scanning alert Incident Signals (M69.4E).

Groups normalized GitHub code-scanning activity (``security_activity_events``,
provider=github, source=code_scanning_alert — ingested in M69.4D) by
repository / alert number / rule / tool and surfaces review-worthy patterns as
Incident Signals (``security_incident_signals``,
signal_type="github_code_scanning_alert", evidence_level="activity",
confidence="medium").

Core idea: a code-scanning (SAST) alert is EVIDENCE that GitHub's analysis tool
(e.g. CodeQL) flagged a pattern in the repository's code. That is review-worthy —
but it is not, on its own, proof that the issue is exploitable, that it was
exploited, that a compromise occurred, or that anyone gained access. Open /
high-severity / reopened alerts are higher review priority; fixed alerts are
lower; dismissed alerts are context only.

CLAIM DISCIPLINE: these are CODE-SCANNING review signals built from alert
evidence. They never assert that a vulnerability was exploited, that exploitation
is confirmed, that a compromise occurred, that an attacker was found, that someone
has access, that access was unauthorized, or that a breach/attack occurred — only
"evidence for review" and, where GitHub itself set it, "marked high severity".

PRIVACY: only allowlisted, flat, safe fields are stored (repository, alert
number, state, rule id/name, tool name, severity, security severity level,
dismissed reason, instances COUNT, counts, window). The source events were
already sanitized in M69.4D (raw SARIF / code snippet / file content / raw
locations never read, raw alert URL salted-hashed, instances reduced to a count)
and signal metadata is re-sanitized through the signal allowlist — NEVER raw
code, file contents, raw SARIF, raw locations/paths, the raw alert URL, the raw
API response, patch, headers, request body, tokens, or credentials.
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
SOURCE = "code_scanning_alert"
SIGNAL_TYPE = "github_code_scanning_alert"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

# Normalized event types (from M69.4D ingestion).
_OPEN = "github.code_scanning.alert.open"
_FIXED = "github.code_scanning.alert.fixed"
_DISMISSED = "github.code_scanning.alert.dismissed"
_REOPENED = "github.code_scanning.alert.reopened"
_EVENT = "github.code_scanning.alert.event"

# GitHub security severity levels considered high review priority.
_HIGH_SEVERITIES = {"critical", "high"}

# Deterministic anchor rank within an alert group. Open/reopened evidence outranks
# fixed/dismissed, which outranks the fallback.
_EVENT_RANK: dict[str, int] = {
    _OPEN: 60,
    _REOPENED: 58,
    _DISMISSED: 40,
    _FIXED: 38,
    _EVENT: 20,
}

# Calibrated note appended to every code-scanning signal summary.
_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm exploitation, "
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


def _is_high_severity(ev: SecurityActivityEvent) -> bool:
    v = _meta(ev).get("security_severity_level")
    return isinstance(v, str) and v.strip().lower() in _HIGH_SEVERITIES


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
    return (repo, _alert_number(ev), _str_md(ev, "rule_id"), _str_md(ev, "tool_name"))


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
    rule_id = _str_md(anchor, "rule_id") or ""
    state = _str_md(anchor, "state") or ""
    sev = _str_md(anchor, "security_severity_level") or _str_md(anchor, "severity") or ""
    parts = [
        "github.code_scanning",
        pattern,
        repo,
        str(num) if num is not None else "",
        rule_id,
        state,
        sev,
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
        "rule_id": _str_md(anchor, "rule_id"),
        "rule_name": _str_md(anchor, "rule_name"),
        "tool_name": _str_md(anchor, "tool_name"),
        "severity": _str_md(anchor, "severity"),
        "security_severity_level": _str_md(anchor, "security_severity_level"),
        "dismissed_reason": _str_md(anchor, "dismissed_reason"),
        "instances_count": _meta(anchor).get("instances_count"),
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
    """Return the signal dicts for one alert group (repo, alert#, rule, tool)."""
    signals: list[dict[str, Any]] = []
    open_anchor = _pick_anchor_of_type(group, {_OPEN})

    if open_anchor is not None:
        high = _is_high_severity(open_anchor)

        # Pattern A — open code-scanning alert (always fires for an open alert).
        signals.append(_build_signal(
            pattern="open_alert",
            severity="high" if high else "medium",
            phrase="GitHub code-scanning alert opened",
            summary_core=(
                "GitHub code-scanning alert evidence was observed for this "
                "repository."
            ),
            anchor=open_anchor,
            group=group,
        ))

        # Pattern B — open alert GitHub marked high/critical security severity.
        if high:
            signals.append(_build_signal(
                pattern="high_severity",
                severity="high",
                phrase="GitHub code-scanning alert marked high severity",
                summary_core=(
                    "GitHub marked this code-scanning alert as high or critical "
                    "security severity. This reflects GitHub's alert metadata only "
                    "and does not confirm exploitability."
                ),
                anchor=open_anchor,
                group=group,
            ))

    # Pattern C — reopened alert.
    re_anchor = _pick_anchor_of_type(group, {_REOPENED})
    if re_anchor is not None:
        signals.append(_build_signal(
            pattern="reopened",
            severity="high" if _is_high_severity(re_anchor) else "medium",
            phrase="GitHub code-scanning alert reopened",
            summary_core=(
                "A GitHub code-scanning alert for this repository was reopened."
            ),
            anchor=re_anchor,
            group=group,
        ))

    # Pattern D — fixed alert (lower urgency context).
    fixed_anchor = _pick_anchor_of_type(group, {_FIXED})
    if fixed_anchor is not None:
        signals.append(_build_signal(
            pattern="fixed",
            severity="low",
            phrase="GitHub code-scanning alert fixed",
            summary_core=(
                "A GitHub code-scanning alert for this repository was fixed. This is "
                "useful evidence and is usually lower urgency than an open alert."
            ),
            anchor=fixed_anchor,
            group=group,
        ))

    # Pattern E — dismissed alert (context only).
    dis_anchor = _pick_anchor_of_type(group, {_DISMISSED})
    if dis_anchor is not None:
        # "won't fix" dismissals stay medium when high severity; otherwise low.
        reason = (_str_md(dis_anchor, "dismissed_reason") or "").strip().lower()
        sev_bump = _is_high_severity(dis_anchor) and reason in {"won't fix", "wont fix", "won’t fix"}
        signals.append(_build_signal(
            pattern="dismissed",
            severity="medium" if sev_bump else "low",
            phrase="GitHub code-scanning alert dismissed",
            summary_core=(
                "A GitHub code-scanning alert for this repository was dismissed. A "
                "dismissal is evidence/context and does not, on its own, prove the "
                "issue is harmless."
            ),
            anchor=dis_anchor,
            group=group,
        ))

    return signals


def generate_github_code_scanning_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate GitHub code-scanning review signals for a workspace.

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
