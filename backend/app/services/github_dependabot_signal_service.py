"""GitHub Dependabot alert Incident Signals (M69.4H).

Groups normalized GitHub Dependabot activity (``security_activity_events``,
provider=github, source=dependabot_alert — ingested in M69.4G) by repository /
alert number / package / advisory and surfaces review-worthy patterns as Incident
Signals (``security_incident_signals``, signal_type="github_dependabot_alert",
evidence_level="activity", confidence="medium").

Core idea: a Dependabot alert is EVIDENCE that GitHub matched a known
vulnerability advisory against a dependency declared in the repository. That is
review-worthy — but it is not, on its own, proof that the vulnerable dependency
is reachable, that it was exploited, that a compromise occurred, or that anyone
gained access. Open / high-severity / reopened alerts are higher review priority;
fixed alerts are lower; dismissed/auto-dismissed alerts are context only.

CLAIM DISCIPLINE: these are DEPENDABOT review signals built from alert evidence.
They never assert that exploitation is confirmed, that the vulnerable dependency
was exploited, that a compromise occurred, that an attacker was found, that
someone has access, that access was unauthorized, or that a breach/attack
occurred — only "evidence for review" and, where GitHub itself set it, "marked
high severity".

PRIVACY: only allowlisted, flat, safe fields are stored (repository, alert
number, state, package name/ecosystem, version ranges, advisory GHSA/CVE ids +
severity, CVSS/EPSS scores, scope, counts, window). The source events were
already sanitized in M69.4G (raw advisory body, raw manifest/file paths, and the
raw dependency-graph/API response never read) and signal metadata is re-sanitized
through the signal allowlist — NEVER raw manifest paths, file paths, the raw
dependency-graph response, advisory bodies/details, the raw API response, patch,
headers, request body, tokens, or credentials.
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
SOURCE = "dependabot_alert"
SIGNAL_TYPE = "github_dependabot_alert"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

# Normalized event types (from M69.4G ingestion).
_OPEN = "github.dependabot.alert.open"
_FIXED = "github.dependabot.alert.fixed"
_DISMISSED = "github.dependabot.alert.dismissed"
_AUTO_DISMISSED = "github.dependabot.alert.auto_dismissed"
_REOPENED = "github.dependabot.alert.reopened"
_EVENT = "github.dependabot.alert.event"

_DISMISSED_TYPES = {_DISMISSED, _AUTO_DISMISSED}

# Advisory severities considered high review priority.
_HIGH_SEVERITIES = {"critical", "high"}

# Deterministic anchor rank within an alert group. Open/reopened evidence outranks
# fixed/dismissed, which outranks the fallback.
_EVENT_RANK: dict[str, int] = {
    _OPEN: 60,
    _REOPENED: 58,
    _DISMISSED: 40,
    _AUTO_DISMISSED: 38,
    _FIXED: 36,
    _EVENT: 20,
}

# Calibrated note appended to every Dependabot signal summary.
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


def _advisory_id(ev: SecurityActivityEvent) -> str:
    return _str_md(ev, "advisory_ghsa_id") or _str_md(ev, "advisory_cve_id") or ""


def _is_high_severity(ev: SecurityActivityEvent) -> bool:
    v = _meta(ev).get("advisory_severity")
    if isinstance(v, str) and v.strip().lower() in _HIGH_SEVERITIES:
        return True
    # Optional CVSS escalation when the score is safely available.
    score = _meta(ev).get("cvss_score")
    return isinstance(score, (int, float)) and not isinstance(score, bool) and score >= 7.0


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
    return (
        repo,
        _alert_number(ev),
        _str_md(ev, "dependency_package_name"),
        _str_md(ev, "dependency_ecosystem"),
        _advisory_id(ev),
    )


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
    package = _str_md(anchor, "dependency_package_name") or ""
    ecosystem = _str_md(anchor, "dependency_ecosystem") or ""
    advisory = _advisory_id(anchor)
    state = _str_md(anchor, "state") or ""
    sev = _str_md(anchor, "advisory_severity") or ""
    parts = [
        "github.dependabot",
        pattern,
        repo,
        str(num) if num is not None else "",
        package,
        ecosystem,
        advisory,
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
        "dependency_package_name": _str_md(anchor, "dependency_package_name"),
        "dependency_ecosystem": _str_md(anchor, "dependency_ecosystem"),
        "vulnerable_version_range": _str_md(anchor, "vulnerable_version_range"),
        "patched_versions": _str_md(anchor, "patched_versions"),
        "advisory_ghsa_id": _str_md(anchor, "advisory_ghsa_id"),
        "advisory_cve_id": _str_md(anchor, "advisory_cve_id"),
        "advisory_severity": _str_md(anchor, "advisory_severity"),
        "cvss_score": _meta(anchor).get("cvss_score"),
        "epss_percentage": _meta(anchor).get("epss_percentage"),
        "scope": _str_md(anchor, "scope"),
        "dismissed_reason": _str_md(anchor, "dismissed_reason"),
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
    """Return the signal dicts for one alert group (repo, alert#, pkg, advisory)."""
    signals: list[dict[str, Any]] = []
    open_anchor = _pick_anchor_of_type(group, {_OPEN})

    if open_anchor is not None:
        high = _is_high_severity(open_anchor)

        # Pattern A — open Dependabot alert (always fires for an open alert).
        signals.append(_build_signal(
            pattern="open_alert",
            severity="high" if high else "medium",
            phrase="GitHub Dependabot alert opened",
            summary_core=(
                "GitHub Dependabot alert evidence was observed for this repository."
            ),
            anchor=open_anchor,
            group=group,
        ))

        # Pattern B — open alert GitHub marked high/critical advisory severity.
        if high:
            signals.append(_build_signal(
                pattern="high_severity",
                severity="high",
                phrase="GitHub Dependabot alert marked high severity",
                summary_core=(
                    "GitHub marked this Dependabot alert as a high or critical "
                    "severity advisory. This reflects GitHub's advisory metadata "
                    "only and does not confirm exploitability."
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
            phrase="GitHub Dependabot alert reopened",
            summary_core=(
                "A GitHub Dependabot alert for this repository was reopened."
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
            phrase="GitHub Dependabot alert fixed",
            summary_core=(
                "A GitHub Dependabot alert for this repository was fixed. This is "
                "useful evidence and is usually lower urgency than an open alert."
            ),
            anchor=fixed_anchor,
            group=group,
        ))

    # Pattern E — dismissed / auto-dismissed alert (context only).
    dis_anchor = _pick_anchor_of_type(group, _DISMISSED_TYPES)
    if dis_anchor is not None:
        reason = (_str_md(dis_anchor, "dismissed_reason") or "").strip().lower()
        # "won't fix" / "tolerable_risk" on a high/critical advisory stays medium.
        sev_bump = _is_high_severity(dis_anchor) and reason in {
            "wont_fix", "won't fix", "tolerable_risk",
        }
        signals.append(_build_signal(
            pattern="dismissed",
            severity="medium" if sev_bump else "low",
            phrase="GitHub Dependabot alert dismissed",
            summary_core=(
                "A GitHub Dependabot alert for this repository was dismissed. A "
                "dismissal is evidence/context and does not, on its own, prove the "
                "issue is harmless."
            ),
            anchor=dis_anchor,
            group=group,
        ))

    return signals


def generate_github_dependabot_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate GitHub Dependabot review signals for a workspace.

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
