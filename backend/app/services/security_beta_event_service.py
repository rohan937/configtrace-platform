"""Beta usage instrumentation for Security Exposure (M63.1).

Records coarse, workspace-scoped usage events with an allowlisted, truncated,
metadata-only payload. First-party storage only; no third-party analytics.

Privacy contract:
  * ``event_name`` must be in EVENT_NAMES, else ValueError (the endpoint maps
    this to HTTP 422).
  * metadata keys not in ALLOWED_METADATA_KEYS are silently dropped (lenient,
    non-breaking for callers).
  * Only scalar values (str / int / float / bool) are kept; nested
    objects/arrays are dropped. Strings are truncated to MAX_STR_LEN.
  * Forbidden keys (evidence, remediation, secrets, tokens, payloads, raw
    provider/rule data, note bodies) are never on the allowlist, so they can
    never be stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_beta_event import SecurityBetaEvent

# Stable, boring event names. Keep additions backwards-compatible.
EVENT_NAMES: frozenset[str] = frozenset(
    {
        "security_page_viewed",
        "security_demo_seed_clicked",
        "security_demo_seed_completed",
        "security_demo_clear_clicked",
        "security_walkthrough_opened",
        "security_walkthrough_step_clicked",
        "security_onboarding_cta_clicked",
        "security_exposure_opened",
        "security_exposure_action_clicked",
        "security_exposure_action_completed",
        "security_note_added",
        "security_report_exported",
        "security_rule_toggled",
        "security_coverage_viewed",
        "security_incident_review_run",
        "security_asset_expanded",
    }
)

# Small allowlist of non-sensitive metadata keys. Anything else is dropped.
ALLOWED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "provider",
        "severity",
        "status",
        "rule_key",
        "finding_id",
        "asset_type",
        "report_type",
        "demo_loaded",
        "checklist_item_id",
        "action",
        "result",
        "error_code",
        "route_group",
    }
)

MAX_STR_LEN = 200
MAX_PAGE_PATH_LEN = 300
MAX_METADATA_KEYS = 20


def sanitize_metadata(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return a safe, allowlisted, truncated copy of metadata.

    Drops unknown keys, drops nested/complex values, truncates strings.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in ALLOWED_METADATA_KEYS:
            continue  # strip unknown / forbidden keys
        if isinstance(value, bool):
            out[key] = value
        elif isinstance(value, (int, float)):
            out[key] = value
        elif isinstance(value, str):
            out[key] = value[:MAX_STR_LEN]
        else:
            # Drop None, dicts, lists, and anything else — keep payload flat/safe.
            continue
        if len(out) >= MAX_METADATA_KEYS:
            break
    return out


def record_event(
    *,
    workspace_id: uuid.UUID,
    user_id: Optional[uuid.UUID],
    event_name: str,
    page_path: Optional[str],
    metadata: Optional[dict[str, Any]],
    db: Session,
) -> SecurityBetaEvent:
    """Validate + persist a single beta event. Raises ValueError on bad name."""
    if not isinstance(event_name, str) or event_name not in EVENT_NAMES:
        raise ValueError(f"Unknown event_name: {event_name!r}")

    safe_path: Optional[str] = None
    if isinstance(page_path, str) and page_path:
        safe_path = page_path[:MAX_PAGE_PATH_LEN]

    event = SecurityBetaEvent(
        workspace_id=workspace_id,
        user_id=user_id,
        event_name=event_name,
        event_category="security_beta",
        page_path=safe_path,
        event_metadata=sanitize_metadata(metadata),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


# ── Analytics summary (M63.4) ─────────────────────────────────────────────────

ALLOWED_SUMMARY_DAYS = (1, 7, 30, 90)
RECENT_EVENTS_LIMIT = 20
TOP_ACTIONS_LIMIT = 10


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def summarize(
    *,
    workspace_id: uuid.UUID,
    days: int,
    db: Session,
    event_name: Optional[str] = None,
    route_group: Optional[str] = None,
) -> dict[str, Any]:
    """Read-only, workspace-scoped analytics over security_beta_events (M63.4).

    Aggregates in Python over the workspace's rows in the window (datasets are
    small and workspace-bounded). Returns only allowlisted, already-sanitized
    metadata — no evidence/remediation/secrets/note bodies are ever read.
    """
    if days not in ALLOWED_SUMMARY_DAYS:
        days = 7
    period_end = _utcnow()
    period_start = period_end - timedelta(days=days)

    q = (
        db.query(SecurityBetaEvent)
        .filter(
            SecurityBetaEvent.workspace_id == workspace_id,
            SecurityBetaEvent.created_at >= period_start,
        )
    )
    if event_name:
        q = q.filter(SecurityBetaEvent.event_name == event_name)
    rows = q.order_by(SecurityBetaEvent.created_at.desc()).all()

    def _rg(ev: SecurityBetaEvent) -> Optional[str]:
        md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
        rg = md.get("route_group")
        return rg if isinstance(rg, str) else None

    if route_group:
        rows = [ev for ev in rows if _rg(ev) == route_group]

    events_by_name: dict[str, int] = {}
    events_by_route_group: dict[str, int] = {}
    events_by_day_map: dict[str, int] = {}
    actions_map: dict[str, int] = {}
    users: set[str] = set()

    for ev in rows:
        events_by_name[ev.event_name] = events_by_name.get(ev.event_name, 0) + 1
        rg = _rg(ev)
        if rg:
            events_by_route_group[rg] = events_by_route_group.get(rg, 0) + 1
        day = ev.created_at.astimezone(timezone.utc).strftime("%Y-%m-%d")
        events_by_day_map[day] = events_by_day_map.get(day, 0) + 1
        if ev.user_id is not None:
            users.add(str(ev.user_id))
        md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
        action = md.get("action")
        if isinstance(action, str) and action:
            actions_map[action] = actions_map.get(action, 0) + 1

    def _count(name: str) -> int:
        return events_by_name.get(name, 0)

    top_actions = sorted(
        ({"action": a, "count": c} for a, c in actions_map.items()),
        key=lambda x: (-x["count"], x["action"]),
    )[:TOP_ACTIONS_LIMIT]

    events_by_day = [
        {"day": d, "count": events_by_day_map[d]} for d in sorted(events_by_day_map)
    ]

    recent_events = [
        {
            "event_name": ev.event_name,
            "page_path": ev.page_path,
            # Re-sanitize defensively even though writes are already allowlisted.
            "metadata": sanitize_metadata(
                ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
            ),
            "created_at": ev.created_at,
            "user_id": str(ev.user_id) if ev.user_id is not None else None,
        }
        for ev in rows[:RECENT_EVENTS_LIMIT]
    ]

    return {
        "period_start": period_start,
        "period_end": period_end,
        "days": days,
        "total_events": len(rows),
        "unique_users": len(users),
        "events_by_name": events_by_name,
        "events_by_route_group": events_by_route_group,
        "events_by_day": events_by_day,
        "top_actions": top_actions,
        "report_exports": _count("security_report_exported"),
        "demo_seeds": _count("security_demo_seed_completed"),
        "walkthrough_opens": _count("security_walkthrough_opened"),
        "exposure_actions": _count("security_exposure_action_completed"),
        "rule_toggles": _count("security_rule_toggled"),
        "page_views": _count("security_page_viewed"),
        "recent_events": recent_events,
    }
