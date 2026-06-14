"""Vercel activity Incident Signals (M70C).

Promotes Vercel team audit-log activity (provider=vercel, source=audit_log,
ingested in M70B) into review-worthy Incident Signals
(signal_type="vercel_activity_signal", evidence_level="activity",
confidence="medium").

Conservative + deterministic + idempotent: events are grouped by
(project, event_type, target, branch/deployment_target); each group yields one
signal anchored on the group's latest event, with a deterministic signal_key so
re-running creates no duplicates.

CLAIM DISCIPLINE: these are control-plane change review signals. They NEVER
assert that a secret was exposed, that anyone gained access, that access was
unauthorized, or that a breach/attack occurred. Severity reflects review
priority only.

PRIVACY: metadata is allowlisted + flat. NEVER env var values, deploy hook URLs,
tokens, authorization headers, raw API responses, actor emails, or raw payloads
(none of those are even present on the M70B activity events).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "vercel"
SOURCE = "audit_log"
SIGNAL_TYPE = "vercel_activity_signal"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is evidence for review and may require review. ConfigTrace does not "
    "confirm unauthorized access or compromise."
)

# Branch names that count as the production branch (raises deploy-hook severity).
_PRODUCTION_BRANCHES = frozenset({"production", "prod", "main", "master", "release", "live"})

# Substrings / tokens in an env var KEY name that suggest secret material. Only the
# KEY name is ever inspected; the value is never read or stored.
_SENSITIVE_SUBSTRINGS = (
    "secret", "token", "password", "passwd", "webhook", "signing", "credential",
    "private_key", "privatekey", "api_key", "apikey", "access_key", "accesskey",
    "database_url", "db_password", "db_url", "dsn", "auth_token",
)
_SENSITIVE_TOKENS = frozenset({
    "secret", "token", "password", "passwd", "pwd", "key", "keys", "webhook",
    "signing", "credential", "credentials", "private", "dsn", "auth", "cert",
})

# event_type → (pattern, title). Fallback events (vercel.project.event) are
# intentionally NOT promoted (too low-signal).
_EVENT_PATTERNS: dict[str, tuple[str, str]] = {
    "vercel.project.updated": ("project_settings_changed", "Vercel project settings changed"),
    "vercel.domain.added": ("domain_changed", "Vercel domain configuration changed"),
    "vercel.domain.removed": ("domain_changed", "Vercel domain configuration changed"),
    "vercel.env_var.created": ("env_var_changed", "Vercel environment variable metadata changed"),
    "vercel.env_var.updated": ("env_var_changed", "Vercel environment variable metadata changed"),
    "vercel.env_var.deleted": ("env_var_changed", "Vercel environment variable metadata changed"),
    "vercel.deploy_hook.created": ("deploy_hook_changed", "Vercel deploy hook configuration changed"),
    "vercel.deploy_hook.deleted": ("deploy_hook_changed", "Vercel deploy hook configuration changed"),
    "vercel.deployment.created": ("deployment_activity", "Vercel deployment activity observed"),
    "vercel.deployment.promoted": ("deployment_activity", "Vercel deployment activity observed"),
}

# Per-pattern summary core (claim-safe).
_PATTERN_SUMMARY: dict[str, str] = {
    "project_settings_changed": "Vercel project settings changed, observed in Vercel audit activity.",
    "domain_changed": "Vercel domain configuration changed, observed in Vercel audit activity.",
    "env_var_changed": "Vercel environment variable metadata changed, observed in Vercel audit activity. Only the variable key name is recorded — never its value.",
    "deploy_hook_changed": "Vercel deploy hook configuration changed, observed in Vercel audit activity. The deploy hook URL is never recorded.",
    "deployment_activity": "Vercel deployment activity was observed in Vercel audit activity.",
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


def _is_sensitive_key(key: Optional[str]) -> bool:
    if not key:
        return False
    kl = key.lower()
    if any(s in kl for s in _SENSITIVE_SUBSTRINGS):
        return True
    tokens = [t for t in re.split(r"[^a-z0-9]+", kl) if t]
    return any(t in _SENSITIVE_TOKENS for t in tokens)


def _target_ident(ev: SecurityActivityEvent) -> str:
    return (
        _md(ev, "target_id") or _md(ev, "target_name") or _md(ev, "domain")
        or _md(ev, "env_var_key") or _md(ev, "deploy_hook_name")
        or _md(ev, "deployment_id") or ""
    )


def _branch_or_target(ev: SecurityActivityEvent) -> str:
    return _md(ev, "branch") or _md(ev, "deployment_target") or ""


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    pattern_title = _EVENT_PATTERNS.get(ev.event_type)
    if pattern_title is None:
        return None
    pattern = pattern_title[0]
    project = _md(ev, "project_id") or _md(ev, "project_name") or ""
    return "|".join([
        "vercel.activity", pattern, project, ev.event_type,
        _target_ident(ev), _branch_or_target(ev),
    ])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(pattern: str, anchor: SecurityActivityEvent) -> str:
    if pattern == "env_var_changed":
        return "high" if _is_sensitive_key(_md(anchor, "env_var_key")) else "medium"
    if pattern == "deploy_hook_changed":
        branch = (_md(anchor, "branch") or "").lower()
        return "high" if branch in _PRODUCTION_BRANCHES else "medium"
    if pattern == "deployment_activity":
        target = (_md(anchor, "deployment_target") or "").lower()
        return "medium" if target == "production" else "low"
    return "medium"  # project_settings_changed, domain_changed


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    pattern_title = _EVENT_PATTERNS.get(anchor.event_type)
    if pattern_title is None:
        return None
    pattern, title_phrase = pattern_title

    project = _md(anchor, "project_name") or _md(anchor, "project_id")
    label = project or "a Vercel project"
    title = f"{title_phrase} on {label}"

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    summary = f"{_PATTERN_SUMMARY[pattern]} {_REVIEW_NOTE}"

    metadata = signal_svc.sanitize_signal_metadata({
        "source": SOURCE,
        "pattern": pattern,
        "event_type": anchor.event_type,
        "event_action": _md(anchor, "event_action"),
        "event_source": _md(anchor, "event_source"),
        "project_id": _md(anchor, "project_id"),
        "project_name": _md(anchor, "project_name"),
        "team_id": _md(anchor, "team_id"),
        "target_type": _md(anchor, "target_type"),
        "target_id": _md(anchor, "target_id"),
        "target_name": _md(anchor, "target_name"),
        "domain": _md(anchor, "domain"),
        "env_var_key": _md(anchor, "env_var_key"),
        "deploy_hook_name": _md(anchor, "deploy_hook_name"),
        "branch": _md(anchor, "branch"),
        "deployment_id": _md(anchor, "deployment_id"),
        "deployment_target": _md(anchor, "deployment_target"),
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


def generate_vercel_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Vercel activity review signals for a workspace. Never raises."""
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

    # Group by deterministic signal_key (only promotable event types).
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
