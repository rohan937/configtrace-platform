"""Firebase activity Incident Signals (M72C).

Promotes Firebase / Google Cloud Audit Log activity (provider=firebase,
source=audit_log, ingested in M72B) into review-worthy Incident Signals
(signal_type="firebase_activity_signal", evidence_level="activity",
confidence="medium").

Conservative + deterministic + idempotent: events are grouped by
(project, pattern, event_type, target/ruleset/database/bucket/function/app/site),
each group yields one signal anchored on the group's latest event, with a
deterministic signal_key so re-running creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration-change review signals.
They NEVER assert that data was exposed, that a credential was leaked, that
anyone gained access, that access was unauthorized, or that a breach/compromise/
attack occurred. Severity reflects review priority only.

PRIVACY: metadata is allowlisted + flat. NEVER Firestore documents, Realtime
Database data, storage object contents, auth users, emails, private keys,
service-account JSON secrets, tokens, authorization/raw headers, raw API
responses, raw rule source, request/response bodies, or Cloud Function env var
values (none of those are even present on the M72B activity events).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "firebase"
SOURCE = "audit_log"
SIGNAL_TYPE = "firebase_activity_signal"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm data exposure, "
    "unauthorized access, or compromise. This is evidence for review."
)

# Tokens in a Cloud Function name that suggest a sensitive function (raises
# severity). Only the function NAME is inspected — never its source or env vars.
_SENSITIVE_FN_TOKENS = frozenset({
    "auth", "admin", "internal", "private", "secret", "webhook", "payment",
    "payments", "billing", "token", "tokens", "session", "sessions", "delete",
    "user", "users", "account", "accounts",
})

# event_type → (pattern, title). Every M72B event type is promotable.
_EVENT_PATTERNS: dict[str, tuple[str, str]] = {
    "firebase.firestore_rules.updated": ("firestore_rules_changed", "Firebase Firestore rules changed"),
    "firebase.database_rules.updated": ("database_rules_changed", "Firebase Realtime Database rules changed"),
    "firebase.storage_rules.updated": ("storage_rules_changed", "Firebase Storage rules changed"),
    "firebase.auth_config.updated": ("auth_config_changed", "Firebase authentication configuration changed"),
    "firebase.function.created": ("function_changed", "Firebase Cloud Function configuration changed"),
    "firebase.function.updated": ("function_changed", "Firebase Cloud Function configuration changed"),
    "firebase.function.deleted": ("function_changed", "Firebase Cloud Function configuration changed"),
    "firebase.hosting.updated": ("hosting_changed", "Firebase Hosting configuration changed"),
    "firebase.app.updated": ("project_config_changed", "Firebase project or app configuration changed"),
    "firebase.project.updated": ("project_config_changed", "Firebase project or app configuration changed"),
    "firebase.project.event": ("project_config_changed", "Firebase project or app configuration changed"),
}

# Per-pattern summary core (claim-safe).
_PATTERN_SUMMARY: dict[str, str] = {
    "firestore_rules_changed": "Firebase Firestore rules changed, observed in Firebase audit activity. Only the ruleset name is recorded — never the raw rules source.",
    "database_rules_changed": "Firebase Realtime Database rules changed, observed in Firebase audit activity. Only the instance name is recorded — never the raw rules source.",
    "storage_rules_changed": "Firebase Storage rules changed, observed in Firebase audit activity. Only the ruleset name is recorded — never the raw rules source.",
    "auth_config_changed": "Firebase authentication configuration changed, observed in Firebase audit activity.",
    "function_changed": "Firebase Cloud Function configuration changed, observed in Firebase audit activity. Only the function name is recorded — never its source or environment variable values.",
    "hosting_changed": "Firebase Hosting configuration changed, observed in Firebase audit activity.",
    "project_config_changed": "Firebase project or app configuration changed, observed in Firebase audit activity.",
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


def _has_sensitive_token(value: Optional[str], tokens: frozenset[str]) -> bool:
    if not value:
        return False
    parts = [t for t in re.split(r"[^a-z0-9]+", value.lower()) if t]
    return any(t in tokens for t in parts)


def _target_ident(ev: SecurityActivityEvent) -> str:
    return (
        _md(ev, "target_id") or _md(ev, "target_name")
        or _md(ev, "ruleset_name") or _md(ev, "database_instance")
        or _md(ev, "storage_bucket_name") or _md(ev, "function_name")
        or _md(ev, "app_id") or _md(ev, "hosting_site_id")
        or _md(ev, "auth_setting_name") or ""
    )


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    pattern_title = _EVENT_PATTERNS.get(ev.event_type)
    if pattern_title is None:
        return None
    pattern = pattern_title[0]
    project = _md(ev, "project_id") or ""
    return "|".join([
        "firebase.activity", pattern, project, ev.event_type,
        _md(ev, "target_type") or "", _target_ident(ev),
        _md(ev, "function_region") or "",
    ])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(pattern: str, anchor: SecurityActivityEvent) -> str:
    if pattern in ("firestore_rules_changed", "database_rules_changed", "storage_rules_changed"):
        return "high"
    if pattern == "function_changed":
        name = _md(anchor, "function_name") or _md(anchor, "target_name")
        return "high" if _has_sensitive_token(name, _SENSITIVE_FN_TOKENS) else "medium"
    if pattern == "project_config_changed":
        # A bare project.event fallback with no specific resource identifier is the
        # lowest signal (target_type is the generic GCP resource type, so it is
        # not used here — a real app/resource identifier is the meaningful signal).
        has_identifier = bool(_md(anchor, "app_id") or _md(anchor, "target_name"))
        if anchor.event_type == "firebase.project.event" and not has_identifier:
            return "low"
        return "medium"
    return "medium"  # auth_config_changed, hosting_changed


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    pattern_title = _EVENT_PATTERNS.get(anchor.event_type)
    if pattern_title is None:
        return None
    pattern, title_phrase = pattern_title

    project = _md(anchor, "project_id")
    label = project or "a Firebase project"
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
        "project_number": _md(anchor, "project_number"),
        "service_name": _md(anchor, "service_name"),
        "method_name": _md(anchor, "method_name"),
        "target_type": _md(anchor, "target_type"),
        "target_id": _md(anchor, "target_id"),
        "target_name": _md(anchor, "target_name"),
        "ruleset_name": _md(anchor, "ruleset_name"),
        "database_instance": _md(anchor, "database_instance"),
        "storage_bucket_name": _md(anchor, "storage_bucket_name"),
        "function_name": _md(anchor, "function_name"),
        "function_region": _md(anchor, "function_region"),
        "app_id": _md(anchor, "app_id"),
        "app_platform": _md(anchor, "app_platform"),
        "hosting_site_id": _md(anchor, "hosting_site_id"),
        "auth_setting_name": _md(anchor, "auth_setting_name"),
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


def generate_firebase_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Firebase activity review signals for a workspace. Never raises."""
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
