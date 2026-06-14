"""Supabase activity Incident Signals (M71C).

Promotes Supabase organization audit-log activity (provider=supabase,
source=audit_log, ingested in M71B) into review-worthy Incident Signals
(signal_type="supabase_activity_signal", evidence_level="activity",
confidence="medium").

Conservative + deterministic + idempotent: events are grouped by
(project, pattern, event_type, target/schema/table/policy/bucket/function/auth),
each group yields one signal anchored on the group's latest event, with a
deterministic signal_key so re-running creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration-change review signals.
They NEVER assert that data was exposed, that a credential was leaked, that
anyone gained access, that access was unauthorized, or that a breach/compromise/
attack occurred. Severity reflects review priority only.

PRIVACY: metadata is allowlisted + flat. NEVER database row data, SQL result
rows, auth users, emails, JWT secrets, service-role/anon keys, db passwords,
tokens, authorization headers, raw API responses, policy expressions / SQL
conditions, or Edge Function env var values (none of those are even present on
the M71B activity events).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "supabase"
SOURCE = "audit_log"
SIGNAL_TYPE = "supabase_activity_signal"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm data exposure, "
    "unauthorized access, or compromise. This is evidence for review."
)

# Tokens in a table name that suggest sensitive data (raises severity). Only the
# table NAME is inspected — never row data or contents.
_SENSITIVE_TABLE_TOKENS = frozenset({
    "user", "users", "customer", "customers", "payment", "payments", "order",
    "orders", "account", "accounts", "profile", "profiles", "session",
    "sessions", "token", "tokens", "apikey", "secret", "secrets", "credential",
    "credentials", "billing", "invoice", "invoices", "subscription",
    "subscriptions", "auth", "admin",
})

# Tokens in a storage bucket name that suggest private/sensitive contents.
_SENSITIVE_BUCKET_TOKENS = frozenset({
    "private", "user", "users", "upload", "uploads", "document", "documents",
    "invoice", "invoices", "contract", "contracts", "backup", "backups",
    "secret", "secrets", "secure", "confidential", "payment", "payments",
})

# Tokens in an Edge Function name that suggest a sensitive function.
_SENSITIVE_FN_TOKENS = frozenset({
    "auth", "admin", "internal", "private", "secret", "webhook", "payment",
    "payments", "billing", "delete", "user", "users", "account", "accounts",
})

# Write-ish policy commands that raise policy-change severity.
_WRITE_COMMANDS = frozenset({"insert", "update", "delete", "all"})

# event_type → (pattern, title). Every M71B event type is promotable.
_EVENT_PATTERNS: dict[str, tuple[str, str]] = {
    "supabase.rls.updated": ("table_access_posture_changed", "Supabase table access posture changed"),
    "supabase.table.updated": ("table_access_posture_changed", "Supabase table access posture changed"),
    "supabase.policy.created": ("policy_changed", "Supabase access policy changed"),
    "supabase.policy.updated": ("policy_changed", "Supabase access policy changed"),
    "supabase.policy.deleted": ("policy_changed", "Supabase access policy changed"),
    "supabase.storage_bucket.created": ("storage_bucket_changed", "Supabase storage bucket configuration changed"),
    "supabase.storage_bucket.updated": ("storage_bucket_changed", "Supabase storage bucket configuration changed"),
    "supabase.storage_bucket.deleted": ("storage_bucket_changed", "Supabase storage bucket configuration changed"),
    "supabase.edge_function.created": ("edge_function_changed", "Supabase Edge Function configuration changed"),
    "supabase.edge_function.updated": ("edge_function_changed", "Supabase Edge Function configuration changed"),
    "supabase.edge_function.deleted": ("edge_function_changed", "Supabase Edge Function configuration changed"),
    "supabase.auth_config.updated": ("auth_config_changed", "Supabase authentication configuration changed"),
    "supabase.project.updated": ("project_config_changed", "Supabase project configuration changed"),
    "supabase.project.event": ("project_config_changed", "Supabase project configuration changed"),
}

# Per-pattern summary core (claim-safe).
_PATTERN_SUMMARY: dict[str, str] = {
    "table_access_posture_changed": "Supabase table access posture changed, observed in Supabase audit activity.",
    "policy_changed": "A Supabase access policy was changed, observed in Supabase audit activity. Only the policy name and command are recorded — never the policy expression or SQL condition.",
    "storage_bucket_changed": "Supabase storage bucket configuration changed, observed in Supabase audit activity.",
    "edge_function_changed": "Supabase Edge Function configuration changed, observed in Supabase audit activity. Only the function name is recorded — never its source or environment variable values.",
    "auth_config_changed": "Supabase authentication configuration changed, observed in Supabase audit activity.",
    "project_config_changed": "Supabase project configuration changed, observed in Supabase audit activity.",
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
        or _md(ev, "table_name") or _md(ev, "policy_name")
        or _md(ev, "storage_bucket_id") or _md(ev, "storage_bucket_name")
        or _md(ev, "edge_function_id") or _md(ev, "edge_function_name")
        or _md(ev, "auth_setting_name") or ""
    )


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    pattern_title = _EVENT_PATTERNS.get(ev.event_type)
    if pattern_title is None:
        return None
    pattern = pattern_title[0]
    project = _md(ev, "project_ref") or _md(ev, "project_name") or ""
    schema = _md(ev, "schema_name") or ""
    return "|".join([
        "supabase.activity", pattern, project, ev.event_type,
        _md(ev, "target_type") or "", _target_ident(ev), schema,
        _md(ev, "policy_command") or "",
    ])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(pattern: str, anchor: SecurityActivityEvent) -> str:
    if pattern == "table_access_posture_changed":
        schema = (_md(anchor, "schema_name") or "").lower()
        table = _md(anchor, "table_name")
        if schema == "public" and _has_sensitive_token(table, _SENSITIVE_TABLE_TOKENS):
            return "high"
        return "medium"
    if pattern == "policy_changed":
        cmd = (_md(anchor, "policy_command") or "").lower()
        table = _md(anchor, "table_name")
        if cmd in _WRITE_COMMANDS or _has_sensitive_token(table, _SENSITIVE_TABLE_TOKENS):
            return "high"
        return "medium"
    if pattern == "storage_bucket_changed":
        name = _md(anchor, "storage_bucket_name") or _md(anchor, "storage_bucket_id")
        return "high" if _has_sensitive_token(name, _SENSITIVE_BUCKET_TOKENS) else "medium"
    if pattern == "edge_function_changed":
        name = _md(anchor, "edge_function_name") or _md(anchor, "edge_function_id")
        return "high" if _has_sensitive_token(name, _SENSITIVE_FN_TOKENS) else "medium"
    if pattern == "project_config_changed":
        # A project.event fallback with no specific target is the lowest signal.
        if anchor.event_type == "supabase.project.event" and not _md(anchor, "target_type"):
            return "low"
        return "medium"
    return "medium"  # auth_config_changed


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    pattern_title = _EVENT_PATTERNS.get(anchor.event_type)
    if pattern_title is None:
        return None
    pattern, title_phrase = pattern_title

    project = _md(anchor, "project_name") or _md(anchor, "project_ref")
    label = project or "a Supabase project"
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
        "project_ref": _md(anchor, "project_ref"),
        "project_name": _md(anchor, "project_name"),
        "organization_id": _md(anchor, "organization_id"),
        "target_type": _md(anchor, "target_type"),
        "target_id": _md(anchor, "target_id"),
        "target_name": _md(anchor, "target_name"),
        "schema_name": _md(anchor, "schema_name"),
        "table_name": _md(anchor, "table_name"),
        "policy_name": _md(anchor, "policy_name"),
        "policy_command": _md(anchor, "policy_command"),
        "storage_bucket_id": _md(anchor, "storage_bucket_id"),
        "storage_bucket_name": _md(anchor, "storage_bucket_name"),
        "edge_function_id": _md(anchor, "edge_function_id"),
        "edge_function_name": _md(anchor, "edge_function_name"),
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


def generate_supabase_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 100,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Supabase activity review signals for a workspace. Never raises."""
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
