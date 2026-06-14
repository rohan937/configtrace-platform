"""Supabase activity/audit ingestion (M71B).

Ingests Supabase organization audit-log activity into the shared
``security_activity_events`` table (``provider="supabase"``,
``source="audit_log"``) — control-plane configuration-change activity (project /
table / RLS / policy / storage bucket / Edge Function / auth-config events).

INGESTION SOURCE (deliberate): Supabase audit logs are an ORGANIZATION-scoped
surface that requires an organization slug and a token with audit-log read
access. A project-scoped personal access token (``access_token`` +
``project_ref``) alone cannot read them. When that access is not available,
ingestion fails soft and reports ``permission_limited`` — it NEVER breaks the
existing Supabase configuration-risk sync, and it never scrapes or infers events.

CLAIM DISCIPLINE: this ingests provider audit activity. It does NOT confirm a
breach, attacker, compromise, unauthorized access, data exposure, or leaked
secret. Events are "evidence for review".

NON-FATAL BY DESIGN: missing permission / unavailable endpoint / throttling /
network failures are captured in the returned summary, never raised.

PRIVACY: only allowlisted, flat, safe fields are stored (project ref/name,
organization id, schema/table/policy NAMES, policy command verb, storage bucket
id/name, Edge Function id/name, auth setting NAME, and the action string). NEVER
database row data, SQL result rows, auth users, emails, JWT secrets, service-role
/anon keys, database passwords, tokens, authorization/raw headers, raw API
responses, request/response bodies, policy expressions, Edge Function env var
values, secrets, credentials, or private member identities (actor email/name).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.supabase import SupabaseConnector
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "supabase"
SOURCE = "audit_log"
EVENT_SOURCE = "supabase_audit_log"


def _safe_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value.strip() else None


def _ts(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    try:
        if isinstance(raw, datetime):
            return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        if isinstance(raw, (int, float)):
            ts = float(raw)
            if ts > 1e12:  # epoch milliseconds → seconds
                ts /= 1000.0
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(raw, str):
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        return None
    return None


def _map_event_type(action: str) -> str:
    """Map a raw Supabase audit action string → a normalized event type."""
    a = action.lower()
    is_create = any(k in a for k in ("create", "add", "insert"))
    is_delete = any(k in a for k in ("delete", "remove", "drop"))

    if "policy" in a:
        if is_create:
            return "supabase.policy.created"
        if is_delete:
            return "supabase.policy.deleted"
        return "supabase.policy.updated"
    if "rls" in a or "row_level_security" in a or "row-level-security" in a:
        return "supabase.rls.updated"
    if "bucket" in a or "storage" in a:
        if is_create:
            return "supabase.storage_bucket.created"
        if is_delete:
            return "supabase.storage_bucket.deleted"
        return "supabase.storage_bucket.updated"
    if "function" in a or "edge" in a:
        if is_create:
            return "supabase.edge_function.created"
        if is_delete:
            return "supabase.edge_function.deleted"
        return "supabase.edge_function.updated"
    if "table" in a:
        return "supabase.table.updated"
    if "auth" in a:
        return "supabase.auth_config.updated"
    if "project" in a:
        return "supabase.project.updated"
    return "supabase.project.event"


def _action_string(entry: dict[str, Any]) -> Optional[str]:
    """Extract the action string from the several shapes Supabase may use."""
    action = entry.get("action")
    if isinstance(action, dict):
        action = action.get("name") or action.get("action") or action.get("type")
    return (
        _safe_str(action)
        or _safe_str(entry.get("name"))
        or _safe_str(entry.get("type"))
        or _safe_str(entry.get("event"))
    )


def _merged_context(entry: dict[str, Any]) -> dict[str, Any]:
    """Merge the safe sub-objects a Supabase audit entry may carry, shallowly.

    Only flat dict sub-objects are merged; the metadata allowlist still drops any
    non-allowlisted (e.g. secret/email/raw) key downstream.
    """
    out: dict[str, Any] = {}
    target = entry.get("target")
    if isinstance(target, dict):
        out.update({k: v for k, v in target.items() if k != "metadata"})
        tmeta = target.get("metadata")
        if isinstance(tmeta, dict):
            out.update(tmeta)
    for key in ("context", "metadata", "payload"):
        sub = entry.get(key)
        if isinstance(sub, dict):
            out.update(sub)
    return out


def normalize_supabase_activity_event(entry: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map one raw Supabase audit-log entry → a normalized activity dict.

    Returns ``None`` for malformed entries or entries with no recognizable action
    (skipped safely). Only safe, flat, allowlisted fields are extracted; actor
    email/name (a private member identity), policy expressions, and secrets are
    never read.
    """
    if not isinstance(entry, dict):
        return None

    action = _action_string(entry)
    if not action:
        return None

    event_type = _map_event_type(action)
    ctx = _merged_context(entry)

    actor = entry.get("actor") if isinstance(entry.get("actor"), dict) else {}
    # Actor TYPE only — NEVER the actor's email/name/id (private member identity).
    actor_type = _safe_str(actor.get("type")) or "user"

    project_ref = _safe_str(ctx.get("project_ref")) or _safe_str(ctx.get("projectRef"))
    project_name = _safe_str(ctx.get("project_name")) or _safe_str(ctx.get("name"))
    organization_id = (
        _safe_str(ctx.get("organization_id"))
        or _safe_str(ctx.get("organization_slug"))
        or _safe_str(ctx.get("org_slug"))
    )
    target_type = _safe_str(ctx.get("target_type")) or _safe_str(ctx.get("type"))
    target_id = _safe_str(ctx.get("target_id")) or _safe_str(ctx.get("id"))
    target_name = _safe_str(ctx.get("target_name")) or _safe_str(ctx.get("description"))
    schema_name = _safe_str(ctx.get("schema_name")) or _safe_str(ctx.get("schema"))
    table_name = _safe_str(ctx.get("table_name")) or _safe_str(ctx.get("table"))
    policy_name = _safe_str(ctx.get("policy_name")) or _safe_str(ctx.get("policy"))
    policy_command = _safe_str(ctx.get("policy_command")) or _safe_str(ctx.get("command"))
    storage_bucket_id = _safe_str(ctx.get("storage_bucket_id")) or _safe_str(ctx.get("bucket_id"))
    storage_bucket_name = _safe_str(ctx.get("storage_bucket_name")) or _safe_str(ctx.get("bucket"))
    edge_function_id = _safe_str(ctx.get("edge_function_id")) or _safe_str(ctx.get("function_id"))
    edge_function_name = _safe_str(ctx.get("edge_function_name")) or _safe_str(ctx.get("function_name"))
    auth_setting_name = _safe_str(ctx.get("auth_setting_name")) or _safe_str(ctx.get("setting_name"))

    occurred_at = _ts(
        entry.get("occurred_at")
        or entry.get("created_at")
        or entry.get("timestamp")
        or ctx.get("occurred_at")
    )

    metadata = {
        "project_ref": project_ref,
        "project_name": project_name,
        "organization_id": organization_id,
        "event_action": action,
        "event_source": EVENT_SOURCE,
        "target_type": target_type,
        "target_id": target_id,
        "target_name": target_name,
        "schema_name": schema_name,
        "table_name": table_name,
        "policy_name": policy_name,
        "policy_command": policy_command,
        "storage_bucket_id": storage_bucket_id,
        "storage_bucket_name": storage_bucket_name,
        "edge_function_id": edge_function_id,
        "edge_function_name": edge_function_name,
        "auth_setting_name": auth_setting_name,
        "event_time": occurred_at.isoformat() if occurred_at else None,
    }

    event_id = _safe_str(entry.get("id")) or _safe_str(entry.get("event_id"))
    resource_type = target_type or "project"
    resource_id = (
        target_id or table_name or storage_bucket_name or edge_function_name or project_ref
    )

    provider_event_id = event_id or activity_svc.compute_event_fingerprint(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        actor_id=None,
        resource_id=resource_id,
        occurred_at=occurred_at,
    )

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        occurred_at=occurred_at,
        provider_event_id=provider_event_id,
        # Actor email/name/id intentionally omitted (privacy). Only the type kept.
        actor_id=None,
        actor_type=actor_type,
        resource_type=resource_type,
        resource_id=resource_id,
        source_ip=None,
        metadata=metadata,
        raw_ref=event_id,
    )


def _empty_summary(integration_id: Optional[uuid.UUID]) -> dict[str, Any]:
    return {
        "attempted": False,
        "succeeded": False,
        "provider": PROVIDER,
        "integration_id": str(integration_id) if integration_id else None,
        "source": SOURCE,
        "events_seen": 0,
        "events_inserted": 0,
        "events_skipped": 0,
        "permission_limited": False,
        "error_message": None,
    }


def ingest_supabase_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Ingest Supabase organization audit activity for one integration. Never raises."""
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not a Supabase integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("supabase_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve Supabase credentials."
        return summary

    connector = SupabaseConnector()
    hard_error: Optional[str] = None

    try:
        events = connector.list_activity_events(
            credentials, max_events=max_events, lookback_hours=lookback_hours
        )
    except AuthenticationError:
        summary["permission_limited"] = True
        events = []
    except ConnectorError as exc:
        events = []
        code = getattr(exc, "status_code", None)
        if code in (401, 403, 404, 422):
            summary["permission_limited"] = True
        elif code == 503:
            hard_error = "Supabase is temporarily unavailable."
        else:
            hard_error = "Supabase audit-log request failed."
    except RateLimitError:
        events = []
        hard_error = "Supabase rate limit reached; try again later."
    except NetworkError:
        events = []
        hard_error = "Network error reaching Supabase."
    except Exception:  # noqa: BLE001
        logger.exception("supabase_activity: unexpected error")
        events = []
        hard_error = "Unexpected error ingesting Supabase audit activity."

    seen = inserted = skipped = 0
    for entry in events:
        seen += 1
        normalized = normalize_supabase_activity_event(entry)
        if normalized is None:
            continue  # malformed / unrecognized action → skip safely
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id, integration_id=integration.id,
                normalized=normalized, db=db,
            )
        except Exception:  # noqa: BLE001 — one bad row never fails the batch
            logger.warning("supabase_activity: failed to upsert one event; continuing")
            continue
        if outcome == "inserted":
            inserted += 1
        else:
            skipped += 1

    summary["events_seen"] = seen
    summary["events_inserted"] = inserted
    summary["events_skipped"] = skipped
    if hard_error is not None:
        summary["error_message"] = hard_error
        summary["succeeded"] = False
    else:
        summary["succeeded"] = True
        if summary["permission_limited"] and seen == 0:
            summary["error_message"] = (
                "Supabase audit-log access is limited for this token/project "
                "(an organization slug with audit-log read access is required)."
            )
    return summary
