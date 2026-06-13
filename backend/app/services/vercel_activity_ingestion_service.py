"""Vercel activity/audit ingestion (M70B).

Ingests Vercel TEAM audit-log activity into the shared ``security_activity_events``
table (``provider="vercel"``, ``source="audit_log"``) — control-plane change
activity (project / domain / env var / deploy hook / deployment events).

INGESTION SOURCE (deliberate): Vercel audit logs are a team-scoped surface that
requires a team id and a token with audit-log read access (typically
Enterprise). When that access is not available, ingestion fails soft and reports
``permission_limited`` — it NEVER breaks the existing Vercel config-risk sync.

CLAIM DISCIPLINE: this ingests provider audit activity. It does NOT confirm a
breach, attacker, compromise, or unauthorized access. Events are "evidence for
review".

NON-FATAL BY DESIGN: missing permission / unavailable endpoint / throttling /
network failures are captured in the returned summary, never raised.

PRIVACY: only allowlisted, flat, safe fields are stored (project/domain/env-var
KEY name/deploy-hook name/branch/deployment ids + the action string). NEVER env
var VALUES, deploy hook URLs, tokens, headers, raw request/response bodies, raw
API responses, actor emails, secrets, or credentials.
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
from app.connectors.vercel import VercelConnector
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "vercel"
SOURCE = "audit_log"
EVENT_SOURCE = "vercel_audit_log"


def _safe_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value.strip() else None


def _ts(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    try:
        if isinstance(raw, datetime):
            return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        if isinstance(raw, (int, float)):
            # Vercel timestamps are epoch milliseconds; fall back to seconds.
            ts = float(raw)
            if ts > 1e12:
                ts /= 1000.0
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(raw, str):
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        return None
    return None


def _map_event_type(action: str) -> str:
    """Map a raw Vercel audit action string → a normalized event type."""
    a = action.lower()
    is_create = any(k in a for k in ("create", "add"))
    is_delete = any(k in a for k in ("delete", "remove"))

    if "deployhook" in a or "deploy_hook" in a or "deploy-hook" in a:
        if is_delete:
            return "vercel.deploy_hook.deleted"
        return "vercel.deploy_hook.created"
    if "deployment" in a:
        if any(k in a for k in ("promote", "alias", "rollback")):
            return "vercel.deployment.promoted"
        return "vercel.deployment.created"
    if "domain" in a:
        if is_delete:
            return "vercel.domain.removed"
        return "vercel.domain.added"
    if a.startswith("env") or ".env" in a or "environment-variable" in a or "env_var" in a:
        if is_create:
            return "vercel.env_var.created"
        if is_delete:
            return "vercel.env_var.deleted"
        return "vercel.env_var.updated"
    if "project" in a:
        return "vercel.project.updated"
    return "vercel.project.event"


def _merged_context(entry: dict[str, Any]) -> dict[str, Any]:
    """Merge the safe sub-objects a Vercel audit entry may carry, shallowly."""
    out: dict[str, Any] = {}
    for key in ("entry", "payload", "context", "metadata"):
        sub = entry.get(key)
        if isinstance(sub, dict):
            out.update(sub)
    return out


def normalize_vercel_audit_event(entry: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map one raw Vercel audit-log entry → a normalized activity dict.

    Returns ``None`` for malformed entries or entries with no recognizable
    action (skipped safely). Only safe, flat, allowlisted fields are extracted;
    actor email, env var values, and deploy hook URLs are never read.
    """
    if not isinstance(entry, dict):
        return None

    action = (
        _safe_str(entry.get("action"))
        or _safe_str(entry.get("type"))
        or _safe_str(entry.get("event"))
    )
    if not action:
        return None

    event_type = _map_event_type(action)
    ctx = _merged_context(entry)

    actor = entry.get("actor") if isinstance(entry.get("actor"), dict) else {}
    # Actor type only — NEVER store the actor's email/name for this milestone.
    actor_type = _safe_str(actor.get("type")) or "user"

    project_id = _safe_str(ctx.get("projectId")) or _safe_str(entry.get("projectId"))
    project_name = _safe_str(ctx.get("projectName")) or _safe_str(ctx.get("project"))
    team_id = _safe_str(ctx.get("teamId")) or _safe_str(entry.get("teamId"))
    target_type = _safe_str(ctx.get("targetType")) or _safe_str(ctx.get("entityType"))
    target_id = _safe_str(ctx.get("targetId")) or _safe_str(ctx.get("entityId"))
    target_name = _safe_str(ctx.get("targetName")) or _safe_str(ctx.get("name"))
    domain = _safe_str(ctx.get("domain")) or _safe_str(ctx.get("domainName"))
    env_var_key = _safe_str(ctx.get("envKey")) or _safe_str(ctx.get("key"))
    deploy_hook_name = _safe_str(ctx.get("deployHookName")) or _safe_str(ctx.get("hookName"))
    branch = _safe_str(ctx.get("branch")) or _safe_str(ctx.get("ref"))
    deployment_id = _safe_str(ctx.get("deploymentId")) or _safe_str(ctx.get("deployId"))
    deployment_target = _safe_str(ctx.get("target")) or _safe_str(ctx.get("deploymentTarget"))

    occurred_at = _ts(
        entry.get("createdAt")
        or entry.get("occurredAt")
        or entry.get("timestamp")
        or entry.get("when")
    )

    metadata = {
        "project_id": project_id,
        "project_name": project_name,
        "team_id": team_id,
        "event_action": action,
        "event_source": EVENT_SOURCE,
        "target_type": target_type,
        "target_id": target_id,
        "target_name": target_name,
        "domain": domain,
        "env_var_key": env_var_key,
        "deploy_hook_name": deploy_hook_name,
        "branch": branch,
        "deployment_id": deployment_id,
        "deployment_target": deployment_target,
        "event_time": occurred_at.isoformat() if occurred_at else None,
    }

    event_id = _safe_str(entry.get("id")) or _safe_str(entry.get("eventId"))
    resource_type = target_type or "project"
    resource_id = target_id or deployment_id or project_id

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
        # Actor email/name intentionally omitted (privacy). Only the type is kept.
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


def ingest_vercel_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Ingest Vercel audit activity for one integration. Never raises."""
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not a Vercel integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("vercel_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve Vercel credentials."
        return summary

    connector = VercelConnector()
    hard_error: Optional[str] = None

    try:
        events = connector.list_audit_events(
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
            hard_error = "Vercel is temporarily unavailable."
        else:
            hard_error = "Vercel audit-log request failed."
    except RateLimitError:
        events = []
        hard_error = "Vercel rate limit reached; try again later."
    except NetworkError:
        events = []
        hard_error = "Network error reaching Vercel."
    except Exception:  # noqa: BLE001
        logger.exception("vercel_activity: unexpected error")
        events = []
        hard_error = "Unexpected error ingesting Vercel audit activity."

    seen = inserted = skipped = 0
    for entry in events:
        seen += 1
        normalized = normalize_vercel_audit_event(entry)
        if normalized is None:
            continue  # malformed / unrecognized action → skip safely
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id, integration_id=integration.id,
                normalized=normalized, db=db,
            )
        except Exception:  # noqa: BLE001 — one bad row never fails the batch
            logger.warning("vercel_activity: failed to upsert one event; continuing")
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
                "Vercel audit-log access is limited for this token/team "
                "(a team id and audit-log read access are required)."
            )
    return summary
