"""Firebase activity/audit ingestion (M72B).

Ingests Firebase control-plane change activity — surfaced through Google Cloud
Audit Logs (Cloud Logging) — into the shared ``security_activity_events`` table
(``provider="firebase"``, ``source="audit_log"``): Firestore/Realtime
Database/Storage rules changes, Auth-config changes, Cloud Function deploys,
Hosting deploys, and project/app config changes.

INGESTION SOURCE (deliberate): reading Cloud Audit Logs requires an IAM role with
``logging.privateLogEntries.list`` (e.g. roles/logging.viewer / Private Logs
Viewer) on the project — a permission the read-only config-sync service account
commonly lacks. When that access is not available, ingestion fails soft and
reports ``permission_limited`` — it NEVER breaks the existing Firebase
configuration-risk sync, and it never scrapes or infers events.

CLAIM DISCIPLINE: this ingests provider audit activity. It does NOT confirm a
breach, attacker, compromise, unauthorized access, data exposure, or leaked
secret. Events are "evidence for review".

NON-FATAL BY DESIGN: missing permission / unavailable endpoint / throttling /
network failures are captured in the returned summary, never raised.

PRIVACY: only allowlisted, flat, safe fields are stored (project id/number,
service/method NAMES, ruleset/database/bucket/function/app/site NAMES + ids, and
the action string). NEVER Firestore documents, Realtime Database data, storage
object contents, auth users, emails, private keys, service-account JSON secrets,
tokens, authorization/raw headers, raw API responses, raw rule source,
request/response bodies, Cloud Function env var values, secrets, credentials, or
private member identities (actor email/name).
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
from app.connectors.firebase import FirebaseConnector
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "firebase"
SOURCE = "audit_log"
EVENT_SOURCE = "firebase_audit_log"


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
            if ts > 1e12:
                ts /= 1000.0
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(raw, str):
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        return None
    return None


def _last_segment(value: Optional[str]) -> Optional[str]:
    """Return the trailing path segment of a resource name (a NAME, not data)."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value.rstrip("/").split("/")[-1] or None


def _map_event_type(service: str, method: str, resource: str) -> str:
    """Map a Cloud Audit Log (service, method, resource) → a normalized type."""
    s = (service or "").lower()
    m = (method or "").lower()
    r = (resource or "").lower()
    blob = f"{m} {r}"
    is_create = any(k in m for k in ("create", "insert"))
    is_delete = any(k in m for k in ("delete", "remove"))

    # Service-specific branches first — checked before the generic rules/"release"
    # keyword branch, because Hosting/Functions also use "release"/"create".
    if "firebasehosting" in s:
        return "firebase.hosting.updated"
    if "cloudfunctions" in s:
        if is_create:
            return "firebase.function.created"
        if is_delete:
            return "firebase.function.deleted"
        return "firebase.function.updated"
    if "identitytoolkit" in s:
        return "firebase.auth_config.updated"
    if "firebasedatabase" in s:
        return "firebase.database_rules.updated"
    if "firebasestorage" in s:
        return "firebase.storage_rules.updated"
    if "firebaserules" in s or "ruleset" in blob or "rules" in blob or "release" in blob:
        if "storage" in blob:
            return "firebase.storage_rules.updated"
        if "database" in blob or "rtdb" in blob:
            return "firebase.database_rules.updated"
        if "firestore" in blob:
            return "firebase.firestore_rules.updated"
        return "firebase.firestore_rules.updated"
    if "firebase.googleapis" in s:
        if "app" in blob:
            return "firebase.app.updated"
        return "firebase.project.updated"
    # Generic fallbacks by keyword (no recognized service).
    if "function" in blob:
        if is_create:
            return "firebase.function.created"
        if is_delete:
            return "firebase.function.deleted"
        return "firebase.function.updated"
    if "auth" in blob:
        return "firebase.auth_config.updated"
    if "hosting" in blob:
        return "firebase.hosting.updated"
    return "firebase.project.event"


def normalize_firebase_activity_event(entry: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map one Cloud Audit Log entry → a normalized activity dict.

    Returns ``None`` for malformed entries or entries with no service/method
    (skipped safely). Only safe, flat, allowlisted fields are extracted; the
    actor principalEmail (a private member identity), request/response bodies,
    and raw rule source are never read.
    """
    if not isinstance(entry, dict):
        return None

    proto = entry.get("protoPayload") if isinstance(entry.get("protoPayload"), dict) else {}
    service = _safe_str(proto.get("serviceName")) or _safe_str(entry.get("serviceName"))
    method = _safe_str(proto.get("methodName")) or _safe_str(entry.get("methodName"))
    if not service and not method:
        return None  # not a recognizable audit entry → skip safely

    resource_name = _safe_str(proto.get("resourceName")) or ""
    resource = entry.get("resource") if isinstance(entry.get("resource"), dict) else {}
    labels = resource.get("labels") if isinstance(resource.get("labels"), dict) else {}

    event_type = _map_event_type(service or "", method or "", resource_name)

    project_id = _safe_str(labels.get("project_id")) or _safe_str(entry.get("project_id"))
    project_number = _safe_str(labels.get("project_number"))
    resource_type = _safe_str(resource.get("type"))

    # Surface-specific NAME extraction (never raw rules / data / objects).
    ruleset_name = None
    database_instance = _safe_str(labels.get("database_id")) or _safe_str(labels.get("resource_id"))
    storage_bucket_name = _safe_str(labels.get("bucket_name"))
    function_name = None
    function_region = _safe_str(labels.get("region")) or _safe_str(labels.get("location"))
    app_id = _safe_str(labels.get("app_id"))
    hosting_site_id = _safe_str(labels.get("site_name")) or _safe_str(labels.get("site_id"))

    if "rules" in event_type:
        ruleset_name = _last_segment(resource_name)
    if "function" in event_type:
        function_name = _last_segment(resource_name)
    target_name = _last_segment(resource_name)

    actor = proto.get("authenticationInfo") if isinstance(proto.get("authenticationInfo"), dict) else {}
    # Actor TYPE only — NEVER the principalEmail (private member identity).
    actor_type = "service_account" if _safe_str(actor.get("serviceAccountKeyName")) else "user"

    occurred_at = _ts(
        entry.get("timestamp") or entry.get("receiveTimestamp") or proto.get("timestamp")
    )

    metadata = {
        "project_id": project_id,
        "project_number": project_number,
        "event_action": method or service,
        "event_source": EVENT_SOURCE,
        "service_name": service,
        "method_name": method,
        "target_type": resource_type,
        "target_name": target_name,
        "ruleset_name": ruleset_name,
        "database_instance": database_instance,
        "storage_bucket_name": storage_bucket_name,
        "function_name": function_name,
        "function_region": function_region,
        "app_id": app_id,
        "hosting_site_id": hosting_site_id,
        "event_time": occurred_at.isoformat() if occurred_at else None,
    }

    event_id = _safe_str(entry.get("insertId")) or _safe_str(entry.get("id"))
    resource_id = target_name or app_id or project_id
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
        actor_id=None,           # principalEmail intentionally never stored
        actor_type=actor_type,
        resource_type=resource_type or "project",
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


def ingest_firebase_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Ingest Firebase audit activity for one integration. Never raises."""
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not a Firebase integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("firebase_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve Firebase credentials."
        return summary

    connector = FirebaseConnector()
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
            hard_error = "Firebase is temporarily unavailable."
        else:
            hard_error = "Firebase audit-log request failed."
    except RateLimitError:
        events = []
        hard_error = "Firebase rate limit reached; try again later."
    except NetworkError:
        events = []
        hard_error = "Network error reaching Firebase."
    except Exception:  # noqa: BLE001
        logger.exception("firebase_activity: unexpected error")
        events = []
        hard_error = "Unexpected error ingesting Firebase audit activity."

    seen = inserted = skipped = 0
    for entry in events:
        seen += 1
        normalized = normalize_firebase_activity_event(entry)
        if normalized is None:
            continue  # malformed / unrecognized entry → skip safely
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id, integration_id=integration.id,
                normalized=normalized, db=db,
            )
        except Exception:  # noqa: BLE001 — one bad row never fails the batch
            logger.warning("firebase_activity: failed to upsert one event; continuing")
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
                "Firebase audit-log access is limited for these credentials "
                "(a Cloud Logging viewer role with audit-log read access is required)."
            )
    return summary
