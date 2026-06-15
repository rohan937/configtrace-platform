"""Google Cloud Audit Log ingestion (M78D).

Ingests Google Cloud Admin Activity audit log entries — surfaced through the
Cloud Logging entries:list API filtered to
``cloudaudit.googleapis.com/activity`` — into the shared
``security_activity_events`` table (``provider="google_cloud"``,
``source="google_cloud_audit_log"``).

INGESTION SCOPE (deliberate):
  Only WRITE/DELETE/CREATE/UPDATE operations on IAM, firewall rules, VPC
  networks, Cloud Storage buckets, Cloud SQL instances, Cloud Run services,
  GKE clusters, and Secret Manager secrets are ingested. Read/list operations,
  data-plane access (Cloud SQL query logs, Cloud Storage object reads/writes,
  Secret Manager secret access events), VM logs, Kubernetes workload logs, and
  application logs are explicitly excluded at both the connector and here.

CLAIM DISCIPLINE: events are configuration-change evidence for review. This
service does NOT confirm a breach, attacker, compromise, unauthorized access,
data exposure, or leaked secret.

NON-FATAL BY DESIGN: missing permission / unavailable endpoint / throttling /
network failures are captured in the returned summary, never raised. Existing
Google Cloud drift sync is never interrupted by audit-log failures.

PRIVACY: only allowlisted, flat, safe fields are stored:
  project_id, method_name, service_name, resource_name (no emails), resource_type,
  operation_name, operation_family, operation_action, status_code,
  status_message_safe, category, google_cloud_event_id (insertId — opaque),
  google_cloud_operation_id_hash (hashed, never raw), event_time, and
  resource-specific name fields (network_name, firewall_rule_name, bucket_name,
  sql_instance_name, run_service_name, gke_cluster_name).

NEVER stored: protoPayload raw object, request, response, metadata,
authenticationInfo, authorizationInfo, principalEmail, serviceAccountDelegationInfo,
callerIp, userAgent, resource.labels, raw operation IDs, raw correlation IDs,
IAM principal emails, service account emails, secret names/values, database names,
database users, passwords, connection strings, query data, object names, env var
names/values, container args, kubeconfig, certificates, node names, workload data,
pod specs, logs, customer data, or any PII.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.google_cloud import GoogleCloudConnector
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "google_cloud"
SOURCE = "google_cloud_audit_log"
EVENT_SOURCE = "google_cloud_audit_log"

# Maximum safe length for stored string fields.
_MAX_STR = 200


# ── Method → event type mapping ───────────────────────────────────────────────
#
# Maps each allowlisted methodName (lower-cased for comparison) to a safe,
# ConfigTrace-normalized event type string. Only operations in this map are
# stored. Defense-in-depth: the connector already filtered to the allowlist;
# this map is the second gate.

_METHOD_EVENT_TYPE_MAP: dict[str, str] = {
    # IAM
    "google.iam.admin.v1.iam.setiampolicy": "google_cloud.iam_policy.updated",
    "setiampolicy": "google_cloud.iam_policy.updated",
    "google.iam.admin.v1.iam.createserviceaccount": "google_cloud.service_account.created",
    "google.iam.admin.v1.iam.deleteserviceaccount": "google_cloud.service_account.deleted",
    "google.iam.admin.v1.iam.updateserviceaccount": "google_cloud.service_account.updated",
    "google.iam.admin.v1.iam.createserviceaccountkey": "google_cloud.service_account_key.created",
    "google.iam.admin.v1.iam.deleteserviceaccountkey": "google_cloud.service_account_key.deleted",
    # Firewall rules
    "compute.firewalls.insert": "google_cloud.firewall_rule.created",
    "compute.firewalls.patch": "google_cloud.firewall_rule.updated",
    "compute.firewalls.update": "google_cloud.firewall_rule.updated",
    "compute.firewalls.delete": "google_cloud.firewall_rule.deleted",
    # VPC networks
    "compute.networks.insert": "google_cloud.vpc_network.created",
    "compute.networks.patch": "google_cloud.vpc_network.updated",
    "compute.networks.delete": "google_cloud.vpc_network.deleted",
    # Cloud Storage
    "storage.buckets.create": "google_cloud.storage_bucket.created",
    "storage.buckets.update": "google_cloud.storage_bucket.updated",
    "storage.buckets.delete": "google_cloud.storage_bucket.deleted",
    "storage.setiampermissions": "google_cloud.storage_iam.updated",
    # Cloud SQL
    "cloudsql.instances.create": "google_cloud.sql_instance.created",
    "cloudsql.instances.update": "google_cloud.sql_instance.updated",
    "cloudsql.instances.delete": "google_cloud.sql_instance.deleted",
    # Cloud Run (v2)
    "google.cloud.run.v2.services.createservice": "google_cloud.run_service.created",
    "google.cloud.run.v2.services.updateservice": "google_cloud.run_service.updated",
    "google.cloud.run.v2.services.deleteservice": "google_cloud.run_service.deleted",
    # Cloud Run (v1 equivalents)
    "google.cloud.run.v1.namespaces.services.create": "google_cloud.run_service.created",
    "google.cloud.run.v1.namespaces.services.replaceservice": "google_cloud.run_service.updated",
    "google.cloud.run.v1.namespaces.services.delete": "google_cloud.run_service.deleted",
    # GKE
    "google.container.v1.clustermanager.createcluster": "google_cloud.gke_cluster.created",
    "google.container.v1.clustermanager.updatecluster": "google_cloud.gke_cluster.updated",
    "google.container.v1.clustermanager.deletecluster": "google_cloud.gke_cluster.deleted",
    "google.container.v1.clustermanager.setnetworkpolicy": "google_cloud.gke_network_policy.updated",
    "google.container.v1.clustermanager.setmasterauth": "google_cloud.gke_master_auth.updated",
    # Secret Manager (metadata changes only)
    "google.cloud.secretmanager.v1.secretmanagerservice.createsecret": "google_cloud.secret.created",
    "google.cloud.secretmanager.v1.secretmanagerservice.updatesecret": "google_cloud.secret.updated",
    "google.cloud.secretmanager.v1.secretmanagerservice.deletesecret": "google_cloud.secret.deleted",
}


def _safe_str(value: Any, default: str = "") -> str:
    if isinstance(value, str):
        return value[:_MAX_STR]
    return default


def _ts(raw: Any) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp → UTC-aware datetime."""
    if raw is None:
        return None
    try:
        if isinstance(raw, datetime):
            return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        if isinstance(raw, str):
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        return None
    return None


def _hash_operation_id(op_id: str) -> Optional[str]:
    """Return a salted hash of a GCP operation id (never the raw value)."""
    if not isinstance(op_id, str) or not op_id.strip():
        return None
    key = getattr(settings, "ENCRYPTION_KEY", "") or ""
    salt = ("ct_gcp_op_v1:" + str(key)).encode("utf-8")
    digest = hashlib.sha256(salt + op_id.strip().encode("utf-8")).hexdigest()
    return digest[:32]


def _extract_resource_name_from_path(resource_name: Optional[str], method_name_low: str) -> dict[str, str]:
    """Extract a safe resource identifier from the GCP resourceName path.

    The resourceName follows a hierarchical pattern like:
        projects/my-proj/global/firewalls/my-firewall-rule
        projects/my-proj/regions/us-central1/instances/my-sql-instance
        projects/my-proj/locations/us-central1/services/my-service
        projects/my-proj/locations/-/clusters/my-cluster

    We extract only the FINAL name segment (the resource's own name) and map
    it to a surface-specific metadata key. The full path is NOT stored as-is
    if it might contain sensitive segments (e.g. service account email).

    SECURITY: serviceAccount paths contain the email after /serviceAccounts/.
    We never store the email — only the method-level category.
    """
    if not isinstance(resource_name, str) or not resource_name.strip():
        return {}

    # For service account operations, the path contains the email — never store.
    if "serviceaccounts" in resource_name.lower():
        return {}

    parts = [p for p in resource_name.strip("/").split("/") if p]
    if not parts:
        return {}

    # The last non-empty segment is the resource's own name.
    name = _safe_str(parts[-1])
    if not name:
        return {}

    m = method_name_low
    result: dict[str, str] = {}

    if "firewalls." in m or "firewalls/" in m:
        result["firewall_rule_name"] = name
    elif "networks." in m or "networks/" in m:
        result["network_name"] = name
    elif "storage.buckets" in m or "storage.setiampermissions" in m:
        result["bucket_name"] = name
    elif "cloudsql.instances" in m:
        result["sql_instance_name"] = name
    elif "run" in m and "service" in m:
        result["run_service_name"] = name
    elif "cluster" in m or "networkpolicy" in m or "masterauth" in m:
        result["gke_cluster_name"] = name
    # Secret names could be sensitive (user-chosen) — we don't extract them.

    return result


def normalize_google_cloud_audit_event(
    entry: dict[str, Any],
    project_id: str,
) -> Optional[dict[str, Any]]:
    """Map one pre-stripped Google Cloud audit log entry → a normalized event.

    Returns None for malformed entries or for any methodName NOT in the event
    type map (defense-in-depth even though the connector already filtered).

    The ``entry`` dict is already stripped by the connector's
    ``_strip_audit_entry`` method and contains only safe flat fields:
    insert_id, log_name, timestamp, severity, method_name, service_name,
    resource_name, resource_type, status_code, status_message_safe.

    NEVER touches protoPayload, request, response, metadata,
    authenticationInfo, authorizationInfo, or callerIp/userAgent.
    """
    if not isinstance(entry, dict):
        return None

    method_name = _safe_str(entry.get("method_name") or "")
    if not method_name:
        return None

    method_low = method_name.lower()
    event_type = _METHOD_EVENT_TYPE_MAP.get(method_low)
    if not event_type:
        # Defense-in-depth: drop any method not in the explicit map.
        logger.debug("gcp_activity: dropping unrecognized method %s", method_name[:60])
        return None

    occurred_at = _ts(entry.get("timestamp"))
    insert_id = _safe_str(entry.get("insert_id") or "")
    service_name = _safe_str(entry.get("service_name") or "")
    # Re-check resource_name for email (defense-in-depth even after connector strip).
    _resource_name_raw = _safe_str(entry.get("resource_name") or "")
    resource_name = _resource_name_raw if "@" not in _resource_name_raw else ""
    resource_type = _safe_str(entry.get("resource_type") or "")
    status_code = entry.get("status_code")
    status_message_safe = _safe_str(entry.get("status_message_safe") or "")
    severity = _safe_str(entry.get("severity") or "")

    # Derive operation family (namespace/resource) and action (verb).
    method_parts = method_name.split(".")
    operation_action = method_parts[-1] if method_parts else method_name
    operation_family = ".".join(method_parts[:-1]) if len(method_parts) > 1 else method_name

    # Extract safe resource-specific name metadata.
    resource_names = _extract_resource_name_from_path(resource_name, method_low)

    metadata: dict[str, Any] = {
        "event_source": EVENT_SOURCE,
        "project_id": project_id or None,
        "google_cloud_event_id": insert_id or None,
        "method_name": method_name,
        "service_name": service_name or None,
        "resource_name": resource_name or None,
        "resource_type": resource_type or None,
        "operation_name": method_name,
        "operation_family": operation_family or None,
        "operation_action": operation_action or None,
        "status_code": status_code if isinstance(status_code, int) else None,
        "status_message_safe": status_message_safe or None,
        "category": "Admin Activity",
        "event_time": occurred_at.isoformat() if occurred_at else None,
    }
    if severity:
        metadata["severity"] = severity
    metadata.update(resource_names)

    # Stable event ID: the insertId is a stable, opaque identifier per Cloud
    # Logging entry. Use it directly as provider_event_id when present.
    provider_event_id: Optional[str] = insert_id or None
    if not provider_event_id:
        provider_event_id = activity_svc.compute_event_fingerprint(
            provider=PROVIDER,
            source=SOURCE,
            event_type=event_type,
            actor_id=None,
            resource_id=resource_name or None,
            occurred_at=occurred_at,
        )

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        occurred_at=occurred_at,
        provider_event_id=provider_event_id,
        # Principal identity (principalEmail / serviceAccountDelegationInfo)
        # is intentionally NEVER stored.
        actor_id=None,
        actor_type=None,
        resource_type=resource_type or None,
        resource_id=resource_name or None,
        source_ip=None,
        metadata=metadata,
        raw_ref=insert_id or None,
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


def ingest_google_cloud_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Ingest Google Cloud Admin Activity audit log entries for one integration.

    Never raises. All errors are captured in the returned summary dict. The
    existing Google Cloud drift sync is never interrupted by failures here.

    Args:
        integration:    A ``google_cloud`` Integration model row.
        workspace_id:   Workspace UUID for storage scoping.
        db:             Database session.
        lookback_hours: Lookback window (1–168 hours; capped internally).
        max_events:     Maximum events to ingest (1–1000; capped internally).

    Returns:
        Summary dict with attempted/succeeded/events_seen/events_inserted/
        events_skipped/permission_limited/error_message fields.
    """
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not a Google Cloud integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("gcp_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve Google Cloud credentials."
        return summary

    # Resolve project_id from credentials for normalization.
    connector = GoogleCloudConnector()
    project_id: str = GoogleCloudConnector._project_id(credentials) or ""

    hard_error: Optional[str] = None
    events: list[dict] = []

    try:
        events = connector.list_audit_events(
            credentials,
            max_events=max_events,
            lookback_hours=lookback_hours,
        )
    except AuthenticationError:
        summary["permission_limited"] = True
    except ConnectorError as exc:
        code = getattr(exc, "status_code", None)
        if code in (401, 403, 404, 422):
            summary["permission_limited"] = True
        else:
            hard_error = "Google Cloud Audit Log request failed."
    except RateLimitError:
        hard_error = "Google Cloud rate limit reached; try again later."
    except NetworkError:
        hard_error = "Network error reaching Google Cloud."
    except Exception:  # noqa: BLE001
        logger.exception("gcp_activity: unexpected error")
        hard_error = "Unexpected error ingesting Google Cloud Audit Log."

    seen = inserted = skipped = 0
    for entry in events:
        seen += 1
        normalized = normalize_google_cloud_audit_event(entry, project_id)
        if normalized is None:
            continue
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id,
                integration_id=integration.id,
                normalized=normalized,
                db=db,
            )
        except Exception:  # noqa: BLE001
            logger.warning("gcp_activity: failed to upsert one event; continuing")
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
                "Google Cloud Audit Log access is limited for these credentials. "
                "Ensure the service account has the roles/logging.viewer role or "
                "equivalent permission (logging.logEntries.list) on the project, "
                "and that Admin Activity audit logs are enabled."
            )

    return summary
