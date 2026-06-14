"""Azure Activity Log ingestion (M77D).

Ingests Azure control-plane management events — surfaced through the Azure
Activity Log management events endpoint — into the shared
``security_activity_events`` table (``provider="azure"``,
``source="azure_activity_log"``).

The connector applies a STRICT operation-name allowlist at the fetch level:
only WRITE/DELETE operations on NSGs, Storage Accounts, Key Vaults, role
assignments, App Services, SQL Servers, and AKS clusters are retrieved.
READ/LIST operations, data-plane access, diagnostic logs, VM logs, application
logs, Key Vault secret access logs, and database query logs are
deliberately NEVER requested or ingested.

CLAIM DISCIPLINE: this ingests provider configuration-change activity. It does
NOT confirm a breach, attack, compromise, unauthorized access, leaked secret,
exposed data, attacker presence, or any security incident. Events are evidence
for review.

NON-FATAL BY DESIGN: missing permission / unavailable endpoint / throttling /
network failures are captured in the returned summary, never raised. The
existing Azure drift sync is never interrupted by activity-log failures.

PRIVACY: only allowlisted, flat, safe fields are stored:
  subscription_id, resource_group, resource_id, resource_type, operation_name,
  operation_family, operation_action, azure_event_id, azure_correlation_id_hash
  (HASHED — never the raw correlationId), status, sub_status, category,
  event_time, and resource-specific name fields (nsg_name, storage_account_name,
  key_vault_name, app_service_name, sql_server_name, aks_cluster_name, etc.).

NEVER stored: caller email/UPN/name/object-ID, raw correlationId, claims,
authorization objects, properties payload, httpRequest body, raw event payload,
storage keys, SAS tokens, connection strings, Key Vault secret names/values,
certificate material, key material, database contents, VM user data, app setting
names/values, env var values, customer/workload data, or any PII.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.connectors.azure import AzureConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "azure"
SOURCE = "azure_activity_log"
EVENT_SOURCE = "azure_activity_log"

# Operation name (lowercased) → normalized event type.
# Every key is also in the connector's _ALLOWED_OPERATION_NAMES set.
# Defense-in-depth: any operation not in this map is silently dropped here
# even if it somehow passed the connector's allowlist.
_OPERATION_EVENT_TYPE_MAP: dict[str, str] = {
    # Network Security Groups
    "microsoft.network/networksecuritygroups/write": "azure.nsg.updated",
    "microsoft.network/networksecuritygroups/delete": "azure.nsg.deleted",
    "microsoft.network/networksecuritygroups/securityrules/write": "azure.nsg_rule.updated",
    "microsoft.network/networksecuritygroups/securityrules/delete": "azure.nsg_rule.deleted",
    # Storage Accounts
    "microsoft.storage/storageaccounts/write": "azure.storage_account.updated",
    "microsoft.storage/storageaccounts/delete": "azure.storage_account.deleted",
    # Key Vaults
    "microsoft.keyvault/vaults/write": "azure.key_vault.updated",
    "microsoft.keyvault/vaults/delete": "azure.key_vault.deleted",
    # Role Assignments (IAM)
    "microsoft.authorization/roleassignments/write": "azure.role_assignment.created",
    "microsoft.authorization/roleassignments/delete": "azure.role_assignment.deleted",
    # App Service / Function Apps
    "microsoft.web/sites/write": "azure.app_service.updated",
    "microsoft.web/sites/delete": "azure.app_service.deleted",
    "microsoft.web/sites/config/write": "azure.app_service_config.updated",
    # SQL Servers
    "microsoft.sql/servers/write": "azure.sql_server.updated",
    "microsoft.sql/servers/delete": "azure.sql_server.deleted",
    "microsoft.sql/servers/firewallrules/write": "azure.sql_firewall_rule.updated",
    "microsoft.sql/servers/firewallrules/delete": "azure.sql_firewall_rule.deleted",
    # AKS Clusters
    "microsoft.containerservice/managedclusters/write": "azure.aks_cluster.updated",
    "microsoft.containerservice/managedclusters/delete": "azure.aks_cluster.deleted",
}

_MAX_STR = 200


def _safe_str(value: Any, default: str = "") -> str:
    if isinstance(value, str):
        return value[:_MAX_STR]
    return default


def _ts(raw: Any) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp string → UTC-aware datetime."""
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


def _hash_correlation_id(correlation_id: str) -> Optional[str]:
    """Return a salted, truncated hash of an Azure correlationId.

    The correlationId is an opaque GUID that groups related Activity Log entries.
    It contains no PII itself but we hash it anyway to avoid storing a value
    that could theoretically be cross-referenced with external Azure logs.

    Returns None if correlation_id is empty or None.
    """
    if not isinstance(correlation_id, str) or not correlation_id.strip():
        return None
    key = getattr(settings, "ENCRYPTION_KEY", "") or ""
    salt = ("ct_az_corr_v1:" + str(key)).encode("utf-8")
    digest = hashlib.sha256(salt + correlation_id.strip().encode("utf-8")).hexdigest()
    return digest[:32]


def _extract_resource_names(
    resource_id: str, operation_name_low: str
) -> dict[str, str]:
    """Extract safe resource-name metadata from an ARM resource ID.

    Parses the resource ID path to extract the resource name and (where
    applicable) a sub-resource name, then maps them to operation-specific
    metadata keys.

    Only resource/sub-resource NAME segments are extracted (no path or query).
    The segments are user-chosen infrastructure identifiers; these are the same
    fields ConfigTrace already stores in its M77A–M77C drift records.

    Returns a dict of safe metadata keys suitable for inclusion in the event
    metadata after allowlist sanitization.
    """
    if not isinstance(resource_id, str) or not resource_id.strip():
        return {}

    parts = [p for p in resource_id.strip("/").split("/") if p]
    # Find the "providers" segment to start parsing the resource type hierarchy.
    try:
        prov_idx = next(i for i, p in enumerate(parts) if p.lower() == "providers")
    except StopIteration:
        return {}

    # After "providers": [namespace, type, name, sub-type, sub-name, ...]
    # e.g. ["Microsoft.Network", "networkSecurityGroups", "my-nsg",
    #        "securityRules", "my-rule"]
    after_prov = parts[prov_idx + 1:]
    if len(after_prov) < 3:
        return {}

    resource_name = _safe_str(after_prov[2])
    sub_resource_name = _safe_str(after_prov[4]) if len(after_prov) >= 5 else ""

    result: dict[str, str] = {}
    op = operation_name_low

    if "networksecuritygroups" in op:
        if resource_name:
            result["nsg_name"] = resource_name
        if "securityrules" in op and sub_resource_name:
            result["nsg_rule_name"] = sub_resource_name
    elif "storageaccounts" in op and resource_name:
        result["storage_account_name"] = resource_name
    elif "/vaults/" in resource_id.lower() or "vaults" in op:
        if resource_name:
            result["key_vault_name"] = resource_name
    elif "roleassignments" in op and resource_name:
        # Role assignments use a UUID as the resource name — safe to include.
        pass  # no specific name field; scope is captured in other fields
    elif "/sites/" in resource_id.lower() or ("web/sites" in op and "config" not in op):
        if resource_name:
            result["app_service_name"] = resource_name
    elif "config" in op and "web/sites" in op and resource_name:
        result["app_service_name"] = resource_name
    elif "sql/servers" in op:
        if resource_name:
            result["sql_server_name"] = resource_name
        if "firewallrules" in op and sub_resource_name:
            result["sql_firewall_rule_name"] = sub_resource_name
    elif "managedclusters" in op and resource_name:
        result["aks_cluster_name"] = resource_name

    return result


def normalize_azure_activity_event(entry: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map one pre-stripped Azure Activity Log event dict → a normalized activity dict.

    Returns ``None`` for malformed entries or for any operation NOT in the event
    type map (defense-in-depth even though the connector already filters).

    Only safe, flat, allowlisted fields are extracted. The raw ``properties``,
    ``claims``, ``authorization``, ``caller``, ``httpRequest``, and
    ``description`` fields are NEVER present in the stripped connector dict
    (the connector excludes them before returning); this normalizer never
    traverses them.
    """
    if not isinstance(entry, dict):
        return None

    operation_name = _safe_str(entry.get("operation_name", ""))
    if not operation_name:
        return None
    op_low = operation_name.lower()
    event_type = _OPERATION_EVENT_TYPE_MAP.get(op_low)
    if not event_type:
        # Defense-in-depth: drop any operation not in the explicit event type map.
        return None

    occurred_at = _ts(entry.get("event_timestamp"))
    azure_event_id = _safe_str(entry.get("event_data_id", ""))
    resource_id = _safe_str(entry.get("resource_id", ""))
    resource_group = _safe_str(entry.get("resource_group_name", ""))
    resource_type = _safe_str(entry.get("resource_type", ""))
    subscription_id = _safe_str(entry.get("subscription_id", ""))
    status = _safe_str(entry.get("status", ""))
    sub_status = _safe_str(entry.get("sub_status", ""))
    category = _safe_str(entry.get("category", ""))

    # Derive operation_family (namespace + resource type) and operation_action (verb).
    op_parts = operation_name.split("/")
    operation_action = op_parts[-1] if op_parts else ""
    operation_family = "/".join(op_parts[:-1]) if len(op_parts) > 1 else operation_name

    # Hash the correlationId — never store raw.
    raw_correlation_id = entry.get("correlation_id", "")
    azure_correlation_id_hash = _hash_correlation_id(raw_correlation_id)

    # Extract resource-specific name metadata from the resource ID path.
    resource_names = _extract_resource_names(resource_id, op_low)

    metadata: dict[str, Any] = {
        "event_source": EVENT_SOURCE,
        "azure_event_id": azure_event_id or None,
        "azure_correlation_id_hash": azure_correlation_id_hash,
        "subscription_id": subscription_id or None,
        "resource_group": resource_group or None,
        "resource_id": resource_id or None,
        "resource_type": resource_type or None,
        "operation_name": operation_name or None,
        "operation_family": operation_family or None,
        "operation_action": operation_action or None,
        "status": status or None,
        "sub_status": sub_status or None,
        "category": category or None,
        "event_time": occurred_at.isoformat() if occurred_at else None,
    }
    metadata.update(resource_names)

    # Stable event ID: use the Azure eventDataId UUID when available.
    provider_event_id: Optional[str] = azure_event_id or None
    if not provider_event_id:
        provider_event_id = activity_svc.compute_event_fingerprint(
            provider=PROVIDER,
            source=SOURCE,
            event_type=event_type,
            actor_id=None,
            resource_id=resource_id or None,
            occurred_at=occurred_at,
        )

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        occurred_at=occurred_at,
        provider_event_id=provider_event_id,
        # Caller identity (UPN/email/object-ID) is intentionally never included.
        actor_id=None,
        actor_type=None,
        resource_type=resource_type or None,
        resource_id=resource_id or None,
        source_ip=None,
        metadata=metadata,
        raw_ref=azure_event_id or None,
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


def ingest_azure_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_events: int = 100,
) -> dict[str, Any]:
    """Ingest Azure Activity Log management events for one integration. Never raises."""
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not an Azure integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("azure_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve Azure credentials."
        return summary

    connector = AzureConnector()
    hard_error: Optional[str] = None

    try:
        events = connector.list_activity_events(
            credentials, max_events=max_events, lookback_hours=lookback_hours
        )
    except AuthenticationError:
        events = []
        summary["permission_limited"] = True
    except ConnectorError as exc:
        events = []
        code = getattr(exc, "status_code", None)
        if code in (401, 403, 404, 422):
            summary["permission_limited"] = True
        else:
            hard_error = "Azure Activity Log request failed."
    except RateLimitError:
        events = []
        hard_error = "Azure rate limit reached; try again later."
    except NetworkError:
        events = []
        hard_error = "Network error reaching Azure."
    except Exception:  # noqa: BLE001
        logger.exception("azure_activity: unexpected error")
        events = []
        hard_error = "Unexpected error ingesting Azure Activity Log."

    seen = inserted = skipped = 0
    for entry in events:
        seen += 1
        normalized = normalize_azure_activity_event(entry)
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
            logger.warning("azure_activity: failed to upsert one event; continuing")
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
                "Azure Activity Log access is limited for these credentials. "
                "Ensure the service principal has the Reader role on the "
                "subscription and that the Activity Log is enabled."
            )
    return summary
