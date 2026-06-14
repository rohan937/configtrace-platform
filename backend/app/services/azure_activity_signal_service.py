"""Azure Activity Log Incident Signals (M77E).

Promotes Azure Activity Log management events (provider=azure,
source=azure_activity_log, ingested in M77D) into review-worthy Incident
Signals covering NSG, Storage Account, Key Vault, role assignment, App
Service, SQL Server, and AKS cluster configuration changes.

Conservative + deterministic + idempotent: events are grouped by
(signal_type, subscription, resource_group, resource_id, event_type); each
group yields one signal anchored on the group's latest event, with a
deterministic signal_key so re-running creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration-change review signals.
They NEVER assert that a breach, compromise, unauthorized access, leaked
secret, exposed data, or attacker presence has been confirmed. Severity
reflects review priority only.

PRIVACY: signal metadata is allowlisted + flat. NEVER caller email/UPN/name,
principal IDs, object IDs, raw correlationId, claims, authorization objects,
properties payload, httpRequest body, raw event payload, storage keys, SAS
tokens, connection strings, Key Vault secret names/values, certificate material,
key material, database contents, VM user data, app setting names/values, env
var values, customer/workload data, user names, or PII (none of those are
present on M77D activity events — they are stripped at the connector level and
never stored).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "azure"
SOURCE = "azure_activity_log"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is evidence for review and may require review. ConfigTrace does not "
    "confirm compromise, unauthorized access, or data exposure."
)

# Built-in Azure role names that constitute "broad privilege."
_BROAD_PRIVILEGE_ROLES: frozenset[str] = frozenset({
    "Owner",
    "Contributor",
    "User Access Administrator",
})

# ── Event type → (signal_type, pattern, title_phrase) ────────────────────────
# Every M77D Azure activity event type is covered. Unknown event types are
# silently dropped (defense-in-depth on top of the connector's allowlist).
_EVENT_PATTERNS: dict[str, tuple[str, str, str]] = {
    # Network Security Groups
    "azure.nsg.updated":                 ("azure_network_exposure_changed", "network_exposure_changed", "Azure NSG configuration changed"),
    "azure.nsg.deleted":                 ("azure_nsg_deleted",              "nsg_deleted",              "Azure NSG deleted"),
    "azure.nsg_rule.updated":            ("azure_network_exposure_changed", "network_exposure_changed", "Azure NSG rule changed"),
    "azure.nsg_rule.deleted":            ("azure_network_exposure_changed", "network_exposure_changed", "Azure NSG rule deleted"),
    # Storage Accounts
    "azure.storage_account.updated":     ("azure_storage_config_changed",   "storage_config_changed",  "Azure Storage account configuration changed"),
    "azure.storage_account.deleted":     ("azure_storage_account_deleted",  "storage_deleted",         "Azure Storage account deleted"),
    # Key Vaults
    "azure.key_vault.updated":           ("azure_key_vault_config_changed", "key_vault_config_changed","Azure Key Vault configuration changed"),
    "azure.key_vault.deleted":           ("azure_key_vault_deleted",        "key_vault_deleted",       "Azure Key Vault deleted"),
    # Role Assignments
    "azure.role_assignment.created":     ("azure_role_assignment_changed",  "role_assignment_changed", "Azure role assignment created"),
    "azure.role_assignment.deleted":     ("azure_role_assignment_changed",  "role_assignment_changed", "Azure role assignment deleted"),
    # App Service / Function Apps
    "azure.app_service.updated":         ("azure_app_service_config_changed","app_service_changed",    "Azure App Service configuration changed"),
    "azure.app_service.deleted":         ("azure_app_service_deleted",      "app_service_deleted",     "Azure App Service deleted"),
    "azure.app_service_config.updated":  ("azure_app_service_config_changed","app_service_changed",    "Azure App Service configuration changed"),
    # SQL Servers
    "azure.sql_server.updated":          ("azure_sql_network_config_changed","sql_config_changed",     "Azure SQL Server configuration changed"),
    "azure.sql_server.deleted":          ("azure_sql_server_deleted",       "sql_deleted",             "Azure SQL Server deleted"),
    "azure.sql_firewall_rule.updated":   ("azure_sql_network_config_changed","sql_config_changed",     "Azure SQL firewall rule changed"),
    "azure.sql_firewall_rule.deleted":   ("azure_sql_network_config_changed","sql_config_changed",     "Azure SQL firewall rule deleted"),
    # AKS Clusters
    "azure.aks_cluster.updated":         ("azure_aks_cluster_config_changed","aks_config_changed",    "Azure AKS cluster configuration changed"),
    "azure.aks_cluster.deleted":         ("azure_aks_cluster_deleted",      "aks_deleted",             "Azure AKS cluster deleted"),
    # Generic fallback for any other allowlisted management event
    "azure.config.event":                ("azure_config_activity",          "config_event",            "Azure configuration event observed"),
}

# ── Per-pattern review-safe description cores ─────────────────────────────────
_PATTERN_SUMMARY: dict[str, str] = {
    "network_exposure_changed": (
        "An Azure Network Security Group or NSG rule changed, observed in Azure "
        "Activity Log evidence. This may affect network exposure for attached "
        "resources and may require review. Only the NSG/rule name and resource "
        "group are recorded — never traffic payloads, packet data, or customer "
        "workload content."
    ),
    "nsg_deleted": (
        "An Azure Network Security Group was deleted, observed in Azure Activity "
        "Log evidence. This may affect network controls for attached resources and "
        "may require review."
    ),
    "storage_config_changed": (
        "An Azure Storage account configuration changed, observed in Azure Activity "
        "Log evidence. This may affect public access, network access, TLS, or "
        "shared-key posture and may require review. Only the account name and "
        "resource group are recorded — never storage keys, SAS tokens, connection "
        "strings, blob contents, or customer data."
    ),
    "storage_deleted": (
        "An Azure Storage account was deleted, observed in Azure Activity Log "
        "evidence. This may affect data availability and may require review."
    ),
    "key_vault_config_changed": (
        "An Azure Key Vault configuration changed, observed in Azure Activity Log "
        "evidence. This may affect access governance, public network access, soft "
        "delete, or purge-protection posture and may require review. Only the vault "
        "name and resource group are recorded — never Key Vault secret names, "
        "secret values, certificate material, or key material."
    ),
    "key_vault_deleted": (
        "An Azure Key Vault was deleted, observed in Azure Activity Log evidence. "
        "This may affect secret, key, and certificate availability and may require "
        "review."
    ),
    "role_assignment_changed": (
        "An Azure role assignment changed, observed in Azure Activity Log evidence. "
        "This may affect access governance and may require review. Only the role "
        "definition name, principal type (User/Group/ServicePrincipal), and scope "
        "type are recorded — never principal IDs, emails, or object IDs."
    ),
    "app_service_changed": (
        "An Azure App Service or function-app configuration changed, observed in "
        "Azure Activity Log evidence. This may affect HTTPS enforcement, TLS "
        "version, FTP access, or public network access posture and may require "
        "review. Only the app name and resource group are recorded — never app "
        "setting names/values, connection strings, or deployment credentials."
    ),
    "app_service_deleted": (
        "An Azure App Service or function app was deleted, observed in Azure "
        "Activity Log evidence. This may require review."
    ),
    "sql_config_changed": (
        "An Azure SQL Server configuration or firewall rule changed, observed in "
        "Azure Activity Log evidence. This may affect network access or TLS posture "
        "and may require review. Only the server name and resource group are "
        "recorded — never admin credentials, database names, or query data."
    ),
    "sql_deleted": (
        "An Azure SQL Server was deleted, observed in Azure Activity Log evidence. "
        "This may require review."
    ),
    "aks_config_changed": (
        "An Azure AKS cluster configuration changed, observed in Azure Activity Log "
        "evidence. This may affect cluster access controls, local accounts, network "
        "policy, or API server access posture and may require review. Only the "
        "cluster name and resource group are recorded — never kubeconfig, "
        "certificates, or node/pod data."
    ),
    "aks_deleted": (
        "An Azure AKS cluster was deleted, observed in Azure Activity Log evidence. "
        "This may require review."
    ),
    "config_event": (
        "An Azure management configuration event was observed in Azure Activity Log "
        "evidence. Only the operation name and resource group are recorded — never "
        "raw event payloads, properties, or customer data. This may require review."
    ),
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> datetime:
    if not isinstance(dt, datetime):
        return datetime.min.replace(tzinfo=timezone.utc)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _when(ev: SecurityActivityEvent) -> datetime:
    return _aware(ev.occurred_at or ev.ingested_at or ev.created_at)


def _md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    """Read a string metadata field from the activity event (never raises)."""
    data = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = data.get(key)
    return v if isinstance(v, str) and v.strip() else None


def _resource_ident(ev: SecurityActivityEvent) -> str:
    """Pick the most specific resource identifier available (NEVER a secret)."""
    return (
        _md(ev, "nsg_name")
        or _md(ev, "storage_account_name")
        or _md(ev, "key_vault_name")
        or _md(ev, "app_service_name")
        or _md(ev, "sql_server_name")
        or _md(ev, "aks_cluster_name")
        or _md(ev, "resource_name")
        or ev.resource_id or ""
    )


def _resource_desc(ev: SecurityActivityEvent) -> str:
    """Safe description for signal title (never PII)."""
    name = _resource_ident(ev)
    rg = _md(ev, "resource_group") or ""
    if name and rg:
        return f"'{name}' in resource group '{rg}'"
    if name:
        return f"'{name}'"
    if rg:
        return f"in resource group '{rg}'"
    return ""


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    """Deterministic group key — one signal per (signal_type, subscription, resource, event_type)."""
    triple = _EVENT_PATTERNS.get(ev.event_type)
    if triple is None:
        return None
    signal_type = triple[0]
    sub = _md(ev, "subscription_id") or ""
    rg = _md(ev, "resource_group") or ""
    rid = ev.resource_id or _resource_ident(ev)
    return "|".join(["azure.activity", signal_type, sub, rg, rid, ev.event_type])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id)."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(pattern: str, anchor: SecurityActivityEvent) -> str:
    """Conservative review-priority severity. Never asserts confirmed impact."""
    # Deletions are always high — they change or remove a protection.
    if pattern in ("nsg_deleted", "storage_deleted", "key_vault_deleted",
                   "app_service_deleted", "sql_deleted", "aks_deleted"):
        return "high"

    # Key Vault config changes are high regardless — posture drift on KV is
    # always worth escalating (soft-delete, purge-protection, access changes).
    if pattern == "key_vault_config_changed":
        return "high"

    # Role assignment: escalate to high for broad built-in roles at wide scope.
    if pattern == "role_assignment_changed":
        role_name = _md(anchor, "role_definition_name") or ""
        if role_name in _BROAD_PRIVILEGE_ROLES:
            return "high"
        return "medium"

    # SQL firewall rule changes warrant high (network boundary control).
    if pattern == "sql_config_changed":
        if anchor.event_type in ("azure.sql_firewall_rule.updated",
                                 "azure.sql_firewall_rule.deleted"):
            return "high"
        return "medium"

    # NSG rule deletions (removing a control): medium (still review-worthy).
    if pattern == "network_exposure_changed":
        if anchor.event_type == "azure.nsg_rule.deleted":
            return "medium"
        return "medium"

    # App Service, AKS, Storage config changes: medium (review-worthy).
    if pattern in ("app_service_changed", "aks_config_changed",
                   "storage_config_changed"):
        return "medium"

    # Generic fallback: low if no specific resource identity, medium otherwise.
    if pattern == "config_event":
        return "medium" if _resource_ident(anchor) else "low"

    return "medium"


def _build_signal(group: list[SecurityActivityEvent]) -> Optional[dict[str, Any]]:
    anchor = _pick_anchor(group)
    triple = _EVENT_PATTERNS.get(anchor.event_type)
    if triple is None:
        return None
    signal_type, pattern, title_phrase = triple

    desc = _resource_desc(anchor)
    title = f"{title_phrase}{' ' + desc if desc else ''}"

    times = [_when(e) for e in group]
    window_start, window_end = min(times), max(times)

    summary = f"{_PATTERN_SUMMARY[pattern]} {_REVIEW_NOTE}"

    gk = _group_key(anchor)

    metadata = signal_svc.sanitize_signal_metadata({
        "source": SOURCE,
        "pattern": pattern,
        "event_type": anchor.event_type,
        "event_source": _md(anchor, "event_source"),
        "event_action": _md(anchor, "event_action"),
        "provider_event_id": str(anchor.provider_event_id) if anchor.provider_event_id else None,
        "subscription_id": _md(anchor, "subscription_id"),
        "resource_group": _md(anchor, "resource_group"),
        "resource_id": (anchor.resource_id or "")[:200] or None,
        "resource_type": _md(anchor, "resource_type") or (anchor.resource_type or None),
        "operation_name": _md(anchor, "operation_name"),
        "operation_family": _md(anchor, "operation_family"),
        "operation_action": _md(anchor, "operation_action"),
        "azure_event_id": _md(anchor, "azure_event_id"),
        "azure_correlation_id_hash": _md(anchor, "azure_correlation_id_hash"),
        "status": _md(anchor, "status"),
        "sub_status": _md(anchor, "sub_status"),
        "category": _md(anchor, "category"),
        # Resource-specific names
        "nsg_name": _md(anchor, "nsg_name"),
        "nsg_rule_name": _md(anchor, "nsg_rule_name"),
        "storage_account_name": _md(anchor, "storage_account_name"),
        "key_vault_name": _md(anchor, "key_vault_name"),
        "app_service_name": _md(anchor, "app_service_name"),
        "sql_server_name": _md(anchor, "sql_server_name"),
        "sql_firewall_rule_name": _md(anchor, "sql_firewall_rule_name"),
        "aks_cluster_name": _md(anchor, "aks_cluster_name"),
        # Role assignment fields (safe — no principal IDs or emails)
        "scope_type": _md(anchor, "scope_type"),
        "role_definition_name": _md(anchor, "role_definition_name"),
        "principal_type": _md(anchor, "principal_type"),
        # Group aggregate
        "event_count": len(group),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
    })

    return {
        "provider": PROVIDER,
        "integration_id": anchor.integration_id,
        "signal_key": gk,
        "signal_type": signal_type,
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


def generate_azure_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 250,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Azure Activity Log review signals for a workspace. Never raises."""
    hours = max(1, min(int(lookback_hours or 24), 168))
    cap = max(1, min(int(max_signals or 250), 1000))
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
        try:
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
        except Exception:  # noqa: BLE001
            import logging
            logging.getLogger(__name__).warning(
                "azure_signals: failed to build or upsert one group; continuing"
            )
            continue

    return {
        "provider": PROVIDER,
        "source": SOURCE,
        "events_scanned": len(events),
        "groups_scanned": len(groups),
        "signals_created": created,
        "signals_skipped": skipped,
    }
