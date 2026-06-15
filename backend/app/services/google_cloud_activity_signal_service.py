"""Google Cloud Activity Log Incident Signals (M78E).

Promotes Google Cloud Admin Activity audit log events (provider=google_cloud,
source=google_cloud_audit_log, ingested in M78D) into review-worthy Incident
Signals covering IAM policy changes, service account changes, firewall rule
changes, VPC network changes, Cloud Storage changes, Cloud SQL changes, Cloud
Run changes, GKE cluster changes, and Secret Manager changes.

Conservative + deterministic + idempotent: events are grouped by
(signal_type, project_id, resource_name, event_type); each group yields one
signal anchored on the group's latest event, with a deterministic signal_key
so re-running creates no duplicates.

CLAIM DISCIPLINE: these are control-plane configuration-change review signals.
They NEVER assert that a breach, compromise, unauthorized access, leaked
secret, exposed data, or attacker presence has been confirmed. Severity
reflects review priority only.

PRIVACY: signal metadata is allowlisted + flat. NEVER principal emails,
service account emails, caller IPs, userAgent, protoPayload, request,
response, authenticationInfo, authorizationInfo, raw payloads, secret
names/values, database names/users/passwords, connection strings, query data,
env var names/values, container args, kubeconfig, certs, node names, workload
data, pod specs, logs, customer data, or PII (none of those are present on
M78D activity events — they are stripped at the connector level and never
stored).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.services import security_incident_signal_service as signal_svc

PROVIDER = "google_cloud"
SOURCE = "google_cloud_audit_log"
EVIDENCE_LEVEL = "activity"
CONFIDENCE = "medium"

_REVIEW_NOTE = (
    "This is evidence for review and may require review. ConfigTrace does not "
    "confirm compromise, unauthorized access, or data exposure."
)

# ── Event type → (signal_type, pattern, title_phrase) ────────────────────────
# Every M78D Google Cloud event type is covered. Unknown event types are
# silently dropped (defense-in-depth on top of the connector allowlist).
_EVENT_PATTERNS: dict[str, tuple[str, str, str]] = {
    # IAM policy
    "google_cloud.iam_policy.updated": (
        "google_cloud_iam_policy_changed",
        "iam_policy_changed",
        "Google Cloud IAM policy changed",
    ),
    # Service accounts
    "google_cloud.service_account.created": (
        "google_cloud_service_account_changed",
        "service_account_changed",
        "Google Cloud service account created",
    ),
    "google_cloud.service_account.updated": (
        "google_cloud_service_account_changed",
        "service_account_changed",
        "Google Cloud service account updated",
    ),
    "google_cloud.service_account.deleted": (
        "google_cloud_service_account_changed",
        "service_account_deleted",
        "Google Cloud service account deleted",
    ),
    # Service account keys
    "google_cloud.service_account_key.created": (
        "google_cloud_service_account_key_changed",
        "service_account_key_created",
        "Google Cloud service account key created",
    ),
    "google_cloud.service_account_key.deleted": (
        "google_cloud_service_account_key_changed",
        "service_account_key_deleted",
        "Google Cloud service account key deleted",
    ),
    # Firewall rules
    "google_cloud.firewall_rule.created": (
        "google_cloud_firewall_config_changed",
        "firewall_rule_created",
        "Google Cloud firewall rule created",
    ),
    "google_cloud.firewall_rule.updated": (
        "google_cloud_firewall_config_changed",
        "firewall_rule_updated",
        "Google Cloud firewall rule updated",
    ),
    "google_cloud.firewall_rule.deleted": (
        "google_cloud_firewall_config_changed",
        "firewall_rule_deleted",
        "Google Cloud firewall rule deleted",
    ),
    # VPC networks
    "google_cloud.vpc_network.created": (
        "google_cloud_vpc_network_changed",
        "vpc_network_changed",
        "Google Cloud VPC network created",
    ),
    "google_cloud.vpc_network.updated": (
        "google_cloud_vpc_network_changed",
        "vpc_network_changed",
        "Google Cloud VPC network updated",
    ),
    "google_cloud.vpc_network.deleted": (
        "google_cloud_vpc_network_changed",
        "vpc_network_deleted",
        "Google Cloud VPC network deleted",
    ),
    # Cloud Storage
    "google_cloud.storage_bucket.created": (
        "google_cloud_storage_bucket_changed",
        "storage_bucket_changed",
        "Google Cloud Storage bucket created",
    ),
    "google_cloud.storage_bucket.updated": (
        "google_cloud_storage_bucket_changed",
        "storage_bucket_changed",
        "Google Cloud Storage bucket configuration changed",
    ),
    "google_cloud.storage_bucket.deleted": (
        "google_cloud_storage_bucket_changed",
        "storage_bucket_deleted",
        "Google Cloud Storage bucket deleted",
    ),
    "google_cloud.storage_iam.updated": (
        "google_cloud_storage_bucket_changed",
        "storage_iam_changed",
        "Google Cloud Storage bucket IAM policy changed",
    ),
    # Cloud SQL
    "google_cloud.sql_instance.created": (
        "google_cloud_sql_instance_changed",
        "sql_instance_changed",
        "Google Cloud SQL instance created",
    ),
    "google_cloud.sql_instance.updated": (
        "google_cloud_sql_instance_changed",
        "sql_instance_changed",
        "Google Cloud SQL instance configuration changed",
    ),
    "google_cloud.sql_instance.deleted": (
        "google_cloud_sql_instance_changed",
        "sql_instance_deleted",
        "Google Cloud SQL instance deleted",
    ),
    # Cloud Run
    "google_cloud.run_service.created": (
        "google_cloud_run_service_changed",
        "run_service_changed",
        "Google Cloud Run service created",
    ),
    "google_cloud.run_service.updated": (
        "google_cloud_run_service_changed",
        "run_service_changed",
        "Google Cloud Run service configuration changed",
    ),
    "google_cloud.run_service.deleted": (
        "google_cloud_run_service_changed",
        "run_service_deleted",
        "Google Cloud Run service deleted",
    ),
    # GKE clusters
    "google_cloud.gke_cluster.created": (
        "google_cloud_gke_cluster_changed",
        "gke_cluster_changed",
        "Google Kubernetes Engine cluster created",
    ),
    "google_cloud.gke_cluster.updated": (
        "google_cloud_gke_cluster_changed",
        "gke_cluster_changed",
        "Google Kubernetes Engine cluster configuration changed",
    ),
    "google_cloud.gke_cluster.deleted": (
        "google_cloud_gke_cluster_changed",
        "gke_cluster_deleted",
        "Google Kubernetes Engine cluster deleted",
    ),
    "google_cloud.gke_network_policy.updated": (
        "google_cloud_gke_cluster_changed",
        "gke_network_policy_changed",
        "Google Kubernetes Engine cluster network policy changed",
    ),
    "google_cloud.gke_master_auth.updated": (
        "google_cloud_gke_cluster_changed",
        "gke_master_auth_changed",
        "Google Kubernetes Engine cluster master auth changed",
    ),
    # Secret Manager (metadata changes only; secret values are never stored)
    "google_cloud.secret.created": (
        "google_cloud_secret_config_changed",
        "secret_config_changed",
        "Google Cloud Secret Manager secret created",
    ),
    "google_cloud.secret.updated": (
        "google_cloud_secret_config_changed",
        "secret_config_changed",
        "Google Cloud Secret Manager secret configuration changed",
    ),
    "google_cloud.secret.deleted": (
        "google_cloud_secret_config_changed",
        "secret_config_deleted",
        "Google Cloud Secret Manager secret deleted",
    ),
    # Generic fallback (allowlisted control-plane events)
    "google_cloud.config.event": (
        "google_cloud_config_activity",
        "config_event",
        "Google Cloud configuration event observed",
    ),
}

# ── Per-pattern review-safe description cores ─────────────────────────────────
_PATTERN_SUMMARY: dict[str, str] = {
    "iam_policy_changed": (
        "A Google Cloud IAM policy changed, observed in Google Cloud Audit Log "
        "evidence. This may affect access governance and requires review. "
        "ConfigTrace does not confirm unauthorized access or data exposure. "
        "Only the project id and operation name are recorded — never principal "
        "identities, emails, or raw IAM bindings."
    ),
    "service_account_changed": (
        "A Google Cloud service account configuration changed, observed in Google "
        "Cloud Audit Log evidence. This may affect credential-management posture "
        "and requires review. Only the project id and operation name are recorded "
        "— never service account emails, key material, or tokens."
    ),
    "service_account_deleted": (
        "A Google Cloud service account was deleted, observed in Google Cloud "
        "Audit Log evidence. This may affect services relying on the deleted "
        "service account and requires review."
    ),
    "service_account_key_created": (
        "A Google Cloud service account key was created, observed in Google Cloud "
        "Audit Log evidence. This may increase credential-management risk and "
        "requires review. ConfigTrace does not confirm the key is in active use "
        "or represents unauthorized access. Only the project id and operation "
        "name are recorded — never key material, key IDs, or service account emails."
    ),
    "service_account_key_deleted": (
        "A Google Cloud service account key was deleted, observed in Google Cloud "
        "Audit Log evidence. This may affect services using the deleted key and "
        "requires review."
    ),
    "firewall_rule_created": (
        "A Google Cloud firewall rule was created, observed in Google Cloud Audit "
        "Log evidence. This may affect network exposure for targeted resources and "
        "requires review. ConfigTrace does not confirm reachability, compromise, "
        "unauthorized access, or data exposure. Only safe rule and network names "
        "are recorded — never traffic payloads or customer workload data."
    ),
    "firewall_rule_updated": (
        "A Google Cloud firewall rule was updated, observed in Google Cloud Audit "
        "Log evidence. This may affect network exposure for targeted resources and "
        "requires review. ConfigTrace does not confirm reachability, compromise, "
        "unauthorized access, or data exposure. Only safe rule and network names "
        "are recorded — never traffic payloads or customer workload data."
    ),
    "firewall_rule_deleted": (
        "A Google Cloud firewall rule was deleted, observed in Google Cloud Audit "
        "Log evidence. This may affect network controls for targeted resources and "
        "requires review."
    ),
    "vpc_network_changed": (
        "A Google Cloud VPC network configuration changed, observed in Google "
        "Cloud Audit Log evidence. This may affect network topology and requires "
        "review."
    ),
    "vpc_network_deleted": (
        "A Google Cloud VPC network was deleted, observed in Google Cloud Audit "
        "Log evidence. This may affect network connectivity for attached resources "
        "and requires review."
    ),
    "storage_bucket_changed": (
        "A Google Cloud Storage bucket configuration changed, observed in Google "
        "Cloud Audit Log evidence. This may affect public access, IAM, or "
        "versioning posture and requires review. Only the bucket name and project "
        "id are recorded — never object contents, object keys, or customer data."
    ),
    "storage_bucket_deleted": (
        "A Google Cloud Storage bucket was deleted, observed in Google Cloud Audit "
        "Log evidence. This may affect data availability and requires review."
    ),
    "storage_iam_changed": (
        "A Google Cloud Storage bucket IAM policy changed, observed in Google "
        "Cloud Audit Log evidence. This may affect access governance for the bucket "
        "and requires review. Only the bucket name and project id are recorded — "
        "never IAM bindings, principal identities, or object contents."
    ),
    "sql_instance_changed": (
        "A Google Cloud SQL instance configuration changed, observed in Google "
        "Cloud Audit Log evidence. This may affect database access or posture and "
        "requires review. Only the instance name and project id are recorded — "
        "never database names, users, passwords, or query data."
    ),
    "sql_instance_deleted": (
        "A Google Cloud SQL instance was deleted, observed in Google Cloud Audit "
        "Log evidence. This may affect database availability and requires review."
    ),
    "run_service_changed": (
        "A Google Cloud Run service configuration changed, observed in Google "
        "Cloud Audit Log evidence. This may affect service access, ingress, or "
        "invoker policy and requires review. Only the service name and project id "
        "are recorded — never env var names/values or container arguments."
    ),
    "run_service_deleted": (
        "A Google Cloud Run service was deleted, observed in Google Cloud Audit "
        "Log evidence. This may affect service availability and requires review."
    ),
    "gke_cluster_changed": (
        "A Google Kubernetes Engine cluster configuration changed, observed in "
        "Google Cloud Audit Log evidence. This may affect cluster access controls, "
        "network policy, or workload identity posture and requires review. Only "
        "the cluster name and location are recorded — never kubeconfig, "
        "certificates, node names, or pod/workload data."
    ),
    "gke_cluster_deleted": (
        "A Google Kubernetes Engine cluster was deleted, observed in Google Cloud "
        "Audit Log evidence. This may affect workload availability and requires "
        "review."
    ),
    "gke_network_policy_changed": (
        "A Google Kubernetes Engine cluster network policy was updated, observed "
        "in Google Cloud Audit Log evidence. This may affect pod-to-pod traffic "
        "controls and requires review."
    ),
    "gke_master_auth_changed": (
        "A Google Kubernetes Engine cluster master authentication configuration "
        "changed, observed in Google Cloud Audit Log evidence. This may affect "
        "cluster control-plane access and requires review."
    ),
    "secret_config_changed": (
        "A Google Cloud Secret Manager secret configuration changed, observed in "
        "Google Cloud Audit Log evidence. This may affect secret governance posture "
        "and requires review. Only the project id and operation name are recorded "
        "— never secret names, secret values, secret version payloads, or any "
        "credential material."
    ),
    "secret_config_deleted": (
        "A Google Cloud Secret Manager secret was deleted, observed in Google "
        "Cloud Audit Log evidence. This may affect services relying on the secret "
        "and requires review. Secret names and values are never stored."
    ),
    "config_event": (
        "A Google Cloud configuration event was observed in Google Cloud Audit "
        "Log evidence. Only the operation name and project id are recorded — never "
        "raw event payloads, request/response objects, or customer data. "
        "This may require review."
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
    """Pick the most specific resource identifier (NEVER a secret or email)."""
    return (
        _md(ev, "firewall_rule_name")
        or _md(ev, "bucket_name")
        or _md(ev, "sql_instance_name")
        or _md(ev, "run_service_name")
        or _md(ev, "gke_cluster_name")
        or _md(ev, "network_name")
        or _md(ev, "resource_name")
        or ev.resource_id or ""
    )


def _resource_desc(ev: SecurityActivityEvent) -> str:
    """Safe description for signal title (never PII or email)."""
    name = _resource_ident(ev)
    project = _md(ev, "project_id") or ""
    if name and project:
        return f"'{name}' in project '{project}'"
    if name:
        return f"'{name}'"
    if project:
        return f"in project '{project}'"
    return ""


def _group_key(ev: SecurityActivityEvent) -> Optional[str]:
    """Deterministic group key — one signal per (signal_type, project, resource, event_type)."""
    triple = _EVENT_PATTERNS.get(ev.event_type)
    if triple is None:
        return None
    signal_type = triple[0]
    project = _md(ev, "project_id") or ""
    rid = ev.resource_id or _resource_ident(ev)
    return "|".join(["google_cloud.activity", signal_type, project, rid, ev.event_type])


def _pick_anchor(group: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Latest event by (occurred_at, provider_event_id)."""
    return max(group, key=lambda e: (_when(e), str(e.provider_event_id or "")))


def _severity(pattern: str, anchor: SecurityActivityEvent) -> str:
    """Conservative review-priority severity. Never asserts confirmed impact."""

    # Deletions are high — they permanently change or remove a resource.
    if pattern in (
        "service_account_deleted",
        "vpc_network_deleted",
        "storage_bucket_deleted",
        "sql_instance_deleted",
        "run_service_deleted",
        "gke_cluster_deleted",
        "secret_config_deleted",
    ):
        return "high"

    # IAM policy changes are always high — access governance is critical.
    if pattern == "iam_policy_changed":
        return "high"

    # Service account key creation is high (new long-lived credential).
    if pattern == "service_account_key_created":
        return "high"

    # GKE master auth and network policy changes are high.
    if pattern in ("gke_master_auth_changed", "gke_network_policy_changed"):
        return "high"

    # Storage IAM changes are high (access governance on storage).
    if pattern == "storage_iam_changed":
        return "high"

    # Firewall rule creation/updates are high (network boundary changes).
    if pattern in ("firewall_rule_created", "firewall_rule_updated"):
        return "high"

    # Firewall rule deletion is high (removing a control).
    if pattern == "firewall_rule_deleted":
        return "high"

    # Secret config changes (create/update) are high.
    if pattern in ("secret_config_changed",):
        return "high"

    # Service account changed (created/updated): medium.
    if pattern == "service_account_changed":
        return "medium"

    # Service account key deleted: medium.
    if pattern == "service_account_key_deleted":
        return "medium"

    # VPC network changes (created/updated): medium.
    if pattern == "vpc_network_changed":
        return "medium"

    # Storage bucket created/updated: medium.
    if pattern == "storage_bucket_changed":
        return "medium"

    # Cloud SQL created/updated: medium.
    if pattern == "sql_instance_changed":
        return "medium"

    # Cloud Run created/updated: medium.
    if pattern == "run_service_changed":
        return "medium"

    # GKE cluster created/updated: medium.
    if pattern == "gke_cluster_changed":
        return "medium"

    # Generic fallback: low if no resource identity, medium otherwise.
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

    pattern_summary = _PATTERN_SUMMARY.get(pattern, "")
    summary = f"{pattern_summary} {_REVIEW_NOTE}".strip()

    gk = _group_key(anchor)

    metadata = signal_svc.sanitize_signal_metadata({
        "source": SOURCE,
        "pattern": pattern,
        "event_type": anchor.event_type,
        "event_source": _md(anchor, "event_source"),
        "provider_event_id": (
            str(anchor.provider_event_id) if anchor.provider_event_id else None
        ),
        "google_cloud_event_id": _md(anchor, "google_cloud_event_id"),
        "project_id": _md(anchor, "project_id"),
        "resource_id": (anchor.resource_id or "")[:200] or None,
        "resource_type": (
            _md(anchor, "resource_type") or (anchor.resource_type or None)
        ),
        "resource_name": _md(anchor, "resource_name"),
        "service_name": _md(anchor, "service_name"),
        "method_name": _md(anchor, "method_name"),
        "operation_name": _md(anchor, "operation_name"),
        "operation_family": _md(anchor, "operation_family"),
        "operation_action": _md(anchor, "operation_action"),
        "status_code": (
            anchor.event_metadata.get("status_code")
            if isinstance(anchor.event_metadata, dict)
            else None
        ),
        "category": _md(anchor, "category"),
        # Resource-specific safe identifiers
        "network_name": _md(anchor, "network_name"),
        "firewall_rule_name": _md(anchor, "firewall_rule_name"),
        "bucket_name": _md(anchor, "bucket_name"),
        "sql_instance_name": _md(anchor, "sql_instance_name"),
        "run_service_name": _md(anchor, "run_service_name"),
        "gke_cluster_name": _md(anchor, "gke_cluster_name"),
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


def generate_google_cloud_activity_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_signals: int = 250,
    scan_limit: int = 10000,
) -> dict[str, Any]:
    """Generate Google Cloud Audit Log review signals for a workspace.

    Reads normalized google_cloud / google_cloud_audit_log activity events
    and promotes selected control-plane change events into Incident Signals.
    Idempotent — re-running creates no duplicates. Never raises.

    Args:
        workspace_id:   Workspace UUID for data scoping.
        db:             Database session.
        lookback_hours: Lookback window (1–168 hours; capped internally).
        max_signals:    Maximum signals to create (1–1000; capped internally).
        scan_limit:     Maximum activity events to scan.

    Returns:
        Summary dict with provider/source/events_scanned/groups_scanned/
        signals_created/signals_skipped fields.
    """
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
                "gcp_signals: failed to build or upsert one group; continuing"
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
