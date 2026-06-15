"""M78H — Google Cloud provider-depth QA guardrails.

Durable, deterministic guardrails that prove the whole Google Cloud arc
(M78A–M78G) stays internally consistent. This file adds NO product code —
it pins taxonomy parity, privacy / sanitization discipline, false-positive
behavior, demo isolation, and router admin / member guards.

Sections:

  A. Taxonomy parity
     Record types ↔ rule keys ↔ ingestion method names ↔ event types ↔
     signal event types ↔ signal types ↔ correlation finding rules ↔
     correlation activity types.

  B. Privacy guardrails
     Google-Cloud-shaped denylist applied to every Google Cloud source
     file we own (connector, ingestion, signal, correlation, demo); also
     asserted on a live in-memory pipeline (_build_signal →
     build_google_cloud_correlation → seed/clear case-report blobs).

  C. Claim discipline
     Forbidden-phrase scan over every Google Cloud production module and
     the demo fixtures.

  D. False-positive behavior
     End-to-end "should NOT fire" cases pinning resource-name vs aggregate
     matching: provider-only, project-only-for-resource-bearing,
     mis-matched names, mis-matched project_id, generic config event,
     stale window, unknown record type, unknown event type.

  E. Demo isolation
     Seed-twice / clear-twice idempotency; clear_google_cloud leaves every
     other provider demo intact and never touches a real Google Cloud
     integration.

  F. Router/API guards
     Google Cloud activity sync / signal-generate / correlation-generate /
     incident demo seed-clear require admin; read-only endpoints stay
     member-accessible.

  G. Frontend Google Cloud consistency (skip if frontend tree absent)
     Provider selectors / type filter dropdowns / rule catalog / demo card
     / api unions / demo-script copy all carry "google_cloud".

  H. Regression smoke
     Mappers + allowlists + correlation rule shape pin so the future M78I
     polish cannot drift them silently.
"""

from __future__ import annotations

import inspect
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.connectors import google_cloud as gcp_conn
from app.connectors.google_cloud_schema import (
    GOOGLE_CLOUD_FIREWALL_RULE,
    GOOGLE_CLOUD_GKE_CLUSTER,
    GOOGLE_CLOUD_IAM_POLICY_SUMMARY,
    GOOGLE_CLOUD_PROJECT,
    GOOGLE_CLOUD_RECORD_TYPES,
    GOOGLE_CLOUD_RUN_SERVICE,
    GOOGLE_CLOUD_SECRET_MANAGER_SUMMARY,
    GOOGLE_CLOUD_SERVICE_ACCOUNT_KEY_SUMMARY,
    GOOGLE_CLOUD_SQL_INSTANCE,
    GOOGLE_CLOUD_STORAGE_BUCKET,
    GOOGLE_CLOUD_VPC_NETWORK,
)
from app.services import google_cloud_activity_ingestion_service as gcp_ingest
from app.services import google_cloud_activity_signal_service as gcp_sig
from app.services import security_case_report_service as report_svc
from app.services import security_incident_demo_service as demo_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services.provider_capability_matrix_service import (
    get_provider_capability,
)
from app.services.provider_expansion_framework import get_framework
from app.services.security_activity_event_service import (
    ALLOWED_METADATA_KEYS as ACTIVITY_ALLOWED,
)
from app.services.security_coverage_service import (
    PROVIDER_SURFACES, PROVIDERS as COVERAGE_PROVIDERS, RULE_RECORD_TYPES,
)
from app.services.security_incident_signal_service import (
    ALLOWED_METADATA_KEYS as SIGNAL_ALLOWED,
)
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules.google_cloud import (
    GOOGLE_CLOUD_RULE_KEYS, evaluate as gcp_eval,
)


# ════════════════════════════════════════════════════════════════════════════
# Fixed expected sets — the M78H baseline.
# Drift here triggers an intentional update of this file (with a note in the
# commit message explaining the change).
# ════════════════════════════════════════════════════════════════════════════

EXPECTED_RECORD_TYPES = {
    "google_cloud_project", "google_cloud_iam_policy_summary",
    "google_cloud_vpc_network", "google_cloud_firewall_rule",
    "google_cloud_storage_bucket", "google_cloud_sql_instance",
    "google_cloud_run_service", "google_cloud_gke_cluster",
    "google_cloud_service_account_key_summary",
    "google_cloud_secret_manager_summary",
}

EXPECTED_RULE_KEYS = {
    # IAM (M78B + M78C)
    "google_cloud_iam_public_member", "google_cloud_iam_broad_privileged_role",
    # Firewall (M78B)
    "google_cloud_firewall_public_admin_ingress",
    "google_cloud_firewall_public_broad_ingress",
    "google_cloud_firewall_rule_no_targets",
    # Cloud Storage (M78B)
    "google_cloud_storage_public_access_prevention_disabled",
    "google_cloud_storage_uniform_access_disabled",
    "google_cloud_storage_versioning_disabled",
    "google_cloud_storage_retention_not_locked",
    # Cloud SQL (M78C)
    "google_cloud_sql_public_network_access", "google_cloud_sql_weak_tls",
    "google_cloud_sql_backups_disabled",
    "google_cloud_sql_deletion_protection_disabled",
    # Cloud Run (M78C)
    "google_cloud_run_public_invoker", "google_cloud_run_all_ingress",
    # GKE (M78C)
    "google_cloud_gke_public_control_plane",
    "google_cloud_gke_legacy_abac_enabled",
    "google_cloud_gke_network_policy_disabled",
    "google_cloud_gke_workload_identity_disabled",
    # Service account keys (M78C)
    "google_cloud_service_account_user_managed_keys",
    "google_cloud_service_account_old_keys",
    # Secret Manager (M78C)
    "google_cloud_secret_manager_auto_replication_without_cmek",
}

EXPECTED_INGESTION_EVENT_TYPES = {
    "google_cloud.iam_policy.updated",
    "google_cloud.service_account.created",
    "google_cloud.service_account.updated",
    "google_cloud.service_account.deleted",
    "google_cloud.service_account_key.created",
    "google_cloud.service_account_key.deleted",
    "google_cloud.firewall_rule.created",
    "google_cloud.firewall_rule.updated",
    "google_cloud.firewall_rule.deleted",
    "google_cloud.vpc_network.created",
    "google_cloud.vpc_network.updated",
    "google_cloud.vpc_network.deleted",
    "google_cloud.storage_bucket.created",
    "google_cloud.storage_bucket.updated",
    "google_cloud.storage_bucket.deleted",
    "google_cloud.storage_iam.updated",
    "google_cloud.sql_instance.created",
    "google_cloud.sql_instance.updated",
    "google_cloud.sql_instance.deleted",
    "google_cloud.run_service.created",
    "google_cloud.run_service.updated",
    "google_cloud.run_service.deleted",
    "google_cloud.gke_cluster.created",
    "google_cloud.gke_cluster.updated",
    "google_cloud.gke_cluster.deleted",
    "google_cloud.gke_network_policy.updated",
    "google_cloud.gke_master_auth.updated",
    "google_cloud.secret.created",
    "google_cloud.secret.updated",
    "google_cloud.secret.deleted",
}

EXPECTED_SIGNAL_TYPES = {
    "google_cloud_iam_policy_changed",
    "google_cloud_service_account_changed",
    "google_cloud_service_account_key_changed",
    "google_cloud_firewall_config_changed",
    "google_cloud_vpc_network_changed",
    "google_cloud_storage_bucket_changed",
    "google_cloud_sql_instance_changed",
    "google_cloud_run_service_changed",
    "google_cloud_gke_cluster_changed",
    "google_cloud_secret_config_changed",
    "google_cloud_config_activity",
}

EXPECTED_CORRELATION_TYPES = {
    "google_cloud_iam_risk_activity_correlation",
    "google_cloud_firewall_risk_activity_correlation",
    "google_cloud_storage_risk_activity_correlation",
    "google_cloud_sql_risk_activity_correlation",
    "google_cloud_run_risk_activity_correlation",
    "google_cloud_gke_risk_activity_correlation",
    "google_cloud_service_account_key_risk_activity_correlation",
    "google_cloud_secret_manager_risk_activity_correlation",
}

# ── Forbidden claim wording (M75A pin) ───────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# ── Google-Cloud-shaped privacy denylist (M78H) ─────────────────────────────
# Substrings that MUST NOT appear (case-insensitive) as quoted JSON keys in
# any Google Cloud production blob we generate (signal/correlation metadata,
# case report previews, demo evidence). Written as the JSON-style
# `"key":` substring so we catch dict serialisation but not narrative text.
GOOGLE_CLOUD_FORBIDDEN_METADATA_KEYS = (
    # Credentials / tokens
    "private_key", "private_key_id", "client_secret",
    "access_token", "refresh_token", "id_token", "bearer",
    "authorization", "signed_jwt",
    # Raw Cloud Logging / protoPayload pieces
    "protopayload", "request", "response", "requestbody", "responsebody",
    "authenticationinfo", "authorizationinfo", "requestmetadata",
    "serviceaccountdelegationinfo",
    # Principal / caller PII
    "principal_email", "principalemail", "service_account_email",
    "user_email", "user_name", "group_name",
    "principal_id", "object_id", "caller", "caller_email", "caller_upn",
    "upn", "callerip", "caller_ip", "client_ip", "raw_ip", "ip_address",
    "user_agent", "useragent",
    # Database / connection / query data
    "database_name", "database_user", "password", "connection_string",
    "query",
    # Cloud Run / GKE workload data
    "env_var_name", "env_var_value", "container_args", "kubeconfig",
    "certificate", "certificate_data", "node_name", "pod", "workload",
    # Secret Manager payloads
    "secret_name", "secret_value", "secret_payload",
    # Storage object / customer data
    "object_key", "customer_data",
    # Full IAM bindings (we never store the membership list)
    "bindings", "members",
)

# Shape-only substrings that may appear in narrative copy but never as a
# quoted JSON value.
GOOGLE_CLOUD_FORBIDDEN_VALUE_PATTERNS = (
    "begin private key",           # PEM header
    "begin rsa private",
    "begin certificate",
    "ya29.",                       # OAuth access token prefix
    ".iam.gserviceaccount.com",    # SA email suffix
)


# ════════════════════════════════════════════════════════════════════════════
# Section A — Taxonomy parity
# ════════════════════════════════════════════════════════════════════════════


def test_record_types_match_expected():
    assert set(GOOGLE_CLOUD_RECORD_TYPES) == EXPECTED_RECORD_TYPES


def test_record_type_constants_are_canonical_lowercase():
    """Each schema constant uses the canonical lowercase value."""
    pairs = (
        ("GOOGLE_CLOUD_PROJECT", GOOGLE_CLOUD_PROJECT),
        ("GOOGLE_CLOUD_IAM_POLICY_SUMMARY", GOOGLE_CLOUD_IAM_POLICY_SUMMARY),
        ("GOOGLE_CLOUD_VPC_NETWORK", GOOGLE_CLOUD_VPC_NETWORK),
        ("GOOGLE_CLOUD_FIREWALL_RULE", GOOGLE_CLOUD_FIREWALL_RULE),
        ("GOOGLE_CLOUD_STORAGE_BUCKET", GOOGLE_CLOUD_STORAGE_BUCKET),
        ("GOOGLE_CLOUD_SQL_INSTANCE", GOOGLE_CLOUD_SQL_INSTANCE),
        ("GOOGLE_CLOUD_RUN_SERVICE", GOOGLE_CLOUD_RUN_SERVICE),
        ("GOOGLE_CLOUD_GKE_CLUSTER", GOOGLE_CLOUD_GKE_CLUSTER),
        ("GOOGLE_CLOUD_SERVICE_ACCOUNT_KEY_SUMMARY",
         GOOGLE_CLOUD_SERVICE_ACCOUNT_KEY_SUMMARY),
        ("GOOGLE_CLOUD_SECRET_MANAGER_SUMMARY",
         GOOGLE_CLOUD_SECRET_MANAGER_SUMMARY),
    )
    for name, val in pairs:
        assert val == name.lower(), (
            f"{name} value ({val!r}) must be its lowercased name "
            f"({name.lower()!r}); evaluator dispatch keys on this."
        )


def test_rule_keys_match_expected():
    assert set(GOOGLE_CLOUD_RULE_KEYS) == EXPECTED_RULE_KEYS


def test_rule_registry_parity_for_google_cloud_keys():
    in_registry = {k for k in KNOWN_RULE_KEYS if k.startswith("google_cloud_")}
    assert in_registry == EXPECTED_RULE_KEYS

    in_confidence = {k for k in RULE_CONFIDENCE if k.startswith("google_cloud_")}
    assert in_confidence == EXPECTED_RULE_KEYS

    in_pack = {k for k, v in _RULE_META.items() if v[0] == "google_cloud"}
    assert in_pack == EXPECTED_RULE_KEYS

    in_coverage = {
        k for k in RULE_RECORD_TYPES if k.startswith("google_cloud_")
    }
    assert in_coverage == EXPECTED_RULE_KEYS


def test_google_cloud_in_coverage_providers_and_surfaces():
    assert "google_cloud" in COVERAGE_PROVIDERS
    surfaces = PROVIDER_SURFACES["google_cloud"]
    for s in surfaces:
        assert isinstance(s, str) and s.strip()


def test_ingestion_method_event_type_map_covers_every_allowed_method():
    """Every connector allowlisted methodName (lowercased) has an ingest mapping."""
    allowed_low = {m.lower() for m in gcp_conn._AUDIT_ALLOWED_METHOD_PREFIXES}
    mapped = set(gcp_ingest._METHOD_EVENT_TYPE_MAP)
    missing = allowed_low - mapped
    assert missing == set(), (
        f"connector allowlist methods with no event-type mapping: "
        f"{sorted(missing)}"
    )


def test_ingestion_map_does_not_reference_disallowed_methods():
    """Every ingestion-map key (lowercased) is a connector-allowlisted method."""
    allowed_low = {m.lower() for m in gcp_conn._AUDIT_ALLOWED_METHOD_PREFIXES}
    extra = set(gcp_ingest._METHOD_EVENT_TYPE_MAP) - allowed_low
    assert extra == set(), (
        f"ingestion map references non-allowlisted methods: {sorted(extra)}"
    )


def test_ingestion_event_types_match_expected():
    types = set(gcp_ingest._METHOD_EVENT_TYPE_MAP.values())
    assert types == EXPECTED_INGESTION_EVENT_TYPES


def test_signal_event_patterns_cover_every_ingested_type():
    sig_event_types = set(gcp_sig._EVENT_PATTERNS)
    # The signal service tolerates one synthetic generic fallback type.
    extra_in_signal = sig_event_types - EXPECTED_INGESTION_EVENT_TYPES
    assert extra_in_signal == {"google_cloud.config.event"}, (
        f"signal-service event types diverge from ingestion: "
        f"extras={sorted(extra_in_signal)}"
    )
    missing_in_signal = EXPECTED_INGESTION_EVENT_TYPES - sig_event_types
    assert missing_in_signal == set(), (
        f"ingestion emits event types not handled by signal service: "
        f"{sorted(missing_in_signal)}"
    )


def test_signal_types_match_expected():
    types = {v[0] for v in gcp_sig._EVENT_PATTERNS.values()}
    assert types == EXPECTED_SIGNAL_TYPES


def test_correlation_rules_match_registered_rule_keys():
    assert set(corr_svc.GOOGLE_CLOUD_CORRELATION_RULES) == EXPECTED_RULE_KEYS


def test_correlation_types_match_expected():
    types = {
        v["correlation_type"]
        for v in corr_svc.GOOGLE_CLOUD_CORRELATION_RULES.values()
    }
    assert types == EXPECTED_CORRELATION_TYPES


def test_correlation_activity_types_are_subset_of_ingested():
    """Correlations may only match against activity event types ingestion emits."""
    referenced: set[str] = set()
    for rule in corr_svc.GOOGLE_CLOUD_CORRELATION_RULES.values():
        referenced.update(rule["activity_types"])
    not_ingested = referenced - EXPECTED_INGESTION_EVENT_TYPES
    assert not_ingested == set(), (
        f"correlation references event types ingestion does not emit: "
        f"{sorted(not_ingested)}"
    )


def test_capability_matrix_pins_google_cloud_partial_demo_ready():
    cap = get_provider_capability("google_cloud")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True
    assert cap.drift.drift_review_workflow is True
    assert cap.maturity == "partial"
    notes = (cap.notes or "")
    # M78H rewrote the notes to call out provider-depth QA hardening.
    assert "M78H" in notes
    assert "Audit Log" in notes


def test_expansion_framework_points_to_m78i():
    """M79B is now complete — planned_next_stage rolls to M79C (Twilio Messaging/Webhook Risk Expansion)."""
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert "M79C" in planned, planned
    assert "Twilio" in planned
    assert "M78H" not in planned, "M78H is done; pointer must advance past it"
    assert "M78I" not in planned, "M78I is done; pointer must advance past it"


def test_google_cloud_not_in_canonical_eight_provider_matrix():
    """Google Cloud stays in PROVIDER_CAPABILITIES_PARTIAL — never canonical 8."""
    from app.services.provider_capability_matrix_service import (
        PROVIDER_CAPABILITIES, PROVIDER_CAPABILITIES_PARTIAL,
    )
    canonical = {p.provider for p in PROVIDER_CAPABILITIES}
    partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
    assert "google_cloud" not in canonical
    assert "google_cloud" in partial


def test_google_cloud_label_in_timeline_provider_labels():
    """build_case_evidence_timeline must render 'Google Cloud' as the dominant label."""
    assert report_svc._TIMELINE_PROVIDER_LABELS.get(
        "google_cloud"
    ) == "Google Cloud"


# ════════════════════════════════════════════════════════════════════════════
# Section B — Privacy guardrails (allowlist + denylist)
# ════════════════════════════════════════════════════════════════════════════


# M78D activity-event metadata keys (full set the ingester writes).
_GCP_ACTIVITY_SAFE_KEYS = {
    "project_id", "method_name", "service_name", "resource_name",
    "resource_type", "operation_name", "operation_family", "operation_action",
    "status_code", "status_message_safe", "category",
    "google_cloud_event_id", "google_cloud_operation_id_hash", "event_time",
    "network_name", "firewall_rule_name", "bucket_name",
    "sql_instance_name", "run_service_name", "gke_cluster_name",
}

# M78E signal-metadata subset.
_GCP_SIGNAL_SAFE_KEYS = {
    "project_id", "google_cloud_event_id", "resource_name", "resource_type",
    "service_name", "method_name", "network_name", "firewall_rule_name",
    "bucket_name", "sql_instance_name", "run_service_name", "gke_cluster_name",
    "status_code",
}

# M78F correlation-metadata subset.
_GCP_CORRELATION_SAFE_KEYS = _GCP_SIGNAL_SAFE_KEYS | {
    "finding_family",
}


def test_activity_allowlist_contains_all_google_cloud_safe_keys():
    """Every key the M78D ingester writes must be in the activity allowlist."""
    missing = _GCP_ACTIVITY_SAFE_KEYS - ACTIVITY_ALLOWED
    assert missing == set(), (
        f"M78D safe keys missing from activity allowlist: {missing}"
    )


def test_signal_allowlist_contains_all_google_cloud_safe_keys():
    """Every Google-Cloud-safe key the M78E signal builder emits must be allowlisted."""
    missing = _GCP_SIGNAL_SAFE_KEYS - SIGNAL_ALLOWED
    assert missing == set(), (
        f"M78E safe keys missing from signal allowlist: {missing}"
    )


def test_correlation_allowlist_contains_all_google_cloud_safe_keys():
    missing = _GCP_CORRELATION_SAFE_KEYS - corr_svc.ALLOWED_METADATA_KEYS
    assert missing == set(), (
        f"M78F safe keys missing from correlation allowlist: {missing}"
    )


def test_correlation_allowlist_includes_match_metadata():
    """M77F/M78F add matched_on / match_confidence / time_window_hours."""
    for key in ("matched_on", "match_confidence", "time_window_hours"):
        assert key in corr_svc.ALLOWED_METADATA_KEYS, (
            f"correlation allowlist missing {key!r}"
        )


# ── Denylist guardrails on the in-memory pipeline ──────────────────────────


def _denylist_assert(blob: str, *, where: str) -> None:
    lower = blob.lower()
    for bad in GOOGLE_CLOUD_FORBIDDEN_METADATA_KEYS:
        assert f'"{bad}":' not in lower, (
            f"{where}: forbidden quoted key {bad!r} present"
        )
    for bad in GOOGLE_CLOUD_FORBIDDEN_VALUE_PATTERNS:
        assert bad not in lower, (
            f"{where}: forbidden substring {bad!r} present"
        )


def _build_polluted_signal() -> dict:
    """Build a signal from an event polluted with PII/payload keys.

    sanitize_signal_metadata() must drop every forbidden key before persisting.
    """
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = "google_cloud.firewall_rule.updated"
    ev.provider = "google_cloud"
    ev.source = "google_cloud_audit_log"
    ev.resource_id = (
        "projects/p/global/firewalls/fw-admin"
    )
    ev.resource_type = "compute.googleapis.com/Firewall"
    ev.provider_event_id = "demo-gcp-evt-1"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = datetime.now(timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.event_metadata = {
        # Safe keys (must survive):
        "project_id": "p",
        "google_cloud_event_id": "demo-gcp-evt-1",
        "method_name": "v1.compute.firewalls.patch",
        "service_name": "compute.googleapis.com",
        "firewall_rule_name": "fw-admin",
        "network_name": "vpc-prod",
        # Forbidden pollution that MUST be dropped:
        "principal_email": "owner@example.com",
        "service_account_email": "sa@p.iam.gserviceaccount.com",
        "caller_ip": "1.2.3.4", "callerip": "1.2.3.4",
        "user_agent": "demo-agent",
        "useragent": "demo-agent",
        "authenticationinfo": {"principalEmail": "x"},
        "authorizationinfo": [{"granted": True}],
        "protopayload": {"x": 1}, "request": {"x": 1}, "response": {"x": 1},
        "requestmetadata": {"callerIp": "x"},
        "private_key": "-----BEGIN PRIVATE KEY-----",
        "private_key_id": "k1", "client_secret": "shhh",
        "access_token": "ya29.SECRET", "refresh_token": "rt",
        "id_token": "id.tok", "bearer": "Bearer x",
        "secret_name": "db-pw", "secret_value": "topsecret",
        "secret_payload": "raw",
        "database_name": "billing", "database_user": "root",
        "password": "p@ss", "connection_string": "host=x;user=u",
        "query": "SELECT *",
        "env_var_value": "API_KEY=...", "env_var_name": "API_KEY",
        "kubeconfig": "k", "certificate_data": "MIIB", "node_name": "n",
        "pod": "p", "workload": "w",
        "principal_id": "pid", "object_id": "oid", "upn": "u@u",
        "customer_data": "cust",
        "bindings": [{"role": "roles/owner", "members": ["x"]}],
        "members": ["allUsers"],
    }
    sig = gcp_sig._build_signal([ev])
    assert sig is not None
    return sig


def test_signal_metadata_drops_every_polluted_key():
    sig = _build_polluted_signal()
    meta = sig["metadata"]
    # Safe metadata survives.
    assert meta.get("project_id") == "p"
    assert meta.get("firewall_rule_name") == "fw-admin"
    assert meta.get("service_name") == "compute.googleapis.com"
    # Forbidden keys dropped.
    for bad in (
        "principal_email", "service_account_email", "caller_ip", "callerip",
        "user_agent", "useragent", "authenticationinfo", "authorizationinfo",
        "protopayload", "request", "response", "requestmetadata",
        "private_key", "private_key_id", "client_secret", "access_token",
        "refresh_token", "id_token", "bearer",
        "secret_name", "secret_value", "secret_payload",
        "database_name", "database_user", "password", "connection_string",
        "query", "env_var_value", "env_var_name", "kubeconfig",
        "certificate_data", "node_name", "pod", "workload",
        "principal_id", "object_id", "upn", "customer_data",
        "bindings", "members",
    ):
        assert bad not in meta, (
            f"forbidden key {bad!r} survived in signal metadata"
        )
    # PII values never appear in any serialisable surface of the signal.
    blob = json.dumps({
        "metadata": meta, "title": sig["title"], "summary": sig["summary"],
    })
    for value in (
        "owner@example.com",
        "sa@p.iam.gserviceaccount.com",
        "ya29.SECRET",
        "BEGIN PRIVATE KEY",
        "API_KEY=...",
        "topsecret",
    ):
        assert value not in blob, f"PII value {value!r} in signal blob"


def _make_finding_mock(rule_key: str, **evidence) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.finding_key = f"{rule_key}:resource-x"
    f.severity = "high"
    f.title = "Demo finding"
    f.evidence = evidence
    f.first_detected_at = datetime.now(timezone.utc) - timedelta(hours=1)
    f.last_seen_at = datetime.now(timezone.utc)
    f.linked_change_id = None
    f.integration_id = uuid.uuid4()
    return f


def _make_event_mock(event_type: str, metadata: dict) -> MagicMock:
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = event_type
    ev.source = "google_cloud_audit_log"
    ev.provider = "google_cloud"
    ev.actor_id = None
    ev.event_metadata = metadata
    ev.occurred_at = datetime.now(timezone.utc)
    return ev


def test_correlation_metadata_drops_every_polluted_key():
    f = _make_finding_mock(
        "google_cloud_firewall_public_admin_ingress",
        firewall_rule_name="fw-admin", network_name="vpc-prod",
        project_id="p",
        # Pollution on the finding side:
        principal_email="owner@example.com",
        service_account_email="sa@p.iam.gserviceaccount.com",
        caller_ip="9.9.9.9",
    )
    ev = _make_event_mock(
        "google_cloud.firewall_rule.updated",
        {
            "project_id": "p",
            "firewall_rule_name": "fw-admin",
            "network_name": "vpc-prod",
            "method_name": "v1.compute.firewalls.patch",
            "service_name": "compute.googleapis.com",
            "google_cloud_event_id": "evt-1",
            # Pollution on the event side:
            "principal_email": "owner@example.com",
            "principalemail": "owner@example.com",
            "service_account_email": "sa@p.iam.gserviceaccount.com",
            "callerip": "9.9.9.9", "caller_ip": "9.9.9.9",
            "user_agent": "ua",
            "authenticationinfo": "x", "authorizationinfo": "y",
            "protopayload": "raw", "request": "rq", "response": "rs",
            "private_key": "-----BEGIN PRIVATE KEY-----",
            "private_key_id": "k1",
            "access_token": "ya29.X", "refresh_token": "r",
            "id_token": "t", "bearer": "Bearer Z",
            "client_secret": "x",
            "secret_value": "v", "secret_name": "s",
            "kubeconfig": "k", "certificate_data": "c", "node_name": "n",
            "database_name": "db", "password": "p",
            "connection_string": "x", "query": "q",
            "env_var_value": "v", "env_var_name": "n",
            "customer_data": "c",
            "bindings": [{"role": "roles/owner"}],
            "members": ["allUsers"],
            "principal_id": "P", "object_id": "O", "upn": "u@u",
        },
    )
    rule = corr_svc.GOOGLE_CLOUD_CORRELATION_RULES[
        "google_cloud_firewall_public_admin_ingress"
    ]
    c = corr_svc.build_google_cloud_correlation(
        finding=f, event=ev, rule=rule,
        matched_on="firewall_rule_name+project_id",
        resource_label='firewall rule "fw-admin"',
    )
    blob = json.dumps({
        "metadata": c["metadata"], "title": c["title"], "summary": c["summary"],
    })
    _denylist_assert(blob, where="correlation built from polluted finding+event")


def test_google_cloud_demo_case_artifacts_pass_denylist(test_user, db_session):
    """The Google Cloud demo seed/report/timeline/graph stay denylist-clean."""
    from app.services import workspace_service
    ws = workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M78H demo", db=db_session,
    )
    try:
        seed = demo_svc.seed_google_cloud(
            workspace_id=ws.id, actor_user_id=test_user.id, db=db_session,
        )
        case_id = uuid.UUID(seed["case_id"])
        from app.models.security_case import SecurityCase
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        timeline = report_svc.build_case_evidence_timeline(
            case_id=case_id, workspace_id=ws.id, db=db_session,
        )
        graph = report_svc.build_case_evidence_graph(
            case_id=case_id, workspace_id=ws.id, db=db_session,
        )
        blob = (
            json.dumps(report, default=str)
            + json.dumps(timeline, default=str)
            + json.dumps(graph, default=str)
        )
        _denylist_assert(blob, where="google_cloud demo report/timeline/graph")
    finally:
        demo_svc.clear_google_cloud(workspace_id=ws.id, db=db_session)


# ════════════════════════════════════════════════════════════════════════════
# Section C — Claim discipline (forbidden phrases on Google Cloud modules)
# ════════════════════════════════════════════════════════════════════════════


_GCP_MODULES = [
    gcp_conn, gcp_ingest, gcp_sig, demo_svc,
]


def _strip_known_negation_contexts(src: str) -> str:
    """Remove lines that explicitly NEGATE a forbidden claim."""
    out = []
    for line in src.splitlines():
        low = line.lower()
        if any(
            tok in low
            for tok in (
                "does not confirm", "never assert", "never claim",
                "do not claim", "is not a claim", "without claiming",
                "claim discipline", "claim-discipline",
                "review-safe wording", "review safe wording",
                "without overclaim", "review-safe", "doesn't confirm",
                "forbidden", "not confirm",
            )
        ):
            continue
        out.append(line)
    return "\n".join(out)


@pytest.mark.parametrize("module", _GCP_MODULES)
def test_google_cloud_modules_have_no_forbidden_claims(module):
    src = inspect.getsource(module)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in {module.__name__} "
            f"outside a negation context"
        )


def test_google_cloud_security_rules_module_has_no_forbidden_claims():
    """The security_rules.google_cloud module ships claim-discipline copy."""
    from app.services.security_rules import google_cloud as gcp_rules
    src = inspect.getsource(gcp_rules)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in security_rules.google_cloud"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section D — False-positive behavior pins
# ════════════════════════════════════════════════════════════════════════════


def _fw_record(**extra) -> dict:
    base = {
        "record_type": GOOGLE_CLOUD_FIREWALL_RULE,
        "record_id": "projects/p/global/firewalls/fw-x",
        "firewall_rule_name": "fw-x",
        "network_name": "vpc-x",
        "project_id": "p",
        "direction": "INGRESS",
        "disabled": False,
        "allowed": [],
        "source_ranges": [],
        "target_tags": [],
        "target_service_accounts": [],
    }
    base.update(extra)
    return base


def test_private_source_never_triggers_public_firewall_finding():
    """Private CIDRs aren't 'public' — admin/broad rules stay silent."""
    rec = _fw_record(
        source_ranges=["10.0.0.0/8"],
        allowed=[{"IPProtocol": "tcp", "ports": ["22"]}],
        target_tags=["web"],
    )
    findings = gcp_eval(rec)
    assert all(
        f.rule_key not in (
            "google_cloud_firewall_public_admin_ingress",
            "google_cloud_firewall_public_broad_ingress",
        ) for f in findings
    )


@pytest.mark.parametrize("port", ["80", "443"])
def test_public_web_port_never_triggers_admin_or_broad_firewall(port: str):
    """Public 80/443 isn't an admin/database/cache port — never fires admin/broad."""
    rec = _fw_record(
        source_ranges=["0.0.0.0/0"],
        allowed=[{"IPProtocol": "tcp", "ports": [port]}],
        target_tags=["web"],
    )
    findings = gcp_eval(rec)
    keys = {f.rule_key for f in findings}
    assert "google_cloud_firewall_public_admin_ingress" not in keys
    assert "google_cloud_firewall_public_broad_ingress" not in keys


def test_disabled_firewall_rule_never_fires():
    """A disabled rule cannot be exploited and must not generate findings."""
    rec = _fw_record(
        disabled=True,
        source_ranges=["0.0.0.0/0"],
        allowed=[{"IPProtocol": "tcp", "ports": ["22"]}],
        target_tags=["web"],
    )
    findings = gcp_eval(rec)
    assert findings == []


def test_resource_name_mismatch_does_not_correlate():
    """Same project, different firewall name → no correlation match."""
    rule = corr_svc.GOOGLE_CLOUD_CORRELATION_RULES[
        "google_cloud_firewall_public_admin_ingress"
    ]
    f = _make_finding_mock(
        "google_cloud_firewall_public_admin_ingress",
        firewall_rule_name="fw-a", project_id="p",
    )
    ev = _make_event_mock(
        "google_cloud.firewall_rule.updated",
        {"firewall_rule_name": "fw-b", "project_id": "p"},
    )
    assert corr_svc._gcp_match_resource(f, ev, rule) is None


def test_project_id_mismatch_does_not_correlate_for_resource_rule():
    """Same firewall name, different project_id → no match."""
    rule = corr_svc.GOOGLE_CLOUD_CORRELATION_RULES[
        "google_cloud_firewall_public_admin_ingress"
    ]
    f = _make_finding_mock(
        "google_cloud_firewall_public_admin_ingress",
        firewall_rule_name="fw-a", project_id="p1",
    )
    ev = _make_event_mock(
        "google_cloud.firewall_rule.updated",
        {"firewall_rule_name": "fw-a", "project_id": "p2"},
    )
    assert corr_svc._gcp_match_resource(f, ev, rule) is None


def test_project_id_mismatch_does_not_correlate_for_aggregate_rule():
    """Different project_id → no IAM/SA-key/Secret-Manager aggregate match."""
    rule = corr_svc.GOOGLE_CLOUD_CORRELATION_RULES[
        "google_cloud_iam_public_member"
    ]
    f = _make_finding_mock(
        "google_cloud_iam_public_member", project_id="p1",
    )
    ev = _make_event_mock(
        "google_cloud.iam_policy.updated", {"project_id": "p2"},
    )
    assert corr_svc._gcp_match_aggregate(f, ev, rule) is None


def test_missing_project_id_aborts_aggregate_match():
    """No project_id on either side → no aggregate match (defense-in-depth)."""
    rule = corr_svc.GOOGLE_CLOUD_CORRELATION_RULES[
        "google_cloud_iam_public_member"
    ]
    f = _make_finding_mock("google_cloud_iam_public_member")
    ev = _make_event_mock("google_cloud.iam_policy.updated", {})
    assert corr_svc._gcp_match_aggregate(f, ev, rule) is None


def test_generic_config_event_alone_does_not_become_a_correlation():
    """`google_cloud.config.event` is not in any correlation rule activity_types."""
    for rule in corr_svc.GOOGLE_CLOUD_CORRELATION_RULES.values():
        assert "google_cloud.config.event" not in rule["activity_types"]


def test_unknown_record_type_returns_no_findings():
    """The Google Cloud evaluator dispatch is closed — unknown types yield []."""
    assert gcp_eval({"record_type": "google_cloud_unknown_thing"}) == []
    assert gcp_eval({"record_type": ""}) == []
    assert gcp_eval({}) == []


def test_unknown_signal_event_type_returns_no_signal():
    """The signal dispatcher silently drops unmapped event types."""
    ev = _make_event_mock("google_cloud.totally.unknown", {"project_id": "p"})
    assert gcp_sig._build_signal([ev]) is None


# ════════════════════════════════════════════════════════════════════════════
# Section E — Demo isolation
# ════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def _ws(test_user, db_session):
    from app.services import workspace_service
    return workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M78H ws", db=db_session,
    )


def test_seed_google_cloud_demo_is_idempotent(test_user, db_session, _ws):
    try:
        r1 = demo_svc.seed_google_cloud(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        r2 = demo_svc.seed_google_cloud(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
    finally:
        demo_svc.clear_google_cloud(workspace_id=_ws.id, db=db_session)


def test_clear_google_cloud_demo_is_idempotent(test_user, db_session, _ws):
    demo_svc.seed_google_cloud(
        workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
    )
    demo_svc.clear_google_cloud(workspace_id=_ws.id, db=db_session)
    # Second clear is a no-op.
    out = demo_svc.clear_google_cloud(workspace_id=_ws.id, db=db_session)
    assert out == {"cleared": True}
    assert demo_svc.get_google_cloud_status(
        _ws.id, db_session
    )["seeded"] is False


def test_clear_google_cloud_demo_leaves_real_gcp_integration_alone(
    test_user, db_session, _ws,
):
    """Real-but-non-demo Google Cloud rows survive clear_google_cloud."""
    from app.core.encryption import encrypt_credentials
    from app.models.integration import Integration
    from app.models.security_finding import SecurityFinding
    ct, iv = encrypt_credentials({
        "type": "service_account", "project_id": "real-project",
        "private_key_id": "real-key-id",
        "private_key": (
            "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n"
        ),
        "client_email": "real@real-project.iam.gserviceaccount.com",
        "client_id": "1234567890",
    })
    real = Integration(
        user_id=test_user.id, workspace_id=_ws.id, provider="google_cloud",
        display_name="real-google-cloud", encrypted_credentials=ct,
        credential_iv=iv, status="active",
    )
    db_session.add(real); db_session.commit(); db_session.refresh(real)
    keep = SecurityFinding(
        workspace_id=_ws.id, integration_id=real.id, provider="google_cloud",
        finding_key="google_cloud_firewall_public_admin_ingress:real#keep",
        severity="critical", title="Real Google Cloud risk (keep)",
        status="active",
        evidence={
            "rule": "google_cloud_firewall_public_admin_ingress",
            "firewall_rule_name": "real-fw",
        },
        remediation={"summary": "x"},
    )
    db_session.add(keep); db_session.commit(); db_session.refresh(keep)
    keep_id = keep.id
    try:
        demo_svc.seed_google_cloud(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        demo_svc.clear_google_cloud(workspace_id=_ws.id, db=db_session)
        assert demo_svc.get_google_cloud_demo_integration(
            _ws.id, db_session
        ) is None
        survivor = db_session.query(SecurityFinding).filter(
            SecurityFinding.id == keep_id).first()
        assert survivor is not None, (
            "clear_google_cloud removed a non-demo Google Cloud finding"
        )
        # The real Google Cloud integration also survives.
        assert db_session.query(Integration).filter(
            Integration.id == real.id).first() is not None
    finally:
        db_session.query(SecurityFinding).filter(
            SecurityFinding.id == keep_id).delete(synchronize_session=False)
        db_session.query(Integration).filter(
            Integration.id == real.id).delete(synchronize_session=False)
        db_session.commit()
        demo_svc.clear_google_cloud(workspace_id=_ws.id, db=db_session)


def test_clear_google_cloud_demo_does_not_touch_other_provider_demos(
    test_user, db_session, _ws,
):
    """A multi-provider workspace: clearing GCP leaves every other demo alone."""
    other_providers = (
        ("azure",    demo_svc.seed_azure,    demo_svc.clear_azure,    demo_svc.get_azure_status),
        ("shopify",  demo_svc.seed_shopify,  demo_svc.clear_shopify,  demo_svc.get_shopify_status),
        ("stripe",   demo_svc.seed_stripe,   demo_svc.clear_stripe,   demo_svc.get_stripe_status),
        ("vercel",   demo_svc.seed_vercel,   demo_svc.clear_vercel,   demo_svc.get_vercel_status),
    )
    try:
        for _p, seed_fn, _c, _s in other_providers:
            seed_fn(workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session)
        demo_svc.seed_google_cloud(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        # All five demos are seeded.
        for _p, _, _c, status_fn in other_providers:
            assert status_fn(_ws.id, db_session)["seeded"] is True
        assert demo_svc.get_google_cloud_status(
            _ws.id, db_session
        )["seeded"] is True

        # Clear Google Cloud only.
        demo_svc.clear_google_cloud(workspace_id=_ws.id, db=db_session)

        # GCP gone; everyone else intact.
        assert demo_svc.get_google_cloud_status(
            _ws.id, db_session
        )["seeded"] is False
        for p, _, _c, status_fn in other_providers:
            assert status_fn(_ws.id, db_session)["seeded"] is True, (
                f"clear_google_cloud incorrectly removed the {p} demo"
            )
    finally:
        for _p, _s, clear_fn, _status in other_providers:
            try:
                clear_fn(workspace_id=_ws.id, db=db_session)
            except Exception:
                db_session.rollback()
        try:
            demo_svc.clear_google_cloud(workspace_id=_ws.id, db=db_session)
        except Exception:
            db_session.rollback()


def test_google_cloud_demo_integration_is_hidden_and_safe(
    test_user, db_session, _ws,
):
    """The demo integration must use the DEMO_PROVIDER_TAG and 'deleted' status."""
    try:
        demo_svc.seed_google_cloud(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        integ = demo_svc.get_google_cloud_demo_integration(_ws.id, db_session)
        assert integ is not None
        # Hidden / non-syncing / clearly marked.
        assert integ.provider == demo_svc.DEMO_PROVIDER_TAG
        assert integ.status == "deleted"
        assert integ.scheduled_sync_enabled is False
        assert "Google Cloud" in integ.display_name
        assert "demo" in integ.display_name.lower()
    finally:
        demo_svc.clear_google_cloud(workspace_id=_ws.id, db=db_session)


# ════════════════════════════════════════════════════════════════════════════
# Section F — Router/API guards (admin-only mutations; member reads)
# ════════════════════════════════════════════════════════════════════════════


def _scan_router_source() -> str:
    from app.routers import security as sec_router
    return inspect.getsource(sec_router)


def test_router_google_cloud_activity_sync_requires_admin():
    src = _scan_router_source()
    idx = src.find('"/google-cloud-activity/sync"')
    assert idx != -1, "google-cloud-activity/sync endpoint missing"
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block, (
        "/google-cloud-activity/sync handler missing admin guard"
    )


def test_router_google_cloud_signal_generate_requires_admin():
    src = _scan_router_source()
    idx = src.find('"/google-cloud-activity/generate-signals"')
    assert idx != -1, "google-cloud-activity/generate-signals endpoint missing"
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block


def test_router_correlations_generate_dispatches_to_google_cloud():
    """The generic /correlations/generate dispatcher routes to GCP correlations."""
    src = _scan_router_source()
    idx = src.find('"/correlations/generate"')
    assert idx != -1, "/correlations/generate endpoint missing"
    fn_block = src[idx: idx + 8000]
    assert "require_workspace_admin" in fn_block
    assert "generate_google_cloud_correlations" in fn_block


def test_router_incident_demo_seed_clear_require_admin():
    """seed/clear are admin-only; status is member-readable."""
    src = _scan_router_source()
    for ep in ('"/incident-demo/seed"', '"/incident-demo/clear"'):
        idx = src.find(ep)
        assert idx != -1, f"{ep} endpoint missing"
        fn_block = src[idx: idx + 4000]
        assert "require_workspace_admin" in fn_block, (
            f"{ep} handler missing admin guard"
        )


def test_router_incident_demo_status_is_member_readable():
    """The status endpoint must NOT require admin (members read demo status)."""
    src = _scan_router_source()
    idx = src.find('@router.get("/incident-demo/status"')
    assert idx != -1, "/incident-demo/status endpoint missing or not GET"
    next_router = src.find("\n@router", idx + 1)
    fn_block = src[idx: next_router if next_router > 0 else idx + 4000]
    assert "require_workspace_admin" not in fn_block, (
        "/incident-demo/status must not require admin"
    )


def test_router_dispatches_google_cloud_for_all_demo_endpoints():
    """All three incident-demo endpoints route provider='google_cloud'."""
    src = _scan_router_source()
    for substring in (
        "get_google_cloud_status", "seed_google_cloud", "clear_google_cloud",
    ):
        assert substring in src, f"router missing dispatch to {substring}"


def test_unknown_provider_in_correlations_generate_returns_empty_summary():
    """The /correlations/generate else-branch returns an empty summary."""
    src = _scan_router_source()
    idx = src.find('"/correlations/generate"')
    fn_block = src[idx: idx + 8000]
    assert "SecurityCorrelationGenerateResponse(provider=provider)" in fn_block


# ════════════════════════════════════════════════════════════════════════════
# Section G — Frontend Google Cloud consistency (skip if frontend absent)
# ════════════════════════════════════════════════════════════════════════════


_FE_ROOT_CANDIDATES = (
    Path(__file__).resolve().parents[2] / "frontend" / "src",
)


def _fe_src() -> Path | None:
    for c in _FE_ROOT_CANDIDATES:
        if c.is_dir():
            return c
    return None


def _read_fe(rel: str) -> str:
    root = _fe_src()
    if root is None:
        pytest.skip("frontend/src not mounted")
    return (root / rel).read_text(encoding="utf-8")


def test_fe_activity_page_includes_google_cloud_provider_and_types():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert '"google_cloud"' in text
    assert "Google Cloud" in text
    assert "GOOGLE_CLOUD_EVENT_TYPES" in text
    # Spot-check every M78D event type the filter renders.
    for ev in EXPECTED_INGESTION_EVENT_TYPES:
        assert ev in text, (
            f"activity page filter missing google_cloud event type {ev!r}"
        )


def test_fe_signals_page_includes_google_cloud_provider_and_types():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert '"google_cloud"' in text
    assert "GOOGLE_CLOUD_SIGNAL_TYPES" in text
    # Every M78E signal type appears in the filter dropdown.
    for s in EXPECTED_SIGNAL_TYPES:
        assert s in text, f"signals page filter missing {s!r}"


def test_fe_correlations_page_includes_google_cloud_provider_and_types():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    assert '"google_cloud"' in text
    # Every M78F correlation type appears in the static type-filter map.
    for ctype in EXPECTED_CORRELATION_TYPES:
        assert ctype in text, f"correlations page missing {ctype!r}"


def test_fe_cases_page_has_google_cloud_demo_card():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert "Load Google Cloud security demo" in text
    assert "Clear Google Cloud demo" in text
    assert 'provider: "google_cloud"' in text


def test_fe_demo_script_mentions_google_cloud():
    """securityDemoScript talk-track includes Google Cloud."""
    text = _read_fe("lib/securityDemoScript.ts")
    assert "Google Cloud" in text


def test_fe_rule_catalog_includes_every_google_cloud_rule_key():
    text = _read_fe("lib/securityRuleCatalog.ts")
    for key in EXPECTED_RULE_KEYS:
        assert f'key: "{key}"' in text, (
            f"frontend securityRuleCatalog missing rule key {key}"
        )


def test_fe_api_demo_provider_unions_include_google_cloud():
    """getIncidentDemoStatus / seedIncidentDemo / clearIncidentDemo unions."""
    text = _read_fe("lib/api.ts")
    count = text.count(
        '"github" | "aws" | "cloudflare" | "vercel" | "supabase" | '
        '"firebase" | "stripe" | "shopify" | "azure" | "google_cloud"'
    )
    assert count >= 3, (
        f"expected 3 demo helper unions to include google_cloud; found {count}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section H — Regression smoke (M78A–M78G still wire together)
# ════════════════════════════════════════════════════════════════════════════


def test_evaluator_dispatcher_handles_every_record_type_safely():
    """Every Google Cloud record type round-trips through evaluate() without raising."""
    for rt in EXPECTED_RECORD_TYPES:
        rec = {"record_type": rt, "record_id": f"projects/p/{rt}"}
        out = gcp_eval(rec)
        assert isinstance(out, list)


def test_allowed_method_names_round_trip_to_event_types():
    """Every connector allowlist method (lowercased) has a normalized event type."""
    for m in gcp_conn._AUDIT_ALLOWED_METHOD_PREFIXES:
        assert m.lower() in gcp_ingest._METHOD_EVENT_TYPE_MAP, (
            f"connector allowlist method {m!r} has no event-type mapping"
        )


def test_signal_pattern_summary_completeness():
    """Every signal pattern from _EVENT_PATTERNS has a summary entry."""
    patterns = {v[1] for v in gcp_sig._EVENT_PATTERNS.values()}
    missing = patterns - set(gcp_sig._PATTERN_SUMMARY)
    assert missing == set(), f"signal patterns missing summaries: {missing}"


def test_correlation_rules_split_resource_vs_aggregate_branches():
    """name_field=None ⇔ aggregate (IAM / SA-keys / Secret Manager) rules."""
    aggregate = {
        k for k, v in corr_svc.GOOGLE_CLOUD_CORRELATION_RULES.items()
        if v.get("name_field") is None
    }
    expected_aggregate = {
        "google_cloud_iam_public_member",
        "google_cloud_iam_broad_privileged_role",
        "google_cloud_service_account_user_managed_keys",
        "google_cloud_service_account_old_keys",
        "google_cloud_secret_manager_auto_replication_without_cmek",
    }
    assert aggregate == expected_aggregate, (
        f"aggregate-rule set drifted: {sorted(aggregate ^ expected_aggregate)}"
    )


def test_correlation_rules_event_name_field_alignment():
    """Resource rules carry both name_field (finding) and event_name_field (event)."""
    for k, v in corr_svc.GOOGLE_CLOUD_CORRELATION_RULES.items():
        nf = v.get("name_field")
        evn = v.get("event_name_field")
        if nf is None:
            assert evn is None, (
                f"{k}: aggregate rule must NOT carry event_name_field"
            )
        else:
            assert evn, f"{k}: resource rule missing event_name_field"


def test_demo_script_carries_review_safe_anchor_phrases():
    """The user-facing demo script must explicitly anchor review-safe wording.

    Forbidden-phrase scanning of the frontend demo script is handled by the
    existing M75A guardrails; here we pin the positive review-safe anchor
    phrases on the Google Cloud talk track so a future copy refactor cannot
    drop them silently.
    """
    root = _fe_src()
    if root is None:
        pytest.skip("frontend/src not mounted")
    text = (root / "lib" / "securityDemoScript.ts").read_text()
    # Anchor phrases that frame Google Cloud evidence as review material.
    low = text.lower()
    assert "evidence for review" in low
    # Google Cloud appears in the script's main flow.
    assert "Google Cloud" in text
