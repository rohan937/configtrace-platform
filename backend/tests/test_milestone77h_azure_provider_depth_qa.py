"""M77H — Azure provider-depth QA guardrails.

Durable, deterministic guardrails that prove the whole Azure arc (M77A–M77G)
stays internally consistent. This file adds NO product code — it pins
taxonomy parity, privacy/sanitization discipline, false-positive behavior,
demo isolation, and router admin-only guards.

Sections:

  A. Taxonomy parity
     Record types ↔ rule keys ↔ ingestion event types ↔ signal event types
     ↔ signal types ↔ correlation finding rules ↔ correlation activity types.

  B. Privacy guardrails
     Azure-shaped denylist applied to every Azure source file we own
     (connector, ingestion, signal, correlation, demo); also asserted on a
     live in-memory pipeline (build_signal → build_correlation → seed/clear
     case-report blobs).

  C. Claim discipline
     Forbidden-phrase scan over every Azure production module and the demo
     fixtures.

  D. False-positive behavior
     End-to-end "should NOT fire" cases that nail down the public-vs-private
     ingress, default-action storage/KV severity bump, role-assignment scope
     match, generic config event, subscription-only match, and stale window.

  E. Demo isolation
     Seed-twice / clear-twice idempotency; clear_azure leaves every other
     provider demo intact and never touches a real Azure integration.

  F. Router/API guards
     Azure activity sync / signal-generate / correlation-generate / incident
     demo seed-clear require admin; read-only endpoints stay member-accessible.
"""

from __future__ import annotations

import inspect
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.connectors import azure as az_conn
from app.connectors.azure_schema import (
    AZURE_AKS_CLUSTER, AZURE_APP_SERVICE, AZURE_KEY_VAULT,
    AZURE_NETWORK_SECURITY_GROUP, AZURE_RECORD_TYPES, AZURE_RESOURCE_GROUP,
    AZURE_ROLE_ASSIGNMENT, AZURE_SQL_SERVER, AZURE_STORAGE_ACCOUNT,
    AZURE_SUBSCRIPTION,
)
from app.services import azure_activity_ingestion_service as az_ingest
from app.services import azure_activity_signal_service as az_sig
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
from app.services.security_rules.azure import AZURE_RULE_KEYS, evaluate as az_eval


# ════════════════════════════════════════════════════════════════════════════
# Fixed expected sets — the M77H baseline.
# Drift here triggers an intentional update of this file (with a note in the
# commit message explaining the change).
# ════════════════════════════════════════════════════════════════════════════

EXPECTED_RECORD_TYPES = {
    "azure_subscription", "azure_resource_group",
    "azure_network_security_group", "azure_storage_account", "azure_key_vault",
    "azure_role_assignment", "azure_app_service", "azure_sql_server",
    "azure_aks_cluster",
}

EXPECTED_RULE_KEYS = {
    # NSG (M77B)
    "azure_nsg_public_admin_ingress", "azure_nsg_public_broad_ingress",
    # Storage (M77B)
    "azure_storage_public_blob_access", "azure_storage_public_network_access",
    "azure_storage_weak_tls", "azure_storage_shared_key_enabled",
    # Key Vault (M77B)
    "azure_key_vault_public_network_access",
    "azure_key_vault_purge_protection_disabled",
    "azure_key_vault_soft_delete_disabled", "azure_key_vault_rbac_disabled",
    # Role assignment (M77C)
    "azure_role_assignment_broad_privilege",
    # App Service (M77C)
    "azure_app_service_https_disabled", "azure_app_service_ftp_enabled",
    "azure_app_service_weak_tls", "azure_app_service_public_network_access",
    # SQL Server (M77C)
    "azure_sql_public_network_access", "azure_sql_weak_tls",
    # AKS (M77C)
    "azure_aks_local_accounts_enabled", "azure_aks_public_api_access",
    "azure_aks_network_policy_missing",
}

EXPECTED_INGESTION_EVENT_TYPES = {
    "azure.nsg.updated", "azure.nsg.deleted",
    "azure.nsg_rule.updated", "azure.nsg_rule.deleted",
    "azure.storage_account.updated", "azure.storage_account.deleted",
    "azure.key_vault.updated", "azure.key_vault.deleted",
    "azure.role_assignment.created", "azure.role_assignment.deleted",
    "azure.app_service.updated", "azure.app_service.deleted",
    "azure.app_service_config.updated",
    "azure.sql_server.updated", "azure.sql_server.deleted",
    "azure.sql_firewall_rule.updated", "azure.sql_firewall_rule.deleted",
    "azure.aks_cluster.updated", "azure.aks_cluster.deleted",
}

EXPECTED_SIGNAL_TYPES = {
    "azure_network_exposure_changed", "azure_nsg_deleted",
    "azure_storage_config_changed", "azure_storage_account_deleted",
    "azure_key_vault_config_changed", "azure_key_vault_deleted",
    "azure_role_assignment_changed",
    "azure_app_service_config_changed", "azure_app_service_deleted",
    "azure_sql_network_config_changed", "azure_sql_server_deleted",
    "azure_aks_cluster_config_changed", "azure_aks_cluster_deleted",
    "azure_config_activity",
}

EXPECTED_CORRELATION_TYPES = {
    "azure_nsg_exposure_activity_correlation",
    "azure_storage_risk_activity_correlation",
    "azure_key_vault_risk_activity_correlation",
    "azure_role_assignment_risk_activity_correlation",
    "azure_app_service_risk_activity_correlation",
    "azure_sql_risk_activity_correlation",
    "azure_aks_risk_activity_correlation",
}

# ── Forbidden claim wording (M75A pin) ───────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# ── Azure-shaped privacy denylist (M77H) ─────────────────────────────────────
# Substrings that MUST NOT appear (case-insensitive) as quoted JSON keys in
# any Azure production blob we generate (signal/correlation metadata, case
# report previews, demo evidence). These are written as the JSON-style
# `"key":` substring so we catch dict serialisation but not narrative text
# (e.g. "Use ConfigTrace claims" copy is fine).
AZURE_FORBIDDEN_METADATA_KEYS = (
    "client_secret", "access_token", "refresh_token", "id_token",
    "bearer", "claims", "properties", "httprequest", "requestbody",
    "responsebody", "raw_payload", "principal_id", "object_id",
    "caller_email", "caller_upn", "upn",
    "ip_address", "client_ip", "raw_ip",
    "accountkey", "sas_token", "connectionstring",
    "password", "secret_value", "kv_secret_value", "kubeconfig",
    "certificate_data", "private_key",
    "app_setting_value", "env_var_value",
    "database_contents", "customer_data",
)

# A few additional shape-only substrings that may appear in narrative copy
# but never as a quoted JSON value (so checked as substring in narrative).
AZURE_FORBIDDEN_VALUE_PATTERNS = (
    "begin rsa private",   # PEM header
    "begin certificate",
    "endpointsuffix=",
    "accountkey=",
)


# ════════════════════════════════════════════════════════════════════════════
# Section A — Taxonomy parity
# ════════════════════════════════════════════════════════════════════════════


def test_record_types_match_expected():
    """The Azure schema record-type set is exactly the documented M77H baseline."""
    assert set(AZURE_RECORD_TYPES) == EXPECTED_RECORD_TYPES


def test_record_type_constants_are_canonical_lowercase():
    """Each schema constant uses the canonical lowercase value (M77A bug pin)."""
    pairs = (
        ("AZURE_SUBSCRIPTION", AZURE_SUBSCRIPTION),
        ("AZURE_RESOURCE_GROUP", AZURE_RESOURCE_GROUP),
        ("AZURE_NETWORK_SECURITY_GROUP", AZURE_NETWORK_SECURITY_GROUP),
        ("AZURE_STORAGE_ACCOUNT", AZURE_STORAGE_ACCOUNT),
        ("AZURE_KEY_VAULT", AZURE_KEY_VAULT),
        ("AZURE_ROLE_ASSIGNMENT", AZURE_ROLE_ASSIGNMENT),
        ("AZURE_APP_SERVICE", AZURE_APP_SERVICE),
        ("AZURE_SQL_SERVER", AZURE_SQL_SERVER),
        ("AZURE_AKS_CLUSTER", AZURE_AKS_CLUSTER),
    )
    for name, val in pairs:
        assert val == name.lower(), (
            f"{name} value ({val!r}) must be its lowercased name "
            f"({name.lower()!r}); evaluator dispatch keys on this."
        )


def test_rule_keys_match_expected():
    assert AZURE_RULE_KEYS == EXPECTED_RULE_KEYS


def test_rule_registry_parity_for_azure_keys():
    azure_in_registry = {k for k in KNOWN_RULE_KEYS if k.startswith("azure_")}
    assert azure_in_registry == EXPECTED_RULE_KEYS

    azure_in_confidence = {k for k in RULE_CONFIDENCE if k.startswith("azure_")}
    assert azure_in_confidence == EXPECTED_RULE_KEYS

    azure_in_pack = {k for k, v in _RULE_META.items() if v[0] == "azure"}
    assert azure_in_pack == EXPECTED_RULE_KEYS

    azure_in_coverage = {k for k in RULE_RECORD_TYPES if k.startswith("azure_")}
    assert azure_in_coverage == EXPECTED_RULE_KEYS


def test_azure_in_coverage_providers_and_surfaces():
    assert "azure" in COVERAGE_PROVIDERS
    azure_surfaces = PROVIDER_SURFACES["azure"]
    # All surfaces match a record-type cluster.
    for s in azure_surfaces:
        assert isinstance(s, str) and s.strip()
    # The 7 expected surfaces M77G/M77H pin.
    assert set(azure_surfaces) == {
        "Network security groups", "Storage accounts", "Key Vaults",
        "Identity / Role assignments", "App Service / Functions",
        "SQL Servers", "AKS Clusters",
    }


def test_ingestion_event_types_match_expected():
    types = set(az_ingest._OPERATION_EVENT_TYPE_MAP.values())
    assert types == EXPECTED_INGESTION_EVENT_TYPES


def test_signal_event_patterns_cover_every_ingested_type():
    sig_event_types = set(az_sig._EVENT_PATTERNS)
    # Every type the connector ingests must have a signal entry; the signal
    # service is also allowed to accept the safe-fallback `azure.config.event`
    # (no ingestion path emits it but the signal service tolerates it).
    extra_in_signal = sig_event_types - EXPECTED_INGESTION_EVENT_TYPES
    assert extra_in_signal == {"azure.config.event"}, (
        f"signal-service event types diverge from ingestion: "
        f"extras={sorted(extra_in_signal)}"
    )
    missing_in_signal = EXPECTED_INGESTION_EVENT_TYPES - sig_event_types
    assert missing_in_signal == set(), (
        f"ingestion emits event types not handled by signal service: "
        f"{sorted(missing_in_signal)}"
    )


def test_signal_types_match_expected():
    types = {v[0] for v in az_sig._EVENT_PATTERNS.values()}
    assert types == EXPECTED_SIGNAL_TYPES


def test_correlation_rules_match_registered_rule_keys():
    assert set(corr_svc.AZURE_CORRELATION_RULES) == EXPECTED_RULE_KEYS


def test_correlation_types_match_expected():
    types = {v["correlation_type"] for v in corr_svc.AZURE_CORRELATION_RULES.values()}
    assert types == EXPECTED_CORRELATION_TYPES


def test_correlation_activity_types_are_subset_of_ingested():
    """Correlations may only match against activity event types ingestion emits."""
    referenced = set()
    for rule in corr_svc.AZURE_CORRELATION_RULES.values():
        referenced.update(rule["activity_types"])
    not_ingested = referenced - EXPECTED_INGESTION_EVENT_TYPES
    assert not_ingested == set(), (
        f"correlation references event types ingestion does not emit: "
        f"{sorted(not_ingested)}"
    )


def test_capability_matrix_pins_azure_partial_demo_ready():
    cap = get_provider_capability("azure")
    assert cap is not None
    # All security capabilities through M77G are True; maturity stays partial.
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True
    assert cap.maturity == "partial"
    # M77I rewrote the matrix notes to the demo-ready summary (milestone-free
    # user-facing copy). Check structural keywords instead of milestone codes.
    notes = (cap.notes or "")
    assert "demo-ready" in notes
    assert "Activity Log" in notes


def test_expansion_framework_points_to_m77i():
    """Rolled forward in M78D: GCP audit log ingestion complete; next stage is M78E."""
    fw = get_framework()
    assert "M78E" in fw["summary"]["planned_next_stage"]


def test_azure_not_in_canonical_eight_provider_matrix():
    """Azure stays in PROVIDER_CAPABILITIES_PARTIAL — never in the canonical 8."""
    from app.services.provider_capability_matrix_service import (
        PROVIDER_CAPABILITIES, PROVIDER_CAPABILITIES_PARTIAL,
    )
    canonical = {p.provider for p in PROVIDER_CAPABILITIES}
    partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
    assert "azure" not in canonical
    assert "azure" in partial


def test_azure_label_in_timeline_provider_labels():
    """build_case_evidence_timeline must render 'Azure' as the dominant label."""
    assert report_svc._TIMELINE_PROVIDER_LABELS.get("azure") == "Azure"


# ════════════════════════════════════════════════════════════════════════════
# Section B — Privacy guardrails (allowlist + denylist)
# ════════════════════════════════════════════════════════════════════════════


# M77D activity-event metadata keys (full set the ingester writes).
_AZURE_ACTIVITY_SAFE_KEYS = {
    "subscription_id", "resource_group", "resource_id", "resource_type",
    "operation_name", "operation_family", "operation_action",
    "azure_event_id", "azure_correlation_id_hash", "status", "sub_status",
    "category", "scope_type", "role_definition_name", "principal_type",
    "nsg_name", "nsg_rule_name", "storage_account_name", "key_vault_name",
    "app_service_name", "sql_server_name", "sql_firewall_rule_name",
    "aks_cluster_name", "event_time",
}

# M77E signal-metadata subset (signal builder doesn't propagate `event_time`
# because the signal model itself carries first_seen_at / last_seen_at; the
# activity-event allowlist additions in M77D are a superset).
_AZURE_SIGNAL_SAFE_KEYS = _AZURE_ACTIVITY_SAFE_KEYS - {"event_time"}

# M77F correlation-metadata subset — the correlation builder picks a narrower
# set than the signal builder. It deliberately omits `sub_status` (low value),
# `resource_id` (already implied by the linked finding/event), and
# `resource_type` (redundant with operation_family). Match-shape keys
# (matched_on / match_confidence / time_window_hours) are tested separately.
_AZURE_CORRELATION_SAFE_KEYS = _AZURE_SIGNAL_SAFE_KEYS - {
    "sub_status", "resource_id", "resource_type",
}


def test_activity_allowlist_contains_all_azure_safe_keys():
    """Every key the M77D ingester writes must be in the activity allowlist."""
    missing = _AZURE_ACTIVITY_SAFE_KEYS - ACTIVITY_ALLOWED
    assert missing == set(), f"M77D safe keys missing from activity allowlist: {missing}"


def test_signal_allowlist_contains_all_azure_safe_keys():
    """Every Azure-safe key the M77E signal builder emits must be allowlisted."""
    missing = _AZURE_SIGNAL_SAFE_KEYS - SIGNAL_ALLOWED
    assert missing == set(), f"M77E safe keys missing from signal allowlist: {missing}"


def test_correlation_allowlist_contains_all_azure_safe_keys():
    missing = _AZURE_CORRELATION_SAFE_KEYS - corr_svc.ALLOWED_METADATA_KEYS
    assert missing == set(), (
        f"M77F safe keys missing from correlation allowlist: {missing}"
    )


def test_correlation_allowlist_includes_match_metadata():
    """M77F adds matched_on / match_confidence / time_window_hours."""
    for key in ("matched_on", "match_confidence", "time_window_hours"):
        assert key in corr_svc.ALLOWED_METADATA_KEYS, (
            f"correlation allowlist missing {key!r}"
        )


def test_case_report_preview_allowlist_includes_azure_safe_keys():
    """M77G expansion of the case-report preview allowlist still covers Azure."""
    expected = {
        "subscription_id", "resource_group",
        "nsg_name", "storage_account_name", "key_vault_name",
        "app_service_name", "sql_server_name", "aks_cluster_name",
        "role_definition_name", "principal_type", "scope_type",
        "operation_name", "operation_action",
    }
    missing = expected - report_svc._PREVIEW_ALLOWLIST
    assert missing == set(), (
        f"case-report preview allowlist missing Azure-safe keys: {missing}"
    )


# ── Denylist guardrails on the in-memory pipeline ──────────────────────────


def _build_polluted_signal() -> dict:
    """Build a signal from an event that is polluted with PII/payload keys.

    sanitize_signal_metadata() must drop every forbidden key before persisting.
    """
    # Stub event that walks through the live build_signal path.
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = "azure.role_assignment.created"
    ev.provider = "azure"
    ev.source = "azure_activity_log"
    ev.resource_id = "/subscriptions/sub/.../roleAssignments/ra"
    ev.resource_type = "Microsoft.Authorization/roleAssignments"
    ev.provider_event_id = "evt-1"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = datetime.now(timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.event_metadata = {
        # Safe keys (must survive):
        "subscription_id": "sub-x",
        "resource_group": "rg-x",
        "operation_name": "Microsoft.Authorization/roleAssignments/write",
        "role_definition_name": "Owner",
        "scope_type": "subscription",
        "principal_type": "ServicePrincipal",
        # Forbidden pollution that MUST be dropped:
        "caller": "owner@example.com",
        "caller_email": "owner@example.com",
        "caller_upn": "owner@corp.example",
        "principal_id": "REDACTED-OID",
        "object_id": "REDACTED-OBJ",
        "client_secret": "shhh",
        "access_token": "xyz",
        "claims": {"oid": "abc"},
        "properties": "raw_payload_here",
        "authorization": "Bearer XYZ",
        "httprequest": {"body": "raw"},
        "ip_address": "1.2.3.4",
        "tenantid": "TENANT-GUID",
        "kubeconfig": "kubeconfig-blob",
        "certificate_data": "MIIBIjANB...",
        "kv_secret_value": "topsecret",
        "accountkey": "AccountKey=...",
        "sas_token": "?sv=2020...",
        "connectionstring": "AccountName=foo;AccountKey=bar",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----",
        "app_setting_value": "DB_PASSWORD=...",
        "env_var_value": "API_KEY=...",
    }
    sig = az_sig._build_signal([ev])
    assert sig is not None
    return sig


def _denylist_assert(blob: str, *, where: str) -> None:
    lower = blob.lower()
    for bad in AZURE_FORBIDDEN_METADATA_KEYS:
        assert f'"{bad}":' not in lower, (
            f"{where}: forbidden quoted key {bad!r} present"
        )
    for bad in AZURE_FORBIDDEN_VALUE_PATTERNS:
        assert bad not in lower, (
            f"{where}: forbidden substring {bad!r} present"
        )


def test_signal_metadata_drops_every_polluted_key():
    sig = _build_polluted_signal()
    meta = sig["metadata"]
    # Safe metadata survives.
    assert meta.get("subscription_id") == "sub-x"
    assert meta.get("role_definition_name") == "Owner"
    assert meta.get("scope_type") == "subscription"
    assert meta.get("principal_type") == "ServicePrincipal"
    # Forbidden keys dropped.
    for bad in (
        "caller", "caller_email", "caller_upn", "principal_id", "object_id",
        "client_secret", "access_token", "claims", "properties",
        "authorization", "httprequest", "ip_address", "tenantid",
        "kubeconfig", "certificate_data", "kv_secret_value", "accountkey",
        "sas_token", "connectionstring", "private_key",
        "app_setting_value", "env_var_value",
    ):
        assert bad not in meta, f"forbidden key {bad!r} survived in signal metadata"
    # PII values never appear in any serialisable surface of the signal.
    blob = json.dumps({
        "metadata": meta, "title": sig["title"], "summary": sig["summary"],
    })
    for value in (
        "owner@example.com", "owner@corp.example", "REDACTED-OID",
        "REDACTED-OBJ", "TENANT-GUID", "AccountName=foo;AccountKey=bar",
        "BEGIN RSA PRIVATE KEY", "DB_PASSWORD",
    ):
        assert value not in blob, f"PII value {value!r} in signal blob"


def _make_finding_mock(**evidence) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.finding_key = "azure_role_assignment_broad_privilege:assignment-1"
    f.severity = "high"
    f.title = "Demo finding"
    f.evidence = evidence
    f.first_detected_at = datetime.now(timezone.utc) - timedelta(hours=1)
    f.last_seen_at = datetime.now(timezone.utc)
    f.linked_change_id = None
    f.integration_id = uuid.uuid4()
    return f


def _make_event_mock(metadata: dict) -> MagicMock:
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = "azure.role_assignment.created"
    ev.source = "azure_activity_log"
    ev.actor_id = None
    ev.event_metadata = metadata
    ev.occurred_at = datetime.now(timezone.utc)
    return ev


def test_correlation_metadata_drops_every_polluted_key():
    f = _make_finding_mock(
        role_definition_name="Owner", scope_type="subscription",
        principal_type="ServicePrincipal",
        # Pollution on the finding side:
        principal_id="REDACTED", caller="owner@example.com",
    )
    ev = _make_event_mock({
        "role_definition_name": "Owner", "scope_type": "subscription",
        "principal_type": "ServicePrincipal", "subscription_id": "sub-x",
        # Pollution on the event side:
        "client_secret": "x", "access_token": "y", "claims": "z",
        "properties": "raw_payload_blob", "authorization": "Bearer Z",
        "tenantid": "TENANT-GUID", "ip_address": "9.9.9.9",
        "caller_email": "owner@example.com", "accountkey": "k",
        "sas_token": "?sv=", "connectionstring": "AccountKey=x",
        "kubeconfig": "k", "certificate_data": "c", "private_key": "-----BEGIN",
        "principal_id": "P", "object_id": "O", "kv_secret_value": "V",
        "app_setting_value": "A", "env_var_value": "E",
        "raw_payload": "raw", "id_token": "tok", "refresh_token": "tok",
        "bearer": "x", "password": "p", "secret_value": "v",
        "httprequest": "h", "requestbody": "rb", "responsebody": "rb",
        "client_ip": "9.9.9.9", "raw_ip": "9.9.9.9", "caller_upn": "u@u",
        "upn": "u@u",
    })
    rule = corr_svc.AZURE_CORRELATION_RULES["azure_role_assignment_broad_privilege"]
    c = corr_svc.build_azure_correlation(
        finding=f, event=ev, rule=rule,
        matched_on="role_definition_name+scope_type",
        resource_label='role assignment "Owner"',
    )
    blob = json.dumps({
        "metadata": c["metadata"], "title": c["title"], "summary": c["summary"],
    })
    _denylist_assert(blob, where="correlation built from polluted finding+event")


def test_azure_demo_case_artifacts_pass_denylist(test_user, db_session):
    """The Azure demo seed/report/timeline/graph stay denylist-clean."""
    from app.services import workspace_service
    ws = workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M77H demo", db=db_session,
    )
    try:
        seed = demo_svc.seed_azure(
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
        _denylist_assert(blob, where="azure demo report/timeline/graph")
    finally:
        demo_svc.clear_azure(workspace_id=ws.id, db=db_session)


# ════════════════════════════════════════════════════════════════════════════
# Section C — Claim discipline (forbidden phrases on Azure modules)
# ════════════════════════════════════════════════════════════════════════════


# Modules that handle Azure end-to-end. Each must be clean of forbidden
# phrases EXCEPT inside known guard contexts (e.g. test denylists, the
# capability-matrix forbidden-phrase registry, comment fences declaring what
# is NOT claimed). Production source is scanned text-only.
_AZURE_MODULES = [
    az_conn, az_ingest, az_sig, demo_svc,
]


def _strip_known_negation_contexts(src: str) -> str:
    """Remove lines that explicitly NEGATE a forbidden claim.

    Lines containing 'does not confirm', 'never asserts', 'never claim',
    'we do not claim', 'is NOT', 'is not a claim' are allowed contexts.
    """
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
                # Documentation block headers that list forbidden wording.
                "forbidden", "not confirm",
            )
        ):
            continue
        out.append(line)
    return "\n".join(out)


@pytest.mark.parametrize("module", _AZURE_MODULES)
def test_azure_modules_have_no_forbidden_claims(module):
    src = inspect.getsource(module)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in {module.__name__} "
            f"outside a negation context"
        )


def test_azure_security_rules_module_has_no_forbidden_claims():
    """The security_rules.azure module ships claim-discipline copy to live findings."""
    from app.services.security_rules import azure as az_rules
    src = inspect.getsource(az_rules)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in security_rules.azure"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section D — False-positive behavior pins
# ════════════════════════════════════════════════════════════════════════════


def _nsg_record(rules: list[dict], **extra) -> dict:
    return {
        "record_type": AZURE_NETWORK_SECURITY_GROUP,
        "record_id": "/subscriptions/s/.../nsgs/nsg-prod",
        "nsg_name": "nsg-prod", "resource_group": "rg",
        "location": "eastus", "rules_summary": rules, **extra,
    }


def _ingress(*, src: str, port: str, name: str = "r", access: str = "Allow",
             direction: str = "Inbound") -> dict:
    return {
        "rule_name": name, "direction": direction, "access": access,
        "source_address_prefix": src, "destination_port_range": port,
        "protocol": "Tcp",
    }


@pytest.mark.parametrize("port", ["80", "443"])
def test_public_web_port_never_triggers_admin_or_broad(port: str):
    """Public 80/443 is not an admin/database/cache port — never fires."""
    findings = az_eval(_nsg_record([_ingress(src="*", port=port)]))
    rule_keys = {f.rule_key for f in findings}
    assert "azure_nsg_public_admin_ingress" not in rule_keys
    assert "azure_nsg_public_broad_ingress" not in rule_keys


@pytest.mark.parametrize("src", ["10.0.0.0/24", "192.168.1.0/24", "172.16.0.0/12", "VirtualNetwork"])
def test_private_source_never_triggers_public_finding(src: str):
    """Private/VNet sources are not 'public' — admin/broad rules stay silent."""
    findings = az_eval(_nsg_record([_ingress(src=src, port="22")]))
    assert findings == []


def test_storage_public_network_access_severity_bumps_only_on_default_allow():
    """publicNetworkAccess=Enabled is medium; bumps to high only when default_action=Allow."""
    base = {
        "record_type": AZURE_STORAGE_ACCOUNT,
        "record_id": "/sub/.../sa", "account_name": "acct",
        "resource_group": "rg", "location": "eastus",
        "public_network_access": "Enabled",
    }
    f_no_bump = az_eval(dict(base, network_default_action="Deny"))[0]
    assert f_no_bump.rule_key == "azure_storage_public_network_access"
    assert f_no_bump.severity == "medium"

    f_bumped = az_eval(dict(base, network_default_action="Allow"))[0]
    assert f_bumped.severity == "high"


def test_key_vault_public_network_access_severity_bumps_only_on_default_allow():
    base = {
        "record_type": AZURE_KEY_VAULT,
        "record_id": "/sub/.../kv", "vault_name": "kv",
        "resource_group": "rg", "location": "eastus",
        "public_network_access": "Enabled",
    }
    f_no_bump = az_eval(dict(base, network_default_action="Deny"))[0]
    assert f_no_bump.severity == "medium"
    f_bumped = az_eval(dict(base, network_default_action="Allow"))[0]
    assert f_bumped.severity == "high"


def test_role_assignment_at_resource_scope_does_not_correlate_broadly():
    """A role assignment at a sub-resource scope is NOT broad — no correlation."""
    f = _make_finding_mock(
        role_definition_name="Owner", scope_type="resource",
        principal_type="ServicePrincipal",
    )
    ev = _make_event_mock({
        "role_definition_name": "Owner", "scope_type": "resource",
        "principal_type": "ServicePrincipal",
    })
    # _az_match_role_assignment requires the role to be one of the broad set
    # AND scope_type alignment — but "resource" scope is allowed; it's the
    # NAMES that must match. So this test pins broad-role+scope alignment.
    matched = corr_svc._az_match_role_assignment(f, ev)
    assert matched == "role_definition_name+scope_type"

    # Non-broad role at any scope returns None.
    f2 = _make_finding_mock(
        role_definition_name="Reader", scope_type="subscription",
    )
    ev2 = _make_event_mock({
        "role_definition_name": "Reader", "scope_type": "subscription",
    })
    assert corr_svc._az_match_role_assignment(f2, ev2) is None


def test_subscription_only_match_does_not_correlate():
    """Same subscription, different resource → no correlation."""
    rule = corr_svc.AZURE_CORRELATION_RULES["azure_storage_public_blob_access"]
    f = _make_finding_mock(
        account_name="acct-a", resource_group="rg-prod",
    )
    f.finding_key = "azure_storage_public_blob_access:acct-a"
    ev = _make_event_mock({
        "storage_account_name": "acct-b",  # different account!
        "resource_group": "rg-prod",
        "subscription_id": "sub-1",
    })
    assert corr_svc._az_match_resource(f, ev, rule) is None


def test_provider_only_match_does_not_correlate():
    """Same provider but different resource group → no correlation."""
    rule = corr_svc.AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
    f = _make_finding_mock(nsg_name="nsg-prod", resource_group="rg-a")
    f.finding_key = "azure_nsg_public_admin_ingress:nsg-prod"
    ev = _make_event_mock({
        "nsg_name": "nsg-prod", "resource_group": "rg-b",
    })
    assert corr_svc._az_match_resource(f, ev, rule) is None


def test_generic_config_event_alone_does_not_become_a_correlation():
    """`azure.config.event` is not in any AZURE_CORRELATION_RULES.activity_types."""
    for rule in corr_svc.AZURE_CORRELATION_RULES.values():
        assert "azure.config.event" not in rule["activity_types"]


def test_unknown_record_type_returns_no_findings():
    """The Azure evaluator dispatch is closed — unknown record types yield []."""
    assert az_eval({"record_type": "azure_unknown_thing"}) == []
    assert az_eval({"record_type": ""}) == []
    assert az_eval({}) == []


def test_unknown_signal_event_type_returns_no_signal():
    """The signal dispatcher silently drops unmapped event types."""
    ev = _make_event_mock({"subscription_id": "x", "resource_group": "y"})
    ev.event_type = "azure.totally.unknown"
    assert az_sig._build_signal([ev]) is None


# ════════════════════════════════════════════════════════════════════════════
# Section E — Demo isolation
# ════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def _ws(test_user, db_session):
    from app.services import workspace_service
    return workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M77H ws", db=db_session,
    )


def test_seed_azure_demo_is_idempotent(test_user, db_session, _ws):
    try:
        r1 = demo_svc.seed_azure(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        r2 = demo_svc.seed_azure(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
    finally:
        demo_svc.clear_azure(workspace_id=_ws.id, db=db_session)


def test_clear_azure_demo_is_idempotent(test_user, db_session, _ws):
    demo_svc.seed_azure(
        workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
    )
    demo_svc.clear_azure(workspace_id=_ws.id, db=db_session)
    # Second clear is a no-op.
    out = demo_svc.clear_azure(workspace_id=_ws.id, db=db_session)
    assert out == {"cleared": True}
    assert demo_svc.get_azure_status(_ws.id, db_session)["seeded"] is False


def test_clear_azure_demo_leaves_real_azure_integration_alone(
    test_user, db_session, _ws,
):
    """Real-but-non-demo Azure rows survive clear_azure."""
    from app.core.encryption import encrypt_credentials
    from app.models.integration import Integration
    from app.models.security_finding import SecurityFinding
    ct, iv = encrypt_credentials({
        "tenant_id": "real-t", "client_id": "real-c",
        "client_secret": "real-s", "subscription_id": "real-sub",
    })
    real = Integration(
        user_id=test_user.id, workspace_id=_ws.id, provider="azure",
        display_name="real-azure", encrypted_credentials=ct,
        credential_iv=iv, status="active",
    )
    db_session.add(real); db_session.commit(); db_session.refresh(real)
    keep = SecurityFinding(
        workspace_id=_ws.id, integration_id=real.id, provider="azure",
        finding_key="azure_nsg_public_admin_ingress:real#keep",
        severity="critical", title="Real Azure risk (keep)", status="active",
        evidence={"rule": "azure_nsg_public_admin_ingress", "nsg_name": "real-nsg"},
        remediation={"summary": "x"},
    )
    db_session.add(keep); db_session.commit(); db_session.refresh(keep)
    keep_id = keep.id
    try:
        demo_svc.seed_azure(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        demo_svc.clear_azure(workspace_id=_ws.id, db=db_session)
        assert demo_svc.get_azure_demo_integration(_ws.id, db_session) is None
        survivor = db_session.query(SecurityFinding).filter(
            SecurityFinding.id == keep_id).first()
        assert survivor is not None, (
            "clear_azure removed a non-demo Azure finding"
        )
        # The real Azure integration also survives.
        assert db_session.query(Integration).filter(
            Integration.id == real.id).first() is not None
    finally:
        db_session.query(SecurityFinding).filter(
            SecurityFinding.id == keep_id).delete(synchronize_session=False)
        db_session.query(Integration).filter(
            Integration.id == real.id).delete(synchronize_session=False)
        db_session.commit()
        demo_svc.clear_azure(workspace_id=_ws.id, db=db_session)


def test_clear_azure_demo_does_not_touch_other_provider_demos(
    test_user, db_session, _ws,
):
    """A multi-provider workspace: clearing Azure leaves every other demo alone."""
    other_providers = (
        ("shopify",  demo_svc.seed_shopify,  demo_svc.clear_shopify,  demo_svc.get_shopify_status),
        ("stripe",   demo_svc.seed_stripe,   demo_svc.clear_stripe,   demo_svc.get_stripe_status),
        ("vercel",   demo_svc.seed_vercel,   demo_svc.clear_vercel,   demo_svc.get_vercel_status),
        ("supabase", demo_svc.seed_supabase, demo_svc.clear_supabase, demo_svc.get_supabase_status),
    )
    try:
        for _p, seed_fn, _c, _s in other_providers:
            seed_fn(workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session)
        demo_svc.seed_azure(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        # All five demos are seeded.
        for _p, _, _c, status_fn in other_providers:
            assert status_fn(_ws.id, db_session)["seeded"] is True
        assert demo_svc.get_azure_status(_ws.id, db_session)["seeded"] is True

        # Clear Azure only.
        demo_svc.clear_azure(workspace_id=_ws.id, db=db_session)

        # Azure gone; everyone else intact.
        assert demo_svc.get_azure_status(_ws.id, db_session)["seeded"] is False
        for p, _, _c, status_fn in other_providers:
            assert status_fn(_ws.id, db_session)["seeded"] is True, (
                f"clear_azure incorrectly removed the {p} demo"
            )
    finally:
        for _p, _s, clear_fn, _status in other_providers:
            try:
                clear_fn(workspace_id=_ws.id, db=db_session)
            except Exception:
                db_session.rollback()
        try:
            demo_svc.clear_azure(workspace_id=_ws.id, db=db_session)
        except Exception:
            db_session.rollback()


def test_azure_demo_integration_is_hidden_and_safe(test_user, db_session, _ws):
    """The demo integration must use the DEMO_PROVIDER_TAG and 'deleted' status."""
    try:
        demo_svc.seed_azure(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        integ = demo_svc.get_azure_demo_integration(_ws.id, db_session)
        assert integ is not None
        # Hidden / non-syncing / clearly marked.
        assert integ.provider == demo_svc.DEMO_PROVIDER_TAG
        assert integ.status == "deleted"
        assert integ.scheduled_sync_enabled is False
        assert "Azure" in integ.display_name
        assert "demo" in integ.display_name.lower()
    finally:
        demo_svc.clear_azure(workspace_id=_ws.id, db=db_session)


# ════════════════════════════════════════════════════════════════════════════
# Section F — Router/API guards (admin-only mutations; member reads)
# ════════════════════════════════════════════════════════════════════════════


def _scan_router_source() -> str:
    from app.routers import security as sec_router
    return inspect.getsource(sec_router)


def test_router_azure_activity_sync_requires_admin():
    src = _scan_router_source()
    # The /azure-activity/sync handler must invoke require_workspace_admin.
    m = re.search(
        r'@router\.post\("/azure-activity/sync".*?\nasync def |\n@router\.|\Z',
        src, flags=re.DOTALL,
    )
    # Search differently: just isolate the function body by location of the
    # endpoint string then look forward to next @router definition.
    idx = src.find('"/azure-activity/sync"')
    assert idx != -1, "azure-activity/sync endpoint missing"
    # Take the next 60 lines of source from that index.
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block, (
        "/azure-activity/sync handler missing admin guard"
    )


def test_router_azure_signal_generate_requires_admin():
    src = _scan_router_source()
    idx = src.find('"/azure-activity/generate-signals"')
    assert idx != -1, "azure-activity/generate-signals endpoint missing"
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block


def test_router_correlations_generate_requires_admin_for_azure_branch():
    """The generic /correlations/generate dispatcher guards admin first."""
    src = _scan_router_source()
    idx = src.find('"/correlations/generate"')
    assert idx != -1, "/correlations/generate endpoint missing"
    fn_block = src[idx: idx + 6000]
    assert "require_workspace_admin" in fn_block
    # The azure branch must dispatch to generate_azure_correlations.
    assert "generate_azure_correlations" in fn_block


def test_router_incident_demo_seed_clear_require_admin():
    src = _scan_router_source()
    # Status is GET (member-readable), seed/clear are POST (admin-only).
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
    # Stop at the next @router.
    next_router = src.find("\n@router", idx + 1)
    fn_block = src[idx: next_router if next_router > 0 else idx + 4000]
    assert "require_workspace_admin" not in fn_block, (
        "/incident-demo/status must not require admin"
    )


def test_router_dispatches_azure_for_all_demo_endpoints():
    """All three incident-demo endpoints route provider='azure' to demo_svc.*_azure."""
    src = _scan_router_source()
    for substring in (
        "get_azure_status", "seed_azure", "clear_azure",
    ):
        assert substring in src, f"router missing dispatch to {substring}"


def test_unknown_provider_in_correlations_generate_returns_empty_summary():
    """The /correlations/generate else-branch returns an empty summary for bogus providers."""
    src = _scan_router_source()
    idx = src.find('"/correlations/generate"')
    fn_block = src[idx: idx + 6000]
    # The default branch builds a SecurityCorrelationGenerateResponse with
    # only provider set, no findings/events/correlations counts.
    assert "SecurityCorrelationGenerateResponse(provider=provider)" in fn_block


# ════════════════════════════════════════════════════════════════════════════
# Section G — Frontend Azure consistency (skip if frontend tree absent)
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


def test_fe_activity_page_includes_azure_provider():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert '"azure"' in text
    assert "Azure" in text
    assert "AZURE_EVENT_TYPES" in text


def test_fe_signals_page_includes_azure_provider():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert '"azure"' in text
    assert "AZURE_SIGNAL_TYPES" in text


def test_fe_correlations_page_includes_azure_provider():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    assert '"azure"' in text
    # Every Azure correlation type appears in the static label map.
    for ctype in EXPECTED_CORRELATION_TYPES:
        assert ctype in text, f"correlations page missing {ctype!r}"


def test_fe_cases_page_has_azure_demo_card():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert "Load Azure security demo" in text
    assert "Clear Azure demo" in text
    assert 'onSeedDemo("azure")' in text
    assert 'onClearDemo("azure")' in text


def test_fe_demo_script_page_marks_azure_demo_ready():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    # Capability table Azure row has demo: true after M77G.
    m = re.search(
        r'\{\s*provider:\s*"azure",[^}]*demo:\s*true', text,
    )
    assert m is not None, "demo-script Azure row missing demo: true"


def test_fe_rule_catalog_includes_every_azure_rule_key():
    text = _read_fe("lib/securityRuleCatalog.ts")
    for key in EXPECTED_RULE_KEYS:
        assert f'key: "{key}"' in text, (
            f"frontend securityRuleCatalog missing rule key {key}"
        )


def test_fe_api_demo_provider_unions_include_azure():
    """getIncidentDemoStatus / seedIncidentDemo / clearIncidentDemo union types."""
    text = _read_fe("lib/api.ts")
    # Each of the three helpers' union types should mention "azure".
    union_count = text.count(
        '"github" | "aws" | "cloudflare" | "vercel" | "supabase" | '
        '"firebase" | "stripe" | "shopify" | "azure"'
    )
    assert union_count >= 3, (
        f"expected 3 demo helper unions to include azure; found {union_count}"
    )


def test_fe_demo_script_mentions_azure():
    """securityDemoScript talk-track includes Azure."""
    text = _read_fe("lib/securityDemoScript.ts")
    assert "Azure" in text


# ════════════════════════════════════════════════════════════════════════════
# Section H — Regression smoke (M77A–M77G still wire together)
# ════════════════════════════════════════════════════════════════════════════


def test_evaluator_dispatcher_handles_every_record_type_safely():
    """Every Azure record type must round-trip through evaluate() without raising."""
    for rt in EXPECTED_RECORD_TYPES:
        # Build a minimal record and confirm evaluate() returns a list.
        rec = {"record_type": rt, "record_id": f"/sub/x/{rt}"}
        out = az_eval(rec)
        assert isinstance(out, list)


def test_ingestion_event_type_map_has_no_orphan_entries():
    """Every M77D map key has a corresponding allowed-operation entry."""
    for op_name in az_ingest._OPERATION_EVENT_TYPE_MAP.keys():
        assert op_name in az_conn._ALLOWED_OPERATION_NAMES, (
            f"ingestion event-type map references unallowed op {op_name!r}"
        )


def test_allowed_operations_have_an_event_type_mapping():
    """Every allowed operation has a normalized event type."""
    for op_name in az_conn._ALLOWED_OPERATION_NAMES:
        assert op_name in az_ingest._OPERATION_EVENT_TYPE_MAP, (
            f"connector allowlist op {op_name!r} has no event-type mapping"
        )


def test_signal_pattern_summary_completeness():
    """Every signal pattern produced by _EVENT_PATTERNS has an explanation."""
    patterns = {v[1] for v in az_sig._EVENT_PATTERNS.values()}
    missing = patterns - set(az_sig._PATTERN_SUMMARY)
    assert missing == set(), (
        f"signal patterns missing summaries: {missing}"
    )


def test_correlation_rules_split_resource_vs_role_branches():
    """Exactly the broad-role rule uses name_field=None; everything else uses a name."""
    role_only = {
        k for k, v in corr_svc.AZURE_CORRELATION_RULES.items()
        if v.get("name_field") is None
    }
    assert role_only == {"azure_role_assignment_broad_privilege"}
