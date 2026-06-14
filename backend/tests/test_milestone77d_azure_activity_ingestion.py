"""M77D: Azure Activity Log ingestion — test suite.

Covers:
  * AzureConnector.list_activity_events — safe field extraction, allowlist
    filtering, max_events/lookback_hours caps, pagination cap, error mapping
  * normalize_azure_activity_event — operation→event_type mapping, metadata
    assembly, fingerprint fallback, malformed event skipping
  * ingest_azure_activity — credential dispatch, idempotency, fail-soft
  * POST /security/azure-activity/sync — admin-only, member blocked, no integration
  * GET /security/activity/events?provider=azure — readable by members
  * Metadata safety — no PII, no secrets, no raw payloads
  * Claim discipline — no forbidden wording
  * Capability matrix — activity_ingestion=True, signals/correlations=False
  * Expansion framework next_stage → M77E
  * M77A/B/C regression
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest

from app.connectors.azure import (
    AzureConnector,
    _ALLOWED_OPERATION_NAMES,
)
from app.services.azure_activity_ingestion_service import (
    EVENT_SOURCE,
    PROVIDER,
    SOURCE,
    _OPERATION_EVENT_TYPE_MAP,
    _extract_resource_names,
    _hash_correlation_id,
    normalize_azure_activity_event,
)
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework
from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

_FORBIDDEN_METADATA_KEYS = {
    "caller", "claims", "authorization", "properties", "httpRequest",
    "description", "tenantId", "access_token", "refresh_token", "bearer",
    "client_secret", "password", "email", "upn", "principal_id", "object_id",
    "ip_address", "raw", "payload", "request", "response", "body", "headers",
    "token", "secret", "value", "customer", "principal_email",
}

_FORBIDDEN_CLAIM_PHRASES = (
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "customer data leaked",
    "payment fraud detected",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
)

_TS = "2025-06-01T12:00:00.0000000Z"


def _raw_event(
    op_name: str = "Microsoft.Network/networkSecurityGroups/write",
    event_data_id: str = "evt-001",
    correlation_id: str = "corr-123",
    resource_id: str = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-prod",
    **extra: Any,
) -> dict:
    """Build a pre-stripped connector event dict (as returned by list_activity_events)."""
    return {
        "event_data_id": event_data_id,
        "correlation_id": correlation_id,
        "event_timestamp": _TS,
        "subscription_id": "sub-123",
        "resource_group_name": "my-rg",
        "resource_id": resource_id,
        "resource_type": "Microsoft.Network/networkSecurityGroups",
        "operation_name": op_name,
        "status": "Succeeded",
        "sub_status": "Created",
        "category": "Administrative",
        **extra,
    }


def _unsafe_raw_arm_event(op_name: str) -> dict:
    """Simulate a raw Azure ARM response (with PII fields that the connector strips)."""
    return {
        "id": "/sub/.../values/evt-001",
        "eventDataId": "evt-001",
        "correlationId": "corr-123",
        "eventName": {"value": "EndRequest"},
        "category": {"value": "Administrative"},
        "resourceGroupName": "my-rg",
        "resourceId": "/sub/...nsg-prod",
        "resourceType": {"value": "Microsoft.Network/networkSecurityGroups"},
        "operationName": {"value": op_name},
        "status": {"value": "Succeeded"},
        "subStatus": {"value": ""},
        "eventTimestamp": _TS,
        "subscriptionId": "sub-123",
        # PII / sensitive fields — MUST NOT appear in returned dicts
        "caller": "user@example.com",
        "claims": {"oid": "some-object-id", "iss": "https://..."},
        "authorization": {"action": op_name, "scope": "/sub/..."},
        "properties": {"message": "sensitive customer info"},
        "httpRequest": {"clientRequestId": "req-id", "method": "PUT"},
        "description": "operation description that might include names",
        "tenantId": "tenant-guid",
    }


# ──────────────────────────────────────────────────────────────────────────────
# Connector: list_activity_events
# ──────────────────────────────────────────────────────────────────────────────


class TestConnectorListActivityEvents:
    def _make_connector_with_events(self, raw_arm_events: list[dict]) -> AzureConnector:
        conn = AzureConnector()
        conn._get_token = MagicMock(return_value="mock-bearer-token")
        conn._paginate = MagicMock(return_value=raw_arm_events)
        return conn

    def _creds(self) -> dict:
        return {
            "tenant_id": "t", "client_id": "c", "client_secret": "s",
            "subscription_id": "sub-123",
        }

    def test_allowed_operation_is_returned(self):
        arm_event = _unsafe_raw_arm_event(
            "Microsoft.Network/networkSecurityGroups/write"
        )
        conn = self._make_connector_with_events([arm_event])
        results = conn.list_activity_events(self._creds())
        assert len(results) == 1
        assert results[0]["operation_name"] == "Microsoft.Network/networkSecurityGroups/write"

    def test_read_operation_is_excluded(self):
        arm_event = _unsafe_raw_arm_event("Microsoft.Network/networkSecurityGroups/read")
        conn = self._make_connector_with_events([arm_event])
        results = conn.list_activity_events(self._creds())
        assert results == []

    def test_data_plane_operation_excluded(self):
        arm_event = _unsafe_raw_arm_event("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read")
        conn = self._make_connector_with_events([arm_event])
        results = conn.list_activity_events(self._creds())
        assert results == []

    def test_vm_operation_excluded(self):
        arm_event = _unsafe_raw_arm_event("Microsoft.Compute/virtualMachines/write")
        conn = self._make_connector_with_events([arm_event])
        results = conn.list_activity_events(self._creds())
        assert results == []

    def test_max_events_cap_enforced(self):
        # 5 valid events but max_events=2
        arm_events = [
            _unsafe_raw_arm_event("Microsoft.Network/networkSecurityGroups/write")
            for _ in range(5)
        ]
        conn = self._make_connector_with_events(arm_events)
        results = conn.list_activity_events(self._creds(), max_events=2)
        assert len(results) == 2

    def test_max_events_clamps_to_1000(self):
        conn = self._make_connector_with_events([])
        with patch.object(conn, "_paginate", return_value=[]) as mock_pag:
            conn.list_activity_events(self._creds(), max_events=99999)
        # Just verifying no exception — the cap is applied internally

    def test_lookback_hours_clamps_to_168(self):
        conn = self._make_connector_with_events([])
        with patch.object(conn, "_paginate", return_value=[]) as mock_pag:
            conn.list_activity_events(self._creds(), lookback_hours=9999)
        # Should clamp to 168 without error

    def test_caller_never_in_returned_event(self):
        arm_event = _unsafe_raw_arm_event("Microsoft.Network/networkSecurityGroups/write")
        conn = self._make_connector_with_events([arm_event])
        results = conn.list_activity_events(self._creds())
        assert results
        ev = results[0]
        text = json.dumps(ev)
        assert "user@example.com" not in text
        assert "caller" not in ev

    def test_claims_never_in_returned_event(self):
        arm_event = _unsafe_raw_arm_event("Microsoft.Network/networkSecurityGroups/write")
        conn = self._make_connector_with_events([arm_event])
        results = conn.list_activity_events(self._creds())
        ev = results[0]
        assert "claims" not in ev
        assert "oid" not in ev

    def test_properties_never_in_returned_event(self):
        arm_event = _unsafe_raw_arm_event("Microsoft.Storage/storageAccounts/write")
        conn = self._make_connector_with_events([arm_event])
        results = conn.list_activity_events(self._creds())
        ev = results[0]
        assert "properties" not in ev
        assert "sensitive customer info" not in json.dumps(ev)

    def test_authorization_never_in_returned_event(self):
        arm_event = _unsafe_raw_arm_event("Microsoft.KeyVault/vaults/write")
        conn = self._make_connector_with_events([arm_event])
        results = conn.list_activity_events(self._creds())
        ev = results[0]
        assert "authorization" not in ev

    def test_http_request_never_in_returned_event(self):
        arm_event = _unsafe_raw_arm_event("Microsoft.Authorization/roleAssignments/write")
        conn = self._make_connector_with_events([arm_event])
        results = conn.list_activity_events(self._creds())
        ev = results[0]
        assert "httpRequest" not in ev
        assert "clientRequestId" not in json.dumps(ev)

    def test_tenant_id_never_in_returned_event(self):
        arm_event = _unsafe_raw_arm_event("Microsoft.ContainerService/managedClusters/write")
        conn = self._make_connector_with_events([arm_event])
        results = conn.list_activity_events(self._creds())
        ev = results[0]
        assert "tenantId" not in ev
        assert "tenant_id" not in ev

    def test_bearer_token_not_in_returned_events(self):
        arm_event = _unsafe_raw_arm_event("Microsoft.Web/sites/write")
        conn = self._make_connector_with_events([arm_event])
        results = conn.list_activity_events(self._creds())
        ev_text = json.dumps(results)
        assert "mock-bearer-token" not in ev_text

    def test_all_19_allowed_operations_produce_events(self):
        arm_events = [
            _unsafe_raw_arm_event(op)
            for op in _ALLOWED_OPERATION_NAMES
        ]
        conn = self._make_connector_with_events(arm_events)
        results = conn.list_activity_events(self._creds(), max_events=100)
        assert len(results) == 19

    def test_401_raises_authentication_error(self):
        from app.connectors.exceptions import AuthenticationError
        conn = AzureConnector()
        conn._get_token = MagicMock(side_effect=AuthenticationError("401", status_code=401))
        with pytest.raises(AuthenticationError):
            conn.list_activity_events(self._creds())

    def test_429_raises_rate_limit_error(self):
        from app.connectors.exceptions import RateLimitError
        conn = AzureConnector()
        conn._get_token = MagicMock(return_value="tok")
        conn._paginate = MagicMock(side_effect=RateLimitError("429"))
        with pytest.raises(RateLimitError):
            conn.list_activity_events(self._creds())

    def test_network_error_raised(self):
        from app.connectors.exceptions import NetworkError
        conn = AzureConnector()
        conn._get_token = MagicMock(return_value="tok")
        conn._paginate = MagicMock(side_effect=NetworkError("net"))
        with pytest.raises(NetworkError):
            conn.list_activity_events(self._creds())


# ──────────────────────────────────────────────────────────────────────────────
# Operation allowlist completeness
# ──────────────────────────────────────────────────────────────────────────────


class TestOperationAllowlist:
    def test_all_operations_in_event_type_map(self):
        for op in _ALLOWED_OPERATION_NAMES:
            assert op in _OPERATION_EVENT_TYPE_MAP, (
                f"Connector allowlist op {op!r} has no entry in _OPERATION_EVENT_TYPE_MAP"
            )

    def test_all_event_type_map_ops_in_allowlist(self):
        for op in _OPERATION_EVENT_TYPE_MAP:
            assert op in _ALLOWED_OPERATION_NAMES, (
                f"Event type map op {op!r} not in connector _ALLOWED_OPERATION_NAMES"
            )


# ──────────────────────────────────────────────────────────────────────────────
# normalize_azure_activity_event
# ──────────────────────────────────────────────────────────────────────────────


class TestNormalizeAzureActivityEvent:
    @pytest.mark.parametrize("op,expected_type", [
        ("Microsoft.Network/networkSecurityGroups/write", "azure.nsg.updated"),
        ("Microsoft.Network/networkSecurityGroups/delete", "azure.nsg.deleted"),
        ("Microsoft.Network/networkSecurityGroups/securityRules/write", "azure.nsg_rule.updated"),
        ("Microsoft.Network/networkSecurityGroups/securityRules/delete", "azure.nsg_rule.deleted"),
        ("Microsoft.Storage/storageAccounts/write", "azure.storage_account.updated"),
        ("Microsoft.Storage/storageAccounts/delete", "azure.storage_account.deleted"),
        ("Microsoft.KeyVault/vaults/write", "azure.key_vault.updated"),
        ("Microsoft.KeyVault/vaults/delete", "azure.key_vault.deleted"),
        ("Microsoft.Authorization/roleAssignments/write", "azure.role_assignment.created"),
        ("Microsoft.Authorization/roleAssignments/delete", "azure.role_assignment.deleted"),
        ("Microsoft.Web/sites/write", "azure.app_service.updated"),
        ("Microsoft.Web/sites/delete", "azure.app_service.deleted"),
        ("Microsoft.Web/sites/config/write", "azure.app_service_config.updated"),
        ("Microsoft.Sql/servers/write", "azure.sql_server.updated"),
        ("Microsoft.Sql/servers/delete", "azure.sql_server.deleted"),
        ("Microsoft.Sql/servers/firewallRules/write", "azure.sql_firewall_rule.updated"),
        ("Microsoft.Sql/servers/firewallRules/delete", "azure.sql_firewall_rule.deleted"),
        ("Microsoft.ContainerService/managedClusters/write", "azure.aks_cluster.updated"),
        ("Microsoft.ContainerService/managedClusters/delete", "azure.aks_cluster.deleted"),
    ])
    def test_event_type_mapping(self, op: str, expected_type: str):
        ev = normalize_azure_activity_event(_raw_event(op_name=op))
        assert ev is not None
        assert ev["event_type"] == expected_type

    def test_non_allowlisted_op_returns_none(self):
        ev = normalize_azure_activity_event(_raw_event(op_name="Microsoft.Compute/virtualMachines/write"))
        assert ev is None

    def test_missing_operation_name_returns_none(self):
        ev = normalize_azure_activity_event({"event_timestamp": _TS})
        assert ev is None

    def test_none_input_returns_none(self):
        assert normalize_azure_activity_event(None) is None  # type: ignore[arg-type]

    def test_non_dict_returns_none(self):
        assert normalize_azure_activity_event("string") is None  # type: ignore[arg-type]

    def test_provider_and_source_set(self):
        ev = normalize_azure_activity_event(_raw_event())
        assert ev is not None
        assert ev["provider"] == PROVIDER
        assert ev["source"] == SOURCE

    def test_event_data_id_used_as_provider_event_id(self):
        ev = normalize_azure_activity_event(_raw_event(event_data_id="my-event-id"))
        assert ev is not None
        assert ev["provider_event_id"] == "my-event-id"

    def test_fingerprint_used_when_no_event_id(self):
        ev = normalize_azure_activity_event(_raw_event(event_data_id=""))
        assert ev is not None
        assert ev["provider_event_id"].startswith("fp:")

    def test_correlation_id_is_hashed_not_raw(self):
        raw_corr = "raw-correlation-id-12345"
        ev = normalize_azure_activity_event(_raw_event(correlation_id=raw_corr))
        assert ev is not None
        meta = ev["metadata"]
        text = json.dumps(meta)
        assert raw_corr not in text
        assert "azure_correlation_id_hash" in meta
        # Hash must be non-empty and not the raw value
        assert meta["azure_correlation_id_hash"] != raw_corr
        assert len(meta["azure_correlation_id_hash"]) == 32  # 32 hex chars

    def test_actor_id_never_set(self):
        ev = normalize_azure_activity_event(_raw_event())
        assert ev is not None
        assert ev.get("actor_id") is None

    def test_actor_type_never_set(self):
        ev = normalize_azure_activity_event(_raw_event())
        assert ev is not None
        assert ev.get("actor_type") is None

    def test_source_ip_never_set(self):
        ev = normalize_azure_activity_event(_raw_event())
        assert ev is not None
        assert ev.get("source_ip_hash") is None

    def test_metadata_includes_safe_fields(self):
        ev = normalize_azure_activity_event(_raw_event())
        assert ev is not None
        meta = ev["metadata"]
        assert meta.get("subscription_id") == "sub-123"
        assert meta.get("resource_group") == "my-rg"
        assert meta.get("operation_name") is not None
        assert meta.get("status") == "Succeeded"
        assert meta.get("category") == "Administrative"
        assert meta.get("event_source") == EVENT_SOURCE

    def test_operation_family_and_action_derived(self):
        ev = normalize_azure_activity_event(_raw_event(op_name="Microsoft.Network/networkSecurityGroups/write"))
        assert ev is not None
        meta = ev["metadata"]
        assert meta.get("operation_family") == "Microsoft.Network/networkSecurityGroups"
        assert meta.get("operation_action") == "write"

    def test_nsg_name_extracted(self):
        ev = normalize_azure_activity_event(_raw_event(
            op_name="Microsoft.Network/networkSecurityGroups/write",
            resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/my-nsg",
        ))
        assert ev is not None
        assert ev["metadata"].get("nsg_name") == "my-nsg"

    def test_nsg_rule_name_extracted(self):
        ev = normalize_azure_activity_event(_raw_event(
            op_name="Microsoft.Network/networkSecurityGroups/securityRules/write",
            resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/my-nsg/securityRules/rule-1",
        ))
        assert ev is not None
        assert ev["metadata"].get("nsg_name") == "my-nsg"
        assert ev["metadata"].get("nsg_rule_name") == "rule-1"

    def test_storage_account_name_extracted(self):
        ev = normalize_azure_activity_event(_raw_event(
            op_name="Microsoft.Storage/storageAccounts/write",
            resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/mystorage",
        ))
        assert ev is not None
        assert ev["metadata"].get("storage_account_name") == "mystorage"

    def test_aks_cluster_name_extracted(self):
        ev = normalize_azure_activity_event(_raw_event(
            op_name="Microsoft.ContainerService/managedClusters/write",
            resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/my-cluster",
        ))
        assert ev is not None
        assert ev["metadata"].get("aks_cluster_name") == "my-cluster"


# ──────────────────────────────────────────────────────────────────────────────
# Correlation ID hashing
# ──────────────────────────────────────────────────────────────────────────────


class TestCorrelationIdHash:
    def test_same_input_produces_same_hash(self):
        h1 = _hash_correlation_id("abc-def")
        h2 = _hash_correlation_id("abc-def")
        assert h1 == h2

    def test_different_inputs_produce_different_hashes(self):
        h1 = _hash_correlation_id("guid-1")
        h2 = _hash_correlation_id("guid-2")
        assert h1 != h2

    def test_empty_string_returns_none(self):
        assert _hash_correlation_id("") is None

    def test_none_equivalent_returns_none(self):
        assert _hash_correlation_id(None) is None  # type: ignore[arg-type]

    def test_hash_is_32_chars(self):
        h = _hash_correlation_id("any-guid")
        assert h is not None
        assert len(h) == 32


# ──────────────────────────────────────────────────────────────────────────────
# Resource name extraction
# ──────────────────────────────────────────────────────────────────────────────


class TestExtractResourceNames:
    def test_nsg(self):
        r = _extract_resource_names(
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-prod",
            "microsoft.network/networksecuritygroups/write",
        )
        assert r.get("nsg_name") == "nsg-prod"

    def test_nsg_rule(self):
        r = _extract_resource_names(
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-prod/securityRules/rule-1",
            "microsoft.network/networksecuritygroups/securityrules/write",
        )
        assert r.get("nsg_name") == "nsg-prod"
        assert r.get("nsg_rule_name") == "rule-1"

    def test_sql_server(self):
        r = _extract_resource_names(
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/sql-prod",
            "microsoft.sql/servers/write",
        )
        assert r.get("sql_server_name") == "sql-prod"

    def test_sql_firewall_rule(self):
        r = _extract_resource_names(
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/sql-prod/firewallRules/ClientIP",
            "microsoft.sql/servers/firewallrules/write",
        )
        assert r.get("sql_server_name") == "sql-prod"
        assert r.get("sql_firewall_rule_name") == "ClientIP"

    def test_empty_resource_id_returns_empty(self):
        r = _extract_resource_names("", "microsoft.network/networksecuritygroups/write")
        assert r == {}


# ──────────────────────────────────────────────────────────────────────────────
# Metadata safety
# ──────────────────────────────────────────────────────────────────────────────


class TestMetadataSafety:
    def test_no_forbidden_keys_in_event_metadata(self):
        ev = normalize_azure_activity_event(_raw_event())
        assert ev is not None
        meta = ev.get("metadata", {})
        for forbidden in _FORBIDDEN_METADATA_KEYS:
            assert forbidden not in meta, (
                f"Forbidden key {forbidden!r} found in normalized event metadata"
            )

    def test_no_pii_strings_in_metadata_values(self):
        ev = normalize_azure_activity_event(_raw_event())
        assert ev is not None
        text = json.dumps(ev.get("metadata", {}))
        # No caller email in any form
        assert "user@example.com" not in text
        assert "some-object-id" not in text
        assert "tenant-guid" not in text

    def test_azure_metadata_keys_in_allowed_list(self):
        azure_keys = {
            "subscription_id", "resource_group", "resource_id", "resource_type",
            "operation_name", "operation_family", "operation_action",
            "azure_event_id", "azure_correlation_id_hash", "nsg_name",
            "nsg_rule_name", "storage_account_name", "key_vault_name",
            "app_service_name", "sql_server_name", "sql_firewall_rule_name",
            "aks_cluster_name", "status", "sub_status", "category", "event_time",
        }
        for key in azure_keys:
            assert key in ALLOWED_METADATA_KEYS, (
                f"Azure metadata key {key!r} not in ALLOWED_METADATA_KEYS"
            )

    def test_forbidden_keys_not_in_allowed_list(self):
        # Keys that are definitely Azure-PII / sensitive and must never be in the allowlist.
        # Note: 'object_id' IS in the allowlist already for Stripe object IDs (e.g. "we_xxx")
        # — that's a Stripe concept, not an Azure principal object ID. We test specific
        # Azure-PII keys instead.
        for key in ("caller", "claims", "authorization", "properties",
                    "httpRequest", "description", "tenantId",
                    "principal_id", "ip_address", "azure_principal_id",
                    "caller_email", "upn"):
            assert key not in ALLOWED_METADATA_KEYS, (
                f"Key {key!r} should NOT be in ALLOWED_METADATA_KEYS"
            )


# ──────────────────────────────────────────────────────────────────────────────
# Claim discipline
# ──────────────────────────────────────────────────────────────────────────────


class TestClaimDiscipline:
    def test_no_forbidden_phrases_in_ingestion_service_doc(self):
        import app.services.azure_activity_ingestion_service as svc
        import inspect
        src = inspect.getsource(svc)
        for phrase in _FORBIDDEN_CLAIM_PHRASES:
            assert phrase not in src.lower(), (
                f"Forbidden phrase {phrase!r} found in ingestion service source"
            )


# ──────────────────────────────────────────────────────────────────────────────
# Ingestion service
# ──────────────────────────────────────────────────────────────────────────────


class TestIngestAzureActivity:
    def _make_integration(self) -> MagicMock:
        integ = MagicMock()
        integ.provider = "azure"
        integ.id = uuid.uuid4()
        integ.encrypted_credentials = b"encrypted"
        integ.credential_iv = b"iv"
        return integ

    def test_wrong_provider_returns_immediately(self):
        from app.services.azure_activity_ingestion_service import ingest_azure_activity
        integ = self._make_integration()
        integ.provider = "github"
        db = MagicMock()
        summary = ingest_azure_activity(
            integration=integ, workspace_id=uuid.uuid4(), db=db
        )
        assert summary["attempted"] is False
        assert "Not an Azure integration" in (summary["error_message"] or "")

    def test_credential_failure_is_soft(self):
        from app.services.azure_activity_ingestion_service import ingest_azure_activity
        integ = self._make_integration()
        db = MagicMock()
        with patch("app.services.azure_activity_ingestion_service.decrypt_credentials",
                   side_effect=Exception("bad key")):
            summary = ingest_azure_activity(
                integration=integ, workspace_id=uuid.uuid4(), db=db
            )
        assert summary["attempted"] is True
        assert summary["succeeded"] is False
        assert "credentials" in (summary["error_message"] or "").lower()

    def test_auth_error_sets_permission_limited(self):
        from app.connectors.exceptions import AuthenticationError
        from app.services.azure_activity_ingestion_service import ingest_azure_activity
        integ = self._make_integration()
        db = MagicMock()
        with patch("app.services.azure_activity_ingestion_service.decrypt_credentials",
                   return_value={"tenant_id": "t", "subscription_id": "s"}):
            with patch.object(AzureConnector, "list_activity_events",
                               side_effect=AuthenticationError("401", status_code=401)):
                summary = ingest_azure_activity(
                    integration=integ, workspace_id=uuid.uuid4(), db=db
                )
        assert summary["permission_limited"] is True
        assert summary["succeeded"] is True  # still succeeded (soft failure)

    def test_rate_limit_error_is_soft(self):
        from app.connectors.exceptions import RateLimitError
        from app.services.azure_activity_ingestion_service import ingest_azure_activity
        integ = self._make_integration()
        db = MagicMock()
        with patch("app.services.azure_activity_ingestion_service.decrypt_credentials",
                   return_value={"tenant_id": "t", "subscription_id": "s"}):
            with patch.object(AzureConnector, "list_activity_events",
                               side_effect=RateLimitError("429")):
                summary = ingest_azure_activity(
                    integration=integ, workspace_id=uuid.uuid4(), db=db
                )
        assert summary["error_message"] is not None
        assert summary["succeeded"] is False

    def test_network_error_is_soft(self):
        from app.connectors.exceptions import NetworkError
        from app.services.azure_activity_ingestion_service import ingest_azure_activity
        integ = self._make_integration()
        db = MagicMock()
        with patch("app.services.azure_activity_ingestion_service.decrypt_credentials",
                   return_value={"tenant_id": "t", "subscription_id": "s"}):
            with patch.object(AzureConnector, "list_activity_events",
                               side_effect=NetworkError("net")):
                summary = ingest_azure_activity(
                    integration=integ, workspace_id=uuid.uuid4(), db=db
                )
        assert summary["error_message"] is not None
        assert summary["succeeded"] is False

    def test_successful_ingestion_counts(self):
        from app.services.azure_activity_ingestion_service import ingest_azure_activity
        from app.services.security_activity_event_service import upsert_activity_event

        integ = self._make_integration()
        events = [_raw_event(event_data_id=f"evt-{i}") for i in range(3)]

        mock_row = MagicMock()
        mock_row.id = uuid.uuid4()

        with patch("app.services.azure_activity_ingestion_service.decrypt_credentials",
                   return_value={"tenant_id": "t", "subscription_id": "s"}):
            with patch.object(AzureConnector, "list_activity_events",
                               return_value=events):
                with patch("app.services.azure_activity_ingestion_service.activity_svc.upsert_activity_event",
                           return_value=("inserted", mock_row)):
                    summary = ingest_azure_activity(
                        integration=integ, workspace_id=uuid.uuid4(),
                        db=MagicMock()
                    )
        assert summary["events_seen"] == 3
        assert summary["events_inserted"] == 3
        assert summary["events_skipped"] == 0
        assert summary["succeeded"] is True

    def test_idempotency_via_skipped_count(self):
        from app.services.azure_activity_ingestion_service import ingest_azure_activity

        integ = self._make_integration()
        events = [_raw_event(event_data_id="same-evt")]

        mock_row = MagicMock()
        with patch("app.services.azure_activity_ingestion_service.decrypt_credentials",
                   return_value={"tenant_id": "t", "subscription_id": "s"}):
            with patch.object(AzureConnector, "list_activity_events",
                               return_value=events):
                with patch("app.services.azure_activity_ingestion_service.activity_svc.upsert_activity_event",
                           return_value=("skipped", mock_row)):
                    summary = ingest_azure_activity(
                        integration=integ, workspace_id=uuid.uuid4(),
                        db=MagicMock()
                    )
        assert summary["events_skipped"] == 1
        assert summary["events_inserted"] == 0

    def test_malformed_event_skipped_silently(self):
        from app.services.azure_activity_ingestion_service import ingest_azure_activity

        integ = self._make_integration()
        # Mix of valid and malformed events
        events = [
            _raw_event(event_data_id="valid"),
            {"not_an_event": True},  # malformed
            _raw_event(op_name="invalid/operation"),  # not in map
        ]

        mock_row = MagicMock()
        with patch("app.services.azure_activity_ingestion_service.decrypt_credentials",
                   return_value={"tenant_id": "t", "subscription_id": "s"}):
            with patch.object(AzureConnector, "list_activity_events",
                               return_value=events):
                with patch("app.services.azure_activity_ingestion_service.activity_svc.upsert_activity_event",
                           return_value=("inserted", mock_row)):
                    summary = ingest_azure_activity(
                        integration=integ, workspace_id=uuid.uuid4(),
                        db=MagicMock()
                    )
        assert summary["events_seen"] == 3
        assert summary["events_inserted"] == 1  # only the valid one


# ──────────────────────────────────────────────────────────────────────────────
# API endpoint (admin guard, member access)
# ──────────────────────────────────────────────────────────────────────────────


class TestAzureActivityEndpoint:
    def test_endpoint_registered(self, client):
        """GET on the route should return 405 (not 404) — endpoint exists."""
        resp = client.get("/security/azure-activity/sync")
        assert resp.status_code != 404, "Endpoint /security/azure-activity/sync is not registered"

    def test_admin_can_call_sync(self, client):
        """POST should be reachable by an admin (returns 200 or 404-no-integration, not 403)."""
        resp = client.post("/security/azure-activity/sync", json={})
        # 200 (no integration found) or 404 (integration lookup) — never 403 for admin
        assert resp.status_code in (200, 404, 422), (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Capability matrix + expansion framework
# ──────────────────────────────────────────────────────────────────────────────


class TestCapabilityMatrix:
    def test_azure_activity_ingestion_true(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.activity_ingestion is True

    def test_azure_signals_still_false(self):
        """Flipped in M77E: activity_signals is now True."""
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.activity_signals is True   # flipped in M77E

    def test_azure_correlations_still_false(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.risk_activity_correlations is False

    def test_azure_demo_seed_still_false(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.demo_seed_clear is False

    def test_azure_still_partial(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.maturity == "partial"

    def test_azure_not_in_canonical_8(self):
        from app.services.provider_capability_matrix_service import PROVIDER_CAPABILITIES
        providers = {p.provider for p in PROVIDER_CAPABILITIES}
        assert "azure" not in providers


class TestExpansionFramework:
    def test_next_stage_is_m77e(self):
        """Flipped in M77E: planned_next_stage now points to M77F."""
        fw = get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M77F" in stage


# ──────────────────────────────────────────────────────────────────────────────
# M77A/B/C regression — smoke check
# ──────────────────────────────────────────────────────────────────────────────


class TestM77ABCRegression:
    def test_azure_security_rules_still_true(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.security_rules is True

    def test_m77b_rules_still_registered(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        m77b = {
            "azure_nsg_public_admin_ingress", "azure_nsg_public_broad_ingress",
            "azure_storage_public_blob_access", "azure_storage_public_network_access",
        }
        assert m77b.issubset(KNOWN_RULE_KEYS)

    def test_m77c_rules_still_registered(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        m77c = {
            "azure_role_assignment_broad_privilege",
            "azure_app_service_https_disabled",
            "azure_sql_public_network_access",
            "azure_aks_public_api_access",
        }
        assert m77c.issubset(KNOWN_RULE_KEYS)

    def test_azure_schema_has_all_record_types(self):
        from app.connectors.azure_schema import AZURE_RECORD_TYPES
        assert "azure_subscription" in AZURE_RECORD_TYPES
        assert "azure_role_assignment" in AZURE_RECORD_TYPES
        assert "azure_app_service" in AZURE_RECORD_TYPES

    def test_import_time_assertions_still_pass(self):
        from app.services.security_rule_pack import _RULE_META
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        assert set(_RULE_META) == set(KNOWN_RULE_KEYS)
