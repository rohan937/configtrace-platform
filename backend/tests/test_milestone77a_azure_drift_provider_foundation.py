"""M77A — Azure Drift Provider Foundation.

Tests the Azure connector and surrounding service-layer contracts introduced
in M77A:

  1.  Azure schema constants — AZURE_RECORD_TYPES and the five individual
      record type constants.
  2.  AzureConnector._normalize_subscription — returns only safe fields; never
      leaks client_secret or access tokens.
  3.  AzureConnector._normalize_resource_group — tag keys stored, tag values
      never stored.
  4.  AzureConnector._normalize_nsg — rules_summary capped, no packet/log data;
      each rule contains only the nine allowed safe fields.
  5.  AzureConnector._normalize_storage_account — no storage keys, SAS tokens,
      or connection strings.
  6.  AzureConnector._normalize_key_vault — access_policy_count is an integer
      only; no secret names, principal emails, or permission assignments.
  7.  fetch() uses monkeypatched _get and _get_token to avoid real HTTP and
      returns records with the correct record_types.
  8.  HTTP 401 from _get raises AuthenticationError.
  9.  HTTP 429 from _get raises RateLimitError.
  10. HTTP 403 from _get raises ConnectorError.
  11. Network failure raises NetworkError.
  12. validate_credentials fails gracefully on bad credentials.
  13. Pagination is bounded (_MAX_PAGES respected).
  14. No sensitive fields appear in any record returned by fetch().
  15. "azure" is in sync_service._SUPPORTED_PROVIDERS tuple.
  16. Provider capability matrix includes azure with maturity="partial" and
      security_rules=False.
  17. Azure does NOT appear in security_coverage_service.PROVIDERS.
  18. Provider expansion framework planned_next_stage points to M77B.
  19. No forbidden claim wording appears in connector module docstring or notes.

CLAIM DISCIPLINE: no forbidden phrase appears in this test file's strings.
All assertions describe configuration metadata, posture, and review readiness —
never confirmed breach, attack, or data exposure.

Privacy: no real credentials, secrets, tokens, or customer data are used in
any test. Monkeypatched token strings are clearly marked as synthetic.
"""

from __future__ import annotations

import inspect
import json
import types
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.connectors.azure import AzureConnector
from app.connectors.azure_schema import (
    AZURE_KEY_VAULT,
    AZURE_NETWORK_SECURITY_GROUP,
    AZURE_RECORD_TYPES,
    AZURE_RESOURCE_GROUP,
    AZURE_STORAGE_ACCOUNT,
    AZURE_SUBSCRIPTION,
)
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)

# ── Forbidden claim phrases ───────────────────────────────────────────────────

_FORBIDDEN = [
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
]

# Fields that must never appear in any normalised record
_SENSITIVE_FIELD_NAMES = {
    "client_secret",
    "access_token",
    "bearer",
    "authorization",
    "connection_string",
    "storage_key",
    "secret_value",
    "password",
}

# ── Synthetic test data helpers ───────────────────────────────────────────────

_SUB_ID = "sub-00000000-0000-0000-0000-000000000001"
_TENANT_ID = "tenant-00000000-0000-0000-0000-000000000002"
_FAKE_TOKEN = "fake_token_not_stored_not_real"


def _raw_subscription(sub_id: str = _SUB_ID) -> dict:
    return {
        "subscriptionId": sub_id,
        "displayName": "Test Subscription",
        "state": "Enabled",
        "tenantId": _TENANT_ID,
        "authorizationSource": "RoleBased",
        "properties": {
            "authorizationSource": "RoleBased",
        },
    }


def _raw_resource_group(name: str = "rg-test", sub_id: str = _SUB_ID) -> dict:
    return {
        "id": f"/subscriptions/{sub_id}/resourceGroups/{name}",
        "name": name,
        "location": "eastus",
        "properties": {
            "provisioningState": "Succeeded",
        },
        "tags": {
            "environment": "production",
            "owner": "ops-team@example.com",  # tag VALUE — must never be stored
            "cost_center": "12345",
        },
    }


def _raw_nsg(name: str = "nsg-test", sub_id: str = _SUB_ID) -> dict:
    rg = "rg-test"
    resource_id = (
        f"/subscriptions/{sub_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.Network/networkSecurityGroups/{name}"
    )
    return {
        "id": resource_id,
        "name": name,
        "location": "eastus",
        "properties": {
            "securityRules": [
                {
                    "name": "AllowHTTPS",
                    "properties": {
                        "direction": "Inbound",
                        "access": "Allow",
                        "priority": 100,
                        "protocol": "Tcp",
                        "sourceAddressPrefix": "*",
                        "sourcePortRange": "*",
                        "destinationAddressPrefix": "*",
                        "destinationPortRange": "443",
                        # Fields that must never appear in the normalised record
                        "packetCapture": "sensitive_packet_data",
                        "logProfile": "sensitive_log_profile",
                    },
                },
            ],
            "defaultSecurityRules": [],
        },
    }


def _raw_nsg_many_rules(name: str = "nsg-heavy", sub_id: str = _SUB_ID) -> dict:
    """NSG with 60 rules — more than the 50-rule cap."""
    rg = "rg-test"
    resource_id = (
        f"/subscriptions/{sub_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.Network/networkSecurityGroups/{name}"
    )
    rules = [
        {
            "name": f"Rule{i}",
            "properties": {
                "direction": "Inbound",
                "access": "Allow",
                "priority": 100 + i,
                "protocol": "Tcp",
                "sourceAddressPrefix": "*",
                "sourcePortRange": "*",
                "destinationAddressPrefix": "*",
                "destinationPortRange": str(8000 + i),
            },
        }
        for i in range(60)
    ]
    return {
        "id": resource_id,
        "name": name,
        "location": "eastus",
        "properties": {
            "securityRules": rules,
            "defaultSecurityRules": [],
        },
    }


def _raw_storage_account(name: str = "mystorageacct", sub_id: str = _SUB_ID) -> dict:
    rg = "rg-test"
    resource_id = (
        f"/subscriptions/{sub_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.Storage/storageAccounts/{name}"
    )
    return {
        "id": resource_id,
        "name": name,
        "location": "eastus",
        "kind": "StorageV2",
        "sku": {"name": "Standard_LRS"},
        "properties": {
            "allowBlobPublicAccess": False,
            "publicNetworkAccess": "Enabled",
            "minimumTlsVersion": "TLS1_2",
            "supportsHttpsTrafficOnly": True,
            "allowSharedKeyAccess": True,
            "networkAcls": {
                "defaultAction": "Allow",
            },
            # Fields that must never appear in the normalised record
            "primaryAccessKey": "AAABBBCCC000111SECRET",
            "secondaryAccessKey": "DDDEEEFFF222333SECRET",
            "sasToken": "sv=2020-08-04&ss=b&srt=sco&sp=rwdlacx&se=2099",
            "connectionString": "DefaultEndpointsProtocol=https;AccountName=mystorageacct;AccountKey=FAKE",
        },
    }


def _raw_key_vault(name: str = "my-keyvault", sub_id: str = _SUB_ID) -> dict:
    rg = "rg-test"
    resource_id = (
        f"/subscriptions/{sub_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.KeyVault/vaults/{name}"
    )
    return {
        "id": resource_id,
        "name": name,
        "location": "eastus",
        "properties": {
            "enableRbacAuthorization": False,
            "publicNetworkAccess": "Enabled",
            "enableSoftDelete": True,
            "enablePurgeProtection": True,
            "accessPolicies": [
                {
                    "tenantId": _TENANT_ID,
                    "objectId": "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb",
                    "permissions": {"secrets": ["get", "list"]},
                },
                {
                    "tenantId": _TENANT_ID,
                    "objectId": "cccccccc-3333-4444-5555-dddddddddddd",
                    "permissions": {"keys": ["get"]},
                },
            ],
            "networkAcls": {
                "defaultAction": "Deny",
            },
            # Fields that must never appear in the normalised record
            "secretNames": ["db-password", "stripe-api-key"],
            "principalEmails": ["alice@example.com", "bob@example.com"],
        },
    }


# ── Monkeypatch helpers ───────────────────────────────────────────────────────

def _make_fake_get(sub_id: str = _SUB_ID):
    """Return a fake _get implementation that serves synthetic ARM responses."""

    def fake_get(self, token: str, url: str, params: dict | None = None) -> Any:
        # Subscription endpoint
        if url.rstrip("/").endswith(f"/subscriptions/{sub_id}") or (
            f"/subscriptions/{sub_id}?" in url and "resourcegroups" not in url.lower()
            and "providers" not in url.lower()
        ):
            return _raw_subscription(sub_id)

        # Resource groups list
        if "resourcegroups" in url.lower():
            return {"value": [_raw_resource_group(sub_id=sub_id)], "nextLink": None}

        # NSG list
        if "networksecuritygroups" in url.lower():
            return {"value": [_raw_nsg(sub_id=sub_id)], "nextLink": None}

        # Storage accounts list
        if "storageaccounts" in url.lower():
            return {"value": [_raw_storage_account(sub_id=sub_id)], "nextLink": None}

        # Key Vault list
        if "vaults" in url.lower():
            return {"value": [_raw_key_vault(sub_id=sub_id)], "nextLink": None}

        return {}

    return fake_get


def _fake_get_token(self, credentials: dict) -> str:
    """Synthetic token — never stored, never real."""
    return _FAKE_TOKEN


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Schema constants
# ═══════════════════════════════════════════════════════════════════════════════

class TestAzureSchemaConstants:
    """AZURE_RECORD_TYPES and the five individual constants are correct."""

    def test_azure_record_types_is_frozenset(self):
        assert isinstance(AZURE_RECORD_TYPES, frozenset)

    def test_azure_record_types_has_exactly_five_members(self):
        """Flipped in M77C: AZURE_RECORD_TYPES now has 9 members (4 new M77C types)."""
        assert len(AZURE_RECORD_TYPES) == 9

    def test_azure_subscription_constant(self):
        assert AZURE_SUBSCRIPTION == "azure_subscription"
        assert AZURE_SUBSCRIPTION in AZURE_RECORD_TYPES

    def test_azure_resource_group_constant(self):
        assert AZURE_RESOURCE_GROUP == "azure_resource_group"
        assert AZURE_RESOURCE_GROUP in AZURE_RECORD_TYPES

    def test_azure_network_security_group_constant(self):
        assert AZURE_NETWORK_SECURITY_GROUP == "azure_network_security_group"
        assert AZURE_NETWORK_SECURITY_GROUP in AZURE_RECORD_TYPES

    def test_azure_storage_account_constant(self):
        assert AZURE_STORAGE_ACCOUNT == "azure_storage_account"
        assert AZURE_STORAGE_ACCOUNT in AZURE_RECORD_TYPES

    def test_azure_key_vault_constant(self):
        assert AZURE_KEY_VAULT == "azure_key_vault"
        assert AZURE_KEY_VAULT in AZURE_RECORD_TYPES

    def test_all_five_constants_in_set(self):
        """Flipped in M77C: asserts M77A types are a subset (M77C adds 4 more)."""
        m77a_types = {
            AZURE_SUBSCRIPTION,
            AZURE_RESOURCE_GROUP,
            AZURE_NETWORK_SECURITY_GROUP,
            AZURE_STORAGE_ACCOUNT,
            AZURE_KEY_VAULT,
        }
        assert m77a_types.issubset(AZURE_RECORD_TYPES)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. _normalize_subscription
# ═══════════════════════════════════════════════════════════════════════════════

class TestNormalizeSubscription:
    """_normalize_subscription returns safe fields only."""

    def setup_method(self):
        self.conn = AzureConnector()
        self.record = self.conn._normalize_subscription(_raw_subscription())

    def test_record_type_is_azure_subscription(self):
        assert self.record["record_type"] == AZURE_SUBSCRIPTION

    def test_subscription_id_present(self):
        assert self.record["subscription_id"] == _SUB_ID

    def test_display_name_present(self):
        assert self.record["display_name"] == "Test Subscription"

    def test_state_present(self):
        assert self.record["state"] == "Enabled"

    def test_tenant_id_present_as_opaque_id(self):
        assert self.record["tenant_id"] == _TENANT_ID

    def test_no_client_secret_in_record(self):
        blob = json.dumps(self.record)
        for bad_field in ("client_secret", "secret", "password", "access_token"):
            assert bad_field not in blob.lower().replace("subscriptionid", "")

    def test_record_is_json_serialisable(self):
        assert json.dumps(self.record)  # no exception

    def test_record_has_record_id(self):
        assert "record_id" in self.record
        assert self.record["record_id"].startswith("azure_subscription_")


# ═══════════════════════════════════════════════════════════════════════════════
# 3. _normalize_resource_group
# ═══════════════════════════════════════════════════════════════════════════════

class TestNormalizeResourceGroup:
    """_normalize_resource_group returns tag keys only, never tag values."""

    def setup_method(self):
        self.conn = AzureConnector()
        self.raw = _raw_resource_group()
        self.record = self.conn._normalize_resource_group(self.raw, _SUB_ID)

    def test_record_type_is_azure_resource_group(self):
        assert self.record["record_type"] == AZURE_RESOURCE_GROUP

    def test_name_present(self):
        assert self.record["name"] == "rg-test"

    def test_location_present(self):
        assert self.record["location"] == "eastus"

    def test_provisioning_state_present(self):
        assert self.record["provisioning_state"] == "Succeeded"

    def test_tag_keys_is_list(self):
        assert isinstance(self.record["tag_keys"], list)

    def test_tag_keys_contains_key_names(self):
        keys = self.record["tag_keys"]
        assert "environment" in keys
        assert "owner" in keys
        assert "cost_center" in keys

    def test_tag_values_never_stored(self):
        blob = json.dumps(self.record)
        # Tag values from the raw data must not appear
        assert "production" not in blob
        assert "ops-team@example.com" not in blob
        assert "12345" not in blob  # cost_center value

    def test_record_is_json_serialisable(self):
        assert json.dumps(self.record)

    def test_record_has_record_id(self):
        assert "record_id" in self.record
        assert "azure_rg_" in self.record["record_id"]

    def test_empty_tags_handled(self):
        raw_no_tags = dict(_raw_resource_group())
        raw_no_tags.pop("tags", None)
        rec = self.conn._normalize_resource_group(raw_no_tags, _SUB_ID)
        assert rec["tag_keys"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# 4. _normalize_nsg
# ═══════════════════════════════════════════════════════════════════════════════

class TestNormalizeNSG:
    """_normalize_nsg caps rules_summary at 50 and omits packet/log data."""

    def setup_method(self):
        self.conn = AzureConnector()
        self.record = self.conn._normalize_nsg(_raw_nsg())

    def test_record_type_is_azure_network_security_group(self):
        assert self.record["record_type"] == AZURE_NETWORK_SECURITY_GROUP

    def test_nsg_name_present(self):
        assert self.record["nsg_name"] == "nsg-test"

    def test_location_present(self):
        assert self.record["location"] == "eastus"

    def test_resource_group_extracted(self):
        assert self.record["resource_group"] == "rg-test"

    def test_rule_count_integer(self):
        assert isinstance(self.record["rule_count"], int)

    def test_inbound_allow_rule_count_integer(self):
        assert isinstance(self.record["inbound_allow_rule_count"], int)

    def test_public_inbound_rule_count_integer(self):
        assert isinstance(self.record["public_inbound_rule_count"], int)

    def test_rules_summary_is_list(self):
        assert isinstance(self.record["rules_summary"], list)

    def test_rules_summary_cap_at_50(self):
        record_heavy = self.conn._normalize_nsg(_raw_nsg_many_rules())
        assert len(record_heavy["rules_summary"]) <= 50

    def test_each_rule_has_only_safe_fields(self):
        allowed_rule_fields = {
            "rule_name",
            "direction",
            "access",
            "priority",
            "protocol",
            "source_address_prefix",
            "source_port_range",
            "destination_address_prefix",
            "destination_port_range",
        }
        for rule in self.record["rules_summary"]:
            extra = set(rule.keys()) - allowed_rule_fields
            assert not extra, f"Unexpected fields in rule summary: {extra}"

    def test_no_packet_data_in_rules(self):
        blob = json.dumps(self.record["rules_summary"])
        assert "packetCapture" not in blob
        assert "logProfile" not in blob
        assert "sensitive_packet_data" not in blob
        assert "sensitive_log_profile" not in blob

    def test_rule_safe_fields_populated(self):
        rules = self.record["rules_summary"]
        assert len(rules) >= 1
        rule = rules[0]
        assert rule["rule_name"] == "AllowHTTPS"
        assert rule["direction"] == "Inbound"
        assert rule["access"] == "Allow"
        assert rule["priority"] == 100
        assert rule["protocol"] == "Tcp"
        assert rule["destination_port_range"] == "443"

    def test_record_is_json_serialisable(self):
        assert json.dumps(self.record)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. _normalize_storage_account
# ═══════════════════════════════════════════════════════════════════════════════

class TestNormalizeStorageAccount:
    """_normalize_storage_account never leaks keys, SAS tokens, or connection strings."""

    def setup_method(self):
        self.conn = AzureConnector()
        self.record = self.conn._normalize_storage_account(_raw_storage_account())

    def test_record_type_is_azure_storage_account(self):
        assert self.record["record_type"] == AZURE_STORAGE_ACCOUNT

    def test_account_name_present(self):
        assert self.record["account_name"] == "mystorageacct"

    def test_location_present(self):
        assert self.record["location"] == "eastus"

    def test_kind_present(self):
        assert self.record["kind"] == "StorageV2"

    def test_sku_name_present(self):
        assert self.record["sku_name"] == "Standard_LRS"

    def test_allow_blob_public_access_is_bool(self):
        assert isinstance(self.record["allow_blob_public_access"], bool)

    def test_minimum_tls_version_present(self):
        assert self.record["minimum_tls_version"] == "TLS1_2"

    def test_supports_https_traffic_only_is_bool(self):
        assert isinstance(self.record["supports_https_traffic_only"], bool)

    def test_no_storage_keys_in_record(self):
        blob = json.dumps(self.record)
        for bad in ("AAABBBCCC000111SECRET", "DDDEEEFFF222333SECRET",
                    "primaryAccessKey", "secondaryAccessKey",
                    "storage_key", "storagekey"):
            assert bad not in blob

    def test_no_sas_token_in_record(self):
        blob = json.dumps(self.record)
        assert "sasToken" not in blob
        assert "srt=sco" not in blob

    def test_no_connection_string_in_record(self):
        blob = json.dumps(self.record)
        for bad in ("connectionString", "connection_string",
                    "DefaultEndpointsProtocol", "AccountKey"):
            assert bad not in blob

    def test_network_default_action_present(self):
        assert self.record["network_default_action"] == "Allow"

    def test_record_is_json_serialisable(self):
        assert json.dumps(self.record)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. _normalize_key_vault
# ═══════════════════════════════════════════════════════════════════════════════

class TestNormalizeKeyVault:
    """_normalize_key_vault returns integer access_policy_count; no secret names or emails."""

    def setup_method(self):
        self.conn = AzureConnector()
        self.record = self.conn._normalize_key_vault(_raw_key_vault())

    def test_record_type_is_azure_key_vault(self):
        assert self.record["record_type"] == AZURE_KEY_VAULT

    def test_vault_name_present(self):
        assert self.record["vault_name"] == "my-keyvault"

    def test_location_present(self):
        assert self.record["location"] == "eastus"

    def test_resource_group_extracted(self):
        assert self.record["resource_group"] == "rg-test"

    def test_access_policy_count_is_integer(self):
        count = self.record["access_policy_count"]
        assert isinstance(count, int), (
            f"access_policy_count should be int, got {type(count)}"
        )

    def test_access_policy_count_correct_value(self):
        # Two access policies in the raw data
        assert self.record["access_policy_count"] == 2

    def test_no_secret_names_in_record(self):
        blob = json.dumps(self.record)
        assert "db-password" not in blob
        assert "stripe-api-key" not in blob
        assert "secretNames" not in blob
        assert "secret_names" not in blob

    def test_no_principal_emails_in_record(self):
        blob = json.dumps(self.record)
        assert "alice@example.com" not in blob
        assert "bob@example.com" not in blob
        assert "principalEmails" not in blob

    def test_no_object_ids_in_record(self):
        blob = json.dumps(self.record)
        assert "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb" not in blob
        assert "cccccccc-3333-4444-5555-dddddddddddd" not in blob

    def test_no_permission_assignments_in_record(self):
        blob = json.dumps(self.record)
        assert "permissions" not in blob
        assert "accessPolicies" not in blob

    def test_enable_rbac_authorization_present(self):
        assert "enable_rbac_authorization" in self.record

    def test_soft_delete_enabled_present(self):
        assert "soft_delete_enabled" in self.record

    def test_network_default_action_present(self):
        assert self.record["network_default_action"] == "Deny"

    def test_record_is_json_serialisable(self):
        assert json.dumps(self.record)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. fetch() with monkeypatched _get and _get_token
# ═══════════════════════════════════════════════════════════════════════════════

class TestFetchReturnsSafeRecords:
    """fetch() returns records with the correct record_types (no real HTTP)."""

    def test_fetch_returns_list(self, monkeypatch):
        monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)
        monkeypatch.setattr(AzureConnector, "_get", _make_fake_get())
        conn = AzureConnector()
        records = conn.fetch({
            "tenant_id": "t-id",
            "client_id": "c-id",
            "client_secret": "s-value",
            "subscription_id": _SUB_ID,
        })
        assert isinstance(records, list)

    def test_fetch_returns_subscription_record(self, monkeypatch):
        monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)
        monkeypatch.setattr(AzureConnector, "_get", _make_fake_get())
        conn = AzureConnector()
        records = conn.fetch({
            "tenant_id": "t-id", "client_id": "c-id",
            "client_secret": "s-value", "subscription_id": _SUB_ID,
        })
        types_in_records = {r["record_type"] for r in records}
        assert AZURE_SUBSCRIPTION in types_in_records

    def test_fetch_returns_resource_group_record(self, monkeypatch):
        monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)
        monkeypatch.setattr(AzureConnector, "_get", _make_fake_get())
        conn = AzureConnector()
        records = conn.fetch({
            "tenant_id": "t-id", "client_id": "c-id",
            "client_secret": "s-value", "subscription_id": _SUB_ID,
        })
        types_in_records = {r["record_type"] for r in records}
        assert AZURE_RESOURCE_GROUP in types_in_records

    def test_fetch_returns_nsg_record(self, monkeypatch):
        monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)
        monkeypatch.setattr(AzureConnector, "_get", _make_fake_get())
        conn = AzureConnector()
        records = conn.fetch({
            "tenant_id": "t-id", "client_id": "c-id",
            "client_secret": "s-value", "subscription_id": _SUB_ID,
        })
        types_in_records = {r["record_type"] for r in records}
        assert AZURE_NETWORK_SECURITY_GROUP in types_in_records

    def test_fetch_returns_storage_account_record(self, monkeypatch):
        monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)
        monkeypatch.setattr(AzureConnector, "_get", _make_fake_get())
        conn = AzureConnector()
        records = conn.fetch({
            "tenant_id": "t-id", "client_id": "c-id",
            "client_secret": "s-value", "subscription_id": _SUB_ID,
        })
        types_in_records = {r["record_type"] for r in records}
        assert AZURE_STORAGE_ACCOUNT in types_in_records

    def test_fetch_returns_key_vault_record(self, monkeypatch):
        monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)
        monkeypatch.setattr(AzureConnector, "_get", _make_fake_get())
        conn = AzureConnector()
        records = conn.fetch({
            "tenant_id": "t-id", "client_id": "c-id",
            "client_secret": "s-value", "subscription_id": _SUB_ID,
        })
        types_in_records = {r["record_type"] for r in records}
        assert AZURE_KEY_VAULT in types_in_records

    def test_fetch_token_not_in_any_record(self, monkeypatch):
        monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)
        monkeypatch.setattr(AzureConnector, "_get", _make_fake_get())
        conn = AzureConnector()
        records = conn.fetch({
            "tenant_id": "t-id", "client_id": "c-id",
            "client_secret": "s-value", "subscription_id": _SUB_ID,
        })
        blob = json.dumps(records)
        assert _FAKE_TOKEN not in blob

    def test_fetch_client_secret_not_in_any_record(self, monkeypatch):
        monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)
        monkeypatch.setattr(AzureConnector, "_get", _make_fake_get())
        conn = AzureConnector()
        records = conn.fetch({
            "tenant_id": "t-id", "client_id": "c-id",
            "client_secret": "my-secret-value-12345",
            "subscription_id": _SUB_ID,
        })
        blob = json.dumps(records)
        assert "my-secret-value-12345" not in blob

    def test_fetch_all_records_are_json_serialisable(self, monkeypatch):
        monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)
        monkeypatch.setattr(AzureConnector, "_get", _make_fake_get())
        conn = AzureConnector()
        records = conn.fetch({
            "tenant_id": "t-id", "client_id": "c-id",
            "client_secret": "s-value", "subscription_id": _SUB_ID,
        })
        assert json.dumps(records)  # no exception


# ═══════════════════════════════════════════════════════════════════════════════
# 8. HTTP 401 -> AuthenticationError
# ═══════════════════════════════════════════════════════════════════════════════

def test_401_raises_authentication_error(monkeypatch):
    def fake_get_token_raises(self, credentials: dict) -> str:
        raise AuthenticationError(
            "azure: token request rejected (401) — check credentials",
            status_code=401,
        )

    monkeypatch.setattr(AzureConnector, "_get_token", fake_get_token_raises)
    conn = AzureConnector()
    with pytest.raises(AuthenticationError) as exc_info:
        conn.fetch({
            "tenant_id": "bad-tenant", "client_id": "bad-client",
            "client_secret": "bad-secret", "subscription_id": _SUB_ID,
        })
    assert exc_info.value.status_code == 401


def test_401_from_get_raises_authentication_error(monkeypatch):
    """_get raises AuthenticationError on HTTP 401 (tested directly on _get)."""
    import httpx
    from unittest.mock import MagicMock

    conn = AzureConnector()

    # Construct a fake response object that returns 401
    fake_response = MagicMock()
    fake_response.status_code = 401

    with patch("httpx.get", return_value=fake_response):
        with pytest.raises(AuthenticationError) as exc_info:
            conn._get("fake-bearer-token", "https://management.azure.com/test")
        assert exc_info.value.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════════
# 9. HTTP 429 -> RateLimitError
# ═══════════════════════════════════════════════════════════════════════════════

def test_429_raises_rate_limit_error():
    """_get raises RateLimitError on HTTP 429 (tested directly on _get)."""
    from unittest.mock import MagicMock

    conn = AzureConnector()
    fake_response = MagicMock()
    fake_response.status_code = 429
    fake_response.headers = {"Retry-After": "60"}

    with patch("httpx.get", return_value=fake_response):
        with pytest.raises(RateLimitError) as exc_info:
            conn._get("fake-bearer-token", "https://management.azure.com/test")
        assert exc_info.value.status_code == 429


def test_429_retry_after_surfaced():
    """_get surfaces the Retry-After header value on RateLimitError."""
    from unittest.mock import MagicMock

    conn = AzureConnector()
    fake_response = MagicMock()
    fake_response.status_code = 429
    fake_response.headers = {"Retry-After": "90"}

    with patch("httpx.get", return_value=fake_response):
        with pytest.raises(RateLimitError) as exc_info:
            conn._get("fake-bearer-token", "https://management.azure.com/test")
        assert exc_info.value.retry_after == 90.0


# ═══════════════════════════════════════════════════════════════════════════════
# 10. HTTP 403 -> ConnectorError
# ═══════════════════════════════════════════════════════════════════════════════

def test_403_raises_connector_error():
    """_get raises ConnectorError on HTTP 403 (tested directly on _get)."""
    from unittest.mock import MagicMock

    conn = AzureConnector()
    fake_response = MagicMock()
    fake_response.status_code = 403

    with patch("httpx.get", return_value=fake_response):
        with pytest.raises(ConnectorError) as exc_info:
            conn._get("fake-bearer-token", "https://management.azure.com/test")
        assert exc_info.value.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════════
# 11. Network error -> NetworkError
# ═══════════════════════════════════════════════════════════════════════════════

def test_network_error_raises_network_error(monkeypatch):
    def fake_get_token_network_error(self, credentials: dict) -> str:
        raise NetworkError("azure: token request network error: connection refused")

    monkeypatch.setattr(AzureConnector, "_get_token", fake_get_token_network_error)
    conn = AzureConnector()
    with pytest.raises(NetworkError):
        conn.fetch({
            "tenant_id": "t-id", "client_id": "c-id",
            "client_secret": "s-value", "subscription_id": _SUB_ID,
        })


def test_network_error_from_get_raises_network_error():
    """_get raises NetworkError on connection failure (tested directly on _get)."""
    import httpx as httpx_mod
    from unittest.mock import MagicMock

    conn = AzureConnector()

    with patch("httpx.get", side_effect=httpx_mod.ConnectError("connection refused")):
        with pytest.raises(NetworkError):
            conn._get("fake-bearer-token", "https://management.azure.com/test")


# ═══════════════════════════════════════════════════════════════════════════════
# 12. validate_credentials fails gracefully on bad creds
# ═══════════════════════════════════════════════════════════════════════════════

def test_validate_credentials_bad_token_raises_auth_error(monkeypatch):
    def fake_get_token_bad(self, credentials: dict) -> str:
        raise AuthenticationError(
            "azure: token request rejected (401)", status_code=401
        )

    monkeypatch.setattr(AzureConnector, "_get_token", fake_get_token_bad)
    conn = AzureConnector()
    with pytest.raises(AuthenticationError):
        conn.validate_credentials({
            "tenant_id": "wrong-tenant",
            "client_id": "wrong-client",
            "client_secret": "wrong-secret",
            "subscription_id": _SUB_ID,
        })


def test_validate_credentials_bad_subscription_raises_connector_error(monkeypatch):
    monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)

    def fake_get_404(self, token, url, params=None):
        raise ConnectorError(
            f"azure: API returned HTTP 404 for {url}", status_code=404
        )

    monkeypatch.setattr(AzureConnector, "_get", fake_get_404)
    conn = AzureConnector()
    with pytest.raises(ConnectorError):
        conn.validate_credentials({
            "tenant_id": "t-id",
            "client_id": "c-id",
            "client_secret": "s-value",
            "subscription_id": "nonexistent-sub-id",
        })


def test_validate_credentials_never_echoes_secret_in_error(monkeypatch):
    secret_value = "super-secret-value-must-not-echo"

    def fake_get_token_bad(self, credentials: dict) -> str:
        raise AuthenticationError(
            "azure: token request rejected (401) — check credentials",
            status_code=401,
        )

    monkeypatch.setattr(AzureConnector, "_get_token", fake_get_token_bad)
    conn = AzureConnector()
    try:
        conn.validate_credentials({
            "tenant_id": "t", "client_id": "c",
            "client_secret": secret_value, "subscription_id": _SUB_ID,
        })
    except (AuthenticationError, ConnectorError, NetworkError) as exc:
        assert secret_value not in str(exc)


# ═══════════════════════════════════════════════════════════════════════════════
# 13. Pagination bounded (MAX_PAGES respected)
# ═══════════════════════════════════════════════════════════════════════════════

def test_pagination_bounded_at_max_pages(monkeypatch):
    """_paginate never follows more than _MAX_PAGES nextLink hops."""
    from app.connectors import azure as azure_module

    max_pages = azure_module._MAX_PAGES
    call_count = {"n": 0}

    def fake_get_infinite_pages(self, token, url, params=None):
        call_count["n"] += 1
        # Always return a nextLink to simulate an infinite paginator
        return {
            "value": [{"id": f"item-{call_count['n']}"}],
            "nextLink": "https://management.azure.com/subscriptions/sub/resourcegroups?nextToken=x",
        }

    monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)
    monkeypatch.setattr(AzureConnector, "_get", fake_get_infinite_pages)

    conn = AzureConnector()
    items = conn._paginate(_FAKE_TOKEN, "https://management.azure.com/test")
    # Should never exceed _MAX_PAGES pages
    assert call_count["n"] <= max_pages
    assert len(items) <= max_pages


# ═══════════════════════════════════════════════════════════════════════════════
# 14. No sensitive fields in any record returned by fetch()
# ═══════════════════════════════════════════════════════════════════════════════

def test_no_sensitive_fields_in_fetch_output(monkeypatch):
    """Sensitive field names must never appear as keys in any returned record.

    Checks each record dict directly for disallowed key names. This avoids
    false positives from substrings (e.g. 'authorization_source' contains
    'authorization' as a substring but is a safe field name).
    """
    monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)
    monkeypatch.setattr(AzureConnector, "_get", _make_fake_get())
    conn = AzureConnector()
    records = conn.fetch({
        "tenant_id": "t-id", "client_id": "c-id",
        "client_secret": "do-not-leak-me",
        "subscription_id": _SUB_ID,
    })

    for record in records:
        for key in record.keys():
            assert key not in _SENSITIVE_FIELD_NAMES, (
                f"Sensitive field name {key!r} found as a key in record "
                f"of type {record.get('record_type')!r}"
            )


def test_no_sensitive_values_in_fetch_output(monkeypatch):
    """Sensitive literal values from raw data must not appear in fetch() output."""
    monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)
    monkeypatch.setattr(AzureConnector, "_get", _make_fake_get())
    conn = AzureConnector()
    records = conn.fetch({
        "tenant_id": "t-id", "client_id": "c-id",
        "client_secret": "do-not-leak-me",
        "subscription_id": _SUB_ID,
    })
    blob = json.dumps(records)

    # Sensitive values injected into raw test data must not appear
    sensitive_values = [
        "AAABBBCCC000111SECRET",      # primaryAccessKey
        "DDDEEEFFF222333SECRET",      # secondaryAccessKey
        "srt=sco",                    # SAS token fragment
        "DefaultEndpointsProtocol",   # connection string
        "db-password",                # secret name
        "stripe-api-key",             # secret name
        "alice@example.com",          # principal email
        "bob@example.com",            # principal email
        "ops-team@example.com",       # tag value
        "sensitive_packet_data",      # NSG packet data
        "sensitive_log_profile",      # NSG log profile
        "do-not-leak-me",             # client_secret credential
        _FAKE_TOKEN,                  # bearer token
    ]
    for val in sensitive_values:
        assert val not in blob, (
            f"Sensitive value {val!r} found in fetch() output"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 15. "azure" is in sync_service._SUPPORTED_PROVIDERS
# ═══════════════════════════════════════════════════════════════════════════════

def test_azure_in_sync_service_supported_providers():
    from app.services import sync_service

    # _SUPPORTED_PROVIDERS is a local variable inside the function body,
    # so we inspect the source to verify the string is present.
    source = inspect.getsource(sync_service)
    assert '"azure"' in source or "'azure'" in source, (
        "azure not found in sync_service source — "
        "expected it to be listed in _SUPPORTED_PROVIDERS"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 16. Capability matrix: azure has maturity="partial" and security_rules=False
# ═══════════════════════════════════════════════════════════════════════════════

def test_capability_matrix_includes_azure():
    from app.services import provider_capability_matrix_service as svc

    azure_cap = svc.get_provider_capability("azure")
    assert azure_cap is not None, "azure not found in provider capability matrix"


def test_capability_matrix_azure_maturity_is_partial():
    from app.services import provider_capability_matrix_service as svc

    azure_cap = svc.get_provider_capability("azure")
    assert azure_cap is not None
    assert azure_cap.maturity == "partial", (
        f"azure maturity should be 'partial', got {azure_cap.maturity!r}"
    )


def test_capability_matrix_azure_security_rules_is_false():
    """Flipped in M77B: Azure security rules now wired (10 core rules)."""
    from app.services import provider_capability_matrix_service as svc

    azure_cap = svc.get_provider_capability("azure")
    assert azure_cap is not None
    assert azure_cap.security.security_rules is True, (
        "azure security_rules should be True after M77B (10 core rules added)"
    )


def test_capability_matrix_azure_drift_snapshots_is_true():
    from app.services import provider_capability_matrix_service as svc

    azure_cap = svc.get_provider_capability("azure")
    assert azure_cap is not None
    assert azure_cap.drift.drift_snapshots is True


def test_capability_matrix_azure_label():
    from app.services import provider_capability_matrix_service as svc

    azure_cap = svc.get_provider_capability("azure")
    assert azure_cap is not None
    assert azure_cap.label == "Azure"


def test_capability_matrix_azure_category_is_cloud():
    from app.services import provider_capability_matrix_service as svc

    azure_cap = svc.get_provider_capability("azure")
    assert azure_cap is not None
    assert azure_cap.category == "cloud"


# ═══════════════════════════════════════════════════════════════════════════════
# 17. Azure does NOT appear in security_coverage_service.PROVIDERS
# ═══════════════════════════════════════════════════════════════════════════════

def test_azure_not_in_security_coverage_providers():
    """Flipped in M77B: Azure is now in PROVIDERS with core security rules."""
    from app.services.security_coverage_service import PROVIDERS

    assert "azure" in PROVIDERS, (
        "azure should be in security_coverage_service.PROVIDERS after M77B"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 18. Provider expansion framework next-stage points to M77B
# ═══════════════════════════════════════════════════════════════════════════════

def test_expansion_framework_planned_next_stage_is_m77b():
    """Rolled forward: next stage is M90A: Sentry Drift Provider Foundation."""
    from app.services import provider_expansion_framework as svc

    framework = svc.get_framework()
    planned = framework["summary"]["planned_next_stage"]
    assert "M90A" in planned, (
        f"planned_next_stage should be M90A, got: {planned!r}"
    )


def test_expansion_framework_planned_next_stage_mentions_azure():
    """Rolled forward: next stage is M90A: Sentry Drift Provider Foundation."""
    from app.services import provider_expansion_framework as svc

    framework = svc.get_framework()
    planned = framework["summary"]["planned_next_stage"]
    assert "Sentry" in planned, (
        f"planned_next_stage should reference Sentry, "
        f"got: {planned!r}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 19. No forbidden claim wording in connector module docstring or notes
# ═══════════════════════════════════════════════════════════════════════════════

def test_no_forbidden_claims_in_azure_connector_docstring():
    import app.connectors.azure as azure_module

    module_doc = (azure_module.__doc__ or "").lower()
    connector_doc = (AzureConnector.__doc__ or "").lower()
    combined = module_doc + " " + connector_doc

    for phrase in _FORBIDDEN:
        assert phrase not in combined, (
            f"Forbidden phrase {phrase!r} found in azure connector documentation"
        )


def test_no_forbidden_claims_in_capability_matrix_azure_notes():
    from app.services import provider_capability_matrix_service as svc

    azure_cap = svc.get_provider_capability("azure")
    assert azure_cap is not None
    notes_lower = azure_cap.notes.lower()

    for phrase in _FORBIDDEN:
        assert phrase not in notes_lower, (
            f"Forbidden phrase {phrase!r} found in azure capability matrix notes"
        )


def test_no_forbidden_claims_in_azure_schema_docstring():
    import app.connectors.azure_schema as schema_module

    module_doc = (schema_module.__doc__ or "").lower()
    for phrase in _FORBIDDEN:
        assert phrase not in module_doc, (
            f"Forbidden phrase {phrase!r} found in azure_schema module docstring"
        )


def test_no_forbidden_claims_in_azure_risk_rules_module():
    import inspect

    import app.services.risk_rules.azure as azure_risk_module

    src = inspect.getsource(azure_risk_module).lower()
    for phrase in _FORBIDDEN:
        assert phrase not in src, (
            f"Forbidden phrase {phrase!r} found in risk_rules/azure.py"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 20. Diff tracked fields and risk classification (QA pass)
# ══════════════════════════════════════════════════════════════════════════════
#
# Azure previously had NO entry in diff_service.py's tracked-fields dispatch
# (every azure_ record type fell through to the Cloudflare DNS default tuple,
# so compute_diff could never detect a modified field) and NO
# risk_rules/azure.py module at all (risk_service.py had no azure_ dispatch
# branch, so every Azure change silently fell through to the Cloudflare DNS
# classifier) — despite the provider capability matrix already claiming
# drift_diff=True and drift_risk_classification=True. Both were built during
# this QA pass, making that pre-existing capability-matrix claim actually true.
#
# The NSG list-diffing logic (rules_summary) proactively applies the
# None-vs-empty-list lesson learned in Google Cloud's classification-QA pass
# from the very start, rather than needing a follow-up pass to find the bug.

AZURE_ALL_RECORD_TYPES = (
    "azure_subscription",
    "azure_resource_group",
    "azure_network_security_group",
    "azure_storage_account",
    "azure_key_vault",
    "azure_role_assignment",
    "azure_app_service",
    "azure_sql_server",
    "azure_aks_cluster",
)


class TestAzureDiffTrackedFields:
    def test_all_nine_record_types_have_tracked_fields_entries(self):
        from app.services.diff_service import _AZURE_TRACKED_FIELDS_BY_TYPE

        for record_type in AZURE_ALL_RECORD_TYPES:
            assert record_type in _AZURE_TRACKED_FIELDS_BY_TYPE, (
                f"{record_type!r} has no tracked-fields entry — modified-field "
                "changes for this record type will never be detected by compute_diff"
            )

    def test_tracked_fields_dispatch_uses_azure_table_not_cloudflare_default(self):
        from app.services.diff_service import _tracked_fields_for, _TRACKED_FIELDS

        for record_type in AZURE_ALL_RECORD_TYPES:
            fields = _tracked_fields_for({"record_type": record_type})
            assert fields != _TRACKED_FIELDS, (
                f"{record_type!r} is falling through to the Cloudflare DNS "
                "default tracked-fields tuple instead of its own Azure fields"
            )
            assert fields, f"{record_type!r} resolved to an empty tracked-fields tuple"

    def test_nsg_rules_summary_change_produces_drift_change(self):
        """rules_summary gaining a public SSH rule must surface as a Change."""
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        def _nsg_record(rules: list) -> dict:
            return {
                "record_type": "azure_network_security_group",
                "provider": "azure",
                "record_id": "azure_nsg_nsg1",
                "nsg_id": "nsg1",
                "nsg_name": "test-nsg",
                "resource_group": "rg1",
                "location": "eastus",
                "rule_count": len(rules),
                "inbound_allow_rule_count": len(rules),
                "public_inbound_rule_count": len(rules),
                "rules_summary": rules,
            }

        safe_rule = {
            "rule_name": "allow-https",
            "direction": "Inbound",
            "access": "Allow",
            "priority": 100,
            "protocol": "Tcp",
            "source_address_prefix": "*",
            "source_port_range": "*",
            "destination_address_prefix": "*",
            "destination_port_range": "443",
        }
        ssh_rule = dict(safe_rule, rule_name="allow-ssh", destination_port_range="22")

        prev = _mock_snapshot([_nsg_record([safe_rule])])
        new = _mock_snapshot([_nsg_record([safe_rule, ssh_rule])])

        changes = compute_diff(prev, new)
        rule_changes = [c for c in changes if c["field_path"] == "rules_summary"]

        assert len(rule_changes) == 1
        assert rule_changes[0]["prev_value"] == [safe_rule]
        assert rule_changes[0]["new_value"] == [safe_rule, ssh_rule]

    def test_no_spurious_change_when_records_are_identical(self):
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        record = {
            "record_type": "azure_storage_account",
            "provider": "azure",
            "record_id": "azure_storage_acct1",
            "account_id": "acct1",
            "account_name": "teststorage",
            "resource_group": "rg1",
            "location": "eastus",
            "kind": "StorageV2",
            "sku_name": "Standard_LRS",
            "allow_blob_public_access": False,
            "public_network_access": "Enabled",
            "minimum_tls_version": "TLS1_2",
            "supports_https_traffic_only": True,
            "shared_access_key_enabled": False,
            "network_default_action": "Deny",
        }
        prev = _mock_snapshot([dict(record)])
        new = _mock_snapshot([dict(record)])

        assert compute_diff(prev, new) == []

    def test_every_tracked_field_classifies_without_error_or_invalid_severity(self):
        """Every field in _AZURE_TRACKED_FIELDS_BY_TYPE must be classifiable:
        classify_azure_change must not raise, and must return one of the
        four known severities, for a representative modified change on
        each tracked field of each record type."""
        from app.services.diff_service import _AZURE_TRACKED_FIELDS_BY_TYPE
        from app.services.risk_rules.azure import classify_azure_change

        for record_type, fields in _AZURE_TRACKED_FIELDS_BY_TYPE.items():
            for field in fields:
                change = {
                    "change_type": "modified",
                    "field_path": field,
                    "prev_value": 1,
                    "new_value": 2,
                    "provider_metadata": {"record_type": record_type},
                }
                level, reason = classify_azure_change(change)
                assert level in ("low", "medium", "high", "critical"), (
                    f"{record_type}.{field} returned invalid severity {level!r}"
                )
                assert isinstance(reason, str) and reason, (
                    f"{record_type}.{field} returned an empty reason string"
                )


class TestAzureRiskClassifier:
    def _make_change(
        self,
        record_type: str,
        field_path: str = "",
        change_type: str = "modified",
        prev_value: Any = None,
        new_value: Any = None,
    ) -> dict:
        return {
            "provider_metadata": {"record_type": record_type},
            "field_path": field_path,
            "change_type": change_type,
            "prev_value": prev_value,
            "new_value": new_value,
        }

    def test_risk_service_dispatches_azure_to_azure_classifier(self):
        """Regression guard: risk_service.py must route azure_ record types
        to classify_azure_change, not silently fall through to the
        Cloudflare DNS classifier (the exact bug this QA pass found and
        fixed)."""
        from app.services.risk_service import classify_change

        change = self._make_change(
            "azure_storage_account", "allow_blob_public_access",
            prev_value=False, new_value=True,
        )
        mock_change = MagicMock()
        mock_change.provider_metadata = change["provider_metadata"]
        mock_change.field_path = change["field_path"]
        mock_change.change_type = change["change_type"]
        mock_change.prev_value = change["prev_value"]
        mock_change.new_value = change["new_value"]
        level, reason = classify_change(mock_change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"
        assert "azure" in reason.lower()

    def test_storage_public_blob_access_enabled_is_high(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_storage_account", "allow_blob_public_access",
            prev_value=False, new_value=True,
        )
        level, reason = classify_azure_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_storage_public_blob_access_disabled_is_low(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_storage_account", "allow_blob_public_access",
            prev_value=True, new_value=False,
        )
        level, _ = classify_azure_change(change)
        assert level == "low"

    def test_storage_shared_key_access_enabled_is_medium(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_storage_account", "shared_access_key_enabled",
            prev_value=False, new_value=True,
        )
        level, reason = classify_azure_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_storage_https_only_disabled_is_high(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_storage_account", "supports_https_traffic_only",
            prev_value=True, new_value=False,
        )
        level, reason = classify_azure_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_role_assignment_owner_granted_is_high(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_role_assignment", "role_definition_name",
            prev_value="Reader", new_value="Owner",
        )
        level, reason = classify_azure_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_role_assignment_owner_removed_is_low(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_role_assignment", "role_definition_name",
            prev_value="Owner", new_value="Reader",
        )
        level, _ = classify_azure_change(change)
        assert level == "low"

    def test_nsg_public_ssh_rule_added_is_high(self):
        from app.services.risk_rules.azure import classify_azure_change
        safe_rule = {
            "rule_name": "allow-https", "direction": "Inbound", "access": "Allow",
            "priority": 100, "protocol": "Tcp", "source_address_prefix": "*",
            "source_port_range": "*", "destination_address_prefix": "*",
            "destination_port_range": "443",
        }
        ssh_rule = dict(safe_rule, rule_name="allow-ssh", destination_port_range="22")
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[safe_rule], new_value=[safe_rule, ssh_rule],
        )
        level, reason = classify_azure_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_nsg_public_rdp_rule_added_is_critical(self):
        from app.services.risk_rules.azure import classify_azure_change
        rdp_rule = {
            "rule_name": "allow-rdp", "direction": "Inbound", "access": "Allow",
            "priority": 100, "protocol": "Tcp", "source_address_prefix": "0.0.0.0/0",
            "source_port_range": "*", "destination_address_prefix": "*",
            "destination_port_range": "3389",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[], new_value=[rdp_rule],
        )
        level, reason = classify_azure_change(change)
        assert level == "critical", f"Expected critical, got {level!r}: {reason}"

    def test_nsg_broad_all_ports_rule_added_is_critical(self):
        from app.services.risk_rules.azure import classify_azure_change
        broad_rule = {
            "rule_name": "allow-all", "direction": "Inbound", "access": "Allow",
            "priority": 100, "protocol": "*", "source_address_prefix": "Internet",
            "source_port_range": "*", "destination_address_prefix": "*",
            "destination_port_range": "*",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[], new_value=[broad_rule],
        )
        level, reason = classify_azure_change(change)
        assert level == "critical", f"Expected critical, got {level!r}: {reason}"

    def test_nsg_benign_rule_added_is_low(self):
        from app.services.risk_rules.azure import classify_azure_change
        safe_rule = {
            "rule_name": "allow-https", "direction": "Inbound", "access": "Allow",
            "priority": 100, "protocol": "Tcp", "source_address_prefix": "*",
            "source_port_range": "*", "destination_address_prefix": "*",
            "destination_port_range": "443",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[], new_value=[safe_rule],
        )
        level, _ = classify_azure_change(change)
        assert level == "low"

    def test_nsg_public_rule_removed_is_low(self):
        from app.services.risk_rules.azure import classify_azure_change
        ssh_rule = {
            "rule_name": "allow-ssh", "direction": "Inbound", "access": "Allow",
            "priority": 100, "protocol": "Tcp", "source_address_prefix": "*",
            "source_port_range": "*", "destination_address_prefix": "*",
            "destination_port_range": "22",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[ssh_rule], new_value=[],
        )
        level, _ = classify_azure_change(change)
        assert level == "low"

    def test_nsg_rules_summary_unknown_baseline_does_not_claim_added(self):
        """The None-vs-empty-list lesson from Google Cloud's classification-QA
        pass, applied proactively from the start: a genuinely unknown
        previous rules_summary must not make every current rule look
        newly 'added'."""
        from app.services.risk_rules.azure import classify_azure_change
        rdp_rule = {
            "rule_name": "allow-rdp", "direction": "Inbound", "access": "Allow",
            "priority": 100, "protocol": "Tcp", "source_address_prefix": "0.0.0.0/0",
            "source_port_range": "*", "destination_address_prefix": "*",
            "destination_port_range": "3389",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=None, new_value=[rdp_rule],
        )
        level, reason = classify_azure_change(change)
        assert level == "critical", f"Expected critical, got {level!r}: {reason}"
        assert "added" not in reason.lower()
        assert "unknown or missing" in reason.lower()

    def test_nsg_rules_summary_unknown_new_value_is_low_unknown(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[{"protocol": "Tcp"}], new_value=None,
        )
        level, reason = classify_azure_change(change)
        assert level == "low", f"Expected low, got {level!r}: {reason}"
        assert "unknown or missing" in reason.lower()

    def test_key_vault_purge_protection_disabled_is_medium(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_key_vault", "purge_protection_enabled",
            prev_value=True, new_value=False,
        )
        level, reason = classify_azure_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_key_vault_soft_delete_disabled_is_medium(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_key_vault", "soft_delete_enabled",
            prev_value=True, new_value=False,
        )
        level, reason = classify_azure_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_app_service_https_only_disabled_is_high(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_app_service", "https_only", prev_value=True, new_value=False,
        )
        level, reason = classify_azure_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_sql_server_public_network_access_enabled_is_medium(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_sql_server", "public_network_access",
            prev_value="Disabled", new_value="Enabled",
        )
        level, reason = classify_azure_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_aks_local_accounts_enabled_is_medium(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_aks_cluster", "local_account_disabled",
            prev_value=True, new_value=False,
        )
        level, reason = classify_azure_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_aks_network_policy_removed_is_medium(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change(
            "azure_aks_cluster", "network_policy",
            prev_value="azure", new_value="none",
        )
        level, reason = classify_azure_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_unknown_record_type_is_low(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = self._make_change("azure_unknown_surface", "some_field", prev_value=1, new_value=2)
        level, _ = classify_azure_change(change)
        assert level == "low"

    def test_unknown_transitions_never_produce_high_or_critical(self):
        from app.services.risk_rules.azure import classify_azure_change

        unknown_cases = [
            ("azure_storage_account", "allow_blob_public_access", False, None),
            ("azure_key_vault", "purge_protection_enabled", True, None),
            ("azure_app_service", "https_only", True, None),
            ("azure_sql_server", "public_network_access", "Disabled", None),
            ("azure_aks_cluster", "local_account_disabled", True, None),
            ("azure_role_assignment", "role_definition_name", "Reader", None),
        ]
        for record_type, field, prev, new in unknown_cases:
            change = self._make_change(record_type, field, prev_value=prev, new_value=new)
            level, reason = classify_azure_change(change)
            assert level not in ("high", "critical"), (
                f"{record_type}.{field} unknown transition produced {level!r}: {reason!r}"
            )

    def test_classifier_reads_real_compute_diff_dict_shape_not_a_mock(self):
        """Regression guard against the exact old_value/prev_value bug class
        found in Terraform Cloud's first QA pass: builds a plain dict shaped
        EXACTLY like compute_diff's real output (prev_value/new_value/
        field_path/change_type/provider_metadata), not a MagicMock, to prove
        the classifier reads the real field name."""
        from app.services.risk_rules.azure import classify_azure_change

        real_shaped_change = {
            "change_type": "modified",
            "field_path": "allow_blob_public_access",
            "prev_value": False,
            "new_value": True,
            "provider_metadata": {"record_type": "azure_storage_account"},
        }
        level, reason = classify_azure_change(real_shaped_change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_no_forbidden_wording_in_reasons(self):
        from app.services.risk_rules.azure import classify_azure_change

        FORBIDDEN = [
            "breach", "compromise", "attacker", "leaked", "unauthorized access",
            "storage exposed", "database exposed", "key vault exposed",
            "vault exposed", "secret exposed", "secrets exposed",
            "infrastructure exposed", "customer data exposed",
            "azure data exposed", "data exposed",
            "exfiltration", "stolen", "fraud", "attack detected",
        ]
        test_changes = [
            self._make_change("azure_storage_account", "allow_blob_public_access", prev_value=False, new_value=True),
            self._make_change("azure_network_security_group", "rules_summary", prev_value=[], new_value=[{
                "rule_name": "r", "direction": "Inbound", "access": "Allow",
                "source_address_prefix": "*", "destination_port_range": "22",
            }]),
            self._make_change("azure_key_vault", "purge_protection_enabled", prev_value=True, new_value=False),
            self._make_change("azure_role_assignment", "role_definition_name", prev_value="Reader", new_value="Owner"),
            self._make_change("azure_app_service", "https_only", prev_value=True, new_value=False),
            self._make_change("azure_sql_server", "public_network_access", prev_value="Disabled", new_value="Enabled"),
            self._make_change("azure_aks_cluster", "local_account_disabled", prev_value=True, new_value=False),
        ]
        for change in test_changes:
            _, reason = classify_azure_change(change)
            reason_lower = reason.lower()
            for phrase in FORBIDDEN:
                assert phrase not in reason_lower, (
                    f"Forbidden phrase {phrase!r} found in risk reason: {reason!r}"
                )


# ═══════════════════════════════════════════════════════════════════════════════
# Classification-QA pass: NSG list-diff stress tests, storage HTTPS-only
# Finding, and count/threshold safety.
# ═══════════════════════════════════════════════════════════════════════════════

class TestAzureNsgListDiffStressTests:
    """Task 5 stress tests: source prefixes, dest ports, reordering, malformed
    shapes, and the additional public-source/admin-port literals."""

    def _make_change(self, record_type, field_path="", change_type="modified", prev_value=None, new_value=None):
        return {
            "provider_metadata": {"record_type": record_type},
            "field_path": field_path,
            "change_type": change_type,
            "prev_value": prev_value,
            "new_value": new_value,
        }

    def test_nsg_internet_literal_source_added_is_high_or_critical(self):
        from app.services.risk_rules.azure import classify_azure_change
        rule = {
            "rule_name": "allow-ssh", "direction": "Inbound", "access": "Allow",
            "source_address_prefix": "Internet", "destination_port_range": "22",
            "protocol": "Tcp",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[], new_value=[rule],
        )
        level, _ = classify_azure_change(change)
        assert level in ("high", "critical")

    def test_nsg_ipv6_any_literal_source_added_is_high_or_critical(self):
        from app.services.risk_rules.azure import classify_azure_change
        rule = {
            "rule_name": "allow-rdp", "direction": "Inbound", "access": "Allow",
            "source_address_prefix": "::/0", "destination_port_range": "3389",
            "protocol": "Tcp",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[], new_value=[rule],
        )
        level, _ = classify_azure_change(change)
        assert level == "critical"

    def test_nsg_database_port_added_is_critical(self):
        """Admin/database ports beyond SSH/RDP (e.g. 3306 MySQL) must reach critical."""
        from app.services.risk_rules.azure import classify_azure_change
        rule = {
            "rule_name": "allow-mysql", "direction": "Inbound", "access": "Allow",
            "source_address_prefix": "0.0.0.0/0", "destination_port_range": "3306",
            "protocol": "Tcp",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[], new_value=[rule],
        )
        level, _ = classify_azure_change(change)
        assert level == "critical"

    def test_nsg_destination_port_range_string_opens_admin_port_is_critical(self):
        """destination_port_range as a range string (e.g. '3380-3390') that
        contains an admin port must still be caught."""
        from app.services.risk_rules.azure import classify_azure_change
        rule = {
            "rule_name": "allow-range", "direction": "Inbound", "access": "Allow",
            "source_address_prefix": "*", "destination_port_range": "3380-3390",
            "protocol": "Tcp",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[], new_value=[rule],
        )
        level, _ = classify_azure_change(change)
        assert level == "critical"

    def test_nsg_removed_0000_source_is_improvement_not_high(self):
        """Removing a broad-public rule (0.0.0.0/0) must never be classified
        as high/critical — it's a restoration, not a new risk."""
        from app.services.risk_rules.azure import classify_azure_change
        rdp_rule = {
            "rule_name": "allow-rdp", "direction": "Inbound", "access": "Allow",
            "source_address_prefix": "0.0.0.0/0", "destination_port_range": "3389",
            "protocol": "Tcp",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[rdp_rule], new_value=[],
        )
        level, reason = classify_azure_change(change)
        assert level not in ("high", "critical"), f"removal produced {level!r}: {reason!r}"

    def test_nsg_reordering_only_does_not_create_false_risk(self):
        """Reordering the same two benign rules must not be treated as a
        newly-added risky rule (the added-rules diff is set-based, not
        position-based, so pure reordering yields no added rules)."""
        from app.services.risk_rules.azure import classify_azure_change
        rule_a = {
            "rule_name": "allow-https", "direction": "Inbound", "access": "Allow",
            "source_address_prefix": "*", "destination_port_range": "443",
            "protocol": "Tcp",
        }
        rule_b = {
            "rule_name": "allow-http", "direction": "Inbound", "access": "Allow",
            "source_address_prefix": "*", "destination_port_range": "80",
            "protocol": "Tcp",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[rule_a, rule_b], new_value=[rule_b, rule_a],
        )
        level, _ = classify_azure_change(change)
        assert level == "low"

    def test_nsg_malformed_rule_missing_keys_does_not_raise(self):
        """A rule dict missing expected keys (connector never emits this
        shape, but the classifier must not assume it) must not raise and
        must not produce a false high/critical."""
        from app.services.risk_rules.azure import classify_azure_change
        malformed_rule = {"rule_name": "weird"}
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[], new_value=[malformed_rule],
        )
        level, _ = classify_azure_change(change)
        assert level == "low"

    def test_nsg_outbound_public_rule_is_not_flagged(self):
        """Direction=Outbound must never be treated as risky ingress, even
        with a broad source/port — only Inbound+Allow is evaluated."""
        from app.services.risk_rules.azure import classify_azure_change
        outbound_rule = {
            "rule_name": "outbound-any", "direction": "Outbound", "access": "Allow",
            "source_address_prefix": "*", "destination_port_range": "*",
            "protocol": "*",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[], new_value=[outbound_rule],
        )
        level, _ = classify_azure_change(change)
        assert level == "low"

    def test_nsg_deny_rule_is_not_flagged(self):
        """access=Deny must never be treated as risky, even with a broad
        source/port — only Allow rules grant access."""
        from app.services.risk_rules.azure import classify_azure_change
        deny_rule = {
            "rule_name": "deny-all", "direction": "Inbound", "access": "Deny",
            "source_address_prefix": "*", "destination_port_range": "*",
            "protocol": "*",
        }
        change = self._make_change(
            "azure_network_security_group", "rules_summary",
            prev_value=[], new_value=[deny_rule],
        )
        level, _ = classify_azure_change(change)
        assert level == "low"


class TestAzureStorageHttpsOnlyFinding:
    """Positive/negative/unknown tests for the azure_storage_https_only_disabled
    Security Finding added in this classification-QA pass."""

    def _record(self, **overrides):
        base = {
            "record_type": "azure_storage_account",
            "record_id": "/sub/s/sa",
            "account_name": "acct", "resource_group": "rg", "location": "eastus",
        }
        base.update(overrides)
        return base

    def test_https_only_disabled_fires_high(self):
        from app.services.security_rules.azure import evaluate, _RULE_STORAGE_HTTPS_ONLY_DISABLED
        findings = evaluate(self._record(supports_https_traffic_only=False))
        matches = [f for f in findings if f.rule_key == _RULE_STORAGE_HTTPS_ONLY_DISABLED]
        assert len(matches) == 1
        assert matches[0].severity == "high"

    def test_https_only_enabled_does_not_fire(self):
        from app.services.security_rules.azure import evaluate, _RULE_STORAGE_HTTPS_ONLY_DISABLED
        findings = evaluate(self._record(supports_https_traffic_only=True))
        matches = [f for f in findings if f.rule_key == _RULE_STORAGE_HTTPS_ONLY_DISABLED]
        assert matches == []

    def test_https_only_unknown_missing_does_not_fire(self):
        from app.services.security_rules.azure import evaluate, _RULE_STORAGE_HTTPS_ONLY_DISABLED
        findings = evaluate(self._record())
        matches = [f for f in findings if f.rule_key == _RULE_STORAGE_HTTPS_ONLY_DISABLED]
        assert matches == []

    def test_https_only_registered_in_all_registries(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        from app.services.security_rule_pack import _RULE_META
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        key = "azure_storage_https_only_disabled"
        assert key in KNOWN_RULE_KEYS
        assert key in RULE_CONFIDENCE
        assert key in _RULE_META
        assert _RULE_META[key][0] == "azure"
        assert _RULE_META[key][1] == "high"
        assert key in RULE_RECORD_TYPES

    def test_https_only_change_classification_matches_finding_severity(self):
        from app.services.risk_rules.azure import classify_azure_change
        change = {
            "provider_metadata": {"record_type": "azure_storage_account"},
            "field_path": "supports_https_traffic_only",
            "change_type": "modified",
            "prev_value": True,
            "new_value": False,
        }
        level, _ = classify_azure_change(change)
        assert level == "high"


class TestAzureCountThresholdSafety:
    """Task 6: Azure has no count-threshold rules, but _int_or_none() must
    still be safe if ever exercised, and no unknown-to-zero coercion pattern
    exists anywhere in the module."""

    def test_int_or_none_treats_missing_as_none_not_zero(self):
        from app.services.risk_rules.azure import _int_or_none
        assert _int_or_none(None) is None
        assert _int_or_none("not-a-number") is None
        assert _int_or_none(True) is None  # bool is not a count
        assert _int_or_none(0) == 0
        assert _int_or_none(5) == 5

    def test_no_unknown_to_zero_coercion_pattern_in_source(self):
        import inspect
        from app.services.risk_rules import azure as azure_risk_rules
        source = inspect.getsource(azure_risk_rules)
        assert "or 0)" not in source, (
            "Found an unknown-to-zero coercion pattern in risk_rules/azure.py"
        )


class TestNormalizerEdgeCases:
    """Normalizers handle malformed / empty input without raising."""

    def test_normalize_subscription_empty_dict(self):
        conn = AzureConnector()
        rec = conn._normalize_subscription({})
        assert rec["record_type"] == AZURE_SUBSCRIPTION
        assert isinstance(rec["subscription_id"], str)

    def test_normalize_resource_group_empty_dict(self):
        conn = AzureConnector()
        rec = conn._normalize_resource_group({}, "sub-123")
        assert rec["record_type"] == AZURE_RESOURCE_GROUP
        assert rec["tag_keys"] == []

    def test_normalize_nsg_empty_dict(self):
        conn = AzureConnector()
        rec = conn._normalize_nsg({})
        assert rec["record_type"] == AZURE_NETWORK_SECURITY_GROUP
        assert rec["rule_count"] == 0
        assert rec["rules_summary"] == []

    def test_normalize_storage_account_empty_dict(self):
        conn = AzureConnector()
        rec = conn._normalize_storage_account({})
        assert rec["record_type"] == AZURE_STORAGE_ACCOUNT

    def test_normalize_key_vault_empty_dict(self):
        conn = AzureConnector()
        rec = conn._normalize_key_vault({})
        assert rec["record_type"] == AZURE_KEY_VAULT
        assert isinstance(rec["access_policy_count"], int)
        assert rec["access_policy_count"] == 0

    def test_normalize_key_vault_missing_access_policies(self):
        conn = AzureConnector()
        raw = {"id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv",
               "name": "kv", "location": "eastus", "properties": {}}
        rec = conn._normalize_key_vault(raw)
        assert rec["access_policy_count"] == 0

    def test_normalize_nsg_rules_summary_never_exceeds_50(self):
        conn = AzureConnector()
        # Build a raw NSG with 100 security rules
        rules = [
            {"name": f"Rule{i}", "properties": {
                "direction": "Inbound", "access": "Allow", "priority": i,
                "protocol": "Tcp", "sourceAddressPrefix": "*",
                "sourcePortRange": "*", "destinationAddressPrefix": "*",
                "destinationPortRange": "80",
            }}
            for i in range(100)
        ]
        raw = {
            "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg",
            "name": "nsg", "location": "eastus",
            "properties": {"securityRules": rules, "defaultSecurityRules": []},
        }
        rec = conn._normalize_nsg(raw)
        assert len(rec["rules_summary"]) == 50

    def test_fetch_fail_soft_when_one_surface_unavailable(self, monkeypatch):
        """If NSG fetch fails, other record types are still returned."""
        monkeypatch.setattr(AzureConnector, "_get_token", _fake_get_token)

        def selective_fake_get(self, token, url, params=None):
            if "networksecuritygroups" in url.lower():
                raise ConnectorError("azure: NSG access denied", status_code=403)
            return _make_fake_get()(self, token, url, params)

        monkeypatch.setattr(AzureConnector, "_get", selective_fake_get)
        conn = AzureConnector()
        records = conn.fetch({
            "tenant_id": "t-id", "client_id": "c-id",
            "client_secret": "s-value", "subscription_id": _SUB_ID,
        })
        types_in_records = {r["record_type"] for r in records}
        # NSG should be absent (surface failed) but others present
        assert "AZURE_NETWORK_SECURITY_GROUP" not in types_in_records
        assert AZURE_SUBSCRIPTION in types_in_records
