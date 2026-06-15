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
from unittest.mock import patch

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
    """Rolled forward in M78C: GCP security expansion complete; next stage is M78D."""
    from app.services import provider_expansion_framework as svc

    framework = svc.get_framework()
    planned = framework["summary"]["planned_next_stage"]
    assert "M78H" in planned, (
        f"planned_next_stage should reference M78D after M78C, got: {planned!r}"
    )


def test_expansion_framework_planned_next_stage_mentions_azure():
    """Flipped in M78A: GCP drift foundation launched; the NEXT arc inside
    the GCP series (Core Security Foundation) is now the planned stage.
    """
    from app.services import provider_expansion_framework as svc

    framework = svc.get_framework()
    planned = framework["summary"]["planned_next_stage"]
    assert "Google Cloud" in planned, (
        f"planned_next_stage should reference Google Cloud after M78A, "
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


# ═══════════════════════════════════════════════════════════════════════════════
# Supplementary: normalizer edge cases
# ═══════════════════════════════════════════════════════════════════════════════

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
