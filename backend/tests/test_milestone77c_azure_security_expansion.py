"""M77C: Azure security expansion — test suite.

Covers:
  * Connector normalizers for new record types (role assignment, app service,
    SQL server, AKS cluster) — unit tests with mock API payloads
  * Security rule evaluators for all 10 M77C rules
  * Negative cases — non-triggering inputs, missing fields, private scopes
  * Evidence safety — no PII, principal IDs, secrets, connection strings, etc.
  * Claim discipline — no overclaim wording
  * Registry / confidence / pack / coverage / catalog parity
  * Capability matrix Azure still partial, activity/signals/correlations=false
  * Expansion framework next_stage → M77D
  * M77A + M77B regression
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.connectors.azure_schema import (
    AZURE_AKS_CLUSTER,
    AZURE_APP_SERVICE,
    AZURE_ROLE_ASSIGNMENT,
    AZURE_SQL_SERVER,
    # M77A types must still resolve
    AZURE_KEY_VAULT,
    AZURE_NETWORK_SECURITY_GROUP,
    AZURE_STORAGE_ACCOUNT,
    AZURE_SUBSCRIPTION,
    AZURE_RESOURCE_GROUP,
    AZURE_RECORD_TYPES,
)
from app.connectors.azure import (
    AzureConnector,
    _derive_scope_type,
    _resolve_role_name,
    _BUILTIN_ROLE_NAMES,
)
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework
from app.services.security_coverage_service import (
    PROVIDERS as COVERAGE_PROVIDERS,
    PROVIDER_SURFACES,
    RULE_RECORD_TYPES,
)
from app.services.security_finding_evaluator import _PROVIDER_RULES
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules import azure as azure_rules
from app.services.security_rules.azure import AZURE_RULE_KEYS, evaluate

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"

M77C_RULE_KEYS = {
    "azure_role_assignment_broad_privilege",
    "azure_app_service_https_disabled",
    "azure_app_service_ftp_enabled",
    "azure_app_service_weak_tls",
    "azure_app_service_public_network_access",
    "azure_sql_public_network_access",
    "azure_sql_weak_tls",
    "azure_aks_local_accounts_enabled",
    "azure_aks_public_api_access",
    "azure_aks_network_policy_missing",
}

ALL_AZURE_RULE_KEYS = M77C_RULE_KEYS | {
    "azure_nsg_public_admin_ingress",
    "azure_nsg_public_broad_ingress",
    "azure_storage_public_blob_access",
    "azure_storage_public_network_access",
    "azure_storage_weak_tls",
    "azure_storage_shared_key_enabled",
    "azure_key_vault_public_network_access",
    "azure_key_vault_purge_protection_disabled",
    "azure_key_vault_soft_delete_disabled",
    "azure_key_vault_rbac_disabled",
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

_FORBIDDEN_EVIDENCE_SUBSTRINGS = (
    "password",
    "passwd",
    "client_secret",
    "accountkey=",
    "?sv=",
    "connection_string",
    "connectionstring",
    "principal_id",
    "object_id",
    "display_name",
    "principal_email",
    "begin rsa",
    "begin certificate",
    "kubeconfig",
)


def _assert_evidence_safe(ev: dict, rule: str) -> None:
    text = json.dumps(ev, sort_keys=True).lower()
    for bad in _FORBIDDEN_EVIDENCE_SUBSTRINGS:
        assert bad not in text, (
            f"Forbidden substring {bad!r} in evidence for {rule}: {ev}"
        )


def _assert_no_overclaim(description: str, rule: str) -> None:
    low = description.lower()
    for bad in _FORBIDDEN_CLAIM_PHRASES:
        assert bad not in low, (
            f"Forbidden claim {bad!r} in description for {rule}: {description}"
        )
    assert "does not confirm compromise" in low, (
        f"{rule} description missing claim disclaimer"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Connector helper fixtures
# ──────────────────────────────────────────────────────────────────────────────


def _make_role_assignment(
    *,
    role_def_id: str = "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    principal_type: str = "ServicePrincipal",
    scope: str = "/subscriptions/sub",
    condition: str | None = None,
) -> dict:
    return {
        "id": "/subscriptions/sub/providers/Microsoft.Authorization/roleAssignments/ra-id-1",
        "type": "Microsoft.Authorization/roleAssignments",
        "properties": {
            "roleDefinitionId": role_def_id,
            "principalId": "NEVER-STORED-GUID",
            "principalType": principal_type,
            "scope": scope,
            "condition": condition,
            "createdOn": "2025-01-01T00:00:00Z",
            "updatedOn": "2025-06-01T00:00:00Z",
        },
    }


def _make_app_service(
    *,
    name: str = "myapp",
    https_only: bool = True,
    public_network_access: str = "Disabled",
    client_cert_enabled: bool = False,
) -> dict:
    return {
        "id": f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/{name}",
        "name": name,
        "kind": "app",
        "location": "eastus",
        "properties": {
            "httpsOnly": https_only,
            "publicNetworkAccess": public_network_access,
            "clientCertEnabled": client_cert_enabled,
        },
    }


def _make_site_config(
    *,
    ftps_state: str = "FtpsOnly",
    min_tls_version: str = "1.2",
    site_auth_enabled: bool = False,
    app_settings: list | None = None,
    connection_strings: list | None = None,
) -> dict:
    return {
        "properties": {
            "ftpsState": ftps_state,
            "minTlsVersion": min_tls_version,
            "siteAuthEnabled": site_auth_enabled,
            "appSettings": app_settings or [],
            "connectionStrings": connection_strings or [],
        }
    }


def _make_sql_server(
    *,
    name: str = "sql-prod",
    public_network_access: str = "Enabled",
    minimal_tls: str = "1.2",
    azure_ad_only: bool | None = None,
) -> dict:
    props: dict = {
        "publicNetworkAccess": public_network_access,
        "minimalTlsVersion": minimal_tls,
    }
    if azure_ad_only is not None:
        props["administrators"] = {"azureADOnlyAuthentication": azure_ad_only}
    return {
        "id": f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/{name}",
        "name": name,
        "location": "eastus",
        "properties": props,
    }


def _make_aks_cluster(
    *,
    name: str = "aks-prod",
    private_cluster: bool = False,
    local_account_disabled: bool = True,
    azure_rbac: bool = True,
    network_plugin: str = "azure",
    network_policy: str = "azure",
    public_network_access: str = "Disabled",
    ip_ranges: list | None = None,
) -> dict:
    return {
        "id": f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/{name}",
        "name": name,
        "location": "eastus",
        "properties": {
            "disableLocalAccounts": local_account_disabled,
            "publicNetworkAccess": public_network_access,
            "apiServerAccessProfile": {
                "enablePrivateCluster": private_cluster,
                "authorizedIPRanges": ip_ranges or [],
            },
            "aadProfile": {
                "enableAzureRBAC": azure_rbac,
            },
            "networkProfile": {
                "networkPlugin": network_plugin,
                "networkPolicy": network_policy,
            },
        },
    }


# ──────────────────────────────────────────────────────────────────────────────
# Schema constants
# ──────────────────────────────────────────────────────────────────────────────


class TestAzureSchemaM77C:
    def test_new_record_types_defined(self):
        assert AZURE_ROLE_ASSIGNMENT == "azure_role_assignment"
        assert AZURE_APP_SERVICE == "azure_app_service"
        assert AZURE_SQL_SERVER == "azure_sql_server"
        assert AZURE_AKS_CLUSTER == "azure_aks_cluster"

    def test_all_m77c_types_in_aggregate_set(self):
        for rt in (AZURE_ROLE_ASSIGNMENT, AZURE_APP_SERVICE, AZURE_SQL_SERVER, AZURE_AKS_CLUSTER):
            assert rt in AZURE_RECORD_TYPES, f"{rt} missing from AZURE_RECORD_TYPES"

    def test_m77a_types_still_present(self):
        for rt in (
            AZURE_SUBSCRIPTION, AZURE_RESOURCE_GROUP,
            AZURE_NETWORK_SECURITY_GROUP, AZURE_STORAGE_ACCOUNT, AZURE_KEY_VAULT,
        ):
            assert rt in AZURE_RECORD_TYPES


# ──────────────────────────────────────────────────────────────────────────────
# Connector helper functions
# ──────────────────────────────────────────────────────────────────────────────


class TestScopeDerivation:
    def test_subscription_scope(self):
        assert _derive_scope_type("/subscriptions/abc-123") == "subscription"
        assert _derive_scope_type("/subscriptions/abc-123/") == "subscription"

    def test_resource_group_scope(self):
        assert _derive_scope_type("/subscriptions/sub/resourceGroups/rg") == "resource_group"
        assert _derive_scope_type("/subscriptions/sub/resourceGroups/rg/") == "resource_group"

    def test_resource_scope(self):
        result = _derive_scope_type(
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/myapp"
        )
        assert result == "resource"

    def test_management_group_scope(self):
        assert _derive_scope_type("/managementGroups/mg-id") == "management_group"

    def test_empty_and_invalid(self):
        assert _derive_scope_type("") in ("global", "")
        assert _derive_scope_type("notapath") == "resource"


class TestRoleNameResolution:
    def test_owner_resolved(self):
        role_id = "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
        assert _resolve_role_name(role_id) == "Owner"

    def test_contributor_resolved(self):
        role_id = "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
        assert _resolve_role_name(role_id) == "Contributor"

    def test_user_access_admin_resolved(self):
        role_id = "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
        assert _resolve_role_name(role_id) == "User Access Administrator"

    def test_reader_resolved(self):
        role_id = "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
        assert _resolve_role_name(role_id) == "Reader"

    def test_custom_role_returns_empty(self):
        role_id = "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-0000-0000-0000-000000000000"
        assert _resolve_role_name(role_id) == ""

    def test_non_string_input(self):
        assert _resolve_role_name(None) == ""  # type: ignore[arg-type]


# ──────────────────────────────────────────────────────────────────────────────
# Connector normalizers
# ──────────────────────────────────────────────────────────────────────────────


class TestRoleAssignmentNormalizer:
    def setup_method(self):
        self.conn = AzureConnector()

    def _normalize(self, raw: dict) -> dict:
        return self.conn._normalize_role_assignment(raw)

    def test_basic_fields_present(self):
        rec = self._normalize(_make_role_assignment())
        assert rec["record_type"] == AZURE_ROLE_ASSIGNMENT
        assert rec["scope_type"] == "subscription"
        assert rec["role_definition_name"] == "Owner"
        assert rec["principal_type"] == "ServicePrincipal"

    def test_principal_id_never_stored(self):
        rec = self._normalize(_make_role_assignment())
        assert "principal_id" not in rec
        assert "NEVER-STORED-GUID" not in json.dumps(rec)

    def test_resource_group_scope(self):
        rec = self._normalize(
            _make_role_assignment(scope="/subscriptions/sub/resourceGroups/my-rg")
        )
        assert rec["scope_type"] == "resource_group"
        assert rec["resource_group"] == "my-rg"

    def test_condition_present_when_set(self):
        rec = self._normalize(_make_role_assignment(condition="@Resource[...]=..."))
        assert rec["condition_present"] is True

    def test_condition_present_false_when_null(self):
        rec = self._normalize(_make_role_assignment(condition=None))
        assert rec["condition_present"] is None

    def test_role_definition_id_is_guid_only(self):
        rec = self._normalize(_make_role_assignment())
        # Must be just the GUID, not the full ARM path
        rdid = rec["role_definition_id"]
        assert "/" not in rdid
        assert rdid == "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"


class TestAppServiceNormalizer:
    def setup_method(self):
        self.conn = AzureConnector()

    def _normalize(self, raw: dict, config: dict | None = None) -> dict:
        return self.conn._normalize_app_service(raw, config)

    def test_basic_fields_without_config(self):
        rec = self._normalize(_make_app_service())
        assert rec["record_type"] == AZURE_APP_SERVICE
        assert rec["app_name"] == "myapp"
        assert rec["https_only"] is True
        assert rec["ftps_state"] is None
        assert rec["min_tls_version"] is None

    def test_fields_from_site_config(self):
        rec = self._normalize(
            _make_app_service(https_only=False),
            _make_site_config(
                ftps_state="AllAllowed",
                min_tls_version="1.1",
                app_settings=[{"name": "KEY", "value": "VAL"}],
                connection_strings=[{"name": "CS"}],
            ),
        )
        assert rec["https_only"] is False
        assert rec["ftps_state"] == "AllAllowed"
        assert rec["min_tls_version"] == "1.1"
        # Count only — never names or values
        assert rec["app_settings_count"] == 1
        assert rec["connection_string_count"] == 1

    def test_app_setting_values_never_stored(self):
        config = _make_site_config(app_settings=[{"name": "DB_PASS", "value": "SECRET123"}])
        rec = self._normalize(_make_app_service(), config)
        text = json.dumps(rec)
        assert "SECRET123" not in text
        assert "DB_PASS" not in text  # setting NAMES also not stored


class TestSQLServerNormalizer:
    def setup_method(self):
        self.conn = AzureConnector()

    def _normalize(self, raw: dict, fw: list | None = None) -> dict:
        return self.conn._normalize_sql_server(raw, fw)

    def test_basic_fields(self):
        rec = self._normalize(_make_sql_server())
        assert rec["record_type"] == AZURE_SQL_SERVER
        assert rec["server_name"] == "sql-prod"
        assert rec["public_network_access"] == "Enabled"
        assert rec["minimum_tls_version"] == "1.2"

    def test_firewall_count_when_provided(self):
        fw = [
            {"properties": {"startIpAddress": "10.0.0.1", "endIpAddress": "10.0.0.255"}},
            {"properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}},
        ]
        rec = self._normalize(_make_sql_server(), fw)
        assert rec["firewall_rule_count"] == 2
        assert rec["has_allow_azure_services_rule"] is True

    def test_no_azure_services_rule_when_absent(self):
        fw = [{"properties": {"startIpAddress": "10.0.0.1", "endIpAddress": "10.0.0.10"}}]
        rec = self._normalize(_make_sql_server(), fw)
        assert rec["has_allow_azure_services_rule"] is False

    def test_no_firewall_data(self):
        rec = self._normalize(_make_sql_server(), None)
        assert rec["firewall_rule_count"] is None
        assert rec["has_allow_azure_services_rule"] is None

    def test_admin_login_never_stored(self):
        raw = _make_sql_server()
        raw["properties"]["administratorLogin"] = "sqladmin"
        raw["properties"]["administratorLoginPassword"] = "SUPERSECRET"
        rec = self._normalize(raw)
        text = json.dumps(rec)
        assert "sqladmin" not in text
        assert "SUPERSECRET" not in text


class TestAKSClusterNormalizer:
    def setup_method(self):
        self.conn = AzureConnector()

    def _normalize(self, raw: dict) -> dict:
        return self.conn._normalize_aks_cluster(raw)

    def test_basic_fields(self):
        rec = self._normalize(_make_aks_cluster())
        assert rec["record_type"] == AZURE_AKS_CLUSTER
        assert rec["cluster_name"] == "aks-prod"
        assert rec["private_cluster_enabled"] is False
        assert rec["local_account_disabled"] is True
        assert rec["network_policy"] == "azure"
        assert rec["api_server_authorized_ip_range_count"] == 0

    def test_ip_ranges_count(self):
        rec = self._normalize(_make_aks_cluster(ip_ranges=["1.2.3.4/32", "5.6.7.8/32"]))
        assert rec["api_server_authorized_ip_range_count"] == 2

    def test_no_kubeconfig_or_certs(self):
        rec = self._normalize(_make_aks_cluster())
        text = json.dumps(rec)
        assert "kubeconfig" not in text.lower()
        assert "certificate" not in text.lower()


# ──────────────────────────────────────────────────────────────────────────────
# Security rule evaluators
# ──────────────────────────────────────────────────────────────────────────────

_SUB = "/subscriptions/sub"
_RG = "/subscriptions/sub/resourceGroups/rg"


def _ra_record(**kwargs) -> dict:
    conn = AzureConnector()
    raw = _make_role_assignment(**kwargs)
    return conn._normalize_role_assignment(raw)


def _app_record(raw_kwargs: dict | None = None, config: dict | None = None) -> dict:
    conn = AzureConnector()
    raw = _make_app_service(**(raw_kwargs or {}))
    return conn._normalize_app_service(raw, config)


def _sql_record(raw_kwargs: dict | None = None, fw: list | None = None) -> dict:
    conn = AzureConnector()
    raw = _make_sql_server(**(raw_kwargs or {}))
    return conn._normalize_sql_server(raw, fw)


def _aks_record(**kwargs) -> dict:
    conn = AzureConnector()
    return conn._normalize_aks_cluster(_make_aks_cluster(**kwargs))


class TestRoleAssignmentRule:
    def test_owner_at_subscription_fires_high(self):
        findings = evaluate(_ra_record(scope=_SUB))
        ra = [f for f in findings if f.rule_key == "azure_role_assignment_broad_privilege"]
        assert len(ra) == 1
        assert ra[0].severity == "high"
        assert ra[0].evidence["role_definition_name"] == "Owner"
        assert ra[0].evidence["scope_type"] == "subscription"

    def test_contributor_at_resource_group_fires_medium(self):
        findings = evaluate(_ra_record(
            role_def_id=f"{_SUB}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
            scope=_RG,
        ))
        ra = [f for f in findings if f.rule_key == "azure_role_assignment_broad_privilege"]
        assert len(ra) == 1
        assert ra[0].severity == "medium"

    def test_reader_does_not_fire(self):
        findings = evaluate(_ra_record(
            role_def_id=f"{_SUB}/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
            scope=_SUB,
        ))
        assert not any(f.rule_key == "azure_role_assignment_broad_privilege" for f in findings)

    def test_resource_scope_does_not_fire(self):
        findings = evaluate(_ra_record(
            scope=f"{_RG}/providers/Microsoft.Web/sites/myapp",
        ))
        assert not any(f.rule_key == "azure_role_assignment_broad_privilege" for f in findings)

    def test_custom_role_does_not_fire(self):
        findings = evaluate(_ra_record(
            role_def_id=f"{_SUB}/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-0000-0000-0000-000000000000",
            scope=_SUB,
        ))
        assert not any(f.rule_key == "azure_role_assignment_broad_privilege" for f in findings)

    def test_principal_id_not_in_evidence(self):
        findings = evaluate(_ra_record(scope=_SUB))
        for f in findings:
            assert "principal_id" not in f.evidence
            assert "NEVER-STORED-GUID" not in json.dumps(f.evidence)

    def test_evidence_safe(self):
        findings = evaluate(_ra_record(scope=_SUB))
        for f in findings:
            _assert_evidence_safe(f.evidence, f.rule_key)
            _assert_no_overclaim(f.description, f.rule_key)


class TestAppServiceRules:
    def test_https_disabled_fires_high(self):
        rec = _app_record({"https_only": False})
        findings = evaluate(rec)
        h = [f for f in findings if f.rule_key == "azure_app_service_https_disabled"]
        assert len(h) == 1
        assert h[0].severity == "high"

    def test_https_enabled_does_not_fire(self):
        rec = _app_record({"https_only": True})
        findings = evaluate(rec)
        assert not any(f.rule_key == "azure_app_service_https_disabled" for f in findings)

    def test_ftp_enabled_fires(self):
        rec = _app_record(config=_make_site_config(ftps_state="AllAllowed"))
        findings = evaluate(rec)
        f = next((f for f in findings if f.rule_key == "azure_app_service_ftp_enabled"), None)
        assert f is not None
        assert f.severity == "medium"

    def test_ftps_only_does_not_fire(self):
        rec = _app_record(config=_make_site_config(ftps_state="FtpsOnly"))
        findings = evaluate(rec)
        assert not any(f.rule_key == "azure_app_service_ftp_enabled" for f in findings)

    def test_disabled_ftp_does_not_fire(self):
        rec = _app_record(config=_make_site_config(ftps_state="Disabled"))
        findings = evaluate(rec)
        assert not any(f.rule_key == "azure_app_service_ftp_enabled" for f in findings)

    @pytest.mark.parametrize("tls", ["1.0", "1.1"])
    def test_weak_tls_fires(self, tls: str):
        rec = _app_record(config=_make_site_config(min_tls_version=tls))
        findings = evaluate(rec)
        f = next((f for f in findings if f.rule_key == "azure_app_service_weak_tls"), None)
        assert f is not None
        assert f.evidence["min_tls_version"] == tls

    @pytest.mark.parametrize("tls", ["1.2", "1.3", ""])
    def test_strong_or_missing_tls_does_not_fire(self, tls: str):
        rec = _app_record(config=_make_site_config(min_tls_version=tls))
        findings = evaluate(rec)
        assert not any(f.rule_key == "azure_app_service_weak_tls" for f in findings)

    def test_public_network_access_fires(self):
        rec = _app_record({"public_network_access": "Enabled"})
        findings = evaluate(rec)
        f = next((f for f in findings if f.rule_key == "azure_app_service_public_network_access"), None)
        assert f is not None
        assert f.severity == "medium"

    def test_disabled_public_access_does_not_fire(self):
        rec = _app_record({"public_network_access": "Disabled"})
        findings = evaluate(rec)
        assert not any(f.rule_key == "azure_app_service_public_network_access" for f in findings)

    def test_app_setting_names_not_in_evidence(self):
        config = _make_site_config(app_settings=[{"name": "DB_PASSWORD", "value": "S3CR3T"}])
        rec = _app_record({"https_only": False, "public_network_access": "Enabled"}, config)
        findings = evaluate(rec)
        for f in findings:
            _assert_evidence_safe(f.evidence, f.rule_key)
            assert "DB_PASSWORD" not in json.dumps(f.evidence)


class TestSQLServerRules:
    def test_public_network_access_fires_medium_without_azure_services(self):
        rec = _sql_record(
            {"public_network_access": "Enabled", "minimal_tls": "1.2"},
            fw=[{"properties": {"startIpAddress": "10.0.0.0", "endIpAddress": "10.0.0.255"}}],
        )
        findings = evaluate(rec)
        f = next(f for f in findings if f.rule_key == "azure_sql_public_network_access")
        assert f.severity == "medium"
        assert f.evidence.get("has_allow_azure_services_rule") is False

    def test_public_network_access_fires_high_with_azure_services(self):
        fw = [{"properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}]
        rec = _sql_record({"public_network_access": "Enabled"}, fw)
        findings = evaluate(rec)
        f = next(f for f in findings if f.rule_key == "azure_sql_public_network_access")
        assert f.severity == "high"

    def test_public_disabled_does_not_fire(self):
        rec = _sql_record({"public_network_access": "Disabled"})
        findings = evaluate(rec)
        assert not any(f.rule_key == "azure_sql_public_network_access" for f in findings)

    @pytest.mark.parametrize("tls", ["1.0", "1.1"])
    def test_weak_tls_fires(self, tls: str):
        rec = _sql_record({"public_network_access": "Disabled", "minimal_tls": tls})
        findings = evaluate(rec)
        f = next((f for f in findings if f.rule_key == "azure_sql_weak_tls"), None)
        assert f is not None

    def test_strong_tls_does_not_fire(self):
        rec = _sql_record({"public_network_access": "Disabled", "minimal_tls": "1.2"})
        findings = evaluate(rec)
        assert not any(f.rule_key == "azure_sql_weak_tls" for f in findings)

    def test_evidence_safe(self):
        fw = [{"properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}]
        rec = _sql_record({"public_network_access": "Enabled", "minimal_tls": "1.0"}, fw)
        for f in evaluate(rec):
            _assert_evidence_safe(f.evidence, f.rule_key)
            _assert_no_overclaim(f.description, f.rule_key)


class TestAKSClusterRules:
    def test_local_accounts_enabled_fires(self):
        rec = _aks_record(local_account_disabled=False)
        findings = evaluate(rec)
        f = next(f for f in findings if f.rule_key == "azure_aks_local_accounts_enabled")
        assert f.severity == "medium"

    def test_local_accounts_disabled_does_not_fire(self):
        rec = _aks_record(local_account_disabled=True)
        findings = evaluate(rec)
        assert not any(f.rule_key == "azure_aks_local_accounts_enabled" for f in findings)

    def test_public_api_no_ip_ranges_fires_high(self):
        rec = _aks_record(private_cluster=False, ip_ranges=[])
        findings = evaluate(rec)
        f = next(f for f in findings if f.rule_key == "azure_aks_public_api_access")
        assert f.severity == "high"
        assert f.evidence["api_server_authorized_ip_range_count"] == 0

    def test_public_api_with_ip_ranges_does_not_fire(self):
        rec = _aks_record(private_cluster=False, ip_ranges=["10.0.0.0/24"])
        findings = evaluate(rec)
        assert not any(f.rule_key == "azure_aks_public_api_access" for f in findings)

    def test_private_cluster_does_not_fire(self):
        rec = _aks_record(private_cluster=True, ip_ranges=[])
        findings = evaluate(rec)
        assert not any(f.rule_key == "azure_aks_public_api_access" for f in findings)

    @pytest.mark.parametrize("policy", ["", "none", "None"])
    def test_network_policy_missing_fires(self, policy: str):
        rec = _aks_record(network_policy=policy)
        findings = evaluate(rec)
        f = next(f for f in findings if f.rule_key == "azure_aks_network_policy_missing")
        assert f.severity == "medium"

    @pytest.mark.parametrize("policy", ["azure", "calico", "cilium"])
    def test_network_policy_set_does_not_fire(self, policy: str):
        rec = _aks_record(network_policy=policy)
        findings = evaluate(rec)
        assert not any(f.rule_key == "azure_aks_network_policy_missing" for f in findings)

    def test_kubeconfig_not_in_evidence(self):
        rec = _aks_record(private_cluster=False, ip_ranges=[], network_policy="", local_account_disabled=False)
        for f in evaluate(rec):
            _assert_evidence_safe(f.evidence, f.rule_key)


class TestDispatchNegatives:
    def test_subscription_record_returns_empty(self):
        assert evaluate({"record_type": AZURE_SUBSCRIPTION}) == []

    def test_resource_group_record_returns_empty(self):
        assert evaluate({"record_type": AZURE_RESOURCE_GROUP}) == []

    def test_unknown_record_type_returns_empty(self):
        assert evaluate({"record_type": "github_repo"}) == []

    def test_non_dict_returns_empty(self):
        assert evaluate(None) == []  # type: ignore[arg-type]
        assert evaluate("string") == []  # type: ignore[arg-type]


# ──────────────────────────────────────────────────────────────────────────────
# Registry / confidence / pack / coverage / catalog parity
# ──────────────────────────────────────────────────────────────────────────────


class TestRuleKeyParity:
    def test_azure_rule_keys_module_has_all_20(self):
        assert AZURE_RULE_KEYS == ALL_AZURE_RULE_KEYS

    def test_m77c_keys_in_registry(self):
        missing = M77C_RULE_KEYS - set(KNOWN_RULE_KEYS)
        assert missing == set(), f"missing in KNOWN_RULE_KEYS: {missing}"

    def test_m77c_keys_in_confidence(self):
        missing = M77C_RULE_KEYS - set(RULE_CONFIDENCE)
        assert missing == set(), f"missing in RULE_CONFIDENCE: {missing}"

    def test_m77c_keys_in_pack(self):
        missing = M77C_RULE_KEYS - set(_RULE_META)
        assert missing == set(), f"missing in _RULE_META: {missing}"
        for k in M77C_RULE_KEYS:
            provider, _sev, _cat = _RULE_META[k]
            assert provider == "azure"

    def test_m77c_keys_in_coverage(self):
        missing = M77C_RULE_KEYS - set(RULE_RECORD_TYPES)
        assert missing == set(), f"missing in RULE_RECORD_TYPES: {missing}"

    def test_coverage_record_type_mappings(self):
        assert RULE_RECORD_TYPES["azure_role_assignment_broad_privilege"] == ("azure_role_assignment",)
        for k in ("azure_app_service_https_disabled", "azure_app_service_ftp_enabled",
                  "azure_app_service_weak_tls", "azure_app_service_public_network_access"):
            assert RULE_RECORD_TYPES[k] == ("azure_app_service",)
        for k in ("azure_sql_public_network_access", "azure_sql_weak_tls"):
            assert RULE_RECORD_TYPES[k] == ("azure_sql_server",)
        for k in ("azure_aks_local_accounts_enabled", "azure_aks_public_api_access",
                  "azure_aks_network_policy_missing"):
            assert RULE_RECORD_TYPES[k] == ("azure_aks_cluster",)

    def test_provider_surfaces_updated(self):
        surfaces = PROVIDER_SURFACES["azure"]
        assert "Identity / Role assignments" in surfaces
        assert "App Service / Functions" in surfaces
        assert "SQL Servers" in surfaces
        assert "AKS Clusters" in surfaces

    def test_pack_import_time_assert_passes(self):
        from app.services.security_rule_pack import pack_summary
        summary = pack_summary()
        keys_in_pack = {r["rule_key"] for r in summary["rules"]}
        assert M77C_RULE_KEYS.issubset(keys_in_pack)


class TestFrontendCatalog:
    def test_all_m77c_keys_in_catalog(self):
        if not FRONTEND_CATALOG.exists():
            pytest.skip("frontend/src not mounted in this environment")
        text = FRONTEND_CATALOG.read_text()
        for key in M77C_RULE_KEYS:
            assert f'key: "{key}"' in text, f"frontend catalog missing {key}"

    def test_azure_in_provider_coverage(self):
        if not FRONTEND_CATALOG.exists():
            pytest.skip("frontend/src not mounted in this environment")
        text = FRONTEND_CATALOG.read_text()
        # Check that the azure PROVIDER_COVERAGE entry has the new surfaces
        assert "Identity / Role assignments" in text
        assert "App Service / Functions" in text
        assert "SQL Servers" in text
        assert "AKS Clusters" in text


# ──────────────────────────────────────────────────────────────────────────────
# Capability matrix + expansion framework
# ──────────────────────────────────────────────────────────────────────────────


class TestCapabilityMatrix:
    def test_azure_still_partial(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.maturity == "partial"

    def test_azure_security_rules_true(self):
        cap = get_provider_capability("azure")
        assert cap.security.security_rules is True

    def test_azure_activity_still_false(self):
        """Flipped in M77D/E/F/G: all Azure security capabilities now True."""
        cap = get_provider_capability("azure")
        assert cap.security.activity_ingestion is True   # flipped in M77D
        assert cap.security.activity_signals is True     # flipped in M77E
        assert cap.security.risk_activity_correlations is True  # flipped in M77F
        assert cap.security.demo_seed_clear is True      # flipped in M77G
        assert cap.security.case_report is True          # flipped in M77G

    def test_azure_not_in_canonical_8(self):
        from app.services.provider_capability_matrix_service import PROVIDER_CAPABILITIES
        providers_in_canonical = {p.provider for p in PROVIDER_CAPABILITIES}
        assert "azure" not in providers_in_canonical

    def test_azure_in_partial_list(self):
        from app.services.provider_capability_matrix_service import PROVIDER_CAPABILITIES_PARTIAL
        providers_partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert "azure" in providers_partial


class TestExpansionFramework:
    def test_next_stage_is_m77d(self):
        """Rolled forward in M78B: GCP core security foundation landed → M78C."""
        fw = get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M78F" in stage


# ──────────────────────────────────────────────────────────────────────────────
# Deferred rules documented
# ──────────────────────────────────────────────────────────────────────────────


class TestDeferredRules:
    DEFERRED = {
        "azure_role_assignment_no_condition",
        "azure_app_registration_client_secret_present",
        "azure_app_registration_public_client_enabled",
        "azure_app_registration_broad_audience",
    }

    def test_deferred_rules_not_in_registry(self):
        for key in self.DEFERRED:
            assert key not in KNOWN_RULE_KEYS, (
                f"Deferred rule {key} should not be in KNOWN_RULE_KEYS"
            )

    def test_deferred_not_in_evaluator(self):
        # Keys must not appear as quoted string literals in the module;
        # they are allowed to appear in docstring comments.
        import inspect
        src = inspect.getsource(azure_rules)
        for key in self.DEFERRED:
            # Check that key is not assigned as a Python string value
            assert f'"{key}"' not in src and f"'{key}'" not in src, (
                f"Deferred rule key {key} should not be a string literal in azure_rules"
            )


# ──────────────────────────────────────────────────────────────────────────────
# M77A + M77B regression
# ──────────────────────────────────────────────────────────────────────────────


class TestM77ABRegression:
    def test_m77a_record_types_canonical(self):
        assert AZURE_SUBSCRIPTION == "azure_subscription"
        assert AZURE_RESOURCE_GROUP == "azure_resource_group"
        assert AZURE_NETWORK_SECURITY_GROUP == "azure_network_security_group"
        assert AZURE_STORAGE_ACCOUNT == "azure_storage_account"
        assert AZURE_KEY_VAULT == "azure_key_vault"

    def test_m77b_rules_still_registered(self):
        m77b = {
            "azure_nsg_public_admin_ingress", "azure_nsg_public_broad_ingress",
            "azure_storage_public_blob_access", "azure_storage_public_network_access",
            "azure_storage_weak_tls", "azure_storage_shared_key_enabled",
            "azure_key_vault_public_network_access", "azure_key_vault_purge_protection_disabled",
            "azure_key_vault_soft_delete_disabled", "azure_key_vault_rbac_disabled",
        }
        assert m77b.issubset(KNOWN_RULE_KEYS)

    def test_m77b_nsg_rule_still_fires(self):
        record = {
            "record_type": AZURE_NETWORK_SECURITY_GROUP,
            "record_id": "/subscriptions/s/resourceGroups/rg/providers/nsg-prod",
            "nsg_name": "nsg-prod",
            "resource_group": "rg",
            "location": "eastus",
            "rules_summary": [{
                "rule_name": "allow-ssh",
                "direction": "Inbound",
                "access": "Allow",
                "source_address_prefix": "*",
                "destination_port_range": "22",
                "protocol": "Tcp",
                "priority": 100,
                "source_port_range": "*",
                "destination_address_prefix": "*",
            }],
        }
        findings = evaluate(record)
        assert any(f.rule_key == "azure_nsg_public_admin_ingress" for f in findings)

    def test_m77b_storage_rule_still_fires(self):
        record = {
            "record_type": AZURE_STORAGE_ACCOUNT,
            "record_id": "/subscriptions/s/resourceGroups/rg/providers/acct",
            "account_name": "acct",
            "resource_group": "rg",
            "location": "eastus",
            "allow_blob_public_access": True,
            "public_network_access": "",
            "network_default_action": "",
            "minimum_tls_version": "",
            "shared_access_key_enabled": None,
        }
        findings = evaluate(record)
        assert any(f.rule_key == "azure_storage_public_blob_access" for f in findings)

    def test_evaluator_still_registered(self):
        assert "azure" in _PROVIDER_RULES
        assert azure_rules.evaluate in _PROVIDER_RULES["azure"]
