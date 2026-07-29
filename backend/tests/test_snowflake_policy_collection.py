"""Snowflake security-policy collection tests (Snowflake message 4 of 8).

Covers the SHOW+bounded-DESCRIBE collection built in this message for
network policies, network rules, authentication policies, and security/
storage/external-access integrations: list/detail pattern, per-record
detail completeness, family independence, identifier quoting, and scale.

All tests are pure-mock (respx) or unit-level; no real Snowflake account is
contacted.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.connectors.snowflake import SnowflakeConnector, _ACCOUNT_IDENTITY_STATEMENT
from app.connectors.snowflake_schema import (
    DETAIL_COMPLETE,
    DETAIL_DENIED,
    DETAIL_UNAVAILABLE,
    FAMILY_DENIED,
    SNOWFLAKE_AUTHENTICATION_POLICY,
    SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION,
    SNOWFLAKE_NETWORK_POLICY,
    SNOWFLAKE_NETWORK_RULE,
    SNOWFLAKE_SECURITY_INTEGRATION,
    SNOWFLAKE_STORAGE_INTEGRATION,
)

_ACCOUNT_ID = "myorg-myaccount"
_USERNAME = "CONFIGTRACE_MONITOR"
_TOKEN = "fake-snowflake-pat-value"
_ROLE = "CONFIGTRACE_MONITOR"
_CREDS = {
    "account_identifier": _ACCOUNT_ID,
    "username": _USERNAME,
    "programmatic_access_token": _TOKEN,
    "role": _ROLE,
}
_BASE = f"https://{_ACCOUNT_ID}.snowflakecomputing.com"
_STATEMENTS_URL = f"{_BASE}/api/v2/statements"


def _cols(names: list[str]) -> dict:
    return {"resultSetMetaData": {"rowType": [{"name": n} for n in names]}}


def _resp(names: list[str], rows: list[list]) -> httpx.Response:
    body = _cols(names)
    body["data"] = rows
    return httpx.Response(200, json=body)


def _identity_resp(org="ACME", account="PROD", locator="AB123", role=_ROLE) -> httpx.Response:
    return _resp(["ORG_NAME", "ACCOUNT_NAME", "ACCOUNT_LOCATOR", "SESSION_ROLE"], [[org, account, locator, role]])


_NETWORK_POLICIES_COLS = [
    "NAME", "OWNER", "ENTRIES_IN_ALLOWED_IP_LIST", "ENTRIES_IN_BLOCKED_IP_LIST",
    "ENTRIES_IN_ALLOWED_NETWORK_RULES", "ENTRIES_IN_BLOCKED_NETWORK_RULES",
]
_NETWORK_RULES_COLS = ["NAME", "DATABASE_NAME", "SCHEMA_NAME", "OWNER", "TYPE", "MODE", "ENTRIES_IN_VALUELIST"]
_AUTH_POLICIES_COLS = ["NAME", "OWNER", "SET_ON"]
_DESCRIBE_NAME_VALUE_COLS = ["NAME", "VALUE"]
_INTEGRATIONS_COLS = ["NAME", "TYPE", "ENABLED", "OWNER"]
_DESCRIBE_PROPERTY_COLS = ["PROPERTY", "PROPERTY_VALUE"]


class _Router:
    def __init__(self):
        self.exact: dict[str, httpx.Response] = {_ACCOUNT_IDENTITY_STATEMENT: _identity_resp()}
        self.calls: list[str] = []

    def set(self, statement: str, response: httpx.Response) -> "_Router":
        self.exact[statement] = response
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        statement = body.get("statement", "")
        self.calls.append(statement)
        if statement in self.exact:
            return self.exact[statement]
        return httpx.Response(400, json={"message": f"unmocked statement: {statement}"})


def _noop_sleep(_seconds: float) -> None:
    pass


def _basic_router() -> _Router:
    r = _Router()
    r.set("SHOW USERS", _resp(["NAME"], []))
    r.set("SHOW ROLES", _resp(["NAME", "OWNER", "ASSIGNED_TO_USERS", "GRANTED_TO_ROLES", "GRANTED_ROLES"], []))
    r.set("SHOW DATABASES", _resp(["NAME"], []))
    r.set("SHOW WAREHOUSES", _resp(["NAME"], []))
    r.set("SHOW SHARES", _resp(["KIND", "NAME"], []))
    r.set("SHOW NETWORK POLICIES", _resp(_NETWORK_POLICIES_COLS, [
        ["OPEN_POLICY", "SECURITYADMIN", "1", "0", "0", "0"],
    ]))
    r.set('DESCRIBE NETWORK POLICY "OPEN_POLICY"', _resp(_DESCRIBE_NAME_VALUE_COLS, [
        ["ALLOWED_IP_LIST", "10.0.0.0/8"], ["BLOCKED_IP_LIST", ""],
    ]))
    r.set("SHOW NETWORK RULES", _resp(_NETWORK_RULES_COLS, [
        ["MY_RULE", "MYDB", "PUBLIC", "SYSADMIN", "HOST_PORT", "EGRESS", "3"],
    ]))
    r.set("SHOW AUTHENTICATION POLICIES", _resp(_AUTH_POLICIES_COLS, [
        ["STRICT_POLICY", "SECURITYADMIN", "ACCOUNT"],
    ]))
    r.set('DESCRIBE AUTHENTICATION POLICY "STRICT_POLICY"', _resp(_DESCRIBE_NAME_VALUE_COLS, [
        ["AUTHENTICATION_METHODS", "['SAML','PASSWORD']"],
        ["MFA_ENROLLMENT", "REQUIRED"],
        ["CLIENT_TYPES", "['ALL']"],
    ]))
    r.set("SHOW SECURITY INTEGRATIONS", _resp(_INTEGRATIONS_COLS, [
        ["MY_SAML", "SAML2", "true", "SECURITYADMIN"],
    ]))
    r.set('DESCRIBE INTEGRATION "MY_SAML"', _resp(_DESCRIBE_PROPERTY_COLS, [
        ["SAML2_ISSUER", "https://idp.example.com"],
        ["SAML2_SSO_URL", "https://idp.example.com/sso"],
        ["SAML2_X509_CERT", "MIIB-redacted"],
    ]))
    r.set("SHOW STORAGE INTEGRATIONS", _resp(_INTEGRATIONS_COLS, [
        ["MY_S3", "EXTERNAL_STAGE", "true", "SYSADMIN"],
    ]))
    r.set('DESCRIBE INTEGRATION "MY_S3"', _resp(_DESCRIBE_PROPERTY_COLS, [
        ["STORAGE_PROVIDER", "S3"],
        ["STORAGE_ALLOWED_LOCATIONS", "['s3://bucket1/', 's3://bucket2/']"],
        ["STORAGE_AWS_IAM_USER_ARN", "arn:aws:iam::123:user/x"],
    ]))
    r.set("SHOW EXTERNAL ACCESS INTEGRATIONS", _resp(_INTEGRATIONS_COLS, [
        ["MY_EAI", "EXTERNAL_ACCESS", "true", "SYSADMIN"],
    ]))
    r.set('DESCRIBE INTEGRATION "MY_EAI"', _resp(_DESCRIBE_PROPERTY_COLS, [
        ["ALLOWED_NETWORK_RULES", "['MY_RULE']"],
        ["ALLOWED_AUTHENTICATION_SECRETS", "['MY_SECRET']"],
        ["ALLOWED_API_AUTHENTICATION_INTEGRATIONS", "[]"],
    ]))
    return r


def _fetch(router: _Router) -> list[dict]:
    with respx.mock:
        respx.post(_STATEMENTS_URL).mock(side_effect=router)
        conn = SnowflakeConnector()
        return conn.fetch(_CREDS, _sleep_fn=_noop_sleep)


def _by_type(records: list[dict], record_type: str) -> list[dict]:
    return [r for r in records if r["record_type"] == record_type]


# ── Network policies ──────────────────────────────────────────────────────────


class TestNetworkPolicyCollection:
    def test_network_policies_collected(self):
        records = _fetch(_basic_router())
        policies = _by_type(records, SNOWFLAKE_NETWORK_POLICY)
        assert len(policies) == 1
        assert policies[0]["policy_name"] == "OPEN_POLICY"
        assert policies[0]["allowed_ipv4_count"] == 1

    def test_network_policies_family_denied(self):
        router = _basic_router()
        router.set("SHOW NETWORK POLICIES", httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["network_policies"] == FAMILY_DENIED
        assert _by_type(records, SNOWFLAKE_NETWORK_POLICY) == []

    def test_detail_succeeds_marks_complete(self):
        records = _fetch(_basic_router())
        policy = _by_type(records, SNOWFLAKE_NETWORK_POLICY)[0]
        assert policy["detail_collection_status"] == DETAIL_COMPLETE

    def test_list_succeeds_detail_denied_preserves_identity(self):
        """A per-policy DESCRIBE failure must never remove the policy's
        list-level identity/count fields — only detail fields stay
        unknown/unavailable."""
        router = _basic_router()
        router.set('DESCRIBE NETWORK POLICY "OPEN_POLICY"', httpx.Response(403))
        records = _fetch(router)
        policies = _by_type(records, SNOWFLAKE_NETWORK_POLICY)
        assert len(policies) == 1
        assert policies[0]["policy_name"] == "OPEN_POLICY"
        assert policies[0]["allowed_ipv4_count"] == 1
        assert policies[0]["detail_collection_status"] == DETAIL_DENIED
        assert policies[0]["allows_anywhere_ipv4"] == "unknown"

    def test_raw_ip_list_never_persisted(self):
        """DESCRIBE NETWORK POLICY returns the actual CIDR value — it must
        never appear anywhere in the normalized record."""
        records = _fetch(_basic_router())
        policy = _by_type(records, SNOWFLAKE_NETWORK_POLICY)[0]
        assert "10.0.0.0/8" not in str(policy)


# ── Network rules ─────────────────────────────────────────────────────────────


class TestNetworkRuleCollection:
    def test_network_rules_collected_no_describe_needed(self):
        """SHOW NETWORK RULES already exposes type/mode/count — no
        DESCRIBE NETWORK RULE call should ever be issued."""
        router = _basic_router()
        records = _fetch(router)
        rules = _by_type(records, SNOWFLAKE_NETWORK_RULE)
        assert len(rules) == 1
        assert rules[0]["rule_type"] == "HOST_PORT"
        assert rules[0]["rule_mode"] == "EGRESS"
        assert rules[0]["value_count"] == 3
        assert not any("DESCRIBE NETWORK RULE" in c for c in router.calls)

    def test_network_rules_family_denied(self):
        router = _basic_router()
        router.set("SHOW NETWORK RULES", httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["network_rules"] == FAMILY_DENIED


# ── Authentication policies ───────────────────────────────────────────────────


class TestAuthenticationPolicyCollection:
    def test_authentication_policies_collected(self):
        records = _fetch(_basic_router())
        policies = _by_type(records, SNOWFLAKE_AUTHENTICATION_POLICY)
        assert len(policies) == 1
        assert policies[0]["mfa_enrollment"] == "required"

    def test_authentication_policies_family_denied(self):
        router = _basic_router()
        router.set("SHOW AUTHENTICATION POLICIES", httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["authentication_policies"] == FAMILY_DENIED

    def test_list_succeeds_detail_denied_preserves_identity(self):
        router = _basic_router()
        router.set('DESCRIBE AUTHENTICATION POLICY "STRICT_POLICY"', httpx.Response(403))
        records = _fetch(router)
        policies = _by_type(records, SNOWFLAKE_AUTHENTICATION_POLICY)
        assert len(policies) == 1
        assert policies[0]["policy_name"] == "STRICT_POLICY"
        assert policies[0]["mfa_enrollment"] == "unknown"
        assert policies[0]["detail_collection_status"] == DETAIL_UNAVAILABLE


# ── Security integrations ─────────────────────────────────────────────────────


class TestSecurityIntegrationCollection:
    def test_security_integrations_collected(self):
        records = _fetch(_basic_router())
        integrations = _by_type(records, SNOWFLAKE_SECURITY_INTEGRATION)
        assert len(integrations) == 1
        assert integrations[0]["integration_type"] == "saml2"
        assert integrations[0]["saml2_certificate_configured"] == "true"

    def test_security_integrations_family_denied(self):
        router = _basic_router()
        router.set("SHOW SECURITY INTEGRATIONS", httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["security_integrations"] == FAMILY_DENIED

    def test_certificate_body_never_persisted(self):
        records = _fetch(_basic_router())
        integration = _by_type(records, SNOWFLAKE_SECURITY_INTEGRATION)[0]
        assert "MIIB-redacted" not in str(integration)

    def test_list_succeeds_detail_denied_preserves_identity(self):
        router = _basic_router()
        router.set('DESCRIBE INTEGRATION "MY_SAML"', httpx.Response(403))
        records = _fetch(router)
        integrations = _by_type(records, SNOWFLAKE_SECURITY_INTEGRATION)
        assert len(integrations) == 1
        assert integrations[0]["integration_name"] == "MY_SAML"
        assert integrations[0]["detail_collection_status"] == DETAIL_UNAVAILABLE


# ── Storage integrations ──────────────────────────────────────────────────────


class TestStorageIntegrationCollection:
    def test_storage_integrations_collected(self):
        records = _fetch(_basic_router())
        integrations = _by_type(records, SNOWFLAKE_STORAGE_INTEGRATION)
        assert len(integrations) == 1
        assert integrations[0]["storage_provider"] == "s3"
        assert integrations[0]["allowed_location_count"] == 2

    def test_storage_integrations_family_denied(self):
        router = _basic_router()
        router.set("SHOW STORAGE INTEGRATIONS", httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["storage_integrations"] == FAMILY_DENIED

    def test_cloud_arn_never_persisted(self):
        records = _fetch(_basic_router())
        integration = _by_type(records, SNOWFLAKE_STORAGE_INTEGRATION)[0]
        assert "arn:aws:iam" not in str(integration)


# ── External access integrations ──────────────────────────────────────────────


class TestExternalAccessIntegrationCollection:
    def test_external_access_integrations_collected(self):
        records = _fetch(_basic_router())
        integrations = _by_type(records, SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION)
        assert len(integrations) == 1
        assert integrations[0]["allowed_network_rule_count"] == 1
        assert integrations[0]["allowed_secret_count"] == 1

    def test_external_access_integrations_family_denied(self):
        router = _basic_router()
        router.set("SHOW EXTERNAL ACCESS INTEGRATIONS", httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["external_access_integrations"] == FAMILY_DENIED

    def test_secret_names_never_persisted(self):
        records = _fetch(_basic_router())
        integration = _by_type(records, SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION)[0]
        assert "MY_SECRET" not in str(integration)


# ── Family independence ──────────────────────────────────────────────────────


class TestFamilyIndependence:
    def test_network_policies_denied_does_not_affect_auth_policies(self):
        router = _basic_router()
        router.set("SHOW NETWORK POLICIES", httpx.Response(403))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_AUTHENTICATION_POLICY)) == 1

    def test_all_six_families_independent_statuses(self):
        router = _basic_router()
        router.set("SHOW NETWORK POLICIES", httpx.Response(403))
        router.set("SHOW STORAGE INTEGRATIONS", httpx.Response(429))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        fc = account["family_completeness"]
        assert fc["network_policies"] == FAMILY_DENIED
        assert fc["network_rules"] == "complete"
        assert fc["authentication_policies"] == "complete"
        assert fc["storage_integrations"] == "unavailable"


# ── Identifier safety ────────────────────────────────────────────────────────


class TestIdentifierSafety:
    def test_quoted_integration_name(self):
        router = _basic_router()
        router.set("SHOW SECURITY INTEGRATIONS", _resp(_INTEGRATIONS_COLS, [
            ['WEIRD"NAME', "SAML2", "true", "SECURITYADMIN"],
        ]))
        router.set('DESCRIBE INTEGRATION "WEIRD""NAME"', _resp(_DESCRIBE_PROPERTY_COLS, []))
        records = _fetch(router)
        integrations = _by_type(records, SNOWFLAKE_SECURITY_INTEGRATION)
        assert any(i["integration_name"] == 'WEIRD"NAME' for i in integrations)

    def test_quote_in_policy_name(self):
        router = _basic_router()
        router.set("SHOW AUTHENTICATION POLICIES", _resp(_AUTH_POLICIES_COLS, [
            ['WEIRD"POLICY', "SECURITYADMIN", "ACCOUNT"],
        ]))
        router.set('DESCRIBE AUTHENTICATION POLICY "WEIRD""POLICY"', _resp(_DESCRIBE_NAME_VALUE_COLS, []))
        records = _fetch(router)
        policies = _by_type(records, SNOWFLAKE_AUTHENTICATION_POLICY)
        assert any(p["policy_name"] == 'WEIRD"POLICY' for p in policies)

    def test_injection_shaped_integration_name_stays_an_identifier(self):
        router = _basic_router()
        malicious_name = 'x"; DROP TABLE x; --'
        router.set("SHOW SECURITY INTEGRATIONS", _resp(_INTEGRATIONS_COLS, [
            [malicious_name, "SAML2", "true", "SECURITYADMIN"],
        ]))
        escaped = malicious_name.replace(chr(34), chr(34) * 2)
        router.set(f'DESCRIBE INTEGRATION "{escaped}"', _resp(_DESCRIBE_PROPERTY_COLS, []))
        records = _fetch(router)
        integrations = _by_type(records, SNOWFLAKE_SECURITY_INTEGRATION)
        assert any(i["integration_name"] == malicious_name for i in integrations)


# ── Scale ─────────────────────────────────────────────────────────────────────


class TestScale:
    def test_1000_network_policies(self):
        router = _basic_router()
        rows = [[f"POLICY_{i}", "SECURITYADMIN", "1", "0", "0", "0"] for i in range(1000)]
        router.set("SHOW NETWORK POLICIES", _resp(_NETWORK_POLICIES_COLS, rows))
        for i in range(1000):
            router.set(f'DESCRIBE NETWORK POLICY "POLICY_{i}"', _resp(_DESCRIBE_NAME_VALUE_COLS, []))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_NETWORK_POLICY)) == 1000

    def test_1000_authentication_policies(self):
        router = _basic_router()
        rows = [[f"AUTHPOL_{i}", "SECURITYADMIN", "ACCOUNT"] for i in range(1000)]
        router.set("SHOW AUTHENTICATION POLICIES", _resp(_AUTH_POLICIES_COLS, rows))
        for i in range(1000):
            router.set(f'DESCRIBE AUTHENTICATION POLICY "AUTHPOL_{i}"', _resp(_DESCRIBE_NAME_VALUE_COLS, []))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_AUTHENTICATION_POLICY)) == 1000

    def test_2000_security_integrations(self):
        router = _basic_router()
        rows = [[f"INTEGRATION_{i}", "OAUTH", "true", "SYSADMIN"] for i in range(2000)]
        router.set("SHOW SECURITY INTEGRATIONS", _resp(_INTEGRATIONS_COLS, rows))
        for i in range(2000):
            router.set(f'DESCRIBE INTEGRATION "INTEGRATION_{i}"', _resp(_DESCRIBE_PROPERTY_COLS, []))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_SECURITY_INTEGRATION)) == 2000

    def test_2000_storage_integrations(self):
        router = _basic_router()
        rows = [[f"STORAGE_{i}", "EXTERNAL_STAGE", "true", "SYSADMIN"] for i in range(2000)]
        router.set("SHOW STORAGE INTEGRATIONS", _resp(_INTEGRATIONS_COLS, rows))
        for i in range(2000):
            router.set(f'DESCRIBE INTEGRATION "STORAGE_{i}"', _resp(_DESCRIBE_PROPERTY_COLS, []))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_STORAGE_INTEGRATION)) == 2000

    def test_2000_external_access_integrations(self):
        router = _basic_router()
        rows = [[f"EAI_{i}", "EXTERNAL_ACCESS", "true", "SYSADMIN"] for i in range(2000)]
        router.set("SHOW EXTERNAL ACCESS INTEGRATIONS", _resp(_INTEGRATIONS_COLS, rows))
        for i in range(2000):
            router.set(f'DESCRIBE INTEGRATION "EAI_{i}"', _resp(_DESCRIBE_PROPERTY_COLS, []))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION)) == 2000
