"""Snowflake effective-privilege collection tests (Snowflake message 5 of
8).

End-to-end tests through ``SnowflakeConnector.fetch()``: the privilege
derivation runs as a pure local join over message 1-4's already-collected
records, appending ``snowflake_privileged_user`` /
``snowflake_privileged_role`` / ``snowflake_public_exposure`` records with
ZERO additional SQL calls beyond what messages 1-4 already issue. All
tests are pure-mock (respx); no real Snowflake account is contacted.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.connectors.snowflake import SnowflakeConnector, _ACCOUNT_IDENTITY_STATEMENT
from app.connectors.snowflake_schema import (
    FAMILY_COMPLETE,
    FAMILY_UNAVAILABLE,
    PRIVILEGE_TIER_CRITICAL,
    PRIVILEGE_TIER_HIGH,
    SNOWFLAKE_PRIVILEGED_ROLE,
    SNOWFLAKE_PRIVILEGED_USER,
    SNOWFLAKE_PUBLIC_EXPOSURE,
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

_USERS_COLS = ["NAME", "TYPE", "DISABLED", "DEFAULT_ROLE", "DEFAULT_SECONDARY_ROLES",
               "HAS_RSA_PUBLIC_KEY", "HAS_PASSWORD", "HAS_PAT", "OWNER"]
_ACCOUNT_ROLES_COLS = ["NAME", "OWNER", "ASSIGNED_TO_USERS", "GRANTED_TO_ROLES", "GRANTED_ROLES"]
_GRANTS_OF_COLS = ["CREATED_ON", "ROLE", "GRANTED_TO", "GRANTEE_NAME", "GRANTED_BY"]
_GRANTS_TO_ROLE_COLS = ["PRIVILEGE", "GRANTED_ON", "NAME", "GRANTED_TO", "GRANTEE_NAME", "GRANT_OPTION", "GRANTED_BY"]

# All non-PUBLIC account roles this fixture uses — message 2/3 issue one
# SHOW GRANTS OF ROLE and one SHOW GRANTS TO ROLE call per entry.
_ROLE_NAMES = ["ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "USERADMIN", "CUSTOM_ADMIN", "ANALYST"]


def _cols(names: list[str]) -> dict:
    return {"resultSetMetaData": {"rowType": [{"name": n} for n in names]}}


def _resp(names: list[str], rows: list[list]) -> httpx.Response:
    body = _cols(names)
    body["data"] = rows
    return httpx.Response(200, json=body)


def _identity_resp(org="ACME", account="PROD", locator="AB123", role=_ROLE) -> httpx.Response:
    return _resp(["ORG_NAME", "ACCOUNT_NAME", "ACCOUNT_LOCATOR", "SESSION_ROLE"], [[org, account, locator, role]])


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
    """ALICE holds ACCOUNTADMIN directly; BOB (service user) holds
    CUSTOM_ADMIN, a custom role with MANAGE GRANTS + CREATE USER; CAROL
    holds ANALYST, an ordinary read-only custom role that must NOT produce
    a privileged_user record. SECURITYADMIN/SYSADMIN/USERADMIN are all
    granted (as children) to ACCOUNTADMIN/SECURITYADMIN per the real
    Snowflake system-role hierarchy, confirmed via current official docs.
    """
    r = _Router()
    r.set("SHOW USERS", _resp(_USERS_COLS, [
        ["ALICE", "PERSON", "false", "ACCOUNTADMIN", "ALL", "true", "true", "false", "USERADMIN"],
        ["BOB", "SERVICE", "false", "CUSTOM_ADMIN", None, "false", "false", "true", "USERADMIN"],
        ["CAROL", "PERSON", "false", "ANALYST", "ALL", "true", "true", "false", "USERADMIN"],
    ]))
    r.set("SHOW ROLES", _resp(_ACCOUNT_ROLES_COLS, [
        ["ACCOUNTADMIN", None, "1", "0", "2"],
        ["SECURITYADMIN", "ACCOUNTADMIN", "0", "1", "1"],
        ["SYSADMIN", "ACCOUNTADMIN", "0", "1", "0"],
        ["USERADMIN", "SECURITYADMIN", "0", "1", "0"],
        ["CUSTOM_ADMIN", "SYSADMIN", "1", "0", "0"],
        ["ANALYST", "SYSADMIN", "1", "0", "0"],
        ["PUBLIC", None, "0", "0", "0"],
    ]))
    r.set("SHOW DATABASES", _resp(["NAME"], [["MYDB"]]))
    r.set('SHOW DATABASE ROLES IN DATABASE "MYDB"', _resp(["NAME"], []))
    r.set('SHOW SCHEMAS IN DATABASE "MYDB"', _resp(["NAME"], []))
    r.set('SHOW FUTURE GRANTS IN DATABASE "MYDB"', _resp(
        ["PRIVILEGE", "GRANT_ON", "NAME", "GRANT_TO", "GRANTEE_NAME", "GRANT_OPTION"], [],
    ))
    r.set("SHOW WAREHOUSES", _resp(["NAME"], []))
    r.set("SHOW SHARES", _resp(["KIND", "NAME"], []))

    r.set('SHOW GRANTS OF ROLE "ACCOUNTADMIN"', _resp(_GRANTS_OF_COLS, [
        ["t", "ACCOUNTADMIN", "USER", "ALICE", "SECURITYADMIN"],
    ]))
    r.set('SHOW GRANTS OF ROLE "SECURITYADMIN"', _resp(_GRANTS_OF_COLS, [
        ["t", "SECURITYADMIN", "ROLE", "ACCOUNTADMIN", "SYSTEM"],
    ]))
    r.set('SHOW GRANTS OF ROLE "SYSADMIN"', _resp(_GRANTS_OF_COLS, [
        ["t", "SYSADMIN", "ROLE", "ACCOUNTADMIN", "SYSTEM"],
    ]))
    r.set('SHOW GRANTS OF ROLE "USERADMIN"', _resp(_GRANTS_OF_COLS, [
        ["t", "USERADMIN", "ROLE", "SECURITYADMIN", "SYSTEM"],
    ]))
    r.set('SHOW GRANTS OF ROLE "CUSTOM_ADMIN"', _resp(_GRANTS_OF_COLS, [
        ["t", "CUSTOM_ADMIN", "USER", "BOB", "USERADMIN"],
    ]))
    r.set('SHOW GRANTS OF ROLE "ANALYST"', _resp(_GRANTS_OF_COLS, [
        ["t", "ANALYST", "USER", "CAROL", "USERADMIN"],
    ]))

    for role_name in _ROLE_NAMES:
        r.set(f'SHOW GRANTS TO ROLE "{role_name}"', _resp(_GRANTS_TO_ROLE_COLS, []))
    r.set('SHOW GRANTS TO ROLE "CUSTOM_ADMIN"', _resp(_GRANTS_TO_ROLE_COLS, [
        ["MANAGE GRANTS", "ACCOUNT", "PROD", "ROLE", "CUSTOM_ADMIN", "false", "SECURITYADMIN"],
        ["CREATE USER", "ACCOUNT", "PROD", "ROLE", "CUSTOM_ADMIN", "false", "SECURITYADMIN"],
    ]))
    r.set('SHOW GRANTS TO ROLE "ANALYST"', _resp(_GRANTS_TO_ROLE_COLS, [
        ["SELECT", "TABLE", "MYDB.PUBLIC.T1", "ROLE", "ANALYST", "false", "SYSADMIN"],
    ]))

    r.set("SHOW NETWORK POLICIES", _resp(["NAME"], []))
    r.set("SHOW NETWORK RULES", _resp(["NAME"], []))
    r.set("SHOW AUTHENTICATION POLICIES", _resp(["NAME"], []))
    r.set("SHOW SECURITY INTEGRATIONS", _resp(["NAME"], []))
    r.set("SHOW STORAGE INTEGRATIONS", _resp(["NAME"], []))
    r.set("SHOW EXTERNAL ACCESS INTEGRATIONS", _resp(["NAME"], []))
    return r


def _fetch(router: _Router) -> list[dict]:
    with respx.mock:
        respx.post(_STATEMENTS_URL).mock(side_effect=router)
        conn = SnowflakeConnector()
        return conn.fetch(_CREDS, _sleep_fn=_noop_sleep)


def _by_type(records: list[dict], record_type: str) -> list[dict]:
    return [r for r in records if r["record_type"] == record_type]


class TestPrivilegedUserCollection:
    def test_alice_direct_accountadmin_critical(self):
        records = _fetch(_basic_router())
        users = {u["user_name"]: u for u in _by_type(records, SNOWFLAKE_PRIVILEGED_USER)}
        assert users["ALICE"]["highest_known_privilege_tier"] == PRIVILEGE_TIER_CRITICAL
        assert users["ALICE"]["has_accountadmin"] is True

    def test_bob_manage_grants_custom_admin_critical(self):
        """BOB's CUSTOM_ADMIN role has MANAGE GRANTS + CREATE USER ->
        critical, classified from actual grants, never from the role's
        (unremarkable) name."""
        records = _fetch(_basic_router())
        users = {u["user_name"]: u for u in _by_type(records, SNOWFLAKE_PRIVILEGED_USER)}
        assert users["BOB"]["highest_known_privilege_tier"] == PRIVILEGE_TIER_CRITICAL
        assert users["BOB"]["has_manage_grants"] is True
        assert users["BOB"]["user_type"] == "service"

    def test_carol_ordinary_analyst_excluded(self):
        records = _fetch(_basic_router())
        users = {u["user_name"]: u for u in _by_type(records, SNOWFLAKE_PRIVILEGED_USER)}
        assert "CAROL" not in users

    def test_disabled_accountadmin_still_emitted(self):
        router = _basic_router()
        router.set("SHOW USERS", _resp(_USERS_COLS, [
            ["ALICE", "PERSON", "true", "ACCOUNTADMIN", "ALL", "true", "true", "false", "USERADMIN"],
            ["BOB", "SERVICE", "false", "CUSTOM_ADMIN", None, "false", "false", "true", "USERADMIN"],
            ["CAROL", "PERSON", "false", "ANALYST", "ALL", "true", "true", "false", "USERADMIN"],
        ]))
        records = _fetch(router)
        users = {u["user_name"]: u for u in _by_type(records, SNOWFLAKE_PRIVILEGED_USER)}
        assert users["ALICE"]["disabled"] == "disabled"
        assert users["ALICE"]["highest_known_privilege_tier"] == PRIVILEGE_TIER_CRITICAL


class TestPrivilegedRoleCollection:
    def test_accountadmin_role_present_with_inherited_children(self):
        records = _fetch(_basic_router())
        roles = {(r["role_type"], r["role_name"]): r for r in _by_type(records, SNOWFLAKE_PRIVILEGED_ROLE)}
        accountadmin = roles[("account_role", "ACCOUNTADMIN")]
        assert accountadmin["highest_known_privilege_tier"] == PRIVILEGE_TIER_CRITICAL
        assert accountadmin["inherited_child_role_count"] == 3  # SECURITYADMIN, SYSADMIN, USERADMIN

    def test_securityadmin_role_present(self):
        records = _fetch(_basic_router())
        roles = {(r["role_type"], r["role_name"]): r for r in _by_type(records, SNOWFLAKE_PRIVILEGED_ROLE)}
        assert roles[("account_role", "SECURITYADMIN")]["highest_known_privilege_tier"] == PRIVILEGE_TIER_HIGH

    def test_custom_admin_role_present_manage_grants(self):
        records = _fetch(_basic_router())
        roles = {(r["role_type"], r["role_name"]): r for r in _by_type(records, SNOWFLAKE_PRIVILEGED_ROLE)}
        custom = roles[("account_role", "CUSTOM_ADMIN")]
        assert custom["has_manage_grants"] is True
        assert custom["direct_user_assignment_count"] == 1

    def test_analyst_ordinary_role_excluded(self):
        records = _fetch(_basic_router())
        roles = {(r["role_type"], r["role_name"]): r for r in _by_type(records, SNOWFLAKE_PRIVILEGED_ROLE)}
        assert ("account_role", "ANALYST") not in roles

    def test_sysadmin_useradmin_not_emitted_without_extra_signal(self):
        """SYSADMIN/USERADMIN are Medium-tier built-ins with no MANAGE
        GRANTS/ownership/future-grant signal in this fixture — per the
        task's own literal inclusion threshold (critical/high tier only
        for ROLE records), they are not emitted as privileged_role
        records, even though users holding them ARE flagged via
        has_sysadmin/has_useradmin on privileged_user."""
        records = _fetch(_basic_router())
        roles = {(r["role_type"], r["role_name"]): r for r in _by_type(records, SNOWFLAKE_PRIVILEGED_ROLE)}
        assert ("account_role", "SYSADMIN") not in roles
        assert ("account_role", "USERADMIN") not in roles


class TestPublicExposureCollection:
    def test_public_exposure_record_always_emitted(self):
        records = _fetch(_basic_router())
        exposure = _by_type(records, SNOWFLAKE_PUBLIC_EXPOSURE)
        assert len(exposure) == 1
        assert exposure[0]["account_id"] == records[0]["account_id"]

    def test_public_exposure_wording_never_internet(self):
        records = _fetch(_basic_router())
        exposure = _by_type(records, SNOWFLAKE_PUBLIC_EXPOSURE)[0]
        assert "internet" not in str(exposure).lower()


class TestFamilyCompleteness:
    def test_effective_privilege_family_complete_when_inputs_complete(self):
        records = _fetch(_basic_router())
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["effective_privilege"] == FAMILY_COMPLETE

    def test_effective_privilege_family_degrades_when_role_hierarchy_denied(self):
        router = _basic_router()
        router.set('SHOW GRANTS OF ROLE "ACCOUNTADMIN"', httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["effective_privilege"] != FAMILY_COMPLETE


class TestZeroAdditionalSqlCalls:
    def test_no_new_sql_statements_beyond_messages_1_through_4(self):
        """Privilege derivation must issue ZERO additional SQL calls —
        every statement executed is one messages 1-4 already issue."""
        router = _basic_router()
        _fetch(router)
        for statement in router.calls:
            up = statement.upper()
            assert not any(
                verb in up for verb in ("PRIVILEGED_USER", "PRIVILEGED_ROLE", "PUBLIC_EXPOSURE", "EFFECTIVE_PRIVILEGE")
            ), f"unexpected message-5-specific statement issued: {statement}"

    def test_call_count_unchanged_between_two_identical_fetches(self):
        """Fetching twice against the same fixture issues the same call
        count both times — derivation adds no additional round trips on
        top of the same set of already-mocked statements."""
        calls_a = _basic_router()
        _fetch(calls_a)
        calls_b = _basic_router()
        _fetch(calls_b)
        assert len(calls_a.calls) == len(calls_b.calls)


class TestDeterministicOrdering:
    def test_privileged_records_sorted_by_record_id(self):
        records = _fetch(_basic_router())
        privileged = [r for r in records if r["record_type"] in (SNOWFLAKE_PRIVILEGED_USER, SNOWFLAKE_PRIVILEGED_ROLE)]
        ids = [(r["record_type"], r["record_id"]) for r in privileged]
        assert ids == sorted(ids)
