"""Snowflake data-object collection tests (Snowflake message 3 of 8).

Covers the SHOW-based collection built in this message for databases,
schemas, warehouses, shares, and object/future grants: per-parent
completeness, dedup, identifier escaping, caching (SHOW DATABASES issued
exactly once per fetch()), role-hierarchy-row exclusion from object grants,
and scale.

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
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    FAMILY_PARTIAL,
    FAMILY_UNAVAILABLE,
    SNOWFLAKE_DATABASE,
    SNOWFLAKE_OBJECT_GRANT,
    SNOWFLAKE_SCHEMA,
    SNOWFLAKE_SHARE,
    SNOWFLAKE_WAREHOUSE,
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


_DATABASES_COLS = ["NAME", "KIND", "OWNER", "OPTIONS", "RETENTION_TIME", "ORIGIN"]
_SCHEMAS_COLS = ["NAME", "OWNER", "OPTIONS", "RETENTION_TIME"]
_WAREHOUSES_COLS = [
    "NAME", "OWNER", "STATE", "SIZE", "AUTO_SUSPEND", "AUTO_RESUME",
    "SCALING_POLICY", "MIN_CLUSTER_COUNT", "MAX_CLUSTER_COUNT", "RESOURCE_MONITOR",
]
_SHARES_COLS = ["KIND", "NAME", "DATABASE_NAME", "TO", "OWNER"]
_GRANTS_TO_ROLE_COLS = ["PRIVILEGE", "GRANTED_ON", "NAME", "GRANTED_TO", "GRANTEE_NAME", "GRANT_OPTION", "GRANTED_BY"]
_FUTURE_GRANTS_COLS = ["PRIVILEGE", "GRANT_ON", "NAME", "GRANT_TO", "GRANTEE_NAME", "GRANT_OPTION"]
_ACCOUNT_ROLES_COLS = ["NAME", "OWNER", "ASSIGNED_TO_USERS", "GRANTED_TO_ROLES", "GRANTED_ROLES"]
_GRANTS_OF_ROLE_COLS = ["CREATED_ON", "ROLE", "GRANTED_TO", "GRANTEE_NAME", "GRANTED_BY"]


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
    r.set("SHOW ROLES", _resp(_ACCOUNT_ROLES_COLS, [
        ["SYSADMIN", None, "0", "0", "0"],
        ["ANALYST", "SYSADMIN", "1", "0", "0"],
        ["PUBLIC", None, "0", "0", "0"],
    ]))
    r.set("SHOW DATABASES", _resp(_DATABASES_COLS, [
        ["MYDB", "STANDARD", "SYSADMIN", "", "1", None],
    ]))
    r.set('SHOW DATABASE ROLES IN DATABASE "MYDB"', _resp(["NAME"], []))
    r.set('SHOW GRANTS OF ROLE "SYSADMIN"', _resp(_GRANTS_OF_ROLE_COLS, []))
    r.set('SHOW GRANTS OF ROLE "ANALYST"', _resp(_GRANTS_OF_ROLE_COLS, []))
    r.set('SHOW SCHEMAS IN DATABASE "MYDB"', _resp(_SCHEMAS_COLS, [
        ["PUBLIC", "SYSADMIN", "MANAGED ACCESS", "1"],
    ]))
    r.set("SHOW WAREHOUSES", _resp(_WAREHOUSES_COLS, [
        ["COMPUTE_WH", "SYSADMIN", "STARTED", "X-Small", "600", "true", "STANDARD", "1", "1", None],
    ]))
    r.set("SHOW SHARES", _resp(_SHARES_COLS, [
        ["OUTBOUND", "MY_SHARE", "MYDB", "XY12345", "SYSADMIN"],
    ]))
    r.set('SHOW GRANTS TO ROLE "SYSADMIN"', _resp(_GRANTS_TO_ROLE_COLS, [
        ["OWNERSHIP", "DATABASE", "MYDB", "ROLE", "SYSADMIN", "false", None],
    ]))
    r.set('SHOW GRANTS TO ROLE "ANALYST"', _resp(_GRANTS_TO_ROLE_COLS, [
        ["SELECT", "TABLE", "MYDB.PUBLIC.ORDERS", "ROLE", "ANALYST", "false", "SYSADMIN"],
    ]))
    r.set('SHOW FUTURE GRANTS IN DATABASE "MYDB"', _resp(_FUTURE_GRANTS_COLS, []))
    return r


def _fetch(router: _Router) -> list[dict]:
    with respx.mock:
        respx.post(_STATEMENTS_URL).mock(side_effect=router)
        conn = SnowflakeConnector()
        return conn.fetch(_CREDS, _sleep_fn=_noop_sleep)


def _by_type(records: list[dict], record_type: str) -> list[dict]:
    return [r for r in records if r["record_type"] == record_type]


# ── Databases ─────────────────────────────────────────────────────────────────


class TestDatabaseCollection:
    def test_databases_collected(self):
        records = _fetch(_basic_router())
        dbs = _by_type(records, SNOWFLAKE_DATABASE)
        assert len(dbs) == 1
        assert dbs[0]["database_name"] == "MYDB"

    def test_databases_family_denied(self):
        router = _basic_router()
        router.set("SHOW DATABASES", httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["databases"] == FAMILY_DENIED
        assert _by_type(records, SNOWFLAKE_DATABASE) == []

    def test_show_databases_issued_exactly_once_per_fetch(self):
        """SHOW DATABASES feeds database-role discovery (message 2), the
        schema/future-grant per-database loops, AND full database
        inventory (message 3) — it must never be queried twice."""
        router = _basic_router()
        _fetch(router)
        assert router.calls.count("SHOW DATABASES") == 1


# ── Schemas ───────────────────────────────────────────────────────────────────


class TestSchemaCollection:
    def test_schemas_collected(self):
        records = _fetch(_basic_router())
        schemas = _by_type(records, SNOWFLAKE_SCHEMA)
        assert len(schemas) == 1
        assert schemas[0]["database_name"] == "MYDB"
        assert schemas[0]["schema_name"] == "PUBLIC"

    def test_no_databases_marks_schemas_unavailable(self):
        router = _basic_router()
        router.set("SHOW DATABASES", _resp(_DATABASES_COLS, []))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["schemas"] == FAMILY_UNAVAILABLE

    def test_one_database_schemas_denied_marks_partial(self):
        router = _basic_router()
        router.set("SHOW DATABASES", _resp(_DATABASES_COLS, [
            ["MYDB", "STANDARD", "SYSADMIN", "", "1", None],
            ["OTHERDB", "STANDARD", "SYSADMIN", "", "1", None],
        ]))
        router.set('SHOW DATABASE ROLES IN DATABASE "OTHERDB"', _resp(["NAME"], []))
        router.set('SHOW SCHEMAS IN DATABASE "OTHERDB"', httpx.Response(403))
        router.set('SHOW FUTURE GRANTS IN DATABASE "OTHERDB"', _resp(_FUTURE_GRANTS_COLS, []))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["schemas"] == FAMILY_PARTIAL
        # MYDB's schema is still collected despite OTHERDB's denial.
        assert len(_by_type(records, SNOWFLAKE_SCHEMA)) == 1


# ── Warehouses ────────────────────────────────────────────────────────────────


class TestWarehouseCollection:
    def test_warehouses_collected(self):
        records = _fetch(_basic_router())
        whs = _by_type(records, SNOWFLAKE_WAREHOUSE)
        assert len(whs) == 1
        assert whs[0]["warehouse_name"] == "COMPUTE_WH"

    def test_warehouses_family_denied(self):
        router = _basic_router()
        router.set("SHOW WAREHOUSES", httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["warehouses"] == FAMILY_DENIED


# ── Shares ────────────────────────────────────────────────────────────────────


class TestShareCollection:
    def test_shares_collected(self):
        records = _fetch(_basic_router())
        shares = _by_type(records, SNOWFLAKE_SHARE)
        assert len(shares) == 1
        assert shares[0]["share_name"] == "MY_SHARE"
        assert shares[0]["share_kind"] == "outbound"

    def test_shares_family_denied(self):
        router = _basic_router()
        router.set("SHOW SHARES", httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["shares"] == FAMILY_DENIED


# ── Object / future grants ────────────────────────────────────────────────────


class TestObjectGrantCollection:
    def test_object_grants_collected(self):
        records = _fetch(_basic_router())
        grants = _by_type(records, SNOWFLAKE_OBJECT_GRANT)
        privileges = {(g["grantee_name"], g["privilege"]) for g in grants}
        assert ("SYSADMIN", "OWNERSHIP") in privileges
        assert ("ANALYST", "SELECT") in privileges

    def test_role_hierarchy_row_excluded_from_object_grants(self):
        """A SHOW GRANTS TO ROLE row with granted_on=ROLE is a hierarchy
        edge (message 2's domain via SHOW GRANTS OF ROLE) — it must never
        be re-normalized as an object grant here."""
        router = _basic_router()
        router.set('SHOW GRANTS TO ROLE "ANALYST"', _resp(_GRANTS_TO_ROLE_COLS, [
            ["SELECT", "TABLE", "MYDB.PUBLIC.ORDERS", "ROLE", "ANALYST", "false", "SYSADMIN"],
            ["USAGE", "ROLE", "SYSADMIN", "ROLE", "ANALYST", "false", "SYSADMIN"],
        ]))
        records = _fetch(router)
        grants = _by_type(records, SNOWFLAKE_OBJECT_GRANT)
        analyst_grants = [g for g in grants if g["grantee_name"] == "ANALYST"]
        assert len(analyst_grants) == 1
        assert analyst_grants[0]["privilege"] == "SELECT"

    def test_future_grants_collected(self):
        router = _basic_router()
        router.set('SHOW FUTURE GRANTS IN DATABASE "MYDB"', _resp(_FUTURE_GRANTS_COLS, [
            ["SELECT", "TABLE", "MYDB.PUBLIC.<TABLE>", "ROLE", "PUBLIC", "false"],
        ]))
        records = _fetch(router)
        grants = _by_type(records, SNOWFLAKE_OBJECT_GRANT)
        future_grants = [g for g in grants if g["future_grant"]]
        assert len(future_grants) == 1
        assert future_grants[0]["grantee_name"] == "PUBLIC"

    def test_future_grant_to_user_safely_skipped(self):
        """Future grants are documented as granted to roles, never
        directly to a user — an unexpected USER grantee is skipped rather
        than silently accepted."""
        router = _basic_router()
        router.set('SHOW FUTURE GRANTS IN DATABASE "MYDB"', _resp(_FUTURE_GRANTS_COLS, [
            ["SELECT", "TABLE", "MYDB.PUBLIC.<TABLE>", "USER", "ALICE", "false"],
        ]))
        records = _fetch(router)
        grants = _by_type(records, SNOWFLAKE_OBJECT_GRANT)
        assert all(g["grantee_name"] != "ALICE" for g in grants)

    def test_object_grants_family_unavailable_when_all_calls_fail(self):
        router = _basic_router()
        router.set('SHOW GRANTS TO ROLE "SYSADMIN"', httpx.Response(403))
        router.set('SHOW GRANTS TO ROLE "ANALYST"', httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["object_grants"] == FAMILY_UNAVAILABLE

    def test_object_grants_family_partial_when_some_calls_fail(self):
        router = _basic_router()
        router.set('SHOW GRANTS TO ROLE "ANALYST"', httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["object_grants"] == FAMILY_PARTIAL
        # SYSADMIN's grant still collected despite ANALYST's denial.
        assert len(_by_type(records, SNOWFLAKE_OBJECT_GRANT)) == 1

    def test_future_grants_family_unavailable(self):
        router = _basic_router()
        router.set('SHOW FUTURE GRANTS IN DATABASE "MYDB"', httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["future_grants"] == FAMILY_UNAVAILABLE

    def test_duplicate_grant_rows_dedup(self):
        router = _basic_router()
        router.set('SHOW GRANTS TO ROLE "ANALYST"', _resp(_GRANTS_TO_ROLE_COLS, [
            ["SELECT", "TABLE", "MYDB.PUBLIC.ORDERS", "ROLE", "ANALYST", "false", "SYSADMIN"],
            ["SELECT", "TABLE", "MYDB.PUBLIC.ORDERS", "ROLE", "ANALYST", "false", "SYSADMIN"],
        ]))
        records = _fetch(router)
        grants = [g for g in _by_type(records, SNOWFLAKE_OBJECT_GRANT) if g["grantee_name"] == "ANALYST"]
        assert len(grants) == 1


# ── Identifier safety ────────────────────────────────────────────────────────


class TestIdentifierSafety:
    def test_database_name_with_embedded_quote_is_safely_escaped(self):
        router = _basic_router()
        router.set("SHOW DATABASES", _resp(_DATABASES_COLS, [
            ['WEIRD"DB', "STANDARD", "SYSADMIN", "", "1", None],
        ]))
        router.set('SHOW DATABASE ROLES IN DATABASE "WEIRD""DB"', _resp(["NAME"], []))
        router.set('SHOW SCHEMAS IN DATABASE "WEIRD""DB"', _resp(_SCHEMAS_COLS, []))
        router.set('SHOW FUTURE GRANTS IN DATABASE "WEIRD""DB"', _resp(_FUTURE_GRANTS_COLS, []))
        records = _fetch(router)
        dbs = _by_type(records, SNOWFLAKE_DATABASE)
        assert any(d["database_name"] == 'WEIRD"DB' for d in dbs)

    def test_injection_shaped_database_name_stays_an_identifier(self):
        """A database named like a SQL injection attempt must never break
        out of its quoted identifier position into a new clause."""
        router = _basic_router()
        malicious_name = 'x"; DROP TABLE x; --'
        router.set("SHOW DATABASES", _resp(_DATABASES_COLS, [
            [malicious_name, "STANDARD", "SYSADMIN", "", "1", None],
        ]))
        expected_stmt = f'SHOW SCHEMAS IN DATABASE "{malicious_name.replace(chr(34), chr(34)*2)}"'
        router.set(expected_stmt, _resp(_SCHEMAS_COLS, []))
        expected_db_role_stmt = f'SHOW DATABASE ROLES IN DATABASE "{malicious_name.replace(chr(34), chr(34)*2)}"'
        router.set(expected_db_role_stmt, _resp(["NAME"], []))
        expected_future_stmt = f'SHOW FUTURE GRANTS IN DATABASE "{malicious_name.replace(chr(34), chr(34)*2)}"'
        router.set(expected_future_stmt, _resp(_FUTURE_GRANTS_COLS, []))
        records = _fetch(router)
        # No exception raised; the malicious name was safely quoted and
        # treated purely as an identifier value, never executed as SQL.
        dbs = _by_type(records, SNOWFLAKE_DATABASE)
        assert any(d["database_name"] == malicious_name for d in dbs)

    def test_role_name_with_embedded_quote_escaped_in_grants_to_role(self):
        router = _basic_router()
        router.set("SHOW ROLES", _resp(_ACCOUNT_ROLES_COLS, [
            ['WEIRD"ROLE', "SYSADMIN", "0", "0", "0"],
        ]))
        router.set('SHOW GRANTS OF ROLE "WEIRD""ROLE"', _resp(_GRANTS_OF_ROLE_COLS, []))
        router.set('SHOW GRANTS TO ROLE "WEIRD""ROLE"', _resp(_GRANTS_TO_ROLE_COLS, []))
        records = _fetch(router)
        roles = _by_type(records, "snowflake_account_role")
        assert any(r["role_name"] == 'WEIRD"ROLE' for r in roles)


# ── Scale ─────────────────────────────────────────────────────────────────────


class TestScale:
    def test_1000_databases(self):
        router = _basic_router()
        rows = [[f"DB_{i}", "STANDARD", "SYSADMIN", "", "1", None] for i in range(1000)]
        router.set("SHOW DATABASES", _resp(_DATABASES_COLS, rows))
        for i in range(1000):
            router.set(f'SHOW DATABASE ROLES IN DATABASE "DB_{i}"', _resp(["NAME"], []))
            router.set(f'SHOW SCHEMAS IN DATABASE "DB_{i}"', _resp(_SCHEMAS_COLS, []))
            router.set(f'SHOW FUTURE GRANTS IN DATABASE "DB_{i}"', _resp(_FUTURE_GRANTS_COLS, []))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_DATABASE)) == 1000

    def test_10000_schemas(self):
        router = _basic_router()
        db_names = [f"DB_{i}" for i in range(10)]
        router.set("SHOW DATABASES", _resp(_DATABASES_COLS, [
            [d, "STANDARD", "SYSADMIN", "", "1", None] for d in db_names
        ]))
        for db in db_names:
            router.set(f'SHOW DATABASE ROLES IN DATABASE "{db}"', _resp(["NAME"], []))
            router.set(f'SHOW FUTURE GRANTS IN DATABASE "{db}"', _resp(_FUTURE_GRANTS_COLS, []))
            rows = [[f"SCHEMA_{db}_{i}", "SYSADMIN", "", "1"] for i in range(1000)]
            router.set(f'SHOW SCHEMAS IN DATABASE "{db}"', _resp(_SCHEMAS_COLS, rows))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_SCHEMA)) == 10000

    def test_2000_warehouses(self):
        router = _basic_router()
        rows = [[f"WH_{i}", "SYSADMIN", "STARTED", "X-Small", "600", "true", "STANDARD", "1", "1", None] for i in range(2000)]
        router.set("SHOW WAREHOUSES", _resp(_WAREHOUSES_COLS, rows))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_WAREHOUSE)) == 2000

    def test_2000_shares(self):
        router = _basic_router()
        rows = [["OUTBOUND", f"SHARE_{i}", "MYDB", "XY12345", "SYSADMIN"] for i in range(2000)]
        router.set("SHOW SHARES", _resp(_SHARES_COLS, rows))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_SHARE)) == 2000

    def test_100000_grants(self):
        """100 roles x 1,000 grant rows each = 100,000 object grants."""
        router = _basic_router()
        role_names = [f"BULK_ROLE_{i}" for i in range(100)]
        router.set("SHOW ROLES", _resp(_ACCOUNT_ROLES_COLS, [
            [name, "SYSADMIN", "0", "0", "0"] for name in role_names
        ]))
        for role_name in role_names:
            router.set(f'SHOW GRANTS OF ROLE "{role_name}"', _resp(_GRANTS_OF_ROLE_COLS, []))
            rows = [
                ["SELECT", "TABLE", f"MYDB.PUBLIC.TABLE_{j}", "ROLE", role_name, "false", "SYSADMIN"]
                for j in range(1000)
            ]
            router.set(f'SHOW GRANTS TO ROLE "{role_name}"', _resp(_GRANTS_TO_ROLE_COLS, rows))
        records = _fetch(router)
        grants = _by_type(records, SNOWFLAKE_OBJECT_GRANT)
        assert len(grants) == 100000
        assert len({g["record_id"] for g in grants}) == 100000
