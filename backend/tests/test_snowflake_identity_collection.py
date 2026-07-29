"""Snowflake identity/role collection tests (Snowflake message 2 of 8).

Covers the SHOW-based collection built in this message for users, account
roles, database roles, user-role grants, and role-hierarchy edges: family
independence/completeness, query failures, dedup, deterministic ordering,
PUBLIC-role exclusion from grant enumeration, and scale.

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
    SNOWFLAKE_ACCOUNT_ROLE,
    SNOWFLAKE_DATABASE_ROLE,
    SNOWFLAKE_ROLE_HIERARCHY_GRANT,
    SNOWFLAKE_USER,
    SNOWFLAKE_USER_ROLE_GRANT,
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
    return _resp(
        ["ORG_NAME", "ACCOUNT_NAME", "ACCOUNT_LOCATOR", "SESSION_ROLE"],
        [[org, account, locator, role]],
    )


_USERS_COLS = [
    "NAME", "TYPE", "DISABLED", "DEFAULT_ROLE", "DEFAULT_SECONDARY_ROLES",
    "HAS_RSA_PUBLIC_KEY", "HAS_PASSWORD", "HAS_PAT", "OWNER",
]
_ACCOUNT_ROLES_COLS = ["NAME", "OWNER", "ASSIGNED_TO_USERS", "GRANTED_TO_ROLES", "GRANTED_ROLES"]
_DATABASES_COLS = ["NAME"]
_DATABASE_ROLES_COLS = ["NAME", "OWNER", "GRANTED_TO_ROLES", "GRANTED_DATABASE_ROLES"]
_GRANTS_COLS = ["CREATED_ON", "ROLE", "GRANTED_TO", "GRANTEE_NAME", "GRANTED_BY"]


class _Router:
    """respx side_effect dispatching on the exact POSTed 'statement' text —
    every Snowflake SQL API call hits the same URL, so routing must inspect
    the request body, never the path."""

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
    r.set("SHOW USERS", _resp(_USERS_COLS, [
        ["ALICE", "PERSON", "false", "ANALYST", "ALL", "true", "true", "false", "USERADMIN"],
        ["SVC_ETL", "SERVICE", "false", "ETL_ROLE", None, "false", "false", "true", "USERADMIN"],
    ]))
    r.set("SHOW ROLES", _resp(_ACCOUNT_ROLES_COLS, [
        ["ACCOUNTADMIN", None, "1", "0", "2"],
        ["ANALYST", "SYSADMIN", "1", "1", "0"],
        ["ETL_ROLE", "SYSADMIN", "1", "0", "0"],
        ["PUBLIC", None, "0", "0", "0"],
    ]))
    r.set("SHOW DATABASES", _resp(_DATABASES_COLS, [["MYDB"]]))
    r.set('SHOW DATABASE ROLES IN DATABASE "MYDB"', _resp(_DATABASE_ROLES_COLS, [
        ["DB_READER", "SYSADMIN", "1", "0"],
    ]))
    r.set('SHOW GRANTS OF ROLE "ACCOUNTADMIN"', _resp(_GRANTS_COLS, [
        ["t", "ACCOUNTADMIN", "USER", "ALICE", "SECURITYADMIN"],
    ]))
    r.set('SHOW GRANTS OF ROLE "ANALYST"', _resp(_GRANTS_COLS, [
        ["t", "ANALYST", "USER", "ALICE", "USERADMIN"],
    ]))
    r.set('SHOW GRANTS OF ROLE "ETL_ROLE"', _resp(_GRANTS_COLS, [
        ["t", "ETL_ROLE", "ROLE", "SYSADMIN", "USERADMIN"],
    ]))
    r.set('SHOW GRANTS OF DATABASE ROLE "MYDB"."DB_READER"', _resp(_GRANTS_COLS, [
        ["t", "DB_READER", "ROLE", "SYSADMIN", "SYSADMIN"],
    ]))
    return r


def _fetch(router: _Router) -> list[dict]:
    with respx.mock:
        respx.post(_STATEMENTS_URL).mock(side_effect=router)
        conn = SnowflakeConnector()
        return conn.fetch(_CREDS, _sleep_fn=_noop_sleep)


def _by_type(records: list[dict], record_type: str) -> list[dict]:
    return [r for r in records if r["record_type"] == record_type]


# ── Users ─────────────────────────────────────────────────────────────────────


class TestUserCollection:
    def test_users_collected(self):
        records = _fetch(_basic_router())
        users = _by_type(records, SNOWFLAKE_USER)
        assert len(users) == 2
        names = {u["user_name"] for u in users}
        assert names == {"ALICE", "SVC_ETL"}

    def test_users_family_denied_on_permission_error(self):
        router = _basic_router()
        router.set("SHOW USERS", httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["users"] == FAMILY_DENIED
        assert _by_type(records, SNOWFLAKE_USER) == []

    def test_users_family_unavailable_on_malformed_response(self):
        router = _basic_router()
        router.set("SHOW USERS", httpx.Response(200, content=b"not json"))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["users"] == FAMILY_UNAVAILABLE


# ── Account roles ─────────────────────────────────────────────────────────────


class TestAccountRoleCollection:
    def test_account_roles_collected_including_public(self):
        records = _fetch(_basic_router())
        roles = _by_type(records, SNOWFLAKE_ACCOUNT_ROLE)
        assert len(roles) == 4
        names = {r["role_name"] for r in roles}
        assert "PUBLIC" in names

    def test_account_roles_family_denied(self):
        router = _basic_router()
        router.set("SHOW ROLES", httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["account_roles"] == FAMILY_DENIED


# ── Database roles ────────────────────────────────────────────────────────────


class TestDatabaseRoleCollection:
    def test_database_roles_collected(self):
        records = _fetch(_basic_router())
        db_roles = _by_type(records, SNOWFLAKE_DATABASE_ROLE)
        assert len(db_roles) == 1
        assert db_roles[0]["database_name"] == "MYDB"
        assert db_roles[0]["role_name"] == "DB_READER"

    def test_no_databases_marks_family_unavailable(self):
        router = _basic_router()
        router.set("SHOW DATABASES", _resp(_DATABASES_COLS, []))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["database_roles"] == FAMILY_UNAVAILABLE
        assert _by_type(records, SNOWFLAKE_DATABASE_ROLE) == []

    def test_database_discovery_denied_marks_database_roles_unavailable(self):
        router = _basic_router()
        router.set("SHOW DATABASES", httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["database_roles"] == FAMILY_UNAVAILABLE

    def test_one_database_denied_marks_partial(self):
        router = _basic_router()
        router.set("SHOW DATABASES", _resp(_DATABASES_COLS, [["MYDB"], ["OTHERDB"]]))
        router.set('SHOW DATABASE ROLES IN DATABASE "OTHERDB"', httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["database_roles"] == FAMILY_PARTIAL
        # MYDB's role is still collected despite OTHERDB's denial.
        assert len(_by_type(records, SNOWFLAKE_DATABASE_ROLE)) == 1


# ── User-role grants and role hierarchy ──────────────────────────────────────


class TestGrantsAndHierarchy:
    def test_user_role_grants_collected(self):
        records = _fetch(_basic_router())
        grants = _by_type(records, SNOWFLAKE_USER_ROLE_GRANT)
        pairs = {(g["user_name"], g["role_name"]) for g in grants}
        assert ("ALICE", "ACCOUNTADMIN") in pairs
        assert ("ALICE", "ANALYST") in pairs

    def test_role_hierarchy_edges_collected(self):
        records = _fetch(_basic_router())
        edges = _by_type(records, SNOWFLAKE_ROLE_HIERARCHY_GRANT)
        pairs = {(e["child_role_name"], e["parent_role_name"]) for e in edges}
        assert ("ETL_ROLE", "SYSADMIN") in pairs
        assert ("DB_READER", "SYSADMIN") in pairs

    def test_public_role_excluded_from_grant_enumeration(self):
        router = _basic_router()
        records = _fetch(router)
        assert 'SHOW GRANTS OF ROLE "PUBLIC"' not in router.calls

    def test_unknown_principal_type_safely_skipped(self):
        router = _basic_router()
        router.set('SHOW GRANTS OF ROLE "ETL_ROLE"', _resp(_GRANTS_COLS, [
            ["t", "ETL_ROLE", "APPLICATION_ROLE", "SOME_APP", "USERADMIN"],
        ]))
        records = _fetch(router)
        edges = _by_type(records, SNOWFLAKE_ROLE_HIERARCHY_GRANT)
        assert all(e["child_role_name"] != "ETL_ROLE" for e in edges)

    def test_grants_family_denied_when_all_role_grant_calls_fail(self):
        router = _basic_router()
        for stmt in [
            'SHOW GRANTS OF ROLE "ACCOUNTADMIN"',
            'SHOW GRANTS OF ROLE "ANALYST"',
            'SHOW GRANTS OF ROLE "ETL_ROLE"',
            'SHOW GRANTS OF DATABASE ROLE "MYDB"."DB_READER"',
        ]:
            router.set(stmt, httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["user_role_grants"] == FAMILY_UNAVAILABLE
        assert account["family_completeness"]["role_hierarchy"] == FAMILY_UNAVAILABLE

    def test_grants_family_partial_when_some_role_grant_calls_fail(self):
        router = _basic_router()
        router.set('SHOW GRANTS OF ROLE "ETL_ROLE"', httpx.Response(403))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        assert account["family_completeness"]["user_role_grants"] == FAMILY_PARTIAL
        assert account["family_completeness"]["role_hierarchy"] == FAMILY_PARTIAL
        # ACCOUNTADMIN/ANALYST grants still collected despite ETL_ROLE's denial.
        assert len(_by_type(records, SNOWFLAKE_USER_ROLE_GRANT)) == 2

    def test_default_role_match_true(self):
        records = _fetch(_basic_router())
        grants = _by_type(records, SNOWFLAKE_USER_ROLE_GRANT)
        analyst_grant = next(g for g in grants if g["role_name"] == "ANALYST")
        assert analyst_grant["default_role_match"] is True

    def test_default_role_match_false(self):
        records = _fetch(_basic_router())
        grants = _by_type(records, SNOWFLAKE_USER_ROLE_GRANT)
        admin_grant = next(g for g in grants if g["role_name"] == "ACCOUNTADMIN")
        assert admin_grant["default_role_match"] is False


# ── Family independence ──────────────────────────────────────────────────────


class TestFamilyIndependence:
    def test_users_denied_does_not_affect_account_roles(self):
        router = _basic_router()
        router.set("SHOW USERS", httpx.Response(403))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_ACCOUNT_ROLE)) == 4

    def test_account_roles_denied_does_not_affect_users(self):
        router = _basic_router()
        router.set("SHOW ROLES", httpx.Response(403))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_USER)) == 2

    def test_all_five_families_independent_statuses(self):
        router = _basic_router()
        router.set("SHOW USERS", httpx.Response(403))
        router.set("SHOW DATABASES", httpx.Response(429))
        records = _fetch(router)
        account = _by_type(records, "snowflake_account")[0]
        fc = account["family_completeness"]
        assert fc["users"] == FAMILY_DENIED
        assert fc["account_roles"] == FAMILY_COMPLETE
        assert fc["database_roles"] == FAMILY_UNAVAILABLE


# ── Dedup ─────────────────────────────────────────────────────────────────────


class TestDedup:
    def test_duplicate_user_rows_collapse_to_one_record(self):
        router = _basic_router()
        router.set("SHOW USERS", _resp(_USERS_COLS, [
            ["ALICE", "PERSON", "false", "ANALYST", "ALL", "true", "true", "false", "USERADMIN"],
            ["ALICE", "PERSON", "false", "ANALYST", "ALL", "true", "true", "false", "USERADMIN"],
        ]))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_USER)) == 1

    def test_duplicate_grant_rows_collapse_to_one_record(self):
        router = _basic_router()
        router.set('SHOW GRANTS OF ROLE "ANALYST"', _resp(_GRANTS_COLS, [
            ["t", "ANALYST", "USER", "ALICE", "USERADMIN"],
            ["t", "ANALYST", "USER", "ALICE", "USERADMIN"],
        ]))
        records = _fetch(router)
        grants = _by_type(records, SNOWFLAKE_USER_ROLE_GRANT)
        assert len([g for g in grants if g["role_name"] == "ANALYST"]) == 1


# ── Deterministic ordering ───────────────────────────────────────────────────


class TestDeterministicOrdering:
    def test_reordered_user_rows_produce_same_sorted_output(self):
        router1 = _basic_router()
        router1.set("SHOW USERS", _resp(_USERS_COLS, [
            ["ALICE", "PERSON", "false", "ANALYST", "ALL", "true", "true", "false", "USERADMIN"],
            ["SVC_ETL", "SERVICE", "false", "ETL_ROLE", None, "false", "false", "true", "USERADMIN"],
        ]))
        router2 = _basic_router()
        router2.set("SHOW USERS", _resp(_USERS_COLS, [
            ["SVC_ETL", "SERVICE", "false", "ETL_ROLE", None, "false", "false", "true", "USERADMIN"],
            ["ALICE", "PERSON", "false", "ANALYST", "ALL", "true", "true", "false", "USERADMIN"],
        ]))
        records1 = _fetch(router1)
        records2 = _fetch(router2)
        ids1 = [r["record_id"] for r in records1]
        ids2 = [r["record_id"] for r in records2]
        assert ids1 == ids2


# ── Scale ─────────────────────────────────────────────────────────────────────


class TestScale:
    def test_5000_users(self):
        router = _basic_router()
        rows = [
            [f"USER_{i}", "PERSON", "false", "ANALYST", "ALL", "true", "true", "false", "USERADMIN"]
            for i in range(5000)
        ]
        router.set("SHOW USERS", _resp(_USERS_COLS, rows))
        records = _fetch(router)
        users = _by_type(records, SNOWFLAKE_USER)
        assert len(users) == 5000
        assert len({u["record_id"] for u in users}) == 5000

    def test_2000_account_roles(self):
        router = _basic_router()
        rows = [[f"ROLE_{i}", "SYSADMIN", "1", "0", "0"] for i in range(2000)]
        router.set("SHOW ROLES", _resp(_ACCOUNT_ROLES_COLS, rows))
        # Each of the 2000 roles now triggers a SHOW GRANTS OF ROLE call —
        # mock all of them with a tiny response to keep the test fast.
        for i in range(2000):
            router.set(f'SHOW GRANTS OF ROLE "ROLE_{i}"', _resp(_GRANTS_COLS, []))
        records = _fetch(router)
        roles = _by_type(records, SNOWFLAKE_ACCOUNT_ROLE)
        assert len(roles) == 2000

    def test_2000_database_roles(self):
        router = _basic_router()
        db_names = [f"DB_{i}" for i in range(4)]
        router.set("SHOW DATABASES", _resp(_DATABASES_COLS, [[d] for d in db_names]))
        for db in db_names:
            rows = [[f"DBROLE_{db}_{i}", "SYSADMIN", "0", "0"] for i in range(500)]
            router.set(f'SHOW DATABASE ROLES IN DATABASE "{db}"', _resp(_DATABASE_ROLES_COLS, rows))
            for i in range(500):
                router.set(f'SHOW GRANTS OF DATABASE ROLE "{db}"."DBROLE_{db}_{i}"', _resp(_GRANTS_COLS, []))
        records = _fetch(router)
        db_roles = _by_type(records, SNOWFLAKE_DATABASE_ROLE)
        assert len(db_roles) == 2000

    def test_20000_grant_and_hierarchy_rows(self):
        """100 roles x 200 grantee rows each = 20,000 rows total, split
        across user-role grants and role-hierarchy edges. Proves
        dedup/sort/normalization handle bulk data without error."""
        router = _basic_router()
        # Suppress the baseline MYDB/DB_READER database role from
        # _basic_router() so it doesn't add a stray 20,001st edge —
        # this test isolates the bulk account-role grant/hierarchy count.
        router.set("SHOW DATABASES", _resp(_DATABASES_COLS, []))
        role_names = [f"BULK_ROLE_{i}" for i in range(100)]
        router.set("SHOW ROLES", _resp(_ACCOUNT_ROLES_COLS, [
            [name, "SYSADMIN", "0", "0", "0"] for name in role_names
        ]))
        for role_name in role_names:
            rows = []
            for j in range(200):
                if j % 2 == 0:
                    rows.append(["t", role_name, "USER", f"BULK_USER_{j}", "USERADMIN"])
                else:
                    rows.append(["t", role_name, "ROLE", f"PARENT_ROLE_{j}", "USERADMIN"])
            router.set(f'SHOW GRANTS OF ROLE "{role_name}"', _resp(_GRANTS_COLS, rows))
        records = _fetch(router)
        grants = _by_type(records, SNOWFLAKE_USER_ROLE_GRANT)
        edges = _by_type(records, SNOWFLAKE_ROLE_HIERARCHY_GRANT)
        assert len(grants) + len(edges) == 20000
        assert len(grants) == 100 * 100
        assert len(edges) == 100 * 100
        assert len({g["record_id"] for g in grants}) == len(grants)
        assert len({e["record_id"] for e in edges}) == len(edges)
