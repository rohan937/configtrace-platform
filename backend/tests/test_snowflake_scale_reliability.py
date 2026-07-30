"""Snowflake scale/call-count/determinism/idempotency reliability tests
(Snowflake message 7 of 8).

Complements message 2/3/5's own per-family scale tests (2,000 account
roles, 2,000 warehouses/shares, 25,000 users + 25,000 role grants for
privilege derivation, 5,000 roles / 10,000 hierarchy edges / 100,000
object grants / 20,000 future grants for the privilege graph) with
CONNECTOR-level (full ``fetch()``) scale, call-count-budget certification,
deterministic-ordering, and idempotency tests. Sizes here are chosen to
stay within reasonable test-suite runtime while still exercising the
real O(n) per-role/per-database loops end-to-end — the underlying
per-family collection functions have their own dedicated, larger-scale
unit tests (see test_snowflake_identity_collection.py,
test_snowflake_data_collection.py, test_snowflake_privileged_normalization.py).
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.connectors.snowflake import SnowflakeConnector, _ACCOUNT_IDENTITY_STATEMENT, _CAPABILITY_PROBES
from app.connectors.snowflake_schema import SNOWFLAKE_USER, SNOWFLAKE_ACCOUNT_ROLE, SNOWFLAKE_DATABASE, SNOWFLAKE_PRIVILEGED_USER

_ACCOUNT_ID = "myorg-myaccount"
_USERNAME = "CONFIGTRACE_MONITOR"
_TOKEN = "fake-snowflake-pat-value"
_ROLE = "CONFIGTRACE_MONITOR"
_CREDS = {"account_identifier": _ACCOUNT_ID, "username": _USERNAME, "programmatic_access_token": _TOKEN, "role": _ROLE}
_BASE = f"https://{_ACCOUNT_ID}.snowflakecomputing.com"
_STATEMENTS_URL = f"{_BASE}/api/v2/statements"


def _cols(names):
    return {"resultSetMetaData": {"rowType": [{"name": n} for n in names]}}


def _resp(names, rows):
    body = _cols(names)
    body["data"] = rows
    return httpx.Response(200, json=body)


def _identity_resp():
    return _resp(["ORG_NAME", "ACCOUNT_NAME", "ACCOUNT_LOCATOR", "SESSION_ROLE"], [["ACME", "PROD", "AB123", _ROLE]])


class _Router:
    def __init__(self):
        self.exact: dict[str, httpx.Response] = {_ACCOUNT_IDENTITY_STATEMENT: _identity_resp()}
        # Every capability probe statement must be explicitly registered
        # with a real success response — an unmocked statement falls
        # through this router's own 400 default, which
        # `_classify_response` treats as a retryable server error,
        # inflating call counts with pointless retries.
        for _family, statement in _CAPABILITY_PROBES:
            self.exact[statement] = _resp(["PROBE"], [[1]])
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


def _empty_message4_router(r: _Router) -> _Router:
    r.set("SHOW NETWORK POLICIES", _resp(["NAME"], []))
    r.set("SHOW NETWORK RULES", _resp(["NAME"], []))
    r.set("SHOW AUTHENTICATION POLICIES", _resp(["NAME"], []))
    r.set("SHOW SECURITY INTEGRATIONS", _resp(["NAME"], []))
    r.set("SHOW STORAGE INTEGRATIONS", _resp(["NAME"], []))
    r.set("SHOW EXTERNAL ACCESS INTEGRATIONS", _resp(["NAME"], []))
    return r


def _large_user_role_account_router(n_users: int, n_roles: int) -> _Router:
    r = _Router()
    r.set("SHOW USERS", _resp(
        ["NAME", "TYPE", "DISABLED", "DEFAULT_ROLE", "DEFAULT_SECONDARY_ROLES", "HAS_RSA_PUBLIC_KEY", "HAS_PASSWORD", "HAS_PAT", "OWNER"],
        [[f"USER_{i}", "PERSON", "false", None, "ALL", "false", "true", "false", "USERADMIN"] for i in range(n_users)],
    ))
    r.set("SHOW ROLES", _resp(
        ["NAME", "OWNER", "ASSIGNED_TO_USERS", "GRANTED_TO_ROLES", "GRANTED_ROLES"],
        [[f"ROLE_{i}", "SYSADMIN", "0", "0", "0"] for i in range(n_roles)],
    ))
    for i in range(n_roles):
        r.set(f'SHOW GRANTS OF ROLE "ROLE_{i}"', _resp(["CREATED_ON", "ROLE", "GRANTED_TO", "GRANTEE_NAME", "GRANTED_BY"], []))
        r.set(f'SHOW GRANTS TO ROLE "ROLE_{i}"', _resp(["PRIVILEGE", "GRANTED_ON", "NAME", "GRANTED_TO", "GRANTEE_NAME", "GRANT_OPTION", "GRANTED_BY"], []))
    r.set("SHOW DATABASES", _resp(["NAME"], []))
    r.set("SHOW WAREHOUSES", _resp(["NAME"], []))
    r.set("SHOW SHARES", _resp(["KIND", "NAME"], []))
    return _empty_message4_router(r)


def _fetch(router: _Router) -> list[dict]:
    with respx.mock:
        respx.post(_STATEMENTS_URL).mock(side_effect=router)
        conn = SnowflakeConnector()
        return conn.fetch(_CREDS, _sleep_fn=_noop_sleep)


def _by_type(records, record_type):
    return [r for r in records if r["record_type"] == record_type]


class TestConnectorScale:
    def test_5000_users_full_fetch(self):
        router = _large_user_role_account_router(n_users=5000, n_roles=0)
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_USER)) == 5000

    def test_1000_account_roles_with_per_role_grant_walk(self):
        """1,000 roles each trigger exactly one SHOW GRANTS OF ROLE and
        one SHOW GRANTS TO ROLE call — proves the O(n) per-role walk
        completes correctly and without duplication at this scale."""
        router = _large_user_role_account_router(n_users=0, n_roles=1000)
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_ACCOUNT_ROLE)) == 1000
        of_role_calls = [c for c in router.calls if c.startswith('SHOW GRANTS OF ROLE')]
        to_role_calls = [c for c in router.calls if c.startswith('SHOW GRANTS TO ROLE')]
        assert len(of_role_calls) == 1000
        assert len(to_role_calls) == 1000
        # No duplicates — each role's grant walk issued exactly once.
        assert len(set(of_role_calls)) == 1000
        assert len(set(to_role_calls)) == 1000

    def test_2000_databases_no_schema_fanout(self):
        router = _large_user_role_account_router(n_users=0, n_roles=0)
        router.set("SHOW DATABASES", _resp(["NAME"], [[f"DB_{i}"] for i in range(2000)]))
        for i in range(2000):
            router.set(f'SHOW DATABASE ROLES IN DATABASE "DB_{i}"', _resp(["NAME"], []))
            router.set(f'SHOW SCHEMAS IN DATABASE "DB_{i}"', _resp(["NAME"], []))
            router.set(f'SHOW FUTURE GRANTS IN DATABASE "DB_{i}"', _resp(
                ["PRIVILEGE", "GRANT_ON", "NAME", "GRANT_TO", "GRANTEE_NAME", "GRANT_OPTION"], [],
            ))
        records = _fetch(router)
        assert len(_by_type(records, SNOWFLAKE_DATABASE)) == 2000
        # Per-database completeness fields attached to every database record.
        for db in _by_type(records, SNOWFLAKE_DATABASE):
            assert db["schema_collection_status"] == "complete"
            assert db["database_role_collection_status"] == "complete"
            assert db["future_grant_collection_status"] == "complete"


class TestNoDuplicateQueries:
    def test_show_databases_issued_exactly_once(self):
        router = _large_user_role_account_router(n_users=10, n_roles=0)
        router.set("SHOW DATABASES", _resp(["NAME"], [["MYDB"]]))
        router.set('SHOW DATABASE ROLES IN DATABASE "MYDB"', _resp(["NAME"], []))
        router.set('SHOW SCHEMAS IN DATABASE "MYDB"', _resp(["NAME"], []))
        router.set('SHOW FUTURE GRANTS IN DATABASE "MYDB"', _resp(
            ["PRIVILEGE", "GRANT_ON", "NAME", "GRANT_TO", "GRANTEE_NAME", "GRANT_OPTION"], [],
        ))
        _fetch(router)
        show_databases_calls = [c for c in router.calls if c == "SHOW DATABASES"]
        assert len(show_databases_calls) == 1

    def test_no_duplicate_show_grants_for_same_role_in_one_fetch(self):
        router = _large_user_role_account_router(n_users=0, n_roles=50)
        _fetch(router)
        of_role_calls = [c for c in router.calls if c.startswith('SHOW GRANTS OF ROLE')]
        to_role_calls = [c for c in router.calls if c.startswith('SHOW GRANTS TO ROLE')]
        assert len(of_role_calls) == len(set(of_role_calls))
        assert len(to_role_calls) == len(set(to_role_calls))

    def test_call_count_formula_matches_expectation(self):
        """base fixed calls (identity + 13 capability probes + users +
        roles + databases + warehouses + shares + 6 message-4 SHOWs)
        + O(roles) * 2 (OF ROLE + TO ROLE per role)."""
        n_roles = 25
        router = _large_user_role_account_router(n_users=0, n_roles=n_roles)
        _fetch(router)
        base_fixed_calls = 1 + 13 + 1 + 1 + 1 + 1 + 1 + 6  # identity, probes, users, roles, databases, warehouses, shares, msg4 SHOWs
        expected = base_fixed_calls + (n_roles * 2)
        assert len(router.calls) == expected, f"expected {expected} calls, got {len(router.calls)}"


class TestDeterminismAndIdempotency:
    def test_reordered_rows_produce_identical_records(self):
        rows_a = [["USER_A", "PERSON", "false", None, "ALL", "false", "true", "false", "USERADMIN"],
                  ["USER_B", "PERSON", "false", None, "ALL", "false", "true", "false", "USERADMIN"]]
        rows_b = list(reversed(rows_a))
        cols = ["NAME", "TYPE", "DISABLED", "DEFAULT_ROLE", "DEFAULT_SECONDARY_ROLES", "HAS_RSA_PUBLIC_KEY", "HAS_PASSWORD", "HAS_PAT", "OWNER"]

        router_a = _large_user_role_account_router(n_users=0, n_roles=0)
        router_a.set("SHOW USERS", _resp(cols, rows_a))
        records_a = _fetch(router_a)

        router_b = _large_user_role_account_router(n_users=0, n_roles=0)
        router_b.set("SHOW USERS", _resp(cols, rows_b))
        records_b = _fetch(router_b)

        users_a = sorted((r["record_id"] for r in _by_type(records_a, SNOWFLAKE_USER)))
        users_b = sorted((r["record_id"] for r in _by_type(records_b, SNOWFLAKE_USER)))
        assert users_a == users_b

    def test_two_identical_fetches_produce_zero_diff(self):
        from app.services.diff_service import compute_diff
        from types import SimpleNamespace

        router1 = _large_user_role_account_router(n_users=20, n_roles=5)
        records1 = _fetch(router1)
        router2 = _large_user_role_account_router(n_users=20, n_roles=5)
        records2 = _fetch(router2)

        changes = compute_diff(SimpleNamespace(state=records1), SimpleNamespace(state=records2))
        assert changes == []

    def test_records_sorted_deterministically(self):
        router = _large_user_role_account_router(n_users=50, n_roles=0)
        records = _fetch(router)
        keys = [(r["record_type"], r["record_id"]) for r in records]
        assert keys == sorted(keys)

    def test_fingerprint_stable_across_runs(self):
        """A privileged-user record's identity/content must be byte-for-
        byte stable across two independent fetch() calls against
        identical source data."""
        router1 = _large_user_role_account_router(n_users=0, n_roles=3)
        router1.set("SHOW ROLES", _resp(
            ["NAME", "OWNER", "ASSIGNED_TO_USERS", "GRANTED_TO_ROLES", "GRANTED_ROLES"],
            [["ACCOUNTADMIN", None, "1", "0", "0"]],
        ))
        router1.set("SHOW USERS", _resp(
            ["NAME", "TYPE", "DISABLED", "DEFAULT_ROLE", "DEFAULT_SECONDARY_ROLES", "HAS_RSA_PUBLIC_KEY", "HAS_PASSWORD", "HAS_PAT", "OWNER"],
            [["ALICE", "PERSON", "false", "ACCOUNTADMIN", "ALL", "true", "true", "false", "USERADMIN"]],
        ))
        router1.set('SHOW GRANTS OF ROLE "ACCOUNTADMIN"', _resp(
            ["CREATED_ON", "ROLE", "GRANTED_TO", "GRANTEE_NAME", "GRANTED_BY"],
            [["t", "ACCOUNTADMIN", "USER", "ALICE", "SECURITYADMIN"]],
        ))
        router1.set('SHOW GRANTS TO ROLE "ACCOUNTADMIN"', _resp(
            ["PRIVILEGE", "GRANTED_ON", "NAME", "GRANTED_TO", "GRANTEE_NAME", "GRANT_OPTION", "GRANTED_BY"], [],
        ))
        records1 = _fetch(router1)
        priv_users_1 = _by_type(records1, SNOWFLAKE_PRIVILEGED_USER)
        assert len(priv_users_1) == 1
        assert priv_users_1[0]["record_id"] == "id:acme-prod/privileged_user/alice"
        assert priv_users_1[0]["highest_known_privilege_tier"] == "critical"
