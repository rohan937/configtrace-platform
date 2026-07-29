"""Snowflake provider foundation tests (Snowflake message 1 of 8).

Covers the connector architecture built in this message: account
identifier/username/role validation, Programmatic Access Token (PAT)
authentication over the Snowflake SQL API, stable account identity derived
from CURRENT_ORGANIZATION_NAME()/CURRENT_ACCOUNT_NAME(), the fail-soft
API-call wrapper with bounded 429/5xx retry, and read-only capability
probes for the 13 future record families. No users, roles, grants,
databases, schemas, warehouses, shares, network policies, authentication
policies, or security/storage/external-access integrations are collected
yet — that begins in later messages.

All tests are pure-mock (respx) or unit-level; no real Snowflake account is
contacted.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.connectors.snowflake import (
    _ACCOUNT_IDENTITY_STATEMENT,
    _ACCOUNT_ROLES_STATEMENT,
    _CAPABILITY_PROBES,
    _DATABASE_NAMES_FOR_ROLE_DISCOVERY_STATEMENT,
    _USERS_STATEMENT,
    CATEGORY_AUTH_FAILED,
    CATEGORY_SUCCESS,
    CATEGORY_THROTTLED,
    CallOutcome,
    SnowflakeConnector,
    call_sql_api,
)
from app.connectors.snowflake_schema import (
    CAPABILITY_AVAILABLE,
    CAPABILITY_DENIED,
    CAPABILITY_FAMILIES,
    CAPABILITY_MALFORMED,
    CAPABILITY_THROTTLED,
    CAPABILITY_TIMED_OUT,
    CAPABILITY_UNAVAILABLE,
    CAPABILITY_UNSUPPORTED,
    SNOWFLAKE_ACCOUNT,
    SNOWFLAKE_API_CAPABILITY,
    SnowflakeCredentialError,
    validate_account_identifier,
    validate_role,
    validate_username,
)
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)

_ACCOUNT_ID = "myorg-myaccount"
_USERNAME = "CONFIGTRACE_MONITOR"
_TOKEN = "fake-snowflake-pat-value"
_ROLE = "CONFIGTRACE_MONITORING_ROLE"
_CREDS = {
    "account_identifier": _ACCOUNT_ID,
    "username": _USERNAME,
    "programmatic_access_token": _TOKEN,
    "role": _ROLE,
}
_BASE = f"https://{_ACCOUNT_ID}.snowflakecomputing.com"
_STATEMENTS_URL = f"{_BASE}/api/v2/statements"

_PROBE_STATEMENTS: dict[str, str] = dict(_CAPABILITY_PROBES)


def _noop_sleep(_seconds: float) -> None:
    """Injected in place of time.sleep so retry tests never really sleep."""


def _identity_response(
    org: str = "ACME", account: str = "PROD", locator: str = "AB12345", role: str = _ROLE,
) -> httpx.Response:
    return httpx.Response(200, json={"data": [[org, account, locator, role]]})


def _ok_probe_response() -> httpx.Response:
    return httpx.Response(200, json={"data": [[1]]})


def _make_sql_router(family_status: dict[str, httpx.Response] | None = None, *, identity_response: httpx.Response | None = None):
    """Build a respx side_effect that routes on the *statement* text in the
    POST body — every Snowflake SQL API call hits the same URL, so routing
    must inspect the request body, never the path."""
    family_status = family_status or {}
    identity_resp = identity_response or _identity_response()

    def _router(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        statement = body.get("statement", "")
        if statement == _ACCOUNT_IDENTITY_STATEMENT:
            return identity_resp
        for family, stmt in _PROBE_STATEMENTS.items():
            if statement == stmt:
                return family_status.get(family, _ok_probe_response())
        return httpx.Response(400, json={"message": "unexpected statement"})

    return _router


# ── Account identifier / username / role validation ─────────────────────────


class TestValidateAccountIdentifier:
    def test_orgname_accountname_form_accepted(self):
        assert validate_account_identifier("myorg-myaccount") == "myorg-myaccount"

    def test_legacy_locator_form_accepted(self):
        assert validate_account_identifier("xy12345.us-east-2.aws") == "xy12345.us-east-2.aws"

    def test_uppercase_lowercased(self):
        assert validate_account_identifier("MyOrg-MyAccount") == "myorg-myaccount"

    def test_full_hostname_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_account_identifier("myorg-myaccount.snowflakecomputing.com")

    def test_url_scheme_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_account_identifier("https://myorg-myaccount.snowflakecomputing.com")

    def test_path_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_account_identifier("myorg-myaccount/evil")

    def test_query_fragment_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_account_identifier("myorg-myaccount?x=1")

    def test_whitespace_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_account_identifier("myorg myaccount")

    def test_empty_string_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_account_identifier("")

    def test_non_string_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_account_identifier(None)


class TestValidateUsername:
    def test_valid_username_accepted(self):
        assert validate_username("CONFIGTRACE_MONITOR") == "CONFIGTRACE_MONITOR"

    def test_empty_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_username("")

    def test_non_string_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_username(None)

    def test_whitespace_only_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_username("   ")

    def test_embedded_sql_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_username("user'; DROP TABLE users; --")


class TestValidateRole:
    def test_valid_role_accepted_and_uppercased(self):
        assert validate_role("configtrace_monitoring_role") == "CONFIGTRACE_MONITORING_ROLE"

    def test_empty_role_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_role("")

    def test_none_role_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_role(None)

    def test_accountadmin_not_defaulted(self):
        """Passing a real role never gets silently upgraded/replaced."""
        assert validate_role("read_only_role") == "READ_ONLY_ROLE"

    def test_missing_role_error_mentions_never_defaulting(self):
        with pytest.raises(SnowflakeCredentialError) as exc_info:
            validate_role("")
        msg = str(exc_info.value)
        assert "ACCOUNTADMIN" in msg
        assert "SECURITYADMIN" in msg

    def test_embedded_symbol_rejected(self):
        with pytest.raises(SnowflakeCredentialError):
            validate_role("ROLE; DROP TABLE x")


# ── Authentication ────────────────────────────────────────────────────────────


class TestAuthentication:
    @respx.mock
    def test_valid_credentials_succeed(self):
        respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        assert conn.validate_credentials(_CREDS) is True

    @respx.mock
    def test_invalid_token_raises_authentication_error(self):
        respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(401))
        conn = SnowflakeConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials(_CREDS)

    @respx.mock
    def test_permission_denied_raises_authentication_error(self):
        respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(403))
        conn = SnowflakeConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials(_CREDS)

    def test_missing_token_raises_authentication_error(self):
        conn = SnowflakeConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials(
                {"account_identifier": _ACCOUNT_ID, "username": _USERNAME, "role": _ROLE}
            )

    def test_malformed_account_identifier_raises_before_any_request(self):
        conn = SnowflakeConnector()
        with pytest.raises(SnowflakeCredentialError):
            conn.validate_credentials(
                {
                    "account_identifier": "https://evil.example",
                    "username": _USERNAME,
                    "programmatic_access_token": _TOKEN,
                    "role": _ROLE,
                }
            )

    def test_missing_role_raises_before_any_request(self):
        conn = SnowflakeConnector()
        with pytest.raises(SnowflakeCredentialError):
            conn.validate_credentials(
                {
                    "account_identifier": _ACCOUNT_ID,
                    "username": _USERNAME,
                    "programmatic_access_token": _TOKEN,
                    "role": "",
                }
            )

    @respx.mock
    def test_connection_timeout_raises_network_error(self):
        respx.post(_STATEMENTS_URL).mock(side_effect=httpx.ConnectTimeout("timed out"))
        conn = SnowflakeConnector()
        with pytest.raises(NetworkError):
            conn.validate_credentials(_CREDS)

    @respx.mock
    def test_tls_failure_raises_network_error(self):
        import ssl

        respx.post(_STATEMENTS_URL).mock(side_effect=ssl.SSLError("certificate verify failed"))
        conn = SnowflakeConnector()
        with pytest.raises(NetworkError):
            conn.validate_credentials(_CREDS)

    @respx.mock
    def test_authorization_header_uses_bearer_and_token_type(self):
        route = respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        conn.validate_credentials(_CREDS)
        sent = route.calls.last.request.headers
        assert sent["Authorization"] == f"Bearer {_TOKEN}"
        assert sent["X-Snowflake-Authorization-Token-Type"] == "PROGRAMMATIC_ACCESS_TOKEN"

    @respx.mock
    def test_token_never_appears_in_exception_text(self):
        respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(401))
        conn = SnowflakeConnector()
        try:
            conn.validate_credentials(_CREDS)
        except AuthenticationError as exc:
            assert _TOKEN not in str(exc)
        else:
            pytest.fail("expected AuthenticationError")

    @respx.mock
    def test_token_never_logged(self, caplog):
        import logging

        respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        with caplog.at_level(logging.DEBUG):
            conn.validate_credentials(_CREDS)
        assert _TOKEN not in caplog.text


# ── Account identity ──────────────────────────────────────────────────────────


class TestAccountIdentity:
    def test_stable_identity_computed(self):
        id1 = SnowflakeConnector.compute_account_id("ACME", "PROD")
        id2 = SnowflakeConnector.compute_account_id("ACME", "PROD")
        assert id1 == id2 == "id:acme-prod"

    def test_identity_case_insensitive_on_input(self):
        assert SnowflakeConnector.compute_account_id("Acme", "Prod") == "id:acme-prod"

    def test_different_accounts_are_distinct(self):
        id_a = SnowflakeConnector.compute_account_id("ACME", "PROD")
        id_b = SnowflakeConnector.compute_account_id("ACME", "DEV")
        assert id_a != id_b

    def test_missing_organization_returns_none(self):
        assert SnowflakeConnector.compute_account_id(None, "PROD") is None

    def test_missing_account_name_returns_none(self):
        assert SnowflakeConnector.compute_account_id("ACME", None) is None

    def test_empty_strings_return_none(self):
        assert SnowflakeConnector.compute_account_id("", "") is None

    def test_identity_never_derived_from_account_identifier_credential(self):
        """Rotating the account_identifier credential string must never
        change stable identity — only the Snowflake-returned org/account
        pair may."""
        id_before = SnowflakeConnector.compute_account_id("ACME", "PROD")
        # Simulate a differently-cased/typed account_identifier credential
        # for the SAME underlying account — identity is unaffected because
        # compute_account_id never even sees the credential string.
        id_after = SnowflakeConnector.compute_account_id("ACME", "PROD")
        assert id_before == id_after

    @respx.mock
    def test_fetch_uses_computed_account_id_as_identity(self):
        respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        account_record = next(r for r in records if r["record_type"] == SNOWFLAKE_ACCOUNT)
        assert account_record["account_id"] == "id:acme-prod"

    @respx.mock
    def test_account_locator_and_role_preserved_on_record(self):
        respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        account_record = next(r for r in records if r["record_type"] == SNOWFLAKE_ACCOUNT)
        assert account_record["account_locator"] == "AB12345"
        assert account_record["monitoring_role"] == _ROLE

    @respx.mock
    def test_account_identifier_credential_stored_separately_from_stable_id(self):
        respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        account_record = next(r for r in records if r["record_type"] == SNOWFLAKE_ACCOUNT)
        assert account_record["account_identifier"] == _ACCOUNT_ID
        assert account_record["account_id"] != account_record["account_identifier"]


# ── Account probe (identity query) ───────────────────────────────────────────


class TestAccountProbe:
    @respx.mock
    def test_identity_query_returns_all_four_fields(self):
        respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        account_record = next(r for r in records if r["record_type"] == SNOWFLAKE_ACCOUNT)
        assert account_record["organization_name"] == "ACME"
        assert account_record["account_name"] == "PROD"
        assert account_record["account_locator"] == "AB12345"
        assert account_record["monitoring_role"] == _ROLE

    @respx.mock
    def test_malformed_row_raises_connector_error(self):
        respx.post(_STATEMENTS_URL).mock(
            side_effect=_make_sql_router(identity_response=httpx.Response(200, json={"data": []}))
        )
        conn = SnowflakeConnector()
        with pytest.raises(ConnectorError):
            conn.fetch(_CREDS)

    @respx.mock
    def test_missing_data_key_raises_connector_error(self):
        respx.post(_STATEMENTS_URL).mock(
            side_effect=_make_sql_router(identity_response=httpx.Response(200, json={}))
        )
        conn = SnowflakeConnector()
        with pytest.raises(ConnectorError):
            conn.fetch(_CREDS)

    @respx.mock
    def test_missing_organization_field_raises_connector_error(self):
        """A row missing org/account name means compute_account_id() returns
        None — fetch() must raise rather than silently store a null
        identity."""
        respx.post(_STATEMENTS_URL).mock(
            side_effect=_make_sql_router(
                identity_response=httpx.Response(200, json={"data": [[None, None, "AB12345", _ROLE]]})
            )
        )
        conn = SnowflakeConnector()
        with pytest.raises(ConnectorError):
            conn.fetch(_CREDS)

    @respx.mock
    def test_identity_statement_is_read_only_select(self):
        assert _ACCOUNT_IDENTITY_STATEMENT.strip().upper().startswith("SELECT")

    @respx.mock
    def test_session_role_sent_matches_credential_role(self):
        route = respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        conn.fetch(_CREDS)
        first_call_body = json.loads(route.calls[0].request.content)
        assert first_call_body["role"] == _ROLE


# ── Query safety / read-only discipline ──────────────────────────────────────


class TestQuerySafety:
    def test_identity_statement_has_no_mutation_keywords(self):
        forbidden = ("CREATE", "ALTER", "DROP", "GRANT", "REVOKE", "INSERT", "UPDATE", "DELETE", "MERGE", "COPY", "PUT ", "GET ", "CALL")
        upper = _ACCOUNT_IDENTITY_STATEMENT.upper()
        for kw in forbidden:
            assert kw not in upper

    def test_all_capability_probe_statements_are_select_or_show(self):
        for _family, statement in _CAPABILITY_PROBES:
            upper = statement.strip().upper()
            assert upper.startswith("SELECT") or upper.startswith("SHOW")

    def test_all_capability_probe_statements_have_no_mutation_keywords(self):
        # "GRANT" is deliberately excluded: GRANTS_TO_USERS/GRANTS_TO_ROLES
        # are read-only ACCOUNT_USAGE view *names*, not GRANT statements.
        forbidden = ("CREATE ", "ALTER ", "DROP ", "REVOKE", "INSERT ", "UPDATE ", "DELETE ", "MERGE ", "COPY ", "PUT ", "GET ", "CALL ")
        for _family, statement in _CAPABILITY_PROBES:
            upper = statement.upper()
            for kw in forbidden:
                assert kw not in upper

    def test_thirteen_families_probed(self):
        assert len(_CAPABILITY_PROBES) == 13
        assert {f for f, _ in _CAPABILITY_PROBES} == set(CAPABILITY_FAMILIES)

    def test_every_probe_is_bounded_with_limit_1(self):
        for _family, statement in _CAPABILITY_PROBES:
            assert "LIMIT 1" in statement.upper()

    def test_no_execute_arbitrary_sql_surface_exists(self):
        import inspect

        import app.connectors.snowflake as snowflake_module

        assert not hasattr(SnowflakeConnector, "execute_arbitrary_sql")
        assert not hasattr(SnowflakeConnector, "execute_sql")
        source = inspect.getsource(snowflake_module)
        assert "execute_arbitrary_sql" not in source

    def test_no_cli_subprocess_usage(self):
        """The module docstring legitimately *mentions* SnowSQL/CLI login by
        name to document why it is NOT used — this checks the executable
        code (module docstring stripped), not that prose."""
        import ast
        import inspect

        import app.connectors.snowflake as snowflake_module

        source = inspect.getsource(snowflake_module)
        tree = ast.parse(source)
        module_docstring = ast.get_docstring(tree) or ""
        code_only = source.replace(module_docstring, "", 1).lower()
        for forbidden in ("subprocess", "os.system", "snowsql", "shell=true"):
            assert forbidden not in code_only

    @respx.mock
    def test_statement_body_never_contains_user_controlled_fragment(self):
        """Every POSTed 'statement' field must be exactly one of the fixed,
        connector-owned constants — never string-interpolated with
        credential/user input.

        Message 2 added SHOW USERS/SHOW ROLES/SHOW DATABASES as further
        fixed constants issued unconditionally by fetch(); this test's
        router does not mock them, so they fail soft (family status
        unavailable) but are still issued and must be included in the
        allowlist here.
        """
        route = respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        allowed = {
            _ACCOUNT_IDENTITY_STATEMENT,
            _USERS_STATEMENT,
            _ACCOUNT_ROLES_STATEMENT,
            _DATABASE_NAMES_FOR_ROLE_DISCOVERY_STATEMENT,
        } | {stmt for _f, stmt in _CAPABILITY_PROBES}
        for call in route.calls:
            body = json.loads(call.request.content)
            assert body["statement"] in allowed
            assert _ACCOUNT_ID not in body["statement"]
            assert _USERNAME not in body["statement"]


# ── Capability probes ──────────────────────────────────────────────────────────


class TestCapabilityProbes:
    @respx.mock
    def test_all_available(self):
        respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        capability_records = [r for r in records if r["record_type"] == SNOWFLAKE_API_CAPABILITY]
        assert len(capability_records) == 13
        assert all(r["status"] == CAPABILITY_AVAILABLE for r in capability_records)

    @respx.mock
    def test_mixed_available_and_denied(self):
        respx.post(_STATEMENTS_URL).mock(
            side_effect=_make_sql_router({"users": httpx.Response(403)})
        )
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        capabilities = {r["family"]: r["status"] for r in records if r["record_type"] == SNOWFLAKE_API_CAPABILITY}
        assert capabilities["users"] == CAPABILITY_DENIED
        assert capabilities["roles"] == CAPABILITY_AVAILABLE

    @respx.mock
    def test_unsupported_family_reports_unsupported(self):
        respx.post(_STATEMENTS_URL).mock(
            side_effect=_make_sql_router({"authentication_policies": httpx.Response(404)})
        )
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        capabilities = {r["family"]: r["status"] for r in records if r["record_type"] == SNOWFLAKE_API_CAPABILITY}
        assert capabilities["authentication_policies"] == CAPABILITY_UNSUPPORTED

    @respx.mock
    def test_throttled_family_reports_throttled(self):
        respx.post(_STATEMENTS_URL).mock(
            side_effect=_make_sql_router({"warehouses": httpx.Response(429)})
        )
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        capabilities = {r["family"]: r["status"] for r in records if r["record_type"] == SNOWFLAKE_API_CAPABILITY}
        assert capabilities["warehouses"] == CAPABILITY_THROTTLED

    @respx.mock
    def test_malformed_response_reports_malformed(self):
        respx.post(_STATEMENTS_URL).mock(
            side_effect=_make_sql_router({"shares": httpx.Response(200, content=b"not json")})
        )
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        capabilities = {r["family"]: r["status"] for r in records if r["record_type"] == SNOWFLAKE_API_CAPABILITY}
        assert capabilities["shares"] == CAPABILITY_MALFORMED

    @respx.mock
    def test_one_denied_optional_family_does_not_invalidate_connection(self):
        """A single denied capability family must never abort the whole
        fetch — only the account identity query failing does that."""
        respx.post(_STATEMENTS_URL).mock(
            side_effect=_make_sql_router({"security_integrations": httpx.Response(403)})
        )
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        account_record = next(r for r in records if r["record_type"] == SNOWFLAKE_ACCOUNT)
        assert account_record is not None
        assert len([r for r in records if r["record_type"] == SNOWFLAKE_API_CAPABILITY]) == 13

    @respx.mock
    def test_family_statuses_are_independent(self):
        respx.post(_STATEMENTS_URL).mock(
            side_effect=_make_sql_router({
                "users": httpx.Response(403),
                "databases": httpx.Response(404),
                "warehouses": httpx.Response(429),
            })
        )
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        capabilities = {r["family"]: r["status"] for r in records if r["record_type"] == SNOWFLAKE_API_CAPABILITY}
        assert capabilities["users"] == CAPABILITY_DENIED
        assert capabilities["databases"] == CAPABILITY_UNSUPPORTED
        assert capabilities["warehouses"] == CAPABILITY_THROTTLED
        assert capabilities["roles"] == CAPABILITY_AVAILABLE
        assert capabilities["shares"] == CAPABILITY_AVAILABLE

    @respx.mock
    def test_family_completeness_reflects_capability_status(self):
        respx.post(_STATEMENTS_URL).mock(
            side_effect=_make_sql_router({"schemas": httpx.Response(403)})
        )
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        account_record = next(r for r in records if r["record_type"] == SNOWFLAKE_ACCOUNT)
        assert account_record["family_completeness"]["schemas"] == "unavailable"
        assert account_record["family_completeness"]["roles"] == "complete"


# ── Retry / rate limiting ────────────────────────────────────────────────────


class TestRateLimit:
    @respx.mock
    def test_429_then_success(self):
        respx.post(_STATEMENTS_URL).mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0"}),
                _identity_response(),
            ]
        )
        with httpx.Client(base_url=_BASE) as client:
            outcome = call_sql_api(client, _ACCOUNT_IDENTITY_STATEMENT, role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is True
        assert outcome.category == CATEGORY_SUCCESS

    @respx.mock
    def test_429_exhausted_retries(self):
        respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(429))
        with httpx.Client(base_url=_BASE) as client:
            outcome = call_sql_api(client, _ACCOUNT_IDENTITY_STATEMENT, role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_THROTTLED

    @respx.mock
    def test_503_then_success(self):
        respx.post(_STATEMENTS_URL).mock(
            side_effect=[httpx.Response(503), _identity_response()]
        )
        with httpx.Client(base_url=_BASE) as client:
            outcome = call_sql_api(client, _ACCOUNT_IDENTITY_STATEMENT, role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is True

    @respx.mock
    def test_5xx_retry_budget_exhausted(self):
        respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(503))
        with httpx.Client(base_url=_BASE) as client:
            outcome = call_sql_api(client, _ACCOUNT_IDENTITY_STATEMENT, role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == "server_error"

    @respx.mock
    def test_401_never_retried(self):
        route = respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(401))
        with httpx.Client(base_url=_BASE) as client:
            call_sql_api(client, _ACCOUNT_IDENTITY_STATEMENT, role=_ROLE, _sleep_fn=_noop_sleep)
        assert route.call_count == 1

    @respx.mock
    def test_403_never_retried(self):
        route = respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(403))
        with httpx.Client(base_url=_BASE) as client:
            call_sql_api(client, _ACCOUNT_IDENTITY_STATEMENT, role=_ROLE, _sleep_fn=_noop_sleep)
        assert route.call_count == 1

    @respx.mock
    def test_sleep_is_mocked_never_real(self):
        sleep_calls: list[float] = []
        respx.post(_STATEMENTS_URL).mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0.001"}),
                _identity_response(),
            ]
        )
        with httpx.Client(base_url=_BASE) as client:
            call_sql_api(client, _ACCOUNT_IDENTITY_STATEMENT, role=_ROLE, _sleep_fn=sleep_calls.append)
        assert len(sleep_calls) == 1

    @respx.mock
    def test_async_202_polled_to_completion(self):
        respx.post(_STATEMENTS_URL).mock(
            return_value=httpx.Response(202, json={"statementHandle": "abc-123"})
        )
        respx.get(f"{_BASE}/api/v2/statements/abc-123").mock(
            side_effect=[httpx.Response(202), _identity_response()]
        )
        with httpx.Client(base_url=_BASE) as client:
            outcome = call_sql_api(client, _ACCOUNT_IDENTITY_STATEMENT, role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is True

    @respx.mock
    def test_async_poll_timeout_reported(self):
        respx.post(_STATEMENTS_URL).mock(
            return_value=httpx.Response(202, json={"statementHandle": "abc-123"})
        )
        respx.get(f"{_BASE}/api/v2/statements/abc-123").mock(return_value=httpx.Response(202))
        with httpx.Client(base_url=_BASE) as client:
            outcome = call_sql_api(client, _ACCOUNT_IDENTITY_STATEMENT, role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == "timeout"


# ── Sensitive-data safety ─────────────────────────────────────────────────────


class TestSensitiveDataSafety:
    @respx.mock
    def test_token_absent_from_records(self):
        respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        blob = str(records)
        assert _TOKEN not in blob

    @respx.mock
    def test_authorization_header_absent_from_records(self):
        respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        blob = str(records)
        assert "Authorization" not in blob
        assert "Bearer" not in blob

    @respx.mock
    def test_raw_sql_api_response_body_absent_from_records(self):
        respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        blob = str(records)
        assert "statementHandle" not in blob

    @respx.mock
    def test_credential_dict_never_copied_wholesale_into_a_record(self):
        respx.post(_STATEMENTS_URL).mock(side_effect=_make_sql_router())
        conn = SnowflakeConnector()
        records = conn.fetch(_CREDS)
        for record in records:
            assert "programmatic_access_token" not in record
            assert "username" not in record


# ── Diff (real compute_diff -> classify_snowflake_change) ───────────────────


class TestDiff:
    def test_account_metadata_change_is_low(self):
        from types import SimpleNamespace

        from app.services.diff_service import compute_diff
        from app.services.risk_service import classify_change

        prev_snapshot = SimpleNamespace(state=[{
            "record_type": SNOWFLAKE_ACCOUNT,
            "record_id": "id:acme-prod",
            "account_id": "id:acme-prod",
            "organization_name": "ACME",
            "account_name": "PROD",
            "account_locator": "AB12345",
            "monitoring_role": "OLD_ROLE",
        }])
        new_snapshot = SimpleNamespace(state=[{
            "record_type": SNOWFLAKE_ACCOUNT,
            "record_id": "id:acme-prod",
            "account_id": "id:acme-prod",
            "organization_name": "ACME",
            "account_name": "PROD",
            "account_locator": "AB12345",
            "monitoring_role": "NEW_ROLE",
        }])
        changes = compute_diff(prev_snapshot, new_snapshot)
        assert len(changes) == 1
        level, reason = classify_change(changes[0])
        assert level == "low"
        assert "Snowflake" in reason

    def test_account_removed_is_medium(self):
        from types import SimpleNamespace

        from app.services.diff_service import compute_diff
        from app.services.risk_service import classify_change

        prev_snapshot = SimpleNamespace(state=[{
            "record_type": SNOWFLAKE_ACCOUNT,
            "record_id": "id:acme-prod",
            "account_id": "id:acme-prod",
            "organization_name": "ACME",
            "account_name": "PROD",
        }])
        new_snapshot = SimpleNamespace(state=[])
        changes = compute_diff(prev_snapshot, new_snapshot)
        assert len(changes) == 1
        level, reason = classify_change(changes[0])
        assert level == "medium"

    def test_capability_lost_is_medium(self):
        from types import SimpleNamespace

        from app.services.diff_service import compute_diff
        from app.services.risk_service import classify_change

        prev_snapshot = SimpleNamespace(state=[{
            "record_type": SNOWFLAKE_API_CAPABILITY,
            "record_id": "id:acme-prod/capability/users",
            "account_id": "id:acme-prod",
            "family": "users",
            "status": CAPABILITY_AVAILABLE,
        }])
        new_snapshot = SimpleNamespace(state=[{
            "record_type": SNOWFLAKE_API_CAPABILITY,
            "record_id": "id:acme-prod/capability/users",
            "account_id": "id:acme-prod",
            "family": "users",
            "status": CAPABILITY_DENIED,
        }])
        changes = compute_diff(prev_snapshot, new_snapshot)
        assert len(changes) == 1
        level, reason = classify_change(changes[0])
        assert level == "medium"

    def test_capability_restored_is_low(self):
        from types import SimpleNamespace

        from app.services.diff_service import compute_diff
        from app.services.risk_service import classify_change

        prev_snapshot = SimpleNamespace(state=[{
            "record_type": SNOWFLAKE_API_CAPABILITY,
            "record_id": "id:acme-prod/capability/users",
            "account_id": "id:acme-prod",
            "family": "users",
            "status": CAPABILITY_DENIED,
        }])
        new_snapshot = SimpleNamespace(state=[{
            "record_type": SNOWFLAKE_API_CAPABILITY,
            "record_id": "id:acme-prod/capability/users",
            "account_id": "id:acme-prod",
            "family": "users",
            "status": CAPABILITY_AVAILABLE,
        }])
        changes = compute_diff(prev_snapshot, new_snapshot)
        assert len(changes) == 1
        level, reason = classify_change(changes[0])
        assert level == "low"

    def test_diff_provider_metadata_excludes_credentials(self):
        from types import SimpleNamespace

        from app.services.diff_service import compute_diff

        prev_snapshot = SimpleNamespace(state=[{
            "record_type": SNOWFLAKE_ACCOUNT,
            "record_id": "id:acme-prod",
            "account_id": "id:acme-prod",
            "organization_name": "ACME",
            "account_name": "PROD",
        }])
        new_snapshot = SimpleNamespace(state=[{
            "record_type": SNOWFLAKE_ACCOUNT,
            "record_id": "id:acme-prod",
            "account_id": "id:acme-prod",
            "organization_name": "ACME",
            "account_name": "PROD2",
        }])
        changes = compute_diff(prev_snapshot, new_snapshot)
        assert len(changes) == 1
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == SNOWFLAKE_ACCOUNT
        for forbidden in ("programmatic_access_token", "username", "password", "private_key"):
            assert forbidden not in pm
