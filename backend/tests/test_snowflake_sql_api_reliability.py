"""Snowflake SQL API transport reliability tests (Snowflake message 7 of
8).

Message 1's own test_snowflake_foundation.py already covers a large slice
of this ground (429/503/401/403 retry behavior, async 202 polling to
completion/timeout, sensitive-data redaction, bounded mocked sleep). This
file adds the specific gaps this message's mandatory current-docs
verification surfaced: HTTP 408 (execution-timeout) handling, malformed
result-set metadata shapes, and explicit documentation-as-tests for the
two SQL API capabilities this connector deliberately does NOT implement
(result-set partition pagination, statement cancellation) — every read-
only metadata query this connector issues is a small SHOW/DESCRIBE lookup
never expected to cross a partition boundary or need mid-flight
cancellation, but the gap is certified here rather than silently assumed
away.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.connectors.snowflake import (
    SnowflakeConnector,
    CATEGORY_TIMEOUT,
    CATEGORY_MALFORMED_RESPONSE,
    _ACCOUNT_IDENTITY_STATEMENT,
    call_sql_api,
    _classify_response,
    _parse_success,
    _extract_column_names,
    _rows_as_dicts,
)

_ACCOUNT_ID = "myorg-myaccount"
_ROLE = "CONFIGTRACE_MONITOR"
_BASE = f"https://{_ACCOUNT_ID}.snowflakecomputing.com"
_STATEMENTS_URL = f"{_BASE}/api/v2/statements"


def _noop_sleep(_seconds: float) -> None:
    pass


def _cols(names: list[str]) -> dict:
    return {"resultSetMetaData": {"rowType": [{"name": n} for n in names]}}


def _resp(names: list[str], rows: list[list]) -> httpx.Response:
    body = _cols(names)
    body["data"] = rows
    return httpx.Response(200, json=body)


class _SeqRouter:
    """Returns responses from a fixed sequence, one per call, regardless
    of statement content — used for polling-sequence tests."""

    def __init__(self, responses: list[httpx.Response]):
        self.responses = list(responses)
        self.calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        idx = min(self.calls, len(self.responses) - 1)
        self.calls += 1
        return self.responses[idx]


class TestHttp408Timeout:
    def test_408_classified_as_timeout_not_retried_as_server_error(self):
        resp = httpx.Response(408, json={"message": "execution timeout"})
        category, detail = _classify_response(resp)
        assert category == CATEGORY_TIMEOUT
        assert "408" in detail
        assert "timeout" in detail.lower()

    def test_408_never_appears_in_5xx_retry_path(self):
        """A 408 must never trigger the transient-5xx retry loop (which
        would be pointless — retrying the identical statement is very
        likely to time out again) — it fails immediately as a timeout."""
        with respx.mock:
            respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(408, json={"message": "timeout"}))
            with httpx.Client(base_url=_BASE) as client:
                outcome = call_sql_api(client, "SHOW USERS", role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_TIMEOUT

    def test_408_never_leaks_credential_material(self):
        with respx.mock:
            respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(408, json={"message": "timeout for token abc-secret-pat"}))
            with httpx.Client(base_url=_BASE) as client:
                outcome = call_sql_api(client, "SHOW USERS", role=_ROLE, _sleep_fn=_noop_sleep)
        assert "abc-secret-pat" not in outcome.detail


class TestResultMetadataParsing:
    def test_missing_metadata_returns_none_columns(self):
        assert _extract_column_names({}) is None

    def test_malformed_row_type_returns_none(self):
        assert _extract_column_names({"resultSetMetaData": {"rowType": "not-a-list"}}) is None

    def test_missing_data_key_is_malformed(self):
        resp = httpx.Response(200, json={"resultSetMetaData": {"rowType": [{"name": "NAME"}]}})
        outcome = _parse_success(resp)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_MALFORMED_RESPONSE

    def test_non_json_body_is_malformed(self):
        resp = httpx.Response(200, content=b"not json at all")
        outcome = _parse_success(resp)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_MALFORMED_RESPONSE

    def test_non_dict_json_body_is_malformed(self):
        resp = httpx.Response(200, json=[1, 2, 3])
        outcome = _parse_success(resp)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_MALFORMED_RESPONSE

    def test_reordered_columns_still_map_correctly(self):
        """Column ORDER in the metadata determines row->dict mapping —
        confirm rows are zipped by position against whatever order the
        metadata declares, not a hardcoded expectation."""
        columns = ["OWNER", "NAME"]
        rows = [["SYSADMIN", "ALICE"]]
        dicts = _rows_as_dicts(columns, rows)
        assert dicts == [{"OWNER": "SYSADMIN", "NAME": "ALICE"}]

    def test_extra_row_values_beyond_column_count_are_ignored_safely(self):
        columns = ["NAME"]
        rows = [["ALICE", "EXTRA_VALUE", "ANOTHER"]]
        dicts = _rows_as_dicts(columns, rows)
        assert dicts == [{"NAME": "ALICE"}]

    def test_short_row_missing_trailing_values_fills_none(self):
        columns = ["NAME", "OWNER", "TYPE"]
        rows = [["ALICE"]]
        dicts = _rows_as_dicts(columns, rows)
        assert dicts == [{"NAME": "ALICE", "OWNER": None, "TYPE": None}]

    def test_non_list_row_is_dropped_not_guessed(self):
        columns = ["NAME"]
        rows = ["not-a-list-row", ["ALICE"]]
        dicts = _rows_as_dicts(columns, rows)
        assert dicts == [{"NAME": "ALICE"}]

    def test_no_columns_returns_empty_list_never_guesses_positions(self):
        assert _rows_as_dicts(None, [["ALICE"]]) == []
        assert _rows_as_dicts([], [["ALICE"]]) == []

    def test_null_cells_preserved_as_none(self):
        columns = ["NAME", "OWNER"]
        rows = [["ALICE", None]]
        dicts = _rows_as_dicts(columns, rows)
        assert dicts[0]["OWNER"] is None

    def test_column_names_uppercased_for_lookup(self):
        columns = ["name", "Owner"]
        rows = [["ALICE", "SYSADMIN"]]
        dicts = _rows_as_dicts(columns, rows)
        assert dicts == [{"NAME": "ALICE", "OWNER": "SYSADMIN"}]


class TestAsyncPollingSequences:
    def test_202_then_404_reports_not_found(self):
        client_router = _SeqRouter([
            httpx.Response(202, json={"statementHandle": "h1"}),
            httpx.Response(404, json={"message": "not found"}),
        ])
        with respx.mock:
            respx.post(_STATEMENTS_URL).mock(side_effect=lambda req: client_router(req))
            respx.get(f"{_STATEMENTS_URL}/h1").mock(side_effect=lambda req: client_router(req))
            with httpx.Client(base_url=_BASE) as client:
                outcome = call_sql_api(client, "SHOW USERS", role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == "not_found"

    def test_202_with_missing_handle_is_malformed(self):
        with respx.mock:
            respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(202, json={}))
            with httpx.Client(base_url=_BASE) as client:
                outcome = call_sql_api(client, "SHOW USERS", role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_MALFORMED_RESPONSE

    def test_202_polling_exhaustion_is_bounded_timeout(self):
        """5 poll attempts (the connector's bound) all return 202 ->
        terminal timeout, never an infinite loop."""
        poll_count = {"n": 0}

        def _poll_handler(request: httpx.Request) -> httpx.Response:
            poll_count["n"] += 1
            return httpx.Response(202)

        with respx.mock:
            respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(202, json={"statementHandle": "h1"}))
            respx.get(f"{_STATEMENTS_URL}/h1").mock(side_effect=_poll_handler)
            with httpx.Client(base_url=_BASE) as client:
                outcome = call_sql_api(client, "SHOW USERS", role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_TIMEOUT
        assert poll_count["n"] == 5  # _MAX_POLL_ATTEMPTS

    def test_202_then_success_returns_rows(self):
        with respx.mock:
            respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(202, json={"statementHandle": "h1"}))
            respx.get(f"{_STATEMENTS_URL}/h1").mock(return_value=_resp(["NAME"], [["ALICE"]]))
            with httpx.Client(base_url=_BASE) as client:
                outcome = call_sql_api(client, "SHOW USERS", role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is True
        assert outcome.rows == [["ALICE"]]

    def test_poll_transport_exception_classified_safely(self):
        def _raise(_request):
            raise httpx.ReadTimeout("timed out")

        with respx.mock:
            respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(202, json={"statementHandle": "h1"}))
            respx.get(f"{_STATEMENTS_URL}/h1").mock(side_effect=_raise)
            with httpx.Client(base_url=_BASE) as client:
                outcome = call_sql_api(client, "SHOW USERS", role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_TIMEOUT


class TestDocumentedGaps:
    """These capabilities are confirmed via current official Snowflake
    SQL API docs (message 7) but are NOT implemented — every statement
    this connector issues is a small, bounded metadata SHOW/DESCRIBE
    lookup, never expected to trigger either. Documented here rather
    than silently assumed away."""

    def test_no_partition_query_parameter_is_ever_sent(self):
        """Result-set partition pagination (``?partition=N``) is
        undocumented-as-implemented here — confirm no request this
        connector issues carries a partition parameter."""
        captured = []

        def _capture(request: httpx.Request) -> httpx.Response:
            captured.append(str(request.url))
            return _resp(["NAME"], [])

        with respx.mock:
            respx.post(_STATEMENTS_URL).mock(side_effect=_capture)
            with httpx.Client(base_url=_BASE) as client:
                call_sql_api(client, _ACCOUNT_IDENTITY_STATEMENT, role=_ROLE, _sleep_fn=_noop_sleep)
        assert all("partition" not in url for url in captured)

    def test_no_cancel_endpoint_is_ever_called(self):
        """Statement cancellation (``POST .../cancel``) is not
        implemented — a poll-timeout leaves the statement to expire
        server-side on its own rather than issuing a cancel request this
        connector has no code path for."""
        cancel_called = {"hit": False}

        def _cancel_handler(_request: httpx.Request) -> httpx.Response:
            cancel_called["hit"] = True
            return httpx.Response(200, json={})

        with respx.mock:
            respx.post(_STATEMENTS_URL).mock(return_value=httpx.Response(202, json={"statementHandle": "h1"}))
            respx.get(f"{_STATEMENTS_URL}/h1").mock(return_value=httpx.Response(202))
            respx.post(f"{_STATEMENTS_URL}/h1/cancel").mock(side_effect=_cancel_handler)
            with httpx.Client(base_url=_BASE) as client:
                call_sql_api(client, "SHOW USERS", role=_ROLE, _sleep_fn=_noop_sleep)
        assert cancel_called["hit"] is False


class TestNoInfiniteLoops:
    def test_throttle_retry_bounded_at_four_attempts(self):
        attempts = {"n": 0}

        def _handler(_request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            return httpx.Response(429, json={"message": "throttled"})

        with respx.mock:
            respx.post(_STATEMENTS_URL).mock(side_effect=_handler)
            with httpx.Client(base_url=_BASE) as client:
                outcome = call_sql_api(client, "SHOW USERS", role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == "throttled"
        # Initial attempt + 4 retries = 5 total calls.
        assert attempts["n"] == 5

    def test_server_error_retry_bounded_at_two_attempts(self):
        attempts = {"n": 0}

        def _handler(_request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            return httpx.Response(503, json={"message": "unavailable"})

        with respx.mock:
            respx.post(_STATEMENTS_URL).mock(side_effect=_handler)
            with httpx.Client(base_url=_BASE) as client:
                outcome = call_sql_api(client, "SHOW USERS", role=_ROLE, _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        # Initial attempt + 2 retries = 3 total calls.
        assert attempts["n"] == 3
