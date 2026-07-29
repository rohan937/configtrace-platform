"""Snowflake provider foundation connector (Snowflake message 1 of 8).

Establishes a secure, read-only connection to a Snowflake account using a
Programmatic Access Token (PAT) over the Snowflake SQL API, resolves a
stable account identity, and probes (never collects) the future record
families (users, roles, role/object grants, databases, schemas,
warehouses, shares, network policies, authentication policies, security/
storage/external-access integrations) that later messages will build.

This connector intentionally does NOT collect users, roles, grants,
databases, schemas, warehouses, shares, network policies, or integrations
yet. The connector is registered internally (dispatch, schema, capability
matrix) but is NOT publicly connectable — it is excluded from the
frontend's PROVIDER_IDS / CONNECTABLE_PROVIDER_IDS until Snowflake
message 8.

Roadmap (this message owns foundation ONLY — do not begin later messages):
  msg 1 (this message) — foundation, authentication, account identity, connector.
  msg 2 — users, account roles, role hierarchy, user-role grants.
  msg 3 — databases, schemas, warehouses, shares, ownership/object grants.
  msg 4 — network policies, authentication policies, OAuth/security
          integrations, account security controls.
  msg 5 — effective privilege, ACCOUNTADMIN/SYSADMIN/security-admin
          posture, ownership/privilege graph.
  msg 6 — Security Findings.
  msg 7 — exhaustive Change classification, partial-sync/reliability
          hardening.
  msg 8 — public launch.

Authentication
---------------
Programmatic Access Token (PAT), sent as an HTTP Bearer token to the
Snowflake SQL API — no separate token-acquisition/exchange step (unlike
Okta's API-token-over-REST or Entra's OAuth client-credentials flow): the
PAT itself IS the bearer credential used directly on every request.

    Authorization: Bearer <programmatic_access_token>
    X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN

Credentials dict:
    account_identifier : str — Snowflake account identifier, preferred
                 ``orgname-accountname`` form or the legacy (optionally
                 region/cloud-qualified) account-locator form. Used ONLY
                 to construct the fixed request hostname
                 ``https://{account_identifier}.snowflakecomputing.com`` —
                 never accepted as a full URL.
    username    : str — the service user's Snowflake login name.
    programmatic_access_token : str — the PAT secret. NEVER logged, NEVER
                 stored outside the encrypted credentials column, NEVER
                 returned in any API response, NEVER copied into a
                 normalized record.
    role        : str — REQUIRED explicit monitoring role. Never silently
                 defaulted to ACCOUNTADMIN or SECURITYADMIN. Current
                 Snowflake documentation notes that PATs issued to service
                 users require an explicit role restriction by default —
                 ConfigTrace's own explicit-role requirement is a superset
                 of that guidance, not a workaround for it.

Why PAT (not key-pair, not OAuth) for message 1
-------------------------------------------------
Current official Snowflake documentation
(https://docs.snowflake.com/en/user-guide/programmatic-access-tokens,
https://docs.snowflake.com/en/user-guide/key-pair-auth) confirms Snowflake
is moving service users toward exactly three non-interactive methods:
key-pair, OAuth, and PAT (plus newer WIF). Of these, PAT was chosen for
message 1 because:

  * It requires zero new production dependency — the SQL API accepts the
    PAT directly as an HTTP Bearer token, so the existing ``httpx`` client
    is sufficient (see "Transport choice" below). Key-pair auth requires
    generating/holding a JWT signed with the customer's RSA/ECDSA private
    key, which is a materially larger onboarding and credential-handling
    surface for a first foundation message.
  * It matches ConfigTrace's existing single-secret-field onboarding
    pattern (Okta's ``api_token``, GitLab's PAT, Linear's API key) more
    closely than key-pair's private-key(+passphrase) material.
  * Snowflake explicitly documents PAT role-restriction semantics for
    service users, which lines up with this connector's own explicit-role
    requirement (see ``role`` above).

Key-pair authentication is a documented future enhancement — NOT
implemented here. OAuth is not implemented because it requires an
interactive/administrator consent flow that does not fit "backend SaaS
connector with a dedicated service user" better than PAT does for this
provider's first message.

No interactive authentication of any kind (browser SSO, human MFA
prompts, SnowSQL/CLI login, external-browser auth, interactive username/
password sessions) is implemented or ever will be — ConfigTrace is a
backend SaaS connector with no interactive session.

Transport choice: Snowflake SQL API over HTTPS (not the Python Connector)
--------------------------------------------------------------------------
The Snowflake SQL API is a plain REST API (``POST /api/v2/statements``,
``GET /api/v2/statements/{handle}``) that accepts a PAT as a bearer token
exactly like every other HTTP-based connector in this codebase already
uses ``httpx`` for. Choosing the SQL API over ``snowflake-connector-
python``:

  * Adds ZERO new production dependencies (``snowflake-connector-python``
    pulls in a large C-extension/OpenSSL-adjacent dependency tree; this
    repository's existing ``httpx`` client is already fully sufficient).
  * Has fully bounded, explicit HTTP timeout behavior under ConfigTrace's
    control (see ``_TIMEOUT``), rather than relying on a third-party
    driver's own internal timeout/retry/session-management behavior.
  * Requires no local libssl/ODBC/native-driver installation story for
    the Render deployment environment.
  * Supports the chosen PAT auth model natively via a single header.

Snowpark, SnowSQL, and any ODBC/JDBC driver are explicitly NOT used —
Snowpark is a compute/dataframe framework (unnecessary for metadata-only
collection) and SnowSQL is an interactive CLI tool (violates the
no-interactive-auth / no-CLI-dependency constraint below).

SQL / read-only discipline
----------------------------
Every statement this connector issues is a fixed, connector-owned,
allowlisted SQL string — never user-controlled SQL, never an interpolated
object name. Only ``SELECT``/``SHOW`` statements are ever issued.
``CREATE``/``ALTER``/``DROP``/``GRANT``/``REVOKE``/``INSERT``/``UPDATE``/
``DELETE``/``MERGE``/``COPY``/``PUT``/``GET``/``CALL`` are never executed
by this connector under any code path — ConfigTrace never mutates a
connected Snowflake account.

No warehouse is required in the credential model: the foundation
validation query and every message-1 capability probe use context
functions (``CURRENT_ORGANIZATION_NAME()`` etc.), ``SHOW`` commands, or
``SNOWFLAKE.ACCOUNT_USAGE`` metadata views — none of which require an
active/resumed virtual warehouse. If a future message's collection
genuinely needs compute (e.g. a heavier Account Usage aggregation), a
warehouse will be introduced then as an OPTIONAL setting, never a
foundation requirement.

SHOW vs ACCOUNT_USAGE strategy (documented once, applied consistently)
-------------------------------------------------------------------------
  * SHOW-based probes/collection: structural/object families with no
    meaningful Account Usage replication lag concern and where the
    "current state right now" is what matters — databases, schemas,
    warehouses, shares, authentication policies, security integrations,
    storage integrations, external-access integrations (SHOW variants
    documented for all of these; no corresponding ACCOUNT_USAGE view was
    confirmed via current official docs for the four integration/policy
    families, so SHOW is used and documented as this message's decision
    rather than guessed).
  * ACCOUNT_USAGE-based probes/collection: users, roles, role grants
    (``GRANTS_TO_USERS``), object grants (``GRANTS_TO_ROLES``), and
    network policies (``NETWORK_POLICIES`` — confirmed via current
    official Snowflake documentation, which also documents up to ~120
    minutes of replication latency for this view). These are the security/
    identity-inventory families message 2+ will actually collect from
    Account Usage (for fields like RSA-key/PAT-configured flags that SHOW
    USERS does not expose), so the message-1 capability probe tests the
    SAME surface that will later be used for real collection — never a
    proxy surface that could pass while the real target fails.

Account Usage latency is a documented architectural reality: some views
(confirmed: ``NETWORK_POLICIES``, up to ~120 minutes) are NOT
near-real-time. Later messages that rely on Account Usage views for drift
detection must document per-view latency rather than implying immediate
detection.

SECURITY — what is NEVER stored, logged, or returned
------------------------------------------------------
- programmatic_access_token — NEVER stored on the connector instance
  beyond one call's local scope, NEVER logged, NEVER included in error
  messages or exceptions, NEVER written to any record.
- Authorization header value — NEVER appears in logs or exception text.
- Raw Snowflake SQL API response bodies — NEVER stored; only flat safe
  scalars extracted via a dedicated per-query normalizer.
- passwords, private keys, private key passphrases, session tokens, OAuth
  tokens, query IDs (beyond what a failure category needs), and arbitrary
  account/user data — NEVER fetched in this foundation message.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.snowflake_schema import (
    CAPABILITY_AVAILABLE,
    CAPABILITY_DENIED,
    CAPABILITY_FAMILIES,
    CAPABILITY_FAMILY_AUTHENTICATION_POLICIES,
    CAPABILITY_FAMILY_DATABASES,
    CAPABILITY_FAMILY_EXTERNAL_ACCESS_INTEGRATIONS,
    CAPABILITY_FAMILY_NETWORK_POLICIES,
    CAPABILITY_FAMILY_OBJECT_GRANTS,
    CAPABILITY_FAMILY_ROLE_GRANTS,
    CAPABILITY_FAMILY_ROLES,
    CAPABILITY_FAMILY_SCHEMAS,
    CAPABILITY_FAMILY_SECURITY_INTEGRATIONS,
    CAPABILITY_FAMILY_SHARES,
    CAPABILITY_FAMILY_STORAGE_INTEGRATIONS,
    CAPABILITY_FAMILY_USERS,
    CAPABILITY_FAMILY_WAREHOUSES,
    CAPABILITY_MALFORMED,
    CAPABILITY_THROTTLED,
    CAPABILITY_TIMED_OUT,
    CAPABILITY_UNAVAILABLE,
    CAPABILITY_UNKNOWN,
    CAPABILITY_UNSUPPORTED,
    COLLECTION_FAMILY_ACCOUNT_ROLES,
    COLLECTION_FAMILY_DATABASE_ROLES,
    COLLECTION_FAMILY_ROLE_HIERARCHY,
    COLLECTION_FAMILY_USER_ROLE_GRANTS,
    COLLECTION_FAMILY_USERS,
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    FAMILY_PARTIAL,
    FAMILY_UNAVAILABLE,
    GRANT_OPTION_UNKNOWN,
    PRINCIPAL_TYPE_ACCOUNT_ROLE,
    PRINCIPAL_TYPE_DATABASE_ROLE,
    PRINCIPAL_TYPE_USER,
    SNOWFLAKE_ACCOUNT,
    SNOWFLAKE_ACCOUNT_ROLE,
    SNOWFLAKE_API_CAPABILITY,
    SNOWFLAKE_DATABASE_ROLE,
    SNOWFLAKE_ROLE_HIERARCHY_GRANT,
    SNOWFLAKE_USER,
    SNOWFLAKE_USER_ROLE_GRANT,
    categorize_account_role,
    categorize_disabled,
    categorize_principal_type,
    categorize_secondary_roles,
    categorize_tristate_bool,
    categorize_user_type,
    is_public_role,
    validate_account_identifier,
    validate_role,
    validate_username,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ──────────────────────────────────────────────────

_TIMEOUT = 30.0
_MAX_STR_LEN = 200

# Snowflake SQL API statement-level execution timeout (seconds). Kept small
# and fixed — every query this connector issues is a tiny metadata lookup,
# never a heavyweight scan. Never user-controlled.
_STATEMENT_TIMEOUT_SECONDS = 30
_SQL_API_VERSION = "v2"

# Bounded polling for the (rare, for these tiny queries) async 202 path.
_MAX_POLL_ATTEMPTS = 5
_POLL_INTERVAL_SECONDS = 1.0

# 429/5xx retry bounds — bounded exponential backoff with jitter, mirroring
# the Okta/Entra/Kubernetes reliability pattern.
_MAX_THROTTLE_RETRIES = 4
_THROTTLE_BASE_DELAY_SECONDS = 1.0
_THROTTLE_MAX_DELAY_SECONDS = 30.0
_MAX_SERVER_ERROR_RETRIES = 2
_SERVER_ERROR_BASE_DELAY_SECONDS = 0.5

# Fixed, connector-owned, read-only statements. Never user-controlled SQL,
# never string-interpolated with untrusted input.
_ACCOUNT_IDENTITY_STATEMENT = (
    "SELECT CURRENT_ORGANIZATION_NAME() AS ORG_NAME, "
    "CURRENT_ACCOUNT_NAME() AS ACCOUNT_NAME, "
    "CURRENT_ACCOUNT() AS ACCOUNT_LOCATOR, "
    "CURRENT_ROLE() AS SESSION_ROLE"
)

# Capability probes: (family, statement). Every probe is a single, minimal,
# read-only query — never a broad enumeration. See the module docstring's
# "SHOW vs ACCOUNT_USAGE strategy" section for the rationale behind each
# family's chosen source.
_CAPABILITY_PROBES: tuple[tuple[str, str], ...] = (
    (CAPABILITY_FAMILY_USERS, "SELECT 1 AS PROBE FROM SNOWFLAKE.ACCOUNT_USAGE.USERS LIMIT 1"),
    (CAPABILITY_FAMILY_ROLES, "SELECT 1 AS PROBE FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES LIMIT 1"),
    (CAPABILITY_FAMILY_ROLE_GRANTS, "SELECT 1 AS PROBE FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS LIMIT 1"),
    (CAPABILITY_FAMILY_OBJECT_GRANTS, "SELECT 1 AS PROBE FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES LIMIT 1"),
    (CAPABILITY_FAMILY_DATABASES, "SHOW DATABASES LIMIT 1"),
    (CAPABILITY_FAMILY_SCHEMAS, "SHOW SCHEMAS LIMIT 1"),
    (CAPABILITY_FAMILY_WAREHOUSES, "SHOW WAREHOUSES LIMIT 1"),
    (CAPABILITY_FAMILY_SHARES, "SHOW SHARES LIMIT 1"),
    (CAPABILITY_FAMILY_NETWORK_POLICIES, "SELECT 1 AS PROBE FROM SNOWFLAKE.ACCOUNT_USAGE.NETWORK_POLICIES LIMIT 1"),
    (CAPABILITY_FAMILY_AUTHENTICATION_POLICIES, "SHOW AUTHENTICATION POLICIES LIMIT 1"),
    (CAPABILITY_FAMILY_SECURITY_INTEGRATIONS, "SHOW SECURITY INTEGRATIONS LIMIT 1"),
    (CAPABILITY_FAMILY_STORAGE_INTEGRATIONS, "SHOW STORAGE INTEGRATIONS LIMIT 1"),
    (CAPABILITY_FAMILY_EXTERNAL_ACCESS_INTEGRATIONS, "SHOW EXTERNAL ACCESS INTEGRATIONS LIMIT 1"),
)

assert {f for f, _ in _CAPABILITY_PROBES} == set(CAPABILITY_FAMILIES)


# ── Message 2: identity/role collection statements ──────────────────────────
#
# Collection-strategy decision (see module docstring's "SHOW vs
# ACCOUNT_USAGE" section, extended below): every message-2 family uses
# SHOW, never SNOWFLAKE.ACCOUNT_USAGE. Rationale: ACCOUNT_USAGE views
# require an active/resumed virtual warehouse to scan (they are ordinary
# table-backed views, unlike the context functions and SHOW commands used
# throughout message 1), and the message-1 credential model deliberately
# has no warehouse field. Introducing a mandatory warehouse requirement
# here — silently or otherwise — was explicitly out of scope for this
# message. SHOW is also strictly better for this data: it reflects current
# state with no replication latency (ACCOUNT_USAGE.USERS/ROLES/
# GRANTS_TO_USERS/GRANTS_TO_ROLES all document up to ~120 minutes of lag),
# and it never returns a dropped/deleted object at all, which sidesteps
# ACCOUNT_USAGE's historical-row retention entirely (no risk of a stale
# deleted row being mistaken for a live one).
#
# Trade-off accepted: SHOW USERS/ROLES filter most columns to NULL unless
# the active role has OWNERSHIP on the object or MANAGE GRANTS on the
# account (documented). Missing values are therefore normalized as
# "unknown", never coerced to a default.
_USERS_STATEMENT = "SHOW USERS"
_ACCOUNT_ROLES_STATEMENT = "SHOW ROLES"

# Used ONLY to discover database names so database roles (which require
# ``IN DATABASE <name>`` — Snowflake does not offer an account-wide
# variant of SHOW DATABASE ROLES) can be enumerated. This is NOT database
# inventory collection — no ``snowflake_database`` record is produced from
# this query. Full database/schema/warehouse/share inventory is message 3.
_DATABASE_NAMES_FOR_ROLE_DISCOVERY_STATEMENT = "SHOW DATABASES"


def _database_roles_statement(database_name: str) -> str:
    return f"SHOW DATABASE ROLES IN DATABASE {_quote_identifier(database_name)}"


def _grants_of_account_role_statement(role_name: str) -> str:
    return f"SHOW GRANTS OF ROLE {_quote_identifier(role_name)}"


def _grants_of_database_role_statement(database_name: str, role_name: str) -> str:
    return f"SHOW GRANTS OF DATABASE ROLE {_quote_identifier(database_name)}.{_quote_identifier(role_name)}"


# ── Fail-soft API-call wrapper (mirrors the Okta/Entra/Kubernetes
#    reliability pattern) ────────────────────────────────────────────────────


@dataclass
class CallOutcome:
    """Result of one fail-soft Snowflake SQL API call. ``category`` never
    leaks credential material — only a safe, fixed message plus the HTTP
    status code (if any) is retained in ``detail``."""

    ok: bool
    rows: Any = None
    columns: Optional[list[str]] = None
    category: str = "success"
    detail: str = ""


CATEGORY_SUCCESS = "success"
CATEGORY_AUTH_FAILED = "auth_failed"
CATEGORY_PERMISSION_DENIED = "permission_denied"
CATEGORY_NOT_FOUND = "not_found"
CATEGORY_THROTTLED = "throttled"
CATEGORY_SERVER_ERROR = "server_error"
CATEGORY_CONNECTION_ERROR = "connection_error"
CATEGORY_TLS_ERROR = "tls_error"
CATEGORY_TIMEOUT = "timeout"
CATEGORY_MALFORMED_RESPONSE = "malformed_response"


def _classify_response(resp: httpx.Response) -> tuple[str, str]:
    status = resp.status_code
    if status == 401:
        return CATEGORY_AUTH_FAILED, "HTTP 401: Snowflake rejected the supplied token."
    if status == 403:
        return CATEGORY_PERMISSION_DENIED, "HTTP 403: permission denied for this resource."
    if status == 404:
        return CATEGORY_NOT_FOUND, "HTTP 404: resource or endpoint not found."
    if status == 429:
        return CATEGORY_THROTTLED, "HTTP 429: request was throttled by the Snowflake SQL API."
    if status >= 500:
        return CATEGORY_SERVER_ERROR, f"HTTP {status}: Snowflake SQL API returned a server error."
    return CATEGORY_SERVER_ERROR, f"HTTP {status}: unexpected Snowflake SQL API response."


def _classify_transport_exception(exc: Exception) -> tuple[str, str]:
    import ssl

    if isinstance(exc, ssl.SSLError):
        return CATEGORY_TLS_ERROR, "TLS certificate verification failed."
    if isinstance(exc, httpx.ConnectTimeout):
        return CATEGORY_TIMEOUT, "The request to the Snowflake SQL API timed out connecting."
    if isinstance(exc, httpx.ReadTimeout):
        return CATEGORY_TIMEOUT, "The request to the Snowflake SQL API timed out waiting for a response."
    if isinstance(exc, httpx.TimeoutException):
        return CATEGORY_TIMEOUT, "The request to the Snowflake SQL API timed out."
    if isinstance(exc, httpx.ConnectError):
        cause = str(exc).lower()
        if "certificate" in cause or "ssl" in cause or "tls" in cause:
            return CATEGORY_TLS_ERROR, "TLS certificate verification failed."
        if "name or service not known" in cause or "nodename nor servname" in cause or "getaddrinfo failed" in cause:
            return CATEGORY_CONNECTION_ERROR, "Could not resolve the Snowflake account hostname (DNS failure) — check the account identifier."
        return CATEGORY_CONNECTION_ERROR, "Could not connect to the Snowflake SQL API."
    if isinstance(exc, httpx.RequestError):
        return CATEGORY_CONNECTION_ERROR, "Could not connect to the Snowflake SQL API."
    return CATEGORY_MALFORMED_RESPONSE, "Snowflake returned a response that could not be processed."


def _retry_after_seconds(resp: httpx.Response) -> Optional[float]:
    raw = resp.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _throttle_backoff_seconds(attempt: int, *, retry_after: Optional[float]) -> float:
    """Bounded exponential backoff with jitter for a 429 retry attempt
    (0-indexed). Honors Retry-After when present and within bounds."""
    import random

    if retry_after is not None:
        return min(retry_after, _THROTTLE_MAX_DELAY_SECONDS)
    base = min(_THROTTLE_BASE_DELAY_SECONDS * (2 ** attempt), _THROTTLE_MAX_DELAY_SECONDS)
    jitter = random.uniform(0, base * 0.25)
    return min(base + jitter, _THROTTLE_MAX_DELAY_SECONDS)


def _server_error_backoff_seconds(attempt: int) -> float:
    return _SERVER_ERROR_BASE_DELAY_SECONDS * (2 ** attempt)


def _raise_for_outcome(outcome: CallOutcome, *, context: str) -> Any:
    """Raise the appropriate connector exception for a failed ``CallOutcome``,
    or return ``outcome.rows`` (the parsed row list) on success. Never
    includes credential material in the raised message — only the fixed,
    safe ``detail`` string set by ``_classify_response``/
    ``_classify_transport_exception``."""
    if outcome.ok:
        return outcome.rows
    if outcome.category == CATEGORY_AUTH_FAILED:
        raise AuthenticationError(f"snowflake: {outcome.detail} ({context})", status_code=401)
    if outcome.category == CATEGORY_PERMISSION_DENIED:
        raise AuthenticationError(f"snowflake: {outcome.detail} ({context})", status_code=403)
    if outcome.category == CATEGORY_THROTTLED:
        raise RateLimitError(f"snowflake: {outcome.detail} ({context})")
    if outcome.category in (CATEGORY_CONNECTION_ERROR, CATEGORY_TIMEOUT, CATEGORY_TLS_ERROR):
        raise NetworkError(f"snowflake: {outcome.detail} ({context})")
    raise ConnectorError(f"snowflake: {outcome.detail} ({context})")


def call_sql_api(
    client: httpx.Client,
    statement: str,
    *,
    role: str,
    _sleep_fn: Callable[[float], None] = None,
) -> CallOutcome:
    """Fail-soft wrapper around one Snowflake SQL API statement execution.

    Every read-only metadata query this connector issues routes through
    this wrapper so callers get the same distinguishable failure
    categories instead of an uncaught exception.

    401/403/404 are NEVER retried as if transient. 429 gets a bounded
    retry with exponential backoff and jitter (honoring ``Retry-After``
    when present), capped at ``_MAX_THROTTLE_RETRIES`` attempts. Transient
    5xx responses get a smaller bounded retry (``_MAX_SERVER_ERROR_RETRIES``).
    A 202 (async, statement still executing) is polled up to
    ``_MAX_POLL_ATTEMPTS`` times — every query this connector issues is a
    tiny metadata lookup, so this path is not expected to trigger in
    practice, but is handled correctly per the SQL API's documented
    asynchronous contract rather than assumed away.

    SECURITY: never includes the Authorization header or token value in
    any returned ``CallOutcome.detail`` — only a fixed, category-specific
    message plus the HTTP status code.
    """
    sleep_fn = _sleep_fn or __import__("time").sleep
    body = {
        "statement": statement,
        "timeout": _STATEMENT_TIMEOUT_SECONDS,
        "role": role,
    }

    throttle_attempt = 0
    server_error_attempt = 0
    while True:
        try:
            resp = client.post(f"/api/{_SQL_API_VERSION}/statements", json=body, timeout=_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — deliberately broad; classified below
            category, detail = _classify_transport_exception(exc)
            return CallOutcome(ok=False, category=category, detail=detail)

        if resp.status_code == 202:
            handle = _extract_statement_handle(resp)
            if handle is None:
                return CallOutcome(ok=False, category=CATEGORY_MALFORMED_RESPONSE, detail="Snowflake returned an async response with no statement handle.")
            polled = _poll_statement(client, handle, _sleep_fn=sleep_fn)
            return polled

        if resp.status_code < 300:
            return _parse_success(resp)

        category, detail = _classify_response(resp)
        if category == CATEGORY_THROTTLED and throttle_attempt < _MAX_THROTTLE_RETRIES:
            retry_after = _retry_after_seconds(resp)
            delay = _throttle_backoff_seconds(throttle_attempt, retry_after=retry_after)
            logger.warning(
                "snowflake_connector rate limited (attempt %d/%d); sleeping %.1fs",
                throttle_attempt + 1, _MAX_THROTTLE_RETRIES, delay,
            )
            sleep_fn(delay)
            throttle_attempt += 1
            continue
        if category == CATEGORY_SERVER_ERROR and server_error_attempt < _MAX_SERVER_ERROR_RETRIES:
            delay = _server_error_backoff_seconds(server_error_attempt)
            logger.warning(
                "snowflake_connector transient server error (attempt %d/%d); sleeping %.1fs",
                server_error_attempt + 1, _MAX_SERVER_ERROR_RETRIES, delay,
            )
            sleep_fn(delay)
            server_error_attempt += 1
            continue

        return CallOutcome(ok=False, category=category, detail=detail)


def _extract_statement_handle(resp: httpx.Response) -> Optional[str]:
    try:
        data = resp.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    handle = data.get("statementHandle")
    return handle if isinstance(handle, str) and handle.strip() else None


def _poll_statement(
    client: httpx.Client, handle: str, *, _sleep_fn: Callable[[float], None],
) -> CallOutcome:
    for _attempt in range(_MAX_POLL_ATTEMPTS):
        _sleep_fn(_POLL_INTERVAL_SECONDS)
        try:
            resp = client.get(f"/api/{_SQL_API_VERSION}/statements/{handle}", timeout=_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            category, detail = _classify_transport_exception(exc)
            return CallOutcome(ok=False, category=category, detail=detail)
        if resp.status_code == 202:
            continue
        if resp.status_code < 300:
            return _parse_success(resp)
        category, detail = _classify_response(resp)
        return CallOutcome(ok=False, category=category, detail=detail)
    return CallOutcome(ok=False, category=CATEGORY_TIMEOUT, detail="The Snowflake statement did not complete within the polling window.")


def _parse_success(resp: httpx.Response) -> CallOutcome:
    try:
        data = resp.json()
    except ValueError:
        return CallOutcome(ok=False, category=CATEGORY_MALFORMED_RESPONSE, detail="Snowflake returned a response that was not valid JSON.")
    if not isinstance(data, dict):
        return CallOutcome(ok=False, category=CATEGORY_MALFORMED_RESPONSE, detail="Snowflake returned an unexpected response shape.")
    rows = data.get("data")
    if not isinstance(rows, list):
        return CallOutcome(ok=False, category=CATEGORY_MALFORMED_RESPONSE, detail="Snowflake returned a response with no result rows.")
    columns = _extract_column_names(data)
    return CallOutcome(ok=True, rows=rows, columns=columns, category=CATEGORY_SUCCESS)


def _extract_column_names(body: dict) -> Optional[list[str]]:
    """Extract column names (in row order) from the SQL API's
    ``resultSetMetaData.rowType`` array, used to map SHOW-command rows by
    column name rather than by hardcoded position — SHOW USERS alone
    returns ~30 columns, and guessing positions would be exactly the kind
    of unverified assumption this connector avoids. Returns ``None`` (never
    an empty-but-wrong list) if the metadata is absent or malformed."""
    meta = body.get("resultSetMetaData")
    if not isinstance(meta, dict):
        return None
    row_type = meta.get("rowType")
    if not isinstance(row_type, list):
        return None
    names: list[str] = []
    for col in row_type:
        if isinstance(col, dict) and isinstance(col.get("name"), str):
            names.append(col["name"])
        else:
            names.append("")
    return names


def _rows_as_dicts(columns: Optional[list[str]], rows: Any) -> list[dict[str, Any]]:
    """Zip SQL API rows with their column names into dicts keyed by
    UPPERCASE column name. Rows that can't be matched to a column list
    (metadata missing) are dropped rather than guessed at."""
    if not columns or not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, list):
            continue
        d: dict[str, Any] = {}
        for i, col in enumerate(columns):
            if not col:
                continue
            d[col.upper()] = row[i] if i < len(row) else None
        out.append(d)
    return out


# Snowflake unquoted-identifier characters are letters/digits/underscore/
# dollar; a quoted identifier can contain almost anything, escaped by
# doubling embedded double-quotes. SHOW's own grammar requires the target
# object name as an identifier (not a bind-parameterizable string
# literal), so database/role names returned by Snowflake itself must be
# safely re-quoted before being composed into a follow-up SHOW statement.
# Double-quoting + escaping guarantees the value can never break out of
# the identifier position into a new SQL clause.
def _quote_identifier(name: str) -> str:
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


def _safe_int(raw_value: object) -> Optional[int]:
    """Best-effort int coercion for a SHOW-command count column. Returns
    ``None`` (never ``0``) for anything that isn't cleanly an integer —
    a missing/filtered count must never be mistaken for a real zero."""
    if isinstance(raw_value, bool):
        return None
    if isinstance(raw_value, int):
        return raw_value
    if isinstance(raw_value, str) and raw_value.strip().lstrip("-").isdigit():
        return int(raw_value.strip())
    return None


def _family_status_for_outcome(outcome: "CallOutcome") -> str:
    """Map a failed message-2 collection ``CallOutcome`` to a family
    completeness status. Reuses the same ``FAMILY_*`` taxonomy as the
    message-1 ``family_completeness`` field."""
    if outcome.category == CATEGORY_PERMISSION_DENIED:
        return FAMILY_DENIED
    return FAMILY_UNAVAILABLE


class SnowflakeConnector(BaseConnector):
    """Read-only Snowflake account connector (Snowflake message 1 of 8).

    Stateless: credentials are supplied per call, never cached across
    ``SnowflakeConnector`` instances. See the module docstring for the
    full authentication, transport, and sensitive-data-boundary rationale.
    """

    @staticmethod
    def _credentials(credentials: dict) -> tuple[str, str, str, str]:
        """Validate and return (account_identifier, username, token, role).

        Raises ``SnowflakeCredentialError`` (a ``ValueError`` subclass —
        see ``snowflake_schema.py``) for a malformed account_identifier/
        username/role, or ``AuthenticationError`` if the token is absent.
        """
        account_identifier = validate_account_identifier(credentials.get("account_identifier"))
        username = validate_username(credentials.get("username"))
        role = validate_role(credentials.get("role"))

        token = credentials.get("programmatic_access_token")
        if not isinstance(token, str) or not token.strip():
            raise AuthenticationError(
                "snowflake: credentials must contain a non-empty 'programmatic_access_token'"
            )
        return account_identifier, username, token, role

    @staticmethod
    def _make_client(account_identifier: str, token: str) -> httpx.Client:
        """Build an ``httpx.Client`` scoped to exactly one Snowflake
        account's fixed, trusted hostname.

        SECURITY: the token is placed in the Authorization header only,
        never logged, never included in any exception text. The base URL
        is derived entirely from the validated ``account_identifier`` —
        never from arbitrary user input — so this connector can never be
        pointed at an untrusted host.
        """
        base_url = f"https://{account_identifier}.snowflakecomputing.com"
        return httpx.Client(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {token}",
                "X-Snowflake-Authorization-Token-Type": "PROGRAMMATIC_ACCESS_TOKEN",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "ConfigTrace/1.0",
            },
            timeout=_TIMEOUT,
        )

    @staticmethod
    def compute_account_id(organization_name: Optional[str], account_name: Optional[str]) -> Optional[str]:
        """Return a stable account identifier derived from the immutable
        (organization_name, account_name) pair returned by Snowflake
        itself — never from the user-supplied ``account_identifier``
        credential or any display label, so credential rotation and
        account renames (of the *identifier* string, if one were ever
        reused) never change identity as long as the underlying
        organization/account pair is unchanged.

        Returns ``None`` if either value is missing/malformed — callers
        must treat that as "identity could not be established", never
        silently coerce a partial identity.
        """
        if not isinstance(organization_name, str) or not organization_name.strip():
            return None
        if not isinstance(account_name, str) or not account_name.strip():
            return None
        return f"id:{organization_name.strip().lower()}-{account_name.strip().lower()}"

    # ── Record normalizers ───────────────────────────────────────────────────

    @staticmethod
    def _normalize_account(
        account_id: str,
        *,
        organization_name: Optional[str],
        account_name: Optional[str],
        account_locator: Optional[str],
        session_role: Optional[str],
        account_identifier_credential: str,
        family_completeness: Optional[dict] = None,
    ) -> dict:
        """Normalize the Snowflake account identity record.

        SECURITY: only safe, flat scalar fields are extracted here — never
        the raw SQL API response row, never any credential material.
        """
        return {
            "record_type": SNOWFLAKE_ACCOUNT,
            "record_id": account_id,
            "provider_resource_id": f"account/{account_id}",
            "account_id": account_id,
            "organization_name": (
                organization_name.strip()[:_MAX_STR_LEN]
                if isinstance(organization_name, str) and organization_name.strip()
                else None
            ),
            "account_name": (
                account_name.strip()[:_MAX_STR_LEN]
                if isinstance(account_name, str) and account_name.strip()
                else None
            ),
            "account_locator": (
                account_locator.strip()[:_MAX_STR_LEN]
                if isinstance(account_locator, str) and account_locator.strip()
                else None
            ),
            "monitoring_role": (
                session_role.strip()[:_MAX_STR_LEN]
                if isinstance(session_role, str) and session_role.strip()
                else None
            ),
            "account_identifier": account_identifier_credential,
            "family_completeness": family_completeness or {},
        }

    @staticmethod
    def _normalize_capability(account_id: str, family: str, status: str) -> dict:
        return {
            "record_type": SNOWFLAKE_API_CAPABILITY,
            "record_id": f"{account_id}/capability/{family}",
            "provider_resource_id": f"capability/{family}",
            "account_id": account_id,
            "family": family,
            "status": status,
        }

    # ── Message 2: identity/role normalizers ─────────────────────────────────

    @staticmethod
    def _normalize_user(account_id: str, row: dict) -> Optional[dict]:
        """Normalize one SHOW USERS row. Returns ``None`` for a row with no
        usable name (never fabricates a record for an unidentifiable row).

        SECURITY: only the allowlisted safe fields below are copied out of
        the row — password/RSA-key/PAT *contents*, email, phone, and
        arbitrary comment text are never read from this row at all.
        """
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        user_name = name.strip()[:_MAX_STR_LEN]
        default_role = row.get("DEFAULT_ROLE")
        return {
            "record_type": SNOWFLAKE_USER,
            "record_id": f"{account_id}/user/{user_name.lower()}",
            "provider_resource_id": f"user/{user_name}",
            "account_id": account_id,
            "user_name": user_name,
            "user_type": categorize_user_type(row.get("TYPE")),
            "disabled": categorize_disabled(row.get("DISABLED")),
            "default_role": (
                default_role.strip()[:_MAX_STR_LEN]
                if isinstance(default_role, str) and default_role.strip()
                else None
            ),
            "default_secondary_roles": categorize_secondary_roles(row.get("DEFAULT_SECONDARY_ROLES")),
            "rsa_key_configured": categorize_tristate_bool(row.get("HAS_RSA_PUBLIC_KEY")),
            "password_configured": categorize_tristate_bool(row.get("HAS_PASSWORD")),
            "programmatic_access_token_configured": categorize_tristate_bool(row.get("HAS_PAT")),
            "owner": (
                row["OWNER"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("OWNER"), str) and row["OWNER"].strip()
                else None
            ),
        }

    @staticmethod
    def _normalize_account_role(account_id: str, row: dict) -> Optional[dict]:
        """Normalize one SHOW ROLES row into a ``snowflake_account_role``
        record. PUBLIC is normalized like any other role (its existence is
        tracked) — only its automatic grantee relationships are excluded
        from enumeration (see ``_collect_grants``)."""
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        role_name = name.strip()[:_MAX_STR_LEN]
        return {
            "record_type": SNOWFLAKE_ACCOUNT_ROLE,
            "record_id": f"{account_id}/account_role/{role_name.lower()}",
            "provider_resource_id": f"account_role/{role_name}",
            "account_id": account_id,
            "role_name": role_name,
            "role_category": categorize_account_role(role_name),
            "owner": (
                row["OWNER"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("OWNER"), str) and row["OWNER"].strip()
                else None
            ),
            "assigned_to_users_count": _safe_int(row.get("ASSIGNED_TO_USERS")),
            "granted_to_roles_count": _safe_int(row.get("GRANTED_TO_ROLES")),
            "granted_roles_count": _safe_int(row.get("GRANTED_ROLES")),
        }

    @staticmethod
    def _normalize_database_role(account_id: str, database_name: str, row: dict) -> Optional[dict]:
        """Normalize one SHOW DATABASE ROLES row. Stable identity is
        ``account + database + role name`` — the same role name in two
        different databases is a distinct object, never collapsed.

        SHOW DATABASE ROLES' full output-column table is not documented
        (confirmed via current docs) beyond the SHOW ROLES-like fields it
        is known to share, so multiple candidate column-name aliases are
        checked defensively rather than assuming a single name; anything
        not found is left as ``None``/unknown rather than guessed at.
        """
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        role_name = name.strip()[:_MAX_STR_LEN]
        granted_to_roles = row.get("GRANTED_TO_ROLES")
        if granted_to_roles is None:
            granted_to_roles = row.get("GRANTED_TO_DATABASE_ROLES")
        granted_roles = row.get("GRANTED_DATABASE_ROLES")
        if granted_roles is None:
            granted_roles = row.get("GRANTED_ROLES")
        return {
            "record_type": SNOWFLAKE_DATABASE_ROLE,
            "record_id": f"{account_id}/database_role/{database_name.lower()}.{role_name.lower()}",
            "provider_resource_id": f"database_role/{database_name}.{role_name}",
            "account_id": account_id,
            "database_name": database_name[:_MAX_STR_LEN],
            "role_name": role_name,
            "owner": (
                row["OWNER"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("OWNER"), str) and row["OWNER"].strip()
                else None
            ),
            "granted_to_roles_count": _safe_int(granted_to_roles),
            "granted_roles_count": _safe_int(granted_roles),
        }

    @staticmethod
    def _normalize_user_role_grant(
        account_id: str,
        *,
        user_name: str,
        role_name: str,
        role_type: str,
        default_role_match: bool,
        granted_by: Optional[str],
    ) -> dict:
        return {
            "record_type": SNOWFLAKE_USER_ROLE_GRANT,
            "record_id": f"{account_id}/user_role_grant/{user_name.lower()}/{role_name.lower()}",
            "provider_resource_id": f"user_role_grant/{user_name}/{role_name}",
            "account_id": account_id,
            "user_name": user_name[:_MAX_STR_LEN],
            "role_name": role_name[:_MAX_STR_LEN],
            "role_type": role_type,
            "default_role_match": default_role_match,
            "grant_option": GRANT_OPTION_UNKNOWN,
            "granted_by": (
                granted_by.strip()[:_MAX_STR_LEN]
                if isinstance(granted_by, str) and granted_by.strip()
                else None
            ),
        }

    @staticmethod
    def _normalize_role_hierarchy_grant(
        account_id: str,
        *,
        child_role_name: str,
        child_role_type: str,
        parent_role_name: str,
        parent_role_type: str,
        granted_by: Optional[str],
    ) -> dict:
        return {
            "record_type": SNOWFLAKE_ROLE_HIERARCHY_GRANT,
            "record_id": (
                f"{account_id}/role_hierarchy_grant/"
                f"{child_role_type}:{child_role_name.lower()}/{parent_role_type}:{parent_role_name.lower()}"
            ),
            "provider_resource_id": f"role_hierarchy_grant/{child_role_name}/{parent_role_name}",
            "account_id": account_id,
            "child_role_name": child_role_name[:_MAX_STR_LEN],
            "child_role_type": child_role_type,
            "parent_role_name": parent_role_name[:_MAX_STR_LEN],
            "parent_role_type": parent_role_type,
            "grant_option": GRANT_OPTION_UNKNOWN,
            "granted_by": (
                granted_by.strip()[:_MAX_STR_LEN]
                if isinstance(granted_by, str) and granted_by.strip()
                else None
            ),
        }

    # ── Message 2: identity/role collection ──────────────────────────────────

    @classmethod
    def _collect_users(cls, client: httpx.Client, account_id: str, *, role: str, _sleep_fn=None) -> tuple[list[dict], str, dict[str, str]]:
        """Returns (user records, family status, {user_name: default_role})."""
        outcome = call_sql_api(client, _USERS_STATEMENT, role=role, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            return [], _family_status_for_outcome(outcome), {}
        rows = _rows_as_dicts(outcome.columns, outcome.rows)
        seen: dict[str, dict] = {}
        default_roles: dict[str, str] = {}
        for row in rows:
            record = cls._normalize_user(account_id, row)
            if record is None:
                continue
            seen[record["record_id"]] = record
            if record["default_role"]:
                default_roles[record["user_name"]] = record["default_role"]
        return list(seen.values()), FAMILY_COMPLETE, default_roles

    @classmethod
    def _collect_account_roles(cls, client: httpx.Client, account_id: str, *, role: str, _sleep_fn=None) -> tuple[list[dict], str, list[str]]:
        """Returns (account role records, family status, non-PUBLIC role
        names to enumerate grants/hierarchy for)."""
        outcome = call_sql_api(client, _ACCOUNT_ROLES_STATEMENT, role=role, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            return [], _family_status_for_outcome(outcome), []
        rows = _rows_as_dicts(outcome.columns, outcome.rows)
        seen: dict[str, dict] = {}
        grantable_role_names: list[str] = []
        for row in rows:
            record = cls._normalize_account_role(account_id, row)
            if record is None:
                continue
            seen[record["record_id"]] = record
            if not is_public_role(record["role_name"]):
                grantable_role_names.append(record["role_name"])
        return list(seen.values()), FAMILY_COMPLETE, grantable_role_names

    @classmethod
    def _discover_database_names(cls, client: httpx.Client, *, role: str, _sleep_fn=None) -> tuple[list[str], str]:
        """SHOW DATABASES used ONLY to discover database names for database
        role enumeration — never normalized into a database inventory
        record (that is message 3's scope)."""
        outcome = call_sql_api(client, _DATABASE_NAMES_FOR_ROLE_DISCOVERY_STATEMENT, role=role, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            return [], _family_status_for_outcome(outcome)
        rows = _rows_as_dicts(outcome.columns, outcome.rows)
        names: list[str] = []
        for row in rows:
            name = row.get("NAME")
            if isinstance(name, str) and name.strip():
                names.append(name.strip())
        return names, FAMILY_COMPLETE

    @classmethod
    def _collect_database_roles(
        cls, client: httpx.Client, account_id: str, database_names: list[str], *, role: str, _sleep_fn=None,
    ) -> tuple[list[dict], str, list[tuple[str, str]]]:
        """Returns (database role records, family status, [(database, role_name), ...]
        non-PUBLIC pairs to enumerate grants/hierarchy for)."""
        if not database_names:
            return [], FAMILY_UNAVAILABLE, []
        seen: dict[str, dict] = {}
        pairs: list[tuple[str, str]] = []
        any_ok = False
        any_failed = False
        for db_name in database_names:
            outcome = call_sql_api(client, _database_roles_statement(db_name), role=role, _sleep_fn=_sleep_fn)
            if not outcome.ok:
                any_failed = True
                continue
            any_ok = True
            rows = _rows_as_dicts(outcome.columns, outcome.rows)
            for row in rows:
                record = cls._normalize_database_role(account_id, db_name, row)
                if record is None:
                    continue
                seen[record["record_id"]] = record
                if not is_public_role(record["role_name"]):
                    pairs.append((db_name, record["role_name"]))
        if any_ok and not any_failed:
            status = FAMILY_COMPLETE
        elif any_ok and any_failed:
            status = FAMILY_PARTIAL
        else:
            status = FAMILY_UNAVAILABLE
        return list(seen.values()), status, pairs

    @classmethod
    def _collect_grants(
        cls,
        client: httpx.Client,
        account_id: str,
        *,
        account_role_names: list[str],
        database_role_pairs: list[tuple[str, str]],
        default_roles_by_user: dict[str, str],
        role: str,
        _sleep_fn=None,
    ) -> tuple[list[dict], list[dict], str, str]:
        """Enumerate SHOW GRANTS OF ROLE / SHOW GRANTS OF DATABASE ROLE for
        every non-PUBLIC account/database role, classifying each returned
        row by its ``granted_to`` principal type into either a
        ``snowflake_user_role_grant`` (principal type USER) or a
        ``snowflake_role_hierarchy_grant`` (principal type ROLE/
        DATABASE_ROLE). Returns (user_role_grants, role_hierarchy_grants,
        user_grants_family_status, role_hierarchy_family_status)."""
        user_grants: dict[str, dict] = {}
        hierarchy_grants: dict[str, dict] = {}
        any_ok = False
        any_failed = False

        def _process_rows(rows: list[dict], child_name: str, child_type: str) -> None:
            for row in rows:
                grantee_name = row.get("GRANTEE_NAME")
                if not isinstance(grantee_name, str) or not grantee_name.strip():
                    continue
                principal_type = categorize_principal_type(row.get("GRANTED_TO"))
                granted_by = row.get("GRANTED_BY")
                if principal_type == PRINCIPAL_TYPE_USER:
                    user_name = grantee_name.strip()
                    grant = cls._normalize_user_role_grant(
                        account_id,
                        user_name=user_name,
                        role_name=child_name,
                        role_type=child_type,
                        default_role_match=default_roles_by_user.get(user_name) == child_name,
                        granted_by=granted_by,
                    )
                    user_grants[grant["record_id"]] = grant
                elif principal_type in (PRINCIPAL_TYPE_ACCOUNT_ROLE, PRINCIPAL_TYPE_DATABASE_ROLE):
                    grant = cls._normalize_role_hierarchy_grant(
                        account_id,
                        child_role_name=child_name,
                        child_role_type=child_type,
                        parent_role_name=grantee_name.strip(),
                        parent_role_type=principal_type,
                        granted_by=granted_by,
                    )
                    hierarchy_grants[grant["record_id"]] = grant
                # PRINCIPAL_TYPE_UNKNOWN rows (an unrecognized/future
                # granted_to value) are safely skipped rather than
                # misclassified — a new principal type must be explicitly
                # taught to this connector, never guessed.

        for role_name in account_role_names:
            outcome = call_sql_api(client, _grants_of_account_role_statement(role_name), role=role, _sleep_fn=_sleep_fn)
            if not outcome.ok:
                any_failed = True
                continue
            any_ok = True
            _process_rows(_rows_as_dicts(outcome.columns, outcome.rows), role_name, PRINCIPAL_TYPE_ACCOUNT_ROLE)

        for db_name, role_name in database_role_pairs:
            outcome = call_sql_api(client, _grants_of_database_role_statement(db_name, role_name), role=role, _sleep_fn=_sleep_fn)
            if not outcome.ok:
                any_failed = True
                continue
            any_ok = True
            _process_rows(_rows_as_dicts(outcome.columns, outcome.rows), role_name, PRINCIPAL_TYPE_DATABASE_ROLE)

        if not account_role_names and not database_role_pairs:
            status = FAMILY_UNAVAILABLE
        elif any_ok and not any_failed:
            status = FAMILY_COMPLETE
        elif any_ok and any_failed:
            status = FAMILY_PARTIAL
        else:
            status = FAMILY_UNAVAILABLE
        return list(user_grants.values()), list(hierarchy_grants.values()), status, status

    # ── Capability probes ────────────────────────────────────────────────────

    @staticmethod
    def _probe_one(client: httpx.Client, statement: str, *, role: str, _sleep_fn: Callable[[float], None] = None) -> str:
        """Return a CAPABILITY_* status string for one probe. Never
        raises — every failure mode maps to a status category instead."""
        outcome = call_sql_api(client, statement, role=role, _sleep_fn=_sleep_fn)
        if outcome.ok:
            return CAPABILITY_AVAILABLE
        if outcome.category == CATEGORY_PERMISSION_DENIED:
            return CAPABILITY_DENIED
        if outcome.category == CATEGORY_NOT_FOUND:
            return CAPABILITY_UNSUPPORTED
        if outcome.category == CATEGORY_THROTTLED:
            return CAPABILITY_THROTTLED
        if outcome.category == CATEGORY_AUTH_FAILED:
            # A 401 on a capability probe (after validate_credentials
            # already succeeded) is treated as unavailable, not raised —
            # a single family losing auth mid-probe-sweep should not abort
            # the whole foundation fetch.
            return CAPABILITY_UNAVAILABLE
        if outcome.category == CATEGORY_TIMEOUT:
            return CAPABILITY_TIMED_OUT
        if outcome.category in (CATEGORY_CONNECTION_ERROR, CATEGORY_TLS_ERROR):
            return CAPABILITY_UNAVAILABLE
        if outcome.category == CATEGORY_MALFORMED_RESPONSE:
            return CAPABILITY_MALFORMED
        return CAPABILITY_UNKNOWN

    @classmethod
    def _probe_capabilities(cls, client: httpx.Client, account_id: str, *, role: str, _sleep_fn: Callable[[float], None] = None) -> list[dict]:
        records = []
        for family, statement in _CAPABILITY_PROBES:
            status = cls._probe_one(client, statement, role=role, _sleep_fn=_sleep_fn)
            records.append(cls._normalize_capability(account_id, family, status))
        return records

    # ── Public connector interface ───────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Verify Snowflake credentials with a token acquisition-free,
        single lightweight account-identity query.

        Uses the fixed, narrow ``_ACCOUNT_IDENTITY_STATEMENT`` — the
        narrowest read-only query that simultaneously proves (a) the PAT
        is accepted and (b) the account is reachable, without requiring
        any broader read permission.

        Raises:
            AuthenticationError: Token rejected, invalid account
                identifier/username/role, or malformed credentials.
            ConnectorError: Snowflake returned an unexpected error.
            NetworkError: Transport-level failure.
        """
        account_identifier, _username, token, role = self._credentials(credentials)
        with self._make_client(account_identifier, token) as client:
            outcome = call_sql_api(client, _ACCOUNT_IDENTITY_STATEMENT, role=role)
            _raise_for_outcome(outcome, context="account identity query")
        return True

    def fetch(self, credentials: dict, *, _sleep_fn: Callable[[float], None] = None) -> list[dict]:
        """Fetch the Snowflake account identity, API capability inventory,
        and (Snowflake message 2) users/account roles/database roles/
        user-role grants/role-hierarchy edges.

        Does NOT collect databases/schemas/warehouses/shares/object grants,
        network/authentication policies, security integrations, effective
        privilege, or Security Findings yet — see the module docstring for
        the full roadmap and sensitive-data boundary.

        SECURITY: programmatic_access_token is used only within this
        method's scope, never logged, never persisted beyond the local
        ``httpx.Client`` instance's lifetime.

        Raises:
            AuthenticationError: Token rejected or malformed credentials.
            ConnectorError: Snowflake returned an unexpected error fetching
                the account identity itself (every other family fails soft
                into a family-completeness status instead of raising).
            NetworkError: Transport-level failure reaching the account.
        """
        account_identifier, _username, token, role = self._credentials(credentials)

        records: list[dict] = []
        with self._make_client(account_identifier, token) as client:
            outcome = call_sql_api(client, _ACCOUNT_IDENTITY_STATEMENT, role=role, _sleep_fn=_sleep_fn)
            rows = _raise_for_outcome(outcome, context="account identity query")

            if not isinstance(rows, list) or not rows or not isinstance(rows[0], list):
                raise ConnectorError("snowflake: account identity query returned no usable row")
            row = rows[0]
            # Column order matches _ACCOUNT_IDENTITY_STATEMENT's SELECT list.
            organization_name = row[0] if len(row) > 0 else None
            account_name = row[1] if len(row) > 1 else None
            account_locator = row[2] if len(row) > 2 else None
            session_role = row[3] if len(row) > 3 else None

            account_id = self.compute_account_id(organization_name, account_name)
            if account_id is None:
                raise ConnectorError(
                    "snowflake: could not establish a stable account identity — "
                    "CURRENT_ORGANIZATION_NAME()/CURRENT_ACCOUNT_NAME() returned no usable value"
                )

            capability_records = self._probe_capabilities(client, account_id, role=role, _sleep_fn=_sleep_fn)
            family_completeness = {
                r["family"]: (
                    "complete" if r["status"] == CAPABILITY_AVAILABLE else "unavailable"
                )
                for r in capability_records
            }

            # ── Message 2: users, account roles, database roles, grants,
            #    role hierarchy. Each family's completeness is tracked
            #    independently — one denied/unavailable family never
            #    erases another (same principle as the message-1 probes).
            user_records, users_status, default_roles_by_user = self._collect_users(
                client, account_id, role=role, _sleep_fn=_sleep_fn,
            )
            account_role_records, account_roles_status, grantable_account_role_names = self._collect_account_roles(
                client, account_id, role=role, _sleep_fn=_sleep_fn,
            )
            database_names, _db_discovery_status = self._discover_database_names(
                client, role=role, _sleep_fn=_sleep_fn,
            )
            database_role_records, database_roles_status, database_role_pairs = self._collect_database_roles(
                client, account_id, database_names, role=role, _sleep_fn=_sleep_fn,
            )
            user_role_grants, role_hierarchy_grants, user_grants_status, role_hierarchy_status = self._collect_grants(
                client,
                account_id,
                account_role_names=grantable_account_role_names,
                database_role_pairs=database_role_pairs,
                default_roles_by_user=default_roles_by_user,
                role=role,
                _sleep_fn=_sleep_fn,
            )

            family_completeness[COLLECTION_FAMILY_USERS] = users_status
            family_completeness[COLLECTION_FAMILY_ACCOUNT_ROLES] = account_roles_status
            family_completeness[COLLECTION_FAMILY_DATABASE_ROLES] = database_roles_status
            family_completeness[COLLECTION_FAMILY_USER_ROLE_GRANTS] = user_grants_status
            family_completeness[COLLECTION_FAMILY_ROLE_HIERARCHY] = role_hierarchy_status

            account_record = self._normalize_account(
                account_id,
                organization_name=organization_name,
                account_name=account_name,
                account_locator=account_locator,
                session_role=session_role,
                account_identifier_credential=account_identifier,
                family_completeness=family_completeness,
            )

            records.append(account_record)
            records.extend(capability_records)
            records.extend(user_records)
            records.extend(account_role_records)
            records.extend(database_role_records)
            records.extend(user_role_grants)
            records.extend(role_hierarchy_grants)

        # Deterministic ordering — API response ordering must never affect
        # the normalized snapshot or its fingerprint. Dedup is already
        # enforced per-family (keyed by stable record_id in each
        # ``_collect_*`` method), so this sort only needs to fix ordering.
        records.sort(key=lambda r: (r["record_type"], r["record_id"]))
        return records
