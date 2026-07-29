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
    COLLECTION_FAMILY_AUTHENTICATION_POLICIES,
    COLLECTION_FAMILY_DATABASE_ROLES,
    COLLECTION_FAMILY_DATABASES,
    COLLECTION_FAMILY_EXTERNAL_ACCESS_INTEGRATIONS,
    COLLECTION_FAMILY_FUTURE_GRANTS,
    COLLECTION_FAMILY_NETWORK_POLICIES,
    COLLECTION_FAMILY_NETWORK_RULES,
    COLLECTION_FAMILY_OBJECT_GRANTS,
    COLLECTION_FAMILY_ROLE_HIERARCHY,
    COLLECTION_FAMILY_SCHEMAS,
    COLLECTION_FAMILY_SECURITY_INTEGRATIONS,
    COLLECTION_FAMILY_SHARES,
    COLLECTION_FAMILY_STORAGE_INTEGRATIONS,
    COLLECTION_FAMILY_USER_ROLE_GRANTS,
    COLLECTION_FAMILY_USERS,
    COLLECTION_FAMILY_WAREHOUSES,
    DETAIL_COMPLETE,
    DETAIL_DENIED,
    DETAIL_UNAVAILABLE,
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    FAMILY_PARTIAL,
    FAMILY_UNAVAILABLE,
    GRANT_OPTION_UNKNOWN,
    OBJECT_TYPE_DATABASE,
    OBJECT_TYPE_SCHEMA,
    PRINCIPAL_TYPE_ACCOUNT_ROLE,
    PRINCIPAL_TYPE_DATABASE_ROLE,
    PRINCIPAL_TYPE_USER,
    SNOWFLAKE_ACCOUNT,
    SNOWFLAKE_ACCOUNT_ROLE,
    SNOWFLAKE_API_CAPABILITY,
    SNOWFLAKE_AUTHENTICATION_POLICY,
    SNOWFLAKE_DATABASE,
    SNOWFLAKE_DATABASE_ROLE,
    SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION,
    SNOWFLAKE_NETWORK_POLICY,
    SNOWFLAKE_NETWORK_RULE,
    SNOWFLAKE_OBJECT_GRANT,
    SNOWFLAKE_ROLE_HIERARCHY_GRANT,
    SNOWFLAKE_SCHEMA,
    SNOWFLAKE_SECURITY_INTEGRATION,
    SNOWFLAKE_SHARE,
    SNOWFLAKE_STORAGE_INTEGRATION,
    SNOWFLAKE_USER,
    SNOWFLAKE_USER_ROLE_GRANT,
    SNOWFLAKE_WAREHOUSE,
    categorize_account_role,
    categorize_auth_methods,
    categorize_broad_access,
    categorize_client_types,
    categorize_database_kind,
    categorize_disabled,
    categorize_grant_option,
    categorize_integration_type,
    categorize_managed_access,
    categorize_mfa_enrollment,
    categorize_object_type,
    categorize_principal_type,
    categorize_privilege,
    categorize_secondary_roles,
    categorize_share_kind,
    categorize_storage_provider,
    categorize_transient,
    categorize_tristate_bool,
    categorize_user_type,
    categorize_warehouse_state,
    is_public_role,
    is_role_hierarchy_row,
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

# Message 1/2 used this SOLELY to discover database names for database-role
# enumeration (``IN DATABASE <name>`` is mandatory — Snowflake does not
# offer an account-wide variant of SHOW DATABASE ROLES). Message 3 issues
# this SAME statement exactly once per fetch() and reuses its rows BOTH
# for that name-discovery purpose AND to normalize full
# ``snowflake_database`` inventory records — never a second, duplicate
# SHOW DATABASES call.
_DATABASE_NAMES_FOR_ROLE_DISCOVERY_STATEMENT = "SHOW DATABASES"

# ── Message 3: data-object collection statements ────────────────────────────
#
# Continues message 2's SHOW-over-ACCOUNT_USAGE bias for the same reasons
# (no warehouse requirement, zero reporting lag, current-state semantics,
# no historical-row retention to filter). Databases/warehouses/shares are
# each a single account-wide SHOW call; schemas require one SHOW SCHEMAS
# IN DATABASE call per database (bounded by database count, same shape as
# message 2's per-database SHOW DATABASE ROLES loop); object/future grants
# reuse the SAME account-role and database-role name lists message 2
# already discovered (via SHOW GRANTS TO ROLE / SHOW GRANTS TO DATABASE
# ROLE per role, and SHOW FUTURE GRANTS IN DATABASE per database) — never
# a second, redundant per-object enumeration.
_WAREHOUSES_STATEMENT = "SHOW WAREHOUSES"
_SHARES_STATEMENT = "SHOW SHARES"


def _database_roles_statement(database_name: str) -> str:
    return f"SHOW DATABASE ROLES IN DATABASE {_quote_identifier(database_name)}"


def _grants_of_account_role_statement(role_name: str) -> str:
    return f"SHOW GRANTS OF ROLE {_quote_identifier(role_name)}"


def _grants_of_database_role_statement(database_name: str, role_name: str) -> str:
    return f"SHOW GRANTS OF DATABASE ROLE {_quote_identifier(database_name)}.{_quote_identifier(role_name)}"


def _schemas_statement(database_name: str) -> str:
    return f"SHOW SCHEMAS IN DATABASE {_quote_identifier(database_name)}"


def _grants_to_account_role_statement(role_name: str) -> str:
    return f"SHOW GRANTS TO ROLE {_quote_identifier(role_name)}"


def _grants_to_database_role_statement(database_name: str, role_name: str) -> str:
    return f"SHOW GRANTS TO DATABASE ROLE {_quote_identifier(database_name)}.{_quote_identifier(role_name)}"


def _future_grants_in_database_statement(database_name: str) -> str:
    return f"SHOW FUTURE GRANTS IN DATABASE {_quote_identifier(database_name)}"


# ── Message 4: network/authentication policy + security/storage/external-
#    access integration collection statements ───────────────────────────────
#
# Continues the SHOW-over-ACCOUNT_USAGE bias. Each family's SHOW command is
# a single account-wide call; per-record DESCRIBE calls are bounded by
# object count (same shape as message 2/3's per-role loops), never a
# per-user or per-object-instance walk. Network-policy DESCRIBE calls are
# used ONLY to derive a boolean "allows anywhere" signal — the actual IP/
# CIDR list is discarded immediately after that check and never stored
# (task's IP/CIDR privacy boundary). Deferred this message (documented):
# API integrations (category=API — deployment/API-Gateway infrastructure,
# not central account security posture) and session policies (materially
# smaller security signal than network/authentication policies for the
# added SHOW + per-policy DESCRIBE cost).
_NETWORK_POLICIES_STATEMENT = "SHOW NETWORK POLICIES"
_NETWORK_RULES_STATEMENT = "SHOW NETWORK RULES"
_AUTHENTICATION_POLICIES_STATEMENT = "SHOW AUTHENTICATION POLICIES"
_SECURITY_INTEGRATIONS_STATEMENT = "SHOW SECURITY INTEGRATIONS"
_STORAGE_INTEGRATIONS_STATEMENT = "SHOW STORAGE INTEGRATIONS"
_EXTERNAL_ACCESS_INTEGRATIONS_STATEMENT = "SHOW EXTERNAL ACCESS INTEGRATIONS"


def _describe_network_policy_statement(policy_name: str) -> str:
    return f"DESCRIBE NETWORK POLICY {_quote_identifier(policy_name)}"


def _describe_authentication_policy_statement(policy_name: str) -> str:
    return f"DESCRIBE AUTHENTICATION POLICY {_quote_identifier(policy_name)}"


def _describe_integration_statement(integration_name: str) -> str:
    return f"DESCRIBE INTEGRATION {_quote_identifier(integration_name)}"


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


def _count_list_like(raw_value: object) -> Optional[int]:
    """Count entries in a DESCRIBE-property list-shaped value.

    Snowflake's SQL API returns every property value as a scalar string
    (list-typed properties like STORAGE_ALLOWED_LOCATIONS or
    ALLOWED_NETWORK_RULES render as a Python-repr-like bracketed,
    comma-separated string, e.g. ``"['a', 'b']"``) — never a native JSON
    list. This performs a bounded, defensive count (never a full parse or
    validation of the underlying entries) and returns ``None`` (never 0)
    for anything that isn't a parseable list-shaped string, so a missing/
    malformed property is never mistaken for an empty list."""
    if isinstance(raw_value, list):
        return len(raw_value)
    if not isinstance(raw_value, str):
        return None
    cleaned = raw_value.strip()
    if not cleaned:
        return None
    if cleaned.upper() in ("NONE", "NULL"):
        return 0
    inner = cleaned.strip("[]").strip()
    if not inner:
        return 0
    entries = [e.strip().strip("'\"") for e in inner.split(",")]
    entries = [e for e in entries if e]
    return len(entries)


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

    # ── Message 3: data-object normalizers ───────────────────────────────────

    @staticmethod
    def _normalize_database(account_id: str, row: dict) -> Optional[dict]:
        """Normalize one SHOW DATABASES row. Stable identity is account +
        database name — SHOW DATABASES exposes no stronger internal object
        ID, and no rename-tracking mechanism is documented, so a rename
        is modeled (conservatively) as a removal of the old name plus an
        addition of the new one, same as message 2's user/role identity."""
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        database_name = name.strip()[:_MAX_STR_LEN]
        return {
            "record_type": SNOWFLAKE_DATABASE,
            "record_id": f"{account_id}/database/{database_name.lower()}",
            "provider_resource_id": f"database/{database_name}",
            "account_id": account_id,
            "database_name": database_name,
            "database_kind": categorize_database_kind(row.get("KIND")),
            "owner": (
                row["OWNER"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("OWNER"), str) and row["OWNER"].strip()
                else None
            ),
            "transient": categorize_transient(row.get("OPTIONS")),
            "retention_time": _safe_int(row.get("RETENTION_TIME")),
            "origin": (
                row["ORIGIN"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("ORIGIN"), str) and row["ORIGIN"].strip()
                else None
            ),
        }

    @staticmethod
    def _normalize_schema(account_id: str, database_name: str, row: dict) -> Optional[dict]:
        """Normalize one SHOW SCHEMAS row. Stable identity is account +
        database + schema name."""
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        schema_name = name.strip()[:_MAX_STR_LEN]
        return {
            "record_type": SNOWFLAKE_SCHEMA,
            "record_id": f"{account_id}/schema/{database_name.lower()}.{schema_name.lower()}",
            "provider_resource_id": f"schema/{database_name}.{schema_name}",
            "account_id": account_id,
            "database_name": database_name[:_MAX_STR_LEN],
            "schema_name": schema_name,
            "owner": (
                row["OWNER"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("OWNER"), str) and row["OWNER"].strip()
                else None
            ),
            "managed_access": categorize_managed_access(row.get("OPTIONS")),
            "transient": categorize_transient(row.get("OPTIONS")),
            "retention_time": _safe_int(row.get("RETENTION_TIME")),
        }

    @staticmethod
    def _normalize_warehouse(account_id: str, row: dict) -> Optional[dict]:
        """Normalize one SHOW WAREHOUSES row. Cost/performance tuning
        fields (query acceleration, resource constraints, generation) are
        intentionally NOT collected — this connector tracks only the
        security-relevant posture fields (owner, state, auto_suspend/
        resume, scaling policy, resource monitor); warehouse cost controls
        are never turned into a security signal."""
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        warehouse_name = name.strip()[:_MAX_STR_LEN]
        return {
            "record_type": SNOWFLAKE_WAREHOUSE,
            "record_id": f"{account_id}/warehouse/{warehouse_name.lower()}",
            "provider_resource_id": f"warehouse/{warehouse_name}",
            "account_id": account_id,
            "warehouse_name": warehouse_name,
            "owner": (
                row["OWNER"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("OWNER"), str) and row["OWNER"].strip()
                else None
            ),
            "state": categorize_warehouse_state(row.get("STATE")),
            "size": (
                row["SIZE"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("SIZE"), str) and row["SIZE"].strip()
                else None
            ),
            "auto_suspend": _safe_int(row.get("AUTO_SUSPEND")),
            "auto_resume": categorize_tristate_bool(row.get("AUTO_RESUME")),
            "scaling_policy": (
                row["SCALING_POLICY"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("SCALING_POLICY"), str) and row["SCALING_POLICY"].strip()
                else None
            ),
            "min_cluster_count": _safe_int(row.get("MIN_CLUSTER_COUNT")),
            "max_cluster_count": _safe_int(row.get("MAX_CLUSTER_COUNT")),
            "resource_monitor": (
                row["RESOURCE_MONITOR"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("RESOURCE_MONITOR"), str) and row["RESOURCE_MONITOR"].strip()
                else None
            ),
        }

    @staticmethod
    def _normalize_share(account_id: str, row: dict) -> Optional[dict]:
        """Normalize one SHOW SHARES row.

        SECURITY: a share is Snowflake-to-Snowflake controlled secure
        sharing — its existence is never equated with "data is public".
        The ``to`` column is documented to display at most 3 consumer
        account identifiers even when more exist, so ``consumer_count`` is
        only ever the count of what SHOW actually returned, plus an
        explicit ``consumer_count_may_be_truncated`` flag rather than
        silently reporting a precise-looking but potentially wrong number.
        """
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        share_name = name.strip()[:_MAX_STR_LEN]
        raw_to = row.get("TO")
        consumers: list[str] = []
        if isinstance(raw_to, str) and raw_to.strip():
            consumers = [c.strip() for c in raw_to.split(",") if c.strip()]
        return {
            "record_type": SNOWFLAKE_SHARE,
            "record_id": f"{account_id}/share/{share_name.lower()}",
            "provider_resource_id": f"share/{share_name}",
            "account_id": account_id,
            "share_name": share_name,
            "share_kind": categorize_share_kind(row.get("KIND")),
            "owner": (
                row["OWNER"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("OWNER"), str) and row["OWNER"].strip()
                else None
            ),
            "database_name": (
                row["DATABASE_NAME"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("DATABASE_NAME"), str) and row["DATABASE_NAME"].strip()
                else None
            ),
            "consumer_count": len(consumers),
            "consumer_count_may_be_truncated": len(consumers) >= 3,
        }

    @staticmethod
    def _split_object_fqn(object_type: str, name: object) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Best-effort decomposition of a SHOW GRANTS ``name``/object
        identifier into (database, schema, object). Never attempted when
        the raw string contains a quote character — a quoted identifier
        can itself legally contain an embedded, unescaped-looking dot, so
        naive splitting on ``.`` would silently misparse it. In that case
        the full raw value is preserved as the object's FQN and the
        component fields are left ``None`` rather than guessed."""
        if not isinstance(name, str) or not name.strip():
            return None, None, None
        cleaned = name.strip()
        if '"' in cleaned:
            return None, None, None
        parts = cleaned.split(".")
        if object_type == OBJECT_TYPE_DATABASE and len(parts) == 1:
            return parts[0], None, None
        if object_type == OBJECT_TYPE_SCHEMA and len(parts) == 2:
            return parts[0], parts[1], None
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
        if len(parts) == 2:
            return parts[0], None, parts[1]
        if len(parts) == 1:
            # Account-scoped objects (warehouse, share, integration, ...)
            # are never namespaced under a database/schema.
            return None, None, parts[0]
        return None, None, None

    @classmethod
    def _normalize_object_grant(
        cls,
        account_id: str,
        row: dict,
        *,
        grantee_name: str,
        grantee_type: str,
        future_grant: bool,
    ) -> Optional[dict]:
        """Normalize one SHOW GRANTS TO ROLE / SHOW GRANTS TO DATABASE
        ROLE / SHOW FUTURE GRANTS row into a ``snowflake_object_grant``.

        Current-grant rows use ``granted_on``/``name``; future-grant rows
        use ``grant_on``/``name`` (confirmed via current official docs —
        future grants never have ``granted_to``/``grantee_name`` distinct
        from the role being enumerated, since SHOW FUTURE GRANTS is
        already scoped to one container, so ``grantee_name`` is passed in
        by the caller from context, not read off the row).
        """
        raw_privilege = row.get("PRIVILEGE")
        if not isinstance(raw_privilege, str) or not raw_privilege.strip():
            return None
        privilege = raw_privilege.strip().upper()[:_MAX_STR_LEN]
        raw_object_type_col = row.get("GRANT_ON") if future_grant else row.get("GRANTED_ON")
        object_type = categorize_object_type(raw_object_type_col)
        object_name_raw = row.get("NAME")
        database_name, schema_name, object_name = cls._split_object_fqn(object_type, object_name_raw)
        object_fqn = (
            object_name_raw.strip()[:_MAX_STR_LEN]
            if isinstance(object_name_raw, str) and object_name_raw.strip()
            else None
        )
        granted_by = row.get("GRANTED_BY")
        privilege_category = categorize_privilege(privilege)
        return {
            "record_type": SNOWFLAKE_OBJECT_GRANT,
            "record_id": (
                f"{account_id}/object_grant/{grantee_type}:{grantee_name.lower()}/"
                f"{privilege.lower()}/{object_type}/future={future_grant}/"
                f"{(object_fqn or '').lower()}"
            ),
            "provider_resource_id": f"object_grant/{grantee_name}/{privilege}/{object_fqn or object_type}",
            "account_id": account_id,
            "grantee_type": grantee_type,
            "grantee_name": grantee_name[:_MAX_STR_LEN],
            "privilege": privilege,
            "privilege_category": privilege_category,
            "object_type": object_type,
            "database_name": database_name[:_MAX_STR_LEN] if database_name else None,
            "schema_name": schema_name[:_MAX_STR_LEN] if schema_name else None,
            "object_name": object_name[:_MAX_STR_LEN] if object_name else None,
            "object_fqn": object_fqn,
            "grant_option": categorize_grant_option(row.get("GRANT_OPTION")),
            "granted_by": (
                granted_by.strip()[:_MAX_STR_LEN]
                if isinstance(granted_by, str) and granted_by.strip()
                else None
            ),
            "future_grant": future_grant,
            "ownership": privilege == "OWNERSHIP",
        }

    # ── Message 4: DESCRIBE property-row parsing ─────────────────────────────

    @staticmethod
    def _property_value_map(rows: list[dict]) -> dict[str, Any]:
        """Flatten a DESCRIBE-style property/value row list into a dict
        keyed by UPPERCASE property name. Handles both observed DESCRIBE
        row shapes (``PROPERTY``/``PROPERTY_VALUE`` for DESCRIBE
        INTEGRATION, or ``NAME``/``VALUE`` for DESCRIBE NETWORK POLICY /
        DESCRIBE AUTHENTICATION POLICY) rather than assuming a single
        fixed shape. Unrecognized row shapes are safely skipped."""
        out: dict[str, Any] = {}
        for row in rows:
            key = row.get("PROPERTY") if "PROPERTY" in row else row.get("NAME")
            value = row.get("PROPERTY_VALUE") if "PROPERTY_VALUE" in row else row.get("VALUE")
            if isinstance(key, str) and key.strip():
                out[key.strip().upper()] = value
        return out

    @staticmethod
    def _contains_anywhere_sentinel(raw_value: object) -> Optional[bool]:
        """Check a DESCRIBE NETWORK POLICY IP-list value for the literal
        IPv4/IPv6 "anywhere" sentinels. Returns ``None`` (unknown) if the
        value itself is missing/malformed — never coerced to False. The
        raw value is NEVER stored anywhere; only this boolean check's
        result is retained by the caller."""
        if not isinstance(raw_value, str):
            return None
        return "0.0.0.0/0" in raw_value or "::/0" in raw_value

    # ── Message 4: network/authentication policy normalizers ────────────────

    @staticmethod
    def _normalize_network_policy(
        account_id: str,
        row: dict,
        *,
        allows_anywhere_ipv4: Optional[bool] = None,
        allows_anywhere_ipv6: Optional[bool] = None,
        detail_collection_status: str = DETAIL_UNAVAILABLE,
    ) -> Optional[dict]:
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        policy_name = name.strip()[:_MAX_STR_LEN]
        allowed_ip_count = _safe_int(row.get("ENTRIES_IN_ALLOWED_IP_LIST"))
        blocked_ip_count = _safe_int(row.get("ENTRIES_IN_BLOCKED_IP_LIST"))
        allowed_rule_count = _safe_int(row.get("ENTRIES_IN_ALLOWED_NETWORK_RULES"))
        blocked_rule_count = _safe_int(row.get("ENTRIES_IN_BLOCKED_NETWORK_RULES"))
        return {
            "record_type": SNOWFLAKE_NETWORK_POLICY,
            "record_id": f"{account_id}/network_policy/{policy_name.lower()}",
            "provider_resource_id": f"network_policy/{policy_name}",
            "account_id": account_id,
            "policy_name": policy_name,
            "owner": (
                row["OWNER"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("OWNER"), str) and row["OWNER"].strip()
                else None
            ),
            "allowed_ipv4_count": allowed_ip_count,
            "blocked_ipv4_count": blocked_ip_count,
            "allowed_network_rule_count": allowed_rule_count,
            "blocked_network_rule_count": blocked_rule_count,
            "has_allowlist": bool(allowed_ip_count or allowed_rule_count) if (allowed_ip_count is not None or allowed_rule_count is not None) else None,
            "has_blocklist": bool(blocked_ip_count or blocked_rule_count) if (blocked_ip_count is not None or blocked_rule_count is not None) else None,
            # Derived from a bounded per-policy DESCRIBE NETWORK POLICY —
            # the raw IP list itself is NEVER stored; only this boolean
            # check's result. Unknown (never coerced to false) when the
            # DESCRIBE call was not attempted or failed.
            "allows_anywhere_ipv4": categorize_broad_access(allows_anywhere_ipv4),
            "allows_anywhere_ipv6": categorize_broad_access(allows_anywhere_ipv6),
            "detail_collection_status": detail_collection_status,
        }

    @staticmethod
    def _normalize_network_rule(account_id: str, row: dict) -> Optional[dict]:
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        rule_name = name.strip()[:_MAX_STR_LEN]
        database_name = row.get("DATABASE_NAME")
        schema_name = row.get("SCHEMA_NAME")
        return {
            "record_type": SNOWFLAKE_NETWORK_RULE,
            "record_id": f"{account_id}/network_rule/{rule_name.lower()}",
            "provider_resource_id": f"network_rule/{rule_name}",
            "account_id": account_id,
            "rule_name": rule_name,
            "database_name": (
                database_name.strip()[:_MAX_STR_LEN]
                if isinstance(database_name, str) and database_name.strip()
                else None
            ),
            "schema_name": (
                schema_name.strip()[:_MAX_STR_LEN]
                if isinstance(schema_name, str) and schema_name.strip()
                else None
            ),
            "owner": (
                row["OWNER"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("OWNER"), str) and row["OWNER"].strip()
                else None
            ),
            "rule_type": (
                row["TYPE"].strip().upper()[:_MAX_STR_LEN]
                if isinstance(row.get("TYPE"), str) and row["TYPE"].strip()
                else None
            ),
            "rule_mode": (
                row["MODE"].strip().upper()[:_MAX_STR_LEN]
                if isinstance(row.get("MODE"), str) and row["MODE"].strip()
                else None
            ),
            "value_count": _safe_int(row.get("ENTRIES_IN_VALUELIST")),
        }

    @classmethod
    def _normalize_authentication_policy(cls, account_id: str, row: dict, *, properties: Optional[dict] = None) -> Optional[dict]:
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        policy_name = name.strip()[:_MAX_STR_LEN]
        props = properties or {}
        return {
            "record_type": SNOWFLAKE_AUTHENTICATION_POLICY,
            "record_id": f"{account_id}/authentication_policy/{policy_name.lower()}",
            "provider_resource_id": f"authentication_policy/{policy_name}",
            "account_id": account_id,
            "policy_name": policy_name,
            "owner": (
                row["OWNER"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("OWNER"), str) and row["OWNER"].strip()
                else None
            ),
            "set_on": (
                row["SET_ON"].strip().upper()[:_MAX_STR_LEN]
                if isinstance(row.get("SET_ON"), str) and row["SET_ON"].strip()
                else None
            ),
            "authentication_methods": categorize_auth_methods(props.get("AUTHENTICATION_METHODS")) if properties is not None else None,
            "mfa_enrollment": categorize_mfa_enrollment(props.get("MFA_ENROLLMENT")) if properties is not None else "unknown",
            "client_types": categorize_client_types(props.get("CLIENT_TYPES")) if properties is not None else "unknown",
            "detail_collection_status": DETAIL_COMPLETE if properties is not None else DETAIL_UNAVAILABLE,
        }

    @classmethod
    def _normalize_security_integration(cls, account_id: str, row: dict, *, properties: Optional[dict] = None) -> Optional[dict]:
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        integration_name = name.strip()[:_MAX_STR_LEN]
        integration_type = categorize_integration_type(row.get("TYPE"))
        props = properties or {}
        record = {
            "record_type": SNOWFLAKE_SECURITY_INTEGRATION,
            "record_id": f"{account_id}/security_integration/{integration_name.lower()}/{integration_type}",
            "provider_resource_id": f"security_integration/{integration_name}",
            "account_id": account_id,
            "integration_name": integration_name,
            "integration_type": integration_type,
            "enabled": categorize_tristate_bool(row.get("ENABLED")),
            "owner": (
                row["OWNER"].strip()[:_MAX_STR_LEN]
                if isinstance(row.get("OWNER"), str) and row["OWNER"].strip()
                else None
            ),
            "detail_collection_status": DETAIL_COMPLETE if properties is not None else DETAIL_UNAVAILABLE,
        }
        if properties is None:
            return record
        # Type-specific safe posture only — never certificate/secret bodies.
        if integration_type == "saml2":
            record["saml2_issuer_configured"] = categorize_tristate_bool(bool(props.get("SAML2_ISSUER")) or None)
            record["saml2_sso_url_configured"] = categorize_tristate_bool(bool(props.get("SAML2_SSO_URL")) or None)
            record["saml2_certificate_configured"] = categorize_tristate_bool(bool(props.get("SAML2_X509_CERT")) or None)
        elif integration_type in ("oauth_snowflake", "external_oauth"):
            record["oauth_client_category"] = (
                str(props.get("OAUTH_CLIENT_TYPE") or props.get("EXTERNAL_OAUTH_TYPE") or "")[:_MAX_STR_LEN] or None
            )
            record["oauth_issuer_configured"] = categorize_tristate_bool(bool(props.get("EXTERNAL_OAUTH_ISSUER")) or None)
        elif integration_type == "scim":
            run_as_role = props.get("SCIM_RUN_AS_ROLE") or props.get("RUN_AS_ROLE")
            record["scim_run_as_role"] = (
                str(run_as_role).strip()[:_MAX_STR_LEN] if isinstance(run_as_role, str) and run_as_role.strip() else None
            )
        return record

    @classmethod
    def _normalize_storage_integration(cls, account_id: str, row: dict, *, properties: Optional[dict] = None) -> Optional[dict]:
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        integration_name = name.strip()[:_MAX_STR_LEN]
        props = properties or {}
        allowed_locations = props.get("STORAGE_ALLOWED_LOCATIONS")
        blocked_locations = props.get("STORAGE_BLOCKED_LOCATIONS")
        return {
            "record_type": SNOWFLAKE_STORAGE_INTEGRATION,
            "record_id": f"{account_id}/storage_integration/{integration_name.lower()}",
            "provider_resource_id": f"storage_integration/{integration_name}",
            "account_id": account_id,
            "integration_name": integration_name,
            "enabled": categorize_tristate_bool(row.get("ENABLED")),
            "storage_provider": categorize_storage_provider(props.get("STORAGE_PROVIDER")) if properties is not None else "unknown",
            "allowed_location_count": _count_list_like(allowed_locations),
            "blocked_location_count": _count_list_like(blocked_locations),
            "cloud_identity_configured": categorize_tristate_bool(
                bool(props.get("STORAGE_AWS_IAM_USER_ARN") or props.get("AZURE_CONSENT_URL") or props.get("STORAGE_GCP_SERVICE_ACCOUNT")) or None
            ),
            "detail_collection_status": DETAIL_COMPLETE if properties is not None else DETAIL_UNAVAILABLE,
        }

    @classmethod
    def _normalize_external_access_integration(cls, account_id: str, row: dict, *, properties: Optional[dict] = None) -> Optional[dict]:
        name = row.get("NAME")
        if not isinstance(name, str) or not name.strip():
            return None
        integration_name = name.strip()[:_MAX_STR_LEN]
        props = properties or {}
        allowed_rules = props.get("ALLOWED_NETWORK_RULES")
        allowed_secrets = props.get("ALLOWED_AUTHENTICATION_SECRETS")
        allowed_api_auth = props.get("ALLOWED_API_AUTHENTICATION_INTEGRATIONS")
        return {
            "record_type": SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION,
            "record_id": f"{account_id}/external_access_integration/{integration_name.lower()}",
            "provider_resource_id": f"external_access_integration/{integration_name}",
            "account_id": account_id,
            "integration_name": integration_name,
            "enabled": categorize_tristate_bool(row.get("ENABLED")),
            "allowed_network_rule_count": _count_list_like(allowed_rules),
            "allowed_secret_count": _count_list_like(allowed_secrets),
            "allowed_api_authentication_integration_count": _count_list_like(allowed_api_auth),
            "detail_collection_status": DETAIL_COMPLETE if properties is not None else DETAIL_UNAVAILABLE,
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
    def _discover_database_names(
        cls, client: httpx.Client, *, role: str, _sleep_fn=None,
    ) -> tuple[list[str], str, list[dict]]:
        """Single SHOW DATABASES call, issued exactly once per fetch().

        Returns (database names, family status, raw row dicts). The name
        list feeds database-role enumeration (message 2) and the schema/
        future-grant per-database loops (message 3); the raw rows are
        separately normalized into ``snowflake_database`` records by the
        caller. Never queried twice in one fetch()."""
        outcome = call_sql_api(client, _DATABASE_NAMES_FOR_ROLE_DISCOVERY_STATEMENT, role=role, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            return [], _family_status_for_outcome(outcome), []
        rows = _rows_as_dicts(outcome.columns, outcome.rows)
        names: list[str] = []
        for row in rows:
            name = row.get("NAME")
            if isinstance(name, str) and name.strip():
                names.append(name.strip())
        return names, FAMILY_COMPLETE, rows

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

    # ── Message 3: data-object collection ────────────────────────────────────

    @classmethod
    def _collect_schemas(
        cls, client: httpx.Client, account_id: str, database_names: list[str], *, role: str, _sleep_fn=None,
    ) -> tuple[list[dict], str]:
        """One SHOW SCHEMAS IN DATABASE call per database. A single
        database's schema collection failing (denied/unavailable) never
        wipes out schemas already collected from other databases — same
        per-parent completeness shape as message 2's database-role
        collection."""
        if not database_names:
            return [], FAMILY_UNAVAILABLE
        seen: dict[str, dict] = {}
        any_ok = False
        any_failed = False
        for db_name in database_names:
            outcome = call_sql_api(client, _schemas_statement(db_name), role=role, _sleep_fn=_sleep_fn)
            if not outcome.ok:
                any_failed = True
                continue
            any_ok = True
            rows = _rows_as_dicts(outcome.columns, outcome.rows)
            for row in rows:
                record = cls._normalize_schema(account_id, db_name, row)
                if record is None:
                    continue
                seen[record["record_id"]] = record
        if any_ok and not any_failed:
            status = FAMILY_COMPLETE
        elif any_ok and any_failed:
            status = FAMILY_PARTIAL
        else:
            status = FAMILY_UNAVAILABLE
        return list(seen.values()), status

    @classmethod
    def _collect_warehouses(cls, client: httpx.Client, account_id: str, *, role: str, _sleep_fn=None) -> tuple[list[dict], str]:
        outcome = call_sql_api(client, _WAREHOUSES_STATEMENT, role=role, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            return [], _family_status_for_outcome(outcome)
        rows = _rows_as_dicts(outcome.columns, outcome.rows)
        seen: dict[str, dict] = {}
        for row in rows:
            record = cls._normalize_warehouse(account_id, row)
            if record is None:
                continue
            seen[record["record_id"]] = record
        return list(seen.values()), FAMILY_COMPLETE

    @classmethod
    def _collect_shares(cls, client: httpx.Client, account_id: str, *, role: str, _sleep_fn=None) -> tuple[list[dict], str]:
        outcome = call_sql_api(client, _SHARES_STATEMENT, role=role, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            return [], _family_status_for_outcome(outcome)
        rows = _rows_as_dicts(outcome.columns, outcome.rows)
        seen: dict[str, dict] = {}
        for row in rows:
            record = cls._normalize_share(account_id, row)
            if record is None:
                continue
            seen[record["record_id"]] = record
        return list(seen.values()), FAMILY_COMPLETE

    @classmethod
    def _collect_object_and_future_grants(
        cls,
        client: httpx.Client,
        account_id: str,
        *,
        account_role_names: list[str],
        database_role_pairs: list[tuple[str, str]],
        database_names: list[str],
        role: str,
        _sleep_fn=None,
    ) -> tuple[list[dict], str, str]:
        """Reuses the SAME account-role and database-role name lists
        message 2 already discovered (via SHOW GRANTS TO ROLE / SHOW
        GRANTS TO DATABASE ROLE per role) for current object grants, and
        the same database name list (via SHOW FUTURE GRANTS IN DATABASE
        per database) for future grants — never a second, redundant
        per-object enumeration, and never the same SHOW GRANTS query
        message 2 already issued (that was SHOW GRANTS OF ROLE; this is
        SHOW GRANTS TO ROLE — a different command, confirmed via current
        docs, answering "what does this role hold" rather than "where was
        this role granted").

        Rows whose ``granted_on``/``grant_on`` is ROLE or DATABASE_ROLE are
        role-hierarchy edges, not object grants — they are skipped here
        entirely (never re-normalized as a second, potentially
        conflicting, hierarchy source; message 2's SHOW GRANTS OF ROLE
        walk remains the sole hierarchy source).

        Returns (object_grant_records, object_grants_family_status,
        future_grants_family_status).
        """
        grants: dict[str, dict] = {}
        any_ok = False
        any_failed = False

        def _process_current_rows(rows: list[dict], grantee_name: str, grantee_type: str) -> None:
            for row in rows:
                if is_role_hierarchy_row(row.get("GRANTED_ON")):
                    continue
                record = cls._normalize_object_grant(
                    account_id, row, grantee_name=grantee_name, grantee_type=grantee_type, future_grant=False,
                )
                if record is None:
                    continue
                grants[record["record_id"]] = record

        for role_name in account_role_names:
            outcome = call_sql_api(client, _grants_to_account_role_statement(role_name), role=role, _sleep_fn=_sleep_fn)
            if not outcome.ok:
                any_failed = True
                continue
            any_ok = True
            _process_current_rows(_rows_as_dicts(outcome.columns, outcome.rows), role_name, PRINCIPAL_TYPE_ACCOUNT_ROLE)

        for db_name, role_name in database_role_pairs:
            outcome = call_sql_api(client, _grants_to_database_role_statement(db_name, role_name), role=role, _sleep_fn=_sleep_fn)
            if not outcome.ok:
                any_failed = True
                continue
            any_ok = True
            _process_current_rows(_rows_as_dicts(outcome.columns, outcome.rows), role_name, PRINCIPAL_TYPE_DATABASE_ROLE)

        if not account_role_names and not database_role_pairs:
            object_grants_status = FAMILY_UNAVAILABLE
        elif any_ok and not any_failed:
            object_grants_status = FAMILY_COMPLETE
        elif any_ok and any_failed:
            object_grants_status = FAMILY_PARTIAL
        else:
            object_grants_status = FAMILY_UNAVAILABLE

        future_any_ok = False
        future_any_failed = False
        for db_name in database_names:
            outcome = call_sql_api(client, _future_grants_in_database_statement(db_name), role=role, _sleep_fn=_sleep_fn)
            if not outcome.ok:
                future_any_failed = True
                continue
            future_any_ok = True
            rows = _rows_as_dicts(outcome.columns, outcome.rows)
            for row in rows:
                grantee_name = row.get("GRANTEE_NAME")
                if not isinstance(grantee_name, str) or not grantee_name.strip():
                    continue
                grantee_type = categorize_principal_type(row.get("GRANT_TO"))
                if grantee_type == PRINCIPAL_TYPE_USER:
                    # Future grants are documented as granted to roles
                    # (account or database), never directly to a user —
                    # an unexpected USER grantee is treated conservatively
                    # as unrecognized rather than silently accepted.
                    continue
                record = cls._normalize_object_grant(
                    account_id, row, grantee_name=grantee_name.strip(), grantee_type=grantee_type, future_grant=True,
                )
                if record is None:
                    continue
                grants[record["record_id"]] = record

        if not database_names:
            future_grants_status = FAMILY_UNAVAILABLE
        elif future_any_ok and not future_any_failed:
            future_grants_status = FAMILY_COMPLETE
        elif future_any_ok and future_any_failed:
            future_grants_status = FAMILY_PARTIAL
        else:
            future_grants_status = FAMILY_UNAVAILABLE

        return list(grants.values()), object_grants_status, future_grants_status

    # ── Message 4: network/authentication policy + integration collection ───

    @classmethod
    def _collect_network_policies(cls, client: httpx.Client, account_id: str, *, role: str, _sleep_fn=None) -> tuple[list[dict], str]:
        """SHOW NETWORK POLICIES (single account-wide call) followed by a
        bounded per-policy DESCRIBE NETWORK POLICY — used ONLY to derive
        the allows-anywhere booleans. The DESCRIBE response's raw IP list
        is discarded immediately after that check; a per-policy DESCRIBE
        failure never removes the policy's identity/count fields, only
        leaves ``detail_collection_status``/``allows_anywhere_*`` at their
        unknown/unavailable defaults."""
        outcome = call_sql_api(client, _NETWORK_POLICIES_STATEMENT, role=role, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            return [], _family_status_for_outcome(outcome)
        rows = _rows_as_dicts(outcome.columns, outcome.rows)
        records: dict[str, dict] = {}
        for row in rows:
            name = row.get("NAME")
            detail_outcome = None
            if isinstance(name, str) and name.strip():
                detail_outcome = call_sql_api(
                    client, _describe_network_policy_statement(name.strip()), role=role, _sleep_fn=_sleep_fn,
                )
            allows_v4 = allows_v6 = None
            detail_status = DETAIL_UNAVAILABLE
            if detail_outcome is not None:
                if detail_outcome.ok:
                    props = cls._property_value_map(_rows_as_dicts(detail_outcome.columns, detail_outcome.rows))
                    allows_v4 = cls._contains_anywhere_sentinel(props.get("ALLOWED_IP_LIST"))
                    allows_v6 = cls._contains_anywhere_sentinel(props.get("ALLOWED_IP_LIST"))
                    detail_status = DETAIL_COMPLETE
                elif detail_outcome.category == CATEGORY_PERMISSION_DENIED:
                    detail_status = DETAIL_DENIED
            record = cls._normalize_network_policy(
                account_id, row,
                allows_anywhere_ipv4=allows_v4, allows_anywhere_ipv6=allows_v6,
                detail_collection_status=detail_status,
            )
            if record is not None:
                records[record["record_id"]] = record
        return list(records.values()), FAMILY_COMPLETE

    @classmethod
    def _collect_network_rules(cls, client: httpx.Client, account_id: str, *, role: str, _sleep_fn=None) -> tuple[list[dict], str]:
        """SHOW NETWORK RULES already exposes type/mode/value-count — no
        per-rule DESCRIBE is needed to satisfy this record's safe-fields
        list."""
        outcome = call_sql_api(client, _NETWORK_RULES_STATEMENT, role=role, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            return [], _family_status_for_outcome(outcome)
        rows = _rows_as_dicts(outcome.columns, outcome.rows)
        records: dict[str, dict] = {}
        for row in rows:
            record = cls._normalize_network_rule(account_id, row)
            if record is not None:
                records[record["record_id"]] = record
        return list(records.values()), FAMILY_COMPLETE

    @classmethod
    def _collect_authentication_policies(cls, client: httpx.Client, account_id: str, *, role: str, _sleep_fn=None) -> tuple[list[dict], str]:
        outcome = call_sql_api(client, _AUTHENTICATION_POLICIES_STATEMENT, role=role, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            return [], _family_status_for_outcome(outcome)
        rows = _rows_as_dicts(outcome.columns, outcome.rows)
        records: dict[str, dict] = {}
        for row in rows:
            name = row.get("NAME")
            properties = None
            if isinstance(name, str) and name.strip():
                detail_outcome = call_sql_api(
                    client, _describe_authentication_policy_statement(name.strip()), role=role, _sleep_fn=_sleep_fn,
                )
                if detail_outcome.ok:
                    properties = cls._property_value_map(_rows_as_dicts(detail_outcome.columns, detail_outcome.rows))
            record = cls._normalize_authentication_policy(account_id, row, properties=properties)
            if record is not None:
                records[record["record_id"]] = record
        return list(records.values()), FAMILY_COMPLETE

    @classmethod
    def _collect_security_integrations(cls, client: httpx.Client, account_id: str, *, role: str, _sleep_fn=None) -> tuple[list[dict], str]:
        outcome = call_sql_api(client, _SECURITY_INTEGRATIONS_STATEMENT, role=role, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            return [], _family_status_for_outcome(outcome)
        rows = _rows_as_dicts(outcome.columns, outcome.rows)
        records: dict[str, dict] = {}
        for row in rows:
            name = row.get("NAME")
            properties = None
            if isinstance(name, str) and name.strip():
                detail_outcome = call_sql_api(
                    client, _describe_integration_statement(name.strip()), role=role, _sleep_fn=_sleep_fn,
                )
                if detail_outcome.ok:
                    properties = cls._property_value_map(_rows_as_dicts(detail_outcome.columns, detail_outcome.rows))
            record = cls._normalize_security_integration(account_id, row, properties=properties)
            if record is not None:
                records[record["record_id"]] = record
        return list(records.values()), FAMILY_COMPLETE

    @classmethod
    def _collect_storage_integrations(cls, client: httpx.Client, account_id: str, *, role: str, _sleep_fn=None) -> tuple[list[dict], str]:
        outcome = call_sql_api(client, _STORAGE_INTEGRATIONS_STATEMENT, role=role, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            return [], _family_status_for_outcome(outcome)
        rows = _rows_as_dicts(outcome.columns, outcome.rows)
        records: dict[str, dict] = {}
        for row in rows:
            name = row.get("NAME")
            properties = None
            if isinstance(name, str) and name.strip():
                detail_outcome = call_sql_api(
                    client, _describe_integration_statement(name.strip()), role=role, _sleep_fn=_sleep_fn,
                )
                if detail_outcome.ok:
                    properties = cls._property_value_map(_rows_as_dicts(detail_outcome.columns, detail_outcome.rows))
            record = cls._normalize_storage_integration(account_id, row, properties=properties)
            if record is not None:
                records[record["record_id"]] = record
        return list(records.values()), FAMILY_COMPLETE

    @classmethod
    def _collect_external_access_integrations(cls, client: httpx.Client, account_id: str, *, role: str, _sleep_fn=None) -> tuple[list[dict], str]:
        outcome = call_sql_api(client, _EXTERNAL_ACCESS_INTEGRATIONS_STATEMENT, role=role, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            return [], _family_status_for_outcome(outcome)
        rows = _rows_as_dicts(outcome.columns, outcome.rows)
        records: dict[str, dict] = {}
        for row in rows:
            name = row.get("NAME")
            properties = None
            if isinstance(name, str) and name.strip():
                detail_outcome = call_sql_api(
                    client, _describe_integration_statement(name.strip()), role=role, _sleep_fn=_sleep_fn,
                )
                if detail_outcome.ok:
                    properties = cls._property_value_map(_rows_as_dicts(detail_outcome.columns, detail_outcome.rows))
            record = cls._normalize_external_access_integration(account_id, row, properties=properties)
            if record is not None:
                records[record["record_id"]] = record
        return list(records.values()), FAMILY_COMPLETE

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
            # SHOW DATABASES is issued exactly ONCE per fetch() — its rows
            # feed database-role discovery (message 2), full database
            # inventory (message 3), and the schema/future-grant
            # per-database loops (message 3) below.
            database_names, db_discovery_status, database_rows = self._discover_database_names(
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

            # ── Message 3: databases, schemas, warehouses, shares, object/
            #    future grants.
            database_records: dict[str, dict] = {}
            for db_row in database_rows:
                db_record = self._normalize_database(account_id, db_row)
                if db_record is not None:
                    database_records[db_record["record_id"]] = db_record
            databases_status = db_discovery_status

            schema_records, schemas_status = self._collect_schemas(
                client, account_id, database_names, role=role, _sleep_fn=_sleep_fn,
            )
            warehouse_records, warehouses_status = self._collect_warehouses(
                client, account_id, role=role, _sleep_fn=_sleep_fn,
            )
            share_records, shares_status = self._collect_shares(
                client, account_id, role=role, _sleep_fn=_sleep_fn,
            )
            object_grant_records, object_grants_status, future_grants_status = self._collect_object_and_future_grants(
                client,
                account_id,
                account_role_names=grantable_account_role_names,
                database_role_pairs=database_role_pairs,
                database_names=database_names,
                role=role,
                _sleep_fn=_sleep_fn,
            )

            # ── Message 4: network/authentication policies + security/
            #    storage/external-access integrations.
            network_policy_records, network_policies_status = self._collect_network_policies(
                client, account_id, role=role, _sleep_fn=_sleep_fn,
            )
            network_rule_records, network_rules_status = self._collect_network_rules(
                client, account_id, role=role, _sleep_fn=_sleep_fn,
            )
            authentication_policy_records, authentication_policies_status = self._collect_authentication_policies(
                client, account_id, role=role, _sleep_fn=_sleep_fn,
            )
            security_integration_records, security_integrations_status = self._collect_security_integrations(
                client, account_id, role=role, _sleep_fn=_sleep_fn,
            )
            storage_integration_records, storage_integrations_status = self._collect_storage_integrations(
                client, account_id, role=role, _sleep_fn=_sleep_fn,
            )
            external_access_integration_records, external_access_integrations_status = self._collect_external_access_integrations(
                client, account_id, role=role, _sleep_fn=_sleep_fn,
            )

            family_completeness[COLLECTION_FAMILY_USERS] = users_status
            family_completeness[COLLECTION_FAMILY_ACCOUNT_ROLES] = account_roles_status
            family_completeness[COLLECTION_FAMILY_DATABASE_ROLES] = database_roles_status
            family_completeness[COLLECTION_FAMILY_USER_ROLE_GRANTS] = user_grants_status
            family_completeness[COLLECTION_FAMILY_ROLE_HIERARCHY] = role_hierarchy_status
            family_completeness[COLLECTION_FAMILY_DATABASES] = databases_status
            family_completeness[COLLECTION_FAMILY_SCHEMAS] = schemas_status
            family_completeness[COLLECTION_FAMILY_WAREHOUSES] = warehouses_status
            family_completeness[COLLECTION_FAMILY_SHARES] = shares_status
            family_completeness[COLLECTION_FAMILY_OBJECT_GRANTS] = object_grants_status
            family_completeness[COLLECTION_FAMILY_FUTURE_GRANTS] = future_grants_status
            family_completeness[COLLECTION_FAMILY_NETWORK_POLICIES] = network_policies_status
            family_completeness[COLLECTION_FAMILY_NETWORK_RULES] = network_rules_status
            family_completeness[COLLECTION_FAMILY_AUTHENTICATION_POLICIES] = authentication_policies_status
            family_completeness[COLLECTION_FAMILY_SECURITY_INTEGRATIONS] = security_integrations_status
            family_completeness[COLLECTION_FAMILY_STORAGE_INTEGRATIONS] = storage_integrations_status
            family_completeness[COLLECTION_FAMILY_EXTERNAL_ACCESS_INTEGRATIONS] = external_access_integrations_status

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
            records.extend(database_records.values())
            records.extend(schema_records)
            records.extend(warehouse_records)
            records.extend(share_records)
            records.extend(object_grant_records)
            records.extend(network_policy_records)
            records.extend(network_rule_records)
            records.extend(authentication_policy_records)
            records.extend(security_integration_records)
            records.extend(storage_integration_records)
            records.extend(external_access_integration_records)

        # Deterministic ordering — API response ordering must never affect
        # the normalized snapshot or its fingerprint. Dedup is already
        # enforced per-family (keyed by stable record_id in each
        # ``_collect_*`` method), so this sort only needs to fix ordering.
        records.sort(key=lambda r: (r["record_type"], r["record_id"]))
        return records
