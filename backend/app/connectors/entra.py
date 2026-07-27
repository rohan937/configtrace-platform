"""Microsoft Entra ID provider foundation connector (Entra message 1 of 8).

Establishes a secure, read-only connection to a Microsoft Entra ID tenant
using OAuth 2.0 client_credentials (app-only) authentication against the
Microsoft identity platform, resolves a stable tenant identity, and probes
(never collects) the future record families (users, groups, applications,
service principals, Conditional Access, authentication methods, directory
roles, OAuth2 permission grants) that later messages will build.

This connector intentionally does NOT collect users, groups, applications,
service principals, Conditional Access policies, authentication methods,
directory roles, or consent grants yet — see ``entra_schema.py``'s module
docstring for the full sensitive-data boundary. The connector is registered
internally (dispatch, schema, capability matrix) but is NOT publicly
connectable — it is excluded from the frontend's PROVIDER_IDS /
CONNECTABLE_PROVIDER_IDS until Entra message 8.

Microsoft Entra ID is distinct from this repository's existing ``azure``
provider (Azure cloud infrastructure — subscriptions, resource groups,
network security groups, Key Vaults, AKS clusters). The two providers are
never merged; this connector never imports from or writes ``azure_*``
record types.

Authentication
---------------
OAuth 2.0 client_credentials grant against the tenant-specific Microsoft
identity platform v2.0 token endpoint:

    POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
        grant_type=client_credentials
        client_id=<client_id>
        client_secret=<client_secret>
        scope=https://graph.microsoft.com/.default

Only app-only (application permission) client_credentials auth is
supported. Delegated/interactive/device-code/username-password flows, the
Azure CLI, and PowerShell are never used — ConfigTrace is a backend SaaS
connector with no interactive session.

Credentials dict:
    tenant_id      : str — Entra tenant GUID. Rejects "common"/
                     "organizations"/"consumers" and any non-GUID value —
                     a ConfigTrace integration targets exactly one tenant.
    client_id      : str — app registration (client) GUID.
    client_secret  : str — app registration client secret. NEVER logged,
                     NEVER stored outside the encrypted credentials column,
                     NEVER returned in any API response, NEVER copied into
                     a normalized record.

Certificate-based app authentication is a documented future enhancement —
NOT implemented here; a client secret is sufficient for this foundation
stage.

Cloud support
-------------
This connector targets the Microsoft commercial/global cloud only
(``login.microsoftonline.com`` / ``graph.microsoft.com``). GCC High, DoD,
and China (21Vianet) national clouds use different, hardcoded authority
and Graph hosts and are NOT supported — this is not silently claimed
anywhere in this module or its registration metadata.

SECURITY — what is NEVER stored, logged, or returned
------------------------------------------------------
- client_secret — NEVER stored on the connector instance beyond one
  in-memory token-cache lifetime, NEVER logged, NEVER included in error
  messages or exceptions, NEVER written to any record.
- access_token — held only in the connector instance's in-memory token
  cache for its own lifetime; NEVER logged, NEVER persisted to any
  snapshot/record/database column.
- Authorization header value / raw token endpoint response — NEVER appears
  in logs or exception text.
- Raw Microsoft Graph API response dicts — NEVER stored; only flat safe
  scalars.
- passwords, password hashes, recovery codes, authentication method
  secrets, private keys, certificates containing private key material,
  session/refresh token telemetry, arbitrary user profile data — NEVER
  fetched.
"""

from __future__ import annotations

import logging
import time as _time
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.connectors.base import BaseConnector
from app.connectors.entra_schema import (
    CAPABILITY_AVAILABLE,
    CAPABILITY_DENIED,
    CAPABILITY_FAMILY_APPLICATIONS,
    CAPABILITY_FAMILY_AUTHENTICATION_METHODS,
    CAPABILITY_FAMILY_CONDITIONAL_ACCESS,
    CAPABILITY_FAMILY_DIRECTORY_ROLES,
    CAPABILITY_FAMILY_GROUPS,
    CAPABILITY_FAMILY_OAUTH2_PERMISSION_GRANTS,
    CAPABILITY_FAMILY_SERVICE_PRINCIPALS,
    CAPABILITY_FAMILY_USERS,
    CAPABILITY_THROTTLED,
    CAPABILITY_UNAVAILABLE,
    CAPABILITY_UNKNOWN,
    CAPABILITY_UNSUPPORTED,
    ENTRA_API_CAPABILITY,
    ENTRA_APPLICATION,
    ENTRA_APPLICATION_GROUP_ASSIGNMENT,
    ENTRA_APPLICATION_USER_ASSIGNMENT,
    ENTRA_GROUP,
    ENTRA_GROUP_MEMBERSHIP,
    ENTRA_OAUTH2_PERMISSION_GRANT,
    ENTRA_ORGANIZATION,
    ENTRA_SERVICE_PRINCIPAL,
    ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT,
    ENTRA_USER,
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    FAMILY_PARTIAL,
    FAMILY_UNAVAILABLE,
    GRAPH_MEMBER_TYPE_USER,
    GRAPH_PRINCIPAL_TYPE_GROUP,
    GRAPH_PRINCIPAL_TYPE_SERVICE_PRINCIPAL,
    GRAPH_PRINCIPAL_TYPE_USER,
    MICROSOFT_FIRST_PARTY_TENANT_ID,
    MICROSOFT_GRAPH_APP_ID,
    categorize_account_enabled,
    categorize_app_owner_organization,
    categorize_consent_type,
    categorize_external_user_state,
    categorize_group_type,
    categorize_membership_count,
    categorize_nearest_credential_expiry,
    categorize_on_premises_sync,
    categorize_permission_risk,
    categorize_service_principal_type,
    categorize_sign_in_audience,
    categorize_user_type,
    categorize_verified_publisher,
    lifecycle_posture_for_user,
    normalize_group_types,
    normalize_scopes,
    summarize_application_redirects,
    summarize_required_resource_access,
    validate_client_id,
    validate_tenant_id,
)
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ─────────────────────────────────────────────────────

_TIMEOUT = 30.0
_MAX_STR_LEN = 100

# Fixed, trusted hosts — Microsoft commercial/global cloud only. Never
# overridable by credentials or any user-supplied value.
_TOKEN_HOST = "login.microsoftonline.com"
_GRAPH_ORIGIN = "https://graph.microsoft.com"
_GRAPH_BASE_URL = f"{_GRAPH_ORIGIN}/v1.0"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Pagination bounds (reused by later messages' list collection).
_MAX_PAGES = 50

# Graph list page size — a single, connector-owned constant (never
# user-controlled), applied via ``$top``.
_PAGE_SIZE = 999  # Graph's own max page size for /users and /groups

# ── Identity collection bounds (Entra message 2) ────────────────────────────
#
# Per-family caps bound pathological cases without imposing a flaky timing
# threshold. Membership enumeration is per-group (see
# ``_fetch_memberships()`` docstring for the call-complexity rationale), so
# it additionally needs a cap on the number of groups walked and a global
# cap on total membership records collected, to bound the worst case where
# many large groups exist. Mirrors Okta's identical bounding pattern.
_MAX_USERS = 20_000
_MAX_GROUPS = 5_000
_MAX_MEMBERS_PER_GROUP = 20_000
_MAX_GROUPS_FOR_MEMBERSHIP_ENUMERATION = 5_000
_MAX_TOTAL_MEMBERSHIPS = 200_000

# ── Application/service-principal collection bounds (Entra message 3) ──────
#
# App-role-assignment enumeration is per-resource-service-principal (see
# ``_fetch_app_role_assignments()`` docstring for the call-complexity
# rationale) — same bounding pattern as message 2's per-group membership
# walk. OAuth2 permission grants are tenant-wide (a single family, no
# per-parent walk needed).
_MAX_APPLICATIONS = 5_000
_MAX_SERVICE_PRINCIPALS = 10_000
_MAX_ASSIGNMENTS_PER_SP = 20_000
_MAX_SPS_FOR_ASSIGNMENT_ENUMERATION = 10_000
_MAX_TOTAL_APP_USER_ASSIGNMENTS = 200_000
_MAX_TOTAL_APP_GROUP_ASSIGNMENTS = 200_000
_MAX_TOTAL_SP_APP_ROLE_ASSIGNMENTS = 200_000
_MAX_OAUTH2_PERMISSION_GRANTS = 200_000

# 429/5xx retry bounds — bounded exponential backoff with jitter, mirroring
# the Okta/Kubernetes reliability pattern.
_MAX_THROTTLE_RETRIES = 4
_THROTTLE_BASE_DELAY_SECONDS = 1.0
_THROTTLE_MAX_DELAY_SECONDS = 30.0
_MAX_SERVER_ERROR_RETRIES = 2
_SERVER_ERROR_BASE_DELAY_SECONDS = 0.5

# Token cache safety window — refresh this many seconds before the token's
# reported expiry, so a Graph call never starts with a token that expires
# mid-request.
_TOKEN_SAFETY_WINDOW_SECONDS = 60.0
# Conservative default if the token endpoint omits expires_in (Microsoft
# always returns it in practice, but never trust that blindly).
_DEFAULT_TOKEN_TTL_SECONDS = 3600.0


class EntraTokenError(AuthenticationError):
    """Raised when the Microsoft identity platform token endpoint rejects
    the supplied credentials or returns a malformed response."""


# ── Fail-soft API-call wrapper (mirrors the Okta/Kubernetes reliability
#    pattern) ────────────────────────────────────────────────────────────────


@dataclass
class CallOutcome:
    """Result of one fail-soft Graph API call. ``category`` never leaks
    credential material — only a safe, fixed message plus the HTTP status
    code (if any) is retained in ``detail``."""

    ok: bool
    response: Any = None
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
        return CATEGORY_AUTH_FAILED, "HTTP 401: Microsoft Graph rejected the supplied token."
    if status == 403:
        return CATEGORY_PERMISSION_DENIED, "HTTP 403: permission denied for this resource."
    if status == 404:
        return CATEGORY_NOT_FOUND, "HTTP 404: resource or endpoint not found."
    if status == 429:
        return CATEGORY_THROTTLED, "HTTP 429: request was throttled by Microsoft Graph."
    if status >= 500:
        return CATEGORY_SERVER_ERROR, f"HTTP {status}: Microsoft Graph returned a server error."
    return CATEGORY_SERVER_ERROR, f"HTTP {status}: unexpected Microsoft Graph API response."


def _classify_transport_exception(exc: Exception) -> tuple[str, str]:
    import ssl

    if isinstance(exc, ssl.SSLError):
        return CATEGORY_TLS_ERROR, "TLS certificate verification failed."
    if isinstance(exc, httpx.ConnectTimeout):
        return CATEGORY_TIMEOUT, "The request to Microsoft Graph timed out connecting."
    if isinstance(exc, httpx.ReadTimeout):
        return CATEGORY_TIMEOUT, "The request to Microsoft Graph timed out waiting for a response."
    if isinstance(exc, httpx.TimeoutException):
        return CATEGORY_TIMEOUT, "The request to Microsoft Graph timed out."
    if isinstance(exc, httpx.ConnectError):
        cause = str(exc).lower()
        if "certificate" in cause or "ssl" in cause or "tls" in cause:
            return CATEGORY_TLS_ERROR, "TLS certificate verification failed."
        if "name or service not known" in cause or "nodename nor servname" in cause or "getaddrinfo failed" in cause:
            return CATEGORY_CONNECTION_ERROR, "Could not resolve the Microsoft Graph hostname (DNS failure)."
        return CATEGORY_CONNECTION_ERROR, "Could not connect to Microsoft Graph."
    if isinstance(exc, httpx.RequestError):
        return CATEGORY_CONNECTION_ERROR, "Could not connect to Microsoft Graph."
    return CATEGORY_MALFORMED_RESPONSE, "Microsoft Graph returned a response that could not be processed."


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


def call_graph(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    params: Optional[dict] = None,
    _sleep_fn: Callable[[float], None] = None,
) -> CallOutcome:
    """Fail-soft wrapper around a single Microsoft Graph API call.

    Every request this connector makes (and every request future messages'
    collection code makes) should route through this wrapper so callers get
    the same distinguishable failure categories instead of an uncaught
    exception.

    401/403/404 are NEVER retried as if transient. 429 gets a bounded retry
    with exponential backoff and jitter (honoring ``Retry-After`` when
    present), capped at ``_MAX_THROTTLE_RETRIES`` attempts. Transient 5xx
    responses get a smaller bounded retry (``_MAX_SERVER_ERROR_RETRIES``) —
    permanent 400/401/403 failures are never retried. Tests inject
    ``_sleep_fn`` (a no-op) so retry tests never actually sleep.

    SECURITY: never includes the Authorization header or token value in
    any returned ``CallOutcome.detail`` — only a fixed, category-specific
    message plus the HTTP status code.
    """
    sleep_fn = _sleep_fn or _time.sleep
    throttle_attempt = 0
    server_error_attempt = 0
    while True:
        try:
            resp = client.request(method, url, params=params, timeout=_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — deliberately broad; classified below
            category, detail = _classify_transport_exception(exc)
            return CallOutcome(ok=False, category=category, detail=detail)

        if resp.status_code < 400:
            return CallOutcome(ok=True, response=resp, category=CATEGORY_SUCCESS)

        category, detail = _classify_response(resp)
        if category == CATEGORY_THROTTLED and throttle_attempt < _MAX_THROTTLE_RETRIES:
            retry_after = _retry_after_seconds(resp)
            delay = _throttle_backoff_seconds(throttle_attempt, retry_after=retry_after)
            logger.warning(
                "entra_connector rate limited (attempt %d/%d); sleeping %.1fs",
                throttle_attempt + 1, _MAX_THROTTLE_RETRIES, delay,
            )
            sleep_fn(delay)
            throttle_attempt += 1
            continue
        if category == CATEGORY_SERVER_ERROR and server_error_attempt < _MAX_SERVER_ERROR_RETRIES:
            delay = _server_error_backoff_seconds(server_error_attempt)
            logger.warning(
                "entra_connector transient server error (attempt %d/%d); sleeping %.1fs",
                server_error_attempt + 1, _MAX_SERVER_ERROR_RETRIES, delay,
            )
            sleep_fn(delay)
            server_error_attempt += 1
            continue

        return CallOutcome(ok=False, category=category, detail=detail)


_CATEGORY_STATUS_CODE = {
    CATEGORY_PERMISSION_DENIED: 403,
    CATEGORY_NOT_FOUND: 404,
    CATEGORY_SERVER_ERROR: 500,
    CATEGORY_MALFORMED_RESPONSE: None,
}


def _raise_for_outcome(outcome: CallOutcome, *, context: str = "") -> httpx.Response:
    """Raise the appropriate connector exception for a failed CallOutcome,
    or return the response for a successful one."""
    if outcome.ok:
        return outcome.response
    suffix = f" — {context}" if context else ""
    if outcome.category == CATEGORY_AUTH_FAILED:
        raise AuthenticationError(f"entra: {outcome.detail}{suffix}", status_code=401)
    if outcome.category == CATEGORY_THROTTLED:
        raise RateLimitError(f"entra: {outcome.detail}{suffix}")
    if outcome.category in (CATEGORY_CONNECTION_ERROR, CATEGORY_TIMEOUT, CATEGORY_TLS_ERROR):
        raise NetworkError(f"entra: {outcome.detail}{suffix}")
    raise ConnectorError(
        f"entra: {outcome.detail}{suffix}",
        status_code=_CATEGORY_STATUS_CODE.get(outcome.category),
    )


# ── Pagination (@odata.nextLink) ────────────────────────────────────────────


def _extract_next_link(body: dict) -> Optional[str]:
    """Return the ``@odata.nextLink`` URL from a Graph list response body,
    or ``None`` if absent or not a string.

    SECURITY: the caller (``paginate_graph``) verifies this URL's origin
    exactly matches the trusted Graph origin before ever following it — a
    malformed or malicious response can never redirect the connector to an
    attacker-controlled host.
    """
    if not isinstance(body, dict):
        return None
    next_link = body.get("@odata.nextLink")
    if not isinstance(next_link, str) or not next_link.strip():
        return None
    return next_link.strip()


def _validate_next_link_origin(next_link: str, *, trusted_origin: str) -> Optional[str]:
    """Resolve and validate a candidate nextLink against the trusted Graph
    origin. Returns the resolved absolute URL if it is HTTPS and exactly
    matches ``trusted_origin``, else ``None``."""
    try:
        resolved = urljoin(trusted_origin + "/", next_link)
        parsed_candidate = urlparse(resolved)
        parsed_trusted = urlparse(trusted_origin)
    except ValueError:
        return None

    if parsed_candidate.scheme.lower() != "https":
        return None

    candidate_origin = f"{parsed_candidate.scheme}://{parsed_candidate.netloc}".lower()
    trusted = f"{parsed_trusted.scheme}://{parsed_trusted.netloc}".lower()
    if candidate_origin != trusted:
        logger.warning(
            "entra_connector: rejected cross-origin pagination nextLink "
            "(expected origin %s)", trusted,
        )
        return None
    return resolved


def paginate_graph(
    client: httpx.Client,
    start_url: str,
    *,
    trusted_origin: str = _GRAPH_ORIGIN,
    params: Optional[dict] = None,
    max_pages: int = _MAX_PAGES,
    _sleep_fn: Callable[[float], None] = None,
) -> tuple[list[dict], bool]:
    """Follow Microsoft Graph's ``@odata.nextLink`` pagination safely.

    Bounded by ``max_pages``. Detects a repeated ``nextLink`` URL (a
    misbehaving or malicious server serving the same page forever) and
    stops rather than looping. Only follows a ``nextLink`` whose origin
    exactly matches ``trusted_origin`` (HTTPS, exact scheme+host match) —
    any cross-origin or non-HTTPS ``nextLink`` is silently dropped
    (pagination simply stops at the current page). Deduplicates items by
    their ``id`` field when present (defends against a server re-serving
    an overlapping page).

    Raises the same exceptions as ``call_graph`` via ``_raise_for_outcome``
    on the FIRST page failure (a fully broken credential should fail
    loudly); any LATER page's failure stops pagination and returns what
    was collected so far, since the first page already proved the
    credential works — a transient failure mid-pagination should degrade
    to partial results, not lose everything already fetched.

    Returns ``(items, truncated)``. ``truncated`` is ``True`` when
    pagination stopped for a reason OTHER than a natural end-of-list — a
    later-page failure (403/429/5xx/timeout/malformed body), a repeated
    nextLink, a rejected cross-origin/non-HTTPS nextLink, or hitting
    ``max_pages`` without reaching a natural end. The caller must treat a
    truncated result as PARTIAL even when it happens to be under any
    record cap — silently reporting a mid-pagination failure as "complete"
    would make later diffs infer false removals for every record that
    would have been on the unread pages.
    """
    items: list[dict] = []
    seen_ids: set = set()
    seen_urls: set = set()
    url = start_url
    current_params: Optional[dict] = params
    truncated = False

    for page_num in range(max_pages):
        outcome = call_graph(client, "GET", url, params=current_params, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            if page_num == 0:
                _raise_for_outcome(outcome, context=f"page {page_num + 1}")
            logger.debug("entra_connector: pagination stopped early on page %d (%s)", page_num + 1, outcome.category)
            truncated = True
            break

        resp = outcome.response
        try:
            body = resp.json()
        except ValueError:
            if page_num == 0:
                raise ConnectorError("entra: response was not valid JSON")
            truncated = True
            break
        if not isinstance(body, dict) or not isinstance(body.get("value"), list):
            if page_num == 0:
                raise ConnectorError("entra: expected a JSON object with a 'value' array")
            truncated = True
            break

        for raw in body["value"]:
            if isinstance(raw, dict) and isinstance(raw.get("id"), str):
                if raw["id"] in seen_ids:
                    continue
                seen_ids.add(raw["id"])
            items.append(raw)

        raw_next_link = _extract_next_link(body)
        if not raw_next_link:
            break
        next_url = _validate_next_link_origin(raw_next_link, trusted_origin=trusted_origin)
        if not next_url:
            # Graph claimed there was more data (a nextLink was present)
            # but it failed the origin/scheme check — we deliberately
            # don't follow it, but the result must still be treated as
            # truncated, not a confirmed-complete natural end.
            truncated = True
            break
        if next_url in seen_urls:
            logger.warning("entra_connector: repeated pagination nextLink detected; stopping")
            truncated = True
            break
        seen_urls.add(next_url)
        url = next_url
        # nextLink already carries its own query string.
        current_params = None
    else:
        # The `for` loop's `max_pages` bound was hit without a `break` —
        # there may be more pages beyond what we read.
        truncated = True

    return items, truncated


# ── Token acquisition / in-memory cache ─────────────────────────────────────


@dataclass
class _TokenCache:
    """In-memory, connector-instance-scoped OAuth token cache.

    Never persisted to disk/DB/snapshot, never logged. Lives only for the
    lifetime of the ``EntraConnector`` instance holding it — a fresh
    instance (as created per sync/validate call — see ``sync_task.py``)
    starts with an empty cache.
    """

    access_token: Optional[str] = None
    expires_at: Optional[float] = None  # monotonic seconds


class EntraConnector(BaseConnector):
    """Microsoft Entra ID provider foundation connector (Entra message 1 of 8).

    Stateless with respect to credentials: they are passed at call time and
    never stored beyond one method invocation. The one exception is the
    in-memory, instance-scoped OAuth token cache (``_TokenCache``), which
    exists specifically so a single ``fetch()``/``validate_credentials()``
    call reuses one token across multiple Graph calls instead of minting a
    fresh one per request — this cache is never written to any record,
    never logged, and never survives beyond the connector instance's
    lifetime (a fresh instance starts with an empty cache; see
    ``app/workers/sync_task.py`` for how instances are created per sync).
    """

    def __init__(self) -> None:
        self._token_cache = _TokenCache()

    # ── Credential validation ──────────────────────────────────────────────

    @staticmethod
    def _credentials(credentials: dict) -> tuple[str, str, str]:
        """Validate and return (tenant_id, client_id, client_secret).

        Raises AuthenticationError (via EntraCredentialError re-raised
        below) for a malformed tenant_id/client_id, or if client_secret is
        missing.
        """
        from app.connectors.entra_schema import EntraCredentialError

        try:
            tenant_id = validate_tenant_id(credentials.get("tenant_id"))
            client_id = validate_client_id(credentials.get("client_id"))
        except EntraCredentialError as exc:
            raise AuthenticationError(str(exc), status_code=401) from exc

        client_secret = credentials.get("client_secret")
        if not isinstance(client_secret, str) or not client_secret.strip():
            raise AuthenticationError(
                "entra: credentials must contain a non-empty 'client_secret'",
                status_code=401,
            )
        return tenant_id, client_id, client_secret

    # ── Token acquisition ──────────────────────────────────────────────────

    @staticmethod
    def _acquire_token(
        tenant_id: str, client_id: str, client_secret: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[str, float]:
        """Mint a fresh app-only Graph access token via the OAuth2
        client_credentials grant.

        The token endpoint host is always the fixed, trusted Microsoft
        identity platform host — never derived from user input beyond the
        already-validated GUID ``tenant_id`` path segment.

        Returns ``(access_token, expires_in_seconds)``.

        SECURITY: client_secret is passed in the POST body only, never
        logged. The raw token response body is never logged or stored.

        Raises:
            AuthenticationError: invalid_client / invalid tenant / 401/403
                from the token endpoint.
            RateLimitError: token endpoint rate limited (429).
            ConnectorError: token endpoint returned an unexpected error or
                a response missing 'access_token'.
            NetworkError: transport-level failure contacting the token
                endpoint.
        """
        sleep_fn = _sleep_fn or _time.sleep
        token_url = f"https://{_TOKEN_HOST}/{tenant_id}/oauth2/v2.0/token"

        attempt = 0
        while True:
            try:
                resp = httpx.post(
                    token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "scope": _GRAPH_SCOPE,
                    },
                    timeout=_TIMEOUT,
                )
            except Exception as exc:  # noqa: BLE001 — classified below
                category, detail = _classify_transport_exception(exc)
                if category in (CATEGORY_CONNECTION_ERROR, CATEGORY_TLS_ERROR):
                    raise NetworkError(f"entra: token endpoint {detail}") from exc
                raise NetworkError(f"entra: token endpoint {detail}") from exc

            if resp.status_code == 429:
                if attempt < _MAX_THROTTLE_RETRIES:
                    retry_after = _retry_after_seconds(resp)
                    delay = _throttle_backoff_seconds(attempt, retry_after=retry_after)
                    sleep_fn(delay)
                    attempt += 1
                    continue
                raise RateLimitError(
                    "entra: token endpoint rate limited (429), retries exhausted",
                    retry_after=_retry_after_seconds(resp),
                )

            if resp.status_code in (400, 401):
                # Microsoft's token endpoint uses 400 for most OAuth error
                # codes (invalid_client, invalid_request, unauthorized_client)
                # and occasionally 401. Never propagate the raw error body
                # (may include correlation IDs/trace text) — only a fixed,
                # safe summary.
                error_code = "unknown"
                try:
                    body = resp.json()
                    if isinstance(body, dict) and isinstance(body.get("error"), str):
                        error_code = body["error"][:64]
                except ValueError:
                    pass
                raise EntraTokenError(
                    f"entra: token endpoint rejected the request "
                    f"(error={error_code!r}) — check tenant_id, client_id, "
                    "and client_secret",
                    status_code=resp.status_code,
                )

            if resp.status_code >= 500:
                if attempt < _MAX_SERVER_ERROR_RETRIES:
                    sleep_fn(_server_error_backoff_seconds(attempt))
                    attempt += 1
                    continue
                raise ConnectorError(
                    f"entra: token endpoint returned HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )

            if resp.status_code >= 400:
                raise ConnectorError(
                    f"entra: token endpoint returned HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )

            try:
                data = resp.json()
            except ValueError as exc:
                raise ConnectorError(
                    "entra: token endpoint response was not valid JSON"
                ) from exc

            token = data.get("access_token") if isinstance(data, dict) else None
            if not isinstance(token, str) or not token:
                raise EntraTokenError(
                    "entra: token endpoint returned no access_token",
                    status_code=401,
                )
            expires_in = data.get("expires_in", _DEFAULT_TOKEN_TTL_SECONDS)
            try:
                expires_in = float(expires_in)
            except (TypeError, ValueError):
                expires_in = _DEFAULT_TOKEN_TTL_SECONDS
            if expires_in <= 0:
                expires_in = _DEFAULT_TOKEN_TTL_SECONDS
            return token, expires_in

    def _get_token(
        self,
        credentials: dict,
        *,
        _sleep_fn: Callable[[float], None] = None,
        _time_fn: Callable[[], float] = None,
    ) -> str:
        """Return a cached access token, refreshing it if absent or within
        the safety window of expiry.

        Multiple Graph calls within one ``fetch()``/``validate_credentials()``
        invocation reuse the same cached token — a fresh token is never
        requested per call.
        """
        time_fn = _time_fn or _time.monotonic
        now = time_fn()
        cache = self._token_cache
        if (
            cache.access_token is not None
            and cache.expires_at is not None
            and now < (cache.expires_at - _TOKEN_SAFETY_WINDOW_SECONDS)
        ):
            return cache.access_token

        tenant_id, client_id, client_secret = self._credentials(credentials)
        token, expires_in = self._acquire_token(
            tenant_id, client_id, client_secret, _sleep_fn=_sleep_fn,
        )
        cache.access_token = token
        cache.expires_at = now + expires_in
        return token

    # ── HTTP client ────────────────────────────────────────────────────────

    @staticmethod
    def _make_client(access_token: str) -> httpx.Client:
        """Build an httpx.Client for the Microsoft Graph API.

        SECURITY: the token is placed in the Authorization header only,
        never stored on the connector instance beyond the token cache, and
        never logged. The base URL is always the fixed, trusted Graph v1.0
        endpoint — never overridable by credentials.
        """
        return httpx.Client(
            base_url=_GRAPH_BASE_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
            timeout=_TIMEOUT,
        )

    # ── Tenant identity ────────────────────────────────────────────────────

    @staticmethod
    def compute_tenant_id(credential_tenant_id: str, raw_org: dict) -> str:
        """Return a stable tenant identifier.

        The credential's own ``tenant_id`` (already GUID-validated) IS the
        immutable Entra tenant identity — unlike some providers, Microsoft
        Graph requires the tenant GUID to be supplied up front, so there is
        no separate "resolve identity from a lookup" step. When the
        ``/organization`` response includes an ``id`` field, it is cross-
        checked (both are the same tenant GUID in every real Entra tenant);
        the credential's own validated value is returned either way, so
        token rotation and tenant display-name changes never alter
        identity.
        """
        return f"id:{credential_tenant_id}"

    # ── Record normalizers ─────────────────────────────────────────────────

    @staticmethod
    def _normalize_organization(
        tenant_id: str, raw: dict, *, family_completeness: Optional[dict] = None,
    ) -> dict:
        """Normalize the Entra organization/tenant record.

        SECURITY: the raw Graph organization object (which may include
        technical contact emails, marketing notification emails, security
        compliance notification details, and other tenant contact PII) is
        NEVER stored — only the specific safe fields below are extracted.

        Microsoft Graph's ``organization`` resource has no documented
        "tenant type" field for app-only reads — this is intentionally NOT
        fabricated (see instruction to never silently claim unsupported
        detail).

        ``family_completeness`` (Entra message 2) reports what actually
        happened collecting users/groups/memberships this fetch — e.g.
        ``{"users": "complete", "groups": "complete", "memberships": "denied"}``
        — informational only, never diff-tracked, so a permission change
        alone never produces a noisy Change on its own.
        """
        display_name = raw.get("displayName") if isinstance(raw, dict) else None
        verified_domains = raw.get("verifiedDomains") if isinstance(raw, dict) else None
        verified_domains = verified_domains if isinstance(verified_domains, list) else []

        default_domain_name = None
        for domain in verified_domains:
            if isinstance(domain, dict) and domain.get("isDefault") is True:
                name = domain.get("name")
                if isinstance(name, str) and name.strip():
                    default_domain_name = name.strip()[:_MAX_STR_LEN]
                break

        return {
            "record_type": ENTRA_ORGANIZATION,
            "record_id": tenant_id,
            "provider_resource_id": f"organization/{tenant_id}",
            "tenant_id": tenant_id,
            "display_name": (
                display_name.strip()[:_MAX_STR_LEN]
                if isinstance(display_name, str) and display_name.strip()
                else None
            ),
            "verified_domain_count": len(verified_domains),
            "default_verified_domain": default_domain_name,
            "on_premises_sync_enabled_category": categorize_on_premises_sync(
                raw.get("onPremisesSyncEnabled") if isinstance(raw, dict) else None
            ),
            "family_completeness": dict(family_completeness) if family_completeness else {},
        }

    @staticmethod
    def _normalize_capability(tenant_id: str, family: str, status: str) -> dict:
        return {
            "record_type": ENTRA_API_CAPABILITY,
            "record_id": f"{tenant_id}/capability/{family}",
            "provider_resource_id": f"capability/{family}",
            "tenant_id": tenant_id,
            "family": family,
            "status": status,
        }

    # ── User / group / membership normalizers (Entra message 2) ────────────

    @staticmethod
    def _normalize_user(tenant_id: str, raw: dict) -> Optional[dict]:
        """Normalize one Entra directory user record.

        SECURITY: only the fields explicitly listed below are ever read
        from ``raw``. Phone numbers, addresses, manager, employee ID,
        extension properties, the ``identities`` array, ``proxyAddresses``,
        ``passwordProfile``, and raw sign-in activity are NEVER read here,
        even if present in the Graph response (which they should not be,
        given the explicit ``$select`` used by ``_fetch_users``, but this
        normalizer defends independently of that allowlist too).
        """
        user_id = raw.get("id")
        if not isinstance(user_id, str) or not user_id.strip():
            return None

        upn = raw.get("userPrincipalName")
        upn = upn.strip()[:_MAX_STR_LEN] if isinstance(upn, str) and upn.strip() else None

        display_name = raw.get("displayName")
        display_name = display_name.strip()[:_MAX_STR_LEN] if isinstance(display_name, str) and display_name.strip() else None

        account_enabled_category = categorize_account_enabled(raw.get("accountEnabled"))
        user_type_category = categorize_user_type(raw.get("userType"))
        lifecycle_posture = lifecycle_posture_for_user(account_enabled_category, user_type_category)

        created = raw.get("createdDateTime")
        created = created if isinstance(created, str) and created.strip() else None

        return {
            "record_type": ENTRA_USER,
            "record_id": f"{tenant_id}/user/{user_id}",
            "provider_resource_id": f"users/{user_id}",
            "tenant_id": tenant_id,
            "user_id": user_id,
            "user_principal_name": upn,
            "display_name": display_name,
            "account_enabled_category": account_enabled_category,
            "user_type_category": user_type_category,
            "guest": user_type_category == "Guest",
            "member": user_type_category == "Member",
            "lifecycle_posture": lifecycle_posture,
            "external_user_state_category": categorize_external_user_state(raw.get("externalUserState")),
            "on_premises_sync_enabled_category": categorize_on_premises_sync(raw.get("onPremisesSyncEnabled")),
            # Informational only — NEVER diff-tracked (routine timestamp).
            "created_date_time": created,
        }

    @staticmethod
    def _normalize_group(
        tenant_id: str, raw: dict, *, membership_count: Optional[int],
    ) -> Optional[dict]:
        """Normalize one Entra directory group record.

        SECURITY: the raw dynamic-membership rule expression (which can
        reveal internal business logic — department names, cost centers,
        naming conventions), mail aliases, proxy addresses, owners, and the
        group description are NEVER read here — only the boolean/derived
        posture fields below.
        """
        group_id = raw.get("id")
        if not isinstance(group_id, str) or not group_id.strip():
            return None

        display_name = raw.get("displayName")
        display_name = display_name.strip()[:_MAX_STR_LEN] if isinstance(display_name, str) and display_name.strip() else None

        security_enabled = raw.get("securityEnabled") if isinstance(raw.get("securityEnabled"), bool) else None
        mail_enabled = raw.get("mailEnabled") if isinstance(raw.get("mailEnabled"), bool) else None
        group_types = normalize_group_types(raw.get("groupTypes"))
        group_type_category = categorize_group_type(security_enabled, mail_enabled, group_types)

        role_assignable = raw.get("isAssignableToRole")
        role_assignable = role_assignable if isinstance(role_assignable, bool) else None

        return {
            "record_type": ENTRA_GROUP,
            "record_id": f"{tenant_id}/group/{group_id}",
            "provider_resource_id": f"groups/{group_id}",
            "tenant_id": tenant_id,
            "group_id": group_id,
            "display_name": display_name,
            "security_enabled": security_enabled,
            "mail_enabled": mail_enabled,
            "group_types": group_types,
            "group_type_category": group_type_category,
            "dynamic_membership": "DynamicMembership" in group_types,
            "microsoft_365_group": "Unified" in group_types,
            "security_group": security_enabled is True,
            "role_assignable": role_assignable,
            "membership_count": membership_count,
            "membership_count_category": categorize_membership_count(membership_count),
        }

    @staticmethod
    def _normalize_membership(
        tenant_id: str, user_record: Optional[dict], group_record: dict, user_id: str,
    ) -> dict:
        """Normalize one DIRECT user<->group membership edge.

        Never duplicates the full user/group record — only denormalizes
        the small set of display/context fields a Change needs (UPN, user
        type, account-enabled state, group name/type posture) so downstream
        consumers don't need a join back to the full records. Direct
        membership only — transitive membership and nested-group
        containment are never modeled here (see the connector's module
        docstring).
        """
        group_id = group_record["group_id"]
        user_upn = user_record.get("user_principal_name") if user_record else None
        user_type_category = user_record.get("user_type_category") if user_record else "unknown"
        account_enabled_category = user_record.get("account_enabled_category") if user_record else "unknown"

        return {
            "record_type": ENTRA_GROUP_MEMBERSHIP,
            "record_id": f"{tenant_id}/membership/{group_id}/{user_id}",
            "provider_resource_id": f"groups/{group_id}/members/{user_id}",
            "tenant_id": tenant_id,
            "user_id": user_id,
            "group_id": group_id,
            "user_principal_name": user_upn,
            "group_name": group_record.get("display_name"),
            "user_type_category": user_type_category,
            "account_enabled_category": account_enabled_category,
            "group_type_category": group_record.get("group_type_category"),
            "dynamic_group": bool(group_record.get("dynamic_membership")),
            "role_assignable_group": group_record.get("role_assignable"),
            "membership_type": "direct",
        }

    # ── Application / service-principal normalizers (Entra message 3) ──────

    @staticmethod
    def _normalize_application(tenant_id: str, raw: dict) -> Optional[dict]:
        """Normalize one Entra application (app registration) record.

        SECURITY: ``passwordCredentials``/``keyCredentials`` are read ONLY
        for their ``endDateTime`` (via ``categorize_nearest_credential_expiry``)
        — ``secretText``/``key``/certificate bytes are never read.
        ``requiredResourceAccess`` is summarized into counts only (never
        equated with granted access). Redirect URIs are summarized into
        structural counts/booleans only — never stored raw.
        """
        object_id = raw.get("id")
        if not isinstance(object_id, str) or not object_id.strip():
            return None

        app_id = raw.get("appId")
        app_id = app_id.strip()[:_MAX_STR_LEN] if isinstance(app_id, str) and app_id.strip() else None

        display_name = raw.get("displayName")
        display_name = display_name.strip()[:_MAX_STR_LEN] if isinstance(display_name, str) and display_name.strip() else None

        publisher_domain = raw.get("publisherDomain")
        publisher_domain = publisher_domain.strip()[:_MAX_STR_LEN] if isinstance(publisher_domain, str) and publisher_domain.strip() else None

        web = raw.get("web") if isinstance(raw.get("web"), dict) else {}
        spa = raw.get("spa") if isinstance(raw.get("spa"), dict) else {}
        public_client = raw.get("publicClient") if isinstance(raw.get("publicClient"), dict) else {}
        redirect_posture = summarize_application_redirects(
            web.get("redirectUris"), spa.get("redirectUris"), public_client.get("redirectUris"),
        )

        password_creds = raw.get("passwordCredentials") if isinstance(raw.get("passwordCredentials"), list) else []
        key_creds = raw.get("keyCredentials") if isinstance(raw.get("keyCredentials"), list) else []
        all_creds = list(password_creds) + list(key_creds)

        app_roles = raw.get("appRoles") if isinstance(raw.get("appRoles"), list) else []
        app_role_enabled_count = sum(1 for r in app_roles if isinstance(r, dict) and r.get("isEnabled") is True)

        return {
            "record_type": ENTRA_APPLICATION,
            "record_id": f"{tenant_id}/application/{object_id}",
            "provider_resource_id": f"applications/{object_id}",
            "tenant_id": tenant_id,
            "object_id": object_id,
            "app_id": app_id,
            "display_name": display_name,
            "sign_in_audience_category": categorize_sign_in_audience(raw.get("signInAudience")),
            "publisher_domain": publisher_domain,
            **redirect_posture,
            **summarize_required_resource_access(raw.get("requiredResourceAccess")),
            "password_credential_count": len(password_creds),
            "key_credential_count": len(key_creds),
            "nearest_credential_expiry_category": categorize_nearest_credential_expiry(all_creds),
            "app_role_count": len(app_roles),
            "app_role_enabled_count": app_role_enabled_count,
        }

    @staticmethod
    def _normalize_service_principal(tenant_id: str, raw: dict, own_tenant_guid: str) -> Optional[dict]:
        """Normalize one Entra service principal (Enterprise Application)
        record.

        SECURITY: same credential/permission-count-only discipline as
        ``_normalize_application``. The raw ``tags`` array and ``info``
        object (which may contain support/marketing URLs and free-text
        notes) are never read.
        """
        sp_id = raw.get("id")
        if not isinstance(sp_id, str) or not sp_id.strip():
            return None

        app_id = raw.get("appId")
        app_id = app_id.strip()[:_MAX_STR_LEN] if isinstance(app_id, str) and app_id.strip() else None

        display_name = raw.get("displayName")
        display_name = display_name.strip()[:_MAX_STR_LEN] if isinstance(display_name, str) and display_name.strip() else None

        account_enabled = raw.get("accountEnabled") if isinstance(raw.get("accountEnabled"), bool) else None
        assignment_required = raw.get("appRoleAssignmentRequired") if isinstance(raw.get("appRoleAssignmentRequired"), bool) else None

        app_owner_org_id = raw.get("appOwnerOrganizationId")
        app_owner_org_category = categorize_app_owner_organization(app_owner_org_id, own_tenant_guid)
        is_microsoft_first_party = (
            isinstance(app_owner_org_id, str)
            and app_owner_org_id.strip().lower() == MICROSOFT_FIRST_PARTY_TENANT_ID.lower()
        )

        password_creds = raw.get("passwordCredentials") if isinstance(raw.get("passwordCredentials"), list) else []
        key_creds = raw.get("keyCredentials") if isinstance(raw.get("keyCredentials"), list) else []
        all_creds = list(password_creds) + list(key_creds)

        app_roles = raw.get("appRoles") if isinstance(raw.get("appRoles"), list) else []
        oauth2_scopes = raw.get("oauth2PermissionScopes") if isinstance(raw.get("oauth2PermissionScopes"), list) else []

        return {
            "record_type": ENTRA_SERVICE_PRINCIPAL,
            "record_id": f"{tenant_id}/service_principal/{sp_id}",
            "provider_resource_id": f"servicePrincipals/{sp_id}",
            "tenant_id": tenant_id,
            "service_principal_id": sp_id,
            "app_id": app_id,
            "display_name": display_name,
            "service_principal_type_category": categorize_service_principal_type(raw.get("servicePrincipalType")),
            "account_enabled": account_enabled,
            "assignment_required": assignment_required,
            "app_owner_organization_category": app_owner_org_category,
            "is_microsoft_first_party": is_microsoft_first_party,
            "is_microsoft_graph_resource": app_id == MICROSOFT_GRAPH_APP_ID,
            "verified_publisher_category": categorize_verified_publisher(raw.get("verifiedPublisher")),
            "app_role_count": len(app_roles),
            "oauth2_permission_scope_count": len(oauth2_scopes),
            "password_credential_count": len(password_creds),
            "key_credential_count": len(key_creds),
            "nearest_credential_expiry_category": categorize_nearest_credential_expiry(all_creds),
        }

    @staticmethod
    def _resolve_app_role(roles_by_id: Optional[dict], app_role_id: object) -> tuple[Optional[str], str]:
        """Resolve an ``appRoleId`` GUID to its ``value`` string using the
        RESOURCE service principal's own app-roles local index (built once
        per SP from its raw ``appRoles`` array during collection — never a
        per-assignment Graph call, and never persisted onto the normalized
        ``entra_service_principal`` record itself). Returns
        ``(value_or_None, risk_category)``. Unknown IDs stay unknown — never
        guessed as benign."""
        if not isinstance(app_role_id, str):
            return None, categorize_permission_risk(None)
        roles_by_id = roles_by_id or {}
        role = roles_by_id.get(app_role_id)
        if role is None:
            # The well-known "default" all-zero app role ID means
            # "no specific app role" (ordinary sign-in access), not unknown.
            if app_role_id == "00000000-0000-0000-0000-000000000000":
                return "(default)", categorize_permission_risk(None)
            return None, categorize_permission_risk(None)
        value = role.get("value")
        return value, categorize_permission_risk(value)

    @staticmethod
    def _normalize_app_user_assignment(
        tenant_id: str, sp_record: dict, user_record: Optional[dict], raw: dict,
        *, roles_by_id: Optional[dict] = None,
    ) -> Optional[dict]:
        """Normalize one user<->service-principal app-role assignment edge.

        SECURITY: only ``id``, ``principalId``, ``appRoleId``, and
        ``principalType`` are ever read from the raw assignment object.
        """
        assignment_id = raw.get("id")
        principal_id = raw.get("principalId")
        if not isinstance(principal_id, str) or not principal_id.strip():
            return None

        sp_id = sp_record["service_principal_id"]
        record_id = (
            f"{tenant_id}/app_role_assignment/{assignment_id}"
            if isinstance(assignment_id, str) and assignment_id.strip()
            else f"{tenant_id}/app_assignment/{sp_id}/user/{principal_id}"
        )

        app_role_value, app_role_risk = EntraConnector._resolve_app_role(roles_by_id, raw.get("appRoleId"))
        user_upn = user_record.get("user_principal_name") if user_record else None
        account_enabled_category = user_record.get("account_enabled_category") if user_record else "unknown"
        user_type_category = user_record.get("user_type_category") if user_record else "unknown"

        return {
            "record_type": ENTRA_APPLICATION_USER_ASSIGNMENT,
            "record_id": record_id,
            "provider_resource_id": f"servicePrincipals/{sp_id}/appRoleAssignedTo/{principal_id}",
            "tenant_id": tenant_id,
            "service_principal_id": sp_id,
            "app_id": sp_record.get("app_id"),
            "application_name": sp_record.get("display_name"),
            "principal_id": principal_id,
            "user_id": principal_id,
            "user_principal_name": user_upn,
            "account_enabled_category": account_enabled_category,
            "user_type_category": user_type_category,
            "app_role_category": app_role_value,
            "app_role_risk_category": app_role_risk,
            "assignment_type": "user",
        }

    @staticmethod
    def _normalize_app_group_assignment(
        tenant_id: str, sp_record: dict, group_record: Optional[dict], raw: dict,
        *, roles_by_id: Optional[dict] = None,
    ) -> Optional[dict]:
        """Normalize one group<->service-principal app-role assignment edge.

        Never conflates a group assignment with each member's own effective
        access — this is the GROUP's own assignment edge only; per-user fan-
        out is not modeled here (would require joining message-2 membership
        data and is deferred, since app-role-granted-via-group-membership
        evaluation is a message-5-scope privilege question).
        """
        assignment_id = raw.get("id")
        principal_id = raw.get("principalId")
        if not isinstance(principal_id, str) or not principal_id.strip():
            return None

        sp_id = sp_record["service_principal_id"]
        record_id = (
            f"{tenant_id}/app_role_assignment/{assignment_id}"
            if isinstance(assignment_id, str) and assignment_id.strip()
            else f"{tenant_id}/app_assignment/{sp_id}/group/{principal_id}"
        )

        app_role_value, app_role_risk = EntraConnector._resolve_app_role(roles_by_id, raw.get("appRoleId"))
        group_name = group_record.get("display_name") if group_record else None
        group_type_category = group_record.get("group_type_category") if group_record else "unknown"
        dynamic_group = bool(group_record.get("dynamic_membership")) if group_record else False
        role_assignable_group = group_record.get("role_assignable") if group_record else None

        return {
            "record_type": ENTRA_APPLICATION_GROUP_ASSIGNMENT,
            "record_id": record_id,
            "provider_resource_id": f"servicePrincipals/{sp_id}/appRoleAssignedTo/{principal_id}",
            "tenant_id": tenant_id,
            "service_principal_id": sp_id,
            "app_id": sp_record.get("app_id"),
            "application_name": sp_record.get("display_name"),
            "group_id": principal_id,
            "group_name": group_name,
            "group_type_category": group_type_category,
            "dynamic_group": dynamic_group,
            "role_assignable_group": role_assignable_group,
            "app_role_category": app_role_value,
            "app_role_risk_category": app_role_risk,
            "assignment_type": "group",
        }

    @staticmethod
    def _normalize_sp_app_role_assignment(
        tenant_id: str, resource_sp_record: dict, principal_sp_record: Optional[dict], raw: dict,
        *, roles_by_id: Optional[dict] = None,
    ) -> Optional[dict]:
        """Normalize one service-principal<->service-principal application-
        permission assignment edge (e.g. an automation SP granted an
        application permission against Microsoft Graph or another API)."""
        assignment_id = raw.get("id")
        principal_id = raw.get("principalId")
        if not isinstance(principal_id, str) or not principal_id.strip():
            return None

        resource_sp_id = resource_sp_record["service_principal_id"]
        record_id = (
            f"{tenant_id}/app_role_assignment/{assignment_id}"
            if isinstance(assignment_id, str) and assignment_id.strip()
            else f"{tenant_id}/app_assignment/{resource_sp_id}/sp/{principal_id}"
        )

        app_role_value, app_role_risk = EntraConnector._resolve_app_role(roles_by_id, raw.get("appRoleId"))

        return {
            "record_type": ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT,
            "record_id": record_id,
            "provider_resource_id": f"servicePrincipals/{resource_sp_id}/appRoleAssignedTo/{principal_id}",
            "tenant_id": tenant_id,
            "resource_service_principal_id": resource_sp_id,
            "resource_app_id": resource_sp_record.get("app_id"),
            "resource_name": resource_sp_record.get("display_name"),
            "resource_is_microsoft_graph": resource_sp_record.get("is_microsoft_graph_resource", False),
            "principal_service_principal_id": principal_id,
            "principal_app_id": principal_sp_record.get("app_id") if principal_sp_record else None,
            "principal_name": principal_sp_record.get("display_name") if principal_sp_record else None,
            "app_role_category": app_role_value,
            "app_role_risk_category": app_role_risk,
            "assignment_type": "service_principal",
        }

    @staticmethod
    def _normalize_oauth2_permission_grant(
        tenant_id: str, raw: dict, sp_by_id: dict,
    ) -> Optional[dict]:
        """Normalize one delegated OAuth2 consent grant.

        SECURITY: only ``id``, ``clientId``, ``resourceId``, ``consentType``,
        ``principalId``, and ``scope`` are ever read — never any token
        value. ``scope`` (a raw space-delimited string) is parsed into a
        bounded, deduplicated, sorted list — never stored as one opaque
        string.
        """
        grant_id = raw.get("id")
        if not isinstance(grant_id, str) or not grant_id.strip():
            return None

        client_sp_id = raw.get("clientId")
        resource_sp_id = raw.get("resourceId")
        client_sp_record = sp_by_id.get(client_sp_id) if isinstance(client_sp_id, str) else None
        resource_sp_record = sp_by_id.get(resource_sp_id) if isinstance(resource_sp_id, str) else None

        scopes = normalize_scopes(raw.get("scope"))
        high_risk_scope_present = any(categorize_permission_risk(s) == "high_risk" for s in scopes)

        consent_type_category = categorize_consent_type(raw.get("consentType"))
        principal_id = raw.get("principalId") if consent_type_category == "Principal" else None

        return {
            "record_type": ENTRA_OAUTH2_PERMISSION_GRANT,
            "record_id": f"{tenant_id}/oauth2_permission_grant/{grant_id}",
            "provider_resource_id": f"oauth2PermissionGrants/{grant_id}",
            "tenant_id": tenant_id,
            "grant_id": grant_id,
            "client_service_principal_id": client_sp_id if isinstance(client_sp_id, str) else None,
            "client_name": client_sp_record.get("display_name") if client_sp_record else None,
            "resource_service_principal_id": resource_sp_id if isinstance(resource_sp_id, str) else None,
            "resource_name": resource_sp_record.get("display_name") if resource_sp_record else None,
            "resource_is_microsoft_graph": (resource_sp_record or {}).get("is_microsoft_graph_resource", False),
            "consent_type_category": consent_type_category,
            "principal_id": principal_id,
            "scope_count": len(scopes),
            "scopes": scopes,
            "high_risk_scope_present": high_risk_scope_present,
        }

    # ── Family collection helper (mirrors the Okta reliability pattern) ────

    @classmethod
    def _collect_family(
        cls,
        client: httpx.Client,
        path: str,
        *,
        params: Optional[dict],
        cap: int,
        _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        """Paginate one Graph list endpoint, classifying the outcome into a
        FAMILY_* completeness rather than raising for anything but a
        first-page failure. Every family fails independently — a denied or
        unavailable family never aborts the whole fetch.

        Returns ``(items, completeness)``. Hitting ``cap`` OR a mid-
        pagination failure (``paginate_graph()``'s ``truncated`` flag) is
        treated as ``FAMILY_PARTIAL`` — never claim complete when the
        result may have been truncated by a later-page 403/429/5xx/
        timeout, a repeated nextLink, or a rejected cross-origin nextLink.
        """
        try:
            items, truncated = paginate_graph(
                client, path, params=params, max_pages=_MAX_PAGES, _sleep_fn=_sleep_fn,
            )
        except AuthenticationError:
            return [], FAMILY_DENIED
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) == 403:
                return [], FAMILY_DENIED
            return [], FAMILY_UNAVAILABLE
        except (NetworkError, RateLimitError):
            return [], FAMILY_UNAVAILABLE

        if len(items) >= cap:
            return items[:cap], FAMILY_PARTIAL
        if truncated:
            return items, FAMILY_PARTIAL
        return items, FAMILY_COMPLETE

    # Explicit, connector-owned $select allowlists — never user-controlled,
    # never "$select=*". Only the fields this message's normalizers read.
    _USER_SELECT = (
        "id,userPrincipalName,displayName,accountEnabled,userType,"
        "createdDateTime,externalUserState,onPremisesSyncEnabled"
    )
    _GROUP_SELECT = "id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole"

    @classmethod
    def _fetch_users(
        cls, client: httpx.Client, tenant_id: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        raw_items, completeness = cls._collect_family(
            client, "/users",
            params={"$top": str(_PAGE_SIZE), "$select": cls._USER_SELECT},
            cap=_MAX_USERS, _sleep_fn=_sleep_fn,
        )
        records = []
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            rec = cls._normalize_user(tenant_id, raw)
            if rec is not None:
                records.append(rec)
        return records, completeness

    @classmethod
    def _fetch_groups_raw(
        cls, client: httpx.Client,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        return cls._collect_family(
            client, "/groups",
            params={"$top": str(_PAGE_SIZE), "$select": cls._GROUP_SELECT},
            cap=_MAX_GROUPS, _sleep_fn=_sleep_fn,
        )

    @classmethod
    def _fetch_memberships(
        cls,
        client: httpx.Client,
        tenant_id: str,
        raw_groups: list[dict],
        group_records_by_id: dict,
        user_index: dict,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str, dict, dict]:
        """Collect DIRECT user<->group membership edges.

        Call-complexity design: Microsoft Graph has no single "list all
        memberships across the tenant" endpoint — membership is only
        enumerable per-group (``GET /groups/{id}/members``) or per-user
        (``GET /users/{id}/memberOf``). This connector walks per-GROUP (one
        paginated call per group, capped at
        ``_MAX_GROUPS_FOR_MEMBERSHIP_ENUMERATION`` groups) rather than
        per-user, because a real tenant almost always has far fewer groups
        than users (fewer top-level requests) — the exact same choice and
        rationale as the Okta connector's ``_fetch_memberships()``. This is
        intentionally NOT optimized further in this message — message 7
        owns full partial-sync/scale hardening; here it is bounded and
        documented, not silently unbounded.

        ``/groups/{id}/members`` is polymorphic (users, groups, service
        principals, devices). Rather than relying on the
        ``/members/microsoft.graph.user`` OData type-cast segment (whose
        app-only-permission behavior is not something to assume), each
        returned directoryObject's own ``@odata.type`` annotation is
        inspected locally and only ``#microsoft.graph.user`` members are
        normalized — nested groups, service principals, and devices are
        silently excluded from ``entra_group_membership`` (deferred to
        messages 3/5, or permanently unmodeled for devices). Nested groups
        are never flattened into direct user membership.

        Also returns a ``membership_count_by_group_id`` dict so
        ``_normalize_group()`` can report a count derived from what was
        actually collected, without a separate per-group count API call,
        and a ``status_by_group_id`` dict recording each walked group's OWN
        completeness — this lets future false-removal suppression (message
        7) scope itself to just the groups whose walk actually failed,
        rather than suppressing every membership removal tenant-wide
        whenever any single group's walk fails.

        Returns ``(records, completeness, membership_count_by_group_id, status_by_group_id)``.
        completeness is FAMILY_COMPLETE only if every walked group
        succeeded; FAMILY_DENIED if the walk never got any group's members
        due to permission; FAMILY_PARTIAL if some groups succeeded and
        others didn't (or the group cap / total cap was hit); FAMILY_
        UNAVAILABLE if every walked group failed for a non-permission
        reason.
        """
        if not raw_groups:
            # No groups at all -> trivially complete, zero memberships —
            # never inferred as "unknown"/"denied".
            return [], FAMILY_COMPLETE, {}, {}

        groups_to_walk = raw_groups[:_MAX_GROUPS_FOR_MEMBERSHIP_ENUMERATION]
        truncated_group_list = len(raw_groups) > len(groups_to_walk)

        records: list[dict] = []
        counts_by_group: dict = {}
        status_by_group: dict = {}
        succeeded = 0
        denied = 0
        other_failed = 0
        cap_hit = False

        for raw_group in groups_to_walk:
            if not isinstance(raw_group, dict):
                continue
            group_id = raw_group.get("id")
            if not isinstance(group_id, str) or not group_id.strip():
                continue
            group_record = group_records_by_id.get(group_id)
            if group_record is None:
                continue

            members, group_completeness = cls._collect_family(
                client, f"/groups/{group_id}/members",
                params={"$top": str(_PAGE_SIZE), "$select": "id"},
                cap=_MAX_MEMBERS_PER_GROUP, _sleep_fn=_sleep_fn,
            )
            status_by_group[group_id] = group_completeness
            if group_completeness == FAMILY_DENIED:
                denied += 1
                continue
            if group_completeness == FAMILY_UNAVAILABLE:
                other_failed += 1
                continue
            if group_completeness == FAMILY_PARTIAL:
                cap_hit = True

            succeeded += 1
            member_ids: set = set()
            for raw_member in members:
                if not isinstance(raw_member, dict):
                    continue
                # Non-user directory members (nested groups, service
                # principals, devices) are excluded — user members only.
                odata_type = raw_member.get("@odata.type")
                if odata_type != GRAPH_MEMBER_TYPE_USER:
                    continue
                member_id = raw_member.get("id")
                if not isinstance(member_id, str) or not member_id.strip():
                    continue
                if member_id in member_ids:
                    continue  # dedup within a single group's page set
                member_ids.add(member_id)
                if len(records) >= _MAX_TOTAL_MEMBERSHIPS:
                    cap_hit = True
                    break
                user_record = user_index.get(member_id)
                records.append(
                    cls._normalize_membership(tenant_id, user_record, group_record, member_id)
                )
            counts_by_group[group_id] = len(member_ids)
            if len(records) >= _MAX_TOTAL_MEMBERSHIPS:
                cap_hit = True
                break

        if succeeded == 0 and denied > 0 and other_failed == 0:
            completeness = FAMILY_DENIED
        elif succeeded == 0 and other_failed > 0:
            completeness = FAMILY_UNAVAILABLE
        elif denied > 0 or other_failed > 0 or cap_hit or truncated_group_list:
            completeness = FAMILY_PARTIAL
        else:
            completeness = FAMILY_COMPLETE

        return records, completeness, counts_by_group, status_by_group

    # ── Application / service-principal collection (Entra message 3) ──────

    _APPLICATION_SELECT = (
        "id,appId,displayName,signInAudience,publisherDomain,web,spa,publicClient,"
        "requiredResourceAccess,passwordCredentials,keyCredentials,appRoles"
    )
    _SERVICE_PRINCIPAL_SELECT = (
        "id,appId,displayName,servicePrincipalType,accountEnabled,appRoleAssignmentRequired,"
        "appOwnerOrganizationId,verifiedPublisher,passwordCredentials,keyCredentials,"
        "appRoles,oauth2PermissionScopes"
    )

    @classmethod
    def _fetch_applications_raw(
        cls, client: httpx.Client, *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        return cls._collect_family(
            client, "/applications",
            params={"$top": str(_PAGE_SIZE), "$select": cls._APPLICATION_SELECT},
            cap=_MAX_APPLICATIONS, _sleep_fn=_sleep_fn,
        )

    @classmethod
    def _fetch_service_principals_raw(
        cls, client: httpx.Client, *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        return cls._collect_family(
            client, "/servicePrincipals",
            params={"$top": str(_PAGE_SIZE), "$select": cls._SERVICE_PRINCIPAL_SELECT},
            cap=_MAX_SERVICE_PRINCIPALS, _sleep_fn=_sleep_fn,
        )

    @classmethod
    def _fetch_app_role_assignments(
        cls,
        client: httpx.Client,
        tenant_id: str,
        raw_sps: list[dict],
        sp_records_by_id: dict,
        roles_by_id_by_sp: dict,
        user_index: dict,
        group_index: dict,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], list[dict], list[dict], str, dict]:
        """Collect app-role assignments INTO every service principal (i.e.
        who/what has been granted access to each resource SP), branching
        locally on ``principalType`` into three separate record types.

        Call-complexity design: Microsoft Graph has no tenant-wide
        "list every app-role assignment" endpoint — assignments are only
        enumerable per-resource-service-principal
        (``GET /servicePrincipals/{id}/appRoleAssignedTo``). This walks
        SPs once (capped at ``_MAX_SPS_FOR_ASSIGNMENT_ENUMERATION``) —
        exactly the same call-complexity choice and rationale as message
        2's per-group membership walk and Okta's per-app assignment walk.

        Returns ``(user_assignments, group_assignments, sp_assignments,
        completeness, status_by_sp_id)``. ``status_by_sp_id`` records each
        walked SP's own completeness for future per-parent false-removal
        suppression (message 7), mirroring message 2's ``status_by_group``.
        """
        if not raw_sps:
            return [], [], [], FAMILY_COMPLETE, {}

        sps_to_walk = raw_sps[:_MAX_SPS_FOR_ASSIGNMENT_ENUMERATION]
        truncated_sp_list = len(raw_sps) > len(sps_to_walk)

        user_assignments: list[dict] = []
        group_assignments: list[dict] = []
        sp_assignments: list[dict] = []
        status_by_sp: dict = {}
        succeeded = 0
        denied = 0
        other_failed = 0
        cap_hit = False
        total_records = 0

        for raw_sp in sps_to_walk:
            if not isinstance(raw_sp, dict):
                continue
            sp_id = raw_sp.get("id")
            if not isinstance(sp_id, str) or not sp_id.strip():
                continue
            sp_record = sp_records_by_id.get(sp_id)
            if sp_record is None:
                continue

            assignees, sp_completeness = cls._collect_family(
                client, f"/servicePrincipals/{sp_id}/appRoleAssignedTo",
                params={"$top": str(_PAGE_SIZE)},
                cap=_MAX_ASSIGNMENTS_PER_SP, _sleep_fn=_sleep_fn,
            )
            status_by_sp[sp_id] = sp_completeness
            if sp_completeness == FAMILY_DENIED:
                denied += 1
                continue
            if sp_completeness == FAMILY_UNAVAILABLE:
                other_failed += 1
                continue
            if sp_completeness == FAMILY_PARTIAL:
                cap_hit = True

            succeeded += 1
            seen_principal_ids: set = set()
            roles_by_id = roles_by_id_by_sp.get(sp_id, {})
            for raw_assignment in assignees:
                if not isinstance(raw_assignment, dict):
                    continue
                principal_id = raw_assignment.get("principalId")
                if not isinstance(principal_id, str) or not principal_id.strip():
                    continue
                if principal_id in seen_principal_ids:
                    continue  # dedup within a single SP's page set
                seen_principal_ids.add(principal_id)
                if total_records >= _MAX_TOTAL_APP_USER_ASSIGNMENTS + _MAX_TOTAL_APP_GROUP_ASSIGNMENTS + _MAX_TOTAL_SP_APP_ROLE_ASSIGNMENTS:
                    cap_hit = True
                    break

                principal_type = raw_assignment.get("principalType")
                if principal_type == GRAPH_PRINCIPAL_TYPE_USER:
                    user_record = user_index.get(principal_id)
                    rec = cls._normalize_app_user_assignment(
                        tenant_id, sp_record, user_record, raw_assignment, roles_by_id=roles_by_id,
                    )
                    if rec is not None:
                        user_assignments.append(rec)
                        total_records += 1
                elif principal_type == GRAPH_PRINCIPAL_TYPE_GROUP:
                    group_record = group_index.get(principal_id)
                    rec = cls._normalize_app_group_assignment(
                        tenant_id, sp_record, group_record, raw_assignment, roles_by_id=roles_by_id,
                    )
                    if rec is not None:
                        group_assignments.append(rec)
                        total_records += 1
                elif principal_type == GRAPH_PRINCIPAL_TYPE_SERVICE_PRINCIPAL:
                    principal_sp_record = sp_records_by_id.get(principal_id)
                    rec = cls._normalize_sp_app_role_assignment(
                        tenant_id, sp_record, principal_sp_record, raw_assignment, roles_by_id=roles_by_id,
                    )
                    if rec is not None:
                        sp_assignments.append(rec)
                        total_records += 1
                # An unrecognized future principalType is silently skipped
                # here (never mis-normalized as a user) — never raised,
                # since this is a data-shape surprise, not a call failure.

            if total_records >= _MAX_TOTAL_APP_USER_ASSIGNMENTS + _MAX_TOTAL_APP_GROUP_ASSIGNMENTS + _MAX_TOTAL_SP_APP_ROLE_ASSIGNMENTS:
                cap_hit = True
                break

        if succeeded == 0 and denied > 0 and other_failed == 0:
            completeness = FAMILY_DENIED
        elif succeeded == 0 and other_failed > 0:
            completeness = FAMILY_UNAVAILABLE
        elif denied > 0 or other_failed > 0 or cap_hit or truncated_sp_list:
            completeness = FAMILY_PARTIAL
        else:
            completeness = FAMILY_COMPLETE

        return user_assignments, group_assignments, sp_assignments, completeness, status_by_sp

    @classmethod
    def _fetch_oauth2_permission_grants(
        cls, client: httpx.Client, tenant_id: str, sp_by_id: dict,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        """Collect delegated OAuth2 consent grants tenant-wide via the flat
        ``/oauth2PermissionGrants`` collection — Graph exposes this as a
        single list (confirmed before implementation), so no per-app or
        per-user consent enumeration is needed here."""
        raw_items, completeness = cls._collect_family(
            client, "/oauth2PermissionGrants",
            params={"$top": str(_PAGE_SIZE)},
            cap=_MAX_OAUTH2_PERMISSION_GRANTS, _sleep_fn=_sleep_fn,
        )
        records = []
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            rec = cls._normalize_oauth2_permission_grant(tenant_id, raw, sp_by_id)
            if rec is not None:
                records.append(rec)
        return records, completeness

    # ── Capability probes ──────────────────────────────────────────────────
    #
    # Every probe is a single, minimal, read-only GET with the smallest
    # page size Graph accepts ($top=1 where applicable, or a bare singleton
    # read) — never a broad enumeration.

    _CAPABILITY_PROBES: tuple[tuple[str, str, dict], ...] = (
        (CAPABILITY_FAMILY_USERS, "/users", {"$top": "1"}),
        (CAPABILITY_FAMILY_GROUPS, "/groups", {"$top": "1"}),
        (CAPABILITY_FAMILY_APPLICATIONS, "/applications", {"$top": "1"}),
        (CAPABILITY_FAMILY_SERVICE_PRINCIPALS, "/servicePrincipals", {"$top": "1"}),
        (CAPABILITY_FAMILY_CONDITIONAL_ACCESS, "/identity/conditionalAccess/policies", {"$top": "1"}),
        # authenticationMethodsPolicy is a singleton resource — no $top.
        (CAPABILITY_FAMILY_AUTHENTICATION_METHODS, "/policies/authenticationMethodsPolicy", {}),
        (CAPABILITY_FAMILY_DIRECTORY_ROLES, "/directoryRoles", {"$top": "1"}),
        (CAPABILITY_FAMILY_OAUTH2_PERMISSION_GRANTS, "/oauth2PermissionGrants", {"$top": "1"}),
    )

    @staticmethod
    def _probe_one(client: httpx.Client, path: str, params: dict) -> str:
        """Return a CAPABILITY_* status string for one probe. Never raises —
        every failure mode maps to a status category instead."""
        outcome = call_graph(client, "GET", path, params=params or None)
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
        if outcome.category in (CATEGORY_CONNECTION_ERROR, CATEGORY_TIMEOUT, CATEGORY_TLS_ERROR):
            return CAPABILITY_UNAVAILABLE
        return CAPABILITY_UNKNOWN

    @classmethod
    def _probe_capabilities(cls, client: httpx.Client, tenant_id: str) -> list[dict]:
        records = []
        for family, path, params in cls._CAPABILITY_PROBES:
            status = cls._probe_one(client, path, params)
            records.append(cls._normalize_capability(tenant_id, family, status))
        return records

    # ── Public connector interface ─────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Verify Entra credentials with a token acquisition plus a single
        lightweight tenant-info call.

        Uses ``GET /organization`` — the narrowest official Microsoft
        Graph endpoint that simultaneously proves (a) the app-only token is
        accepted and (b) the tenant is reachable, without requiring any
        broader read permission (application permission
        ``Organization.Read.All`` — or the broader ``Directory.Read.All`` —
        is sufficient; no delegated user context is ever required).

        Raises:
            AuthenticationError: Token rejected, invalid tenant/client, or
                malformed credentials.
            ConnectorError: Microsoft Graph returned an unexpected error.
            NetworkError: Transport-level failure.
        """
        tenant_id, client_id, client_secret = self._credentials(credentials)
        token = self._get_token(credentials)
        with self._make_client(token) as client:
            outcome = call_graph(client, "GET", "/organization")
            _raise_for_outcome(outcome, context="GET /organization")
        return True

    def fetch(self, credentials: dict, *, _sleep_fn: Callable[[float], None] = None) -> list[dict]:
        """Fetch the Entra tenant identity + user/group/membership inventory
        + application/service-principal/assignment/consent inventory + API
        capability inventory: ``entra_organization``, ``entra_user``,
        ``entra_group``, ``entra_group_membership``, ``entra_application``,
        ``entra_service_principal``, ``entra_application_user_assignment``,
        ``entra_application_group_assignment``,
        ``entra_service_principal_app_role_assignment``,
        ``entra_oauth2_permission_grant``, ``entra_api_capability`` probes.

        Does NOT collect Conditional Access/authentication methods
        (message 4), or directory roles/privileged identities/consent
        expansion (message 5) yet — see the module docstring for the
        permanent sensitive-data boundary and ``entra_schema.py`` for what
        later messages will add.

        Every family (users/groups/memberships/applications/service
        principals/assignments/OAuth grants) fails independently: if e.g.
        group memberships are denied while users and groups are readable,
        the rest is still returned and
        ``entra_organization.family_completeness`` reports the gap — a
        family failure never aborts the whole fetch, and a denied/
        unreadable family is never silently reported as "zero" (see
        ``_collect_family``/``_fetch_memberships``/
        ``_fetch_app_role_assignments``).

        SECURITY: client_secret and access_token are used only within this
        method's scope (or the connector instance's token cache), never
        logged, and the access token is discarded when the connector
        instance is garbage-collected.

        Raises:
            AuthenticationError: Token rejected or malformed credentials.
            ConnectorError: Microsoft Graph returned an unexpected error
                fetching the organization record itself (every other family
                fails soft instead of raising — see ``_collect_family``).
            NetworkError: Transport-level failure reaching the org endpoint.
        """
        tenant_id, client_id, client_secret = self._credentials(credentials)
        token = self._get_token(credentials, _sleep_fn=_sleep_fn)

        records: list[dict] = []
        with self._make_client(token) as client:
            outcome = call_graph(client, "GET", "/organization", _sleep_fn=_sleep_fn)
            resp = _raise_for_outcome(outcome, context="GET /organization")
            try:
                body = resp.json()
            except ValueError as exc:
                raise ConnectorError("entra: /organization response was not valid JSON") from exc

            # Microsoft Graph's /organization endpoint returns a collection
            # (the tenant's own organization object is always the sole
            # member) — never a bare object.
            raw_org: dict = {}
            if isinstance(body, dict) and isinstance(body.get("value"), list) and body["value"]:
                first = body["value"][0]
                if isinstance(first, dict):
                    raw_org = first
            elif isinstance(body, dict) and "id" in body:
                # Defensive: tolerate a bare-object response shape too.
                raw_org = body

            stable_tenant_id = self.compute_tenant_id(tenant_id, raw_org)

            # ── Users ──────────────────────────────────────────────────────
            user_records, users_completeness = self._fetch_users(
                client, stable_tenant_id, _sleep_fn=_sleep_fn,
            )
            user_index = {u["user_id"]: u for u in user_records}

            # ── Groups (raw kept for membership walk; normalized after) ────
            raw_groups, groups_completeness = self._fetch_groups_raw(
                client, _sleep_fn=_sleep_fn,
            )
            group_records_by_id: dict = {}
            for raw_group in raw_groups:
                if not isinstance(raw_group, dict):
                    continue
                group_id = raw_group.get("id")
                if not isinstance(group_id, str) or not group_id.strip():
                    continue
                # membership_count filled in below once memberships are collected.
                rec = self._normalize_group(stable_tenant_id, raw_group, membership_count=None)
                if rec is not None:
                    group_records_by_id[group_id] = rec

            # ── Memberships ──────────────────────────────────────────────
            membership_records, memberships_completeness, counts_by_group, _status_by_group = (
                self._fetch_memberships(
                    client, stable_tenant_id, raw_groups, group_records_by_id, user_index,
                    _sleep_fn=_sleep_fn,
                )
            )

            # Backfill membership_count only for groups whose own membership
            # walk actually succeeded — a group whose walk was denied/failed
            # keeps membership_count=None (unknown), never 0.
            group_records: list[dict] = []
            group_index: dict = {}
            for group_id, group_rec in group_records_by_id.items():
                count = counts_by_group.get(group_id)
                group_rec["membership_count"] = count
                group_rec["membership_count_category"] = categorize_membership_count(count)
                group_records.append(group_rec)
                group_index[group_id] = group_rec

            # ── Applications ───────────────────────────────────────────────
            raw_applications, applications_completeness = self._fetch_applications_raw(
                client, _sleep_fn=_sleep_fn,
            )
            application_records: list[dict] = []
            for raw_app in raw_applications:
                if not isinstance(raw_app, dict):
                    continue
                rec = self._normalize_application(stable_tenant_id, raw_app)
                if rec is not None:
                    application_records.append(rec)

            # ── Service principals (raw kept for role-index + assignment
            #    walk; normalized after) ─────────────────────────────────────
            raw_sps, service_principals_completeness = self._fetch_service_principals_raw(
                client, _sleep_fn=_sleep_fn,
            )
            sp_records_by_id: dict = {}
            roles_by_id_by_sp: dict = {}
            for raw_sp in raw_sps:
                if not isinstance(raw_sp, dict):
                    continue
                sp_id = raw_sp.get("id")
                if not isinstance(sp_id, str) or not sp_id.strip():
                    continue
                rec = self._normalize_service_principal(stable_tenant_id, raw_sp, tenant_id)
                if rec is not None:
                    sp_records_by_id[sp_id] = rec
                # Local app-role index (id -> {value, ...}) built from the
                # SP's OWN raw appRoles array — never persisted onto the
                # normalized record, never a per-assignment Graph call.
                roles = raw_sp.get("appRoles") if isinstance(raw_sp.get("appRoles"), list) else []
                roles_by_id: dict = {}
                for role in roles:
                    if isinstance(role, dict) and isinstance(role.get("id"), str):
                        roles_by_id[role["id"]] = role
                roles_by_id_by_sp[sp_id] = roles_by_id

            # ── App-role assignments (user/group/service-principal) ────────
            (
                app_user_assignment_records, app_group_assignment_records,
                sp_app_role_assignment_records, assignments_completeness, _status_by_sp,
            ) = self._fetch_app_role_assignments(
                client, stable_tenant_id, raw_sps, sp_records_by_id, roles_by_id_by_sp,
                user_index, group_index, _sleep_fn=_sleep_fn,
            )

            # ── OAuth2 delegated permission grants (tenant-wide) ────────────
            oauth2_grant_records, oauth2_grants_completeness = self._fetch_oauth2_permission_grants(
                client, stable_tenant_id, sp_records_by_id, _sleep_fn=_sleep_fn,
            )

            org_record = self._normalize_organization(
                stable_tenant_id, raw_org,
                family_completeness={
                    "users": users_completeness,
                    "groups": groups_completeness,
                    "memberships": memberships_completeness,
                    "applications": applications_completeness,
                    "service_principals": service_principals_completeness,
                    "app_role_assignments": assignments_completeness,
                    "oauth2_permission_grants": oauth2_grants_completeness,
                },
            )

            records.append(org_record)
            records.extend(user_records)
            records.extend(group_records)
            records.extend(membership_records)
            records.extend(application_records)
            records.extend(sp_records_by_id.values())
            records.extend(app_user_assignment_records)
            records.extend(app_group_assignment_records)
            records.extend(sp_app_role_assignment_records)
            records.extend(oauth2_grant_records)
            records.extend(self._probe_capabilities(client, stable_tenant_id))

        # Deterministic ordering — API response ordering must never affect
        # the normalized snapshot or its fingerprint.
        records.sort(key=lambda r: (r["record_type"], r["record_id"]))
        return records
