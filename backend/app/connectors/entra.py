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
    ENTRA_ORGANIZATION,
    categorize_on_premises_sync,
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
        tenant_id: str, raw: dict, *, capability_note: Optional[str] = None,
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
        """Fetch the Entra tenant identity + API capability inventory:
        ``entra_organization``, ``entra_api_capability`` probes.

        Does NOT collect users/groups/applications/service principals/
        Conditional Access/authentication methods/directory roles/consent
        grants yet — see the module docstring for the permanent sensitive-
        data boundary and ``entra_schema.py`` for what later messages will
        add.

        SECURITY: client_secret and access_token are used only within this
        method's scope (or the connector instance's token cache), never
        logged, and the access token is discarded when the connector
        instance is garbage-collected.

        Raises:
            AuthenticationError: Token rejected or malformed credentials.
            ConnectorError: Microsoft Graph returned an unexpected error
                fetching the organization record itself (capability probes
                fail soft instead of raising — see ``_probe_capabilities``).
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
            org_record = self._normalize_organization(stable_tenant_id, raw_org)
            records.append(org_record)
            records.extend(self._probe_capabilities(client, stable_tenant_id))

        return records
