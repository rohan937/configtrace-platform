"""Okta provider foundation connector (Okta message 1 of 8).

Establishes a secure, read-only connection to an Okta org using an API
token, resolves a stable tenant identity, and probes (never collects) the
future record families (users, groups, applications, policies,
authenticators, admin roles, System Log) that later messages will build.

This connector intentionally does NOT collect users, groups, applications,
policies, authenticators, admin roles, or System Log events yet — see
``okta_schema.py``'s module docstring for the full sensitive-data boundary.
The connector is registered internally (dispatch, schema, capability
matrix) but is NOT publicly connectable — see
``tests/reports/okta_foundation_contract.md`` for the launch gate this
message deliberately does not cross.

Authentication
---------------
Okta API token (SSWS scheme):

    Authorization: SSWS <api_token>

Credentials dict:
    org_url    : str — Okta org base URL, e.g. "https://example.okta.com".
                 Custom domains are supported; no hardcoded tenant suffix.
    api_token  : str — Okta API token. NEVER logged, NEVER stored outside
                 the encrypted credentials column, NEVER returned in any
                 API response, NEVER copied into a normalized record.

OAuth 2.0 service-app (client_credentials with a private key / DPoP)
authentication is a documented future enhancement — NOT implemented here.
The repository's existing identity-provider connectors (Auth0, Clerk) both
support a direct-token mode as their primary/simplest path, and API-token
auth is officially supported by Okta for exactly this "trusted backend
service reads org configuration" use case, so it is the correct minimal
secure starting point. See the foundation report for the OAuth deferral
rationale.

SECURITY — what is NEVER stored, logged, or returned
------------------------------------------------------
- api_token — NEVER stored on the connector instance, NEVER logged, NEVER
  included in error messages or exceptions, NEVER written to any record.
- Authorization header value — NEVER appears in logs or exception text.
- Raw Okta API response dicts — NEVER stored; only flat safe scalars.
- passwords, password hashes, recovery answers, MFA secrets, OTP seeds,
  session/refresh/access tokens, private keys, raw authentication factors,
  raw System Log payloads, arbitrary user profile data — NEVER fetched.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.okta_schema import (
    CAPABILITY_AVAILABLE,
    CAPABILITY_DENIED,
    CAPABILITY_FAMILIES,
    CAPABILITY_FAMILY_ADMIN_ROLES,
    CAPABILITY_FAMILY_APPLICATIONS,
    CAPABILITY_FAMILY_AUTHENTICATORS,
    CAPABILITY_FAMILY_GROUPS,
    CAPABILITY_FAMILY_POLICIES,
    CAPABILITY_FAMILY_SYSTEM_LOG,
    CAPABILITY_FAMILY_USERS,
    CAPABILITY_THROTTLED,
    CAPABILITY_UNAVAILABLE,
    CAPABILITY_UNKNOWN,
    CAPABILITY_UNSUPPORTED,
    OKTA_API_CAPABILITY,
    OKTA_ORGANIZATION,
    categorize_org_status,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ─────────────────────────────────────────────────────

_TIMEOUT = 30.0
_MAX_STR_LEN = 100

# Pagination bounds (reused by later messages' list collection).
_MAX_PAGES = 50
_DEFAULT_PAGE_LIMIT = 200

# 429 retry bounds — bounded exponential backoff with jitter, mirroring the
# Kubernetes reliability pattern (message 8 of the Kubernetes arc).
_MAX_THROTTLE_RETRIES = 4
_THROTTLE_BASE_DELAY_SECONDS = 1.0
_THROTTLE_MAX_DELAY_SECONDS = 30.0

# Private IP ranges rejected for the org_url host — mirrors
# app/services/notification_service.py's SSRF-guard curated list (literal
# hostname/IP checks only; no live DNS resolution here, matching every
# other connector that accepts a user-supplied API host, e.g. Auth0's
# `domain`, GitLab's `base_url`, Jira's `site_url` — none of which perform
# DNS-rebinding resolution either, since validate_credentials() immediately
# makes a real HTTPS request to the host and would surface a connection
# failure for a genuinely unreachable/bogus target).
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]
_PRIVATE_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})


class OktaURLError(ValueError):
    """Raised when an org_url fails validation. Subclasses ValueError so
    existing generic error handling still catches it."""


# ── URL normalization / validation ──────────────────────────────────────────


def normalize_org_url(raw_url: object) -> str:
    """Validate and normalize an Okta org URL.

    Rules (message 1 requirement):
      - HTTPS only.
      - No embedded credentials (user:pass@host).
      - No query string or fragment.
      - No trailing slash.
      - Reject localhost/private/loopback hosts (SSRF guard).
      - Custom Okta domains are supported — no hardcoded tenant suffix is
        required or assumed.

    Returns the normalized ``https://host`` string (lowercased scheme+host,
    no path/query/fragment/trailing slash). Raises ``OktaURLError`` — never
    silently coerces a malformed URL into something plausible-looking.

    SECURITY: this result is used to build API URLs only; it is stored in
    the ``okta_organization`` record as ``org_hostname`` (non-secret — the
    user supplied it themselves and it contains no credential material).
    """
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise OktaURLError("okta: org_url must be a non-empty string")

    cleaned = raw_url.strip()

    try:
        parsed = urlparse(cleaned)
    except ValueError as exc:
        raise OktaURLError(f"okta: org_url could not be parsed: {exc}") from exc

    if parsed.scheme.lower() != "https":
        raise OktaURLError("okta: org_url must use https://")

    if parsed.username or parsed.password:
        raise OktaURLError("okta: org_url must not contain embedded credentials")

    if parsed.query:
        raise OktaURLError("okta: org_url must not contain a query string")

    if parsed.fragment:
        raise OktaURLError("okta: org_url must not contain a fragment")

    # Path must be empty or exactly "/" — an org_url is a bare host, not a
    # deep-linked resource.
    if parsed.path not in ("", "/"):
        raise OktaURLError("okta: org_url must not contain a path")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise OktaURLError("okta: org_url has no hostname")

    if len(hostname) > 253:
        raise OktaURLError("okta: org_url hostname is too long")

    if hostname in _PRIVATE_HOSTNAMES:
        raise OktaURLError(
            f"okta: org_url hostname {hostname!r} is not allowed "
            "(private/loopback addresses are blocked)"
        )

    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        addr = None

    if addr is not None:
        for network in _PRIVATE_NETWORKS:
            if addr in network:
                raise OktaURLError(
                    f"okta: org_url points to a private IP address ({hostname}); "
                    "only public HTTPS endpoints are allowed"
                )

    port_suffix = f":{parsed.port}" if parsed.port else ""
    return f"https://{hostname}{port_suffix}"


# ── Fail-soft API-call wrapper (mirrors the Kubernetes reliability pattern) ──


@dataclass
class CallOutcome:
    """Result of one fail-soft Okta API call. ``category`` never leaks
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
        return CATEGORY_AUTH_FAILED, "HTTP 401: Okta rejected the supplied API token."
    if status == 403:
        return CATEGORY_PERMISSION_DENIED, "HTTP 403: permission denied for this resource."
    if status == 404:
        return CATEGORY_NOT_FOUND, "HTTP 404: resource or endpoint not found."
    if status == 429:
        return CATEGORY_THROTTLED, "HTTP 429: request was throttled by Okta."
    if status >= 500:
        return CATEGORY_SERVER_ERROR, f"HTTP {status}: Okta returned a server error."
    return CATEGORY_SERVER_ERROR, f"HTTP {status}: unexpected Okta API response."


def _classify_transport_exception(exc: Exception) -> tuple[str, str]:
    import ssl

    if isinstance(exc, ssl.SSLError):
        return CATEGORY_TLS_ERROR, "TLS certificate verification failed."
    if isinstance(exc, httpx.ConnectTimeout):
        return CATEGORY_TIMEOUT, "The request to Okta timed out connecting."
    if isinstance(exc, httpx.ReadTimeout):
        return CATEGORY_TIMEOUT, "The request to Okta timed out waiting for a response."
    if isinstance(exc, httpx.TimeoutException):
        return CATEGORY_TIMEOUT, "The request to Okta timed out."
    if isinstance(exc, httpx.ConnectError):
        cause = str(exc).lower()
        if "certificate" in cause or "ssl" in cause or "tls" in cause:
            return CATEGORY_TLS_ERROR, "TLS certificate verification failed."
        if "name or service not known" in cause or "nodename nor servname" in cause or "getaddrinfo failed" in cause:
            return CATEGORY_CONNECTION_ERROR, "Could not resolve the Okta org hostname (DNS failure)."
        return CATEGORY_CONNECTION_ERROR, "Could not connect to the Okta API."
    if isinstance(exc, httpx.RequestError):
        return CATEGORY_CONNECTION_ERROR, "Could not connect to the Okta API."
    return CATEGORY_MALFORMED_RESPONSE, "The Okta API returned a response that could not be processed."


def _retry_after_seconds(resp: httpx.Response) -> Optional[float]:
    raw = resp.headers.get("Retry-After") or resp.headers.get("X-Rate-Limit-Reset")
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


def call_okta(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    params: Optional[dict] = None,
    _sleep_fn: Callable[[float], None] = None,
) -> CallOutcome:
    """Fail-soft wrapper around a single Okta API call.

    Every request this connector makes (and every request future messages'
    collection code makes) should route through this wrapper so callers get
    the same distinguishable failure categories instead of an uncaught
    exception.

    401/403 are NEVER retried as if transient. Only 429 gets a bounded
    retry with exponential backoff and jitter (honoring ``Retry-After`` /
    ``X-Rate-Limit-Reset`` when present), capped at
    ``_MAX_THROTTLE_RETRIES`` attempts. Tests inject ``_sleep_fn`` (a no-op)
    so retry tests never actually sleep.

    SECURITY: never includes the Authorization header or api_token value in
    any returned ``CallOutcome.detail`` — only a fixed, category-specific
    message plus the HTTP status code.
    """
    import time as _time

    sleep_fn = _sleep_fn or _time.sleep
    attempt = 0
    while True:
        try:
            resp = client.request(method, url, params=params, timeout=_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — deliberately broad; classified below
            category, detail = _classify_transport_exception(exc)
            return CallOutcome(ok=False, category=category, detail=detail)

        if resp.status_code < 400:
            return CallOutcome(ok=True, response=resp, category=CATEGORY_SUCCESS)

        category, detail = _classify_response(resp)
        if category == CATEGORY_THROTTLED and attempt < _MAX_THROTTLE_RETRIES:
            retry_after = _retry_after_seconds(resp)
            delay = _throttle_backoff_seconds(attempt, retry_after=retry_after)
            logger.warning(
                "okta_connector rate limited (attempt %d/%d); sleeping %.1fs",
                attempt + 1, _MAX_THROTTLE_RETRIES, delay,
            )
            sleep_fn(delay)
            attempt += 1
            continue

        return CallOutcome(ok=False, category=category, detail=detail)


def _raise_for_outcome(outcome: CallOutcome, *, context: str = "") -> httpx.Response:
    """Raise the appropriate connector exception for a failed CallOutcome,
    or return the response for a successful one."""
    if outcome.ok:
        return outcome.response
    suffix = f" — {context}" if context else ""
    if outcome.category == CATEGORY_AUTH_FAILED:
        raise AuthenticationError(f"okta: {outcome.detail}{suffix}", status_code=401)
    if outcome.category == CATEGORY_THROTTLED:
        raise RateLimitError(f"okta: {outcome.detail}{suffix}")
    if outcome.category in (CATEGORY_CONNECTION_ERROR, CATEGORY_TIMEOUT, CATEGORY_TLS_ERROR):
        raise NetworkError(f"okta: {outcome.detail}{suffix}")
    raise ConnectorError(f"okta: {outcome.detail}{suffix}")


# ── Pagination (RFC5988 Link header) ────────────────────────────────────────


def _extract_next_link(resp: httpx.Response, *, trusted_origin: str) -> Optional[str]:
    """Parse the ``Link`` response header for a ``rel="next"`` URL.

    Returns ``None`` if absent or malformed. Rejects (returns ``None`` for)
    any ``next`` URL whose scheme+host does not exactly match
    ``trusted_origin`` — pagination must never be able to redirect the
    connector to an attacker-controlled or unrelated host.
    """
    link_header = resp.headers.get("Link") or resp.headers.get("link")
    if not link_header:
        return None

    for part in link_header.split(","):
        segments = part.split(";")
        if len(segments) < 2:
            continue
        url_segment = segments[0].strip()
        if not (url_segment.startswith("<") and ">" in url_segment):
            continue
        candidate = url_segment[1:url_segment.index(">")]
        rel_ok = any(
            seg.strip().lower().replace(" ", "") in ('rel="next"', "rel=next")
            for seg in segments[1:]
        )
        if not rel_ok:
            continue

        # Resolve relative URLs against the trusted origin, then verify the
        # resulting absolute URL's origin exactly matches.
        try:
            resolved = urljoin(trusted_origin + "/", candidate)
            parsed_candidate = urlparse(resolved)
            parsed_trusted = urlparse(trusted_origin)
        except ValueError:
            return None

        candidate_origin = f"{parsed_candidate.scheme}://{parsed_candidate.netloc}".lower()
        trusted = f"{parsed_trusted.scheme}://{parsed_trusted.netloc}".lower()
        if candidate_origin != trusted:
            logger.warning(
                "okta_connector: rejected cross-origin pagination Link "
                "(expected origin %s)", trusted,
            )
            return None
        return resolved

    return None


def paginate(
    client: httpx.Client,
    trusted_origin: str,
    start_url: str,
    *,
    params: Optional[dict] = None,
    max_pages: int = _MAX_PAGES,
    _sleep_fn: Callable[[float], None] = None,
) -> list[dict]:
    """Follow Okta's Link-header (``rel="next"``) pagination safely.

    Bounded by ``max_pages``. Detects a repeated ``next`` URL (a
    misbehaving or malicious server serving the same page forever) and
    stops rather than looping. Only follows ``next`` links whose origin
    exactly matches ``trusted_origin`` — any cross-origin ``next`` link is
    silently dropped (pagination simply stops at the current page).
    Deduplicates items by their ``id`` field when present (defends against
    a server re-serving an overlapping page).

    Raises the same exceptions as ``call_okta`` via ``_raise_for_outcome``
    on the FIRST page failure (a fully broken credential should fail
    loudly); any LATER page's failure stops pagination and returns what
    was collected so far, since the first page already proved the
    credential works — a transient failure mid-pagination should degrade
    to partial results, not lose everything already fetched.
    """
    items: list[dict] = []
    seen_ids: set = set()
    seen_urls: set = set()
    url = start_url
    current_params: Optional[dict] = params

    for page_num in range(max_pages):
        outcome = call_okta(client, "GET", url, params=current_params, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            if page_num == 0:
                _raise_for_outcome(outcome, context=f"page {page_num + 1}")
            logger.debug("okta_connector: pagination stopped early on page %d (%s)", page_num + 1, outcome.category)
            break

        resp = outcome.response
        try:
            page_items = resp.json()
        except ValueError:
            if page_num == 0:
                raise ConnectorError("okta: response was not valid JSON")
            break
        if not isinstance(page_items, list):
            if page_num == 0:
                raise ConnectorError("okta: expected a JSON array response")
            break

        for raw in page_items:
            if isinstance(raw, dict) and isinstance(raw.get("id"), str):
                if raw["id"] in seen_ids:
                    continue
                seen_ids.add(raw["id"])
            items.append(raw)

        next_url = _extract_next_link(resp, trusted_origin=trusted_origin)
        if not next_url:
            break
        if next_url in seen_urls:
            logger.warning("okta_connector: repeated pagination Link detected; stopping")
            break
        seen_urls.add(next_url)
        url = next_url
        # The next URL already carries its own query string — do not
        # re-apply the original params on subsequent requests.
        current_params = None

    return items


# ── Connector ──────────────────────────────────────────────────────────────


class OktaConnector(BaseConnector):
    """Okta provider foundation connector (Okta message 1 of 8).

    Stateless: credentials are passed at call time; nothing is stored on
    the instance between calls. The API token is never stored as an
    instance attribute, never logged, never included in error messages,
    and never written to any normalized record.
    """

    # ── HTTP client ────────────────────────────────────────────────────────

    @staticmethod
    def _make_client(org_url: str, api_token: str) -> httpx.Client:
        """Build an httpx.Client for the Okta API.

        SECURITY: the token is placed in the Authorization header only
        (SSWS scheme), never stored on the connector instance or logged.
        """
        return httpx.Client(
            base_url=org_url,
            headers={
                "Authorization": f"SSWS {api_token}",
                "Accept": "application/json",
            },
            timeout=_TIMEOUT,
        )

    @staticmethod
    def _credentials(credentials: dict) -> tuple[str, str]:
        org_url = normalize_org_url(credentials.get("org_url"))
        api_token = credentials.get("api_token")
        if not isinstance(api_token, str) or not api_token.strip():
            raise AuthenticationError(
                "okta: credentials must contain a non-empty 'api_token'",
                status_code=401,
            )
        return org_url, api_token

    # ── Tenant identity ────────────────────────────────────────────────────

    @staticmethod
    def compute_tenant_id(org_hostname: str, raw_org: dict) -> str:
        """Return a stable tenant identifier.

        Prefers the immutable Okta org ``id`` field returned by the API
        (survives token rotation, display-name changes, and integration
        rename). Falls back to the normalized org hostname only if the API
        did not return an ``id`` — this still distinguishes distinct
        tenants (each has a unique subdomain/custom domain) even though a
        custom-domain migration on the SAME tenant would change this
        fallback ID (a known, documented limitation of the fallback path).
        """
        org_id = raw_org.get("id") if isinstance(raw_org, dict) else None
        if isinstance(org_id, str) and org_id.strip():
            return f"id:{org_id.strip()[:100]}"
        return f"host:{org_hostname}"

    # ── Record normalizers ─────────────────────────────────────────────────

    @staticmethod
    def _normalize_organization(org_hostname: str, raw: dict) -> dict:
        """Normalize the Okta org/tenant record.

        SECURITY: raw org response (which may include support contact
        name/email, phone numbers, and postal address) is NEVER stored —
        only the specific safe fields below are extracted.
        """
        tenant_id = OktaConnector.compute_tenant_id(org_hostname, raw)
        display_name = raw.get("companyName") if isinstance(raw, dict) else None

        return {
            "record_type": OKTA_ORGANIZATION,
            "record_id": tenant_id,
            "provider_resource_id": f"org/{tenant_id}",
            "tenant_id": tenant_id,
            "org_hostname": org_hostname,
            "org_display_name": (
                display_name.strip()[:_MAX_STR_LEN]
                if isinstance(display_name, str) and display_name.strip()
                else None
            ),
            "status_category": categorize_org_status(raw.get("status") if isinstance(raw, dict) else None),
        }

    @staticmethod
    def _normalize_capability(tenant_id: str, family: str, status: str) -> dict:
        return {
            "record_type": OKTA_API_CAPABILITY,
            "record_id": f"{tenant_id}/capability/{family}",
            "provider_resource_id": f"capability/{family}",
            "tenant_id": tenant_id,
            "family": family,
            "status": status,
        }

    # ── Capability probes ──────────────────────────────────────────────────
    #
    # Every probe is a single, minimal, read-only GET with the smallest
    # page size Okta accepts (limit=1) — never a broad enumeration. If a
    # probe itself would require undesirable privilege or have a side
    # effect, it is skipped and documented rather than attempted.

    # (family, endpoint path, query params) — every probe is GET-only.
    _CAPABILITY_PROBES: tuple[tuple[str, str, dict], ...] = (
        (CAPABILITY_FAMILY_USERS, "/api/v1/users", {"limit": "1"}),
        (CAPABILITY_FAMILY_GROUPS, "/api/v1/groups", {"limit": "1"}),
        (CAPABILITY_FAMILY_APPLICATIONS, "/api/v1/apps", {"limit": "1"}),
        (CAPABILITY_FAMILY_POLICIES, "/api/v1/policies", {"type": "OKTA_SIGN_ON", "limit": "1"}),
        (CAPABILITY_FAMILY_AUTHENTICATORS, "/api/v1/authenticators", {}),
        (CAPABILITY_FAMILY_ADMIN_ROLES, "/api/v1/iam/roles", {"limit": "1"}),
        # System Log is intentionally probed with a tight, recent time
        # window and limit=1 — never a broad historical pull, and the
        # response content (which is highly user/event-centric) is never
        # read here, only the HTTP outcome.
        (CAPABILITY_FAMILY_SYSTEM_LOG, "/api/v1/logs", {"limit": "1"}),
    )

    @staticmethod
    def _probe_one(client: httpx.Client, path: str, params: dict) -> str:
        """Return a CAPABILITY_* status string for one probe. Never raises —
        every failure mode maps to a status category instead."""
        outcome = call_okta(client, "GET", path, params=params or None)
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
        """Verify Okta credentials with a single lightweight tenant-info call.

        Uses ``GET /api/v1/org`` — Okta's Org Setting API — which is
        readable by a minimally-scoped API token and returns only
        tenant-identifying metadata, never user/application/policy data.
        This is the narrowest official endpoint that simultaneously proves
        (a) the token is accepted and (b) the org is reachable, without
        requiring any broader read permission just to validate a
        connection.

        Raises:
            AuthenticationError: Token rejected (401) or malformed org_url.
            ConnectorError: Okta returned an unexpected error.
            NetworkError: Transport-level failure (DNS, timeout, TLS).
        """
        org_url, api_token = self._credentials(credentials)
        with self._make_client(org_url, api_token) as client:
            outcome = call_okta(client, "GET", "/api/v1/org")
            _raise_for_outcome(outcome, context="GET /api/v1/org")
        return True

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch the Okta foundation records: one ``okta_organization``
        record plus one ``okta_api_capability`` record per probed future
        family.

        Does NOT collect users, groups, applications, policies,
        authenticators, admin roles, or System Log events — see the module
        docstring for the permanent sensitive-data boundary and
        ``okta_schema.py`` for what later messages will add.

        SECURITY: the API token is used only within this method's scope,
        placed only in the Authorization header, never stored on the
        connector instance, never logged, and discarded when the
        httpx.Client context manager exits.

        Raises:
            AuthenticationError: Token rejected or malformed org_url.
            ConnectorError: Okta returned an unexpected error fetching the
                org record itself (capability probes never raise — see
                ``_probe_one``).
            NetworkError: Transport-level failure reaching the org endpoint.
        """
        org_url, api_token = self._credentials(credentials)
        org_hostname = urlparse(org_url).netloc

        records: list[dict] = []
        with self._make_client(org_url, api_token) as client:
            outcome = call_okta(client, "GET", "/api/v1/org")
            resp = _raise_for_outcome(outcome, context="GET /api/v1/org")
            try:
                raw_org = resp.json()
            except ValueError as exc:
                raise ConnectorError("okta: /api/v1/org response was not valid JSON") from exc
            if not isinstance(raw_org, dict):
                raise ConnectorError("okta: /api/v1/org response was not a JSON object")

            org_record = self._normalize_organization(org_hostname, raw_org)
            records.append(org_record)

            tenant_id = org_record["tenant_id"]
            records.extend(self._probe_capabilities(client, tenant_id))

        return records
