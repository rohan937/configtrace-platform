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
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    FAMILY_PARTIAL,
    FAMILY_UNAVAILABLE,
    OKTA_API_CAPABILITY,
    OKTA_APPLICATION,
    OKTA_APPLICATION_GROUP_ASSIGNMENT,
    OKTA_APPLICATION_USER_ASSIGNMENT,
    OKTA_GROUP,
    OKTA_GROUP_MEMBERSHIP,
    OKTA_ORGANIZATION,
    OKTA_USER,
    categorize_algorithm,
    categorize_app_status,
    categorize_app_type,
    categorize_assignment_scope,
    categorize_group_type,
    categorize_last_login,
    categorize_membership_count,
    categorize_org_status,
    categorize_redirect_uris,
    categorize_sign_on_mode,
    categorize_token_auth_method,
    categorize_user_status,
    is_everyone_group,
    lifecycle_posture_for_status,
    protocol_category_for_sign_on_mode,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ─────────────────────────────────────────────────────

_TIMEOUT = 30.0
_MAX_STR_LEN = 100

# Pagination bounds (reused by later messages' list collection).
_MAX_PAGES = 50
_DEFAULT_PAGE_LIMIT = 200

# ── Identity collection bounds (Okta message 2) ─────────────────────────────
#
# Per-family caps bound pathological cases (a tenant with far more objects
# than any real Okta org would have) without imposing a flaky timing
# threshold. Membership enumeration is per-group (see fetch_memberships()
# docstring for the call-complexity rationale), so it additionally needs a
# cap on the number of groups walked and a global cap on total membership
# records collected, to bound the worst case where many large groups exist.
_MAX_USERS = 20_000
_MAX_GROUPS = 5_000
_MAX_MEMBERS_PER_GROUP = 20_000
_MAX_GROUPS_FOR_MEMBERSHIP_ENUMERATION = 5_000
_MAX_TOTAL_MEMBERSHIPS = 200_000

# ── Application collection bounds (Okta message 3) ──────────────────────────
#
# Same rationale as the identity bounds above — assignment enumeration is
# per-app (see _fetch_app_assignments() docstring), so this additionally
# needs a cap on the number of apps walked and global caps on total
# assignment records collected.
_MAX_APPLICATIONS = 5_000
_MAX_ASSIGNEES_PER_APP = 20_000
_MAX_APPS_FOR_ASSIGNMENT_ENUMERATION = 5_000
_MAX_TOTAL_USER_ASSIGNMENTS = 200_000
_MAX_TOTAL_GROUP_ASSIGNMENTS = 200_000
_MAX_REDIRECT_URIS = 200

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


# Representative HTTP status codes for the categories that raise a plain
# ConnectorError — lets callers (e.g. message 2's family-completeness
# logic) distinguish "denied" (403) from other unexpected errors via
# ``exc.status_code`` without needing a second round-trip.
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
        raise AuthenticationError(f"okta: {outcome.detail}{suffix}", status_code=401)
    if outcome.category == CATEGORY_THROTTLED:
        raise RateLimitError(f"okta: {outcome.detail}{suffix}")
    if outcome.category in (CATEGORY_CONNECTION_ERROR, CATEGORY_TIMEOUT, CATEGORY_TLS_ERROR):
        raise NetworkError(f"okta: {outcome.detail}{suffix}")
    raise ConnectorError(
        f"okta: {outcome.detail}{suffix}",
        status_code=_CATEGORY_STATUS_CODE.get(outcome.category),
    )


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
    def _normalize_organization(
        org_hostname: str, raw: dict, *, family_completeness: Optional[dict] = None,
    ) -> dict:
        """Normalize the Okta org/tenant record.

        SECURITY: raw org response (which may include support contact
        name/email, phone numbers, and postal address) is NEVER stored —
        only the specific safe fields below are extracted.

        ``family_completeness`` (message 2) reports what actually happened
        collecting users/groups/memberships this fetch — e.g.
        ``{"users": "complete", "groups": "complete", "memberships": "denied"}``
        — informational only, never diff-tracked (see
        ``diff_service._OKTA_TRACKED_FIELDS_BY_TYPE``), so a permission
        change alone never produces a noisy Change on its own.
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
            "family_completeness": dict(family_completeness) if family_completeness else {},
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

    # ── User / group / membership normalizers (Okta message 2) ─────────────

    @staticmethod
    def _normalize_user(tenant_id: str, raw: dict) -> Optional[dict]:
        """Normalize one Okta user record.

        SECURITY: only the fields explicitly listed below are ever read
        from ``raw``. ``raw["credentials"]`` is touched ONLY at the single
        path ``credentials.provider.type`` (a short categorical string,
        e.g. "OKTA"/"IMPORT"/"FEDERATION" — never the password/
        recovery_question sub-objects). ``raw["profile"]`` is touched ONLY
        at ``profile.login``, ``profile.firstName``, ``profile.lastName``
        — never iterated/copied wholesale, so arbitrary custom profile
        attributes (phone, address, department, title, manager, etc.) can
        never leak in even if present in a real tenant's profile map.
        """
        user_id = raw.get("id")
        if not isinstance(user_id, str) or not user_id.strip():
            return None

        profile = raw.get("profile") if isinstance(raw.get("profile"), dict) else {}
        login = profile.get("login")
        login = login.strip()[:_MAX_STR_LEN] if isinstance(login, str) and login.strip() else None

        first_name = profile.get("firstName")
        last_name = profile.get("lastName")
        display_name_parts = [
            p.strip() for p in (first_name, last_name)
            if isinstance(p, str) and p.strip()
        ]
        display_name = " ".join(display_name_parts)[:_MAX_STR_LEN] if display_name_parts else None

        status = categorize_user_status(raw.get("status"))
        posture = lifecycle_posture_for_status(status)

        user_type = raw.get("type") if isinstance(raw.get("type"), dict) else {}
        user_type_id = user_type.get("id")
        user_type_id = user_type_id.strip()[:_MAX_STR_LEN] if isinstance(user_type_id, str) and user_type_id.strip() else None

        credentials = raw.get("credentials") if isinstance(raw.get("credentials"), dict) else {}
        cred_provider = credentials.get("provider") if isinstance(credentials.get("provider"), dict) else {}
        credential_provider_category = cred_provider.get("type")
        credential_provider_category = (
            credential_provider_category.strip()[:30]
            if isinstance(credential_provider_category, str) and credential_provider_category.strip()
            else None
        )

        created = raw.get("created") if isinstance(raw.get("created"), str) else None
        activated = raw.get("activated") if isinstance(raw.get("activated"), str) else None

        return {
            "record_type": OKTA_USER,
            "record_id": f"{tenant_id}/user/{user_id}",
            "provider_resource_id": f"users/{user_id}",
            "tenant_id": tenant_id,
            "user_id": user_id,
            "login": login,
            "display_name": display_name,
            "status": status,
            "lifecycle_posture": posture,
            "active": status == "ACTIVE",
            "staged": status == "STAGED",
            "provisioned": status == "PROVISIONED",
            "recovery": status == "RECOVERY",
            "locked_out": status == "LOCKED_OUT",
            "password_expired": status == "PASSWORD_EXPIRED",
            "suspended": status == "SUSPENDED",
            "deprovisioned": status == "DEPROVISIONED",
            "user_type_id": user_type_id,
            "credential_provider_category": credential_provider_category,
            "last_login_category": categorize_last_login(raw.get("lastLogin")),
            "created": created,
            "activated": activated,
        }

    @staticmethod
    def _normalize_group(
        tenant_id: str, raw: dict, *, membership_count: Optional[int],
    ) -> Optional[dict]:
        """Normalize one Okta group record.

        SECURITY: ``raw["profile"]`` is touched ONLY at ``profile.name``
        and ``profile.description`` — never iterated wholesale, so
        arbitrary group profile attributes can never leak in.
        """
        group_id = raw.get("id")
        if not isinstance(group_id, str) or not group_id.strip():
            return None

        profile = raw.get("profile") if isinstance(raw.get("profile"), dict) else {}
        group_name = profile.get("name")
        group_name = group_name.strip()[:_MAX_STR_LEN] if isinstance(group_name, str) and group_name.strip() else None

        description = profile.get("description")
        description = description.strip()[:200] if isinstance(description, str) and description.strip() else None

        group_type = categorize_group_type(raw.get("type"))

        return {
            "record_type": OKTA_GROUP,
            "record_id": f"{tenant_id}/group/{group_id}",
            "provider_resource_id": f"groups/{group_id}",
            "tenant_id": tenant_id,
            "group_id": group_id,
            "group_name": group_name,
            "group_type": group_type,
            "description": description,
            "built_in": group_type == "BUILT_IN",
            "everyone_group": is_everyone_group(group_type, group_name),
            "membership_count": membership_count,
            "membership_count_category": categorize_membership_count(membership_count),
        }

    @staticmethod
    def _normalize_membership(
        tenant_id: str, user_record: Optional[dict], group_record: dict, user_id: str,
    ) -> dict:
        """Normalize one user<->group membership edge.

        Never duplicates the full user/group record — only denormalizes
        the small set of display/context fields a Change or Finding needs
        (login, group name/type, user status) so downstream consumers
        don't need a join back to the full records.
        """
        group_id = group_record["group_id"]
        user_login = user_record.get("login") if user_record else None
        user_status = user_record.get("status") if user_record else "UNKNOWN"

        return {
            "record_type": OKTA_GROUP_MEMBERSHIP,
            "record_id": f"{tenant_id}/membership/{group_id}/{user_id}",
            "provider_resource_id": f"groups/{group_id}/users/{user_id}",
            "tenant_id": tenant_id,
            "user_id": user_id,
            "group_id": group_id,
            "user_login": user_login,
            "group_name": group_record.get("group_name"),
            "group_type": group_record.get("group_type"),
            "user_status": user_status,
            "built_in_group": bool(group_record.get("built_in")),
        }

    # ── Application normalizers (Okta message 3) ────────────────────────────

    @staticmethod
    def _normalize_application(
        tenant_id: str, raw: dict, *,
        user_assignment_count: Optional[int], group_assignment_count: Optional[int],
    ) -> Optional[dict]:
        """Normalize one Okta application record.

        SECURITY: ``raw["credentials"]`` is touched ONLY at
        ``credentials.signing.rotationMode`` — never
        ``credentials.oauthClient.client_secret`` (which Okta's GET
        /api/v1/apps response DOES include in plaintext for OIDC apps —
        this is a well-known Okta API characteristic, not a hypothetical
        risk) and never any other credentials sub-field. ``raw["settings"]``
        is touched only at the specific safe sub-paths documented in
        ``_normalize_saml_posture``/``_normalize_oidc_posture`` below —
        never copied wholesale. ``raw["profile"]`` (app-instance profile
        overrides) is never read at all.
        """
        app_id = raw.get("id")
        if not isinstance(app_id, str) or not app_id.strip():
            return None

        label = raw.get("label")
        label = label.strip()[:_MAX_STR_LEN] if isinstance(label, str) and label.strip() else None

        status = categorize_app_status(raw.get("status"))
        sign_on_mode = categorize_sign_on_mode(raw.get("signOnMode"))
        protocol_category = protocol_category_for_sign_on_mode(sign_on_mode)

        visibility = raw.get("visibility") if isinstance(raw.get("visibility"), dict) else {}
        hide = visibility.get("hide") if isinstance(visibility.get("hide"), dict) else {}
        hidden_from_self_service = bool(hide.get("web")) if isinstance(hide.get("web"), bool) else None
        auto_submit = visibility.get("autoSubmitToolbar")
        auto_submit = bool(auto_submit) if isinstance(auto_submit, bool) else None

        credentials = raw.get("credentials") if isinstance(raw.get("credentials"), dict) else {}
        signing = credentials.get("signing") if isinstance(credentials.get("signing"), dict) else {}
        signing_key_rotation_category = signing.get("rotationMode")
        signing_key_rotation_category = (
            signing_key_rotation_category.strip()[:30]
            if isinstance(signing_key_rotation_category, str) and signing_key_rotation_category.strip()
            else None
        )

        record: dict = {
            "record_type": OKTA_APPLICATION,
            "record_id": f"{tenant_id}/app/{app_id}",
            "provider_resource_id": f"apps/{app_id}",
            "tenant_id": tenant_id,
            "app_id": app_id,
            "label": label,
            "status": status,
            "active": status == "ACTIVE",
            "sign_on_mode": sign_on_mode,
            "protocol_category": protocol_category,
            "hidden_from_self_service": hidden_from_self_service,
            "auto_submit_toolbar": auto_submit,
            "signing_key_rotation_category": signing_key_rotation_category,
            "user_assignment_count": user_assignment_count,
            "group_assignment_count": group_assignment_count,
        }

        settings = raw.get("settings") if isinstance(raw.get("settings"), dict) else {}
        if protocol_category == "SAML":
            record.update(OktaConnector._normalize_saml_posture(settings))
        elif protocol_category == "OIDC_OAUTH":
            record.update(OktaConnector._normalize_oidc_posture(settings))

        return record

    @staticmethod
    def _normalize_saml_posture(settings: dict) -> dict:
        """Extract safe SAML configuration posture from
        ``app.settings.signOn`` ONLY. Never touches certificates, private
        keys, or raw XML metadata — those are not returned by this
        endpoint and would never be read even if they were.
        """
        sign_on = settings.get("signOn") if isinstance(settings.get("signOn"), dict) else {}
        return {
            "saml_destination_configured": bool(sign_on.get("destination")),
            "saml_audience_configured": bool(sign_on.get("audience")),
            "saml_response_signed": (
                bool(sign_on["responseSigned"]) if isinstance(sign_on.get("responseSigned"), bool) else None
            ),
            "saml_assertion_signed": (
                bool(sign_on["assertionSigned"]) if isinstance(sign_on.get("assertionSigned"), bool) else None
            ),
            "saml_signature_algorithm_category": categorize_algorithm(sign_on.get("signatureAlgorithm")),
            "saml_digest_algorithm_category": categorize_algorithm(sign_on.get("digestAlgorithm")),
            "saml_encryption_enabled": (
                bool(sign_on["assertionEncrypted"]) if isinstance(sign_on.get("assertionEncrypted"), bool) else None
            ),
        }

    @staticmethod
    def _normalize_oidc_posture(settings: dict) -> dict:
        """Extract safe OIDC/OAuth configuration posture from
        ``app.settings.oauthClient`` ONLY. Redirect URIs are summarized
        into counts/booleans and NEVER stored raw — see
        ``categorize_redirect_uris()``. Never touches ``client_secret``
        (that lives under ``credentials.oauthClient``, not ``settings``,
        and is never read by this method or any other in this module).
        """
        oauth = settings.get("oauthClient") if isinstance(settings.get("oauthClient"), dict) else {}

        redirect_uris = oauth.get("redirect_uris")
        redirect_posture = categorize_redirect_uris(
            redirect_uris[:_MAX_REDIRECT_URIS] if isinstance(redirect_uris, list) else redirect_uris
        )
        logout_uris = oauth.get("post_logout_redirect_uris")
        logout_redirect_count = len(logout_uris) if isinstance(logout_uris, list) else None

        grant_types = oauth.get("grant_types") if isinstance(oauth.get("grant_types"), list) else []
        response_types = oauth.get("response_types") if isinstance(oauth.get("response_types"), list) else []

        return {
            "app_type_category": categorize_app_type(oauth.get("application_type")),
            "token_endpoint_auth_method_category": categorize_token_auth_method(
                oauth.get("token_endpoint_auth_method")
            ),
            "grant_types_summary": ",".join(sorted(g for g in grant_types if isinstance(g, str)))[:200],
            "response_types_summary": ",".join(sorted(r for r in response_types if isinstance(r, str)))[:200],
            "logout_redirect_count": logout_redirect_count,
            **redirect_posture,
        }

    @staticmethod
    def _normalize_app_user_assignment(
        tenant_id: str, app_record: dict, user_record: Optional[dict], raw: dict,
    ) -> Optional[dict]:
        """Normalize one user<->app assignment edge.

        SECURITY: ``raw["credentials"]`` (app-user username/password
        template) and ``raw["profile"]`` (app-user custom profile
        mapping) are NEVER read — only ``id``, ``status``, and ``scope``.
        """
        user_id = raw.get("id")
        if not isinstance(user_id, str) or not user_id.strip():
            return None

        app_id = app_record["app_id"]
        user_login = user_record.get("login") if user_record else None
        user_status = user_record.get("status") if user_record else "UNKNOWN"

        return {
            "record_type": OKTA_APPLICATION_USER_ASSIGNMENT,
            "record_id": f"{tenant_id}/app_assignment/{app_id}/user/{user_id}",
            "provider_resource_id": f"apps/{app_id}/users/{user_id}",
            "tenant_id": tenant_id,
            "app_id": app_id,
            "app_label": app_record.get("label"),
            "user_id": user_id,
            "user_login": user_login,
            "user_status": user_status,
            "assignment_status_category": categorize_app_status(raw.get("status")),
            "assignment_scope_category": categorize_assignment_scope(raw.get("scope")),
        }

    @staticmethod
    def _normalize_app_group_assignment(
        tenant_id: str, app_record: dict, group_record: Optional[dict], raw: dict,
    ) -> Optional[dict]:
        """Normalize one group<->app assignment edge.

        SECURITY: only ``id`` (and, defensively, ``priority`` — a plain
        integer, never sensitive) is ever read from the raw assignment
        object; no entitlement/profile-mapping payload is read.
        """
        group_id = raw.get("id")
        if not isinstance(group_id, str) or not group_id.strip():
            return None

        app_id = app_record["app_id"]
        return {
            "record_type": OKTA_APPLICATION_GROUP_ASSIGNMENT,
            "record_id": f"{tenant_id}/app_assignment/{app_id}/group/{group_id}",
            "provider_resource_id": f"apps/{app_id}/groups/{group_id}",
            "tenant_id": tenant_id,
            "app_id": app_id,
            "app_label": app_record.get("label"),
            "group_id": group_id,
            "group_name": group_record.get("group_name") if group_record else None,
            "group_type": group_record.get("group_type") if group_record else "unknown",
            "built_in_group": bool(group_record.get("built_in")) if group_record else False,
            "everyone_group": bool(group_record.get("everyone_group")) if group_record else False,
        }

    # ── Family collection (Okta message 2) ──────────────────────────────────

    @staticmethod
    def _collect_family(
        client: httpx.Client,
        trusted_origin: str,
        path: str,
        *,
        params: Optional[dict],
        cap: int,
        _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        """Paginate a whole family (users/groups) and report what actually
        happened, rather than raising and aborting the whole fetch.

        Returns ``(items, completeness)`` where completeness is one of
        ``FAMILY_COMPLETE`` / ``FAMILY_PARTIAL`` / ``FAMILY_DENIED`` /
        ``FAMILY_UNAVAILABLE``. Hitting ``cap`` is treated as
        ``FAMILY_PARTIAL`` (unknown-safe: never claim complete when the
        result may have been truncated).
        """
        try:
            items = paginate(
                client, trusted_origin, path, params=params,
                max_pages=_MAX_PAGES, _sleep_fn=_sleep_fn,
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
        return items, FAMILY_COMPLETE

    @classmethod
    def _fetch_users(
        cls, client: httpx.Client, trusted_origin: str, tenant_id: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        raw_items, completeness = cls._collect_family(
            client, trusted_origin, "/api/v1/users",
            params={"limit": str(_DEFAULT_PAGE_LIMIT)},
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
        cls, client: httpx.Client, trusted_origin: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        return cls._collect_family(
            client, trusted_origin, "/api/v1/groups",
            params={"limit": str(_DEFAULT_PAGE_LIMIT)},
            cap=_MAX_GROUPS, _sleep_fn=_sleep_fn,
        )

    @classmethod
    def _fetch_memberships(
        cls,
        client: httpx.Client,
        trusted_origin: str,
        tenant_id: str,
        raw_groups: list[dict],
        group_records_by_id: dict,
        user_index: dict,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str, dict]:
        """Collect user<->group membership edges.

        Call-complexity design: Okta's API has no single "list all
        memberships across the tenant" endpoint — membership is only
        enumerable per-group (``GET /api/v1/groups/{groupId}/users``) or
        per-user (``GET /api/v1/users/{userId}/groups``). This connector
        walks per-GROUP (one paginated call per group, capped at
        ``_MAX_GROUPS_FOR_MEMBERSHIP_ENUMERATION`` groups) rather than
        per-user, because a real tenant almost always has far fewer groups
        than users (fewer top-level requests), and group->users is the
        conventional direction for directory-sync tooling. This is
        intentionally NOT optimized further in this message — message 7
        owns full partial-sync/scale hardening; here it is bounded and
        documented, not silently unbounded.

        Also returns a ``membership_count_by_group_id`` dict so
        ``_normalize_group()`` can report a count derived from what was
        actually collected, without a separate per-group count API call.

        Returns ``(records, completeness, membership_count_by_group_id)``.
        completeness is FAMILY_COMPLETE only if every walked group
        succeeded; FAMILY_DENIED if the walk never got any group members
        due to permission; FAMILY_PARTIAL if some groups succeeded and
        others didn't (or the group cap / total cap was hit);
        FAMILY_UNAVAILABLE if every walked group failed for a
        non-permission reason.
        """
        if not raw_groups:
            # No groups at all -> trivially complete, zero memberships —
            # never inferred as "unknown"/"denied".
            return [], FAMILY_COMPLETE, {}

        groups_to_walk = raw_groups[:_MAX_GROUPS_FOR_MEMBERSHIP_ENUMERATION]
        truncated_group_list = len(raw_groups) > len(groups_to_walk)

        records: list[dict] = []
        counts_by_group: dict = {}
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
                client, trusted_origin, f"/api/v1/groups/{group_id}/users",
                params={"limit": str(_DEFAULT_PAGE_LIMIT)},
                cap=_MAX_MEMBERS_PER_GROUP, _sleep_fn=_sleep_fn,
            )
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

        return records, completeness, counts_by_group

    # ── Application collection (Okta message 3) ─────────────────────────────

    @classmethod
    def _fetch_applications_raw(
        cls, client: httpx.Client, trusted_origin: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        return cls._collect_family(
            client, trusted_origin, "/api/v1/apps",
            params={"limit": str(_DEFAULT_PAGE_LIMIT)},
            cap=_MAX_APPLICATIONS, _sleep_fn=_sleep_fn,
        )

    @classmethod
    def _fetch_app_user_assignments(
        cls,
        client: httpx.Client,
        trusted_origin: str,
        tenant_id: str,
        raw_apps: list[dict],
        app_records_by_id: dict,
        user_index: dict,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str, dict]:
        """Collect user<->app assignment edges.

        Call-complexity design: mirrors ``_fetch_memberships()`` — Okta's
        API enumerates app assignments per-app
        (``GET /api/v1/apps/{appId}/users``), so this walks apps once
        (capped at ``_MAX_APPS_FOR_ASSIGNMENT_ENUMERATION``) rather than
        querying assignments user-centrically, and never re-fetches the
        app list itself. Bounded and documented, not silently unbounded —
        message 7 owns further scale hardening.

        Returns ``(records, completeness, user_assignment_count_by_app_id)``.
        """
        if not raw_apps:
            return [], FAMILY_COMPLETE, {}

        apps_to_walk = raw_apps[:_MAX_APPS_FOR_ASSIGNMENT_ENUMERATION]
        truncated_app_list = len(raw_apps) > len(apps_to_walk)

        records: list[dict] = []
        counts_by_app: dict = {}
        succeeded = 0
        denied = 0
        other_failed = 0
        cap_hit = False

        for raw_app in apps_to_walk:
            if not isinstance(raw_app, dict):
                continue
            app_id = raw_app.get("id")
            if not isinstance(app_id, str) or not app_id.strip():
                continue
            app_record = app_records_by_id.get(app_id)
            if app_record is None:
                continue

            assignees, app_completeness = cls._collect_family(
                client, trusted_origin, f"/api/v1/apps/{app_id}/users",
                params={"limit": str(_DEFAULT_PAGE_LIMIT)},
                cap=_MAX_ASSIGNEES_PER_APP, _sleep_fn=_sleep_fn,
            )
            if app_completeness == FAMILY_DENIED:
                denied += 1
                continue
            if app_completeness == FAMILY_UNAVAILABLE:
                other_failed += 1
                continue
            if app_completeness == FAMILY_PARTIAL:
                cap_hit = True

            succeeded += 1
            seen_ids: set = set()
            for raw_assignment in assignees:
                if not isinstance(raw_assignment, dict):
                    continue
                user_id = raw_assignment.get("id")
                if not isinstance(user_id, str) or not user_id.strip():
                    continue
                if user_id in seen_ids:
                    continue  # dedup within a single app's page set
                seen_ids.add(user_id)
                if len(records) >= _MAX_TOTAL_USER_ASSIGNMENTS:
                    cap_hit = True
                    break
                user_record = user_index.get(user_id)
                rec = cls._normalize_app_user_assignment(tenant_id, app_record, user_record, raw_assignment)
                if rec is not None:
                    records.append(rec)
            counts_by_app[app_id] = len(seen_ids)
            if len(records) >= _MAX_TOTAL_USER_ASSIGNMENTS:
                cap_hit = True
                break

        if succeeded == 0 and denied > 0 and other_failed == 0:
            completeness = FAMILY_DENIED
        elif succeeded == 0 and other_failed > 0:
            completeness = FAMILY_UNAVAILABLE
        elif denied > 0 or other_failed > 0 or cap_hit or truncated_app_list:
            completeness = FAMILY_PARTIAL
        else:
            completeness = FAMILY_COMPLETE

        return records, completeness, counts_by_app

    @classmethod
    def _fetch_app_group_assignments(
        cls,
        client: httpx.Client,
        trusted_origin: str,
        tenant_id: str,
        raw_apps: list[dict],
        app_records_by_id: dict,
        group_records_by_id: dict,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str, dict]:
        """Collect group<->app assignment edges.

        Same per-app walk design as ``_fetch_app_user_assignments()`` —
        ``GET /api/v1/apps/{appId}/groups`` — collected in the SAME pass
        over ``raw_apps`` as user assignments (never a duplicate,
        redundant enumeration of the app list itself).

        Returns ``(records, completeness, group_assignment_count_by_app_id)``.
        """
        if not raw_apps:
            return [], FAMILY_COMPLETE, {}

        apps_to_walk = raw_apps[:_MAX_APPS_FOR_ASSIGNMENT_ENUMERATION]
        truncated_app_list = len(raw_apps) > len(apps_to_walk)

        records: list[dict] = []
        counts_by_app: dict = {}
        succeeded = 0
        denied = 0
        other_failed = 0
        cap_hit = False

        for raw_app in apps_to_walk:
            if not isinstance(raw_app, dict):
                continue
            app_id = raw_app.get("id")
            if not isinstance(app_id, str) or not app_id.strip():
                continue
            app_record = app_records_by_id.get(app_id)
            if app_record is None:
                continue

            assignments, app_completeness = cls._collect_family(
                client, trusted_origin, f"/api/v1/apps/{app_id}/groups",
                params={"limit": str(_DEFAULT_PAGE_LIMIT)},
                cap=_MAX_ASSIGNEES_PER_APP, _sleep_fn=_sleep_fn,
            )
            if app_completeness == FAMILY_DENIED:
                denied += 1
                continue
            if app_completeness == FAMILY_UNAVAILABLE:
                other_failed += 1
                continue
            if app_completeness == FAMILY_PARTIAL:
                cap_hit = True

            succeeded += 1
            seen_ids: set = set()
            for raw_assignment in assignments:
                if not isinstance(raw_assignment, dict):
                    continue
                group_id = raw_assignment.get("id")
                if not isinstance(group_id, str) or not group_id.strip():
                    continue
                if group_id in seen_ids:
                    continue
                seen_ids.add(group_id)
                if len(records) >= _MAX_TOTAL_GROUP_ASSIGNMENTS:
                    cap_hit = True
                    break
                group_record = group_records_by_id.get(group_id)
                rec = cls._normalize_app_group_assignment(tenant_id, app_record, group_record, raw_assignment)
                if rec is not None:
                    records.append(rec)
            counts_by_app[app_id] = len(seen_ids)
            if len(records) >= _MAX_TOTAL_GROUP_ASSIGNMENTS:
                cap_hit = True
                break

        if succeeded == 0 and denied > 0 and other_failed == 0:
            completeness = FAMILY_DENIED
        elif succeeded == 0 and other_failed > 0:
            completeness = FAMILY_UNAVAILABLE
        elif denied > 0 or other_failed > 0 or cap_hit or truncated_app_list:
            completeness = FAMILY_PARTIAL
        else:
            completeness = FAMILY_COMPLETE

        return records, completeness, counts_by_app

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

    def fetch(self, credentials: dict, *, _sleep_fn: Callable[[float], None] = None) -> list[dict]:
        """Fetch the Okta identity + application inventory:
        ``okta_organization``, ``okta_api_capability`` probes (message 1);
        ``okta_user`` / ``okta_group`` / ``okta_group_membership`` (message
        2); ``okta_application`` / ``okta_application_user_assignment`` /
        ``okta_application_group_assignment`` (message 3).

        Does NOT collect policies, authenticators, or admin roles yet —
        see the module docstring for the permanent sensitive-data boundary
        and ``okta_schema.py`` for what later messages will add.

        Every family fails independently: if e.g. app group assignments
        are denied while everything else is readable, the rest is still
        returned and ``okta_organization.family_completeness`` reports the
        gap — a family failure never aborts the whole fetch, and a denied/
        unreadable family is never silently reported as "zero" (see
        ``_collect_family``/``_fetch_memberships``/
        ``_fetch_app_user_assignments``/``_fetch_app_group_assignments``).

        SECURITY: the API token is used only within this method's scope,
        placed only in the Authorization header, never stored on the
        connector instance, never logged, and discarded when the
        httpx.Client context manager exits.

        Raises:
            AuthenticationError: Token rejected or malformed org_url.
            ConnectorError: Okta returned an unexpected error fetching the
                org record itself (every other family fails soft instead
                of raising — see ``_collect_family``).
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

            tenant_id = self.compute_tenant_id(org_hostname, raw_org)

            # ── Users ──────────────────────────────────────────────────────
            user_records, users_completeness = self._fetch_users(
                client, org_url, tenant_id, _sleep_fn=_sleep_fn,
            )
            user_index = {u["user_id"]: u for u in user_records}

            # ── Groups (raw kept for membership walk; normalized after) ────
            raw_groups, groups_completeness = self._fetch_groups_raw(
                client, org_url, _sleep_fn=_sleep_fn,
            )
            group_records_by_id: dict = {}
            for raw_group in raw_groups:
                if not isinstance(raw_group, dict):
                    continue
                group_id = raw_group.get("id")
                if not isinstance(group_id, str) or not group_id.strip():
                    continue
                # membership_count filled in below once memberships are collected.
                rec = self._normalize_group(tenant_id, raw_group, membership_count=None)
                if rec is not None:
                    group_records_by_id[group_id] = rec

            # ── Memberships ──────────────────────────────────────────────
            membership_records, memberships_completeness, counts_by_group = self._fetch_memberships(
                client, org_url, tenant_id, raw_groups, group_records_by_id, user_index,
                _sleep_fn=_sleep_fn,
            )

            # Backfill membership_count only for groups whose own membership
            # walk actually succeeded — a group whose walk was denied/failed
            # keeps membership_count=None (unknown), never 0.
            group_records: list[dict] = []
            for group_id, group_rec in group_records_by_id.items():
                count = counts_by_group.get(group_id)
                group_rec["membership_count"] = count
                group_rec["membership_count_category"] = categorize_membership_count(count)
                group_records.append(group_rec)

            # ── Applications (raw kept for assignment walks; normalized after) ──
            raw_apps, applications_completeness = self._fetch_applications_raw(
                client, org_url, _sleep_fn=_sleep_fn,
            )
            app_records_by_id: dict = {}
            for raw_app in raw_apps:
                if not isinstance(raw_app, dict):
                    continue
                app_id = raw_app.get("id")
                if not isinstance(app_id, str) or not app_id.strip():
                    continue
                # assignment counts filled in below once assignments are collected.
                rec = self._normalize_application(
                    tenant_id, raw_app, user_assignment_count=None, group_assignment_count=None,
                )
                if rec is not None:
                    app_records_by_id[app_id] = rec

            # ── Application user assignments ────────────────────────────────
            app_user_assignment_records, app_user_assignments_completeness, user_counts_by_app = (
                self._fetch_app_user_assignments(
                    client, org_url, tenant_id, raw_apps, app_records_by_id, user_index,
                    _sleep_fn=_sleep_fn,
                )
            )

            # ── Application group assignments ───────────────────────────────
            app_group_assignment_records, app_group_assignments_completeness, group_counts_by_app = (
                self._fetch_app_group_assignments(
                    client, org_url, tenant_id, raw_apps, app_records_by_id, group_records_by_id,
                    _sleep_fn=_sleep_fn,
                )
            )

            # Backfill assignment counts only for apps whose own assignment
            # walk actually succeeded — an app whose walk was denied/failed
            # keeps the count=None (unknown), never 0.
            app_records: list[dict] = []
            for app_id, app_rec in app_records_by_id.items():
                app_rec["user_assignment_count"] = user_counts_by_app.get(app_id)
                app_rec["group_assignment_count"] = group_counts_by_app.get(app_id)
                app_records.append(app_rec)

            org_record = self._normalize_organization(
                org_hostname, raw_org,
                family_completeness={
                    "users": users_completeness,
                    "groups": groups_completeness,
                    "memberships": memberships_completeness,
                    "applications": applications_completeness,
                    "app_user_assignments": app_user_assignments_completeness,
                    "app_group_assignments": app_group_assignments_completeness,
                },
            )

            records.append(org_record)
            records.extend(user_records)
            records.extend(group_records)
            records.extend(membership_records)
            records.extend(app_records)
            records.extend(app_user_assignment_records)
            records.extend(app_group_assignment_records)
            records.extend(self._probe_capabilities(client, tenant_id))

        return records
