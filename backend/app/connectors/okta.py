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
    OKTA_ADMIN_ROLE,
    OKTA_API_CAPABILITY,
    OKTA_APPLICATION,
    OKTA_APPLICATION_GROUP_ASSIGNMENT,
    OKTA_APPLICATION_USER_ASSIGNMENT,
    OKTA_AUTHENTICATOR,
    OKTA_GROUP,
    OKTA_GROUP_ADMIN_ROLE_ASSIGNMENT,
    OKTA_GROUP_MEMBERSHIP,
    OKTA_ORGANIZATION,
    OKTA_POLICY,
    OKTA_POLICY_RULE,
    OKTA_PRIVILEGED_GROUP,
    OKTA_PRIVILEGED_IDENTITY,
    OKTA_USER,
    OKTA_USER_ADMIN_ROLE_ASSIGNMENT,
    categorize_access,
    categorize_admin_assignment_scope,
    categorize_algorithm,
    categorize_app_status,
    categorize_app_type,
    categorize_assignment_scope,
    categorize_authenticator_key,
    categorize_dormant_privileged,
    categorize_group_type,
    categorize_hardware_protection,
    categorize_last_login,
    categorize_membership_count,
    categorize_org_status,
    categorize_password_min_length,
    categorize_permission,
    categorize_policy_type,
    categorize_redirect_uris,
    categorize_resource_set_resources,
    categorize_role_type,
    categorize_scope,
    categorize_session_lifetime_minutes,
    categorize_sign_on_mode,
    categorize_token_auth_method,
    categorize_user_status,
    highest_privilege_tier,
    is_everyone_group,
    is_knowledge_authenticator,
    is_possession_authenticator,
    lifecycle_posture_for_status,
    mfa_requirement_from_signon_actions,
    mfa_requirement_from_verification_method,
    parse_iso8601_duration_to_minutes,
    phishing_resistance_for_authenticator_key,
    phishing_resistance_from_possession_constraint,
    privilege_tier_for_permissions,
    privilege_tier_for_role_type,
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

# ── Policy/authenticator collection bounds (Okta message 4) ────────────────
#
# Same rationale as the application/identity bounds above — rule
# enumeration is per-policy (see _fetch_policy_rules() docstring), so this
# additionally needs a cap on the number of policies walked and a global
# cap on total rule records collected.
_MAX_POLICIES_PER_TYPE = 1_000
_MAX_RULES_PER_POLICY = 5_000
_MAX_POLICIES_FOR_RULE_ENUMERATION = 5_000
_MAX_TOTAL_RULES = 200_000
_MAX_AUTHENTICATORS = 1_000

# ── Admin-role / privileged-identity collection bounds (Okta message 5) ────
#
# Okta exposes no single tenant-wide "list every admin-role assignment"
# endpoint for BUILT-IN roles — assignments are only enumerable per-user
# (``GET /api/v1/users/{userId}/roles``) or per-group
# (``GET /api/v1/groups/{groupId}/roles``). Unlike groups (far fewer than
# users in a real tenant, so a per-group membership walk is cheap), a
# per-USER role-assignment walk genuinely is proportional to the total
# user count and IS a real N+1 concern at scale (a 20,000-user tenant
# would need 20,000 additional requests just to find its handful of
# admins). This connector deliberately caps the per-user walk at
# ``_MAX_USERS_FOR_ROLE_ENUMERATION`` — well below ``_MAX_USERS`` — and
# reports FAMILY_PARTIAL when the cap is hit, rather than silently
# scanning only a prefix of the user list and calling it complete.
# Message 7 owns further scale hardening of this specific bound (e.g.
# System-Log-driven admin discovery, or Okta's newer Identity Governance
# assignee-search endpoints where available).
_MAX_USERS_FOR_ROLE_ENUMERATION = 2_000
_MAX_GROUPS_FOR_ROLE_ENUMERATION = 2_000
_MAX_ROLES_PER_PRINCIPAL = 200
_MAX_TOTAL_USER_ADMIN_ROLE_ASSIGNMENTS = 50_000
_MAX_TOTAL_GROUP_ADMIN_ROLE_ASSIGNMENTS = 50_000
_MAX_CUSTOM_ADMIN_ROLES = 500
_MAX_PERMISSIONS_PER_ROLE = 300
_MAX_RESOURCE_SETS = 500
_MAX_RESOURCES_PER_SET = 1_000

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
) -> tuple[list[dict], bool]:
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

    Returns ``(items, truncated)``. ``truncated`` is ``True`` (Okta
    message 7) when pagination stopped for a reason OTHER than a natural
    end-of-list — a later-page failure (403/429/5xx/timeout/malformed
    body), a repeated Link, or a rejected cross-origin Link. The caller
    (``_collect_family``) must treat a truncated result as PARTIAL even
    when it happens to be under the record cap — silently reporting a
    mid-pagination failure as "complete" would make later diffs treat an
    incomplete page set as fully trustworthy and infer false removals for
    every record that would have been on the unread pages.
    """
    items: list[dict] = []
    seen_ids: set = set()
    seen_urls: set = set()
    url = start_url
    current_params: Optional[dict] = params
    truncated = False

    for page_num in range(max_pages):
        outcome = call_okta(client, "GET", url, params=current_params, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            if page_num == 0:
                _raise_for_outcome(outcome, context=f"page {page_num + 1}")
            logger.debug("okta_connector: pagination stopped early on page %d (%s)", page_num + 1, outcome.category)
            truncated = True
            break

        resp = outcome.response
        try:
            page_items = resp.json()
        except ValueError:
            if page_num == 0:
                raise ConnectorError("okta: response was not valid JSON")
            truncated = True
            break
        if not isinstance(page_items, list):
            if page_num == 0:
                raise ConnectorError("okta: expected a JSON array response")
            truncated = True
            break

        for raw in page_items:
            if isinstance(raw, dict) and isinstance(raw.get("id"), str):
                if raw["id"] in seen_ids:
                    continue
                seen_ids.add(raw["id"])
            items.append(raw)

        next_url = _extract_next_link(resp, trusted_origin=trusted_origin)
        if not next_url:
            # A completely absent Link header is a genuine natural end.
            # But a Link header that DID advertise a rel="next" candidate
            # (rejected only because it failed the cross-origin/malformed
            # checks in `_extract_next_link`) means the server claimed
            # there was more data — we deliberately don't follow it for
            # safety, but the result must still be treated as truncated,
            # not a confirmed-complete natural end.
            raw_link_header = resp.headers.get("Link") or ""
            if "rel=\"next\"" in raw_link_header or "rel=next" in raw_link_header.replace(" ", ""):
                truncated = True
            break
        if next_url in seen_urls:
            logger.warning("okta_connector: repeated pagination Link detected; stopping")
            truncated = True
            break
        seen_urls.add(next_url)
        url = next_url
        # The next URL already carries its own query string — do not
        # re-apply the original params on subsequent requests.
        current_params = None
    else:
        # The `for` loop's `max_pages` bound was hit without a `break` —
        # there may be more pages beyond what we read, so this is also a
        # truncated (partial) result, not a confirmed complete one.
        truncated = True

    return items, truncated


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
            # When the group's own record couldn't be resolved (e.g. group
            # collection was denied/partial while app-group-assignment
            # collection succeeded), whether this is the built-in/Everyone
            # group is genuinely UNKNOWN — never coerced to False, which
            # would silently suppress a real Everyone-group assignment
            # Finding.
            "built_in_group": bool(group_record.get("built_in")) if group_record else None,
            "everyone_group": bool(group_record.get("everyone_group")) if group_record else None,
        }

    # ── Policy / rule / authenticator normalizers (Okta message 4) ─────────

    # Every Okta policy type this connector knows how to request. Okta's
    # Policies API requires an explicit `type` query parameter per call —
    # there is no single "list all policies" endpoint — so collection
    # loops over this fixed, bounded set (6 calls), never an unbounded
    # per-tenant discovery.
    _POLICY_TYPES: tuple[str, ...] = (
        "OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL",
        "ACCESS_POLICY", "PROFILE_ENROLLMENT", "IDP_DISCOVERY",
    )

    @staticmethod
    def _safe_int(value: object) -> Optional[int]:
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        return None

    @staticmethod
    def _people_targeting_counts(conditions: dict) -> tuple[Optional[int], Optional[int], Optional[int]]:
        """Extract (group_include_count, group_exclude_count, user_include_count)
        from a Policy or Rule's ``conditions.people`` block. Only list
        lengths are ever read — never the actual group/user IDs inside."""
        people = conditions.get("people") if isinstance(conditions.get("people"), dict) else {}
        groups = people.get("groups") if isinstance(people.get("groups"), dict) else {}
        users = people.get("users") if isinstance(people.get("users"), dict) else {}
        group_include = groups.get("include")
        group_exclude = groups.get("exclude")
        user_include = users.get("include")
        return (
            len(group_include) if isinstance(group_include, list) else None,
            len(group_exclude) if isinstance(group_exclude, list) else None,
            len(user_include) if isinstance(user_include, list) else None,
        )

    @staticmethod
    def _normalize_password_posture(settings: dict) -> dict:
        """Extract safe password-policy posture from
        ``policy.settings.password`` ONLY. Never touches
        ``settings.recovery`` (recovery question/factor configuration) or
        any credential material — Okta's Policies API never returns
        password values/hashes/history contents in the first place.
        """
        password = settings.get("password") if isinstance(settings.get("password"), dict) else {}
        complexity = password.get("complexity") if isinstance(password.get("complexity"), dict) else {}
        age = password.get("age") if isinstance(password.get("age"), dict) else {}
        lockout = password.get("lockout") if isinstance(password.get("lockout"), dict) else {}

        min_length = OktaConnector._safe_int(complexity.get("minLength"))
        min_lower = OktaConnector._safe_int(complexity.get("minLowerCase"))
        min_upper = OktaConnector._safe_int(complexity.get("minUpperCase"))
        min_number = OktaConnector._safe_int(complexity.get("minNumber"))
        min_symbol = OktaConnector._safe_int(complexity.get("minSymbol"))
        history_count = OktaConnector._safe_int(age.get("historyCount"))
        max_age_days = OktaConnector._safe_int(age.get("maxAgeDays"))
        min_age_minutes = OktaConnector._safe_int(age.get("minAgeMinutes"))
        max_attempts = OktaConnector._safe_int(lockout.get("maxAttempts"))

        complexity_counts = [c for c in (min_lower, min_upper, min_number, min_symbol) if c is not None]
        complexity_required = (
            any(c > 0 for c in complexity_counts) if complexity_counts else None
        )
        exclude_username = complexity.get("excludeUsername")
        exclude_username = bool(exclude_username) if isinstance(exclude_username, bool) else None
        dictionary = complexity.get("dictionary") if isinstance(complexity.get("dictionary"), dict) else {}
        common_dict = dictionary.get("common") if isinstance(dictionary.get("common"), dict) else {}
        common_password_excluded = common_dict.get("exclude")
        common_password_excluded = bool(common_password_excluded) if isinstance(common_password_excluded, bool) else None

        return {
            "password_min_length": min_length,
            "password_min_length_category": categorize_password_min_length(min_length),
            "password_complexity_required": complexity_required,
            "password_exclude_username": exclude_username,
            "password_common_password_excluded": common_password_excluded,
            "password_history_count": history_count,
            "password_history_present": (history_count > 0) if history_count is not None else None,
            "password_max_age_days": max_age_days,
            "password_lifetime_bounded": (max_age_days > 0) if max_age_days is not None else None,
            "password_min_age_minutes": min_age_minutes,
            "password_lockout_max_attempts": max_attempts,
            "password_lockout_present": (max_attempts > 0) if max_attempts is not None else None,
        }

    @staticmethod
    def _normalize_policy(
        tenant_id: str, raw: dict, *, rule_count: Optional[int],
    ) -> Optional[dict]:
        """Normalize one Okta policy record.

        SECURITY: ``raw["conditions"]`` is touched ONLY at
        ``conditions.people.groups.include/exclude`` and
        ``conditions.people.users.include`` list LENGTHS — never the
        actual group/user IDs, and never any other conditions sub-tree
        (network/platform/risk at the policy level are not read here).
        ``raw["settings"]`` is touched only via ``_normalize_password_posture``
        for PASSWORD-type policies, at the specific safe fields documented
        there — never copied wholesale.
        """
        policy_id = raw.get("id")
        if not isinstance(policy_id, str) or not policy_id.strip():
            return None

        name = raw.get("name")
        name = name.strip()[:_MAX_STR_LEN] if isinstance(name, str) and name.strip() else None

        policy_type = categorize_policy_type(raw.get("type"))
        status = categorize_app_status(raw.get("status"))
        priority = OktaConnector._safe_int(raw.get("priority"))
        system = raw.get("system")
        system = bool(system) if isinstance(system, bool) else None

        conditions = raw.get("conditions") if isinstance(raw.get("conditions"), dict) else {}
        group_include, group_exclude, user_include = OktaConnector._people_targeting_counts(conditions)

        record: dict = {
            "record_type": OKTA_POLICY,
            "record_id": f"{tenant_id}/policy/{policy_id}",
            "provider_resource_id": f"policies/{policy_id}",
            "tenant_id": tenant_id,
            "policy_id": policy_id,
            "policy_name": name,
            "policy_type": policy_type,
            "status": status,
            "active": status == "ACTIVE",
            "priority": priority,
            "system": system,
            "group_include_count": group_include,
            "group_exclude_count": group_exclude,
            "user_include_count": user_include,
            "scope_category": categorize_scope(
                group_include_count=group_include, user_include_count=user_include,
            ),
            "rule_count": rule_count,
        }

        if policy_type == "PASSWORD":
            settings = raw.get("settings") if isinstance(raw.get("settings"), dict) else {}
            record.update(OktaConnector._normalize_password_posture(settings))

        return record

    @staticmethod
    def _normalize_policy_rule(tenant_id: str, policy_record: dict, raw: dict) -> Optional[dict]:
        """Normalize one Okta policy rule record.

        SECURITY: ``raw["conditions"]`` and ``raw["actions"]`` are touched
        ONLY at the specific safe sub-paths documented inline below — never
        copied wholesale. No factor secrets, challenge data, or credential
        material ever exist in these API responses in the first place, but
        this normalizer additionally never reads any field that could
        plausibly carry them (e.g. any ``credentials``-shaped sub-object).
        """
        rule_id = raw.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            return None

        name = raw.get("name")
        name = name.strip()[:_MAX_STR_LEN] if isinstance(name, str) and name.strip() else None
        status = categorize_app_status(raw.get("status"))
        priority = OktaConnector._safe_int(raw.get("priority"))

        conditions = raw.get("conditions") if isinstance(raw.get("conditions"), dict) else {}
        group_include, group_exclude, user_include = OktaConnector._people_targeting_counts(conditions)

        network = conditions.get("network") if isinstance(conditions.get("network"), dict) else {}
        network_connection = network.get("connection")
        if network_connection == "ZONE" and isinstance(network.get("include"), list):
            network_zone_category = "zone_restricted"
        elif network_connection == "ANYWHERE":
            network_zone_category = "any"
        else:
            network_zone_category = "unknown"

        actions = raw.get("actions") if isinstance(raw.get("actions"), dict) else {}

        # Classic OKTA_SIGN_ON rule action shape.
        signon = actions.get("signon") if isinstance(actions.get("signon"), dict) else {}
        access_category = categorize_access(signon.get("access"))
        mfa_requirement_category = mfa_requirement_from_signon_actions(actions)
        session = signon.get("session") if isinstance(signon.get("session"), dict) else {}
        session_lifetime_minutes = OktaConnector._safe_int(session.get("maxSessionLifetimeMinutes"))

        # Modern (Identity Engine) ACCESS_POLICY rule action shape —
        # consulted only when the classic shape didn't yield a definitive
        # access/MFA answer, since a rule is one or the other, never both.
        possession: Optional[dict] = None
        knowledge: Optional[dict] = None
        required_factor_count: Optional[int] = None
        reauth_minutes: Optional[int] = None
        app_sign_on = actions.get("appSignOn") if isinstance(actions.get("appSignOn"), dict) else {}
        verification_method = (
            app_sign_on.get("verificationMethod")
            if isinstance(app_sign_on.get("verificationMethod"), dict) else {}
        )
        if app_sign_on:
            if access_category == "unknown":
                access_category = categorize_access(app_sign_on.get("access"))
            if mfa_requirement_category == "unknown" and verification_method:
                mfa_requirement_category = mfa_requirement_from_verification_method(verification_method)
            factor_mode = verification_method.get("factorMode")
            if factor_mode == "1FA":
                required_factor_count = 1
            elif factor_mode == "2FA":
                required_factor_count = 2
            constraints = verification_method.get("constraints")
            if isinstance(constraints, list) and constraints and isinstance(constraints[0], dict):
                possession = constraints[0].get("possession") if isinstance(constraints[0].get("possession"), dict) else None
                knowledge = constraints[0].get("knowledge") if isinstance(constraints[0].get("knowledge"), dict) else None
            reauth_minutes = parse_iso8601_duration_to_minutes(verification_method.get("reauthenticateIn"))

        possession_required = isinstance(possession, dict) if app_sign_on else None
        knowledge_required = isinstance(knowledge, dict) if app_sign_on else None
        phishing_resistant_category = phishing_resistance_from_possession_constraint(possession)
        hardware_protected_category = categorize_hardware_protection(possession)
        device_bound = (
            possession.get("deviceBound") if isinstance(possession, dict) and isinstance(possession.get("deviceBound"), bool)
            else None
        )

        re_auth_minutes = reauth_minutes if reauth_minutes is not None else session_lifetime_minutes

        return {
            "record_type": OKTA_POLICY_RULE,
            "record_id": f"{tenant_id}/policy_rule/{policy_record['policy_id']}/{rule_id}",
            "provider_resource_id": f"policies/{policy_record['policy_id']}/rules/{rule_id}",
            "tenant_id": tenant_id,
            "policy_id": policy_record["policy_id"],
            "policy_name": policy_record.get("policy_name"),
            "policy_type": policy_record.get("policy_type"),
            "rule_id": rule_id,
            "rule_name": name,
            "status": status,
            "active": status == "ACTIVE",
            "priority": priority,
            "group_include_count": group_include,
            "group_exclude_count": group_exclude,
            "user_include_count": user_include,
            "scope_category": categorize_scope(
                group_include_count=group_include, user_include_count=user_include,
            ),
            "network_zone_category": network_zone_category,
            "access_category": access_category,
            "mfa_requirement_category": mfa_requirement_category,
            "required_factor_count": required_factor_count,
            "possession_required": possession_required,
            "knowledge_required": knowledge_required,
            "phishing_resistant_category": phishing_resistant_category,
            "hardware_protected_category": hardware_protected_category,
            "device_bound": device_bound,
            "session_lifetime_category": categorize_session_lifetime_minutes(session_lifetime_minutes),
            "re_authentication_category": categorize_session_lifetime_minutes(re_auth_minutes),
        }

    @staticmethod
    def _normalize_authenticator(tenant_id: str, raw: dict) -> Optional[dict]:
        """Normalize one Okta authenticator record.

        SECURITY: only ``id``, ``key``, ``type``, ``name``, and ``status``
        are ever read from ``raw``. ``raw["settings"]`` (which may include
        enrollment-related configuration) is never read at all — no OTP
        seeds, private keys, shared secrets, recovery codes, or phone
        numbers exist in this record's construction path.
        """
        authenticator_id = raw.get("id")
        if not isinstance(authenticator_id, str) or not authenticator_id.strip():
            return None

        key = categorize_authenticator_key(raw.get("key"))
        raw_type = raw.get("type")
        raw_type = raw_type.strip()[:30] if isinstance(raw_type, str) and raw_type.strip() else None
        name = raw.get("name")
        name = name.strip()[:_MAX_STR_LEN] if isinstance(name, str) and name.strip() else None
        status = categorize_app_status(raw.get("status"))

        hardware_backed_category = "hardware_backed" if raw_type == "security_key" else "unknown"

        return {
            "record_type": OKTA_AUTHENTICATOR,
            "record_id": f"{tenant_id}/authenticator/{authenticator_id}",
            "provider_resource_id": f"authenticators/{authenticator_id}",
            "tenant_id": tenant_id,
            "authenticator_id": authenticator_id,
            "key": key,
            "type": raw_type,
            "name": name,
            "status": status,
            "active": status == "ACTIVE",
            "phishing_resistant_category": phishing_resistance_for_authenticator_key(key),
            "possession_factor": is_possession_authenticator(key),
            "knowledge_factor": is_knowledge_authenticator(key),
            "inherence_factor": None,  # never fabricated — see module docstring
            "hardware_backed_category": hardware_backed_category,
        }

    # ── Admin-role / privileged-identity normalizers (Okta message 5) ──────

    @staticmethod
    def _parse_role_assignment(raw: dict) -> Optional[dict]:
        """Parse one raw Okta role-assignment object (from
        ``/api/v1/users/{id}/roles`` or ``/api/v1/groups/{id}/roles``)
        into a small safe dict — never returns the raw object itself.

        SECURITY: only ``id``, ``label``, ``type``, ``status``, ``role``
        (custom role ID reference), and the PRESENCE (not contents) of a
        ``_links.targets``/``_links.resource-set`` entry are ever read.
        """
        assignment_id = raw.get("id")
        assignment_id = assignment_id.strip()[:_MAX_STR_LEN] if isinstance(assignment_id, str) and assignment_id.strip() else None
        if assignment_id is None:
            return None

        label = raw.get("label")
        label = label.strip()[:_MAX_STR_LEN] if isinstance(label, str) and label.strip() else None

        role_type = categorize_role_type(raw.get("type"))
        status = categorize_app_status(raw.get("status"))

        custom_role_id: Optional[str] = None
        resource_set_id: Optional[str] = None
        if role_type == "CUSTOM":
            raw_role_ref = raw.get("role")
            if isinstance(raw_role_ref, str) and raw_role_ref.strip():
                custom_role_id = raw_role_ref.strip()[:_MAX_STR_LEN]
            raw_rs_ref = raw.get("resource-set")
            if isinstance(raw_rs_ref, str) and raw_rs_ref.strip():
                resource_set_id = raw_rs_ref.strip()[:_MAX_STR_LEN]

        raw_links = raw.get("_links")
        if isinstance(raw_links, dict):
            # An unscoped ("all resources of this type") assignment still
            # carries a `_links` block (e.g. `self`) — it simply lacks a
            # `targets` entry, which is definitive "not scoped" information,
            # not an unknown. Only a MISSING `_links` block entirely (an
            # unexpected/malformed response shape) is unknown.
            has_targets_link: Optional[bool] = "targets" in raw_links
        else:
            has_targets_link = None
        scope_category = categorize_admin_assignment_scope(has_targets_link=has_targets_link)

        return {
            "assignment_id": assignment_id,
            "label": label,
            "role_type": role_type,
            "status": status,
            "active": status == "ACTIVE",
            "custom_role_id": custom_role_id,
            "resource_set_id": resource_set_id,
            "scope_category": scope_category,
        }

    @staticmethod
    def _normalize_builtin_admin_role(tenant_id: str, role_type: str, label: Optional[str]) -> dict:
        """Build the local role-catalog entry for a BUILT-IN role type
        discovered via an assignment. Okta has no endpoint that lists the
        built-in role catalog directly — this is the connector's own
        deduplicated view of every distinct built-in type it has seen."""
        return {
            "record_type": OKTA_ADMIN_ROLE,
            "record_id": f"{tenant_id}/admin_role/{role_type}",
            "provider_resource_id": f"iam/roles/{role_type}",
            "tenant_id": tenant_id,
            "role_id": role_type,
            "role_type": role_type,
            "role_label": label,
            "built_in": True,
            "custom": False,
            "privilege_tier": privilege_tier_for_role_type(role_type),
            "permissions_count": None,
            "collection_completeness": "derived_from_assignments",
        }

    @staticmethod
    def _normalize_custom_admin_role(tenant_id: str, raw: dict, permissions: list) -> Optional[dict]:
        """Normalize one custom role from ``GET /api/v1/iam/roles``.

        SECURITY: only ``id``, ``label``, and the raw permission
        IDENTIFIER STRINGS (never permission "conditions"/resource-scope
        sub-objects) are read. ``permissions`` here is the already-fetched
        list of identifier strings from
        ``GET /api/v1/iam/roles/{id}/permissions`` — the raw response
        body for that call is never stored on the record, only the
        derived count and privilege tier.
        """
        role_id = raw.get("id")
        if not isinstance(role_id, str) or not role_id.strip():
            return None

        label = raw.get("label")
        label = label.strip()[:_MAX_STR_LEN] if isinstance(label, str) and label.strip() else None

        safe_permissions = [p for p in permissions if isinstance(p, str)] if isinstance(permissions, list) else None

        return {
            "record_type": OKTA_ADMIN_ROLE,
            "record_id": f"{tenant_id}/admin_role/{role_id}",
            "provider_resource_id": f"iam/roles/{role_id}",
            "tenant_id": tenant_id,
            "role_id": role_id,
            "role_type": "CUSTOM",
            "role_label": label,
            "built_in": False,
            "custom": True,
            "privilege_tier": privilege_tier_for_permissions(safe_permissions),
            "permissions_count": len(safe_permissions) if safe_permissions is not None else None,
            "collection_completeness": "collected",
        }

    @staticmethod
    def _normalize_user_admin_role_assignment(
        tenant_id: str, user_record: dict, parsed: dict, admin_role_record: dict,
    ) -> dict:
        role_id = admin_role_record["role_id"]
        scope = parsed["scope_category"]
        return {
            "record_type": OKTA_USER_ADMIN_ROLE_ASSIGNMENT,
            "record_id": f"{tenant_id}/user_admin_role/{user_record['user_id']}/{role_id}/{scope}",
            "provider_resource_id": f"users/{user_record['user_id']}/roles/{parsed['assignment_id']}",
            "tenant_id": tenant_id,
            "user_id": user_record["user_id"],
            "user_login": user_record.get("login"),
            "user_status": user_record.get("status"),
            "role_id": role_id,
            "role_type": admin_role_record["role_type"],
            "custom": admin_role_record["custom"],
            "privilege_tier": admin_role_record["privilege_tier"],
            "direct_assignment": True,
            "assignment_scope_category": scope,
            "resource_set_id": parsed.get("resource_set_id"),
            "resource_set_scope_category": None,
            "resource_set_app_count": None,
            "resource_set_group_count": None,
            "resource_set_user_count": None,
            "active": parsed["active"],
        }

    @staticmethod
    def _normalize_group_admin_role_assignment(
        tenant_id: str, group_record: dict, parsed: dict, admin_role_record: dict,
    ) -> dict:
        role_id = admin_role_record["role_id"]
        scope = parsed["scope_category"]
        return {
            "record_type": OKTA_GROUP_ADMIN_ROLE_ASSIGNMENT,
            "record_id": f"{tenant_id}/group_admin_role/{group_record['group_id']}/{role_id}/{scope}",
            "provider_resource_id": f"groups/{group_record['group_id']}/roles/{parsed['assignment_id']}",
            "tenant_id": tenant_id,
            "group_id": group_record["group_id"],
            "group_name": group_record.get("group_name"),
            "group_type": group_record.get("group_type"),
            "role_id": role_id,
            "role_type": admin_role_record["role_type"],
            "custom": admin_role_record["custom"],
            "privilege_tier": admin_role_record["privilege_tier"],
            "assignment_scope_category": scope,
            "resource_set_id": parsed.get("resource_set_id"),
            "resource_set_scope_category": None,
            "resource_set_app_count": None,
            "resource_set_group_count": None,
            "resource_set_user_count": None,
            "active": parsed["active"],
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
        ``FAMILY_UNAVAILABLE``. Hitting ``cap`` OR a mid-pagination
        failure (``paginate()``'s ``truncated`` flag — Okta message 7) is
        treated as ``FAMILY_PARTIAL``: unknown-safe, never claim complete
        when the result may have been truncated by a later-page 403/429/
        5xx/timeout, a repeated Link, or a rejected cross-origin Link.
        """
        try:
            items, truncated = paginate(
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
        if truncated:
            return items, FAMILY_PARTIAL
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
        actually collected, without a separate per-group count API call,
        and a ``status_by_group_id`` dict (Okta message 7) recording each
        walked group's OWN completeness — this lets diff-time false-
        removal suppression scope itself to just the groups whose walk
        actually failed, rather than suppressing every membership removal
        tenant-wide whenever any single group's walk fails (see
        ``_okta_removal_suppressed`` in diff_service.py).

        Returns ``(records, completeness, membership_count_by_group_id, status_by_group_id)``.
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
                client, trusted_origin, f"/api/v1/groups/{group_id}/users",
                params={"limit": str(_DEFAULT_PAGE_LIMIT)},
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

        Returns ``(records, completeness, user_assignment_count_by_app_id, status_by_app_id)``.
        ``status_by_app_id`` (Okta message 7) records each walked app's OWN
        completeness for per-parent false-removal suppression — see
        ``_fetch_memberships``'s docstring for the same rationale.
        """
        if not raw_apps:
            return [], FAMILY_COMPLETE, {}, {}

        apps_to_walk = raw_apps[:_MAX_APPS_FOR_ASSIGNMENT_ENUMERATION]
        truncated_app_list = len(raw_apps) > len(apps_to_walk)

        records: list[dict] = []
        counts_by_app: dict = {}
        status_by_app: dict = {}
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
            status_by_app[app_id] = app_completeness
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

        return records, completeness, counts_by_app, status_by_app

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

        Returns ``(records, completeness, group_assignment_count_by_app_id, status_by_app_id)``.
        """
        if not raw_apps:
            return [], FAMILY_COMPLETE, {}, {}

        apps_to_walk = raw_apps[:_MAX_APPS_FOR_ASSIGNMENT_ENUMERATION]
        truncated_app_list = len(raw_apps) > len(apps_to_walk)

        records: list[dict] = []
        counts_by_app: dict = {}
        status_by_app: dict = {}
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
            status_by_app[app_id] = app_completeness
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

        return records, completeness, counts_by_app, status_by_app

    # ── Policy / rule / authenticator collection (Okta message 4) ──────────

    @classmethod
    def _fetch_policies_raw(
        cls, client: httpx.Client, trusted_origin: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        """Collect all policies across every known policy type.

        Okta's Policies API requires an explicit ``type`` query parameter
        per call — there is no single "list all policies" endpoint — so
        this loops over the fixed, bounded ``_POLICY_TYPES`` set (6 calls),
        never an unbounded per-tenant discovery. Each type's own request
        is bounded/paginated via ``_collect_family`` like every other
        family in this connector.

        Returns ``(raw_policies, completeness)`` where completeness is
        FAMILY_COMPLETE only if every policy type succeeded; FAMILY_DENIED
        if every type was denied; FAMILY_UNAVAILABLE if every type failed
        for a non-permission reason; FAMILY_PARTIAL otherwise (including
        when any single type's cap was hit).
        """
        all_items: list[dict] = []
        succeeded = 0
        denied = 0
        other_failed = 0
        cap_hit = False

        for policy_type in cls._POLICY_TYPES:
            items, completeness = cls._collect_family(
                client, trusted_origin, "/api/v1/policies",
                params={"type": policy_type, "limit": str(_DEFAULT_PAGE_LIMIT)},
                cap=_MAX_POLICIES_PER_TYPE, _sleep_fn=_sleep_fn,
            )
            if completeness == FAMILY_DENIED:
                denied += 1
                continue
            if completeness == FAMILY_UNAVAILABLE:
                other_failed += 1
                continue
            if completeness == FAMILY_PARTIAL:
                cap_hit = True
            succeeded += 1
            all_items.extend(items)

        if succeeded == 0 and denied > 0 and other_failed == 0:
            return all_items, FAMILY_DENIED
        if succeeded == 0 and other_failed > 0:
            return all_items, FAMILY_UNAVAILABLE
        if denied > 0 or other_failed > 0 or cap_hit:
            return all_items, FAMILY_PARTIAL
        return all_items, FAMILY_COMPLETE

    @classmethod
    def _fetch_policy_rules(
        cls,
        client: httpx.Client,
        trusted_origin: str,
        tenant_id: str,
        raw_policies: list[dict],
        policy_records_by_id: dict,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str, dict]:
        """Collect policy rules for every collected policy.

        Call-complexity design: mirrors ``_fetch_memberships()``/
        ``_fetch_app_user_assignments()`` — Okta's API enumerates rules
        per-policy (``GET /api/v1/policies/{policyId}/rules``), so this
        walks policies once (capped at
        ``_MAX_POLICIES_FOR_RULE_ENUMERATION``) rather than any
        alternative broader enumeration, and never re-fetches the policy
        list itself.

        Returns ``(records, completeness, rule_count_by_policy_id, status_by_policy_id)``.
        """
        if not raw_policies:
            return [], FAMILY_COMPLETE, {}, {}

        policies_to_walk = raw_policies[:_MAX_POLICIES_FOR_RULE_ENUMERATION]
        truncated_policy_list = len(raw_policies) > len(policies_to_walk)

        records: list[dict] = []
        counts_by_policy: dict = {}
        status_by_policy: dict = {}
        succeeded = 0
        denied = 0
        other_failed = 0
        cap_hit = False

        for raw_policy in policies_to_walk:
            if not isinstance(raw_policy, dict):
                continue
            policy_id = raw_policy.get("id")
            if not isinstance(policy_id, str) or not policy_id.strip():
                continue
            policy_record = policy_records_by_id.get(policy_id)
            if policy_record is None:
                continue

            rules, policy_completeness = cls._collect_family(
                client, trusted_origin, f"/api/v1/policies/{policy_id}/rules",
                params={"limit": str(_DEFAULT_PAGE_LIMIT)},
                cap=_MAX_RULES_PER_POLICY, _sleep_fn=_sleep_fn,
            )
            status_by_policy[policy_id] = policy_completeness
            if policy_completeness == FAMILY_DENIED:
                denied += 1
                continue
            if policy_completeness == FAMILY_UNAVAILABLE:
                other_failed += 1
                continue
            if policy_completeness == FAMILY_PARTIAL:
                cap_hit = True

            succeeded += 1
            seen_ids: set = set()
            for raw_rule in rules:
                if not isinstance(raw_rule, dict):
                    continue
                rule_id = raw_rule.get("id")
                if not isinstance(rule_id, str) or not rule_id.strip():
                    continue
                if rule_id in seen_ids:
                    continue
                seen_ids.add(rule_id)
                if len(records) >= _MAX_TOTAL_RULES:
                    cap_hit = True
                    break
                rec = cls._normalize_policy_rule(tenant_id, policy_record, raw_rule)
                if rec is not None:
                    records.append(rec)
            counts_by_policy[policy_id] = len(seen_ids)
            if len(records) >= _MAX_TOTAL_RULES:
                cap_hit = True
                break

        if succeeded == 0 and denied > 0 and other_failed == 0:
            completeness = FAMILY_DENIED
        elif succeeded == 0 and other_failed > 0:
            completeness = FAMILY_UNAVAILABLE
        elif denied > 0 or other_failed > 0 or cap_hit or truncated_policy_list:
            completeness = FAMILY_PARTIAL
        else:
            completeness = FAMILY_COMPLETE

        return records, completeness, counts_by_policy, status_by_policy

    @classmethod
    def _fetch_authenticators(
        cls, client: httpx.Client, trusted_origin: str, tenant_id: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        raw_items, completeness = cls._collect_family(
            client, trusted_origin, "/api/v1/authenticators",
            params=None, cap=_MAX_AUTHENTICATORS, _sleep_fn=_sleep_fn,
        )
        records = []
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            rec = cls._normalize_authenticator(tenant_id, raw)
            if rec is not None:
                records.append(rec)
        return records, completeness

    # ── Admin-role / privileged-identity collection (Okta message 5) ───────

    @staticmethod
    def _fetch_iam_object_list(
        client: httpx.Client, trusted_origin: str, path: str, list_key: str,
        *, cap: int, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        """Fetch an Okta IAM-API list endpoint that wraps its array in a
        JSON object (e.g. ``{"roles": [...], "_links": {"next": {...}}}``)
        rather than the bare-array shape every other endpoint in this
        connector uses (handled by ``paginate()``/``_collect_family()``).
        Bounded by ``_MAX_PAGES`` pages and ``cap`` total items, same
        DENIED/UNAVAILABLE/PARTIAL/COMPLETE semantics as
        ``_collect_family()``. Defensively also accepts a bare-array
        response, in case a given Okta API version/edition returns one.
        """
        items: list[dict] = []
        url = path
        params: Optional[dict] = {"limit": str(_DEFAULT_PAGE_LIMIT)}
        trusted_netloc = urlparse(trusted_origin).netloc

        for page_num in range(_MAX_PAGES):
            outcome = call_okta(client, "GET", url, params=params, _sleep_fn=_sleep_fn)
            if not outcome.ok:
                if page_num == 0:
                    if outcome.category == CATEGORY_PERMISSION_DENIED:
                        return [], FAMILY_DENIED
                    return [], FAMILY_UNAVAILABLE
                break

            try:
                body = outcome.response.json()
            except ValueError:
                if page_num == 0:
                    return [], FAMILY_UNAVAILABLE
                break

            if isinstance(body, dict):
                page_items = body.get(list_key)
            elif isinstance(body, list):
                page_items = body
            else:
                page_items = None
            if not isinstance(page_items, list):
                if page_num == 0:
                    return [], FAMILY_UNAVAILABLE
                break
            items.extend(page_items)

            next_url = None
            if isinstance(body, dict):
                links = body.get("_links") if isinstance(body.get("_links"), dict) else {}
                next_link = links.get("next") if isinstance(links.get("next"), dict) else {}
                candidate = next_link.get("href")
                if isinstance(candidate, str) and candidate and urlparse(candidate).netloc == trusted_netloc:
                    next_url = candidate
            if not next_url or len(items) >= cap:
                break
            url = next_url
            params = None

        if len(items) >= cap:
            return items[:cap], FAMILY_PARTIAL
        return items, FAMILY_COMPLETE

    @classmethod
    def _resolve_resource_set_scope(
        cls,
        client: httpx.Client,
        trusted_origin: str,
        resource_set_id: Optional[str],
        cache: dict,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> dict:
        """Resolve a custom-role ASSIGNMENT's resource-set scope posture.

        Only resolves resource sets that are ACTUALLY referenced by a
        collected assignment — never a blind walk of every resource set
        in the tenant — and caches by ``resource_set_id`` so the same set
        referenced by multiple assignments is only fetched once. Returns
        a dict merge-able onto an assignment record; never raw resource
        ORNs/paths beyond the categorized counts.
        """
        empty = {
            "resource_set_scope_category": None,
            "resource_set_app_count": None,
            "resource_set_group_count": None,
            "resource_set_user_count": None,
        }
        if not resource_set_id:
            return empty
        if resource_set_id in cache:
            return cache[resource_set_id]

        raw_resources, completeness = cls._fetch_iam_object_list(
            client, trusted_origin, f"/api/v1/iam/resource-sets/{resource_set_id}/resources", "resources",
            cap=_MAX_RESOURCES_PER_SET, _sleep_fn=_sleep_fn,
        )
        if completeness not in (FAMILY_COMPLETE, FAMILY_PARTIAL):
            result = dict(empty)
        else:
            scope, app_count, group_count, user_count = categorize_resource_set_resources(raw_resources)
            result = {
                "resource_set_scope_category": scope,
                "resource_set_app_count": app_count,
                "resource_set_group_count": group_count,
                "resource_set_user_count": user_count,
            }
        cache[resource_set_id] = result
        return result

    @classmethod
    def _fetch_custom_admin_roles(
        cls, client: httpx.Client, trusted_origin: str, tenant_id: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        """Collect real custom admin roles from ``GET /api/v1/iam/roles``
        (tenant-wide, not per-principal) plus, per role, its permission
        identifiers from ``GET /api/v1/iam/roles/{roleId}/permissions``
        (bounded — one call per custom role, and real tenants have at
        most a few dozen custom roles, never proportional to user count).
        """
        raw_roles, completeness = cls._fetch_iam_object_list(
            client, trusted_origin, "/api/v1/iam/roles", "roles",
            cap=_MAX_CUSTOM_ADMIN_ROLES, _sleep_fn=_sleep_fn,
        )
        records: list[dict] = []
        for raw_role in raw_roles:
            if not isinstance(raw_role, dict):
                continue
            role_id = raw_role.get("id")
            if not isinstance(role_id, str) or not role_id.strip():
                continue
            permissions, perm_completeness = cls._fetch_iam_object_list(
                client, trusted_origin, f"/api/v1/iam/roles/{role_id}/permissions", "permissions",
                cap=_MAX_PERMISSIONS_PER_ROLE, _sleep_fn=_sleep_fn,
            )
            permission_ids = [
                p.get("label") if isinstance(p, dict) else p
                for p in permissions
            ] if perm_completeness in (FAMILY_COMPLETE, FAMILY_PARTIAL) else None
            rec = cls._normalize_custom_admin_role(tenant_id, raw_role, permission_ids)
            if rec is not None:
                records.append(rec)
        return records, completeness

    @classmethod
    def _fetch_user_admin_role_assignments(
        cls,
        client: httpx.Client,
        trusted_origin: str,
        tenant_id: str,
        user_records: list[dict],
        custom_role_records_by_id: dict,
        resource_set_cache: dict,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str, dict]:
        """Collect user<->admin-role direct assignment edges.

        Call-complexity design: Okta has no tenant-wide endpoint listing
        every built-in role assignment — only ``GET /api/v1/users/{id}/roles``
        exists. This genuinely IS one request per user walked (unlike
        groups/apps/policies, where the parent collection itself is the
        bottleneck resource). Bounded at
        ``_MAX_USERS_FOR_ROLE_ENUMERATION`` (see that constant's docstring
        for the scale rationale) — a truncated walk is reported
        FAMILY_PARTIAL, never silently treated as "these users have no
        admin roles".

        Returns ``(assignment_records, completeness, builtin_role_records_by_type)``.
        """
        if not user_records:
            return [], FAMILY_COMPLETE, {}

        users_to_walk = user_records[:_MAX_USERS_FOR_ROLE_ENUMERATION]
        truncated_user_list = len(user_records) > len(users_to_walk)

        records: list[dict] = []
        builtin_roles_by_type: dict = {}
        succeeded = 0
        denied = 0
        other_failed = 0
        cap_hit = False

        for user_record in users_to_walk:
            user_id = user_record.get("user_id")
            if not isinstance(user_id, str) or not user_id.strip():
                continue

            raw_assignments, completeness = cls._collect_family(
                client, trusted_origin, f"/api/v1/users/{user_id}/roles",
                params=None, cap=_MAX_ROLES_PER_PRINCIPAL, _sleep_fn=_sleep_fn,
            )
            if completeness == FAMILY_DENIED:
                denied += 1
                continue
            if completeness == FAMILY_UNAVAILABLE:
                other_failed += 1
                continue
            if completeness == FAMILY_PARTIAL:
                cap_hit = True
            succeeded += 1

            for raw_assignment in raw_assignments:
                if not isinstance(raw_assignment, dict):
                    continue
                parsed = cls._parse_role_assignment(raw_assignment)
                if parsed is None:
                    continue

                if parsed["role_type"] == "CUSTOM":
                    admin_role_record = custom_role_records_by_id.get(parsed["custom_role_id"])
                    if admin_role_record is None:
                        continue
                else:
                    admin_role_record = builtin_roles_by_type.get(parsed["role_type"])
                    if admin_role_record is None:
                        admin_role_record = cls._normalize_builtin_admin_role(
                            tenant_id, parsed["role_type"], parsed.get("label"),
                        )
                        builtin_roles_by_type[parsed["role_type"]] = admin_role_record

                if len(records) >= _MAX_TOTAL_USER_ADMIN_ROLE_ASSIGNMENTS:
                    cap_hit = True
                    break
                assignment_record = cls._normalize_user_admin_role_assignment(
                    tenant_id, user_record, parsed, admin_role_record,
                )
                if parsed["role_type"] == "CUSTOM" and parsed.get("resource_set_id"):
                    assignment_record.update(cls._resolve_resource_set_scope(
                        client, trusted_origin, parsed["resource_set_id"], resource_set_cache,
                        _sleep_fn=_sleep_fn,
                    ))
                records.append(assignment_record)
            if len(records) >= _MAX_TOTAL_USER_ADMIN_ROLE_ASSIGNMENTS:
                cap_hit = True
                break

        if succeeded == 0 and denied > 0 and other_failed == 0:
            overall = FAMILY_DENIED
        elif succeeded == 0 and other_failed > 0:
            overall = FAMILY_UNAVAILABLE
        elif denied > 0 or other_failed > 0 or cap_hit or truncated_user_list:
            overall = FAMILY_PARTIAL
        else:
            overall = FAMILY_COMPLETE

        return records, overall, builtin_roles_by_type

    @classmethod
    def _fetch_group_admin_role_assignments(
        cls,
        client: httpx.Client,
        trusted_origin: str,
        tenant_id: str,
        group_records: list[dict],
        custom_role_records_by_id: dict,
        builtin_roles_by_type: dict,
        resource_set_cache: dict,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        """Collect group<->admin-role direct assignment edges via
        ``GET /api/v1/groups/{id}/roles``. Real tenants have far fewer
        groups than users, so — unlike the user-role walk — this is not
        specially capped below the groups family's own size, mirroring
        message 2's membership-walk precedent.

        ``builtin_roles_by_type`` is shared/mutated with the user-role
        walk's discovered catalog so the SAME built-in role type observed
        on both a user and a group resolves to one identical
        ``okta_admin_role`` record.
        """
        if not group_records:
            return [], FAMILY_COMPLETE

        groups_to_walk = group_records[:_MAX_GROUPS_FOR_ROLE_ENUMERATION]
        truncated_group_list = len(group_records) > len(groups_to_walk)

        records: list[dict] = []
        succeeded = 0
        denied = 0
        other_failed = 0
        cap_hit = False

        for group_record in groups_to_walk:
            group_id = group_record.get("group_id")
            if not isinstance(group_id, str) or not group_id.strip():
                continue

            raw_assignments, completeness = cls._collect_family(
                client, trusted_origin, f"/api/v1/groups/{group_id}/roles",
                params=None, cap=_MAX_ROLES_PER_PRINCIPAL, _sleep_fn=_sleep_fn,
            )
            if completeness == FAMILY_DENIED:
                denied += 1
                continue
            if completeness == FAMILY_UNAVAILABLE:
                other_failed += 1
                continue
            if completeness == FAMILY_PARTIAL:
                cap_hit = True
            succeeded += 1

            for raw_assignment in raw_assignments:
                if not isinstance(raw_assignment, dict):
                    continue
                parsed = cls._parse_role_assignment(raw_assignment)
                if parsed is None:
                    continue

                if parsed["role_type"] == "CUSTOM":
                    admin_role_record = custom_role_records_by_id.get(parsed["custom_role_id"])
                    if admin_role_record is None:
                        continue
                else:
                    admin_role_record = builtin_roles_by_type.get(parsed["role_type"])
                    if admin_role_record is None:
                        admin_role_record = cls._normalize_builtin_admin_role(
                            tenant_id, parsed["role_type"], parsed.get("label"),
                        )
                        builtin_roles_by_type[parsed["role_type"]] = admin_role_record

                if len(records) >= _MAX_TOTAL_GROUP_ADMIN_ROLE_ASSIGNMENTS:
                    cap_hit = True
                    break
                assignment_record = cls._normalize_group_admin_role_assignment(
                    tenant_id, group_record, parsed, admin_role_record,
                )
                if parsed["role_type"] == "CUSTOM" and parsed.get("resource_set_id"):
                    assignment_record.update(cls._resolve_resource_set_scope(
                        client, trusted_origin, parsed["resource_set_id"], resource_set_cache,
                        _sleep_fn=_sleep_fn,
                    ))
                records.append(assignment_record)
            if len(records) >= _MAX_TOTAL_GROUP_ADMIN_ROLE_ASSIGNMENTS:
                cap_hit = True
                break

        if succeeded == 0 and denied > 0 and other_failed == 0:
            overall = FAMILY_DENIED
        elif succeeded == 0 and other_failed > 0:
            overall = FAMILY_UNAVAILABLE
        elif denied > 0 or other_failed > 0 or cap_hit or truncated_group_list:
            overall = FAMILY_PARTIAL
        else:
            overall = FAMILY_COMPLETE

        return records, overall

    @staticmethod
    def _derive_privileged_identities(
        tenant_id: str,
        user_index: dict,
        user_admin_assignments: list[dict],
        group_admin_assignments: list[dict],
        membership_records: list[dict],
    ) -> list[dict]:
        """Derive one ``okta_privileged_identity`` per user with >=1
        effective admin role — direct, or inherited via a privileged
        group membership. Pure local join over already-collected records
        — no additional API calls.
        """
        direct_by_user: dict = {}
        for a in user_admin_assignments:
            direct_by_user.setdefault(a["user_id"], []).append(a)

        # group_id -> list of that group's direct admin-role assignments
        group_roles: dict = {}
        for a in group_admin_assignments:
            group_roles.setdefault(a["group_id"], []).append(a)

        # user_id -> set of group_ids they belong to (from message-2 memberships)
        groups_by_user: dict = {}
        for m in membership_records:
            if m.get("group_id") in group_roles:
                groups_by_user.setdefault(m["user_id"], set()).add(m["group_id"])

        # Sorted for deterministic output ordering regardless of API
        # response order or set/dict hash-iteration order — the same
        # source data must always produce records in the same order.
        privileged_user_ids = sorted(set(direct_by_user) | set(groups_by_user))
        records: list[dict] = []

        for user_id in privileged_user_ids:
            direct_assignments = direct_by_user.get(user_id, [])
            inherited_group_ids = groups_by_user.get(user_id, set())
            inherited_assignments: list[dict] = []
            for gid in inherited_group_ids:
                inherited_assignments.extend(group_roles.get(gid, []))

            if not direct_assignments and not inherited_assignments:
                continue

            tiers = [a["privilege_tier"] for a in direct_assignments + inherited_assignments]
            highest_tier = highest_privilege_tier(tiers)
            has_super_admin = any(a["role_type"] == "SUPER_ADMIN" for a in direct_assignments + inherited_assignments)

            app_admin_scopes = {
                a["assignment_scope_category"] for a in direct_assignments
                if a["role_type"] == "APP_ADMIN"
            }
            if "all" in app_admin_scopes:
                app_admin_scope: Optional[str] = "all"
            elif "scoped" in app_admin_scopes:
                app_admin_scope = "scoped"
            elif app_admin_scopes:
                app_admin_scope = "unknown"
            else:
                app_admin_scope = None

            user_record = user_index.get(user_id)
            last_login_category = user_record.get("last_login_category") if user_record else "unknown"

            records.append({
                "record_type": OKTA_PRIVILEGED_IDENTITY,
                "record_id": f"{tenant_id}/privileged_identity/{user_id}",
                "provider_resource_id": f"users/{user_id}",
                "tenant_id": tenant_id,
                "user_id": user_id,
                "login": user_record.get("login") if user_record else None,
                "user_status": user_record.get("status") if user_record else "UNKNOWN",
                "direct_admin_role_count": len(direct_assignments),
                "group_admin_role_count": len(inherited_assignments),
                "highest_privilege_tier": highest_tier,
                "has_super_admin": has_super_admin,
                "has_high_privilege": highest_tier in ("critical", "high"),
                "privileged_via_group": len(inherited_assignments) > 0,
                "privileged_via_direct_assignment": len(direct_assignments) > 0,
                "custom_admin_role_count": sum(
                    1 for a in direct_assignments + inherited_assignments if a.get("custom")
                ),
                "application_admin_scope": app_admin_scope,
                "last_login_category": last_login_category,
                "dormant_privileged_category": categorize_dormant_privileged(last_login_category),
            })

        return records

    @staticmethod
    def _derive_privileged_groups(
        tenant_id: str,
        group_index: dict,
        group_admin_assignments: list[dict],
        membership_records: list[dict],
        user_index: dict,
    ) -> list[dict]:
        """Derive one ``okta_privileged_group`` per group with >=1 direct
        admin-role assignment. Pure local join — no additional API
        calls, and never duplicates every member's full profile (only
        aggregate suspended/deprovisioned counts)."""
        roles_by_group: dict = {}
        for a in group_admin_assignments:
            roles_by_group.setdefault(a["group_id"], []).append(a)

        members_by_group: dict = {}
        for m in membership_records:
            members_by_group.setdefault(m["group_id"], []).append(m["user_id"])

        records: list[dict] = []
        for group_id, assignments in roles_by_group.items():
            group_record = group_index.get(group_id)
            tiers = [a["privilege_tier"] for a in assignments]

            suspended = 0
            deprovisioned = 0
            for user_id in members_by_group.get(group_id, []):
                user_record = user_index.get(user_id)
                if user_record is None:
                    continue
                if user_record.get("status") == "SUSPENDED":
                    suspended += 1
                elif user_record.get("status") == "DEPROVISIONED":
                    deprovisioned += 1

            records.append({
                "record_type": OKTA_PRIVILEGED_GROUP,
                "record_id": f"{tenant_id}/privileged_group/{group_id}",
                "provider_resource_id": f"groups/{group_id}",
                "tenant_id": tenant_id,
                "group_id": group_id,
                "group_name": group_record.get("group_name") if group_record else None,
                "member_count": group_record.get("membership_count") if group_record else None,
                "admin_role_count": len(assignments),
                "highest_privilege_tier": highest_privilege_tier(tiers),
                "contains_suspended_members": suspended,
                "contains_deprovisioned_members": deprovisioned,
            })

        return records

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
        """Fetch the Okta identity + application + authentication-policy
        inventory: ``okta_organization``, ``okta_api_capability`` probes
        (message 1); ``okta_user`` / ``okta_group`` /
        ``okta_group_membership`` (message 2); ``okta_application`` /
        ``okta_application_user_assignment`` /
        ``okta_application_group_assignment`` (message 3); ``okta_policy``
        / ``okta_policy_rule`` / ``okta_authenticator`` (message 4).

        Does NOT collect privileged/admin roles yet — see the module
        docstring for the permanent sensitive-data boundary and
        ``okta_schema.py`` for what later messages will add.

        Every family fails independently: if e.g. policy rules are denied
        while everything else is readable, the rest is still returned and
        ``okta_organization.family_completeness`` reports the gap — a
        family failure never aborts the whole fetch, and a denied/
        unreadable family is never silently reported as "zero" (see
        ``_collect_family``/``_fetch_memberships``/
        ``_fetch_app_user_assignments``/``_fetch_app_group_assignments``/
        ``_fetch_policy_rules``).

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
            membership_records, memberships_completeness, counts_by_group, membership_status_by_group = (
                self._fetch_memberships(
                    client, org_url, tenant_id, raw_groups, group_records_by_id, user_index,
                    _sleep_fn=_sleep_fn,
                )
            )

            # Backfill membership_count only for groups whose own membership
            # walk actually succeeded — a group whose walk was denied/failed
            # keeps membership_count=None (unknown), never 0. Also backfill
            # each group's own membership_collection_status (Okta message 7)
            # so diff-time false-removal suppression can scope itself to
            # just the groups whose walk failed, not every group tenant-wide.
            group_records: list[dict] = []
            for group_id, group_rec in group_records_by_id.items():
                count = counts_by_group.get(group_id)
                group_rec["membership_count"] = count
                group_rec["membership_count_category"] = categorize_membership_count(count)
                group_rec["membership_collection_status"] = membership_status_by_group.get(group_id, "unknown")
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
            app_user_assignment_records, app_user_assignments_completeness, user_counts_by_app, user_assignment_status_by_app = (
                self._fetch_app_user_assignments(
                    client, org_url, tenant_id, raw_apps, app_records_by_id, user_index,
                    _sleep_fn=_sleep_fn,
                )
            )

            # ── Application group assignments ───────────────────────────────
            app_group_assignment_records, app_group_assignments_completeness, group_counts_by_app, group_assignment_status_by_app = (
                self._fetch_app_group_assignments(
                    client, org_url, tenant_id, raw_apps, app_records_by_id, group_records_by_id,
                    _sleep_fn=_sleep_fn,
                )
            )

            # Backfill assignment counts only for apps whose own assignment
            # walk actually succeeded — an app whose walk was denied/failed
            # keeps the count=None (unknown), never 0. Also backfill each
            # app's own per-parent collection status (Okta message 7).
            app_records: list[dict] = []
            for app_id, app_rec in app_records_by_id.items():
                app_rec["user_assignment_count"] = user_counts_by_app.get(app_id)
                app_rec["group_assignment_count"] = group_counts_by_app.get(app_id)
                app_rec["user_assignment_collection_status"] = user_assignment_status_by_app.get(app_id, "unknown")
                app_rec["group_assignment_collection_status"] = group_assignment_status_by_app.get(app_id, "unknown")
                app_records.append(app_rec)

            # ── Policies (raw kept for rule walk; normalized after) ─────────
            raw_policies, policies_completeness = self._fetch_policies_raw(
                client, org_url, _sleep_fn=_sleep_fn,
            )
            policy_records_by_id: dict = {}
            for raw_policy in raw_policies:
                if not isinstance(raw_policy, dict):
                    continue
                policy_id = raw_policy.get("id")
                if not isinstance(policy_id, str) or not policy_id.strip():
                    continue
                # rule_count filled in below once rules are collected.
                rec = self._normalize_policy(tenant_id, raw_policy, rule_count=None)
                if rec is not None:
                    policy_records_by_id[policy_id] = rec

            # ── Policy rules ─────────────────────────────────────────────
            policy_rule_records, policy_rules_completeness, rule_counts_by_policy, rule_status_by_policy = (
                self._fetch_policy_rules(
                    client, org_url, tenant_id, raw_policies, policy_records_by_id,
                    _sleep_fn=_sleep_fn,
                )
            )

            # Backfill rule_count only for policies whose own rule walk
            # actually succeeded — a policy whose walk was denied/failed
            # keeps rule_count=None (unknown), never 0. Also backfill each
            # policy's own rule_collection_status (Okta message 7).
            policy_records: list[dict] = []
            for policy_id, policy_rec in policy_records_by_id.items():
                policy_rec["rule_count"] = rule_counts_by_policy.get(policy_id)
                policy_rec["rule_collection_status"] = rule_status_by_policy.get(policy_id, "unknown")
                policy_records.append(policy_rec)

            # ── Authenticators ───────────────────────────────────────────
            authenticator_records, authenticators_completeness = self._fetch_authenticators(
                client, org_url, tenant_id, _sleep_fn=_sleep_fn,
            )

            # ── Custom admin roles (tenant-wide) ────────────────────────────
            custom_admin_role_records, custom_admin_roles_completeness = self._fetch_custom_admin_roles(
                client, org_url, tenant_id, _sleep_fn=_sleep_fn,
            )
            custom_role_records_by_id = {r["role_id"]: r for r in custom_admin_role_records}
            # Shared across both walks so a resource set referenced by both
            # a user- and a group-scoped custom-role assignment is only
            # ever fetched once.
            resource_set_cache: dict = {}

            # ── User admin-role assignments (per-user walk — see
            #    _MAX_USERS_FOR_ROLE_ENUMERATION for the bounded N+1 design) ──
            user_admin_role_assignment_records, user_admin_roles_completeness, builtin_roles_by_type = (
                self._fetch_user_admin_role_assignments(
                    client, org_url, tenant_id, user_records, custom_role_records_by_id,
                    resource_set_cache, _sleep_fn=_sleep_fn,
                )
            )

            # ── Group admin-role assignments (per-group walk) ───────────────
            group_admin_role_assignment_records, group_admin_roles_completeness = (
                self._fetch_group_admin_role_assignments(
                    client, org_url, tenant_id, group_records, custom_role_records_by_id,
                    builtin_roles_by_type, resource_set_cache, _sleep_fn=_sleep_fn,
                )
            )

            admin_role_records = list(custom_admin_role_records) + list(builtin_roles_by_type.values())

            # ── Effective privileged identity / group derivation (local
            #    join over already-collected records — no extra API calls) ──
            group_index = {g["group_id"]: g for g in group_records}
            privileged_identity_records = self._derive_privileged_identities(
                tenant_id, user_index,
                user_admin_role_assignment_records, group_admin_role_assignment_records,
                membership_records,
            )
            privileged_group_records = self._derive_privileged_groups(
                tenant_id, group_index,
                group_admin_role_assignment_records, membership_records, user_index,
            )

            org_record = self._normalize_organization(
                org_hostname, raw_org,
                family_completeness={
                    "users": users_completeness,
                    "groups": groups_completeness,
                    "memberships": memberships_completeness,
                    "applications": applications_completeness,
                    "app_user_assignments": app_user_assignments_completeness,
                    "app_group_assignments": app_group_assignments_completeness,
                    "policies": policies_completeness,
                    "policy_rules": policy_rules_completeness,
                    "authenticators": authenticators_completeness,
                    "custom_admin_roles": custom_admin_roles_completeness,
                    "user_admin_role_assignments": user_admin_roles_completeness,
                    "group_admin_role_assignments": group_admin_roles_completeness,
                },
            )

            records.append(org_record)
            records.extend(user_records)
            records.extend(group_records)
            records.extend(membership_records)
            records.extend(app_records)
            records.extend(app_user_assignment_records)
            records.extend(app_group_assignment_records)
            records.extend(policy_records)
            records.extend(policy_rule_records)
            records.extend(authenticator_records)
            records.extend(admin_role_records)
            records.extend(user_admin_role_assignment_records)
            records.extend(group_admin_role_assignment_records)
            records.extend(privileged_identity_records)
            records.extend(privileged_group_records)
            records.extend(self._probe_capabilities(client, tenant_id))

        return records


# ── Permission diagnostics (Okta message 8 — public launch) ────────────────
#
# The 12 monitored API families, in the order surfaced to the user. Each key
# matches a key in ``okta_organization.family_completeness`` (see
# ``OktaConnector.fetch()`` above).
_OKTA_DIAGNOSTIC_FAMILIES: tuple[tuple[str, str], ...] = (
    ("users", "Users"),
    ("groups", "Groups"),
    ("memberships", "Group memberships"),
    ("applications", "Applications"),
    ("app_user_assignments", "Application user assignments"),
    ("app_group_assignments", "Application group assignments"),
    ("policies", "Authentication / password policies"),
    ("policy_rules", "Policy rules"),
    ("authenticators", "Authenticators (MFA factor types)"),
    ("custom_admin_roles", "Custom administrator roles"),
    ("user_admin_role_assignments", "User administrator-role assignments"),
    ("group_admin_role_assignments", "Group administrator-role assignments"),
)

_OKTA_DIAGNOSTIC_STATUS_LABEL: dict[str, str] = {
    FAMILY_COMPLETE: "readable",
    FAMILY_PARTIAL: "partially readable",
    FAMILY_DENIED: "denied by this token's admin role",
    FAMILY_UNAVAILABLE: "unavailable",
    "unknown": "status unknown",
}


def build_okta_permission_diagnostics(records: list[dict]) -> dict:
    """Build a redacted, user-facing permission/coverage diagnostics report
    from a normalized Okta record list (the output of ``fetch()``).

    Never includes the API token, Authorization header value, or any raw
    Okta API response — only category labels and the per-family
    ``family_completeness`` status already present on the
    ``okta_organization`` record.

    Coverage semantics (Okta message 8):
      * ``"full"``    — every monitored family reports ``"complete"``.
      * ``"partial"`` — the org is reachable and at least one family is
        readable, but one or more of the 12 families is denied,
        unavailable, or only partially collected. This is NOT rejected —
        Okta API tokens inherit the creating admin's role, and a
        least-privileged (non-Super-Admin) role commonly cannot see custom
        admin roles, System Log, or every admin-role-assignment edge case.
      * ``"invalid"`` — the org record itself could not be found (the org
        call never succeeded), or literally zero of the 12 families are
        readable — a token that can prove tenant identity but reads
        nothing meaningful is not useful for monitoring.
    """
    org_record = next((r for r in records if r.get("record_type") == OKTA_ORGANIZATION), None)
    if org_record is None:
        return {
            "org_reachable": False,
            "coverage": "invalid",
            "sections": [],
            "security_findings_note": (
                "Security Findings were not evaluated — the Okta org could not be reached."
            ),
            "change_detection_note": "Change detection is unavailable without a successful sync.",
        }

    family_completeness = org_record.get("family_completeness") or {}
    entries = []
    complete_count = 0
    readable_count = 0
    for family_key, label in _OKTA_DIAGNOSTIC_FAMILIES:
        status = family_completeness.get(family_key, "unknown")
        entries.append({
            "resource": label,
            "status": status,
            "status_label": _OKTA_DIAGNOSTIC_STATUS_LABEL.get(status, "status unknown"),
        })
        if status == FAMILY_COMPLETE:
            complete_count += 1
        if status in (FAMILY_COMPLETE, FAMILY_PARTIAL):
            readable_count += 1

    if readable_count == 0:
        coverage = "invalid"
    elif complete_count == len(_OKTA_DIAGNOSTIC_FAMILIES):
        coverage = "full"
    else:
        coverage = "partial"

    return {
        "org_reachable": True,
        "tenant_id": org_record.get("tenant_id"),
        "org_hostname": org_record.get("org_hostname"),
        "sections": [{"name": "Monitored API families", "resources": entries}],
        "coverage": coverage,
        "security_findings_note": (
            "Security Findings are evaluated only for families ConfigTrace could read; "
            "denied/unavailable families are excluded, never assumed safe."
        ),
        "change_detection_note": (
            "Change detection is available for every family marked readable above; "
            "denied/unavailable/partial families never generate false removal Changes."
        ),
        "record_count": len(records),
    }


def format_okta_permission_diagnostics_text(report: dict) -> str:
    """Render ``build_okta_permission_diagnostics()``'s output as a plain-text
    report. Purely a display helper — contains no information not already in
    the structured report."""
    if not report.get("org_reachable"):
        return "Okta connection could not be validated.\n\n" + report.get("security_findings_note", "")

    lines = ["Okta connection validated", "", f"Coverage:\n  {report['coverage'].capitalize()}", ""]
    for section in report["sections"]:
        lines.append(f"{section['name']}:")
        for entry in section["resources"]:
            lines.append(f"  {entry['resource']}: {entry['status_label']}")
    lines.append("")
    lines.append(f"Security Findings:\n  {report['security_findings_note']}")
    return "\n".join(lines)
