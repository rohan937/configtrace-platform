"""Sentry provider connector (Sentry messages 1-2 of 8).

Establishes a secure, read-only connection to a Sentry SaaS organization
using a bearer auth token over Sentry's REST API, resolves a stable
organization identity, probes (msg 1) the future record families this
connector doesn't collect yet, and collects (msg 2) projects, teams,
organization members, team memberships, and project-team assignments.

This connector intentionally does NOT yet collect alert rules (issue or
metric), integrations, webhooks, repositories, ownership rules, or
releases. The connector is registered internally (dispatch, schema,
capability matrix) but is NOT publicly connectable — it is excluded from
the frontend's PROVIDER_IDS / CONNECTABLE_PROVIDER_IDS until Sentry
message 8.

Roadmap (message 2 owns projects/teams/members/access ONLY — do not begin
later messages):
  msg 1 — foundation, authentication, organization identity, connector.
  msg 2 (this message) — projects, teams, members, organization access,
          team membership, project-team assignment.
  msg 3 — alert rules (issue + metric), notification routing.
  msg 4 — integrations, webhooks, repositories, ownership rules, releases/
          deployment settings.
  msg 5 — security/privacy posture, effective access, privileged identities.
  msg 6 — Security Findings.
  msg 7 — exhaustive Change classification, partial-sync/reliability
          hardening.
  msg 8 — public launch.

Scope: Sentry SaaS only
------------------------
Self-hosted Sentry is NOT supported by this connector. Current official
documentation (https://develop.sentry.dev/self-hosted/) confirms
self-hosted installs configure an operator-chosen ``system.url-prefix``
with no auto-discovery mechanism — a genuinely different trust boundary
(arbitrary operator-controlled host/CA) than a single fixed, trusted SaaS
origin. Introducing an arbitrary user-supplied API host would reopen
exactly the SSRF-adjacent risk this codebase's other connectors
(Snowflake, Okta) go out of their way to avoid — so self-hosted support
is an explicit, documented foundation limitation, not an oversight.

Regional routing: current official docs confirm Sentry SaaS org-detail
responses include a ``links.regionUrl`` field, implying region-specific
hosts exist (``us.sentry.io``, ``de.sentry.io`` were seen referenced).
This connector deliberately does NOT follow ``links.regionUrl`` — doing
so would mean the SERVER tells the client which origin to trust next,
which is the same category of risk this codebase's pagination
trusted-origin enforcement exists to prevent. Every request in this
connector always targets the single fixed origin below. If a customer's
organization data genuinely lives in a region that isn't transparently
proxied through ``sentry.io``, requests may fail with a normal
not-found/permission-style error — this is a documented, acceptable
foundation limitation, not a silent failure mode.

Authentication
---------------
Bearer auth token sent as an HTTP Authorization header — no separate
token-acquisition/exchange step:

    Authorization: Bearer <auth_token>
    Accept: application/json

Credentials dict:
    organization_slug : str — the Sentry organization's URL slug. Used
                 ONLY as a path segment on the fixed ``sentry.io`` origin
                 — never accepted as a full URL, never used to construct
                 a request host.
    auth_token        : str — the bearer token secret. NEVER logged,
                 NEVER stored outside the encrypted credentials column,
                 NEVER returned in any API response, NEVER copied into a
                 normalized record.

Why an Organization Auth Token (not a personal token, not OAuth)
------------------------------------------------------------------
Current official Sentry documentation
(https://docs.sentry.io/account/auth-tokens) explicitly recommends
organization-scoped tokens for exactly this use case: "Sentry recommends
using organizational auth tokens whenever possible, as they aren't linked
to specific user accounts" — a personal (user) auth token stops working
the moment the human who created it leaves the organization, which is an
unacceptable production-reliability risk for a backend monitoring
integration. Organization tokens are bound to the organization itself,
not tied to any one human's account, and are the terminology Sentry uses
for its non-interactive, backend-owned credential — the same
"organization/tenant-owned service credential" shape as Snowflake's PAT
and Okta's API token elsewhere in this codebase.

No interactive OAuth (Authorization Code + PKCE, Device Authorization
Flow) is implemented — those exist in current Sentry docs for
third-party/CI integrations with a human consent step, which does not
fit "backend SaaS connector with a dedicated organization credential"
for this provider's first message. No browser SSO, device flow, or CLI
login is implemented or ever will be — ConfigTrace is a backend SaaS
connector with no interactive session.

Token scopes (narrowest practical read-only set, exact strings confirmed
via current official docs at https://docs.sentry.io/api/permissions/ and
the individual endpoint reference pages this message actually calls):
    org:read           — organization detail, projects list, teams list
    member:read        — organization members list
    alerts:read         — metric alert rules
    org:integrations    — integrations, repositories
    project:releases    — releases

No write/admin scope is ever requested. ConfigTrace never mutates a
connected Sentry organization.

Transport choice: plain HTTPS REST (not the Sentry SDK)
----------------------------------------------------------
Sentry's REST management API is a plain JSON-over-HTTPS API exactly like
every other HTTP-based connector in this codebase already uses ``httpx``
for. ``sentry-sdk`` (if ever added to this repository for ConfigTrace's
OWN error telemetry) is a client instrumentation library for SENDING
error events — it has no bearing on and is never used for reading a
customer's Sentry organization configuration via the management API. This
separation is permanent and load-bearing: this module never imports
``sentry_sdk``, never reads ``SENTRY_DSN``/``SENTRY_AUTH_TOKEN`` (or any
other environment variable) for a customer's credentials, and a
customer's ``auth_token`` never enters a global environment variable —
it lives only in the per-request credentials dict decrypted from that
customer's ``Integration`` row.

Read-only API discipline
--------------------------
Every request this connector issues is a GET request to a fixed,
connector-owned path template — never a broad user-controlled path, never
POST/PUT/PATCH/DELETE. ConfigTrace never mutates a connected Sentry
organization.

No Sentry event data, ever
-----------------------------
This provider is about Sentry CONFIGURATION, never event/issue data. This
connector never fetches error events, stack traces, breadcrumbs, request
bodies, user context, issue titles/messages, source code, release
artifacts, attachments, replay data, session replay, performance spans,
profiles, or logs — and never will, in any later message. ConfigTrace's
Sentry scope is configuration and access posture, not issue aggregation.

SECURITY — what is NEVER stored, logged, or returned
------------------------------------------------------
- auth_token — NEVER stored on the connector instance beyond one call's
  local scope, NEVER logged, NEVER included in error messages or
  exceptions, NEVER written to any record.
- Authorization header value — NEVER appears in logs or exception text.
- Raw Sentry API response bodies — NEVER stored; only flat safe scalars
  extracted via a dedicated per-endpoint normalizer.
- DSNs, client keys, secret keys, webhook secrets, integration
  credentials, session cookies, and arbitrary organization/project data —
  NEVER fetched in this foundation message.

Documentation verification (current official docs only, accessed
2026-07-30, docs.sentry.io / develop.sentry.dev)
---------------------------------------------------------------------
See ``backend/tests/reports/sentry_foundation_contract.md`` for the full
verification log with URLs, dates, and per-topic notes/ambiguities
(including the several points current docs left genuinely ambiguous —
e.g. no officially-documented 429/Retry-After contract for this REST
surface specifically, no officially-confirmed token-prefix format). This
connector's design choices err conservative wherever docs were ambiguous
rather than guessing.
"""

from __future__ import annotations

import logging
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
from app.connectors.sentry_schema import (
    CAPABILITY_AVAILABLE,
    CAPABILITY_DENIED,
    CAPABILITY_FAMILIES,
    CAPABILITY_FAMILY_INTEGRATIONS,
    CAPABILITY_FAMILY_ISSUE_ALERTS,
    CAPABILITY_FAMILY_MEMBERS,
    CAPABILITY_FAMILY_METRIC_ALERTS,
    CAPABILITY_FAMILY_OWNERSHIP_RULES,
    CAPABILITY_FAMILY_PROJECTS,
    CAPABILITY_FAMILY_RELEASES,
    CAPABILITY_FAMILY_REPOSITORIES,
    CAPABILITY_FAMILY_TEAMS,
    CAPABILITY_FAMILY_WEBHOOKS,
    CAPABILITY_MALFORMED,
    CAPABILITY_THROTTLED,
    CAPABILITY_TIMED_OUT,
    CAPABILITY_UNAVAILABLE,
    CAPABILITY_UNKNOWN,
    CAPABILITY_UNSUPPORTED,
    COLLECTION_FAMILIES_ALWAYS_UNSUPPORTED,
    COLLECTION_FAMILY_ALERT_ACTIONS,
    COLLECTION_FAMILY_CODE_MAPPINGS,
    COLLECTION_FAMILY_ISSUE_ALERT_RULES,
    COLLECTION_FAMILY_MEMBERS,
    COLLECTION_FAMILY_METRIC_ALERT_RULES,
    COLLECTION_FAMILY_ORGANIZATION_INTEGRATIONS,
    COLLECTION_FAMILY_OWNERSHIP_RULES,
    COLLECTION_FAMILY_PRIVILEGED_MEMBERS,
    COLLECTION_FAMILY_PRIVILEGED_TEAMS,
    COLLECTION_FAMILY_PROJECT_TEAM_ASSIGNMENTS,
    COLLECTION_FAMILY_PROJECTS,
    COLLECTION_FAMILY_REPOSITORIES,
    COLLECTION_FAMILY_ROUTING_CONTEXT,
    COLLECTION_FAMILY_TEAM_MEMBERSHIPS,
    COLLECTION_FAMILY_TEAMS,
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    FAMILY_PARTIAL,
    FAMILY_UNAVAILABLE,
    ORG_ROLE_UNKNOWN,
    OWNER_TYPE_TEAM,
    OWNER_TYPE_UNKNOWN,
    OWNER_TYPE_USER,
    ROUTING_CONTEXT_TYPE_ALERT_ACTION,
    ROUTING_CONTEXT_TYPE_OWNERSHIP_RULE,
    SENTRY_ALERT_ACTION,
    SENTRY_API_CAPABILITY,
    SENTRY_CODE_MAPPING,
    SENTRY_ISSUE_ALERT_RULE,
    SENTRY_MEMBER,
    SENTRY_METRIC_ALERT_RULE,
    SENTRY_METRIC_ALERT_TRIGGER,
    SENTRY_ORGANIZATION,
    SENTRY_ORGANIZATION_INTEGRATION,
    SENTRY_OWNERSHIP_RULE,
    SENTRY_PRIVILEGED_MEMBER,
    SENTRY_PRIVILEGED_TEAM,
    SENTRY_PROJECT,
    SENTRY_PROJECT_TEAM_ASSIGNMENT,
    SENTRY_REPOSITORY,
    SENTRY_ROUTING_CONTEXT,
    SENTRY_TEAM,
    SENTRY_TEAM_MEMBERSHIP,
    STRUCTURALLY_UNSUPPORTED_FAMILIES,
    TEAM_ADMIN_CONTRIBUTION_TIER,
    TEAM_ROLE_ADMIN,
    compute_coverage_state,
    format_capability_diagnostics,
    categorize_aggregate,
    categorize_auto_assignment,
    categorize_dataset,
    categorize_detection_type,
    categorize_environment,
    categorize_integration_control,
    categorize_issue_action_id,
    categorize_issue_alert_status,
    categorize_match_type,
    categorize_matcher,
    categorize_member_status,
    categorize_metric_action_type,
    categorize_metric_alert_status,
    categorize_object_status,
    categorize_org_role,
    categorize_owner,
    categorize_platform,
    categorize_project_status,
    categorize_provider,
    categorize_repository_control,
    categorize_target_type,
    categorize_team_role,
    categorize_threshold_type,
    categorize_trigger_label,
    highest_privilege_tier,
    organization_wide_access_for_org_role,
    privilege_tier_for_org_role,
    validate_auth_token,
    validate_organization_slug,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ──────────────────────────────────────────────────

_TIMEOUT = 30.0
_MAX_STR_LEN = 200

# Fixed, trusted Sentry SaaS API origin. Never derived from user input —
# see the module docstring's "Scope: Sentry SaaS only" and "Regional
# routing" sections for why this is never overridden by a credential
# field or a server-supplied URL (e.g. ``links.regionUrl``).
_BASE_URL = "https://sentry.io/api/0"
_TRUSTED_ORIGIN = "https://sentry.io"

# Bounded pagination (production-ready for later messages' collection —
# message 1's own probes never paginate beyond a single page).
_MAX_PAGES = 200

# Bounded collection caps (Sentry message 2 of 8) — mirror the Okta
# connector's naming/value conventions (``_MAX_USERS``, ``_MAX_GROUPS``,
# ``_MAX_GROUPS_FOR_MEMBERSHIP_ENUMERATION``). Hitting a cap is reported as
# FAMILY_PARTIAL, never silently truncated as if complete.
_MAX_PROJECTS = 20_000
_MAX_TEAMS = 10_000
_MAX_MEMBERS = 100_000
_MAX_TEAMS_FOR_MEMBERSHIP_ENUMERATION = 10_000
_MAX_MEMBERS_PER_TEAM_WALK = 5_000
_MAX_TOTAL_TEAM_MEMBERSHIPS = 500_000
_PAGE_SIZE_PARAMS = {"per_page": "100"}

# Bounded collection caps (Sentry message 3 of 8) — same conventions as
# message 2's caps above.
_MAX_METRIC_ALERT_RULES = 25_000
_MAX_ISSUE_ALERT_RULES_PER_PROJECT = 1_000
_MAX_PROJECTS_FOR_ISSUE_ALERT_ENUMERATION = 20_000
_MAX_TOTAL_ISSUE_ALERT_RULES = 50_000
_MAX_TOTAL_ALERT_ACTIONS = 100_000

# Bounded collection caps (Sentry message 4 of 8) — same conventions.
_MAX_ORGANIZATION_INTEGRATIONS = 5_000
_MAX_REPOSITORIES = 10_000
_MAX_CODE_MAPPINGS = 25_000
_MAX_PROJECTS_FOR_OWNERSHIP_ENUMERATION = 20_000
_MAX_OWNERSHIP_RULES_PER_PROJECT = 5_000
_MAX_TOTAL_OWNERSHIP_RULES = 50_000

# 429/5xx retry bounds — bounded exponential backoff with jitter, mirroring
# the Okta/Entra/Snowflake reliability pattern.
_MAX_THROTTLE_RETRIES = 4
_THROTTLE_BASE_DELAY_SECONDS = 1.0
_THROTTLE_MAX_DELAY_SECONDS = 30.0
_MAX_SERVER_ERROR_RETRIES = 2
_SERVER_ERROR_BASE_DELAY_SECONDS = 0.5

# Capability probes: (family, path). Every probe is a single, minimal,
# organization-scoped GET — never a broad enumeration, never a second
# page. No ``limit``/``per_page`` parameter is sent: current official
# docs do not confirm a generically-supported page-size parameter across
# all these endpoints, so probes bound cost by reading page 1 only and
# never following pagination, rather than guessing at an unconfirmed
# parameter name. Families in ``STRUCTURALLY_UNSUPPORTED_FAMILIES`` are
# NOT in this tuple — they never make an HTTP call at all (see
# ``sentry_schema.py``'s module docstring for why).
_CAPABILITY_PROBES: tuple[tuple[str, str], ...] = (
    (CAPABILITY_FAMILY_PROJECTS, "/organizations/{slug}/projects/"),
    (CAPABILITY_FAMILY_TEAMS, "/organizations/{slug}/teams/"),
    (CAPABILITY_FAMILY_MEMBERS, "/organizations/{slug}/members/"),
    (CAPABILITY_FAMILY_METRIC_ALERTS, "/organizations/{slug}/alert-rules/"),
    (CAPABILITY_FAMILY_INTEGRATIONS, "/organizations/{slug}/integrations/"),
    (CAPABILITY_FAMILY_REPOSITORIES, "/organizations/{slug}/repos/"),
    (CAPABILITY_FAMILY_RELEASES, "/organizations/{slug}/releases/"),
)

assert {f for f, _ in _CAPABILITY_PROBES} | STRUCTURALLY_UNSUPPORTED_FAMILIES == set(CAPABILITY_FAMILIES)


# ── Fail-soft API-call wrapper (mirrors the Okta/Entra/Snowflake
#    reliability pattern) ────────────────────────────────────────────────────


@dataclass
class CallOutcome:
    """Result of one fail-soft Sentry API call. ``category`` never leaks
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
CATEGORY_CLIENT_ERROR = "client_error"
CATEGORY_CONNECTION_ERROR = "connection_error"
CATEGORY_TLS_ERROR = "tls_error"
CATEGORY_TIMEOUT = "timeout"
CATEGORY_MALFORMED_RESPONSE = "malformed_response"


def _classify_response(resp: httpx.Response) -> tuple[str, str]:
    status = resp.status_code
    if status == 401:
        return CATEGORY_AUTH_FAILED, "HTTP 401: Sentry rejected the authentication token."
    if status == 403:
        return CATEGORY_PERMISSION_DENIED, "HTTP 403: the token cannot access this resource."
    if status == 404:
        return CATEGORY_NOT_FOUND, "HTTP 404: organization or resource not found."
    if status == 429:
        return CATEGORY_THROTTLED, "HTTP 429: Sentry rate-limited the request."
    if status >= 500:
        return CATEGORY_SERVER_ERROR, f"HTTP {status}: Sentry returned a server error."
    if 400 <= status < 500:
        # Any OTHER 4xx (400 malformed request, 405, 409, 422, ...) is a
        # client-side problem, never transient — must never be retried as
        # if it were a server error (Sentry message 7 fix: previously fell
        # through to CATEGORY_SERVER_ERROR and was retried).
        return CATEGORY_CLIENT_ERROR, f"HTTP {status}: Sentry rejected the request."
    return CATEGORY_SERVER_ERROR, f"HTTP {status}: unexpected Sentry API response."


def _classify_transport_exception(exc: Exception) -> tuple[str, str]:
    import ssl

    if isinstance(exc, ssl.SSLError):
        return CATEGORY_TLS_ERROR, "TLS certificate verification failed."
    if isinstance(exc, httpx.ConnectTimeout):
        return CATEGORY_TIMEOUT, "The request to the Sentry API timed out connecting."
    if isinstance(exc, httpx.ReadTimeout):
        return CATEGORY_TIMEOUT, "The request to the Sentry API timed out waiting for a response."
    if isinstance(exc, httpx.TimeoutException):
        return CATEGORY_TIMEOUT, "The request to the Sentry API timed out."
    if isinstance(exc, httpx.ConnectError):
        cause = str(exc).lower()
        if "certificate" in cause or "ssl" in cause or "tls" in cause:
            return CATEGORY_TLS_ERROR, "TLS certificate verification failed."
        if "name or service not known" in cause or "nodename nor servname" in cause or "getaddrinfo failed" in cause:
            return CATEGORY_CONNECTION_ERROR, "Could not resolve the Sentry API hostname (DNS failure)."
        return CATEGORY_CONNECTION_ERROR, "Could not connect to the Sentry API."
    if isinstance(exc, httpx.RequestError):
        return CATEGORY_CONNECTION_ERROR, "Could not connect to the Sentry API."
    return CATEGORY_MALFORMED_RESPONSE, "Sentry returned a response that could not be processed."


def _retry_after_seconds(resp: httpx.Response) -> Optional[float]:
    """Current official Sentry docs do NOT document a ``Retry-After``
    header for this REST management API surface (only for the separate
    SDK/ingestion transport rate-limit contract) — but honoring it if
    present costs nothing and is strictly safer than ignoring it, so this
    connector still checks for it defensively. Falls back to
    ``X-Sentry-Rate-Limit-Reset`` (a documented header — an absolute
    epoch-seconds reset time) when ``Retry-After`` is absent."""
    raw = resp.headers.get("Retry-After")
    if raw is not None:
        try:
            value = float(raw)
            if value >= 0:
                return value
        except (TypeError, ValueError):
            pass

    reset_raw = resp.headers.get("X-Sentry-Rate-Limit-Reset")
    if reset_raw is not None:
        try:
            import time as _time

            reset_epoch = float(reset_raw)
            delta = reset_epoch - _time.time()
            if delta >= 0:
                return delta
        except (TypeError, ValueError):
            pass
    return None


def _throttle_backoff_seconds(attempt: int, *, retry_after: Optional[float]) -> float:
    """Bounded exponential backoff with jitter for a 429 retry attempt
    (0-indexed). Honors a resolved retry-after hint when present."""
    import random

    if retry_after is not None:
        return min(retry_after, _THROTTLE_MAX_DELAY_SECONDS)
    base = min(_THROTTLE_BASE_DELAY_SECONDS * (2 ** attempt), _THROTTLE_MAX_DELAY_SECONDS)
    jitter = random.uniform(0, base * 0.25)
    return min(base + jitter, _THROTTLE_MAX_DELAY_SECONDS)


def _server_error_backoff_seconds(attempt: int) -> float:
    return _SERVER_ERROR_BASE_DELAY_SECONDS * (2 ** attempt)


_CATEGORY_STATUS_CODE = {
    CATEGORY_PERMISSION_DENIED: 403,
    CATEGORY_NOT_FOUND: 404,
    CATEGORY_SERVER_ERROR: 500,
    CATEGORY_MALFORMED_RESPONSE: None,
}


def _raise_for_outcome(outcome: CallOutcome, *, context: str = "") -> httpx.Response:
    """Raise the appropriate connector exception for a failed
    ``CallOutcome``, or return the response for a successful one. Never
    includes credential material in the raised message — only the fixed,
    safe ``detail`` string set by ``_classify_response``/
    ``_classify_transport_exception``."""
    if outcome.ok:
        return outcome.response
    suffix = f" — {context}" if context else ""
    if outcome.category == CATEGORY_AUTH_FAILED:
        raise AuthenticationError(f"sentry: {outcome.detail}{suffix}", status_code=401)
    if outcome.category == CATEGORY_PERMISSION_DENIED:
        raise AuthenticationError(f"sentry: {outcome.detail}{suffix}", status_code=403)
    if outcome.category == CATEGORY_THROTTLED:
        raise RateLimitError(f"sentry: {outcome.detail}{suffix}")
    if outcome.category in (CATEGORY_CONNECTION_ERROR, CATEGORY_TIMEOUT, CATEGORY_TLS_ERROR):
        raise NetworkError(f"sentry: {outcome.detail}{suffix}")
    raise ConnectorError(
        f"sentry: {outcome.detail}{suffix}",
        status_code=_CATEGORY_STATUS_CODE.get(outcome.category),
    )


def call_sentry(
    client: httpx.Client,
    path: str,
    *,
    params: Optional[dict] = None,
    _sleep_fn: Callable[[float], None] = None,
) -> CallOutcome:
    """Fail-soft wrapper around a single Sentry API GET call.

    Every request this connector (and every request future messages'
    collection code makes) should route through this wrapper so callers
    get the same distinguishable failure categories instead of an
    uncaught exception. This connector NEVER issues POST/PUT/PATCH/DELETE
    — ``call_sentry`` has no method parameter and always performs a GET.

    401/403 are NEVER retried as if transient. Only 429 gets a bounded
    retry with exponential backoff and jitter, capped at
    ``_MAX_THROTTLE_RETRIES`` attempts. Tests inject ``_sleep_fn`` (a
    no-op) so retry tests never actually sleep.

    SECURITY: never includes the Authorization header or auth_token value
    in any returned ``CallOutcome.detail`` — only a fixed, category-
    specific message plus the HTTP status code.
    """
    import time as _time

    sleep_fn = _sleep_fn or _time.sleep
    attempt = 0
    server_error_attempt = 0
    while True:
        try:
            resp = client.get(path, params=params, timeout=_TIMEOUT)
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
                "sentry_connector rate limited (attempt %d/%d); sleeping %.1fs",
                attempt + 1, _MAX_THROTTLE_RETRIES, delay,
            )
            sleep_fn(delay)
            attempt += 1
            continue
        if category == CATEGORY_SERVER_ERROR and server_error_attempt < _MAX_SERVER_ERROR_RETRIES:
            delay = _server_error_backoff_seconds(server_error_attempt)
            logger.warning(
                "sentry_connector transient server error (attempt %d/%d); sleeping %.1fs",
                server_error_attempt + 1, _MAX_SERVER_ERROR_RETRIES, delay,
            )
            sleep_fn(delay)
            server_error_attempt += 1
            continue

        return CallOutcome(ok=False, category=category, detail=detail)


# ── Pagination (RFC5988-style Link header, Sentry's cursor convention) ──────


def _parse_link_header(link_header: str, *, trusted_origin: str) -> dict[str, dict]:
    """Parse a Sentry ``Link`` response header into
    ``{rel: {"url": str, "results": bool, "cursor": str | None}}``.

    Sentry ALWAYS includes both ``rel="previous"`` and ``rel="next"``
    entries, each carrying its own ``results="true"/"false"`` attribute —
    unlike a header that's simply absent when there's no more data, a
    Sentry ``rel="next"`` entry with ``results="false"`` IS the documented
    "no more pages" signal (see
    https://docs.sentry.io/api/pagination/, verified via current official
    docs). Any candidate URL whose origin does not exactly match
    ``trusted_origin`` is dropped (its ``url`` key omitted) — pagination
    must never be able to redirect this connector to an attacker-
    controlled or unrelated host.
    """
    parsed: dict[str, dict] = {}
    for part in link_header.split(","):
        segments = [s.strip() for s in part.split(";")]
        if len(segments) < 2:
            continue
        url_segment = segments[0]
        if not (url_segment.startswith("<") and url_segment.endswith(">")):
            continue
        candidate = url_segment[1:-1]

        rel = None
        results = None
        cursor = None
        for seg in segments[1:]:
            if seg.startswith('rel="') and seg.endswith('"'):
                rel = seg[5:-1]
            elif seg.startswith("rel=") and not seg.startswith('rel="'):
                rel = seg[4:].strip('"')
            elif seg.startswith('results="') and seg.endswith('"'):
                results = seg[9:-1].lower() == "true"
            elif seg.startswith('cursor="') and seg.endswith('"'):
                cursor = seg[8:-1]

        if rel is None:
            continue

        entry: dict = {"results": results, "cursor": cursor, "url": None}
        try:
            resolved = urljoin(trusted_origin + "/", candidate)
            parsed_candidate = urlparse(resolved)
            parsed_trusted = urlparse(trusted_origin)
        except ValueError:
            parsed[rel] = entry
            continue

        candidate_origin = f"{parsed_candidate.scheme}://{parsed_candidate.netloc}".lower()
        trusted = f"{parsed_trusted.scheme}://{parsed_trusted.netloc}".lower()
        if candidate_origin == trusted:
            entry["url"] = resolved
        else:
            logger.warning(
                "sentry_connector: rejected cross-origin pagination Link (expected origin %s)",
                trusted,
            )
        parsed[rel] = entry

    return parsed


def paginate_sentry(
    client: httpx.Client,
    start_path: str,
    *,
    params: Optional[dict] = None,
    max_pages: int = _MAX_PAGES,
    _sleep_fn: Callable[[float], None] = None,
) -> tuple[list[dict], bool]:
    """Follow Sentry's cursor-based Link-header pagination safely.

    Bounded by ``max_pages``. Detects a repeated cursor/URL (a
    misbehaving or malicious server serving the same page forever) and
    stops rather than looping. Only follows a ``rel="next"`` URL whose
    origin exactly matches ``_TRUSTED_ORIGIN`` — a cross-origin candidate
    is dropped and pagination is treated as truncated (see
    ``_parse_link_header``). Deduplicates items by their ``id`` field when
    present (defends against a server re-serving an overlapping page).

    Raises the same exceptions as ``call_sentry`` via ``_raise_for_outcome``
    on the FIRST page failure (a fully broken credential should fail
    loudly); any LATER page's failure stops pagination and returns what
    was collected so far, since the first page already proved the
    credential works — a transient failure mid-pagination should degrade
    to partial results, not lose everything already fetched.

    Returns ``(items, truncated)``. ``truncated`` is ``True`` when
    pagination stopped for a reason OTHER than the documented natural end
    (a ``rel="next"`` entry with ``results="false"``) — a later-page
    failure (403/429/5xx/timeout/malformed body), a repeated cursor, a
    rejected cross-origin Link, a missing/malformed Link header on a page
    that isn't the last, or hitting ``max_pages``. The caller must treat a
    truncated result as PARTIAL even when it happens to be under any
    record cap — silently reporting a mid-pagination failure as "complete"
    would make later diffs infer false removals for every record that
    would have been on the unread pages.

    Foundation note: message 1's own capability probes never call this
    function (they read page 1 only and stop) — this helper exists in
    production-ready form now so message 2+'s real collection code can
    reuse it unmodified, per this message's foundation-reuse requirement.
    """
    items: list[dict] = []
    seen_ids: set = set()
    seen_cursors: set = set()
    path = start_path
    current_params: Optional[dict] = params
    truncated = False

    for page_num in range(max_pages):
        outcome = call_sentry(client, path, params=current_params, _sleep_fn=_sleep_fn)
        if not outcome.ok:
            if page_num == 0:
                _raise_for_outcome(outcome, context=f"page {page_num + 1}")
            logger.debug("sentry_connector: pagination stopped early on page %d (%s)", page_num + 1, outcome.category)
            truncated = True
            break

        resp = outcome.response
        try:
            page_items = resp.json()
        except ValueError:
            if page_num == 0:
                raise ConnectorError("sentry: response was not valid JSON")
            truncated = True
            break
        if not isinstance(page_items, list):
            if page_num == 0:
                raise ConnectorError("sentry: expected a JSON array response")
            truncated = True
            break

        for raw in page_items:
            if isinstance(raw, dict) and isinstance(raw.get("id"), (str, int)):
                item_id = raw["id"]
                if item_id in seen_ids:
                    continue
                seen_ids.add(item_id)
            items.append(raw)

        link_header = resp.headers.get("Link") or resp.headers.get("link")
        if not link_header:
            # Sentry's documented contract always includes a Link header
            # with both relations — a completely absent header on any
            # page is unexpected, so treat conservatively as truncated
            # rather than assuming a natural end.
            truncated = True
            break

        links = _parse_link_header(link_header, trusted_origin=_TRUSTED_ORIGIN)
        next_entry = links.get("next")
        if next_entry is None or next_entry.get("results") is False:
            # Documented natural end: no next relation, or next relation
            # explicitly declares results="false".
            break
        next_url = next_entry.get("url")
        if next_url is None:
            # A next relation claimed more results but was rejected
            # (cross-origin) or malformed — do not follow it, but the
            # result must be reported as truncated, not complete.
            truncated = True
            break

        cursor_key = next_entry.get("cursor") or next_url
        if cursor_key in seen_cursors:
            logger.warning("sentry_connector: repeated pagination cursor detected; stopping")
            truncated = True
            break
        seen_cursors.add(cursor_key)

        # `next_url` has already been origin-validated against
        # `_TRUSTED_ORIGIN` by `_parse_link_header` — pass it straight
        # back into `call_sentry` as the next request's path. httpx
        # resolves an absolute URL against a client's `base_url`
        # correctly regardless of whether it shares the same path
        # prefix, so no manual path/query re-derivation is needed (and
        # re-deriving one could silently drop a prefix or param).
        path = next_url
        current_params = None
    else:
        # The `for` loop's `max_pages` bound was hit without a `break` —
        # there may be more pages beyond what we read.
        truncated = True

    return items, truncated


# ── Connector ──────────────────────────────────────────────────────────────


class SentryConnector(BaseConnector):
    """Sentry provider foundation connector (Sentry message 1 of 8).

    Stateless: credentials are passed at call time; nothing is stored on
    the instance between calls. The auth token is never stored as an
    instance attribute, never logged, never included in error messages,
    and never written to any normalized record.
    """

    # ── HTTP client ──────────────────────────────────────────────────────

    @staticmethod
    def _make_client(auth_token: str) -> httpx.Client:
        """Build an httpx.Client for the Sentry API.

        SECURITY: the token is placed in the Authorization header only
        (Bearer scheme), never stored on the connector instance or logged.
        The base URL is the single fixed, trusted SaaS origin — never
        derived from credentials or any server response.
        """
        return httpx.Client(
            base_url=_BASE_URL,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "Accept": "application/json",
            },
            timeout=_TIMEOUT,
        )

    @staticmethod
    def _credentials(credentials: dict) -> tuple[str, str]:
        organization_slug = validate_organization_slug(credentials.get("organization_slug"))
        auth_token = validate_auth_token(credentials.get("auth_token"))
        return organization_slug, auth_token

    # ── Organization identity ────────────────────────────────────────────

    @staticmethod
    def compute_organization_id(raw_id: object) -> Optional[str]:
        """Return a stable organization identifier derived from Sentry's
        own immutable ``id`` field — never the user-supplied
        ``organization_slug`` credential, since current official docs
        confirm slugs can be renamed by organization admins (renaming
        breaks deep links but does not create a new organization).

        Returns ``None`` if the raw ID is missing/malformed — callers
        must treat that as "identity could not be established", never
        silently coerce a partial identity.
        """
        if isinstance(raw_id, str) and raw_id.strip():
            return f"id:{raw_id.strip()[:100]}"
        if isinstance(raw_id, int):
            return f"id:{raw_id}"
        return None

    # ── Record normalizers ───────────────────────────────────────────────

    @staticmethod
    def _normalize_organization(
        organization_id: str,
        *,
        slug: str,
        raw: dict,
        family_completeness: Optional[dict] = None,
    ) -> dict:
        """Normalize the Sentry organization record.

        SECURITY: only the specific safe fields below are extracted from
        ``raw`` — never a raw payload dump. Fields never read/stored:
        billing information, feature-flag payloads, avatar data, customer
        data, or anything beyond the small allowlist here.

        ``family_completeness`` (later messages) reports what actually
        happened collecting projects/teams/members/etc. this fetch —
        informational only, never diff-tracked (see
        ``diff_service._SENTRY_TRACKED_FIELDS_BY_TYPE``), so a permission
        change alone never produces a noisy Change on its own.
        """
        name = raw.get("name") if isinstance(raw, dict) else None
        status = raw.get("status") if isinstance(raw, dict) else None
        status_id = status.get("id") if isinstance(status, dict) else None
        date_created = raw.get("dateCreated") if isinstance(raw, dict) else None

        # The tracked `slug` field reflects Sentry's OWN current slug from
        # the response body — never just the credential's request-time
        # slug — so a real organization rename is observable as a Change.
        # Falls back to the credential slug only if the response omitted
        # its own (should not normally happen).
        raw_slug = raw.get("slug") if isinstance(raw, dict) else None
        observed_slug = raw_slug.strip().lower()[:_MAX_STR_LEN] if isinstance(raw_slug, str) and raw_slug.strip() else slug

        return {
            "record_type": SENTRY_ORGANIZATION,
            "record_id": organization_id,
            "provider_resource_id": f"organizations/{slug}",
            "organization_id": organization_id,
            "slug": observed_slug,
            "name": (
                name.strip()[:_MAX_STR_LEN]
                if isinstance(name, str) and name.strip()
                else None
            ),
            "status_category": (
                status_id.strip()[:50]
                if isinstance(status_id, str) and status_id.strip()
                else "unknown"
            ),
            "date_created": date_created if isinstance(date_created, str) else None,
            "family_completeness": dict(family_completeness) if family_completeness else {},
        }

    @staticmethod
    def _normalize_capability(organization_id: str, family: str, status: str) -> dict:
        return {
            "record_type": SENTRY_API_CAPABILITY,
            "record_id": f"{organization_id}/capability/{family}",
            "provider_resource_id": f"capability/{family}",
            "organization_id": organization_id,
            "family": family,
            "status": status,
        }

    # ── Stable identity (Sentry message 2 of 8) ──────────────────────────
    #
    # Every project/team/member/edge below uses Sentry's own immutable
    # numeric/string ``id`` field — never ``slug``/``name``/``email`` —
    # exactly like ``compute_organization_id`` above. A rename must never
    # change identity.

    @staticmethod
    def _stable_entity_id(raw_id: object) -> Optional[str]:
        if isinstance(raw_id, str) and raw_id.strip():
            return raw_id.strip()[:100]
        if isinstance(raw_id, int):
            return str(raw_id)
        return None

    # ── Record normalizers (Sentry message 2 of 8) ───────────────────────

    @classmethod
    def _normalize_project(cls, organization_id: str, raw: dict) -> Optional[dict]:
        """Normalize a Sentry project. Never stores DSNs, client keys, or
        any event/issue data — see the module docstring's sensitive-data
        boundary."""
        project_id = cls._stable_entity_id(raw.get("id"))
        if project_id is None:
            return None

        slug = raw.get("slug")
        name = raw.get("name")
        date_created = raw.get("dateCreated")

        return {
            "record_type": SENTRY_PROJECT,
            "record_id": f"{organization_id}/project/{project_id}",
            "provider_resource_id": f"projects/{project_id}",
            "organization_id": organization_id,
            "project_id": project_id,
            "slug": slug.strip().lower()[:_MAX_STR_LEN] if isinstance(slug, str) and slug.strip() else None,
            "name": name.strip()[:_MAX_STR_LEN] if isinstance(name, str) and name.strip() else None,
            "platform_category": categorize_platform(raw.get("platform")),
            "status_category": categorize_project_status(raw.get("status")),
            "date_created": date_created if isinstance(date_created, str) else None,
        }

    @classmethod
    def _normalize_team(cls, organization_id: str, raw: dict) -> Optional[dict]:
        team_id = cls._stable_entity_id(raw.get("id"))
        if team_id is None:
            return None

        slug = raw.get("slug")
        name = raw.get("name")
        member_count = raw.get("memberCount")
        date_created = raw.get("dateCreated")

        return {
            "record_type": SENTRY_TEAM,
            "record_id": f"{organization_id}/team/{team_id}",
            "provider_resource_id": f"teams/{team_id}",
            "organization_id": organization_id,
            "team_id": team_id,
            "slug": slug.strip().lower()[:_MAX_STR_LEN] if isinstance(slug, str) and slug.strip() else None,
            "name": name.strip()[:_MAX_STR_LEN] if isinstance(name, str) and name.strip() else None,
            "member_count": member_count if isinstance(member_count, int) else None,
            "date_created": date_created if isinstance(date_created, str) else None,
        }

    @classmethod
    def _normalize_member(cls, organization_id: str, raw: dict) -> Optional[dict]:
        """Normalize an organization member.

        SECURITY: deliberately never stores email address, phone number,
        IP address, last login, avatar URL, user preferences, or auth
        material — the member's own immutable ``id`` field (the
        OrganizationMember record ID, confirmed stable independent of
        ``slug``/``name``/``email``) is the only identity stored.
        """
        member_id = cls._stable_entity_id(raw.get("id"))
        if member_id is None:
            return None

        raw_role = raw.get("orgRole") if isinstance(raw.get("orgRole"), str) else raw.get("role")
        raw_pending = raw.get("pending")
        raw_expired = raw.get("expired")
        date_created = raw.get("dateCreated")

        return {
            "record_type": SENTRY_MEMBER,
            "record_id": f"{organization_id}/member/{member_id}",
            "provider_resource_id": f"members/{member_id}",
            "organization_id": organization_id,
            "member_id": member_id,
            "org_role_category": categorize_org_role(raw_role),
            "member_status_category": categorize_member_status(raw_pending, raw_expired),
            "date_created": date_created if isinstance(date_created, str) else None,
        }

    @staticmethod
    def _normalize_team_membership(
        organization_id: str, *, team_id: str, member_id: str, team_role_category: str,
    ) -> dict:
        return {
            "record_type": SENTRY_TEAM_MEMBERSHIP,
            "record_id": f"{organization_id}/team_membership/{team_id}/{member_id}",
            "provider_resource_id": f"teams/{team_id}/members/{member_id}",
            "organization_id": organization_id,
            "team_id": team_id,
            "member_id": member_id,
            "team_role_category": team_role_category,
        }

    @staticmethod
    def _normalize_project_team_assignment(
        organization_id: str, *, project_id: str, team_id: str,
    ) -> dict:
        # Direction preserved explicitly via named ``project_id``/
        # ``team_id`` fields (team -> project, per Sentry's own nested
        # teams-list -> projects shape) rather than a single combined key.
        return {
            "record_type": SENTRY_PROJECT_TEAM_ASSIGNMENT,
            "record_id": f"{organization_id}/project_team_assignment/{project_id}/{team_id}",
            "provider_resource_id": f"projects/{project_id}/teams/{team_id}",
            "organization_id": organization_id,
            "project_id": project_id,
            "team_id": team_id,
        }

    # ── Family collection (Sentry message 2 of 8) ────────────────────────

    @staticmethod
    def _collect_family(
        client: httpx.Client,
        path: str,
        *,
        params: Optional[dict],
        cap: int,
        _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        """Paginate a whole family and report what actually happened,
        rather than raising and aborting the whole fetch.

        Mirrors ``okta.py``'s ``_collect_family`` exactly (same
        exception-to-completeness mapping), reusing this connector's own
        ``paginate_sentry`` helper instead of re-implementing pagination.
        Hitting ``cap`` OR ``paginate_sentry``'s ``truncated`` flag is
        always FAMILY_PARTIAL — never silently reported as complete.
        """
        try:
            items, truncated = paginate_sentry(
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

    @classmethod
    def _collect_projects(
        cls, client: httpx.Client, slug: str, organization_id: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        raw_items, completeness = cls._collect_family(
            client, f"/organizations/{slug}/projects/",
            params=_PAGE_SIZE_PARAMS, cap=_MAX_PROJECTS, _sleep_fn=_sleep_fn,
        )
        records: list[dict] = []
        seen_ids: set = set()
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            rec = cls._normalize_project(organization_id, raw)
            if rec is None or rec["project_id"] in seen_ids:
                continue
            seen_ids.add(rec["project_id"])
            records.append(rec)
        records.sort(key=lambda r: r["project_id"])
        return records, completeness

    @classmethod
    def _collect_teams(
        cls, client: httpx.Client, slug: str, organization_id: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], list[dict], str]:
        """Collect teams AND project-team assignments from the SAME
        response — Sentry's list-teams endpoint nests each team's
        assigned ``projects`` array by default, so no separate per-team
        or per-project call is needed for the assignment edge (see
        ``sentry_schema.COLLECTION_FAMILY_PROJECT_TEAM_ASSIGNMENTS``).

        Returns ``(team_records, assignment_records, completeness)`` —
        both record lists share the single teams-list completeness.
        """
        raw_items, completeness = cls._collect_family(
            client, f"/organizations/{slug}/teams/",
            params=_PAGE_SIZE_PARAMS, cap=_MAX_TEAMS, _sleep_fn=_sleep_fn,
        )
        team_records: list[dict] = []
        assignment_records: list[dict] = []
        seen_team_ids: set = set()
        seen_assignment_ids: set = set()

        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            team_rec = cls._normalize_team(organization_id, raw)
            if team_rec is None or team_rec["team_id"] in seen_team_ids:
                continue
            seen_team_ids.add(team_rec["team_id"])
            team_records.append(team_rec)

            nested_projects = raw.get("projects")
            if isinstance(nested_projects, list):
                for raw_project in nested_projects:
                    if not isinstance(raw_project, dict):
                        continue
                    project_id = cls._stable_entity_id(raw_project.get("id"))
                    if project_id is None:
                        continue
                    assignment_rec = cls._normalize_project_team_assignment(
                        organization_id, project_id=project_id, team_id=team_rec["team_id"],
                    )
                    if assignment_rec["record_id"] in seen_assignment_ids:
                        continue
                    seen_assignment_ids.add(assignment_rec["record_id"])
                    assignment_records.append(assignment_rec)

        team_records.sort(key=lambda r: r["team_id"])
        assignment_records.sort(key=lambda r: r["record_id"])
        return team_records, assignment_records, completeness

    @classmethod
    def _collect_members(
        cls, client: httpx.Client, slug: str, organization_id: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        raw_items, completeness = cls._collect_family(
            client, f"/organizations/{slug}/members/",
            params=_PAGE_SIZE_PARAMS, cap=_MAX_MEMBERS, _sleep_fn=_sleep_fn,
        )
        records: list[dict] = []
        seen_ids: set = set()
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            rec = cls._normalize_member(organization_id, raw)
            if rec is None or rec["member_id"] in seen_ids:
                continue
            seen_ids.add(rec["member_id"])
            records.append(rec)
        records.sort(key=lambda r: r["member_id"])
        return records, completeness

    @classmethod
    def _collect_team_memberships(
        cls, client: httpx.Client, slug: str, organization_id: str, team_records: list[dict],
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str, dict]:
        """Collect member<->team edges.

        Call-complexity design: Sentry has no single "list all team
        memberships across the organization" endpoint — membership is
        only enumerable per-TEAM (``GET
        /teams/{org}/{team_slug}/members/``) or per-member detail (``GET
        /organizations/{org}/members/{id}/``, which returns
        ``teams``/``teamRoles`` for ONE member at a time). This connector
        walks per-TEAM, directly mirroring Okta's own documented
        per-group-not-per-user precedent (``okta.py``'s
        ``_fetch_memberships``) — a real organization has far fewer teams
        than members. Bounded at
        ``_MAX_TEAMS_FOR_MEMBERSHIP_ENUMERATION`` teams; message 7 owns
        full partial-sync/scale hardening.

        Per current official docs, the per-team members endpoint excludes
        pending-invite members — a walked team's membership list reflects
        active team members only. This is a documented limitation, not a
        bug: organization-level pending/expired status is still preserved
        on ``sentry_member.member_status_category``.

        Returns ``(records, completeness, status_by_team_id)`` —
        ``status_by_team_id`` (Sentry message 7) lets diff-time
        false-removal suppression scope itself to just the teams whose
        walk actually failed.
        """
        if not team_records:
            return [], FAMILY_COMPLETE, {}

        teams_to_walk = team_records[:_MAX_TEAMS_FOR_MEMBERSHIP_ENUMERATION]
        truncated_team_list = len(team_records) > len(teams_to_walk)

        records: list[dict] = []
        status_by_team: dict = {}
        seen_edge_ids: set = set()
        succeeded = 0
        denied = 0
        other_failed = 0
        cap_hit = False

        for team_rec in teams_to_walk:
            team_id = team_rec["team_id"]
            team_slug = team_rec.get("slug")
            if not isinstance(team_slug, str) or not team_slug.strip():
                # No slug to address the per-team walk endpoint with — an
                # unaddressable team is a failed walk, never a silent skip.
                status_by_team[team_id] = FAMILY_UNAVAILABLE
                other_failed += 1
                continue

            raw_members, team_completeness = cls._collect_family(
                client, f"/teams/{slug}/{team_slug}/members/",
                params=_PAGE_SIZE_PARAMS, cap=_MAX_MEMBERS_PER_TEAM_WALK, _sleep_fn=_sleep_fn,
            )
            status_by_team[team_id] = team_completeness
            if team_completeness == FAMILY_DENIED:
                denied += 1
                continue
            if team_completeness == FAMILY_UNAVAILABLE:
                other_failed += 1
                continue
            if team_completeness == FAMILY_PARTIAL:
                cap_hit = True

            succeeded += 1
            for raw_member in raw_members:
                if not isinstance(raw_member, dict):
                    continue
                member_id = cls._stable_entity_id(raw_member.get("id"))
                if member_id is None:
                    continue
                raw_team_role = (
                    raw_member.get("teamRole") if isinstance(raw_member.get("teamRole"), str) else raw_member.get("role")
                )
                edge = cls._normalize_team_membership(
                    organization_id, team_id=team_id, member_id=member_id,
                    team_role_category=categorize_team_role(raw_team_role),
                )
                if edge["record_id"] in seen_edge_ids:
                    continue
                seen_edge_ids.add(edge["record_id"])
                if len(records) >= _MAX_TOTAL_TEAM_MEMBERSHIPS:
                    cap_hit = True
                    break
                records.append(edge)
            if len(records) >= _MAX_TOTAL_TEAM_MEMBERSHIPS:
                cap_hit = True
                break

        if succeeded == 0 and denied > 0 and other_failed == 0:
            completeness = FAMILY_DENIED
        elif succeeded == 0 and other_failed > 0:
            completeness = FAMILY_UNAVAILABLE
        elif denied > 0 or other_failed > 0 or cap_hit or truncated_team_list:
            completeness = FAMILY_PARTIAL
        else:
            completeness = FAMILY_COMPLETE

        records.sort(key=lambda r: r["record_id"])
        return records, completeness, status_by_team

    # ── Record normalizers (Sentry message 3 of 8) ───────────────────────
    #
    # Alert rules never persist raw query strings, condition/filter
    # payloads, or action target identifiers that could be an email
    # address, webhook URL, or integration secret — see the module
    # docstring's sensitive-data boundary.

    @classmethod
    def _normalize_metric_alert_rule(cls, organization_id: str, raw: dict, *, project_id: Optional[str]) -> Optional[dict]:
        rule_id = cls._stable_entity_id(raw.get("id"))
        if rule_id is None:
            return None

        name = raw.get("name")
        raw_query = raw.get("query")
        raw_time_window = raw.get("timeWindow")
        raw_resolve_threshold = raw.get("resolveThreshold")
        raw_comparison_delta = raw.get("comparisonDelta")
        owner_type, owner_id = categorize_owner(raw.get("owner"))
        raw_triggers = raw.get("triggers")
        date_created = raw.get("dateCreated")

        return {
            "record_type": SENTRY_METRIC_ALERT_RULE,
            "record_id": f"{organization_id}/metric_alert_rule/{rule_id}",
            "provider_resource_id": f"alert-rules/{rule_id}",
            "organization_id": organization_id,
            "project_id": project_id,
            "rule_id": rule_id,
            "name": name.strip()[:_MAX_STR_LEN] if isinstance(name, str) and name.strip() else None,
            "status_category": categorize_metric_alert_status(raw.get("status")),
            "dataset_category": categorize_dataset(raw.get("dataset")),
            "aggregate_category": categorize_aggregate(raw.get("aggregate")),
            "has_query": bool(isinstance(raw_query, str) and raw_query.strip()),
            "time_window_minutes": raw_time_window if isinstance(raw_time_window, int) and not isinstance(raw_time_window, bool) else None,
            "environment_category": categorize_environment(raw.get("environment")),
            "threshold_type_category": categorize_threshold_type(raw.get("thresholdType")),
            "resolve_threshold": (
                float(raw_resolve_threshold)
                if isinstance(raw_resolve_threshold, (int, float)) and not isinstance(raw_resolve_threshold, bool)
                else None
            ),
            "detection_type_category": categorize_detection_type(raw.get("detectionType")),
            "comparison_delta_minutes": (
                raw_comparison_delta if isinstance(raw_comparison_delta, int) and not isinstance(raw_comparison_delta, bool) else None
            ),
            "owner_type_category": owner_type,
            "owner_id": owner_id,
            "trigger_count": len(raw_triggers) if isinstance(raw_triggers, list) else None,
            "action_count": None,  # filled in by _collect_metric_alert_rules once actions are counted
            "date_created": date_created if isinstance(date_created, str) else None,
        }

    @classmethod
    def _normalize_metric_alert_trigger(
        cls, organization_id: str, rule_id: str, raw: dict, *, threshold_type_category: str,
    ) -> Optional[dict]:
        trigger_id = cls._stable_entity_id(raw.get("id"))
        if trigger_id is None:
            return None

        raw_threshold = raw.get("alertThreshold")
        raw_actions = raw.get("actions")

        return {
            "record_type": SENTRY_METRIC_ALERT_TRIGGER,
            "record_id": f"{organization_id}/metric_alert_trigger/{rule_id}/{trigger_id}",
            "provider_resource_id": f"alert-rule-triggers/{trigger_id}",
            "organization_id": organization_id,
            "rule_id": rule_id,
            "trigger_id": trigger_id,
            "label_category": categorize_trigger_label(raw.get("label")),
            "alert_threshold": (
                float(raw_threshold) if isinstance(raw_threshold, (int, float)) and not isinstance(raw_threshold, bool) else None
            ),
            "action_count": len(raw_actions) if isinstance(raw_actions, list) else None,
            # Informational only, copied from the owning rule — NOT
            # diff-tracked on this record type (the rule's own
            # threshold_type_category change is what's tracked); exists
            # so the risk classifier can determine threshold-weakening
            # direction for a trigger-level alert_threshold change
            # without a second lookup.
            "threshold_type_category": threshold_type_category,
        }

    @classmethod
    def _normalize_issue_alert_rule(cls, organization_id: str, project_id: str, raw: dict) -> Optional[dict]:
        rule_id = cls._stable_entity_id(raw.get("id"))
        if rule_id is None:
            return None

        name = raw.get("name")
        raw_conditions = raw.get("conditions")
        raw_filters = raw.get("filters")
        raw_actions = raw.get("actions")
        raw_frequency = raw.get("frequency")
        owner_type, owner_id = categorize_owner(raw.get("owner"))
        date_created = raw.get("dateCreated")

        return {
            "record_type": SENTRY_ISSUE_ALERT_RULE,
            "record_id": f"{organization_id}/issue_alert_rule/{rule_id}",
            "provider_resource_id": f"rules/{rule_id}",
            "organization_id": organization_id,
            "project_id": project_id,
            "rule_id": rule_id,
            "name": name.strip()[:_MAX_STR_LEN] if isinstance(name, str) and name.strip() else None,
            "status_category": categorize_issue_alert_status(raw.get("status")),
            "environment_category": categorize_environment(raw.get("environment")),
            "action_match_category": categorize_match_type(raw.get("actionMatch")),
            "filter_match_category": categorize_match_type(raw.get("filterMatch")),
            "frequency_minutes": raw_frequency if isinstance(raw_frequency, int) and not isinstance(raw_frequency, bool) else None,
            "condition_count": len(raw_conditions) if isinstance(raw_conditions, list) else None,
            "filter_count": len(raw_filters) if isinstance(raw_filters, list) else None,
            "action_count": len(raw_actions) if isinstance(raw_actions, list) else None,
            "owner_type_category": owner_type,
            "owner_id": owner_id,
            "date_created": date_created if isinstance(date_created, str) else None,
        }

    @classmethod
    def _normalize_metric_alert_action(cls, organization_id: str, rule_id: str, trigger_id: str, raw: dict) -> Optional[dict]:
        action_id = cls._stable_entity_id(raw.get("id"))
        if action_id is None:
            return None
        return cls._build_alert_action_record(
            organization_id, rule_type="metric", rule_id=rule_id, trigger_id=trigger_id,
            action_key=action_id, action_category=categorize_metric_action_type(raw.get("type")), raw=raw,
        )

    @classmethod
    def _normalize_issue_alert_action(cls, organization_id: str, rule_id: str, index: int, raw: dict) -> Optional[dict]:
        # Issue-alert actions have no independent stable identity in
        # Sentry's own data model — they are embedded JSON on the Rule's
        # own ``data`` field, not separate database rows (unlike metric-
        # alert-trigger actions, which ARE real AlertRuleTriggerAction
        # rows with their own numeric ``id``). Position within the rule's
        # own actions array is the only available identity signal; this
        # is a documented limitation (a same-content action changing
        # position alone could produce a spurious remove+add Change), not
        # a fabricated stable ID.
        return cls._build_alert_action_record(
            organization_id, rule_type="issue", rule_id=rule_id, trigger_id=None,
            action_key=str(index), action_category=categorize_issue_action_id(raw.get("id")), raw=raw,
        )

    @staticmethod
    def _build_alert_action_record(
        organization_id: str, *, rule_type: str, rule_id: str, trigger_id: Optional[str],
        action_key: str, action_category: str, raw: dict,
    ) -> dict:
        target_type_category = categorize_target_type(raw.get("targetType"))
        raw_target_identifier = raw.get("targetIdentifier")
        # SECURITY: only a team/user target's identifier is stored (an
        # already-known message-2 stable ID) — a "specific"/issue_owners/
        # sentry_app target's identifier may be a raw email address,
        # Slack channel ID, or other external reference and is NEVER
        # persisted.
        target_id = (
            str(raw_target_identifier).strip()[:100]
            if target_type_category in ("team", "user")
            and isinstance(raw_target_identifier, (str, int))
            and str(raw_target_identifier).strip()
            else None
        )
        raw_integration_id = raw.get("integrationId") if raw.get("integrationId") is not None else raw.get("integration")
        integration_id = (
            str(raw_integration_id).strip()[:100]
            if isinstance(raw_integration_id, (str, int)) and str(raw_integration_id).strip()
            else None
        )

        scope = f"{trigger_id}" if rule_type == "metric" else f"{rule_id}"
        return {
            "record_type": SENTRY_ALERT_ACTION,
            "record_id": f"{organization_id}/alert_action/{rule_type}/{scope}/{action_key}",
            "provider_resource_id": f"alert-actions/{rule_type}/{scope}/{action_key}",
            "organization_id": organization_id,
            "rule_type": rule_type,
            "rule_id": rule_id,
            "trigger_id": trigger_id,
            "action_category": action_category,
            "target_type_category": target_type_category,
            "target_id": target_id,
            "integration_id": integration_id,
        }

    # ── Family collection (Sentry message 3 of 8) ────────────────────────

    @classmethod
    def _collect_metric_alert_rules(
        cls, client: httpx.Client, slug: str, organization_id: str, project_id_by_slug: dict,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], list[dict], list[dict], str]:
        """Collect metric alert rules (one organization-scoped paginated
        call) plus their embedded triggers/actions — no extra calls are
        needed since Sentry's list-alert-rules response nests full
        trigger/action detail per rule.

        Returns ``(rule_records, trigger_records, action_records, completeness)``.
        """
        raw_items, completeness = cls._collect_family(
            client, f"/organizations/{slug}/alert-rules/",
            params=_PAGE_SIZE_PARAMS, cap=_MAX_METRIC_ALERT_RULES, _sleep_fn=_sleep_fn,
        )

        rule_records: list[dict] = []
        trigger_records: list[dict] = []
        action_records: list[dict] = []
        seen_rule_ids: set = set()
        seen_trigger_ids: set = set()
        seen_action_ids: set = set()

        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            raw_projects = raw.get("projects")
            project_slug = (
                raw_projects[0] if isinstance(raw_projects, list) and raw_projects and isinstance(raw_projects[0], str) else None
            )
            project_id = project_id_by_slug.get(project_slug) if project_slug else None

            rule_rec = cls._normalize_metric_alert_rule(organization_id, raw, project_id=project_id)
            if rule_rec is None or rule_rec["rule_id"] in seen_rule_ids:
                continue
            seen_rule_ids.add(rule_rec["rule_id"])

            rule_action_count = 0
            raw_triggers = raw.get("triggers")
            if isinstance(raw_triggers, list):
                for raw_trigger in raw_triggers:
                    if not isinstance(raw_trigger, dict):
                        continue
                    trigger_rec = cls._normalize_metric_alert_trigger(
                        organization_id, rule_rec["rule_id"], raw_trigger,
                        threshold_type_category=rule_rec["threshold_type_category"],
                    )
                    if trigger_rec is None or trigger_rec["trigger_id"] in seen_trigger_ids:
                        continue
                    seen_trigger_ids.add(trigger_rec["trigger_id"])
                    trigger_records.append(trigger_rec)

                    raw_actions = raw_trigger.get("actions")
                    if isinstance(raw_actions, list):
                        for raw_action in raw_actions:
                            if not isinstance(raw_action, dict):
                                continue
                            action_rec = cls._normalize_metric_alert_action(
                                organization_id, rule_rec["rule_id"], trigger_rec["trigger_id"], raw_action,
                            )
                            if action_rec is None or action_rec["record_id"] in seen_action_ids:
                                continue
                            seen_action_ids.add(action_rec["record_id"])
                            action_records.append(action_rec)
                            rule_action_count += 1

            rule_rec["action_count"] = rule_action_count
            rule_records.append(rule_rec)

        rule_records.sort(key=lambda r: r["rule_id"])
        trigger_records.sort(key=lambda r: r["record_id"])
        action_records.sort(key=lambda r: r["record_id"])
        return rule_records, trigger_records, action_records, completeness

    @classmethod
    def _collect_issue_alert_rules(
        cls, client: httpx.Client, slug: str, organization_id: str, project_records: list[dict],
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], list[dict], str, dict]:
        """Collect issue alert rules via a bounded per-PROJECT walk (no
        organization-scoped bulk endpoint exists for issue alert rules —
        see the module docstring's documentation-verification log),
        directly mirroring message 2's per-team membership walk.

        Returns ``(rule_records, action_records, completeness, status_by_project_id)``.
        """
        if not project_records:
            return [], [], FAMILY_COMPLETE, {}

        projects_to_walk = project_records[:_MAX_PROJECTS_FOR_ISSUE_ALERT_ENUMERATION]
        truncated_project_list = len(project_records) > len(projects_to_walk)

        rule_records: list[dict] = []
        action_records: list[dict] = []
        status_by_project: dict = {}
        seen_rule_ids: set = set()
        seen_action_ids: set = set()
        succeeded = 0
        denied = 0
        other_failed = 0
        cap_hit = False

        for project_rec in projects_to_walk:
            project_id = project_rec["project_id"]
            project_slug = project_rec.get("slug")
            if not isinstance(project_slug, str) or not project_slug.strip():
                status_by_project[project_id] = FAMILY_UNAVAILABLE
                other_failed += 1
                continue

            raw_rules, project_completeness = cls._collect_family(
                client, f"/projects/{slug}/{project_slug}/rules/",
                params=_PAGE_SIZE_PARAMS, cap=_MAX_ISSUE_ALERT_RULES_PER_PROJECT, _sleep_fn=_sleep_fn,
            )
            status_by_project[project_id] = project_completeness
            if project_completeness == FAMILY_DENIED:
                denied += 1
                continue
            if project_completeness == FAMILY_UNAVAILABLE:
                other_failed += 1
                continue
            if project_completeness == FAMILY_PARTIAL:
                cap_hit = True

            succeeded += 1
            for raw_rule in raw_rules:
                if not isinstance(raw_rule, dict):
                    continue
                rule_rec = cls._normalize_issue_alert_rule(organization_id, project_id, raw_rule)
                if rule_rec is None or rule_rec["rule_id"] in seen_rule_ids:
                    continue
                seen_rule_ids.add(rule_rec["rule_id"])
                if len(rule_records) >= _MAX_TOTAL_ISSUE_ALERT_RULES:
                    cap_hit = True
                    break
                rule_records.append(rule_rec)

                raw_actions = raw_rule.get("actions")
                if isinstance(raw_actions, list):
                    for index, raw_action in enumerate(raw_actions):
                        if not isinstance(raw_action, dict):
                            continue
                        action_rec = cls._normalize_issue_alert_action(organization_id, rule_rec["rule_id"], index, raw_action)
                        if action_rec is None or action_rec["record_id"] in seen_action_ids:
                            continue
                        seen_action_ids.add(action_rec["record_id"])
                        if len(action_records) >= _MAX_TOTAL_ALERT_ACTIONS:
                            cap_hit = True
                            break
                        action_records.append(action_rec)
            if len(rule_records) >= _MAX_TOTAL_ISSUE_ALERT_RULES or len(action_records) >= _MAX_TOTAL_ALERT_ACTIONS:
                cap_hit = True
                break

        if succeeded == 0 and denied > 0 and other_failed == 0:
            completeness = FAMILY_DENIED
        elif succeeded == 0 and other_failed > 0:
            completeness = FAMILY_UNAVAILABLE
        elif denied > 0 or other_failed > 0 or cap_hit or truncated_project_list:
            completeness = FAMILY_PARTIAL
        else:
            completeness = FAMILY_COMPLETE

        rule_records.sort(key=lambda r: r["record_id"])
        action_records.sort(key=lambda r: r["record_id"])
        return rule_records, action_records, completeness, status_by_project

    # ── Record normalizers (Sentry message 4 of 8) ───────────────────────
    #
    # Never persist OAuth/access/refresh tokens, client secrets, webhook
    # URLs/secrets, repository clone URLs/credentials/SSH keys, raw
    # ownership-rule text, or raw integration config blobs — see the
    # module docstring's sensitive-data boundary.

    @classmethod
    def _normalize_organization_integration(cls, organization_id: str, raw: dict) -> Optional[dict]:
        integration_id = cls._stable_entity_id(raw.get("id"))
        if integration_id is None:
            return None

        name = raw.get("name")
        raw_provider = raw.get("provider")
        provider_key = raw_provider.get("key") if isinstance(raw_provider, dict) else None
        raw_status = raw.get("organizationIntegrationStatus")
        if not isinstance(raw_status, str):
            raw_status = raw.get("status")
        raw_external_id = raw.get("externalId")
        raw_features = raw_provider.get("features") if isinstance(raw_provider, dict) else None
        feature_categories = (
            sorted({f.strip()[:50] for f in raw_features if isinstance(f, str) and f.strip()})
            if isinstance(raw_features, list)
            else None
        )
        raw_out_of_date = raw.get("outOfDate")

        return {
            "record_type": SENTRY_ORGANIZATION_INTEGRATION,
            "record_id": f"{organization_id}/organization_integration/{integration_id}",
            "provider_resource_id": f"integrations/{integration_id}",
            "organization_id": organization_id,
            "integration_id": integration_id,
            "name": name.strip()[:_MAX_STR_LEN] if isinstance(name, str) and name.strip() else None,
            "provider_category": categorize_provider(provider_key),
            "status_category": categorize_object_status(raw_status),
            "external_id": (
                raw_external_id.strip()[:_MAX_STR_LEN]
                if isinstance(raw_external_id, str) and raw_external_id.strip()
                else None
            ),
            "feature_categories": feature_categories,
            "out_of_date": raw_out_of_date if isinstance(raw_out_of_date, bool) else None,
        }

    @classmethod
    def _normalize_repository(cls, organization_id: str, raw: dict) -> Optional[dict]:
        repo_id = cls._stable_entity_id(raw.get("id"))
        if repo_id is None:
            return None

        name = raw.get("name")
        raw_provider = raw.get("provider")
        provider_id = raw_provider.get("id") if isinstance(raw_provider, dict) else None
        integration_id = cls._stable_entity_id(raw.get("integrationId"))
        raw_external_id = raw.get("externalId")
        date_created = raw.get("dateCreated")

        return {
            "record_type": SENTRY_REPOSITORY,
            "record_id": f"{organization_id}/repository/{repo_id}",
            "provider_resource_id": f"repos/{repo_id}",
            "organization_id": organization_id,
            "repository_id": repo_id,
            "name": name.strip()[:_MAX_STR_LEN] if isinstance(name, str) and name.strip() else None,
            "provider_category": categorize_provider(provider_id),
            "status_category": categorize_object_status(raw.get("status")),
            "integration_id": integration_id,
            "external_id": (
                raw_external_id.strip()[:_MAX_STR_LEN]
                if isinstance(raw_external_id, str) and raw_external_id.strip()
                else None
            ),
            "date_created": date_created if isinstance(date_created, str) else None,
        }

    @classmethod
    def _normalize_code_mapping(cls, organization_id: str, raw: dict) -> Optional[dict]:
        mapping_id = cls._stable_entity_id(raw.get("id"))
        if mapping_id is None:
            return None

        project_id = cls._stable_entity_id(raw.get("projectId"))
        repository_id = cls._stable_entity_id(raw.get("repoId"))
        integration_id = cls._stable_entity_id(raw.get("integrationId"))
        raw_auto_generated = raw.get("automaticallyGenerated")

        return {
            "record_type": SENTRY_CODE_MAPPING,
            "record_id": f"{organization_id}/code_mapping/{mapping_id}",
            "provider_resource_id": f"code-mappings/{mapping_id}",
            "organization_id": organization_id,
            "mapping_id": mapping_id,
            "project_id": project_id,
            "repository_id": repository_id,
            "integration_id": integration_id,
            "stack_root_configured": bool(raw.get("stackRoot")) if isinstance(raw.get("stackRoot"), str) else False,
            "source_root_configured": bool(raw.get("sourceRoot")) if isinstance(raw.get("sourceRoot"), str) else False,
            "default_branch_configured": bool(raw.get("defaultBranch")) if isinstance(raw.get("defaultBranch"), str) else False,
            "automatically_generated": raw_auto_generated if isinstance(raw_auto_generated, bool) else None,
        }

    @staticmethod
    def _categorize_ownership_owner(raw_owner: dict) -> tuple[str, Optional[str]]:
        """Return ``(owner_type_category, owner_stable_id)`` from a raw
        ownership-rule owner dict (``{"type": "team"/"user", "name": str,
        "id": Optional[str]}``). Never reads ``name`` — it may be a raw
        identifier (username or email) rather than a stable ID. Returns
        ``(OWNER_TYPE_UNKNOWN, None)`` if the owner is unresolved (no
        ``id``) or the type is unrecognized."""
        raw_type = raw_owner.get("type")
        raw_id = raw_owner.get("id")
        if isinstance(raw_id, (str, int)) and str(raw_id).strip():
            if raw_type == "team":
                return OWNER_TYPE_TEAM, str(raw_id).strip()
            if raw_type == "user":
                return OWNER_TYPE_USER, str(raw_id).strip()
        return OWNER_TYPE_UNKNOWN, None

    @classmethod
    def _normalize_ownership_rules(cls, organization_id: str, project_id: str, raw: dict) -> list[dict]:
        """Normalize a project's full ``ProjectOwnership`` response into
        zero or more ``sentry_ownership_rule`` records — one per (rule,
        owner) pair, preserving Sentry's own rule order (first-match
        semantics) via ``rule_index``.

        Never reads the ``raw`` ownership-text field — only the already-
        parsed ``schema.rules`` array. A rule with zero resolvable owners
        still emits one record (owner_index=0, owner fields unknown) so
        the rule's existence is not silently dropped.
        """
        records: list[dict] = []
        raw_is_active = raw.get("isActive")
        raw_fallthrough = raw.get("fallthrough")
        auto_assignment_category = categorize_auto_assignment(raw.get("autoAssignment"))
        is_active = raw_is_active if isinstance(raw_is_active, bool) else None
        fallthrough = raw_fallthrough if isinstance(raw_fallthrough, bool) else None

        raw_schema = raw.get("schema")
        raw_rules = raw_schema.get("rules") if isinstance(raw_schema, dict) else None
        if not isinstance(raw_rules, list):
            return records

        for rule_index, raw_rule in enumerate(raw_rules):
            if not isinstance(raw_rule, dict):
                continue
            raw_matcher = raw_rule.get("matcher")
            matcher_type = raw_matcher.get("type") if isinstance(raw_matcher, dict) else None
            matcher_category = categorize_matcher(matcher_type)

            raw_owners = raw_rule.get("owners")
            owners_to_process = raw_owners if isinstance(raw_owners, list) and raw_owners else [{}]

            for owner_index, raw_owner in enumerate(owners_to_process):
                owner_type_category, owner_id = cls._categorize_ownership_owner(
                    raw_owner if isinstance(raw_owner, dict) else {}
                )
                records.append({
                    "record_type": SENTRY_OWNERSHIP_RULE,
                    "record_id": f"{organization_id}/ownership_rule/{project_id}/{rule_index}/{owner_index}",
                    "provider_resource_id": f"ownership/{project_id}/{rule_index}/{owner_index}",
                    "organization_id": organization_id,
                    "project_id": project_id,
                    "rule_index": rule_index,
                    "owner_index": owner_index,
                    "matcher_category": matcher_category,
                    "owner_type_category": owner_type_category,
                    "owner_id": owner_id,
                    "is_active": is_active,
                    "fallthrough": fallthrough,
                    "auto_assignment_category": auto_assignment_category,
                })
        return records

    # ── Family collection (Sentry message 4 of 8) ────────────────────────

    @classmethod
    def _collect_organization_integrations(
        cls, client: httpx.Client, slug: str, organization_id: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        raw_items, completeness = cls._collect_family(
            client, f"/organizations/{slug}/integrations/",
            params=_PAGE_SIZE_PARAMS, cap=_MAX_ORGANIZATION_INTEGRATIONS, _sleep_fn=_sleep_fn,
        )
        records: list[dict] = []
        seen_ids: set = set()
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            rec = cls._normalize_organization_integration(organization_id, raw)
            if rec is None or rec["integration_id"] in seen_ids:
                continue
            seen_ids.add(rec["integration_id"])
            records.append(rec)
        records.sort(key=lambda r: r["integration_id"])
        return records, completeness

    @classmethod
    def _collect_repositories(
        cls, client: httpx.Client, slug: str, organization_id: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        raw_items, completeness = cls._collect_family(
            client, f"/organizations/{slug}/repos/",
            params=_PAGE_SIZE_PARAMS, cap=_MAX_REPOSITORIES, _sleep_fn=_sleep_fn,
        )
        records: list[dict] = []
        seen_ids: set = set()
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            rec = cls._normalize_repository(organization_id, raw)
            if rec is None or rec["repository_id"] in seen_ids:
                continue
            seen_ids.add(rec["repository_id"])
            records.append(rec)
        records.sort(key=lambda r: r["repository_id"])
        return records, completeness

    @classmethod
    def _collect_code_mappings(
        cls, client: httpx.Client, slug: str, organization_id: str,
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str]:
        raw_items, completeness = cls._collect_family(
            client, f"/organizations/{slug}/code-mappings/",
            params=_PAGE_SIZE_PARAMS, cap=_MAX_CODE_MAPPINGS, _sleep_fn=_sleep_fn,
        )
        records: list[dict] = []
        seen_ids: set = set()
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            rec = cls._normalize_code_mapping(organization_id, raw)
            if rec is None or rec["mapping_id"] in seen_ids:
                continue
            seen_ids.add(rec["mapping_id"])
            records.append(rec)
        records.sort(key=lambda r: r["mapping_id"])
        return records, completeness

    @classmethod
    def _collect_ownership_rules(
        cls, client: httpx.Client, slug: str, organization_id: str, project_records: list[dict],
        *, _sleep_fn: Callable[[float], None] = None,
    ) -> tuple[list[dict], str, dict]:
        """Collect ownership rules via a bounded per-PROJECT walk.

        Unlike every other message-4 family, this endpoint
        (``GET /projects/{org}/{project}/ownership/``) returns a SINGLE
        object per project, not a list — so this walk calls
        ``call_sentry`` directly instead of ``_collect_family``/
        ``paginate_sentry`` (which assume a JSON array response).

        A 404 means the project has no ownership configuration at all —
        trivially complete with zero rules, never denied/unavailable. A
        response with non-empty ``raw`` ownership text but no parsed
        ``schema`` is treated as PARTIAL for that project (evidence of
        rules exists but they could not be collected into structured
        records) — never silently reported as zero rules.

        Returns ``(records, completeness, status_by_project_id)``.
        """
        if not project_records:
            return [], FAMILY_COMPLETE, {}

        projects_to_walk = project_records[:_MAX_PROJECTS_FOR_OWNERSHIP_ENUMERATION]
        truncated_project_list = len(project_records) > len(projects_to_walk)

        records: list[dict] = []
        status_by_project: dict = {}
        seen_record_ids: set = set()
        succeeded = 0
        denied = 0
        other_failed = 0
        malformed = 0
        cap_hit = False

        for project_rec in projects_to_walk:
            project_id = project_rec["project_id"]
            project_slug = project_rec.get("slug")
            if not isinstance(project_slug, str) or not project_slug.strip():
                status_by_project[project_id] = FAMILY_UNAVAILABLE
                other_failed += 1
                continue

            outcome = call_sentry(client, f"/projects/{slug}/{project_slug}/ownership/", _sleep_fn=_sleep_fn)
            if not outcome.ok:
                if outcome.category == CATEGORY_NOT_FOUND:
                    status_by_project[project_id] = FAMILY_COMPLETE
                    succeeded += 1
                    continue
                if outcome.category == CATEGORY_PERMISSION_DENIED:
                    status_by_project[project_id] = FAMILY_DENIED
                    denied += 1
                    continue
                status_by_project[project_id] = FAMILY_UNAVAILABLE
                other_failed += 1
                continue

            try:
                raw = outcome.response.json()
            except ValueError:
                status_by_project[project_id] = FAMILY_UNAVAILABLE
                other_failed += 1
                continue
            if not isinstance(raw, dict):
                status_by_project[project_id] = FAMILY_UNAVAILABLE
                other_failed += 1
                continue

            raw_text = raw.get("raw")
            raw_schema = raw.get("schema")
            if isinstance(raw_text, str) and raw_text.strip() and not isinstance(raw_schema, dict):
                # Evidence of configured rules exists (raw text) but they
                # could not be parsed into structured records — PARTIAL,
                # never silently zero.
                status_by_project[project_id] = FAMILY_PARTIAL
                malformed += 1
                continue

            succeeded += 1
            status_by_project[project_id] = FAMILY_COMPLETE
            project_rules = cls._normalize_ownership_rules(organization_id, project_id, raw)
            if len(project_rules) > _MAX_OWNERSHIP_RULES_PER_PROJECT:
                project_rules = project_rules[:_MAX_OWNERSHIP_RULES_PER_PROJECT]
                status_by_project[project_id] = FAMILY_PARTIAL
                cap_hit = True
            for rec in project_rules:
                if rec["record_id"] in seen_record_ids:
                    continue
                seen_record_ids.add(rec["record_id"])
                if len(records) >= _MAX_TOTAL_OWNERSHIP_RULES:
                    cap_hit = True
                    break
                records.append(rec)
            if len(records) >= _MAX_TOTAL_OWNERSHIP_RULES:
                cap_hit = True
                break

        if succeeded == 0 and (denied > 0 or malformed > 0) and other_failed == 0:
            completeness = FAMILY_DENIED if denied > 0 and malformed == 0 else FAMILY_PARTIAL
        elif succeeded == 0 and other_failed > 0:
            completeness = FAMILY_UNAVAILABLE
        elif denied > 0 or other_failed > 0 or malformed > 0 or cap_hit or truncated_project_list:
            completeness = FAMILY_PARTIAL
        else:
            completeness = FAMILY_COMPLETE

        records.sort(key=lambda r: (r["project_id"], r["rule_index"], r["owner_index"]))
        return records, completeness, status_by_project

    # ── Effective-access derivation (Sentry message 5 of 8) ──────────────
    #
    # Everything below is PURE LOCAL DERIVATION over already-collected
    # message-1-4 records — it makes zero additional HTTP calls. See
    # ``_derive_effective_access`` for the orchestrating entry point and
    # the exact source-family-to-derived-family completeness mapping.

    _COMPLETENESS_RANK = {
        FAMILY_COMPLETE: 0,
        FAMILY_PARTIAL: 1,
        FAMILY_DENIED: 2,
        FAMILY_UNAVAILABLE: 2,
    }

    @classmethod
    def _worse_completeness(cls, *statuses: str) -> str:
        """Return the least-complete status among ``statuses`` (never
        invents a value outside the existing FAMILY_* taxonomy)."""
        if not statuses:
            return FAMILY_COMPLETE
        return max(statuses, key=lambda s: cls._COMPLETENESS_RANK.get(s, 1))

    @classmethod
    def _resolution_completeness(cls, *, resolved: bool, source_family_completeness: str) -> str:
        """A resolved target is always reported FAMILY_COMPLETE — positive
        evidence stands on its own regardless of unrelated family gaps.
        An UNRESOLVED target inherits the source family's own
        completeness: only a fully COMPLETE source family can turn an
        unresolved target into a confirmed orphan; anything less keeps
        the ambiguity visible rather than asserting orphan-hood."""
        if resolved:
            return FAMILY_COMPLETE
        return source_family_completeness

    @staticmethod
    def _normalize_privileged_member(
        organization_id: str, member_id: str, *, org_role_category: str, member_status_category: str,
        privilege_tier: str, organization_wide_project_access: Optional[bool],
        direct_team_count: int, team_admin_team_count: int,
        effective_project_count: Optional[int], project_access_source_categories: list,
        alert_routing_target_count: int, ownership_rule_target_count: int,
        integration_control_context: str, repository_control_context: str,
        privilege_completeness: str,
    ) -> dict:
        return {
            "record_type": SENTRY_PRIVILEGED_MEMBER,
            "record_id": f"{organization_id}/privileged_member/{member_id}",
            "provider_resource_id": f"privileged-members/{member_id}",
            "organization_id": organization_id,
            "member_id": member_id,
            "org_role_category": org_role_category,
            "member_status_category": member_status_category,
            "privilege_tier": privilege_tier,
            "organization_wide_project_access": organization_wide_project_access,
            "direct_team_count": direct_team_count,
            "team_admin_team_count": team_admin_team_count,
            "effective_project_count": effective_project_count,
            "project_access_source_categories": sorted(project_access_source_categories),
            "alert_routing_target_count": alert_routing_target_count,
            "ownership_rule_target_count": ownership_rule_target_count,
            "integration_control_context": integration_control_context,
            "repository_control_context": repository_control_context,
            "privilege_completeness": privilege_completeness,
        }

    @staticmethod
    def _normalize_privileged_team(
        organization_id: str, team_id: str, *, project_count: int,
        ownership_rule_target_count: int, alert_action_target_count: int,
        privileged_member_count: int, unresolved_member_count: int,
        access_completeness: str,
    ) -> dict:
        return {
            "record_type": SENTRY_PRIVILEGED_TEAM,
            "record_id": f"{organization_id}/privileged_team/{team_id}",
            "provider_resource_id": f"privileged-teams/{team_id}",
            "organization_id": organization_id,
            "team_id": team_id,
            "project_count": project_count,
            "ownership_rule_target_count": ownership_rule_target_count,
            "alert_action_target_count": alert_action_target_count,
            "privileged_member_count": privileged_member_count,
            "unresolved_member_count": unresolved_member_count,
            "access_completeness": access_completeness,
        }

    @staticmethod
    def _normalize_routing_context(
        organization_id: str, *, context_type: str, source_record_id: str,
        project_id: Optional[str], rule_type: Optional[str], rule_id: Optional[str],
        target_type_category: str, target_id: Optional[str], target_resolved: bool,
        target_active: Optional[bool], target_privilege_tier: Optional[str],
        integration_status_category: Optional[str], context_enabled: Optional[bool],
        completeness: str,
    ) -> dict:
        # Rebuild a routing_context-scoped stable ID by re-keying the
        # source record's own stable suffix — never a synthesized index.
        suffix = source_record_id.split("/", 2)[-1] if source_record_id.count("/") >= 2 else source_record_id
        return {
            "record_type": SENTRY_ROUTING_CONTEXT,
            "record_id": f"{organization_id}/routing_context/{context_type}/{suffix}",
            "provider_resource_id": f"routing-context/{context_type}/{suffix}",
            "organization_id": organization_id,
            "context_type": context_type,
            "source_record_id": source_record_id,
            "project_id": project_id,
            "rule_type": rule_type,
            "rule_id": rule_id,
            "target_type_category": target_type_category,
            "target_id": target_id,
            "target_resolved": target_resolved,
            "target_active": target_active,
            "target_privilege_tier": target_privilege_tier,
            "integration_status_category": integration_status_category,
            "context_enabled": context_enabled,
            "completeness": completeness,
        }

    @classmethod
    def _derive_effective_access(
        cls, organization_id: str, *,
        project_records: list, team_records: list, member_records: list,
        membership_records: list, assignment_records: list,
        metric_rule_records: list, issue_rule_records: list,
        metric_action_records: list, issue_action_records: list,
        ownership_records: list, integration_records: list,
        member_completeness: str, team_completeness: str,
        membership_completeness: str, assignment_completeness: str,
        ownership_completeness: str, action_completeness: str,
        integration_completeness: str,
    ) -> tuple[list[dict], list[dict], list[dict]]:
        """Derive ``sentry_privileged_member``/``sentry_privileged_team``/
        ``sentry_routing_context`` records from already-collected
        message-1-4 records. Makes ZERO additional HTTP calls — every
        input here is a list already produced by this fetch() call.

        Source-family dependency per derived family (for the
        organization record's ``family_completeness`` propagation):
          privileged_members  <- members, teams, team_memberships,
                                  project_team_assignments, alert_actions,
                                  ownership_rules
          privileged_teams    <- teams, team_memberships,
                                  project_team_assignments, alert_actions,
                                  ownership_rules
          routing_context     <- ownership_rules/alert_actions (1:1) plus
                                  members, teams, organization_integrations
                                  for target resolution
        """
        project_ids = {r["project_id"] for r in project_records}
        team_index = {r["team_id"]: r for r in team_records}
        member_index = {r["member_id"]: r for r in member_records}
        integration_index = {r["integration_id"]: r for r in integration_records}
        metric_rule_status = {r["rule_id"]: r["status_category"] for r in metric_rule_records}
        issue_rule_status = {r["rule_id"]: r["status_category"] for r in issue_rule_records}

        memberships_by_member: dict = {}
        memberships_by_team: dict = {}
        for m in membership_records:
            memberships_by_member.setdefault(m["member_id"], []).append(m)
            memberships_by_team.setdefault(m["team_id"], []).append(m)

        assignments_by_team: dict = {}
        for a in assignment_records:
            assignments_by_team.setdefault(a["team_id"], set()).add(a["project_id"])

        alert_actions_all = metric_action_records + issue_action_records
        alert_user_targets_by_member: dict = {}
        alert_team_targets_by_team: dict = {}
        for a in alert_actions_all:
            if a["target_type_category"] == "user" and a["target_id"]:
                alert_user_targets_by_member.setdefault(a["target_id"], 0)
                alert_user_targets_by_member[a["target_id"]] += 1
            if a["target_type_category"] == "team" and a["target_id"]:
                alert_team_targets_by_team.setdefault(a["target_id"], 0)
                alert_team_targets_by_team[a["target_id"]] += 1

        ownership_user_targets_by_member: dict = {}
        ownership_team_targets_by_team: dict = {}
        for o in ownership_records:
            if o["owner_type_category"] == "user" and o["owner_id"]:
                ownership_user_targets_by_member.setdefault(o["owner_id"], 0)
                ownership_user_targets_by_member[o["owner_id"]] += 1
            if o["owner_type_category"] == "team" and o["owner_id"]:
                ownership_team_targets_by_team.setdefault(o["owner_id"], 0)
                ownership_team_targets_by_team[o["owner_id"]] += 1

        member_privilege_tier: dict = {}

        # ── Privileged members ────────────────────────────────────────
        privilege_source_completeness = cls._worse_completeness(
            member_completeness, team_completeness, membership_completeness, assignment_completeness,
        )
        privileged_member_records: list[dict] = []
        for member in member_records:
            member_id = member["member_id"]
            org_role_category = member["org_role_category"]
            base_tier = privilege_tier_for_org_role(org_role_category)
            member_memberships = memberships_by_member.get(member_id, [])
            direct_team_count = len(member_memberships)
            team_admin_team_count = sum(1 for m in member_memberships if m["team_role_category"] == TEAM_ROLE_ADMIN)

            tiers_to_combine = [base_tier]
            if team_admin_team_count > 0:
                tiers_to_combine.append(TEAM_ADMIN_CONTRIBUTION_TIER)
            privilege_tier = highest_privilege_tier(tiers_to_combine)
            member_privilege_tier[member_id] = privilege_tier

            org_wide_access = organization_wide_access_for_org_role(org_role_category)
            access_sources: list = []
            if org_wide_access is True:
                effective_project_ids = set(project_ids)
                access_sources.append("organization_wide")
                effective_project_count = len(effective_project_ids)
            elif org_wide_access is False:
                effective_project_ids = set()
                for m in member_memberships:
                    effective_project_ids |= assignments_by_team.get(m["team_id"], set())
                effective_project_count = len(effective_project_ids)
                access_sources.append("team_membership" if effective_project_count > 0 else "none")
            else:
                effective_project_count = None
                access_sources.append("unknown")

            alert_routing_target_count = alert_user_targets_by_member.get(member_id, 0)
            ownership_rule_target_count = ownership_user_targets_by_member.get(member_id, 0)

            is_privileged_org_role = org_role_category in ("owner", "manager", "admin") or org_role_category == ORG_ROLE_UNKNOWN
            has_meaningful_authority = (
                is_privileged_org_role
                or team_admin_team_count > 0
                or alert_routing_target_count > 0
                or ownership_rule_target_count > 0
            )
            if not has_meaningful_authority:
                continue

            privileged_member_records.append(cls._normalize_privileged_member(
                organization_id, member_id,
                org_role_category=org_role_category,
                member_status_category=member["member_status_category"],
                privilege_tier=privilege_tier,
                organization_wide_project_access=org_wide_access,
                direct_team_count=direct_team_count,
                team_admin_team_count=team_admin_team_count,
                effective_project_count=effective_project_count,
                project_access_source_categories=access_sources,
                alert_routing_target_count=alert_routing_target_count,
                ownership_rule_target_count=ownership_rule_target_count,
                integration_control_context=categorize_integration_control(org_role_category),
                repository_control_context=categorize_repository_control(org_role_category),
                privilege_completeness=privilege_source_completeness,
            ))
        privileged_member_records.sort(key=lambda r: r["member_id"])

        # ── Privileged teams ──────────────────────────────────────────
        team_source_completeness = cls._worse_completeness(
            team_completeness, membership_completeness, assignment_completeness,
        )
        privileged_team_records: list[dict] = []
        for team in team_records:
            team_id = team["team_id"]
            project_count = len(assignments_by_team.get(team_id, set()))
            ownership_rule_target_count = ownership_team_targets_by_team.get(team_id, 0)
            alert_action_target_count = alert_team_targets_by_team.get(team_id, 0)
            team_memberships = memberships_by_team.get(team_id, [])
            privileged_member_count = sum(1 for m in team_memberships if m["team_role_category"] == TEAM_ROLE_ADMIN)
            unresolved_member_count = sum(1 for m in team_memberships if m["member_id"] not in member_index)

            if not (
                project_count > 0 or ownership_rule_target_count > 0
                or alert_action_target_count > 0 or privileged_member_count > 0
                or unresolved_member_count > 0
            ):
                continue

            privileged_team_records.append(cls._normalize_privileged_team(
                organization_id, team_id,
                project_count=project_count,
                ownership_rule_target_count=ownership_rule_target_count,
                alert_action_target_count=alert_action_target_count,
                privileged_member_count=privileged_member_count,
                unresolved_member_count=unresolved_member_count,
                access_completeness=team_source_completeness,
            ))
        privileged_team_records.sort(key=lambda r: r["team_id"])

        # ── Routing context (ownership rules) ────────────────────────────
        identity_completeness = cls._worse_completeness(member_completeness, team_completeness)
        routing_context_records: list[dict] = []
        for rule in ownership_records:
            target_type_category = rule["owner_type_category"]
            target_id = rule["owner_id"]
            if target_type_category == "team":
                target_resolved = bool(target_id) and target_id in team_index
                target_active = True if target_resolved else None
                target_tier = None
            elif target_type_category == "user":
                target_resolved = bool(target_id) and target_id in member_index
                if target_resolved:
                    target_active = member_index[target_id]["member_status_category"] == "active"
                    target_tier = member_privilege_tier.get(target_id) or privilege_tier_for_org_role(
                        member_index[target_id]["org_role_category"]
                    )
                else:
                    target_active = None
                    target_tier = None
            else:
                target_resolved = False
                target_active = None
                target_tier = None

            routing_context_records.append(cls._normalize_routing_context(
                organization_id, context_type=ROUTING_CONTEXT_TYPE_OWNERSHIP_RULE,
                source_record_id=rule["record_id"], project_id=rule["project_id"],
                rule_type=None, rule_id=None,
                target_type_category=target_type_category, target_id=target_id,
                target_resolved=target_resolved, target_active=target_active,
                target_privilege_tier=target_tier, integration_status_category=None,
                context_enabled=rule.get("is_active"),
                completeness=cls._resolution_completeness(
                    resolved=target_resolved, source_family_completeness=identity_completeness,
                ),
            ))

        # ── Routing context (alert actions) ──────────────────────────────
        for action in alert_actions_all:
            target_type_category = action["target_type_category"]
            target_id = action["target_id"]
            if target_type_category == "team":
                target_resolved = bool(target_id) and target_id in team_index
                target_active = True if target_resolved else None
                target_tier = None
            elif target_type_category == "user":
                target_resolved = bool(target_id) and target_id in member_index
                if target_resolved:
                    target_active = member_index[target_id]["member_status_category"] == "active"
                    target_tier = member_privilege_tier.get(target_id) or privilege_tier_for_org_role(
                        member_index[target_id]["org_role_category"]
                    )
                else:
                    target_active = None
                    target_tier = None
            else:
                # specific / sentry_app / issue_owners / unknown — no
                # stable ID is ever stored for these (message-3
                # sensitive-data boundary), so resolution is never
                # attempted or claimed.
                target_resolved = False
                target_active = None
                target_tier = None

            integration_id = action.get("integration_id")
            if integration_id:
                integration_rec = integration_index.get(integration_id)
                integration_status_category = integration_rec["status_category"] if integration_rec else None
            else:
                integration_status_category = None

            rule_type = action["rule_type"]
            rule_id = action["rule_id"]
            if rule_type == "metric":
                rule_status = metric_rule_status.get(rule_id)
            elif rule_type == "issue":
                rule_status = issue_rule_status.get(rule_id)
            else:
                rule_status = None
            context_enabled = (rule_status == "enabled") if rule_status is not None else None

            action_completeness_for_target = cls._resolution_completeness(
                resolved=target_resolved,
                source_family_completeness=cls._worse_completeness(identity_completeness, action_completeness),
            )
            routing_context_records.append(cls._normalize_routing_context(
                organization_id, context_type=ROUTING_CONTEXT_TYPE_ALERT_ACTION,
                source_record_id=action["record_id"], project_id=None,
                rule_type=rule_type, rule_id=rule_id,
                target_type_category=target_type_category, target_id=target_id,
                target_resolved=target_resolved, target_active=target_active,
                target_privilege_tier=target_tier,
                integration_status_category=integration_status_category,
                context_enabled=context_enabled,
                completeness=action_completeness_for_target,
            ))

        routing_context_records.sort(key=lambda r: r["record_id"])
        return privileged_member_records, privileged_team_records, routing_context_records

    # ── Capability probes ────────────────────────────────────────────────
    #
    # Every probe is a single, minimal, read-only GET against page 1 only
    # — never a broad enumeration, never pagination follow-through. If a
    # family is structurally unsupported this message (see
    # ``sentry_schema.STRUCTURALLY_UNSUPPORTED_FAMILIES``), no HTTP call
    # is made at all.

    @staticmethod
    def _probe_one(client: httpx.Client, path: str) -> str:
        """Return a CAPABILITY_* status string for one probe. Never
        raises — every failure mode maps to a status category instead."""
        outcome = call_sentry(client, path)
        if outcome.ok:
            return CAPABILITY_AVAILABLE
        if outcome.category == CATEGORY_PERMISSION_DENIED:
            return CAPABILITY_DENIED
        if outcome.category == CATEGORY_NOT_FOUND:
            return CAPABILITY_UNSUPPORTED
        if outcome.category == CATEGORY_THROTTLED:
            return CAPABILITY_THROTTLED
        if outcome.category == CATEGORY_AUTH_FAILED:
            # A 401 on a capability probe (after the organization-identity
            # call already succeeded) is treated as unavailable, not
            # raised — a single family losing auth mid-probe-sweep should
            # not abort the whole foundation fetch.
            return CAPABILITY_UNAVAILABLE
        if outcome.category == CATEGORY_TIMEOUT:
            return CAPABILITY_TIMED_OUT
        if outcome.category in (CATEGORY_CONNECTION_ERROR, CATEGORY_TLS_ERROR):
            return CAPABILITY_UNAVAILABLE
        if outcome.category == CATEGORY_MALFORMED_RESPONSE:
            return CAPABILITY_MALFORMED
        return CAPABILITY_UNKNOWN

    @classmethod
    def _probe_capabilities(cls, client: httpx.Client, organization_id: str, *, slug: str) -> list[dict]:
        records = []
        for family, path_template in _CAPABILITY_PROBES:
            status = cls._probe_one(client, path_template.format(slug=slug))
            records.append(cls._normalize_capability(organization_id, family, status))
        for family in sorted(STRUCTURALLY_UNSUPPORTED_FAMILIES):
            records.append(cls._normalize_capability(organization_id, family, CAPABILITY_UNSUPPORTED))
        return records

    # ── Public connector interface ───────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Verify Sentry credentials with a single lightweight
        organization-info call.

        Uses ``GET /organizations/{slug}/`` — the narrowest official
        endpoint that simultaneously proves (a) the token is accepted and
        (b) the organization exists and is accessible, without requiring
        any broader read permission.

        Raises:
            AuthenticationError: Token rejected (401/403) or malformed
                organization_slug/auth_token.
            ConnectorError: Sentry returned an unexpected error.
            NetworkError: Transport-level failure (DNS, timeout, TLS).
        """
        slug, auth_token = self._credentials(credentials)
        with self._make_client(auth_token) as client:
            outcome = call_sentry(client, f"/organizations/{slug}/")
            _raise_for_outcome(outcome, context=f"GET /organizations/{slug}/")
        return True

    def probe_coverage(self, credentials: dict) -> dict:
        """Synchronous, bounded credential validation + coverage diagnosis
        (Sentry message 8 of 8).

        Runs exactly two things against the live organization: the
        organization-detail request (``validate_credentials``'s own
        endpoint) and the 7 bounded, page-1-only capability probes
        (message 1's ``_CAPABILITY_PROBES`` — never a full inventory
        collection). This is the SAME bounded probe sweep already used to
        seed ``family_completeness`` during a real ``fetch()``, never a
        separate, heavier surface.

        Returns a dict:
            {
                "coverage": COVERAGE_FULL | COVERAGE_PARTIAL | COVERAGE_INVALID,
                "organization_id": str,
                "slug": str,
                "name": Optional[str],
                "family_status": {family: CAPABILITY_*},
                "diagnostics": {group_label: "Available" | "Permission denied" | "Unavailable"},
            }

        Raises AuthenticationError/ConnectorError/NetworkError if the
        organization-detail request itself fails — a family-probe failure
        never raises, it only affects ``coverage``/``diagnostics``.
        """
        slug, auth_token = self._credentials(credentials)
        with self._make_client(auth_token) as client:
            outcome = call_sentry(client, f"/organizations/{slug}/")
            resp = _raise_for_outcome(outcome, context=f"GET /organizations/{slug}/")
            try:
                raw_org = resp.json()
            except ValueError as exc:
                raise ConnectorError("sentry: /organizations/{slug}/ response was not valid JSON") from exc
            if not isinstance(raw_org, dict):
                raise ConnectorError("sentry: /organizations/{slug}/ response was not a JSON object")

            organization_id = self.compute_organization_id(raw_org.get("id"))
            if organization_id is None:
                raise ConnectorError(
                    "sentry: could not establish a stable organization identity — "
                    "the organization detail response did not include a usable 'id' field"
                )

            capability_records = self._probe_capabilities(client, organization_id, slug=slug)
            family_status = {r["family"]: r["status"] for r in capability_records}

        coverage = compute_coverage_state(family_status)
        name = raw_org.get("name")
        return {
            "coverage": coverage,
            "organization_id": organization_id,
            "slug": slug,
            "name": name.strip() if isinstance(name, str) and name.strip() else None,
            "family_status": family_status,
            "diagnostics": format_capability_diagnostics(family_status),
        }

    def fetch(self, credentials: dict, *, _sleep_fn: Callable[[float], None] = None) -> list[dict]:
        """Fetch the Sentry organization identity, API capability
        inventory, project/team/member/access-edge collection,
        metric/issue alert-rule + notification-action collection,
        organization-integration/repository/code-mapping/ownership-rule
        collection, and effective-access derivation (Sentry messages 1-5
        of 8).

        Does NOT collect webhooks (no public API — see module docstring)
        or release/deployment configuration (no stable persistent
        settings endpoint exists — see module docstring) — these are
        permanently reported unsupported, never attempted. Message-5's
        privileged-member/privileged-team/routing-context derivation
        makes ZERO additional HTTP calls — it is pure local computation
        over the records already collected above.

        SECURITY: auth_token is used only within this method's scope,
        never logged, never persisted beyond the local ``httpx.Client``
        instance's lifetime.

        Raises:
            AuthenticationError: Token rejected or malformed credentials.
            ConnectorError: Sentry returned an unexpected error fetching
                the organization identity itself (every capability probe
                and every message-2 family collection fails soft into a
                status instead of raising).
            NetworkError: Transport-level failure reaching the organization.
        """
        slug, auth_token = self._credentials(credentials)

        records: list[dict] = []
        with self._make_client(auth_token) as client:
            outcome = call_sentry(client, f"/organizations/{slug}/", _sleep_fn=_sleep_fn)
            resp = _raise_for_outcome(outcome, context=f"GET /organizations/{slug}/")
            try:
                raw_org = resp.json()
            except ValueError as exc:
                raise ConnectorError("sentry: /organizations/{slug}/ response was not valid JSON") from exc
            if not isinstance(raw_org, dict):
                raise ConnectorError("sentry: /organizations/{slug}/ response was not a JSON object")

            organization_id = self.compute_organization_id(raw_org.get("id"))
            if organization_id is None:
                raise ConnectorError(
                    "sentry: could not establish a stable organization identity — "
                    "the organization detail response did not include a usable 'id' field"
                )

            capability_records = self._probe_capabilities(client, organization_id, slug=slug)
            family_completeness = {
                r["family"]: (
                    "complete" if r["status"] == CAPABILITY_AVAILABLE else "unavailable"
                )
                for r in capability_records
            }

            project_records, project_completeness = self._collect_projects(
                client, slug, organization_id, _sleep_fn=_sleep_fn,
            )
            team_records, assignment_records, team_completeness = self._collect_teams(
                client, slug, organization_id, _sleep_fn=_sleep_fn,
            )
            member_records, member_completeness = self._collect_members(
                client, slug, organization_id, _sleep_fn=_sleep_fn,
            )
            membership_records, membership_completeness, status_by_team = self._collect_team_memberships(
                client, slug, organization_id, team_records, _sleep_fn=_sleep_fn,
            )

            project_id_by_slug = {
                r["slug"]: r["project_id"] for r in project_records if r.get("slug")
            }
            metric_rule_records, metric_trigger_records, metric_action_records, metric_completeness = (
                self._collect_metric_alert_rules(client, slug, organization_id, project_id_by_slug, _sleep_fn=_sleep_fn)
            )
            issue_rule_records, issue_action_records, issue_completeness, status_by_project_issue_alerts = (
                self._collect_issue_alert_rules(client, slug, organization_id, project_records, _sleep_fn=_sleep_fn)
            )
            # Both metric-trigger actions and issue-rule actions share one
            # family key — combined completeness matches both sources only
            # when they agree; any disagreement (including one complete/
            # one denied) is reported as partial rather than guessing
            # which source's status should win.
            action_completeness = metric_completeness if metric_completeness == issue_completeness else FAMILY_PARTIAL

            integration_records, integration_completeness = self._collect_organization_integrations(
                client, slug, organization_id, _sleep_fn=_sleep_fn,
            )
            repository_records, repository_completeness = self._collect_repositories(
                client, slug, organization_id, _sleep_fn=_sleep_fn,
            )
            code_mapping_records, code_mapping_completeness = self._collect_code_mappings(
                client, slug, organization_id, _sleep_fn=_sleep_fn,
            )
            ownership_records, ownership_completeness, status_by_project_ownership = self._collect_ownership_rules(
                client, slug, organization_id, project_records, _sleep_fn=_sleep_fn,
            )

            # Sentry message 7 of 8: expose the per-team/per-project
            # completeness signals already computed above (previously
            # discarded) onto the team/project records themselves, so
            # diff_service._sentry_removal_suppressed() can localize
            # false-removal suppression to just the ONE team/project whose
            # nested walk failed, rather than either suppressing nothing
            # (false "removed" Changes) or suppressing the entire
            # organization-wide family (masking real removals elsewhere).
            # These are diagnostic completeness fields, never diff-tracked
            # (see _SENTRY_TRACKED_FIELDS_BY_TYPE in diff_service.py).
            for team_rec in team_records:
                team_rec["membership_collection_status"] = status_by_team.get(
                    team_rec["team_id"], FAMILY_UNAVAILABLE
                )
            for project_rec in project_records:
                project_rec["issue_alert_collection_status"] = status_by_project_issue_alerts.get(
                    project_rec["project_id"], FAMILY_UNAVAILABLE
                )
                project_rec["ownership_collection_status"] = status_by_project_ownership.get(
                    project_rec["project_id"], FAMILY_UNAVAILABLE
                )

            # Message-2/3 collection completeness is the ground truth for
            # these families — it must never be overridden by a stale
            # message-1 capability-probe success. If a capability probe
            # said "available" but the real collection failed, the
            # snapshot completeness reported here reflects the collection
            # result, not the probe.
            family_completeness[COLLECTION_FAMILY_PROJECTS] = project_completeness
            family_completeness[COLLECTION_FAMILY_TEAMS] = team_completeness
            family_completeness[COLLECTION_FAMILY_MEMBERS] = member_completeness
            family_completeness[COLLECTION_FAMILY_TEAM_MEMBERSHIPS] = membership_completeness
            family_completeness[COLLECTION_FAMILY_PROJECT_TEAM_ASSIGNMENTS] = team_completeness
            family_completeness[COLLECTION_FAMILY_METRIC_ALERT_RULES] = metric_completeness
            family_completeness[COLLECTION_FAMILY_ISSUE_ALERT_RULES] = issue_completeness
            family_completeness[COLLECTION_FAMILY_ALERT_ACTIONS] = action_completeness
            family_completeness[COLLECTION_FAMILY_ORGANIZATION_INTEGRATIONS] = integration_completeness
            family_completeness[COLLECTION_FAMILY_REPOSITORIES] = repository_completeness
            family_completeness[COLLECTION_FAMILY_CODE_MAPPINGS] = code_mapping_completeness
            family_completeness[COLLECTION_FAMILY_OWNERSHIP_RULES] = ownership_completeness
            # webhooks / release_configuration / deployment_configuration:
            # always unsupported this message — no HTTP call is ever
            # attempted for them (see the module docstring's message-4
            # documentation-verification log).
            for always_unsupported_family in COLLECTION_FAMILIES_ALWAYS_UNSUPPORTED:
                family_completeness[always_unsupported_family] = CAPABILITY_UNSUPPORTED

            # Message-5 effective-access derivation — PURE LOCAL
            # DERIVATION over the records already collected above. Makes
            # zero additional HTTP calls (no new `client.get`/`call_sentry`
            # invocation appears anywhere in this block).
            privileged_member_records, privileged_team_records, routing_context_records = (
                self._derive_effective_access(
                    organization_id,
                    project_records=project_records, team_records=team_records, member_records=member_records,
                    membership_records=membership_records, assignment_records=assignment_records,
                    metric_rule_records=metric_rule_records, issue_rule_records=issue_rule_records,
                    metric_action_records=metric_action_records, issue_action_records=issue_action_records,
                    ownership_records=ownership_records, integration_records=integration_records,
                    member_completeness=member_completeness, team_completeness=team_completeness,
                    membership_completeness=membership_completeness, assignment_completeness=team_completeness,
                    ownership_completeness=ownership_completeness, action_completeness=action_completeness,
                    integration_completeness=integration_completeness,
                )
            )
            family_completeness[COLLECTION_FAMILY_PRIVILEGED_MEMBERS] = self._worse_completeness(
                member_completeness, team_completeness, membership_completeness,
            )
            family_completeness[COLLECTION_FAMILY_PRIVILEGED_TEAMS] = self._worse_completeness(
                team_completeness, membership_completeness,
            )
            family_completeness[COLLECTION_FAMILY_ROUTING_CONTEXT] = self._worse_completeness(
                ownership_completeness, action_completeness,
            )

            organization_record = self._normalize_organization(
                organization_id,
                slug=slug,
                raw=raw_org,
                family_completeness=family_completeness,
            )
            records.append(organization_record)
            records.extend(capability_records)
            records.extend(project_records)
            records.extend(team_records)
            records.extend(member_records)
            records.extend(membership_records)
            records.extend(assignment_records)
            records.extend(metric_rule_records)
            records.extend(metric_trigger_records)
            records.extend(issue_rule_records)
            records.extend(metric_action_records)
            records.extend(issue_action_records)
            records.extend(integration_records)
            records.extend(repository_records)
            records.extend(code_mapping_records)
            records.extend(ownership_records)
            records.extend(privileged_member_records)
            records.extend(privileged_team_records)
            records.extend(routing_context_records)

        return records
