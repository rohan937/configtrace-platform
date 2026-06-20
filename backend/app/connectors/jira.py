"""Jira Cloud configuration drift connector (M86A).

Configuration snapshot connector for Jira Cloud.  Connects to the Jira Cloud
REST API v3 (and the Agile + automation REST APIs) using HTTP Basic auth
(email:api_token) and snapshots a set of safe configuration surfaces.  All
raw secrets, URLs, user identities, project keys, issue content, and PII are
discarded before the record is returned.

Surfaces covered
─────────────────
  Site                          — deployment type, version posture; never base URL
  Projects                      — type/style/privacy/archival posture; never keys
  Boards                        — board type category, location presence
  Workflows                     — step/transition counts; never rule expressions
  Workflow schemes              — mapping counts; never project/issue-type names
  Permission schemes            — permission grant counts; never holder identities
  Notification schemes          — event/notification counts; never recipients
  Issue type schemes            — issue-type-count posture; never names
  Field configuration schemes   — presence/description posture
  Screen schemes                — screen-mapping posture
  Webhooks                      — enabled, event count, URL scheme category;
                                  never the delivery URL or secret
  Automation rules              — enabled, state posture; never rule logic

Credentials dict expected by fetch() and validate_credentials():
  {
    "site_url":  "<Jira site base domain, e.g. myco.atlassian.net>",
    "email":     "<Atlassian account email>",
    "api_token": "<Atlassian API token>"
  }

SECURITY:
  The api_token and email are used ONLY in the _request() Authorization header
  (HTTP Basic auth).  They are NEVER stored on the connector instance, NEVER
  copied into any normalised record, and NEVER logged.

  Issue keys, issue titles, issue descriptions, comments, attachments, user
  names, user emails, account IDs, and raw URLs are NEVER fetched or stored in
  normalised records.

  Raw API responses are processed immediately and discarded.  Only flat safe
  scalars (opaque IDs, booleans, counts, category strings) are returned.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)

logger = logging.getLogger(__name__)

_TIMEOUT = 30.0
_MAX_STR_LEN = 100
_PAGE_LIMIT = 100  # records per page request

# API base path segments
_API_V3 = "rest/api/3"
_API_AGILE = "rest/agile/1.0"
_API_AUTOMATION = "rest/cb-automation/1.0"

# Per-surface record caps (bounds runaway pagination)
_MAX_PROJECTS = 200
_MAX_BOARDS = 200
_MAX_WORKFLOWS = 200
_MAX_WORKFLOW_SCHEMES = 200
_MAX_PERMISSION_SCHEMES = 200
_MAX_NOTIFICATION_SCHEMES = 200
_MAX_ISSUE_TYPE_SCHEMES = 200
_MAX_FIELD_CONFIG_SCHEMES = 200
_MAX_SCREEN_SCHEMES = 200
_MAX_WEBHOOKS = 200
_MAX_AUTOMATION_RULES = 200

# ── Record type constants ──────────────────────────────────────────────────────

JIRA_SITE = "jira_site"
JIRA_PROJECT = "jira_project"
JIRA_BOARD = "jira_board"
JIRA_WORKFLOW = "jira_workflow"
JIRA_WORKFLOW_SCHEME = "jira_workflow_scheme"
JIRA_PERMISSION_SCHEME = "jira_permission_scheme"
JIRA_NOTIFICATION_SCHEME = "jira_notification_scheme"
JIRA_ISSUE_TYPE_SCHEME = "jira_issue_type_scheme"
JIRA_FIELD_CONFIGURATION_SCHEME = "jira_field_configuration_scheme"
JIRA_SCREEN_SCHEME = "jira_screen_scheme"
JIRA_WEBHOOK = "jira_webhook"
JIRA_AUTOMATION_RULE = "jira_automation_rule"

JIRA_RECORD_TYPES: frozenset[str] = frozenset({
    JIRA_SITE,
    JIRA_PROJECT,
    JIRA_BOARD,
    JIRA_WORKFLOW,
    JIRA_WORKFLOW_SCHEME,
    JIRA_PERMISSION_SCHEME,
    JIRA_NOTIFICATION_SCHEME,
    JIRA_ISSUE_TYPE_SCHEME,
    JIRA_FIELD_CONFIGURATION_SCHEME,
    JIRA_SCREEN_SCHEME,
    JIRA_WEBHOOK,
    JIRA_AUTOMATION_RULE,
})

# ── Module-level helpers ────────────────────────────────────────────────────────


def _trunc(value: Any, length: int = _MAX_STR_LEN) -> str:
    """Return str(value) truncated to length, or '' for None/non-string."""
    if isinstance(value, str):
        return value[:length]
    return ""


def _bool(value: Any, default: bool = False) -> bool:
    """Coerce value to bool safely (None falls back to default)."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return bool(value)


def _int(value: Any, default: int = 0) -> int:
    """Coerce value to a non-negative int, excluding booleans."""
    if isinstance(value, bool):
        return default
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _count(value: Any) -> int:
    """Return len() for a list/dict, else 0.  Never stores the values."""
    if isinstance(value, (list, dict)):
        return len(value)
    return 0


def _url_scheme_category(url: Any) -> str:
    """Return 'https' | 'http' | 'other' | 'absent' — never store the URL value."""
    if not isinstance(url, str) or not url.strip():
        return "absent"
    u = url.strip().lower()
    if u.startswith("https://"):
        return "https"
    if u.startswith("http://"):
        return "http"
    return "other"


# ── Connector ───────────────────────────────────────────────────────────────────


class JiraConnector(BaseConnector):
    """Jira Cloud REST API v3 configuration drift connector (M86A).

    Uses HTTP Basic auth (email:api_token).  Neither the email nor the token
    is ever stored on the instance or in any returned record.

    SECURITY: Credentials are passed into the per-request helpers at call time
    only.  They are not logged, not written to any record, and not returned in
    any API response.
    """

    def __init__(self) -> None:  # noqa: D107 — explicit no-credential init
        pass

    # ── Low-level transport ───────────────────────────────────────────────────

    def _raise_for_status(self, response: httpx.Response, surface: str) -> None:
        """Map Jira HTTP status codes to typed connector exceptions.

        ``surface`` is a static, credential-free label used only for error
        context (never the request URL, which may carry query parameters).
        """
        code = response.status_code
        if code in (200, 201, 204):
            return
        if code == 401:
            raise AuthenticationError(
                "Jira authentication failed — check the email and API token."
            )
        if code == 403:
            raise ConnectorError(
                f"Jira permission denied (403) for surface {surface!r}.",
                status_code=403,
            )
        if code == 429:
            retry_after: Optional[float] = None
            raw_retry = response.headers.get("Retry-After")
            if raw_retry:
                try:
                    retry_after = float(raw_retry)
                except (TypeError, ValueError):
                    retry_after = None
            raise RateLimitError(
                "Jira rate limit exceeded (429).", retry_after=retry_after
            )
        if code >= 500:
            raise ConnectorError(
                f"Jira server error ({code}) for surface {surface!r}.",
                status_code=code,
            )
        if code >= 400:
            raise ConnectorError(
                f"Jira client error ({code}) for surface {surface!r}.",
                status_code=code,
            )

    def _request_base(
        self,
        site_url: str,
        email: str,
        api_token: str,
        api_base: str,
        path: str,
        surface: str,
        params: Optional[dict] = None,
    ) -> dict:
        """Execute a GET against a Jira REST endpoint and return parsed JSON.

        SECURITY: ``email`` and ``api_token`` are passed ONLY to httpx's
        ``auth=`` (Basic auth) and never stored, logged, or returned.

        Raises:
            AuthenticationError: 401 response.
            ConnectorError: 403, other 4xx, or 5xx responses.
            RateLimitError: 429 response.
            NetworkError: transport-level failure or undecodable body.
        """
        url = f"https://{site_url}/{api_base}/{path.lstrip('/')}"
        try:
            with httpx.Client(timeout=_TIMEOUT, follow_redirects=False) as client:
                response = client.get(
                    url,
                    params=params,
                    auth=(email, api_token),
                    headers={"Accept": "application/json"},
                )
        except httpx.TransportError as exc:
            raise NetworkError(
                f"Jira network error on surface {surface!r}: {type(exc).__name__}"
            ) from exc

        self._raise_for_status(response, surface)

        try:
            data = response.json()
        except ValueError as exc:
            raise NetworkError(
                f"Jira returned a non-JSON body on surface {surface!r}."
            ) from exc

        if isinstance(data, list):
            # Some endpoints (e.g. permissionscheme top-level) wrap in a key;
            # callers that expect a list handle this, but normalise to a dict.
            return {"values": data}
        if not isinstance(data, dict):
            return {}
        return data

    def _request(
        self,
        site_url: str,
        email: str,
        api_token: str,
        path: str,
        surface: str,
        params: Optional[dict] = None,
    ) -> dict:
        """Issue a request against the REST API v3 base."""
        return self._request_base(
            site_url, email, api_token, _API_V3, path, surface, params
        )

    def _request_agile(
        self,
        site_url: str,
        email: str,
        api_token: str,
        path: str,
        surface: str,
        params: Optional[dict] = None,
    ) -> dict:
        """Issue a request against the Agile (board) REST API base."""
        return self._request_base(
            site_url, email, api_token, _API_AGILE, path, surface, params
        )

    def _request_automation(
        self,
        site_url: str,
        email: str,
        api_token: str,
        path: str,
        surface: str,
        params: Optional[dict] = None,
    ) -> dict:
        """Issue a request against the automation REST API base.

        This endpoint may 404/403 on some plans — callers fail-soft.
        """
        return self._request_base(
            site_url, email, api_token, _API_AUTOMATION, path, surface, params
        )

    def _sanitize_site_url(self, site_url: Any) -> str:
        """Reduce a site URL to its bare host (e.g. ``myco.atlassian.net``).

        Strips scheme, any path/query, and trailing slashes.  The full URL with
        credentials is never stored or logged.
        """
        if not isinstance(site_url, str) or not site_url.strip():
            raise AuthenticationError("Jira site_url is missing or empty.")
        host = site_url.strip()
        # Strip scheme.
        if "://" in host:
            host = host.split("://", 1)[1]
        # Strip credentials in a user@host form, if any.
        if "@" in host:
            host = host.split("@", 1)[1]
        # Strip path / query / fragment.
        for sep in ("/", "?", "#"):
            if sep in host:
                host = host.split(sep, 1)[0]
        host = host.strip().rstrip(".").lower()
        if not host:
            raise AuthenticationError("Jira site_url is invalid after sanitisation.")
        return host

    # ── Pagination helper ─────────────────────────────────────────────────────

    def _paginate(
        self,
        site_url: str,
        email: str,
        api_token: str,
        api_base: str,
        path: str,
        surface: str,
        *,
        values_key: str = "values",
        max_records: int = _PAGE_LIMIT,
        extra_params: Optional[dict] = None,
    ) -> list[dict]:
        """Page through a Jira startAt/maxResults list endpoint.

        Caps at ``max_records`` to bound runaway pagination.
        """
        records: list[dict] = []
        start_at = 0
        page_size = min(_PAGE_LIMIT, max_records)
        while True:
            params: dict = {"startAt": start_at, "maxResults": page_size}
            if extra_params:
                params.update(extra_params)
            data = self._request_base(
                site_url, email, api_token, api_base, path, surface, params
            )
            page = data.get(values_key)
            if not isinstance(page, list):
                break
            records.extend(page)
            if len(records) >= max_records:
                break
            is_last = data.get("isLast")
            total = data.get("total")
            if is_last is True:
                break
            if not page:
                break
            if isinstance(total, int) and start_at + len(page) >= total:
                break
            start_at += len(page)
        return records[:max_records]

    # ── Surface fetchers ──────────────────────────────────────────────────────

    def _fetch_site(
        self, site_url: str, email: str, api_token: str
    ) -> list[dict]:
        """Fetch safe site metadata via GET /serverInfo."""
        data = self._request(site_url, email, api_token, "serverInfo", "site")
        if not data:
            return []
        return [self._normalize_site(data)]

    def _fetch_projects(
        self, site_url: str, email: str, api_token: str
    ) -> list[dict]:
        """Fetch projects via GET /project/search."""
        raw = self._paginate(
            site_url, email, api_token, _API_V3, "project/search", "project",
            values_key="values", max_records=_MAX_PROJECTS,
        )
        return [self._normalize_project(r) for r in raw if isinstance(r, dict)]

    def _fetch_boards(
        self, site_url: str, email: str, api_token: str
    ) -> list[dict]:
        """Fetch boards via the Agile API.  Fail-soft on 403/404."""
        try:
            raw = self._paginate(
                site_url, email, api_token, _API_AGILE, "board", "board",
                values_key="values", max_records=_MAX_BOARDS,
            )
        except ConnectorError:
            return []
        return [self._normalize_board(r) for r in raw if isinstance(r, dict)]

    def _fetch_workflows(
        self, site_url: str, email: str, api_token: str
    ) -> list[dict]:
        """Fetch workflows via GET /workflow/search.  Fail-soft on 403/404."""
        try:
            raw = self._paginate(
                site_url, email, api_token, _API_V3, "workflow/search", "workflow",
                values_key="values", max_records=_MAX_WORKFLOWS,
                extra_params={"expand": "transitions,statuses"},
            )
        except ConnectorError:
            return []
        return [self._normalize_workflow(r) for r in raw if isinstance(r, dict)]

    def _fetch_workflow_schemes(
        self, site_url: str, email: str, api_token: str
    ) -> list[dict]:
        """Fetch workflow schemes.  Fail-soft on 403/404."""
        try:
            raw = self._paginate(
                site_url, email, api_token, _API_V3, "workflowscheme", "workflow_scheme",
                values_key="values", max_records=_MAX_WORKFLOW_SCHEMES,
            )
        except ConnectorError:
            return []
        return [
            self._normalize_workflow_scheme(r) for r in raw if isinstance(r, dict)
        ]

    def _fetch_permission_schemes(
        self, site_url: str, email: str, api_token: str
    ) -> list[dict]:
        """Fetch permission schemes via GET /permissionscheme.  Fail-soft."""
        try:
            data = self._request(
                site_url, email, api_token, "permissionscheme", "permission_scheme",
                params={"expand": "permissions"},
            )
        except ConnectorError:
            return []
        raw = data.get("permissionSchemes")
        if not isinstance(raw, list):
            raw = data.get("values") if isinstance(data.get("values"), list) else []
        out: list[dict] = []
        for r in raw[:_MAX_PERMISSION_SCHEMES]:
            if isinstance(r, dict):
                out.append(self._normalize_permission_scheme(r))
        return out

    def _fetch_notification_schemes(
        self, site_url: str, email: str, api_token: str
    ) -> list[dict]:
        """Fetch notification schemes.  Fail-soft on 403/404."""
        try:
            raw = self._paginate(
                site_url, email, api_token, _API_V3, "notificationscheme",
                "notification_scheme", values_key="values",
                max_records=_MAX_NOTIFICATION_SCHEMES,
                extra_params={"expand": "notificationSchemeEvents"},
            )
        except ConnectorError:
            return []
        return [
            self._normalize_notification_scheme(r)
            for r in raw
            if isinstance(r, dict)
        ]

    def _fetch_issue_type_schemes(
        self, site_url: str, email: str, api_token: str
    ) -> list[dict]:
        """Fetch issue type schemes.  Fail-soft on 403/404."""
        try:
            raw = self._paginate(
                site_url, email, api_token, _API_V3, "issuetypescheme",
                "issue_type_scheme", values_key="values",
                max_records=_MAX_ISSUE_TYPE_SCHEMES,
            )
        except ConnectorError:
            return []
        return [
            self._normalize_issue_type_scheme(r)
            for r in raw
            if isinstance(r, dict)
        ]

    def _fetch_field_configuration_schemes(
        self, site_url: str, email: str, api_token: str
    ) -> list[dict]:
        """Fetch field configuration schemes.  Fail-soft on 403/404."""
        try:
            raw = self._paginate(
                site_url, email, api_token, _API_V3, "fieldconfigurationscheme",
                "field_configuration_scheme", values_key="values",
                max_records=_MAX_FIELD_CONFIG_SCHEMES,
            )
        except ConnectorError:
            return []
        return [
            self._normalize_field_configuration_scheme(r)
            for r in raw
            if isinstance(r, dict)
        ]

    def _fetch_screen_schemes(
        self, site_url: str, email: str, api_token: str
    ) -> list[dict]:
        """Fetch screen schemes.  Fail-soft on 403/404."""
        try:
            raw = self._paginate(
                site_url, email, api_token, _API_V3, "screenscheme", "screen_scheme",
                values_key="values", max_records=_MAX_SCREEN_SCHEMES,
            )
        except ConnectorError:
            return []
        return [
            self._normalize_screen_scheme(r) for r in raw if isinstance(r, dict)
        ]

    def _fetch_webhooks(
        self, site_url: str, email: str, api_token: str
    ) -> list[dict]:
        """Fetch registered webhooks.  Fail-soft on 403/404."""
        try:
            raw = self._paginate(
                site_url, email, api_token, _API_V3, "webhook", "webhook",
                values_key="values", max_records=_MAX_WEBHOOKS,
            )
        except ConnectorError:
            return []
        return [self._normalize_webhook(r) for r in raw if isinstance(r, dict)]

    def _fetch_automation_rules(
        self, site_url: str, email: str, api_token: str
    ) -> list[dict]:
        """Fetch automation rules via the automation API.  Fail-soft."""
        try:
            data = self._request_automation(
                site_url, email, api_token, "rule", "automation_rule",
            )
        except ConnectorError:
            return []
        raw = data.get("values")
        if not isinstance(raw, list):
            raw = data.get("data") if isinstance(data.get("data"), list) else []
        out: list[dict] = []
        for r in raw[:_MAX_AUTOMATION_RULES]:
            if isinstance(r, dict):
                out.append(self._normalize_automation_rule(r))
        return out

    # ── Normalizers ───────────────────────────────────────────────────────────

    def _normalize_site(self, raw: dict) -> dict:
        """Normalise /serverInfo into safe site metadata.

        SECURITY: the base URL, server title, and any health-check messages are
        never stored.  Only deployment type and version posture is kept.
        """
        deployment_raw = _trunc(raw.get("deploymentType", ""), 32).lower()
        if deployment_raw in ("cloud", "server"):
            deployment = deployment_raw
        else:
            deployment = "unknown"
        version_numbers = raw.get("versionNumbers")
        major_version: Optional[int] = None
        if isinstance(version_numbers, list) and version_numbers:
            major_version = _int(version_numbers[0])
        return {
            "record_type": JIRA_SITE,
            "provider": "jira",
            "record_id": "site",
            "resource_id": "site",
            "deployment_type": deployment,
            "major_version": major_version,
            "build_number": _int(raw.get("buildNumber")),
            "scm_info_present": bool(raw.get("scmInfo")),
            # Schema fields (JiraSiteRecord) consumed by the M86B site rules.
            # site_url_present reflects whether /serverInfo returned a base URL
            # indicator (the raw URL itself is never stored).  The project /
            # webhook / automation counts are populated in fetch() once the
            # other surfaces have been snapshotted; default to None here so the
            # rules treat them as "unknown" until wired.
            "site_url_present": bool(raw.get("baseUrl")),
            "project_count": None,
            "webhook_count": None,
            "automation_rule_count": None,
        }

    def _normalize_project(self, raw: dict) -> dict:
        """Normalise one project to a safe flat record.

        SECURITY: project key, name (as a customer-content field), lead
        identity, avatar URLs, and description are never stored.  The opaque
        numeric project ID is retained for diff correlation only.
        """
        pid = _trunc(raw.get("id", ""), 64) or "unknown"
        type_key = _trunc(raw.get("projectTypeKey", ""), 32) or "unknown"
        style = _trunc(raw.get("style", ""), 32) or "unknown"
        # Normalise the project type / style into the bounded category enums the
        # M86B rules classify against (an unrecognised value maps to "unknown").
        _known_type_categories = {"software", "business", "service_desk", "product_discovery"}
        type_category = type_key if type_key in _known_type_categories else "unknown"
        _known_style_categories = {"classic", "next-gen"}
        style_category = style if style in _known_style_categories else "unknown"
        return {
            "record_type": JIRA_PROJECT,
            "provider": "jira",
            "record_id": pid,
            "resource_id": pid,
            "has_key": bool(raw.get("key")),
            "project_type_key": type_key,
            "style": style,
            "is_private": _bool(raw.get("isPrivate")),
            "is_archived": _bool(raw.get("archived")),
            "is_deleted": _bool(raw.get("deleted")),
            "is_simplified": _bool(raw.get("simplified")),
            # Schema fields (JiraProjectRecord) consumed by the M86B project
            # rules.  board_count / issue_type_count are not enumerated per
            # project by this connector, so they are left as None ("unknown")
            # to avoid false-positive "no boards / no issue types" findings.
            "project_key_present": bool(raw.get("key")),
            "project_type_category": type_category,
            "project_private": _bool(raw.get("isPrivate")),
            "project_archived": _bool(raw.get("archived")),
            "project_deleted": _bool(raw.get("deleted")),
            "project_simplified": _bool(raw.get("simplified")),
            "project_style_category": style_category,
            "board_count": None,
            "issue_type_count": None,
            "lead_present": bool(raw.get("lead")),
        }

    def _normalize_board(self, raw: dict) -> dict:
        """Normalise one Agile board to a safe flat record.

        SECURITY: board name and the project/filter it is scoped to are never
        stored beyond a location-presence boolean.

        M86C — derive safe board scope posture. The raw JQL of the board filter,
        filter name, column names, quick-filter names, and swimlane query text
        are NEVER stored: only counts, booleans, and a hardcoded swimlane
        strategy category enum.
        """
        bid = _trunc(raw.get("id", ""), 64) or "unknown"
        type_raw = _trunc(raw.get("type", ""), 32).lower()
        if type_raw in ("scrum", "kanban", "simple"):
            board_type = type_raw
        else:
            board_type = "unknown"

        # Board filter presence — a board scoped to a filter (saved search) vs
        # a project. We never read the filter's JQL, only its presence and a
        # broad-scope heuristic flag if the API exposes a coarse indicator.
        config = raw.get("columnConfig")
        sub_query = raw.get("subQuery")
        filter_obj = raw.get("filter")
        location = raw.get("location")
        filter_present = bool(filter_obj) or (
            isinstance(location, dict)
            and _trunc(location.get("type", ""), 32).lower() == "filter"
        )

        # Broad-JQL heuristic. We never store or inspect raw JQL text. We treat
        # a board as broad only when the API explicitly flags an unbounded
        # subQuery/filter via a safe boolean indicator.
        jql_broad = _bool(raw.get("jqlFilterBroad")) or _bool(
            raw.get("filterUnbounded")
        )
        if not jql_broad and isinstance(sub_query, dict):
            # An empty subQuery query string means no additional scoping — treat
            # as broad. We only inspect emptiness, never the query text itself.
            q = sub_query.get("query")
            if isinstance(q, str) and not q.strip():
                jql_broad = True

        # Column / quick-filter counts (structure only, never names).
        column_count = 0
        if isinstance(config, dict):
            column_count = _count(config.get("columns"))

        quick_filter_count = _count(raw.get("quickFilters"))

        # Swimlane strategy category — hardcoded enum, never raw API text.
        swimlane = raw.get("swimlaneStrategy") or raw.get("swimlanes")
        strategy_raw = ""
        if isinstance(swimlane, str):
            strategy_raw = _trunc(swimlane, 32).lower()
        elif isinstance(swimlane, dict):
            strategy_raw = _trunc(swimlane.get("strategy", ""), 32).lower()
        _swimlane_map = {
            "project": "project",
            "assignee": "assignee",
            "epic": "epic",
            "query": "query",
            "custom": "query",
            "parentchild": "parentChild",
            "parentchildren": "parentChild",
            "stories": "parentChild",
            "none": "none",
            "no_swimlane": "none",
        }
        swimlane_category = _swimlane_map.get(strategy_raw, "unknown")
        if not strategy_raw:
            swimlane_category = "unknown"

        # Board location type category — classify the location wrapper by its
        # bounded type only (project / user / filter); never the location value.
        location_type_raw = ""
        if isinstance(location, dict):
            location_type_raw = _trunc(location.get("type", ""), 32).lower()
        if location_type_raw in ("project", "user", "filter"):
            location_type_category = location_type_raw
        elif isinstance(location, dict) and location.get("projectId"):
            location_type_category = "project"
        elif location:
            location_type_category = "unknown"
        else:
            location_type_category = "unknown"
        # Opaque project linkage id (never a project key/name).
        project_id_val: Optional[str] = None
        if isinstance(location, dict):
            raw_pid = location.get("projectId") or location.get("projectKey")
            if raw_pid is not None:
                project_id_val = _trunc(str(raw_pid), 64) or None

        return {
            "record_type": JIRA_BOARD,
            "provider": "jira",
            "record_id": bid,
            "resource_id": bid,
            "board_type": board_type,
            "location_present": bool(location),
            # Schema fields (JiraBoardRecord) consumed by the M86B board rules.
            "board_type_category": board_type,
            "board_location_type_category": location_type_category,
            "project_id": project_id_val,
            # M86C safe board scope posture
            "board_filter_present": bool(filter_present),
            "board_jql_filter_broad": bool(jql_broad),
            "board_column_count": _int(column_count),
            "board_quick_filter_count": _int(quick_filter_count),
            "board_swimlane_strategy_category": swimlane_category,
        }

    def _normalize_workflow(self, raw: dict) -> dict:
        """Normalise one workflow to a safe flat record.

        SECURITY: workflow name, description, transition rule expressions,
        condition/validator configs, and post-functions are never stored.
        Only structural counts are kept.
        """
        ident = raw.get("id")
        wf_id = ""
        if isinstance(ident, dict):
            wf_id = _trunc(ident.get("entityId", ""), 64)
        if not wf_id:
            wf_id = _trunc(raw.get("entityId", ""), 64)
        if not wf_id:
            wf_id = "unknown"
        transitions = raw.get("transitions")
        statuses = raw.get("statuses")
        # M86C — derive safe workflow structure posture. No status/transition
        # names, rule expressions, or configs are stored: only counts/booleans.
        has_done = False
        has_in_progress = False
        category_keys: set[str] = set()
        if isinstance(statuses, list):
            for st in statuses:
                if not isinstance(st, dict):
                    continue
                cat = st.get("statusCategory")
                cat_key = ""
                if isinstance(cat, dict):
                    cat_key = _trunc(cat.get("key", ""), 32).lower()
                elif isinstance(cat, str):
                    cat_key = _trunc(cat, 32).lower()
                if cat_key:
                    category_keys.add(cat_key)
                if cat_key == "done":
                    has_done = True
                if cat_key == "indeterminate":
                    has_in_progress = True
        validator_count = 0
        condition_count = 0
        post_function_count = 0
        global_transition_count = 0
        if isinstance(transitions, list):
            for tr in transitions:
                if not isinstance(tr, dict):
                    continue
                if _trunc(tr.get("type", ""), 32).lower() == "global":
                    global_transition_count += 1
                rules = tr.get("rules")
                if isinstance(rules, dict):
                    validator_count += _count(rules.get("validators"))
                    condition_count += _count(rules.get("conditions"))
                    post_function_count += _count(rules.get("postFunctions"))
        return {
            "record_type": JIRA_WORKFLOW,
            "provider": "jira",
            "record_id": wf_id,
            "resource_id": wf_id,
            "is_default": _bool(raw.get("isDefault")),
            "transition_count": _int(_count(transitions)),
            "status_count": _int(_count(statuses)),
            "has_description": bool(raw.get("description")),
            # Schema fields (JiraWorkflowRecord) consumed by the M86B workflow rules.
            "workflow_status_count": _int(_count(statuses)),
            "workflow_transition_count": _int(_count(transitions)),
            # M86C safe structure posture
            "workflow_global_transition_count": _int(global_transition_count),
            "workflow_active": _bool(raw.get("isActive"), default=True),
            "workflow_draft": _bool(raw.get("draft")),
            "workflow_has_done_status": has_done,
            "workflow_has_in_progress_status": has_in_progress,
            "workflow_transition_rule_count": _int(
                validator_count + condition_count + post_function_count
            ),
            "workflow_validator_count": _int(validator_count),
            "workflow_condition_count": _int(condition_count),
            "workflow_post_function_count": _int(post_function_count),
            "workflow_orphan_status_count": _int(_count(raw.get("orphanStatuses"))),
            "workflow_status_category_count": _int(len(category_keys)),
        }

    def _normalize_workflow_scheme(self, raw: dict) -> dict:
        """Normalise one workflow scheme to a safe flat record.

        SECURITY: scheme name/description and the named workflow/issue-type
        mappings are never stored — only mapping counts.
        """
        sid = _trunc(raw.get("id", ""), 64) or "unknown"
        mapping = raw.get("issueTypeMappings")
        # Associated-project count is only known when the API echoes it; left as
        # None ("unknown") otherwise so the unused-scheme rule does not misfire.
        _scheme_projects = raw.get("projects") or raw.get("projectIds")
        scheme_project_count = (
            _int(_count(_scheme_projects)) if _scheme_projects is not None else None
        )
        default_present = bool(
            raw.get("defaultWorkflow") is not None or raw.get("default")
        )
        # M86C — safe mapping posture. Distinct mapped workflow names are never
        # stored; only counts of mappings and unmapped issue types are kept.
        mapping_count = _count(mapping)
        unmapped = _count(raw.get("unmappedIssueTypes") or raw.get("unmapped"))
        workflow_count = _count(raw.get("workflows"))
        if workflow_count == 0 and isinstance(mapping, dict):
            # Distinct workflow values referenced by the mapping (count only).
            distinct = {v for v in mapping.values() if isinstance(v, (str, int))}
            workflow_count = len(distinct)
        return {
            "record_type": JIRA_WORKFLOW_SCHEME,
            "provider": "jira",
            "record_id": sid,
            "resource_id": sid,
            "is_default": _bool(raw.get("defaultWorkflow") is not None
                                or raw.get("default")),
            "issue_type_mapping_count": _int(mapping_count),
            "has_draft": _bool(raw.get("draft")),
            "has_description": bool(raw.get("description")),
            # Schema fields (JiraWorkflowSchemeRecord) consumed by the M86B rules.
            "workflow_scheme_project_count": scheme_project_count,
            "workflow_scheme_default_present": default_present,
            # M86C safe scheme mapping posture
            "workflow_scheme_workflow_count": _int(workflow_count),
            "workflow_scheme_issue_type_mapping_count": _int(mapping_count),
            "workflow_scheme_unmapped_issue_type_count": _int(unmapped),
        }

    def _normalize_permission_scheme(self, raw: dict) -> dict:
        """Normalise one permission scheme to a safe flat record.

        SECURITY: grant holder identities (users, groups, roles), scheme
        name, and description are never stored — only grant counts.

        M86C — derive safe public/high-privilege grant posture. Holder
        identities, group names, and account IDs are NEVER stored: only
        booleans indicating that a *public* holder type (anonymous / anyone /
        loggedin / applicationRole) holds a sensitive permission, plus counts.
        """
        sid = _trunc(raw.get("id", ""), 64) or "unknown"
        permissions = raw.get("permissions")

        # Holder types that represent "public" / broad principals. We classify
        # by holder *type* only — never the holder's parameter (group/role id).
        _public_holder_types = {
            "anonymous",
            "anyone",
            "loggedin",
            "applicationrole",
        }
        # Sensitive permission keys mapped to their public-flag field.
        _public_perm_fields = {
            "BROWSE_PROJECTS": "permission_public_browse_projects",
            "ADMINISTER_PROJECTS": "permission_public_administer_projects",
            "MANAGE_SPRINTS_PERMISSION": "permission_public_manage_sprints",
            "CREATE_ISSUES": "permission_public_create_issues",
            "TRANSITION_ISSUES": "permission_public_transition_issues",
        }
        # High-privilege permission keys (counted when granted to anyone).
        _high_privilege_perms = {
            "ADMINISTER_PROJECTS",
            "ADMINISTER",
            "SYSTEM_ADMIN",
            "MANAGE_SPRINTS_PERMISSION",
            "DELETE_ALL_WORKLOGS",
            "DELETE_ALL_COMMENTS",
            "EDIT_ALL_WORKLOGS",
            "MODIFY_REPORTER",
            "MANAGE_WATCHERS",
        }

        public_flags = {field: False for field in _public_perm_fields.values()}
        unknown_holder_count = 0
        high_privilege_grant_count = 0
        public_grant_count = 0
        # Per-holder-type grant counts consumed by the M86B permission rules.
        anonymous_grant_count = 0
        anyone_grant_count = 0
        logged_in_grant_count = 0
        project_role_grant_count = 0

        if isinstance(permissions, list):
            for grant in permissions:
                if not isinstance(grant, dict):
                    continue
                perm_key = _trunc(grant.get("permission", ""), 64).upper()
                holder = grant.get("holder")
                holder_type = ""
                if isinstance(holder, dict):
                    holder_type = _trunc(holder.get("type", ""), 32).lower()
                elif isinstance(holder, str):
                    holder_type = _trunc(holder, 32).lower()

                if holder_type == "anonymous":
                    anonymous_grant_count += 1
                elif holder_type == "anyone":
                    anyone_grant_count += 1
                elif holder_type == "loggedin":
                    logged_in_grant_count += 1
                elif holder_type in ("projectrole", "role"):
                    project_role_grant_count += 1

                is_public = holder_type in _public_holder_types
                if not holder_type:
                    unknown_holder_count += 1
                if is_public:
                    public_grant_count += 1
                    field = _public_perm_fields.get(perm_key)
                    if field is not None:
                        public_flags[field] = True
                    if perm_key in _high_privilege_perms:
                        high_privilege_grant_count += 1

        return {
            "record_type": JIRA_PERMISSION_SCHEME,
            "provider": "jira",
            "record_id": sid,
            "resource_id": sid,
            "permission_grant_count": _int(_count(permissions)),
            "has_description": bool(raw.get("description")),
            # Schema fields (JiraPermissionSchemeRecord) consumed by the M86B rules.
            "permission_anonymous_grant_count": _int(anonymous_grant_count),
            "permission_anyone_grant_count": _int(anyone_grant_count),
            "permission_logged_in_grant_count": _int(logged_in_grant_count),
            "permission_project_role_grant_count": _int(project_role_grant_count),
            # M86C safe public/high-privilege grant posture
            "permission_public_browse_projects": public_flags[
                "permission_public_browse_projects"
            ],
            "permission_public_administer_projects": public_flags[
                "permission_public_administer_projects"
            ],
            "permission_public_manage_sprints": public_flags[
                "permission_public_manage_sprints"
            ],
            "permission_public_create_issues": public_flags[
                "permission_public_create_issues"
            ],
            "permission_public_transition_issues": public_flags[
                "permission_public_transition_issues"
            ],
            "permission_unknown_holder_count": _int(unknown_holder_count),
            "permission_high_privilege_grant_count": _int(
                high_privilege_grant_count
            ),
            "permission_public_grant_count": _int(public_grant_count),
        }

    def _normalize_notification_scheme(self, raw: dict) -> dict:
        """Normalise one notification scheme to a safe flat record.

        SECURITY: recipient identities (users, groups, emails), scheme name,
        and description are never stored — only event/notification counts.
        """
        sid = _trunc(raw.get("id", ""), 64) or "unknown"
        events = raw.get("notificationSchemeEvents")
        notification_count = 0
        # M86C — derive safe recipient posture. Recipient identities (users,
        # groups, emails, account IDs) are NEVER stored: only counts of
        # all-watcher and unrecognised recipient *types*, plus event count.
        all_watchers_count = 0
        unknown_recipient_count = 0
        # Per-recipient-type counts consumed by the M86B notification rules.
        email_recipient_count = 0
        group_recipient_count = 0
        project_role_recipient_count = 0
        _known_recipient_types = {
            "currentassignee",
            "reporter",
            "currentuser",
            "projectlead",
            "componentlead",
            "user",
            "group",
            "projectrole",
            "emailaddress",
            "allwatchers",
            "groupcustomfield",
            "usercustomfield",
        }
        if isinstance(events, list):
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                notifications = ev.get("notifications")
                notification_count += _count(notifications)
                if isinstance(notifications, list):
                    for notif in notifications:
                        if not isinstance(notif, dict):
                            continue
                        ntype = _trunc(
                            notif.get("notificationType", ""), 48
                        ).lower()
                        if ntype == "allwatchers":
                            all_watchers_count += 1
                        elif ntype == "emailaddress":
                            email_recipient_count += 1
                        elif ntype == "group":
                            group_recipient_count += 1
                        elif ntype == "projectrole":
                            project_role_recipient_count += 1
                        elif ntype and ntype not in _known_recipient_types:
                            unknown_recipient_count += 1
                        elif not ntype:
                            unknown_recipient_count += 1
        return {
            "record_type": JIRA_NOTIFICATION_SCHEME,
            "provider": "jira",
            "record_id": sid,
            "resource_id": sid,
            "event_count": _int(_count(events)),
            "notification_count": _int(notification_count),
            "has_description": bool(raw.get("description")),
            # Schema fields (JiraNotificationSchemeRecord) consumed by the M86B rules.
            "notification_email_recipient_count": _int(email_recipient_count),
            "notification_group_recipient_count": _int(group_recipient_count),
            "notification_project_role_recipient_count": _int(
                project_role_recipient_count
            ),
            # M86C safe recipient posture
            "notification_all_watchers_recipient_count": _int(all_watchers_count),
            "notification_unknown_recipient_count": _int(unknown_recipient_count),
            "notification_event_count": _int(_count(events)),
        }

    def _normalize_issue_type_scheme(self, raw: dict) -> dict:
        """Normalise one issue type scheme to a safe flat record.

        SECURITY: scheme name and description are never stored — only the
        default-issue-type presence and a bucketed posture.
        """
        sid = _trunc(raw.get("id", ""), 64) or "unknown"
        # Issue-type membership count is only known when the API echoes the
        # mapping; left as None ("unknown") otherwise so the no-types rule does
        # not misfire on schemes whose members were not expanded.
        _issue_types = raw.get("issueTypeIds") or raw.get("issueTypes")
        issue_type_count = (
            _int(_count(_issue_types)) if _issue_types is not None else None
        )
        return {
            "record_type": JIRA_ISSUE_TYPE_SCHEME,
            "provider": "jira",
            "record_id": sid,
            "resource_id": sid,
            "is_default": _bool(raw.get("isDefault")),
            "has_default_issue_type": bool(raw.get("defaultIssueTypeId")),
            "has_description": bool(raw.get("description")),
            # Schema fields (JiraIssueTypeSchemeRecord) consumed by the M86B rules.
            "issue_type_count": issue_type_count,
            "default_issue_type_present": bool(raw.get("defaultIssueTypeId")),
        }

    def _normalize_field_configuration_scheme(self, raw: dict) -> dict:
        """Normalise one field configuration scheme to a safe flat record.

        SECURITY: scheme name and description are never stored.
        """
        sid = _trunc(raw.get("id", ""), 64) or "unknown"
        # Field-configuration membership counts are only known when the API
        # echoes the mappings; left as None ("unknown") otherwise so the
        # no-configurations / hidden-required-conflict rules do not misfire.
        _mappings = raw.get("fieldConfigurationToIssueTypeMappings") or raw.get(
            "mappings"
        )
        field_configuration_count = (
            _int(_count(_mappings)) if _mappings is not None else None
        )
        return {
            "record_type": JIRA_FIELD_CONFIGURATION_SCHEME,
            "provider": "jira",
            "record_id": sid,
            "resource_id": sid,
            "has_description": bool(raw.get("description")),
            # Schema fields (JiraFieldConfigurationSchemeRecord) consumed by M86B.
            "field_configuration_count": field_configuration_count,
            "required_field_count": None,
            "hidden_field_count": None,
        }

    def _normalize_screen_scheme(self, raw: dict) -> dict:
        """Normalise one screen scheme to a safe flat record.

        SECURITY: scheme name, description, and the named screens it maps to
        are never stored — only mapping counts and a default-screen boolean.
        """
        sid = _trunc(raw.get("id", ""), 64) or "unknown"
        screens = raw.get("screens")
        has_default = False
        if isinstance(screens, dict):
            has_default = bool(screens.get("default"))
        # M86C — derive safe screen mapping posture. Screen names, tab names,
        # and field names are NEVER stored: only counts.
        tab_count = _int(_count(raw.get("tabs")))
        # Operation slots a screen scheme may map: default/create/edit/view.
        unmapped_screen_count = 0
        if isinstance(screens, dict):
            for slot in ("default", "create", "edit", "view"):
                if not screens.get(slot):
                    unmapped_screen_count += 1
        else:
            # No screens mapping at all — all four operation slots unmapped.
            unmapped_screen_count = 4
        return {
            "record_type": JIRA_SCREEN_SCHEME,
            "provider": "jira",
            "record_id": sid,
            "resource_id": sid,
            "screen_mapping_count": _int(_count(screens)),
            "has_default_screen": has_default,
            "has_description": bool(raw.get("description")),
            # Schema fields (JiraScreenSchemeRecord) consumed by the M86B rules.
            # screen_count mirrors the mapped-screen count; field_count is not
            # enumerated by this connector, so it is None ("unknown") to avoid a
            # false-positive "no fields" finding.
            "screen_count": _int(_count(screens)),
            "tab_count": _int(tab_count),
            "field_count": None,
            # M86C safe screen scheme mapping posture
            "screen_tab_count": _int(tab_count),
            "screen_unmapped_screen_count": _int(unmapped_screen_count),
        }

    def _normalize_webhook(self, raw: dict) -> dict:
        """Normalise one webhook to a safe flat record.

        SECURITY: the delivery URL and any secret are never stored.  Only the
        URL scheme category, an enabled flag, and the subscribed-event count
        are kept.
        """
        wid = _trunc(raw.get("id", ""), 64) or "unknown"
        events = raw.get("events")
        url = raw.get("url")

        # M86C — derive safe event-scope posture. Raw event identifiers are
        # classified into hardcoded category booleans; the raw event strings,
        # delivery URL, JQL filter, and secret are NEVER stored.
        has_issue = False
        has_comment = False
        has_attachment = False
        has_project = False
        has_sprint = False
        has_worklog = False
        issue_event_kinds: set[str] = set()
        # The canonical Jira issue lifecycle events.
        _issue_event_kinds = {"created", "updated", "deleted"}
        if isinstance(events, list):
            for ev in events:
                name = _trunc(ev, 64).lower() if isinstance(ev, str) else ""
                if not name and isinstance(ev, dict):
                    name = _trunc(ev.get("event", ""), 64).lower()
                if not name:
                    continue
                if "comment" in name:
                    has_comment = True
                elif "attachment" in name:
                    has_attachment = True
                elif "worklog" in name:
                    has_worklog = True
                elif "sprint" in name:
                    has_sprint = True
                elif "project" in name:
                    has_project = True
                elif name.startswith("jira:issue") or name.startswith("issue"):
                    has_issue = True
                    for kind in _issue_event_kinds:
                        if name.endswith(kind):
                            issue_event_kinds.add(kind)

        all_issue_events = _issue_event_kinds.issubset(issue_event_kinds)

        # JQL empty-or-broad — never inspect the JQL text. We flag broad only
        # when there is no filter indicator at all, or the API exposes a safe
        # broad-scope boolean.
        has_filter = bool(raw.get("filters") or raw.get("jqlFilter"))
        jql_empty_or_broad = not has_filter or _bool(raw.get("jqlFilterBroad"))

        # Event scope category — hardcoded enum derived from how many distinct
        # event families the webhook subscribes to.
        family_hits = sum(
            1
            for flag in (
                has_issue,
                has_comment,
                has_attachment,
                has_project,
                has_sprint,
                has_worklog,
            )
            if flag
        )
        if not isinstance(events, list) or not events:
            scope_category = "unknown"
        elif family_hits <= 1:
            scope_category = "narrow"
        elif family_hits <= 3:
            scope_category = "medium"
        else:
            scope_category = "broad"

        return {
            "record_type": JIRA_WEBHOOK,
            "provider": "jira",
            "record_id": wid,
            "resource_id": wid,
            "enabled": _bool(raw.get("enabled"), default=True),
            "event_count": _int(_count(events)),
            "webhook_url_present": bool(url),
            "webhook_url_scheme_category": _url_scheme_category(url),
            "has_filter": has_filter,
            # Schema fields (JiraWebhookRecord) consumed by the M86B webhook rules.
            # webhook_secret_present reflects whether a signing-secret indicator
            # was present; the secret value itself is NEVER read or stored.
            "webhook_enabled": _bool(raw.get("enabled"), default=True),
            "webhook_event_count": _int(_count(events)),
            "webhook_jql_filter_present": has_filter,
            "webhook_secret_present": bool(
                raw.get("secret") or raw.get("secretToken") or raw.get("signingSecret")
            ),
            # M86C safe event-scope posture
            "webhook_has_issue_events": bool(has_issue),
            "webhook_has_comment_events": bool(has_comment),
            "webhook_has_attachment_events": bool(has_attachment),
            "webhook_has_project_events": bool(has_project),
            "webhook_has_sprint_events": bool(has_sprint),
            "webhook_has_worklog_events": bool(has_worklog),
            "webhook_all_issue_events": bool(all_issue_events),
            "webhook_jql_empty_or_broad": bool(jql_empty_or_broad),
            "webhook_event_scope_category": scope_category,
        }

    def _normalize_automation_rule(self, raw: dict) -> dict:
        """Normalise one automation rule to a safe flat record.

        SECURITY: rule name, description, the trigger/condition/action
        component logic, and any actor identities are never stored — only
        enabled/state posture and component counts.
        """
        rid = _trunc(raw.get("id", ""), 64) or "unknown"
        state_raw = _trunc(raw.get("state", ""), 32).upper()
        if state_raw in ("ENABLED", "DISABLED", "DRAFT"):
            state = state_raw.lower()
        else:
            state = "unknown"
        components = raw.get("components") or raw.get("ruleComponents")

        # Trigger type category — classify the trigger wrapper by a bounded set
        # of safe tokens only; never the raw trigger expression/config.
        trigger = raw.get("trigger")
        trigger_token = ""
        if isinstance(trigger, dict):
            trigger_token = _trunc(
                trigger.get("type", "") or trigger.get("component", ""), 64
            ).lower()
        elif isinstance(trigger, str):
            trigger_token = _trunc(trigger, 64).lower()
        _t = trigger_token.replace("_", ".").replace(" ", "")
        if not trigger_token:
            trigger_category = "unknown"
        elif "schedule" in _t or "cron" in _t:
            trigger_category = "scheduled"
        elif "manual" in _t:
            trigger_category = "manual"
        elif "webhook" in _t or "incoming" in _t:
            trigger_category = "webhook"
        elif "issue" in _t or "comment" in _t or "field" in _t or "transition" in _t:
            trigger_category = "issue"
        else:
            trigger_category = "unknown"

        # M86C — derive safe action posture. Component logic, action
        # configuration, URLs, email addresses, and rule expressions are NEVER
        # stored: only counts by component *type* and hardcoded action-class
        # booleans, plus a hardcoded scope category enum.
        action_count = 0
        condition_count = 0
        branch_count = 0
        has_web_request = False
        has_email = False
        has_external = False
        has_comment = False
        if isinstance(components, list):
            for comp in components:
                if not isinstance(comp, dict):
                    continue
                ctype = _trunc(comp.get("component", ""), 48).lower()
                ctype_alt = _trunc(comp.get("type", ""), 48).lower()
                kind = ctype or ctype_alt
                if kind == "action":
                    action_count += 1
                elif kind == "condition":
                    condition_count += 1
                elif kind in ("branch", "iterate", "loop"):
                    branch_count += 1
                # Classify action sub-type by a safe type/value token only.
                comp_type = _trunc(comp.get("value", ""), 64).lower()
                if not comp_type:
                    schema = comp.get("schemaVersion")
                    comp_type = _trunc(comp.get("type", ""), 64).lower() if schema else comp_type
                token = " ".join([kind, comp_type]).lower()
                normalized = token.replace(".", "").replace("_", "").replace(" ", "")
                if (
                    "webrequest" in normalized
                    or "outgoingwebhook" in normalized
                    or "sendwebrequest" in normalized
                ):
                    has_web_request = True
                if "sendemail" in normalized or "email" in normalized:
                    has_email = True
                if (
                    "slack" in normalized
                    or "microsoftteams" in normalized
                    or "teams" in normalized
                    or "outgoing" in normalized
                ):
                    has_external = True
                if "comment" in normalized:
                    has_comment = True

        # Scope category — hardcoded enum, never raw project ids/names.
        scope_raw = _trunc(raw.get("ruleScope") or raw.get("scope"), 32).lower()
        project_ids = raw.get("projects") or raw.get("projectIds")
        project_scope_count = _count(project_ids)
        if scope_raw in ("global", "all"):
            scope_category = "global"
        elif project_scope_count > 1:
            scope_category = "multi-project"
        elif project_scope_count == 1 or scope_raw in ("project", "single"):
            scope_category = "project"
        else:
            scope_category = "unknown"

        return {
            "record_type": JIRA_AUTOMATION_RULE,
            "provider": "jira",
            "record_id": rid,
            "resource_id": rid,
            "enabled": _bool(raw.get("enabled"), default=(state == "enabled")),
            "state": state,
            "component_count": _int(_count(components)),
            "has_description": bool(raw.get("description")),
            # Schema fields (JiraAutomationRuleRecord) consumed by the M86B rules.
            "automation_enabled": _bool(
                raw.get("enabled"), default=(state == "enabled")
            ),
            "automation_trigger_type_category": trigger_category,
            "automation_component_count": _int(_count(components)),
            # M86C safe action posture
            "automation_action_count": _int(action_count),
            "automation_condition_count": _int(condition_count),
            "automation_branch_count": _int(branch_count),
            "automation_scope_category": scope_category,
            "automation_has_web_request_action": bool(has_web_request),
            "automation_has_email_action": bool(has_email),
            "automation_has_external_action": bool(has_external),
            "automation_has_comment_action": bool(has_comment),
        }

    # ── Public interface ──────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Snapshot all Jira configuration surfaces and return safe records.

        SECURITY: the email and api_token are used only within per-request
        Basic-auth headers and are never stored on the connector instance or in
        any returned record.

        The site and projects surfaces are required (auth/rate-limit errors
        propagate).  All remaining surfaces are optional and fail soft on
        403/404 (plan-gated or permission-gated).
        """
        site_url = str(credentials.get("site_url", "") or "").strip()
        email = str(credentials.get("email", "") or "").strip()
        api_token = str(credentials.get("api_token", "") or "").strip()
        if not site_url or not email or not api_token:
            raise AuthenticationError(
                "Jira credentials missing — site_url, email, and api_token are required."
            )
        site_url = self._sanitize_site_url(site_url)

        records: list[dict] = []

        # Required surfaces — propagate auth/rate-limit errors.
        site_records = self._fetch_site(site_url, email, api_token)
        records.extend(site_records)
        project_records = self._fetch_projects(site_url, email, api_token)
        records.extend(project_records)

        # Optional surfaces — each fetcher fails soft on 403/404.
        records.extend(self._fetch_boards(site_url, email, api_token))
        records.extend(self._fetch_workflows(site_url, email, api_token))
        records.extend(self._fetch_workflow_schemes(site_url, email, api_token))
        records.extend(self._fetch_permission_schemes(site_url, email, api_token))
        records.extend(self._fetch_notification_schemes(site_url, email, api_token))
        records.extend(self._fetch_issue_type_schemes(site_url, email, api_token))
        records.extend(
            self._fetch_field_configuration_schemes(site_url, email, api_token)
        )
        records.extend(self._fetch_screen_schemes(site_url, email, api_token))
        webhook_records = self._fetch_webhooks(site_url, email, api_token)
        records.extend(webhook_records)
        automation_records = self._fetch_automation_rules(site_url, email, api_token)
        records.extend(automation_records)

        # Backfill the site-level rollup counts now that the project, webhook,
        # and automation surfaces have been snapshotted.  These feed the M86B
        # site rules (jira_site_no_projects / _no_webhooks / _no_automation_rules).
        # Only counts are stored — never any identity, key, or URL value.
        if site_records:
            site_records[0]["project_count"] = len(project_records)
            site_records[0]["webhook_count"] = len(webhook_records)
            site_records[0]["automation_rule_count"] = len(automation_records)

        return records

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate Jira credentials with a minimal GET /myself call.

        Returns True on a 200 response.  Returns False on auth failure rather
        than raising, so the caller can surface a clean error message.

        SECURITY: the account email and accountId from the /myself response are
        never read into a return value or logged.
        """
        site_url = str(credentials.get("site_url", "") or "").strip()
        email = str(credentials.get("email", "") or "").strip()
        api_token = str(credentials.get("api_token", "") or "").strip()
        if not site_url or not email or not api_token:
            return False
        try:
            site_url = self._sanitize_site_url(site_url)
        except AuthenticationError:
            return False

        url = f"https://{site_url}/{_API_V3}/myself"
        try:
            with httpx.Client(timeout=_TIMEOUT, follow_redirects=False) as client:
                try:
                    response = client.get(
                        url,
                        auth=(email, api_token),
                        headers={"Accept": "application/json"},
                    )
                except httpx.TransportError:
                    return False
            return response.status_code == 200
        except Exception:  # noqa: BLE001 — validation must never raise
            return False
