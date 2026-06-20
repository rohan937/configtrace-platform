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
        }

    def _normalize_board(self, raw: dict) -> dict:
        """Normalise one Agile board to a safe flat record.

        SECURITY: board name and the project/filter it is scoped to are never
        stored beyond a location-presence boolean.
        """
        bid = _trunc(raw.get("id", ""), 64) or "unknown"
        type_raw = _trunc(raw.get("type", ""), 32).lower()
        if type_raw in ("scrum", "kanban", "simple"):
            board_type = type_raw
        else:
            board_type = "unknown"
        return {
            "record_type": JIRA_BOARD,
            "provider": "jira",
            "record_id": bid,
            "resource_id": bid,
            "board_type": board_type,
            "location_present": bool(raw.get("location")),
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
        return {
            "record_type": JIRA_WORKFLOW,
            "provider": "jira",
            "record_id": wf_id,
            "resource_id": wf_id,
            "is_default": _bool(raw.get("isDefault")),
            "transition_count": _int(_count(transitions)),
            "status_count": _int(_count(statuses)),
            "has_description": bool(raw.get("description")),
        }

    def _normalize_workflow_scheme(self, raw: dict) -> dict:
        """Normalise one workflow scheme to a safe flat record.

        SECURITY: scheme name/description and the named workflow/issue-type
        mappings are never stored — only mapping counts.
        """
        sid = _trunc(raw.get("id", ""), 64) or "unknown"
        mapping = raw.get("issueTypeMappings")
        return {
            "record_type": JIRA_WORKFLOW_SCHEME,
            "provider": "jira",
            "record_id": sid,
            "resource_id": sid,
            "is_default": _bool(raw.get("defaultWorkflow") is not None
                                or raw.get("default")),
            "issue_type_mapping_count": _int(_count(mapping)),
            "has_draft": _bool(raw.get("draft")),
            "has_description": bool(raw.get("description")),
        }

    def _normalize_permission_scheme(self, raw: dict) -> dict:
        """Normalise one permission scheme to a safe flat record.

        SECURITY: grant holder identities (users, groups, roles), scheme
        name, and description are never stored — only grant counts.
        """
        sid = _trunc(raw.get("id", ""), 64) or "unknown"
        permissions = raw.get("permissions")
        return {
            "record_type": JIRA_PERMISSION_SCHEME,
            "provider": "jira",
            "record_id": sid,
            "resource_id": sid,
            "permission_grant_count": _int(_count(permissions)),
            "has_description": bool(raw.get("description")),
        }

    def _normalize_notification_scheme(self, raw: dict) -> dict:
        """Normalise one notification scheme to a safe flat record.

        SECURITY: recipient identities (users, groups, emails), scheme name,
        and description are never stored — only event/notification counts.
        """
        sid = _trunc(raw.get("id", ""), 64) or "unknown"
        events = raw.get("notificationSchemeEvents")
        notification_count = 0
        if isinstance(events, list):
            for ev in events:
                if isinstance(ev, dict):
                    notification_count += _count(ev.get("notifications"))
        return {
            "record_type": JIRA_NOTIFICATION_SCHEME,
            "provider": "jira",
            "record_id": sid,
            "resource_id": sid,
            "event_count": _int(_count(events)),
            "notification_count": _int(notification_count),
            "has_description": bool(raw.get("description")),
        }

    def _normalize_issue_type_scheme(self, raw: dict) -> dict:
        """Normalise one issue type scheme to a safe flat record.

        SECURITY: scheme name and description are never stored — only the
        default-issue-type presence and a bucketed posture.
        """
        sid = _trunc(raw.get("id", ""), 64) or "unknown"
        return {
            "record_type": JIRA_ISSUE_TYPE_SCHEME,
            "provider": "jira",
            "record_id": sid,
            "resource_id": sid,
            "is_default": _bool(raw.get("isDefault")),
            "has_default_issue_type": bool(raw.get("defaultIssueTypeId")),
            "has_description": bool(raw.get("description")),
        }

    def _normalize_field_configuration_scheme(self, raw: dict) -> dict:
        """Normalise one field configuration scheme to a safe flat record.

        SECURITY: scheme name and description are never stored.
        """
        sid = _trunc(raw.get("id", ""), 64) or "unknown"
        return {
            "record_type": JIRA_FIELD_CONFIGURATION_SCHEME,
            "provider": "jira",
            "record_id": sid,
            "resource_id": sid,
            "has_description": bool(raw.get("description")),
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
        return {
            "record_type": JIRA_SCREEN_SCHEME,
            "provider": "jira",
            "record_id": sid,
            "resource_id": sid,
            "screen_mapping_count": _int(_count(screens)),
            "has_default_screen": has_default,
            "has_description": bool(raw.get("description")),
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
        return {
            "record_type": JIRA_WEBHOOK,
            "provider": "jira",
            "record_id": wid,
            "resource_id": wid,
            "enabled": _bool(raw.get("enabled"), default=True),
            "event_count": _int(_count(events)),
            "webhook_url_present": bool(url),
            "webhook_url_scheme_category": _url_scheme_category(url),
            "has_filter": bool(raw.get("filters") or raw.get("jqlFilter")),
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
        return {
            "record_type": JIRA_AUTOMATION_RULE,
            "provider": "jira",
            "record_id": rid,
            "resource_id": rid,
            "enabled": _bool(raw.get("enabled"), default=(state == "enabled")),
            "state": state,
            "component_count": _int(_count(components)),
            "has_description": bool(raw.get("description")),
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
        records.extend(self._fetch_site(site_url, email, api_token))
        records.extend(self._fetch_projects(site_url, email, api_token))

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
        records.extend(self._fetch_webhooks(site_url, email, api_token))
        records.extend(self._fetch_automation_rules(site_url, email, api_token))

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
