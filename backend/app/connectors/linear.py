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
from app.connectors.linear_schema import (
    LINEAR_CYCLE,
    LINEAR_INTEGRATION,
    LINEAR_LABEL,
    LINEAR_PROJECT,
    LINEAR_RECORD_TYPES,
    LINEAR_TEAM,
    LINEAR_VIEW,
    LINEAR_WEBHOOK,
    LINEAR_WORKFLOW_STATE,
    LINEAR_WORKSPACE,
)

logger = logging.getLogger(__name__)

GRAPHQL_URL = "https://api.linear.app/graphql"
_TIMEOUT = 30.0
_MAX_STR_LEN = 100

# ── Module-level helpers ──────────────────────────────────────────────────────


def _trunc(value: Any, length: int = _MAX_STR_LEN) -> str:
    """Return str(value) truncated to length, or '' for None/falsy."""
    if value is None:
        return ""
    return str(value)[:length]


def _bool(value: Any, default: bool = False) -> bool:
    """Coerce value to bool safely."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return bool(value)


def _int(value: Any, default: int = 0) -> int:
    """Coerce value to non-negative int, excluding booleans."""
    if isinstance(value, bool):
        return default
    try:
        result = int(value)
        return max(0, result)
    except (TypeError, ValueError):
        return default


def _sanitize_api_key(key: Any) -> str:
    """Validate and return the API key string, raising AuthenticationError if invalid."""
    if not key or not isinstance(key, str) or not key.strip():
        raise AuthenticationError(
            "Linear API key is missing or empty — check the integration credentials."
        )
    return key.strip()


def _member_count_category(count: Any) -> str:
    """Categorize a member count into a bucketed string."""
    n = _int(count, 0)
    if n == 0:
        return "none"
    if n <= 5:
        return "small"
    if n <= 20:
        return "medium"
    return "large"


def _issue_count_category(count: Any) -> str:
    """Categorize an issue count into a bucketed string."""
    n = _int(count, 0)
    if n == 0:
        return "none"
    if n <= 10:
        return "few"
    if n <= 50:
        return "moderate"
    return "many"


def _cycle_duration_category(duration: Any) -> str:
    """Categorize a cycle duration (days) into a bucketed string."""
    if duration is None:
        return "none"
    d = _int(duration, 0)
    if d == 0:
        return "none"
    if d <= 7:
        return "short"
    if d <= 14:
        return "medium"
    return "long"


def _filter_count_category(filters: Any) -> str:
    """Categorize view filter count into a bucketed string."""
    if not filters:
        return "none"
    if isinstance(filters, dict):
        count = len(filters)
    elif isinstance(filters, list):
        count = len(filters)
    else:
        return "none"
    if count == 0:
        return "none"
    if count <= 3:
        return "few"
    if count <= 10:
        return "moderate"
    return "many"


def _url_scheme_category(url: Any) -> str:
    """Return 'https', 'non_https', or 'absent' — never store the URL value."""
    if not url or not isinstance(url, str):
        return "absent"
    if url.startswith("https"):
        return "https"
    return "non_https"


# ── Connector ─────────────────────────────────────────────────────────────────


class LinearConnector(BaseConnector):
    """ConfigTrace connector for Linear project-management configuration (M85A).

    SECURITY: The API key is NEVER stored on self.  It is passed into
    _query() at call time only and is not logged, not written to any record,
    and not returned in any API response.

    Surfaces fetched (safe configuration metadata only):
      linear_workspace, linear_team, linear_project, linear_workflow_state,
      linear_label, linear_webhook, linear_view, linear_cycle,
      linear_integration

    NEVER fetched or stored: issue titles/descriptions, comment bodies,
    attachment content, user emails, user names, member identities, raw
    webhook URLs, webhook secrets, OAuth tokens, raw API keys, request or
    response payloads, IP addresses, or any PII.
    """

    def __init__(self) -> None:  # noqa: D107 — explicit no-credential init
        pass

    # ── Low-level GraphQL transport ───────────────────────────────────────────

    def _query(
        self,
        api_key: str,
        query_str: str,
        variables: Optional[dict] = None,
    ) -> dict:
        """Execute a GraphQL POST and return the parsed response dict.

        Raises:
            AuthenticationError: 401 response.
            ConnectorError: 403, 4xx client errors, or GraphQL errors.
            RateLimitError: 429 response.
            NetworkError: transport-level failure.
        """
        payload: dict[str, Any] = {"query": query_str}
        if variables:
            payload["variables"] = variables

        try:
            with httpx.Client(timeout=_TIMEOUT, follow_redirects=False) as client:
                response = client.post(
                    GRAPHQL_URL,
                    json=payload,
                    headers={
                        "Authorization": api_key,
                        "Content-Type": "application/json",
                    },
                )
        except httpx.TransportError as exc:
            raise NetworkError(
                f"Linear network error: {type(exc).__name__}"
            ) from exc

        self._raise_for_status(response)

        data = response.json()
        if "errors" in data:
            # GraphQL-layer errors (e.g. permission denied on a specific field)
            messages = "; ".join(
                e.get("message", "unknown") for e in data["errors"]
            )
            raise ConnectorError(f"Linear GraphQL error: {messages}")

        return data.get("data", {})

    def _raise_for_status(self, response: httpx.Response) -> None:
        """Map HTTP status codes to typed exceptions."""
        code = response.status_code
        if code in (200, 201, 204):
            return
        if code == 401:
            raise AuthenticationError(
                "Linear authentication failed — check the API key."
            )
        if code == 403:
            raise ConnectorError(
                f"Linear permission denied (403) for {response.url.path!r}."
            )
        if code == 429:
            raise RateLimitError("Linear rate limit exceeded (429).")
        if code >= 500:
            raise ConnectorError(
                f"Linear server error ({code}) for {response.url.path!r}."
            )
        if code >= 400:
            raise ConnectorError(
                f"Linear client error ({code}) for {response.url.path!r}."
            )

    # ── Surface fetchers ──────────────────────────────────────────────────────

    def _fetch_workspace(self, api_key: str) -> list[dict]:
        """Fetch workspace (organization) configuration."""
        query = """
        query {
          organization {
            id
            name
            urlKey
            logoUrl
            teams(first: 1) { totalCount }
          }
        }
        """
        data = self._query(api_key, query)
        org = data.get("organization")
        if not org:
            return []
        return [self._normalize_workspace(org)]

    def _normalize_workspace(self, raw: dict) -> dict:
        rid = _trunc(raw.get("id", ""), 64) or "unknown"
        name = _trunc(raw.get("name", ""), _MAX_STR_LEN)
        # M85C: team count from organization (safe integer only — never store names/IDs)
        teams_data = raw.get("teams")
        team_count: Optional[int] = (
            _int((teams_data or {}).get("totalCount", 0))
            if teams_data is not None
            else None
        )
        return {
            "record_type": LINEAR_WORKSPACE,
            "provider": "linear",
            "record_id": rid,
            "resource_id": rid,
            "resource_name": name,
            "url_key_present": _bool(raw.get("urlKey")),
            "logo_present": _bool(raw.get("logoUrl")),
            # M85C: webhook_count/integration_count enriched in fetch()
            "team_count": team_count,
            "webhook_count": None,
            "integration_count": None,
        }

    def _fetch_teams(self, api_key: str) -> list[dict]:
        """Fetch team configuration records."""
        query = """
        query {
          teams(first: 100) {
            nodes {
              id
              name
              private
              members(first: 1) { totalCount }
              projects(first: 1) { totalCount }
              autoArchivePeriod
              cyclesEnabled
              cycleDuration
              states(first: 50) { nodes { type } }
              labels(first: 1) { totalCount }
              webhooks(first: 1) { totalCount }
            }
          }
        }
        """
        data = self._query(api_key, query)
        nodes = (data.get("teams") or {}).get("nodes", [])
        return [self._normalize_team(n) for n in nodes]

    def _normalize_team(self, raw: dict) -> dict:
        rid = _trunc(raw.get("id", ""), 64) or "unknown"
        name = _trunc(raw.get("name", ""), _MAX_STR_LEN)
        is_private = _bool(raw.get("private"))
        member_count = _int((raw.get("members") or {}).get("totalCount", 0))
        project_count = _int((raw.get("projects") or {}).get("totalCount", 0))
        auto_archive = raw.get("autoArchivePeriod")
        cycles_enabled = _bool(raw.get("cyclesEnabled"))
        cycle_duration = raw.get("cycleDuration")

        # M85C: workflow state coverage from team.states sub-query.
        # SECURITY: only state type strings (enum labels) are used — never state names/descriptions.
        states_data = raw.get("states")
        if states_data is not None:
            states_nodes = states_data.get("nodes", [])
            state_types = {
                (s.get("type") or "").lower()
                for s in states_nodes
                if isinstance(s, dict)
            }
            workflow_state_count: Optional[int] = len(states_nodes)
            has_backlog_state: Optional[bool] = "backlog" in state_types
            has_started_state: Optional[bool] = "started" in state_types
            has_completed_state: Optional[bool] = "completed" in state_types
            # Linear uses British "cancelled" in the enum
            has_canceled_state: Optional[bool] = "cancelled" in state_types
        else:
            workflow_state_count = None
            has_backlog_state = None
            has_started_state = None
            has_completed_state = None
            has_canceled_state = None

        # M85C: label and webhook counts (safe integers only)
        labels_data = raw.get("labels")
        label_count: Optional[int] = (
            _int((labels_data or {}).get("totalCount", 0))
            if labels_data is not None
            else None
        )
        webhooks_data = raw.get("webhooks")
        team_webhook_count: Optional[int] = (
            _int((webhooks_data or {}).get("totalCount", 0))
            if webhooks_data is not None
            else None
        )

        return {
            "record_type": LINEAR_TEAM,
            "provider": "linear",
            "record_id": rid,
            "resource_id": rid,
            "resource_name": name,
            "private_team": is_private,
            "team_visibility_category": "private" if is_private else "public",
            "member_count_category": _member_count_category(member_count),
            "project_count": project_count,
            "auto_archive_enabled": auto_archive is not None,
            "cycle_enabled": cycles_enabled,
            "cycle_duration_category": _cycle_duration_category(cycle_duration),
            # M85C workflow state coverage
            "workflow_state_count": workflow_state_count,
            "has_backlog_state": has_backlog_state,
            "has_started_state": has_started_state,
            "has_completed_state": has_completed_state,
            "has_canceled_state": has_canceled_state,
            "label_count": label_count,
            "webhook_count": team_webhook_count,
        }

    def _fetch_projects(self, api_key: str) -> list[dict]:
        """Fetch project configuration records."""
        query = """
        query {
          projects(first: 100) {
            nodes {
              id
              name
              state { name }
              health
              lead { id }
              members(first: 1) { totalCount }
              issues(first: 1) { totalCount }
              teams { nodes { id } }
            }
          }
        }
        """
        data = self._query(api_key, query)
        nodes = (data.get("projects") or {}).get("nodes", [])
        return [self._normalize_project(n) for n in nodes]

    def _normalize_project(self, raw: dict) -> dict:
        rid = _trunc(raw.get("id", ""), 64) or "unknown"
        name = _trunc(raw.get("name", ""), _MAX_STR_LEN)
        state_name = ((raw.get("state") or {}).get("name") or "unknown").lower()
        health = (raw.get("health") or "unknown").lower()
        lead_present = _bool(raw.get("lead"))
        member_count = _int((raw.get("members") or {}).get("totalCount", 0))
        issue_count = _int((raw.get("issues") or {}).get("totalCount", 0))
        # M85C: team association count (integer only — team IDs and names never stored)
        team_nodes = (raw.get("teams") or {}).get("nodes", [])
        team_count = len(team_nodes) if isinstance(team_nodes, list) else 0
        return {
            "record_type": LINEAR_PROJECT,
            "provider": "linear",
            "record_id": rid,
            "resource_id": rid,
            "resource_name": name,
            "project_status_category": state_name,
            "project_health_category": health,
            "lead_present": lead_present,
            "member_count_category": _member_count_category(member_count),
            "issue_count_category": _issue_count_category(issue_count),
            "team_count": team_count,
        }

    def _fetch_workflow_states(self, api_key: str) -> list[dict]:
        """Fetch workflow state configuration records."""
        query = """
        query {
          workflowStates(first: 200) {
            nodes {
              id
              name
              type
              position
              team { id }
            }
          }
        }
        """
        data = self._query(api_key, query)
        nodes = (data.get("workflowStates") or {}).get("nodes", [])
        return [self._normalize_workflow_state(n) for n in nodes]

    def _normalize_workflow_state(self, raw: dict) -> dict:
        rid = _trunc(raw.get("id", ""), 64) or "unknown"
        name = _trunc(raw.get("name", ""), _MAX_STR_LEN)
        state_type = (raw.get("type") or "unknown").lower()
        position = _int(raw.get("position"), 0)
        team_id = _trunc((raw.get("team") or {}).get("id", ""), 64) or None
        if position < 33:
            position_category = "early"
        elif position < 67:
            position_category = "middle"
        else:
            position_category = "late"
        return {
            "record_type": LINEAR_WORKFLOW_STATE,
            "provider": "linear",
            "record_id": rid,
            "resource_id": rid,
            "resource_name": name,
            "state_type_category": state_type,
            "position_category": position_category,
            "team_id": team_id,
        }

    def _fetch_labels(self, api_key: str) -> list[dict]:
        """Fetch issue label configuration records."""
        query = """
        query {
          issueLabels(first: 200) {
            nodes {
              id
              name
              isGroup
              parent { id }
              team { id }
            }
          }
        }
        """
        data = self._query(api_key, query)
        nodes = (data.get("issueLabels") or {}).get("nodes", [])
        return [self._normalize_label(n) for n in nodes]

    def _normalize_label(self, raw: dict) -> dict:
        rid = _trunc(raw.get("id", ""), 64) or "unknown"
        name = _trunc(raw.get("name", ""), _MAX_STR_LEN)
        is_group = _bool(raw.get("isGroup"))
        parent_id_present = _bool(raw.get("parent"))
        team_id = _trunc((raw.get("team") or {}).get("id", ""), 64) or None
        return {
            "record_type": LINEAR_LABEL,
            "provider": "linear",
            "record_id": rid,
            "resource_id": rid,
            "resource_name": name,
            "is_group_label": is_group,
            "parent_id_present": parent_id_present,
            "team_id": team_id,
        }

    def _fetch_webhooks(self, api_key: str) -> list[dict]:
        """Fetch webhook subscription records.

        SECURITY: The url and secret fields are used ONLY for safe boolean/
        category derivation. Their values are NEVER stored in any record.
        """
        query = """
        query {
          webhooks(first: 100) {
            nodes {
              id
              resourceTypes
              enabled
              secret
              url
              team { id }
            }
          }
        }
        """
        data = self._query(api_key, query)
        nodes = (data.get("webhooks") or {}).get("nodes", [])
        return [self._normalize_webhook(n) for n in nodes]

    def _normalize_webhook(self, raw: dict) -> dict:
        rid = _trunc(raw.get("id", ""), 64) or "unknown"
        resource_types = raw.get("resourceTypes") or []
        enabled = _bool(raw.get("enabled"))
        secret = raw.get("secret")
        url = raw.get("url")
        team_id = _trunc((raw.get("team") or {}).get("id", ""), 64) or None
        # SECURITY: url and secret values are discarded after these safe derivations.
        url_scheme_cat = _url_scheme_category(url)
        url_present = bool(url)
        secret_present = bool(secret)
        del secret
        del url
        # M85C: derive sensitive resource-type presence booleans before discarding the list.
        # SECURITY: only boolean presence indicators are stored — the raw type name strings
        # are never written to any record or log.
        if isinstance(resource_types, (list, tuple)):
            types_lower = {rt.lower() for rt in resource_types if isinstance(rt, str)}
            rt_count = len(resource_types)
        else:
            types_lower = set()
            rt_count = 0
        has_comment_type = "comment" in types_lower
        has_attachment_type = "attachment" in types_lower
        return {
            "record_type": LINEAR_WEBHOOK,
            "provider": "linear",
            "record_id": rid,
            "resource_id": rid,
            "webhook_resource_types_count": rt_count,
            "webhook_enabled": enabled,
            "webhook_secret_present": secret_present,
            "webhook_url_present": url_present,
            "webhook_url_scheme_category": url_scheme_cat,
            "team_id": team_id,
            "webhook_has_comment_type": has_comment_type,
            "webhook_has_attachment_type": has_attachment_type,
        }

    def _fetch_views(self, api_key: str) -> list[dict]:
        """Fetch custom view configuration records."""
        query = """
        query {
          customViews(first: 100) {
            nodes {
              id
              name
              shared
              filters
              team { id }
            }
          }
        }
        """
        data = self._query(api_key, query)
        nodes = (data.get("customViews") or {}).get("nodes", [])
        return [self._normalize_view(n) for n in nodes]

    def _normalize_view(self, raw: dict) -> dict:
        rid = _trunc(raw.get("id", ""), 64) or "unknown"
        name = _trunc(raw.get("name", ""), _MAX_STR_LEN)
        shared = _bool(raw.get("shared"))
        filters = raw.get("filters")
        team_id = _trunc((raw.get("team") or {}).get("id", ""), 64) or None
        return {
            "record_type": LINEAR_VIEW,
            "provider": "linear",
            "record_id": rid,
            "resource_id": rid,
            "resource_name": name,
            "view_shared": shared,
            "filter_count_category": _filter_count_category(filters),
            "team_id": team_id,
        }

    def _fetch_cycles(self, api_key: str) -> list[dict]:
        """Fetch active cycle configuration records."""
        query = """
        query {
          cycles(first: 100, filter: { isActive: { eq: true } }) {
            nodes {
              id
              name
              team { id }
              issues(first: 1) { totalCount }
            }
          }
        }
        """
        data = self._query(api_key, query)
        nodes = (data.get("cycles") or {}).get("nodes", [])
        return [self._normalize_cycle(n) for n in nodes]

    def _normalize_cycle(self, raw: dict) -> dict:
        rid = _trunc(raw.get("id", ""), 64) or "unknown"
        raw_name = raw.get("name")
        name = _trunc(raw_name, _MAX_STR_LEN) if raw_name else rid[:20]
        team_id = _trunc((raw.get("team") or {}).get("id", ""), 64) or None
        issue_count = _int((raw.get("issues") or {}).get("totalCount", 0))
        return {
            "record_type": LINEAR_CYCLE,
            "provider": "linear",
            "record_id": rid,
            "resource_id": rid,
            "resource_name": name,
            "active": True,
            "team_id": team_id,
            "issue_count_category": _issue_count_category(issue_count),
        }

    def _fetch_integrations(self, api_key: str) -> list[dict]:
        """Fetch integration configuration records (fail-soft: returns [] on error).

        The integrations query may not be available on all Linear plans or
        API key scopes — a ConnectorError (including 403) returns [] silently.
        """
        query = """
        query {
          integrations(first: 100) {
            nodes {
              id
              service
              enabled
              team { id }
            }
          }
        }
        """
        try:
            data = self._query(api_key, query)
        except (ConnectorError, NetworkError, RateLimitError):
            logger.debug("linear: integrations query unavailable, skipping")
            return []
        nodes = (data.get("integrations") or {}).get("nodes", [])
        return [self._normalize_integration(n) for n in nodes]

    def _normalize_integration(self, raw: dict) -> dict:
        rid = _trunc(raw.get("id", ""), 64) or "unknown"
        service = (raw.get("service") or "unknown")[:50]
        enabled = _bool(raw.get("enabled"))
        team_id = _trunc((raw.get("team") or {}).get("id", ""), 64) or None
        return {
            "record_type": LINEAR_INTEGRATION,
            "provider": "linear",
            "record_id": rid,
            "resource_id": rid,
            "integration_type_category": service,
            "integration_enabled": enabled,
            "team_id": team_id,
        }

    # ── Public interface ──────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all Linear configuration surfaces and return a flat record list.

        SECURITY: credentials['api_key'] is validated here and passed to
        _query() only at call time.  It is NEVER stored on self, NEVER
        copied into any record, and NEVER logged.
        """
        api_key = _sanitize_api_key(credentials.get("api_key", ""))

        records: list[dict] = []
        workspace_records = self._fetch_workspace(api_key)
        records.extend(workspace_records)
        records.extend(self._fetch_teams(api_key))
        records.extend(self._fetch_projects(api_key))
        records.extend(self._fetch_workflow_states(api_key))
        records.extend(self._fetch_labels(api_key))

        webhooks = self._fetch_webhooks(api_key)
        records.extend(webhooks)
        records.extend(self._fetch_views(api_key))
        records.extend(self._fetch_cycles(api_key))

        integrations = self._fetch_integrations(api_key)
        records.extend(integrations)

        # M85C: Enrich workspace record with aggregate surface counts.
        # webhook_count = total workspace-level webhooks fetched.
        # integration_count = total integrations visible to this API key.
        if workspace_records:
            ws = workspace_records[0]
            ws["webhook_count"] = len(webhooks)
            ws["integration_count"] = len(integrations)

        return records

    def validate_credentials(self, credentials: dict) -> bool:
        """Return True if the API key can reach the Linear GraphQL endpoint."""
        try:
            api_key = _sanitize_api_key(credentials.get("api_key", ""))
        except AuthenticationError:
            return False
        query = "query { viewer { id } }"
        try:
            self._query(api_key, query)
            return True
        except AuthenticationError:
            return False
        except Exception:
            return False
