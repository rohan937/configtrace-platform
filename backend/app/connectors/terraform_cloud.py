"""Terraform Cloud configuration drift connector (M88A).

Configuration snapshot connector for Terraform Cloud (and Terraform Enterprise).
Connects to the Terraform Cloud API v2 using a team or user API token and
snapshots safe organization and workspace configuration posture. All raw secrets,
variable values, state file contents, plan/apply logs, user identities, workspace
names, project names, VCS URLs, branch names, team names, and customer
infrastructure data are discarded before any record is returned.

Surfaces covered
─────────────────
  Organization        — workspace count, project count, policy/variable-set counts,
                        SSO, 2FA requirement, cost estimation; never org name
  Workspaces          — execution mode, auto-apply, VCS connection, variable counts,
                        notification/team-access counts; never workspace name or vars
  Projects            — workspace count, team access count; never project name
  Variable sets       — scope, counts (total/sensitive/non-sensitive/env/tf);
                        never variable names or values
  Workspace variables — count summaries only; never variable names or values
  Policy sets         — scope, policy count, enforcement level; never policy code
  Notifications       — enabled, destination type, trigger count, URL scheme;
                        never URL, token, or email recipients
  Team access summary — access-level counts per workspace; never team names
  Run triggers        — trigger count per workspace, sourceable type category;
                        never source workspace name or run IDs
  State version summary — presence and count category only; raw state NEVER fetched

Credentials dict expected by fetch() and validate_credentials():
  {
    "api_token":       "<Terraform Cloud team or user API token>",
    "organization":    "<organization name slug — used as API path, not stored>",
    "base_url":        "<optional, default https://app.terraform.io>"
  }

SECURITY:
  The api_token is used ONLY in the Authorization: Bearer header.
  It is NEVER stored on the connector instance, NEVER copied into any
  normalised record, and NEVER logged.

  Organization names, workspace names, project names, variable set names,
  variable names, variable values, HCL variable content, VCS repository URLs,
  VCS branch names, commit SHAs, team names, user emails, usernames,
  state file JSON, plan output, apply logs, cost-estimation data, resource
  addresses, resource attribute values, provider credentials, and customer
  infrastructure data are NEVER fetched or stored in normalised records.

  Raw API responses are processed immediately and discarded. Only flat safe
  scalars (opaque IDs, booleans, counts, category strings) are returned.

  State file endpoints are NEVER called. The ``/state-versions``,
  ``/state-version-outputs``, ``/plans``, ``/applies``, and ``/runs``
  (other than to count/categorize current run status from workspace attributes)
  endpoints are NOT called.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Optional
from urllib.parse import urlparse

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
_PAGE_SIZE = 100
_MAX_WORKSPACES = 300
_MAX_PROJECTS = 100
_MAX_VARIABLE_SETS = 100
_MAX_POLICY_SETS = 100
_DEFAULT_BASE_URL = "https://app.terraform.io"

PROVIDER = "terraform_cloud"


# ── Module-level helpers ──────────────────────────────────────────────────────


def _opaque_id(value: Any) -> str:
    """Return a sha256-based opaque identifier for a raw value."""
    raw = str(value) if value is not None else ""
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _bool(value: Any, default: bool = False) -> bool:
    """Coerce a raw API value to bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes")
    if isinstance(value, int):
        return bool(value)
    return default


def _int(value: Any, default: int = 0) -> int:
    """Coerce a raw API value to int."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _count(lst: Any) -> int:
    """Return len(lst) for lists; 0 for None or non-list."""
    if isinstance(lst, list):
        return len(lst)
    return 0


def _normalize_base_url(base_url: Optional[str]) -> str:
    """Normalize the Terraform API base URL — strip trailing slash."""
    if not base_url:
        return _DEFAULT_BASE_URL
    url = base_url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _attr(item: dict, key: str) -> Any:
    """Get an attribute from a JSON:API item's attributes dict."""
    return (item.get("attributes") or {}).get(key)


def _execution_mode_category(raw: Any) -> str:
    """Map raw execution-mode to a safe category."""
    if not isinstance(raw, str):
        return "unknown"
    m = raw.lower().strip()
    if m in ("remote", "local", "agent"):
        return m
    return "unknown"


def _terraform_version_category(raw: Any) -> str:
    """Map raw terraform-version to a safe category (pinned/latest/unknown)."""
    if not isinstance(raw, str) or not raw:
        return "unknown"
    v = raw.strip().lower()
    if v == "latest":
        return "latest"
    if v and v[0].isdigit():
        return "pinned"
    return "unknown"


def _team_count_category(count: Any) -> str:
    """Map raw team count to a safe size category."""
    try:
        n = int(count)
    except (TypeError, ValueError):
        return "unknown"
    if n == 0:
        return "empty"
    if n <= 5:
        return "small"
    if n <= 20:
        return "medium"
    return "large"


def _state_version_count_category(count: Any) -> str:
    """Map raw state version count to a safe size category."""
    try:
        n = int(count)
    except (TypeError, ValueError):
        return "unknown"
    if n == 0:
        return "none"
    if n <= 10:
        return "few"
    if n <= 100:
        return "moderate"
    return "many"


def _enforcement_level_category(raw: Any) -> str:
    """Map raw enforcement level to a safe category."""
    if not isinstance(raw, str):
        return "unknown"
    lvl = raw.lower().strip().replace("-", "_")
    if lvl in ("advisory", "soft_mandatory", "mandatory"):
        return lvl
    return "unknown"


def _destination_type_category(raw: Any) -> str:
    """Map raw notification destination type to a safe category."""
    if not isinstance(raw, str):
        return "unknown"
    dt = raw.lower().strip()
    if dt in ("slack", "email", "webhook", "microsoft_teams", "pagerduty",
              "microsoft-teams"):
        return dt.replace("-", "_")
    return "other"


def _run_status_category(raw: Any) -> Optional[str]:
    """Map raw run status to a safe review category."""
    if not isinstance(raw, str):
        return None
    s = raw.lower().strip().replace("-", "_")
    # Group into broad safe categories — never a specific resource address
    safe = {
        "applied": "applied",
        "planned": "planned",
        "planned_and_finished": "planned_and_finished",
        "apply_queued": "queued",
        "plan_queued": "queued",
        "planning": "in_progress",
        "applying": "in_progress",
        "errored": "errored",
        "canceled": "canceled",
        "discarded": "discarded",
        "policy_checked": "policy_checked",
        "policy_override": "policy_override",
        "pending": "pending",
        "fetching": "in_progress",
        "cost_estimating": "in_progress",
        "cost_estimated": "in_progress",
    }
    return safe.get(s, "other")


def _url_scheme(url: Any) -> Optional[str]:
    """Extract URL scheme safely without storing the URL."""
    if not isinstance(url, str) or not url:
        return None
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        return scheme if scheme in ("http", "https") else "other"
    except Exception:
        return None


def _collaborator_auth_policy_category(raw: Any) -> Optional[str]:
    """Map raw collaborator-auth-policy to a safe category."""
    if not isinstance(raw, str):
        return None
    p = raw.lower().strip()
    if p in ("password", "two_factor_mandatory"):
        return p
    return "other"


# ── Connector class ───────────────────────────────────────────────────────────


class TerraformCloudConnector(BaseConnector):
    """Terraform Cloud organization and workspace configuration drift connector.

    Uses a Terraform Cloud API token (team or user) for authentication.
    SECURITY: Token never stored on instance, never logged, never in records.
    """

    def __init__(self) -> None:
        pass  # No credentials stored on the instance.

    # ── Low-level transport ───────────────────────────────────────────────────

    def _request(
        self,
        base_url: str,
        token: str,
        path: str,
        params: Optional[dict] = None,
    ) -> Any:
        """Make a single authenticated GET request. Returns parsed JSON."""
        url = f"{base_url}/api/v2/{path.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/vnd.api+json",
        }
        try:
            response = httpx.get(
                url,
                headers=headers,
                params=params,
                timeout=_TIMEOUT,
                follow_redirects=True,
            )
            self._raise_for_status(response, path)
            return response.json()
        except (AuthenticationError, ConnectorError, RateLimitError):
            raise
        except httpx.TimeoutException as exc:
            raise NetworkError(
                f"Terraform Cloud request timed out: {path}"
            ) from exc
        except httpx.RequestError as exc:
            raise NetworkError(
                f"Terraform Cloud network error: {path}: {exc}"
            ) from exc

    def _raise_for_status(self, response: httpx.Response, surface: str) -> None:
        """Raise a typed exception for non-2xx responses."""
        code = response.status_code
        if code in (401, 403):
            raise AuthenticationError(
                f"Terraform Cloud authentication failed (HTTP {code}) on {surface}. "
                "Verify the API token has the required permissions."
            )
        if code == 429:
            raise RateLimitError(
                f"Terraform Cloud rate limit exceeded on {surface}."
            )
        if code >= 500:
            raise ConnectorError(
                f"Terraform Cloud server error (HTTP {code}) on {surface}."
            )
        if code >= 400:
            raise ConnectorError(
                f"Terraform Cloud request failed (HTTP {code}) on {surface}."
            )

    def _paginate(
        self,
        base_url: str,
        token: str,
        path: str,
        extra_params: Optional[dict] = None,
        max_records: int = _MAX_WORKSPACES,
    ) -> list[dict]:
        """Fetch a paginated JSON:API list endpoint. Returns up to max_records items."""
        results: list[dict] = []
        page_num = 1
        while len(results) < max_records:
            params: dict = {"page[size]": str(_PAGE_SIZE), "page[number]": str(page_num)}
            if extra_params:
                params.update(extra_params)
            try:
                resp = self._request(base_url, token, path, params=params)
            except ConnectorError:
                break
            batch = resp.get("data") if isinstance(resp, dict) else None
            if not isinstance(batch, list) or not batch:
                break
            results.extend(batch)
            # Check for next page in JSON:API meta
            meta = resp.get("meta") or {}
            pagination = meta.get("pagination") or {}
            total_pages = pagination.get("total-pages") or pagination.get("totalPages")
            try:
                if total_pages is not None and page_num >= int(total_pages):
                    break
            except (TypeError, ValueError):
                pass
            if len(batch) < _PAGE_SIZE:
                break
            page_num += 1
        return results[:max_records]

    def _get_single(self, base_url: str, token: str, path: str) -> Optional[dict]:
        """Fetch a single JSON:API resource. Returns the data dict or None on error."""
        try:
            resp = self._request(base_url, token, path)
            data = resp.get("data") if isinstance(resp, dict) else None
            return data if isinstance(data, dict) else None
        except ConnectorError:
            return None

    def _fetch_fail_soft(
        self,
        base_url: str,
        token: str,
        path: str,
        max_records: int = 200,
    ) -> list[dict]:
        """Paginate with fail-soft: return empty list on error."""
        try:
            return self._paginate(base_url, token, path, max_records=max_records)
        except (ConnectorError, AuthenticationError, RateLimitError, NetworkError):
            return []

    # ── Normalizers ───────────────────────────────────────────────────────────

    def _normalize_organization(
        self,
        data: dict,
        org_resource_id: str,
    ) -> dict:
        """Normalize an organization data item into a safe record.

        NEVER stores: organization name, email, owner identity, billing info,
        raw plan tier, collaborator identities.
        """
        attrs = data.get("attributes") or {}

        # Workspace count may be in attributes or from relationships
        workspace_count = _int(attrs.get("workspace-count"), -1)
        project_count = _int(attrs.get("project-count"), -1)

        # Team count is not always exposed; use relationships if available
        rels = data.get("relationships") or {}
        teams_data = (rels.get("teams") or {}).get("data")
        team_count: Optional[int] = None
        if isinstance(teams_data, list):
            team_count = len(teams_data)

        resource_id = _opaque_id(f"terraform_cloud_organization:{org_resource_id}")

        return {
            "record_type": "terraform_cloud_organization",
            "provider": PROVIDER,
            "record_id": f"terraform_cloud_organization:{resource_id}",
            "resource_id": resource_id,
            "organization_resource_id": org_resource_id,
            "workspace_count": workspace_count if workspace_count >= 0 else None,
            "project_count": project_count if project_count >= 0 else None,
            "policy_set_count": None,   # filled in after policy-set fetch
            "variable_set_count": None,  # filled in after varset fetch
            "team_count_category": _team_count_category(team_count) if team_count is not None else None,
            "sso_enabled": _bool(attrs.get("sso-enabled")) if "sso-enabled" in attrs else None,
            "two_factor_requirement_enabled": (
                _bool(attrs.get("two-factor-conformant"))
                if "two-factor-conformant" in attrs
                else None
            ),
            "cost_estimation_enabled": (
                _bool(attrs.get("cost-estimation-enabled"))
                if "cost-estimation-enabled" in attrs
                else None
            ),
            "collaborator_auth_policy_category": _collaborator_auth_policy_category(
                attrs.get("collaborator-auth-policy")
            ),
        }

    def _normalize_workspace(
        self,
        item: dict,
        org_resource_id: str,
        variable_items: list[dict],
        notification_items: list[dict],
        team_access_items: list[dict],
        run_trigger_items: list[dict],
    ) -> dict:
        """Normalize a workspace JSON:API item into a safe record.

        NEVER stores: workspace name, description, working-directory path,
        trigger-prefix values, VCS repo name/URL, branch name, commit SHA,
        variable names, variable values, state file content, plan/apply logs.
        """
        ws_id = str(item.get("id") or "")
        workspace_resource_id = _opaque_id(ws_id)

        attrs = item.get("attributes") or {}

        # VCS connection presence — boolean only, never store URL/branch/repo
        vcs_repo = attrs.get("vcs-repo")
        vcs_connected = vcs_repo is not None and bool(vcs_repo)

        # Working directory — presence only, never the actual path
        working_dir = attrs.get("working-directory") or ""
        working_directory_present = bool(working_dir.strip())

        # Trigger prefixes — count only, never the prefix values
        trigger_prefixes = attrs.get("trigger-prefixes") or []
        trigger_prefix_count = _count(trigger_prefixes)

        # Variable counts from fetched variable items
        var_count = len(variable_items)
        sensitive_count = sum(1 for v in variable_items if _bool(_attr(v, "sensitive")))
        non_sensitive_count = var_count - sensitive_count
        env_count = sum(1 for v in variable_items if _attr(v, "category") == "env")
        tf_count = sum(1 for v in variable_items if _attr(v, "category") == "terraform")

        # Current run status — safe category only
        run_status = _run_status_category(attrs.get("latest-run-status"))

        # State version presence — from workspace attributes
        current_state = attrs.get("current-state-version") or {}
        state_present = bool(current_state) if isinstance(current_state, dict) else False

        resource_id = _opaque_id(f"terraform_cloud_workspace:{workspace_resource_id}")

        return {
            "record_type": "terraform_cloud_workspace",
            "provider": PROVIDER,
            "record_id": f"terraform_cloud_workspace:{resource_id}",
            "resource_id": resource_id,
            "workspace_resource_id": workspace_resource_id,
            "organization_resource_id": org_resource_id,
            "execution_mode_category": _execution_mode_category(attrs.get("execution-mode")),
            "terraform_version_category": _terraform_version_category(
                attrs.get("terraform-version")
            ),
            "auto_apply": _bool(attrs.get("auto-apply")),
            "file_triggers_enabled": _bool(attrs.get("file-triggers-enabled")),
            "queue_all_runs": _bool(attrs.get("queue-all-runs")),
            "speculative_enabled": _bool(attrs.get("speculative-enabled")),
            "global_remote_state": _bool(attrs.get("global-remote-state")),
            "vcs_connected": vcs_connected,
            "working_directory_present": working_directory_present,
            "trigger_prefix_count": trigger_prefix_count,
            "run_trigger_count": _count(run_trigger_items),
            "variable_count": var_count,
            "sensitive_variable_count": sensitive_count,
            "non_sensitive_variable_count": non_sensitive_count,
            "environment_variable_count": env_count,
            "terraform_variable_count": tf_count,
            "notification_count": _count(notification_items),
            "team_access_count": _count(team_access_items),
            "current_state_version_present": state_present,
            "latest_run_status_category": run_status,
        }

    def _normalize_workspace_variable_summary(
        self,
        workspace_resource_id: str,
        variable_items: list[dict],
    ) -> dict:
        """Normalize workspace variable counts into a safe summary record.

        NEVER stores: variable names, variable values, HCL content, descriptions.
        raw_value_never_read=True confirms no variable values were read.
        """
        var_count = len(variable_items)
        sensitive_count = sum(1 for v in variable_items if _bool(_attr(v, "sensitive")))
        non_sensitive_count = var_count - sensitive_count
        env_count = sum(1 for v in variable_items if _attr(v, "category") == "env")
        tf_count = sum(1 for v in variable_items if _attr(v, "category") == "terraform")
        unprotected_non_sensitive = sum(
            1 for v in variable_items
            if not _bool(_attr(v, "sensitive")) and _attr(v, "category") == "env"
        )

        resource_id = _opaque_id(
            f"terraform_cloud_workspace_variable_summary:{workspace_resource_id}"
        )
        return {
            "record_type": "terraform_cloud_workspace_variable_summary",
            "provider": PROVIDER,
            "record_id": f"terraform_cloud_workspace_variable_summary:{resource_id}",
            "resource_id": resource_id,
            "workspace_resource_id": workspace_resource_id,
            "variable_count": var_count,
            "sensitive_variable_count": sensitive_count,
            "non_sensitive_variable_count": non_sensitive_count,
            "environment_variable_count": env_count,
            "terraform_variable_count": tf_count,
            "unprotected_non_sensitive_count": unprotected_non_sensitive,
            "raw_value_never_read": True,
        }

    def _normalize_project(
        self,
        item: dict,
        org_resource_id: str,
    ) -> dict:
        """Normalize a project item. NEVER stores project name."""
        proj_id = str(item.get("id") or "")
        project_resource_id = _opaque_id(proj_id)
        attrs = item.get("attributes") or {}

        resource_id = _opaque_id(f"terraform_cloud_project:{project_resource_id}")
        return {
            "record_type": "terraform_cloud_project",
            "provider": PROVIDER,
            "record_id": f"terraform_cloud_project:{resource_id}",
            "resource_id": resource_id,
            "project_resource_id": project_resource_id,
            "organization_resource_id": org_resource_id,
            "workspace_count": _int(attrs.get("workspace-count"), -1) or None,
            "team_access_count": None,  # requires additional call, skip in M88A
        }

    def _normalize_variable_set(
        self,
        item: dict,
        org_resource_id: str,
        var_items: list[dict],
    ) -> dict:
        """Normalize a variable set. NEVER stores name, variable names/values."""
        vs_id = str(item.get("id") or "")
        variable_set_resource_id = _opaque_id(vs_id)
        attrs = item.get("attributes") or {}

        rels = item.get("relationships") or {}
        ws_data = (rels.get("workspaces") or {}).get("data") or []
        proj_data = (rels.get("projects") or {}).get("data") or []

        var_count = len(var_items)
        sensitive_count = sum(1 for v in var_items if _bool(_attr(v, "sensitive")))
        env_count = sum(1 for v in var_items if _attr(v, "category") == "env")
        tf_count = sum(1 for v in var_items if _attr(v, "category") == "terraform")

        resource_id = _opaque_id(f"terraform_cloud_variable_set:{variable_set_resource_id}")
        return {
            "record_type": "terraform_cloud_variable_set",
            "provider": PROVIDER,
            "record_id": f"terraform_cloud_variable_set:{resource_id}",
            "resource_id": resource_id,
            "variable_set_resource_id": variable_set_resource_id,
            "organization_resource_id": org_resource_id,
            "global_scope": _bool(attrs.get("global")),
            "workspace_count": _count(ws_data) if ws_data else _int(attrs.get("workspace-count")),
            "project_count": _count(proj_data) if proj_data else _int(attrs.get("project-count")),
            "variable_count": var_count,
            "sensitive_variable_count": sensitive_count,
            "non_sensitive_variable_count": var_count - sensitive_count,
            "environment_variable_count": env_count,
            "terraform_variable_count": tf_count,
        }

    def _normalize_policy_set(
        self,
        item: dict,
        org_resource_id: str,
    ) -> dict:
        """Normalize a policy set. NEVER stores name, policy code, or VCS details."""
        ps_id = str(item.get("id") or "")
        policy_set_resource_id = _opaque_id(ps_id)
        attrs = item.get("attributes") or {}

        rels = item.get("relationships") or {}
        ws_data = (rels.get("workspaces") or {}).get("data") or []
        proj_data = (rels.get("projects") or {}).get("data") or []
        policy_data = (rels.get("policies") or {}).get("data") or []

        vcs_repo = attrs.get("vcs-repo")
        vcs_connected = vcs_repo is not None and bool(vcs_repo)

        resource_id = _opaque_id(f"terraform_cloud_policy_set:{policy_set_resource_id}")
        return {
            "record_type": "terraform_cloud_policy_set",
            "provider": PROVIDER,
            "record_id": f"terraform_cloud_policy_set:{resource_id}",
            "resource_id": resource_id,
            "policy_set_resource_id": policy_set_resource_id,
            "organization_resource_id": org_resource_id,
            "global_scope": _bool(attrs.get("global")),
            "workspace_count": _count(ws_data) if ws_data else _int(attrs.get("workspace-count")),
            "project_count": _count(proj_data) if proj_data else _int(attrs.get("project-count")),
            "policy_count": _count(policy_data) if policy_data else _int(attrs.get("policy-count")),
            "enforcement_level_category": _enforcement_level_category(
                attrs.get("enforcement-level")
            ),
            "vcs_connected": vcs_connected,
        }

    def _normalize_notification(
        self,
        item: dict,
        workspace_resource_id: str,
    ) -> dict:
        """Normalize a notification configuration.

        NEVER stores: URL, token, email recipients, Slack channel, team ID.
        Stores only: enabled flag, destination type category, trigger count,
        URL scheme (http/https/other/None), token presence boolean.
        """
        nc_id = str(item.get("id") or "")
        notification_resource_id = _opaque_id(nc_id)
        attrs = item.get("attributes") or {}

        url = attrs.get("url") or ""
        scheme = _url_scheme(url)
        url_present = bool(url)

        token = attrs.get("token") or ""
        token_present = bool(token)

        triggers = attrs.get("triggers") or []

        resource_id = _opaque_id(
            f"terraform_cloud_notification:{notification_resource_id}:{workspace_resource_id}"
        )
        return {
            "record_type": "terraform_cloud_notification_configuration",
            "provider": PROVIDER,
            "record_id": f"terraform_cloud_notification_configuration:{resource_id}",
            "resource_id": resource_id,
            "notification_resource_id": notification_resource_id,
            "workspace_resource_id": workspace_resource_id,
            "enabled": _bool(attrs.get("enabled")),
            "destination_type_category": _destination_type_category(
                attrs.get("destination-type")
            ),
            "trigger_count": _count(triggers),
            "webhook_url_present": url_present,
            "webhook_url_scheme_category": scheme,
            "token_present": token_present,
        }

    def _normalize_team_access_summary(
        self,
        workspace_resource_id: str,
        team_access_items: list[dict],
    ) -> dict:
        """Normalize team access into an aggregate count summary.

        NEVER stores: team names, user names, emails, exact permission payloads.
        Stores only: access-level counts.
        """
        admin_count = 0
        write_count = 0
        read_count = 0
        plan_count = 0
        custom_count = 0

        for item in team_access_items:
            access = (_attr(item, "access") or "").lower()
            if access == "admin":
                admin_count += 1
            elif access == "write":
                write_count += 1
            elif access == "read":
                read_count += 1
            elif access == "plan":
                plan_count += 1
            elif access == "custom":
                custom_count += 1

        resource_id = _opaque_id(
            f"terraform_cloud_team_access_summary:{workspace_resource_id}"
        )
        return {
            "record_type": "terraform_cloud_team_access_summary",
            "provider": PROVIDER,
            "record_id": f"terraform_cloud_team_access_summary:{resource_id}",
            "resource_id": resource_id,
            "workspace_resource_id": workspace_resource_id,
            "team_access_count": len(team_access_items),
            "admin_access_count": admin_count,
            "write_access_count": write_count,
            "read_access_count": read_count,
            "plan_access_count": plan_count,
            "custom_permission_count": custom_count,
        }

    def _normalize_run_trigger(
        self,
        item: dict,
        workspace_resource_id: str,
    ) -> dict:
        """Normalize a run trigger. NEVER stores source workspace name or run IDs."""
        rt_id = str(item.get("id") or "")
        run_trigger_resource_id = _opaque_id(rt_id)
        attrs = item.get("attributes") or {}

        sourceable_type = attrs.get("sourceable-type") or attrs.get("source-type") or ""
        st_safe = sourceable_type.lower().strip() if isinstance(sourceable_type, str) else "unknown"
        if st_safe not in ("workspace", "module", "registry_module"):
            st_safe = "other" if st_safe else "unknown"

        resource_id = _opaque_id(
            f"terraform_cloud_run_trigger:{run_trigger_resource_id}:{workspace_resource_id}"
        )
        return {
            "record_type": "terraform_cloud_run_trigger",
            "provider": PROVIDER,
            "record_id": f"terraform_cloud_run_trigger:{resource_id}",
            "resource_id": resource_id,
            "run_trigger_resource_id": run_trigger_resource_id,
            "workspace_resource_id": workspace_resource_id,
            "sourceable_type_category": st_safe,
        }

    def _normalize_state_version_summary(
        self,
        workspace_resource_id: str,
        current_state_present: bool,
    ) -> dict:
        """Normalize state version summary. NEVER fetches or stores state file content.

        Only records whether a state version exists for the workspace.
        raw_state_never_fetched=True confirms no state file APIs were called.
        """
        resource_id = _opaque_id(
            f"terraform_cloud_state_version_summary:{workspace_resource_id}"
        )
        return {
            "record_type": "terraform_cloud_state_version_summary",
            "provider": PROVIDER,
            "record_id": f"terraform_cloud_state_version_summary:{resource_id}",
            "resource_id": resource_id,
            "workspace_resource_id": workspace_resource_id,
            "state_version_present": current_state_present,
            "state_version_count_category": "present" if current_state_present else "none",
            "raw_state_never_fetched": True,
        }

    # ── fetch() entrypoint ────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch safe Terraform Cloud configuration records.

        Returns a list of flat, JSON-serializable, privacy-safe record dicts.
        Raises AuthenticationError if credentials are missing or invalid.
        """
        token = credentials.get("api_token") or ""
        org_name = (credentials.get("organization") or "").strip()
        base_url = _normalize_base_url(credentials.get("base_url"))

        if not token:
            raise AuthenticationError(
                "Terraform Cloud api_token is required for configuration snapshots."
            )
        if not org_name:
            raise AuthenticationError(
                "Terraform Cloud organization is required for configuration snapshots."
            )

        # Opaque org resource ID — org name is used as API path but never stored
        org_resource_id = _opaque_id(org_name)

        records: list[dict] = []

        # ── 1. Organization record ─────────────────────────────────────────
        org_data = self._get_single(base_url, token, f"organizations/{org_name}")
        if org_data is not None:
            org_record = self._normalize_organization(org_data, org_resource_id)
            records.append(org_record)

        # ── 2. Workspace records (with per-workspace sub-resources) ────────
        workspaces = self._paginate(
            base_url, token,
            f"organizations/{org_name}/workspaces",
            max_records=_MAX_WORKSPACES,
        )

        for ws_item in workspaces:
            ws_id = str(ws_item.get("id") or "")
            if not ws_id:
                continue
            workspace_resource_id = _opaque_id(ws_id)

            # Per-workspace sub-resources (fail-soft on 403/404)
            var_items = self._fetch_fail_soft(
                base_url, token, f"workspaces/{ws_id}/vars", max_records=500
            )
            notif_items = self._fetch_fail_soft(
                base_url, token,
                f"workspaces/{ws_id}/notification-configurations",
                max_records=100,
            )
            team_access_items = self._fetch_fail_soft(
                base_url, token,
                f"workspaces/{ws_id}/team-access",
                max_records=200,
            )
            run_trigger_items = self._fetch_fail_soft(
                base_url, token,
                f"workspaces/{ws_id}/run-triggers",
                max_records=100,
            )

            # Workspace record
            ws_record = self._normalize_workspace(
                ws_item,
                org_resource_id,
                var_items,
                notif_items,
                team_access_items,
                run_trigger_items,
            )
            records.append(ws_record)

            # Variable summary (separate record for diff tracking)
            records.append(
                self._normalize_workspace_variable_summary(workspace_resource_id, var_items)
            )

            # Notification configuration records
            for notif_item in notif_items:
                records.append(
                    self._normalize_notification(notif_item, workspace_resource_id)
                )

            # Team access summary
            records.append(
                self._normalize_team_access_summary(workspace_resource_id, team_access_items)
            )

            # Run trigger records
            for rt_item in run_trigger_items:
                records.append(
                    self._normalize_run_trigger(rt_item, workspace_resource_id)
                )

            # State version summary (presence only — never fetches state file)
            current_state_present = ws_record.get("current_state_version_present", False)
            records.append(
                self._normalize_state_version_summary(
                    workspace_resource_id, current_state_present
                )
            )

        # ── 3. Project records ─────────────────────────────────────────────
        projects = self._fetch_fail_soft(
            base_url, token,
            f"organizations/{org_name}/projects",
            max_records=_MAX_PROJECTS,
        )
        for proj_item in projects:
            records.append(self._normalize_project(proj_item, org_resource_id))

        # ── 4. Variable set records ────────────────────────────────────────
        varsets = self._fetch_fail_soft(
            base_url, token,
            f"organizations/{org_name}/varsets",
            max_records=_MAX_VARIABLE_SETS,
        )
        for vs_item in varsets:
            vs_id = str(vs_item.get("id") or "")
            if not vs_id:
                continue
            # Fetch variable set variables (counts only; names/values discarded)
            vs_var_items = self._fetch_fail_soft(
                base_url, token, f"varsets/{vs_id}/vars", max_records=200
            )
            records.append(
                self._normalize_variable_set(vs_item, org_resource_id, vs_var_items)
            )

        # ── 5. Policy set records ──────────────────────────────────────────
        policy_sets = self._fetch_fail_soft(
            base_url, token,
            f"organizations/{org_name}/policy-sets",
            max_records=_MAX_POLICY_SETS,
        )
        for ps_item in policy_sets:
            records.append(self._normalize_policy_set(ps_item, org_resource_id))

        # Update org record with policy_set_count and variable_set_count
        for rec in records:
            if rec.get("record_type") == "terraform_cloud_organization":
                rec["policy_set_count"] = len(policy_sets)
                rec["variable_set_count"] = len(varsets)
                break

        logger.info(
            "terraform_cloud: fetched %d safe configuration records for org %s",
            len(records),
            org_resource_id,  # log only the opaque ID, never the org name
        )
        return records

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate credentials by fetching the organization resource.

        Returns True if credentials are valid, raises AuthenticationError otherwise.
        """
        token = credentials.get("api_token") or ""
        org_name = (credentials.get("organization") or "").strip()
        base_url = _normalize_base_url(credentials.get("base_url"))

        if not token:
            raise AuthenticationError(
                "Terraform Cloud api_token is required."
            )
        if not org_name:
            raise AuthenticationError(
                "Terraform Cloud organization is required."
            )
        # Attempt to fetch the organization — this validates both token and org
        self._request(base_url, token, f"organizations/{org_name}")
        return True
