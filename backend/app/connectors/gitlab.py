"""GitLab configuration drift connector (M87A).

Configuration snapshot connector for GitLab. Connects to the GitLab REST
API v4 using a personal access token (PAT) and snapshots safe configuration
surfaces. All raw secrets, URLs, user identities, project names, paths,
repo content, CI variable names/values, and PII are discarded before any
record is returned.

Surfaces covered
─────────────────
  Instance            — version/enterprise posture; admin settings if available
  Projects            — visibility, feature flags, per-project posture counts
  Groups              — visibility, member count category, subgroup counts
  Branch protection   — access level categories; pattern category, not raw name
  Webhooks            — scheme, SSL, secret presence; never raw URL or secret
  CI variable summary — counts only; never variable names or values
  Deploy key summary  — counts only; never key title, fingerprint, or material
  Runner summary      — posture counts; never token, IP, or description
  MR approval summary — approval posture booleans/counts; never approver identities

Credentials dict expected by fetch() and validate_credentials():
  {
    "access_token": "<GitLab PAT>",
    "base_url":     "<optional self-managed base URL, default https://gitlab.com>"
  }

SECURITY:
  The access_token is used ONLY in the _request() PRIVATE-TOKEN header.
  It is NEVER stored on the connector instance, NEVER copied into any
  normalised record, and NEVER logged.

  Project names, namespace paths, web_url, ssh_url, http_url, default_branch
  names, issue titles, MR titles, commit messages, CI variable names/values,
  webhook URLs/secrets, deploy key material, runner tokens/IPs, and user
  emails/usernames are NEVER fetched or stored in normalised records.

  Raw API responses are processed immediately and discarded. Only flat safe
  scalars (opaque IDs, booleans, counts, category strings) are returned.
"""

from __future__ import annotations

import hashlib
import logging
import re
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
_MAX_STR_LEN = 100
_PAGE_SIZE = 100

# Per-surface record caps (bound runaway pagination)
_MAX_PROJECTS = 200
_MAX_GROUPS = 200
_MAX_BRANCHES_PER_PROJECT = 100
_MAX_WEBHOOKS_PER_OWNER = 100
_MAX_VARIABLES_PER_OWNER = 500
_MAX_DEPLOY_KEYS_PER_PROJECT = 100
_MAX_RUNNERS_PER_OWNER = 100

_DEFAULT_BASE_URL = "https://gitlab.com"

# ── Module-level helpers ────────────────────────────────────────────────────────


def _trunc(value: Any, length: int = _MAX_STR_LEN) -> str:
    """Return str(value) truncated to length, or '' for None/non-string."""
    if isinstance(value, str):
        return value[:length]
    if value is None:
        return ""
    return str(value)[:length]


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


def _opaque_id(value: Any) -> str:
    """Return a sha256-based opaque identifier for a raw value."""
    raw = str(value) if value is not None else ""
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _normalize_base_url(base_url: Optional[str]) -> str:
    """Normalize the GitLab base URL to https scheme, no trailing slash."""
    if not base_url:
        return _DEFAULT_BASE_URL
    url = base_url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _url_scheme(url: Any) -> str:
    """Return 'https', 'http', or 'other' from a raw URL string."""
    if not isinstance(url, str) or not url:
        return "absent"
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme in ("https",):
            return "https"
        if scheme in ("http",):
            return "http"
        return "other"
    except Exception:
        return "other"


def _host_category(url: Any) -> str:
    """Return a safe host category: 'internal' / 'external' / 'absent'."""
    if not isinstance(url, str) or not url:
        return "absent"
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            return "absent"
        if re.search(r"\.(internal|corp|local|intranet|lan)$", host):
            return "internal"
        return "external"
    except Exception:
        return "absent"


def _visibility_category(visibility: Any) -> str:
    """Map raw GitLab visibility string to safe category."""
    v = (visibility or "").lower()
    if v in ("private",):
        return "private"
    if v in ("internal",):
        return "internal"
    if v in ("public",):
        return "public"
    return "unknown"


def _access_level_category(level: Any) -> str:
    """Map GitLab access level integer to safe category string."""
    try:
        n = int(level)
    except (TypeError, ValueError):
        return "unknown"
    if n == 0:
        return "no_access"
    if n <= 10:
        return "guest"
    if n <= 20:
        return "reporter"
    if n <= 30:
        return "developer"
    if n <= 40:
        return "maintainer"
    if n <= 50:
        return "owner"
    return "unknown"


def _pattern_category(name: Any) -> str:
    """Categorise a protected branch pattern without storing the name."""
    if not isinstance(name, str) or not name:
        return "unknown"
    if name in ("main", "master", "develop", "release", "production"):
        return "default"
    if "*" in name or "?" in name:
        return "wildcard"
    return "protected"


def _member_count_category(count: Any) -> str:
    """Return a safe member count category."""
    try:
        n = int(count)
    except (TypeError, ValueError):
        return "unknown"
    if n == 0:
        return "empty"
    if n <= 5:
        return "small"
    if n <= 25:
        return "medium"
    if n <= 100:
        return "large"
    return "very_large"


def _shared_runners_setting_category(setting: Any) -> str:
    """Map GitLab group shared_runners_setting to safe category."""
    v = (setting or "").lower()
    mapping = {
        "enabled": "enabled",
        "disabled_and_unoverridable": "disabled_locked",
        "disabled_with_override": "disabled_with_override",
        "disabled_and_overridable": "disabled_overridable",
    }
    return mapping.get(v, "unknown")


# ── Connector ──────────────────────────────────────────────────────────────────


class GitLabConnector(BaseConnector):
    """GitLab project configuration drift connector.

    Uses a GitLab personal access token for authentication.
    SECURITY: Token never stored on instance, never logged, never in records.
    """

    def __init__(self) -> None:
        pass  # No credentials stored on the instance.

    # ── Low-level transport ─────────────────────────────────────────────────────

    def _request(
        self,
        base_url: str,
        token: str,
        path: str,
        params: Optional[dict] = None,
    ) -> Any:
        """Make a single authenticated GET request. Returns parsed JSON."""
        url = f"{base_url}/api/v4/{path.lstrip('/')}"
        headers = {
            "PRIVATE-TOKEN": token,
            "Accept": "application/json",
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
            raise NetworkError(f"GitLab request timed out: {path}") from exc
        except httpx.RequestError as exc:
            raise NetworkError(f"GitLab network error: {path}: {exc}") from exc

    def _raise_for_status(self, response: httpx.Response, surface: str) -> None:
        """Raise a typed exception for non-2xx responses."""
        code = response.status_code
        if code in (401, 403):
            raise AuthenticationError(
                f"GitLab authentication failed (HTTP {code}) on {surface}. "
                "Verify the access token has the required scopes (read_api or api)."
            )
        if code == 429:
            raise RateLimitError(f"GitLab rate limit exceeded on {surface}.")
        if code >= 500:
            raise ConnectorError(
                f"GitLab server error (HTTP {code}) on {surface}."
            )
        if code >= 400:
            # 404 on optional sub-resources: caller can ignore
            raise ConnectorError(
                f"GitLab request failed (HTTP {code}) on {surface}."
            )

    def _paginate(
        self,
        base_url: str,
        token: str,
        path: str,
        extra_params: Optional[dict] = None,
        max_records: int = _MAX_PROJECTS,
    ) -> list[dict]:
        """Fetch a paginated GitLab list endpoint. Returns up to max_records."""
        results: list[dict] = []
        page = 1
        while len(results) < max_records:
            params = {"per_page": _PAGE_SIZE, "page": page}
            if extra_params:
                params.update(extra_params)
            try:
                batch = self._request(base_url, token, path, params=params)
            except ConnectorError:
                break
            if not isinstance(batch, list) or not batch:
                break
            results.extend(batch)
            if len(batch) < _PAGE_SIZE:
                break
            page += 1
        return results[:max_records]

    # ── Fail-soft sub-resource helper ───────────────────────────────────────────

    def _safe_list(
        self,
        base_url: str,
        token: str,
        path: str,
        extra_params: Optional[dict] = None,
        max_records: int = _PAGE_SIZE,
    ) -> list[dict]:
        """Paginate a path, returning [] on 403/404 (permission-limited)."""
        try:
            return self._paginate(
                base_url, token, path,
                extra_params=extra_params,
                max_records=max_records,
            )
        except AuthenticationError:
            raise
        except (ConnectorError, NetworkError):
            return []

    def _safe_get(
        self,
        base_url: str,
        token: str,
        path: str,
    ) -> Optional[dict]:
        """Fetch a single resource, returning None on 403/404."""
        try:
            result = self._request(base_url, token, path)
            if isinstance(result, dict):
                return result
            return None
        except AuthenticationError:
            raise
        except (ConnectorError, NetworkError):
            return None

    # ── Instance-level normalizer ───────────────────────────────────────────────

    def _normalize_instance(
        self,
        version_data: Optional[dict],
        settings_data: Optional[dict],
        project_count: Optional[int],
        group_count: Optional[int],
    ) -> dict:
        """Normalize instance-level posture into a safe record."""
        resource_id = "gitlab_instance"
        return {
            "record_type": "gitlab_instance",
            "provider": "gitlab",
            "record_id": f"gitlab_instance:{resource_id}",
            "resource_id": resource_id,
            "version_present": bool(version_data and version_data.get("version")),
            "revision_present": bool(version_data and version_data.get("revision")),
            "enterprise": _bool(version_data.get("enterprise") if version_data else None),
            "project_count": project_count,
            "group_count": group_count,
            "two_factor_requirement_enabled": (
                _bool(settings_data.get("require_two_factor_authentication"))
                if settings_data else None
            ),
            "sign_up_enabled": (
                _bool(settings_data.get("signup_enabled"))
                if settings_data else None
            ),
            "visibility_restriction_category": (
                _visibility_category(
                    settings_data.get("default_project_visibility")
                )
                if settings_data else None
            ),
            "shared_runners_enabled": (
                _bool(settings_data.get("shared_runners_enabled"))
                if settings_data else None
            ),
        }

    # ── Project normalizer ──────────────────────────────────────────────────────

    def _normalize_project(
        self,
        raw: dict,
        *,
        protected_branch_count: Optional[int] = None,
        webhook_count: Optional[int] = None,
        ci_variable_count: Optional[int] = None,
        deploy_key_count: Optional[int] = None,
        approval_rule_count: Optional[int] = None,
    ) -> dict:
        """Normalize a raw project dict into a safe, flat record."""
        project_id = str(raw.get("id", ""))
        resource_id = _opaque_id(project_id)
        return {
            "record_type": "gitlab_project",
            "provider": "gitlab",
            "record_id": f"gitlab_project:{resource_id}",
            "resource_id": resource_id,
            "visibility_category": _visibility_category(raw.get("visibility")),
            "archived": _bool(raw.get("archived")),
            "default_branch_present": bool(raw.get("default_branch")),
            "merge_requests_enabled": _bool(
                raw.get("merge_requests_enabled"), default=True
            ),
            "issues_enabled": _bool(raw.get("issues_enabled"), default=True),
            "wiki_enabled": _bool(raw.get("wiki_enabled"), default=True),
            "snippets_enabled": _bool(raw.get("snippets_enabled"), default=True),
            "container_registry_enabled": _bool(
                raw.get("container_registry_enabled")
            ),
            "packages_enabled": (
                _bool(raw.get("packages_enabled"))
                if raw.get("packages_enabled") is not None
                else None
            ),
            "shared_runners_enabled": (
                _bool(raw.get("shared_runners_enabled"))
                if raw.get("shared_runners_enabled") is not None
                else None
            ),
            "protected_branch_count": protected_branch_count,
            "webhook_count": webhook_count,
            "ci_variable_count": ci_variable_count,
            "deploy_key_count": deploy_key_count,
            "approval_rule_count": approval_rule_count,
        }

    # ── Group normalizer ────────────────────────────────────────────────────────

    def _normalize_group(self, raw: dict) -> dict:
        """Normalize a raw group dict into a safe, flat record."""
        group_id = str(raw.get("id", ""))
        resource_id = _opaque_id(group_id)
        member_count = raw.get("statistics", {}).get("member_count") if isinstance(raw.get("statistics"), dict) else None
        return {
            "record_type": "gitlab_group",
            "provider": "gitlab",
            "record_id": f"gitlab_group:{resource_id}",
            "resource_id": resource_id,
            "visibility_category": _visibility_category(raw.get("visibility")),
            "project_count": _int(raw.get("projects_count"), default=0) or None,
            "subgroup_count": _int(raw.get("subgroup_count"), default=0) or None,
            "member_count_category": _member_count_category(member_count),
            "two_factor_requirement_enabled": (
                _bool(raw.get("require_two_factor_authentication"))
                if raw.get("require_two_factor_authentication") is not None
                else None
            ),
            "membership_lock": (
                _bool(raw.get("membership_lock"))
                if raw.get("membership_lock") is not None
                else None
            ),
            "shared_runners_setting_category": (
                _shared_runners_setting_category(raw.get("shared_runners_setting"))
                if raw.get("shared_runners_setting") is not None
                else None
            ),
        }

    # ── Branch protection normalizer ────────────────────────────────────────────

    def _normalize_branch_protection(
        self, raw: dict, project_resource_id: str
    ) -> dict:
        """Normalize a raw protected_branch dict into a safe record."""
        # Use pattern category + project ID to produce a stable opaque record ID.
        pattern_cat = _pattern_category(raw.get("name"))
        rule_key = f"{project_resource_id}:{pattern_cat}:{_opaque_id(raw.get('name', ''))}"
        resource_id = _opaque_id(rule_key)

        push_levels = raw.get("push_access_levels") or []
        merge_levels = raw.get("merge_access_levels") or []
        push_level = push_levels[0].get("access_level") if push_levels else None
        merge_level = merge_levels[0].get("access_level") if merge_levels else None

        return {
            "record_type": "gitlab_branch_protection",
            "provider": "gitlab",
            "record_id": f"gitlab_branch_protection:{resource_id}",
            "resource_id": resource_id,
            "project_resource_id": project_resource_id,
            "pattern_category": pattern_cat,
            "allow_force_push": _bool(raw.get("allow_force_push")),
            "code_owner_approval_required": _bool(
                raw.get("code_owner_approval_required")
            ),
            "push_access_level_category": _access_level_category(push_level),
            "merge_access_level_category": _access_level_category(merge_level),
            "allowed_to_push_count": _count(push_levels),
            "allowed_to_merge_count": _count(merge_levels),
        }

    # ── Webhook normalizer ──────────────────────────────────────────────────────

    def _normalize_webhook(
        self, raw: dict, owner_resource_id: str, owner_type: str
    ) -> dict:
        """Normalize a raw hook dict into a safe record.

        SECURITY: webhook URL is never stored. Only scheme + host category
        are derived and stored as safe categorical strings.
        """
        hook_id = str(raw.get("id", ""))
        resource_id = _opaque_id(f"{owner_resource_id}:{hook_id}")
        raw_url = raw.get("url") or ""

        # Count enabled event types from boolean fields
        event_fields = [
            "push_events", "merge_requests_events", "tag_push_events",
            "issues_events", "confidential_issues_events",
            "note_events", "confidential_note_events", "wiki_page_events",
            "pipeline_events", "job_events", "member_events",
            "repository_update_events", "releases_events",
            "deployment_events", "emoji_events", "subgroup_events",
        ]
        event_count = sum(
            1 for f in event_fields if _bool(raw.get(f))
        )

        return {
            "record_type": "gitlab_webhook",
            "provider": "gitlab",
            "record_id": f"gitlab_webhook:{resource_id}",
            "resource_id": resource_id,
            "owner_resource_id": owner_resource_id,
            "owner_type": owner_type,
            "enabled": _bool(raw.get("enable_ssl_verification"), default=True),
            "url_scheme": _url_scheme(raw_url),
            "url_host_category": _host_category(raw_url),
            "ssl_verification_enabled": _bool(
                raw.get("enable_ssl_verification"), default=True
            ),
            "secret_token_present": bool(
                raw.get("token") or raw.get("secret_token")
            ),
            "event_count": event_count,
            "push_events": _bool(raw.get("push_events")),
            "merge_requests_events": _bool(raw.get("merge_requests_events")),
            "pipeline_events": _bool(raw.get("pipeline_events")),
            "job_events": _bool(raw.get("job_events")),
        }

    # ── CI variable summary normalizer ──────────────────────────────────────────

    def _normalize_ci_variable_summary(
        self, variables: list[dict], owner_resource_id: str, owner_type: str
    ) -> dict:
        """Normalize raw CI variables into a count-only summary record.

        SECURITY: variable names and values are NEVER stored.
        """
        resource_id = _opaque_id(f"ci_var:{owner_resource_id}")
        protected_count = sum(
            1 for v in variables if _bool(v.get("protected"))
        )
        masked_count = sum(1 for v in variables if _bool(v.get("masked")))
        env_scoped_count = sum(
            1 for v in variables
            if (v.get("environment_scope") or "*") != "*"
        )
        unprotected_unmasked = sum(
            1 for v in variables
            if not _bool(v.get("protected")) and not _bool(v.get("masked"))
        )
        return {
            "record_type": "gitlab_ci_variable_summary",
            "provider": "gitlab",
            "record_id": f"gitlab_ci_variable_summary:{resource_id}",
            "resource_id": resource_id,
            "owner_resource_id": owner_resource_id,
            "owner_type": owner_type,
            "variable_count": len(variables),
            "protected_variable_count": protected_count,
            "masked_variable_count": masked_count,
            "environment_scoped_count": env_scoped_count,
            "unprotected_unmasked_count": unprotected_unmasked,
        }

    # ── Deploy key summary normalizer ───────────────────────────────────────────

    def _normalize_deploy_key_summary(
        self, deploy_keys: list[dict], project_resource_id: str
    ) -> dict:
        """Normalize raw deploy keys into a count-only summary record.

        SECURITY: key titles, fingerprints, and key material are NEVER stored.
        """
        resource_id = _opaque_id(f"deploy_key:{project_resource_id}")
        write_count = sum(1 for k in deploy_keys if _bool(k.get("can_push")))
        read_only_count = len(deploy_keys) - write_count
        enabled_count = sum(
            1 for k in deploy_keys if k.get("deploy_keys_projects") is not None
        )
        return {
            "record_type": "gitlab_deploy_key_summary",
            "provider": "gitlab",
            "record_id": f"gitlab_deploy_key_summary:{resource_id}",
            "resource_id": resource_id,
            "project_resource_id": project_resource_id,
            "deploy_key_count": len(deploy_keys),
            "write_enabled_count": write_count,
            "read_only_count": read_only_count,
            "enabled_count": enabled_count,
        }

    # ── Runner summary normalizer ────────────────────────────────────────────────

    def _normalize_runner_summary(
        self, runners: list[dict], owner_resource_id: str, owner_type: str
    ) -> dict:
        """Normalize raw runners into a posture count summary record.

        SECURITY: runner tokens, descriptions, IPs, and contact details
        are NEVER stored.
        """
        resource_id = _opaque_id(f"runner:{owner_resource_id}")
        shared_enabled = any(
            (r.get("runner_type") or "").lower() == "instance_type"
            for r in runners
        )
        locked_count = sum(1 for r in runners if _bool(r.get("locked")))
        paused_count = sum(1 for r in runners if _bool(r.get("paused")))
        tagged_count = sum(
            1 for r in runners
            if isinstance(r.get("tag_list"), list) and r["tag_list"]
        )
        untagged_count = len(runners) - tagged_count
        return {
            "record_type": "gitlab_runner_summary",
            "provider": "gitlab",
            "record_id": f"gitlab_runner_summary:{resource_id}",
            "resource_id": resource_id,
            "owner_resource_id": owner_resource_id,
            "owner_type": owner_type,
            "runner_count": len(runners),
            "shared_runner_enabled": shared_enabled,
            "locked_runner_count": locked_count,
            "paused_runner_count": paused_count,
            "tagged_runner_count": tagged_count,
            "untagged_runner_count": untagged_count,
        }

    # ── MR approval summary normalizer ───────────────────────────────────────────

    def _normalize_mr_approval_summary(
        self, approvals: dict, project_resource_id: str
    ) -> dict:
        """Normalize raw MR approval settings into a safe summary record.

        SECURITY: approver names, usernames, emails, and rule names
        are NEVER stored.
        """
        resource_id = _opaque_id(f"mr_approval:{project_resource_id}")
        rules = approvals.get("approval_rules_overwritten") or []
        rule_count = _count(rules) if isinstance(rules, list) else _int(
            approvals.get("approval_rule_count")
        )
        return {
            "record_type": "gitlab_merge_request_approval_summary",
            "provider": "gitlab",
            "record_id": f"gitlab_merge_request_approval_summary:{resource_id}",
            "resource_id": resource_id,
            "project_resource_id": project_resource_id,
            "approval_rule_count": rule_count,
            "approvals_required": (
                _int(approvals.get("approvals_required"))
                if approvals.get("approvals_required") is not None
                else None
            ),
            "code_owner_approval_required": (
                _bool(approvals.get("merge_requests_author_approval"))
                if approvals.get("merge_requests_author_approval") is not None
                else None
            ),
            "reset_approvals_on_push": (
                _bool(approvals.get("reset_approvals_on_push"))
                if approvals.get("reset_approvals_on_push") is not None
                else None
            ),
            "disable_overriding_approvers_per_merge_request": (
                _bool(approvals.get("disable_overriding_approvers_per_merge_request"))
                if approvals.get("disable_overriding_approvers_per_merge_request") is not None
                else None
            ),
        }

    # ── Surface fetchers ────────────────────────────────────────────────────────

    def _fetch_instance(self, base_url: str, token: str) -> dict:
        """Fetch instance-level posture."""
        version_data = self._safe_get(base_url, token, "version")
        settings_data = self._safe_get(base_url, token, "application/settings")
        return {"version": version_data, "settings": settings_data}

    def _fetch_projects(self, base_url: str, token: str) -> list[dict]:
        """Fetch accessible projects (membership only)."""
        return self._safe_list(
            base_url, token,
            "projects",
            extra_params={"membership": "true"},
            max_records=_MAX_PROJECTS,
        )

    def _fetch_groups(self, base_url: str, token: str) -> list[dict]:
        """Fetch accessible groups."""
        return self._safe_list(
            base_url, token,
            "groups",
            extra_params={"all_available": "false"},
            max_records=_MAX_GROUPS,
        )

    def _fetch_protected_branches(
        self, base_url: str, token: str, project_id: str
    ) -> list[dict]:
        """Fetch protected branches for a project."""
        return self._safe_list(
            base_url, token,
            f"projects/{project_id}/protected_branches",
            max_records=_MAX_BRANCHES_PER_PROJECT,
        )

    def _fetch_project_hooks(
        self, base_url: str, token: str, project_id: str
    ) -> list[dict]:
        """Fetch webhooks for a project."""
        return self._safe_list(
            base_url, token,
            f"projects/{project_id}/hooks",
            max_records=_MAX_WEBHOOKS_PER_OWNER,
        )

    def _fetch_group_hooks(
        self, base_url: str, token: str, group_id: str
    ) -> list[dict]:
        """Fetch webhooks for a group."""
        return self._safe_list(
            base_url, token,
            f"groups/{group_id}/hooks",
            max_records=_MAX_WEBHOOKS_PER_OWNER,
        )

    def _fetch_project_variables(
        self, base_url: str, token: str, project_id: str
    ) -> list[dict]:
        """Fetch CI variables for a project (counts only; names/values discarded)."""
        return self._safe_list(
            base_url, token,
            f"projects/{project_id}/variables",
            max_records=_MAX_VARIABLES_PER_OWNER,
        )

    def _fetch_group_variables(
        self, base_url: str, token: str, group_id: str
    ) -> list[dict]:
        """Fetch CI variables for a group (counts only; names/values discarded)."""
        return self._safe_list(
            base_url, token,
            f"groups/{group_id}/variables",
            max_records=_MAX_VARIABLES_PER_OWNER,
        )

    def _fetch_deploy_keys(
        self, base_url: str, token: str, project_id: str
    ) -> list[dict]:
        """Fetch deploy keys for a project (counts only; key material discarded)."""
        return self._safe_list(
            base_url, token,
            f"projects/{project_id}/deploy_keys",
            max_records=_MAX_DEPLOY_KEYS_PER_PROJECT,
        )

    def _fetch_project_runners(
        self, base_url: str, token: str, project_id: str
    ) -> list[dict]:
        """Fetch runners for a project."""
        return self._safe_list(
            base_url, token,
            f"projects/{project_id}/runners",
            max_records=_MAX_RUNNERS_PER_OWNER,
        )

    def _fetch_mr_approvals(
        self, base_url: str, token: str, project_id: str
    ) -> Optional[dict]:
        """Fetch MR approval settings for a project."""
        return self._safe_get(
            base_url, token, f"projects/{project_id}/approvals"
        )

    # ── Public interface ────────────────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Return True if the credentials successfully authenticate."""
        token = credentials.get("access_token") or ""
        base_url = _normalize_base_url(credentials.get("base_url"))
        if not token:
            raise AuthenticationError(
                "GitLab access_token is required."
            )
        try:
            result = self._request(base_url, token, "user")
            return isinstance(result, dict) and bool(result.get("id"))
        except AuthenticationError:
            return False

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all safe configuration records for this GitLab instance.

        Returns a list of flat, JSON-serializable dicts. No secrets, tokens,
        URLs, user identities, or raw payloads are included.

        Args:
            credentials: dict with "access_token" (required) and optional
                         "base_url" for self-managed GitLab instances.

        Returns:
            List of normalized record dicts ready for snapshotting.

        Raises:
            AuthenticationError: if credentials are missing or invalid.
        """
        token = credentials.get("access_token") or ""
        base_url = _normalize_base_url(credentials.get("base_url"))
        if not token:
            raise AuthenticationError(
                "GitLab access_token is required for configuration snapshots."
            )

        records: list[dict] = []

        # ── Instance record ─────────────────────────────────────────────────
        instance_data = self._fetch_instance(base_url, token)
        projects_raw = self._fetch_projects(base_url, token)
        groups_raw = self._fetch_groups(base_url, token)

        instance_record = self._normalize_instance(
            version_data=instance_data.get("version"),
            settings_data=instance_data.get("settings"),
            project_count=len(projects_raw),
            group_count=len(groups_raw),
        )
        records.append(instance_record)

        # ── Project records ─────────────────────────────────────────────────
        for raw_project in projects_raw:
            project_id = str(raw_project.get("id", ""))
            if not project_id:
                continue
            project_resource_id = _opaque_id(project_id)

            # Per-project sub-resources (fail-soft)
            branches = self._fetch_protected_branches(base_url, token, project_id)
            hooks = self._fetch_project_hooks(base_url, token, project_id)
            variables = self._fetch_project_variables(base_url, token, project_id)
            deploy_keys = self._fetch_deploy_keys(base_url, token, project_id)
            runners = self._fetch_project_runners(base_url, token, project_id)
            approvals = self._fetch_mr_approvals(base_url, token, project_id)

            # Project record with counts
            project_record = self._normalize_project(
                raw_project,
                protected_branch_count=len(branches),
                webhook_count=len(hooks),
                ci_variable_count=len(variables),
                deploy_key_count=len(deploy_keys),
                approval_rule_count=(
                    _int(approvals.get("approvals_required"))
                    if approvals else None
                ),
            )
            records.append(project_record)

            # Branch protection records
            for branch in branches:
                records.append(
                    self._normalize_branch_protection(branch, project_resource_id)
                )

            # Webhook records
            for hook in hooks:
                records.append(
                    self._normalize_webhook(hook, project_resource_id, "project")
                )

            # CI variable summary (if any)
            if variables is not None:
                records.append(
                    self._normalize_ci_variable_summary(
                        variables, project_resource_id, "project"
                    )
                )

            # Deploy key summary (if any)
            if deploy_keys is not None:
                records.append(
                    self._normalize_deploy_key_summary(deploy_keys, project_resource_id)
                )

            # Runner summary (if any)
            if runners is not None:
                records.append(
                    self._normalize_runner_summary(
                        runners, project_resource_id, "project"
                    )
                )

            # MR approval summary
            if approvals is not None:
                records.append(
                    self._normalize_mr_approval_summary(approvals, project_resource_id)
                )

        # ── Group records ───────────────────────────────────────────────────
        for raw_group in groups_raw:
            group_id = str(raw_group.get("id", ""))
            if not group_id:
                continue
            group_resource_id = _opaque_id(group_id)

            records.append(self._normalize_group(raw_group))

            # Group webhooks
            group_hooks = self._fetch_group_hooks(base_url, token, group_id)
            for hook in group_hooks:
                records.append(
                    self._normalize_webhook(hook, group_resource_id, "group")
                )

            # Group CI variables
            group_vars = self._fetch_group_variables(base_url, token, group_id)
            if group_vars is not None:
                records.append(
                    self._normalize_ci_variable_summary(
                        group_vars, group_resource_id, "group"
                    )
                )

        logger.info(
            "gitlab: fetched %d safe configuration records from %s",
            len(records),
            base_url,
        )
        return records
