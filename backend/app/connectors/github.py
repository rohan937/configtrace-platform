"""GitHub repository configuration connector — Milestone 26.

Fetches repository-level configuration (not code) from the GitHub REST API
using a fine-grained Personal Access Token (PAT).

Seven categories are monitored per repository:
    1. Repository settings     (visibility, default branch, merge policies, …)
    2. Default-branch protection rules
    3. Actions secrets metadata  (names + ``last_updated_at`` — **never** values)
    4. Actions variables         (name + value)
    5. Repository webhooks       (URL, events, active, content_type)
    6. Actions permissions       (enabled, allowed_actions)
    7. Deploy keys               (title, read_only, verified)

Usage
-----
    from app.connectors.github import GitHubConnector

    connector = GitHubConnector()
    records = connector.fetch({
        "github_token": "github_pat_...",
        "repo_owner":   "acme",
        "repo_name":    "myapp",
    })

Credentials dict
----------------
    github_token : str
        Fine-grained PAT with the following **repository** permissions:
            - Metadata: Read  (always required for fine-grained PATs)
            - Administration: Read  (branch protection, webhooks, deploy keys,
                                     Actions permissions)
            - Secrets: Read         (Actions secrets metadata — names + timestamps)
            - Variables: Read       (Actions variables)
    repo_owner : str
        The GitHub username or organisation that owns the repository.
    repo_name : str
        The repository name (without the owner prefix).

Security constraints
---------------------
    * GitHub tokens are **never** logged.
    * Secret values are **never** fetched or stored — only name + updated_at.
    * All records are JSON-serialisable plain dicts.
    * Token extraction runs only in the function body, not at class level.

Rate limiting
-------------
    GitHub's primary rate limit is 5,000 requests/hour for authenticated
    PATs (core endpoint).  A fetch for one repository uses ≤ 10 requests
    (one per category, plus pagination if there are > 100 items in any
    paginated collection).

    HTTP 429 responses are retried up to ``_MAX_RETRIES`` times using the
    ``Retry-After`` header value (default 60 s when absent).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.github_schema import (
    GITHUB_ACTIONS_PERMISSIONS,
    GITHUB_ACTIONS_SECRET,
    GITHUB_ACTIONS_VARIABLE,
    GITHUB_AUTOMATION_PERMISSIONS,
    GITHUB_BRANCH_PROTECTION,
    GITHUB_DEPLOY_KEY,
    GITHUB_ENVIRONMENT_PROTECTION,
    GITHUB_REPO_SETTINGS,
    GITHUB_RULESET,
    GITHUB_WEBHOOK,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ───────────────────────────────────────────────────

_BASE_URL = "https://api.github.com"
_PER_PAGE = 100
_MAX_RETRIES = 3
_TIMEOUT = 30.0


# ── Auth headers ─────────────────────────────────────────────────────────────

def _auth_headers(token: str) -> dict[str, str]:
    """Build the GitHub REST API authentication headers."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


# ── Webhook config normalization ─────────────────────────────────────────────

def _normalize_insecure_ssl(raw: Any) -> Optional[bool]:
    """Normalize GitHub's ``config.insecure_ssl`` field to a bool.

    GitHub's webhook config API is inconsistent about the shape of this field
    across API versions/clients: it may be the string ``"1"``/``"0"``, the
    int ``1``/``0``, or an actual bool. ``"1"``/``1``/``True`` mean insecure
    SSL is enabled (verification disabled); ``"0"``/``0``/``False`` mean
    verification is enabled. When the field is absent or an unrecognised
    shape, return ``None`` (unknown) rather than defaulting to False — we
    must not silently claim SSL verification is enabled when we don't know.
    """
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        if raw == "1":
            return True
        if raw == "0":
            return False
        return None
    if isinstance(raw, int):
        if raw == 1:
            return True
        if raw == 0:
            return False
        return None
    return None


# ── Connector class ──────────────────────────────────────────────────────────

class GitHubConnector(BaseConnector):
    """Connector for GitHub repository configuration via the REST API.

    This class is stateless — safe to construct once and reuse across calls.
    Each ``fetch()`` / ``validate_credentials()`` call is fully self-contained.
    """

    # ── Public API ───────────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all monitored configuration categories for a repository.

        Calls seven GitHub REST API endpoints and returns a flat list of
        normalised record dicts, one per monitored item (one settings record,
        one branch-protection record, N secrets, N variables, N webhooks,
        one permissions record, N deploy keys).

        Args:
            credentials: Must contain ``github_token``, ``repo_owner``,
                         ``repo_name``.

        Returns:
            List of record dicts.  Each dict contains at least
            ``record_id``, ``record_type``, and ``name``.

        Raises:
            ConnectorError:      Missing credentials, 404 repo not found, or
                                 other API error.
            AuthenticationError: HTTP 401 or 403 from any endpoint.
            RateLimitError:      HTTP 429 after all retries are exhausted.
            NetworkError:        Timeout or transport-level failure.
        """
        token, owner, repo = self._extract_credentials(credentials)
        headers = _auth_headers(token)
        slug = f"{owner}/{repo}"

        records: list[dict] = []

        with httpx.Client(timeout=_TIMEOUT) as client:
            # 1. Repository settings — also extracts the default branch name
            #    so the branch-protection call uses the right branch.
            settings_record = self._fetch_repo_settings(
                client, headers, owner, repo, slug
            )
            records.append(settings_record)
            default_branch: str = settings_record.get("default_branch", "main")

            # 2. Branch protection for the default branch
            records.append(
                self._fetch_branch_protection(
                    client, headers, owner, repo, slug, default_branch
                )
            )

            # 3. Actions secrets metadata (names + updated_at, never values)
            records.extend(
                self._fetch_actions_secrets(client, headers, owner, repo, slug)
            )

            # 4. Actions variables
            records.extend(
                self._fetch_actions_variables(client, headers, owner, repo, slug)
            )

            # 5. Webhooks
            records.extend(
                self._fetch_webhooks(client, headers, owner, repo, slug)
            )

            # 6. Actions permissions
            records.append(
                self._fetch_actions_permissions(client, headers, owner, repo, slug)
            )

            # 7. Deploy keys
            records.extend(
                self._fetch_deploy_keys(client, headers, owner, repo, slug)
            )

            # 8. Deployment environment protection rules — optional, M57.9
            records.extend(
                self._fetch_environments(client, headers, owner, repo, slug)
            )

            # 9. Repository rulesets — modern branch protection (M69.5A).
            # Fully fail-soft: rulesets are unavailable on some plans / tokens,
            # so this helper swallows its own errors and returns [] rather than
            # break the rest of the GitHub sync.
            records.extend(
                self._fetch_rulesets(client, headers, owner, repo, slug)
            )

            # 10. Automation credential / token permission posture (M69.5B).
            # Fully fail-soft. Stores only the repo permission level and (for
            # classic PATs) OAuth scope NAMES — never the token, headers, or
            # secrets.
            records.extend(
                self._fetch_automation_permissions(
                    client, headers, owner, repo, slug,
                    credential_type=credentials.get("credential_type") or "github_token",
                )
            )

        logger.info(
            "github_connector fetch complete  repo=%s  record_count=%d",
            slug,
            len(records),
        )
        return records

    def validate_credentials(self, credentials: dict) -> bool:
        """Verify that the token can access the repository.

        Issues a single ``GET /repos/{owner}/{repo}`` call — the lightest
        possible probe that exercises both authentication and repository-level
        access.

        Args:
            credentials: Must contain ``github_token``, ``repo_owner``,
                         ``repo_name``.

        Returns:
            ``True`` if the credentials are valid.

        Raises:
            AuthenticationError: HTTP 401 or 403.
            ConnectorError:      HTTP 404 (repo not found / inaccessible) or
                                 other API error.
            NetworkError:        Timeout or transport failure.
        """
        token, owner, repo = self._extract_credentials(credentials)
        headers = _auth_headers(token)

        with httpx.Client(timeout=_TIMEOUT) as client:
            self._get(client, f"{_BASE_URL}/repos/{owner}/{repo}", headers)

        return True

    # ── Audit-log activity (M66.2) ───────────────────────────────────────────

    def list_audit_log_events(
        self,
        credentials: dict,
        *,
        per_page: int = 100,
        max_pages: int = 3,
    ) -> list[dict[str, Any]]:
        """Fetch recent GitHub organization audit-log events (control-plane).

        Uses ``GET /orgs/{org}/audit-log``; the org is taken from ``repo_owner``.
        This is the activity-event source for the FUTURE Incident Signals product.
        It only returns control-plane activity — it does NOT detect breaches,
        identify attackers, or confirm compromise.

        GitHub's audit-log API requires organization-owner permissions and is only
        available for GitHub Enterprise Cloud organizations. For user accounts,
        non-admin tokens, or unsupported plans GitHub returns 401/403/404 — the
        ingestion service treats those as *permission-limited*, never fatal.

        Returns a list of raw audit-event dicts (newest first, per GitHub).

        Raises:
            AuthenticationError: HTTP 401/403 — token lacks org audit-log access.
            ConnectorError:      HTTP 404 (org audit log unavailable) or other error.
            RateLimitError / NetworkError: as per ``_get``.
        """
        token = credentials.get("github_token", "")
        org = credentials.get("repo_owner", "")
        if not token or not org:
            raise ConnectorError(
                "GitHub audit-log ingestion needs 'github_token' and 'repo_owner' (org)."
            )
        headers = _auth_headers(token)
        url = f"{_BASE_URL}/orgs/{org}/audit-log"

        events: list[dict[str, Any]] = []
        with httpx.Client(timeout=_TIMEOUT) as client:
            page = 1
            while page <= max_pages:
                resp = self._get(
                    client,
                    url,
                    headers,
                    params={"per_page": per_page, "page": page, "include": "all"},
                    allow_404=True,
                )
                if resp.status_code == 404:
                    raise ConnectorError(
                        f"GitHub organization audit log is not available for "
                        f"'{org}' (HTTP 404). Requires an Enterprise Cloud org and "
                        f"a token with audit-log read permission.",
                        status_code=404,
                    )
                body = resp.json()
                page_items = body if isinstance(body, list) else []
                events.extend(page_items)
                if len(page_items) < per_page:
                    break
                page += 1
        return events

    def list_secret_scanning_alerts(
        self,
        credentials: dict,
        *,
        per_page: int = 100,
        max_alerts: int = 1000,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        """Fetch repository secret-scanning alerts (M69.4A).

        Uses ``GET /repos/{owner}/{repo}/secret-scanning/alerts`` (repo-scoped,
        matching the existing credential model). This is a SECURITY-ALERT
        evidence source — it surfaces provider-reported secret-scanning alerts
        for review. It never reads or returns the raw secret value.

        Secret scanning requires GitHub Advanced Security (or a public repo) and a
        token with ``secret_scanning_alerts:read`` (or repo admin). When the
        feature is disabled, the token lacks scope, or the repo is unavailable,
        GitHub returns 401/403/404 — the ingestion service treats those as
        *permission-limited*, never fatal.

        Bounded: ``per_page`` ≤ 100, capped to ``max_alerts`` total across at most
        ``max_pages`` pages (no unbounded pagination).

        Returns a list of raw alert dicts (newest first, per GitHub).

        Raises:
            AuthenticationError: HTTP 401/403 — token lacks secret-scanning access.
            ConnectorError:      HTTP 404 (feature disabled / repo unavailable) or
                                 other non-2xx.
            RateLimitError / NetworkError: as per ``_get``.
        """
        token = credentials.get("github_token", "")
        owner = credentials.get("repo_owner", "")
        repo = credentials.get("repo_name", "")
        if not token or not owner or not repo:
            raise ConnectorError(
                "GitHub secret-scanning ingestion needs 'github_token', "
                "'repo_owner', and 'repo_name'."
            )
        headers = _auth_headers(token)
        url = f"{_BASE_URL}/repos/{owner}/{repo}/secret-scanning/alerts"

        page_size = max(1, min(int(per_page or 100), 100))
        cap = max(1, min(int(max_alerts or 1000), 1000))
        page_cap = max(1, min(int(max_pages or 10), 50))

        alerts: list[dict[str, Any]] = []
        with httpx.Client(timeout=_TIMEOUT) as client:
            page = 1
            while page <= page_cap and len(alerts) < cap:
                resp = self._get(
                    client,
                    url,
                    headers,
                    params={"per_page": page_size, "page": page, "sort": "created",
                            "direction": "desc"},
                    allow_404=True,
                )
                if resp.status_code == 404:
                    raise ConnectorError(
                        f"GitHub secret scanning is not available for "
                        f"'{owner}/{repo}' (HTTP 404). Requires GitHub Advanced "
                        f"Security (or a public repo) and a token with "
                        f"secret-scanning read permission.",
                        status_code=404,
                    )
                body = resp.json()
                page_items = body if isinstance(body, list) else []
                alerts.extend(page_items)
                if len(page_items) < page_size:
                    break
                page += 1
        return alerts[:cap]

    def list_code_scanning_alerts(
        self,
        credentials: dict,
        *,
        per_page: int = 100,
        max_alerts: int = 1000,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        """Fetch repository code-scanning alerts (M69.4D).

        Uses ``GET /repos/{owner}/{repo}/code-scanning/alerts`` (repo-scoped,
        matching the existing credential model). This is a SECURITY-ALERT
        evidence source — it surfaces provider-reported code-scanning (SAST)
        alerts for review. It never reads or returns raw SARIF, raw code
        snippets, raw file contents, or raw alert locations.

        Code scanning requires GitHub Advanced Security (or a public repo with
        code scanning enabled) and a token with ``security_events:read`` (or repo
        admin). When the feature is disabled, the token lacks scope, or the repo
        is unavailable, GitHub returns 401/403/404 — the ingestion service treats
        those as *permission-limited*, never fatal.

        Bounded: ``per_page`` ≤ 100, capped to ``max_alerts`` total across at most
        ``max_pages`` pages (no unbounded pagination).

        Returns a list of raw alert dicts (newest first, per GitHub).

        Raises:
            AuthenticationError: HTTP 401/403 — token lacks code-scanning access.
            ConnectorError:      HTTP 404 (feature disabled / repo unavailable) or
                                 other non-2xx.
            RateLimitError / NetworkError: as per ``_get``.
        """
        token = credentials.get("github_token", "")
        owner = credentials.get("repo_owner", "")
        repo = credentials.get("repo_name", "")
        if not token or not owner or not repo:
            raise ConnectorError(
                "GitHub code-scanning ingestion needs 'github_token', "
                "'repo_owner', and 'repo_name'."
            )
        headers = _auth_headers(token)
        url = f"{_BASE_URL}/repos/{owner}/{repo}/code-scanning/alerts"

        page_size = max(1, min(int(per_page or 100), 100))
        cap = max(1, min(int(max_alerts or 1000), 1000))
        page_cap = max(1, min(int(max_pages or 10), 50))

        alerts: list[dict[str, Any]] = []
        with httpx.Client(timeout=_TIMEOUT) as client:
            page = 1
            while page <= page_cap and len(alerts) < cap:
                resp = self._get(
                    client,
                    url,
                    headers,
                    params={"per_page": page_size, "page": page, "sort": "created",
                            "direction": "desc"},
                    allow_404=True,
                )
                if resp.status_code == 404:
                    raise ConnectorError(
                        f"GitHub code scanning is not available for "
                        f"'{owner}/{repo}' (HTTP 404). Requires GitHub Advanced "
                        f"Security (or a public repo with code scanning) and a "
                        f"token with security-events read permission.",
                        status_code=404,
                    )
                body = resp.json()
                page_items = body if isinstance(body, list) else []
                alerts.extend(page_items)
                if len(page_items) < page_size:
                    break
                page += 1
        return alerts[:cap]

    def list_dependabot_alerts(
        self,
        credentials: dict,
        *,
        per_page: int = 100,
        max_alerts: int = 1000,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        """Fetch repository Dependabot alerts (M69.4G).

        Uses ``GET /repos/{owner}/{repo}/dependabot/alerts`` (repo-scoped,
        matching the existing credential model). This is a SECURITY-ALERT
        evidence source — it surfaces provider-reported vulnerable-dependency
        alerts for review. It never reads or returns raw advisory bodies, raw
        manifest/file paths, or the raw dependency-graph response.

        Dependabot alerts require the feature enabled on the repo and a token
        with ``security_events:read`` (or repo admin / Dependabot alerts read).
        When the feature is disabled, the token lacks scope, or the repo is
        unavailable, GitHub returns 401/403/404 — the ingestion service treats
        those as *permission-limited*, never fatal.

        Bounded: ``per_page`` ≤ 100, capped to ``max_alerts`` total across at most
        ``max_pages`` pages (no unbounded pagination).

        Returns a list of raw alert dicts (newest first, per GitHub).

        Raises:
            AuthenticationError: HTTP 401/403 — token lacks Dependabot access.
            ConnectorError:      HTTP 404 (feature disabled / repo unavailable) or
                                 other non-2xx.
            RateLimitError / NetworkError: as per ``_get``.
        """
        token = credentials.get("github_token", "")
        owner = credentials.get("repo_owner", "")
        repo = credentials.get("repo_name", "")
        if not token or not owner or not repo:
            raise ConnectorError(
                "GitHub Dependabot ingestion needs 'github_token', "
                "'repo_owner', and 'repo_name'."
            )
        headers = _auth_headers(token)
        url = f"{_BASE_URL}/repos/{owner}/{repo}/dependabot/alerts"

        page_size = max(1, min(int(per_page or 100), 100))
        cap = max(1, min(int(max_alerts or 1000), 1000))
        page_cap = max(1, min(int(max_pages or 10), 50))

        alerts: list[dict[str, Any]] = []
        with httpx.Client(timeout=_TIMEOUT) as client:
            page = 1
            while page <= page_cap and len(alerts) < cap:
                resp = self._get(
                    client,
                    url,
                    headers,
                    params={"per_page": page_size, "page": page, "sort": "created",
                            "direction": "desc"},
                    allow_404=True,
                )
                if resp.status_code == 404:
                    raise ConnectorError(
                        f"GitHub Dependabot alerts are not available for "
                        f"'{owner}/{repo}' (HTTP 404). Requires Dependabot alerts "
                        f"enabled and a token with security-events read permission.",
                        status_code=404,
                    )
                body = resp.json()
                page_items = body if isinstance(body, list) else []
                alerts.extend(page_items)
                if len(page_items) < page_size:
                    break
                page += 1
        return alerts[:cap]

    # ── Per-category fetch helpers ───────────────────────────────────────────

    def _fetch_repo_settings(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        owner: str,
        repo: str,
        slug: str,
    ) -> dict[str, Any]:
        """Fetch overall repository settings."""
        resp = self._get(client, f"{_BASE_URL}/repos/{owner}/{repo}", headers)
        raw = resp.json()
        return {
            "record_id":              f"{slug}#settings",
            "record_type":            GITHUB_REPO_SETTINGS,
            "name":                   slug,
            "visibility":             raw.get("visibility", "private"),
            "default_branch":         raw.get("default_branch", "main"),
            "has_issues":             bool(raw.get("has_issues", True)),
            "has_projects":           bool(raw.get("has_projects", True)),
            "has_wiki":               bool(raw.get("has_wiki", True)),
            "allow_merge_commit":     bool(raw.get("allow_merge_commit", True)),
            "allow_squash_merge":     bool(raw.get("allow_squash_merge", True)),
            "allow_rebase_merge":     bool(raw.get("allow_rebase_merge", True)),
            "delete_branch_on_merge": bool(raw.get("delete_branch_on_merge", False)),
            "archived":               bool(raw.get("archived", False)),
        }

    def _fetch_branch_protection(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        owner: str,
        repo: str,
        slug: str,
        branch: str,
    ) -> dict[str, Any]:
        """Fetch branch protection rules; 404 is normalised to 'disabled' state.

        GitHub returns HTTP 404 (not 200 with an empty payload) when no branch
        protection rule is configured.  We normalise this to a record with
        ``protection_enabled=False`` so that enable/disable transitions diff
        correctly on the next sync.
        """
        url = f"{_BASE_URL}/repos/{owner}/{repo}/branches/{branch}/protection"
        resp = self._get(client, url, headers, allow_404=True)

        if resp.status_code == 404:
            return self._disabled_protection_record(slug, branch)

        raw = resp.json()
        rpc: dict = raw.get("required_pull_request_reviews") or {}
        rsc: dict = raw.get("required_status_checks") or {}
        return {
            "record_id":                             f"{slug}#branch_protection#{branch}",
            "record_type":                           GITHUB_BRANCH_PROTECTION,
            "name":                                  f"{branch} branch",
            "branch":                                branch,
            "protection_enabled":                    True,
            "required_status_checks_enabled":        bool(rsc),
            "required_pull_request_reviews_enabled": bool(rpc),
            "required_approving_review_count":       rpc.get("required_approving_review_count"),
            "dismiss_stale_reviews":                 bool(rpc.get("dismiss_stale_reviews", False)),
            "enforce_admins": bool(
                (raw.get("enforce_admins") or {}).get("enabled", False)
            ),
            "required_linear_history": bool(
                (raw.get("required_linear_history") or {}).get("enabled", False)
            ),
            "allow_force_pushes": bool(
                (raw.get("allow_force_pushes") or {}).get("enabled", False)
            ),
            "allow_deletions": bool(
                (raw.get("allow_deletions") or {}).get("enabled", False)
            ),
        }

    # ── Repository rulesets (M69.5A) ─────────────────────────────────────────

    def _fetch_rulesets(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        owner: str,
        repo: str,
        slug: str,
        *,
        max_rulesets: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch repository rulesets (modern branch protection), fully fail-soft.

        Rulesets require ``GET /repos/{owner}/{repo}/rulesets`` and a per-ruleset
        detail call for the rules / bypass-actor / condition summary. The feature
        is unavailable on some plans and for some tokens (403/404), so this helper
        SWALLOWS its own errors and returns ``[]`` rather than break the rest of
        the GitHub sync. Only safe AGGREGATE fields (counts, booleans, enforcement
        / target strings, the ruleset name) are stored — never raw bypass-actor
        identities, branch glob strings, or the raw API response.
        """
        list_url = f"{_BASE_URL}/repos/{owner}/{repo}/rulesets"
        try:
            resp = self._get(
                client, list_url, headers,
                params={"per_page": _PER_PAGE}, allow_404=True,
            )
            if resp.status_code == 404:
                return []  # feature unavailable / repo without rulesets
            body = resp.json()
            items = body if isinstance(body, list) else []
        except (AuthenticationError, ConnectorError, RateLimitError, NetworkError):
            logger.info(
                "github_connector: rulesets unavailable for %s (non-fatal)", slug
            )
            return []
        except Exception:  # noqa: BLE001 — never break sync on a ruleset hiccup
            logger.warning(
                "github_connector: unexpected error listing rulesets for %s "
                "(non-fatal)", slug
            )
            return []

        records: list[dict[str, Any]] = []
        for item in items[:max_rulesets]:
            if not isinstance(item, dict):
                continue
            rid = item.get("id")
            if rid is None:
                continue
            # Per-ruleset detail carries rules / bypass_actors / conditions; the
            # list response does not. Fall back to the summary if detail fails.
            detail = item
            try:
                durl = f"{_BASE_URL}/repos/{owner}/{repo}/rulesets/{rid}"
                dresp = self._get(client, durl, headers, allow_404=True)
                if dresp.status_code != 404:
                    parsed = dresp.json()
                    if isinstance(parsed, dict):
                        detail = parsed
            except (AuthenticationError, ConnectorError, RateLimitError, NetworkError):
                detail = item
            except Exception:  # noqa: BLE001
                detail = item
            records.append(self._normalize_ruleset(slug, item, detail))
        return records

    @staticmethod
    def _ruleset_targets_protected(include_refs: list[Any]) -> bool:
        """Heuristic: does the ruleset target a default/main/release branch ref?

        Uses only the safe ref tokens; never persists the raw glob strings.
        """
        hints = ("main", "master", "release", "~default_branch", "~all")
        for ref in include_refs:
            if not isinstance(ref, str):
                continue
            low = ref.lower()
            if any(h in low for h in hints):
                return True
        return False

    def _normalize_ruleset(
        self, slug: str, summary: dict[str, Any], detail: dict[str, Any]
    ) -> dict[str, Any]:
        """Normalize one ruleset → a safe aggregate record (counts only)."""
        rid = summary.get("id")
        name = summary.get("name") if isinstance(summary.get("name"), str) else ""
        target = summary.get("target") if isinstance(summary.get("target"), str) else ""
        enforcement = detail.get("enforcement") or summary.get("enforcement") or ""
        enforcement = enforcement.lower() if isinstance(enforcement, str) else ""

        # Conditions → branch-pattern COUNT + protected-branch heuristic (no globs).
        conditions = detail.get("conditions") if isinstance(detail.get("conditions"), dict) else {}
        ref_name = conditions.get("ref_name") if isinstance(conditions.get("ref_name"), dict) else {}
        include = ref_name.get("include") if isinstance(ref_name.get("include"), list) else []
        exclude = ref_name.get("exclude") if isinstance(ref_name.get("exclude"), list) else []

        # Rules → which rule types are present + required-status-check COUNT.
        rules = detail.get("rules") if isinstance(detail.get("rules"), list) else []
        rule_types = {
            r.get("type") for r in rules
            if isinstance(r, dict) and isinstance(r.get("type"), str)
        }
        rsc_count = 0
        for r in rules:
            if isinstance(r, dict) and r.get("type") == "required_status_checks":
                params = r.get("parameters") if isinstance(r.get("parameters"), dict) else {}
                checks = params.get("required_status_checks")
                if isinstance(checks, list):
                    rsc_count = len(checks)

        # Bypass actors → COUNT only (never identities).
        bypass = detail.get("bypass_actors") if isinstance(detail.get("bypass_actors"), list) else []

        return {
            "record_id":                    f"{slug}#ruleset#{rid}",
            "record_type":                  GITHUB_RULESET,
            "name":                         name or f"ruleset #{rid}",
            "ruleset_id":                   str(rid),
            "target":                       target.lower() if isinstance(target, str) else "",
            "enforcement":                  enforcement,
            "branch_patterns_count":        len(include) + len(exclude),
            "targets_protected_branch":     self._ruleset_targets_protected(include),
            "bypass_actor_count":           len(bypass),
            "required_status_checks_count": rsc_count,
            # "non_fast_forward" present ⇒ force-push blocked. Absent ⇒ ALLOWED.
            "restrict_force_pushes":        "non_fast_forward" in rule_types,
            "restrict_deletions":           "deletion" in rule_types,
            "required_pr_reviews_required": "pull_request" in rule_types,
            "require_signed_commits":       "required_signatures" in rule_types,
            "requires_linear_history":      "required_linear_history" in rule_types,
            "requires_code_scanning":       "code_scanning" in rule_types,
        }

    # ── Automation credential / token permission posture (M69.5B) ────────────

    # Classic-PAT OAuth scopes that grant broad write/admin blast radius.
    _BROAD_TOKEN_SCOPES: frozenset[str] = frozenset({
        "repo", "admin:org", "admin:repo_hook", "admin:org_hook",
        "admin:public_key", "admin:enterprise", "write:org", "delete_repo",
        "site_admin", "workflow",
    })
    # Repository permission levels that broaden blast radius beyond read-only.
    _BROAD_REPO_PERMS: tuple[str, ...] = ("admin", "maintain", "push")

    def _fetch_automation_permissions(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        owner: str,
        repo: str,
        slug: str,
        *,
        credential_type: str,
    ) -> list[dict[str, Any]]:
        """Fetch the authenticated credential's repo-permission + token-scope posture.

        Fully fail-soft (returns ``[]`` on any error). Reads ``GET /repos`` which
        returns a ``permissions`` object describing the AUTHENTICATED credential's
        access, plus the ``X-OAuth-Scopes`` response header (populated only for
        classic PATs). Stores ONLY safe aggregate fields — never the token, the
        Authorization header, raw response headers, or any secret.
        """
        url = f"{_BASE_URL}/repos/{owner}/{repo}"
        try:
            resp = self._get(client, url, headers, allow_404=True)
            if resp.status_code == 404:
                return []
            raw = resp.json()
            if not isinstance(raw, dict):
                return []
        except (AuthenticationError, ConnectorError, RateLimitError, NetworkError):
            logger.info(
                "github_connector: automation permissions unavailable for %s "
                "(non-fatal)", slug
            )
            return []
        except Exception:  # noqa: BLE001 — never break sync
            logger.warning(
                "github_connector: unexpected error reading automation "
                "permissions for %s (non-fatal)", slug
            )
            return []

        perms = raw.get("permissions") if isinstance(raw.get("permissions"), dict) else {}
        admin = bool(perms.get("admin", False))
        maintain = bool(perms.get("maintain", False))
        push = bool(perms.get("push", False))
        triage = bool(perms.get("triage", False))
        pull = bool(perms.get("pull", False))
        # Only meaningful when the API actually returned a permissions object.
        permissions_present = bool(perms)
        broad_permission_count = sum(1 for v in (admin, maintain, push) if v)

        # Classic-PAT OAuth scope NAMES from the response header (never the token).
        scope_header = resp.headers.get("X-OAuth-Scopes", "") if hasattr(resp, "headers") else ""
        scope_names = sorted(
            {s.strip() for s in scope_header.split(",") if isinstance(s, str) and s.strip()}
        )
        broad_scope_names = sorted(set(scope_names) & self._BROAD_TOKEN_SCOPES)

        return [{
            "record_id":                 f"{slug}#automation_permissions",
            "record_type":               GITHUB_AUTOMATION_PERMISSIONS,
            "name":                       slug,
            "credential_type":           credential_type,
            "permissions_present":       permissions_present,
            "repository_permission_admin":    admin,
            "repository_permission_maintain": maintain,
            "repository_permission_push":     push,
            "repository_permission_triage":   triage,
            "repository_permission_pull":     pull,
            "broad_permission_count":    broad_permission_count,
            "token_scope_names":         scope_names,        # safe scope strings only
            "token_scope_count":         len(scope_names),
            "token_broad_scopes":        bool(broad_scope_names),
            "broad_scope_names":         broad_scope_names,
        }]

    def _fetch_actions_secrets(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        owner: str,
        repo: str,
        slug: str,
    ) -> list[dict[str, Any]]:
        """Fetch Actions secrets metadata — names and ``updated_at`` only.

        Secret values are **never** fetched.  The GitHub Secrets API never
        returns values in any response — only metadata.
        """
        items = self._paginate(
            client,
            f"{_BASE_URL}/repos/{owner}/{repo}/actions/secrets",
            headers,
            items_key="secrets",
        )
        return [
            {
                "record_id":       f"{slug}#secret#{item['name']}",
                "record_type":     GITHUB_ACTIONS_SECRET,
                "name":            item["name"],
                "secret_name":     item["name"],
                "last_updated_at": item.get("updated_at", ""),
            }
            for item in items
        ]

    def _fetch_actions_variables(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        owner: str,
        repo: str,
        slug: str,
    ) -> list[dict[str, Any]]:
        """Fetch Actions variables (name + value)."""
        items = self._paginate(
            client,
            f"{_BASE_URL}/repos/{owner}/{repo}/actions/variables",
            headers,
            items_key="variables",
        )
        return [
            {
                "record_id":     f"{slug}#variable#{item['name']}",
                "record_type":   GITHUB_ACTIONS_VARIABLE,
                "name":          item["name"],
                "variable_name": item["name"],
                "value":         item.get("value", ""),
            }
            for item in items
        ]

    def _fetch_webhooks(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        owner: str,
        repo: str,
        slug: str,
    ) -> list[dict[str, Any]]:
        """Fetch repository webhooks.

        Webhook payloads use a ``config`` sub-object for the URL and
        content_type.  The top-level ``url`` field is the GitHub API URL
        for the hook itself (not the delivery URL).
        """
        items = self._paginate(
            client,
            f"{_BASE_URL}/repos/{owner}/{repo}/hooks",
            headers,
        )
        records = []
        for item in items:
            hook_id = item["id"]
            config: dict = item.get("config") or {}
            insecure_ssl_enabled = _normalize_insecure_ssl(config.get("insecure_ssl"))
            records.append({
                "record_id":    f"{slug}#webhook#{hook_id}",
                "record_type":  GITHUB_WEBHOOK,
                "name":         f"hook #{hook_id}",
                "hook_id":      hook_id,
                "url":          config.get("url", ""),
                "active":       bool(item.get("active", True)),
                "events":       sorted(item.get("events", [])),
                "content_type": config.get("content_type", "json"),
                # GitHub masks a configured secret as "********" (and omits the
                # field entirely when none is set). We store ONLY the boolean
                # presence — never the masked or real secret value (M69.5B).
                "webhook_secret_configured": bool(config.get("secret")),
                # GitHub's ``config.insecure_ssl`` — "1"/1/True means SSL
                # verification is DISABLED for deliveries; "0"/0/False means
                # it's enabled. None means the field was absent/unrecognised
                # (unknown posture — never defaulted to a verified state).
                "insecure_ssl_enabled": insecure_ssl_enabled,
                "ssl_verification_enabled": (
                    None if insecure_ssl_enabled is None else not insecure_ssl_enabled
                ),
            })
        return records

    def _fetch_actions_permissions(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        owner: str,
        repo: str,
        slug: str,
    ) -> dict[str, Any]:
        """Fetch Actions permissions (enabled, allowed_actions).

        Returns a 'disabled / unknown' record on HTTP 404 — this can happen
        when Actions is not available for a repository (e.g. Actions is
        disabled at the organisation level).
        """
        url = f"{_BASE_URL}/repos/{owner}/{repo}/actions/permissions"
        resp = self._get(client, url, headers, allow_404=True)

        if resp.status_code == 404:
            return {
                "record_id":       f"{slug}#actions_permissions",
                "record_type":     GITHUB_ACTIONS_PERMISSIONS,
                "name":            slug,
                "enabled":         False,
                "allowed_actions": "",
            }

        raw = resp.json()
        return {
            "record_id":       f"{slug}#actions_permissions",
            "record_type":     GITHUB_ACTIONS_PERMISSIONS,
            "name":            slug,
            "enabled":         bool(raw.get("enabled", True)),
            "allowed_actions": raw.get("allowed_actions", "all"),
        }

    def _fetch_deploy_keys(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        owner: str,
        repo: str,
        slug: str,
    ) -> list[dict[str, Any]]:
        """Fetch repository deploy keys."""
        items = self._paginate(
            client,
            f"{_BASE_URL}/repos/{owner}/{repo}/keys",
            headers,
        )
        return [
            {
                "record_id":  f"{slug}#deploy_key#{item['id']}",
                "record_type": GITHUB_DEPLOY_KEY,
                "name":       item.get("title", f"key #{item['id']}"),
                "key_id":     item["id"],
                "title":      item.get("title", ""),
                "read_only":  bool(item.get("read_only", True)),
                "verified":   bool(item.get("verified", False)),
            }
            for item in items
        ]

    def _fetch_environments(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        owner: str,
        repo: str,
        slug: str,
    ) -> list[dict[str, Any]]:
        """Fetch deployment environment protection rules — M57.9.

        API: GET /repos/{owner}/{repo}/environments

        Returns one ``github_environment_protection`` record per environment.
        Returns an empty list when:
          - the repository has no environments (404)
          - the token lacks the ``environments: read`` permission (403)

        SECURITY
        --------
        - Reviewer identities (usernames, team slugs) are NEVER stored.
        - Only reviewer *count* is recorded.
        - Secret names and values are NEVER fetched.
        - Workflow file contents are NEVER accessed.
        """
        url = f"{_BASE_URL}/repos/{owner}/{repo}/environments"
        try:
            resp = self._get(client, url, headers)
        except Exception as exc:
            # 404 = no environments configured; 403 = no permission.
            # Both are soft failures — return empty list.
            logger.info(
                "github: environments not accessible repo=%s (%s) — skipping",
                slug,
                type(exc).__name__,
            )
            return []

        body = resp.json()
        if not isinstance(body, dict):
            return []

        environments = body.get("environments") or []
        if not isinstance(environments, list):
            return []

        records: list[dict[str, Any]] = []
        for env in environments:
            if not isinstance(env, dict):
                continue

            env_name: str = env.get("name") or ""
            if not env_name:
                continue

            # Parse protection rules — each rule has a "type" field.
            protection_rules: list[dict] = env.get("protection_rules") or []
            wait_timer: int = 0
            reviewers_count: int = 0
            prevent_self_review: bool = False

            for rule in protection_rules:
                if not isinstance(rule, dict):
                    continue
                rule_type = rule.get("type") or ""
                if rule_type == "wait_timer":
                    wait_timer = int(rule.get("wait_timer") or 0)
                elif rule_type == "required_reviewers":
                    reviewers: list = rule.get("reviewers") or []
                    reviewers_count = len(reviewers)
                    # prevent_self_review may appear on this rule
                    if rule.get("prevent_self_review") is True:
                        prevent_self_review = True

            # prevent_self_review may also appear at the environment level
            if env.get("prevent_self_review") is True:
                prevent_self_review = True

            # Deployment branch policy
            dbp = env.get("deployment_branch_policy")
            protected_branches: bool | None = None
            custom_branch_policies: bool | None = None
            if isinstance(dbp, dict):
                protected_branches = bool(dbp.get("protected_branches", False))
                custom_branch_policies = bool(dbp.get("custom_branch_policies", False))

            records.append(
                {
                    "record_id":            f"{slug}#environment#{env_name}",
                    "record_type":          GITHUB_ENVIRONMENT_PROTECTION,
                    "name":                 env_name,
                    "environment_name":     env_name,
                    "wait_timer":           wait_timer,
                    "reviewers_count":      reviewers_count,
                    "prevent_self_review":  prevent_self_review,
                    "protected_branches":   protected_branches,
                    "custom_branch_policies": custom_branch_policies,
                }
            )

        return records

    # ── Pagination helper ────────────────────────────────────────────────────

    def _paginate(
        self,
        client: httpx.Client,
        url: str,
        headers: dict[str, str],
        *,
        items_key: str | None = None,
    ) -> list[dict]:
        """Collect all items from a paginated GitHub API endpoint.

        Handles two response shapes:

        * **Envelope** (``items_key`` provided): the response is a JSON object
          ``{"total_count": N, "<items_key>": [{...}, ...]}`` — used by the
          Secrets and Variables APIs.
        * **Array** (``items_key`` is ``None``): the response is a JSON array
          ``[{...}, ...]`` — used by the Hooks and Keys APIs.

        Pagination terminates when a page returns fewer than ``_PER_PAGE``
        items, or when the total count is reached (envelope mode only).

        Args:
            client:    Active ``httpx.Client``.
            url:       Full endpoint URL (no query parameters).
            headers:   Auth headers.
            items_key: Key to extract from envelope responses, or ``None``
                       for plain-array responses.

        Returns:
            Flat list of all item dicts across all pages.
        """
        all_items: list[dict] = []
        page = 1

        while True:
            resp = self._get(
                client, url, headers,
                params={"per_page": _PER_PAGE, "page": page},
            )
            body = resp.json()

            if items_key:
                page_items: list[dict] = body.get(items_key, [])
                total_count: int = body.get("total_count", 0)
            else:
                page_items = body if isinstance(body, list) else []
                total_count = len(all_items) + len(page_items)

            all_items.extend(page_items)

            logger.debug(
                "github_connector paginate  url=%s  page=%d  fetched=%d",
                url, page, len(all_items),
            )

            # Terminal condition: last page is smaller than the page size.
            if len(page_items) < _PER_PAGE:
                break
            # For envelope responses, also stop when the count is satisfied.
            if items_key and len(all_items) >= total_count:
                break

            page += 1

        return all_items

    # ── HTTP helper ──────────────────────────────────────────────────────────

    def _get(
        self,
        client: httpx.Client,
        url: str,
        headers: dict[str, str],
        params: dict | None = None,
        *,
        allow_404: bool = False,
    ) -> httpx.Response:
        """Issue a GET with 429 retry-backoff.

        Retries up to ``_MAX_RETRIES`` times on HTTP 429.  The inter-retry
        delay is taken from the ``Retry-After`` response header (default 60 s).

        Args:
            client:     Active ``httpx.Client``.
            url:        Full endpoint URL.
            headers:    Request headers (including Authorization).
            params:     Query parameters dict, or ``None``.
            allow_404:  When ``True``, return the 404 response instead of
                        raising ``ConnectorError``.  Used by endpoints where
                        a 404 has a well-defined semantic (e.g. no branch
                        protection configured).

        Returns:
            Successful (2xx) ``httpx.Response``, or a 404 response when
            ``allow_404=True``.

        Raises:
            AuthenticationError: HTTP 401 or 403.
            RateLimitError:      HTTP 429 after all retries are exhausted.
            ConnectorError:      HTTP 404 (when ``allow_404=False``) or any
                                 other non-2xx response.
            NetworkError:        ``httpx.TimeoutException`` or
                                 ``httpx.RequestError``.
        """
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = client.get(url, headers=headers, params=params or {})
            except httpx.TimeoutException as exc:
                raise NetworkError(f"Request timed out: {exc}") from exc
            except httpx.RequestError as exc:
                raise NetworkError(f"Network error: {exc}") from exc

            if resp.status_code == 429:
                if attempt >= _MAX_RETRIES:
                    raise RateLimitError(
                        f"GitHub rate limit exceeded after {_MAX_RETRIES} retries. "
                        "Try again later.",
                    )
                try:
                    retry_after = float(resp.headers.get("Retry-After", "60"))
                except ValueError:
                    retry_after = 60.0
                logger.warning(
                    "github_connector rate limited (attempt %d/%d). "
                    "Sleeping %.1f s before retry.",
                    attempt + 1,
                    _MAX_RETRIES,
                    retry_after,
                )
                time.sleep(retry_after)
                continue

            if resp.status_code in (401, 403):
                raise AuthenticationError(
                    f"GitHub authentication failed (HTTP {resp.status_code}). "
                    "Verify the fine-grained PAT has the required repository "
                    "permissions: Metadata:Read, Administration:Read, "
                    "Secrets:Read, Variables:Read.",
                    status_code=resp.status_code,
                )

            if resp.status_code == 404:
                if allow_404:
                    return resp
                raise ConnectorError(
                    f"GitHub resource not found (HTTP 404): {url}. "
                    "Check that the repository owner and name are correct and "
                    "that the token has Metadata:Read permission.",
                    status_code=404,
                )

            if not resp.is_success:
                raise ConnectorError(
                    f"GitHub API error (HTTP {resp.status_code}): {resp.text[:500]}",
                    status_code=resp.status_code,
                )

            return resp

        # The loop always raises or returns — this line is unreachable.
        raise ConnectorError("Unexpected end of retry loop")  # pragma: no cover

    # ── Credentials helper ───────────────────────────────────────────────────

    @staticmethod
    def _extract_credentials(credentials: dict) -> tuple[str, str, str]:
        """Return ``(github_token, repo_owner, repo_name)`` or raise."""
        token = credentials.get("github_token", "")
        owner = credentials.get("repo_owner", "")
        repo = credentials.get("repo_name", "")
        if not token or not owner or not repo:
            raise ConnectorError(
                "GitHub credentials must include 'github_token', "
                "'repo_owner', and 'repo_name'."
            )
        return token, owner, repo

    # ── Static helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _disabled_protection_record(slug: str, branch: str) -> dict[str, Any]:
        """Return a record representing 'no branch protection configured'.

        All boolean fields are ``False`` and ``required_approving_review_count``
        is ``None``.  Future syncs will diff correctly when protection is
        added, because the baseline will show ``protection_enabled=False``.
        """
        return {
            "record_id":                             f"{slug}#branch_protection#{branch}",
            "record_type":                           GITHUB_BRANCH_PROTECTION,
            "name":                                  f"{branch} branch",
            "branch":                                branch,
            "protection_enabled":                    False,
            "required_status_checks_enabled":        False,
            "required_pull_request_reviews_enabled": False,
            "required_approving_review_count":       None,
            "dismiss_stale_reviews":                 False,
            "enforce_admins":                        False,
            "required_linear_history":               False,
            "allow_force_pushes":                    False,
            "allow_deletions":                       False,
        }
