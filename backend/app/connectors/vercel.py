"""Vercel connector — M33.

Fetches project settings, environment variable metadata (key names + targets,
NEVER values), and custom domain configuration from the Vercel REST API v9.

Credentials dict
----------------
    vercel_token      : str
        A Vercel personal access token with read access to the project.
        Generated at vercel.com → Settings → Tokens.  Must have at least
        "Read" scope on the target project.
    vercel_project_id : str
        The Vercel project ID (``prj_xxx``) or project slug name.
        Found at vercel.com → <project> → Settings → General → Project ID.

SECURITY GUARANTEES
-------------------
* Environment variable VALUES are never fetched or stored.  The ``/env``
  response always includes a ``value`` field; we explicitly drop it before
  returning any record.  This ensures secrets never enter the snapshot store,
  timeline, email alerts, or test fixtures.
* The API token is never logged (even on failure — error messages use
  ``"(token not logged)"`` as a placeholder where needed).
* All requests are read-only (GET only).
* Sensitive headers are not written to application logs.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.vercel_schema import VERCEL_DOMAIN, VERCEL_ENV_VAR, VERCEL_PROJECT

logger = logging.getLogger(__name__)

# ── Module-level constants ───────────────────────────────────────────────────

_BASE_URL = "https://api.vercel.com"

# Number of 429/5xx retry attempts before giving up (attempt 0 is the first try)
_MAX_RETRIES = 3

# Base back-off multiplier for 429 / 5xx retries
_RETRY_BASE_SECONDS = 1.5

# Per-request HTTP timeout in seconds
_TIMEOUT = 30.0


# ── Connector class ──────────────────────────────────────────────────────────


class VercelConnector(BaseConnector):
    """Read-only Vercel connector.

    Fetches three categories per project:

    1. **Project settings** — framework, build command, output/root directory,
       Node.js version.
    2. **Environment variables (metadata only)** — key name, target
       environments (production / preview / development), type, and timestamps.
       The actual secret VALUE is deliberately excluded from every record.
    3. **Custom domains** — domain name, verification status, redirects.

    All three categories are collapsed into a single flat list of record dicts.
    The ``record_type`` field distinguishes them.
    """

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all Vercel records for the configured project.

        Args:
            credentials: Must contain ``vercel_token`` and ``vercel_project_id``.

        Returns:
            Flat list of record dicts.  One ``vercel_project`` record, N
            ``vercel_env_var`` records (one per env var key), and M
            ``vercel_domain`` records (one per custom domain).

        Raises:
            AuthenticationError: Token rejected (401/403).
            ConnectorError:      Project not found (404) or API error.
            NetworkError:        Transport-level failure.
            RateLimitError:      Rate limit exceeded after all retries.
        """
        token = credentials["vercel_token"]
        project_id = credentials["vercel_project_id"]
        headers = {"Authorization": f"Bearer {token}"}

        records: list[dict] = []

        # ── 1. Project settings ──────────────────────────────────────────────
        raw_project = self._get(f"/v9/projects/{project_id}", headers)
        records.append(_normalize_project(raw_project))

        # ── 2. Env var metadata (paginated) — SECURITY: drop ``value`` ────────
        env_records = self._fetch_env_vars(project_id, headers)
        records.extend(env_records)

        # ── 3. Custom domains (paginated) ────────────────────────────────────
        domain_records = self._fetch_domains(project_id, headers)
        records.extend(domain_records)

        logger.info(
            "vercel connector fetch  project=%s  total_records=%d  "
            "env_vars=%d  domains=%d",
            project_id,
            len(records),
            len(env_records),
            len(domain_records),
        )
        return records

    def validate_credentials(self, credentials: dict) -> bool:
        """Return True iff the token can read the given project.

        Raises ``AuthenticationError`` when the token is invalid (401/403).
        Raises ``ConnectorError`` when the project is not found (404) or another
        API error occurs (so the caller can surface a user-facing message).
        Raises ``NetworkError`` on transport failure.

        Args:
            credentials: Must contain ``vercel_token`` and ``vercel_project_id``.

        Returns:
            Always ``True`` on success — the caller can treat ``False`` as a
            validation failure and ``AuthenticationError`` as an auth failure.
        """
        token = credentials.get("vercel_token", "")
        project_id = credentials.get("vercel_project_id", "")
        if not token or not project_id:
            return False
        headers = {"Authorization": f"Bearer {token}"}
        # A successful GET is enough to confirm read access.
        self._get(f"/v9/projects/{project_id}", headers)
        return True

    # ── Private helpers ───────────────────────────────────────────────────────

    def _fetch_env_vars(self, project_id: str, headers: dict) -> list[dict]:
        """Fetch all env var records using cursor pagination.

        SECURITY: ``value`` is explicitly dropped from every record before
        it is returned.  This method must never return any dict that contains
        a ``value`` key.
        """
        records: list[dict] = []
        params: dict[str, Any] = {"limit": 100}
        while True:
            data = self._get(
                f"/v9/projects/{project_id}/env", headers, params=params
            )
            for ev in data.get("envs", []):
                records.append(_normalize_env_var(ev))

            # Cursor-based pagination (Vercel returns a ``pagination`` object)
            pagination = data.get("pagination") or {}
            next_cursor = pagination.get("next")
            if not next_cursor:
                break
            params = {"limit": 100, "until": next_cursor}

        return records

    def _fetch_domains(self, project_id: str, headers: dict) -> list[dict]:
        """Fetch all custom domains using cursor pagination."""
        records: list[dict] = []
        params: dict[str, Any] = {"limit": 100}
        while True:
            data = self._get(
                f"/v9/projects/{project_id}/domains", headers, params=params
            )
            for d in data.get("domains", []):
                records.append(_normalize_domain(d))

            pagination = data.get("pagination") or {}
            next_cursor = pagination.get("next")
            if not next_cursor:
                break
            params = {"limit": 100, "until": next_cursor}

        return records

    def _get(
        self,
        path: str,
        headers: dict,
        params: dict | None = None,
    ) -> dict:
        """GET *path* with 429 / 5xx retry-backoff.

        Args:
            path:    URL path relative to ``_BASE_URL``.
            headers: Request headers (must include ``Authorization``).
            params:  Optional query parameters.

        Returns:
            Parsed JSON response dict.

        Raises:
            AuthenticationError: 401 or 403 from Vercel.
            ConnectorError:      404, or non-success after all retries.
            NetworkError:        Transport-level failure (no HTTP response).
            RateLimitError:      429 after all retries exhausted.
        """
        url = f"{_BASE_URL}{path}"

        for attempt in range(_MAX_RETRIES):
            try:
                resp = httpx.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=_TIMEOUT,
                )
            except httpx.RequestError as exc:
                raise NetworkError(
                    f"Network error reaching Vercel API: {exc}"
                ) from exc

            if resp.status_code in (401, 403):
                raise AuthenticationError(
                    f"Vercel API rejected the token (HTTP {resp.status_code})."
                )

            if resp.status_code == 429:
                if attempt < _MAX_RETRIES - 1:
                    retry_after = float(
                        resp.headers.get(
                            "Retry-After",
                            _RETRY_BASE_SECONDS * (attempt + 1),
                        )
                    )
                    logger.warning(
                        "vercel: rate limited  attempt=%d  retry_after=%.1fs",
                        attempt,
                        retry_after,
                    )
                    time.sleep(retry_after)
                    continue
                raise RateLimitError(
                    "Vercel API rate limit exceeded after retries.",
                    retry_after=float(
                        resp.headers.get("Retry-After", 0) or 0
                    ),
                )

            if resp.status_code == 404:
                raise ConnectorError(
                    f"Vercel resource not found: {path}",
                    status_code=404,
                )

            if resp.status_code >= 500:
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BASE_SECONDS * (attempt + 1))
                    continue
                raise ConnectorError(
                    f"Vercel API unavailable (HTTP {resp.status_code}).",
                    status_code=resp.status_code,
                )

            if not resp.is_success:
                raise ConnectorError(
                    f"Unexpected Vercel API error (HTTP {resp.status_code}).",
                    status_code=resp.status_code,
                )

            return resp.json()

        # Unreachable — loop always raises or returns inside.
        raise ConnectorError("Vercel request failed after all retries.")  # pragma: no cover


# ── Normalisation helpers ─────────────────────────────────────────────────────


def _normalize_project(raw: dict) -> dict:
    """Map a raw Vercel project API response to a ``VercelProjectRecord``."""
    # Git connection — Vercel returns link (OAuth/GitHub App) or gitRepository (Git Integration)
    link: dict = raw.get("link") or {}
    git_repo_obj: dict = raw.get("gitRepository") or {}
    git_repository: str | None = link.get("repo") or git_repo_obj.get("repo") or None
    git_branch: str | None = (
        link.get("productionBranch")
        or raw.get("gitBranch")
        or None
    )

    return {
        "record_id":           raw.get("id") or raw.get("name", ""),
        "record_type":         VERCEL_PROJECT,
        "name":                raw.get("name", ""),
        "framework":           raw.get("framework"),
        "build_command":       raw.get("buildCommand"),
        "install_command":     raw.get("installCommand"),
        "output_directory":    raw.get("outputDirectory"),
        "root_directory":      raw.get("rootDirectory"),
        "node_version":        raw.get("nodeVersion"),
        "git_repository":      git_repository,
        "git_branch":          git_branch,
        "sso_protection":      _normalize_protection(raw.get("ssoProtection")),
        "password_protection": _normalize_protection(raw.get("passwordProtection")),
    }


def _normalize_protection(raw: object) -> str | None:
    """Normalize a Vercel deployment-protection setting to a stable scalar.

    Returns ``None`` when protection is disabled (API returns ``null``).
    Returns the ``deploymentType`` string when enabled, e.g. ``"all"``.
    Diff tracking then surfaces a change from ``None`` → ``"all"`` as
    "protection enabled" and ``"all"`` → ``None`` as "protection disabled".
    """
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw.get("deploymentType") or "enabled"
    # Unexpected shape — coerce to string so diffs are still meaningful
    return str(raw)


def _normalize_env_var(raw: dict) -> dict:
    """Map a raw Vercel env-var API record to a ``VercelEnvVarRecord``.

    SECURITY: the ``value`` field from the Vercel API response is NEVER
    included in the returned dict.  Only key name, target environments,
    type, and timestamps are stored.
    """
    target = raw.get("target") or []
    if isinstance(target, str):
        # Vercel sometimes returns a single string for single-target vars
        target = [target]
    return {
        "record_id":   raw.get("id", ""),
        "record_type": VERCEL_ENV_VAR,
        "name":        raw.get("key", ""),
        "key":         raw.get("key", ""),
        "env_type":    raw.get("type"),
        "target":      sorted(target),
        "git_branch":  raw.get("gitBranch"),
        "created_at":  raw.get("createdAt"),
        "updated_at":  raw.get("updatedAt"),
        # NOTE: raw.get("value") is intentionally NOT included here.
    }


def _normalize_domain(raw: dict) -> dict:
    """Map a raw Vercel domain API record to a ``VercelDomainRecord``."""
    return {
        "record_id":   raw.get("name", ""),
        "record_type": VERCEL_DOMAIN,
        "name":        raw.get("name", ""),
        "verified":    raw.get("verified", False),
        "git_branch":  raw.get("gitBranch"),
        "redirect":    raw.get("redirect"),
        "created_at":  raw.get("createdAt"),
        "updated_at":  raw.get("updatedAt"),
    }
