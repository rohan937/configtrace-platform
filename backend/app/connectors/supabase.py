"""Supabase provider connector — M54.

Credential model
----------------
``access_token``  — Supabase Management API personal access token (``sbp_...``).
``project_ref``   — 20-char alphanumeric project reference string.

API surfaces
------------
1. Project metadata       GET /v1/projects/{ref}
2. Auth configuration     GET /v1/projects/{ref}/config/auth
3. Database configuration GET /v1/projects/{ref}/config/database/pooler
                          (Postgres major version from project metadata)
4. Storage configuration  GET /v1/projects/{ref}/config/storage
5. Edge Functions         GET /v1/projects/{ref}/functions
6. RLS status             GET /v1/projects/{ref}/database/tables?included_schemas=public
7. PostgREST / API config GET /v1/projects/{ref}/config/postgrest
8. Network restrictions   GET /v1/projects/{ref}/network-restrictions
9. Custom domain          GET /v1/projects/{ref}/custom-hostname
10. OAuth providers        derived from auth config ``external`` map

Fail-soft design
----------------
Each API surface is fetched independently.  A 403 on any optional surface
yields a ``config_fetch_warning`` in that record instead of aborting the
entire sync.  Only a 401/403 on the primary project-metadata call raises
``AuthenticationError`` to abort the whole sync.

SECURITY — data minimisation
-----------------------------
* Row data (database table contents) is NEVER read.
* Auth user PII (emails, phone numbers, UIDs) is NEVER fetched or stored.
* Database passwords, service role keys, auth JWT secrets are NEVER read.
* Edge Function source code is NEVER fetched; only metadata is collected.
* Storage file contents and object names are NEVER accessed.
* OAuth client_secret is NEVER stored; client_id is hashed (SHA-256[:16]).
* Edge Function environment variable values are NEVER stored; only the
  number of configured keys (count) is recorded.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.supabase_schema import (
    REQUIRED_CREDENTIAL_FIELDS,
    SUPABASE_API_CONFIG,
    SUPABASE_AUTH_CONFIG,
    SUPABASE_CUSTOM_DOMAIN,
    SUPABASE_DATABASE_CONFIG,
    SUPABASE_EDGE_FUNCTION,
    SUPABASE_NETWORK_RESTRICTION,
    SUPABASE_OAUTH_PROVIDER,
    SUPABASE_PROJECT,
    SUPABASE_RLS_STATUS,
    SUPABASE_STORAGE_CONFIG,
)

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.supabase.com"
_TIMEOUT = 20.0  # seconds per request
_MAX_RETRIES = 2


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256_prefix(value: str) -> str:
    """Return the first 16 hex chars of the SHA-256 digest of *value*.

    Used for hashing OAuth client_id values so they are never stored raw.
    """
    return hashlib.sha256(value.encode()).hexdigest()[:16]


# ── Connector ─────────────────────────────────────────────────────────────────

class SupabaseConnector(BaseConnector):
    """Fetch Supabase project configuration via the Management API.

    Credentials
    -----------
    ``access_token``  — ``sbp_*`` personal access token.
    ``project_ref``   — 20-char project reference (shown in project URL).

    SECURITY: No database row data, auth user PII, secret values, or file
    contents are ever fetched or stored.
    """

    # ── Credential validation ─────────────────────────────────────────────────

    def _validate_credential_fields(self, credentials: dict) -> None:
        """Raise ValueError if required credential fields are absent."""
        for field in REQUIRED_CREDENTIAL_FIELDS:
            if not credentials.get(field):
                raise ValueError(
                    f"Supabase credentials missing required field: {field!r}. "
                    f"Required: {', '.join(REQUIRED_CREDENTIAL_FIELDS)}."
                )

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _get(
        self,
        path: str,
        access_token: str,
        *,
        params: dict | None = None,
        timeout: float = _TIMEOUT,
    ) -> dict | list:
        """Execute a GET request against the Supabase Management API.

        Raises:
            AuthenticationError: HTTP 401 or 403.
            RateLimitError:      HTTP 429 (all retries exhausted).
            ConnectorError:      Other HTTP errors.
            NetworkError:        Transport-level failures.
        """
        url = f"{_BASE_URL}{path}"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = httpx.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=timeout,
                    follow_redirects=True,
                )
            except httpx.TimeoutException as exc:
                last_exc = NetworkError(f"Request timed out: {url}") if attempt == _MAX_RETRIES else exc
                if attempt < _MAX_RETRIES:
                    continue
                raise NetworkError(f"Request timed out after {_MAX_RETRIES + 1} attempts: {url}") from exc
            except httpx.RequestError as exc:
                if attempt < _MAX_RETRIES:
                    last_exc = exc
                    continue
                raise NetworkError(f"Network error reaching Supabase: {exc}") from exc

            if response.status_code == 401:
                raise AuthenticationError(
                    "Supabase access token was rejected (HTTP 401). "
                    "Verify the token is a valid Management API access token (sbp_...).",
                    status_code=401,
                )
            if response.status_code == 403:
                raise ConnectorError(
                    "Supabase returned HTTP 403 — the access token lacks permission for this resource.",
                    status_code=403,
                )
            if response.status_code == 404:
                raise ConnectorError(
                    f"Supabase returned HTTP 404 — resource not found: {path}",
                    status_code=404,
                )
            if response.status_code == 429:
                if attempt < _MAX_RETRIES:
                    last_exc = RateLimitError("Supabase rate limit hit")
                    continue
                raise RateLimitError(
                    "Supabase rate limit was hit and retries exhausted.",
                )
            if response.status_code >= 500:
                if attempt < _MAX_RETRIES:
                    last_exc = ConnectorError("Supabase 5xx", status_code=response.status_code)
                    continue
                raise ConnectorError(
                    f"Supabase returned HTTP {response.status_code} (server error).",
                    status_code=response.status_code,
                )
            if not response.is_success:
                raise ConnectorError(
                    f"Supabase returned HTTP {response.status_code}: {response.text[:200]}",
                    status_code=response.status_code,
                )

            try:
                return response.json()
            except Exception as exc:
                raise ConnectorError(
                    f"Supabase returned non-JSON response for {path}"
                ) from exc

        # Should be unreachable but satisfy type checkers.
        if last_exc:
            raise last_exc
        raise ConnectorError("Supabase request failed (unknown reason).")

    # ── API surface fetchers ──────────────────────────────────────────────────

    def _fetch_project_metadata(
        self,
        access_token: str,
        project_ref: str,
    ) -> dict:
        """Fetch top-level project metadata (region, status, plan).

        Returns:
            A ``supabase_project`` record dict.

        Raises:
            AuthenticationError, ConnectorError, NetworkError.
        """
        data = self._get(f"/v1/projects/{project_ref}", access_token)
        if not isinstance(data, dict):
            raise ConnectorError("Unexpected response shape for project metadata.")

        record: dict[str, Any] = {
            "record_type": SUPABASE_PROJECT,
            "record_id": f"supabase_project:{project_ref}",
            "project_ref": project_ref,
            "name": data.get("name") or "",
            "region": data.get("region") or "",
            "cloud_provider": data.get("cloud_provider") or "",
            "status": data.get("status") or "",
            # plan info lives in a nested dict
            "plan_id": ((data.get("subscription_tier") or data.get("plan") or {}).get("id") or "")
                       if isinstance(data.get("subscription_tier") or data.get("plan"), dict)
                       else str(data.get("subscription_tier") or data.get("plan") or ""),
            "has_custom_domain": bool(data.get("custom_domain")),
            "config_fetch_warnings": [],
        }
        return record

    def _fetch_auth_config(
        self,
        access_token: str,
        project_ref: str,
    ) -> tuple[dict, list[dict]]:
        """Fetch Auth configuration and OAuth provider entries.

        Returns:
            A tuple: (auth_config_record, list_of_oauth_provider_records).
            On 403, returns a record with a config_fetch_warning instead of
            raising — other surfaces can still be collected.
        """
        warnings: list[str] = []
        oauth_records: list[dict] = []

        try:
            data = self._get(f"/v1/projects/{project_ref}/config/auth", access_token)
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.warning(
                    "supabase: 403 fetching auth config for %s — skipping. "
                    "Grant the service_role on the project.",
                    project_ref,
                )
                auth_record: dict[str, Any] = {
                    "record_type": SUPABASE_AUTH_CONFIG,
                    "record_id": f"supabase_auth_config:{project_ref}",
                    "config_fetch_warnings": [
                        "HTTP 403 fetching Auth configuration. "
                        "The access token may lack the necessary Management API permissions."
                    ],
                }
                return auth_record, []
            raise

        if not isinstance(data, dict):
            data = {}

        # Extract OAuth provider info before building the config record.
        # The external map is keyed by provider name (e.g. "google", "github").
        # SECURITY: client_secret is NEVER stored; client_id is hashed.
        external_map = data.get("external") or {}
        if isinstance(external_map, dict):
            for provider_name, pdata in external_map.items():
                if not isinstance(pdata, dict):
                    continue
                is_enabled = bool(pdata.get("enabled"))
                raw_client_id = pdata.get("client_id") or ""
                oauth_records.append({
                    "record_type": SUPABASE_OAUTH_PROVIDER,
                    "record_id": f"supabase_oauth_provider:{project_ref}:{provider_name}",
                    "provider_name": str(provider_name),
                    "enabled": is_enabled,
                    # Hash client_id so it is not stored raw.
                    "client_id_hash": _sha256_prefix(raw_client_id) if raw_client_id else "",
                    "provider_metadata": {
                        "record_type": SUPABASE_OAUTH_PROVIDER,
                        "provider_name": str(provider_name),
                    },
                    "config_fetch_warnings": warnings[:],
                })

        # ── M57.8: additional security depth fields ───────────────────────────
        # All fields come from the same /config/auth endpoint already called above.
        # Raw redirect URLs are NEVER stored — only the count is recorded.
        additional_redirect_urls = data.get("additional_redirect_urls") or []
        additional_redirect_urls_count = (
            len(additional_redirect_urls)
            if isinstance(additional_redirect_urls, list)
            else 0
        )

        auth_record = {
            "record_type": SUPABASE_AUTH_CONFIG,
            "record_id": f"supabase_auth_config:{project_ref}",
            "email_enabled": bool(data.get("email_enabled")),
            "phone_enabled": bool(data.get("phone_enabled")),
            "anonymous_enabled": bool(data.get("anonymous_enabled")),
            "mfa_totp_enabled": bool(data.get("mfa_totp_enabled")),
            # Session durations (integers or None)
            "session_timebox_seconds": data.get("session_timebox"),
            "session_inactivity_timeout_seconds": data.get("session_inactivity_timeout"),
            # OAuth provider count
            "oauth_provider_count": len(oauth_records),
            # Password policy
            "password_min_length": data.get("password_min_length"),
            # Site URL
            "site_url": str(data.get("site_url") or ""),
            # Rate limits
            "max_request_users_per_day": data.get("rate_limit_anonymous_users"),
            # M57.8: additional security fields (same API endpoint)
            # Leaked password protection (Have I Been Pwned integration)
            "leaked_password_protection_enabled": bool(
                data.get("password_hibp_enabled", False)
            ),
            # Bot / captcha protection
            "captcha_enabled": bool(data.get("security_captcha_enabled", False)),
            # Require reauthentication on password update
            "require_reauthentication_for_password_update": bool(
                data.get("security_update_password_require_reauthentication", False)
            ),
            # Refresh token rotation — defends against token theft
            "refresh_token_rotation_enabled": bool(
                data.get("refresh_token_rotation_enabled", False)
            ),
            # JWT access token expiry in seconds (NOT the JWT secret)
            "jwt_exp": data.get("jwt_exp"),
            # Count of additional redirect URLs — raw URLs NEVER stored
            "additional_redirect_urls_count": additional_redirect_urls_count,
            "config_fetch_warnings": warnings,
        }
        return auth_record, oauth_records

    def _fetch_database_config(
        self,
        access_token: str,
        project_ref: str,
        project_data: dict,
    ) -> dict:
        """Fetch connection pooler and Postgres version config.

        Returns a ``supabase_database_config`` record.
        On 403, returns the record with a warning.
        """
        warnings: list[str] = []

        try:
            data = self._get(
                f"/v1/projects/{project_ref}/config/database/pooler",
                access_token,
            )
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.warning(
                    "supabase: 403 fetching database pooler config for %s — skipping.",
                    project_ref,
                )
                warnings.append(
                    "HTTP 403 fetching database pooler configuration. "
                    "The access token may lack the necessary Management API permissions."
                )
                data = {}
            else:
                raise

        if not isinstance(data, dict):
            data = {}

        record: dict[str, Any] = {
            "record_type": SUPABASE_DATABASE_CONFIG,
            "record_id": f"supabase_database_config:{project_ref}",
            "pool_mode": str(data.get("pool_mode") or ""),
            "pool_size": data.get("pool_size"),
            "default_pool_size": data.get("default_pool_size"),
            "max_client_conn": data.get("max_client_conn"),
            # Postgres version from project metadata (major only, e.g. "15")
            "postgres_version": str(project_data.get("db_version") or ""),
            "config_fetch_warnings": warnings,
        }
        return record

    def _fetch_storage_config(
        self,
        access_token: str,
        project_ref: str,
    ) -> dict:
        """Fetch Storage service configuration.

        SECURITY: File contents and object names are NEVER read.
        Only global service-level configuration is collected.

        Returns a ``supabase_storage_config`` record.
        """
        warnings: list[str] = []

        try:
            data = self._get(
                f"/v1/projects/{project_ref}/config/storage",
                access_token,
            )
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.warning(
                    "supabase: 403 fetching storage config for %s — skipping.",
                    project_ref,
                )
                warnings.append(
                    "HTTP 403 fetching Storage configuration. "
                    "The access token may lack the necessary Management API permissions."
                )
                data = {}
            else:
                raise

        if not isinstance(data, dict):
            data = {}

        record: dict[str, Any] = {
            "record_type": SUPABASE_STORAGE_CONFIG,
            "record_id": f"supabase_storage_config:{project_ref}",
            "file_size_limit": data.get("fileSizeLimit") or data.get("file_size_limit"),
            "allowed_mime_types": data.get("allowedMimeTypes") or data.get("allowed_mime_types"),
            "s3_protocol_enabled": bool(data.get("s3Protocol", data.get("s3_protocol_enabled", False))),
            "config_fetch_warnings": warnings,
        }
        return record

    def _fetch_edge_functions(
        self,
        access_token: str,
        project_ref: str,
    ) -> list[dict]:
        """Fetch Edge Function metadata.

        SECURITY: Source code, environment variable values, and secrets are
        NEVER fetched or stored.  Only name, status, version, and env var
        key count are stored.

        Returns a list of ``supabase_edge_function`` records.
        """
        try:
            data = self._get(f"/v1/projects/{project_ref}/functions", access_token)
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.warning(
                    "supabase: 403 fetching edge functions for %s — skipping.",
                    project_ref,
                )
                return [{
                    "record_type": SUPABASE_EDGE_FUNCTION,
                    "record_id": f"supabase_edge_function:{project_ref}:_access_denied",
                    "config_fetch_warnings": [
                        "HTTP 403 fetching Edge Functions. "
                        "The access token may lack the necessary Management API permissions."
                    ],
                }]
            raise

        if not isinstance(data, list):
            data = []

        records = []
        for fn in data:
            if not isinstance(fn, dict):
                continue
            fn_slug = str(fn.get("slug") or fn.get("name") or "")
            fn_name = str(fn.get("name") or fn_slug)
            # env_vars is a list of env var configs; we record only the count.
            # Values are NEVER stored.
            env_var_keys = fn.get("envVarKeys") or fn.get("env_var_keys") or []
            env_var_count = len(env_var_keys) if isinstance(env_var_keys, list) else 0

            records.append({
                "record_type": SUPABASE_EDGE_FUNCTION,
                "record_id": f"supabase_edge_function:{project_ref}:{fn_slug}",
                "function_name": fn_name,
                "slug": fn_slug,
                "status": str(fn.get("status") or ""),
                "version": fn.get("version"),
                "env_var_key_count": env_var_count,
                "verify_jwt": bool(fn.get("verify_jwt", True)),
                "provider_metadata": {
                    "record_type": SUPABASE_EDGE_FUNCTION,
                    "function_name": fn_name,
                    "slug": fn_slug,
                },
                "config_fetch_warnings": [],
            })
        return records

    def _fetch_rls_status(
        self,
        access_token: str,
        project_ref: str,
    ) -> list[dict]:
        """Fetch RLS enable/force status per public schema table.

        Uses the Management API database/tables endpoint which returns
        schema-level metadata (no row data).

        SECURITY: Row data is NEVER read.  Only the RLS enabled/forced flags
        per table are stored.

        Returns a list of ``supabase_rls_status`` records.
        """
        try:
            data = self._get(
                f"/v1/projects/{project_ref}/database/tables",
                access_token,
                params={"included_schemas": "public"},
            )
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.warning(
                    "supabase: 403 fetching RLS status for %s — skipping.",
                    project_ref,
                )
                return [{
                    "record_type": SUPABASE_RLS_STATUS,
                    "record_id": f"supabase_rls_status:{project_ref}:_access_denied",
                    "config_fetch_warnings": [
                        "HTTP 403 fetching RLS status from database/tables endpoint. "
                        "The access token may lack the necessary Management API permissions."
                    ],
                }]
            raise

        if not isinstance(data, list):
            data = []

        records = []
        for table in data:
            if not isinstance(table, dict):
                continue
            table_name = str(table.get("name") or "")
            schema_name = str(table.get("schema") or "public")
            records.append({
                "record_type": SUPABASE_RLS_STATUS,
                "record_id": f"supabase_rls_status:{project_ref}:{schema_name}.{table_name}",
                "table_name": table_name,
                "schema_name": schema_name,
                "rls_enabled": bool(table.get("rls_enabled", False)),
                "rls_forced": bool(table.get("rls_forced", False)),
                "provider_metadata": {
                    "record_type": SUPABASE_RLS_STATUS,
                    "table_name": table_name,
                    "schema_name": schema_name,
                },
                "config_fetch_warnings": [],
            })
        return records

    def _fetch_api_config(
        self,
        access_token: str,
        project_ref: str,
    ) -> dict:
        """Fetch PostgREST / Data API configuration.

        SECURITY: anon_key and service_role_key values are NEVER stored.
        Only structural configuration (schema, max_rows) is recorded.

        Returns a ``supabase_api_config`` record.
        """
        warnings: list[str] = []

        try:
            data = self._get(
                f"/v1/projects/{project_ref}/config/postgrest",
                access_token,
            )
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.warning(
                    "supabase: 403 fetching PostgREST config for %s — skipping.",
                    project_ref,
                )
                warnings.append(
                    "HTTP 403 fetching PostgREST/API configuration. "
                    "The access token may lack the necessary Management API permissions."
                )
                data = {}
            else:
                raise

        if not isinstance(data, dict):
            data = {}

        record: dict[str, Any] = {
            "record_type": SUPABASE_API_CONFIG,
            "record_id": f"supabase_api_config:{project_ref}",
            "db_schema": str(data.get("db_schema") or "public"),
            "db_extra_search_path": str(data.get("db_extra_search_path") or ""),
            "max_rows": data.get("max_rows"),
            "config_fetch_warnings": warnings,
        }
        return record

    def _fetch_network_restrictions(
        self,
        access_token: str,
        project_ref: str,
    ) -> list[dict]:
        """Fetch network restriction (CIDR allow-list) entries.

        Returns a list of ``supabase_network_restriction`` records.
        An empty allow-list means unrestricted access.
        """
        try:
            data = self._get(
                f"/v1/projects/{project_ref}/network-restrictions",
                access_token,
            )
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.warning(
                    "supabase: 403 fetching network restrictions for %s — skipping.",
                    project_ref,
                )
                return [{
                    "record_type": SUPABASE_NETWORK_RESTRICTION,
                    "record_id": f"supabase_network_restriction:{project_ref}:_access_denied",
                    "config_fetch_warnings": [
                        "HTTP 403 fetching Network Restrictions. "
                        "The access token may lack the necessary Management API permissions."
                    ],
                }]
            raise

        if not isinstance(data, dict):
            data = {}

        # ``allowed_ranges`` is a list of CIDR strings.
        allowed_ranges = data.get("allowed_ranges") or []
        if not isinstance(allowed_ranges, list):
            allowed_ranges = []

        if not allowed_ranges:
            # Empty list means unrestricted — represent as a single record.
            return [{
                "record_type": SUPABASE_NETWORK_RESTRICTION,
                "record_id": f"supabase_network_restriction:{project_ref}:unrestricted",
                "cidr": "",
                "is_unrestricted": True,
                "provider_metadata": {
                    "record_type": SUPABASE_NETWORK_RESTRICTION,
                },
                "config_fetch_warnings": [],
            }]

        records = []
        for cidr in allowed_ranges:
            cidr_str = str(cidr)
            is_open = cidr_str in ("0.0.0.0/0", "::/0", "")
            records.append({
                "record_type": SUPABASE_NETWORK_RESTRICTION,
                "record_id": f"supabase_network_restriction:{project_ref}:{cidr_str}",
                "cidr": cidr_str,
                "is_unrestricted": is_open,
                "provider_metadata": {
                    "record_type": SUPABASE_NETWORK_RESTRICTION,
                    "cidr": cidr_str,
                },
                "config_fetch_warnings": [],
            })
        return records

    def _fetch_custom_domain(
        self,
        access_token: str,
        project_ref: str,
    ) -> list[dict]:
        """Fetch custom domain / vanity URL configuration.

        Returns a list with at most one ``supabase_custom_domain`` record.
        Returns an empty list if the project has no custom domain configured.
        """
        try:
            data = self._get(
                f"/v1/projects/{project_ref}/custom-hostname",
                access_token,
            )
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                # 404 is expected for projects without a custom domain feature.
                logger.debug(
                    "supabase: %s fetching custom domain for %s — skipping.",
                    exc.status_code,
                    project_ref,
                )
                return []
            raise

        if not isinstance(data, dict):
            return []

        custom_domain = str(data.get("custom_hostname") or data.get("hostname") or "")
        if not custom_domain:
            return []

        return [{
            "record_type": SUPABASE_CUSTOM_DOMAIN,
            "record_id": f"supabase_custom_domain:{project_ref}:{custom_domain}",
            "custom_domain": custom_domain,
            "status": str(data.get("status") or ""),
            "provider_metadata": {
                "record_type": SUPABASE_CUSTOM_DOMAIN,
                "custom_domain": custom_domain,
            },
            "config_fetch_warnings": [],
        }]

    # ── Public interface ──────────────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Verify the access token can read project metadata.

        Makes a single GET to ``/v1/projects/{ref}`` to confirm the token
        is valid and has access to the specified project.

        Raises:
            ValueError:           Missing required credential fields.
            AuthenticationError:  Token rejected (401/403).
            ConnectorError:       Other API error.
            NetworkError:         Transport failure.
        """
        self._validate_credential_fields(credentials)
        access_token: str = credentials["access_token"]
        project_ref: str = credentials["project_ref"]

        self._get(f"/v1/projects/{project_ref}", access_token)
        return True

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all Supabase project configuration records.

        Returns a flat list of normalised record dicts, one per monitored
        configuration surface.

        SECURITY:
        * Row data (database table contents) is NEVER read.
        * Database passwords, service role keys, auth JWT secrets are NEVER
          fetched or stored.
        * Edge Function source code and env var values are NEVER stored.
        * Auth user PII is NEVER fetched.
        * Storage file contents and object names are NEVER accessed.
        * OAuth client_secret is NEVER stored; client_id is SHA-256 hashed.

        Args:
            credentials: ``{"access_token": str, "project_ref": str}``.

        Returns:
            List of normalised record dicts.

        Raises:
            ValueError:           Missing or malformed credentials.
            AuthenticationError:  Token rejected on the primary project call.
            ConnectorError:       Unrecoverable API error.
            NetworkError:         Transport-level failure.
        """
        self._validate_credential_fields(credentials)
        access_token: str = credentials["access_token"]
        project_ref: str = credentials["project_ref"]

        records: list[dict] = []

        # ── 1. Project metadata (required — fail whole sync on error) ─────────
        project_record = self._fetch_project_metadata(access_token, project_ref)
        records.append(project_record)
        # Pass the raw project data for postgres_version extraction below.
        project_data = project_record  # dict already built

        # ── 2. Auth config (fail-soft on 403) ─────────────────────────────────
        auth_record, oauth_records = self._fetch_auth_config(access_token, project_ref)
        records.append(auth_record)
        records.extend(oauth_records)

        # ── 3. Database/pooler config (fail-soft on 403) ─────────────────────
        db_record = self._fetch_database_config(access_token, project_ref, project_data)
        records.append(db_record)

        # ── 4. Storage config (fail-soft on 403) ─────────────────────────────
        storage_record = self._fetch_storage_config(access_token, project_ref)
        records.append(storage_record)

        # ── 5. Edge Functions (fail-soft on 403) ──────────────────────────────
        fn_records = self._fetch_edge_functions(access_token, project_ref)
        records.extend(fn_records)

        # ── 6. RLS status (fail-soft on 403) ─────────────────────────────────
        rls_records = self._fetch_rls_status(access_token, project_ref)
        records.extend(rls_records)

        # ── 7. PostgREST / API config (fail-soft on 403) ──────────────────────
        api_record = self._fetch_api_config(access_token, project_ref)
        records.append(api_record)

        # ── 8. Network restrictions (fail-soft on 403) ───────────────────────
        net_records = self._fetch_network_restrictions(access_token, project_ref)
        records.extend(net_records)

        # ── 9. Custom domain (fail-soft on 403/404) ───────────────────────────
        domain_records = self._fetch_custom_domain(access_token, project_ref)
        records.extend(domain_records)

        logger.debug(
            "supabase: fetched %d records for project=%s",
            len(records),
            project_ref,
        )
        return records
