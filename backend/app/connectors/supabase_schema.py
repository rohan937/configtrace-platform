"""Supabase record type constants and TypedDicts — M54.

Record types
------------
SUPABASE_PROJECT            — top-level project metadata (region, plan, status)
SUPABASE_AUTH_CONFIG        — Auth settings (email/phone/OAuth enable flags,
                              MFA, session config, password policy)
SUPABASE_DATABASE_CONFIG    — Database / connection pooler settings (no rows)
SUPABASE_STORAGE_CONFIG     — Storage service config (file size limit, allowed
                              MIME types, S3 protocol enabled)
SUPABASE_EDGE_FUNCTION      — Edge Function metadata (name, status, version,
                              env var key count — values never stored)
SUPABASE_RLS_STATUS         — RLS-enabled flag per public schema table (no row
                              data; derived from pg_catalog system tables)
SUPABASE_API_CONFIG         — PostgREST / Data API configuration (anon/service
                              role key exposure not stored — key count only)
SUPABASE_NETWORK_RESTRICTION — Allowed CIDR ranges for direct database access
SUPABASE_CUSTOM_DOMAIN      — Custom domain / vanity URL for the project
SUPABASE_OAUTH_PROVIDER     — Enabled OAuth provider entries (client_id hashed)

Required credentials
--------------------
``access_token``   — Supabase Management API personal access token
                     (starts with ``sbp_``).  Stored encrypted; never returned.
``project_ref``    — Supabase project reference string (20-char alphanumeric).
                     Stored in resource metadata but never logged.

SECURITY
--------
Row-level data is NEVER read.
Database passwords, service role keys, and auth JWT secrets are NEVER
fetched or stored.
Edge Function source code is NEVER accessed.
Auth user PII (email, phone, UID) is NEVER fetched.
Storage file contents and object names are NEVER accessed.
"""

from __future__ import annotations

from typing import Any

# ── Record type constants ─────────────────────────────────────────────────────

SUPABASE_PROJECT              = "supabase_project"
SUPABASE_AUTH_CONFIG          = "supabase_auth_config"
SUPABASE_DATABASE_CONFIG      = "supabase_database_config"
SUPABASE_STORAGE_CONFIG       = "supabase_storage_config"
SUPABASE_EDGE_FUNCTION        = "supabase_edge_function"
SUPABASE_RLS_STATUS           = "supabase_rls_status"
SUPABASE_API_CONFIG           = "supabase_api_config"
SUPABASE_NETWORK_RESTRICTION  = "supabase_network_restriction"
SUPABASE_CUSTOM_DOMAIN        = "supabase_custom_domain"
SUPABASE_OAUTH_PROVIDER       = "supabase_oauth_provider"

# ── Required credential fields ────────────────────────────────────────────────

REQUIRED_CREDENTIAL_FIELDS: tuple[str, ...] = ("access_token", "project_ref")

# ── Record TypedDicts ─────────────────────────────────────────────────────────
# All TypedDicts use total=False so partial records are safe.
# Every record carries at minimum ``record_type`` and ``record_id``.

try:
    from typing import TypedDict

    class SupabaseProjectRecord(TypedDict, total=False):
        record_type: str
        record_id: str
        project_ref: str
        name: str
        region: str
        cloud_provider: str
        status: str
        plan_id: str
        # Whether the project has a custom domain configured.
        has_custom_domain: bool
        config_fetch_warnings: list[str]

    class SupabaseAuthConfigRecord(TypedDict, total=False):
        record_type: str
        record_id: str
        # Sign-in method enable flags
        email_enabled: bool
        phone_enabled: bool
        anonymous_enabled: bool
        # MFA
        mfa_totp_enabled: bool
        # Session config (durations only — no token values)
        session_timebox_seconds: Any
        session_inactivity_timeout_seconds: Any
        # External OAuth provider count (not names/secrets)
        oauth_provider_count: int
        # Password strength policy
        password_min_length: Any
        # User rate limits (counts only)
        max_request_users_per_day: Any
        # Site URL (public)
        site_url: str
        # M57.8: additional security depth fields
        # Leaked password protection (Have I Been Pwned — password_hibp_enabled)
        leaked_password_protection_enabled: bool
        # Bot / captcha protection (security_captcha_enabled)
        captcha_enabled: bool
        # Require reauthentication on password update
        require_reauthentication_for_password_update: bool
        # Refresh token rotation (defends against token theft)
        refresh_token_rotation_enabled: bool
        # JWT access token expiry in seconds — NOT the JWT secret
        jwt_exp: Any
        # Count of additional redirect URLs — raw URLs NEVER stored
        additional_redirect_urls_count: int
        config_fetch_warnings: list[str]

    class SupabaseDatabaseConfigRecord(TypedDict, total=False):
        record_type: str
        record_id: str
        # Connection pooler settings (no passwords)
        pool_mode: str
        pool_size: Any
        default_pool_size: Any
        max_client_conn: Any
        # Postgres version (major)
        postgres_version: str
        config_fetch_warnings: list[str]

    class SupabaseStorageConfigRecord(TypedDict, total=False):
        record_type: str
        record_id: str
        # Global storage limits
        file_size_limit: Any         # bytes; None if not configured
        allowed_mime_types: Any      # list or None; file contents never accessed
        # Feature flags
        s3_protocol_enabled: bool
        config_fetch_warnings: list[str]

    class SupabaseEdgeFunctionRecord(TypedDict, total=False):
        record_type: str
        record_id: str
        function_name: str
        slug: str
        status: str
        version: Any
        # Number of env-var keys configured (values never stored)
        env_var_key_count: int
        # Whether the function is importmap-pinned
        verify_jwt: bool
        config_fetch_warnings: list[str]

    class SupabaseRlsStatusRecord(TypedDict, total=False):
        record_type: str
        record_id: str
        table_name: str
        schema_name: str
        rls_enabled: bool
        rls_forced: bool
        config_fetch_warnings: list[str]

    class SupabaseApiConfigRecord(TypedDict, total=False):
        record_type: str
        record_id: str
        # PostgREST settings (no key values)
        db_schema: str
        db_extra_search_path: str
        max_rows: Any
        # Whether anon key is exposed in the Supabase dashboard (flag only)
        config_fetch_warnings: list[str]

    class SupabaseNetworkRestrictionRecord(TypedDict, total=False):
        record_type: str
        record_id: str
        # CIDR allow-list entry
        cidr: str
        # Whether unrestricted (0.0.0.0/0 or empty list means open)
        is_unrestricted: bool
        config_fetch_warnings: list[str]

    class SupabaseCustomDomainRecord(TypedDict, total=False):
        record_type: str
        record_id: str
        custom_domain: str
        status: str
        config_fetch_warnings: list[str]

    class SupabaseOAuthProviderRecord(TypedDict, total=False):
        record_type: str
        record_id: str
        provider_name: str
        enabled: bool
        # client_id is hashed before storage (first 16 hex chars of SHA-256)
        client_id_hash: str
        config_fetch_warnings: list[str]

except ImportError:
    # Python < 3.8 fallback — TypedDicts degrade to plain dicts at runtime.
    pass
