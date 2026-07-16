"""Supabase risk classification rules — M54.

Entry point: ``classify_supabase_change(change)``

Risk levels
-----------
critical  — RLS disabled on a previously-enabled table (data may be exposed).
            Network restrictions removed entirely (database becomes publicly
            reachable).
            Anonymous auth enabled.

high      — OAuth provider added without prior review.
            All network restrictions removed (is_unrestricted=True added).
            Auth config: anonymous enabled / MFA disabled.
            Storage file size limit removed (None or very large).
            PostgREST schema changed (unexpected data exposure).
            Edge Function JWT verification disabled (verify_jwt=False).

medium    — RLS not yet enabled on a new table.
            Auth setting changed (email/phone/OAuth enabled/disabled).
            Database pooler mode or connection limits changed.
            Network restriction entry added or removed (non-unrestricted).
            Custom domain status changed.
            Edge Function status/version changed.
            OAuth provider disabled.
            Storage MIME type allow-list changed.

low       — Project metadata changed (name, region — informational).
            Session durations changed.
            Password min-length strengthened.
            Expected OAuth provider added.
            Auth config baseline captured.

Language policy
---------------
All risk_reason strings use may/could language:
  "RLS may be disabled on table X — data could be publicly readable."
  "Network restrictions may have been removed — direct database access
   could be unrestricted."

NEVER assert data was leaked, breached, or compromised.

Directionality
--------------
Security-weakening changes (RLS removed, network open, JWT verification
disabled) → higher risk.
Security-strengthening changes (RLS added, network restricted, MFA enabled)
→ low.
"""

from __future__ import annotations

from typing import Any


def _get(obj: object, field: str) -> Any:
    """Safely retrieve a field from a Change object or plain dict."""
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


# ── supabase_project ──────────────────────────────────────────────────────────

def _classify_project_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("low", "A new Supabase project was added to ConfigTrace monitoring.")
    if ct == "removed":
        return (
            "high",
            "The Supabase project record was removed — unexpected; "
            "verify the project still exists.",
        )

    if fp == "status":
        if str(new_v).lower() in ("inactive", "removed", "deleted", "paused"):
            return (
                "high",
                f"The Supabase project status changed to {new_v!r}. "
                "Verify whether the project has been paused or deleted.",
            )
        return ("medium", f"The Supabase project status changed to {new_v!r}.")

    if fp == "region":
        return (
            "medium",
            "The Supabase project region changed. "
            "Verify data residency requirements are still met.",
        )

    if fp == "has_custom_domain":
        if new_v is False:
            return (
                "medium",
                "The Supabase project custom domain was removed. "
                "Verify this is intentional.",
            )
        if new_v is None:
            return (
                "low",
                "The Supabase project's custom domain status changed, but the "
                "new state could not be determined. Review the current "
                "Supabase configuration.",
            )
        return ("low", "A custom domain was added to the Supabase project.")

    if fp == "name":
        return ("low", "The Supabase project display name changed.")

    if fp == "plan_id":
        return ("medium", f"The Supabase project plan changed to {new_v!r}.")

    return ("low", "A Supabase project metadata field changed.")


# ── supabase_auth_config ──────────────────────────────────────────────────────

def _classify_auth_config_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("low", "Supabase Auth configuration baseline captured.")
    if ct == "removed":
        return ("high", "Supabase Auth configuration record removed — unexpected.")

    if fp == "anonymous_enabled":
        if new_v is True or new_v == "true":
            return (
                "critical",
                "Anonymous authentication was enabled on this Supabase project. "
                "Anonymous users can sign in without credentials; verify this is intentional "
                "and that RLS policies restrict their data access appropriately.",
            )
        if new_v is False or new_v == "false":
            return (
                "low",
                "Anonymous authentication was disabled on this Supabase project. "
                "Users can no longer sign in anonymously.",
            )
        return (
            "medium",
            "Anonymous authentication's enabled state changed, but the new "
            "state could not be determined. Review the current Supabase "
            "Auth configuration.",
        )

    if fp == "mfa_totp_enabled":
        if new_v is False or new_v == "false":
            return (
                "high",
                "TOTP multi-factor authentication was disabled on this Supabase project. "
                "Verify this is intentional and that alternative security controls are in place.",
            )
        if new_v is True or new_v == "true":
            return (
                "low",
                "TOTP multi-factor authentication was enabled. "
                "This strengthens the security posture of the Supabase project.",
            )
        return (
            "medium",
            "TOTP multi-factor authentication's enabled state changed, but "
            "the new state could not be determined. Review the current "
            "Supabase Auth configuration.",
        )

    if fp == "email_enabled":
        if new_v is False:
            return ("medium", "Email/password sign-in was disabled in Supabase Auth.")
        if new_v is True:
            return ("low", "Email/password sign-in was enabled in Supabase Auth.")
        return (
            "low",
            "Email/password sign-in's enabled state changed, but the new "
            "state could not be determined. Review the current Supabase "
            "Auth configuration.",
        )

    if fp == "phone_enabled":
        if new_v is True or new_v == "true":
            return (
                "medium",
                "Phone number sign-in was enabled in Supabase Auth. "
                "Verify an SMS provider is configured appropriately.",
            )
        if new_v is False or new_v == "false":
            return ("medium", "Phone number sign-in was disabled in Supabase Auth.")
        return (
            "low",
            "Phone number sign-in's enabled state changed, but the new state "
            "could not be determined. Review the current Supabase Auth "
            "configuration.",
        )

    if fp == "oauth_provider_count":
        prev_v = _get(change, "prev_value")
        try:
            if int(new_v) > int(prev_v):
                return (
                    "medium",
                    "The number of configured OAuth providers increased. "
                    "Verify the new provider is intentional.",
                )
            return (
                "medium",
                "The number of configured OAuth providers decreased. "
                "Users who signed in through the removed provider may lose access.",
            )
        except (TypeError, ValueError):
            return ("medium", "The OAuth provider count changed.")

    if fp == "password_min_length":
        prev_v = _get(change, "prev_value")
        try:
            if new_v is not None and prev_v is not None and int(new_v) < int(prev_v):
                return (
                    "medium",
                    "The minimum password length was decreased in Supabase Auth. "
                    "Verify this is intentional.",
                )
        except (TypeError, ValueError):
            pass
        return ("low", "The minimum password length requirement changed in Supabase Auth.")

    if fp in ("session_timebox_seconds", "session_inactivity_timeout_seconds"):
        return ("low", "A Supabase Auth session duration setting changed.")

    if fp == "site_url":
        # site_url is the base for OAuth redirect/callback URLs and for
        # password-reset / email-confirm links. An unexpected change here
        # can hijack OAuth callbacks or steer users to a phishing endpoint
        # → high.
        return (
            "high",
            "The Supabase Auth site URL changed. OAuth callbacks, password "
            "reset links, and email confirmation links resolve against this "
            "URL — verify the new value is controlled by your team and "
            "remove any unknown additional redirect URLs.",
        )

    if fp == "max_request_users_per_day":
        return ("low", "The Supabase Auth anonymous user rate limit changed.")

    # ── M57.8: additional security depth fields ───────────────────────────────

    if fp == "leaked_password_protection_enabled":
        if new_v is False or new_v == "false":
            return (
                "high",
                "Leaked password protection (Have I Been Pwned integration) was disabled "
                "in Supabase Auth. Users may be permitted to set passwords that have appeared "
                "in known data breaches. Verify this is intentional.",
            )
        if new_v is True or new_v == "true":
            return (
                "low",
                "Leaked password protection was enabled in Supabase Auth. "
                "Users will be warned or blocked when choosing compromised passwords.",
            )
        return (
            "medium",
            "Leaked password protection's enabled state changed, but the new "
            "state could not be determined. Review the current Supabase "
            "Auth configuration.",
        )

    if fp == "captcha_enabled":
        if new_v is False or new_v == "false":
            return (
                "medium",
                "CAPTCHA bot protection was disabled in Supabase Auth. "
                "Sign-in and sign-up endpoints may become more susceptible to automated attacks.",
            )
        if new_v is True or new_v == "true":
            return (
                "low",
                "CAPTCHA bot protection was enabled in Supabase Auth.",
            )
        return (
            "low",
            "CAPTCHA bot protection's enabled state changed, but the new "
            "state could not be determined. Review the current Supabase "
            "Auth configuration.",
        )

    if fp == "require_reauthentication_for_password_update":
        if new_v is False or new_v == "false":
            return (
                "medium",
                "Reauthentication requirement for password updates was disabled in Supabase Auth. "
                "Users may be able to change their password without recent authentication.",
            )
        if new_v is True or new_v == "true":
            return (
                "low",
                "Reauthentication is now required before users can update their password.",
            )
        return (
            "medium",
            "The password-update reauthentication requirement changed, but "
            "the new state could not be determined. Review the current "
            "Supabase Auth configuration.",
        )

    if fp == "refresh_token_rotation_enabled":
        if new_v is False or new_v == "false":
            # Disabling rotation widens the window in which a stolen refresh
            # token can be reused without detection, and removes Supabase's
            # built-in defence against token theft → high.
            return (
                "high",
                "Refresh token rotation was disabled in Supabase Auth. "
                "Without rotation, a stolen refresh token can be reused "
                "indefinitely without detection. Verify this is intentional.",
            )
        if new_v is True or new_v == "true":
            return (
                "low",
                "Refresh token rotation was enabled. "
                "Each refresh produces a new token pair, reducing the window for token reuse.",
            )
        return (
            "medium",
            "Refresh token rotation's enabled state changed, but the new "
            "state could not be determined. Review the current Supabase "
            "Auth configuration.",
        )

    if fp == "jwt_exp":
        prev_v = _get(change, "prev_value")
        try:
            old_exp = int(prev_v) if prev_v is not None else None
            new_exp = int(new_v) if new_v is not None else None
            if old_exp is not None and new_exp is not None and new_exp > old_exp:
                # A ≥2× extension of the JWT lifetime materially widens
                # the exposure window for a stolen access token, so we
                # treat it as high rather than medium.
                if old_exp > 0 and new_exp >= old_exp * 2:
                    return (
                        "high",
                        f"Supabase JWT access token expiry increased significantly "
                        f"(from {old_exp}s to {new_exp}s, ≥2×). Longer-lived tokens "
                        "materially widen the exposure window if a token is "
                        "compromised — confirm this is intentional.",
                    )
                return (
                    "medium",
                    f"Supabase JWT access token expiry increased from {old_exp}s to {new_exp}s. "
                    "Longer-lived tokens may increase the window of exposure if a token is compromised.",
                )
        except (TypeError, ValueError):
            pass
        return (
            "low",
            f"Supabase JWT access token expiry changed to {new_v}s.",
        )

    if fp == "additional_redirect_urls_count":
        prev_v = _get(change, "prev_value")
        try:
            if int(new_v) > int(prev_v):
                return (
                    "medium",
                    "The number of additional redirect URLs in Supabase Auth increased. "
                    "Verify that new redirect targets are legitimate and expected.",
                )
        except (TypeError, ValueError):
            pass
        return (
            "low",
            "The number of additional redirect URLs in Supabase Auth changed.",
        )

    return ("medium", "A Supabase Auth configuration setting changed.")


# ── supabase_database_config ──────────────────────────────────────────────────

def _classify_database_config_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("low", "Supabase database configuration baseline captured.")
    if ct == "removed":
        return ("medium", "Supabase database configuration record removed — unexpected.")

    if fp == "pool_mode":
        return (
            "medium",
            f"The Supabase connection pooler mode changed to {new_v!r}. "
            "Verify the new mode is appropriate for your workload.",
        )

    if fp in ("pool_size", "default_pool_size", "max_client_conn"):
        return ("medium", f"A Supabase connection pooler limit changed ({fp} → {new_v}).")

    if fp == "postgres_version":
        return (
            "low",
            f"The Supabase Postgres version changed to {new_v!r}. "
            "Verify the upgrade is intentional.",
        )

    return ("low", "A Supabase database configuration field changed.")


# ── supabase_storage_config ───────────────────────────────────────────────────

def _classify_storage_config_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")
    prev_v = _get(change, "prev_value")

    if ct == "added":
        return ("low", "Supabase Storage configuration baseline captured.")
    if ct == "removed":
        return ("medium", "Supabase Storage configuration record removed — unexpected.")

    if fp == "file_size_limit":
        # If limit is removed (None) or significantly increased, flag it.
        if new_v is None:
            return (
                "high",
                "The Supabase Storage file size limit was removed. "
                "Users may upload arbitrarily large files. "
                "Verify this is intentional.",
            )
        try:
            # Flag if limit increased by more than 10× (e.g. 50MB→500MB)
            if prev_v is not None and int(new_v) > int(prev_v) * 10:
                return (
                    "medium",
                    "The Supabase Storage file size limit increased significantly. "
                    "Verify the new limit is appropriate.",
                )
        except (TypeError, ValueError):
            pass
        return ("low", "The Supabase Storage file size limit changed.")

    if fp == "allowed_mime_types":
        if new_v is None or new_v == []:
            # An empty MIME allow-list means any file type can be uploaded
            # — executables, HTML, malware, etc. This materially widens
            # the attack surface for user-supplied content → high.
            return (
                "high",
                "The Supabase Storage allowed MIME types restriction was removed. "
                "Any file type — including executables, HTML, and unverified "
                "content — may now be uploaded. Restore an explicit allow-list.",
            )
        return ("medium", "The Supabase Storage allowed MIME types list changed.")

    if fp == "s3_protocol_enabled":
        if new_v is True:
            return (
                "medium",
                "The S3-compatible protocol was enabled for Supabase Storage. "
                "Verify that access policies are correctly configured.",
            )
        if new_v is False:
            return ("low", "The S3-compatible protocol for Supabase Storage was disabled.")
        return (
            "low",
            "The S3-compatible protocol's enabled state changed for Supabase "
            "Storage, but the new state could not be determined. Review the "
            "current Supabase Storage configuration.",
        )

    return ("low", "A Supabase Storage configuration field changed.")


# ── supabase_edge_function ────────────────────────────────────────────────────

def _classify_edge_function_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")
    pm = (_get(change, "provider_metadata") or {})
    fn_name = pm.get("function_name") or pm.get("slug") or "" if isinstance(pm, dict) else ""

    if ct == "added":
        return ("low", f"A new Supabase Edge Function was added ({fn_name}).")
    if ct == "removed":
        return ("medium", f"A Supabase Edge Function was removed ({fn_name}).")

    if fp == "verify_jwt":
        if new_v is False:
            return (
                "high",
                f"JWT verification was disabled for Supabase Edge Function {fn_name!r}. "
                "The function may now be callable without a valid JWT. "
                "Verify this is intentional.",
            )
        if new_v is True:
            return (
                "low",
                f"JWT verification was enabled for Supabase Edge Function {fn_name!r}. "
                "Callers must now provide a valid JWT.",
            )
        return (
            "medium",
            f"JWT verification status for Supabase Edge Function {fn_name!r} "
            "changed, but the new state could not be determined. Review the "
            "function's JWT verification setting.",
        )

    if fp == "status":
        if str(new_v).lower() in ("failed", "error"):
            return (
                "medium",
                f"Supabase Edge Function {fn_name!r} status changed to {new_v!r}. "
                "Verify the function is healthy.",
            )
        return ("low", f"Supabase Edge Function {fn_name!r} status changed to {new_v!r}.")

    if fp == "env_var_key_count":
        return (
            "medium",
            f"The number of environment variable keys for Supabase Edge Function "
            f"{fn_name!r} changed. "
            "(ConfigTrace does not store environment variable values.)",
        )

    if fp == "version":
        return ("low", f"The version of Supabase Edge Function {fn_name!r} changed.")

    return ("low", f"A Supabase Edge Function metadata field changed ({fn_name}).")


# ── supabase_rls_status ───────────────────────────────────────────────────────

def _classify_rls_status_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")
    pm = (_get(change, "provider_metadata") or {})
    table_name = pm.get("table_name") or "" if isinstance(pm, dict) else ""
    schema_name = pm.get("schema_name") or "public" if isinstance(pm, dict) else "public"
    full_name = f"{schema_name}.{table_name}" if table_name else schema_name

    if ct == "added":
        # New table appeared — inspect its own rls_enabled posture rather
        # than the truthiness of the whole new-record dict (a populated
        # dict is always truthy, so a plain `if not new_v` never actually
        # distinguished RLS-off from RLS-on for a real added record — this
        # previously misclassified every newly added table as "added with
        # RLS enabled" regardless of its real posture).
        added_record = new_v if isinstance(new_v, dict) else {}
        added_rls = added_record.get("rls_enabled")
        if added_rls is False:
            return (
                "medium",
                f"A new table {full_name!r} was found without Row Level Security enabled. "
                "Verify that the table does not expose data that requires RLS protection.",
            )
        if added_rls is True:
            return ("low", f"A new table {full_name!r} was added with RLS enabled.")
        return (
            "medium",
            f"A new table {full_name!r} was found, but its Row Level Security "
            "status could not be determined. Review the table's RLS "
            "configuration.",
        )

    if ct == "removed":
        return (
            "medium",
            f"The RLS status record for table {full_name!r} was removed — "
            "the table may have been dropped.",
        )

    if fp == "rls_enabled":
        if new_v is False:
            return (
                "critical",
                f"Row Level Security was disabled on table {full_name!r}. "
                "All authenticated (and potentially anonymous) users may now be able to "
                "read or modify all rows in this table. "
                "Verify this is intentional immediately.",
            )
        if new_v is True:
            # RLS was enabled — security strengthened
            return (
                "low",
                f"Row Level Security was enabled on table {full_name!r}. "
                "This is a security improvement.",
            )
        return (
            "medium",
            f"Row Level Security status for table {full_name!r} changed, but "
            "the new state could not be determined. Review the table's RLS "
            "configuration.",
        )

    if fp == "rls_forced":
        if new_v is False:
            return (
                "high",
                f"Row Level Security 'forced' flag was removed on table {full_name!r}. "
                "Table owners may now bypass RLS. "
                "Verify this is intentional.",
            )
        if new_v is None:
            return (
                "medium",
                f"Row Level Security 'forced' flag for table {full_name!r} "
                "changed, but the new state could not be determined. Review "
                "the table's RLS configuration.",
            )
        return (
            "low",
            f"Row Level Security 'forced' flag was enabled on table {full_name!r}. "
            "RLS now applies to table owners as well.",
        )

    # ── M71A — per-table public-policy posture ────────────────────────────────
    if fp == "has_public_select_policy":
        if new_v is True:
            return (
                "high",
                f"A policy targeting the public/anon role was added allowing SELECT "
                f"on table {full_name!r}. This may expose data depending on grants "
                "and application access. Verify this is intentional.",
            )
        if new_v is False:
            return (
                "low",
                f"The public/anon SELECT policy on table {full_name!r} was removed.",
            )
        return (
            "medium",
            f"The public/anon SELECT policy status for table {full_name!r} "
            "changed, but the new state could not be determined. Review the "
            "table's policies.",
        )

    if fp in (
        "has_public_insert_policy",
        "has_public_update_policy",
        "has_public_delete_policy",
    ):
        if new_v is True:
            return (
                "high",
                f"A policy targeting the public/anon role was added allowing a "
                f"write ({fp.replace('has_public_', '').replace('_policy', '')}) "
                f"on table {full_name!r}. This may allow broad writes depending on "
                "grants and application access. Verify this is intentional.",
            )
        if new_v is False:
            return (
                "low",
                f"A public/anon write policy on table {full_name!r} was removed.",
            )
        return (
            "medium",
            f"A public/anon write policy status for table {full_name!r} "
            "changed, but the new state could not be determined. Review the "
            "table's policies.",
        )

    if fp == "exposed_to_anon":
        if new_v is True:
            return (
                "medium",
                f"Table {full_name!r} now has at least one policy targeting the "
                "public/anon role. Review the table's policies for intended access.",
            )
        if new_v is False:
            return (
                "low",
                f"Table {full_name!r} no longer has any policy targeting the "
                "public/anon role.",
            )
        return (
            "low",
            f"Table {full_name!r}'s public/anon policy exposure changed, but "
            "the new state could not be determined. Review the table's "
            "policies.",
        )

    if fp == "policy_count":
        prev_v = _get(change, "prev_value")
        try:
            if int(new_v) < int(prev_v):
                return (
                    "medium",
                    f"The policy count for table {full_name!r} decreased. "
                    "Verify access is still scoped as intended.",
                )
        except (TypeError, ValueError):
            pass
        return ("low", f"The policy count for table {full_name!r} changed.")

    return ("medium", f"An RLS configuration field changed for table {full_name!r}.")


# ── supabase_api_config ───────────────────────────────────────────────────────

def _classify_api_config_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("low", "Supabase PostgREST/API configuration baseline captured.")
    if ct == "removed":
        return ("medium", "Supabase PostgREST/API configuration record removed — unexpected.")

    if fp == "db_schema":
        return (
            "high",
            f"The Supabase PostgREST exposed schema changed to {new_v!r}. "
            "Verify the new schema does not expose unintended tables or data.",
        )

    if fp == "db_extra_search_path":
        return (
            "medium",
            "The Supabase PostgREST extra search path changed. "
            "Verify the new search path does not expose unintended schema data.",
        )

    if fp == "max_rows":
        prev_v = _get(change, "prev_value")
        try:
            if new_v is None or (prev_v is not None and int(new_v) > int(prev_v) * 5):
                return (
                    "medium",
                    "The Supabase PostgREST maximum rows limit was increased significantly or removed. "
                    "Verify this is intentional to avoid excessive data exposure.",
                )
        except (TypeError, ValueError):
            pass
        return ("low", "The Supabase PostgREST maximum rows limit changed.")

    return ("low", "A Supabase PostgREST/API configuration field changed.")


# ── supabase_network_restriction ──────────────────────────────────────────────

def _classify_network_restriction_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    new_v = _get(change, "new_value")
    pm = (_get(change, "provider_metadata") or {})
    cidr = pm.get("cidr") or "" if isinstance(pm, dict) else ""

    if ct == "added":
        # is_unrestricted=True on the newly added record means restrictions
        # were opened (the "unrestricted" sentinel record only ever appears
        # once every explicit CIDR entry has been removed). For "added"
        # Changes, new_value is the FULL new record dict, not a scalar — a
        # dict can never be `is True`, so the previous `new_v is True` /
        # `fp == "is_unrestricted"` checks here were always False (fp is
        # empty for whole-record add/remove events) and this critical case
        # silently fell through to the generic "low" bucket below with
        # backwards copy claiming access was "now limited".
        added_record = new_v if isinstance(new_v, dict) else {}
        if added_record.get("is_unrestricted") is True:
            return (
                "critical",
                "Supabase database network restrictions were removed — the direct database "
                "connection port may now be reachable from any IP address. "
                "Verify this is intentional.",
            )
        if cidr in ("0.0.0.0/0", "::/0"):
            return (
                "critical",
                "A wildcard CIDR (0.0.0.0/0 or ::/0) was added to Supabase network restrictions — "
                "the direct database port may now be reachable from any IP. "
                "Verify this is intentional.",
            )
        return (
            "low",
            f"A network restriction CIDR was added ({cidr or 'unrestricted'}). "
            "Direct database access is now limited to the listed addresses.",
        )

    if ct == "removed":
        if cidr and cidr not in ("0.0.0.0/0", "::/0"):
            return (
                "high",
                f"A network restriction CIDR was removed ({cidr}). "
                "Verify that the direct database port is not now reachable from unexpected addresses.",
            )
        return (
            "medium",
            "A Supabase network restriction entry was removed.",
        )

    if fp == "is_unrestricted":
        if new_v is True:
            return (
                "critical",
                "Supabase database network restrictions were removed — the direct database "
                "connection port may now be reachable from any IP address. "
                "Verify this is intentional.",
            )
        if new_v is False:
            return (
                "low",
                "Supabase database network restrictions were reinstated. "
                "Direct database access is now limited to specified CIDRs.",
            )
        # is_unrestricted is always a real bool from the connector today
        # (the 403 path now returns an empty list rather than a record with
        # this field set to None) — this branch is defensive only.
        return (
            "medium",
            "Supabase database network restriction status changed, but the "
            "new state could not be determined. Review the current network "
            "restriction configuration.",
        )

    if fp == "cidr":
        return (
            "medium",
            f"A Supabase network restriction CIDR changed to {new_v!r}. "
            "Verify this change is expected.",
        )

    return ("medium", "A Supabase network restriction record changed.")


# ── supabase_custom_domain ────────────────────────────────────────────────────

def _classify_custom_domain_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    new_v = _get(change, "new_value")
    pm = (_get(change, "provider_metadata") or {})
    domain = pm.get("custom_domain") or "" if isinstance(pm, dict) else ""

    if ct == "added":
        return (
            "low",
            f"A custom domain was added to the Supabase project ({domain}). "
            "Verify the domain is correctly configured and belongs to your application.",
        )
    if ct == "removed":
        return (
            "medium",
            f"The Supabase project custom domain was removed ({domain}). "
            "API and Auth endpoints will revert to the default Supabase URL.",
        )

    if fp == "status":
        return (
            "medium",
            f"The Supabase custom domain status changed to {new_v!r} ({domain}). "
            "Verify the domain configuration is correct.",
        )

    if fp == "custom_domain":
        return (
            "medium",
            f"The Supabase custom domain was changed to {new_v!r}. "
            "Verify the new domain is correctly configured.",
        )

    return ("medium", f"A Supabase custom domain configuration changed ({domain}).")


# ── supabase_oauth_provider ───────────────────────────────────────────────────

def _classify_oauth_provider_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    new_v = _get(change, "new_value")
    pm = (_get(change, "provider_metadata") or {})
    provider_name = pm.get("provider_name") or "" if isinstance(pm, dict) else ""

    if ct == "added":
        return (
            "medium",
            f"An OAuth provider was added to Supabase Auth ({provider_name}). "
            "Verify the provider configuration is correct and intentional.",
        )
    if ct == "removed":
        # Per audit policy (Supabase brief): OAuth provider add/remove is
        # medium unless additional risky details are present. A removal is
        # an availability/login issue, not a security weakening.
        return (
            "medium",
            f"An OAuth provider was removed from Supabase Auth ({provider_name}). "
            "Users who signed in through this provider may lose access.",
        )

    if fp == "enabled":
        if new_v is True or new_v == "true":
            return (
                "medium",
                f"Supabase Auth OAuth provider {provider_name!r} was enabled. "
                "Users can now sign in using this provider.",
            )
        if new_v is False or new_v == "false":
            return (
                "medium",
                f"Supabase Auth OAuth provider {provider_name!r} was disabled. "
                "Users who signed in through this provider may be affected.",
            )
        return (
            "medium",
            f"Supabase Auth OAuth provider {provider_name!r} enabled state "
            "changed, but the new state could not be determined. Review the "
            "current OAuth provider configuration.",
        )

    if fp == "client_id_hash":
        return (
            "medium",
            f"The client ID for Supabase Auth OAuth provider {provider_name!r} changed. "
            "Verify the new OAuth application credentials are correct.",
        )

    return ("medium", f"A Supabase Auth OAuth provider setting changed ({provider_name}).")


# ── Main dispatcher ────────────────────────────────────────────────────────────

def classify_supabase_change(change: object) -> tuple[str, str]:
    """Return (risk_level, risk_reason) for a Supabase change.

    Dispatches to a per-record-type classifier.  Returns
    ``("low", "…")`` as a safe fallback for unrecognised record types.
    """
    pm = _get(change, "provider_metadata") or {}
    record_type = (pm.get("record_type") or "").lower() if isinstance(pm, dict) else ""

    if record_type == "supabase_project":
        return _classify_project_change(change)
    if record_type == "supabase_auth_config":
        return _classify_auth_config_change(change)
    if record_type == "supabase_database_config":
        return _classify_database_config_change(change)
    if record_type == "supabase_storage_config":
        return _classify_storage_config_change(change)
    if record_type == "supabase_edge_function":
        return _classify_edge_function_change(change)
    if record_type == "supabase_rls_status":
        return _classify_rls_status_change(change)
    if record_type == "supabase_api_config":
        return _classify_api_config_change(change)
    if record_type == "supabase_network_restriction":
        return _classify_network_restriction_change(change)
    if record_type == "supabase_custom_domain":
        return _classify_custom_domain_change(change)
    if record_type == "supabase_oauth_provider":
        return _classify_oauth_provider_change(change)

    return ("low", f"A Supabase configuration record changed ({record_type}).")
