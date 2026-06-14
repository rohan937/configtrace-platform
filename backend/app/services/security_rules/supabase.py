"""Supabase security exposure rules — M60.4 / M60.4.4 / M71A.

Every rule fires only on explicit, reliable normalized fields produced by the
Supabase connector (app/connectors/supabase.py + supabase_schema.py). Evidence
is metadata-only: schema/table names, policy posture booleans, auth setting
booleans/numbers, Edge Function names + verify_jwt flag. No rows, user records,
emails, tokens, service-role keys, JWT secrets, policy expressions, or Edge
Function secret values are ever read or stored.

CLAIM DISCIPLINE: a finding is evidence for review of a configuration that may
expose data depending on grants and application access, or may increase
unauthorized-access risk. It never asserts that data leaked, that users were
exposed, that anyone gained access, that access was unauthorized, or that a
breach/compromise occurred.

Record types consumed
---------------------
- ``supabase_rls_status``    → RLS disabled, or a public/anon policy on a table
- ``supabase_auth_config``   → anon sign-ins / long JWT expiry / missing
                               leaked-password protection
- ``supabase_edge_function`` → Edge Function with JWT verification disabled

Deferred Supabase rules (intentionally NOT implemented — see report)
-------------------------------------------------------------------
* RLS disabled on a public schema table (rule A): already covered by
  ``supabase_rls_disabled`` (it fires on schema=public + rls_enabled=false), so a
  separate ``supabase_rls_disabled_public_table`` key would double-flag the same
  state. Not added.
* Public storage bucket (rule D): listing storage buckets + their public/private
  status requires the project's service-role/anon key, which ConfigTrace
  deliberately does NOT store or use. The Management API exposes no safe bucket
  list. Deferred — never invented.
* Auth redirect URL too broad (rule F): the connector stores only
  ``additional_redirect_urls_count`` (a count) and never the raw redirect URLs
  or patterns, so wildcard/localhost cannot be evaluated. Deferred.
"""

from __future__ import annotations

import re
from typing import Any

from app.connectors.supabase_schema import (
    SUPABASE_AUTH_CONFIG,
    SUPABASE_EDGE_FUNCTION,
    SUPABASE_RLS_STATUS,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

_RULE_RLS_DISABLED = "supabase_rls_disabled"
_RULE_ANON_ENABLED = "supabase_anonymous_access_enabled"
_RULE_JWT_LONG = "supabase_jwt_expiry_long"
# M71A
_RULE_PUBLIC_SELECT_SENSITIVE = "supabase_public_select_sensitive_table"
_RULE_PUBLIC_WRITE = "supabase_public_write_policy"
_RULE_EDGE_JWT_DISABLED = "supabase_edge_function_jwt_disabled"
_RULE_AUTH_PROTECTION_MISSING = "supabase_auth_protection_missing"

# JWT access-token lifetime beyond this (seconds) is treated as too long.
_JWT_MAX_SECONDS = 86_400

# Table-name tokens that suggest sensitive data (public read is higher risk).
_SENSITIVE_TABLE_TOKENS = frozenset({
    "user", "users", "customer", "customers", "payment", "payments", "order",
    "orders", "account", "accounts", "profile", "profiles", "session", "sessions",
    "token", "tokens", "apikey", "apikeys", "secret", "secrets", "credential",
    "credentials", "billing", "invoice", "invoices", "subscription", "subscriptions",
})

# Edge Function-name tokens that raise the severity of disabled JWT verification.
_SENSITIVE_FN_TOKENS = frozenset({
    "admin", "internal", "private", "secret", "webhook", "payment", "payments",
    "billing", "delete", "user", "users", "account", "accounts",
})


def _tokens(name: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", name.lower()) if t}


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == SUPABASE_RLS_STATUS:
        return _eval_rls(record)
    if rtype == SUPABASE_AUTH_CONFIG:
        return _eval_auth_config(record)
    if rtype == SUPABASE_EDGE_FUNCTION:
        return _eval_edge_function(record)
    return []


# ── RLS status: disabled (M60.4) + public-policy posture (M71A) ──────────────


def _eval_rls(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    table = get_str(record, "table_name")
    schema = get_str(record, "schema_name") or "public"
    record_id = get_str(record, "record_id") or None
    where = f"{schema}.{table}" if table else (record_id or "a table")

    # ── RLS disabled (unchanged) — fires only on an explicit False. ───────────
    rls_off = "rls_enabled" in record and record.get("rls_enabled") is False
    if rls_off:
        out.append(
            FindingCandidate(
                provider="supabase",
                rule_key=_RULE_RLS_DISABLED,
                finding_key=make_finding_key(_RULE_RLS_DISABLED, record_id),
                severity="high",
                title="Supabase table has Row Level Security disabled",
                description=(
                    f"Row Level Security is disabled on {where}. Without RLS, rows "
                    f"may be broadly readable or writable depending on grants and "
                    f"application access. This is evidence for review and does not "
                    f"confirm data exposure or unauthorized access."
                ),
                evidence={"rule": _RULE_RLS_DISABLED, "schema": schema, "table": table},
                remediation={
                    "summary": "Enable Row Level Security and add explicit policies.",
                    "steps": [
                        "Enable RLS on the table.",
                        "Add policies that scope access to the intended roles.",
                        "Verify application access still works under the new policies.",
                    ],
                },
                record_id=record_id,
            )
        )

    # M71A public-policy rules apply only when RLS is ENABLED (policies are then
    # active). When RLS is off the disabled-RLS rule already covers the exposure.
    rls_on = record.get("rls_enabled") is True

    # ── B. Public/anon SELECT policy on a sensitively-named table (high). ─────
    if rls_on and record.get("has_public_select_policy") is True and table and (
        _tokens(table) & _SENSITIVE_TABLE_TOKENS
    ):
        out.append(
            FindingCandidate(
                provider="supabase",
                rule_key=_RULE_PUBLIC_SELECT_SENSITIVE,
                finding_key=make_finding_key(_RULE_PUBLIC_SELECT_SENSITIVE, record_id),
                severity="high",
                title="Supabase public read policy on a sensitive-looking table",
                description=(
                    f"A policy targeting the public/anon role allows SELECT on "
                    f"{where}, whose name suggests sensitive data. This may expose "
                    f"data depending on grants and application access. This is "
                    f"evidence for review and does not confirm data exposure or "
                    f"unauthorized access."
                ),
                evidence={
                    "rule": _RULE_PUBLIC_SELECT_SENSITIVE, "schema": schema,
                    "table": table, "policy_count": record.get("policy_count"),
                },
                remediation={
                    "summary": "Scope read access away from the public/anon role.",
                    "steps": [
                        "Review the table's policies and the public/anon SELECT grant.",
                        "Restrict reads to authenticated, row-scoped policies.",
                    ],
                },
                record_id=record_id,
            )
        )

    # ── C. Public/anon write policy (insert/update/delete) on any table (high). ─
    if rls_on and any(
        record.get(k) is True for k in (
            "has_public_insert_policy", "has_public_update_policy", "has_public_delete_policy"
        )
    ):
        actions = [
            a for a, k in (
                ("insert", "has_public_insert_policy"),
                ("update", "has_public_update_policy"),
                ("delete", "has_public_delete_policy"),
            ) if record.get(k) is True
        ]
        out.append(
            FindingCandidate(
                provider="supabase",
                rule_key=_RULE_PUBLIC_WRITE,
                finding_key=make_finding_key(_RULE_PUBLIC_WRITE, record_id),
                severity="high",
                title="Supabase public write policy on a table",
                description=(
                    f"A policy targeting the public/anon role allows "
                    f"{', '.join(actions)} on {where}. This may allow broad writes "
                    f"depending on grants and application access. This is evidence "
                    f"for review and does not confirm unauthorized access or "
                    f"compromise."
                ),
                evidence={
                    "rule": _RULE_PUBLIC_WRITE, "schema": schema, "table": table,
                    "policy_count": record.get("policy_count"),
                },
                remediation={
                    "summary": "Restrict write access away from the public/anon role.",
                    "steps": [
                        "Review the table's insert/update/delete policies.",
                        "Scope writes to authenticated, ownership-checked policies.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Auth config (M60.4.4 + M71A) ─────────────────────────────────────────────


def _eval_auth_config(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or "auth_config"

    if record.get("anonymous_enabled") is True:
        out.append(
            FindingCandidate(
                provider="supabase",
                rule_key=_RULE_ANON_ENABLED,
                finding_key=make_finding_key(_RULE_ANON_ENABLED, record_id),
                severity="medium",
                title="Supabase anonymous sign-ins are enabled",
                description=(
                    "Anonymous authentication is enabled. Combined with weak or "
                    "missing Row Level Security, this may allow unauthenticated "
                    "users to read or write data."
                ),
                evidence={"rule": _RULE_ANON_ENABLED, "anonymous_enabled": True},
                remediation={
                    "summary": "Disable anonymous sign-ins if not required.",
                    "steps": [
                        "Turn off anonymous sign-ins unless your app needs them.",
                        "If kept, ensure RLS strictly scopes anonymous access.",
                    ],
                },
                record_id=record_id,
            )
        )

    jwt_exp = record.get("jwt_exp")
    if isinstance(jwt_exp, int) and not isinstance(jwt_exp, bool) and jwt_exp > _JWT_MAX_SECONDS:
        out.append(
            FindingCandidate(
                provider="supabase",
                rule_key=_RULE_JWT_LONG,
                finding_key=make_finding_key(_RULE_JWT_LONG, record_id),
                severity="medium",
                title="Supabase JWT expiry is very long",
                description=(
                    f"The JWT access-token lifetime is {jwt_exp} seconds "
                    f"(over a day). Long-lived tokens stay valid well after a "
                    f"user signs out and widen the impact of a leaked token."
                ),
                evidence={"rule": _RULE_JWT_LONG, "jwt_exp_seconds": jwt_exp},
                remediation={
                    "summary": "Shorten the JWT expiry toward the default.",
                    "steps": [
                        "Reduce the access-token lifetime (e.g. 3600s).",
                        "Rely on refresh-token rotation for longer sessions.",
                    ],
                },
                record_id=record_id,
            )
        )

    # ── G. Leaked-password (HIBP) protection disabled (M71A). ────────────────
    # Only an explicit False fires; missing/unknown is skipped.
    if record.get("leaked_password_protection_enabled") is False:
        mfa_off = record.get("mfa_totp_enabled") is False
        out.append(
            FindingCandidate(
                provider="supabase",
                rule_key=_RULE_AUTH_PROTECTION_MISSING,
                finding_key=make_finding_key(_RULE_AUTH_PROTECTION_MISSING, record_id),
                severity="medium",
                title="Supabase leaked-password protection is disabled",
                description=(
                    "Leaked-password protection (Have I Been Pwned) is disabled, so "
                    "users may set passwords known to be compromised"
                    + (" and multi-factor authentication is also not enabled" if mfa_off else "")
                    + ". This may increase unauthorized-access risk. This is "
                    "evidence for review and does not confirm unauthorized access "
                    "or compromise."
                ),
                evidence={
                    "rule": _RULE_AUTH_PROTECTION_MISSING,
                    "leaked_password_protection_enabled": False,
                    "mfa_totp_enabled": bool(record.get("mfa_totp_enabled")),
                },
                remediation={
                    "summary": "Enable leaked-password protection (and consider MFA).",
                    "steps": [
                        "Enable the Have I Been Pwned leaked-password check.",
                        "Consider enabling/encouraging multi-factor authentication.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Edge Functions (M71A) ─────────────────────────────────────────────────────


def _eval_edge_function(record: dict[str, Any]) -> list[FindingCandidate]:
    # Only an explicit verify_jwt=False fires; missing/unknown is skipped.
    if "verify_jwt" not in record or record.get("verify_jwt") is not False:
        return []
    record_id = get_str(record, "record_id") or None
    fn_name = get_str(record, "function_name") or get_str(record, "slug") or "an Edge Function"
    sensitive = bool(_tokens(fn_name) & _SENSITIVE_FN_TOKENS)

    return [
        FindingCandidate(
            provider="supabase",
            rule_key=_RULE_EDGE_JWT_DISABLED,
            finding_key=make_finding_key(_RULE_EDGE_JWT_DISABLED, record_id),
            severity="high" if sensitive else "medium",
            title="Supabase Edge Function has JWT verification disabled",
            description=(
                f"Edge Function '{fn_name}' has JWT verification disabled "
                f"(verify_jwt=false), so it accepts unauthenticated requests. "
                f"Depending on what the function does, this may increase "
                f"unauthorized-access risk. This is evidence for review and does "
                f"not confirm unauthorized access or compromise."
            ),
            evidence={
                "rule": _RULE_EDGE_JWT_DISABLED,
                "function_name": fn_name,
                "verify_jwt": False,
            },
            remediation={
                "summary": "Enable JWT verification unless the function is intentionally public.",
                "steps": [
                    "Confirm whether the function must accept unauthenticated calls.",
                    "Enable verify_jwt, or add explicit in-function authorization.",
                ],
            },
            record_id=record_id,
        )
    ]
