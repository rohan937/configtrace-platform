"""Supabase security exposure rules — M60.4 / expanded in M60.4.4.

Every rule fires only on explicit, reliable normalized fields produced by the
Supabase connector (app/connectors/supabase.py + supabase_schema.py). Evidence
is metadata-only: schema/table names, auth setting booleans/numbers. No rows,
user records, tokens, or service-role keys are ever read.

Record types consumed
---------------------
- ``supabase_rls_status``  → a table with Row Level Security disabled
- ``supabase_auth_config`` → anonymous sign-ins enabled / very long JWT expiry

Deferred Supabase rules (intentionally NOT implemented — see report)
-------------------------------------------------------------------
* Public table / public read-write POLICY: there is no per-policy record type;
  only table-level ``rls_enabled`` is captured, so we cannot read a policy's
  roles/actions. The RLS-disabled rule covers the "no row protection" case.
* Public storage bucket: ``supabase_storage_config`` carries only file-size
  limit, allowed MIME types, and an s3-protocol flag — there is NO per-bucket
  public/private signal. Deferred.
* Email confirmation disabled: ``supabase_auth_config`` exposes ``email_enabled``
  (provider on/off) but NO email-confirmation / autoconfirm field. Deferred.
"""

from __future__ import annotations

from typing import Any

from app.connectors.supabase_schema import (
    SUPABASE_AUTH_CONFIG,
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

# JWT access-token lifetime beyond this (seconds) is treated as too long.
# Supabase's default is 3600s (1 hour); >1 day widens the stolen-token window.
_JWT_MAX_SECONDS = 86_400


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == SUPABASE_RLS_STATUS:
        return _eval_rls(record)
    if rtype == SUPABASE_AUTH_CONFIG:
        return _eval_auth_config(record)
    return []


# ── RLS disabled (M60.4, unchanged) ──────────────────────────────────────────


def _eval_rls(record: dict[str, Any]) -> list[FindingCandidate]:
    # Only fire when the field is explicitly present and False (conservative:
    # a missing/unknown flag must not produce a finding).
    if "rls_enabled" not in record:
        return []
    if record.get("rls_enabled") is not False:
        return []

    table = get_str(record, "table_name")
    schema = get_str(record, "schema_name") or "public"
    record_id = get_str(record, "record_id") or None
    where = f"{schema}.{table}" if table else (record_id or "a table")

    return [
        FindingCandidate(
            provider="supabase",
            rule_key=_RULE_RLS_DISABLED,
            finding_key=make_finding_key(_RULE_RLS_DISABLED, record_id),
            severity="high",
            title="Supabase table has Row Level Security disabled",
            description=(
                f"Row Level Security is disabled on {where}. Without RLS, rows "
                f"may be broadly readable or writable by any role that can reach "
                f"the table."
            ),
            evidence={
                "rule": _RULE_RLS_DISABLED,
                "schema": schema,
                "table": table,
            },
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
    ]


# ── Auth config (M60.4.4) ────────────────────────────────────────────────────


def _eval_auth_config(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or "auth_config"

    # Anonymous sign-ins enabled. On its own this is a feature; combined with
    # weak/disabled RLS it may allow unauthenticated data access. Medium.
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

    # JWT access-token lifetime far longer than the default widens the window in
    # which a stolen token remains valid. Only flag a concrete int.
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

    return out
