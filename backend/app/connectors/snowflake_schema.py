"""Snowflake provider schema (Snowflake message 1 of 8).

Defines the record-type constants, credential validators, and capability
taxonomy for the Snowflake provider. Record types so far:

  snowflake_account         — one record per connected Snowflake account
                              (msg 1) — stable account identity and safe
                              context metadata only, never credentials.
  snowflake_api_capability  — one record per probed future-family surface
                              (msg 1) — describes whether a surface is
                              safely readable, never the surface's actual
                              data.

SECURITY: this module never handles the programmatic access token itself —
only the non-secret account_identifier/username/role fields are validated
here. See ``snowflake.py``'s module docstring for the full sensitive-data
boundary.

Future messages (do not implement yet — see the Snowflake roadmap in the
connector module docstring):
  msg 2 — users, account roles, role hierarchy, user-role grants.
  msg 3 — databases, schemas, warehouses, shares, ownership/object grants.
  msg 4 — network policies, authentication policies, OAuth/security
          integrations, account security controls.
  msg 5 — effective privilege, ACCOUNTADMIN/SYSADMIN/security-admin
          posture, ownership/privilege graph.
  msg 6 — Security Findings.
  msg 7 — exhaustive Change classification, partial-sync/reliability
          hardening.
  msg 8 — public launch.
"""

from __future__ import annotations

import re as _re

# ── Record type constants ───────────────────────────────────────────────────

SNOWFLAKE_ACCOUNT = "snowflake_account"
SNOWFLAKE_API_CAPABILITY = "snowflake_api_capability"

ALL_SNOWFLAKE_RECORD_TYPES = frozenset({
    SNOWFLAKE_ACCOUNT,
    SNOWFLAKE_API_CAPABILITY,
})

# ── Family completeness taxonomy (shared by every future collection msg) ───

FAMILY_COMPLETE = "complete"
FAMILY_PARTIAL = "partial"
FAMILY_DENIED = "denied"
FAMILY_UNAVAILABLE = "unavailable"

# ── Capability probe status taxonomy ────────────────────────────────────────

CAPABILITY_AVAILABLE = "available"
CAPABILITY_DENIED = "denied"
CAPABILITY_UNSUPPORTED = "unsupported"
CAPABILITY_UNAVAILABLE = "unavailable"
CAPABILITY_THROTTLED = "throttled"
CAPABILITY_TIMED_OUT = "timed_out"
CAPABILITY_MALFORMED = "malformed"
CAPABILITY_UNKNOWN = "unknown"

# ── Capability families (message 1 probes only; collected starting msg 2+) ─
#
# Strategy decided this message (see connector module docstring for the
# full rationale): SHOW-based probes for structural/object families (fast,
# no Account Usage replication lag); ACCOUNT_USAGE-based probes for
# security/identity-inventory families that message 2+ will actually
# collect from the same source, so the message-1 probe tests the SAME
# surface that will later be used — never a proxy surface.

CAPABILITY_FAMILY_USERS = "users"
CAPABILITY_FAMILY_ROLES = "roles"
CAPABILITY_FAMILY_ROLE_GRANTS = "role_grants"
CAPABILITY_FAMILY_OBJECT_GRANTS = "object_grants"
CAPABILITY_FAMILY_DATABASES = "databases"
CAPABILITY_FAMILY_SCHEMAS = "schemas"
CAPABILITY_FAMILY_WAREHOUSES = "warehouses"
CAPABILITY_FAMILY_SHARES = "shares"
CAPABILITY_FAMILY_NETWORK_POLICIES = "network_policies"
CAPABILITY_FAMILY_AUTHENTICATION_POLICIES = "authentication_policies"
CAPABILITY_FAMILY_SECURITY_INTEGRATIONS = "security_integrations"
CAPABILITY_FAMILY_STORAGE_INTEGRATIONS = "storage_integrations"
CAPABILITY_FAMILY_EXTERNAL_ACCESS_INTEGRATIONS = "external_access_integrations"

CAPABILITY_FAMILIES: tuple[str, ...] = (
    CAPABILITY_FAMILY_USERS,
    CAPABILITY_FAMILY_ROLES,
    CAPABILITY_FAMILY_ROLE_GRANTS,
    CAPABILITY_FAMILY_OBJECT_GRANTS,
    CAPABILITY_FAMILY_DATABASES,
    CAPABILITY_FAMILY_SCHEMAS,
    CAPABILITY_FAMILY_WAREHOUSES,
    CAPABILITY_FAMILY_SHARES,
    CAPABILITY_FAMILY_NETWORK_POLICIES,
    CAPABILITY_FAMILY_AUTHENTICATION_POLICIES,
    CAPABILITY_FAMILY_SECURITY_INTEGRATIONS,
    CAPABILITY_FAMILY_STORAGE_INTEGRATIONS,
    CAPABILITY_FAMILY_EXTERNAL_ACCESS_INTEGRATIONS,
)


# ── Credential validators ───────────────────────────────────────────────────


class SnowflakeCredentialError(ValueError):
    """Raised when a Snowflake credential field fails validation.
    Subclasses ValueError so existing generic error handling still catches
    it."""


# Account identifiers are either the preferred `orgname-accountname` form
# or the legacy locator form (optionally region/cloud-qualified, e.g.
# `xy12345.us-east-2.aws`) — see
# https://docs.snowflake.com/en/user-guide/admin-account-identifier.
# Conservative allowlist: lowercase letters, digits, hyphens, underscores,
# and dots only. Never a full URL — this value is used to construct the
# request hostname, so a URL scheme, path, query, or fragment must never
# be accepted.
_ACCOUNT_IDENTIFIER_RE = _re.compile(r"^[a-z0-9][a-z0-9_.-]{0,251}[a-z0-9]$")


def validate_account_identifier(raw_account_identifier: object) -> str:
    """Validate and normalize a Snowflake account identifier.

    Accepts the preferred ``orgname-accountname`` form and the legacy
    (optionally region/cloud-qualified) account-locator form. Rejects any
    value containing a URL scheme, path, query, or fragment — this value
    is used to construct the request hostname
    (``https://{account_identifier}.snowflakecomputing.com``), so it must
    never itself be treated as an arbitrary target.

    Returns the lowercased, trimmed identifier. Raises
    ``SnowflakeCredentialError`` — never silently coerces a malformed
    value.
    """
    if not isinstance(raw_account_identifier, str) or not raw_account_identifier.strip():
        raise SnowflakeCredentialError("snowflake: account_identifier must be a non-empty string")

    cleaned = raw_account_identifier.strip().lower()

    if "://" in cleaned or "/" in cleaned or "?" in cleaned or "#" in cleaned or " " in cleaned:
        raise SnowflakeCredentialError(
            "snowflake: account_identifier must not contain a URL scheme, path, query, or fragment"
        )
    if cleaned.endswith(".snowflakecomputing.com"):
        raise SnowflakeCredentialError(
            "snowflake: account_identifier must be the bare identifier, not a full hostname/URL"
        )
    if not _ACCOUNT_IDENTIFIER_RE.match(cleaned):
        raise SnowflakeCredentialError(
            "snowflake: account_identifier must contain only letters, digits, hyphens, "
            "underscores, and dots (e.g. 'myorg-myaccount' or 'xy12345.us-east-2.aws')"
        )
    return cleaned


_USERNAME_RE = _re.compile(r"^[A-Za-z0-9_.\-]{1,255}$")


def validate_username(raw_username: object) -> str:
    """Validate a Snowflake username. Conservative allowlist — Snowflake
    unquoted identifiers permit letters/digits/underscore/dollar, but this
    connector never interpolates the username into SQL text (it is only
    ever sent as a connection/API credential field), so the allowlist here
    exists purely to reject obviously malformed input (whitespace, control
    characters, embedded SQL) rather than to fully model Snowflake
    identifier grammar."""
    if not isinstance(raw_username, str) or not raw_username.strip():
        raise SnowflakeCredentialError("snowflake: username must be a non-empty string")
    cleaned = raw_username.strip()
    if not _USERNAME_RE.match(cleaned):
        raise SnowflakeCredentialError(
            "snowflake: username must contain only letters, digits, underscores, dots, "
            "and hyphens"
        )
    return cleaned


_ROLE_RE = _re.compile(r"^[A-Za-z0-9_]{1,255}$")


def validate_role(raw_role: object) -> str:
    """Validate a Snowflake role name.

    A role is REQUIRED (never silently defaulted to ``ACCOUNTADMIN`` or
    ``SECURITYADMIN``) — Programmatic Access Tokens issued to service
    users require an explicit role restriction by default per current
    Snowflake documentation, and ConfigTrace never assumes an elevated
    role on the customer's behalf.
    """
    if not isinstance(raw_role, str) or not raw_role.strip():
        raise SnowflakeCredentialError(
            "snowflake: role must be a non-empty string — ConfigTrace requires an explicit "
            "least-privileged monitoring role and never defaults to ACCOUNTADMIN or "
            "SECURITYADMIN"
        )
    cleaned = raw_role.strip().upper()
    if not _ROLE_RE.match(cleaned):
        raise SnowflakeCredentialError(
            "snowflake: role must contain only letters, digits, and underscores"
        )
    return cleaned
