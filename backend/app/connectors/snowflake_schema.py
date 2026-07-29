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
SNOWFLAKE_USER = "snowflake_user"
SNOWFLAKE_ACCOUNT_ROLE = "snowflake_account_role"
SNOWFLAKE_DATABASE_ROLE = "snowflake_database_role"
SNOWFLAKE_USER_ROLE_GRANT = "snowflake_user_role_grant"
SNOWFLAKE_ROLE_HIERARCHY_GRANT = "snowflake_role_hierarchy_grant"

ALL_SNOWFLAKE_RECORD_TYPES = frozenset({
    SNOWFLAKE_ACCOUNT,
    SNOWFLAKE_API_CAPABILITY,
    SNOWFLAKE_USER,
    SNOWFLAKE_ACCOUNT_ROLE,
    SNOWFLAKE_DATABASE_ROLE,
    SNOWFLAKE_USER_ROLE_GRANT,
    SNOWFLAKE_ROLE_HIERARCHY_GRANT,
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


# ── Snowflake message 2: identity/role collection family names ─────────────
#
# Distinct from the message-1 CAPABILITY_FAMILY_* probe names above (those
# only ever probe *readability*). These are the family names actual
# collection completeness is tracked under, stored in the same
# ``snowflake_account.family_completeness`` dict alongside the message-1
# capability-probe entries.

COLLECTION_FAMILY_USERS = "users"
COLLECTION_FAMILY_ACCOUNT_ROLES = "account_roles"
COLLECTION_FAMILY_DATABASE_ROLES = "database_roles"
COLLECTION_FAMILY_USER_ROLE_GRANTS = "user_role_grants"
COLLECTION_FAMILY_ROLE_HIERARCHY = "role_hierarchy"

COLLECTION_FAMILIES: tuple[str, ...] = (
    COLLECTION_FAMILY_USERS,
    COLLECTION_FAMILY_ACCOUNT_ROLES,
    COLLECTION_FAMILY_DATABASE_ROLES,
    COLLECTION_FAMILY_USER_ROLE_GRANTS,
    COLLECTION_FAMILY_ROLE_HIERARCHY,
)


# ── User type taxonomy ───────────────────────────────────────────────────────
#
# Confirmed via current official Snowflake documentation
# (CREATE USER reference): TYPE accepts PERSON, SERVICE, SERVICE_AGENT, and
# LEGACY_SERVICE (deprecated, kept for backward compatibility). Any other/
# missing value is bucketed as unknown — never invented, never assumed to
# be privileged or unprivileged by existence alone.

USER_TYPE_PERSON = "person"
USER_TYPE_SERVICE = "service"
USER_TYPE_SERVICE_AGENT = "service_agent"
USER_TYPE_LEGACY_SERVICE = "legacy_service"
USER_TYPE_UNKNOWN = "unknown"

_USER_TYPE_MAP = {
    "PERSON": USER_TYPE_PERSON,
    "SERVICE": USER_TYPE_SERVICE,
    "SERVICE_AGENT": USER_TYPE_SERVICE_AGENT,
    "LEGACY_SERVICE": USER_TYPE_LEGACY_SERVICE,
}


def categorize_user_type(raw_type: object) -> str:
    """Map a SHOW USERS ``type`` value to a bounded category. Never invents
    a type; anything not in the documented set (including ``None`` from a
    privilege-filtered row) maps to ``unknown``."""
    if not isinstance(raw_type, str):
        return USER_TYPE_UNKNOWN
    return _USER_TYPE_MAP.get(raw_type.strip().upper(), USER_TYPE_UNKNOWN)


# ── Disabled tri-state ───────────────────────────────────────────────────────
#
# SHOW USERS filters most columns (including ``disabled``) to NULL for a
# role without OWNERSHIP on the user or MANAGE GRANTS on the account —
# missing therefore means "unknown", never "enabled". The SQL API can
# return boolean-like values as native booleans or as the strings
# "true"/"false" depending on the driver/result format, so both are
# handled explicitly.

DISABLED_ENABLED = "enabled"
DISABLED_DISABLED = "disabled"
DISABLED_UNKNOWN = "unknown"


def categorize_disabled(raw_disabled: object) -> str:
    if isinstance(raw_disabled, bool):
        return DISABLED_DISABLED if raw_disabled else DISABLED_ENABLED
    if isinstance(raw_disabled, str):
        cleaned = raw_disabled.strip().lower()
        if cleaned == "true":
            return DISABLED_DISABLED
        if cleaned == "false":
            return DISABLED_ENABLED
    return DISABLED_UNKNOWN


# ── Generic tri-state boolean (RSA key / password / PAT presence) ──────────

TRISTATE_TRUE = "true"
TRISTATE_FALSE = "false"
TRISTATE_UNKNOWN = "unknown"


def categorize_tristate_bool(raw_value: object) -> str:
    """Bounded true/false/unknown category for a presence/configuration
    boolean column. Missing/filtered/malformed values are ``unknown`` —
    NEVER coerced to ``false``, since a privilege-filtered SHOW USERS row
    returns NULL for a column the caller cannot see, not a real ``false``."""
    if isinstance(raw_value, bool):
        return TRISTATE_TRUE if raw_value else TRISTATE_FALSE
    if isinstance(raw_value, str):
        cleaned = raw_value.strip().lower()
        if cleaned == "true":
            return TRISTATE_TRUE
        if cleaned == "false":
            return TRISTATE_FALSE
    return TRISTATE_UNKNOWN


# ── Secondary-role posture ──────────────────────────────────────────────────
#
# Confirmed via current official docs (CREATE USER reference):
# DEFAULT_SECONDARY_ROLES accepts ``('ALL')`` (default) or ``()`` (none).
# SHOW USERS surfaces this as the ``default_secondary_roles`` column.
# Message 2 records only this coarse posture — it never computes the
# resulting effective privilege set (message 5).

SECONDARY_ROLES_ALL = "all"
SECONDARY_ROLES_NONE = "none"
SECONDARY_ROLES_SPECIFIC = "specific"
SECONDARY_ROLES_UNKNOWN = "unknown"


def categorize_secondary_roles(raw_value: object) -> str:
    if not isinstance(raw_value, str):
        return SECONDARY_ROLES_UNKNOWN
    cleaned = raw_value.strip().upper()
    if cleaned in ("ALL", "('ALL')"):
        return SECONDARY_ROLES_ALL
    if cleaned in ("", "NONE", "()"):
        return SECONDARY_ROLES_NONE
    if cleaned:
        return SECONDARY_ROLES_SPECIFIC
    return SECONDARY_ROLES_UNKNOWN


# ── Built-in account-role taxonomy ──────────────────────────────────────────
#
# Confirmed via current official docs (Access Control overview): the
# system-defined account roles are ACCOUNTADMIN, SECURITYADMIN, SYSADMIN,
# USERADMIN, ORGADMIN (being phased out in favor of GLOBALORGADMIN, but
# still currently documented), and PUBLIC (automatically granted to every
# user and role — never a manually-assigned role).

ROLE_CATEGORY_ACCOUNTADMIN = "accountadmin"
ROLE_CATEGORY_SECURITYADMIN = "securityadmin"
ROLE_CATEGORY_SYSADMIN = "sysadmin"
ROLE_CATEGORY_USERADMIN = "useradmin"
ROLE_CATEGORY_ORGADMIN = "orgadmin"
ROLE_CATEGORY_PUBLIC = "public"
ROLE_CATEGORY_CUSTOM = "custom"
ROLE_CATEGORY_UNKNOWN = "unknown"

_BUILT_IN_ACCOUNT_ROLE_MAP = {
    "ACCOUNTADMIN": ROLE_CATEGORY_ACCOUNTADMIN,
    "SECURITYADMIN": ROLE_CATEGORY_SECURITYADMIN,
    "SYSADMIN": ROLE_CATEGORY_SYSADMIN,
    "USERADMIN": ROLE_CATEGORY_USERADMIN,
    "ORGADMIN": ROLE_CATEGORY_ORGADMIN,
    "GLOBALORGADMIN": ROLE_CATEGORY_ORGADMIN,
    "PUBLIC": ROLE_CATEGORY_PUBLIC,
}


def categorize_account_role(role_name: object) -> str:
    """Map an account role name to its built-in category, or ``custom`` for
    any other role. Never assigns a final privilege tier here — that is
    message 5's job; this is purely deterministic name-based
    identification of Snowflake's own documented system roles."""
    if not isinstance(role_name, str) or not role_name.strip():
        return ROLE_CATEGORY_UNKNOWN
    return _BUILT_IN_ACCOUNT_ROLE_MAP.get(role_name.strip().upper(), ROLE_CATEGORY_CUSTOM)


def is_public_role(role_name: object) -> bool:
    """True only for the automatic, universally-granted PUBLIC role — used
    to exclude it from grant/hierarchy enumeration so that its automatic
    membership in every user/role never generates diff noise."""
    return isinstance(role_name, str) and role_name.strip().upper() == "PUBLIC"


# ── Grant / role-type taxonomy (for user-role grants and role hierarchy) ───
#
# ``granted_to``/``granted_to_roles`` type discriminator, confirmed via
# current official docs (SHOW GRANTS reference): a role can be granted to
# a USER, an account ROLE, or a DATABASE_ROLE.

PRINCIPAL_TYPE_USER = "user"
PRINCIPAL_TYPE_ACCOUNT_ROLE = "account_role"
PRINCIPAL_TYPE_DATABASE_ROLE = "database_role"
PRINCIPAL_TYPE_UNKNOWN = "unknown"

_PRINCIPAL_TYPE_MAP = {
    "USER": PRINCIPAL_TYPE_USER,
    "ROLE": PRINCIPAL_TYPE_ACCOUNT_ROLE,
    "DATABASE_ROLE": PRINCIPAL_TYPE_DATABASE_ROLE,
}


def categorize_principal_type(raw_granted_to: object) -> str:
    if not isinstance(raw_granted_to, str):
        return PRINCIPAL_TYPE_UNKNOWN
    return _PRINCIPAL_TYPE_MAP.get(raw_granted_to.strip().upper(), PRINCIPAL_TYPE_UNKNOWN)


# ── Grant-option tri-state ───────────────────────────────────────────────────
#
# ``SHOW GRANTS OF ROLE`` / ``SHOW GRANTS OF DATABASE ROLE`` (confirmed via
# current official docs) do not expose a grant_option column at all — only
# object-privilege grants (``SHOW GRANTS TO ROLE`` / ``GRANTS_TO_ROLES``,
# out of scope until later object-grant work) carry one. Message 2's
# user-role grants and role-hierarchy edges therefore always record
# grant_option as ``unknown`` — this is a documented source limitation, not
# a guess, and must never be coerced to ``false``.

GRANT_OPTION_TRUE = "true"
GRANT_OPTION_FALSE = "false"
GRANT_OPTION_UNKNOWN = "unknown"


def categorize_grant_option(raw_value: object) -> str:
    """Bounded true/false/unknown category for a SHOW GRANTS-family
    ``grant_option`` column. Unlike message 2's user-role/hierarchy grants
    (which never expose this column at all), ``SHOW GRANTS TO ROLE`` /
    ``SHOW FUTURE GRANTS`` DO expose it — so an actual value here is
    trusted, but anything missing/malformed is still ``unknown``, never
    coerced to ``false``."""
    if isinstance(raw_value, bool):
        return GRANT_OPTION_TRUE if raw_value else GRANT_OPTION_FALSE
    if isinstance(raw_value, str):
        cleaned = raw_value.strip().lower()
        if cleaned == "true":
            return GRANT_OPTION_TRUE
        if cleaned == "false":
            return GRANT_OPTION_FALSE
    return GRANT_OPTION_UNKNOWN


# ── Snowflake message 3: data objects (databases/schemas/warehouses/shares)
#    and object/future grants ───────────────────────────────────────────────

SNOWFLAKE_DATABASE = "snowflake_database"
SNOWFLAKE_SCHEMA = "snowflake_schema"
SNOWFLAKE_WAREHOUSE = "snowflake_warehouse"
SNOWFLAKE_SHARE = "snowflake_share"
SNOWFLAKE_OBJECT_GRANT = "snowflake_object_grant"

ALL_SNOWFLAKE_RECORD_TYPES = ALL_SNOWFLAKE_RECORD_TYPES | frozenset({
    SNOWFLAKE_DATABASE,
    SNOWFLAKE_SCHEMA,
    SNOWFLAKE_WAREHOUSE,
    SNOWFLAKE_SHARE,
    SNOWFLAKE_OBJECT_GRANT,
})

COLLECTION_FAMILY_DATABASES = "databases"
COLLECTION_FAMILY_SCHEMAS = "schemas"
COLLECTION_FAMILY_WAREHOUSES = "warehouses"
COLLECTION_FAMILY_SHARES = "shares"
COLLECTION_FAMILY_OBJECT_GRANTS = "object_grants"
COLLECTION_FAMILY_FUTURE_GRANTS = "future_grants"

DATA_OBJECT_COLLECTION_FAMILIES: tuple[str, ...] = (
    COLLECTION_FAMILY_DATABASES,
    COLLECTION_FAMILY_SCHEMAS,
    COLLECTION_FAMILY_WAREHOUSES,
    COLLECTION_FAMILY_SHARES,
    COLLECTION_FAMILY_OBJECT_GRANTS,
    COLLECTION_FAMILY_FUTURE_GRANTS,
)


# ── Database taxonomy ────────────────────────────────────────────────────────
#
# Confirmed via current official docs (SHOW DATABASES reference): the
# ``kind`` column distinguishes STANDARD, IMPORTED DATABASE (shared from
# another account), APPLICATION, PERSONAL DATABASE, and CATALOG-LINKED
# DATABASE. Never inferred from the database's display name.

DATABASE_KIND_STANDARD = "standard"
DATABASE_KIND_IMPORTED = "imported"
DATABASE_KIND_APPLICATION = "application"
DATABASE_KIND_PERSONAL = "personal"
DATABASE_KIND_CATALOG_LINKED = "catalog_linked"
DATABASE_KIND_UNKNOWN = "unknown"

_DATABASE_KIND_MAP = {
    "STANDARD": DATABASE_KIND_STANDARD,
    "IMPORTED DATABASE": DATABASE_KIND_IMPORTED,
    "APPLICATION": DATABASE_KIND_APPLICATION,
    "PERSONAL DATABASE": DATABASE_KIND_PERSONAL,
    "CATALOG-LINKED DATABASE": DATABASE_KIND_CATALOG_LINKED,
}


def categorize_database_kind(raw_kind: object) -> str:
    if not isinstance(raw_kind, str):
        return DATABASE_KIND_UNKNOWN
    return _DATABASE_KIND_MAP.get(raw_kind.strip().upper(), DATABASE_KIND_UNKNOWN)


# ── OPTIONS-column token parsing (shared by databases/schemas) ─────────────
#
# Confirmed via current official docs (CREATE SCHEMA reference): SHOW
# DATABASES/SHOW SCHEMAS' ``options`` column is a space-separated token
# list (e.g. ``TRANSIENT``, ``MANAGED ACCESS``) — never a single fixed
# enum value. Presence/absence of a token is checked directly rather than
# assuming a canonical ordering or a single-value column.

def _options_contains(raw_options: object, token: str) -> str:
    """Return the shared TRISTATE_* category for whether `token` appears
    in a SHOW-command ``options`` column. Missing/non-string options is
    unknown — never coerced to false (an object with no visible options
    value could still have the property; the caller simply couldn't see
    it, e.g. a privilege-filtered row)."""
    if not isinstance(raw_options, str):
        return TRISTATE_UNKNOWN
    tokens = raw_options.upper()
    return TRISTATE_TRUE if token in tokens else TRISTATE_FALSE


def categorize_managed_access(raw_options: object) -> str:
    return _options_contains(raw_options, "MANAGED ACCESS")


def categorize_transient(raw_options: object) -> str:
    return _options_contains(raw_options, "TRANSIENT")


# ── Warehouse auto-resume/state (booleans/categories, never a Finding) ─────

WAREHOUSE_STATE_STARTED = "started"
WAREHOUSE_STATE_SUSPENDED = "suspended"
WAREHOUSE_STATE_RESIZING = "resizing"
WAREHOUSE_STATE_UNKNOWN = "unknown"

_WAREHOUSE_STATE_MAP = {
    "STARTED": WAREHOUSE_STATE_STARTED,
    "SUSPENDED": WAREHOUSE_STATE_SUSPENDED,
    "RESIZING": WAREHOUSE_STATE_RESIZING,
}


def categorize_warehouse_state(raw_state: object) -> str:
    if not isinstance(raw_state, str):
        return WAREHOUSE_STATE_UNKNOWN
    return _WAREHOUSE_STATE_MAP.get(raw_state.strip().upper(), WAREHOUSE_STATE_UNKNOWN)


# ── Share kind taxonomy ───────────────────────────────────────────────────────
#
# Confirmed via current official docs (SHOW SHARES reference): ``kind`` is
# INBOUND (share available to consume/create a database from) or OUTBOUND
# (this account is sharing data out). A share is Snowflake-to-Snowflake
# controlled secure sharing — its mere existence is never treated as "data
# is public" anywhere in this connector or its risk classifier.

SHARE_KIND_OUTBOUND = "outbound"
SHARE_KIND_INBOUND = "inbound"
SHARE_KIND_UNKNOWN = "unknown"

_SHARE_KIND_MAP = {
    "OUTBOUND": SHARE_KIND_OUTBOUND,
    "INBOUND": SHARE_KIND_INBOUND,
}


def categorize_share_kind(raw_kind: object) -> str:
    if not isinstance(raw_kind, str):
        return SHARE_KIND_UNKNOWN
    return _SHARE_KIND_MAP.get(raw_kind.strip().upper(), SHARE_KIND_UNKNOWN)


# ── Object-type taxonomy (grant target) ──────────────────────────────────────
#
# ``granted_on``/``grant_on`` values from SHOW GRANTS TO ROLE / SHOW FUTURE
# GRANTS, confirmed via current official docs. ROLE-typed rows are
# deliberately NOT part of this taxonomy — they represent role-hierarchy
# edges (already collected in message 2 via SHOW GRANTS OF ROLE, the
# reverse direction) and are filtered out before reaching a grant
# normalizer, never re-derived as a second, potentially conflicting,
# hierarchy source.

OBJECT_TYPE_DATABASE = "database"
OBJECT_TYPE_SCHEMA = "schema"
OBJECT_TYPE_TABLE = "table"
OBJECT_TYPE_VIEW = "view"
OBJECT_TYPE_WAREHOUSE = "warehouse"
OBJECT_TYPE_FUNCTION_PROCEDURE = "function_procedure"
OBJECT_TYPE_STAGE = "stage"
OBJECT_TYPE_FILE_FORMAT = "file_format"
OBJECT_TYPE_SEQUENCE = "sequence"
OBJECT_TYPE_PIPE = "pipe"
OBJECT_TYPE_STREAM = "stream"
OBJECT_TYPE_TASK = "task"
OBJECT_TYPE_SHARE = "share"
OBJECT_TYPE_INTEGRATION = "integration"
OBJECT_TYPE_ACCOUNT = "account"
OBJECT_TYPE_UNKNOWN = "unknown"

_OBJECT_TYPE_MAP = {
    "DATABASE": OBJECT_TYPE_DATABASE,
    "SCHEMA": OBJECT_TYPE_SCHEMA,
    "TABLE": OBJECT_TYPE_TABLE,
    "VIEW": OBJECT_TYPE_VIEW,
    "MATERIALIZED VIEW": OBJECT_TYPE_VIEW,
    "WAREHOUSE": OBJECT_TYPE_WAREHOUSE,
    "FUNCTION": OBJECT_TYPE_FUNCTION_PROCEDURE,
    "PROCEDURE": OBJECT_TYPE_FUNCTION_PROCEDURE,
    "STAGE": OBJECT_TYPE_STAGE,
    "FILE FORMAT": OBJECT_TYPE_FILE_FORMAT,
    "SEQUENCE": OBJECT_TYPE_SEQUENCE,
    "PIPE": OBJECT_TYPE_PIPE,
    "STREAM": OBJECT_TYPE_STREAM,
    "TASK": OBJECT_TYPE_TASK,
    "SHARE": OBJECT_TYPE_SHARE,
    "INTEGRATION": OBJECT_TYPE_INTEGRATION,
    "ACCOUNT": OBJECT_TYPE_ACCOUNT,
}


def categorize_object_type(raw_granted_on: object) -> str:
    if not isinstance(raw_granted_on, str):
        return OBJECT_TYPE_UNKNOWN
    return _OBJECT_TYPE_MAP.get(raw_granted_on.strip().upper(), OBJECT_TYPE_UNKNOWN)


def is_role_hierarchy_row(raw_granted_on: object) -> bool:
    """True for a SHOW GRANTS TO ROLE row whose ``granted_on`` is ROLE or
    DATABASE_ROLE — these are role-hierarchy edges (message 2's domain via
    SHOW GRANTS OF ROLE), never normalized as an object grant here."""
    return isinstance(raw_granted_on, str) and raw_granted_on.strip().upper() in ("ROLE", "DATABASE_ROLE")


# ── Privilege taxonomy ────────────────────────────────────────────────────────
#
# Bounded structural-severity categories for Change classification. Uses
# ONLY actual documented Snowflake privilege strings — never invented.
# Message 5 owns full effective-privilege computation; these categories
# exist so message 3 can classify Changes with reasonable structural
# severity today.

PRIVILEGE_CATEGORY_OWNERSHIP = "ownership"
PRIVILEGE_CATEGORY_DATA_READ = "data_read"
PRIVILEGE_CATEGORY_DATA_WRITE = "data_write"
PRIVILEGE_CATEGORY_OBJECT_CREATE = "object_create"
PRIVILEGE_CATEGORY_OPERATIONAL_CONTROL = "operational_control"
PRIVILEGE_CATEGORY_USAGE = "usage"
PRIVILEGE_CATEGORY_MONITOR = "monitor"
PRIVILEGE_CATEGORY_UNKNOWN = "unknown"

_PRIVILEGE_CATEGORY_MAP = {
    "OWNERSHIP": PRIVILEGE_CATEGORY_OWNERSHIP,
    "SELECT": PRIVILEGE_CATEGORY_DATA_READ,
    "REFERENCES": PRIVILEGE_CATEGORY_DATA_READ,
    "REFERENCE_USAGE": PRIVILEGE_CATEGORY_DATA_READ,
    "INSERT": PRIVILEGE_CATEGORY_DATA_WRITE,
    "UPDATE": PRIVILEGE_CATEGORY_DATA_WRITE,
    "DELETE": PRIVILEGE_CATEGORY_DATA_WRITE,
    "TRUNCATE": PRIVILEGE_CATEGORY_DATA_WRITE,
    "USAGE": PRIVILEGE_CATEGORY_USAGE,
    "IMPORTED PRIVILEGES": PRIVILEGE_CATEGORY_USAGE,
    "APPLY": PRIVILEGE_CATEGORY_OPERATIONAL_CONTROL,
    "MODIFY": PRIVILEGE_CATEGORY_OPERATIONAL_CONTROL,
    "OPERATE": PRIVILEGE_CATEGORY_OPERATIONAL_CONTROL,
    "MONITOR": PRIVILEGE_CATEGORY_MONITOR,
}


def categorize_privilege(raw_privilege: object) -> str:
    """Categorize a raw Snowflake privilege string. ``CREATE <OBJECT>``
    privileges (e.g. ``CREATE TABLE``, ``CREATE SCHEMA``) are matched by
    prefix since Snowflake documents a large, growing family of them, all
    of which grant object-creation authority — never invented, only
    recognized by the well-documented ``CREATE `` prefix convention."""
    if not isinstance(raw_privilege, str) or not raw_privilege.strip():
        return PRIVILEGE_CATEGORY_UNKNOWN
    cleaned = raw_privilege.strip().upper()
    if cleaned.startswith("CREATE "):
        return PRIVILEGE_CATEGORY_OBJECT_CREATE
    return _PRIVILEGE_CATEGORY_MAP.get(cleaned, PRIVILEGE_CATEGORY_UNKNOWN)


# ── Snowflake message 4: network/authentication policy + security/storage/
#    external-access integration coverage ────────────────────────────────────

SNOWFLAKE_NETWORK_POLICY = "snowflake_network_policy"
SNOWFLAKE_NETWORK_RULE = "snowflake_network_rule"
SNOWFLAKE_AUTHENTICATION_POLICY = "snowflake_authentication_policy"
SNOWFLAKE_SECURITY_INTEGRATION = "snowflake_security_integration"
SNOWFLAKE_STORAGE_INTEGRATION = "snowflake_storage_integration"
SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION = "snowflake_external_access_integration"

ALL_SNOWFLAKE_RECORD_TYPES = ALL_SNOWFLAKE_RECORD_TYPES | frozenset({
    SNOWFLAKE_NETWORK_POLICY,
    SNOWFLAKE_NETWORK_RULE,
    SNOWFLAKE_AUTHENTICATION_POLICY,
    SNOWFLAKE_SECURITY_INTEGRATION,
    SNOWFLAKE_STORAGE_INTEGRATION,
    SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION,
})

COLLECTION_FAMILY_NETWORK_POLICIES = "network_policies"
COLLECTION_FAMILY_NETWORK_RULES = "network_rules"
COLLECTION_FAMILY_AUTHENTICATION_POLICIES = "authentication_policies"
COLLECTION_FAMILY_SECURITY_INTEGRATIONS = "security_integrations"
COLLECTION_FAMILY_STORAGE_INTEGRATIONS = "storage_integrations"
COLLECTION_FAMILY_EXTERNAL_ACCESS_INTEGRATIONS = "external_access_integrations"

POLICY_COLLECTION_FAMILIES: tuple[str, ...] = (
    COLLECTION_FAMILY_NETWORK_POLICIES,
    COLLECTION_FAMILY_NETWORK_RULES,
    COLLECTION_FAMILY_AUTHENTICATION_POLICIES,
    COLLECTION_FAMILY_SECURITY_INTEGRATIONS,
    COLLECTION_FAMILY_STORAGE_INTEGRATIONS,
    COLLECTION_FAMILY_EXTERNAL_ACCESS_INTEGRATIONS,
)

# Deferred this message (documented, not silently dropped): API integrations
# (category=API, more deployment/API-Gateway infrastructure than central
# account security posture — task explicitly permits deferring) and session
# policies (idle/session timeout posture — materially smaller security
# signal than network/authentication policies; would require yet another
# SHOW + per-policy DESCRIBE round trip for comparatively low value this
# message). Both remain candidates for a future message.


# ── Detail-collection completeness (per-record, distinct from family
#    completeness) ───────────────────────────────────────────────────────────
#
# A SHOW-level list can succeed while a per-record DESCRIBE fails for one
# specific object — the object's identity/list-level fields must still be
# preserved (never dropped), with only the DESCRIBE-derived fields left
# unknown. Reuses the same FAMILY_* string values as message-1's family
# completeness taxonomy for consistency (complete/partial/denied/
# unavailable), scoped to a single record instead of a whole family.
DETAIL_COMPLETE = FAMILY_COMPLETE
DETAIL_DENIED = FAMILY_DENIED
DETAIL_UNAVAILABLE = FAMILY_UNAVAILABLE


# ── Broad-network-access tri-state ──────────────────────────────────────────
#
# Confirmed via current official docs (DESCRIBE NETWORK POLICY reference):
# ALLOWED_IP_LIST/BLOCKED_IP_LIST return the actual configured CIDR ranges.
# This connector checks ONLY for the literal "0.0.0.0/0" (IPv4-anywhere) and
# "::/0" (IPv6-anywhere) substrings in that per-policy DESCRIBE response —
# the full list is discarded immediately after the check and NEVER stored
# on the normalized record (task's own IP/CIDR privacy boundary).

BROAD_ACCESS_TRUE = "true"
BROAD_ACCESS_FALSE = "false"
BROAD_ACCESS_UNKNOWN = "unknown"


def categorize_broad_access(contains_anywhere_sentinel: Optional[bool]) -> str:
    if contains_anywhere_sentinel is None:
        return BROAD_ACCESS_UNKNOWN
    return BROAD_ACCESS_TRUE if contains_anywhere_sentinel else BROAD_ACCESS_FALSE


# ── Authentication-method taxonomy ──────────────────────────────────────────
#
# Confirmed via current official docs (CREATE AUTHENTICATION POLICY
# reference): AUTHENTICATION_METHODS accepts ALL, SAML, OIDC, PASSWORD,
# OAUTH, KEYPAIR, PROGRAMMATIC_ACCESS_TOKEN, WORKLOAD_IDENTITY.

AUTH_METHOD_ALL = "all"
AUTH_METHOD_SAML = "saml"
AUTH_METHOD_OIDC = "oidc"
AUTH_METHOD_PASSWORD = "password"
AUTH_METHOD_OAUTH = "oauth"
AUTH_METHOD_KEYPAIR = "keypair"
AUTH_METHOD_PROGRAMMATIC_ACCESS_TOKEN = "programmatic_access_token"
AUTH_METHOD_WORKLOAD_IDENTITY = "workload_identity"
AUTH_METHOD_UNKNOWN = "unknown"

_AUTH_METHOD_MAP = {
    "ALL": AUTH_METHOD_ALL,
    "SAML": AUTH_METHOD_SAML,
    "OIDC": AUTH_METHOD_OIDC,
    "PASSWORD": AUTH_METHOD_PASSWORD,
    "OAUTH": AUTH_METHOD_OAUTH,
    "KEYPAIR": AUTH_METHOD_KEYPAIR,
    "PROGRAMMATIC_ACCESS_TOKEN": AUTH_METHOD_PROGRAMMATIC_ACCESS_TOKEN,
    "WORKLOAD_IDENTITY": AUTH_METHOD_WORKLOAD_IDENTITY,
}


def categorize_auth_methods(raw_methods: object) -> list[str]:
    """Categorize a comma/list-shaped AUTHENTICATION_METHODS value into a
    bounded list of categories. Never invents a method; anything
    unrecognized is dropped from the list rather than guessed (the caller
    can tell a method was filtered by comparing count-of-raw vs
    count-of-categorized only if it chooses to; this function does not
    fabricate an 'unknown' placeholder per unrecognized entry to avoid
    implying a specific count of unrecognized methods)."""
    if isinstance(raw_methods, str):
        raw_list = [m.strip().strip("'\"") for m in raw_methods.strip("[]").split(",") if m.strip()]
    elif isinstance(raw_methods, list):
        raw_list = [str(m).strip() for m in raw_methods if str(m).strip()]
    else:
        return []
    return [_AUTH_METHOD_MAP[m.upper()] for m in raw_list if m.upper() in _AUTH_METHOD_MAP]


# ── MFA enrollment taxonomy ──────────────────────────────────────────────────
#
# Confirmed via current official docs (CREATE AUTHENTICATION POLICY
# reference): MFA_ENROLLMENT accepts REQUIRED, REQUIRED_PASSWORD_ONLY,
# OPTIONAL. Never conflated with service-user PAT/key-pair authentication —
# Snowflake's MFA enforcement model applies to human/password-adjacent
# login, not machine-to-machine PAT/key-pair auth (see the connector
# module docstring for the full person-vs-service authentication
# rationale).

MFA_ENROLLMENT_REQUIRED = "required"
MFA_ENROLLMENT_REQUIRED_PASSWORD_ONLY = "required_password_only"
MFA_ENROLLMENT_OPTIONAL = "optional"
MFA_ENROLLMENT_UNKNOWN = "unknown"

_MFA_ENROLLMENT_MAP = {
    "REQUIRED": MFA_ENROLLMENT_REQUIRED,
    "REQUIRED_PASSWORD_ONLY": MFA_ENROLLMENT_REQUIRED_PASSWORD_ONLY,
    "OPTIONAL": MFA_ENROLLMENT_OPTIONAL,
}


def categorize_mfa_enrollment(raw_value: object) -> str:
    if not isinstance(raw_value, str):
        return MFA_ENROLLMENT_UNKNOWN
    return _MFA_ENROLLMENT_MAP.get(raw_value.strip().upper(), MFA_ENROLLMENT_UNKNOWN)


# ── Client-types taxonomy ────────────────────────────────────────────────────
#
# Confirmed via current official docs: CLIENT_TYPES accepts ALL,
# SNOWFLAKE_UI, DRIVERS, SNOWFLAKE_CLI, SNOWSQL. Stored as a bounded
# category, never a raw free-form list.

CLIENT_TYPES_ALL = "all"
CLIENT_TYPES_RESTRICTED = "restricted"
CLIENT_TYPES_UNKNOWN = "unknown"


def categorize_client_types(raw_value: object) -> str:
    """ALL means every client type is permitted; any other non-empty,
    narrower configuration is 'restricted' (the specific allowed types are
    intentionally not enumerated here — this is a coarse posture category,
    not a full client-type inventory)."""
    if isinstance(raw_value, list):
        if not raw_value:
            return CLIENT_TYPES_UNKNOWN
        joined = ",".join(str(v) for v in raw_value).upper()
    elif isinstance(raw_value, str) and raw_value.strip():
        joined = raw_value.strip().upper()
    else:
        return CLIENT_TYPES_UNKNOWN
    return CLIENT_TYPES_ALL if "ALL" in joined else CLIENT_TYPES_RESTRICTED


# ── Security-integration type taxonomy ──────────────────────────────────────
#
# Confirmed via current official docs (CREATE SECURITY INTEGRATION
# reference): TYPE accepts API_AUTHENTICATION, EXTERNAL_OAUTH, OAUTH,
# OIDC, SAML2, SCIM. ``OAUTH`` alone (Snowflake OAuth) is distinguished
# from ``EXTERNAL_OAUTH`` — never conflated.

INTEGRATION_TYPE_SAML2 = "saml2"
INTEGRATION_TYPE_OAUTH_SNOWFLAKE = "oauth_snowflake"
INTEGRATION_TYPE_EXTERNAL_OAUTH = "external_oauth"
INTEGRATION_TYPE_OIDC = "oidc"
INTEGRATION_TYPE_SCIM = "scim"
INTEGRATION_TYPE_API_AUTHENTICATION = "api_authentication"
INTEGRATION_TYPE_UNKNOWN = "unknown"

_INTEGRATION_TYPE_MAP = {
    "SAML2": INTEGRATION_TYPE_SAML2,
    "OAUTH": INTEGRATION_TYPE_OAUTH_SNOWFLAKE,
    "EXTERNAL_OAUTH": INTEGRATION_TYPE_EXTERNAL_OAUTH,
    "OIDC": INTEGRATION_TYPE_OIDC,
    "SCIM": INTEGRATION_TYPE_SCIM,
    "API_AUTHENTICATION": INTEGRATION_TYPE_API_AUTHENTICATION,
}


def categorize_integration_type(raw_type: object) -> str:
    if not isinstance(raw_type, str):
        return INTEGRATION_TYPE_UNKNOWN
    cleaned = raw_type.strip().upper()
    # SHOW INTEGRATIONS' `type` column may render as e.g. "OAUTH - SNOWFLAKE_OAUTH"
    # or "SAML2" alone depending on integration subtype — match the leading
    # token against the documented TYPE values rather than requiring an
    # exact full-string match.
    leading_token = cleaned.split(" ")[0].split("-")[0].strip()
    if "EXTERNAL_OAUTH" in cleaned:
        return INTEGRATION_TYPE_EXTERNAL_OAUTH
    return _INTEGRATION_TYPE_MAP.get(leading_token, INTEGRATION_TYPE_UNKNOWN)


# ── Storage-provider taxonomy ────────────────────────────────────────────────
#
# Confirmed via current official docs (CREATE STORAGE INTEGRATION
# reference): STORAGE_PROVIDER accepts S3, S3CHINA, S3GOV, GCS, AZURE.

STORAGE_PROVIDER_S3 = "s3"
STORAGE_PROVIDER_GCS = "gcs"
STORAGE_PROVIDER_AZURE = "azure"
STORAGE_PROVIDER_UNKNOWN = "unknown"

_STORAGE_PROVIDER_MAP = {
    "S3": STORAGE_PROVIDER_S3,
    "S3CHINA": STORAGE_PROVIDER_S3,
    "S3GOV": STORAGE_PROVIDER_S3,
    "GCS": STORAGE_PROVIDER_GCS,
    "AZURE": STORAGE_PROVIDER_AZURE,
}


def categorize_storage_provider(raw_provider: object) -> str:
    if not isinstance(raw_provider, str):
        return STORAGE_PROVIDER_UNKNOWN
    return _STORAGE_PROVIDER_MAP.get(raw_provider.strip().upper(), STORAGE_PROVIDER_UNKNOWN)
