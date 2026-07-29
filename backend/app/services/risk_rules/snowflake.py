"""Snowflake risk classification rules — foundation + identity/role
coverage (Snowflake messages 1-2 of 8).

This module exists to give every ``snowflake_*`` record type a dedicated,
correct classifier so that ``risk_service.classify_change()`` never falls
through to an unrelated provider's default classifier.

This is intentionally NOT a Security Finding taxonomy — that is message 6.
Classification here is deliberately structural, not incident-level:

- An account identity metadata change (organization/account name, locator,
  monitoring role) is Low — these are informational identity fields, not
  security posture by themselves.
- A capability probe losing access is a Medium diagnostic signal, never a
  "security incident" — permission changes are common and expected (e.g.
  the monitoring role's grants being intentionally re-scoped), not proof
  of compromise. Regaining access is Low.
- Message 2 (users/account roles/database roles/user-role grants/role
  hierarchy) classifies DIRECT grants and hierarchy EDGES only — these are
  preliminary severities, not effective-privilege computation (message 5
  traverses the graph and can deepen/override these). A user gaining
  ACCOUNTADMIN or SECURITYADMIN directly is classified more strongly than
  an ordinary custom-role grant, per repository convention for
  privileged-role visibility (see Okta/Entra privileged-identity
  classifiers), but this module never asserts an incident by itself.
- Inventory growth (new user, new role, new database role) is always Low —
  a service user or custom role coming into existence is not inherently
  risky; only privileged grants/hierarchy edges carry elevated severity.

Future messages (3-7) will add classifiers for databases/schemas/
warehouses/shares/object grants, network/authentication policies,
security/storage/external-access integrations, and privileged-role
posture as those record types are introduced — this module's dispatcher
already fails safely into a generic low-severity message for any
``snowflake_*`` record type that does not have a classifier yet, so this
module continues to work unmodified as an incremental target for those
insertions.
"""

from __future__ import annotations

from typing import Any

from app.connectors.snowflake_schema import (
    CAPABILITY_AVAILABLE,
    DISABLED_DISABLED,
    DISABLED_ENABLED,
    SNOWFLAKE_ACCOUNT,
    SNOWFLAKE_ACCOUNT_ROLE,
    SNOWFLAKE_API_CAPABILITY,
    SNOWFLAKE_DATABASE_ROLE,
    SNOWFLAKE_ROLE_HIERARCHY_GRANT,
    SNOWFLAKE_USER,
    SNOWFLAKE_USER_ROLE_GRANT,
)

# Preliminary privileged built-in role tiers used ONLY for message-2 direct
# grant/hierarchy severity — message 5 owns the full effective-privilege
# graph and may deepen or override these.
_CRITICAL_BUILT_IN_ROLES = {"ACCOUNTADMIN", "SECURITYADMIN"}
_ELEVATED_BUILT_IN_ROLES = {"SYSADMIN", "USERADMIN"}


def _get(obj: Any, field: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _classify_account_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Snowflake account was added to monitoring."
    if ct == "removed":
        return (
            "medium",
            "A Snowflake account is no longer visible to ConfigTrace. "
            "Verify the integration still has a valid programmatic access token.",
        )

    fp = (_get(change, "field_path") or "").lower()
    if fp in ("organization_name", "account_name", "account_locator", "monitoring_role"):
        return "low", "The Snowflake account's identifying metadata changed."
    return "low", "A Snowflake account configuration field changed."


def _classify_api_capability_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Snowflake API capability probe was recorded."
    if ct == "removed":
        return "low", "A Snowflake API capability probe is no longer recorded."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "status":
        nv = _get(change, "new_value")
        pv = _get(change, "prev_value")
        if pv == CAPABILITY_AVAILABLE and nv != CAPABILITY_AVAILABLE:
            return (
                "medium",
                "ConfigTrace's Snowflake monitoring role lost read access to a "
                "previously available metadata family. Review the role's "
                "grants if this was not expected.",
            )
        if pv != CAPABILITY_AVAILABLE and nv == CAPABILITY_AVAILABLE:
            return "low", "ConfigTrace's Snowflake monitoring role gained read access to a metadata family."
        return "low", "A Snowflake API capability probe's status changed."
    return "low", "A Snowflake API capability record changed."


def _classify_user_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Snowflake user was added to monitoring."
    if ct == "removed":
        return "low", "A Snowflake user is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "disabled":
        nv = (_get(change, "new_value") or "")
        pv = (_get(change, "prev_value") or "")
        if pv == DISABLED_DISABLED and nv == DISABLED_ENABLED:
            return (
                "medium",
                "A previously disabled Snowflake user was re-enabled, restoring its login access.",
            )
        if pv == DISABLED_ENABLED and nv == DISABLED_DISABLED:
            return "low", "A Snowflake user was disabled, a restrictive change."
        return "low", "A Snowflake user's disabled state changed."
    if fp == "default_role":
        nv = (_get(change, "new_value") or "")
        if isinstance(nv, str) and nv.strip().upper() in _CRITICAL_BUILT_IN_ROLES:
            return (
                "medium",
                "A Snowflake user's default role was changed to a highly privileged built-in role. "
                "Full effective-privilege context is evaluated in a later message.",
            )
        return "low", "A Snowflake user's default role changed."
    return "low", "A Snowflake user's metadata changed."


def _classify_account_role_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Snowflake account role was added to monitoring."
    if ct == "removed":
        return "low", "A Snowflake account role is no longer visible to ConfigTrace."
    return "low", "A Snowflake account role's metadata changed."


def _classify_database_role_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Snowflake database role was added to monitoring."
    if ct == "removed":
        return "low", "A Snowflake database role is no longer visible to ConfigTrace."
    return "low", "A Snowflake database role's metadata changed."


def _role_name_from_change(change: object) -> str:
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    role_name = pm.get("role_name") or pm.get("parent_role_name")
    return role_name.strip().upper() if isinstance(role_name, str) else ""


def _classify_user_role_grant_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    role_name = _role_name_from_change(change)
    if ct == "added":
        if role_name in _CRITICAL_BUILT_IN_ROLES:
            return (
                "high",
                f"A Snowflake user was granted the {role_name} role directly. "
                "Full effective-privilege context is evaluated in a later message.",
            )
        if role_name in _ELEVATED_BUILT_IN_ROLES:
            return "medium", f"A Snowflake user was granted the {role_name} role directly."
        return "low", "A Snowflake user was granted an account role."
    if ct == "removed":
        return "low", "A Snowflake user-role grant was revoked, a restrictive change."
    return "low", "A Snowflake user-role grant's metadata changed."


def _classify_role_hierarchy_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    role_name = _role_name_from_change(change)
    if ct == "added":
        if role_name in _CRITICAL_BUILT_IN_ROLES:
            return (
                "high",
                f"A Snowflake role hierarchy edge was added with {role_name} as the parent role, "
                "broadening effective privileges. Full transitive-privilege computation is a later message.",
            )
        return (
            "medium",
            "A Snowflake role hierarchy edge was added, which can broaden the child role's effective privileges.",
        )
    if ct == "removed":
        return "low", "A Snowflake role hierarchy edge was removed, a restrictive change."
    return "low", "A Snowflake role hierarchy edge's metadata changed."


def classify_snowflake_change(change: object) -> tuple[str, str]:
    """Route a Snowflake Change to its record-type classifier.

    Unknown/future ``snowflake_*`` record types (i.e. any later-message
    planned taxonomy, before their classifiers exist) fail safely into a
    generic low-severity message rather than raising or falling through
    to an unrelated provider's classifier.
    """
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    record_type = (pm.get("record_type") or "").lower()

    if record_type == SNOWFLAKE_ACCOUNT:
        return _classify_account_change(change)
    if record_type == SNOWFLAKE_API_CAPABILITY:
        return _classify_api_capability_change(change)
    if record_type == SNOWFLAKE_USER:
        return _classify_user_change(change)
    if record_type == SNOWFLAKE_ACCOUNT_ROLE:
        return _classify_account_role_change(change)
    if record_type == SNOWFLAKE_DATABASE_ROLE:
        return _classify_database_role_change(change)
    if record_type == SNOWFLAKE_USER_ROLE_GRANT:
        return _classify_user_role_grant_change(change)
    if record_type == SNOWFLAKE_ROLE_HIERARCHY_GRANT:
        return _classify_role_hierarchy_change(change)
    return "low", "A Snowflake configuration field changed."
