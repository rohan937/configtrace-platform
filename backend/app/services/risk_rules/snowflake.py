"""Snowflake risk classification rules — foundation, identity/role, and
data-object security coverage (Snowflake messages 1-3 of 8).

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

- Message 3 (databases/schemas/warehouses/shares/object+future grants)
  classifies ownership and object/future grants with the same
  "preliminary, not effective-privilege" discipline as message 2: OWNERSHIP
  grants and grants to PUBLIC are classified more strongly, a direct grant
  to ACCOUNTADMIN is deliberately dampened (task convention — ACCOUNTADMIN
  already has near-total access by design, so an ordinary grant to it is
  never noise-worthy), and warehouse cost/performance settings are never
  treated as a security signal. A share's mere existence is never treated
  as "data is public" — Snowflake secure sharing is account-to-account
  only, never global.

Future messages (4-7) will add classifiers for network/authentication/
security integrations and privileged-role posture as those record types
are introduced — this module's dispatcher already fails safely into a
generic low-severity message for any ``snowflake_*`` record type that does
not have a classifier yet, so this module continues to work unmodified as
an incremental target for those insertions.
"""

from __future__ import annotations

from typing import Any

from app.connectors.snowflake_schema import (
    CAPABILITY_AVAILABLE,
    DISABLED_DISABLED,
    DISABLED_ENABLED,
    PRIVILEGE_CATEGORY_DATA_WRITE,
    PRIVILEGE_CATEGORY_MONITOR,
    PRIVILEGE_CATEGORY_OBJECT_CREATE,
    PRIVILEGE_CATEGORY_OPERATIONAL_CONTROL,
    PRIVILEGE_CATEGORY_OWNERSHIP,
    SNOWFLAKE_ACCOUNT,
    SNOWFLAKE_ACCOUNT_ROLE,
    SNOWFLAKE_API_CAPABILITY,
    SNOWFLAKE_DATABASE,
    SNOWFLAKE_DATABASE_ROLE,
    SNOWFLAKE_OBJECT_GRANT,
    SNOWFLAKE_ROLE_HIERARCHY_GRANT,
    SNOWFLAKE_SCHEMA,
    SNOWFLAKE_SHARE,
    SNOWFLAKE_USER,
    SNOWFLAKE_USER_ROLE_GRANT,
    SNOWFLAKE_WAREHOUSE,
)

# Preliminary privileged built-in role tiers used ONLY for message-2/3
# direct grant/hierarchy severity — message 5 owns the full
# effective-privilege graph and may deepen or override these.
_CRITICAL_BUILT_IN_ROLES = {"ACCOUNTADMIN", "SECURITYADMIN"}
_ACCOUNTADMIN = "ACCOUNTADMIN"
_PUBLIC = "PUBLIC"
_HIGH_IMPACT_PRIVILEGE_CATEGORIES = {
    PRIVILEGE_CATEGORY_OWNERSHIP,
    PRIVILEGE_CATEGORY_DATA_WRITE,
    PRIVILEGE_CATEGORY_OBJECT_CREATE,
    PRIVILEGE_CATEGORY_OPERATIONAL_CONTROL,
}
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


def _classify_ownership_change(change: object, *, kind: str) -> tuple[str, str]:
    """Shared owner-change classifier for database/schema/warehouse/share
    records. An ownership transfer TO a powerful built-in role is
    classified more strongly; an ordinary transfer between custom roles
    is Medium. Message 5 can deepen this using the full role graph."""
    fp = (_get(change, "field_path") or "").lower()
    if fp != "owner":
        return "low", f"A Snowflake {kind}'s metadata changed."
    new_owner = (_get(change, "new_value") or "")
    if isinstance(new_owner, str) and new_owner.strip().upper() in _CRITICAL_BUILT_IN_ROLES:
        return (
            "medium",
            f"A Snowflake {kind}'s ownership was transferred to a highly privileged built-in role.",
        )
    return "medium", f"A Snowflake {kind}'s ownership was transferred to a different role."


def _classify_database_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Snowflake database was added to monitoring."
    if ct == "removed":
        return "low", "A Snowflake database is no longer visible to ConfigTrace."
    return _classify_ownership_change(change, kind="database")


def _classify_schema_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Snowflake schema was added to monitoring."
    if ct == "removed":
        return "low", "A Snowflake schema is no longer visible to ConfigTrace."
    fp = (_get(change, "field_path") or "").lower()
    if fp == "managed_access":
        return "low", "A Snowflake schema's managed-access configuration changed."
    return _classify_ownership_change(change, kind="schema")


def _classify_warehouse_change(change: object) -> tuple[str, str]:
    """Warehouse cost/performance settings (size, auto_suspend, scaling
    policy) are NEVER treated as a security signal — only ownership is."""
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Snowflake warehouse was added to monitoring."
    if ct == "removed":
        return "low", "A Snowflake warehouse is no longer visible to ConfigTrace."
    return _classify_ownership_change(change, kind="warehouse")


def _classify_share_change(change: object) -> tuple[str, str]:
    """Share existence/broadening is Medium — Snowflake secure sharing is
    controlled account-to-account sharing, never treated as "data leaked"
    or "data is public"."""
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "medium", "A new Snowflake outbound data share was added — data sharing configuration broadened."
    if ct == "removed":
        return "low", "A Snowflake data share was removed."
    fp = (_get(change, "field_path") or "").lower()
    if fp == "consumer_count":
        pv = _get(change, "prev_value")
        nv = _get(change, "new_value")
        if isinstance(pv, int) and isinstance(nv, int):
            if nv > pv:
                return "medium", "A consumer account was added to a Snowflake data share — data sharing configuration broadened."
            if nv < pv:
                return "low", "A consumer account was removed from a Snowflake data share."
        return "low", "A Snowflake data share's consumer count changed."
    return _classify_ownership_change(change, kind="share")


def _classify_object_grant_change(change: object) -> tuple[str, str]:
    """Object/future-grant Change classification.

    ACCOUNTADMIN as grantee is deliberately dampened to Low — it already
    has near-total access by design, so an ordinary grant to it is
    expected, not noise-worthy (task convention, mirrors message 2's
    ACCOUNTADMIN-grant-context guidance). PUBLIC as grantee is classified
    more strongly, since it effectively broadens access to every user —
    especially for a future grant, which is bumped one tier further.
    """
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    grantee_name = (pm.get("grantee_name") or "").strip().upper()
    privilege = (pm.get("privilege") or "").strip().upper()
    privilege_category = pm.get("privilege_category") or ""
    future_grant = bool(pm.get("future_grant"))
    ownership = bool(pm.get("ownership")) or privilege == "OWNERSHIP"

    if ct == "removed":
        return "low", "A Snowflake object grant was revoked, a restrictive change."

    if ct != "added":
        # Metadata-only change on an otherwise-unchanged grant tuple
        # (e.g. grant_option flips) — never re-derive full added-severity
        # here; that only applies to a newly observed grant tuple.
        fp = (_get(change, "field_path") or "").lower()
        if fp == "grant_option":
            nv = _get(change, "new_value")
            if isinstance(nv, str) and nv.lower() == "true" and privilege_category in _HIGH_IMPACT_PRIVILEGE_CATEGORIES:
                return (
                    "high",
                    "Grant option was added to a Snowflake object grant with a powerful privilege, "
                    "allowing the grantee to further delegate access.",
                )
            return "low", "A Snowflake object grant's metadata changed."
        return "low", "A Snowflake object grant's metadata changed."

    # change_type == "added" from here.
    if grantee_name == _ACCOUNTADMIN:
        return "low", "ACCOUNTADMIN was granted a Snowflake privilege — expected given its built-in scope."

    future_note = "future " if future_grant else ""
    if grantee_name == _PUBLIC:
        if privilege_category == PRIVILEGE_CATEGORY_MONITOR and not future_grant:
            return "low", f"A {future_note}Snowflake MONITOR-only grant was made to PUBLIC."
        if ownership or privilege_category in _HIGH_IMPACT_PRIVILEGE_CATEGORIES or future_grant:
            # A future grant to PUBLIC is escalated regardless of
            # privilege category — newly created objects inheriting
            # PUBLIC access by default is especially significant (task
            # convention), stronger than an equivalent single-object grant.
            return (
                "high",
                f"A {future_note}Snowflake {privilege} grant was made to PUBLIC, broadening access to every user/role in the account.",
            )
        return (
            "medium",
            f"A {future_note}Snowflake {privilege} grant was made to PUBLIC, broadening access to every user/role in the account.",
        )

    if ownership:
        return "high", f"OWNERSHIP was granted on a Snowflake object to {grantee_name or 'a role'}."
    if privilege_category == PRIVILEGE_CATEGORY_MONITOR:
        return "low", "A Snowflake MONITOR-only grant was added."
    if future_grant:
        return "medium", f"A future Snowflake {privilege} grant was added — newly created objects may inherit this access."
    if privilege_category in _HIGH_IMPACT_PRIVILEGE_CATEGORIES:
        return "medium", f"A Snowflake {privilege} grant was added, broadening what the grantee can do."
    return "medium", f"A Snowflake {privilege} grant was added."


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
    if record_type == SNOWFLAKE_DATABASE:
        return _classify_database_change(change)
    if record_type == SNOWFLAKE_SCHEMA:
        return _classify_schema_change(change)
    if record_type == SNOWFLAKE_WAREHOUSE:
        return _classify_warehouse_change(change)
    if record_type == SNOWFLAKE_SHARE:
        return _classify_share_change(change)
    if record_type == SNOWFLAKE_OBJECT_GRANT:
        return _classify_object_grant_change(change)
    return "low", "A Snowflake configuration field changed."
