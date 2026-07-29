"""Snowflake risk classification rules — foundation, identity/role,
data-object, and security-policy coverage (Snowflake messages 1-4 of 8).

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

- Message 4 (network policies/rules, authentication policies, security/
  storage/external-access integrations) classifies broad-network-access
  introduction (0.0.0.0/0 or ::/0) as High, MFA-required-removed as High,
  and treats "unknown" broad-access/MFA state as never broad/never
  required (unknown-safe discipline) — a missing per-record DESCRIBE never
  silently implies the strongest OR weakest posture. Enabling a
  federated-SSO/OAuth/SCIM integration is Medium (posture broadened, not
  itself an incident); disabling one is Low (restrictive, though it could
  break functionality — message 6 owns whether that's itself a Finding).

Future messages (5-7) will add privileged-role/effective-privilege posture
as those record types are introduced — this module's dispatcher already
fails safely into a generic low-severity message for any ``snowflake_*``
record type that does not have a classifier yet, so this module continues
to work unmodified as an incremental target for those insertions.
"""

from __future__ import annotations

from typing import Any

from app.connectors.snowflake_schema import (
    BROAD_ACCESS_TRUE,
    CAPABILITY_AVAILABLE,
    DISABLED_DISABLED,
    DISABLED_ENABLED,
    MFA_ENROLLMENT_OPTIONAL,
    MFA_ENROLLMENT_REQUIRED,
    MFA_ENROLLMENT_REQUIRED_PASSWORD_ONLY,
    PRIVILEGE_CATEGORY_DATA_WRITE,
    PRIVILEGE_CATEGORY_MONITOR,
    PRIVILEGE_CATEGORY_OBJECT_CREATE,
    PRIVILEGE_CATEGORY_OPERATIONAL_CONTROL,
    PRIVILEGE_CATEGORY_OWNERSHIP,
    SNOWFLAKE_ACCOUNT,
    SNOWFLAKE_ACCOUNT_ROLE,
    SNOWFLAKE_API_CAPABILITY,
    SNOWFLAKE_AUTHENTICATION_POLICY,
    SNOWFLAKE_DATABASE,
    SNOWFLAKE_DATABASE_ROLE,
    SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION,
    SNOWFLAKE_NETWORK_POLICY,
    SNOWFLAKE_NETWORK_RULE,
    SNOWFLAKE_OBJECT_GRANT,
    SNOWFLAKE_ROLE_HIERARCHY_GRANT,
    SNOWFLAKE_SCHEMA,
    SNOWFLAKE_SECURITY_INTEGRATION,
    SNOWFLAKE_SHARE,
    SNOWFLAKE_STORAGE_INTEGRATION,
    SNOWFLAKE_USER,
    SNOWFLAKE_USER_ROLE_GRANT,
    SNOWFLAKE_WAREHOUSE,
)

# Preliminary privileged built-in role tiers used ONLY for message-2/3
# direct grant/hierarchy severity — message 5 owns the full
# effective-privilege graph and may deepen or override these.
_CRITICAL_BUILT_IN_ROLES = {"ACCOUNTADMIN", "SECURITYADMIN"}

_MFA_WEAKER_RANK = {
    MFA_ENROLLMENT_REQUIRED: 2,
    MFA_ENROLLMENT_REQUIRED_PASSWORD_ONLY: 1,
    MFA_ENROLLMENT_OPTIONAL: 0,
}
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


def _classify_network_policy_change(change: object) -> tuple[str, str]:
    """Broad-network-access (0.0.0.0/0 / ::/0) introduction is High.
    Unknown broad-access state is NEVER treated as broad (unknown-safe
    discipline) — only an explicit "true" escalates."""
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        raw_pm = _get(change, "provider_metadata")
        pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
        if pm.get("allows_anywhere_ipv4") == BROAD_ACCESS_TRUE or pm.get("allows_anywhere_ipv6") == BROAD_ACCESS_TRUE:
            return "high", "A new Snowflake network policy explicitly allows access from anywhere (0.0.0.0/0 or ::/0)."
        return "low", "A new Snowflake network policy was added to monitoring."
    if ct == "removed":
        return "medium", "A Snowflake network policy is no longer visible to ConfigTrace — protective network controls may have been removed."

    fp = (_get(change, "field_path") or "").lower()
    if fp in ("allows_anywhere_ipv4", "allows_anywhere_ipv6"):
        nv = _get(change, "new_value")
        pv = _get(change, "prev_value")
        if nv == BROAD_ACCESS_TRUE and pv != BROAD_ACCESS_TRUE:
            return "high", "A Snowflake network policy now allows access from anywhere (0.0.0.0/0 or ::/0) — broad network access introduced."
        if pv == BROAD_ACCESS_TRUE and nv != BROAD_ACCESS_TRUE:
            return "low", "A Snowflake network policy no longer allows access from anywhere — a restrictive change."
        return "low", "A Snowflake network policy's broad-access posture changed."
    if fp == "allowed_ipv4_count":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            return "medium", "A Snowflake network policy's allowed IP range count increased."
        return "low", "A Snowflake network policy's allowed IP range count changed."
    if fp == "blocked_ipv4_count":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if isinstance(nv, int) and isinstance(pv, int) and nv < pv:
            return "medium", "A Snowflake network policy's blocked IP range count decreased."
        return "low", "A Snowflake network policy's blocked IP range count changed."
    if fp == "owner":
        return "medium", "A Snowflake network policy's ownership was transferred to a different role."
    return "low", "A Snowflake network policy's metadata changed."


def _classify_network_rule_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Snowflake network rule was added to monitoring."
    if ct == "removed":
        return "low", "A Snowflake network rule is no longer visible to ConfigTrace."
    return "low", "A Snowflake network rule's metadata changed."


def _classify_authentication_policy_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Snowflake authentication policy was added to monitoring."
    if ct == "removed":
        return "medium", "A Snowflake authentication policy is no longer visible to ConfigTrace — an authentication requirement may have been removed."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "mfa_enrollment":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        nv_rank = _MFA_WEAKER_RANK.get(nv, None)
        pv_rank = _MFA_WEAKER_RANK.get(pv, None)
        if nv_rank is not None and pv_rank is not None:
            if nv_rank < pv_rank:
                return "high", "A Snowflake authentication policy's MFA enrollment requirement was weakened."
            if nv_rank > pv_rank:
                return "low", "A Snowflake authentication policy's MFA enrollment requirement was strengthened."
        return "low", "A Snowflake authentication policy's MFA enrollment setting changed."
    if fp == "authentication_methods":
        nv = _get(change, "new_value") or []
        pv = _get(change, "prev_value") or []
        if isinstance(nv, list) and isinstance(pv, list):
            if set(nv) - set(pv):
                return "medium", "A Snowflake authentication policy's allowed authentication methods were broadened."
            if set(pv) - set(nv):
                return "low", "A Snowflake authentication policy's allowed authentication methods were narrowed."
        return "low", "A Snowflake authentication policy's allowed authentication methods changed."
    if fp == "client_types":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if nv == "all" and pv == "restricted":
            return "medium", "A Snowflake authentication policy's allowed client types were broadened to all clients."
        return "low", "A Snowflake authentication policy's allowed client types changed."
    if fp == "owner":
        return "medium", "A Snowflake authentication policy's ownership was transferred to a different role."
    return "low", "A Snowflake authentication policy's metadata changed."


def _classify_security_integration_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    enabled = pm.get("enabled")
    integration_type = pm.get("integration_type") or ""

    if ct == "added":
        if enabled == "true":
            return "medium", f"A new Snowflake {integration_type} security integration was added and enabled."
        return "low", f"A new Snowflake {integration_type} security integration was added (disabled)."
    if ct == "removed":
        if enabled == "true":
            return "medium", f"An enabled Snowflake {integration_type} security integration is no longer visible to ConfigTrace."
        return "low", "A Snowflake security integration is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "enabled":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if nv == "true" and pv != "true":
            return "medium", f"A Snowflake {integration_type} security integration was enabled."
        if pv == "true" and nv != "true":
            return "low", f"A Snowflake {integration_type} security integration was disabled."
        return "low", "A Snowflake security integration's enabled state changed."
    if fp == "scim_run_as_role":
        return "medium", "A Snowflake SCIM integration's run-as role changed. Full privilege context is evaluated in a later message."
    return "low", "A Snowflake security integration's metadata changed."


def _classify_storage_integration_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Snowflake storage integration was added to monitoring."
    if ct == "removed":
        return "low", "A Snowflake storage integration is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "enabled":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if nv == "true" and pv != "true":
            return "medium", "A Snowflake storage integration was enabled."
        return "low", "A Snowflake storage integration's enabled state changed."
    if fp == "allowed_location_count":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            return "medium", "A Snowflake storage integration's allowed storage locations were broadened."
        return "low", "A Snowflake storage integration's allowed location count changed."
    if fp == "blocked_location_count":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if isinstance(nv, int) and isinstance(pv, int) and nv < pv:
            return "medium", "A Snowflake storage integration's blocked storage locations were reduced."
        return "low", "A Snowflake storage integration's blocked location count changed."
    return "low", "A Snowflake storage integration's metadata changed."


def _classify_external_access_integration_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "medium", "A new Snowflake external access integration was added, permitting outbound connectivity for UDFs/procedures."
    if ct == "removed":
        return "low", "A Snowflake external access integration is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "enabled":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if nv == "true" and pv != "true":
            return "medium", "A Snowflake external access integration was enabled."
        return "low", "A Snowflake external access integration's enabled state changed."
    if fp == "allowed_network_rule_count":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            return "medium", "A Snowflake external access integration's allowed network rules increased."
        return "low", "A Snowflake external access integration's allowed network rule count changed."
    if fp in ("allowed_secret_count", "allowed_api_authentication_integration_count"):
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            return "medium", "A Snowflake external access integration's allowed secret/API-authentication references increased."
        return "low", "A Snowflake external access integration's metadata changed."
    return "low", "A Snowflake external access integration's metadata changed."


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
    if record_type == SNOWFLAKE_NETWORK_POLICY:
        return _classify_network_policy_change(change)
    if record_type == SNOWFLAKE_NETWORK_RULE:
        return _classify_network_rule_change(change)
    if record_type == SNOWFLAKE_AUTHENTICATION_POLICY:
        return _classify_authentication_policy_change(change)
    if record_type == SNOWFLAKE_SECURITY_INTEGRATION:
        return _classify_security_integration_change(change)
    if record_type == SNOWFLAKE_STORAGE_INTEGRATION:
        return _classify_storage_integration_change(change)
    if record_type == SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION:
        return _classify_external_access_integration_change(change)
    return "low", "A Snowflake configuration field changed."
