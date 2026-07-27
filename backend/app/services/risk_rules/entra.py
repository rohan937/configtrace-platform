"""Microsoft Entra ID risk classification rules — foundation + identity
lifecycle (Entra messages 1-2 of 8).

This module exists to give every ``entra_*`` record type a dedicated,
correct classifier so that ``risk_service.classify_change()`` never falls
through to the unrelated Cloudflare DNS default classifier.

This is intentionally NOT a Security Finding taxonomy — that is message 6.
Classification here is deliberately structural, not incident-level:

- A tenant organization metadata change is informational to medium.
- A capability probe losing access is an informational/medium diagnostic
  signal, never a "security incident" — permission changes are common and
  expected (e.g. an app registration's assigned application permissions
  being intentionally re-scoped), not proof of compromise.
- User lifecycle transitions are classified by DIRECTION, not by treating
  guest or disabled as inherently risky. account_enabled False->True
  restores access and is Medium; True->False is a restriction and is Low.
  Guest/member identity is a normal category, never itself a severity
  signal ("guest == risky" is never implied).
- Group changes: ordinary rename/mail-enabled/M365-category changes are
  Low. securityEnabled False->True and dynamic-membership False->True are
  Medium (broadens automated/security posture). A group becoming
  role-assignable (isAssignableToRole False->True) is classified High —
  the group becomes ELIGIBLE for directory role assignment (a structural
  privilege-surface change), though no actual directory-role assignment is
  modeled until message 5.
- Membership changes are Low/Medium by default; a guest added to a
  security-enabled group, or a user added to a role-assignable group, is
  Medium — described conservatively ("a guest user was added to a
  security-enabled group"), never as confirmed unauthorized access or
  privilege escalation.
"""

from __future__ import annotations

from typing import Any

from app.connectors.entra_schema import (
    CAPABILITY_AVAILABLE,
    ENTRA_API_CAPABILITY,
    ENTRA_GROUP,
    ENTRA_GROUP_MEMBERSHIP,
    ENTRA_ORGANIZATION,
    ENTRA_USER,
    EXTERNAL_USER_STATE_ACCEPTED,
    EXTERNAL_USER_STATE_PENDING,
)


def _get(obj: Any, field: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _classify_organization_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Microsoft Entra ID tenant was added to monitoring."
    if ct == "removed":
        return (
            "medium",
            "A Microsoft Entra ID tenant is no longer visible to ConfigTrace. "
            "Verify the integration still has a valid app registration credential.",
        )

    fp = (_get(change, "field_path") or "").lower()
    if fp in ("display_name", "default_verified_domain"):
        return "low", "The Microsoft Entra ID tenant's identifying metadata changed."
    if fp == "on_premises_sync_enabled_category":
        return (
            "medium",
            "The Microsoft Entra ID tenant's on-premises directory sync "
            "posture changed. Verify this is expected.",
        )
    return "low", "A Microsoft Entra ID tenant configuration field changed."


def _classify_api_capability_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Microsoft Graph API capability probe was recorded."
    if ct == "removed":
        return "low", "A Microsoft Graph API capability probe is no longer recorded."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "status":
        nv = _get(change, "new_value")
        pv = _get(change, "prev_value")
        if pv == CAPABILITY_AVAILABLE and nv != CAPABILITY_AVAILABLE:
            return (
                "medium",
                "ConfigTrace's Microsoft Entra ID app registration lost read "
                "access to a previously available Microsoft Graph API family. "
                "Review the app registration's assigned application "
                "permissions if this was not expected.",
            )
        if pv != CAPABILITY_AVAILABLE and nv == CAPABILITY_AVAILABLE:
            return "low", "ConfigTrace's Microsoft Entra ID app registration gained read access to an API family."
        return "low", "A Microsoft Graph API capability probe's status changed."
    return "low", "A Microsoft Entra ID API capability record changed."


def _classify_user_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        # A new user is visible as an identity addition regardless of
        # enabled/guest status; never automatically High.
        return "low", "A Microsoft Entra ID user was added to the identity inventory."
    if ct == "removed":
        return (
            "low",
            "A Microsoft Entra ID user is no longer present in the observed "
            "Entra snapshot. This reflects the collected snapshot — it does "
            "not by itself confirm the user was deleted in Entra.",
        )

    fp = (_get(change, "field_path") or "")
    if fp == "account_enabled_category":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if nv == "enabled" and pv in ("disabled", "unknown"):
            return "medium", "A Microsoft Entra ID user's account was enabled — access has been restored. Verify this was expected."
        if nv == "disabled" and pv in ("enabled", "unknown"):
            return "low", "A Microsoft Entra ID user's account was disabled. This is commonly an intended restriction, not a weakening."
        if nv == "unknown":
            return "medium", "A Microsoft Entra ID user's account-enabled state became unrecognized/unknown — treat as needing review."
        return "low", "A Microsoft Entra ID user's account-enabled state changed."
    if fp == "lifecycle_posture":
        nv = _get(change, "new_value")
        if nv == "unknown":
            return "medium", "A Microsoft Entra ID user's lifecycle posture became unrecognized/unknown."
        return "low", "A Microsoft Entra ID user's lifecycle posture changed."
    if fp == "user_type_category":
        nv = _get(change, "new_value")
        if nv == "unknown":
            return "medium", "A Microsoft Entra ID user's account type became unrecognized/unknown — treat as needing review."
        return "low", "A Microsoft Entra ID user's account type (member/guest) changed."
    if fp in ("guest", "member"):
        return "low", "A Microsoft Entra ID user's member/guest classification changed."
    if fp == "external_user_state_category":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if pv == EXTERNAL_USER_STATE_PENDING and nv == EXTERNAL_USER_STATE_ACCEPTED:
            return "medium", "A Microsoft Entra ID guest invitation was accepted — the guest's access is now active."
        if nv == "unknown":
            return "medium", "A Microsoft Entra ID user's external invitation state became unrecognized/unknown."
        return "low", "A Microsoft Entra ID user's external invitation state changed."
    if fp in ("user_principal_name", "display_name"):
        return "low", "A Microsoft Entra ID user's identity display field changed."
    if fp == "on_premises_sync_enabled_category":
        return "medium", "A Microsoft Entra ID user's on-premises directory sync posture changed. Verify this is expected."
    return "low", "A Microsoft Entra ID user configuration field changed."


def _classify_group_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Microsoft Entra ID group was added to the identity inventory."
    if ct == "removed":
        return (
            "low",
            "A Microsoft Entra ID group is no longer present in the observed "
            "Entra snapshot. This reflects the collected snapshot — it does "
            "not by itself confirm the group was deleted in Entra.",
        )

    fp = (_get(change, "field_path") or "")
    if fp == "role_assignable":
        nv = _get(change, "new_value")
        if nv is True:
            return (
                "high",
                "A Microsoft Entra ID group became eligible for directory "
                "role assignment (isAssignableToRole). This does not by "
                "itself grant any privilege — no directory role is modeled "
                "until an actual role assignment exists — but it is a "
                "structural change to the tenant's privilege surface.",
            )
        if nv is False:
            return "low", "A Microsoft Entra ID group is no longer eligible for directory role assignment."
        return "medium", "A Microsoft Entra ID group's role-assignable eligibility became unrecognized/unknown."
    if fp == "security_enabled":
        nv = _get(change, "new_value")
        if nv is True:
            return "medium", "A Microsoft Entra ID group became security-enabled."
        if nv is False:
            return "low", "A Microsoft Entra ID group is no longer security-enabled."
        return "medium", "A Microsoft Entra ID group's security-enabled state became unrecognized/unknown."
    if fp == "dynamic_membership":
        nv = _get(change, "new_value")
        if nv is True:
            return (
                "medium",
                "A Microsoft Entra ID group's membership became dynamic — "
                "membership may now broaden automatically based on a rule. "
                "ConfigTrace does not evaluate the membership rule itself.",
            )
        return "low", "A Microsoft Entra ID group's membership is no longer dynamic."
    if fp == "mail_enabled":
        return "low", "A Microsoft Entra ID group's mail-enabled state changed."
    if fp == "group_type_category":
        return "low", "A Microsoft Entra ID group's type category changed."
    if fp == "group_types":
        return "low", "A Microsoft Entra ID group's type flags changed."
    if fp == "display_name":
        return "low", "A Microsoft Entra ID group was renamed."
    if fp == "membership_count":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is None or nv_i is None:
            return "low", "A Microsoft Entra ID group's membership count became unknown or was newly determined."
        if nv_i > pv_i:
            return "low", f"A Microsoft Entra ID group's membership count increased ({pv_i} -> {nv_i})."
        return "low", f"A Microsoft Entra ID group's membership count decreased ({pv_i} -> {nv_i})."
    return "low", "A Microsoft Entra ID group configuration field changed."


def _classify_membership_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    new_value = _get(change, "new_value")
    prev_value = _get(change, "prev_value")
    context = new_value if isinstance(new_value, dict) else (prev_value if isinstance(prev_value, dict) else pm)

    role_assignable_group = context.get("role_assignable_group") if isinstance(context, dict) else None
    user_type_category = context.get("user_type_category") if isinstance(context, dict) else None
    group_type_category = context.get("group_type_category") if isinstance(context, dict) else None
    is_guest = user_type_category == "Guest"
    is_security_group = group_type_category in ("security", "dynamic_security")

    if ct == "added":
        if role_assignable_group is True:
            return (
                "medium",
                "A Microsoft Entra ID user was added to a group that is "
                "eligible for directory role assignment. No directory role "
                "assignment is modeled until message 5 — this is not "
                "confirmed privilege escalation.",
            )
        if is_guest and is_security_group:
            return "medium", "A guest user was added to a security-enabled Microsoft Entra ID group."
        return "low", "A Microsoft Entra ID user was added to a group."
    if ct == "removed":
        return "low", "A Microsoft Entra ID user is no longer a member of a group."
    return "low", "A Microsoft Entra ID group membership record changed."


def classify_entra_change(change: object) -> tuple[str, str]:
    """Route an Entra Change to its record-type classifier.

    Unknown/future ``entra_*`` record types (i.e. any later-message planned
    taxonomy, before their classifiers exist) fail safely into a generic
    low-severity message rather than raising or falling through to an
    unrelated provider's classifier.
    """
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    record_type = (pm.get("record_type") or "").lower()

    if record_type == ENTRA_ORGANIZATION:
        return _classify_organization_change(change)
    if record_type == ENTRA_API_CAPABILITY:
        return _classify_api_capability_change(change)
    if record_type == ENTRA_USER:
        return _classify_user_change(change)
    if record_type == ENTRA_GROUP:
        return _classify_group_change(change)
    if record_type == ENTRA_GROUP_MEMBERSHIP:
        return _classify_membership_change(change)

    return "low", f"A Microsoft Entra ID configuration record changed ({record_type or 'unknown record type'})."
