"""Okta risk classification rules — foundation + identity lifecycle
(Okta messages 1-2 of 8).

This module exists to give every ``okta_*`` record type a dedicated,
correct classifier so that ``risk_service.classify_change()`` never falls
through to the unrelated Cloudflare DNS default classifier.

This is intentionally NOT a Security Finding taxonomy — that is message 6.
Classification here is deliberately structural, not incident-level:

- An org status/tenant posture change is informational to medium.
- A capability probe losing access is an informational/medium diagnostic
  signal, never a "security incident" — permission changes are common and
  expected (e.g. a scoped API token being intentionally re-scoped), not
  proof of compromise.
- User lifecycle transitions are classified by DIRECTION, not by treating
  any particular status as inherently bad. Restrictive transitions
  (active -> suspended/locked/deprovisioned) are informational/low — they
  are very often the intended safety action, not a weakening. Access-
  restoring transitions (suspended/locked/deprovisioned -> active) are
  medium, because access has been (re-)granted and is worth a look — never
  described as "unauthorized," since restoration is frequently a
  legitimate, deliberate admin action.
- Group/membership churn is low/medium with no privilege claims — message
  5 will add the admin-role/privileged-group context needed to say more.
"""

from __future__ import annotations

from typing import Any

from app.connectors.okta_schema import (
    CAPABILITY_AVAILABLE,
    LIFECYCLE_ACTIVE,
    LIFECYCLE_DEPROVISIONED,
    LIFECYCLE_LOCKED,
    LIFECYCLE_PASSWORD_EXPIRED,
    LIFECYCLE_PRE_ACTIVE,
    LIFECYCLE_RECOVERY,
    LIFECYCLE_SUSPENDED,
    LIFECYCLE_UNKNOWN,
    OKTA_API_CAPABILITY,
    OKTA_GROUP,
    OKTA_GROUP_MEMBERSHIP,
    OKTA_ORGANIZATION,
    OKTA_USER,
    ORG_STATUS_ACTIVE,
    lifecycle_posture_for_status,
)


def _get(obj: Any, field: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _classify_organization_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "An Okta organization was added to monitoring."
    if ct == "removed":
        return (
            "medium",
            "An Okta organization is no longer visible to ConfigTrace. "
            "Verify the integration still has a valid API token.",
        )

    fp = (_get(change, "field_path") or "").lower()
    if fp == "status_category":
        nv = _get(change, "new_value")
        if nv != ORG_STATUS_ACTIVE:
            return (
                "medium",
                f"The Okta organization's status changed to {nv!r}, which is "
                "not 'active'. Verify this is expected.",
            )
        return "low", "The Okta organization's status changed."
    if fp in ("org_hostname", "org_display_name"):
        return "low", "The Okta organization's identifying metadata changed."
    return "low", "An Okta organization configuration field changed."


def _classify_api_capability_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Okta API capability probe was recorded."
    if ct == "removed":
        return "low", "An Okta API capability probe is no longer recorded."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "status":
        nv = _get(change, "new_value")
        pv = _get(change, "prev_value")
        if pv == CAPABILITY_AVAILABLE and nv != CAPABILITY_AVAILABLE:
            return (
                "medium",
                "ConfigTrace's Okta API token lost read access to a "
                "previously available API family. Review the token's "
                "assigned admin role/scopes if this was not expected.",
            )
        if pv != CAPABILITY_AVAILABLE and nv == CAPABILITY_AVAILABLE:
            return "low", "ConfigTrace's Okta API token gained read access to an API family."
        return "low", "An Okta API capability probe's status changed."
    return "low", "An Okta API capability record changed."


# Restrictive transitions: the user's access is being narrowed. These are
# usually the INTENDED safety/offboarding action, not a weakening — kept
# informational/low, never High, per the direction given in this
# message's spec.
_RESTRICTIVE_TARGETS = frozenset({
    LIFECYCLE_SUSPENDED, LIFECYCLE_DEPROVISIONED, LIFECYCLE_LOCKED,
})

# Access-restoring transitions: a previously-restricted user regains (or
# is granted) access. Worth surfacing at Medium because access changed,
# but never described as unauthorized — restoration is frequently a
# legitimate, deliberate admin action.
_RESTORING_SOURCES = frozenset({
    LIFECYCLE_SUSPENDED, LIFECYCLE_DEPROVISIONED, LIFECYCLE_LOCKED,
})

_LIFECYCLE_LABELS = {
    LIFECYCLE_ACTIVE: "active",
    LIFECYCLE_PRE_ACTIVE: "pre-active",
    LIFECYCLE_RECOVERY: "recovery",
    LIFECYCLE_LOCKED: "locked out",
    LIFECYCLE_PASSWORD_EXPIRED: "password-expired",
    LIFECYCLE_SUSPENDED: "suspended",
    LIFECYCLE_DEPROVISIONED: "deprovisioned",
    LIFECYCLE_UNKNOWN: "an unrecognized/unknown",
}


def _classify_user_status_transition(prev_status: object, new_status: object) -> tuple[str, str]:
    """Classify a user's ``status`` field transition by direction.

    Never treats SUSPENDED and DEPROVISIONED as equivalent — they're
    reported with their own distinct posture label — and never claims
    termination or compromise from status alone.
    """
    prev_posture = lifecycle_posture_for_status(prev_status) if isinstance(prev_status, str) else LIFECYCLE_UNKNOWN
    new_posture = lifecycle_posture_for_status(new_status) if isinstance(new_status, str) else LIFECYCLE_UNKNOWN
    prev_label = _LIFECYCLE_LABELS.get(prev_posture, "an unrecognized/unknown")
    new_label = _LIFECYCLE_LABELS.get(new_posture, "an unrecognized/unknown")

    if new_posture == LIFECYCLE_UNKNOWN:
        return (
            "medium",
            f"An Okta user's lifecycle status changed to an unrecognized value "
            f"({new_status!r}) — treat as needing review since it cannot be "
            "safely categorized.",
        )

    if new_posture in _RESTRICTIVE_TARGETS and prev_posture == LIFECYCLE_ACTIVE:
        return (
            "low",
            f"An Okta user's lifecycle status changed from active to {new_label}. "
            "This is commonly an intended restriction, not a weakening.",
        )

    if new_posture == LIFECYCLE_ACTIVE and prev_posture in _RESTORING_SOURCES:
        return (
            "medium",
            f"An Okta user's lifecycle status changed from {prev_label} to active — "
            "access has been restored. Verify this was expected.",
        )

    if {prev_posture, new_posture} == {LIFECYCLE_ACTIVE, LIFECYCLE_PASSWORD_EXPIRED}:
        return "low", f"An Okta user's lifecycle status changed from {prev_label} to {new_label}."

    if {prev_posture, new_posture} == {LIFECYCLE_ACTIVE, LIFECYCLE_RECOVERY}:
        return "low", f"An Okta user's lifecycle status changed from {prev_label} to {new_label}."

    if prev_posture == LIFECYCLE_PRE_ACTIVE and new_posture == LIFECYCLE_ACTIVE:
        return "low", "An Okta user completed activation and is now active."

    return "low", f"An Okta user's lifecycle status changed from {prev_label} to {new_label}."


def _classify_user_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        # A new user is visible as an identity addition regardless of its
        # starting lifecycle status; never automatically High.
        return "low", "An Okta user was added to the identity inventory."
    if ct == "removed":
        return (
            "low",
            "An Okta user is no longer visible to ConfigTrace. This reflects "
            "the collected snapshot — it does not by itself confirm the user "
            "was deleted in Okta.",
        )

    fp = (_get(change, "field_path") or "")
    if fp == "status":
        return _classify_user_status_transition(_get(change, "prev_value"), _get(change, "new_value"))
    if fp == "lifecycle_posture":
        nv = _get(change, "new_value")
        if nv == LIFECYCLE_UNKNOWN:
            return "medium", "An Okta user's lifecycle posture became unrecognized/unknown."
        return "low", "An Okta user's lifecycle posture changed."
    if fp in ("suspended", "locked_out", "password_expired", "deprovisioned"):
        nv = _get(change, "new_value")
        if nv is True:
            return "low", f"An Okta user's {fp.replace('_', ' ')} flag was set."
        return "medium", f"An Okta user's {fp.replace('_', ' ')} flag was cleared — access may have been restored."
    if fp in ("login", "display_name"):
        return "low", "An Okta user's identity display field changed."
    if fp in ("user_type_id", "credential_provider_category"):
        return "low", "An Okta user's account category changed."
    return "low", "An Okta user configuration field changed."


def _classify_group_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "An Okta group was added to the identity inventory."
    if ct == "removed":
        return (
            "low",
            "An Okta group is no longer visible to ConfigTrace. This reflects "
            "the collected snapshot — it does not by itself confirm the group "
            "was deleted in Okta.",
        )

    fp = (_get(change, "field_path") or "")
    if fp == "built_in":
        nv = _get(change, "new_value")
        # Deterministic evidence only: the record's own `type` field
        # flipped to/from BUILT_IN. Still kept at medium (not high) absent
        # further context — message 5 will know which groups are actually
        # privileged/admin-scoped.
        if nv is True:
            return "medium", "An Okta group's type changed to a built-in/system category."
        return "low", "An Okta group's type changed away from a built-in/system category."
    if fp == "group_type":
        return "low", "An Okta group's type changed."
    if fp == "group_name":
        return "low", "An Okta group was renamed."
    if fp == "membership_count":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is None or nv_i is None:
            return "low", "An Okta group's membership count became unknown or was newly determined."
        if nv_i > pv_i:
            return "low", f"An Okta group's membership count increased ({pv_i} -> {nv_i})."
        return "low", f"An Okta group's membership count decreased ({pv_i} -> {nv_i})."
    return "low", "An Okta group configuration field changed."


def _classify_membership_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    pm = _get(change, "provider_metadata")
    pm = pm if isinstance(pm, dict) else {}
    group_built_in = None
    if isinstance(_get(change, "new_value"), dict):
        group_built_in = _get(change, "new_value").get("built_in_group")
    elif isinstance(_get(change, "prev_value"), dict):
        group_built_in = _get(change, "prev_value").get("built_in_group")

    if ct == "added":
        if group_built_in is True:
            return "low", "A user was added to a built-in/system Okta group."
        return "low", "A user was added to an Okta group."
    if ct == "removed":
        if group_built_in is True:
            return "low", "A user was removed from a built-in/system Okta group."
        return "low", "A user was removed from an Okta group."

    fp = (_get(change, "field_path") or "")
    if fp == "user_status":
        return "low", "A group member's user status changed (see the user's own record for lifecycle detail)."
    if fp == "built_in_group":
        return "low", "A group membership's built-in/system category changed."
    if fp == "group_type":
        return "low", "A group membership's group type changed."
    return "low", "An Okta group membership field changed."


def classify_okta_change(change: object) -> tuple[str, str]:
    """Route an Okta Change to its record-type classifier.

    Unknown/future ``okta_*`` record types (i.e. any later-message planned
    taxonomy, before their classifiers exist) fail safely into a generic
    low-severity message rather than raising or falling through to an
    unrelated provider's classifier.
    """
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    record_type = (pm.get("record_type") or "").lower()

    if record_type == OKTA_ORGANIZATION:
        return _classify_organization_change(change)
    if record_type == OKTA_API_CAPABILITY:
        return _classify_api_capability_change(change)
    if record_type == OKTA_USER:
        return _classify_user_change(change)
    if record_type == OKTA_GROUP:
        return _classify_group_change(change)
    if record_type == OKTA_GROUP_MEMBERSHIP:
        return _classify_membership_change(change)

    return "low", f"An Okta configuration record changed ({record_type or 'unknown record type'})."
