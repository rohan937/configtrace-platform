"""Okta risk classification rules — foundation + identity lifecycle +
application security + authentication policy (Okta messages 1-4 of 8).

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
- Application activation follows the same directional principle as user
  lifecycle: INACTIVE -> ACTIVE is Medium (access restored), ACTIVE ->
  INACTIVE is Low (restrictive). Redirect-posture changes use precise,
  non-alarmist wording ("allows an HTTP redirect URI"), never claims of
  token theft or account takeover — and a wildcard redirect is the one
  application-posture signal treated as High, mirroring Auth0's existing
  wildcard-callback precedent in this codebase. Assignment additions are
  Low/Medium with no privilege claims — message 5 will know which
  apps/roles are actually privileged.
- Authentication-policy/rule changes are classified by MFA-requirement/
  phishing-resistance DIRECTION: MFA required -> none/optional and
  phishing-resistant-required -> removed are High; the reverse
  (strengthening) is Low/improvement. deny -> allow is High when explicit;
  allow -> deny is Low (a restriction, not a weakening). Unknown states
  are NEVER classified as a known weakening (e.g. an unrecognized/missing
  MFA requirement is Medium "needs review," never treated as "no MFA").
"""

from __future__ import annotations

from typing import Any

from app.connectors.okta_schema import (
    APP_STATUS_ACTIVE,
    CAPABILITY_AVAILABLE,
    LIFECYCLE_ACTIVE,
    LIFECYCLE_DEPROVISIONED,
    LIFECYCLE_LOCKED,
    LIFECYCLE_PASSWORD_EXPIRED,
    LIFECYCLE_PRE_ACTIVE,
    LIFECYCLE_RECOVERY,
    LIFECYCLE_SUSPENDED,
    LIFECYCLE_UNKNOWN,
    MFA_REQUIREMENT_NONE,
    MFA_REQUIREMENT_RANK,
    MFA_REQUIREMENT_UNKNOWN,
    NOT_PHISHING_RESISTANT,
    OKTA_API_CAPABILITY,
    OKTA_APPLICATION,
    OKTA_APPLICATION_GROUP_ASSIGNMENT,
    OKTA_APPLICATION_USER_ASSIGNMENT,
    OKTA_AUTHENTICATOR,
    OKTA_GROUP,
    OKTA_GROUP_MEMBERSHIP,
    OKTA_ORGANIZATION,
    OKTA_POLICY,
    OKTA_POLICY_RULE,
    OKTA_USER,
    ORG_STATUS_ACTIVE,
    PHISHING_RESISTANCE_UNKNOWN,
    PHISHING_RESISTANT,
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


def _classify_app_status_transition(prev_status: object, new_status: object) -> tuple[str, str]:
    """Classify an application's ``status`` field transition by direction.

    Mirrors the user lifecycle transition principle: restrictive
    (ACTIVE -> INACTIVE) is Low; access-restoring (INACTIVE -> ACTIVE) is
    Medium, never described as unauthorized. An unrecognized new status is
    Medium (needs review), never silently treated as safe.
    """
    if new_status not in (APP_STATUS_ACTIVE, "INACTIVE"):
        return (
            "medium",
            f"An Okta application's status changed to an unrecognized value "
            f"({new_status!r}) — treat as needing review since it cannot be "
            "safely categorized.",
        )
    if prev_status == APP_STATUS_ACTIVE and new_status == "INACTIVE":
        return "low", "An Okta application was deactivated."
    if prev_status == "INACTIVE" and new_status == APP_STATUS_ACTIVE:
        return (
            "medium",
            "An Okta application was activated — it was previously inactive. "
            "Verify this was expected.",
        )
    return "low", "An Okta application's status changed."


def _classify_app_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        nv = _get(change, "new_value")
        nv = nv if isinstance(nv, dict) else {}
        if nv.get("status") == APP_STATUS_ACTIVE:
            return "low", "An Okta application was added to the inventory (active)."
        return "low", "An Okta application was added to the inventory (inactive)."
    if ct == "removed":
        return (
            "low",
            "An Okta application is no longer visible to ConfigTrace. This "
            "reflects the collected snapshot — it does not by itself confirm "
            "the application was deleted in Okta.",
        )

    fp = (_get(change, "field_path") or "")
    if fp == "status":
        return _classify_app_status_transition(_get(change, "prev_value"), _get(change, "new_value"))
    if fp == "active":
        nv = _get(change, "new_value")
        if nv is False:
            return "low", "An Okta application was deactivated."
        return "medium", "An Okta application was activated — verify this was expected."
    if fp in ("label",):
        return "low", "An Okta application was renamed."
    if fp in ("sign_on_mode", "protocol_category", "app_type_category"):
        return "low", "An Okta application's protocol/sign-on configuration changed."
    if fp == "token_endpoint_auth_method_category":
        nv = _get(change, "new_value")
        if nv == "none":
            return (
                "medium",
                "An Okta application's token endpoint authentication method "
                "changed to 'none' (public client, no client authentication).",
            )
        return "low", "An Okta application's token endpoint authentication method changed."
    if fp in ("grant_types_summary", "response_types_summary"):
        return "low", "An Okta application's OAuth grant/response type configuration changed."
    if fp == "http_redirect_count":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return (
                "medium",
                "An OIDC application allows an HTTP (non-HTTPS) redirect URI.",
            )
        if pv_i is not None and nv_i is not None and nv_i < pv_i:
            return "low", "An OIDC application's HTTP redirect URI count decreased."
        return "low", "An OIDC application's HTTP redirect URI count changed."
    if fp == "wildcard_redirect_present":
        nv = _get(change, "new_value")
        if nv is True:
            return (
                "high",
                "An OIDC application now allows a wildcard redirect URI. This "
                "may require review.",
            )
        if nv is False:
            return "low", "An OIDC application's wildcard redirect URI was removed."
        return "low", "An OIDC application's wildcard redirect presence is now unknown or missing."
    if fp == "custom_scheme_redirect_count":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return "medium", "An OIDC application now uses a custom-scheme redirect URI."
        return "low", "An OIDC application's custom-scheme redirect URI count changed."
    if fp in ("redirect_count", "https_redirect_count", "localhost_redirect_count",
              "loopback_redirect_count", "logout_redirect_count"):
        return "low", "An Okta application's redirect URI configuration changed."
    if fp in ("saml_response_signed", "saml_assertion_signed"):
        nv = _get(change, "new_value")
        if nv is False:
            return (
                "medium",
                f"An Okta SAML application's {fp.replace('saml_', '').replace('_', ' ')} "
                "posture was disabled.",
            )
        return "low", f"An Okta SAML application's {fp.replace('saml_', '').replace('_', ' ')} posture changed."
    if fp in ("saml_destination_configured", "saml_audience_configured"):
        return "low", "An Okta SAML application's configuration completeness changed."
    if fp in ("saml_signature_algorithm_category", "saml_digest_algorithm_category"):
        return "low", "An Okta SAML application's signing algorithm configuration changed."
    if fp == "saml_encryption_enabled":
        nv = _get(change, "new_value")
        if nv is False:
            return "medium", "An Okta SAML application's assertion encryption was disabled."
        return "low", "An Okta SAML application's assertion encryption posture changed."
    if fp in ("user_assignment_count", "group_assignment_count"):
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is None or nv_i is None:
            return "low", "An Okta application's assignment count became unknown or was newly determined."
        if nv_i > pv_i:
            return "low", f"An Okta application's assignment count increased ({pv_i} -> {nv_i})."
        return "low", f"An Okta application's assignment count decreased ({pv_i} -> {nv_i})."
    return "low", "An Okta application configuration field changed."


def _classify_app_user_assignment_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "medium", "A user was assigned to an Okta application."
    if ct == "removed":
        return "low", "A user's assignment to an Okta application was removed."

    fp = (_get(change, "field_path") or "")
    if fp == "user_status":
        return "low", "An assigned user's status changed (see the user's own record for lifecycle detail)."
    if fp == "assignment_status_category":
        return "low", "A user's Okta application assignment status changed."
    if fp == "assignment_scope_category":
        return "low", "A user's Okta application assignment scope (direct vs. via group) changed."
    return "low", "An Okta application user assignment field changed."


def _classify_app_group_assignment_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    everyone = None
    if isinstance(_get(change, "new_value"), dict):
        everyone = _get(change, "new_value").get("everyone_group")
    elif isinstance(_get(change, "prev_value"), dict):
        everyone = _get(change, "prev_value").get("everyone_group")

    if ct == "added":
        if everyone is True:
            return (
                "medium",
                "The built-in Everyone group was assigned to an Okta application "
                "— every user in the tenant may now have access.",
            )
        return "medium", "A group was assigned to an Okta application."
    if ct == "removed":
        if everyone is True:
            return "low", "The built-in Everyone group's assignment to an Okta application was removed."
        return "low", "A group's assignment to an Okta application was removed."

    fp = (_get(change, "field_path") or "")
    if fp == "group_type":
        return "low", "An assigned group's type changed."
    if fp == "built_in_group":
        return "low", "An assigned group's built-in/system category changed."
    if fp == "everyone_group":
        nv = _get(change, "new_value")
        if nv is True:
            return (
                "medium",
                "An Okta application's group assignment now resolves to the "
                "built-in Everyone group.",
            )
        return "low", "An Okta application's group assignment Everyone-group status changed."
    return "low", "An Okta application group assignment field changed."


def _classify_policy_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "An Okta policy was added to the inventory."
    if ct == "removed":
        return (
            "medium",
            "An Okta policy is no longer visible to ConfigTrace. This "
            "reflects the collected snapshot — it does not by itself "
            "confirm the policy was deleted in Okta, but a removed policy "
            "may indicate a protective control is no longer in effect.",
        )

    fp = (_get(change, "field_path") or "")
    if fp == "status":
        nv = _get(change, "new_value")
        if nv not in (APP_STATUS_ACTIVE, "INACTIVE"):
            return (
                "medium",
                f"An Okta policy's status changed to an unrecognized value "
                f"({nv!r}) — treat as needing review.",
            )
        if nv == "INACTIVE":
            return (
                "medium",
                "An Okta policy was deactivated. If this was a protective "
                "policy, its controls are no longer enforced.",
            )
        return "medium", "An Okta policy was activated."
    if fp == "active":
        nv = _get(change, "new_value")
        if nv is False:
            return "medium", "An Okta policy was deactivated."
        return "medium", "An Okta policy was activated."
    if fp in ("policy_name",):
        return "low", "An Okta policy was renamed."
    if fp == "policy_type":
        return "low", "An Okta policy's type changed."
    if fp == "priority":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is None or nv_i is None:
            return "low", "An Okta policy's priority became unknown or was newly determined."
        return (
            "medium",
            f"An Okta policy's priority order changed ({pv_i} -> {nv_i}). "
            "Policy order can affect which rule applies first — review "
            "whether this broadens or narrows effective access.",
        )
    if fp == "system":
        return "low", "An Okta policy's built-in/system category changed."
    if fp == "scope_category":
        return "low", "An Okta policy's targeting scope changed."
    if fp == "rule_count":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is None or nv_i is None:
            return "low", "An Okta policy's rule count became unknown or was newly determined."
        return "low", f"An Okta policy's rule count changed ({pv_i} -> {nv_i})."
    if fp == "password_min_length":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is None or nv_i is None:
            return "low", "An Okta password policy's minimum length became unknown or was newly determined."
        if nv_i < pv_i:
            return (
                "medium",
                f"An Okta password policy's minimum length decreased ({pv_i} -> {nv_i}).",
            )
        return "low", f"An Okta password policy's minimum length increased ({pv_i} -> {nv_i})."
    if fp == "password_complexity_required":
        nv = _get(change, "new_value")
        if nv is False:
            return "medium", "An Okta password policy's complexity requirement was removed."
        if nv is True:
            return "low", "An Okta password policy's complexity requirement was added."
        return "low", "An Okta password policy's complexity requirement became unknown."
    if fp == "password_history_present":
        nv = _get(change, "new_value")
        if nv is False:
            return "medium", "An Okta password policy's password-history requirement was removed."
        if nv is True:
            return "low", "An Okta password policy's password-history requirement was added."
        return "low", "An Okta password policy's password-history posture became unknown."
    if fp == "password_lockout_present":
        nv = _get(change, "new_value")
        if nv is False:
            return "medium", "An Okta password policy's lockout control was removed or disabled."
        if nv is True:
            return "low", "An Okta password policy's lockout control was added or enabled."
        return "low", "An Okta password policy's lockout posture became unknown."
    if fp == "password_lockout_max_attempts":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is None or nv_i is None:
            return "low", "An Okta password policy's lockout threshold became unknown or was newly determined."
        if nv_i > pv_i:
            return "medium", f"An Okta password policy's lockout threshold was loosened ({pv_i} -> {nv_i})."
        return "low", f"An Okta password policy's lockout threshold was tightened ({pv_i} -> {nv_i})."
    if fp == "password_lifetime_bounded":
        nv = _get(change, "new_value")
        if nv is False:
            return "medium", "An Okta password policy no longer enforces a maximum password age."
        if nv is True:
            return "low", "An Okta password policy now enforces a maximum password age."
        return "low", "An Okta password policy's maximum-age posture became unknown."
    if fp == "password_min_length_category":
        return "low", "An Okta password policy's minimum-length category changed."
    return "low", "An Okta policy configuration field changed."


def _classify_rule_mfa_requirement_transition(prev: object, new: object) -> tuple[str, str]:
    if new == MFA_REQUIREMENT_UNKNOWN:
        return (
            "medium",
            "An Okta policy rule's MFA requirement changed to an "
            "unrecognized/undeterminable value — treat as needing review.",
        )
    prev_rank = MFA_REQUIREMENT_RANK.get(prev, -1) if isinstance(prev, str) else -1
    new_rank = MFA_REQUIREMENT_RANK.get(new, -1) if isinstance(new, str) else -1
    if prev_rank == -1 or new_rank == -1:
        return "low", f"An Okta policy rule's MFA requirement changed ({prev!r} -> {new!r})."
    if new == MFA_REQUIREMENT_NONE and prev != MFA_REQUIREMENT_NONE:
        return (
            "high",
            f"An Okta policy rule's MFA requirement was removed (was {prev!r}). "
            "Multi-factor authentication is no longer required by this rule.",
        )
    if new_rank < prev_rank:
        return (
            "medium",
            f"An Okta policy rule's MFA requirement was weakened ({prev!r} -> {new!r}).",
        )
    if new_rank > prev_rank:
        return (
            "low",
            f"An Okta policy rule's MFA requirement was strengthened ({prev!r} -> {new!r}).",
        )
    return "low", f"An Okta policy rule's MFA requirement changed ({prev!r} -> {new!r})."


def _classify_rule_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "An Okta policy rule was added."
    if ct == "removed":
        return (
            "medium",
            "An Okta policy rule is no longer visible to ConfigTrace. This "
            "reflects the collected snapshot — it does not by itself "
            "confirm the rule was deleted in Okta, but a removed rule may "
            "indicate a protective control is no longer in effect.",
        )

    fp = (_get(change, "field_path") or "")
    if fp == "status":
        nv = _get(change, "new_value")
        if nv not in (APP_STATUS_ACTIVE, "INACTIVE"):
            return "medium", f"An Okta policy rule's status changed to an unrecognized value ({nv!r})."
        if nv == "INACTIVE":
            return "medium", "An Okta policy rule was deactivated."
        return "medium", "An Okta policy rule was activated."
    if fp == "active":
        nv = _get(change, "new_value")
        return ("medium", "An Okta policy rule was deactivated.") if nv is False else (
            "medium", "An Okta policy rule was activated.",
        )
    if fp == "rule_name":
        return "low", "An Okta policy rule was renamed."
    if fp == "priority":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is None or nv_i is None:
            return "low", "An Okta policy rule's priority became unknown or was newly determined."
        return (
            "medium",
            f"An Okta policy rule's priority order changed ({pv_i} -> {nv_i}). "
            "Rule order can broaden or narrow effective access — review the "
            "rules above/below this one.",
        )
    if fp == "scope_category":
        return "low", "An Okta policy rule's targeting scope changed."
    if fp == "access_category":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        if nv == "ALLOW" and pv == "DENY":
            return (
                "high",
                "An Okta policy rule's access changed from deny to allow.",
            )
        if nv == "DENY" and pv == "ALLOW":
            return "low", "An Okta policy rule's access changed from allow to deny."
        if nv == "unknown":
            return "medium", "An Okta policy rule's access outcome became unrecognized/undeterminable."
        return "low", "An Okta policy rule's access outcome changed."
    if fp == "mfa_requirement_category":
        return _classify_rule_mfa_requirement_transition(_get(change, "prev_value"), _get(change, "new_value"))
    if fp == "required_factor_count":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is None or nv_i is None:
            return "low", "An Okta policy rule's required factor count became unknown or was newly determined."
        if nv_i < pv_i:
            return (
                "medium",
                f"An Okta policy rule's required factor count decreased ({pv_i} -> {nv_i}).",
            )
        return "low", f"An Okta policy rule's required factor count increased ({pv_i} -> {nv_i})."
    if fp == "phishing_resistant_category":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        if nv == PHISHING_RESISTANCE_UNKNOWN:
            return "medium", "An Okta policy rule's phishing-resistance posture became unknown."
        if pv == PHISHING_RESISTANT and nv != PHISHING_RESISTANT:
            return (
                "high",
                "An Okta policy rule's phishing-resistant authentication "
                "requirement was removed.",
            )
        if nv == PHISHING_RESISTANT and pv != PHISHING_RESISTANT:
            return "low", "An Okta policy rule now requires phishing-resistant authentication."
        return "low", "An Okta policy rule's phishing-resistance posture changed."
    if fp in ("possession_required", "knowledge_required"):
        factor = fp.replace("_required", "")
        nv = _get(change, "new_value")
        if nv is False:
            return "medium", f"An Okta policy rule no longer requires a {factor} factor."
        if nv is True:
            return "low", f"An Okta policy rule now requires a {factor} factor."
        return "low", f"An Okta policy rule's {factor}-factor requirement became unknown."
    if fp == "hardware_protected_category":
        return "low", "An Okta policy rule's hardware-protection requirement changed."
    if fp == "device_bound":
        nv = _get(change, "new_value")
        if nv is False:
            return "medium", "An Okta policy rule no longer requires a device-bound factor."
        if nv is True:
            return "low", "An Okta policy rule now requires a device-bound factor."
        return "low", "An Okta policy rule's device-bound requirement became unknown."
    if fp in ("session_lifetime_category", "re_authentication_category"):
        return "low", f"An Okta policy rule's {fp.replace('_', ' ')} changed."
    return "low", "An Okta policy rule configuration field changed."


def _classify_authenticator_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "An Okta authenticator was added to the inventory."
    if ct == "removed":
        return (
            "medium",
            "An Okta authenticator is no longer visible to ConfigTrace. "
            "This does not by itself confirm MFA is disabled tenant-wide — "
            "other authenticators/policies may still enforce MFA.",
        )

    fp = (_get(change, "field_path") or "")
    if fp == "status":
        nv = _get(change, "new_value")
        pm = _get(change, "provider_metadata")
        pm = pm if isinstance(pm, dict) else {}
        phishing_resistant = pm.get("phishing_resistant_category") == PHISHING_RESISTANT
        if nv not in (APP_STATUS_ACTIVE, "INACTIVE"):
            return "medium", f"An Okta authenticator's status changed to an unrecognized value ({nv!r})."
        if nv == "INACTIVE":
            if phishing_resistant:
                return (
                    "medium",
                    "A phishing-resistant Okta authenticator was disabled.",
                )
            return "low", "An Okta authenticator was disabled."
        return "low", "An Okta authenticator was enabled."
    if fp == "active":
        nv = _get(change, "new_value")
        return ("low", "An Okta authenticator was disabled.") if nv is False else (
            "low", "An Okta authenticator was enabled.",
        )
    if fp in ("key", "type"):
        return "low", "An Okta authenticator's type changed."
    if fp == "phishing_resistant_category":
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        if pv == PHISHING_RESISTANT and nv == NOT_PHISHING_RESISTANT:
            return "medium", "An Okta authenticator's phishing-resistant capability was lost."
        if nv == PHISHING_RESISTANCE_UNKNOWN:
            return "medium", "An Okta authenticator's phishing-resistant capability became unknown."
        return "low", "An Okta authenticator's phishing-resistant capability changed."
    if fp in ("possession_factor", "knowledge_factor"):
        return "low", "An Okta authenticator's factor category changed."
    if fp == "hardware_backed_category":
        return "low", "An Okta authenticator's hardware-backed category changed."
    return "low", "An Okta authenticator configuration field changed."


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
    if record_type == OKTA_APPLICATION:
        return _classify_app_change(change)
    if record_type == OKTA_APPLICATION_USER_ASSIGNMENT:
        return _classify_app_user_assignment_change(change)
    if record_type == OKTA_APPLICATION_GROUP_ASSIGNMENT:
        return _classify_app_group_assignment_change(change)
    if record_type == OKTA_POLICY:
        return _classify_policy_change(change)
    if record_type == OKTA_POLICY_RULE:
        return _classify_rule_change(change)
    if record_type == OKTA_AUTHENTICATOR:
        return _classify_authenticator_change(change)

    return "low", f"An Okta configuration record changed ({record_type or 'unknown record type'})."
