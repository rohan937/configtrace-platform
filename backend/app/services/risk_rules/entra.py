"""Microsoft Entra ID risk classification rules — foundation + identity
lifecycle + application security (Entra messages 1-3 of 8).

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
- Application changes: single->multi-tenant sign-in audience broadens who
  can authenticate and is Medium; the reverse is Low. A service principal
  being enabled is Medium (restoration); disabled is Low. Assignment-
  required being removed (True->False) is Medium — access may no longer
  require explicit assignment, described conservatively, never as a
  confirmed open-access claim. Redirect posture uses CLIENT-TYPE context:
  an HTTP redirect introduced on a WEB app is Medium/High; loopback/custom-
  scheme redirects on public/native clients are NOT over-ranked (these are
  legitimate patterns for that client type). Credential changes are
  Low/Medium — a credential entering "expired" is Medium (a real
  operational/security gap), a new credential added is Medium at most,
  never a secret-exposure claim.
- Service-principal application-permission grants and tenant-wide OAuth
  consent are the most security-sensitive message-3 changes: a HIGH-RISK
  permission (per the bounded taxonomy in entra_schema.py) being granted is
  High; an unresolved/unknown permission is conservatively Medium (never
  assumed safe); an ordinary/low-risk permission grant is Medium at most.
  Consent removal is always Low/restrictive. None of this is ever
  described as confirmed compromise, phishing, or privilege escalation —
  message 5 deepens actual privileged-identity analysis.
"""

from __future__ import annotations

from typing import Any

from app.connectors.entra_schema import (
    CAPABILITY_AVAILABLE,
    CA_STATE_DISABLED,
    CA_STATE_ENABLED,
    CA_STATE_REPORT_ONLY,
    CONSENT_TYPE_ALL_PRINCIPALS,
    ENTRA_API_CAPABILITY,
    ENTRA_APPLICATION,
    ENTRA_APPLICATION_GROUP_ASSIGNMENT,
    ENTRA_APPLICATION_USER_ASSIGNMENT,
    ENTRA_AUTHENTICATION_METHOD,
    ENTRA_AUTHENTICATION_STRENGTH,
    ENTRA_CONDITIONAL_ACCESS_POLICY,
    ENTRA_DIRECTORY_ROLE,
    ENTRA_DIRECTORY_ROLE_ASSIGNMENT,
    ENTRA_GROUP,
    ENTRA_GROUP_MEMBERSHIP,
    ENTRA_OAUTH2_PERMISSION_GRANT,
    ENTRA_ORGANIZATION,
    ENTRA_PRIVILEGED_GROUP,
    ENTRA_PRIVILEGED_IDENTITY,
    ENTRA_PRIVILEGED_SERVICE_PRINCIPAL,
    ENTRA_SERVICE_PRINCIPAL,
    ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT,
    ENTRA_USER,
    ENTRA_PRIVILEGE_TIER_CRITICAL,
    ENTRA_PRIVILEGE_TIER_HIGH,
    ENTRA_PRIVILEGE_TIER_RANK,
    ENTRA_PRIVILEGE_TIER_UNKNOWN,
    EXTERNAL_USER_STATE_ACCEPTED,
    EXTERNAL_USER_STATE_PENDING,
    FAMILY_COMPLETE,
    MFA_REQUIREMENT_BLOCKED,
    MFA_REQUIREMENT_NOT_REQUIRED,
    MFA_REQUIREMENT_ONE_OF_MULTIPLE,
    MFA_REQUIREMENT_RANK,
    MFA_REQUIREMENT_REQUIRED,
    METHOD_TYPE_CERTIFICATE_BASED_AUTH,
    METHOD_TYPE_FIDO2,
    METHOD_TYPE_WINDOWS_HELLO_FOR_BUSINESS,
    NOT_PHISHING_RESISTANT,
    PERMISSION_RISK_HIGH,
    PHISHING_RESISTANT,
    ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR,
    ROLE_TEMPLATE_PRIVILEGED_ROLE_ADMINISTRATOR,
    SIGN_IN_AUDIENCE_SINGLE_TENANT,
    SIGN_IN_FREQUENCY_RANK,
)

_TIER_GRANT_SEVERITY: dict = {
    ENTRA_PRIVILEGE_TIER_CRITICAL: "critical",
    ENTRA_PRIVILEGE_TIER_HIGH: "high",
    "medium": "medium",
    "low": "low",
    "read_only": "low",
    ENTRA_PRIVILEGE_TIER_UNKNOWN: "medium",
}


def _severity_for_tier_grant(tier: object) -> str:
    return _TIER_GRANT_SEVERITY.get(tier, "medium")


def _tier_rank(tier: object) -> int:
    return ENTRA_PRIVILEGE_TIER_RANK.get(tier, 0) if isinstance(tier, str) else 0

_STRONG_METHOD_TYPES = frozenset(
    {METHOD_TYPE_FIDO2, METHOD_TYPE_CERTIFICATE_BASED_AUTH, METHOD_TYPE_WINDOWS_HELLO_FOR_BUSINESS}
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


def _classify_application_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Microsoft Entra ID application registration was added to the identity inventory."
    if ct == "removed":
        return (
            "low",
            "A Microsoft Entra ID application registration is no longer present in the "
            "observed Entra snapshot.",
        )

    fp = (_get(change, "field_path") or "")
    if fp == "sign_in_audience_category":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if pv == SIGN_IN_AUDIENCE_SINGLE_TENANT and nv != SIGN_IN_AUDIENCE_SINGLE_TENANT:
            return (
                "medium",
                "A Microsoft Entra ID application's sign-in audience broadened beyond a "
                "single tenant. This does not by itself grant external access — it changes "
                "who is ELIGIBLE to authenticate.",
            )
        if nv == SIGN_IN_AUDIENCE_SINGLE_TENANT and pv != SIGN_IN_AUDIENCE_SINGLE_TENANT:
            return "low", "A Microsoft Entra ID application's sign-in audience narrowed to a single tenant."
        if nv == "unknown":
            return "medium", "A Microsoft Entra ID application's sign-in audience became unrecognized/unknown."
        return "low", "A Microsoft Entra ID application's sign-in audience changed."
    if fp in ("has_http_redirect", "web_has_http_redirect"):
        nv = _get(change, "new_value")
        if nv is True:
            return (
                "medium",
                "A Microsoft Entra ID application now has an HTTP (non-HTTPS) redirect URI "
                "configured for a web client.",
            )
        return "low", "A Microsoft Entra ID application no longer has an HTTP redirect URI."
    if fp == "has_wildcard_redirect":
        nv = _get(change, "new_value")
        if nv is True:
            return "high", "A Microsoft Entra ID application now has a wildcard redirect URI configured."
        return "low", "A Microsoft Entra ID application no longer has a wildcard redirect URI."
    if fp in ("has_localhost_redirect", "has_loopback_redirect", "has_custom_scheme_redirect"):
        # These are legitimate, expected patterns for public/native clients
        # — never over-ranked. Structural visibility only.
        return "low", "A Microsoft Entra ID application's redirect URI posture changed."
    if fp in ("web_redirect_count", "spa_redirect_count", "public_client_redirect_count"):
        return "low", "A Microsoft Entra ID application's redirect URI count changed."
    if fp in ("requested_delegated_permission_count", "requested_application_permission_count"):
        return (
            "low",
            "A Microsoft Entra ID application's REQUESTED permission count changed. This "
            "reflects the app manifest's configured request, not granted access.",
        )
    if fp == "nearest_credential_expiry_category":
        nv = _get(change, "new_value")
        if nv == "expired":
            return "medium", "A Microsoft Entra ID application's nearest credential has expired."
        if nv == "expiring_soon":
            return "low", "A Microsoft Entra ID application has a credential expiring soon."
        return "low", "A Microsoft Entra ID application's credential expiry posture changed."
    if fp in ("password_credential_count", "key_credential_count"):
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return "medium", "A new credential was added to a Microsoft Entra ID application."
        return "low", "A Microsoft Entra ID application's credential count decreased."
    if fp in ("display_name", "publisher_domain"):
        return "low", "A Microsoft Entra ID application's identifying metadata changed."
    return "low", "A Microsoft Entra ID application configuration field changed."


def _classify_service_principal_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Microsoft Entra ID service principal (enterprise application) was added to the identity inventory."
    if ct == "removed":
        return (
            "low",
            "A Microsoft Entra ID service principal is no longer present in the observed "
            "Entra snapshot.",
        )

    fp = (_get(change, "field_path") or "")
    if fp == "account_enabled":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        if nv is True and pv is not True:
            return "medium", "A Microsoft Entra ID service principal was enabled — access has been restored."
        if nv is False:
            return "low", "A Microsoft Entra ID service principal was disabled."
        return "medium", "A Microsoft Entra ID service principal's enabled state became unrecognized/unknown."
    if fp == "assignment_required":
        nv = _get(change, "new_value")
        if nv is False:
            return (
                "medium",
                "A Microsoft Entra ID service principal no longer requires explicit user/"
                "group assignment. Whether this actually broadens sign-in access depends on "
                "the application's own configuration — not confirmed open access by itself.",
            )
        if nv is True:
            return "low", "A Microsoft Entra ID service principal now requires explicit user/group assignment."
        return "medium", "A Microsoft Entra ID service principal's assignment-required posture became unrecognized/unknown."
    if fp == "verified_publisher_category":
        nv = _get(change, "new_value")
        if nv == "verified":
            return "low", "A Microsoft Entra ID service principal's publisher became verified."
        return "low", "A Microsoft Entra ID service principal's publisher verification status changed."
    if fp in ("password_credential_count", "key_credential_count"):
        pv, nv = _get(change, "prev_value"), _get(change, "new_value")
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return "medium", "A new credential was added to a Microsoft Entra ID service principal."
        return "low", "A Microsoft Entra ID service principal's credential count decreased."
    if fp == "nearest_credential_expiry_category":
        nv = _get(change, "new_value")
        if nv == "expired":
            return "medium", "A Microsoft Entra ID service principal's nearest credential has expired."
        return "low", "A Microsoft Entra ID service principal's credential expiry posture changed."
    if fp in ("service_principal_type_category", "app_owner_organization_category", "display_name"):
        return "low", "A Microsoft Entra ID service principal's identifying metadata changed."
    return "low", "A Microsoft Entra ID service principal configuration field changed."


def _classify_app_user_assignment_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    new_value = _get(change, "new_value")
    prev_value = _get(change, "prev_value")
    context = new_value if isinstance(new_value, dict) else (prev_value if isinstance(prev_value, dict) else pm)
    user_type_category = context.get("user_type_category") if isinstance(context, dict) else None
    account_enabled_category = context.get("account_enabled_category") if isinstance(context, dict) else None
    is_guest = user_type_category == "Guest"

    if ct == "added":
        if is_guest:
            return "medium", "A guest user was assigned to a Microsoft Entra ID enterprise application."
        if account_enabled_category == "disabled":
            return "low", "A disabled Microsoft Entra ID user retains an application assignment."
        return "low", "A Microsoft Entra ID user was assigned to an enterprise application."
    if ct == "removed":
        return "low", "A Microsoft Entra ID user's application assignment was removed."
    return "low", "A Microsoft Entra ID user application assignment record changed."


def _classify_app_group_assignment_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    new_value = _get(change, "new_value")
    prev_value = _get(change, "prev_value")
    context = new_value if isinstance(new_value, dict) else (prev_value if isinstance(prev_value, dict) else pm)
    dynamic_group = context.get("dynamic_group") if isinstance(context, dict) else False
    role_assignable_group = context.get("role_assignable_group") if isinstance(context, dict) else None

    if ct == "added":
        if role_assignable_group is True:
            return (
                "medium",
                "A Microsoft Entra ID group with directory-role eligibility was assigned "
                "to an enterprise application.",
            )
        if dynamic_group:
            return (
                "medium",
                "A dynamic-membership Microsoft Entra ID group was assigned to an enterprise "
                "application — membership (and therefore app access) can change automatically.",
            )
        return (
            "medium",
            "A Microsoft Entra ID group was assigned to an enterprise application. Access "
            "can fan out to every current and future member of the group.",
        )
    if ct == "removed":
        return "low", "A Microsoft Entra ID group's application assignment was removed."
    return "low", "A Microsoft Entra ID group application assignment record changed."


def _classify_sp_app_role_assignment_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    new_value = _get(change, "new_value")
    prev_value = _get(change, "prev_value")
    context = new_value if isinstance(new_value, dict) else (prev_value if isinstance(prev_value, dict) else pm)
    risk_category = context.get("app_role_risk_category") if isinstance(context, dict) else None
    privilege_tier = context.get("app_role_privilege_tier") if isinstance(context, dict) else None

    if ct == "added":
        if privilege_tier == ENTRA_PRIVILEGE_TIER_CRITICAL:
            return (
                "critical",
                "A Microsoft Entra ID service principal was granted a critical-tier Microsoft "
                "Graph application permission (e.g. directory role management, app-role-"
                "assignment management, or arbitrary permission grant capability).",
            )
        if risk_category == PERMISSION_RISK_HIGH:
            return (
                "high",
                "A Microsoft Entra ID service principal was granted a high-risk application "
                "permission against another service principal (e.g. Microsoft Graph).",
            )
        if risk_category == "unknown":
            return (
                "medium",
                "A Microsoft Entra ID service principal was granted an application permission "
                "that could not be resolved to a known permission name — treated as needing "
                "review, never assumed safe.",
            )
        return (
            "medium",
            "A Microsoft Entra ID service principal was granted an application permission "
            "against another service principal.",
        )
    if ct == "removed":
        return "low", "A Microsoft Entra ID service-principal application permission was removed."

    fp = (_get(change, "field_path") or "")
    if fp == "app_role_privilege_tier":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        nv_rank, pv_rank = ENTRA_PRIVILEGE_TIER_RANK.get(nv), ENTRA_PRIVILEGE_TIER_RANK.get(pv)
        if nv_rank is None or pv_rank is None:
            return "medium", "A Microsoft Entra ID service-principal application permission's privilege tier became unrecognized."
        if nv_rank > pv_rank:
            severity = "high" if nv in (ENTRA_PRIVILEGE_TIER_CRITICAL, ENTRA_PRIVILEGE_TIER_HIGH) else "medium"
            return severity, f"A Microsoft Entra ID service-principal application permission's privilege tier increased ({pv} -> {nv})."
        return "low", f"A Microsoft Entra ID service-principal application permission's privilege tier decreased ({pv} -> {nv})."
    return "low", "A Microsoft Entra ID service-principal application permission record changed."


def _classify_oauth2_permission_grant_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    new_value = _get(change, "new_value")
    prev_value = _get(change, "prev_value")
    context = new_value if isinstance(new_value, dict) else (prev_value if isinstance(prev_value, dict) else pm)
    consent_type = context.get("consent_type_category") if isinstance(context, dict) else None
    high_risk_scope_present = context.get("high_risk_scope_present") if isinstance(context, dict) else False
    scope_tier = context.get("highest_scope_privilege_tier") if isinstance(context, dict) else None
    is_tenant_wide = consent_type == CONSENT_TYPE_ALL_PRINCIPALS

    if ct == "added":
        if is_tenant_wide and scope_tier == ENTRA_PRIVILEGE_TIER_CRITICAL:
            return (
                "critical",
                "Tenant-wide (admin) consent was granted for a Microsoft Entra ID OAuth2 "
                "delegated permission grant that includes a critical-risk scope.",
            )
        if high_risk_scope_present and is_tenant_wide:
            return (
                "high",
                "Tenant-wide (admin) consent was granted for a Microsoft Entra ID OAuth2 "
                "delegated permission grant that includes a high-risk scope.",
            )
        if high_risk_scope_present:
            return (
                "high",
                "A Microsoft Entra ID OAuth2 delegated permission grant with a high-risk "
                "scope was added.",
            )
        if is_tenant_wide:
            return (
                "medium",
                "Tenant-wide (admin) consent was granted for a Microsoft Entra ID OAuth2 "
                "delegated permission grant.",
            )
        return "low", "A Microsoft Entra ID OAuth2 delegated permission grant (single-user consent) was added."
    if ct == "removed":
        return "low", "A Microsoft Entra ID OAuth2 delegated permission grant was removed."

    fp = (_get(change, "field_path") or "")
    if fp == "highest_scope_privilege_tier":
        nv, pv = _get(change, "new_value"), _get(change, "prev_value")
        nv_rank, pv_rank = ENTRA_PRIVILEGE_TIER_RANK.get(nv), ENTRA_PRIVILEGE_TIER_RANK.get(pv)
        if nv_rank is None or pv_rank is None:
            return "medium", "A Microsoft Entra ID OAuth2 delegated permission grant's scope privilege tier became unrecognized."
        if nv_rank > pv_rank:
            severity = "high" if is_tenant_wide and nv in (ENTRA_PRIVILEGE_TIER_CRITICAL, ENTRA_PRIVILEGE_TIER_HIGH) else "medium"
            return severity, f"A Microsoft Entra ID OAuth2 delegated permission grant's scope privilege tier increased ({pv} -> {nv})."
        return "low", f"A Microsoft Entra ID OAuth2 delegated permission grant's scope privilege tier decreased ({pv} -> {nv})."
    return "low", "A Microsoft Entra ID OAuth2 delegated permission grant record changed."


def _classify_conditional_access_policy_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    new_value = _get(change, "new_value")
    prev_value = _get(change, "prev_value")
    context = new_value if isinstance(new_value, dict) else (prev_value if isinstance(prev_value, dict) else pm)
    state_category = context.get("state_category") if isinstance(context, dict) else None
    coverage_category = context.get("coverage_category") if isinstance(context, dict) else None
    mfa_requirement_category = context.get("mfa_requirement_category") if isinstance(context, dict) else None
    block_access = context.get("block_access") if isinstance(context, dict) else None

    if ct == "added":
        if state_category == CA_STATE_ENABLED:
            if coverage_category == "all_users_all_apps" and mfa_requirement_category == MFA_REQUIREMENT_NOT_REQUIRED and not block_access:
                return (
                    "high",
                    "A new enabled Microsoft Entra ID Conditional Access policy was added that "
                    "broadly targets all users/apps without requiring MFA or blocking access.",
                )
            if mfa_requirement_category == MFA_REQUIREMENT_REQUIRED or block_access:
                return "low", "A new enabled Microsoft Entra ID Conditional Access policy with MFA/block controls was added."
            return "medium", "A new enabled Microsoft Entra ID Conditional Access policy was added."
        if state_category == CA_STATE_REPORT_ONLY:
            return "low", "A new report-only Microsoft Entra ID Conditional Access policy was added."
        return "low", "A new Microsoft Entra ID Conditional Access policy was added."
    if ct == "removed":
        if state_category == CA_STATE_ENABLED and (mfa_requirement_category == MFA_REQUIREMENT_REQUIRED or block_access):
            return (
                "high",
                "An enforced Microsoft Entra ID Conditional Access policy with MFA/block "
                "controls was removed.",
            )
        if state_category == CA_STATE_ENABLED:
            return "medium", "An enforced Microsoft Entra ID Conditional Access policy was removed."
        return "low", "A Microsoft Entra ID Conditional Access policy (disabled/report-only) was removed."

    fp = (_get(change, "field_path") or "")
    nv, pv = _get(change, "new_value"), _get(change, "prev_value")

    if fp == "state_category":
        if pv == CA_STATE_ENABLED and nv == CA_STATE_REPORT_ONLY:
            return (
                "medium",
                "A Microsoft Entra ID Conditional Access policy moved from enabled to "
                "report-only — it no longer enforces its controls.",
            )
        if pv == CA_STATE_ENABLED and nv == CA_STATE_DISABLED:
            return "medium", "A Microsoft Entra ID Conditional Access policy was disabled."
        if pv == CA_STATE_REPORT_ONLY and nv == CA_STATE_ENABLED:
            return "low", "A Microsoft Entra ID Conditional Access policy moved from report-only to enforced."
        if pv == CA_STATE_DISABLED and nv == CA_STATE_ENABLED:
            return "low", "A Microsoft Entra ID Conditional Access policy was enabled."
        return "medium", "A Microsoft Entra ID Conditional Access policy's enforcement state became unrecognized/unknown."

    if fp == "block_access":
        if pv is True and nv is not True:
            if state_category == CA_STATE_ENABLED:
                return "high", "An enforced Microsoft Entra ID Conditional Access policy's block-access control was removed."
            return "medium", "A Microsoft Entra ID Conditional Access policy's block-access control was removed."
        if nv is True and pv is not True:
            return "low", "A Microsoft Entra ID Conditional Access policy's block-access control was added."
        return "low", "A Microsoft Entra ID Conditional Access policy's block-access control changed."

    if fp == "mfa_requirement_category":
        pv_rank = MFA_REQUIREMENT_RANK.get(pv)
        nv_rank = MFA_REQUIREMENT_RANK.get(nv)
        if pv_rank is None or nv_rank is None:
            return "medium", "A Microsoft Entra ID Conditional Access policy's MFA requirement became unrecognized/unknown."
        if nv_rank < pv_rank:
            if state_category == CA_STATE_ENABLED and pv == MFA_REQUIREMENT_REQUIRED and nv == MFA_REQUIREMENT_NOT_REQUIRED:
                return (
                    "high",
                    "An enforced Microsoft Entra ID Conditional Access policy's MFA "
                    "requirement was removed entirely.",
                )
            return "medium", "A Microsoft Entra ID Conditional Access policy's MFA requirement was weakened."
        if nv_rank > pv_rank:
            return "low", "A Microsoft Entra ID Conditional Access policy's MFA requirement was strengthened."
        return "low", "A Microsoft Entra ID Conditional Access policy's MFA requirement category changed."

    if fp == "legacy_auth_targeted":
        if pv is True and nv is not True:
            return (
                "high" if block_access else "medium",
                "A Microsoft Entra ID Conditional Access policy no longer explicitly targets "
                "legacy authentication protocols.",
            )
        if nv is True and pv is not True:
            if state_category == CA_STATE_ENABLED and block_access is not True:
                return (
                    "high",
                    "A Microsoft Entra ID Conditional Access policy now explicitly targets "
                    "legacy authentication protocols but does not block access for them — "
                    "this matches the same risky posture as the static Finding for this policy.",
                )
            return "low", "A Microsoft Entra ID Conditional Access policy now explicitly targets legacy authentication protocols."
        return "low", "A Microsoft Entra ID Conditional Access policy's legacy-authentication targeting changed."

    if fp in ("compliant_device_required", "hybrid_joined_device_required", "approved_application_required", "compliant_application_required"):
        if pv is True and nv is not True:
            return "medium", "A Microsoft Entra ID Conditional Access policy's device/application grant requirement was removed."
        if nv is True and pv is not True:
            return "low", "A Microsoft Entra ID Conditional Access policy's device/application grant requirement was added."
        return "low", "A Microsoft Entra ID Conditional Access policy's device/application grant requirement changed."

    if fp == "authentication_strength_referenced":
        if pv is True and nv is not True:
            return "medium", "A Microsoft Entra ID Conditional Access policy no longer references an authentication strength."
        if nv is True and pv is not True:
            return "low", "A Microsoft Entra ID Conditional Access policy now references an authentication strength."
        return "low", "A Microsoft Entra ID Conditional Access policy's authentication strength reference changed."

    if fp in ("exclude_user_count", "exclude_group_count", "exclude_role_count"):
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return "medium", "A Microsoft Entra ID Conditional Access policy's exclusions were broadened."
        return "low", "A Microsoft Entra ID Conditional Access policy's exclusions were narrowed or changed."

    if fp == "guests_excluded":
        if pv is True and nv is not True:
            return "medium", "A Microsoft Entra ID Conditional Access policy no longer excludes guests/external users."
        return "low", "A Microsoft Entra ID Conditional Access policy's guest exclusion changed."

    if fp == "sign_in_frequency_category":
        pv_rank = SIGN_IN_FREQUENCY_RANK.get(pv)
        nv_rank = SIGN_IN_FREQUENCY_RANK.get(nv)
        if pv_rank is None or nv_rank is None:
            return "low", "A Microsoft Entra ID Conditional Access policy's sign-in frequency became unrecognized/unknown."
        if nv_rank > pv_rank:
            return "medium", "A Microsoft Entra ID Conditional Access policy's sign-in frequency was loosened (longer interval)."
        if nv_rank < pv_rank:
            return "low", "A Microsoft Entra ID Conditional Access policy's sign-in frequency was tightened."
        return "low", "A Microsoft Entra ID Conditional Access policy's sign-in frequency changed."

    if fp == "persistent_browser_category":
        if nv == "always" and pv != "always":
            return "medium", "A Microsoft Entra ID Conditional Access policy now persists browser sessions."
        return "low", "A Microsoft Entra ID Conditional Access policy's persistent-browser session control changed."

    if fp == "continuous_access_evaluation_category":
        if pv == "strict_enforcement" and nv != "strict_enforcement":
            return "medium", "A Microsoft Entra ID Conditional Access policy's continuous access evaluation was loosened."
        return "low", "A Microsoft Entra ID Conditional Access policy's continuous access evaluation setting changed."

    if fp == "coverage_category":
        if nv == "all_users_all_apps" and pv != "all_users_all_apps":
            return "medium", "A Microsoft Entra ID Conditional Access policy's coverage broadened to all users and all apps."
        return "low", "A Microsoft Entra ID Conditional Access policy's coverage breadth changed."

    return "low", "A Microsoft Entra ID Conditional Access policy configuration field changed."


def _classify_authentication_strength_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    new_value = _get(change, "new_value")
    prev_value = _get(change, "prev_value")
    context = new_value if isinstance(new_value, dict) else (prev_value if isinstance(prev_value, dict) else pm)
    phishing_resistance_category = context.get("phishing_resistance_category") if isinstance(context, dict) else None
    kind_category = context.get("kind_category") if isinstance(context, dict) else None

    if ct == "added":
        if kind_category == "custom":
            return "low", "A custom Microsoft Entra ID authentication strength policy was added."
        return "low", "A Microsoft Entra ID authentication strength policy was added."
    if ct == "removed":
        if phishing_resistance_category == PHISHING_RESISTANT:
            return (
                "medium",
                "A phishing-resistant Microsoft Entra ID authentication strength policy was "
                "removed. Whether it was actively referenced by a Conditional Access policy "
                "is not confirmed here.",
            )
        return "low", "A Microsoft Entra ID authentication strength policy was removed."

    fp = (_get(change, "field_path") or "")
    nv, pv = _get(change, "new_value"), _get(change, "prev_value")

    if fp == "phishing_resistance_category":
        if pv == PHISHING_RESISTANT and nv == NOT_PHISHING_RESISTANT:
            return (
                "high",
                "A Microsoft Entra ID authentication strength policy's phishing-resistance "
                "posture was weakened to ordinary MFA.",
            )
        if pv == NOT_PHISHING_RESISTANT and nv == PHISHING_RESISTANT:
            return "low", "A Microsoft Entra ID authentication strength policy's phishing-resistance posture was strengthened."
        return "medium", "A Microsoft Entra ID authentication strength policy's phishing-resistance posture became unrecognized/unknown."

    if fp == "passwordless_category":
        if pv == "passwordless" and nv == "not_passwordless":
            return "medium", "A Microsoft Entra ID authentication strength policy's passwordless posture was weakened."
        if pv == "not_passwordless" and nv == "passwordless":
            return "low", "A Microsoft Entra ID authentication strength policy's passwordless posture was strengthened."
        return "low", "A Microsoft Entra ID authentication strength policy's passwordless posture changed."

    if fp == "mfa_capability_category":
        if pv == "mfa_capable" and nv == "unknown":
            return "medium", "A Microsoft Entra ID authentication strength policy's MFA capability became unrecognized/unknown."
        return "low", "A Microsoft Entra ID authentication strength policy's MFA capability changed."

    if fp == "allowed_combination_count":
        return "low", "A Microsoft Entra ID authentication strength policy's allowed combination count changed."

    if fp in ("display_name", "kind_category"):
        return "low", "A Microsoft Entra ID authentication strength policy's identifying metadata changed."

    return "low", "A Microsoft Entra ID authentication strength policy configuration field changed."


def _classify_authentication_method_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    new_value = _get(change, "new_value")
    prev_value = _get(change, "prev_value")
    context = new_value if isinstance(new_value, dict) else (prev_value if isinstance(prev_value, dict) else pm)
    method_type_category = context.get("method_type_category") if isinstance(context, dict) else None
    is_strong = method_type_category in _STRONG_METHOD_TYPES

    if ct == "added":
        return "low", "A Microsoft Entra ID authentication method configuration was added to the tenant policy."
    if ct == "removed":
        return "low", "A Microsoft Entra ID authentication method configuration is no longer present in the observed snapshot."

    fp = (_get(change, "field_path") or "")
    nv, pv = _get(change, "new_value"), _get(change, "prev_value")

    if fp == "state_category":
        if nv == "unknown" or pv == "unknown":
            return "medium", "A Microsoft Entra ID authentication method's enabled state became unrecognized/unknown."
        if pv == "enabled" and nv == "disabled":
            if is_strong:
                return (
                    "medium",
                    "A phishing-resistant Microsoft Entra ID authentication method was "
                    "disabled tenant-wide. This is not a confirmed loss of multi-factor "
                    "authentication overall — other methods may remain enabled.",
                )
            return "low", "A Microsoft Entra ID authentication method was disabled tenant-wide."
        if pv == "disabled" and nv == "enabled":
            if is_strong:
                return "low", "A phishing-resistant Microsoft Entra ID authentication method was enabled tenant-wide."
            return "medium", "A weaker Microsoft Entra ID authentication method was enabled tenant-wide."
        return "low", "A Microsoft Entra ID authentication method's enabled state changed."

    if fp == "target_category":
        if nv == "all_users" and pv != "all_users":
            return "medium", "A Microsoft Entra ID authentication method's targeting broadened to all users."
        return "low", "A Microsoft Entra ID authentication method's targeting scope changed."

    if fp in ("include_target_count", "exclude_target_count"):
        return "low", "A Microsoft Entra ID authentication method's target count changed."

    if fp in ("method_type_category", "phishing_resistance_category"):
        return "low", "A Microsoft Entra ID authentication method's type/category classification changed."

    return "low", "A Microsoft Entra ID authentication method configuration field changed."


def _classify_directory_role_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    new_value = _get(change, "new_value")
    prev_value = _get(change, "prev_value")
    context = new_value if isinstance(new_value, dict) else (prev_value if isinstance(prev_value, dict) else pm)
    tier = context.get("privilege_tier") if isinstance(context, dict) else None

    if ct == "added":
        if tier in (ENTRA_PRIVILEGE_TIER_CRITICAL, ENTRA_PRIVILEGE_TIER_HIGH):
            return "medium", f"A new Microsoft Entra ID directory role was observed with a {tier} privilege tier."
        return "low", "A new Microsoft Entra ID directory role definition was observed."
    if ct == "removed":
        return (
            "low",
            "A Microsoft Entra ID directory role definition is no longer visible to ConfigTrace. "
            "This does not by itself confirm the role was deleted.",
        )

    fp = (_get(change, "field_path") or "")
    nv, pv = _get(change, "new_value"), _get(change, "prev_value")

    if fp == "privilege_tier":
        nv_rank, pv_rank = _tier_rank(nv), _tier_rank(pv)
        if nv not in ENTRA_PRIVILEGE_TIER_RANK or pv not in ENTRA_PRIVILEGE_TIER_RANK:
            return "medium", "A Microsoft Entra ID directory role's privilege tier became unrecognized."
        if nv_rank > pv_rank:
            return _severity_for_tier_grant(nv), f"A Microsoft Entra ID directory role's privilege tier increased ({pv} -> {nv})."
        if nv_rank < pv_rank:
            return "low", f"A Microsoft Entra ID directory role's privilege tier decreased ({pv} -> {nv})."
        return "low", "A Microsoft Entra ID directory role's privilege tier changed."
    if fp == "enabled":
        if nv is False:
            return "low", "A Microsoft Entra ID directory role was disabled."
        if nv is True:
            return "medium", "A Microsoft Entra ID directory role was enabled."
        return "medium", "A Microsoft Entra ID directory role's enabled state became unrecognized/unknown."
    if fp == "is_privileged":
        if nv is True:
            return "medium", "A Microsoft Entra ID directory role's privileged classification was newly determined."
        return "low", "A Microsoft Entra ID directory role's privileged classification changed."
    if fp in ("action_count", "dangerous_action_count"):
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return "medium", f"A Microsoft Entra ID custom directory role's {fp.replace('_', ' ')} increased ({pv_i} -> {nv_i})."
        return "low", f"A Microsoft Entra ID directory role's {fp.replace('_', ' ')} changed."
    if fp in ("display_name", "role_kind_category"):
        return "low", "A Microsoft Entra ID directory role's identifying metadata changed."
    return "low", "A Microsoft Entra ID directory role configuration field changed."


def _classify_directory_role_assignment_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    new_value = _get(change, "new_value")
    prev_value = _get(change, "prev_value")
    context = new_value if isinstance(new_value, dict) else (prev_value if isinstance(prev_value, dict) else pm)
    tier = context.get("privilege_tier") if isinstance(context, dict) else None
    role_template_id = context.get("role_template_id") if isinstance(context, dict) else None
    role_name = context.get("role_name") if isinstance(context, dict) else None

    if ct == "added":
        if role_template_id == ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR:
            return "critical", "A principal was assigned the Global Administrator role."
        if role_template_id == ROLE_TEMPLATE_PRIVILEGED_ROLE_ADMINISTRATOR:
            return "critical", "A principal was assigned the Privileged Role Administrator role."
        severity = _severity_for_tier_grant(tier)
        role_label = role_name or "a directory"
        return severity, f"A principal was assigned the {role_label!r} directory role (privilege tier: {tier})."
    if ct == "removed":
        return (
            "low",
            f"A principal's {role_name!r} directory role assignment is no longer visible to ConfigTrace.",
        )

    fp = (_get(change, "field_path") or "")
    nv, pv = _get(change, "new_value"), _get(change, "prev_value")

    if fp == "privilege_tier":
        if nv not in ENTRA_PRIVILEGE_TIER_RANK or pv not in ENTRA_PRIVILEGE_TIER_RANK:
            return "medium", "A directory-role assignment's privilege tier became unrecognized."
        nv_rank, pv_rank = _tier_rank(nv), _tier_rank(pv)
        if nv_rank > pv_rank:
            return _severity_for_tier_grant(nv), f"A directory-role assignment's privilege tier increased ({pv} -> {nv})."
        if nv_rank < pv_rank:
            return "low", f"A directory-role assignment's privilege tier decreased ({pv} -> {nv})."
        return "low", "A directory-role assignment's privilege tier changed."
    if fp == "directory_scope_category":
        if nv == "tenant_wide" and pv != "tenant_wide":
            severity = "high" if tier in (ENTRA_PRIVILEGE_TIER_CRITICAL, ENTRA_PRIVILEGE_TIER_HIGH) else "medium"
            return severity, "A directory-role assignment's scope was broadened to tenant-wide."
        if pv == "tenant_wide" and nv != "tenant_wide":
            return "low", "A directory-role assignment's scope was narrowed from tenant-wide."
        return "medium", "A directory-role assignment's scope category became unrecognized/unknown."
    if fp == "principal_type":
        return "medium", "A directory-role assignment's principal type became unrecognized/unknown."
    if fp in ("role_name", "role_template_id", "role_definition_id"):
        return "low", "A directory-role assignment's referenced role identity changed."
    return "low", "A Microsoft Entra ID directory-role assignment configuration field changed."


def _classify_privileged_identity_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    tier = pm.get("highest_privilege_tier") or ENTRA_PRIVILEGE_TIER_UNKNOWN

    if ct == "added":
        return (
            _severity_for_tier_grant(tier),
            f"A user became a privileged Microsoft Entra ID identity (highest privilege tier: {tier}).",
        )
    if ct == "removed":
        return "low", "A user is no longer a privileged Microsoft Entra ID identity (holds no directory role ConfigTrace can see)."

    fp = (_get(change, "field_path") or "")
    nv, pv = _get(change, "new_value"), _get(change, "prev_value")

    if fp == "has_global_admin":
        if nv is True:
            return "critical", "A user was granted the Global Administrator role."
        return "low", "A user's Global Administrator privilege was removed."
    if fp == "has_privileged_role_admin":
        if nv is True:
            return "critical", "A user was granted the Privileged Role Administrator role."
        return "low", "A user's Privileged Role Administrator privilege was removed."
    if fp == "has_high_privilege":
        if nv is True:
            return "high", "A user gained high-tier Microsoft Entra ID directory-role privilege."
        return "low", "A user's high-tier Microsoft Entra ID directory-role privilege was removed."
    if fp == "highest_privilege_tier":
        if nv not in ENTRA_PRIVILEGE_TIER_RANK or pv not in ENTRA_PRIVILEGE_TIER_RANK:
            return "medium", "A privileged Microsoft Entra ID identity's highest privilege tier became unrecognized."
        nv_rank, pv_rank = _tier_rank(nv), _tier_rank(pv)
        if nv_rank > pv_rank:
            return _severity_for_tier_grant(nv), f"A privileged Microsoft Entra ID identity's highest privilege tier increased ({pv} -> {nv})."
        if nv_rank < pv_rank:
            return "low", f"A privileged Microsoft Entra ID identity's highest privilege tier decreased ({pv} -> {nv})."
        return "low", "A privileged Microsoft Entra ID identity's highest privilege tier changed."
    if fp == "privileged_via_group":
        if nv is True:
            return _severity_for_tier_grant(tier), "A user gained directory-role privilege via a role-assignable group membership."
        if nv is False:
            return "low", "A user no longer holds directory-role privilege via group membership."
        return "medium", "A privileged Microsoft Entra ID identity's group-inherited privilege visibility became unknown (group memberships incomplete)."
    if fp == "privileged_via_direct":
        if nv is True:
            return _severity_for_tier_grant(tier), "A user gained a direct directory-role assignment."
        return "low", "A user's direct directory-role assignment was removed."
    if fp in ("direct_role_count", "group_inherited_role_count"):
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return "medium", f"A privileged Microsoft Entra ID identity's {fp.replace('_', ' ')} increased ({pv_i} -> {nv_i})."
        return "low", f"A privileged Microsoft Entra ID identity's {fp.replace('_', ' ')} changed."
    if fp == "account_enabled_category":
        restrictive = {"disabled", "unknown"}
        if nv == "enabled" and pv in restrictive:
            return (
                _severity_for_tier_grant(tier),
                f"A privileged Microsoft Entra ID identity (highest tier: {tier}) was re-enabled, restoring its directory-role privilege.",
            )
        if nv == "disabled":
            return "low", "A privileged Microsoft Entra ID identity's account was disabled. Its role assignment remains but is not currently usable."
        return "medium", "A privileged Microsoft Entra ID identity's account-enabled state became unrecognized/unknown."
    if fp == "privilege_derivation_completeness":
        return "low", "A privileged Microsoft Entra ID identity's derivation completeness changed."
    return "low", "A privileged Microsoft Entra ID identity's derived posture changed."


def _classify_privileged_group_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    tier = pm.get("highest_privilege_tier") or ENTRA_PRIVILEGE_TIER_UNKNOWN

    if ct == "added":
        return (
            _severity_for_tier_grant(tier),
            f"A group became a Microsoft Entra ID privileged group (highest privilege tier: {tier}). "
            "Every current and future member of this group inherits that privilege.",
        )
    if ct == "removed":
        return "low", "A group is no longer a Microsoft Entra ID privileged group (holds no directory-role assignment ConfigTrace can see)."

    fp = (_get(change, "field_path") or "")
    nv, pv = _get(change, "new_value"), _get(change, "prev_value")

    if fp == "highest_privilege_tier":
        if nv not in ENTRA_PRIVILEGE_TIER_RANK or pv not in ENTRA_PRIVILEGE_TIER_RANK:
            return "medium", "A Microsoft Entra ID privileged group's highest privilege tier became unrecognized."
        nv_rank, pv_rank = _tier_rank(nv), _tier_rank(pv)
        if nv_rank > pv_rank:
            return _severity_for_tier_grant(nv), f"A Microsoft Entra ID privileged group's highest privilege tier increased ({pv} -> {nv})."
        if nv_rank < pv_rank:
            return "low", f"A Microsoft Entra ID privileged group's highest privilege tier decreased ({pv} -> {nv})."
        return "low", "A Microsoft Entra ID privileged group's highest privilege tier changed."
    if fp == "role_count":
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return _severity_for_tier_grant(tier), f"A Microsoft Entra ID privileged group's directory-role count increased ({pv_i} -> {nv_i})."
        return "low", "A Microsoft Entra ID privileged group's directory-role count decreased."
    if fp == "member_count":
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return "medium", f"A Microsoft Entra ID privileged group's membership grew ({pv_i} -> {nv_i}). More users now inherit its directory-role privilege."
        return "low", "A Microsoft Entra ID privileged group's membership shrank."
    if fp in ("guest_member_count", "disabled_member_count"):
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            if fp == "guest_member_count" and tier == ENTRA_PRIVILEGE_TIER_CRITICAL:
                severity = "critical"
            elif fp == "guest_member_count" and tier == ENTRA_PRIVILEGE_TIER_HIGH:
                severity = "high"
            else:
                severity = "medium"
            return severity, f"A Microsoft Entra ID privileged group's {fp.replace('_', ' ')} increased ({pv_i} -> {nv_i})."
        return "low", f"A Microsoft Entra ID privileged group's {fp.replace('_', ' ')} decreased."
    if fp == "role_assignable":
        return "low", "A Microsoft Entra ID privileged group's role-assignable eligibility flag changed."
    return "low", "A Microsoft Entra ID privileged group's derived posture changed."


def _classify_privileged_service_principal_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    tier = pm.get("highest_privilege_tier") or ENTRA_PRIVILEGE_TIER_UNKNOWN

    if ct == "added":
        return (
            _severity_for_tier_grant(tier),
            f"A Microsoft Entra ID service principal became privileged (highest privilege tier: {tier}), via a "
            "directory role, a high/critical-tier Microsoft Graph application permission, or tenant-wide "
            "high-risk delegated consent.",
        )
    if ct == "removed":
        return "low", "A Microsoft Entra ID service principal is no longer classified as privileged."

    fp = (_get(change, "field_path") or "")
    nv, pv = _get(change, "new_value"), _get(change, "prev_value")

    if fp == "highest_privilege_tier":
        if nv not in ENTRA_PRIVILEGE_TIER_RANK or pv not in ENTRA_PRIVILEGE_TIER_RANK:
            return "medium", "A privileged Microsoft Entra ID service principal's highest privilege tier became unrecognized."
        nv_rank, pv_rank = _tier_rank(nv), _tier_rank(pv)
        if nv_rank > pv_rank:
            return _severity_for_tier_grant(nv), f"A privileged Microsoft Entra ID service principal's highest privilege tier increased ({pv} -> {nv})."
        if nv_rank < pv_rank:
            return "low", f"A privileged Microsoft Entra ID service principal's highest privilege tier decreased ({pv} -> {nv})."
        return "low", "A privileged Microsoft Entra ID service principal's highest privilege tier changed."
    if fp in ("has_role_management_permission", "has_directory_write_permission", "has_application_management_permission"):
        if nv is True:
            return "critical", f"A Microsoft Entra ID service principal was granted a critical-tier Graph permission ({fp.replace('has_', '').replace('_', ' ')})."
        return "low", f"A Microsoft Entra ID service principal's {fp.replace('has_', '').replace('_', ' ')} was removed."
    if fp == "has_graph_high_privilege":
        if nv is True:
            return "high", "A Microsoft Entra ID service principal gained a high/critical-tier Microsoft Graph application permission."
        return "low", "A Microsoft Entra ID service principal's high-tier Microsoft Graph application permission was removed."
    if fp == "critical_app_permission_count":
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return "critical", f"A privileged Microsoft Entra ID service principal's critical-tier application permission count increased ({pv_i} -> {nv_i})."
        return "low", "A privileged Microsoft Entra ID service principal's critical-tier application permission count decreased."
    if fp in ("high_risk_app_permission_count", "tenant_wide_delegated_grant_count"):
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return "high", f"A privileged Microsoft Entra ID service principal's {fp.replace('_', ' ')} increased ({pv_i} -> {nv_i})."
        return "low", f"A privileged Microsoft Entra ID service principal's {fp.replace('_', ' ')} decreased."
    if fp == "directory_role_count":
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return _severity_for_tier_grant(tier), f"A privileged Microsoft Entra ID service principal's directory-role count increased ({pv_i} -> {nv_i})."
        return "low", "A privileged Microsoft Entra ID service principal's directory-role count decreased."
    if fp == "account_enabled":
        if nv is True and pv is not True:
            return (
                _severity_for_tier_grant(tier),
                f"A privileged Microsoft Entra ID service principal (highest tier: {tier}) was re-enabled, restoring its privilege.",
            )
        if nv is False:
            return "low", "A privileged Microsoft Entra ID service principal was disabled."
        return "medium", "A privileged Microsoft Entra ID service principal's enabled state became unrecognized/unknown."
    if fp in ("password_credential_count", "key_credential_count"):
        pv_i = pv if isinstance(pv, int) and not isinstance(pv, bool) else None
        nv_i = nv if isinstance(nv, int) and not isinstance(nv, bool) else None
        if pv_i is not None and nv_i is not None and nv_i > pv_i:
            return "medium", "A new credential was added to a privileged Microsoft Entra ID service principal."
        return "low", "A privileged Microsoft Entra ID service principal's credential count decreased."
    if fp == "privilege_derivation_completeness":
        return "low", "A privileged Microsoft Entra ID service principal's derivation completeness changed."
    return "low", "A privileged Microsoft Entra ID service principal's derived posture changed."


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
    if record_type == ENTRA_APPLICATION:
        return _classify_application_change(change)
    if record_type == ENTRA_SERVICE_PRINCIPAL:
        return _classify_service_principal_change(change)
    if record_type == ENTRA_APPLICATION_USER_ASSIGNMENT:
        return _classify_app_user_assignment_change(change)
    if record_type == ENTRA_APPLICATION_GROUP_ASSIGNMENT:
        return _classify_app_group_assignment_change(change)
    if record_type == ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT:
        return _classify_sp_app_role_assignment_change(change)
    if record_type == ENTRA_OAUTH2_PERMISSION_GRANT:
        return _classify_oauth2_permission_grant_change(change)
    if record_type == ENTRA_CONDITIONAL_ACCESS_POLICY:
        return _classify_conditional_access_policy_change(change)
    if record_type == ENTRA_AUTHENTICATION_STRENGTH:
        return _classify_authentication_strength_change(change)
    if record_type == ENTRA_AUTHENTICATION_METHOD:
        return _classify_authentication_method_change(change)
    if record_type == ENTRA_DIRECTORY_ROLE:
        return _classify_directory_role_change(change)
    if record_type == ENTRA_DIRECTORY_ROLE_ASSIGNMENT:
        return _classify_directory_role_assignment_change(change)
    if record_type == ENTRA_PRIVILEGED_IDENTITY:
        return _classify_privileged_identity_change(change)
    if record_type == ENTRA_PRIVILEGED_GROUP:
        return _classify_privileged_group_change(change)
    if record_type == ENTRA_PRIVILEGED_SERVICE_PRINCIPAL:
        return _classify_privileged_service_principal_change(change)

    return "low", f"A Microsoft Entra ID configuration record changed ({record_type or 'unknown record type'})."
