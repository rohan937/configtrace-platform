"""Microsoft Entra ID provider schema (Entra messages 1-3 of 8).

Defines the record-type constants and safe category vocabularies for the
Microsoft Entra ID provider. Record types so far:

  entra_organization      — one record per connected Entra tenant (msg 1).
  entra_api_capability    — one record per probed future-family Graph API
                            surface (msg 1) — describes whether a surface is
                            safely readable, never the surface's actual data.
  entra_user              — one record per directory user (msg 2) — identity
                            and lifecycle posture only, never credentials or
                            arbitrary profile data (no phone/address/manager/
                            extension attributes).
  entra_group             — one record per directory group (msg 2) —
                            security/mail/dynamic/role-assignable posture
                            only, never the raw dynamic-membership rule,
                            owners, or mail aliases.
  entra_group_membership  — one record per direct user<->group membership
                            edge (msg 2). Direct membership only — never
                            transitive expansion, never nested-group
                            flattening, never non-user directory members
                            (service principals/devices/groups).
  entra_application               — one record per app registration
                            definition (msg 3) — the ``application`` Graph
                            resource. Redirect URIs, requested permissions,
                            and credentials are summarized into counts/
                            categories only, never stored raw.
  entra_service_principal          — one record per tenant-local
                            representation of an application (msg 3) — the
                            ``servicePrincipal`` Graph resource (Enterprise
                            Applications view). Distinct object from
                            ``entra_application`` — see the connector's
                            module docstring for the exact object-model
                            mapping.
  entra_application_user_assignment  — one record per user<->service-
                            principal app-role assignment edge (msg 3).
  entra_application_group_assignment — one record per group<->service-
                            principal app-role assignment edge (msg 3).
  entra_service_principal_app_role_assignment — one record per service-
                            principal<->service-principal application-
                            permission assignment edge (msg 3) — e.g. an
                            automation service principal granted an
                            application permission against Microsoft Graph
                            or another API.
  entra_oauth2_permission_grant — one record per delegated OAuth2 consent
                            grant (msg 3) — tenant-wide admin consent
                            (``AllPrincipals``) or single-user consent
                            (``Principal``). Scopes are parsed, deduplicated,
                            and categorized — never stored as one opaque
                            string.
  entra_conditional_access_policy — one record per Conditional Access
                            policy (msg 4) — enforcement state (enabled/
                            report-only/disabled), targeting/exclusion
                            categories and counts, grant-control semantics
                            (AND/OR, MFA/device/authentication-strength
                            requirements), legacy-authentication targeting,
                            risk targeting, and session-control posture.
                            Raw conditions/grantControls objects and target
                            user/group/role ID arrays are never stored.
  entra_authentication_strength — one record per authentication-strength
                            policy (msg 4), built-in or custom — allowed-
                            combination COUNT plus deterministic phishing-
                            resistant/passwordless/MFA categorization.
                            Never stores the raw allowed-combinations list.
  entra_authentication_method — one record per authentication-method
                            configuration (msg 4) — e.g. FIDO2, Microsoft
                            Authenticator, Temporary Access Pass, SMS,
                            voice, software OATH, X.509 certificate, email.
                            State (enabled/disabled) and safe method-
                            specific posture only — never secrets, key
                            material, phone numbers, or certificate bodies.

This module now defines the message-1/2/3/4 taxonomy. Message 5 (directory
roles/privileged identities/consent expansion) and message 6 (Security
Findings) are still pending.

Microsoft Entra ID is a distinct identity provider from this repository's
existing ``azure`` provider (Azure infrastructure: subscriptions, resource
groups, network security groups, Key Vaults, AKS — see
``app/connectors/azure.py``). The two are never merged.

SENSITIVE-DATA BOUNDARY (permanent, re-affirmed every later message)
----------------------------------------------------------------------
Never collected or stored by this connector, at any stage:
  client_secret, access_token, refresh_token, passwords, password hashes,
  authentication method secrets, recovery codes, private keys, certificates
  containing private key material, session/token telemetry, arbitrary user
  profile data, raw Microsoft Graph payloads.

Message 2 additionally never collects: passwordProfile, phone numbers
(mobilePhone/businessPhones), street address/city/state/postal code,
manager, employee ID, extension properties, the `identities` array,
proxyAddresses, or raw sign-in activity (deferred — see the connector's
module docstring for the sign-in-activity permission/licensing rationale).
Group normalization never collects the raw dynamic-membership rule
expression, mail aliases, proxy addresses, owners, or raw `members`
response payloads.

Message 3 additionally never collects: passwordCredentials.secretText,
keyCredentials.key (or any certificate/key bytes), raw redirect URI strings
(only structural counts/booleans), raw requiredResourceAccess arrays (only
counts), raw appRoles/oauth2PermissionScopes arrays (only counts and
locally-resolved value strings for referenced role/scope IDs), OAuth
tokens of any kind, and application-registration/service-principal owners
(deferred — see the connector's module docstring for the N+1 rationale).

Message 4 additionally never collects: raw Conditional Access
conditions/grantControls/sessionControls objects, target user/group/role
ID arrays, named-location IP ranges, Temporary Access Pass values,
FIDO2/passkey key material or AAGUID lists beyond a bounded count,
certificate bodies, phone numbers, or per-user authentication-method
enrollment data (deferred — tenant-level policy/configuration posture
only; see the connector's module docstring for the per-user N+1/privacy
rationale).
"""

from __future__ import annotations

import re as _re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

# ── Record types ────────────────────────────────────────────────────────────

ENTRA_ORGANIZATION = "entra_organization"
ENTRA_API_CAPABILITY = "entra_api_capability"
ENTRA_USER = "entra_user"
ENTRA_GROUP = "entra_group"
ENTRA_GROUP_MEMBERSHIP = "entra_group_membership"
ENTRA_APPLICATION = "entra_application"
ENTRA_SERVICE_PRINCIPAL = "entra_service_principal"
ENTRA_APPLICATION_USER_ASSIGNMENT = "entra_application_user_assignment"
ENTRA_APPLICATION_GROUP_ASSIGNMENT = "entra_application_group_assignment"
ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT = "entra_service_principal_app_role_assignment"
ENTRA_OAUTH2_PERMISSION_GRANT = "entra_oauth2_permission_grant"
ENTRA_CONDITIONAL_ACCESS_POLICY = "entra_conditional_access_policy"
ENTRA_AUTHENTICATION_STRENGTH = "entra_authentication_strength"
ENTRA_AUTHENTICATION_METHOD = "entra_authentication_method"

ENTRA_RECORD_TYPES = frozenset({
    ENTRA_ORGANIZATION,
    ENTRA_API_CAPABILITY,
    ENTRA_USER,
    ENTRA_GROUP,
    ENTRA_GROUP_MEMBERSHIP,
    ENTRA_APPLICATION,
    ENTRA_SERVICE_PRINCIPAL,
    ENTRA_APPLICATION_USER_ASSIGNMENT,
    ENTRA_APPLICATION_GROUP_ASSIGNMENT,
    ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT,
    ENTRA_OAUTH2_PERMISSION_GRANT,
    ENTRA_CONDITIONAL_ACCESS_POLICY,
    ENTRA_AUTHENTICATION_STRENGTH,
    ENTRA_AUTHENTICATION_METHOD,
})


# ── Tenant / client ID validation ───────────────────────────────────────────
#
# Microsoft Entra tenant IDs and application (client) IDs are both GUIDs
# (RFC 4122 canonical dashed form). A ConfigTrace integration must target
# one concrete tenant, so the special multi-tenant audience values
# "common", "organizations", and "consumers" — valid as an OAuth *audience*
# segment for user-facing sign-in flows, but never a real, single tenant
# identity — are explicitly rejected here.

_GUID_RE = _re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_MULTI_TENANT_AUDIENCES = frozenset({"common", "organizations", "consumers"})


class EntraCredentialError(ValueError):
    """Raised when a tenant_id/client_id credential fails validation.
    Subclasses ValueError so existing generic error handling still catches
    it."""


def validate_tenant_id(raw_tenant_id: object) -> str:
    """Validate and normalize an Entra tenant ID.

    Requires canonical GUID syntax. Rejects the multi-tenant audience
    placeholders ("common"/"organizations"/"consumers"), embedded URLs,
    arbitrary hostnames, and query/fragment content — a ConfigTrace
    integration must target exactly one concrete tenant so tenant identity
    stays deterministic and stable.

    Returns the lowercased, trimmed GUID string. Raises
    ``EntraCredentialError`` — never silently coerces a malformed value.
    """
    if not isinstance(raw_tenant_id, str) or not raw_tenant_id.strip():
        raise EntraCredentialError("entra: tenant_id must be a non-empty string")

    cleaned = raw_tenant_id.strip().lower()

    if cleaned in _MULTI_TENANT_AUDIENCES:
        raise EntraCredentialError(
            f"entra: tenant_id must be a concrete tenant GUID, not the "
            f"multi-tenant audience {cleaned!r} — a ConfigTrace integration "
            "must target exactly one tenant."
        )

    if "://" in cleaned or "/" in cleaned or "?" in cleaned or "#" in cleaned:
        raise EntraCredentialError(
            "entra: tenant_id must not contain a URL, path, query, or fragment"
        )

    if not _GUID_RE.match(cleaned):
        raise EntraCredentialError(
            "entra: tenant_id must be a canonical GUID "
            "(e.g. '11111111-1111-1111-1111-111111111111')"
        )

    return cleaned


def validate_client_id(raw_client_id: object) -> str:
    """Validate and normalize an Entra application (client) ID.

    Application/client IDs are also GUIDs. Validated conservatively — the
    same GUID-syntax check as the tenant ID, since Microsoft does not
    document any other stable client-ID form for app registrations. Never
    used to derive tenant identity.
    """
    if not isinstance(raw_client_id, str) or not raw_client_id.strip():
        raise EntraCredentialError("entra: client_id must be a non-empty string")

    cleaned = raw_client_id.strip().lower()

    if "://" in cleaned or "/" in cleaned or "?" in cleaned or "#" in cleaned:
        raise EntraCredentialError(
            "entra: client_id must not contain a URL, path, query, or fragment"
        )

    if not _GUID_RE.match(cleaned):
        raise EntraCredentialError(
            "entra: client_id must be a canonical GUID "
            "(e.g. '22222222-2222-2222-2222-222222222222')"
        )

    return cleaned


# ── Capability probe families (future record collection surfaces) ─────────
#
# These are the record families message 2-5 will implement. Message 1 only
# probes whether each is readable — it never collects the underlying data.

CAPABILITY_FAMILY_USERS = "users"
CAPABILITY_FAMILY_GROUPS = "groups"
CAPABILITY_FAMILY_APPLICATIONS = "applications"
CAPABILITY_FAMILY_SERVICE_PRINCIPALS = "service_principals"
CAPABILITY_FAMILY_CONDITIONAL_ACCESS = "conditional_access"
CAPABILITY_FAMILY_AUTHENTICATION_METHODS = "authentication_methods"
CAPABILITY_FAMILY_DIRECTORY_ROLES = "directory_roles"
CAPABILITY_FAMILY_OAUTH2_PERMISSION_GRANTS = "oauth2_permission_grants"

CAPABILITY_FAMILIES = (
    CAPABILITY_FAMILY_USERS,
    CAPABILITY_FAMILY_GROUPS,
    CAPABILITY_FAMILY_APPLICATIONS,
    CAPABILITY_FAMILY_SERVICE_PRINCIPALS,
    CAPABILITY_FAMILY_CONDITIONAL_ACCESS,
    CAPABILITY_FAMILY_AUTHENTICATION_METHODS,
    CAPABILITY_FAMILY_DIRECTORY_ROLES,
    CAPABILITY_FAMILY_OAUTH2_PERMISSION_GRANTS,
)

# ── Capability probe outcome categories ─────────────────────────────────────

CAPABILITY_AVAILABLE = "available"
CAPABILITY_DENIED = "denied"
CAPABILITY_UNSUPPORTED = "unsupported"
CAPABILITY_UNAVAILABLE = "unavailable"
CAPABILITY_THROTTLED = "throttled"
CAPABILITY_UNKNOWN = "unknown"

CAPABILITY_STATUSES = frozenset({
    CAPABILITY_AVAILABLE,
    CAPABILITY_DENIED,
    CAPABILITY_UNSUPPORTED,
    CAPABILITY_UNAVAILABLE,
    CAPABILITY_THROTTLED,
    CAPABILITY_UNKNOWN,
})


# ── Organization record helpers ─────────────────────────────────────────────


def categorize_on_premises_sync(raw: object) -> str:
    """Map the Microsoft Graph ``organization.onPremisesSyncEnabled`` field
    to a fixed, safe category.

    Graph returns ``true``, ``false``, or omits the field (``null``/absent
    is common when hybrid sync has never been configured) — this is never
    coerced to a specific boolean guess.
    """
    if raw is True:
        return "enabled"
    if raw is False:
        return "disabled"
    return "unknown"


# ── Family collection completeness (Entra message 2) ────────────────────────
#
# Distinct from CAPABILITY_STATUSES (a message-1 single-probe outcome) —
# this describes what actually happened when message-2 tried to COLLECT a
# whole family (users/groups/memberships), which can partially succeed
# across a paginated, potentially-per-group series of calls. Mirrors Okta's
# identical taxonomy exactly (see okta_schema.py).

FAMILY_COMPLETE = "complete"
FAMILY_PARTIAL = "partial"
FAMILY_DENIED = "denied"
FAMILY_UNAVAILABLE = "unavailable"

FAMILY_COMPLETENESS_STATUSES = frozenset({
    FAMILY_COMPLETE, FAMILY_PARTIAL, FAMILY_DENIED, FAMILY_UNAVAILABLE,
})


# ── Account-enabled tri-state (Entra message 2) ─────────────────────────────
#
# Microsoft Graph's `accountEnabled` is a genuine tri-state in practice:
# True, False, or absent/null (some directory-synced or partially
# provisioned objects omit it). `bool(None)` would silently coerce
# "unknown" into "disabled" — never do that.

ACCOUNT_ENABLED_ENABLED = "enabled"
ACCOUNT_ENABLED_DISABLED = "disabled"
ACCOUNT_ENABLED_UNKNOWN = "unknown"


def categorize_account_enabled(raw: object) -> str:
    """Map Graph's tri-state ``accountEnabled`` to a fixed, safe category.
    ``None`` (or any non-bool) is always ``"unknown"`` — never coerced to
    ``"disabled"``."""
    if raw is True:
        return ACCOUNT_ENABLED_ENABLED
    if raw is False:
        return ACCOUNT_ENABLED_DISABLED
    return ACCOUNT_ENABLED_UNKNOWN


# ── User type taxonomy (Entra message 2) ────────────────────────────────────
#
# Graph's documented `userType` values are exactly "Member" and "Guest".
# Anything else (missing, null, or a genuinely unrecognized future value)
# is "unknown" — NEVER defaulted to "Member".

USER_TYPE_MEMBER = "Member"
USER_TYPE_GUEST = "Guest"
USER_TYPE_UNKNOWN = "unknown"

USER_TYPES = frozenset({USER_TYPE_MEMBER, USER_TYPE_GUEST})


def categorize_user_type(raw: object) -> str:
    """Map a raw Graph ``userType`` string to the fixed USER_TYPE_* set.
    Returns ``USER_TYPE_UNKNOWN`` for anything not exactly "Member" or
    "Guest" — never guessed to be Member."""
    if isinstance(raw, str) and raw in USER_TYPES:
        return raw
    return USER_TYPE_UNKNOWN


# ── Lifecycle posture (Entra message 2) ─────────────────────────────────────
#
# Combines account-enabled state with member/guest identity. Guest/member
# status is a normal identity category, never itself a risk signal — this
# taxonomy keeps it orthogonal to enabled/disabled, never implying
# "guest == risky". Unknown on EITHER axis collapses the whole posture to
# "unknown" — never guessed toward a specific known posture.

LIFECYCLE_ENABLED_MEMBER = "enabled_member"
LIFECYCLE_DISABLED_MEMBER = "disabled_member"
LIFECYCLE_ENABLED_GUEST = "enabled_guest"
LIFECYCLE_DISABLED_GUEST = "disabled_guest"
LIFECYCLE_UNKNOWN = "unknown"

LIFECYCLE_POSTURES = frozenset({
    LIFECYCLE_ENABLED_MEMBER, LIFECYCLE_DISABLED_MEMBER,
    LIFECYCLE_ENABLED_GUEST, LIFECYCLE_DISABLED_GUEST, LIFECYCLE_UNKNOWN,
})


def lifecycle_posture_for_user(account_enabled_category: str, user_type_category: str) -> str:
    """Combine account-enabled + user-type categories into one lifecycle
    posture. Unknown on either axis always yields LIFECYCLE_UNKNOWN."""
    if account_enabled_category == ACCOUNT_ENABLED_UNKNOWN or user_type_category == USER_TYPE_UNKNOWN:
        return LIFECYCLE_UNKNOWN
    if user_type_category == USER_TYPE_GUEST:
        return (
            LIFECYCLE_ENABLED_GUEST if account_enabled_category == ACCOUNT_ENABLED_ENABLED
            else LIFECYCLE_DISABLED_GUEST
        )
    return (
        LIFECYCLE_ENABLED_MEMBER if account_enabled_category == ACCOUNT_ENABLED_ENABLED
        else LIFECYCLE_DISABLED_MEMBER
    )


# ── External user state (Entra message 2) ───────────────────────────────────
#
# Graph's documented `externalUserState` values for B2B guest invitations
# are exactly "PendingAcceptance" and "Accepted". Only meaningful for guest
# users; member users typically have this field absent. Anything else
# (missing, null, unrecognized) is "unknown" — never guessed.

EXTERNAL_USER_STATE_PENDING = "PendingAcceptance"
EXTERNAL_USER_STATE_ACCEPTED = "Accepted"
EXTERNAL_USER_STATE_UNKNOWN = "unknown"

EXTERNAL_USER_STATES = frozenset({EXTERNAL_USER_STATE_PENDING, EXTERNAL_USER_STATE_ACCEPTED})


def categorize_external_user_state(raw: object) -> str:
    """Map a raw Graph ``externalUserState`` string to the fixed
    EXTERNAL_USER_STATE_* set. Returns ``"unknown"`` for anything else."""
    if isinstance(raw, str) and raw in EXTERNAL_USER_STATES:
        return raw
    return EXTERNAL_USER_STATE_UNKNOWN


# ── Group type taxonomy (Entra message 2) ───────────────────────────────────
#
# Microsoft Entra groups are not a single concept — the SAME group can be a
# security group, a mail-enabled distribution list, a Microsoft 365
# ("Unified") group, and/or dynamically-membered, based on the combination
# of `securityEnabled` (tri-state), `mailEnabled` (tri-state), and the
# `groupTypes` list (which may contain "Unified" and/or
# "DynamicMembership"). This category is derived ONLY from that explicit
# Graph evidence — never guessed from the group's display name.

GROUP_TYPE_SECURITY = "security"
GROUP_TYPE_MICROSOFT_365 = "microsoft_365"
GROUP_TYPE_DYNAMIC_SECURITY = "dynamic_security"
GROUP_TYPE_DYNAMIC_MICROSOFT_365 = "dynamic_microsoft_365"
GROUP_TYPE_DISTRIBUTION_OR_MAIL = "distribution_or_mail"
GROUP_TYPE_OTHER = "other"
GROUP_TYPE_UNKNOWN = "unknown"

GROUP_TYPE_CATEGORIES = frozenset({
    GROUP_TYPE_SECURITY, GROUP_TYPE_MICROSOFT_365, GROUP_TYPE_DYNAMIC_SECURITY,
    GROUP_TYPE_DYNAMIC_MICROSOFT_365, GROUP_TYPE_DISTRIBUTION_OR_MAIL,
    GROUP_TYPE_OTHER, GROUP_TYPE_UNKNOWN,
})

# The only two documented `groupTypes` values as of Graph v1.0. Any other
# string is preserved (not discarded) but never treated as one of these
# known signals.
GROUP_TYPES_UNIFIED = "Unified"
GROUP_TYPES_DYNAMIC_MEMBERSHIP = "DynamicMembership"
_KNOWN_GROUP_TYPES_VALUES = frozenset({GROUP_TYPES_UNIFIED, GROUP_TYPES_DYNAMIC_MEMBERSHIP})


def normalize_group_types(raw: object) -> list[str]:
    """Normalize the Graph ``groupTypes`` list: deduplicated, sorted for
    deterministic snapshot ordering, and bounded. Unrecognized values are
    preserved (never silently dropped) — only the ORDER is made
    deterministic; API response ordering must never affect the normalized
    snapshot or its fingerprint."""
    if not isinstance(raw, list):
        return []
    values = {v for v in raw if isinstance(v, str) and v.strip()}
    return sorted(values)[:20]


def categorize_group_type(
    security_enabled: object, mail_enabled: object, group_types: list[str],
) -> str:
    """Derive a deterministic group-type category from explicit Graph
    evidence only — never from the group's display name.

    ``security_enabled``/``mail_enabled`` are read as the RAW tri-state
    values (True/False/None) so "unknown" can be distinguished from
    "false" — if either is unknown, the category itself is unknown, since
    a reliable category cannot be derived without both signals.
    """
    if security_enabled is None or mail_enabled is None:
        return GROUP_TYPE_UNKNOWN

    is_unified = GROUP_TYPES_UNIFIED in group_types
    is_dynamic = GROUP_TYPES_DYNAMIC_MEMBERSHIP in group_types

    if is_unified and mail_enabled is True:
        return GROUP_TYPE_DYNAMIC_MICROSOFT_365 if is_dynamic else GROUP_TYPE_MICROSOFT_365
    if security_enabled is True and mail_enabled is False:
        return GROUP_TYPE_DYNAMIC_SECURITY if is_dynamic else GROUP_TYPE_SECURITY
    if mail_enabled is True and security_enabled is False and not is_unified:
        return GROUP_TYPE_DISTRIBUTION_OR_MAIL
    return GROUP_TYPE_OTHER


# ── Membership count buckets (Entra message 2) ──────────────────────────────
#
# Mirrors Okta's identical taxonomy — ``None`` (membership collection was
# denied/partial for this group, so the count is genuinely unknown) always
# returns "unknown", never "0". Zero is reserved for a group whose walk
# genuinely succeeded and had no matching user members.

MEMBERSHIP_COUNT_ZERO = "0"
MEMBERSHIP_COUNT_SMALL = "1-5"
MEMBERSHIP_COUNT_MEDIUM = "6-20"
MEMBERSHIP_COUNT_LARGE = "21-100"
MEMBERSHIP_COUNT_VERY_LARGE = "100+"
MEMBERSHIP_COUNT_UNKNOWN = "unknown"


def categorize_membership_count(count: object) -> str:
    """Bucket a non-negative integer membership count. ``None``/non-int
    input returns MEMBERSHIP_COUNT_UNKNOWN — never 0."""
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        return MEMBERSHIP_COUNT_UNKNOWN
    if count == 0:
        return MEMBERSHIP_COUNT_ZERO
    if count <= 5:
        return MEMBERSHIP_COUNT_SMALL
    if count <= 20:
        return MEMBERSHIP_COUNT_MEDIUM
    if count <= 100:
        return MEMBERSHIP_COUNT_LARGE
    return MEMBERSHIP_COUNT_VERY_LARGE


# Graph's `@odata.type` annotation for a directoryObject member that is a
# user — the only member type message 2 normalizes. Service principals
# ("#microsoft.graph.servicePrincipal"), devices ("#microsoft.graph.device"),
# and nested groups ("#microsoft.graph.group") are explicitly excluded here
# and deferred to later messages (3/5) or left permanently unmodeled
# (devices).
GRAPH_MEMBER_TYPE_USER = "#microsoft.graph.user"


# ══════════════════════════════════════════════════════════════════════════
# Application / service-principal taxonomy (Entra message 3)
# ══════════════════════════════════════════════════════════════════════════
#
# Object-model mapping (Microsoft Graph, confirmed against current Graph
# v1.0 documentation before implementation):
#
#   application       — the app REGISTRATION definition. Global object;
#                        `id` is the app registration's own object ID,
#                        `appId` is the client ID used in OAuth flows.
#                        Defines requiredResourceAccess (REQUESTED
#                        permissions), redirect URIs, and its own
#                        passwordCredentials/keyCredentials.
#   servicePrincipal  — the TENANT-LOCAL representation of an application
#                        (what the Entra admin center calls "Enterprise
#                        Applications"). Has its OWN object `id` (distinct
#                        from the application's object id) but shares the
#                        same `appId`. Exists for the tenant's own app
#                        registrations, for other tenants' multi-tenant
#                        apps once consented, for Microsoft first-party
#                        apps, and for managed identities. Carries
#                        accountEnabled, appRoleAssignmentRequired,
#                        servicePrincipalType, verifiedPublisher, and its
#                        own passwordCredentials/keyCredentials (client
#                        secrets/certificates issued for THIS tenant's use
#                        of the app, distinct from the application's own).
#   appRoleAssignment — an assignment of an app role to a principal (User,
#                        Group, or ServicePrincipal) FOR a resource service
#                        principal. Retrieved per-resource-SP via
#                        ``GET /servicePrincipals/{id}/appRoleAssignedTo``
#                        (lists everyone assigned INTO this resource) — no
#                        tenant-wide list endpoint exists in Graph v1.0, so
#                        this is necessarily a bounded per-SP walk (see
#                        ``_fetch_app_role_assignments`` in entra.py).
#   oauth2PermissionGrant — a DELEGATED OAuth2 consent grant (a client app
#                        consented, by a user or an admin, to call a
#                        resource API on the signed-in user's behalf with
#                        specific delegated scopes). Retrieved tenant-wide
#                        via ``GET /oauth2PermissionGrants`` — Graph DOES
#                        expose this as a flat collection, so no per-app
#                        walk is needed (confirmed before implementation;
#                        avoids the per-user consent enumeration the task
#                        explicitly warns against).
#
# `requiredResourceAccess` (on `application`) is REQUESTED/configured
# permission — it is NEVER treated as granted access. Only
# `appRoleAssignment` (application permissions) and `oauth2PermissionGrant`
# (delegated permissions) represent actual granted access. This distinction
# is permanent and is never collapsed into one "permissions" field.

ENTRA_APPLICATION_RECORD_TYPES = frozenset({
    ENTRA_APPLICATION, ENTRA_SERVICE_PRINCIPAL,
    ENTRA_APPLICATION_USER_ASSIGNMENT, ENTRA_APPLICATION_GROUP_ASSIGNMENT,
    ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT, ENTRA_OAUTH2_PERMISSION_GRANT,
})

# Microsoft Graph's own well-known application (client) ID. Identical
# across every Microsoft commercial-cloud tenant (it identifies the Graph
# API resource itself, not a tenant-specific object) — this is public,
# stable, Microsoft-documented information, not something inferred or
# guessed. Used ONLY to label a permission assignment/grant as targeting
# Microsoft Graph specifically; never used to infer privilege by itself.
MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

# Microsoft's own well-known first-party publisher tenant ID (the tenant
# that owns Microsoft's own first-party service principals, e.g. "Microsoft
# Graph", "Office 365 Exchange Online"). Public, stable, Microsoft-
# documented. Used only to label service principals as Microsoft first-
# party — never to infer privilege by itself.
MICROSOFT_FIRST_PARTY_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"


# ── Sign-in audience taxonomy ───────────────────────────────────────────────
#
# Graph's `application.signInAudience` documented values, exactly as
# returned (case-sensitive):
SIGN_IN_AUDIENCE_MY_ORG = "AzureADMyOrg"
SIGN_IN_AUDIENCE_MULTI_ORG = "AzureADMultipleOrgs"
SIGN_IN_AUDIENCE_MULTI_ORG_AND_PERSONAL = "AzureADandPersonalMicrosoftAccount"
SIGN_IN_AUDIENCE_PERSONAL_ONLY = "PersonalMicrosoftAccount"

_RAW_SIGN_IN_AUDIENCES = frozenset({
    SIGN_IN_AUDIENCE_MY_ORG, SIGN_IN_AUDIENCE_MULTI_ORG,
    SIGN_IN_AUDIENCE_MULTI_ORG_AND_PERSONAL, SIGN_IN_AUDIENCE_PERSONAL_ONLY,
})

SIGN_IN_AUDIENCE_SINGLE_TENANT = "single_tenant"
SIGN_IN_AUDIENCE_MULTI_TENANT = "multi_tenant"
SIGN_IN_AUDIENCE_MULTI_TENANT_AND_PERSONAL = "multi_tenant_and_personal"
SIGN_IN_AUDIENCE_PERSONAL_ONLY_CATEGORY = "personal_only"
SIGN_IN_AUDIENCE_UNKNOWN = "unknown"

SIGN_IN_AUDIENCE_CATEGORIES = frozenset({
    SIGN_IN_AUDIENCE_SINGLE_TENANT, SIGN_IN_AUDIENCE_MULTI_TENANT,
    SIGN_IN_AUDIENCE_MULTI_TENANT_AND_PERSONAL, SIGN_IN_AUDIENCE_PERSONAL_ONLY_CATEGORY,
    SIGN_IN_AUDIENCE_UNKNOWN,
})

_SIGN_IN_AUDIENCE_MAP = {
    SIGN_IN_AUDIENCE_MY_ORG: SIGN_IN_AUDIENCE_SINGLE_TENANT,
    SIGN_IN_AUDIENCE_MULTI_ORG: SIGN_IN_AUDIENCE_MULTI_TENANT,
    SIGN_IN_AUDIENCE_MULTI_ORG_AND_PERSONAL: SIGN_IN_AUDIENCE_MULTI_TENANT_AND_PERSONAL,
    SIGN_IN_AUDIENCE_PERSONAL_ONLY: SIGN_IN_AUDIENCE_PERSONAL_ONLY_CATEGORY,
}


def categorize_sign_in_audience(raw: object) -> str:
    """Map a raw Graph ``signInAudience`` string to a fixed, safe category.
    Multi-tenant is a normal, legitimate posture — never treated as
    malicious by this categorizer; it is surfaced as security-relevant
    CONTEXT only (message 6 decides Finding semantics)."""
    if isinstance(raw, str) and raw in _RAW_SIGN_IN_AUDIENCES:
        return _SIGN_IN_AUDIENCE_MAP[raw]
    return SIGN_IN_AUDIENCE_UNKNOWN


# ── Redirect URI posture ─────────────────────────────────────────────────────
#
# Mirrors Okta's `categorize_redirect_uris()` structural-summary approach
# exactly — raw URIs (which may embed query strings/fragments/internal
# hostnames) are NEVER stored, only counts/booleans derived from them.
# Entra additionally splits by CLIENT TYPE (web/spa/publicClient) because
# each has different legitimate patterns — a native/public client
# legitimately uses loopback/custom-scheme redirects that would be a
# real weakening for a confidential web app (see risk_rules/entra.py).

_LOOPBACK_HOSTNAMES = frozenset({"127.0.0.1", "::1", "0.0.0.0"})


def _redirect_uri_scheme_and_host(uri: str) -> tuple[Optional[str], Optional[str]]:
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return None, None
    scheme = parsed.scheme.lower() if parsed.scheme else None
    host = parsed.hostname.lower() if parsed.hostname else None
    return scheme, host


def _summarize_redirect_uris(uris: object) -> dict:
    """Return per-list structural counts for one redirect-URI list
    (web/spa/publicClient). Never stores the URIs themselves."""
    if not isinstance(uris, list):
        return {
            "count": 0, "https_count": 0, "http_count": 0,
            "localhost_count": 0, "loopback_count": 0,
            "custom_scheme_count": 0, "wildcard_present": False,
        }
    https_count = http_count = localhost_count = loopback_count = custom_scheme_count = 0
    wildcard_present = False
    valid_uris = [u for u in uris if isinstance(u, str)]
    for uri in valid_uris:
        if "*" in uri:
            wildcard_present = True
        scheme, host = _redirect_uri_scheme_and_host(uri)
        if scheme == "https":
            https_count += 1
        elif scheme == "http":
            http_count += 1
        elif scheme and scheme not in ("http", "https"):
            custom_scheme_count += 1
        if host == "localhost":
            localhost_count += 1
        elif host in _LOOPBACK_HOSTNAMES:
            loopback_count += 1
    return {
        "count": len(valid_uris),
        "https_count": https_count,
        "http_count": http_count,
        "localhost_count": localhost_count,
        "loopback_count": loopback_count,
        "custom_scheme_count": custom_scheme_count,
        "wildcard_present": wildcard_present,
    }


def summarize_application_redirects(web_uris: object, spa_uris: object, public_client_uris: object) -> dict:
    """Summarize an application's web/spa/publicClient redirect URIs into a
    single safe posture dict. Raw URIs (and their query strings/fragments)
    are NEVER stored or returned — only structural counts/booleans."""
    web = _summarize_redirect_uris(web_uris)
    spa = _summarize_redirect_uris(spa_uris)
    public_client = _summarize_redirect_uris(public_client_uris)
    return {
        "web_redirect_count": web["count"],
        "spa_redirect_count": spa["count"],
        "public_client_redirect_count": public_client["count"],
        "has_http_redirect": (web["http_count"] + spa["http_count"] + public_client["http_count"]) > 0,
        "has_localhost_redirect": (
            (web["localhost_count"] + spa["localhost_count"] + public_client["localhost_count"]) > 0
        ),
        "has_loopback_redirect": (
            (web["loopback_count"] + spa["loopback_count"] + public_client["loopback_count"]) > 0
        ),
        "has_custom_scheme_redirect": (
            (web["custom_scheme_count"] + spa["custom_scheme_count"] + public_client["custom_scheme_count"]) > 0
        ),
        "has_wildcard_redirect": web["wildcard_present"] or spa["wildcard_present"] or public_client["wildcard_present"],
        # Web-specific HTTP flag — web apps should generally use HTTPS
        # outside local development; this is tracked separately from the
        # aggregate has_http_redirect so the risk classifier can apply
        # client-type-specific severity (see risk_rules/entra.py).
        "web_has_http_redirect": web["http_count"] > 0,
    }


# ── Service principal type taxonomy ─────────────────────────────────────────
#
# Graph's documented `servicePrincipalType` values.
SP_TYPE_APPLICATION = "Application"
SP_TYPE_MANAGED_IDENTITY = "ManagedIdentity"
SP_TYPE_LEGACY = "Legacy"
SP_TYPE_SOCIAL_IDP = "SocialIdp"
SP_TYPE_UNKNOWN = "unknown"

SP_TYPES = frozenset({SP_TYPE_APPLICATION, SP_TYPE_MANAGED_IDENTITY, SP_TYPE_LEGACY, SP_TYPE_SOCIAL_IDP})


def categorize_service_principal_type(raw: object) -> str:
    """Map a raw Graph ``servicePrincipalType`` to the fixed SP_TYPE_* set.
    Never inferred from display name — Graph's own field only."""
    if isinstance(raw, str) and raw in SP_TYPES:
        return raw
    return SP_TYPE_UNKNOWN


# ── App ownership organization ──────────────────────────────────────────────

APP_OWNER_ORG_TENANT_OWNED = "tenant_owned"
APP_OWNER_ORG_EXTERNAL = "external"
APP_OWNER_ORG_UNKNOWN = "unknown"


def categorize_app_owner_organization(raw_app_owner_org_id: object, own_tenant_guid: str) -> str:
    """Compare a service principal's ``appOwnerOrganizationId`` to this
    integration's own tenant GUID. ``own_tenant_guid`` must be the plain
    GUID (not the ``id:<guid>`` stable-identity form)."""
    if not isinstance(raw_app_owner_org_id, str) or not raw_app_owner_org_id.strip():
        return APP_OWNER_ORG_UNKNOWN
    if raw_app_owner_org_id.strip().lower() == own_tenant_guid.strip().lower():
        return APP_OWNER_ORG_TENANT_OWNED
    return APP_OWNER_ORG_EXTERNAL


# ── Publisher verification ──────────────────────────────────────────────────

PUBLISHER_VERIFIED = "verified"
PUBLISHER_UNVERIFIED = "unverified"
PUBLISHER_UNKNOWN = "unknown"


def categorize_verified_publisher(verified_publisher: object) -> str:
    """Map a Graph ``verifiedPublisher`` object to a fixed category.
    Presence of a non-empty ``verifiedPublisherId`` means Microsoft's
    Partner Center verification succeeded for this publisher. Absence does
    NOT mean malicious — most legitimate line-of-business apps are
    unverified; this categorizer never implies otherwise (message 6 decides
    Finding semantics, if any)."""
    if not isinstance(verified_publisher, dict):
        return PUBLISHER_UNKNOWN
    publisher_id = verified_publisher.get("verifiedPublisherId")
    if isinstance(publisher_id, str) and publisher_id.strip():
        return PUBLISHER_VERIFIED
    return PUBLISHER_UNVERIFIED


# ── Credential (passwordCredentials/keyCredentials) expiry posture ─────────
#
# Deterministic, documented thresholds (no existing ConfigTrace credential-
# expiry convention was found elsewhere in the repo to reuse, so these are
# defined fresh here): a credential expiring within 30 days is "expiring
# soon" (a common rotation-lead-time convention); beyond 365 days out is
# "far_future" (informational — an unusually long-lived credential, not
# itself an alarm here). Message 6 may build Findings on top of these
# categories with its own severity judgment.
CREDENTIAL_EXPIRED = "expired"
CREDENTIAL_EXPIRING_SOON = "expiring_soon"
CREDENTIAL_HEALTHY = "healthy"
CREDENTIAL_FAR_FUTURE = "far_future"
CREDENTIAL_NO_CREDENTIALS = "no_credentials"
CREDENTIAL_UNKNOWN = "unknown"

_CREDENTIAL_EXPIRING_SOON_DAYS = 30
_CREDENTIAL_FAR_FUTURE_DAYS = 365


def _parse_graph_datetime(raw: object):
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        cleaned = raw.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def categorize_nearest_credential_expiry(
    credentials: list, *, now: Optional[object] = None,
) -> str:
    """Return the nearest-expiry category across a combined list of
    passwordCredentials + keyCredentials dicts (each with an ``endDateTime``
    string). Never reads ``secretText``/``key`` — only ``endDateTime``.

    Returns CREDENTIAL_NO_CREDENTIALS if the list is empty,
    CREDENTIAL_UNKNOWN if every entry's endDateTime is missing/unparseable,
    otherwise the category of the SOONEST-expiring parseable credential
    (the most urgent one is the one worth surfacing).
    """
    if not isinstance(credentials, list) or not credentials:
        return CREDENTIAL_NO_CREDENTIALS

    now_dt = now if isinstance(now, datetime) else datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    nearest_delta = None
    for cred in credentials:
        if not isinstance(cred, dict):
            continue
        end = _parse_graph_datetime(cred.get("endDateTime"))
        if end is None:
            continue
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        delta_days = (end - now_dt).total_seconds() / 86400.0
        if nearest_delta is None or delta_days < nearest_delta:
            nearest_delta = delta_days

    if nearest_delta is None:
        return CREDENTIAL_UNKNOWN
    if nearest_delta < 0:
        return CREDENTIAL_EXPIRED
    if nearest_delta <= _CREDENTIAL_EXPIRING_SOON_DAYS:
        return CREDENTIAL_EXPIRING_SOON
    if nearest_delta <= _CREDENTIAL_FAR_FUTURE_DAYS:
        return CREDENTIAL_HEALTHY
    return CREDENTIAL_FAR_FUTURE


# ── Required resource access (REQUESTED permissions — never granted) ───────

def summarize_required_resource_access(raw: object) -> dict:
    """Summarize an application's ``requiredResourceAccess`` array into
    safe counts only. This represents REQUESTED/configured permissions in
    the app manifest — NEVER equated with actually-granted access (see the
    module docstring's permanent requested-vs-granted distinction). The
    raw array (which includes resource App IDs and permission GUIDs) is
    NEVER stored — only aggregate counts.
    """
    if not isinstance(raw, list):
        return {
            "requested_resource_api_count": 0,
            "requested_delegated_permission_count": 0,
            "requested_application_permission_count": 0,
        }
    resource_count = 0
    delegated_count = 0
    application_count = 0
    for resource in raw:
        if not isinstance(resource, dict):
            continue
        resource_count += 1
        access = resource.get("resourceAccess")
        if not isinstance(access, list):
            continue
        for entry in access:
            if not isinstance(entry, dict):
                continue
            # Graph's ResourceAccess.type: "Scope" = delegated, "Role" = application.
            entry_type = entry.get("type")
            if entry_type == "Scope":
                delegated_count += 1
            elif entry_type == "Role":
                application_count += 1
    return {
        "requested_resource_api_count": resource_count,
        "requested_delegated_permission_count": delegated_count,
        "requested_application_permission_count": application_count,
    }


# ── Consent type taxonomy (oauth2PermissionGrant.consentType) ──────────────

CONSENT_TYPE_ALL_PRINCIPALS = "AllPrincipals"
CONSENT_TYPE_PRINCIPAL = "Principal"
CONSENT_TYPE_UNKNOWN = "unknown"

_CONSENT_TYPES = frozenset({CONSENT_TYPE_ALL_PRINCIPALS, CONSENT_TYPE_PRINCIPAL})


def categorize_consent_type(raw: object) -> str:
    """Map a raw Graph ``consentType`` to the fixed CONSENT_TYPE_* set.
    ``AllPrincipals`` is tenant-wide admin consent; ``Principal`` is a
    single user's own delegated consent — materially different security
    postures, never conflated. Neither is treated as malicious by itself."""
    if isinstance(raw, str) and raw in _CONSENT_TYPES:
        return raw
    return CONSENT_TYPE_UNKNOWN


def normalize_scopes(raw_scope_string: object) -> list[str]:
    """Parse a Graph ``oauth2PermissionGrant.scope`` space-delimited string
    into a deduplicated, sorted, bounded list of scope names. Never
    preserves the raw opaque string as-is."""
    if not isinstance(raw_scope_string, str) or not raw_scope_string.strip():
        return []
    scopes = {s.strip() for s in raw_scope_string.split(" ") if s.strip()}
    return sorted(scopes)[:100]


# ── Permission risk taxonomy (app-role VALUES and delegated-scope VALUES) ──
#
# A bounded, deterministic set of well-known, documented Microsoft Graph
# permission VALUE strings (never numeric/GUID permission IDs, which are
# tenant-agnostic but not human-legible) categorized as high-risk because
# they grant broad directory/tenant-wide write or role-management
# capability. This list is intentionally conservative and reused for BOTH
# application permissions (app roles) and delegated scopes, since Microsoft
# Graph commonly uses the same value string for the equivalent
# application-permission and delegated-scope form of a given capability.
# Unknown/unrecognized permission values are NEVER assumed safe — they
# remain "unknown", not "ordinary".
PERMISSION_RISK_HIGH = "high_risk"
PERMISSION_RISK_ORDINARY = "ordinary"
PERMISSION_RISK_UNKNOWN = "unknown"

_HIGH_RISK_PERMISSION_VALUES = frozenset({
    "Directory.ReadWrite.All",
    "Directory.AccessAsUser.All",
    "RoleManagement.ReadWrite.Directory",
    "RoleManagement.ReadWrite.CloudPC",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "User.ReadWrite.All",
    "User.ManageIdentities.All",
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.PermissionGrant",
    "Mail.ReadWrite",
    "Mail.Send",
    "MailboxSettings.ReadWrite",
    "Files.ReadWrite.All",
    "Sites.FullControl.All",
    "Sites.ReadWrite.All",
})


def categorize_permission_risk(permission_value: object) -> str:
    """Categorize a resolved Graph permission VALUE string (app-role value
    or delegated-scope name). An unresolved/unknown value is NEVER
    downgraded to "ordinary" — it stays "unknown" so a future permission
    this taxonomy doesn't yet recognize is never silently treated as safe.
    """
    if not isinstance(permission_value, str) or not permission_value.strip():
        return PERMISSION_RISK_UNKNOWN
    if permission_value in _HIGH_RISK_PERMISSION_VALUES:
        return PERMISSION_RISK_HIGH
    return PERMISSION_RISK_ORDINARY


# Graph's `@odata.type` annotations for appRoleAssignedTo principal types —
# the three possible principal kinds for one app-role assignment. Branched
# on explicitly so a service principal is never mistaken for a user.
GRAPH_PRINCIPAL_TYPE_USER = "User"
GRAPH_PRINCIPAL_TYPE_GROUP = "Group"
GRAPH_PRINCIPAL_TYPE_SERVICE_PRINCIPAL = "ServicePrincipal"


# ---------------------------------------------------------------------------
# Message 4: Conditional Access / authentication strength / authentication
# method taxonomy. Every categorizer below preserves an explicit "unknown"
# for missing/malformed input rather than coercing toward a safe- or
# unsafe-looking default (see the module docstring's unknown-state
# discipline). Report-only Conditional Access state must never be treated
# as enforced, and MFA under an OR grant-control operator must never be
# flattened into "MFA required".
# ---------------------------------------------------------------------------

# Conditional Access policy enforcement state.
CA_STATE_ENABLED = "enabled"
CA_STATE_REPORT_ONLY = "report_only"
CA_STATE_DISABLED = "disabled"
CA_STATE_UNKNOWN = "unknown"

_CA_STATE_MAP = {
    "enabled": CA_STATE_ENABLED,
    "disabled": CA_STATE_DISABLED,
    "enabledForReportingButNotEnforced": CA_STATE_REPORT_ONLY,
}


def categorize_ca_state(raw_state: object) -> str:
    """Normalize a Conditional Access policy's `state` field. Graph's
    report-only value is NEVER folded into "enabled" — a report-only policy
    does not enforce anything, and treating it as enforced would produce a
    dangerous false sense of protection.
    """
    if not isinstance(raw_state, str):
        return CA_STATE_UNKNOWN
    return _CA_STATE_MAP.get(raw_state, CA_STATE_UNKNOWN)


# Conditional Access user/group/role targeting scope category.
CA_TARGET_ALL_USERS = "all_users"
CA_TARGET_SELECTED_USERS = "selected_users"
CA_TARGET_SELECTED_GROUPS = "selected_groups"
CA_TARGET_DIRECTORY_ROLES = "directory_roles"
CA_TARGET_GUESTS_EXTERNAL = "guests_external_users"
CA_TARGET_WORKLOAD_IDENTITIES = "workload_identities"
CA_TARGET_MIXED = "mixed"
CA_TARGET_UNKNOWN = "unknown"


def categorize_ca_targeting(conditions_users: object) -> str:
    """Categorize a Conditional Access policy's `conditions.users` targeting
    shape into a coarse category. Only counts/presence of the standard Graph
    sub-fields are inspected — the actual ID arrays are never read into the
    returned category, and a missing/malformed block stays unknown rather
    than being assumed to mean "all users".
    """
    if not isinstance(conditions_users, dict):
        return CA_TARGET_UNKNOWN

    include_users = conditions_users.get("includeUsers")
    include_groups = conditions_users.get("includeGroups")
    include_roles = conditions_users.get("includeRoles")
    include_guests = conditions_users.get("includeGuestsOrExternalUsers")

    present = [
        bool(include_users),
        bool(include_groups),
        bool(include_roles),
        bool(include_guests),
    ]
    if sum(present) > 1:
        return CA_TARGET_MIXED

    if isinstance(include_users, list) and "All" in include_users:
        return CA_TARGET_ALL_USERS
    if include_guests:
        return CA_TARGET_GUESTS_EXTERNAL
    if include_roles:
        return CA_TARGET_DIRECTORY_ROLES
    if include_groups:
        return CA_TARGET_SELECTED_GROUPS
    if include_users:
        return CA_TARGET_SELECTED_USERS
    return CA_TARGET_UNKNOWN


# Conditional Access application/workload-identity targeting category.
CA_APP_TARGET_ALL_CLOUD_APPS = "all_cloud_apps"
CA_APP_TARGET_SELECTED_APPS = "selected_apps"
CA_APP_TARGET_USER_ACTIONS = "user_actions"
CA_APP_TARGET_AUTHENTICATION_CONTEXT = "authentication_context"
CA_APP_TARGET_UNKNOWN = "unknown"


def categorize_ca_app_targeting(conditions_applications: object) -> str:
    """Categorize a Conditional Access policy's `conditions.applications`
    targeting into a coarse category, preferring counts over storing the
    actual app-ID list.
    """
    if not isinstance(conditions_applications, dict):
        return CA_APP_TARGET_UNKNOWN

    include_apps = conditions_applications.get("includeApplications")
    user_actions = conditions_applications.get("includeUserActions")
    auth_context = conditions_applications.get("includeAuthenticationContextClassReferences")

    if isinstance(include_apps, list) and "All" in include_apps:
        return CA_APP_TARGET_ALL_CLOUD_APPS
    if auth_context:
        return CA_APP_TARGET_AUTHENTICATION_CONTEXT
    if user_actions:
        return CA_APP_TARGET_USER_ACTIONS
    if include_apps:
        return CA_APP_TARGET_SELECTED_APPS
    return CA_APP_TARGET_UNKNOWN


# Conditional Access client-app-type targeting category, used to derive
# whether a policy is explicitly targeting legacy authentication protocols.
CLIENT_APP_BROWSER = "browser"
CLIENT_APP_MOBILE_DESKTOP = "mobileAppsAndDesktopClients"
CLIENT_APP_EXCHANGE_ACTIVESYNC = "exchangeActiveSync"
CLIENT_APP_OTHER_LEGACY = "other"
CLIENT_APP_UNKNOWN = "unknown"

_KNOWN_CLIENT_APP_TYPES = frozenset(
    {
        CLIENT_APP_BROWSER,
        CLIENT_APP_MOBILE_DESKTOP,
        CLIENT_APP_EXCHANGE_ACTIVESYNC,
        CLIENT_APP_OTHER_LEGACY,
    }
)


def categorize_client_app_types(client_app_types: object) -> list:
    """Normalize the `conditions.clientAppTypes` list into bounded, sorted,
    deduplicated categories. An entry Graph doesn't document falls back to
    "unknown" rather than being silently dropped.
    """
    if not isinstance(client_app_types, list) or not client_app_types:
        return [CLIENT_APP_UNKNOWN]
    categories = set()
    for entry in client_app_types:
        if isinstance(entry, str) and entry in _KNOWN_CLIENT_APP_TYPES:
            categories.add(entry)
        else:
            categories.add(CLIENT_APP_UNKNOWN)
    return sorted(categories)


def is_legacy_auth_targeted(client_app_types: object) -> bool:
    """Whether a policy's client-app-type targeting explicitly names legacy
    authentication protocols. Derived ONLY from the explicit
    `exchangeActiveSync`/`other` categories Graph documents as covering
    legacy auth — never inferred from the absence of a client-app-types
    condition, since an absent condition means "all client app types"
    (which includes but is not limited to legacy auth) rather than
    specifically targeting it.
    """
    categories = categorize_client_app_types(client_app_types)
    return CLIENT_APP_EXCHANGE_ACTIVESYNC in categories or CLIENT_APP_OTHER_LEGACY in categories


# Conditional Access grant-control boolean operator.
GRANT_OPERATOR_AND = "AND"
GRANT_OPERATOR_OR = "OR"
GRANT_OPERATOR_UNKNOWN = "unknown"


def categorize_grant_operator(raw_operator: object) -> str:
    """Normalize `grantControls.operator`. Missing/malformed stays unknown —
    it is NEVER assumed to be AND (the stricter reading) or OR (the looser
    reading), since guessing either direction could misclassify a policy's
    actual enforcement strength.
    """
    if raw_operator == "AND":
        return GRANT_OPERATOR_AND
    if raw_operator == "OR":
        return GRANT_OPERATOR_OR
    return GRANT_OPERATOR_UNKNOWN


# Known built-in Conditional Access grant control values.
GRANT_CONTROL_MFA = "mfa"
GRANT_CONTROL_COMPLIANT_DEVICE = "compliantDevice"
GRANT_CONTROL_DOMAIN_JOINED_DEVICE = "domainJoinedDevice"
GRANT_CONTROL_APPROVED_APPLICATION = "approvedApplication"
GRANT_CONTROL_COMPLIANT_APPLICATION = "compliantApplication"
GRANT_CONTROL_PASSWORD_CHANGE = "passwordChange"
GRANT_CONTROL_AUTHENTICATION_STRENGTH = "authenticationStrength"
GRANT_CONTROL_BLOCK = "block"

_KNOWN_GRANT_CONTROLS = frozenset(
    {
        GRANT_CONTROL_MFA,
        GRANT_CONTROL_COMPLIANT_DEVICE,
        GRANT_CONTROL_DOMAIN_JOINED_DEVICE,
        GRANT_CONTROL_APPROVED_APPLICATION,
        GRANT_CONTROL_COMPLIANT_APPLICATION,
        GRANT_CONTROL_PASSWORD_CHANGE,
        GRANT_CONTROL_AUTHENTICATION_STRENGTH,
        GRANT_CONTROL_BLOCK,
    }
)


def normalize_grant_controls(built_in_controls: object) -> list:
    """Normalize `grantControls.builtInControls` into a bounded, sorted,
    deduplicated list of known control names. Unrecognized entries are
    dropped from this list (they cannot be safely modeled) but the caller
    is responsible for using `mfa_requirement_from_grant_controls()`'s
    unknown fallback when the raw controls list itself is malformed.
    """
    if not isinstance(built_in_controls, list):
        return []
    return sorted({c for c in built_in_controls if c in _KNOWN_GRANT_CONTROLS})


# MFA requirement category derived from grant-control operator + controls.
MFA_REQUIREMENT_REQUIRED = "required"
MFA_REQUIREMENT_ONE_OF_MULTIPLE = "one_of_multiple_controls"
MFA_REQUIREMENT_NOT_REQUIRED = "not_required"
MFA_REQUIREMENT_BLOCKED = "blocked"
MFA_REQUIREMENT_UNKNOWN = "unknown"

# Directional rank for classifying MFA-requirement transitions. Only used
# to compare two KNOWN categories against each other — an "unknown" on
# either side of a transition must never be ranked, so callers must check
# for unknown before consulting this table.
MFA_REQUIREMENT_RANK = {
    MFA_REQUIREMENT_NOT_REQUIRED: 0,
    MFA_REQUIREMENT_ONE_OF_MULTIPLE: 1,
    MFA_REQUIREMENT_REQUIRED: 2,
    MFA_REQUIREMENT_BLOCKED: 2,
}


def mfa_requirement_from_grant_controls(
    grant_controls: object,
) -> str:
    """Derive the MFA requirement category from a Conditional Access
    policy's `grantControls` block. `grant_controls` is the raw dict as
    returned by Graph (containing `operator` and `builtInControls`), or
    None/malformed if the policy has no grant controls block at all.

    Rules (must not be shortcut):
    - Missing/malformed grantControls -> unknown (never "not_required" --
      a policy might rely on session controls alone, or the block may have
      failed to collect).
    - `builtInControls` containing "block" -> blocked (access denied
      entirely; MFA is moot).
    - "mfa" absent from builtInControls -> not_required.
    - "mfa" present AND operator is AND (or there is exactly one control)
      -> required.
    - "mfa" present AND operator is OR with more than one control ->
      one_of_multiple_controls (MFA is merely one of several satisfying
      options, NOT strictly required).
    - "mfa" present AND operator unknown -> unknown (cannot tell if MFA is
      actually enforced or just one OR-branch).
    """
    if not isinstance(grant_controls, dict):
        return MFA_REQUIREMENT_UNKNOWN

    controls = normalize_grant_controls(grant_controls.get("builtInControls"))
    if not isinstance(grant_controls.get("builtInControls"), list):
        return MFA_REQUIREMENT_UNKNOWN

    if GRANT_CONTROL_BLOCK in controls:
        return MFA_REQUIREMENT_BLOCKED
    if GRANT_CONTROL_MFA not in controls:
        return MFA_REQUIREMENT_NOT_REQUIRED

    if len(controls) == 1:
        return MFA_REQUIREMENT_REQUIRED

    operator = categorize_grant_operator(grant_controls.get("operator"))
    if operator == GRANT_OPERATOR_AND:
        return MFA_REQUIREMENT_REQUIRED
    if operator == GRANT_OPERATOR_OR:
        return MFA_REQUIREMENT_ONE_OF_MULTIPLE
    return MFA_REQUIREMENT_UNKNOWN


# Conditional Access risk-level category (user risk / sign-in risk
# conditions). Bounded, sorted, deduplicated -- never a raw Identity
# Protection risk-event ingestion.
RISK_LEVEL_LOW = "low"
RISK_LEVEL_MEDIUM = "medium"
RISK_LEVEL_HIGH = "high"
RISK_LEVEL_NONE = "none"
RISK_LEVEL_UNKNOWN = "unknown"

_KNOWN_RISK_LEVELS = frozenset(
    {RISK_LEVEL_LOW, RISK_LEVEL_MEDIUM, RISK_LEVEL_HIGH, RISK_LEVEL_NONE}
)


def normalize_risk_levels(risk_levels: object) -> list:
    """Normalize a `conditions.userRiskLevels` / `conditions.signInRiskLevels`
    list into bounded, sorted, deduplicated categories. This is policy
    CONFIGURATION only -- it never ingests or represents actual Identity
    Protection risk events.
    """
    if not isinstance(risk_levels, list) or not risk_levels:
        return [RISK_LEVEL_UNKNOWN]
    categories = set()
    for entry in risk_levels:
        if isinstance(entry, str) and entry in _KNOWN_RISK_LEVELS:
            categories.add(entry)
        else:
            categories.add(RISK_LEVEL_UNKNOWN)
    return sorted(categories)


# Conditional Access session-control categories.
SESSION_CONTROL_SIGN_IN_FREQUENCY = "sign_in_frequency"
SESSION_CONTROL_PERSISTENT_BROWSER = "persistent_browser"
SESSION_CONTROL_CAE = "continuous_access_evaluation"
SESSION_CONTROL_APP_ENFORCED_RESTRICTIONS = "app_enforced_restrictions"

# Sign-in frequency interval bucket, reusing the same coarse boundary
# philosophy as the session-lifetime bucketing used elsewhere in this
# taxonomy family: shorter intervals re-challenge the user more often and
# are the stricter posture.
SIGN_IN_FREQUENCY_EVERY_TIME = "every_time"
SIGN_IN_FREQUENCY_VERY_SHORT = "very_short"
SIGN_IN_FREQUENCY_SHORT = "short"
SIGN_IN_FREQUENCY_STANDARD = "standard"
SIGN_IN_FREQUENCY_EXTENDED = "extended"
SIGN_IN_FREQUENCY_UNKNOWN = "unknown"

SIGN_IN_FREQUENCY_RANK = {
    SIGN_IN_FREQUENCY_EVERY_TIME: 0,
    SIGN_IN_FREQUENCY_VERY_SHORT: 1,
    SIGN_IN_FREQUENCY_SHORT: 2,
    SIGN_IN_FREQUENCY_STANDARD: 3,
    SIGN_IN_FREQUENCY_EXTENDED: 4,
}

_ISO8601_DURATION_RE = _re.compile(
    r"^P(?:(?P<days>\d+)D)?"
    r"(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$"
)


def parse_iso8601_duration_to_minutes(raw_duration: object) -> Optional[int]:
    """Parse a bounded subset of ISO8601 durations (days/hours/minutes/
    seconds) into whole minutes. Returns None for missing/malformed input
    rather than guessing -- callers must treat None as unknown.
    """
    if not isinstance(raw_duration, str) or not raw_duration:
        return None
    match = _ISO8601_DURATION_RE.match(raw_duration.strip())
    if not match or not any(match.groups()):
        return None
    days = int(match.group("days") or 0)
    hours = int(match.group("hours") or 0)
    minutes = int(match.group("minutes") or 0)
    seconds = int(match.group("seconds") or 0)
    return days * 24 * 60 + hours * 60 + minutes + (1 if seconds else 0)


def categorize_sign_in_frequency(
    is_enabled: object, frequency_value: object, frequency_unit: object
) -> str:
    """Categorize a Conditional Access session control's sign-in-frequency
    setting into a coarse bucket. `frequency_value`/`frequency_unit` follow
    Graph's `signInFrequency.value`/`signInFrequency.type` (hours/days), or
    the newer `everyTime` authentication-based frequency.
    """
    if is_enabled is not True:
        return SIGN_IN_FREQUENCY_UNKNOWN
    if frequency_unit == "everyTime":
        return SIGN_IN_FREQUENCY_EVERY_TIME
    if not isinstance(frequency_value, (int, float)) or frequency_value <= 0:
        return SIGN_IN_FREQUENCY_UNKNOWN

    if frequency_unit == "days":
        minutes = frequency_value * 24 * 60
    elif frequency_unit == "hours":
        minutes = frequency_value * 60
    else:
        return SIGN_IN_FREQUENCY_UNKNOWN

    if minutes < 60:
        return SIGN_IN_FREQUENCY_VERY_SHORT
    if minutes < 24 * 60:
        return SIGN_IN_FREQUENCY_SHORT
    if minutes < 7 * 24 * 60:
        return SIGN_IN_FREQUENCY_STANDARD
    return SIGN_IN_FREQUENCY_EXTENDED


# Conditional Access policy coverage-breadth category, combining user and
# app targeting into one coarse label for reporting/severity guidance.
COVERAGE_ALL_USERS_ALL_APPS = "all_users_all_apps"
COVERAGE_ALL_USERS_SELECTED_APPS = "all_users_selected_apps"
COVERAGE_SELECTED_PRINCIPALS_ALL_APPS = "selected_principals_all_apps"
COVERAGE_SELECTED_PRINCIPALS_SELECTED_APPS = "selected_principals_selected_apps"
COVERAGE_GUESTS = "guests"
COVERAGE_WORKLOADS = "workloads"
COVERAGE_UNKNOWN = "unknown"


def categorize_policy_coverage(user_target: str, app_target: str) -> str:
    """Combine a policy's user-targeting and app-targeting categories into
    a coarse coverage-breadth label, used only for reporting/severity
    guidance -- never as an exact effective-access computation.
    """
    if user_target == CA_TARGET_GUESTS_EXTERNAL:
        return COVERAGE_GUESTS
    if user_target == CA_TARGET_WORKLOAD_IDENTITIES:
        return COVERAGE_WORKLOADS
    if user_target == CA_TARGET_UNKNOWN or app_target == CA_APP_TARGET_UNKNOWN:
        return COVERAGE_UNKNOWN
    if user_target == CA_TARGET_ALL_USERS and app_target == CA_APP_TARGET_ALL_CLOUD_APPS:
        return COVERAGE_ALL_USERS_ALL_APPS
    if user_target == CA_TARGET_ALL_USERS:
        return COVERAGE_ALL_USERS_SELECTED_APPS
    if app_target == CA_APP_TARGET_ALL_CLOUD_APPS:
        return COVERAGE_SELECTED_PRINCIPALS_ALL_APPS
    return COVERAGE_SELECTED_PRINCIPALS_SELECTED_APPS


# ---------------------------------------------------------------------------
# Authentication strength taxonomy.
# ---------------------------------------------------------------------------

AUTH_STRENGTH_BUILT_IN = "built_in"
AUTH_STRENGTH_CUSTOM = "custom"
AUTH_STRENGTH_KIND_UNKNOWN = "unknown"

# Microsoft's well-known, tenant-agnostic built-in authentication strength
# policy IDs (documented, stable GUIDs -- never inferred from display name).
BUILT_IN_AUTH_STRENGTH_IDS = frozenset(
    {
        "00000000-0000-0000-0000-000000000002",  # Multifactor authentication
        "00000000-0000-0000-0000-000000000003",  # Passwordless MFA
        "00000000-0000-0000-0000-000000000004",  # Phishing-resistant MFA
    }
)


def categorize_auth_strength_kind(policy_type: object, policy_id: object = None) -> str:
    """Categorize an authentication strength policy as built-in or custom.

    Prefers Graph's own documented ``policyType`` field ("builtIn"/
    "custom") when present -- this is the authoritative, structured signal.
    Falls back to matching ``policy_id`` against the well-known built-in
    strength GUIDs only when ``policyType`` is missing/malformed. Never
    inferred from ``displayName``, which a tenant admin can freely rename.
    """
    if policy_type == "builtIn":
        return AUTH_STRENGTH_BUILT_IN
    if policy_type == "custom":
        return AUTH_STRENGTH_CUSTOM
    if isinstance(policy_id, str) and policy_id in BUILT_IN_AUTH_STRENGTH_IDS:
        return AUTH_STRENGTH_BUILT_IN
    return AUTH_STRENGTH_KIND_UNKNOWN


# Authentication method combination values (Graph's
# `allowedCombinations` entries) bucketed by phishing-resistance and
# passwordless categories. Combination values not in either set are
# treated conservatively (not phishing-resistant, not passwordless).
PHISHING_RESISTANT_COMBOS = frozenset(
    {
        "fido2",
        "windowsHelloForBusiness",
        "x509CertificateMultiFactor",
        "x509CertificateSingleFactor",
    }
)

PASSWORDLESS_COMBOS = frozenset(
    {
        "fido2",
        "windowsHelloForBusiness",
        "x509CertificateMultiFactor",
        "x509CertificateSingleFactor",
        "microsoftAuthenticatorPasswordless",
        "temporaryAccessPassMultiUse",
        "temporaryAccessPassOneTime",
    }
)

PHISHING_RESISTANT = "phishing_resistant"
NOT_PHISHING_RESISTANT = "not_phishing_resistant"
PHISHING_RESISTANCE_UNKNOWN = "unknown"


def phishing_resistance_from_allowed_combinations(allowed_combinations: object) -> str:
    """Categorize an authentication strength's phishing-resistance posture
    from its `allowedCombinations` list. A strength is only labeled
    "phishing_resistant" when EVERY allowed combination is itself
    phishing-resistant -- a strength that also permits a weaker fallback
    (e.g. password+SMS) cannot be said to enforce phishing resistance
    end-to-end. SMS/voice/email/TOTP-only combinations are NEVER
    classified phishing-resistant.
    """
    if not isinstance(allowed_combinations, list) or not allowed_combinations:
        return PHISHING_RESISTANCE_UNKNOWN
    if all(
        isinstance(combo, str) and combo in PHISHING_RESISTANT_COMBOS
        for combo in allowed_combinations
    ):
        return PHISHING_RESISTANT
    return NOT_PHISHING_RESISTANT


def passwordless_posture_from_allowed_combinations(allowed_combinations: object) -> str:
    """Categorize whether every allowed combination in an authentication
    strength supports passwordless sign-in. Same all-must-qualify rule as
    phishing resistance, for the same end-to-end reasoning.
    """
    if not isinstance(allowed_combinations, list) or not allowed_combinations:
        return PHISHING_RESISTANCE_UNKNOWN
    if all(
        isinstance(combo, str) and combo in PASSWORDLESS_COMBOS
        for combo in allowed_combinations
    ):
        return "passwordless"
    return "not_passwordless"


def count_allowed_combinations(allowed_combinations: object) -> int:
    """Bounded count of an authentication strength's allowed combinations --
    never the raw combinations payload itself."""
    if not isinstance(allowed_combinations, list):
        return 0
    return len(allowed_combinations)


STRENGTH_MFA_CAPABLE = "mfa_capable"
STRENGTH_MFA_UNKNOWN = "unknown"


def categorize_strength_mfa_capability(allowed_combinations: object) -> str:
    """Categorize whether an authentication strength's allowed-combinations
    list is populated (Graph's authenticationStrengthPolicies collection
    only ever lists multi-factor-eligible combinations, so a non-empty,
    well-formed list is treated as MFA-capable). Missing/malformed input
    stays unknown -- never assumed MFA-capable.
    """
    if not isinstance(allowed_combinations, list) or not allowed_combinations:
        return STRENGTH_MFA_UNKNOWN
    return STRENGTH_MFA_CAPABLE


# ---------------------------------------------------------------------------
# Authentication method (tenant-wide method-configuration) taxonomy.
# ---------------------------------------------------------------------------

METHOD_TYPE_FIDO2 = "fido2"
METHOD_TYPE_MICROSOFT_AUTHENTICATOR = "microsoft_authenticator"
METHOD_TYPE_TEMPORARY_ACCESS_PASS = "temporary_access_pass"
METHOD_TYPE_EMAIL_OTP = "email_otp"
METHOD_TYPE_SMS = "sms"
METHOD_TYPE_VOICE = "voice"
METHOD_TYPE_SOFTWARE_OATH = "software_oath"
METHOD_TYPE_HARDWARE_OATH = "hardware_oath"
METHOD_TYPE_CERTIFICATE_BASED_AUTH = "certificate_based_auth"
METHOD_TYPE_WINDOWS_HELLO_FOR_BUSINESS = "windows_hello_for_business"
METHOD_TYPE_UNKNOWN = "unknown"

# Graph's well-known, stable authentication-method configuration IDs (the
# `id` of each singleton config resource under
# `policies/authenticationMethodsPolicy/authenticationMethodConfigurations`).
# These are fixed, tenant-agnostic identifiers documented by Microsoft --
# never inferred from a display name.
_METHOD_CONFIG_ID_MAP = {
    "Fido2": METHOD_TYPE_FIDO2,
    "MicrosoftAuthenticator": METHOD_TYPE_MICROSOFT_AUTHENTICATOR,
    "TemporaryAccessPass": METHOD_TYPE_TEMPORARY_ACCESS_PASS,
    "Email": METHOD_TYPE_EMAIL_OTP,
    "Sms": METHOD_TYPE_SMS,
    "Voice": METHOD_TYPE_VOICE,
    "SoftwareOath": METHOD_TYPE_SOFTWARE_OATH,
    "HardwareOath": METHOD_TYPE_HARDWARE_OATH,
    "X509Certificate": METHOD_TYPE_CERTIFICATE_BASED_AUTH,
}


def categorize_method_type(config_id: object) -> str:
    """Categorize an authentication method configuration's type from its
    stable Graph config ID only. An ID this taxonomy doesn't recognize
    stays unknown rather than being guessed from a display string.
    """
    if not isinstance(config_id, str) or not config_id:
        return METHOD_TYPE_UNKNOWN
    return _METHOD_CONFIG_ID_MAP.get(config_id, METHOD_TYPE_UNKNOWN)


# Fixed method-type -> phishing-resistance mapping. Only FIDO2, CBA, and
# Windows Hello for Business qualify. SMS/voice/email/software-OATH/TAP
# must NEVER be classified phishing-resistant, regardless of configuration.
_PHISHING_RESISTANT_METHOD_TYPES = frozenset(
    {
        METHOD_TYPE_FIDO2,
        METHOD_TYPE_CERTIFICATE_BASED_AUTH,
        METHOD_TYPE_WINDOWS_HELLO_FOR_BUSINESS,
    }
)


def phishing_resistance_for_method_type(method_type: str) -> str:
    """Fixed phishing-resistance category for a given method-type category.
    Unlike authentication strengths (which combine multiple methods), a
    single method type is either always phishing-resistant or never --
    there is no partial-combination case here.
    """
    if method_type == METHOD_TYPE_UNKNOWN:
        return PHISHING_RESISTANCE_UNKNOWN
    if method_type in _PHISHING_RESISTANT_METHOD_TYPES:
        return PHISHING_RESISTANT
    return NOT_PHISHING_RESISTANT


# Authentication method configuration state.
METHOD_STATE_ENABLED = "enabled"
METHOD_STATE_DISABLED = "disabled"
METHOD_STATE_UNKNOWN = "unknown"


def categorize_method_state(raw_state: object) -> str:
    """Normalize an authentication method configuration's `state` field.
    Missing/malformed input stays unknown -- never coerced toward
    "disabled" (which would risk a false "method removed" diff) or
    "enabled" (which would risk overstating the tenant's MFA posture).
    """
    if raw_state == "enabled":
        return METHOD_STATE_ENABLED
    if raw_state == "disabled":
        return METHOD_STATE_DISABLED
    return METHOD_STATE_UNKNOWN


# Authentication method target scope category (mirrors CA targeting's
# include/exclude-count-only philosophy -- never large group ID arrays).
METHOD_TARGET_ALL_USERS = "all_users"
METHOD_TARGET_SELECTED_GROUPS = "selected_groups"
METHOD_TARGET_UNKNOWN = "unknown"


def categorize_method_targeting(include_targets: object) -> str:
    """Categorize an authentication method configuration's
    `includeTargets` list into a coarse scope category. Only the presence
    of the well-known "all_users" target ID is inspected -- individual
    group IDs are never surfaced beyond a count by the caller.
    """
    if not isinstance(include_targets, list) or not include_targets:
        return METHOD_TARGET_UNKNOWN
    for target in include_targets:
        if isinstance(target, dict) and target.get("id") == "all_users":
            return METHOD_TARGET_ALL_USERS
    return METHOD_TARGET_SELECTED_GROUPS


def count_method_targets(targets: object) -> int:
    """Bounded count of an authentication method configuration's
    include/exclude target entries -- never the raw target array."""
    if not isinstance(targets, list):
        return 0
    return len(targets)


# ---------------------------------------------------------------------------
# Conditional Access location targeting + session control categorizers.
# ---------------------------------------------------------------------------

CA_LOCATION_TARGET_ALL = "all"
CA_LOCATION_TARGET_ALL_TRUSTED = "all_trusted"
CA_LOCATION_TARGET_SELECTED = "selected"
CA_LOCATION_TARGET_UNKNOWN = "unknown"


def categorize_ca_location_targeting(conditions_locations: object) -> str:
    """Categorize a Conditional Access policy's `conditions.locations`
    targeting into a coarse category. Only inspects the well-known "All"/
    "AllTrusted" sentinel values -- individual named-location IDs (which
    could reveal IP ranges) are never read beyond presence.
    """
    if not isinstance(conditions_locations, dict):
        return CA_LOCATION_TARGET_UNKNOWN
    include = conditions_locations.get("includeLocations")
    if not isinstance(include, list) or not include:
        return CA_LOCATION_TARGET_UNKNOWN
    if "All" in include:
        return CA_LOCATION_TARGET_ALL
    if "AllTrusted" in include:
        return CA_LOCATION_TARGET_ALL_TRUSTED
    return CA_LOCATION_TARGET_SELECTED


_KNOWN_DEVICE_PLATFORMS = frozenset(
    {"android", "iOS", "windows", "windowsPhone", "macOS", "linux", "all"}
)
DEVICE_PLATFORM_UNKNOWN = "unknown"


def categorize_device_platforms(platforms_condition: object) -> list:
    """Normalize `conditions.platforms.includePlatforms` into a bounded,
    sorted, deduplicated list of known platform categories. An entry this
    taxonomy doesn't recognize falls back to "unknown" rather than being
    silently dropped."""
    if not isinstance(platforms_condition, dict):
        return [DEVICE_PLATFORM_UNKNOWN]
    include = platforms_condition.get("includePlatforms")
    if not isinstance(include, list) or not include:
        return [DEVICE_PLATFORM_UNKNOWN]
    categories = set()
    for entry in include:
        if isinstance(entry, str) and entry in _KNOWN_DEVICE_PLATFORMS:
            categories.add(entry)
        else:
            categories.add(DEVICE_PLATFORM_UNKNOWN)
    return sorted(categories)


PERSISTENT_BROWSER_ALWAYS = "always"
PERSISTENT_BROWSER_NEVER = "never"
PERSISTENT_BROWSER_UNKNOWN = "unknown"


def categorize_persistent_browser_mode(session_controls: object) -> str:
    """Categorize `sessionControls.persistentBrowser` mode. Missing/
    disabled/malformed all stay unknown -- never assumed "never" (which
    would understate a persistent-browser-enabled policy's exposure)."""
    if not isinstance(session_controls, dict):
        return PERSISTENT_BROWSER_UNKNOWN
    persistent_browser = session_controls.get("persistentBrowser")
    if not isinstance(persistent_browser, dict) or persistent_browser.get("isEnabled") is not True:
        return PERSISTENT_BROWSER_UNKNOWN
    mode = persistent_browser.get("mode")
    if mode == "always":
        return PERSISTENT_BROWSER_ALWAYS
    if mode == "never":
        return PERSISTENT_BROWSER_NEVER
    return PERSISTENT_BROWSER_UNKNOWN


CAE_STRICT = "strict_enforcement"
CAE_DISABLED = "disabled"
CAE_UNKNOWN = "unknown"


def categorize_cae_mode(session_controls: object) -> str:
    """Categorize `sessionControls.continuousAccessEvaluation` mode."""
    if not isinstance(session_controls, dict):
        return CAE_UNKNOWN
    cae = session_controls.get("continuousAccessEvaluation")
    if not isinstance(cae, dict):
        return CAE_UNKNOWN
    mode = cae.get("mode")
    if mode == "strictEnforcement":
        return CAE_STRICT
    if mode == "disabled":
        return CAE_DISABLED
    return CAE_UNKNOWN


def app_enforced_restrictions_enabled(session_controls: object) -> Optional[bool]:
    """Whether `sessionControls.applicationEnforcedRestrictions` is
    enabled. Returns None (unknown) rather than False when the block is
    missing/malformed."""
    if not isinstance(session_controls, dict):
        return None
    restriction = session_controls.get("applicationEnforcedRestrictions")
    if not isinstance(restriction, dict):
        return None
    is_enabled = restriction.get("isEnabled")
    return is_enabled if isinstance(is_enabled, bool) else None
