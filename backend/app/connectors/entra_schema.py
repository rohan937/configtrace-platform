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

This module now defines the message-1/2/3 taxonomy. Messages 4-5
(Conditional Access/authentication methods, directory roles/privileged
identities/consent expansion) and message 6 (Security Findings) are still
pending.

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
