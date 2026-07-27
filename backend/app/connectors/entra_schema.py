"""Microsoft Entra ID provider schema (Entra messages 1-2 of 8).

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

This module now defines the message-1/2 taxonomy. Messages 3-5
(applications/service principals/app registrations, Conditional Access/
authentication methods, directory roles/privileged identities/consent) and
message 6 (Security Findings) are still pending.

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
"""

from __future__ import annotations

import re as _re

# ── Record types ────────────────────────────────────────────────────────────

ENTRA_ORGANIZATION = "entra_organization"
ENTRA_API_CAPABILITY = "entra_api_capability"
ENTRA_USER = "entra_user"
ENTRA_GROUP = "entra_group"
ENTRA_GROUP_MEMBERSHIP = "entra_group_membership"

ENTRA_RECORD_TYPES = frozenset({
    ENTRA_ORGANIZATION,
    ENTRA_API_CAPABILITY,
    ENTRA_USER,
    ENTRA_GROUP,
    ENTRA_GROUP_MEMBERSHIP,
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
