"""Microsoft Entra ID provider schema (Entra message 1 of 8).

Defines the record-type constants and safe category vocabularies for the
Microsoft Entra ID provider. Record types so far:

  entra_organization   — one record per connected Entra tenant (msg 1).
  entra_api_capability — one record per probed future-family Graph API
                          surface (msg 1) — describes whether a surface is
                          safely readable, never the surface's actual data.

This module now defines the message-1 taxonomy only. Messages 2-5 (users/
groups, applications/service principals, Conditional Access/authentication
methods, directory roles/privileged identities/consent) and message 6
(Security Findings) are still pending.

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
"""

from __future__ import annotations

import re as _re

# ── Record types ────────────────────────────────────────────────────────────

ENTRA_ORGANIZATION = "entra_organization"
ENTRA_API_CAPABILITY = "entra_api_capability"

ENTRA_RECORD_TYPES = frozenset({
    ENTRA_ORGANIZATION,
    ENTRA_API_CAPABILITY,
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
