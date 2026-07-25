"""Okta provider foundation schema (Okta message 1 of 8).

Defines the record-type constants and safe category vocabularies for the
Okta provider foundation. Only two record types exist at this stage:

  okta_organization    — one record per connected Okta org/tenant.
  okta_api_capability  — one record per probed future-family API surface
                          (users, groups, applications, policies,
                          authenticators, admin roles, System Log),
                          describing whether that surface is safely
                          readable — never the surface's actual data.

Later messages (2-5) will add record types for users, groups, applications,
policies, MFA/authenticators, and admin roles. This module intentionally
defines ONLY the message-1 foundation taxonomy.

SENSITIVE-DATA BOUNDARY (permanent, re-affirmed every later message)
----------------------------------------------------------------------
Never collected or stored by this connector, at any stage:
  passwords, password hashes, recovery answers, MFA secrets, OTP seeds,
  API tokens, session tokens, refresh tokens, access tokens, private keys,
  raw authentication factors, raw System Log payloads, arbitrary user
  profile data.
"""

from __future__ import annotations

# ── Record types ────────────────────────────────────────────────────────────

OKTA_ORGANIZATION = "okta_organization"
OKTA_API_CAPABILITY = "okta_api_capability"

OKTA_RECORD_TYPES = frozenset({OKTA_ORGANIZATION, OKTA_API_CAPABILITY})

# ── Org status categories ───────────────────────────────────────────────────
#
# Okta's Org Setting API returns a small, fixed status vocabulary. Any value
# outside this set is stored as "unknown" rather than guessed at or passed
# through raw, so a future undocumented status string can never leak
# unexpected data into a record.

ORG_STATUS_ACTIVE = "active"
ORG_STATUS_INACTIVE = "inactive"
ORG_STATUS_SUSPENDED = "suspended"
ORG_STATUS_UNKNOWN = "unknown"

_ORG_STATUS_MAP = {
    "active": ORG_STATUS_ACTIVE,
    "inactive": ORG_STATUS_INACTIVE,
    "suspended": ORG_STATUS_SUSPENDED,
}


def categorize_org_status(raw_status: object) -> str:
    """Map a raw Okta org status string to a fixed, safe category."""
    if isinstance(raw_status, str):
        return _ORG_STATUS_MAP.get(raw_status.strip().lower(), ORG_STATUS_UNKNOWN)
    return ORG_STATUS_UNKNOWN


# ── Capability probe families (future record collection surfaces) ─────────
#
# These are the record families message 2-5 will implement. Message 1 only
# probes whether each is readable — it never collects the underlying data.

CAPABILITY_FAMILY_USERS = "users"
CAPABILITY_FAMILY_GROUPS = "groups"
CAPABILITY_FAMILY_APPLICATIONS = "applications"
CAPABILITY_FAMILY_POLICIES = "policies"
CAPABILITY_FAMILY_AUTHENTICATORS = "authenticators"
CAPABILITY_FAMILY_ADMIN_ROLES = "admin_roles"
CAPABILITY_FAMILY_SYSTEM_LOG = "system_log"

CAPABILITY_FAMILIES = (
    CAPABILITY_FAMILY_USERS,
    CAPABILITY_FAMILY_GROUPS,
    CAPABILITY_FAMILY_APPLICATIONS,
    CAPABILITY_FAMILY_POLICIES,
    CAPABILITY_FAMILY_AUTHENTICATORS,
    CAPABILITY_FAMILY_ADMIN_ROLES,
    CAPABILITY_FAMILY_SYSTEM_LOG,
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
