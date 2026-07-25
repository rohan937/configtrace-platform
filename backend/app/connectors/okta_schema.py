"""Okta provider schema (Okta messages 1-2 of 8).

Defines the record-type constants and safe category vocabularies for the
Okta provider. Record types so far:

  okta_organization      — one record per connected Okta org/tenant (msg 1).
  okta_api_capability    — one record per probed future-family API surface
                            (msg 1) — describes whether a surface is safely
                            readable, never the surface's actual data.
  okta_user               — one record per Okta user (msg 2) — identity and
                            lifecycle posture only, never credentials or
                            arbitrary profile data.
  okta_group              — one record per Okta group (msg 2).
  okta_group_membership   — one record per user<->group membership edge
                            (msg 2).

Later messages (3-5) will add record types for applications, policies,
MFA/authenticators, and admin roles. This module intentionally defines
ONLY the message 1-2 taxonomy.

SENSITIVE-DATA BOUNDARY (permanent, re-affirmed every later message)
----------------------------------------------------------------------
Never collected or stored by this connector, at any stage:
  passwords, password hashes, recovery answers, MFA secrets, OTP seeds,
  API tokens, session tokens, refresh tokens, access tokens, private keys,
  raw authentication factors, raw System Log payloads, arbitrary user
  profile data (phone numbers, addresses, department, title, manager,
  custom profile attributes).
"""

from __future__ import annotations

# ── Record types ────────────────────────────────────────────────────────────

OKTA_ORGANIZATION = "okta_organization"
OKTA_API_CAPABILITY = "okta_api_capability"
OKTA_USER = "okta_user"
OKTA_GROUP = "okta_group"
OKTA_GROUP_MEMBERSHIP = "okta_group_membership"

OKTA_RECORD_TYPES = frozenset({
    OKTA_ORGANIZATION,
    OKTA_API_CAPABILITY,
    OKTA_USER,
    OKTA_GROUP,
    OKTA_GROUP_MEMBERSHIP,
})

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


# ── Family collection completeness (Okta message 2) ─────────────────────────
#
# Distinct from CAPABILITY_STATUSES (a message-1 single-probe outcome) —
# this describes what actually happened when message-2 tried to COLLECT a
# whole family (users/groups/memberships), which can partially succeed
# across a paginated, potentially-per-group series of calls.

FAMILY_COMPLETE = "complete"
FAMILY_PARTIAL = "partial"
FAMILY_DENIED = "denied"
FAMILY_UNAVAILABLE = "unavailable"

FAMILY_COMPLETENESS_STATUSES = frozenset({
    FAMILY_COMPLETE, FAMILY_PARTIAL, FAMILY_DENIED, FAMILY_UNAVAILABLE,
})


# ── User lifecycle status taxonomy (Okta message 2) ─────────────────────────
#
# Okta's fixed, documented user lifecycle status vocabulary. Any value
# outside this set — missing, malformed, or an unexpected future Okta
# status — is treated as UNKNOWN and every derived boolean stays False.
# Unknown is never coerced to "safe"/active, and is never treated as
# equivalent to any specific known-bad state either (see
# `categorize_user_status()` module docstring below).

USER_STATUS_STAGED = "STAGED"
USER_STATUS_PROVISIONED = "PROVISIONED"
USER_STATUS_ACTIVE = "ACTIVE"
USER_STATUS_RECOVERY = "RECOVERY"
USER_STATUS_LOCKED_OUT = "LOCKED_OUT"
USER_STATUS_PASSWORD_EXPIRED = "PASSWORD_EXPIRED"
USER_STATUS_SUSPENDED = "SUSPENDED"
USER_STATUS_DEPROVISIONED = "DEPROVISIONED"
USER_STATUS_UNKNOWN = "UNKNOWN"

USER_STATUSES = frozenset({
    USER_STATUS_STAGED, USER_STATUS_PROVISIONED, USER_STATUS_ACTIVE,
    USER_STATUS_RECOVERY, USER_STATUS_LOCKED_OUT, USER_STATUS_PASSWORD_EXPIRED,
    USER_STATUS_SUSPENDED, USER_STATUS_DEPROVISIONED,
})

# Deterministic lifecycle-posture collapse. Every KNOWN status maps to
# exactly one posture; STAGED and PROVISIONED both collapse to
# "pre_active" (both describe a user who has not yet completed
# activation) — every other status is 1:1. SUSPENDED and DEPROVISIONED are
# deliberately kept as DISTINCT postures (never conflated) — they have
# different operational meaning (temporarily restricted vs. permanently
# removed from the directory).

LIFECYCLE_ACTIVE = "active"
LIFECYCLE_PRE_ACTIVE = "pre_active"
LIFECYCLE_RECOVERY = "recovery"
LIFECYCLE_LOCKED = "locked"
LIFECYCLE_PASSWORD_EXPIRED = "password_expired"
LIFECYCLE_SUSPENDED = "suspended"
LIFECYCLE_DEPROVISIONED = "deprovisioned"
LIFECYCLE_UNKNOWN = "unknown"

LIFECYCLE_POSTURES = frozenset({
    LIFECYCLE_ACTIVE, LIFECYCLE_PRE_ACTIVE, LIFECYCLE_RECOVERY,
    LIFECYCLE_LOCKED, LIFECYCLE_PASSWORD_EXPIRED, LIFECYCLE_SUSPENDED,
    LIFECYCLE_DEPROVISIONED, LIFECYCLE_UNKNOWN,
})

_USER_STATUS_TO_POSTURE = {
    USER_STATUS_ACTIVE: LIFECYCLE_ACTIVE,
    USER_STATUS_STAGED: LIFECYCLE_PRE_ACTIVE,
    USER_STATUS_PROVISIONED: LIFECYCLE_PRE_ACTIVE,
    USER_STATUS_RECOVERY: LIFECYCLE_RECOVERY,
    USER_STATUS_LOCKED_OUT: LIFECYCLE_LOCKED,
    USER_STATUS_PASSWORD_EXPIRED: LIFECYCLE_PASSWORD_EXPIRED,
    USER_STATUS_SUSPENDED: LIFECYCLE_SUSPENDED,
    USER_STATUS_DEPROVISIONED: LIFECYCLE_DEPROVISIONED,
}


def categorize_user_status(raw_status: object) -> str:
    """Map a raw Okta user status string to the fixed USER_STATUS_* set.

    Returns ``USER_STATUS_UNKNOWN`` for anything not in the known set
    (``None``, non-string, empty, lowercase-mismatched, or a genuinely
    unrecognized future Okta status) — never guesses, never falls back to
    a "safe" default.
    """
    if isinstance(raw_status, str):
        candidate = raw_status.strip().upper()
        if candidate in USER_STATUSES:
            return candidate
    return USER_STATUS_UNKNOWN


def lifecycle_posture_for_status(status: str) -> str:
    """Map a USER_STATUS_* value to its collapsed lifecycle posture.

    ``USER_STATUS_UNKNOWN`` (and anything else not in the known map) maps
    to ``LIFECYCLE_UNKNOWN`` — never silently treated as active/safe.
    """
    return _USER_STATUS_TO_POSTURE.get(status, LIFECYCLE_UNKNOWN)


# ── Group type taxonomy (Okta message 2) ────────────────────────────────────

GROUP_TYPE_OKTA_GROUP = "OKTA_GROUP"
GROUP_TYPE_APP_GROUP = "APP_GROUP"
GROUP_TYPE_BUILT_IN = "BUILT_IN"
GROUP_TYPE_UNKNOWN = "unknown"

GROUP_TYPES = frozenset({GROUP_TYPE_OKTA_GROUP, GROUP_TYPE_APP_GROUP, GROUP_TYPE_BUILT_IN})

# The one deterministically-recognizable built-in group name. Being named
# "Everyone" alone is NOT sufficient — the group's own `type` must also be
# BUILT_IN (an ordinary OKTA_GROUP happens to be named "Everyone" is a
# real possibility and must NOT be misclassified as the system group).
EVERYONE_GROUP_NAME = "Everyone"


def categorize_group_type(raw_type: object) -> str:
    """Map a raw Okta group `type` string to the fixed GROUP_TYPE_* set.

    Returns ``GROUP_TYPE_UNKNOWN`` for anything not in the known set —
    never guessed to be an ordinary OKTA_GROUP.
    """
    if isinstance(raw_type, str):
        candidate = raw_type.strip().upper()
        if candidate in GROUP_TYPES:
            return candidate
    return GROUP_TYPE_UNKNOWN


def is_everyone_group(group_type: str, group_name: object) -> bool:
    """Return True only when BOTH the type is BUILT_IN AND the name is
    exactly "Everyone" — requires both signals so an ordinary OKTA_GROUP
    that happens to be named "Everyone" is never misclassified."""
    return group_type == GROUP_TYPE_BUILT_IN and group_name == EVERYONE_GROUP_NAME


# ── Membership count buckets (Okta message 2) ───────────────────────────────

MEMBERSHIP_COUNT_ZERO = "0"
MEMBERSHIP_COUNT_SMALL = "1-5"
MEMBERSHIP_COUNT_MEDIUM = "6-20"
MEMBERSHIP_COUNT_LARGE = "21-100"
MEMBERSHIP_COUNT_VERY_LARGE = "100+"
MEMBERSHIP_COUNT_UNKNOWN = "unknown"


def categorize_membership_count(count: object) -> str:
    """Bucket a non-negative integer membership count. ``None``/non-int
    input (e.g. membership collection was denied/partial, so the count is
    genuinely unknown) returns MEMBERSHIP_COUNT_UNKNOWN — never 0."""
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


# ── Last-login recency category (Okta message 2) ────────────────────────────

LAST_LOGIN_NEVER = "never"
LAST_LOGIN_RECENT = "recent"
LAST_LOGIN_STALE = "stale"
LAST_LOGIN_UNKNOWN = "unknown"

LAST_LOGIN_RECENT_THRESHOLD_DAYS = 30


def categorize_last_login(raw_last_login: object, *, now: "object" = None) -> str:
    """Bucket Okta's ``lastLogin`` ISO-8601 timestamp into a recency
    category. ``None``/absent means the user has never logged in
    (``LAST_LOGIN_NEVER``, distinct from unknown). An unparseable value
    returns ``LAST_LOGIN_UNKNOWN`` — never guessed to be recent or stale.

    This category is intentionally NOT diff-tracked (see
    ``diff_service._OKTA_TRACKED_FIELDS_BY_TYPE``) — its bucket would
    otherwise shift on every sync purely from elapsed time, producing
    routine, non-actionable Change noise.
    """
    from datetime import datetime, timezone

    if raw_last_login is None:
        return LAST_LOGIN_NEVER
    if not isinstance(raw_last_login, str) or not raw_last_login.strip():
        return LAST_LOGIN_UNKNOWN
    try:
        parsed = datetime.fromisoformat(raw_last_login.strip().replace("Z", "+00:00"))
    except ValueError:
        return LAST_LOGIN_UNKNOWN
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    reference = now if now is not None else datetime.now(timezone.utc)
    age_days = (reference - parsed).total_seconds() / 86400.0
    if age_days < 0:
        # Clock skew / future timestamp — treat as recent rather than
        # guessing at staleness from a value we can't trust directionally.
        return LAST_LOGIN_RECENT
    if age_days <= LAST_LOGIN_RECENT_THRESHOLD_DAYS:
        return LAST_LOGIN_RECENT
    return LAST_LOGIN_STALE
