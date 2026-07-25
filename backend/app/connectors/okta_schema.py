"""Okta provider schema (Okta messages 1-3 of 8).

Defines the record-type constants and safe category vocabularies for the
Okta provider. Record types so far:

  okta_organization              — one record per connected Okta org/tenant
                                    (msg 1).
  okta_api_capability            — one record per probed future-family API
                                    surface (msg 1) — describes whether a
                                    surface is safely readable, never the
                                    surface's actual data.
  okta_user                      — one record per Okta user (msg 2) —
                                    identity and lifecycle posture only,
                                    never credentials or arbitrary profile
                                    data.
  okta_group                     — one record per Okta group (msg 2).
  okta_group_membership          — one record per user<->group membership
                                    edge (msg 2).
  okta_application                — one record per Okta application (msg 3)
                                    — status, sign-on mode/protocol
                                    posture, and safe SAML/OIDC
                                    configuration posture only, never
                                    client secrets or signing material.
  okta_application_user_assignment  — one record per user<->app assignment
                                    edge (msg 3).
  okta_application_group_assignment — one record per group<->app assignment
                                    edge (msg 3).

Later messages (4-5) will add record types for policies/MFA/authenticators
and admin roles. This module intentionally defines ONLY the message 1-3
taxonomy.

SENSITIVE-DATA BOUNDARY (permanent, re-affirmed every later message)
----------------------------------------------------------------------
Never collected or stored by this connector, at any stage:
  passwords, password hashes, recovery answers, MFA secrets, OTP seeds,
  API tokens, session tokens, refresh tokens, access tokens, private keys,
  raw authentication factors, raw System Log payloads, arbitrary user
  profile data (phone numbers, addresses, department, title, manager,
  custom profile attributes), application client secrets, signing
  certificates/private keys, raw SAML metadata XML, app-user credentials
  or custom profile mappings.
"""

from __future__ import annotations

# ── Record types ────────────────────────────────────────────────────────────

OKTA_ORGANIZATION = "okta_organization"
OKTA_API_CAPABILITY = "okta_api_capability"
OKTA_USER = "okta_user"
OKTA_GROUP = "okta_group"
OKTA_GROUP_MEMBERSHIP = "okta_group_membership"
OKTA_APPLICATION = "okta_application"
OKTA_APPLICATION_USER_ASSIGNMENT = "okta_application_user_assignment"
OKTA_APPLICATION_GROUP_ASSIGNMENT = "okta_application_group_assignment"

OKTA_RECORD_TYPES = frozenset({
    OKTA_ORGANIZATION,
    OKTA_API_CAPABILITY,
    OKTA_USER,
    OKTA_GROUP,
    OKTA_GROUP_MEMBERSHIP,
    OKTA_APPLICATION,
    OKTA_APPLICATION_USER_ASSIGNMENT,
    OKTA_APPLICATION_GROUP_ASSIGNMENT,
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


# ── Application status taxonomy (Okta message 3) ────────────────────────────
#
# Okta applications have a small, fixed status vocabulary — unlike users,
# there is no rich lifecycle (no STAGED/SUSPENDED/etc.), just an explicit
# tri-state: ACTIVE / INACTIVE / unknown. Unknown must never be coerced to
# INACTIVE ("safe"/disabled) or to ACTIVE — it is its own distinct state.

APP_STATUS_ACTIVE = "ACTIVE"
APP_STATUS_INACTIVE = "INACTIVE"
APP_STATUS_UNKNOWN = "UNKNOWN"

APP_STATUSES = frozenset({APP_STATUS_ACTIVE, APP_STATUS_INACTIVE})


def categorize_app_status(raw_status: object) -> str:
    """Map a raw Okta application status string to the fixed
    APP_STATUS_* set. Returns APP_STATUS_UNKNOWN for anything else —
    never guessed, never coerced to ACTIVE or INACTIVE."""
    if isinstance(raw_status, str):
        candidate = raw_status.strip().upper()
        if candidate in APP_STATUSES:
            return candidate
    return APP_STATUS_UNKNOWN


# ── Sign-on mode / protocol taxonomy (Okta message 3) ───────────────────────
#
# Fixed, documented Okta signOnMode vocabulary. Anything else (a genuinely
# new/future signOnMode) is stored as SIGN_ON_MODE_UNKNOWN — never guessed.

SIGN_ON_MODE_SAML_2_0 = "SAML_2_0"
SIGN_ON_MODE_OPENID_CONNECT = "OPENID_CONNECT"
SIGN_ON_MODE_OAUTH_2_0 = "OAUTH_2_0"
SIGN_ON_MODE_SWA = "SWA"
SIGN_ON_MODE_AUTO_LOGIN = "AUTO_LOGIN"
SIGN_ON_MODE_BASIC_AUTH = "BASIC_AUTH"
SIGN_ON_MODE_WS_FEDERATION = "WS_FEDERATION"
SIGN_ON_MODE_BOOKMARK = "BOOKMARK"
SIGN_ON_MODE_UNKNOWN = "unknown"

SIGN_ON_MODES = frozenset({
    SIGN_ON_MODE_SAML_2_0, SIGN_ON_MODE_OPENID_CONNECT, SIGN_ON_MODE_OAUTH_2_0,
    SIGN_ON_MODE_SWA, SIGN_ON_MODE_AUTO_LOGIN, SIGN_ON_MODE_BASIC_AUTH,
    SIGN_ON_MODE_WS_FEDERATION, SIGN_ON_MODE_BOOKMARK,
})

# High-level protocol category, derived from sign_on_mode — lets a
# classifier/UI group SAML vs OIDC/OAuth vs "other" without re-deriving the
# mapping in multiple places.
PROTOCOL_CATEGORY_SAML = "SAML"
PROTOCOL_CATEGORY_OIDC_OAUTH = "OIDC_OAUTH"
PROTOCOL_CATEGORY_WS_FEDERATION = "WS_FEDERATION"
PROTOCOL_CATEGORY_OTHER = "OTHER"
PROTOCOL_CATEGORY_UNKNOWN = "unknown"

_SIGN_ON_MODE_TO_PROTOCOL = {
    SIGN_ON_MODE_SAML_2_0: PROTOCOL_CATEGORY_SAML,
    SIGN_ON_MODE_OPENID_CONNECT: PROTOCOL_CATEGORY_OIDC_OAUTH,
    SIGN_ON_MODE_OAUTH_2_0: PROTOCOL_CATEGORY_OIDC_OAUTH,
    SIGN_ON_MODE_WS_FEDERATION: PROTOCOL_CATEGORY_WS_FEDERATION,
    SIGN_ON_MODE_SWA: PROTOCOL_CATEGORY_OTHER,
    SIGN_ON_MODE_AUTO_LOGIN: PROTOCOL_CATEGORY_OTHER,
    SIGN_ON_MODE_BASIC_AUTH: PROTOCOL_CATEGORY_OTHER,
    SIGN_ON_MODE_BOOKMARK: PROTOCOL_CATEGORY_OTHER,
}


def categorize_sign_on_mode(raw_mode: object) -> str:
    """Map a raw Okta ``signOnMode`` string to the fixed SIGN_ON_MODE_*
    set. Returns SIGN_ON_MODE_UNKNOWN for anything not in the known set —
    never guessed."""
    if isinstance(raw_mode, str):
        candidate = raw_mode.strip().upper()
        if candidate in SIGN_ON_MODES:
            return candidate
    return SIGN_ON_MODE_UNKNOWN


def protocol_category_for_sign_on_mode(sign_on_mode: str) -> str:
    """Map a SIGN_ON_MODE_* value to its high-level protocol category.
    SIGN_ON_MODE_UNKNOWN (and anything else unrecognized) maps to
    PROTOCOL_CATEGORY_UNKNOWN — never silently treated as OTHER."""
    return _SIGN_ON_MODE_TO_PROTOCOL.get(sign_on_mode, PROTOCOL_CATEGORY_UNKNOWN)


# ── OIDC/OAuth redirect URI categorization (Okta message 3) ─────────────────
#
# Only counts/booleans are ever derived from a redirect URI — the raw URL
# (which may embed org-identifying paths) is NEVER stored. Query strings
# and fragments are never persisted since only the scheme/host are
# inspected before the URI is discarded.

_LOOPBACK_HOSTNAMES = frozenset({"127.0.0.1", "::1", "0.0.0.0"})


def _redirect_uri_scheme_and_host(uri: object) -> tuple[str, str]:
    """Return (scheme, hostname) for a redirect URI string, best-effort.
    Returns ("", "") for anything unparseable — never raises."""
    from urllib.parse import urlparse

    if not isinstance(uri, str) or not uri.strip():
        return "", ""
    try:
        parsed = urlparse(uri.strip())
    except ValueError:
        return "", ""
    return (parsed.scheme or "").lower(), (parsed.hostname or "").lower()


def categorize_redirect_uris(uris: object) -> dict:
    """Derive safe structural counts/booleans from a list of OIDC redirect
    URIs. The URIs themselves are NEVER stored or returned — only this
    summary dict.

    Returns a dict with: redirect_count, https_redirect_count,
    http_redirect_count, localhost_redirect_count, loopback_redirect_count,
    custom_scheme_redirect_count, wildcard_redirect_present (bool).
    """
    if not isinstance(uris, list):
        return {
            "redirect_count": None,
            "https_redirect_count": None,
            "http_redirect_count": None,
            "localhost_redirect_count": None,
            "loopback_redirect_count": None,
            "custom_scheme_redirect_count": None,
            "wildcard_redirect_present": None,
        }

    https_count = 0
    http_count = 0
    localhost_count = 0
    loopback_count = 0
    custom_scheme_count = 0
    wildcard_present = False

    for uri in uris:
        if not isinstance(uri, str):
            continue
        if "*" in uri:
            wildcard_present = True
        scheme, host = _redirect_uri_scheme_and_host(uri)

        # Scheme tallies are mutually exclusive.
        if scheme == "https":
            https_count += 1
        elif scheme == "http":
            http_count += 1
        elif scheme and scheme not in ("http", "https"):
            custom_scheme_count += 1

        # Host tallies are independent of scheme — a redirect to
        # "https://localhost" is still a localhost redirect.
        if host == "localhost":
            localhost_count += 1
        elif host in _LOOPBACK_HOSTNAMES:
            loopback_count += 1

    return {
        "redirect_count": len([u for u in uris if isinstance(u, str)]),
        "https_redirect_count": https_count,
        "http_redirect_count": http_count,
        "localhost_redirect_count": localhost_count,
        "loopback_redirect_count": loopback_count,
        "custom_scheme_redirect_count": custom_scheme_count,
        "wildcard_redirect_present": wildcard_present,
    }


# ── App-type / token-auth-method categories (Okta message 3) ────────────────

APP_TYPE_WEB = "web"
APP_TYPE_NATIVE = "native"
APP_TYPE_BROWSER = "browser"
APP_TYPE_SERVICE = "service"
APP_TYPE_UNKNOWN = "unknown"

APP_TYPES = frozenset({APP_TYPE_WEB, APP_TYPE_NATIVE, APP_TYPE_BROWSER, APP_TYPE_SERVICE})


def categorize_app_type(raw_app_type: object) -> str:
    if isinstance(raw_app_type, str):
        candidate = raw_app_type.strip().lower()
        if candidate in APP_TYPES:
            return candidate
    return APP_TYPE_UNKNOWN


TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC = "client_secret_basic"
TOKEN_AUTH_METHOD_CLIENT_SECRET_POST = "client_secret_post"
TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT = "client_secret_jwt"
TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT = "private_key_jwt"
TOKEN_AUTH_METHOD_NONE = "none"
TOKEN_AUTH_METHOD_UNKNOWN = "unknown"

TOKEN_AUTH_METHODS = frozenset({
    TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC, TOKEN_AUTH_METHOD_CLIENT_SECRET_POST,
    TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT, TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT,
    TOKEN_AUTH_METHOD_NONE,
})


def categorize_token_auth_method(raw_method: object) -> str:
    if isinstance(raw_method, str):
        candidate = raw_method.strip().lower()
        if candidate in TOKEN_AUTH_METHODS:
            return candidate
    return TOKEN_AUTH_METHOD_UNKNOWN


# ── SAML posture categories (Okta message 3) ────────────────────────────────

SIGNATURE_ALGORITHM_UNKNOWN = "unknown"
DIGEST_ALGORITHM_UNKNOWN = "unknown"


def categorize_algorithm(raw_algorithm: object) -> str:
    """Truncate/normalize a SAML signature or digest algorithm string.
    Never guessed — returns the raw (short, categorical) value as-is when
    it's a non-empty string, else "unknown"."""
    if isinstance(raw_algorithm, str) and raw_algorithm.strip():
        return raw_algorithm.strip()[:40]
    return SIGNATURE_ALGORITHM_UNKNOWN


# ── Assignment scope/category (Okta message 3) ──────────────────────────────
#
# Okta AppUser.scope distinguishes a direct user assignment from one that
# arrived via a group assignment.

ASSIGNMENT_SCOPE_USER = "USER"
ASSIGNMENT_SCOPE_GROUP = "GROUP"
ASSIGNMENT_SCOPE_UNKNOWN = "unknown"

ASSIGNMENT_SCOPES = frozenset({ASSIGNMENT_SCOPE_USER, ASSIGNMENT_SCOPE_GROUP})


def categorize_assignment_scope(raw_scope: object) -> str:
    if isinstance(raw_scope, str):
        candidate = raw_scope.strip().upper()
        if candidate in ASSIGNMENT_SCOPES:
            return candidate
    return ASSIGNMENT_SCOPE_UNKNOWN
