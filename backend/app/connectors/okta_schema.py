"""Okta provider schema (Okta messages 1-5 of 8).

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
  okta_policy                     — one record per Okta policy (msg 4) —
                                    type/status/priority/targeting posture
                                    only, never raw conditions/actions.
  okta_policy_rule                 — one record per policy rule (msg 4) —
                                    sign-on/MFA/password/assurance posture
                                    derived from safe, explicit fields only.
  okta_authenticator                — one record per Okta authenticator/
                                    factor type (msg 4) — availability and
                                    deterministic phishing-resistance
                                    posture only, never enrollment or
                                    secret material.
  okta_admin_role                  — one record per distinct administrator
                                    role "definition" observed in the
                                    tenant (msg 5): built-in role TYPEs
                                    (discovered from assignments — Okta
                                    has no endpoint that lists the fixed
                                    built-in role catalog, only assignment
                                    endpoints that carry a ``type``) plus
                                    real custom roles from
                                    ``GET /api/v1/iam/roles``. Privilege
                                    tier, permission-derived for custom
                                    roles, never raw permission payloads.
  okta_user_admin_role_assignment   — one record per user<->admin-role
                                    direct assignment edge (msg 5), from
                                    ``GET /api/v1/users/{userId}/roles``.
  okta_group_admin_role_assignment  — one record per group<->admin-role
                                    direct assignment edge (msg 5), from
                                    ``GET /api/v1/groups/{groupId}/roles``.
                                    For CUSTOM-role assignments, carries
                                    the resource-set scope of THAT
                                    assignment — in Okta's model a
                                    resource set scopes an *assignment*
                                    (role + resource-set + principal), not
                                    the role definition itself, since one
                                    custom role can be assigned with
                                    different resource sets to different
                                    principals.
  okta_privileged_identity          — one derived record per user who has
                                    >=1 effective admin role, direct or
                                    via group (msg 5). Never created for
                                    ordinary users.
  okta_privileged_group             — one derived record per group that
                                    itself carries >=1 direct admin-role
                                    assignment (msg 5). Never created for
                                    ordinary groups.

This module now defines the message 1-5 taxonomy. Message 6 (Security
Findings), message 7 (Change/reliability certification), and message 8
(Live launch) are still pending.

SENSITIVE-DATA BOUNDARY (permanent, re-affirmed every later message)
----------------------------------------------------------------------
Never collected or stored by this connector, at any stage:
  passwords, password hashes, recovery answers, MFA secrets, OTP seeds,
  API tokens, session tokens, refresh tokens, access tokens, private keys,
  raw authentication factors, raw System Log payloads, arbitrary user
  profile data (phone numbers, addresses, department, title, manager,
  custom profile attributes), application client secrets, signing
  certificates/private keys, raw SAML metadata XML, app-user credentials
  or custom profile mappings, factor/challenge secrets, recovery codes,
  device secrets, raw policy condition/action maps, raw admin-role
  permission response bodies, arbitrary resource-set resource paths/URLs.
"""

from __future__ import annotations

import re as _re

# ── Record types ────────────────────────────────────────────────────────────

OKTA_ORGANIZATION = "okta_organization"
OKTA_API_CAPABILITY = "okta_api_capability"
OKTA_USER = "okta_user"
OKTA_GROUP = "okta_group"
OKTA_GROUP_MEMBERSHIP = "okta_group_membership"
OKTA_APPLICATION = "okta_application"
OKTA_APPLICATION_USER_ASSIGNMENT = "okta_application_user_assignment"
OKTA_APPLICATION_GROUP_ASSIGNMENT = "okta_application_group_assignment"
OKTA_POLICY = "okta_policy"
OKTA_POLICY_RULE = "okta_policy_rule"
OKTA_AUTHENTICATOR = "okta_authenticator"
OKTA_ADMIN_ROLE = "okta_admin_role"
OKTA_USER_ADMIN_ROLE_ASSIGNMENT = "okta_user_admin_role_assignment"
OKTA_GROUP_ADMIN_ROLE_ASSIGNMENT = "okta_group_admin_role_assignment"
OKTA_PRIVILEGED_IDENTITY = "okta_privileged_identity"
OKTA_PRIVILEGED_GROUP = "okta_privileged_group"

OKTA_RECORD_TYPES = frozenset({
    OKTA_ORGANIZATION,
    OKTA_API_CAPABILITY,
    OKTA_USER,
    OKTA_GROUP,
    OKTA_GROUP_MEMBERSHIP,
    OKTA_APPLICATION,
    OKTA_APPLICATION_USER_ASSIGNMENT,
    OKTA_APPLICATION_GROUP_ASSIGNMENT,
    OKTA_POLICY,
    OKTA_POLICY_RULE,
    OKTA_AUTHENTICATOR,
    OKTA_ADMIN_ROLE,
    OKTA_USER_ADMIN_ROLE_ASSIGNMENT,
    OKTA_GROUP_ADMIN_ROLE_ASSIGNMENT,
    OKTA_PRIVILEGED_IDENTITY,
    OKTA_PRIVILEGED_GROUP,
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


# ── Policy type taxonomy (Okta message 4) ───────────────────────────────────

POLICY_TYPE_OKTA_SIGN_ON = "OKTA_SIGN_ON"
POLICY_TYPE_PASSWORD = "PASSWORD"
POLICY_TYPE_MFA_ENROLL = "MFA_ENROLL"
POLICY_TYPE_ACCESS_POLICY = "ACCESS_POLICY"
POLICY_TYPE_PROFILE_ENROLLMENT = "PROFILE_ENROLLMENT"
POLICY_TYPE_IDP_DISCOVERY = "IDP_DISCOVERY"
POLICY_TYPE_UNKNOWN = "unknown"

POLICY_TYPES = frozenset({
    POLICY_TYPE_OKTA_SIGN_ON, POLICY_TYPE_PASSWORD, POLICY_TYPE_MFA_ENROLL,
    POLICY_TYPE_ACCESS_POLICY, POLICY_TYPE_PROFILE_ENROLLMENT, POLICY_TYPE_IDP_DISCOVERY,
})


def categorize_policy_type(raw_type: object) -> str:
    """Map a raw Okta policy `type` string to the fixed POLICY_TYPE_* set.
    Returns POLICY_TYPE_UNKNOWN for anything not in the known set — never
    fabricated for an unsupported/future policy type."""
    if isinstance(raw_type, str):
        candidate = raw_type.strip().upper()
        if candidate in POLICY_TYPES:
            return candidate
    return POLICY_TYPE_UNKNOWN


# ── Sign-on rule access / MFA requirement taxonomy (Okta message 4) ─────────

ACCESS_CATEGORY_ALLOW = "ALLOW"
ACCESS_CATEGORY_DENY = "DENY"
ACCESS_CATEGORY_UNKNOWN = "unknown"

ACCESS_CATEGORIES = frozenset({ACCESS_CATEGORY_ALLOW, ACCESS_CATEGORY_DENY})


def categorize_access(raw_access: object) -> str:
    if isinstance(raw_access, str):
        candidate = raw_access.strip().upper()
        if candidate in ACCESS_CATEGORIES:
            return candidate
    return ACCESS_CATEGORY_UNKNOWN


# Bounded MFA-requirement vocabulary. UNKNOWN is never coerced to NONE —
# a rule whose MFA posture cannot be determined from the fields actually
# returned is explicitly unknown, not "safe."
MFA_REQUIREMENT_NONE = "none"
MFA_REQUIREMENT_OPTIONAL = "optional"
MFA_REQUIREMENT_REQUIRED = "required"
MFA_REQUIREMENT_REQUIRED_EVERY_SIGNIN = "required_every_signin"
MFA_REQUIREMENT_REQUIRED_PER_SESSION = "required_per_session"
MFA_REQUIREMENT_STEP_UP = "step_up"
MFA_REQUIREMENT_UNKNOWN = "unknown"

MFA_REQUIREMENTS = frozenset({
    MFA_REQUIREMENT_NONE, MFA_REQUIREMENT_OPTIONAL, MFA_REQUIREMENT_REQUIRED,
    MFA_REQUIREMENT_REQUIRED_EVERY_SIGNIN, MFA_REQUIREMENT_REQUIRED_PER_SESSION,
    MFA_REQUIREMENT_STEP_UP,
})

# Ranking used only for directional Change classification (never persisted) —
# higher means more restrictive/protective.
MFA_REQUIREMENT_RANK = {
    MFA_REQUIREMENT_NONE: 0,
    MFA_REQUIREMENT_OPTIONAL: 1,
    MFA_REQUIREMENT_REQUIRED: 2,
    MFA_REQUIREMENT_REQUIRED_PER_SESSION: 2,
    MFA_REQUIREMENT_REQUIRED_EVERY_SIGNIN: 3,
    MFA_REQUIREMENT_STEP_UP: 3,
}


def mfa_requirement_from_signon_actions(actions: dict) -> str:
    """Derive an MFA_REQUIREMENT_* value from an Okta sign-on policy rule's
    ``actions.signon`` block (the classic OKTA_SIGN_ON rule action shape).

    Only ``requireFactor`` (bool) and ``factorPromptMode`` (str) are ever
    read. Returns MFA_REQUIREMENT_UNKNOWN when ``requireFactor`` is absent
    or not a bool — never guessed as NONE.
    """
    signon = actions.get("signon") if isinstance(actions.get("signon"), dict) else None
    if not isinstance(signon, dict):
        return MFA_REQUIREMENT_UNKNOWN
    require_factor = signon.get("requireFactor")
    if not isinstance(require_factor, bool):
        return MFA_REQUIREMENT_UNKNOWN
    if require_factor is False:
        return MFA_REQUIREMENT_NONE
    prompt_mode = signon.get("factorPromptMode")
    if isinstance(prompt_mode, str):
        mode = prompt_mode.strip().upper()
        if mode == "ALWAYS":
            return MFA_REQUIREMENT_REQUIRED_EVERY_SIGNIN
        if mode in ("SESSION", "DEVICE"):
            return MFA_REQUIREMENT_REQUIRED_PER_SESSION
    return MFA_REQUIREMENT_REQUIRED


def mfa_requirement_from_verification_method(verification_method: dict) -> str:
    """Derive an MFA_REQUIREMENT_* value from a modern (Identity Engine)
    Okta authentication policy rule's ``actions.appSignOn.verificationMethod``
    block. Only ``factorMode`` (str) is read for this mapping — never the
    raw ``constraints`` list wholesale.
    """
    factor_mode = verification_method.get("factorMode")
    if not isinstance(factor_mode, str):
        return MFA_REQUIREMENT_UNKNOWN
    mode = factor_mode.strip().upper()
    if mode == "2FA":
        return MFA_REQUIREMENT_REQUIRED
    if mode == "1FA":
        return MFA_REQUIREMENT_NONE
    return MFA_REQUIREMENT_UNKNOWN


# ── Assurance / phishing-resistance posture (Okta message 4) ───────────────

PHISHING_RESISTANT = "phishing_resistant"
NOT_PHISHING_RESISTANT = "not_phishing_resistant"
PHISHING_RESISTANCE_UNKNOWN = "unknown"

PHISHING_RESISTANCE_CATEGORIES = frozenset({PHISHING_RESISTANT, NOT_PHISHING_RESISTANT})


def phishing_resistance_from_possession_constraint(possession: object) -> str:
    """Map an Okta authentication policy rule's
    ``constraints[0].possession.phishingResistant`` value to a fixed
    category. Only ``"REQUIRED"`` is treated as PHISHING_RESISTANT;
    ``"DISALLOWED"``/other explicit non-required values are
    NOT_PHISHING_RESISTANT; anything absent/malformed is UNKNOWN — never
    guessed as either.
    """
    if not isinstance(possession, dict):
        return PHISHING_RESISTANCE_UNKNOWN
    value = possession.get("phishingResistant")
    if isinstance(value, str):
        v = value.strip().upper()
        if v == "REQUIRED":
            return PHISHING_RESISTANT
        if v in ("DISALLOWED", "OPTIONAL"):
            return NOT_PHISHING_RESISTANT
    return PHISHING_RESISTANCE_UNKNOWN


def categorize_hardware_protection(possession: object) -> str:
    """Map ``constraints[0].possession.hardwareProtection`` to a fixed
    category string, or "unknown" if absent/malformed."""
    if isinstance(possession, dict):
        value = possession.get("hardwareProtection")
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
    return "unknown"


# ── Duration parsing (Okta message 4) ───────────────────────────────────────

_ISO8601_DURATION_RE = _re.compile(
    r"^P(?:(?P<days>\d+)D)?"
    r"(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$"
)


def parse_iso8601_duration_to_minutes(raw: object) -> "int | None":
    """Parse a (simple, non-negative) ISO-8601 duration string such as
    ``"PT2H"``/``"PT30M"``/``"P1D"`` into total minutes. Returns ``None``
    for anything unparseable — never guessed."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    match = _ISO8601_DURATION_RE.match(raw.strip().upper())
    if not match:
        return None
    parts = match.groupdict()
    if not any(parts.values()):
        return None
    days = int(parts["days"] or 0)
    hours = int(parts["hours"] or 0)
    minutes = int(parts["minutes"] or 0)
    seconds = int(parts["seconds"] or 0)
    return days * 24 * 60 + hours * 60 + minutes + (1 if seconds else 0)


# ── Session / re-authentication lifetime buckets (Okta message 4) ──────────
#
# Same threshold philosophy as Auth0's _session_category (token_lifetime
# style buckets already established in app/connectors/auth0.py) — reused
# here for consistency across providers rather than inventing new numbers.

SESSION_LIFETIME_VERY_SHORT = "very_short"
SESSION_LIFETIME_SHORT = "short"
SESSION_LIFETIME_STANDARD = "standard"
SESSION_LIFETIME_EXTENDED = "extended"
SESSION_LIFETIME_UNKNOWN = "unknown"


def categorize_session_lifetime_minutes(minutes: object) -> str:
    """Bucket a session/re-authentication lifetime given in minutes.
    ``None``/non-int returns SESSION_LIFETIME_UNKNOWN — never guessed."""
    if not isinstance(minutes, int) or isinstance(minutes, bool) or minutes < 0:
        return SESSION_LIFETIME_UNKNOWN
    hours = minutes / 60.0
    if hours < 1:
        return SESSION_LIFETIME_VERY_SHORT
    if hours < 24:
        return SESSION_LIFETIME_SHORT
    if hours < 168:
        return SESSION_LIFETIME_STANDARD
    return SESSION_LIFETIME_EXTENDED


# ── Policy/rule targeting (scope) categories (Okta message 4) ──────────────

SCOPE_ALL_USERS = "all_users"
SCOPE_SCOPED_GROUPS = "scoped_groups"
SCOPE_SCOPED_USERS = "scoped_users"
SCOPE_UNKNOWN = "unknown"

SCOPE_CATEGORIES = frozenset({SCOPE_ALL_USERS, SCOPE_SCOPED_GROUPS, SCOPE_SCOPED_USERS})


def categorize_scope(*, group_include_count: "int | None", user_include_count: "int | None") -> str:
    """Derive a targeting scope category from safe include-counts.
    Unknown (both counts unavailable) is never coerced to "all_users"."""
    if group_include_count is None and user_include_count is None:
        return SCOPE_UNKNOWN
    if (group_include_count or 0) > 0:
        return SCOPE_SCOPED_GROUPS
    if (user_include_count or 0) > 0:
        return SCOPE_SCOPED_USERS
    return SCOPE_ALL_USERS


# ── Password policy posture (Okta message 4) ────────────────────────────────
#
# Thresholds are deliberately conservative and documented (no existing
# ConfigTrace convention defines password-strength buckets, per the
# message-4 spec's instruction to avoid arbitrary industry numbers unless
# clearly justified): 8 is Okta's own long-standing platform default
# minimum length; 14 is a widely-cited passphrase-strength threshold
# (e.g. CIS Benchmarks' "strong" tier for privileged accounts). These are
# ONLY used for the record's own descriptive category field — Change
# classification (see risk_rules/okta.py) is directional (increase/
# decrease), matching the existing AWS/Supabase password_min_length
# classifiers, never based on crossing these absolute thresholds.

PASSWORD_STRENGTH_WEAK = "weak"
PASSWORD_STRENGTH_BASELINE = "baseline"
PASSWORD_STRENGTH_STRONG = "strong"
PASSWORD_STRENGTH_UNKNOWN = "unknown"

PASSWORD_MIN_LENGTH_WEAK_THRESHOLD = 8   # < this is "weak"
PASSWORD_MIN_LENGTH_STRONG_THRESHOLD = 14  # >= this is "strong"


def categorize_password_min_length(min_length: object) -> str:
    if not isinstance(min_length, int) or isinstance(min_length, bool) or min_length < 0:
        return PASSWORD_STRENGTH_UNKNOWN
    if min_length < PASSWORD_MIN_LENGTH_WEAK_THRESHOLD:
        return PASSWORD_STRENGTH_WEAK
    if min_length >= PASSWORD_MIN_LENGTH_STRONG_THRESHOLD:
        return PASSWORD_STRENGTH_STRONG
    return PASSWORD_STRENGTH_BASELINE


def _safe_int(value: object) -> "int | None":
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


# ── Authenticator taxonomy (Okta message 4) ─────────────────────────────────

AUTHENTICATOR_KEY_PASSWORD = "password"
AUTHENTICATOR_KEY_SECURITY_QUESTION = "security_question"
AUTHENTICATOR_KEY_EMAIL = "email"
AUTHENTICATOR_KEY_PHONE_NUMBER = "phone_number"
AUTHENTICATOR_KEY_OKTA_VERIFY = "okta_verify"
AUTHENTICATOR_KEY_WEBAUTHN = "webauthn"
AUTHENTICATOR_KEY_GOOGLE_OTP = "google_otp"
AUTHENTICATOR_KEY_ONPREM_MFA = "onprem_mfa"
AUTHENTICATOR_KEY_SMART_CARD_IDP = "smart_card_idp"
AUTHENTICATOR_KEY_CUSTOM_APP = "custom_app"
AUTHENTICATOR_KEY_UNKNOWN = "unknown"

_KNOWN_AUTHENTICATOR_KEYS = frozenset({
    AUTHENTICATOR_KEY_PASSWORD, AUTHENTICATOR_KEY_SECURITY_QUESTION, AUTHENTICATOR_KEY_EMAIL,
    AUTHENTICATOR_KEY_PHONE_NUMBER, AUTHENTICATOR_KEY_OKTA_VERIFY, AUTHENTICATOR_KEY_WEBAUTHN,
    AUTHENTICATOR_KEY_GOOGLE_OTP, AUTHENTICATOR_KEY_ONPREM_MFA, AUTHENTICATOR_KEY_SMART_CARD_IDP,
    AUTHENTICATOR_KEY_CUSTOM_APP,
})


def categorize_authenticator_key(raw_key: object) -> str:
    """Map a raw Okta authenticator `key` string to the fixed
    AUTHENTICATOR_KEY_* set. Returns AUTHENTICATOR_KEY_UNKNOWN for
    anything not in the known set — never guessed from the display name."""
    if isinstance(raw_key, str):
        candidate = raw_key.strip().lower()
        if candidate in _KNOWN_AUTHENTICATOR_KEYS:
            return candidate
    return AUTHENTICATOR_KEY_UNKNOWN


# Deterministic phishing-resistance mapping for authenticator TYPES (as
# opposed to the per-rule constraint mapping above). Only WebAuthn/FIDO2
# and smart-card authenticators are ever categorized as phishing-resistant
# — SMS, email, TOTP/OTP, and password are explicitly categorized as NOT
# phishing-resistant (deterministic, not guessed), since these mechanisms
# are well-documented as vulnerable to real-time phishing relay regardless
# of tenant configuration. Anything else (custom_app, onprem_mfa) is
# unknown — never assumed either way.
_PHISHING_RESISTANT_AUTHENTICATOR_KEYS = frozenset({
    AUTHENTICATOR_KEY_WEBAUTHN, AUTHENTICATOR_KEY_SMART_CARD_IDP,
})
_NOT_PHISHING_RESISTANT_AUTHENTICATOR_KEYS = frozenset({
    AUTHENTICATOR_KEY_PASSWORD, AUTHENTICATOR_KEY_SECURITY_QUESTION, AUTHENTICATOR_KEY_EMAIL,
    AUTHENTICATOR_KEY_PHONE_NUMBER, AUTHENTICATOR_KEY_GOOGLE_OTP, AUTHENTICATOR_KEY_OKTA_VERIFY,
})


def phishing_resistance_for_authenticator_key(key: str) -> str:
    if key in _PHISHING_RESISTANT_AUTHENTICATOR_KEYS:
        return PHISHING_RESISTANT
    if key in _NOT_PHISHING_RESISTANT_AUTHENTICATOR_KEYS:
        return NOT_PHISHING_RESISTANT
    return PHISHING_RESISTANCE_UNKNOWN


# Okta's own factor-category convention: password/security_question are
# "knowledge" factors; email/phone/okta_verify/webauthn/smart_card are
# "possession" factors (proof of access to a device/channel). Okta does
# not expose a distinct "inherence" (biometric) authenticator type in this
# API — biometrics are a modifier of WebAuthn/Okta Verify, not a separate
# type — so inherence is always None/unknown here, never fabricated.
_KNOWLEDGE_AUTHENTICATOR_KEYS = frozenset({
    AUTHENTICATOR_KEY_PASSWORD, AUTHENTICATOR_KEY_SECURITY_QUESTION,
})
_POSSESSION_AUTHENTICATOR_KEYS = frozenset({
    AUTHENTICATOR_KEY_EMAIL, AUTHENTICATOR_KEY_PHONE_NUMBER, AUTHENTICATOR_KEY_OKTA_VERIFY,
    AUTHENTICATOR_KEY_WEBAUTHN, AUTHENTICATOR_KEY_GOOGLE_OTP, AUTHENTICATOR_KEY_SMART_CARD_IDP,
})


def is_knowledge_authenticator(key: str) -> "bool | None":
    if key in _KNOWLEDGE_AUTHENTICATOR_KEYS:
        return True
    if key in _POSSESSION_AUTHENTICATOR_KEYS:
        return False
    return None


def is_possession_authenticator(key: str) -> "bool | None":
    if key in _POSSESSION_AUTHENTICATOR_KEYS:
        return True
    if key in _KNOWLEDGE_AUTHENTICATOR_KEYS:
        return False
    return None


# ═════════════════════════════════════════════════════════════════════════
# Privileged identity / administrator role taxonomy (Okta message 5 of 8)
# ═════════════════════════════════════════════════════════════════════════
#
# Okta has no single endpoint that lists the fixed catalog of BUILT-IN
# admin role types — they are a closed, Okta-defined enum that only shows
# up as the ``type`` field on role-ASSIGNMENT objects
# (``GET /api/v1/users/{userId}/roles`` / ``GET /api/v1/groups/{groupId}/roles``).
# CUSTOM roles, by contrast, ARE a real listable resource
# (``GET /api/v1/iam/roles``) with their own permission set. Both are
# normalized into the same ``okta_admin_role`` record type, distinguished
# by the ``built_in``/``custom`` booleans.

ROLE_TYPE_SUPER_ADMIN = "SUPER_ADMIN"
ROLE_TYPE_ORG_ADMIN = "ORG_ADMIN"
ROLE_TYPE_APP_ADMIN = "APP_ADMIN"
ROLE_TYPE_USER_ADMIN = "USER_ADMIN"
ROLE_TYPE_GROUP_ADMIN = "GROUP_ADMIN"
ROLE_TYPE_HELP_DESK_ADMIN = "HELP_DESK_ADMIN"
ROLE_TYPE_READ_ONLY_ADMIN = "READ_ONLY_ADMIN"
ROLE_TYPE_MOBILE_ADMIN = "MOBILE_ADMIN"
ROLE_TYPE_API_ACCESS_MANAGEMENT_ADMIN = "API_ACCESS_MANAGEMENT_ADMIN"
ROLE_TYPE_REPORT_ADMIN = "REPORT_ADMIN"
ROLE_TYPE_CUSTOM = "CUSTOM"
ROLE_TYPE_UNKNOWN = "unknown"

_KNOWN_BUILT_IN_ROLE_TYPES = frozenset({
    ROLE_TYPE_SUPER_ADMIN, ROLE_TYPE_ORG_ADMIN, ROLE_TYPE_APP_ADMIN,
    ROLE_TYPE_USER_ADMIN, ROLE_TYPE_GROUP_ADMIN, ROLE_TYPE_HELP_DESK_ADMIN,
    ROLE_TYPE_READ_ONLY_ADMIN, ROLE_TYPE_MOBILE_ADMIN,
    ROLE_TYPE_API_ACCESS_MANAGEMENT_ADMIN, ROLE_TYPE_REPORT_ADMIN,
})

ROLE_TYPES = frozenset(_KNOWN_BUILT_IN_ROLE_TYPES | {ROLE_TYPE_CUSTOM, ROLE_TYPE_UNKNOWN})


def categorize_role_type(raw_type: object) -> str:
    """Map a raw Okta role-assignment ``type`` to the fixed ROLE_TYPE_* set.

    ``"CUSTOM"`` is Okta's own literal value for a custom-role assignment
    (the actual custom role is then identified separately, via the
    assignment's ``role``/``resourceSet`` fields). Anything else not in
    the known built-in set returns ``ROLE_TYPE_UNKNOWN`` — NEVER inferred
    from a role's display label, and never silently treated as an
    ordinary/ambient role.
    """
    if isinstance(raw_type, str) and raw_type in _KNOWN_BUILT_IN_ROLE_TYPES:
        return raw_type
    if raw_type == ROLE_TYPE_CUSTOM:
        return ROLE_TYPE_CUSTOM
    return ROLE_TYPE_UNKNOWN


# ── Privilege tier ───────────────────────────────────────────────────────
#
# A bounded, documented tier used ONLY for Change-classification severity
# and for `okta_privileged_identity`/`okta_privileged_group` rollups —
# never as a substitute for Okta's own permission model.
#
# Tier justification (built-in roles):
#   critical   — SUPER_ADMIN: unrestricted tenant-wide administrative
#                control (users, groups, apps, policies, other admins).
#                Directly analogous to this codebase's existing
#                AdministratorAccess-attached-to-IAM-principal precedent
#                (`_classify_iam_policy_attachment_change` in
#                risk_rules/aws.py), which already uses "critical" for an
#                equivalently unrestricted grant.
#   high       — ORG_ADMIN (nearly all SUPER_ADMIN capability except
#                managing other administrators/API tokens in some Okta
#                editions) and API_ACCESS_MANAGEMENT_ADMIN (can create/
#                modify authorization servers, scopes, and access
#                policies — i.e. can reshape what OAuth/OIDC clients are
#                allowed to do tenant-wide, a policy-altering capability).
#   medium     — APP_ADMIN / USER_ADMIN / GROUP_ADMIN / MOBILE_ADMIN:
#                scoped administrative capability over one resource
#                category (apps, users, groups, or mobile device
#                management) rather than the whole tenant. Also
#                HELP_DESK_ADMIN: per Okta's documented Help Desk
#                Administrator permissions, this role CAN reset a user's
#                password and unlock their account — a real
#                credential-reset capability, materially more than
#                read-only — but (unlike ORG_ADMIN/SUPER_ADMIN) cannot
#                reset MFA factors, manage groups/apps, or alter policies,
#                so it is scoped to end-user account recovery, not tenant
#                configuration.
#   read_only  — READ_ONLY_ADMIN (explicitly read-only per Okta's own
#                naming and documented permissions) and REPORT_ADMIN
#                (reporting/read access only).
#   unknown    — any role type Okta introduces that this connector
#                doesn't yet recognize, and any custom role whose
#                permission set could not be determined. Unknown is
#                NEVER treated as safe/low — see `_classify_*` in
#                risk_rules/okta.py.

PRIVILEGE_TIER_CRITICAL = "critical"
PRIVILEGE_TIER_HIGH = "high"
PRIVILEGE_TIER_MEDIUM = "medium"
PRIVILEGE_TIER_LOW = "low"
PRIVILEGE_TIER_READ_ONLY = "read_only"
PRIVILEGE_TIER_UNKNOWN = "unknown"

PRIVILEGE_TIERS = frozenset({
    PRIVILEGE_TIER_CRITICAL, PRIVILEGE_TIER_HIGH, PRIVILEGE_TIER_MEDIUM,
    PRIVILEGE_TIER_LOW, PRIVILEGE_TIER_READ_ONLY, PRIVILEGE_TIER_UNKNOWN,
})

# Used only for directional "highest tier"/"tier increased or decreased"
# comparisons — never persisted. `PRIVILEGE_TIER_LOW` sits between
# read_only and medium: it is reserved for custom roles whose permission
# set grants some real but narrow write capability (see
# `privilege_tier_for_permissions()` below) — no BUILT_IN role maps to it.
PRIVILEGE_TIER_RANK: dict = {
    PRIVILEGE_TIER_UNKNOWN: 1,
    PRIVILEGE_TIER_READ_ONLY: 2,
    PRIVILEGE_TIER_LOW: 3,
    PRIVILEGE_TIER_MEDIUM: 4,
    PRIVILEGE_TIER_HIGH: 5,
    PRIVILEGE_TIER_CRITICAL: 6,
}

_BUILT_IN_ROLE_TIER: dict = {
    ROLE_TYPE_SUPER_ADMIN: PRIVILEGE_TIER_CRITICAL,
    ROLE_TYPE_ORG_ADMIN: PRIVILEGE_TIER_HIGH,
    ROLE_TYPE_API_ACCESS_MANAGEMENT_ADMIN: PRIVILEGE_TIER_HIGH,
    ROLE_TYPE_APP_ADMIN: PRIVILEGE_TIER_MEDIUM,
    ROLE_TYPE_USER_ADMIN: PRIVILEGE_TIER_MEDIUM,
    ROLE_TYPE_GROUP_ADMIN: PRIVILEGE_TIER_MEDIUM,
    ROLE_TYPE_MOBILE_ADMIN: PRIVILEGE_TIER_MEDIUM,
    ROLE_TYPE_HELP_DESK_ADMIN: PRIVILEGE_TIER_MEDIUM,
    ROLE_TYPE_READ_ONLY_ADMIN: PRIVILEGE_TIER_READ_ONLY,
    ROLE_TYPE_REPORT_ADMIN: PRIVILEGE_TIER_READ_ONLY,
}


def privilege_tier_for_role_type(role_type: str) -> str:
    """Tier for a BUILT-IN role type. Unrecognized/CUSTOM types return
    ``PRIVILEGE_TIER_UNKNOWN`` — a custom role's tier is instead derived
    from its actual permissions via `privilege_tier_for_permissions()`."""
    return _BUILT_IN_ROLE_TIER.get(role_type, PRIVILEGE_TIER_UNKNOWN)


def highest_privilege_tier(tiers: "list[str]") -> str:
    """Return the highest-ranked tier in ``tiers``, or unknown if empty.

    A known tier always outranks `unknown` (rank 1 is the floor, not the
    ceiling) — a user holding one ORG_ADMIN role and one role of an
    unrecognized future type is reported as `high`, not `unknown`,
    because the known evidence is more informative than the unknown one.
    """
    if not tiers:
        return PRIVILEGE_TIER_UNKNOWN
    return max(tiers, key=lambda t: PRIVILEGE_TIER_RANK.get(t, 0))


# ── Assignment scope ─────────────────────────────────────────────────────
#
# Okta's role-assignment objects indicate a SCOPED (as opposed to
# tenant-wide/"all") grant via the presence of a `_links.targets` (or
# equivalent resource-set binding) rather than a plain enum field. This
# connector categorizes scope WITHOUT following that targets link (doing
# so would add a third level of per-assignment N+1 API calls) — it only
# distinguishes "some scope-narrowing link is present" from "absent",
# never enumerates or persists the specific target apps/groups/users.

ASSIGNMENT_SCOPE_ALL = "all"
ASSIGNMENT_SCOPE_SCOPED = "scoped"
ASSIGNMENT_SCOPE_UNKNOWN = "unknown"

ADMIN_ASSIGNMENT_SCOPE_CATEGORIES = frozenset({
    ASSIGNMENT_SCOPE_ALL, ASSIGNMENT_SCOPE_SCOPED, ASSIGNMENT_SCOPE_UNKNOWN,
})


def categorize_admin_assignment_scope(*, has_targets_link: object) -> str:
    """``has_targets_link`` should be ``True``/``False`` (whether a
    ``_links.targets`` — or equivalent per-resource scoping link — was
    present on the raw assignment), or ``None`` if that couldn't be
    determined. Missing/malformed input is NEVER coerced to "all" —
    unknown scope must never be reported as tenant-wide."""
    if has_targets_link is True:
        return ASSIGNMENT_SCOPE_SCOPED
    if has_targets_link is False:
        return ASSIGNMENT_SCOPE_ALL
    return ASSIGNMENT_SCOPE_UNKNOWN


# ── Resource-set scope (custom-role assignments only) ────────────────────
#
# A resource set scopes an ASSIGNMENT (role + resource-set + principal),
# not the custom role definition itself — the same custom role can be
# assigned with different resource sets to different principals. Only a
# categorized posture is kept (never raw resource URLs/paths).

RESOURCE_SET_SCOPE_ALL_RESOURCES = "all_resources"
RESOURCE_SET_SCOPE_SCOPED = "scoped"
RESOURCE_SET_SCOPE_UNKNOWN = "unknown"

RESOURCE_SET_SCOPE_CATEGORIES = frozenset({
    RESOURCE_SET_SCOPE_ALL_RESOURCES, RESOURCE_SET_SCOPE_SCOPED, RESOURCE_SET_SCOPE_UNKNOWN,
})

# Okta represents an "all resources of this type" binding with a resource
# ORN ending in a wildcard segment, e.g. "okta:apps:*" / "okta:groups:*" /
# "okta:users:*" — vs. a specific resource ORN naming one concrete
# app/group/user. Only the wildcard suffix is inspected; no other part of
# the ORN (which can carry a real resource ID) is ever persisted.
_RESOURCE_SET_ALL_MARKER_SUFFIX = ":*"


def categorize_resource_set_resources(raw_resource_orns: object) -> tuple:
    """From a list of raw resource ORN strings, return
    ``(scope_category, app_count, group_count, user_count)``.

    Counts are per-category tallies of NON-wildcard (specifically scoped)
    resource entries only — a wildcard "all X" entry contributes to the
    scope category but is not counted as a specific app/group/user.
    Returns ``(RESOURCE_SET_SCOPE_UNKNOWN, None, None, None)`` if
    ``raw_resource_orns`` isn't a usable list — never guessed as scoped
    or all-resources.
    """
    if not isinstance(raw_resource_orns, list):
        return RESOURCE_SET_SCOPE_UNKNOWN, None, None, None

    app_count = 0
    group_count = 0
    user_count = 0
    saw_all_marker = False
    saw_specific = False

    for entry in raw_resource_orns:
        orn = entry.get("orn") if isinstance(entry, dict) else entry
        if not isinstance(orn, str) or not orn:
            continue
        if orn.endswith(_RESOURCE_SET_ALL_MARKER_SUFFIX):
            saw_all_marker = True
            continue
        saw_specific = True
        if ":apps:" in orn or ":app:" in orn:
            app_count += 1
        elif ":groups:" in orn or ":group:" in orn:
            group_count += 1
        elif ":users:" in orn or ":user:" in orn:
            user_count += 1

    if not saw_all_marker and not saw_specific:
        return RESOURCE_SET_SCOPE_UNKNOWN, None, None, None
    if saw_all_marker:
        return RESOURCE_SET_SCOPE_ALL_RESOURCES, app_count, group_count, user_count
    return RESOURCE_SET_SCOPE_SCOPED, app_count, group_count, user_count


# ── Dangerous permission taxonomy (custom roles) ─────────────────────────
#
# Deterministic mapping from actual Okta IAM custom-role permission
# identifiers (e.g. "okta.users.manage") to a bounded category set. Based
# on Okta's documented permission-string convention:
# "okta.<resource>.<action>" where <action> is typically "manage" (write)
# or "read". Never invents permission names — an identifier not in this
# map returns `PERMISSION_CATEGORY_UNKNOWN`.

PERMISSION_CATEGORY_ADMIN_MANAGEMENT = "administrator_management"
PERMISSION_CATEGORY_USER_LIFECYCLE = "user_lifecycle_mutation"
PERMISSION_CATEGORY_GROUP_MUTATION = "group_mutation"
PERMISSION_CATEGORY_APPLICATION_MANAGEMENT = "application_management"
PERMISSION_CATEGORY_POLICY_MANAGEMENT = "policy_management"
PERMISSION_CATEGORY_AUTHENTICATOR_MANAGEMENT = "authenticator_management"
PERMISSION_CATEGORY_API_ACCESS_MANAGEMENT = "api_access_management"
PERMISSION_CATEGORY_CREDENTIAL_RESET = "credential_reset"
PERMISSION_CATEGORY_PRIVILEGE_ASSIGNMENT = "privilege_assignment"
PERMISSION_CATEGORY_BROAD_TENANT_CONFIGURATION = "broad_tenant_configuration"
PERMISSION_CATEGORY_READ_ONLY = "read_only"
PERMISSION_CATEGORY_UNKNOWN = "unknown"

# Exact Okta IAM permission identifiers -> category. Deliberately an exact
# allowlist (not a prefix/substring guess) so a future Okta permission
# string this connector has never seen returns "unknown", not a guess.
_PERMISSION_CATEGORY_MAP: dict = {
    "okta.roles.manage": PERMISSION_CATEGORY_ADMIN_MANAGEMENT,
    "okta.roles.read": PERMISSION_CATEGORY_READ_ONLY,
    "okta.authzServers.manage": PERMISSION_CATEGORY_API_ACCESS_MANAGEMENT,
    "okta.authzServers.read": PERMISSION_CATEGORY_READ_ONLY,
    "okta.users.manage": PERMISSION_CATEGORY_USER_LIFECYCLE,
    "okta.users.read": PERMISSION_CATEGORY_READ_ONLY,
    "okta.users.lifecycle.manage": PERMISSION_CATEGORY_USER_LIFECYCLE,
    "okta.users.credentials.manage": PERMISSION_CATEGORY_CREDENTIAL_RESET,
    "okta.users.userprofile.manage": PERMISSION_CATEGORY_USER_LIFECYCLE,
    "okta.groups.manage": PERMISSION_CATEGORY_GROUP_MUTATION,
    "okta.groups.read": PERMISSION_CATEGORY_READ_ONLY,
    "okta.groups.members.manage": PERMISSION_CATEGORY_GROUP_MUTATION,
    "okta.groups.appAssignments.manage": PERMISSION_CATEGORY_GROUP_MUTATION,
    "okta.apps.manage": PERMISSION_CATEGORY_APPLICATION_MANAGEMENT,
    "okta.apps.read": PERMISSION_CATEGORY_READ_ONLY,
    "okta.apps.assignment.manage": PERMISSION_CATEGORY_APPLICATION_MANAGEMENT,
    "okta.policies.manage": PERMISSION_CATEGORY_POLICY_MANAGEMENT,
    "okta.policies.read": PERMISSION_CATEGORY_READ_ONLY,
    "okta.authenticators.manage": PERMISSION_CATEGORY_AUTHENTICATOR_MANAGEMENT,
    "okta.authenticators.read": PERMISSION_CATEGORY_READ_ONLY,
    "okta.governance.accessRequests.manage": PERMISSION_CATEGORY_PRIVILEGE_ASSIGNMENT,
    "okta.governance.accessCertifications.manage": PERMISSION_CATEGORY_PRIVILEGE_ASSIGNMENT,
    "okta.orgs.manage": PERMISSION_CATEGORY_BROAD_TENANT_CONFIGURATION,
    "okta.orgs.read": PERMISSION_CATEGORY_READ_ONLY,
    "okta.customizations.manage": PERMISSION_CATEGORY_BROAD_TENANT_CONFIGURATION,
}

_PERMISSION_CATEGORY_TIER: dict = {
    PERMISSION_CATEGORY_ADMIN_MANAGEMENT: PRIVILEGE_TIER_CRITICAL,
    PERMISSION_CATEGORY_PRIVILEGE_ASSIGNMENT: PRIVILEGE_TIER_CRITICAL,
    PERMISSION_CATEGORY_POLICY_MANAGEMENT: PRIVILEGE_TIER_HIGH,
    PERMISSION_CATEGORY_AUTHENTICATOR_MANAGEMENT: PRIVILEGE_TIER_HIGH,
    PERMISSION_CATEGORY_API_ACCESS_MANAGEMENT: PRIVILEGE_TIER_HIGH,
    PERMISSION_CATEGORY_BROAD_TENANT_CONFIGURATION: PRIVILEGE_TIER_HIGH,
    PERMISSION_CATEGORY_USER_LIFECYCLE: PRIVILEGE_TIER_MEDIUM,
    PERMISSION_CATEGORY_GROUP_MUTATION: PRIVILEGE_TIER_MEDIUM,
    PERMISSION_CATEGORY_APPLICATION_MANAGEMENT: PRIVILEGE_TIER_MEDIUM,
    PERMISSION_CATEGORY_CREDENTIAL_RESET: PRIVILEGE_TIER_MEDIUM,
    PERMISSION_CATEGORY_READ_ONLY: PRIVILEGE_TIER_READ_ONLY,
}


def categorize_permission(raw_permission: object) -> str:
    """Map one raw Okta custom-role permission identifier to the bounded
    category set. Unrecognized/malformed input returns
    ``PERMISSION_CATEGORY_UNKNOWN`` — never guessed from substring
    matching a permission name this connector has never been told about.
    """
    if isinstance(raw_permission, str) and raw_permission in _PERMISSION_CATEGORY_MAP:
        return _PERMISSION_CATEGORY_MAP[raw_permission]
    return PERMISSION_CATEGORY_UNKNOWN


def privilege_tier_for_permissions(raw_permissions: object) -> str:
    """Derive a custom role's overall privilege tier as the HIGHEST tier
    implied by any one of its permissions.

    Returns ``PRIVILEGE_TIER_UNKNOWN`` (never "read_only"/"low"/"safe")
    when ``raw_permissions`` is missing/empty/malformed, or when every
    permission present maps to an unrecognized category — an unknown
    permission set is never assumed safe.
    """
    if not isinstance(raw_permissions, list) or not raw_permissions:
        return PRIVILEGE_TIER_UNKNOWN

    categories = {categorize_permission(p) for p in raw_permissions}
    tiers = [
        _PERMISSION_CATEGORY_TIER.get(c, PRIVILEGE_TIER_UNKNOWN) for c in categories
    ]
    if not tiers or all(t == PRIVILEGE_TIER_UNKNOWN for t in tiers):
        return PRIVILEGE_TIER_UNKNOWN
    return highest_privilege_tier(tiers)


# ── Dormant privileged-identity posture ──────────────────────────────────
#
# Reuses message-2's `LAST_LOGIN_*` categories (never a new threshold) —
# purely descriptive posture, NOT a Finding. Message 6 decides whether a
# dormant privileged identity becomes a Finding.

DORMANT_PRIVILEGED_NEVER_LOGGED_IN = "privileged_never_logged_in"
DORMANT_PRIVILEGED_STALE_LOGIN = "privileged_stale_login"
DORMANT_PRIVILEGED_RECENT_LOGIN = "privileged_recent_login"
DORMANT_PRIVILEGED_UNKNOWN = "unknown"

_LAST_LOGIN_TO_DORMANT_PRIVILEGED: dict = {
    LAST_LOGIN_NEVER: DORMANT_PRIVILEGED_NEVER_LOGGED_IN,
    LAST_LOGIN_STALE: DORMANT_PRIVILEGED_STALE_LOGIN,
    LAST_LOGIN_RECENT: DORMANT_PRIVILEGED_RECENT_LOGIN,
}


def categorize_dormant_privileged(last_login_category: str) -> str:
    return _LAST_LOGIN_TO_DORMANT_PRIVILEGED.get(last_login_category, DORMANT_PRIVILEGED_UNKNOWN)
