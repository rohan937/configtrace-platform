"""Sentry provider schema (Sentry message 1-2 of 8).

Defines the record-type constants, credential validators, and capability
taxonomy for the Sentry provider. Record types so far:

  sentry_organization             — one record per connected Sentry
                                    organization (msg 1) — stable
                                    organization identity and safe
                                    context metadata only, never
                                    credentials.
  sentry_api_capability           — one record per probed future-family
                                    surface (msg 1) — describes whether a
                                    surface is safely readable, never the
                                    surface's actual data.
  sentry_project                 — one record per Sentry project (msg 2)
                                    — stable identity, slug/name, status,
                                    platform category. Never DSNs, client
                                    keys, or event/issue data.
  sentry_team                    — one record per Sentry team (msg 2) —
                                    stable identity, slug/name, member/
                                    project counts.
  sentry_member                  — one record per organization member
                                    (msg 2) — stable identity, organization
                                    role, pending/active status. Never
                                    email, phone, IP, or auth material.
  sentry_team_membership         — one record per member<->team edge
                                    (msg 2) — never duplicates the full
                                    member/team records.
  sentry_project_team_assignment — one record per team<->project edge
                                    (msg 2).

SECURITY: this module never handles the auth token itself — only the
non-secret organization_slug field is validated here. See ``sentry.py``'s
module docstring for the full sensitive-data boundary.

Future messages (do not implement yet — see the Sentry roadmap in the
connector module docstring):
  msg 3 — alert rules (issue + metric), notification routing.
  msg 4 — integrations, webhooks, repositories, ownership rules, releases/
          deployment settings.
  msg 5 — security/privacy posture, effective access, privileged identities.
  msg 6 — Security Findings.
  msg 7 — exhaustive Change classification, partial-sync/reliability
          hardening.
  msg 8 — public launch.
"""

from __future__ import annotations

import re as _re

# ── Record type constants ───────────────────────────────────────────────────

SENTRY_ORGANIZATION = "sentry_organization"
SENTRY_API_CAPABILITY = "sentry_api_capability"
SENTRY_PROJECT = "sentry_project"
SENTRY_TEAM = "sentry_team"
SENTRY_MEMBER = "sentry_member"
SENTRY_TEAM_MEMBERSHIP = "sentry_team_membership"
SENTRY_PROJECT_TEAM_ASSIGNMENT = "sentry_project_team_assignment"

ALL_SENTRY_RECORD_TYPES = frozenset({
    SENTRY_ORGANIZATION,
    SENTRY_API_CAPABILITY,
    SENTRY_PROJECT,
    SENTRY_TEAM,
    SENTRY_MEMBER,
    SENTRY_TEAM_MEMBERSHIP,
    SENTRY_PROJECT_TEAM_ASSIGNMENT,
})

# ── Family completeness taxonomy (shared by every future collection msg) ───

FAMILY_COMPLETE = "complete"
FAMILY_PARTIAL = "partial"
FAMILY_DENIED = "denied"
FAMILY_UNAVAILABLE = "unavailable"

# ── Capability probe status taxonomy ────────────────────────────────────────

CAPABILITY_AVAILABLE = "available"
CAPABILITY_DENIED = "denied"
CAPABILITY_UNSUPPORTED = "unsupported"
CAPABILITY_UNAVAILABLE = "unavailable"
CAPABILITY_THROTTLED = "throttled"
CAPABILITY_TIMED_OUT = "timed_out"
CAPABILITY_MALFORMED = "malformed"
CAPABILITY_UNKNOWN = "unknown"

# ── Capability families (message 1 probes only; collected starting msg 2+) ─
#
# Every family below corresponds to an organization-scoped, current-
# official-docs-confirmed GET endpoint (see the connector module
# docstring's documentation-verification log) EXCEPT the three explicitly
# marked "structurally unsupported this message" — those Sentry surfaces
# are scoped per-PROJECT (e.g. ``/api/0/projects/{org}/{project}/rules/``
# for issue alert rules, ``/api/0/projects/{org}/{project}/ownership/``
# for ownership rules), and no project inventory exists until message 2.
# Rather than guess at a project slug or skip the family from the
# taxonomy entirely, these three always report CAPABILITY_UNSUPPORTED
# without making an HTTP call — an honest, structural "not yet
# collectible" status distinct from a real permission denial. No
# standalone top-level "list webhooks" endpoint was found in current
# official docs (webhook configuration lives inside internal-integration
# settings, which message 4 will address) — it is also unconditionally
# unsupported this message for the same reason: no confirmed endpoint to
# call, so no HTTP call is attempted.

CAPABILITY_FAMILY_PROJECTS = "projects"
CAPABILITY_FAMILY_TEAMS = "teams"
CAPABILITY_FAMILY_MEMBERS = "members"
CAPABILITY_FAMILY_ISSUE_ALERTS = "issue_alerts"
CAPABILITY_FAMILY_METRIC_ALERTS = "metric_alerts"
CAPABILITY_FAMILY_INTEGRATIONS = "integrations"
CAPABILITY_FAMILY_WEBHOOKS = "webhooks"
CAPABILITY_FAMILY_REPOSITORIES = "repositories"
CAPABILITY_FAMILY_OWNERSHIP_RULES = "ownership_rules"
CAPABILITY_FAMILY_RELEASES = "releases"

CAPABILITY_FAMILIES: tuple[str, ...] = (
    CAPABILITY_FAMILY_PROJECTS,
    CAPABILITY_FAMILY_TEAMS,
    CAPABILITY_FAMILY_MEMBERS,
    CAPABILITY_FAMILY_ISSUE_ALERTS,
    CAPABILITY_FAMILY_METRIC_ALERTS,
    CAPABILITY_FAMILY_INTEGRATIONS,
    CAPABILITY_FAMILY_WEBHOOKS,
    CAPABILITY_FAMILY_REPOSITORIES,
    CAPABILITY_FAMILY_OWNERSHIP_RULES,
    CAPABILITY_FAMILY_RELEASES,
)

# ── Message-2 collection families ───────────────────────────────────────────
#
# Distinct from CAPABILITY_FAMILIES (message-1 single-probe outcomes) —
# these describe what actually happened when message-2 tried to COLLECT a
# whole family, which can partially succeed across a paginated, per-team
# series of calls. ``project_team_assignments`` is tracked as its own key
# even though it is currently derived from the SAME response as
# ``teams`` (Sentry's list-teams endpoint nests each team's nested
# ``projects`` array) — kept independent so a later message that adds a
# genuinely separate collection path for it does not require a schema
# change, and so message-7 false-removal suppression has a stable key to
# scope to.
COLLECTION_FAMILY_PROJECTS = "projects"
COLLECTION_FAMILY_TEAMS = "teams"
COLLECTION_FAMILY_MEMBERS = "members"
COLLECTION_FAMILY_TEAM_MEMBERSHIPS = "team_memberships"
COLLECTION_FAMILY_PROJECT_TEAM_ASSIGNMENTS = "project_team_assignments"

COLLECTION_FAMILIES: tuple[str, ...] = (
    COLLECTION_FAMILY_PROJECTS,
    COLLECTION_FAMILY_TEAMS,
    COLLECTION_FAMILY_MEMBERS,
    COLLECTION_FAMILY_TEAM_MEMBERSHIPS,
    COLLECTION_FAMILY_PROJECT_TEAM_ASSIGNMENTS,
)

# Families that are structurally unsupported this message — always
# CAPABILITY_UNSUPPORTED, never an HTTP call. See the module docstring
# comment above ``CAPABILITY_FAMILY_PROJECTS`` for the full rationale.
STRUCTURALLY_UNSUPPORTED_FAMILIES: frozenset[str] = frozenset({
    CAPABILITY_FAMILY_ISSUE_ALERTS,
    CAPABILITY_FAMILY_WEBHOOKS,
    CAPABILITY_FAMILY_OWNERSHIP_RULES,
})


# ── Credential validators ───────────────────────────────────────────────────


class SentryCredentialError(ValueError):
    """Raised when a Sentry credential field fails validation. Subclasses
    ValueError so existing generic error handling still catches it."""


# Sentry organization slugs are conservative URL-safe identifiers: lowercase
# letters, digits, and hyphens only (Sentry's own slug generation rules).
# This value is used ONLY as a path segment in a fixed-host request
# (``https://sentry.io/api/0/organizations/{slug}/...``) — it must never be
# treated as a host, path, or arbitrary string. Rejects any value containing
# a URL scheme, additional path segments, query, or fragment.
_ORGANIZATION_SLUG_RE = _re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def validate_organization_slug(raw_slug: object) -> str:
    """Validate and normalize a Sentry organization slug.

    Returns the lowercased, trimmed slug. Raises ``SentryCredentialError``
    — never silently coerces a malformed value. The slug must never be
    able to control the request host or introduce extra path segments —
    it is always interpolated into a single, fixed path template on the
    fixed ``https://sentry.io`` origin.
    """
    if not isinstance(raw_slug, str) or not raw_slug.strip():
        raise SentryCredentialError("sentry: organization_slug must be a non-empty string")

    cleaned = raw_slug.strip().lower()

    if "://" in cleaned or "/" in cleaned or "?" in cleaned or "#" in cleaned or " " in cleaned or "." in cleaned:
        raise SentryCredentialError(
            "sentry: organization_slug must not contain a URL scheme, path, query, fragment, or dot"
        )
    if not _ORGANIZATION_SLUG_RE.match(cleaned):
        raise SentryCredentialError(
            "sentry: organization_slug must contain only lowercase letters, digits, and hyphens "
            "(e.g. 'my-organization')"
        )
    return cleaned


def validate_auth_token(raw_token: object) -> str:
    """Validate that an auth token is present and non-empty. Never
    validates or asserts a specific token prefix/format — current official
    Sentry documentation does not publish a stable token-prefix contract
    (see the connector module docstring's documentation-verification log),
    so this connector accepts any non-empty string and lets Sentry's own
    API be the source of truth for acceptance."""
    if not isinstance(raw_token, str) or not raw_token.strip():
        raise SentryCredentialError("sentry: auth_token must be a non-empty string")
    return raw_token


# ── Project status taxonomy (Sentry message 2 of 8) ─────────────────────────
#
# Confirmed via current official docs (GET /api/0/projects/{org}/{project}/)
# — the response includes a "status" field (example value: "active"). The
# full enumerated set of possible values is not published on a single
# reference page, so this taxonomy maps every value actually observed in
# current documentation/known Sentry behavior and falls back to UNKNOWN for
# anything else — never guessed, never coerced to "active" by default (a
# missing/unrecognized status must never be silently treated as safe).

PROJECT_STATUS_ACTIVE = "active"
PROJECT_STATUS_DISABLED = "disabled"
PROJECT_STATUS_PENDING_DELETION = "pending_deletion"
PROJECT_STATUS_DELETION_IN_PROGRESS = "deletion_in_progress"
PROJECT_STATUS_UNKNOWN = "unknown"

PROJECT_STATUSES = frozenset({
    PROJECT_STATUS_ACTIVE,
    PROJECT_STATUS_DISABLED,
    PROJECT_STATUS_PENDING_DELETION,
    PROJECT_STATUS_DELETION_IN_PROGRESS,
})


def categorize_project_status(raw_status: object) -> str:
    """Map a raw Sentry project status string to the fixed
    PROJECT_STATUS_* set. Returns PROJECT_STATUS_UNKNOWN for anything not
    in the known set — a missing/unrecognized status is NEVER interpreted
    as active."""
    if isinstance(raw_status, str):
        candidate = raw_status.strip().lower()
        if candidate in PROJECT_STATUSES:
            return candidate
    return PROJECT_STATUS_UNKNOWN


# ── Project platform taxonomy (Sentry message 2 of 8) ───────────────────────
#
# Sentry's "platform" field is a free-form identifier (e.g.
# "javascript-react", "python-django", "java-android", "dotnet",
# "node-express", "php-laravel", "ruby-rails", "go", "rust", "apple-ios",
# "android", "native", "unity", "cocoa"). This connector never retains the
# raw string beyond deriving a bounded category — informational only, not
# security posture — via a simple prefix match against the documented
# platform-identifier family. Anything not matched is OTHER; a genuinely
# absent platform is UNKNOWN (never coerced to OTHER).

PLATFORM_CATEGORY_JAVASCRIPT = "javascript"
PLATFORM_CATEGORY_PYTHON = "python"
PLATFORM_CATEGORY_JAVA = "java"
PLATFORM_CATEGORY_DOTNET = "dotnet"
PLATFORM_CATEGORY_PHP = "php"
PLATFORM_CATEGORY_RUBY = "ruby"
PLATFORM_CATEGORY_GO = "go"
PLATFORM_CATEGORY_RUST = "rust"
PLATFORM_CATEGORY_MOBILE = "mobile"
PLATFORM_CATEGORY_NATIVE = "native"
PLATFORM_CATEGORY_OTHER = "other"
PLATFORM_CATEGORY_UNKNOWN = "unknown"

PLATFORM_CATEGORIES = frozenset({
    PLATFORM_CATEGORY_JAVASCRIPT, PLATFORM_CATEGORY_PYTHON, PLATFORM_CATEGORY_JAVA,
    PLATFORM_CATEGORY_DOTNET, PLATFORM_CATEGORY_PHP, PLATFORM_CATEGORY_RUBY,
    PLATFORM_CATEGORY_GO, PLATFORM_CATEGORY_RUST, PLATFORM_CATEGORY_MOBILE,
    PLATFORM_CATEGORY_NATIVE, PLATFORM_CATEGORY_OTHER, PLATFORM_CATEGORY_UNKNOWN,
})

_PLATFORM_PREFIX_MAP: tuple[tuple[str, str], ...] = (
    ("javascript", PLATFORM_CATEGORY_JAVASCRIPT),
    ("node", PLATFORM_CATEGORY_JAVASCRIPT),
    ("python", PLATFORM_CATEGORY_PYTHON),
    ("java", PLATFORM_CATEGORY_JAVA),  # covers "java" and "java-android" etc.
    ("dotnet", PLATFORM_CATEGORY_DOTNET),
    ("csharp", PLATFORM_CATEGORY_DOTNET),
    ("php", PLATFORM_CATEGORY_PHP),
    ("ruby", PLATFORM_CATEGORY_RUBY),
    ("go", PLATFORM_CATEGORY_GO),
    ("rust", PLATFORM_CATEGORY_RUST),
    ("android", PLATFORM_CATEGORY_MOBILE),
    ("apple-ios", PLATFORM_CATEGORY_MOBILE),
    ("react-native", PLATFORM_CATEGORY_MOBILE),
    ("flutter", PLATFORM_CATEGORY_MOBILE),
    ("dart-flutter", PLATFORM_CATEGORY_MOBILE),
    ("cocoa", PLATFORM_CATEGORY_NATIVE),
    ("native", PLATFORM_CATEGORY_NATIVE),
    ("unity", PLATFORM_CATEGORY_NATIVE),
    ("unreal", PLATFORM_CATEGORY_NATIVE),
    ("c", PLATFORM_CATEGORY_NATIVE),
)


def categorize_platform(raw_platform: object) -> str:
    """Map a raw Sentry platform identifier string to a bounded category.
    Returns PLATFORM_CATEGORY_UNKNOWN if the field is absent/non-string —
    never coerced to OTHER (which specifically means "recognized as a
    real platform string but not in a named bucket")."""
    if not isinstance(raw_platform, str) or not raw_platform.strip():
        return PLATFORM_CATEGORY_UNKNOWN
    candidate = raw_platform.strip().lower()
    for prefix, category in _PLATFORM_PREFIX_MAP:
        if candidate == prefix or candidate.startswith(prefix + "-"):
            return category
    return PLATFORM_CATEGORY_OTHER


# ── Organization role taxonomy (Sentry message 2 of 8) ──────────────────────
#
# Confirmed via current official docs
# (https://docs.sentry.io/organization/membership/) — Sentry currently
# documents exactly 5 organization-level roles. The member list/detail API
# examples fetched during this message's research only showed "member" as
# a literal JSON value; the other 4 string values below are the direct
# lowercase mapping of the documented role NAMES (Billing/Org Members/Org
# Admins/Org Managers/Org Owners) — this connector does not invent
# intermediate tiers and treats anything else as UNKNOWN rather than
# guessing a new role exists.

ORG_ROLE_BILLING = "billing"
ORG_ROLE_MEMBER = "member"
ORG_ROLE_ADMIN = "admin"
ORG_ROLE_MANAGER = "manager"
ORG_ROLE_OWNER = "owner"
ORG_ROLE_UNKNOWN = "unknown"

ORG_ROLES = frozenset({
    ORG_ROLE_BILLING, ORG_ROLE_MEMBER, ORG_ROLE_ADMIN, ORG_ROLE_MANAGER, ORG_ROLE_OWNER,
})


def categorize_org_role(raw_role: object) -> str:
    """Map a raw Sentry organization role string to the fixed ORG_ROLE_*
    set. Returns ORG_ROLE_UNKNOWN for anything not in the known,
    documented set — never classified as an "ordinary member" merely
    because the value is missing or unrecognized (message 5 owns final
    privilege-tier analysis; this is evidence preservation only)."""
    if isinstance(raw_role, str):
        candidate = raw_role.strip().lower()
        if candidate in ORG_ROLES:
            return candidate
    return ORG_ROLE_UNKNOWN


# ── Team role taxonomy (Sentry message 2 of 8) ──────────────────────────────
#
# Confirmed via current official docs example
# (GET /organizations/{org}/members/{member_id}/'s ``teamRoles`` array) —
# the two team-role values observed were "admin" and "contributor". A
# dedicated team-roles reference page was not found during this message's
# research pass; this taxonomy is therefore limited to exactly the two
# directly-observed values plus UNKNOWN, and is documented as such rather
# than treated as an exhaustively-confirmed enumeration.

TEAM_ROLE_CONTRIBUTOR = "contributor"
TEAM_ROLE_ADMIN = "admin"
TEAM_ROLE_UNKNOWN = "unknown"

TEAM_ROLES = frozenset({TEAM_ROLE_CONTRIBUTOR, TEAM_ROLE_ADMIN})


def categorize_team_role(raw_role: object) -> str:
    """Map a raw Sentry team-level role string to the fixed TEAM_ROLE_*
    set. Returns TEAM_ROLE_UNKNOWN for anything not in the known set."""
    if isinstance(raw_role, str):
        candidate = raw_role.strip().lower()
        if candidate in TEAM_ROLES:
            return candidate
    return TEAM_ROLE_UNKNOWN


# ── Member status taxonomy (Sentry message 2 of 8) ──────────────────────────
#
# Confirmed via current official docs
# (GET /organizations/{org}/members/) — member objects carry independent
# ``pending``/``expired`` booleans (never a single combined enum field).
# This connector collapses that pair into one deterministic, tri-state-
# safe category. A MISSING pending/expired field is UNKNOWN — never
# coerced to "active" (an unknown pending state must never be treated as
# confirmed active access).

MEMBER_STATUS_ACTIVE = "active"
MEMBER_STATUS_PENDING = "pending"
MEMBER_STATUS_EXPIRED = "expired"
MEMBER_STATUS_UNKNOWN = "unknown"

MEMBER_STATUSES = frozenset({
    MEMBER_STATUS_ACTIVE, MEMBER_STATUS_PENDING, MEMBER_STATUS_EXPIRED, MEMBER_STATUS_UNKNOWN,
})


def categorize_member_status(raw_pending: object, raw_expired: object) -> str:
    """Derive a deterministic member status category from Sentry's
    independent ``pending``/``expired`` booleans.

    Returns MEMBER_STATUS_UNKNOWN if either field is missing/non-boolean
    — never assumes active. ``expired`` takes precedence over ``pending``
    when both are true (an expired invitation is no longer meaningfully
    "pending" — it requires a new invite, not just acceptance).
    """
    if not isinstance(raw_pending, bool) or not isinstance(raw_expired, bool):
        return MEMBER_STATUS_UNKNOWN
    if raw_expired:
        return MEMBER_STATUS_EXPIRED
    if raw_pending:
        return MEMBER_STATUS_PENDING
    return MEMBER_STATUS_ACTIVE
