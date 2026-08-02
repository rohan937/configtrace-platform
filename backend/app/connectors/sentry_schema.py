"""Sentry provider schema (Sentry message 1-5 of 8).

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
  sentry_metric_alert_rule        — one record per metric alert rule
                                    (msg 3) — organization-scoped,
                                    threshold/dataset/aggregate categories,
                                    never a raw query string.
  sentry_metric_alert_trigger     — one record per metric alert's
                                    critical/warning trigger (msg 3) —
                                    alert_threshold + label category.
  sentry_issue_alert_rule         — one record per project-scoped issue
                                    alert rule (msg 3) — condition/filter/
                                    action counts and categories, never
                                    raw condition/filter payloads.
  sentry_alert_action             — one record per notification action,
                                    shared by metric-alert triggers and
                                    issue-alert rules (msg 3) — target
                                    type/stable-ID only, never emails,
                                    webhook URLs, or integration keys.
  sentry_organization_integration  — one record per installed org
                                    integration (msg 4) — provider
                                    category, status, feature tags. Never
                                    OAuth/access tokens or raw config.
  sentry_repository                — one record per Sentry-tracked
                                    repository (msg 4) — provider,
                                    integration linkage, status. Never
                                    clone URLs, credentials, or SSH keys.
  sentry_code_mapping              — one record per repository<->project
                                    stack-trace path mapping (msg 4) —
                                    booleans only for stack/source root
                                    configuration, never raw paths.
  sentry_ownership_rule            — one record per (project, rule,
                                    owner) tuple from a project's
                                    issue-owner ruleset (msg 4) — matcher
                                    category + resolved team/user stable
                                    ID only, never the raw rule text or
                                    an email address.

  NOT implemented in message 4 (see the connector module docstring's
  message-4 documentation-verification log for why): ``sentry_webhook``
  (Sentry's only webhook-configuration API, ProjectServiceHooksEndpoint,
  is marked PRIVATE and feature-gated — not part of the public API
  surface), ``sentry_release_configuration`` / ``sentry_deployment_configuration``
  (no stable, published persistent settings endpoint exists — release
  thresholds are EXPERIMENTAL and releases/deploys list endpoints are
  historical activity, which this provider never ingests).

  sentry_privileged_member         — one record per organization member
                                    with meaningful organization/team/
                                    routing authority (msg 5) — PURELY
                                    DERIVED from already-collected
                                    records (zero additional HTTP calls).
                                    Ordinary members are never emitted.
  sentry_privileged_team           — one record per team with meaningful
                                    project/routing authority (msg 5) —
                                    derived; ordinary teams are never
                                    emitted.
  sentry_routing_context           — one record per ownership-rule or
                                    alert-action target, resolving
                                    whether the target is a known,
                                    active team/member/integration (msg
                                    5) — derived 1:1 from the existing
                                    ``sentry_ownership_rule``/
                                    ``sentry_alert_action`` records, never
                                    a new API call.

SECURITY: this module never handles the auth token itself — only the
non-secret organization_slug field is validated here. See ``sentry.py``'s
module docstring for the full sensitive-data boundary.

Future messages (do not implement yet — see the Sentry roadmap in the
connector module docstring):
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
SENTRY_METRIC_ALERT_RULE = "sentry_metric_alert_rule"
SENTRY_METRIC_ALERT_TRIGGER = "sentry_metric_alert_trigger"
SENTRY_ISSUE_ALERT_RULE = "sentry_issue_alert_rule"
SENTRY_ALERT_ACTION = "sentry_alert_action"
SENTRY_ORGANIZATION_INTEGRATION = "sentry_organization_integration"
SENTRY_REPOSITORY = "sentry_repository"
SENTRY_CODE_MAPPING = "sentry_code_mapping"
SENTRY_OWNERSHIP_RULE = "sentry_ownership_rule"
SENTRY_PRIVILEGED_MEMBER = "sentry_privileged_member"
SENTRY_PRIVILEGED_TEAM = "sentry_privileged_team"
SENTRY_ROUTING_CONTEXT = "sentry_routing_context"

ALL_SENTRY_RECORD_TYPES = frozenset({
    SENTRY_ORGANIZATION,
    SENTRY_API_CAPABILITY,
    SENTRY_PROJECT,
    SENTRY_TEAM,
    SENTRY_MEMBER,
    SENTRY_TEAM_MEMBERSHIP,
    SENTRY_PROJECT_TEAM_ASSIGNMENT,
    SENTRY_METRIC_ALERT_RULE,
    SENTRY_METRIC_ALERT_TRIGGER,
    SENTRY_ISSUE_ALERT_RULE,
    SENTRY_ALERT_ACTION,
    SENTRY_ORGANIZATION_INTEGRATION,
    SENTRY_REPOSITORY,
    SENTRY_CODE_MAPPING,
    SENTRY_OWNERSHIP_RULE,
    SENTRY_PRIVILEGED_MEMBER,
    SENTRY_PRIVILEGED_TEAM,
    SENTRY_ROUTING_CONTEXT,
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

# Message-3 collection families (Sentry message 3 of 8) — metric alert
# rules are organization-scoped (one paginated call); issue alert rules
# are project-scoped (one call per already-collected project, mirroring
# the message-2 per-team-membership-walk pattern); alert_actions covers
# BOTH metric-alert-trigger actions and issue-alert-rule actions under
# one key since both are the same conceptual "notification action"
# family even though their underlying Sentry storage differs.
COLLECTION_FAMILY_METRIC_ALERT_RULES = "metric_alert_rules"
COLLECTION_FAMILY_ISSUE_ALERT_RULES = "issue_alert_rules"
COLLECTION_FAMILY_ALERT_ACTIONS = "alert_actions"

# Message-4 collection families (Sentry message 4 of 8). organization_
# integrations/repositories/code_mappings are organization-scoped bulk
# calls; ownership_rules is a bounded per-project walk (one
# single-object GET per already-collected project — the endpoint is not
# a list, so message-1's ``paginate_sentry`` does not apply to it).
#
# webhooks / release_configuration / deployment_configuration are always
# reported UNSUPPORTED — never an HTTP call — because current official
# Sentry documentation and source confirm no stable, published,
# organization-scoped persistent-configuration endpoint exists for any
# of the three: the only webhook-configuration API
# (``ProjectServiceHooksEndpoint``) is marked PRIVATE and feature-gated;
# the only persistent release-configuration-shaped API (release
# thresholds) is marked EXPERIMENTAL; and release/deploy LIST endpoints
# are historical activity, which this provider never ingests. See the
# connector module docstring's message-4 documentation-verification log.
COLLECTION_FAMILY_ORGANIZATION_INTEGRATIONS = "organization_integrations"
COLLECTION_FAMILY_REPOSITORIES = "repositories"
COLLECTION_FAMILY_CODE_MAPPINGS = "code_mappings"
COLLECTION_FAMILY_OWNERSHIP_RULES = "ownership_rules"
COLLECTION_FAMILY_WEBHOOKS = "webhooks"
COLLECTION_FAMILY_RELEASE_CONFIGURATION = "release_configuration"
COLLECTION_FAMILY_DEPLOYMENT_CONFIGURATION = "deployment_configuration"

# Message-5 DERIVED families (Sentry message 5 of 8) — never collected via
# a new HTTP call; completeness is computed purely from the completeness
# of the already-collected source families each derivation reads (see
# ``sentry.py``'s ``_derive_effective_access`` docstring for the exact
# source-family dependency list per derived family).
COLLECTION_FAMILY_PRIVILEGED_MEMBERS = "privileged_members"
COLLECTION_FAMILY_PRIVILEGED_TEAMS = "privileged_teams"
COLLECTION_FAMILY_ROUTING_CONTEXT = "routing_context"

COLLECTION_FAMILIES: tuple[str, ...] = (
    COLLECTION_FAMILY_PROJECTS,
    COLLECTION_FAMILY_TEAMS,
    COLLECTION_FAMILY_MEMBERS,
    COLLECTION_FAMILY_TEAM_MEMBERSHIPS,
    COLLECTION_FAMILY_PROJECT_TEAM_ASSIGNMENTS,
    COLLECTION_FAMILY_METRIC_ALERT_RULES,
    COLLECTION_FAMILY_ISSUE_ALERT_RULES,
    COLLECTION_FAMILY_ALERT_ACTIONS,
    COLLECTION_FAMILY_ORGANIZATION_INTEGRATIONS,
    COLLECTION_FAMILY_REPOSITORIES,
    COLLECTION_FAMILY_CODE_MAPPINGS,
    COLLECTION_FAMILY_OWNERSHIP_RULES,
    COLLECTION_FAMILY_WEBHOOKS,
    COLLECTION_FAMILY_RELEASE_CONFIGURATION,
    COLLECTION_FAMILY_DEPLOYMENT_CONFIGURATION,
    COLLECTION_FAMILY_PRIVILEGED_MEMBERS,
    COLLECTION_FAMILY_PRIVILEGED_TEAMS,
    COLLECTION_FAMILY_ROUTING_CONTEXT,
)

# Collection families ALWAYS reported unsupported (message 4) — see the
# doc-comment above the message-4 collection-family constants for why.
COLLECTION_FAMILIES_ALWAYS_UNSUPPORTED: frozenset[str] = frozenset({
    COLLECTION_FAMILY_WEBHOOKS,
    COLLECTION_FAMILY_RELEASE_CONFIGURATION,
    COLLECTION_FAMILY_DEPLOYMENT_CONFIGURATION,
})

# Families that are structurally unsupported this message — always
# CAPABILITY_UNSUPPORTED, never an HTTP call. See the module docstring
# comment above ``CAPABILITY_FAMILY_PROJECTS`` for the full rationale.
# ``CAPABILITY_FAMILY_OWNERSHIP_RULES`` stays here permanently (like
# ``CAPABILITY_FAMILY_ISSUE_ALERTS``): the message-1 probe sweep is
# organization-scoped and single-page-only by design, and ownership
# rules are a genuinely project-scoped, single-object (non-list)
# resource — there is no org-scoped "probe" shape for it to ever call.
# Real per-project collection exists starting message 4 (see
# ``COLLECTION_FAMILY_OWNERSHIP_RULES`` above) and its completeness
# overrides this stale probe-level value post-collection, exactly like
# message-3 already does for ``CAPABILITY_FAMILY_ISSUE_ALERTS``.
STRUCTURALLY_UNSUPPORTED_FAMILIES: frozenset[str] = frozenset({
    CAPABILITY_FAMILY_ISSUE_ALERTS,
    CAPABILITY_FAMILY_WEBHOOKS,
    CAPABILITY_FAMILY_OWNERSHIP_RULES,
})

# ── Core vs extended coverage (Sentry message 8 of 8) ───────────────────────
#
# Only the 7 families message 1's ``_CAPABILITY_PROBES`` actually probes
# (an org-scoped, page-1-only GET) participate in coverage classification.
# The 3 STRUCTURALLY_UNSUPPORTED_FAMILIES are always CAPABILITY_UNSUPPORTED
# regardless of token scope — including them in a Full/Partial check would
# make Full permanently unreachable, since "unsupported" never equals
# "available". Core: organization identity, project/team/member inventory
# — the minimum needed for meaningful monitoring (matches the connector's
# own message-2 access-coverage scope). Extended: alerting, integrations,
# repositories — may require additional token scopes
# (``alerts:read``/``org:integrations``) a narrowly-scoped monitoring
# token legitimately may not have; absence alone must not make the
# integration Invalid.
PROBED_CAPABILITY_FAMILIES: tuple[str, ...] = tuple(
    f for f, _ in (
        (CAPABILITY_FAMILY_PROJECTS, None),
        (CAPABILITY_FAMILY_TEAMS, None),
        (CAPABILITY_FAMILY_MEMBERS, None),
        (CAPABILITY_FAMILY_METRIC_ALERTS, None),
        (CAPABILITY_FAMILY_INTEGRATIONS, None),
        (CAPABILITY_FAMILY_REPOSITORIES, None),
        (CAPABILITY_FAMILY_RELEASES, None),
    )
)
CORE_CAPABILITY_FAMILIES: tuple[str, ...] = (
    CAPABILITY_FAMILY_PROJECTS,
    CAPABILITY_FAMILY_TEAMS,
    CAPABILITY_FAMILY_MEMBERS,
)
EXTENDED_CAPABILITY_FAMILIES: tuple[str, ...] = (
    CAPABILITY_FAMILY_METRIC_ALERTS,
    CAPABILITY_FAMILY_INTEGRATIONS,
    CAPABILITY_FAMILY_REPOSITORIES,
    CAPABILITY_FAMILY_RELEASES,
)
assert set(CORE_CAPABILITY_FAMILIES) | set(EXTENDED_CAPABILITY_FAMILIES) == set(PROBED_CAPABILITY_FAMILIES)
assert not (set(CORE_CAPABILITY_FAMILIES) & set(EXTENDED_CAPABILITY_FAMILIES))

# ── Coverage state taxonomy ──────────────────────────────────────────────────

COVERAGE_FULL = "full"
COVERAGE_PARTIAL = "partial"
COVERAGE_INVALID = "invalid"

_FAMILY_DIAGNOSTIC_GROUP: dict[str, str] = {
    CAPABILITY_FAMILY_PROJECTS: "Projects and teams",
    CAPABILITY_FAMILY_TEAMS: "Projects and teams",
    CAPABILITY_FAMILY_MEMBERS: "Members and access",
    CAPABILITY_FAMILY_METRIC_ALERTS: "Alert rules",
    CAPABILITY_FAMILY_INTEGRATIONS: "Integrations",
    CAPABILITY_FAMILY_REPOSITORIES: "Repositories",
    CAPABILITY_FAMILY_RELEASES: "Releases",
}
assert set(_FAMILY_DIAGNOSTIC_GROUP) == set(PROBED_CAPABILITY_FAMILIES)


def compute_coverage_state(family_status: dict) -> str:
    """Return ``COVERAGE_INVALID``/``COVERAGE_PARTIAL``/``COVERAGE_FULL``
    from a ``{family: CAPABILITY_*}`` map (probed families only).

    Invalid: zero core families are readable — no meaningful monitoring
    would result from creating this integration. Full: every probed
    family (core and extended) is readable. Partial: at least one core
    family is readable, but something is not — the integration is still
    useful and must NOT be rejected merely because an optional/elevated
    family is denied.
    """
    core_available = sum(
        1 for family in CORE_CAPABILITY_FAMILIES if family_status.get(family) == CAPABILITY_AVAILABLE
    )
    if core_available == 0:
        return COVERAGE_INVALID
    all_available = all(
        family_status.get(family) == CAPABILITY_AVAILABLE for family in PROBED_CAPABILITY_FAMILIES
    )
    return COVERAGE_FULL if all_available else COVERAGE_PARTIAL


def format_capability_diagnostics(family_status: dict) -> dict:
    """Collapse per-family capability statuses into grouped, safe,
    human-readable diagnostics (never raw request URLs, never a raw API
    error) — e.g. ``{"Projects and teams": "Available", "Integrations":
    "Permission denied"}``. A group is "Available" only if every family
    mapped into it is available."""
    groups: dict[str, str] = {}
    for family in PROBED_CAPABILITY_FAMILIES:
        label = _FAMILY_DIAGNOSTIC_GROUP[family]
        status = family_status.get(family)
        available = status == CAPABILITY_AVAILABLE
        if label not in groups:
            groups[label] = "Available"
        if not available and groups[label] == "Available":
            groups[label] = "Permission denied" if status == CAPABILITY_DENIED else "Unavailable"
    return groups


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


# ── Metric alert status taxonomy (Sentry message 3 of 8) ────────────────────
#
# Confirmed via actual Sentry source (sentry/incidents/models/alert_rule.py,
# ``AlertRuleStatus``): PENDING=0, SNAPSHOT=4, DISABLED=5,
# NOT_ENOUGH_DATA=6 — there is no explicit numeric value documented as
# "active/enabled". Current official API docs pages for this endpoint
# could not be fetched directly this message (they 404/require JS
# rendering); this taxonomy is therefore sourced from Sentry's own model
# code, the most authoritative fallback per this message's "official docs
# win, but verify against real shapes" instruction. Only the documented
# DISABLED value is treated as disabled; every other recognized value is
# treated as enabled (none of PENDING/SNAPSHOT/NOT_ENOUGH_DATA imply the
# rule is off); a missing/unrecognized raw status is UNKNOWN — never
# assumed enabled.

METRIC_ALERT_STATUS_ENABLED = "enabled"
METRIC_ALERT_STATUS_DISABLED = "disabled"
METRIC_ALERT_STATUS_UNKNOWN = "unknown"

_METRIC_ALERT_DISABLED_VALUE = 5
_METRIC_ALERT_KNOWN_STATUS_VALUES = frozenset({0, 4, 5, 6})


def categorize_metric_alert_status(raw_status: object) -> str:
    """Map a raw Sentry ``AlertRuleStatus`` integer to enabled/disabled/
    unknown. Conservative: only the documented DISABLED(5) value maps to
    disabled; anything else recognized maps to enabled; anything missing
    or unrecognized is UNKNOWN — never coerced to enabled."""
    if isinstance(raw_status, bool):
        return METRIC_ALERT_STATUS_UNKNOWN
    if isinstance(raw_status, int) and raw_status in _METRIC_ALERT_KNOWN_STATUS_VALUES:
        return METRIC_ALERT_STATUS_DISABLED if raw_status == _METRIC_ALERT_DISABLED_VALUE else METRIC_ALERT_STATUS_ENABLED
    return METRIC_ALERT_STATUS_UNKNOWN


# ── Issue alert status taxonomy (Sentry message 3 of 8) ─────────────────────
#
# Issue alert rules (``Rule`` model) expose a ``status`` string field
# (distinct in shape from the metric alert's numeric AlertRuleStatus) —
# confirmed via Sentry's ``RuleSerializerResponse`` (sentry/api/
# serializers/models/rule.py), which includes "status" alongside a
# separate "snooze"/"disableReason"/"disableDate" cluster. Exact string
# values were not directly observed in a fetched example; this taxonomy
# accepts the conventional "active"/"disabled" strings and falls back to
# UNKNOWN for anything else, never assuming active.

ISSUE_ALERT_STATUS_ENABLED = "enabled"
ISSUE_ALERT_STATUS_DISABLED = "disabled"
ISSUE_ALERT_STATUS_UNKNOWN = "unknown"

_ISSUE_ALERT_ENABLED_STRINGS = frozenset({"active", "enabled"})
_ISSUE_ALERT_DISABLED_STRINGS = frozenset({"disabled"})


def categorize_issue_alert_status(raw_status: object) -> str:
    """Map a raw Sentry issue-alert-rule status string to enabled/
    disabled/unknown. Missing/unrecognized is UNKNOWN — never enabled."""
    if isinstance(raw_status, str):
        candidate = raw_status.strip().lower()
        if candidate in _ISSUE_ALERT_ENABLED_STRINGS:
            return ISSUE_ALERT_STATUS_ENABLED
        if candidate in _ISSUE_ALERT_DISABLED_STRINGS:
            return ISSUE_ALERT_STATUS_DISABLED
    return ISSUE_ALERT_STATUS_UNKNOWN


# ── Metric alert dataset taxonomy (Sentry message 3 of 8) ───────────────────
#
# Confirmed via Sentry's ``sentry.snuba.dataset.Dataset`` enum (imported
# directly by the AlertRuleSerializer) that "dataset" is a bounded,
# Snuba-backed enum, not a free-form string — safe to categorize
# directly rather than sanitize.

DATASET_CATEGORY_ERRORS = "errors"
DATASET_CATEGORY_TRANSACTIONS = "transactions"
DATASET_CATEGORY_SESSIONS = "sessions"
DATASET_CATEGORY_METRICS = "metrics"
DATASET_CATEGORY_GENERIC_METRICS = "generic_metrics"
DATASET_CATEGORY_REPLAYS = "replays"
DATASET_CATEGORY_OTHER = "other"
DATASET_CATEGORY_UNKNOWN = "unknown"

_DATASET_KNOWN_VALUES = frozenset({
    "events", "errors", "transactions", "discover", "sessions", "metrics",
    "generic_metrics", "generic-metrics", "replays", "search_issues", "issue_platform",
})


def categorize_dataset(raw_dataset: object) -> str:
    """Map a raw Sentry/Snuba dataset string to a bounded category.
    Missing/non-string is UNKNOWN; a real but unrecognized dataset string
    is OTHER (distinct from UNKNOWN — see the platform-category
    precedent in this module)."""
    if not isinstance(raw_dataset, str) or not raw_dataset.strip():
        return DATASET_CATEGORY_UNKNOWN
    candidate = raw_dataset.strip().lower().replace("-", "_")
    if candidate in ("events", "errors", "issue_platform", "search_issues"):
        return DATASET_CATEGORY_ERRORS
    if candidate in ("transactions", "discover"):
        return DATASET_CATEGORY_TRANSACTIONS
    if candidate == "sessions":
        return DATASET_CATEGORY_SESSIONS
    if candidate == "generic_metrics":
        return DATASET_CATEGORY_GENERIC_METRICS
    if candidate == "metrics":
        return DATASET_CATEGORY_METRICS
    if candidate == "replays":
        return DATASET_CATEGORY_REPLAYS
    if candidate in _DATASET_KNOWN_VALUES:
        return DATASET_CATEGORY_OTHER
    return DATASET_CATEGORY_OTHER


# ── Metric alert aggregate taxonomy (Sentry message 3 of 8) ─────────────────
#
# The raw ``aggregate`` field is a Snuba function expression (e.g.
# "count()", "p95(transaction.duration)", "failure_rate()") that may
# reference project-specific tag/field names — this connector never
# retains the raw expression, only a bounded category derived from the
# outermost function name, per the task's "sanitized/bounded expression"
# guidance.

AGGREGATE_CATEGORY_COUNT = "count"
AGGREGATE_CATEGORY_PERCENTILE = "percentile"
AGGREGATE_CATEGORY_FAILURE_RATE = "failure_rate"
AGGREGATE_CATEGORY_APDEX = "apdex"
AGGREGATE_CATEGORY_USER_MISERY = "user_misery"
AGGREGATE_CATEGORY_THROUGHPUT = "throughput"
AGGREGATE_CATEGORY_STATISTIC = "statistic"  # avg/min/max/sum
AGGREGATE_CATEGORY_OTHER = "other"
AGGREGATE_CATEGORY_UNKNOWN = "unknown"

_AGGREGATE_PREFIX_MAP: tuple[tuple[str, str], ...] = (
    ("count_unique", AGGREGATE_CATEGORY_COUNT),
    ("count_if", AGGREGATE_CATEGORY_COUNT),
    ("count", AGGREGATE_CATEGORY_COUNT),
    ("p50", AGGREGATE_CATEGORY_PERCENTILE),
    ("p75", AGGREGATE_CATEGORY_PERCENTILE),
    ("p90", AGGREGATE_CATEGORY_PERCENTILE),
    ("p95", AGGREGATE_CATEGORY_PERCENTILE),
    ("p99", AGGREGATE_CATEGORY_PERCENTILE),
    ("percentile", AGGREGATE_CATEGORY_PERCENTILE),
    ("failure_rate", AGGREGATE_CATEGORY_FAILURE_RATE),
    ("apdex", AGGREGATE_CATEGORY_APDEX),
    ("user_misery", AGGREGATE_CATEGORY_USER_MISERY),
    ("eps", AGGREGATE_CATEGORY_THROUGHPUT),
    ("epm", AGGREGATE_CATEGORY_THROUGHPUT),
    ("avg", AGGREGATE_CATEGORY_STATISTIC),
    ("min", AGGREGATE_CATEGORY_STATISTIC),
    ("max", AGGREGATE_CATEGORY_STATISTIC),
    ("sum", AGGREGATE_CATEGORY_STATISTIC),
)


def categorize_aggregate(raw_aggregate: object) -> str:
    """Map a raw Snuba aggregate expression to a bounded category derived
    from its outermost function name only. Missing/non-string is
    UNKNOWN; a real but unrecognized function is OTHER."""
    if not isinstance(raw_aggregate, str) or not raw_aggregate.strip():
        return AGGREGATE_CATEGORY_UNKNOWN
    candidate = raw_aggregate.strip().lower()
    for prefix, category in _AGGREGATE_PREFIX_MAP:
        if candidate.startswith(prefix):
            return category
    return AGGREGATE_CATEGORY_OTHER


# ── Environment taxonomy (Sentry message 3 of 8) ─────────────────────────────
#
# A ``null``/absent environment on a Sentry alert rule has documented,
# affirmative meaning — "all environments" — unlike most other missing
# fields in this connector, which map to UNKNOWN. This is a deliberate
# exception, called out explicitly so it is never confused with the
# general missing-is-unknown rule.

ENVIRONMENT_CATEGORY_PRODUCTION = "production"
ENVIRONMENT_CATEGORY_STAGING = "staging"
ENVIRONMENT_CATEGORY_DEVELOPMENT = "development"
ENVIRONMENT_CATEGORY_ALL = "all"
ENVIRONMENT_CATEGORY_OTHER = "other"

_ENVIRONMENT_NAME_MAP: tuple[tuple[str, str], ...] = (
    ("prod", ENVIRONMENT_CATEGORY_PRODUCTION),
    ("staging", ENVIRONMENT_CATEGORY_STAGING),
    ("stage", ENVIRONMENT_CATEGORY_STAGING),
    ("dev", ENVIRONMENT_CATEGORY_DEVELOPMENT),
)


def categorize_environment(raw_environment: object) -> str:
    """Map a raw Sentry environment name to a bounded category. ``None``
    means "all environments" (documented Sentry semantics, NOT unknown).
    A real but unrecognized environment name is OTHER."""
    if raw_environment is None:
        return ENVIRONMENT_CATEGORY_ALL
    if not isinstance(raw_environment, str) or not raw_environment.strip():
        return ENVIRONMENT_CATEGORY_ALL
    candidate = raw_environment.strip().lower()
    for needle, category in _ENVIRONMENT_NAME_MAP:
        if needle in candidate:
            return category
    return ENVIRONMENT_CATEGORY_OTHER


# ── Threshold type / detection type taxonomy (Sentry message 3 of 8) ────────
#
# Confirmed via Sentry source (``AlertRuleThresholdType``): ABOVE=0,
# BELOW=1, ABOVE_AND_BELOW=2. ``AlertRuleDetectionType`` (TextChoices):
# "static", "percent", "dynamic".

THRESHOLD_TYPE_ABOVE = "above"
THRESHOLD_TYPE_BELOW = "below"
THRESHOLD_TYPE_ABOVE_AND_BELOW = "above_and_below"
THRESHOLD_TYPE_UNKNOWN = "unknown"

_THRESHOLD_TYPE_BY_VALUE = {0: THRESHOLD_TYPE_ABOVE, 1: THRESHOLD_TYPE_BELOW, 2: THRESHOLD_TYPE_ABOVE_AND_BELOW}


def categorize_threshold_type(raw_threshold_type: object) -> str:
    """Map a raw Sentry ``AlertRuleThresholdType`` integer to a bounded
    direction category. Missing/unrecognized is UNKNOWN — comparison
    direction must never be guessed (see the Change-classification
    threshold-weakening rules, which require a deterministic direction)."""
    if isinstance(raw_threshold_type, bool):
        return THRESHOLD_TYPE_UNKNOWN
    if isinstance(raw_threshold_type, int):
        return _THRESHOLD_TYPE_BY_VALUE.get(raw_threshold_type, THRESHOLD_TYPE_UNKNOWN)
    return THRESHOLD_TYPE_UNKNOWN


DETECTION_TYPE_STATIC = "static"
DETECTION_TYPE_PERCENT = "percent"
DETECTION_TYPE_DYNAMIC = "dynamic"
DETECTION_TYPE_UNKNOWN = "unknown"

_DETECTION_TYPES = frozenset({DETECTION_TYPE_STATIC, DETECTION_TYPE_PERCENT, DETECTION_TYPE_DYNAMIC})


def categorize_detection_type(raw_detection_type: object) -> str:
    if isinstance(raw_detection_type, str):
        candidate = raw_detection_type.strip().lower()
        if candidate in _DETECTION_TYPES:
            return candidate
    return DETECTION_TYPE_UNKNOWN


# ── Issue-alert action_match / filter_match taxonomy (Sentry message 3) ─────
#
# Current official product docs (docs.sentry.io/product/alerts/alert-types/
# and the issue-alert rule builder UI) confirm exactly three documented
# values for both fields: "all", "any", "none".

MATCH_TYPE_ALL = "all"
MATCH_TYPE_ANY = "any"
MATCH_TYPE_NONE = "none"
MATCH_TYPE_UNKNOWN = "unknown"

_MATCH_TYPES = frozenset({MATCH_TYPE_ALL, MATCH_TYPE_ANY, MATCH_TYPE_NONE})


def categorize_match_type(raw_match: object) -> str:
    if isinstance(raw_match, str):
        candidate = raw_match.strip().lower()
        if candidate in _MATCH_TYPES:
            return candidate
    return MATCH_TYPE_UNKNOWN


# ── Metric alert trigger label taxonomy (Sentry message 3 of 8) ─────────────
#
# Confirmed via Sentry source (sentry/incidents/serializers/alert_rule.py):
# ``CRITICAL_TRIGGER_LABEL``/``WARNING_TRIGGER_LABEL`` are the two
# conventional trigger labels used by Sentry's own UI/API, though the
# ``label`` field itself is a free-form string (max 64 chars) at the
# model level — this connector bounds it to a category rather than
# storing the raw string.

TRIGGER_LABEL_CRITICAL = "critical"
TRIGGER_LABEL_WARNING = "warning"
TRIGGER_LABEL_OTHER = "other"
TRIGGER_LABEL_UNKNOWN = "unknown"


def categorize_trigger_label(raw_label: object) -> str:
    if not isinstance(raw_label, str) or not raw_label.strip():
        return TRIGGER_LABEL_UNKNOWN
    candidate = raw_label.strip().lower()
    if candidate == TRIGGER_LABEL_CRITICAL:
        return TRIGGER_LABEL_CRITICAL
    if candidate == TRIGGER_LABEL_WARNING:
        return TRIGGER_LABEL_WARNING
    return TRIGGER_LABEL_OTHER


# ── Alert action taxonomy (Sentry message 3 of 8) ───────────────────────────
#
# Confirmed via Sentry source (sentry/notifications/models/
# notificationaction.py, ``ActionService``): exact slugs "email",
# "pagerduty", "slack", "slack_staging", "msteams", "sentry_app",
# "sentry_notification", "opsgenie", "discord" for METRIC alert actions
# (the ``type`` field on AlertRuleTriggerAction). Issue-alert actions
# instead carry a fully-qualified Python class-path "id" string (e.g.
# "sentry.mail.actions.NotifyEmailAction") — this connector maps both
# shapes into the SAME bounded category set via substring matching on
# the issue-alert side, since no single shared enum covers both storage
# models directly.

ACTION_CATEGORY_EMAIL = "email"
ACTION_CATEGORY_SLACK = "slack"
ACTION_CATEGORY_PAGERDUTY = "pagerduty"
ACTION_CATEGORY_OPSGENIE = "opsgenie"
ACTION_CATEGORY_MSTEAMS = "msteams"
ACTION_CATEGORY_DISCORD = "discord"
ACTION_CATEGORY_SENTRY_APP = "sentry_app"
ACTION_CATEGORY_SENTRY_NOTIFICATION = "sentry_notification"
ACTION_CATEGORY_INTEGRATION_OTHER = "integration_other"
ACTION_CATEGORY_OTHER = "other"
ACTION_CATEGORY_UNKNOWN = "unknown"

_METRIC_ACTION_TYPE_MAP = {
    "email": ACTION_CATEGORY_EMAIL,
    "slack": ACTION_CATEGORY_SLACK,
    "slack_staging": ACTION_CATEGORY_SLACK,
    "pagerduty": ACTION_CATEGORY_PAGERDUTY,
    "opsgenie": ACTION_CATEGORY_OPSGENIE,
    "msteams": ACTION_CATEGORY_MSTEAMS,
    "discord": ACTION_CATEGORY_DISCORD,
    "sentry_app": ACTION_CATEGORY_SENTRY_APP,
    "sentry_notification": ACTION_CATEGORY_SENTRY_NOTIFICATION,
}


def categorize_metric_action_type(raw_type: object) -> str:
    """Categorize a metric-alert trigger action's ``type`` slug (exact
    ActionService values)."""
    if isinstance(raw_type, str):
        candidate = raw_type.strip().lower()
        if candidate in _METRIC_ACTION_TYPE_MAP:
            return _METRIC_ACTION_TYPE_MAP[candidate]
    return ACTION_CATEGORY_UNKNOWN


_ISSUE_ACTION_ID_SUBSTRING_MAP: tuple[tuple[str, str], ...] = (
    ("mail.actions", ACTION_CATEGORY_EMAIL),
    ("notifyemail", ACTION_CATEGORY_EMAIL),
    ("slack", ACTION_CATEGORY_SLACK),
    ("pagerduty", ACTION_CATEGORY_PAGERDUTY),
    ("opsgenie", ACTION_CATEGORY_OPSGENIE),
    ("msteams", ACTION_CATEGORY_MSTEAMS),
    ("discord", ACTION_CATEGORY_DISCORD),
    ("sentry_app", ACTION_CATEGORY_SENTRY_APP),
    ("sentryapp", ACTION_CATEGORY_SENTRY_APP),
)


def categorize_issue_action_id(raw_id: object) -> str:
    """Categorize an issue-alert action's fully-qualified class-path
    ``id`` string via substring matching. A recognized-but-uncategorized
    integration class path (e.g. Jira/GitHub ticket-creation actions)
    maps to INTEGRATION_OTHER, distinct from a genuinely missing/
    malformed id (UNKNOWN)."""
    if not isinstance(raw_id, str) or not raw_id.strip():
        return ACTION_CATEGORY_UNKNOWN
    candidate = raw_id.strip().lower()
    for needle, category in _ISSUE_ACTION_ID_SUBSTRING_MAP:
        if needle in candidate:
            return category
    if "notify" in candidate or "action" in candidate:
        return ACTION_CATEGORY_INTEGRATION_OTHER
    return ACTION_CATEGORY_OTHER


# ── Alert action target-type taxonomy (Sentry message 3 of 8) ───────────────
#
# Confirmed via Sentry source (``ActionTarget``): SPECIFIC=0, USER=1,
# TEAM=2, SENTRY_APP=3, ISSUE_OWNERS=4, with documented string choices
# "specific"/"user"/"team"/"sentry_app"/"issue_owners". A "specific"
# target's identifier is a direct external reference (an email address,
# a Slack channel ID, etc.) — this connector NEVER stores that raw
# identifier; only user/team targets resolve to an already-known,
# message-2 stable ID.

TARGET_TYPE_SPECIFIC = "specific"
TARGET_TYPE_USER = "user"
TARGET_TYPE_TEAM = "team"
TARGET_TYPE_SENTRY_APP = "sentry_app"
TARGET_TYPE_ISSUE_OWNERS = "issue_owners"
TARGET_TYPE_UNKNOWN = "unknown"

_TARGET_TYPES = frozenset({
    TARGET_TYPE_SPECIFIC, TARGET_TYPE_USER, TARGET_TYPE_TEAM,
    TARGET_TYPE_SENTRY_APP, TARGET_TYPE_ISSUE_OWNERS,
})


def categorize_target_type(raw_target_type: object) -> str:
    if isinstance(raw_target_type, str):
        candidate = raw_target_type.strip().lower()
        if candidate in _TARGET_TYPES:
            return candidate
    return TARGET_TYPE_UNKNOWN


# ── Owner (actor) taxonomy (Sentry message 3 of 8) ──────────────────────────
#
# Alert-rule "owner" is a Sentry Actor reference (team or user), returned
# as a string like "team:123" or "user:456" (or a bare numeric ID in
# older shapes) — this connector never stores a raw display name, only
# the actor type + stable ID.

OWNER_TYPE_TEAM = "team"
OWNER_TYPE_USER = "user"
OWNER_TYPE_UNKNOWN = "unknown"


def categorize_owner(raw_owner: object) -> tuple[str, "Optional[str]"]:
    """Return ``(owner_type_category, owner_stable_id)`` from a raw
    Sentry actor reference string (e.g. ``"team:123"``/``"user:456"``).
    Returns ``(OWNER_TYPE_UNKNOWN, None)`` for anything else — never
    guesses a type from a bare, unprefixed numeric ID."""
    if isinstance(raw_owner, str) and ":" in raw_owner:
        prefix, _, ident = raw_owner.partition(":")
        prefix = prefix.strip().lower()
        ident = ident.strip()
        if prefix == "team" and ident:
            return OWNER_TYPE_TEAM, ident
        if prefix == "user" and ident:
            return OWNER_TYPE_USER, ident
    return OWNER_TYPE_UNKNOWN, None


# ── Object status taxonomy (Sentry message 4 of 8) ──────────────────────────
#
# Confirmed via Sentry source (sentry/integrations/api/serializers/models/
# integration.py: ``"status": obj.get_status_display()``, and
# sentry/api/endpoints/organization_repository_details.py) that
# integrations and repositories share the SAME ``ObjectStatus`` enum
# already confirmed for projects in message 2 (active/disabled/
# pending_deletion/deletion_in_progress) — reuses PROJECT_STATUSES rather
# than redefining an identical frozenset under a new name.

OBJECT_STATUS_ACTIVE = PROJECT_STATUS_ACTIVE
OBJECT_STATUS_DISABLED = PROJECT_STATUS_DISABLED
OBJECT_STATUS_PENDING_DELETION = PROJECT_STATUS_PENDING_DELETION
OBJECT_STATUS_DELETION_IN_PROGRESS = PROJECT_STATUS_DELETION_IN_PROGRESS
OBJECT_STATUS_UNKNOWN = PROJECT_STATUS_UNKNOWN


def categorize_object_status(raw_status: object) -> str:
    """Map a raw Sentry ``ObjectStatus`` display string (shared by
    integrations, repositories, and projects) to a bounded category.
    Missing/unrecognized is UNKNOWN — never assumed active."""
    return categorize_project_status(raw_status)


# ── Integration/repository provider taxonomy (Sentry message 4 of 8) ───────
#
# Sentry's integration/repository ``provider`` identifiers are
# implementation-defined slugs (e.g. "github", "gitlab", "vsts" for Azure
# DevOps, sometimes prefixed "integrations:github" for legacy plugin-vs-
# integration distinction) — this connector matches by substring rather
# than exact value so both prefixed and unprefixed forms categorize
# correctly, mirroring the message-3 issue-alert-action-id categorization
# precedent.

PROVIDER_CATEGORY_GITHUB = "github"
PROVIDER_CATEGORY_GITLAB = "gitlab"
PROVIDER_CATEGORY_BITBUCKET = "bitbucket"
PROVIDER_CATEGORY_AZURE_DEVOPS = "azure_devops"
PROVIDER_CATEGORY_SLACK = "slack"
PROVIDER_CATEGORY_JIRA = "jira"
PROVIDER_CATEGORY_VERCEL = "vercel"
PROVIDER_CATEGORY_PAGERDUTY = "pagerduty"
PROVIDER_CATEGORY_OPSGENIE = "opsgenie"
PROVIDER_CATEGORY_MSTEAMS = "msteams"
PROVIDER_CATEGORY_DISCORD = "discord"
PROVIDER_CATEGORY_OTHER = "other"
PROVIDER_CATEGORY_UNKNOWN = "unknown"

_PROVIDER_SUBSTRING_MAP: tuple[tuple[str, str], ...] = (
    ("github", PROVIDER_CATEGORY_GITHUB),
    ("gitlab", PROVIDER_CATEGORY_GITLAB),
    ("bitbucket", PROVIDER_CATEGORY_BITBUCKET),
    ("vsts", PROVIDER_CATEGORY_AZURE_DEVOPS),
    ("azure", PROVIDER_CATEGORY_AZURE_DEVOPS),
    ("slack", PROVIDER_CATEGORY_SLACK),
    ("jira", PROVIDER_CATEGORY_JIRA),
    ("vercel", PROVIDER_CATEGORY_VERCEL),
    ("pagerduty", PROVIDER_CATEGORY_PAGERDUTY),
    ("opsgenie", PROVIDER_CATEGORY_OPSGENIE),
    ("msteams", PROVIDER_CATEGORY_MSTEAMS),
    ("discord", PROVIDER_CATEGORY_DISCORD),
)


def categorize_provider(raw_provider: object) -> str:
    """Map a raw Sentry integration/repository provider identifier to a
    bounded category via substring matching. Missing/non-string is
    UNKNOWN; a real but unrecognized provider string is OTHER."""
    if not isinstance(raw_provider, str) or not raw_provider.strip():
        return PROVIDER_CATEGORY_UNKNOWN
    candidate = raw_provider.strip().lower()
    for needle, category in _PROVIDER_SUBSTRING_MAP:
        if needle in candidate:
            return category
    return PROVIDER_CATEGORY_OTHER


# ── Ownership-rule matcher taxonomy (Sentry message 4 of 8) ─────────────────
#
# Confirmed via Sentry source (sentry/issues/ownership/grammar.py):
# matcher type constants URL="url", PATH="path", MODULE="module",
# CODEOWNERS="codeowners", plus a dynamic ``tags.<tagname>`` prefix for
# event-tag matchers — this connector categorizes any ``tags.`` prefix as
# TAG (the specific tag name is discarded, matching the "bounded
# category over raw value" boundary applied throughout this module).

MATCHER_CATEGORY_URL = "url"
MATCHER_CATEGORY_PATH = "path"
MATCHER_CATEGORY_MODULE = "module"
MATCHER_CATEGORY_CODEOWNERS = "codeowners"
MATCHER_CATEGORY_TAG = "tag"
MATCHER_CATEGORY_UNKNOWN = "unknown"

_MATCHER_EXACT_MAP = {
    "url": MATCHER_CATEGORY_URL,
    "path": MATCHER_CATEGORY_PATH,
    "module": MATCHER_CATEGORY_MODULE,
    "codeowners": MATCHER_CATEGORY_CODEOWNERS,
}


def categorize_matcher(raw_matcher_type: object) -> str:
    """Map a raw ownership-rule matcher type string to a bounded
    category. Missing/unrecognized is UNKNOWN — never guessed."""
    if isinstance(raw_matcher_type, str):
        candidate = raw_matcher_type.strip().lower()
        if candidate in _MATCHER_EXACT_MAP:
            return _MATCHER_EXACT_MAP[candidate]
        if candidate.startswith("tags."):
            return MATCHER_CATEGORY_TAG
    return MATCHER_CATEGORY_UNKNOWN


# ── Ownership auto-assignment taxonomy (Sentry message 4 of 8) ─────────────
#
# Confirmed via Sentry source (sentry/api/serializers/models/
# projectownership.py): the API returns one of exactly three
# human-readable ``autoAssignment`` display strings, derived from two
# underlying booleans (``auto_assignment`` / ``suspect_committer_auto_
# assignment``) that this connector never re-derives independently —
# only the documented display string is categorized.

AUTO_ASSIGNMENT_SUSPECT_COMMITS = "suspect_commits"
AUTO_ASSIGNMENT_ISSUE_OWNER = "issue_owner"
AUTO_ASSIGNMENT_OFF = "off"
AUTO_ASSIGNMENT_UNKNOWN = "unknown"

_AUTO_ASSIGNMENT_MAP = {
    "auto assign to suspect commits": AUTO_ASSIGNMENT_SUSPECT_COMMITS,
    "auto assign to issue owner": AUTO_ASSIGNMENT_ISSUE_OWNER,
    "turn off auto-assignment": AUTO_ASSIGNMENT_OFF,
}


def categorize_auto_assignment(raw_auto_assignment: object) -> str:
    if isinstance(raw_auto_assignment, str):
        candidate = raw_auto_assignment.strip().lower()
        if candidate in _AUTO_ASSIGNMENT_MAP:
            return _AUTO_ASSIGNMENT_MAP[candidate]
    return AUTO_ASSIGNMENT_UNKNOWN


# ── Privilege tier taxonomy (Sentry message 5 of 8) ─────────────────────────
#
# Confirmed via current official docs
# (https://docs.sentry.io/organization/membership/, accessed this
# message): Owner and Manager both "can perform Team Admin actions
# without needing to join the team" — the documented basis for
# organization-wide project access below. Admin "automatically
# assume[s] the Team Admin role for teams they join" (NOT org-wide by
# default) but can create/remove teams and projects and edit global
# integrations. Member access is team-mediated only ("access projects
# their teams own"). Billing has no project/team/integration authority
# at all — billing/compliance only. Mirrors the Okta/Entra precedent
# (``PRIVILEGE_TIER_*`` + ``highest_privilege_tier()``): a known tier
# always outranks unknown — unknown is the floor, never silently
# coerced to low/ordinary.

PRIVILEGE_TIER_CRITICAL = "critical"
PRIVILEGE_TIER_HIGH = "high"
PRIVILEGE_TIER_MEDIUM = "medium"
PRIVILEGE_TIER_LOW = "low"
PRIVILEGE_TIER_UNKNOWN = "unknown"

PRIVILEGE_TIERS = frozenset({
    PRIVILEGE_TIER_CRITICAL, PRIVILEGE_TIER_HIGH, PRIVILEGE_TIER_MEDIUM,
    PRIVILEGE_TIER_LOW, PRIVILEGE_TIER_UNKNOWN,
})

# Ranks are internal ordering helpers for `highest_privilege_tier()`
# comparisons only — never persisted. UNKNOWN sits at the floor (rank 0)
# so any real, known tier always outranks it.
_PRIVILEGE_TIER_RANK: dict = {
    PRIVILEGE_TIER_UNKNOWN: 0,
    PRIVILEGE_TIER_LOW: 1,
    PRIVILEGE_TIER_MEDIUM: 2,
    PRIVILEGE_TIER_HIGH: 3,
    PRIVILEGE_TIER_CRITICAL: 4,
}

# Owner: "unrestricted access to the organization, its data, and its
# settings" + billing/plan changes -> CRITICAL (the single most powerful
# documented role). Manager: "full management access to all teams and
# projects" + member management, but not billing/plan changes -> HIGH.
# Admin: can create/remove teams/projects and edit global integrations,
# but is NOT org-wide by default and can no longer be assigned on
# Business/Enterprise plans -> MEDIUM. Member: team-mediated access only
# -> LOW. Billing: no project/team/integration authority -> LOW (never
# inflated merely for being "non-member" — see the module docstring's
# billing-role guidance). Unknown: never guessed -> UNKNOWN.
_ORG_ROLE_TIER: dict = {
    "owner": PRIVILEGE_TIER_CRITICAL,
    "manager": PRIVILEGE_TIER_HIGH,
    "admin": PRIVILEGE_TIER_MEDIUM,
    "member": PRIVILEGE_TIER_LOW,
    "billing": PRIVILEGE_TIER_LOW,
}

# Team Admin authority is team-SCOPED, never organization-wide — an
# ordinary member (org role "member"/"billing"/unknown) who is a Team
# Admin for at least one team gains bounded, team-scoped authority. This
# is deliberately capped below MEDIUM's org-role meaning (Admin's
# organization-level team/project creation authority) since a Team Admin
# only controls their own team(s), not the organization.
TEAM_ADMIN_CONTRIBUTION_TIER = PRIVILEGE_TIER_MEDIUM

# Organization roles documented as granting Team-Admin-without-joining
# (i.e. implicit access to every team's projects, regardless of actual
# team membership) — see the doc-comment above this section.
_ORG_WIDE_ACCESS_ROLES = frozenset({"owner", "manager"})


def privilege_tier_for_org_role(org_role_category: object) -> str:
    """Tier for a normalized ``org_role_category`` string (message-2's
    ``categorize_org_role()`` output). Unrecognized/unknown values return
    ``PRIVILEGE_TIER_UNKNOWN`` — never guessed from role-name substrings."""
    if isinstance(org_role_category, str):
        return _ORG_ROLE_TIER.get(org_role_category, PRIVILEGE_TIER_UNKNOWN)
    return PRIVILEGE_TIER_UNKNOWN


def highest_privilege_tier(tiers: "list") -> str:
    """Return the highest-ranked tier in ``tiers``, or unknown if empty.

    A known tier always outranks ``unknown`` (rank 0 is the floor, not
    the ceiling) — a member holding one documented HIGH-tier role and one
    piece of unresolvable evidence is reported as ``high``, not
    ``unknown``, because the known evidence is more informative.
    """
    if not tiers:
        return PRIVILEGE_TIER_UNKNOWN
    return max(tiers, key=lambda t: _PRIVILEGE_TIER_RANK.get(t, -1))


def organization_wide_access_for_org_role(org_role_category: object) -> "Optional[bool]":
    """Return whether ``org_role_category`` documentedly grants implicit,
    organization-wide project access (Team Admin actions without joining
    any team). Returns ``None`` for an unknown/unrecognized role — never
    ``False`` — since we cannot rule out organization-wide access for a
    role whose semantics are unresolved."""
    if not isinstance(org_role_category, str) or org_role_category == ORG_ROLE_UNKNOWN:
        return None
    return org_role_category in _ORG_WIDE_ACCESS_ROLES


# ── Integration/repository control-context taxonomy (Sentry message 5) ─────
#
# Confirmed via current official docs
# (https://docs.sentry.io/organization/membership/): Owner/Manager have
# full integration and repository management authority (edit global
# integrations, remove repositories). Admin can "edit Global
# Integrations" (integration authority) but no documented per-repository
# removal authority beyond that. Member "can add repositories (through
# GitHub integrations)" — a narrow, documented ADD-only capability, not
# full control. Billing has no documented integration/repository
# authority at all.

CONTROL_CONTEXT_FULL = "full"
CONTROL_CONTEXT_INTEGRATION_ONLY = "integration_only"
CONTROL_CONTEXT_ADD_ONLY = "add_only"
CONTROL_CONTEXT_NONE = "none"
CONTROL_CONTEXT_UNKNOWN = "unknown"

_INTEGRATION_CONTROL_BY_ROLE: dict = {
    "owner": CONTROL_CONTEXT_FULL,
    "manager": CONTROL_CONTEXT_FULL,
    "admin": CONTROL_CONTEXT_INTEGRATION_ONLY,
    "member": CONTROL_CONTEXT_NONE,
    "billing": CONTROL_CONTEXT_NONE,
}

_REPOSITORY_CONTROL_BY_ROLE: dict = {
    "owner": CONTROL_CONTEXT_FULL,
    "manager": CONTROL_CONTEXT_FULL,
    "admin": CONTROL_CONTEXT_INTEGRATION_ONLY,
    "member": CONTROL_CONTEXT_ADD_ONLY,
    "billing": CONTROL_CONTEXT_NONE,
}


def categorize_integration_control(org_role_category: object) -> str:
    if isinstance(org_role_category, str) and org_role_category in _INTEGRATION_CONTROL_BY_ROLE:
        return _INTEGRATION_CONTROL_BY_ROLE[org_role_category]
    return CONTROL_CONTEXT_UNKNOWN


def categorize_repository_control(org_role_category: object) -> str:
    if isinstance(org_role_category, str) and org_role_category in _REPOSITORY_CONTROL_BY_ROLE:
        return _REPOSITORY_CONTROL_BY_ROLE[org_role_category]
    return CONTROL_CONTEXT_UNKNOWN


# ── Routing-context taxonomy (Sentry message 5 of 8) ────────────────────────
#
# ``completeness`` on a routing-context record reuses the SAME
# FAMILY_COMPLETE/FAMILY_PARTIAL/FAMILY_DENIED/FAMILY_UNAVAILABLE
# taxonomy defined above (never a new, redundant enum) — a resolved
# target is always ``FAMILY_COMPLETE`` (positive evidence stands on its
# own regardless of unrelated family gaps); an UNRESOLVED target inherits
# the completeness of the source family that would have proven it either
# way, so an unresolved target is only ever reported as a confirmed
# orphan when that source family was itself FAMILY_COMPLETE.

ROUTING_CONTEXT_TYPE_OWNERSHIP_RULE = "ownership_rule"
ROUTING_CONTEXT_TYPE_ALERT_ACTION = "alert_action"
