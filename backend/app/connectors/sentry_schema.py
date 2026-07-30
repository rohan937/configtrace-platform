"""Sentry provider schema (Sentry message 1 of 8).

Defines the record-type constants, credential validators, and capability
taxonomy for the Sentry provider. Record types so far:

  sentry_organization    — one record per connected Sentry organization
                           (msg 1) — stable organization identity and safe
                           context metadata only, never credentials.
  sentry_api_capability  — one record per probed future-family surface
                           (msg 1) — describes whether a surface is
                           safely readable, never the surface's actual
                           data.

SECURITY: this module never handles the auth token itself — only the
non-secret organization_slug field is validated here. See ``sentry.py``'s
module docstring for the full sensitive-data boundary.

Future messages (do not implement yet — see the Sentry roadmap in the
connector module docstring):
  msg 2 — projects, teams, members, organization access, project ownership.
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

ALL_SENTRY_RECORD_TYPES = frozenset({
    SENTRY_ORGANIZATION,
    SENTRY_API_CAPABILITY,
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
