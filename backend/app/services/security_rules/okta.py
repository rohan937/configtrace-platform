"""Okta security exposure rules (Okta message 6 of 8).

Turns the normalized Okta posture collected by messages 1-5 into static
Security Findings: "what risky Okta posture exists right now?" — distinct
from Change classification (``risk_rules/okta.py``), which answers "what
changed?". A rule here evaluates CURRENT STATE only; it never reads Change
history.

Every rule fires only on explicit, reliable normalized fields produced by
the Okta connector (app/connectors/okta.py + okta_schema.py, messages
1-5). Evidence is metadata-only: safe labels/categories, counts, booleans,
and opaque identifiers. Never included in evidence: API tokens, passwords,
password hashes, MFA/OTP secrets, recovery codes, private keys, raw
condition/action/permission payloads, resource-set URLs, or arbitrary user
profile data — matching the connector's own permanent sensitive-data
boundary (see okta_schema.py module docstring).

Claim discipline
-----------------
These are configuration-posture findings that warrant review, not a
confirmed compromise. Titles/descriptions state what is CONFIGURED
("is assigned", "does not require", "allows"), never "compromised",
"attacker", "exploited", "stolen", or "unauthorized". Severity reflects
review priority, not confirmed impact.

Unknown-state discipline
-------------------------
Every rule that reads a category/boolean field derived from
message-1-5 taxonomies fires ONLY on an explicit risky value.
``None``/``"unknown"`` is never treated as risky — see each rule's
docstring for the specific unknown value it refuses to fire on. Findings
based on absence-of-a-record (a tenant-wide "there is no X") are
deliberately NOT implemented in this message where they would require a
family-completeness lookup this evaluator's per-record interface cannot
safely perform — see "Deferred Okta rules" below.

Record types consumed
----------------------
Privileged identity : okta_privileged_identity, okta_privileged_group,
                       okta_admin_role, okta_user_admin_role_assignment,
                       okta_group_admin_role_assignment
Authentication       : okta_policy_rule, okta_authenticator
Password             : okta_policy (PASSWORD type only)
Applications          : okta_application, okta_application_group_assignment,
                       okta_application_user_assignment

Deferred Okta rules (intentionally NOT implemented — see message-6 report)
---------------------------------------------------------------------------
* Generic "scoped administrator privilege assigned" for APP_ADMIN/
  USER_ADMIN/GROUP_ADMIN/MOBILE_ADMIN/HELP_DESK_ADMIN — a normal
  enterprise legitimately has many scoped admins; a bare inventory
  Finding would be noise. ``okta_unscoped_admin_role_assignment`` (below)
  instead flags the specific risky COMBINATION (a normally-scoped role
  type granted without any scoping).
* "Unknown custom role privilege" / "unknown built-in role type" as a
  Finding — unknown coverage is a diagnostic/completeness concern, never
  a risk claim on its own (an unknown permission set is not evidence of
  danger).
* "Read-only administrator assigned" — READ_ONLY_ADMIN/REPORT_ADMIN are
  explicitly non-write-capable; flagging their mere existence would be
  pure inventory noise.
* "Locked identity retains administrative privilege" — LOCKED_OUT is a
  transient, typically self-resolving state; the suspended/deprovisioned
  rules already cover the durable cases with real security value.
* "Policy is inactive" — many inactive policies are normal (staged,
  legacy, or intentionally superseded); this message only flags weak
  CURRENT/active posture, never inactivity alone.
* "Password lifetime is unbounded" — 2026 guidance (NIST SP 800-63B) does
  not recommend forced periodic password expiration; a Finding here would
  be misleading legacy-compliance pressure, not a security improvement.
* "SAML assertion encryption disabled" — encryption is not universally
  required for SAML assertions (many valid deployments rely on
  transport-layer TLS alone); flagging it without deployment context would
  overclaim. Response/assertion SIGNING (which IS broadly expected) are
  covered instead.
* Application-assignment inventory Findings ("user assigned to app") —
  normal inventory, not risk. Only the deterministic Everyone-group
  assignment case is covered (``okta_app_assigned_to_everyone_group``).
* Tenant-wide "no phishing-resistant authenticator exists" /
  "no MFA policy found" aggregate absence rules — meaningful only when
  the relevant record family's collection is known-complete, and this
  evaluator's per-record ``evaluate(record)`` interface has no access to
  ``okta_organization.family_completeness`` from a policy/authenticator
  record. Implementing this safely would require a connector-side
  aggregate/rollup record (as message 5 did for privileged identity/
  group) — deferred; see the message-6 report's gap list.
* "All-users sign-on policy allows no-MFA access while Super
  Administrators exist" — the single highest-value composite rule
  candidate raised for this message. Deferred for the same reason as
  above: it is a genuine cross-RECORD join (a policy rule's posture
  combined with the existence of privileged identities elsewhere in the
  tenant), and this evaluator only ever sees one record at a time. Adding
  it safely requires the CONNECTOR to pre-derive the combined signal onto
  one record (like ``okta_privileged_identity`` itself was derived in
  message 5) — that is collection/normalization scope, not Findings
  scope, so it is deferred rather than implemented unsoundly.
* Ordinary group membership / suspended-or-deprovisioned identity holding
  only ORDINARY group memberships — not security-significant on its own;
  only privilege/entitlement combinations (admin roles, app assignments)
  are treated as Findings for lifecycle state.
* Network-zone ("any network") and default session-lifetime posture —
  Okta's own defaults for the vast majority of tenants; flagging the
  common default would be high-noise with low signal.
"""

from __future__ import annotations

from typing import Any

from app.connectors.okta_schema import (
    OKTA_ADMIN_ROLE,
    OKTA_APPLICATION,
    OKTA_APPLICATION_GROUP_ASSIGNMENT,
    OKTA_APPLICATION_USER_ASSIGNMENT,
    OKTA_AUTHENTICATOR,
    OKTA_GROUP_ADMIN_ROLE_ASSIGNMENT,
    OKTA_POLICY,
    OKTA_POLICY_RULE,
    OKTA_PRIVILEGED_GROUP,
    OKTA_PRIVILEGED_IDENTITY,
    OKTA_USER_ADMIN_ROLE_ASSIGNMENT,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule keys ────────────────────────────────────────────────────────────────

# Privileged identities / admin roles (12)
_RULE_SUPER_ADMIN_ASSIGNED = "okta_super_admin_assigned"
_RULE_HIGH_TIER_ADMIN_ASSIGNED = "okta_high_tier_admin_assigned"
_RULE_CUSTOM_ADMIN_ROLE_HIGH_RISK = "okta_custom_admin_role_high_risk"
_RULE_ADMIN_ROLE_BROAD_RESOURCE_SET = "okta_admin_role_broad_resource_set"
_RULE_UNSCOPED_ADMIN_ROLE_ASSIGNMENT = "okta_unscoped_admin_role_assignment"
_RULE_DEPROVISIONED_RETAINS_ADMIN = "okta_deprovisioned_identity_retains_admin_privilege"
_RULE_SUSPENDED_RETAINS_ADMIN = "okta_suspended_identity_retains_admin_privilege"
_RULE_DORMANT_PRIVILEGED_IDENTITY = "okta_dormant_privileged_identity"
_RULE_NEVER_USED_PRIVILEGED_IDENTITY = "okta_never_used_privileged_identity"
_RULE_PRIVILEGED_GROUP_GRANTS_SUPER_ADMIN = "okta_privileged_group_grants_super_admin"
_RULE_PRIVILEGED_GROUP_GRANTS_HIGH_TIER = "okta_privileged_group_grants_high_tier_admin"
_RULE_BROAD_PRIVILEGED_GROUP = "okta_broad_privileged_group"

# Authentication / MFA (5)
_RULE_SIGNON_MFA_NOT_REQUIRED = "okta_signon_mfa_not_required"
_RULE_SIGNON_MFA_OPTIONAL = "okta_signon_mfa_optional"
_RULE_BROAD_ALLOW_WITHOUT_MFA = "okta_broad_allow_rule_without_mfa"
_RULE_PHISHING_RESISTANT_NOT_REQUIRED = "okta_phishing_resistant_not_required"
_RULE_WEAK_AUTHENTICATOR_ENABLED = "okta_weak_authenticator_enabled"

# Password policy (4)
_RULE_PASSWORD_WEAK_MIN_LENGTH = "okta_password_policy_weak_min_length"
_RULE_PASSWORD_NO_LOCKOUT = "okta_password_policy_no_lockout"
_RULE_PASSWORD_NO_HISTORY = "okta_password_policy_no_history"
_RULE_PASSWORD_NO_COMPLEXITY = "okta_password_policy_no_complexity"

# Applications / SSO (7)
_RULE_OIDC_WILDCARD_REDIRECT = "okta_oidc_wildcard_redirect"
_RULE_OIDC_HTTP_REDIRECT = "okta_oidc_http_redirect"
_RULE_OIDC_CUSTOM_SCHEME_NON_NATIVE = "okta_oidc_custom_scheme_redirect_non_native"
_RULE_SAML_RESPONSE_SIGNING_DISABLED = "okta_saml_response_signing_disabled"
_RULE_SAML_ASSERTION_SIGNING_DISABLED = "okta_saml_assertion_signing_disabled"
_RULE_WEAK_TOKEN_ENDPOINT_AUTH = "okta_weak_token_endpoint_auth"
_RULE_APP_ASSIGNED_TO_EVERYONE_GROUP = "okta_app_assigned_to_everyone_group"

# Identity lifecycle / entitlement (2)
_RULE_DEPROVISIONED_RETAINS_APP_ASSIGNMENT = "okta_deprovisioned_user_retains_app_assignment"
_RULE_SUSPENDED_RETAINS_APP_ASSIGNMENT = "okta_suspended_user_retains_app_assignment"

# ── Fixed vocab ──────────────────────────────────────────────────────────────

_HIGH_OR_CRITICAL_TIERS = frozenset({"critical", "high"})
_SCOPED_ROLE_TYPES = frozenset({"APP_ADMIN", "USER_ADMIN", "GROUP_ADMIN"})
_WEAK_AUTHENTICATOR_KEYS = frozenset({"phone_number", "email"})
_BROAD_GROUP_MEMBERSHIP_CATEGORIES = frozenset({"21-100", "100+"})


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Dispatch a normalized Okta record to the relevant rule(s)."""
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == OKTA_PRIVILEGED_IDENTITY:
        return _eval_privileged_identity(record)
    if rtype == OKTA_PRIVILEGED_GROUP:
        return _eval_privileged_group(record)
    if rtype == OKTA_ADMIN_ROLE:
        return _eval_admin_role(record)
    if rtype in (OKTA_USER_ADMIN_ROLE_ASSIGNMENT, OKTA_GROUP_ADMIN_ROLE_ASSIGNMENT):
        return _eval_admin_role_assignment(record)
    if rtype == OKTA_POLICY_RULE:
        return _eval_policy_rule(record)
    if rtype == OKTA_AUTHENTICATOR:
        return _eval_authenticator(record)
    if rtype == OKTA_POLICY:
        return _eval_policy(record)
    if rtype == OKTA_APPLICATION:
        return _eval_application(record)
    if rtype == OKTA_APPLICATION_GROUP_ASSIGNMENT:
        return _eval_app_group_assignment(record)
    if rtype == OKTA_APPLICATION_USER_ASSIGNMENT:
        return _eval_app_user_assignment(record)
    return []


def _evidence_base(record: dict[str, Any]) -> dict[str, Any]:
    return {"tenant_id": get_str(record, "tenant_id")}


# ── Privileged identity ──────────────────────────────────────────────────────


def _eval_privileged_identity(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    login = get_str(record, "login")
    user_status = get_str(record, "user_status")
    tier = record.get("highest_privilege_tier")

    if record.get("has_super_admin") is True:
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_SUPER_ADMIN_ASSIGNED,
            finding_key=make_finding_key(_RULE_SUPER_ADMIN_ASSIGNED, record_id),
            severity="critical",
            title="Super Administrator privilege assigned",
            description="A user holds the Okta Super Administrator role, the highest tenant-wide administrative privilege.",
            evidence={**evidence, "login": login, "user_status": user_status, "privilege_tier": tier},
            remediation={
                "summary": "Review whether this identity requires Super Administrator access.",
                "steps": [
                    "Confirm the assignment was intentional and is still required.",
                    "Remove or reduce the role if tenant-wide administrative access is unnecessary.",
                    "Okta Admin Console -> Security -> Administrators.",
                ],
            },
            record_id=record_id,
        ))
    elif record.get("has_high_privilege") is True:
        # Exclusion: a Super Admin is never ALSO reported as a generic
        # high-tier admin for the same identity — the more specific rule wins.
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_HIGH_TIER_ADMIN_ASSIGNED,
            finding_key=make_finding_key(_RULE_HIGH_TIER_ADMIN_ASSIGNED, record_id),
            severity="high",
            title="High-privilege administrator assigned",
            description="A user holds a high-tier Okta administrator role (Org Administrator, API Access Management Administrator, or an equivalent high-tier custom role).",
            evidence={**evidence, "login": login, "user_status": user_status, "privilege_tier": tier},
            remediation={
                "summary": "Review whether this identity requires high-tier administrative access.",
                "steps": [
                    "Confirm the assignment matches this person's current responsibilities.",
                    "Consider a narrower built-in or custom role if full high-tier access is not required.",
                    "Okta Admin Console -> Security -> Administrators.",
                ],
            },
            record_id=record_id,
        ))

    if user_status == "DEPROVISIONED" and tier in ("critical", "high", "medium"):
        severity = "high" if tier in _HIGH_OR_CRITICAL_TIERS else "medium"
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_DEPROVISIONED_RETAINS_ADMIN,
            finding_key=make_finding_key(_RULE_DEPROVISIONED_RETAINS_ADMIN, record_id),
            severity=severity,
            title="Deprovisioned identity retains administrative privilege",
            description="A deprovisioned Okta identity still has an administrator role assignment on record.",
            evidence={**evidence, "login": login, "user_status": user_status, "privilege_tier": tier},
            remediation={
                "summary": "Remove administrative role assignments from deprovisioned identities.",
                "steps": [
                    "Confirm the identity is intentionally deprovisioned.",
                    "Remove its administrator role assignment(s).",
                    "Okta Admin Console -> Security -> Administrators.",
                ],
            },
            record_id=record_id,
        ))
    elif user_status == "SUSPENDED" and tier in ("critical", "high", "medium"):
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_SUSPENDED_RETAINS_ADMIN,
            finding_key=make_finding_key(_RULE_SUSPENDED_RETAINS_ADMIN, record_id),
            severity="medium",
            title="Suspended identity retains administrative privilege",
            description="A suspended Okta identity's administrator role assignment remains in place. Access is currently restricted by the suspension, but the entitlement would become effective again if the identity is reactivated.",
            evidence={**evidence, "login": login, "user_status": user_status, "privilege_tier": tier},
            remediation={
                "summary": "Review whether the administrator role should be removed while the identity is suspended.",
                "steps": [
                    "Confirm the suspension is intentional and expected to persist.",
                    "Remove the administrator role assignment if it will not be needed on reactivation.",
                    "Okta Admin Console -> Security -> Administrators.",
                ],
            },
            record_id=record_id,
        ))

    dormant = record.get("dormant_privileged_category")
    if dormant == "privileged_never_logged_in":
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_NEVER_USED_PRIVILEGED_IDENTITY,
            finding_key=make_finding_key(_RULE_NEVER_USED_PRIVILEGED_IDENTITY, record_id),
            severity="medium",
            title="Privileged identity has never signed in",
            description="A user holds an Okta administrator role but has never signed in.",
            evidence={**evidence, "login": login, "user_status": user_status, "privilege_tier": tier},
            remediation={
                "summary": "Confirm the administrator role is still needed for this identity.",
                "steps": [
                    "Verify the account is expected to be used.",
                    "Remove the administrator role if it was provisioned in error or is no longer needed.",
                ],
            },
            record_id=record_id,
        ))
    elif dormant == "privileged_stale_login" and tier in ("critical", "high", "medium"):
        severity = "medium" if tier in _HIGH_OR_CRITICAL_TIERS else "low"
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_DORMANT_PRIVILEGED_IDENTITY,
            finding_key=make_finding_key(_RULE_DORMANT_PRIVILEGED_IDENTITY, record_id),
            severity=severity,
            title="Privileged identity has stale sign-in activity",
            description="A user holds an Okta administrator role but has not signed in recently.",
            evidence={**evidence, "login": login, "user_status": user_status, "privilege_tier": tier},
            remediation={
                "summary": "Review whether this administrator role is still actively needed.",
                "steps": [
                    "Confirm the identity still requires administrative access.",
                    "Remove the role if the account is no longer actively used for administration.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── Privileged group ─────────────────────────────────────────────────────────


def _eval_privileged_group(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    group_name = get_str(record, "group_name")
    tier = record.get("highest_privilege_tier")
    member_count = record.get("member_count")

    if tier == "critical":
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_PRIVILEGED_GROUP_GRANTS_SUPER_ADMIN,
            finding_key=make_finding_key(_RULE_PRIVILEGED_GROUP_GRANTS_SUPER_ADMIN, record_id),
            severity="critical",
            title="Group grants Super Administrator privilege",
            description="A group carries a direct Super Administrator role assignment; every current and future member of this group inherits that privilege.",
            evidence={**evidence, "group_name": group_name, "member_count": member_count},
            remediation={
                "summary": "Review whether group-based Super Administrator delegation is necessary.",
                "steps": [
                    "Confirm the group's membership is tightly controlled.",
                    "Consider direct, individually-reviewed assignments instead of a group grant.",
                    "Okta Admin Console -> Security -> Administrators -> Groups.",
                ],
            },
            record_id=record_id,
        ))
    elif tier == "high":
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_PRIVILEGED_GROUP_GRANTS_HIGH_TIER,
            finding_key=make_finding_key(_RULE_PRIVILEGED_GROUP_GRANTS_HIGH_TIER, record_id),
            severity="high",
            title="Group grants high-tier administrator privilege",
            description="A group carries a direct high-tier administrator role assignment (Org Administrator, API Access Management Administrator, or an equivalent high-tier custom role).",
            evidence={**evidence, "group_name": group_name, "member_count": member_count},
            remediation={
                "summary": "Review whether group-based high-tier delegation is necessary.",
                "steps": [
                    "Confirm the group's membership is tightly controlled.",
                    "Consider a narrower role if full high-tier access is not required for every member.",
                ],
            },
            record_id=record_id,
        ))

    membership_bucket = record.get("member_count_category")
    if membership_bucket is None and isinstance(member_count, int):
        # okta_privileged_group doesn't itself carry a category field —
        # derive it locally using the same bucket semantics as
        # categorize_membership_count (0/1-5/6-20/21-100/100+), rather
        # than inventing a new threshold.
        if member_count > 100:
            membership_bucket = "100+"
        elif member_count > 20:
            membership_bucket = "21-100"
    if tier in _HIGH_OR_CRITICAL_TIERS and membership_bucket in _BROAD_GROUP_MEMBERSHIP_CATEGORIES:
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_BROAD_PRIVILEGED_GROUP,
            finding_key=make_finding_key(_RULE_BROAD_PRIVILEGED_GROUP, record_id),
            severity="high",
            title="Privileged group has broad membership",
            description="A group carrying a high-tier or Super Administrator role assignment has a broad membership (21 or more members).",
            evidence={**evidence, "group_name": group_name, "member_count": member_count, "privilege_tier": tier},
            remediation={
                "summary": "Narrow membership of this privileged group or reduce its granted privilege tier.",
                "steps": [
                    "Review the group's membership and remove members who do not require administrative access.",
                    "Consider splitting broad membership into a smaller, dedicated administrator group.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── Admin role (catalog entry) ───────────────────────────────────────────────


def _eval_admin_role(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    role_label = get_str(record, "role_label")
    tier = record.get("privilege_tier")

    if record.get("custom") is True and tier in _HIGH_OR_CRITICAL_TIERS:
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_CUSTOM_ADMIN_ROLE_HIGH_RISK,
            finding_key=make_finding_key(_RULE_CUSTOM_ADMIN_ROLE_HIGH_RISK, record_id),
            severity=tier,  # "critical" or "high"
            title="High-risk custom administrator role",
            description="A custom Okta administrator role grants permissions that map to a high or critical privilege tier.",
            evidence={**evidence, "role_label": role_label, "privilege_tier": tier, "permissions_count": record.get("permissions_count")},
            remediation={
                "summary": "Review the permissions granted by this custom role.",
                "steps": [
                    "Confirm the role's permission set matches its intended, narrower purpose.",
                    "Split the role or remove high-impact permissions if full tenant-wide impact is not required.",
                    "Okta Admin Console -> Security -> Administrators -> Roles.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── Admin role assignment (user or group) ───────────────────────────────────


def _eval_admin_role_assignment(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    role_type = get_str(record, "role_type")
    tier = record.get("privilege_tier")
    scope = record.get("assignment_scope_category")
    resource_set_scope = record.get("resource_set_scope_category")
    principal_label = get_str(record, "group_name") if record.get("record_type") == OKTA_GROUP_ADMIN_ROLE_ASSIGNMENT else get_str(record, "user_login")

    if record.get("custom") is True and resource_set_scope == "all_resources" and tier in ("critical", "high", "medium"):
        severity = "high" if tier in _HIGH_OR_CRITICAL_TIERS else "medium"
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_ADMIN_ROLE_BROAD_RESOURCE_SET,
            finding_key=make_finding_key(_RULE_ADMIN_ROLE_BROAD_RESOURCE_SET, record_id),
            severity=severity,
            title="Custom administrator role assigned with an all-resources scope",
            description="A custom administrator role assignment is scoped to all resources of its type, rather than a specific subset.",
            evidence={**evidence, "role_type": role_type, "privilege_tier": tier, "resource_set_scope_category": resource_set_scope},
            remediation={
                "summary": "Narrow the resource set bound to this assignment if tenant-wide scope is not required.",
                "steps": [
                    "Review the resource set attached to this assignment.",
                    "Bind a narrower resource set covering only the applications/groups/users that require it.",
                ],
            },
            record_id=record_id,
        ))
    elif role_type in _SCOPED_ROLE_TYPES and scope == "all":
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_UNSCOPED_ADMIN_ROLE_ASSIGNMENT,
            finding_key=make_finding_key(_RULE_UNSCOPED_ADMIN_ROLE_ASSIGNMENT, record_id),
            severity="medium",
            title="Scoped administrator role assigned without any scoping",
            description=f"A {role_type} assignment, which supports being scoped to specific applications/users/groups, was granted with no scoping applied — an all-resources grant.",
            evidence={**evidence, "role_type": role_type, "assignment_scope_category": scope, "principal": principal_label},
            remediation={
                "summary": "Scope this role assignment to only the specific resources that require it.",
                "steps": [
                    "Review whether tenant-wide scope for this role type is actually required.",
                    "Re-create the assignment with an explicit, narrower target if not.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── Policy rule (sign-on) ────────────────────────────────────────────────────


def _eval_policy_rule(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    policy_name = get_str(record, "policy_name")
    rule_name = get_str(record, "rule_name")
    mfa = record.get("mfa_requirement_category")
    access = record.get("access_category")
    scope = record.get("scope_category")

    broad_no_mfa = access == "ALLOW" and mfa == "none" and scope == "all_users"
    if broad_no_mfa:
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_BROAD_ALLOW_WITHOUT_MFA,
            finding_key=make_finding_key(_RULE_BROAD_ALLOW_WITHOUT_MFA, record_id),
            severity="high",
            title="Broad sign-on rule allows access without MFA",
            description="A sign-on rule targeting all users allows access and does not require an additional authentication factor.",
            evidence={**evidence, "policy": policy_name, "rule": rule_name, "scope": scope, "mfa_requirement": mfa},
            remediation={
                "summary": "Require an additional authenticator in this sign-on rule.",
                "steps": [
                    "Edit the sign-on rule to require an additional factor.",
                    "Okta Admin Console -> Security -> Authentication Policies.",
                ],
            },
            record_id=record_id,
        ))
    elif mfa == "none":
        # Superseded by the broader, more specific rule above for the exact
        # same underlying weak posture — avoid firing both on one record.
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_SIGNON_MFA_NOT_REQUIRED,
            finding_key=make_finding_key(_RULE_SIGNON_MFA_NOT_REQUIRED, record_id),
            severity="high",
            title="Sign-on policy does not require MFA",
            description="A sign-on rule does not require an additional authentication factor.",
            evidence={**evidence, "policy": policy_name, "rule": rule_name, "mfa_requirement": mfa},
            remediation={
                "summary": "Require an additional authenticator in the applicable Okta sign-on policy.",
                "steps": [
                    "Edit the sign-on rule to require an additional factor.",
                    "Okta Admin Console -> Security -> Authentication Policies.",
                ],
            },
            record_id=record_id,
        ))
    elif mfa == "optional":
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_SIGNON_MFA_OPTIONAL,
            finding_key=make_finding_key(_RULE_SIGNON_MFA_OPTIONAL, record_id),
            severity="medium",
            title="Sign-on policy makes MFA optional",
            description="A sign-on rule allows, but does not require, an additional authentication factor.",
            evidence={**evidence, "policy": policy_name, "rule": rule_name, "mfa_requirement": mfa},
            remediation={
                "summary": "Consider requiring (not just allowing) an additional authenticator.",
                "steps": [
                    "Edit the sign-on rule to require an additional factor rather than making it optional.",
                    "Okta Admin Console -> Security -> Authentication Policies.",
                ],
            },
            record_id=record_id,
        ))

    if record.get("phishing_resistant_category") == "not_phishing_resistant":
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_PHISHING_RESISTANT_NOT_REQUIRED,
            finding_key=make_finding_key(_RULE_PHISHING_RESISTANT_NOT_REQUIRED, record_id),
            severity="medium",
            title="Sign-on policy does not require phishing-resistant authentication",
            description="A sign-on rule does not require a phishing-resistant authenticator (e.g. WebAuthn/FIDO2 security key).",
            evidence={**evidence, "policy": policy_name, "rule": rule_name},
            remediation={
                "summary": "Consider requiring a phishing-resistant authenticator for this rule's scope.",
                "steps": [
                    "Add a phishing-resistant factor requirement (e.g. FIDO2/WebAuthn) for sensitive access.",
                    "Okta Admin Console -> Security -> Authentication Policies.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── Authenticator ─────────────────────────────────────────────────────────


def _eval_authenticator(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    key = record.get("key")
    name = get_str(record, "name")

    if record.get("active") is True and key in _WEAK_AUTHENTICATOR_KEYS:
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_WEAK_AUTHENTICATOR_ENABLED,
            finding_key=make_finding_key(_RULE_WEAK_AUTHENTICATOR_ENABLED, record_id),
            severity="low",
            title="SMS, phone, or email authenticator is enabled",
            description=f"The {key} authenticator is enabled. This factor type is weaker than possession/phishing-resistant factors and is a common account-recovery/social-engineering target.",
            evidence={**evidence, "authenticator_key": key, "name": name},
            remediation={
                "summary": "Confirm this authenticator is intentional (e.g. for account recovery) and consider requiring a stronger factor for primary authentication.",
                "steps": [
                    "Review where this authenticator is used across sign-on and enrollment policies.",
                    "Prefer WebAuthn/FIDO2 or Okta Verify for primary authentication where feasible.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── Policy (password) ────────────────────────────────────────────────────────


def _eval_policy(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    if record.get("policy_type") != "PASSWORD":
        return out
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    policy_name = get_str(record, "policy_name")

    if record.get("password_min_length_category") == "weak":
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_PASSWORD_WEAK_MIN_LENGTH,
            finding_key=make_finding_key(_RULE_PASSWORD_WEAK_MIN_LENGTH, record_id),
            severity="high",
            title="Password policy minimum length is weak",
            description="The password policy's minimum required length is below a modern baseline (8 characters).",
            evidence={**evidence, "policy": policy_name, "password_min_length": record.get("password_min_length")},
            remediation={
                "summary": "Increase the minimum required password length.",
                "steps": [
                    "Raise the minimum password length (14+ characters is a widely-recommended modern baseline).",
                    "Okta Admin Console -> Security -> Authentication Policies -> Password.",
                ],
            },
            record_id=record_id,
        ))

    if record.get("password_lockout_present") is False:
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_PASSWORD_NO_LOCKOUT,
            finding_key=make_finding_key(_RULE_PASSWORD_NO_LOCKOUT, record_id),
            severity="medium",
            title="Password policy has no lockout control",
            description="The password policy does not lock an account after repeated failed sign-in attempts.",
            evidence={**evidence, "policy": policy_name},
            remediation={
                "summary": "Enable an account lockout threshold.",
                "steps": ["Configure a maximum sign-in attempts threshold in the password policy."],
            },
            record_id=record_id,
        ))

    if record.get("password_history_present") is False:
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_PASSWORD_NO_HISTORY,
            finding_key=make_finding_key(_RULE_PASSWORD_NO_HISTORY, record_id),
            severity="medium",
            title="Password policy has no password history requirement",
            description="The password policy does not prevent reuse of recent passwords.",
            evidence={**evidence, "policy": policy_name},
            remediation={
                "summary": "Enable a password history requirement to prevent immediate reuse.",
                "steps": ["Configure a password-history count in the password policy."],
            },
            record_id=record_id,
        ))

    if record.get("password_complexity_required") is False:
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_PASSWORD_NO_COMPLEXITY,
            finding_key=make_finding_key(_RULE_PASSWORD_NO_COMPLEXITY, record_id),
            severity="low",
            title="Password policy does not require character complexity",
            description="The password policy does not require a mix of uppercase, lowercase, numeric, and symbol characters. Modern guidance (e.g. NIST SP 800-63B) emphasizes length over composition rules, so this is a lower-priority, factual configuration note rather than a strong indicator of weakness.",
            evidence={**evidence, "policy": policy_name},
            remediation={
                "summary": "Consider whether a longer minimum length would be a more effective control than composition rules.",
                "steps": ["Review the password policy's length and composition settings together."],
            },
            record_id=record_id,
        ))

    return out


# ── Application ───────────────────────────────────────────────────────────


def _eval_application(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    label = get_str(record, "label")

    if record.get("wildcard_redirect_present") is True:
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_OIDC_WILDCARD_REDIRECT,
            finding_key=make_finding_key(_RULE_OIDC_WILDCARD_REDIRECT, record_id),
            severity="high",
            title="OIDC application allows a wildcard redirect URI",
            description="An OIDC application's configured redirect URIs include a wildcard pattern.",
            evidence={**evidence, "application": label},
            remediation={
                "summary": "Replace wildcard redirect patterns with explicit trusted redirect URIs.",
                "steps": [
                    "Enumerate the exact redirect URIs the application legitimately uses.",
                    "Okta Admin Console -> Applications -> select application -> General.",
                ],
            },
            record_id=record_id,
        ))

    http_count = record.get("http_redirect_count")
    if isinstance(http_count, int) and http_count > 0:
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_OIDC_HTTP_REDIRECT,
            finding_key=make_finding_key(_RULE_OIDC_HTTP_REDIRECT, record_id),
            severity="medium",
            title="OIDC application allows an HTTP redirect URI",
            description="An OIDC application's configured redirect URIs include a plain-HTTP (non-TLS) URI.",
            evidence={**evidence, "application": label, "http_redirect_count": http_count},
            remediation={
                "summary": "Use HTTPS redirect URIs.",
                "steps": ["Replace HTTP redirect URIs with HTTPS equivalents."],
            },
            record_id=record_id,
        ))

    custom_scheme_count = record.get("custom_scheme_redirect_count")
    app_type = record.get("app_type_category")
    if isinstance(custom_scheme_count, int) and custom_scheme_count > 0 and app_type in ("web", "browser", "service"):
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_OIDC_CUSTOM_SCHEME_NON_NATIVE,
            finding_key=make_finding_key(_RULE_OIDC_CUSTOM_SCHEME_NON_NATIVE, record_id),
            severity="medium",
            title="Non-native OIDC application uses a custom-scheme redirect",
            description=f"An application configured as app type '{app_type}' (not native) uses a custom URI scheme redirect, which is typically expected only for native/mobile OAuth clients.",
            evidence={**evidence, "application": label, "app_type_category": app_type, "custom_scheme_redirect_count": custom_scheme_count},
            remediation={
                "summary": "Confirm the custom-scheme redirect is intentional for this application type.",
                "steps": ["Verify the application type is set correctly and the redirect is expected for its platform."],
            },
            record_id=record_id,
        ))

    if record.get("saml_response_signed") is False:
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_SAML_RESPONSE_SIGNING_DISABLED,
            finding_key=make_finding_key(_RULE_SAML_RESPONSE_SIGNING_DISABLED, record_id),
            severity="medium",
            title="SAML application does not sign responses",
            description="A SAML application is configured without response signing.",
            evidence={**evidence, "application": label},
            remediation={
                "summary": "Enable SAML response signing.",
                "steps": ["Okta Admin Console -> Applications -> select application -> Sign On -> SAML settings."],
            },
            record_id=record_id,
        ))

    if record.get("saml_assertion_signed") is False:
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_SAML_ASSERTION_SIGNING_DISABLED,
            finding_key=make_finding_key(_RULE_SAML_ASSERTION_SIGNING_DISABLED, record_id),
            severity="medium",
            title="SAML application does not sign assertions",
            description="A SAML application is configured without assertion signing.",
            evidence={**evidence, "application": label},
            remediation={
                "summary": "Enable SAML assertion signing.",
                "steps": ["Okta Admin Console -> Applications -> select application -> Sign On -> SAML settings."],
            },
            record_id=record_id,
        ))

    if record.get("token_endpoint_auth_method_category") == "none":
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_WEAK_TOKEN_ENDPOINT_AUTH,
            finding_key=make_finding_key(_RULE_WEAK_TOKEN_ENDPOINT_AUTH, record_id),
            severity="medium",
            title="OIDC application uses no client authentication at the token endpoint",
            description="An OIDC application's token endpoint authentication method is 'none' (a public client with no client credential).",
            evidence={**evidence, "application": label},
            remediation={
                "summary": "Use a confidential client authentication method where the application architecture allows it.",
                "steps": ["Review whether this application can use client_secret or private_key_jwt authentication instead of 'none'."],
            },
            record_id=record_id,
        ))

    return out


# ── Application group assignment ─────────────────────────────────────────────


def _eval_app_group_assignment(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    if record.get("everyone_group") is not True:
        return out
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    out.append(FindingCandidate(
        provider="okta",
        rule_key=_RULE_APP_ASSIGNED_TO_EVERYONE_GROUP,
        finding_key=make_finding_key(_RULE_APP_ASSIGNED_TO_EVERYONE_GROUP, record_id),
        severity="medium",
        title="Application is assigned to the Everyone group",
        description="An application is assigned to Okta's built-in Everyone group, granting access to every user in the tenant.",
        evidence={**evidence, "application": get_str(record, "app_label")},
        remediation={
            "summary": "Confirm tenant-wide access to this application is intended.",
            "steps": [
                "Review whether this application should be scoped to specific groups instead.",
                "Okta Admin Console -> Applications -> select application -> Assignments.",
            ],
        },
        record_id=record_id,
    ))
    return out


# ── Application user assignment ──────────────────────────────────────────────


def _eval_app_user_assignment(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    user_status = get_str(record, "user_status")
    app_label = get_str(record, "app_label")

    if user_status == "DEPROVISIONED":
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_DEPROVISIONED_RETAINS_APP_ASSIGNMENT,
            finding_key=make_finding_key(_RULE_DEPROVISIONED_RETAINS_APP_ASSIGNMENT, record_id),
            severity="medium",
            title="Deprovisioned user retains an application assignment",
            description="A deprovisioned Okta identity still has an active application assignment on record.",
            evidence={**evidence, "application": app_label, "user_status": user_status},
            remediation={
                "summary": "Remove application assignments from deprovisioned identities.",
                "steps": ["Unassign the application from this identity.", "Okta Admin Console -> Applications -> select application -> Assignments."],
            },
            record_id=record_id,
        ))
    elif user_status == "SUSPENDED":
        out.append(FindingCandidate(
            provider="okta",
            rule_key=_RULE_SUSPENDED_RETAINS_APP_ASSIGNMENT,
            finding_key=make_finding_key(_RULE_SUSPENDED_RETAINS_APP_ASSIGNMENT, record_id),
            severity="low",
            title="Suspended user retains an application assignment",
            description="A suspended Okta identity's application assignment remains in place. Access is currently restricted by the suspension, but the entitlement would become effective again on reactivation.",
            evidence={**evidence, "application": app_label, "user_status": user_status},
            remediation={
                "summary": "Review whether the application assignment should be removed while the identity is suspended.",
                "steps": ["Confirm the suspension is expected to persist and remove the assignment if it will not be needed on reactivation."],
            },
            record_id=record_id,
        ))

    return out
