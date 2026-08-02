"""Sentry security exposure rules (Sentry message 6 of 8).

Turns the normalized/derived Sentry posture collected by messages 1-5 into
static Security Findings: "what risky Sentry configuration exists right
now?" — distinct from Change classification (``risk_rules/sentry.py``),
which answers "what changed?". A rule here evaluates CURRENT STATE only; it
never reads Change history.

Every rule fires only on explicit, reliable normalized/derived fields
produced by the Sentry connector (app/connectors/sentry.py +
sentry_schema.py, messages 1-5) — never on undocumented assumptions. Role
authority semantics are grounded in current docs.sentry.io/organization/
membership/ (verified this message): Owner has "full access to the
organization, its data, and settings" and can perform Team Admin actions on
any team without joining it; Manager has "full management access to all
teams and projects" and the same org-wide Team Admin authority; Admin can
"edit global integrations, manage projects, and add/remove teams" and only
auto-assumes Team Admin for teams it joins (not org-wide); Member can "view
most data ... and act on issues" with team-mediated project access only;
Billing has payment/compliance authority only, no project/team/integration
authority. Ownership-rule evaluation is grounded in docs.sentry.io/product/
issues/ownership-rules/ (verified this message): Sentry "requires all
referenced teams and users to have project access before rules can be
saved" — so an unresolved target on an already-stored rule reflects a LATER
removal of that team/user's access, not an invalid rule from the start;
Sentry "automatically ignores rules that are missing team/user mappings" at
match time, so an unresolved target silently stops routing rather than
erroring.

Evidence is metadata-only: safe labels/categories, counts, booleans, and
opaque identifiers. Never included in evidence: auth tokens, member emails,
webhook URLs, DSNs, raw ownership rule text, event/issue data, or
repository URLs — matching the connector's own permanent sensitive-data
boundary (see sentry_schema.py module docstring).

Claim discipline
-----------------
These are configuration-posture findings that warrant review, not a
confirmed compromise. Titles/descriptions state what is CONFIGURED ("holds",
"has no valid destination", "references"), never "compromised", "attacker",
"exploited", "breached", or "unauthorized". Severity reflects review
priority, not confirmed impact.

Unknown-state discipline
-------------------------
Every rule that reads a category/boolean/count field derived from
message-1-5 taxonomies fires ONLY on an explicit risky value. Unknown role
(``ORG_ROLE_UNKNOWN``), unknown/``None`` completeness gaps, and ``None``
counts are never treated as risky — see each rule's docstring for the
specific unknown value it refuses to fire on. A routing-target-unresolved
rule additionally requires the record's own ``completeness`` field to be
``FAMILY_COMPLETE`` (not merely "not denied") before it will claim a target
is confirmed missing — an incomplete source family means the target might
simply not have been observed yet, never a confirmed absence.

Record types consumed
----------------------
Privileged access : sentry_privileged_member, sentry_privileged_team
Alert coverage     : sentry_metric_alert_rule, sentry_issue_alert_rule
Routing            : sentry_routing_context (context_type = ownership_rule
                      or alert_action)
Repository posture : sentry_repository (status-only, no integration join)

Deferred Sentry rules (intentionally NOT implemented — see message-6 report)
------------------------------------------------------------------------------
* "Repository/code mapping references a disabled or missing organization
  integration" and "code mapping references a missing repository/project"
  (spec candidates ``sentry_repository_uses_disabled_integration``,
  ``sentry_repository_missing_integration``,
  ``sentry_code_mapping_missing_repository``,
  ``sentry_code_mapping_missing_project``) — these require joining a
  ``sentry_repository``/``sentry_code_mapping`` record against a SEPARATE
  ``sentry_organization_integration``/``sentry_repository``/
  ``sentry_project`` record. This evaluator's interface is
  ``evaluate(record) -> list[FindingCandidate]``, one record at a time, with
  no access to sibling records — the exact same architectural limit that
  led the Okta message-6 module to defer its "all-users sign-on allows
  no-MFA while Super Admins exist" composite rule. Unlike alert actions
  (which message 5's connector already denormalized onto
  ``sentry_routing_context.integration_status_category``), repositories and
  code mappings were never given an equivalent connector-side join — adding
  one is a connector-schema change, out of this message's Findings-only
  scope. Deferred, not implemented unsoundly.
* "Alert action references a missing (not merely disabled) integration"
  (spec candidate ``sentry_alert_references_missing_integration``) — the
  connector's ``sentry_routing_context.integration_status_category`` is
  ``None`` for BOTH "this action has no integration target" and "this
  action's integration_id could not be resolved"; there is no way to
  distinguish the two from the derived record alone. Only the confirmed
  case (integration resolved AND explicitly disabled) is implemented as
  ``sentry_alert_references_disabled_integration``.
* "Invalid ownership rule" (spec candidate ``sentry_ownership_rule_invalid``)
  — the Sentry API exposes no deterministic per-rule validity flag (verified
  via source citations already recorded in sentry_schema.py message 4); the
  current docs additionally confirm the API refuses to save a rule with an
  unresolved owner in the first place, so "invalid" is not a state this
  connector can observe. Not implemented — would require inferring
  invalidity from parsing failure, which is explicitly disallowed.
* "Project ownership is entirely unroutable" (spec candidate
  ``sentry_project_ownership_unroutable``) — a genuine cross-record
  aggregate (every ownership-rule target for one project is unresolved),
  which the per-record evaluator cannot compute without a connector-side
  rollup (message 5 did not build one). Deferred for the same reason as the
  repository/code-mapping joins above.
* "Project has no ownership rules" (spec candidate
  ``sentry_project_has_no_ownership_rules``) — an absence-of-a-record
  Finding requires access to per-project ``ownership_rules`` family
  completeness, which is only available at the organization-level rollup,
  not on any single record this evaluator sees. Deferred, matching the
  Okta message-6 precedent for absence-based aggregate rules.
* Billing-role privileged-member Finding — current docs establish no
  project/team/integration authority for Billing beyond payment/compliance
  visibility; flagging it would not be grounded in verified role authority.
* Standalone "member holds unknown role" / "team role unknown" Finding —
  unknown coverage is a diagnostic/completeness concern, never a risk claim
  on its own.
* Standalone "organization integration is disabled" Finding (with no
  confirmed reference from an enabled alert action) — a disabled
  integration with nothing depending on it is not itself a live risk;
  only the referenced-and-disabled combination
  (``sentry_alert_references_disabled_integration``) is implemented.
* Threshold-weakening / environment-coverage static Findings — these are
  Change-classification concerns (already covered by
  ``risk_rules/sentry.py``), not application-independent static posture;
  a "threshold too high" or "does not cover production" rule would require
  deployment-specific context this connector cannot verify.
* Multiple valid alert actions on one rule — redundant routing is
  generally positive, not risky. No Finding.
"""

from __future__ import annotations

from typing import Any

from app.connectors.sentry_schema import (
    FAMILY_COMPLETE,
    ISSUE_ALERT_STATUS_DISABLED,
    ISSUE_ALERT_STATUS_ENABLED,
    METRIC_ALERT_STATUS_DISABLED,
    METRIC_ALERT_STATUS_ENABLED,
    OBJECT_STATUS_DELETION_IN_PROGRESS,
    OBJECT_STATUS_PENDING_DELETION,
    ORG_ROLE_ADMIN,
    ORG_ROLE_MANAGER,
    ORG_ROLE_MEMBER,
    ORG_ROLE_OWNER,
    ROUTING_CONTEXT_TYPE_ALERT_ACTION,
    ROUTING_CONTEXT_TYPE_OWNERSHIP_RULE,
    SENTRY_ISSUE_ALERT_RULE,
    SENTRY_METRIC_ALERT_RULE,
    SENTRY_PRIVILEGED_MEMBER,
    SENTRY_PRIVILEGED_TEAM,
    SENTRY_REPOSITORY,
    SENTRY_ROUTING_CONTEXT,
)
from app.services.security_rules.base import FindingCandidate, get_str, make_finding_key

# ── Rule keys ────────────────────────────────────────────────────────────────

# Privileged organization members (4)
_RULE_ACTIVE_OWNER = "sentry_active_organization_owner"
_RULE_ACTIVE_MANAGER = "sentry_active_organization_manager"
_RULE_ACTIVE_ADMIN = "sentry_active_organization_admin"
_RULE_PENDING_PRIVILEGED_INVITATION = "sentry_pending_privileged_invitation"

# Composite member/team routing authority (3)
_RULE_MEMBER_BROAD_ROUTING_AUTHORITY = "sentry_member_broad_routing_authority"
_RULE_MEMBER_TEAM_ADMIN_WITHOUT_ORG_ROLE = "sentry_member_team_admin_without_org_role"
_RULE_TEAM_BROAD_ROUTING_AUTHORITY = "sentry_team_has_broad_routing_authority"

# Team integrity (1)
_RULE_TEAM_HAS_UNRESOLVED_MEMBERS = "sentry_team_has_unresolved_members"

# Alert coverage (4)
_RULE_METRIC_ALERT_UNROUTED = "sentry_metric_alert_unrouted"
_RULE_ISSUE_ALERT_UNROUTED = "sentry_issue_alert_unrouted"
_RULE_METRIC_ALERT_DISABLED_WITH_ROUTING = "sentry_metric_alert_disabled_with_routing_configured"
_RULE_ISSUE_ALERT_DISABLED_WITH_ROUTING = "sentry_issue_alert_disabled_with_routing_configured"

# Alert notification routing (4)
_RULE_ALERT_TARGETS_MISSING_TEAM = "sentry_alert_targets_missing_team"
_RULE_ALERT_TARGETS_MISSING_MEMBER = "sentry_alert_targets_missing_member"
_RULE_ALERT_REFERENCES_INACTIVE_MEMBER = "sentry_alert_references_inactive_member"
_RULE_ALERT_REFERENCES_DISABLED_INTEGRATION = "sentry_alert_references_disabled_integration"

# Ownership routing (3)
_RULE_OWNERSHIP_TARGETS_MISSING_TEAM = "sentry_ownership_targets_missing_team"
_RULE_OWNERSHIP_TARGETS_MISSING_MEMBER = "sentry_ownership_targets_missing_member"
_RULE_OWNERSHIP_TARGETS_INACTIVE_MEMBER = "sentry_ownership_targets_inactive_member"

# Configuration integrity advisory (1)
_RULE_REPOSITORY_PENDING_DELETION = "sentry_repository_pending_deletion"

_PRIVILEGED_ORG_ROLES = frozenset({ORG_ROLE_OWNER, ORG_ROLE_MANAGER, ORG_ROLE_ADMIN})
_PENDING_SEVERITY_BY_ROLE = {
    ORG_ROLE_OWNER: "high",
    ORG_ROLE_MANAGER: "high",
    ORG_ROLE_ADMIN: "medium",
}
_REPOSITORY_ADVISORY_STATUSES = frozenset({OBJECT_STATUS_PENDING_DELETION, OBJECT_STATUS_DELETION_IN_PROGRESS})


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Dispatch a normalized/derived Sentry record to the relevant rule(s)."""
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == SENTRY_PRIVILEGED_MEMBER:
        return _eval_privileged_member(record)
    if rtype == SENTRY_PRIVILEGED_TEAM:
        return _eval_privileged_team(record)
    if rtype == SENTRY_METRIC_ALERT_RULE:
        return _eval_metric_alert_rule(record)
    if rtype == SENTRY_ISSUE_ALERT_RULE:
        return _eval_issue_alert_rule(record)
    if rtype == SENTRY_ROUTING_CONTEXT:
        return _eval_routing_context(record)
    if rtype == SENTRY_REPOSITORY:
        return _eval_repository(record)
    return []


def _evidence_base(record: dict[str, Any]) -> dict[str, Any]:
    return {"organization_id": get_str(record, "organization_id")}


# ── Privileged member ────────────────────────────────────────────────────────


def _eval_privileged_member(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    member_id = get_str(record, "member_id")
    org_role = record.get("org_role_category")
    status = record.get("member_status_category")
    tier = record.get("privilege_tier")
    org_wide = record.get("organization_wide_project_access")

    base_evidence = {
        **evidence,
        "member_id": member_id,
        "org_role": org_role,
        "member_status": status,
        "privilege_tier": tier,
        "organization_wide_project_access": org_wide,
        "effective_project_count": record.get("effective_project_count"),
    }

    # Role-specific active-member rules — mutually exclusive (a member has
    # exactly one org_role_category), so at most one of owner/manager/admin
    # fires per record. No separate generic "privileged member" Finding is
    # emitted for these roles — the specific rule is the complete signal.
    if status == "active" and org_role == ORG_ROLE_OWNER:
        out.append(FindingCandidate(
            provider="sentry",
            rule_key=_RULE_ACTIVE_OWNER,
            finding_key=make_finding_key(_RULE_ACTIVE_OWNER, record_id),
            severity="critical",
            title="Organization member holds the Owner role",
            description="An active Sentry organization member holds the Owner role, which has unrestricted access to the organization, its data, and its settings.",
            evidence=base_evidence,
            remediation={
                "summary": "Review whether this member requires Owner-level authority.",
                "steps": [
                    "Confirm the assignment is intentional and still required.",
                    "Use the narrowest organization role that supports this member's responsibilities.",
                    "Sentry -> Settings -> Members.",
                ],
            },
            record_id=record_id,
        ))
    elif status == "active" and org_role == ORG_ROLE_MANAGER:
        out.append(FindingCandidate(
            provider="sentry",
            rule_key=_RULE_ACTIVE_MANAGER,
            finding_key=make_finding_key(_RULE_ACTIVE_MANAGER, record_id),
            severity="high",
            title="Organization member holds the Manager role",
            description="An active Sentry organization member holds the Manager role, which has full management access to all teams and projects and can manage organization membership.",
            evidence=base_evidence,
            remediation={
                "summary": "Review whether this member requires Manager-level authority.",
                "steps": [
                    "Confirm the assignment is intentional and still required.",
                    "Use the narrowest organization role that supports this member's responsibilities.",
                    "Sentry -> Settings -> Members.",
                ],
            },
            record_id=record_id,
        ))
    elif status == "active" and org_role == ORG_ROLE_ADMIN:
        out.append(FindingCandidate(
            provider="sentry",
            rule_key=_RULE_ACTIVE_ADMIN,
            finding_key=make_finding_key(_RULE_ACTIVE_ADMIN, record_id),
            severity="medium",
            title="Organization member holds the Admin role",
            description="An active Sentry organization member holds the Admin role, which can edit global integrations, manage projects, and add/remove teams.",
            evidence=base_evidence,
            remediation={
                "summary": "Review whether this member requires Admin-level authority.",
                "steps": [
                    "Confirm the assignment is intentional and still required.",
                    "Use the narrowest organization role that supports this member's responsibilities.",
                    "Sentry -> Settings -> Members.",
                ],
            },
            record_id=record_id,
        ))

    # Pending privileged invitation — entitlement, not active access.
    if status == "pending" and org_role in _PRIVILEGED_ORG_ROLES:
        severity = _PENDING_SEVERITY_BY_ROLE[org_role]
        out.append(FindingCandidate(
            provider="sentry",
            rule_key=_RULE_PENDING_PRIVILEGED_INVITATION,
            finding_key=make_finding_key(_RULE_PENDING_PRIVILEGED_INVITATION, record_id),
            severity=severity,
            title="Pending invitation would grant a privileged organization role",
            description=f"A pending Sentry organization invitation would grant the {org_role} role if accepted. This is an entitlement, not currently active access.",
            evidence=base_evidence,
            remediation={
                "summary": "Review or revoke the pending privileged invitation if the recipient no longer requires the requested role.",
                "steps": [
                    "Confirm the invited role matches the recipient's actual responsibilities.",
                    "Revoke the invitation if it is no longer needed.",
                    "Sentry -> Settings -> Members -> Pending Members.",
                ],
            },
            record_id=record_id,
        ))

    # Composite: an ordinary member (not owner/manager/admin) who is
    # simultaneously a resolvable alert-routing AND ownership-routing
    # target holds meaningful combined authority beyond their bare role.
    alert_targets = record.get("alert_routing_target_count")
    ownership_targets = record.get("ownership_rule_target_count")
    if (
        org_role == ORG_ROLE_MEMBER
        and isinstance(alert_targets, int) and alert_targets > 0
        and isinstance(ownership_targets, int) and ownership_targets > 0
    ):
        out.append(FindingCandidate(
            provider="sentry",
            rule_key=_RULE_MEMBER_BROAD_ROUTING_AUTHORITY,
            finding_key=make_finding_key(_RULE_MEMBER_BROAD_ROUTING_AUTHORITY, record_id),
            severity="medium",
            title="Ordinary member is a combined alert and ownership routing destination",
            description="A Sentry member with an ordinary organization role is currently a resolvable destination for both alert notifications and issue-ownership routing.",
            evidence={**base_evidence, "alert_routing_target_count": alert_targets, "ownership_rule_target_count": ownership_targets},
            remediation={
                "summary": "Confirm this member's combined routing responsibilities are still intentional.",
                "steps": ["Review the alert rules and ownership rules that target this member."],
            },
            record_id=record_id,
        ))

    # Team Admin authority without any org-level privileged role.
    team_admin_count = record.get("team_admin_team_count")
    if org_role == ORG_ROLE_MEMBER and isinstance(team_admin_count, int) and team_admin_count > 0:
        out.append(FindingCandidate(
            provider="sentry",
            rule_key=_RULE_MEMBER_TEAM_ADMIN_WITHOUT_ORG_ROLE,
            finding_key=make_finding_key(_RULE_MEMBER_TEAM_ADMIN_WITHOUT_ORG_ROLE, record_id),
            severity="medium",
            title="Member holds Team Admin authority without a privileged organization role",
            description="A Sentry member with an ordinary organization role holds the Team Admin role on at least one team, granting team-scoped membership and project management authority.",
            evidence={**base_evidence, "team_admin_team_count": team_admin_count},
            remediation={
                "summary": "Confirm Team Admin delegation is still appropriate for this member.",
                "steps": ["Review the team(s) where this member holds Team Admin."],
            },
            record_id=record_id,
        ))

    return out


# ── Privileged team ──────────────────────────────────────────────────────────


def _eval_privileged_team(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    team_id = get_str(record, "team_id")
    ownership_targets = record.get("ownership_rule_target_count")
    alert_targets = record.get("alert_action_target_count")
    unresolved = record.get("unresolved_member_count")

    if (
        isinstance(ownership_targets, int) and ownership_targets > 0
        and isinstance(alert_targets, int) and alert_targets > 0
    ):
        out.append(FindingCandidate(
            provider="sentry",
            rule_key=_RULE_TEAM_BROAD_ROUTING_AUTHORITY,
            finding_key=make_finding_key(_RULE_TEAM_BROAD_ROUTING_AUTHORITY, record_id),
            severity="medium",
            title="Team is a combined alert and ownership routing destination",
            description="A Sentry team is currently a resolvable destination for both alert notifications and issue-ownership routing.",
            evidence={**evidence, "team_id": team_id, "ownership_rule_target_count": ownership_targets, "alert_action_target_count": alert_targets},
            remediation={
                "summary": "Confirm this team's combined routing responsibilities are still intentional.",
                "steps": ["Review the alert rules and ownership rules that target this team."],
            },
            record_id=record_id,
        ))

    if isinstance(unresolved, int) and unresolved > 0:
        out.append(FindingCandidate(
            provider="sentry",
            rule_key=_RULE_TEAM_HAS_UNRESOLVED_MEMBERS,
            finding_key=make_finding_key(_RULE_TEAM_HAS_UNRESOLVED_MEMBERS, record_id),
            severity="medium",
            title="Team membership references a member ConfigTrace could not resolve",
            description="A Sentry team's recorded membership includes at least one member ID that could not be found in the complete organization member inventory.",
            evidence={**evidence, "team_id": team_id, "unresolved_member_count": unresolved},
            remediation={
                "summary": "Review this team's membership for stale or removed entries.",
                "steps": ["Sentry -> Settings -> Teams -> select team -> Members."],
            },
            record_id=record_id,
        ))

    return out


# ── Alert rules (coverage) ───────────────────────────────────────────────────


def _eval_metric_alert_rule(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    name = get_str(record, "name")
    status = record.get("status_category")
    action_count = record.get("action_count")
    base_evidence = {**evidence, "rule": name, "rule_type": "metric_alert", "action_count": action_count}

    if status == METRIC_ALERT_STATUS_ENABLED and action_count == 0:
        out.append(FindingCandidate(
            provider="sentry",
            rule_key=_RULE_METRIC_ALERT_UNROUTED,
            finding_key=make_finding_key(_RULE_METRIC_ALERT_UNROUTED, record_id),
            severity="high",
            title="Enabled metric alert rule has no notification actions",
            description="An enabled Sentry metric alert rule currently has zero configured notification actions — it cannot notify anyone when it fires.",
            evidence=base_evidence,
            remediation={
                "summary": "Add at least one valid notification action, or disable/remove the rule if it is no longer used.",
                "steps": ["Sentry -> Alerts -> Metric Alert Rules -> select rule -> Notifications."],
            },
            record_id=record_id,
        ))
    elif status == METRIC_ALERT_STATUS_DISABLED and isinstance(action_count, int) and action_count > 0:
        out.append(FindingCandidate(
            provider="sentry",
            rule_key=_RULE_METRIC_ALERT_DISABLED_WITH_ROUTING,
            finding_key=make_finding_key(_RULE_METRIC_ALERT_DISABLED_WITH_ROUTING, record_id),
            severity="low",
            title="Disabled metric alert rule retains configured notification actions",
            description="A disabled Sentry metric alert rule still has notification actions configured. The rule will not fire while disabled, but the routing configuration remains in place.",
            evidence=base_evidence,
            remediation={
                "summary": "Confirm whether this rule should remain disabled or be re-enabled/removed.",
                "steps": ["Sentry -> Alerts -> Metric Alert Rules -> select rule."],
            },
            record_id=record_id,
        ))

    return out


def _eval_issue_alert_rule(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    name = get_str(record, "name")
    status = record.get("status_category")
    action_count = record.get("action_count")
    base_evidence = {**evidence, "rule": name, "rule_type": "issue_alert", "action_count": action_count}

    if status == ISSUE_ALERT_STATUS_ENABLED and action_count == 0:
        out.append(FindingCandidate(
            provider="sentry",
            rule_key=_RULE_ISSUE_ALERT_UNROUTED,
            finding_key=make_finding_key(_RULE_ISSUE_ALERT_UNROUTED, record_id),
            severity="high",
            title="Enabled issue alert rule has no notification actions",
            description="An enabled Sentry issue alert rule currently has zero configured notification actions — it cannot notify anyone when it fires.",
            evidence=base_evidence,
            remediation={
                "summary": "Add at least one valid notification action, or disable/remove the rule if it is no longer used.",
                "steps": ["Sentry -> Alerts -> Issue Alert Rules -> select rule -> Actions."],
            },
            record_id=record_id,
        ))
    elif status == ISSUE_ALERT_STATUS_DISABLED and isinstance(action_count, int) and action_count > 0:
        out.append(FindingCandidate(
            provider="sentry",
            rule_key=_RULE_ISSUE_ALERT_DISABLED_WITH_ROUTING,
            finding_key=make_finding_key(_RULE_ISSUE_ALERT_DISABLED_WITH_ROUTING, record_id),
            severity="low",
            title="Disabled issue alert rule retains configured notification actions",
            description="A disabled Sentry issue alert rule still has notification actions configured. The rule will not fire while disabled, but the routing configuration remains in place.",
            evidence=base_evidence,
            remediation={
                "summary": "Confirm whether this rule should remain disabled or be re-enabled/removed.",
                "steps": ["Sentry -> Alerts -> Issue Alert Rules -> select rule."],
            },
            record_id=record_id,
        ))

    return out


# ── Routing context (alert-action / ownership-rule targets) ─────────────────


def _eval_routing_context(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    context_type = record.get("context_type")
    target_type = record.get("target_type_category")
    target_resolved = record.get("target_resolved")
    target_active = record.get("target_active")
    completeness = record.get("completeness")
    context_enabled = record.get("context_enabled")
    project_id = get_str(record, "project_id")
    rule_id = get_str(record, "rule_id")
    rule_type = record.get("rule_type")

    base_evidence = {
        **evidence,
        "context_type": context_type,
        "target_type": target_type,
        "project_id": project_id or None,
        "rule_id": rule_id or None,
        "rule_type": rule_type,
    }

    is_confirmed_missing = target_resolved is False and completeness == FAMILY_COMPLETE

    if context_type == ROUTING_CONTEXT_TYPE_ALERT_ACTION:
        if context_enabled is True and is_confirmed_missing and target_type == "team":
            out.append(FindingCandidate(
                provider="sentry",
                rule_key=_RULE_ALERT_TARGETS_MISSING_TEAM,
                finding_key=make_finding_key(_RULE_ALERT_TARGETS_MISSING_TEAM, record_id),
                severity="high",
                title="Enabled alert rule targets a team ConfigTrace could not find",
                description="An enabled Sentry alert rule has a notification action targeting a team that ConfigTrace could not find in the complete organization team inventory.",
                evidence=base_evidence,
                remediation={
                    "summary": "Update the alert action to reference an active Sentry team, or remove it.",
                    "steps": ["Sentry -> Alerts -> select the rule -> review notification actions."],
                },
                record_id=record_id,
            ))
        if context_enabled is True and is_confirmed_missing and target_type == "user":
            out.append(FindingCandidate(
                provider="sentry",
                rule_key=_RULE_ALERT_TARGETS_MISSING_MEMBER,
                finding_key=make_finding_key(_RULE_ALERT_TARGETS_MISSING_MEMBER, record_id),
                severity="high",
                title="Enabled alert rule targets a member ConfigTrace could not find",
                description="An enabled Sentry alert rule has a notification action targeting a member that ConfigTrace could not find in the complete organization member inventory.",
                evidence=base_evidence,
                remediation={
                    "summary": "Update the alert action to reference an active Sentry member, or remove it.",
                    "steps": ["Sentry -> Alerts -> select the rule -> review notification actions."],
                },
                record_id=record_id,
            ))
        if context_enabled is True and target_type == "user" and target_resolved is True and target_active is False:
            out.append(FindingCandidate(
                provider="sentry",
                rule_key=_RULE_ALERT_REFERENCES_INACTIVE_MEMBER,
                finding_key=make_finding_key(_RULE_ALERT_REFERENCES_INACTIVE_MEMBER, record_id),
                severity="medium",
                title="Enabled alert rule targets a member who is not active",
                description="An enabled Sentry alert rule has a notification action targeting a member whose organization membership is not currently active (pending or expired).",
                evidence=base_evidence,
                remediation={
                    "summary": "Update the alert action to reference an active member, or remove it.",
                    "steps": ["Sentry -> Alerts -> select the rule -> review notification actions."],
                },
                record_id=record_id,
            ))
        if context_enabled is True and record.get("integration_status_category") == "disabled":
            out.append(FindingCandidate(
                provider="sentry",
                rule_key=_RULE_ALERT_REFERENCES_DISABLED_INTEGRATION,
                finding_key=make_finding_key(_RULE_ALERT_REFERENCES_DISABLED_INTEGRATION, record_id),
                severity="high",
                title="Enabled alert rule references a disabled integration",
                description="An enabled Sentry alert rule has a notification action targeting an organization integration that is currently disabled.",
                evidence={**base_evidence, "integration_status": "disabled"},
                remediation={
                    "summary": "Reconnect or replace the referenced integration, or update the alert action to a valid destination.",
                    "steps": ["Sentry -> Settings -> Integrations -> reconnect the integration, or edit the alert action."],
                },
                record_id=record_id,
            ))

    elif context_type == ROUTING_CONTEXT_TYPE_OWNERSHIP_RULE:
        if context_enabled is True and is_confirmed_missing and target_type == "team":
            out.append(FindingCandidate(
                provider="sentry",
                rule_key=_RULE_OWNERSHIP_TARGETS_MISSING_TEAM,
                finding_key=make_finding_key(_RULE_OWNERSHIP_TARGETS_MISSING_TEAM, record_id),
                severity="high",
                title="Active ownership rule targets a team ConfigTrace could not find",
                description="An active Sentry issue-ownership rule references a team that ConfigTrace could not find in the complete organization team inventory.",
                evidence=base_evidence,
                remediation={
                    "summary": "Update the ownership rule to reference an active Sentry team.",
                    "steps": ["Sentry -> Settings -> Projects -> select project -> Ownership Rules."],
                },
                record_id=record_id,
            ))
        if context_enabled is True and is_confirmed_missing and target_type == "user":
            out.append(FindingCandidate(
                provider="sentry",
                rule_key=_RULE_OWNERSHIP_TARGETS_MISSING_MEMBER,
                finding_key=make_finding_key(_RULE_OWNERSHIP_TARGETS_MISSING_MEMBER, record_id),
                severity="high",
                title="Active ownership rule targets a member ConfigTrace could not find",
                description="An active Sentry issue-ownership rule references a member that ConfigTrace could not find in the complete organization member inventory.",
                evidence=base_evidence,
                remediation={
                    "summary": "Update the ownership rule to reference an active Sentry member.",
                    "steps": ["Sentry -> Settings -> Projects -> select project -> Ownership Rules."],
                },
                record_id=record_id,
            ))
        if context_enabled is True and target_type == "user" and target_resolved is True and target_active is False:
            out.append(FindingCandidate(
                provider="sentry",
                rule_key=_RULE_OWNERSHIP_TARGETS_INACTIVE_MEMBER,
                finding_key=make_finding_key(_RULE_OWNERSHIP_TARGETS_INACTIVE_MEMBER, record_id),
                severity="medium",
                title="Active ownership rule targets a member who is not active",
                description="An active Sentry issue-ownership rule references a member whose organization membership is not currently active (pending or expired).",
                evidence=base_evidence,
                remediation={
                    "summary": "Update the ownership rule to reference an active member.",
                    "steps": ["Sentry -> Settings -> Projects -> select project -> Ownership Rules."],
                },
                record_id=record_id,
            ))

    return out


# ── Repository (status-only advisory) ────────────────────────────────────────


def _eval_repository(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    if record.get("status_category") not in _REPOSITORY_ADVISORY_STATUSES:
        return out
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    out.append(FindingCandidate(
        provider="sentry",
        rule_key=_RULE_REPOSITORY_PENDING_DELETION,
        finding_key=make_finding_key(_RULE_REPOSITORY_PENDING_DELETION, record_id),
        severity="low",
        title="Repository connection is pending deletion",
        description="A Sentry repository connection is currently in a pending-deletion or deletion-in-progress state.",
        evidence={**evidence, "repository_id": get_str(record, "repository_id"), "status": record.get("status_category")},
        remediation={
            "summary": "Confirm the repository removal is intentional; any code mappings referencing it will stop resolving.",
            "steps": ["Sentry -> Settings -> Integrations -> select integration -> Repositories."],
        },
        record_id=record_id,
    ))
    return out
