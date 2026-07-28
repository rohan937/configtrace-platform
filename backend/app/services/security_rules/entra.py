"""Microsoft Entra ID security exposure rules (Entra message 6 of 8).

Turns the normalized Entra posture collected by messages 1-5 into static
Security Findings: "what risky Microsoft Entra configuration exists right
now?" — distinct from Change classification (``risk_rules/entra.py``),
which answers "what changed?". A rule here evaluates CURRENT STATE only;
it never reads Change history.

Every rule fires only on explicit, reliable normalized fields produced by
the Entra connector (app/connectors/entra.py + entra_schema.py, messages
1-5). Evidence is metadata-only: safe labels/categories, counts, booleans,
and opaque identifiers. Never included in evidence: client secrets, access
tokens, credential secretText/key bytes, certificate bodies, phone
numbers, raw role-action lists, raw Conditional Access
conditions/grantControls, or arbitrary user profile data — matching the
connector's own permanent sensitive-data boundary (see entra_schema.py
module docstring).

Claim discipline
-----------------
These are configuration-posture findings that warrant review, not a
confirmed compromise. Titles/descriptions state what is CONFIGURED/
ASSIGNED/GRANTED, never "compromised", "attacker", "exploited", "stolen",
or "unauthorized". Severity reflects review priority, not confirmed
impact. A disabled identity's residual role assignment is described as
RETAINED entitlement, never as currently-active sign-in access.

Unknown-state discipline
-------------------------
Every rule that reads a category/boolean/tier field derived from
message-1-5 taxonomies fires ONLY on an explicit risky value.
``None``/``"unknown"`` is never treated as risky. In particular:
  * an unknown privilege tier never satisfies a High/Critical admin rule;
  * an unresolved/unknown Graph permission value never satisfies a
    known-critical-permission rule (unlike message 5's derived
    ``entra_privileged_service_principal``, which DOES surface unknown-
    tier evidence for review — that record's mere presence is not itself
    a Finding trigger here; only its EXPLICIT critical/high tier is);
  * report-only Conditional Access state never satisfies an "enforced
    protection" claim;
  * a missing/unknown MFA requirement never satisfies a no-MFA rule.

Record types consumed
----------------------
Privileged identity/role : entra_directory_role_assignment,
                            entra_privileged_identity, entra_privileged_group
Privileged service principal / Graph permission :
                            entra_privileged_service_principal,
                            entra_service_principal_app_role_assignment
Consent                   : entra_oauth2_permission_grant
Conditional Access/MFA    : entra_conditional_access_policy
Authentication methods    : entra_authentication_method,
                            entra_authentication_strength
Applications/credentials  : entra_application, entra_service_principal
Identity/group posture    : entra_application_user_assignment,
                            entra_application_group_assignment

Deferred Entra rules (intentionally NOT implemented — see message-6 report)
----------------------------------------------------------------------------
* "Role-assignable group without an actual role assignment" — eligibility
  alone is not privilege; only an actual ``entra_directory_role_assignment``
  (already covered) is a Finding-worthy signal.
* "Every Guest user" / "every multi-tenant application" / "every
  unverified-publisher app" / "every delegated consent" / "every
  application assignment" / "every disabled user" alone — normal
  inventory in most tenants; only risky COMBINATIONS are implemented.
* "No FIDO2/phishing-resistant authenticator configured" / "no legacy-
  auth block found" tenant-wide absence rules — meaningful only when the
  relevant family's collection is known-complete, and this evaluator's
  per-record ``evaluate(record)`` interface has no access to
  ``entra_organization.family_completeness``. Implementing this safely
  would require a connector-side aggregate/rollup record (as message 5
  did for privileged identity/group) — deferred, same rationale as
  Okta's identical deferred absence rules.
* "Conditional Access policy requires a non-phishing-resistant
  authentication strength" — this is a genuine cross-RECORD join (a CA
  policy's ``authentication_strength_id`` reference resolved against a
  separate ``entra_authentication_strength`` record), and this evaluator
  only ever sees one record at a time. A weaker, single-record proxy
  (``entra_authentication_strength_not_phishing_resistant``, scoped to
  CUSTOM strengths only) is implemented instead — see below.
* Temporary Access Pass lifetime/one-time-use thresholds — the current
  ``entra_authentication_method`` record does not carry TAP-specific
  lifetime/one-time-use fields (message 4 intentionally kept the record
  compact); implementing a threshold rule now would require inventing an
  undocumented threshold. Deferred pending a schema extension.
* "FIDO2 disabled" / any other authentication-method-absence rule —
  presence-based Findings are preferred over absence-based ones; disabling
  one method is not evidence the tenant lacks MFA overall.
* "Requested (not granted) high-risk permission" — ``requiredResourceAccess``
  is a requested/configured value, never a granted permission; message 3's
  own docstring already established this must never be conflated with an
  actual grant. No Finding is derived from requested-only permissions.
* "offline_access alone" — never a Finding by itself; only used as
  contextual evidence inside the broader consent-risk rules via the
  scope-tier taxonomy (which never tiers ``offline_access`` above "low").
* "Multi-tenant app registration alone" — not flagged; would require a
  cross-record join to permission/consent context to be meaningful (same
  reasoning as the CA/authentication-strength join above), deferred.
* "Privileged service principal + password credential exists" — client
  secrets are a normal, common credential type; flagging mere presence
  would be noise. A credential-EXPIRY rule is implemented instead, scoped
  to the base ``entra_application``/``entra_service_principal`` records
  (which already carry ``nearest_credential_expiry_category``) rather than
  to the derived privileged-SP rollup (which does not carry an expiry
  category field this message).
* "Guest assigned to an enterprise application" (generic) — ordinary
  inventory in most tenants; not implemented without a deterministic,
  single-record signal that the application itself is high-privilege.
"""

from __future__ import annotations

from typing import Any

from app.connectors.entra_schema import (
    CONSENT_TYPE_ALL_PRINCIPALS,
    CONSENT_TYPE_PRINCIPAL,
    ENTRA_APPLICATION,
    ENTRA_APPLICATION_GROUP_ASSIGNMENT,
    ENTRA_APPLICATION_USER_ASSIGNMENT,
    ENTRA_AUTHENTICATION_METHOD,
    ENTRA_AUTHENTICATION_STRENGTH,
    ENTRA_CONDITIONAL_ACCESS_POLICY,
    ENTRA_DIRECTORY_ROLE_ASSIGNMENT,
    ENTRA_OAUTH2_PERMISSION_GRANT,
    ENTRA_PRIVILEGED_GROUP,
    ENTRA_PRIVILEGED_IDENTITY,
    ENTRA_PRIVILEGED_SERVICE_PRINCIPAL,
    ENTRA_SERVICE_PRINCIPAL,
    ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT,
    ENTRA_PRIVILEGE_TIER_CRITICAL,
    ENTRA_PRIVILEGE_TIER_HIGH,
    ENTRA_PRIVILEGE_TIER_MEDIUM,
    PUBLISHER_UNVERIFIED,
    ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR,
    ROLE_TEMPLATE_PRIVILEGED_AUTHENTICATION_ADMINISTRATOR,
    ROLE_TEMPLATE_PRIVILEGED_ROLE_ADMINISTRATOR,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule keys ────────────────────────────────────────────────────────────────

# Privileged identities / directory roles (12)
_RULE_GLOBAL_ADMIN_ASSIGNED = "entra_global_admin_assigned"
_RULE_PRIVILEGED_ROLE_ADMINISTRATOR_ASSIGNED = "entra_privileged_role_administrator_assigned"
_RULE_PRIVILEGED_AUTHENTICATION_ADMINISTRATOR_ASSIGNED = "entra_privileged_authentication_administrator_assigned"
_RULE_HIGH_TIER_ADMIN_ASSIGNED = "entra_high_tier_admin_assigned"
_RULE_GUEST_GLOBAL_ADMIN = "entra_guest_global_admin"
_RULE_GUEST_HAS_HIGH_PRIVILEGE = "entra_guest_has_high_privilege"
_RULE_DISABLED_GUEST_RETAINS_HIGH_PRIVILEGE = "entra_disabled_guest_retains_high_privilege"
_RULE_DISABLED_IDENTITY_RETAINS_ADMIN_PRIVILEGE = "entra_disabled_identity_retains_admin_privilege"
_RULE_GROUP_HAS_GLOBAL_ADMIN = "entra_group_has_global_admin"
_RULE_GROUP_HAS_HIGH_PRIVILEGE = "entra_group_has_high_privilege"
_RULE_GUEST_MEMBER_IN_PRIVILEGED_GROUP = "entra_guest_member_in_privileged_group"
_RULE_PRIVILEGED_GROUP_BROAD_MEMBERSHIP = "entra_privileged_group_broad_membership"

# Privileged service principals / Graph permissions (12)
_RULE_SP_HAS_CRITICAL_PRIVILEGE = "entra_service_principal_has_critical_privilege"
_RULE_SP_HAS_HIGH_PRIVILEGE = "entra_service_principal_has_high_privilege"
_RULE_DISABLED_SP_RETAINS_PRIVILEGE = "entra_disabled_service_principal_retains_privilege"
_RULE_SP_CAN_MANAGE_DIRECTORY_ROLES = "entra_service_principal_can_manage_directory_roles"
_RULE_SP_CAN_MANAGE_APP_ROLE_ASSIGNMENTS = "entra_service_principal_can_manage_app_role_assignments"
_RULE_SP_CAN_GRANT_ARBITRARY_PERMISSIONS = "entra_service_principal_can_grant_arbitrary_permissions"
_RULE_SP_HAS_APPLICATION_MANAGEMENT_PERMISSION = "entra_service_principal_has_application_management_permission"
_RULE_SP_CAN_MODIFY_CONDITIONAL_ACCESS = "entra_service_principal_can_modify_conditional_access"
_RULE_SP_CAN_MODIFY_AUTHENTICATION_METHODS = "entra_service_principal_can_modify_authentication_methods"
_RULE_SP_HAS_DIRECTORY_WRITE_PERMISSION = "entra_service_principal_has_directory_write_permission"
_RULE_SP_HAS_USER_WRITE_PERMISSION = "entra_service_principal_has_user_write_permission"
_RULE_SP_HAS_GROUP_WRITE_PERMISSION = "entra_service_principal_has_group_write_permission"

# Consent / OAuth grants (5)
_RULE_TENANT_WIDE_CRITICAL_CONSENT = "entra_tenant_wide_critical_delegated_consent"
_RULE_TENANT_WIDE_HIGH_RISK_CONSENT = "entra_tenant_wide_high_risk_delegated_consent"
_RULE_USER_SCOPED_CRITICAL_CONSENT = "entra_user_scoped_critical_consent"
_RULE_USER_SCOPED_HIGH_RISK_CONSENT = "entra_user_scoped_high_risk_consent"
_RULE_EXTERNAL_UNVERIFIED_APP_TENANT_WIDE_CONSENT = "entra_external_unverified_app_tenant_wide_consent"

# Conditional Access / MFA (5)
_RULE_CA_BROAD_ACCESS_WITHOUT_MFA = "entra_ca_broad_access_without_mfa"
_RULE_CA_ACCESS_WITHOUT_MFA = "entra_ca_access_without_mfa"
_RULE_CA_MFA_OPTIONAL_WITHIN_GRANT_CONTROLS = "entra_ca_mfa_optional_within_grant_controls"
_RULE_CA_LEGACY_AUTH_NOT_BLOCKED = "entra_ca_legacy_auth_not_blocked"
_RULE_CA_REPORT_ONLY_BROAD_PROTECTION = "entra_ca_report_only_broad_protection"

# Authentication methods / strengths (2)
_RULE_WEAK_AUTHENTICATION_METHOD_ENABLED = "entra_weak_authentication_method_enabled"
_RULE_AUTH_STRENGTH_NOT_PHISHING_RESISTANT = "entra_authentication_strength_not_phishing_resistant"

# Applications / credentials (6)
_RULE_APPLICATION_WILDCARD_REDIRECT = "entra_application_wildcard_redirect"
_RULE_APPLICATION_HTTP_REDIRECT = "entra_application_http_redirect"
_RULE_APPLICATION_CUSTOM_SCHEME_REDIRECT_UNEXPECTED = "entra_application_custom_scheme_redirect_unexpected"
_RULE_APPLICATION_EXPIRED_CREDENTIAL = "entra_application_expired_credential"
_RULE_SP_EXPIRED_CREDENTIAL = "entra_service_principal_expired_credential"
_RULE_SP_ASSIGNMENT_NOT_REQUIRED = "entra_service_principal_assignment_not_required"

# Identity lifecycle / entitlement (1)
_RULE_DISABLED_USER_RETAINS_APP_ASSIGNMENT = "entra_disabled_user_retains_application_assignment"

# Groups / app assignment posture (2)
_RULE_DYNAMIC_GROUP_ASSIGNED_TO_APPLICATION = "entra_dynamic_group_assigned_to_application"
_RULE_ROLE_ASSIGNABLE_GROUP_ASSIGNED_TO_APPLICATION = "entra_role_assignable_group_assigned_to_application"

# ── Fixed vocab ──────────────────────────────────────────────────────────────

_HIGH_OR_CRITICAL_TIERS = frozenset({ENTRA_PRIVILEGE_TIER_CRITICAL, ENTRA_PRIVILEGE_TIER_HIGH})
_KNOWN_TIERS_FOR_RETENTION = frozenset({ENTRA_PRIVILEGE_TIER_CRITICAL, ENTRA_PRIVILEGE_TIER_HIGH, ENTRA_PRIVILEGE_TIER_MEDIUM})
_WEAK_AUTHENTICATION_METHOD_TYPES = frozenset({"sms", "voice"})
_BROAD_MEMBERSHIP_THRESHOLD = 20


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Dispatch a normalized Entra record to the relevant rule(s)."""
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == ENTRA_DIRECTORY_ROLE_ASSIGNMENT:
        return _eval_directory_role_assignment(record)
    if rtype == ENTRA_PRIVILEGED_IDENTITY:
        return _eval_privileged_identity(record)
    if rtype == ENTRA_PRIVILEGED_GROUP:
        return _eval_privileged_group(record)
    if rtype == ENTRA_PRIVILEGED_SERVICE_PRINCIPAL:
        return _eval_privileged_service_principal(record)
    if rtype == ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT:
        return _eval_sp_app_role_assignment(record)
    if rtype == ENTRA_OAUTH2_PERMISSION_GRANT:
        return _eval_oauth2_permission_grant(record)
    if rtype == ENTRA_CONDITIONAL_ACCESS_POLICY:
        return _eval_conditional_access_policy(record)
    if rtype == ENTRA_AUTHENTICATION_METHOD:
        return _eval_authentication_method(record)
    if rtype == ENTRA_AUTHENTICATION_STRENGTH:
        return _eval_authentication_strength(record)
    if rtype == ENTRA_APPLICATION:
        return _eval_application(record)
    if rtype == ENTRA_SERVICE_PRINCIPAL:
        return _eval_service_principal(record)
    if rtype == ENTRA_APPLICATION_USER_ASSIGNMENT:
        return _eval_app_user_assignment(record)
    if rtype == ENTRA_APPLICATION_GROUP_ASSIGNMENT:
        return _eval_app_group_assignment(record)
    return []


def _evidence_base(record: dict[str, Any]) -> dict[str, Any]:
    return {"tenant_id": get_str(record, "tenant_id")}


# ── Directory role assignment ────────────────────────────────────────────────


def _eval_directory_role_assignment(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    role_name = get_str(record, "role_name")
    role_template_id = record.get("role_template_id")
    tier = record.get("privilege_tier")
    principal_id = get_str(record, "principal_id")
    principal_type = get_str(record, "principal_type")
    scope = record.get("directory_scope_category")

    common_evidence = {
        **evidence, "role_name": role_name, "privilege_tier": tier,
        "principal_id": principal_id, "principal_type": principal_type,
        "directory_scope_category": scope,
    }

    if role_template_id == ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_GLOBAL_ADMIN_ASSIGNED,
            finding_key=make_finding_key(_RULE_GLOBAL_ADMIN_ASSIGNED, record_id),
            severity="critical",
            title="Global Administrator privilege assigned",
            description="A principal was assigned the Microsoft Entra ID Global Administrator role, the highest tenant-wide administrative privilege.",
            evidence=common_evidence,
            remediation={
                "summary": "Review whether this principal requires Global Administrator.",
                "steps": [
                    "Confirm the assignment was intentional and is still required.",
                    "Use a narrower built-in or custom role where possible.",
                    "Microsoft Entra admin center -> Roles and administrators -> Global Administrator.",
                ],
            },
            record_id=record_id,
        ))
    elif role_template_id == ROLE_TEMPLATE_PRIVILEGED_ROLE_ADMINISTRATOR:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_PRIVILEGED_ROLE_ADMINISTRATOR_ASSIGNED,
            finding_key=make_finding_key(_RULE_PRIVILEGED_ROLE_ADMINISTRATOR_ASSIGNED, record_id),
            severity="critical",
            title="Privileged Role Administrator privilege assigned",
            description="A principal was assigned the Privileged Role Administrator role, which can manage and assign directory roles (including Global Administrator) to any principal.",
            evidence=common_evidence,
            remediation={
                "summary": "Review whether this principal requires Privileged Role Administrator.",
                "steps": [
                    "Confirm the assignment was intentional and is still required.",
                    "This role can grant itself or others further privilege — review its holders carefully.",
                    "Microsoft Entra admin center -> Roles and administrators -> Privileged Role Administrator.",
                ],
            },
            record_id=record_id,
        ))
    elif role_template_id == ROLE_TEMPLATE_PRIVILEGED_AUTHENTICATION_ADMINISTRATOR:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_PRIVILEGED_AUTHENTICATION_ADMINISTRATOR_ASSIGNED,
            finding_key=make_finding_key(_RULE_PRIVILEGED_AUTHENTICATION_ADMINISTRATOR_ASSIGNED, record_id),
            severity="critical",
            title="Privileged Authentication Administrator privilege assigned",
            description="A principal was assigned the Privileged Authentication Administrator role, which can reset authentication methods and credentials for ANY user, including other administrators.",
            evidence=common_evidence,
            remediation={
                "summary": "Review whether this principal requires Privileged Authentication Administrator.",
                "steps": [
                    "Confirm the assignment was intentional and is still required.",
                    "This role can affect the credentials of other administrators — review its holders carefully.",
                    "Microsoft Entra admin center -> Roles and administrators -> Privileged Authentication Administrator.",
                ],
            },
            record_id=record_id,
        ))
    elif tier == ENTRA_PRIVILEGE_TIER_HIGH:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_HIGH_TIER_ADMIN_ASSIGNED,
            finding_key=make_finding_key(_RULE_HIGH_TIER_ADMIN_ASSIGNED, record_id),
            severity="high",
            title="High-tier administrator role assigned",
            description="A principal was assigned a high-tier Microsoft Entra ID directory role (e.g. Application Administrator, Cloud Application Administrator, Conditional Access Administrator, Authentication Administrator, or an equivalent high-tier custom role).",
            evidence=common_evidence,
            remediation={
                "summary": "Review whether this principal requires high-tier administrative access.",
                "steps": [
                    "Confirm the assignment matches this principal's current responsibilities.",
                    "Consider a narrower built-in or custom role if full high-tier access is not required.",
                    "Microsoft Entra admin center -> Roles and administrators.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── Privileged identity ──────────────────────────────────────────────────────


def _eval_privileged_identity(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    upn = get_str(record, "user_principal_name")
    tier = record.get("highest_privilege_tier")
    account_enabled_category = record.get("account_enabled_category")
    guest = record.get("guest")
    common_evidence = {**evidence, "user_principal_name": upn, "privilege_tier": tier, "account_enabled_category": account_enabled_category}

    if guest is True and record.get("has_global_admin") is True:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_GUEST_GLOBAL_ADMIN,
            finding_key=make_finding_key(_RULE_GUEST_GLOBAL_ADMIN, record_id),
            severity="critical",
            title="Guest user holds Global Administrator privilege",
            description="A guest (external) user holds the Microsoft Entra ID Global Administrator role.",
            evidence=common_evidence,
            remediation={
                "summary": "Review whether a guest account should hold Global Administrator.",
                "steps": [
                    "Confirm this is an intentional, tightly-controlled external administrator arrangement.",
                    "Consider using a tenant-native administrator account instead where feasible.",
                    "Microsoft Entra admin center -> Roles and administrators -> Global Administrator.",
                ],
            },
            record_id=record_id,
        ))
    elif guest is True and record.get("has_high_privilege") is True:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_GUEST_HAS_HIGH_PRIVILEGE,
            finding_key=make_finding_key(_RULE_GUEST_HAS_HIGH_PRIVILEGE, record_id),
            severity="high",
            title="Guest user holds high-tier directory-role privilege",
            description="A guest (external) user holds a high-tier Microsoft Entra ID directory role.",
            evidence=common_evidence,
            remediation={
                "summary": "Review whether this guest account requires high-tier administrative access.",
                "steps": [
                    "Confirm the assignment is intentional and still required for this external identity.",
                    "Microsoft Entra admin center -> Roles and administrators.",
                ],
            },
            record_id=record_id,
        ))

    if account_enabled_category == "disabled" and guest is True and tier in _KNOWN_TIERS_FOR_RETENTION:
        severity = "high" if tier in _HIGH_OR_CRITICAL_TIERS else "medium"
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_DISABLED_GUEST_RETAINS_HIGH_PRIVILEGE,
            finding_key=make_finding_key(_RULE_DISABLED_GUEST_RETAINS_HIGH_PRIVILEGE, record_id),
            severity=severity,
            title="Disabled guest identity retains directory-role privilege",
            description="A disabled guest identity's Microsoft Entra ID directory-role assignment remains in place. The entitlement is currently unusable due to the disabled account, but would become effective again if the account is re-enabled.",
            evidence=common_evidence,
            remediation={
                "summary": "Remove the directory-role assignment from this disabled guest identity if it will not be needed again.",
                "steps": [
                    "Confirm the account is intentionally disabled and expected to remain so.",
                    "Remove the role assignment rather than leaving it dormant.",
                ],
            },
            record_id=record_id,
        ))
    elif account_enabled_category == "disabled" and tier in _KNOWN_TIERS_FOR_RETENTION:
        severity = "high" if tier in _HIGH_OR_CRITICAL_TIERS else "medium"
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_DISABLED_IDENTITY_RETAINS_ADMIN_PRIVILEGE,
            finding_key=make_finding_key(_RULE_DISABLED_IDENTITY_RETAINS_ADMIN_PRIVILEGE, record_id),
            severity=severity,
            title="Disabled identity retains directory-role privilege",
            description="A disabled Microsoft Entra ID identity's directory-role assignment remains in place. The entitlement is currently unusable due to the disabled account, but would become effective again if the account is re-enabled.",
            evidence=common_evidence,
            remediation={
                "summary": "Remove directory-role assignments from disabled identities.",
                "steps": [
                    "Confirm the identity is intentionally disabled.",
                    "Remove its directory-role assignment(s) if they will not be needed again.",
                    "Microsoft Entra admin center -> Roles and administrators.",
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
    group_name = get_str(record, "display_name")
    tier = record.get("highest_privilege_tier")
    member_count = record.get("member_count")
    guest_member_count = record.get("guest_member_count")
    common_evidence = {**evidence, "group_name": group_name, "privilege_tier": tier, "member_count": member_count}

    if tier == ENTRA_PRIVILEGE_TIER_CRITICAL:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_GROUP_HAS_GLOBAL_ADMIN,
            finding_key=make_finding_key(_RULE_GROUP_HAS_GLOBAL_ADMIN, record_id),
            severity="critical",
            title="Group grants Global Administrator privilege",
            description="A role-assignable group carries a direct Global Administrator role assignment; every current and future member of this group inherits that privilege.",
            evidence=common_evidence,
            remediation={
                "summary": "Review whether group-based Global Administrator delegation is necessary.",
                "steps": [
                    "Confirm the group's membership is tightly controlled.",
                    "Consider direct, individually-reviewed assignments instead of a group grant.",
                    "Microsoft Entra admin center -> Groups -> select group -> Roles and administrators.",
                ],
            },
            record_id=record_id,
        ))
    elif tier == ENTRA_PRIVILEGE_TIER_HIGH:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_GROUP_HAS_HIGH_PRIVILEGE,
            finding_key=make_finding_key(_RULE_GROUP_HAS_HIGH_PRIVILEGE, record_id),
            severity="high",
            title="Group grants high-tier administrator privilege",
            description="A role-assignable group carries a direct high-tier directory-role assignment.",
            evidence=common_evidence,
            remediation={
                "summary": "Review whether group-based high-tier delegation is necessary.",
                "steps": [
                    "Confirm the group's membership is tightly controlled.",
                    "Consider a narrower role if full high-tier access is not required for every member.",
                ],
            },
            record_id=record_id,
        ))

    if isinstance(guest_member_count, int) and guest_member_count > 0 and tier in _HIGH_OR_CRITICAL_TIERS:
        severity = "critical" if tier == ENTRA_PRIVILEGE_TIER_CRITICAL else "high"
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_GUEST_MEMBER_IN_PRIVILEGED_GROUP,
            finding_key=make_finding_key(_RULE_GUEST_MEMBER_IN_PRIVILEGED_GROUP, record_id),
            severity=severity,
            title="Guest user directly belongs to a privileged group",
            description="A group carrying a critical- or high-tier directory-role assignment has one or more guest (external) users as direct members, who inherit that privilege.",
            evidence={**common_evidence, "guest_member_count": guest_member_count},
            remediation={
                "summary": "Review whether guest membership in this privileged group is intentional.",
                "steps": [
                    "Confirm the guest members require the inherited administrative privilege.",
                    "Remove guest members who do not require this access.",
                ],
            },
            record_id=record_id,
        ))

    if tier in _HIGH_OR_CRITICAL_TIERS and isinstance(member_count, int) and member_count > _BROAD_MEMBERSHIP_THRESHOLD:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_PRIVILEGED_GROUP_BROAD_MEMBERSHIP,
            finding_key=make_finding_key(_RULE_PRIVILEGED_GROUP_BROAD_MEMBERSHIP, record_id),
            severity="high",
            title="Privileged group has broad membership",
            description=f"A group carrying a critical- or high-tier directory-role assignment has broad membership ({member_count} members, more than {_BROAD_MEMBERSHIP_THRESHOLD}).",
            evidence=common_evidence,
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


# ── Privileged service principal ─────────────────────────────────────────────


def _eval_privileged_service_principal(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    display_name = get_str(record, "display_name")
    tier = record.get("highest_privilege_tier")
    account_enabled = record.get("account_enabled")
    common_evidence = {**evidence, "application": display_name, "privilege_tier": tier}

    if tier == ENTRA_PRIVILEGE_TIER_CRITICAL:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_SP_HAS_CRITICAL_PRIVILEGE,
            finding_key=make_finding_key(_RULE_SP_HAS_CRITICAL_PRIVILEGE, record_id),
            severity="critical",
            title="Service principal has critical-tier privilege",
            description="A service principal is privileged via a critical-tier directory role, a critical Microsoft Graph application permission, or tenant-wide critical-risk delegated consent.",
            evidence=common_evidence,
            remediation={
                "summary": "Review this service principal's overall privilege and reduce it where possible.",
                "steps": [
                    "Confirm the application/automation genuinely requires this level of access.",
                    "Remove unused directory-role assignments or Graph application permissions.",
                    "Microsoft Entra admin center -> Enterprise applications -> select application.",
                ],
            },
            record_id=record_id,
        ))
    elif tier == ENTRA_PRIVILEGE_TIER_HIGH:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_SP_HAS_HIGH_PRIVILEGE,
            finding_key=make_finding_key(_RULE_SP_HAS_HIGH_PRIVILEGE, record_id),
            severity="high",
            title="Service principal has high-tier privilege",
            description="A service principal is privileged via a high-tier directory role, a high-risk Microsoft Graph application permission, or tenant-wide high-risk delegated consent.",
            evidence=common_evidence,
            remediation={
                "summary": "Review this service principal's overall privilege and reduce it where possible.",
                "steps": [
                    "Confirm the application/automation genuinely requires this level of access.",
                    "Remove unused directory-role assignments or Graph application permissions.",
                ],
            },
            record_id=record_id,
        ))

    if account_enabled is False and tier in _KNOWN_TIERS_FOR_RETENTION:
        severity = "high" if tier in _HIGH_OR_CRITICAL_TIERS else "medium"
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_DISABLED_SP_RETAINS_PRIVILEGE,
            finding_key=make_finding_key(_RULE_DISABLED_SP_RETAINS_PRIVILEGE, record_id),
            severity=severity,
            title="Disabled service principal retains privilege",
            description="A disabled service principal's directory-role assignment or Graph application permission remains in place. The entitlement is currently unusable, but would become effective again if the service principal is re-enabled.",
            evidence=common_evidence,
            remediation={
                "summary": "Remove privilege from disabled service principals that will not be reactivated.",
                "steps": [
                    "Confirm the service principal is intentionally disabled.",
                    "Remove its directory-role assignment(s) and Graph application permission(s) if no longer needed.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── Service-principal application-permission grant ──────────────────────────

_SP_PERMISSION_RULES: tuple[tuple[str, str, str, str], ...] = (
    # (app_role_category, rule_key, severity, title-fragment)
    ("RoleManagement.ReadWrite.Directory", _RULE_SP_CAN_MANAGE_DIRECTORY_ROLES, "critical", "manage Microsoft Entra ID directory roles"),
    ("AppRoleAssignment.ReadWrite.All", _RULE_SP_CAN_MANAGE_APP_ROLE_ASSIGNMENTS, "critical", "manage any application's app-role assignments (grant itself or others further permissions)"),
    ("Policy.ReadWrite.PermissionGrant", _RULE_SP_CAN_GRANT_ARBITRARY_PERMISSIONS, "critical", "grant arbitrary delegated or application permissions on behalf of the tenant"),
    ("Application.ReadWrite.All", _RULE_SP_HAS_APPLICATION_MANAGEMENT_PERMISSION, "high", "manage any application registration or service principal, including their credentials"),
    ("Policy.ReadWrite.ConditionalAccess", _RULE_SP_CAN_MODIFY_CONDITIONAL_ACCESS, "high", "modify tenant Conditional Access policy"),
    ("UserAuthenticationMethod.ReadWrite.All", _RULE_SP_CAN_MODIFY_AUTHENTICATION_METHODS, "high", "modify any user's authentication methods"),
    ("Directory.ReadWrite.All", _RULE_SP_HAS_DIRECTORY_WRITE_PERMISSION, "high", "write broadly across the directory"),
    ("User.ReadWrite.All", _RULE_SP_HAS_USER_WRITE_PERMISSION, "medium", "write any user's profile"),
    ("Group.ReadWrite.All", _RULE_SP_HAS_GROUP_WRITE_PERMISSION, "medium", "write any group's membership/configuration"),
)


def _eval_sp_app_role_assignment(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    if record.get("resource_is_microsoft_graph") is not True:
        return out
    app_role_category = record.get("app_role_category")
    if not isinstance(app_role_category, str):
        return out

    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    principal_name = get_str(record, "principal_name")
    resource_name = get_str(record, "resource_name")

    for permission_value, rule_key, severity, capability in _SP_PERMISSION_RULES:
        if app_role_category == permission_value:
            out.append(FindingCandidate(
                provider="entra",
                rule_key=rule_key,
                finding_key=make_finding_key(rule_key, record_id),
                severity=severity,
                title=f"Service principal granted {permission_value} Graph permission",
                description=f"A service principal holds the Microsoft Graph application permission {permission_value}, which can {capability}.",
                evidence={**evidence, "application": principal_name, "resource": resource_name, "permission": permission_value},
                remediation={
                    "summary": "Review whether this application genuinely requires this Microsoft Graph application permission.",
                    "steps": [
                        "Confirm the automation's intended purpose requires this permission.",
                        "Remove the application permission if it is broader than necessary.",
                        "Microsoft Entra admin center -> Enterprise applications -> select application -> Permissions.",
                    ],
                },
                record_id=record_id,
            ))
            break

    return out


# ── OAuth2 delegated permission grant (consent) ──────────────────────────────


def _eval_oauth2_permission_grant(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    client_name = get_str(record, "client_name")
    resource_name = get_str(record, "resource_name")
    consent_type = record.get("consent_type_category")
    tier = record.get("highest_scope_privilege_tier")
    publisher_category = record.get("client_verified_publisher_category")
    common_evidence = {**evidence, "client": client_name, "resource": resource_name, "scope_privilege_tier": tier}

    is_tenant_wide = consent_type == CONSENT_TYPE_ALL_PRINCIPALS
    is_user_scoped = consent_type == CONSENT_TYPE_PRINCIPAL

    if is_tenant_wide and tier in _HIGH_OR_CRITICAL_TIERS and publisher_category == PUBLISHER_UNVERIFIED:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_EXTERNAL_UNVERIFIED_APP_TENANT_WIDE_CONSENT,
            finding_key=make_finding_key(_RULE_EXTERNAL_UNVERIFIED_APP_TENANT_WIDE_CONSENT, record_id),
            severity="critical",
            title="Unverified-publisher application holds tenant-wide high-risk consent",
            description="An application from an unverified publisher was granted tenant-wide (admin) delegated consent that includes a critical- or high-risk scope.",
            evidence=common_evidence,
            remediation={
                "summary": "Review this tenant-wide consent grant to an unverified-publisher application.",
                "steps": [
                    "Confirm the application and publisher are trusted and the grant is intentional.",
                    "Reduce or revoke the grant's high-risk scopes if not required.",
                    "Consider requiring publisher verification for tenant-wide admin consent going forward.",
                    "Microsoft Entra admin center -> Enterprise applications -> select application -> Permissions.",
                ],
            },
            record_id=record_id,
        ))
    elif is_tenant_wide and tier == ENTRA_PRIVILEGE_TIER_CRITICAL:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_TENANT_WIDE_CRITICAL_CONSENT,
            finding_key=make_finding_key(_RULE_TENANT_WIDE_CRITICAL_CONSENT, record_id),
            severity="critical",
            title="Tenant-wide delegated consent includes a critical-risk scope",
            description="Tenant-wide (admin) delegated consent was granted for a scope categorized as critical-risk.",
            evidence=common_evidence,
            remediation={
                "summary": "Review the tenant-wide delegated grant and reduce or revoke critical-risk scopes that are not required.",
                "steps": ["Microsoft Entra admin center -> Enterprise applications -> select application -> Permissions."],
            },
            record_id=record_id,
        ))
    elif is_tenant_wide and tier == ENTRA_PRIVILEGE_TIER_HIGH:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_TENANT_WIDE_HIGH_RISK_CONSENT,
            finding_key=make_finding_key(_RULE_TENANT_WIDE_HIGH_RISK_CONSENT, record_id),
            severity="high",
            title="Tenant-wide delegated consent includes a high-risk scope",
            description="Tenant-wide (admin) delegated consent was granted for a scope categorized as high-risk.",
            evidence=common_evidence,
            remediation={
                "summary": "Review the tenant-wide delegated grant and reduce or revoke high-risk scopes that are not required.",
                "steps": ["Microsoft Entra admin center -> Enterprise applications -> select application -> Permissions."],
            },
            record_id=record_id,
        ))
    elif is_user_scoped and tier == ENTRA_PRIVILEGE_TIER_CRITICAL:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_USER_SCOPED_CRITICAL_CONSENT,
            finding_key=make_finding_key(_RULE_USER_SCOPED_CRITICAL_CONSENT, record_id),
            severity="high",
            title="User-scoped delegated consent includes a critical-risk scope",
            description="A single user's own delegated consent grant includes a scope categorized as critical-risk.",
            evidence=common_evidence,
            remediation={
                "summary": "Review this user-scoped delegated consent grant.",
                "steps": ["Microsoft Entra admin center -> Enterprise applications -> select application -> Permissions (user consent)."],
            },
            record_id=record_id,
        ))
    elif is_user_scoped and tier == ENTRA_PRIVILEGE_TIER_HIGH:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_USER_SCOPED_HIGH_RISK_CONSENT,
            finding_key=make_finding_key(_RULE_USER_SCOPED_HIGH_RISK_CONSENT, record_id),
            severity="medium",
            title="User-scoped delegated consent includes a high-risk scope",
            description="A single user's own delegated consent grant includes a scope categorized as high-risk.",
            evidence=common_evidence,
            remediation={
                "summary": "Review this user-scoped delegated consent grant.",
                "steps": ["Microsoft Entra admin center -> Enterprise applications -> select application -> Permissions (user consent)."],
            },
            record_id=record_id,
        ))

    return out


# ── Conditional Access policy ─────────────────────────────────────────────────


def _eval_conditional_access_policy(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    policy_name = get_str(record, "display_name")
    state = record.get("state_category")
    mfa = record.get("mfa_requirement_category")
    coverage = record.get("coverage_category")
    block_access = record.get("block_access")
    legacy_auth_targeted = record.get("legacy_auth_targeted")
    common_evidence = {**evidence, "policy": policy_name, "state": state, "mfa_requirement": mfa, "coverage": coverage}

    if state == "enabled" and block_access is not True and mfa == "not_required" and coverage == "all_users_all_apps":
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_CA_BROAD_ACCESS_WITHOUT_MFA,
            finding_key=make_finding_key(_RULE_CA_BROAD_ACCESS_WITHOUT_MFA, record_id),
            severity="high",
            title="Broad Conditional Access policy allows access without MFA",
            description="An enabled Conditional Access policy targeting all users and all apps allows access and does not require MFA.",
            evidence=common_evidence,
            remediation={
                "summary": "Update this Conditional Access policy to require an appropriate MFA or authentication-strength control.",
                "steps": ["Microsoft Entra admin center -> Protection -> Conditional Access -> select policy -> Grant."],
            },
            record_id=record_id,
        ))
    elif state == "enabled" and block_access is not True and mfa == "not_required":
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_CA_ACCESS_WITHOUT_MFA,
            finding_key=make_finding_key(_RULE_CA_ACCESS_WITHOUT_MFA, record_id),
            severity="medium",
            title="Conditional Access policy allows access without MFA",
            description="An enabled Conditional Access policy allows access and does not require MFA. Its targeting is narrower than all-users/all-apps.",
            evidence=common_evidence,
            remediation={
                "summary": "Consider requiring MFA in this Conditional Access policy.",
                "steps": ["Microsoft Entra admin center -> Protection -> Conditional Access -> select policy -> Grant."],
            },
            record_id=record_id,
        ))
    elif state == "enabled" and mfa == "one_of_multiple_controls" and record.get("user_target_category") == "all_users":
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_CA_MFA_OPTIONAL_WITHIN_GRANT_CONTROLS,
            finding_key=make_finding_key(_RULE_CA_MFA_OPTIONAL_WITHIN_GRANT_CONTROLS, record_id),
            severity="medium",
            title="Conditional Access policy does not strictly require MFA",
            description="An enabled Conditional Access policy targeting all users uses an OR grant-control operator that includes MFA as only one of several satisfying options — MFA is not strictly required.",
            evidence=common_evidence,
            remediation={
                "summary": "Review whether the alternative (non-MFA) grant controls provide equivalent assurance, or switch to requiring MFA explicitly.",
                "steps": ["Microsoft Entra admin center -> Protection -> Conditional Access -> select policy -> Grant."],
            },
            record_id=record_id,
        ))

    if state == "enabled" and legacy_auth_targeted is True and block_access is not True:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_CA_LEGACY_AUTH_NOT_BLOCKED,
            finding_key=make_finding_key(_RULE_CA_LEGACY_AUTH_NOT_BLOCKED, record_id),
            severity="high",
            title="Conditional Access policy targets legacy authentication without blocking it",
            description="An enabled Conditional Access policy explicitly targets legacy authentication client types but does not block access for them.",
            evidence=common_evidence,
            remediation={
                "summary": "Update this policy to block access for legacy authentication protocols.",
                "steps": ["Microsoft Entra admin center -> Protection -> Conditional Access -> select policy -> Grant -> Block access."],
            },
            record_id=record_id,
        ))

    if state == "report_only" and mfa == "required" and coverage == "all_users_all_apps":
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_CA_REPORT_ONLY_BROAD_PROTECTION,
            finding_key=make_finding_key(_RULE_CA_REPORT_ONLY_BROAD_PROTECTION, record_id),
            severity="medium",
            title="Broad MFA-requiring Conditional Access policy is not enforced",
            description="A Conditional Access policy that would require MFA for all users and all apps is configured in report-only mode and is not currently enforced.",
            evidence=common_evidence,
            remediation={
                "summary": "Review the report-only policy's sign-in logs and enable enforcement if the policy is ready.",
                "steps": ["Microsoft Entra admin center -> Protection -> Conditional Access -> select policy -> Enable policy."],
            },
            record_id=record_id,
        ))

    return out


# ── Authentication method ────────────────────────────────────────────────────


def _eval_authentication_method(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    if record.get("state_category") != "enabled":
        return out
    method_type = record.get("method_type_category")
    if method_type not in _WEAK_AUTHENTICATION_METHOD_TYPES:
        return out

    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    out.append(FindingCandidate(
        provider="entra",
        rule_key=_RULE_WEAK_AUTHENTICATION_METHOD_ENABLED,
        finding_key=make_finding_key(_RULE_WEAK_AUTHENTICATION_METHOD_ENABLED, record_id),
        severity="low",
        title="SMS or voice authentication method is enabled",
        description=f"The {method_type} authentication method is enabled tenant-wide. This factor type is weaker than possession/phishing-resistant factors and is a common social-engineering target.",
        evidence={**evidence, "method_type": method_type},
        remediation={
            "summary": "Confirm this method is intentional (e.g. for account recovery) and consider requiring a stronger factor for primary authentication.",
            "steps": ["Microsoft Entra admin center -> Protection -> Authentication methods."],
        },
        record_id=record_id,
    ))
    return out


# ── Authentication strength ──────────────────────────────────────────────────


def _eval_authentication_strength(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    if record.get("kind_category") != "custom":
        return out
    if record.get("phishing_resistance_category") != "not_phishing_resistant":
        return out

    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    display_name = get_str(record, "display_name")
    out.append(FindingCandidate(
        provider="entra",
        rule_key=_RULE_AUTH_STRENGTH_NOT_PHISHING_RESISTANT,
        finding_key=make_finding_key(_RULE_AUTH_STRENGTH_NOT_PHISHING_RESISTANT, record_id),
        severity="medium",
        title="Custom authentication strength does not require phishing-resistant authentication",
        description="A custom authentication strength policy's allowed combinations do not require a phishing-resistant factor (e.g. FIDO2, Windows Hello for Business, certificate-based authentication).",
        evidence={**evidence, "strength": display_name},
        remediation={
            "summary": "Consider adding a phishing-resistant combination to this authentication strength for sensitive access scenarios.",
            "steps": ["Microsoft Entra admin center -> Protection -> Authentication methods -> Authentication strengths."],
        },
        record_id=record_id,
    ))
    return out


# ── Application ───────────────────────────────────────────────────────────


def _eval_application(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    display_name = get_str(record, "display_name")
    common_evidence = {**evidence, "application": display_name}

    if record.get("has_wildcard_redirect") is True:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_APPLICATION_WILDCARD_REDIRECT,
            finding_key=make_finding_key(_RULE_APPLICATION_WILDCARD_REDIRECT, record_id),
            severity="high",
            title="Application allows a wildcard redirect URI",
            description="An application's configured redirect URIs include a wildcard pattern.",
            evidence=common_evidence,
            remediation={
                "summary": "Replace wildcard redirect patterns with explicit trusted HTTPS redirect URIs.",
                "steps": ["Microsoft Entra admin center -> App registrations -> select application -> Authentication."],
            },
            record_id=record_id,
        ))

    if record.get("web_has_http_redirect") is True:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_APPLICATION_HTTP_REDIRECT,
            finding_key=make_finding_key(_RULE_APPLICATION_HTTP_REDIRECT, record_id),
            severity="medium",
            title="Web application allows an HTTP redirect URI",
            description="An application's web redirect URIs include a plain-HTTP (non-TLS) URI.",
            evidence=common_evidence,
            remediation={
                "summary": "Use HTTPS redirect URIs for web clients.",
                "steps": ["Microsoft Entra admin center -> App registrations -> select application -> Authentication -> Web."],
            },
            record_id=record_id,
        ))

    if record.get("has_custom_scheme_redirect") is True and record.get("public_client_redirect_count") in (0, None):
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_APPLICATION_CUSTOM_SCHEME_REDIRECT_UNEXPECTED,
            finding_key=make_finding_key(_RULE_APPLICATION_CUSTOM_SCHEME_REDIRECT_UNEXPECTED, record_id),
            severity="medium",
            title="Application uses a custom-scheme redirect outside a public-client context",
            description="An application uses a custom URI scheme redirect, which is typically expected only for native/mobile (public client) OAuth clients, but this application has no public-client redirect URIs configured.",
            evidence=common_evidence,
            remediation={
                "summary": "Confirm the custom-scheme redirect is intentional for this application's platform.",
                "steps": ["Microsoft Entra admin center -> App registrations -> select application -> Authentication."],
            },
            record_id=record_id,
        ))

    if record.get("nearest_credential_expiry_category") == "expired":
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_APPLICATION_EXPIRED_CREDENTIAL,
            finding_key=make_finding_key(_RULE_APPLICATION_EXPIRED_CREDENTIAL, record_id),
            severity="medium",
            title="Application has an expired credential",
            description="An application registration's nearest password or key credential has expired.",
            evidence=common_evidence,
            remediation={
                "summary": "Rotate this application's credential.",
                "steps": ["Microsoft Entra admin center -> App registrations -> select application -> Certificates & secrets."],
            },
            record_id=record_id,
        ))

    return out


# ── Service principal ─────────────────────────────────────────────────────


def _eval_service_principal(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    display_name = get_str(record, "display_name")
    common_evidence = {**evidence, "application": display_name}

    if record.get("nearest_credential_expiry_category") == "expired":
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_SP_EXPIRED_CREDENTIAL,
            finding_key=make_finding_key(_RULE_SP_EXPIRED_CREDENTIAL, record_id),
            severity="medium",
            title="Service principal has an expired credential",
            description="A service principal's nearest password or key credential has expired.",
            evidence=common_evidence,
            remediation={
                "summary": "Rotate this service principal's credential.",
                "steps": ["Microsoft Entra admin center -> Enterprise applications -> select application -> Certificates & secrets."],
            },
            record_id=record_id,
        ))

    if record.get("assignment_required") is False:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_SP_ASSIGNMENT_NOT_REQUIRED,
            finding_key=make_finding_key(_RULE_SP_ASSIGNMENT_NOT_REQUIRED, record_id),
            severity="low",
            title="Service principal does not require explicit user/group assignment",
            description="A service principal's assignment-required setting is disabled. Whether this actually broadens sign-in access depends on the application's own authorization behavior.",
            evidence=common_evidence,
            remediation={
                "summary": "Consider requiring explicit assignment if this application should be limited to specific users/groups.",
                "steps": ["Microsoft Entra admin center -> Enterprise applications -> select application -> Properties -> Assignment required."],
            },
            record_id=record_id,
        ))

    return out


# ── Application user assignment ──────────────────────────────────────────────


def _eval_app_user_assignment(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    if record.get("account_enabled_category") != "disabled":
        return out
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    out.append(FindingCandidate(
        provider="entra",
        rule_key=_RULE_DISABLED_USER_RETAINS_APP_ASSIGNMENT,
        finding_key=make_finding_key(_RULE_DISABLED_USER_RETAINS_APP_ASSIGNMENT, record_id),
        severity="low",
        title="Disabled user retains an application assignment",
        description="A disabled Microsoft Entra ID user still has an active enterprise-application assignment on record.",
        evidence={**evidence, "application": get_str(record, "application_name")},
        remediation={
            "summary": "Remove application assignments from disabled identities.",
            "steps": ["Microsoft Entra admin center -> Enterprise applications -> select application -> Users and groups."],
        },
        record_id=record_id,
    ))
    return out


# ── Application group assignment ─────────────────────────────────────────────


def _eval_app_group_assignment(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    application_name = get_str(record, "application_name")

    if record.get("role_assignable_group") is True:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_ROLE_ASSIGNABLE_GROUP_ASSIGNED_TO_APPLICATION,
            finding_key=make_finding_key(_RULE_ROLE_ASSIGNABLE_GROUP_ASSIGNED_TO_APPLICATION, record_id),
            severity="medium",
            title="Role-assignable group is assigned to an application",
            description="A group eligible for directory-role assignment (isAssignableToRole) is also assigned to an enterprise application, fanning out application access to every current and future member.",
            evidence={**evidence, "application": application_name, "group_name": get_str(record, "group_name")},
            remediation={
                "summary": "Review whether application access via this role-assignable group is intentional.",
                "steps": ["Microsoft Entra admin center -> Enterprise applications -> select application -> Users and groups."],
            },
            record_id=record_id,
        ))
    elif record.get("dynamic_group") is True:
        out.append(FindingCandidate(
            provider="entra",
            rule_key=_RULE_DYNAMIC_GROUP_ASSIGNED_TO_APPLICATION,
            finding_key=make_finding_key(_RULE_DYNAMIC_GROUP_ASSIGNED_TO_APPLICATION, record_id),
            severity="medium",
            title="Dynamic-membership group is assigned to an application",
            description="A group with dynamic (rule-based) membership is assigned to an enterprise application — membership, and therefore application access, can change automatically.",
            evidence={**evidence, "application": application_name, "group_name": get_str(record, "group_name")},
            remediation={
                "summary": "Review the dynamic membership rule to confirm application access via this group is intended.",
                "steps": ["Microsoft Entra admin center -> Enterprise applications -> select application -> Users and groups."],
            },
            record_id=record_id,
        ))

    return out
