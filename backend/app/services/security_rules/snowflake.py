"""Snowflake security exposure rules (Snowflake message 6 of 8).

Turns the normalized Snowflake posture derived by messages 1-5 into static
Security Findings: "what risky Snowflake posture exists right now?" —
distinct from Change classification (``risk_rules/snowflake.py``), which
answers "what changed?". A rule here evaluates CURRENT STATE only; it
never reads Change history.

Every rule fires only on explicit, reliable normalized fields produced by
the Snowflake connector (app/connectors/snowflake.py + snowflake_schema.py,
messages 1-5) plus one small message-6 enrichment (SCIM run-as role
privilege-tier resolution — see snowflake.py's
``_resolve_scim_run_as_context``, an additive, zero-extra-SQL-call
resolution of a message-4 raw field against message-5's own role-closure
machinery). Evidence is metadata-only: safe labels/categories, counts,
booleans, and opaque identifiers. Never included in evidence: PATs,
passwords, private keys, certificates, OAuth/SCIM secrets, raw IP/CIDR
values, or raw SQL/table data — matching the connector's own permanent
sensitive-data boundary.

Claim discipline
-----------------
These are configuration-posture findings that warrant review, not a
confirmed compromise. Titles/descriptions state what is CONFIGURED
("holds", "is assigned", "allows"), never "compromised", "attacker",
"exploited", "breached", or "unauthorized". Severity reflects review
priority, not confirmed impact.

PUBLIC wording (MANDATORY — a past project mistake this module must never
repeat): Snowflake's PUBLIC role is an automatic, account-wide pseudo-role
granted to every user and role — it is NEVER "publicly accessible on the
internet," "internet-exposed," or "anonymous access." Every PUBLIC-related
rule's copy says "available to Snowflake users through the PUBLIC role" /
"every Snowflake user in the account" — never anything resembling
internet exposure.

Unknown-state discipline
-------------------------
Every rule reading a message-5 derived boolean/tier field fires ONLY on an
explicit risky value. ``None``/``"unknown"`` is never treated as risky:
``has_accountadmin is True`` (not truthy), ``tier == "critical"`` (exact
match, never a default), counts checked with ``isinstance(x, int) and
x > 0`` (a ``None`` count from an incomplete family never satisfies this).
Message 5's own "no fake safe zeros" discipline is the reason this works —
a positively-observed critical privilege remains valid evidence even when
an unrelated family is partial (see message 5's completeness model).

Duplicate suppression / precedence
------------------------------------
A user holding ACCOUNTADMIN (directly or via inherited hierarchy) fires
ONLY the ACCOUNTADMIN rule for that user — never also a generic
SECURITYADMIN/MANAGE-GRANTS/SYSADMIN Finding for the same identity, even
though the underlying role closure technically contains those privileges
too (ACCOUNTADMIN encapsulates them per current Snowflake docs). Precedence
chain: ACCOUNTADMIN > SECURITYADMIN > MANAGE GRANTS > SYSADMIN/USERADMIN.
A service-type user (SERVICE/SERVICE_AGENT) with ACCOUNTADMIN fires the
service-specific rule INSTEAD OF the generic one (mutually exclusive
branches on user_type), never both.

Record types consumed
----------------------
Privileged users/roles : snowflake_privileged_user, snowflake_privileged_role
PUBLIC exposure         : snowflake_public_exposure
Network                : snowflake_network_policy
Authentication          : snowflake_authentication_policy
Integrations            : snowflake_security_integration

Deferred Snowflake rules (intentionally NOT implemented — see message-6
report and the effective-privilege matrix's "Major gaps" section)
---------------------------------------------------------------------------
* "PUBLIC has current (non-future) data-read access" — message 2/3
  deliberately excluded PUBLIC from per-role SHOW GRANTS TO ROLE
  enumeration (to avoid hierarchy/grant noise from its automatic
  membership in every principal), so CURRENT object grants held by PUBLIC
  were never collected. Implementing this Finding from absent data would
  be exactly the "fake it from absent data" mistake this message must
  avoid. Only FUTURE PUBLIC grants (which ARE collected via SHOW FUTURE
  GRANTS IN DATABASE, not scoped to a single grantee) are covered.
* "OAuth integration allows a critical/high-privilege role" — message 4's
  security-integration normalizer does not capture an OAuth allowed-role
  list (only ``oauth_client_category``/``oauth_issuer_configured``).
  Implementing this would require guessing at unmodeled metadata.
* "Sensitive privilege granted with grant option" — ``grant_option`` lives
  on the raw ``snowflake_object_grant`` record (message 3), which carries
  no role-tier/significance context of its own; this evaluator sees one
  record at a time and cannot safely join it against a role's derived
  privilege tier without connector-side pre-derivation (the same
  architectural constraint Okta's own deferred-rule list documents for
  its cross-record composite candidates).
* "External access integration has broad network scope + privileged
  context" — ``snowflake_external_access_integration`` only carries an
  ``allowed_network_rule_count`` (a count), not a resolved "is this scope
  broad" boolean; message 4 did not cross-reference those network rules'
  actual CIDR breadth onto the integration record. A count alone is not
  evidence of broad access.
* "Storage integration can access many/all buckets" — only a location
  *count* is modeled (message 4), never the resolved location scope
  itself; a high count alone is not evidence of unrestricted access.
* Every "role owns a database/schema/warehouse" as a bare inventory
  Finding — expected, routine Snowflake administration; only fires as
  part of a HIGH-PRIVILEGE-CUSTOM-ROLE composite (see
  ``snowflake_high_privilege_role_owns_database`` etc.) — see each rule's
  own docstring for the specific gating.
* "Network policy exists but has no allowlist" / "no network policy
  configured" / "no authentication policy configured" / "no SSO
  configured" — absence-based rules; message 5/4's per-record interface
  cannot safely assert account-wide absence without a family-completeness
  lookup this evaluator's ``evaluate(record)`` signature does not have
  access to (same reasoning as Okta's own deferred tenant-wide absence
  rules).
* "Direct-to-user object privilege" Findings — message 5 documents that
  direct-to-user object grants are not currently collected at all; there
  is no normalized evidence to evaluate.
* "SCIM role can manage grants" as a rule DISTINCT from the tier-based
  SCIM rules — message 5's own custom-role tier derivation guarantees
  ``has_manage_grants=True`` always yields at least a High tier, so a
  separate MANAGE-GRANTS-specific SCIM rule would never fire on evidence
  the tier-based rules haven't already covered; the MANAGE GRANTS flag is
  instead surfaced as EVIDENCE on the tier-based SCIM rules.
* "SAML/OAuth/SCIM/storage/external-access integration exists" or "is
  disabled" as a bare inventory Finding — legitimate, common, and
  frequently intentionally-unused Snowflake functionality; only specific
  structural weaknesses (e.g. an ENABLED SAML integration missing
  issuer/SSO/certificate configuration) are covered.
* "Share exists" / "share was broadened" — Snowflake secure data sharing
  is legitimate, controlled account-to-account functionality; message 3's
  own risk classifier already documents this is never "data is public,"
  and the current share model's truncated consumer-count evidence is not
  a sufficient basis for a static Finding.
"""

from __future__ import annotations

from typing import Any

from app.connectors.snowflake_schema import (
    ROLE_CATEGORY_CUSTOM,
    ROLE_PRIVILEGE_CATEGORY_IDENTITY_ADMINISTRATION,
    SNOWFLAKE_AUTHENTICATION_POLICY,
    SNOWFLAKE_NETWORK_POLICY,
    SNOWFLAKE_PRIVILEGED_ROLE,
    SNOWFLAKE_PRIVILEGED_USER,
    SNOWFLAKE_PUBLIC_EXPOSURE,
    SNOWFLAKE_SECURITY_INTEGRATION,
)
from app.services.security_rules.base import FindingCandidate, get_str, make_finding_key

# ── Rule keys ────────────────────────────────────────────────────────────────

# Privileged users (8)
_RULE_USER_ACCOUNTADMIN = "snowflake_user_accountadmin"
_RULE_SERVICE_USER_ACCOUNTADMIN = "snowflake_service_user_accountadmin"
_RULE_USER_SECURITYADMIN = "snowflake_user_securityadmin"
_RULE_USER_CAN_MANAGE_GRANTS = "snowflake_user_can_manage_grants"
_RULE_USER_SYSADMIN_OR_USERADMIN = "snowflake_user_sysadmin_or_useradmin"
_RULE_DISABLED_PRIVILEGED_USER = "snowflake_disabled_privileged_user"
_RULE_LEGACY_SERVICE_USER_PRIVILEGED = "snowflake_legacy_service_user_privileged"
_RULE_LEGACY_SERVICE_USER = "snowflake_legacy_service_user"

# Privileged / custom roles (11)
_RULE_CUSTOM_ROLE_MANAGE_GRANTS = "snowflake_custom_role_manage_grants"
_RULE_CUSTOM_ROLE_MANAGE_GRANTS_IDENTITY_ADMIN = "snowflake_custom_role_manage_grants_identity_admin"
_RULE_CUSTOM_ROLE_HIGH_PRIVILEGE = "snowflake_custom_role_high_privilege"
_RULE_ROLE_CONTROLS_MANAGED_ACCESS_SCHEMA = "snowflake_role_controls_managed_access_schema"
_RULE_ROLE_OWNS_SECURITY_INTEGRATION = "snowflake_role_owns_security_integration_high_privilege"
_RULE_ROLE_OWNS_STORAGE_INTEGRATION = "snowflake_role_owns_storage_integration_high_privilege"
_RULE_ROLE_OWNS_EXTERNAL_ACCESS_INTEGRATION = "snowflake_role_owns_external_access_integration_high_privilege"
_RULE_ROLE_OWNS_AUTHENTICATION_POLICY = "snowflake_role_owns_authentication_policy_high_privilege"
_RULE_ROLE_OWNS_NETWORK_POLICY = "snowflake_role_owns_network_policy_high_privilege"
_RULE_HIGH_PRIVILEGE_ROLE_OWNS_DATABASE = "snowflake_high_privilege_role_owns_database"
_RULE_FUTURE_OWNERSHIP_GRANT = "snowflake_future_ownership_grant"

# PUBLIC exposure (4)
_RULE_PUBLIC_FUTURE_OWNERSHIP_GRANT = "snowflake_public_future_ownership_grant"
_RULE_PUBLIC_FUTURE_WRITE_ACCESS = "snowflake_public_future_write_access"
_RULE_PUBLIC_FUTURE_DATA_ACCESS = "snowflake_public_future_data_access"
_RULE_PUBLIC_FUTURE_BROAD_PRIVILEGE = "snowflake_public_future_broad_privilege"

# Network (1)
_RULE_NETWORK_POLICY_ALLOWS_ANYWHERE = "snowflake_network_policy_allows_anywhere"

# Authentication (3)
_RULE_MFA_OPTIONAL_WITH_PASSWORD = "snowflake_mfa_optional_with_password"
_RULE_MFA_OPTIONAL_FOR_PERSON_AUTH = "snowflake_mfa_optional_for_person_auth"
_RULE_MFA_PASSWORD_ONLY_SCOPE = "snowflake_mfa_password_only_scope"

# Integrations (3)
_RULE_SCIM_CRITICAL_PRIVILEGE_RUN_AS = "snowflake_scim_critical_privilege_run_as"
_RULE_SCIM_HIGH_PRIVILEGE_RUN_AS = "snowflake_scim_high_privilege_run_as"
_RULE_SAML_INTEGRATION_INCOMPLETE_CONFIG = "snowflake_saml_integration_incomplete_config"

# Composite / cross-signal (1)
_RULE_USER_HIGH_RISK_FUTURE_GRANT = "snowflake_user_high_risk_future_grant"

# ── Fixed vocab ──────────────────────────────────────────────────────────────

_HIGH_OR_CRITICAL_TIERS = frozenset({"critical", "high"})
_SERVICE_LIKE_USER_TYPES = frozenset({"service", "service_agent"})


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Dispatch a normalized Snowflake record to the relevant rule(s)."""
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == SNOWFLAKE_PRIVILEGED_USER:
        return _eval_privileged_user(record)
    if rtype == SNOWFLAKE_PRIVILEGED_ROLE:
        return _eval_privileged_role(record)
    if rtype == SNOWFLAKE_PUBLIC_EXPOSURE:
        return _eval_public_exposure(record)
    if rtype == SNOWFLAKE_NETWORK_POLICY:
        return _eval_network_policy(record)
    if rtype == SNOWFLAKE_AUTHENTICATION_POLICY:
        return _eval_authentication_policy(record)
    if rtype == SNOWFLAKE_SECURITY_INTEGRATION:
        return _eval_security_integration(record)
    return []


def _evidence_base(record: dict[str, Any]) -> dict[str, Any]:
    return {"account_id": get_str(record, "account_id")}


# ── Privileged user ──────────────────────────────────────────────────────────


def _eval_privileged_user(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    user_name = get_str(record, "user_name")
    user_type = get_str(record, "user_type")
    disabled = get_str(record, "disabled")
    tier = record.get("highest_known_privilege_tier")
    is_service_like = user_type in _SERVICE_LIKE_USER_TYPES
    is_legacy_service = user_type == "legacy_service"

    base_evidence = {
        **evidence, "user_name": user_name, "user_type": user_type,
        "disabled": disabled, "privilege_tier": tier,
    }

    # Precedence chain: ACCOUNTADMIN > SECURITYADMIN > MANAGE GRANTS >
    # SYSADMIN/USERADMIN — only the highest applicable rule fires for a
    # given user, never a stack of redundant Findings for privileges the
    # user's top-tier role already encapsulates.
    if record.get("has_accountadmin") is True:
        if is_service_like:
            out.append(FindingCandidate(
                provider="snowflake",
                rule_key=_RULE_SERVICE_USER_ACCOUNTADMIN,
                finding_key=make_finding_key(_RULE_SERVICE_USER_ACCOUNTADMIN, record_id),
                severity="critical",
                title="Service user holds ACCOUNTADMIN privilege",
                description="A Snowflake service identity holds effective ACCOUNTADMIN privilege, the account's top-level administrative role.",
                evidence=base_evidence,
                remediation={
                    "summary": "Review whether this service identity requires ACCOUNTADMIN.",
                    "steps": [
                        "Confirm the service identity's automation genuinely requires full account administration.",
                        "Prefer a narrower role scoped to the automation's actual needs.",
                        "Reserve ACCOUNTADMIN for tightly controlled, individually-reviewed administrative workflows.",
                    ],
                },
                record_id=record_id,
            ))
        else:
            out.append(FindingCandidate(
                provider="snowflake",
                rule_key=_RULE_USER_ACCOUNTADMIN,
                finding_key=make_finding_key(_RULE_USER_ACCOUNTADMIN, record_id),
                severity="critical",
                title="User holds ACCOUNTADMIN privilege",
                description="A Snowflake user holds effective ACCOUNTADMIN privilege, the account's top-level administrative role, encapsulating SECURITYADMIN and SYSADMIN.",
                evidence=base_evidence,
                remediation={
                    "summary": "Review whether this user requires ACCOUNTADMIN.",
                    "steps": [
                        "Confirm this user is one of a tightly controlled set of account administrators.",
                        "Prefer a narrower role and reserve ACCOUNTADMIN for administrative workflows that genuinely require it.",
                    ],
                },
                record_id=record_id,
            ))
    elif record.get("has_securityadmin") is True:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_USER_SECURITYADMIN,
            finding_key=make_finding_key(_RULE_USER_SECURITYADMIN, record_id),
            severity="high",
            title="User holds SECURITYADMIN privilege",
            description="A Snowflake user holds effective SECURITYADMIN privilege, which manages grants and security administration account-wide by default.",
            evidence=base_evidence,
            remediation={
                "summary": "Review whether this user requires SECURITYADMIN.",
                "steps": [
                    "Confirm this user is expected to administer account-wide grants and security.",
                    "Prefer a narrower custom role if full SECURITYADMIN scope is not required.",
                ],
            },
            record_id=record_id,
        ))
    elif record.get("has_manage_grants") is True:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_USER_CAN_MANAGE_GRANTS,
            finding_key=make_finding_key(_RULE_USER_CAN_MANAGE_GRANTS, record_id),
            severity="high",
            title="User can manage grants on objects it does not own",
            description="A Snowflake user holds effective MANAGE GRANTS privilege, allowing it to grant or revoke access on objects it does not own.",
            evidence=base_evidence,
            remediation={
                "summary": "Review whether this user requires MANAGE GRANTS.",
                "steps": [
                    "Confirm the grant-management authority is intentional.",
                    "Remove or narrow MANAGE GRANTS if it is not required for this user's responsibilities.",
                ],
            },
            record_id=record_id,
        ))
    elif (record.get("has_sysadmin") is True or record.get("has_useradmin") is True) and tier == "medium":
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_USER_SYSADMIN_OR_USERADMIN,
            finding_key=make_finding_key(_RULE_USER_SYSADMIN_OR_USERADMIN, record_id),
            severity="medium",
            title="User holds SYSADMIN or USERADMIN privilege",
            description="A Snowflake user holds effective SYSADMIN (infrastructure/object administration) or USERADMIN (identity/role administration) privilege.",
            evidence={**base_evidence, "has_sysadmin": record.get("has_sysadmin"), "has_useradmin": record.get("has_useradmin")},
            remediation={
                "summary": "Confirm this administrative role assignment matches the user's current responsibilities.",
                "steps": [
                    "Review whether the scope of SYSADMIN/USERADMIN access is still needed.",
                    "Consider a narrower custom role if full infrastructure or identity administration is not required.",
                ],
            },
            record_id=record_id,
        ))

    if disabled == "disabled" and tier in _HIGH_OR_CRITICAL_TIERS:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_DISABLED_PRIVILEGED_USER,
            finding_key=make_finding_key(_RULE_DISABLED_PRIVILEGED_USER, record_id),
            severity="high",
            title="Disabled user retains critical or high administrative entitlements",
            description="A disabled Snowflake user retains critical or high-tier administrative entitlements on record — the privilege would become effective again if the identity is re-enabled.",
            evidence=base_evidence,
            remediation={
                "summary": "Review whether the administrative role assignment should be removed while the user is disabled.",
                "steps": [
                    "Confirm the user is intentionally disabled and expected to remain so.",
                    "Remove the role assignment(s) granting this privilege if they will not be needed on re-enablement.",
                ],
            },
            record_id=record_id,
        ))

    if is_legacy_service:
        if tier in _HIGH_OR_CRITICAL_TIERS:
            out.append(FindingCandidate(
                provider="snowflake",
                rule_key=_RULE_LEGACY_SERVICE_USER_PRIVILEGED,
                finding_key=make_finding_key(_RULE_LEGACY_SERVICE_USER_PRIVILEGED, record_id),
                severity=tier,  # "critical" or "high"
                title="Legacy service user holds high or critical privilege",
                description="A Snowflake LEGACY_SERVICE user — a transitional, password-capable service identity that current Snowflake documentation is deprecating in favor of SERVICE with key-pair/OAuth authentication — holds high or critical effective privilege.",
                evidence=base_evidence,
                remediation={
                    "summary": "Migrate this identity off LEGACY_SERVICE and reduce its privilege.",
                    "steps": [
                        "Migrate the identity to TYPE = SERVICE with key-pair or OAuth authentication.",
                        "Review whether this identity's current privilege level is still required.",
                    ],
                },
                record_id=record_id,
            ))
        else:
            out.append(FindingCandidate(
                provider="snowflake",
                rule_key=_RULE_LEGACY_SERVICE_USER,
                finding_key=make_finding_key(_RULE_LEGACY_SERVICE_USER, record_id),
                severity="medium",
                title="Legacy service user authentication model in use",
                description="A Snowflake user is configured as LEGACY_SERVICE, a transitional type that permits password authentication for what should be a service identity. Current Snowflake documentation is deprecating this type in favor of SERVICE with key-pair/OAuth authentication.",
                evidence=base_evidence,
                remediation={
                    "summary": "Migrate this identity to the SERVICE user type with key-pair or OAuth authentication.",
                    "steps": [
                        "Plan migration off LEGACY_SERVICE before Snowflake's documented deprecation takes effect.",
                        "Configure key-pair or OAuth authentication and switch TYPE to SERVICE.",
                    ],
                },
                record_id=record_id,
            ))

    high_risk_future = record.get("high_risk_future_grant_count")
    if (
        isinstance(high_risk_future, int) and high_risk_future > 0
        and not record.get("has_accountadmin") and not record.get("has_securityadmin")
        and not record.get("has_manage_grants")
    ):
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_USER_HIGH_RISK_FUTURE_GRANT,
            finding_key=make_finding_key(_RULE_USER_HIGH_RISK_FUTURE_GRANT, record_id),
            severity="medium",
            title="User's effective roles carry high-risk future grants",
            description="A Snowflake user's effective role set (direct or inherited) carries future-ownership or broad future-grant authority — newly created matching objects would inherit this access automatically.",
            evidence={**base_evidence, "high_risk_future_grant_count": high_risk_future},
            remediation={
                "summary": "Review the future grants held by this user's effective roles.",
                "steps": [
                    "Confirm the future-grant authority is intentional.",
                    "Narrow or remove future OWNERSHIP/broad grants if account-wide automatic inheritance is not intended.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── Privileged role ──────────────────────────────────────────────────────────


def _eval_privileged_role(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    role_name = get_str(record, "role_name")
    role_type = get_str(record, "role_type")
    role_category = get_str(record, "role_category")
    tier = record.get("highest_known_privilege_tier")
    categories = record.get("global_privilege_categories") or []
    is_custom = role_category == ROLE_CATEGORY_CUSTOM
    is_high_or_critical = tier in _HIGH_OR_CRITICAL_TIERS

    base_evidence = {**evidence, "role_name": role_name, "role_type": role_type, "privilege_tier": tier}

    if is_custom and record.get("has_manage_grants") is True:
        if ROLE_PRIVILEGE_CATEGORY_IDENTITY_ADMINISTRATION in categories:
            out.append(FindingCandidate(
                provider="snowflake",
                rule_key=_RULE_CUSTOM_ROLE_MANAGE_GRANTS_IDENTITY_ADMIN,
                finding_key=make_finding_key(_RULE_CUSTOM_ROLE_MANAGE_GRANTS_IDENTITY_ADMIN, record_id),
                severity="critical",
                title="Custom role combines grant management with identity administration",
                description="A custom Snowflake role holds MANAGE GRANTS together with identity-administration privilege (CREATE USER/CREATE ROLE) — an admin-equivalent combination regardless of the role's name.",
                evidence={**base_evidence, "global_privilege_categories": categories},
                remediation={
                    "summary": "Split this role's authority or remove the combined capability.",
                    "steps": [
                        "Confirm both MANAGE GRANTS and identity-administration authority are required together.",
                        "Split grant management and identity administration into separate, narrower roles where possible.",
                    ],
                },
                record_id=record_id,
            ))
        else:
            out.append(FindingCandidate(
                provider="snowflake",
                rule_key=_RULE_CUSTOM_ROLE_MANAGE_GRANTS,
                finding_key=make_finding_key(_RULE_CUSTOM_ROLE_MANAGE_GRANTS, record_id),
                severity="high",
                title="Custom role can manage grants",
                description="A custom Snowflake role holds MANAGE GRANTS, allowing it to grant or revoke privileges on objects it does not own — classified from its actual observed grants, never from its name.",
                evidence=base_evidence,
                remediation={
                    "summary": "Review whether this custom role requires MANAGE GRANTS.",
                    "steps": [
                        "Confirm the grant-management authority matches this role's intended purpose.",
                        "Remove broad grant-management authority where it is not necessary.",
                    ],
                },
                record_id=record_id,
            ))
    elif is_custom and tier == "high":
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_CUSTOM_ROLE_HIGH_PRIVILEGE,
            finding_key=make_finding_key(_RULE_CUSTOM_ROLE_HIGH_PRIVILEGE, record_id),
            severity="high",
            title="Custom role has high effective privilege",
            description="A custom Snowflake role's actual observed grants (identity administration, object creation, or broad ownership) place it at a high effective privilege tier — never inferred from the role's display name.",
            evidence={**base_evidence, "global_privilege_categories": categories},
            remediation={
                "summary": "Confirm this custom role's privilege scope matches its intended purpose.",
                "steps": [
                    "Review the role's actual grants against its intended, narrower responsibility.",
                    "Split the role or remove high-impact grants if full high-tier access is not required.",
                ],
            },
            record_id=record_id,
        ))

    managed_schema_count = record.get("owns_managed_access_schema_count")
    if is_custom and isinstance(managed_schema_count, int) and managed_schema_count > 0:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_ROLE_CONTROLS_MANAGED_ACCESS_SCHEMA,
            finding_key=make_finding_key(_RULE_ROLE_CONTROLS_MANAGED_ACCESS_SCHEMA, record_id),
            severity="high",
            title="Role controls a managed-access schema",
            description="A custom Snowflake role owns a managed-access schema. In a managed-access schema, grant decisions reside with the schema owner (or a role holding MANAGE GRANTS) rather than individual object owners.",
            evidence={**base_evidence, "owns_managed_access_schema_count": managed_schema_count},
            remediation={
                "summary": "Confirm this role's managed-access-schema authority is intentional.",
                "steps": [
                    "Review who can request grant changes in this schema through this role.",
                    "Confirm the role owning this managed-access schema is the intended, tightly-controlled owner.",
                ],
            },
            record_id=record_id,
        ))

    security_int_count = record.get("owns_security_integration_count")
    if is_custom and is_high_or_critical and isinstance(security_int_count, int) and security_int_count > 0:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_ROLE_OWNS_SECURITY_INTEGRATION,
            finding_key=make_finding_key(_RULE_ROLE_OWNS_SECURITY_INTEGRATION, record_id),
            severity="high",
            title="High-privilege custom role owns a security integration",
            description="A custom Snowflake role with high or critical effective privilege owns a security integration (SAML/OAuth/OIDC/SCIM/API authentication), materially affecting the account's trust boundary.",
            evidence={**base_evidence, "owns_security_integration_count": security_int_count},
            remediation={
                "summary": "Review whether this role's combined privilege and integration ownership are both necessary.",
                "steps": [
                    "Confirm this role is the intended, tightly-controlled owner of the integration.",
                    "Consider separating integration ownership from broad account privilege.",
                ],
            },
            record_id=record_id,
        ))

    storage_int_count = record.get("owns_storage_integration_count")
    if is_custom and is_high_or_critical and isinstance(storage_int_count, int) and storage_int_count > 0:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_ROLE_OWNS_STORAGE_INTEGRATION,
            finding_key=make_finding_key(_RULE_ROLE_OWNS_STORAGE_INTEGRATION, record_id),
            severity="medium",
            title="High-privilege custom role owns a storage integration",
            description="A custom Snowflake role with high or critical effective privilege owns a storage integration used for external stages.",
            evidence={**base_evidence, "owns_storage_integration_count": storage_int_count},
            remediation={
                "summary": "Confirm this role's combined privilege and storage-integration ownership are both necessary.",
                "steps": [
                    "Review whether integration ownership should be separated from broad account privilege.",
                ],
            },
            record_id=record_id,
        ))

    ext_access_count = record.get("owns_external_access_integration_count")
    if is_custom and is_high_or_critical and isinstance(ext_access_count, int) and ext_access_count > 0:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_ROLE_OWNS_EXTERNAL_ACCESS_INTEGRATION,
            finding_key=make_finding_key(_RULE_ROLE_OWNS_EXTERNAL_ACCESS_INTEGRATION, record_id),
            severity="medium",
            title="High-privilege custom role owns an external access integration",
            description="A custom Snowflake role with high or critical effective privilege owns an external access integration, which permits outbound network connectivity for UDFs/procedures.",
            evidence={**base_evidence, "owns_external_access_integration_count": ext_access_count},
            remediation={
                "summary": "Confirm this role's combined privilege and external-access ownership are both necessary.",
                "steps": [
                    "Review whether integration ownership should be separated from broad account privilege.",
                ],
            },
            record_id=record_id,
        ))

    auth_policy_count = record.get("owns_authentication_policy_count")
    if is_custom and is_high_or_critical and isinstance(auth_policy_count, int) and auth_policy_count > 0:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_ROLE_OWNS_AUTHENTICATION_POLICY,
            finding_key=make_finding_key(_RULE_ROLE_OWNS_AUTHENTICATION_POLICY, record_id),
            severity="medium",
            title="High-privilege custom role owns an authentication policy",
            description="A custom Snowflake role with high or critical effective privilege owns an authentication policy, controlling MFA/authentication-method enforcement.",
            evidence={**base_evidence, "owns_authentication_policy_count": auth_policy_count},
            remediation={
                "summary": "Confirm this role's combined privilege and authentication-policy ownership are both necessary.",
                "steps": [
                    "Review whether authentication-policy ownership should be separated from broad account privilege.",
                ],
            },
            record_id=record_id,
        ))

    net_policy_count = record.get("owns_network_policy_count")
    if is_custom and is_high_or_critical and isinstance(net_policy_count, int) and net_policy_count > 0:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_ROLE_OWNS_NETWORK_POLICY,
            finding_key=make_finding_key(_RULE_ROLE_OWNS_NETWORK_POLICY, record_id),
            severity="medium",
            title="High-privilege custom role owns a network policy",
            description="A custom Snowflake role with high or critical effective privilege owns a network policy, controlling account network-access restrictions.",
            evidence={**base_evidence, "owns_network_policy_count": net_policy_count},
            remediation={
                "summary": "Confirm this role's combined privilege and network-policy ownership are both necessary.",
                "steps": [
                    "Review whether network-policy ownership should be separated from broad account privilege.",
                ],
            },
            record_id=record_id,
        ))

    db_count = record.get("owns_database_count")
    if is_custom and is_high_or_critical and isinstance(db_count, int) and db_count > 0:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_HIGH_PRIVILEGE_ROLE_OWNS_DATABASE,
            finding_key=make_finding_key(_RULE_HIGH_PRIVILEGE_ROLE_OWNS_DATABASE, record_id),
            severity="medium",
            title="High-privilege custom role owns a database",
            description="A custom Snowflake role with high or critical effective privilege owns a database — only an account role can own a database (per current Snowflake documentation), concentrating both broad privilege and object control in one role.",
            evidence={**base_evidence, "owns_database_count": db_count},
            remediation={
                "summary": "Confirm database ownership and broad privilege are both intentionally concentrated in this role.",
                "steps": [
                    "Review whether database ownership should be separated from broad account-level privilege.",
                ],
            },
            record_id=record_id,
        ))

    future_ownership = record.get("future_ownership_count")
    if isinstance(future_ownership, int) and future_ownership > 0:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_FUTURE_OWNERSHIP_GRANT,
            finding_key=make_finding_key(_RULE_FUTURE_OWNERSHIP_GRANT, record_id),
            severity="high",
            title="Role holds a future OWNERSHIP grant",
            description="A Snowflake role holds a future OWNERSHIP grant — newly created matching objects will automatically be owned by this role.",
            evidence={**base_evidence, "future_ownership_count": future_ownership},
            remediation={
                "summary": "Review the future OWNERSHIP grant for this role.",
                "steps": [
                    "Confirm automatic ownership of newly created objects is intentional for this role.",
                    "Narrow the future grant's scope if account-wide automatic ownership is not intended.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── PUBLIC exposure ───────────────────────────────────────────────────────────


def _eval_public_exposure(record: dict[str, Any]) -> list[FindingCandidate]:
    """PUBLIC != internet public. Every Finding below describes account-
    wide availability through Snowflake's automatic PUBLIC role, never
    internet/anonymous exposure."""
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)

    future_ownership = record.get("future_public_ownership_count")
    future_write = record.get("future_public_write_count")
    future_read = record.get("future_public_read_count")
    future_total = record.get("future_public_exposure_count")

    if isinstance(future_ownership, int) and future_ownership > 0:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_PUBLIC_FUTURE_OWNERSHIP_GRANT,
            finding_key=make_finding_key(_RULE_PUBLIC_FUTURE_OWNERSHIP_GRANT, record_id),
            severity="critical",
            title="Future OWNERSHIP grant to PUBLIC",
            description="A future OWNERSHIP grant exists for Snowflake's PUBLIC role — every Snowflake user in the account would gain ownership of newly created matching objects through the PUBLIC role.",
            evidence={**evidence, "future_public_ownership_count": future_ownership},
            remediation={
                "summary": "Review the future OWNERSHIP grant to PUBLIC.",
                "steps": [
                    "Grant future ownership to an explicit account or database role instead of PUBLIC.",
                    "Confirm account-wide automatic ownership was intended.",
                ],
            },
            record_id=record_id,
        ))
    if isinstance(future_write, int) and future_write > 0:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_PUBLIC_FUTURE_WRITE_ACCESS,
            finding_key=make_finding_key(_RULE_PUBLIC_FUTURE_WRITE_ACCESS, record_id),
            severity="high",
            title="Future write access granted to PUBLIC",
            description="A future data-write grant (INSERT/UPDATE/DELETE/TRUNCATE) exists for Snowflake's PUBLIC role — newly created matching objects will be writable by every Snowflake user through the PUBLIC role.",
            evidence={**evidence, "future_public_write_count": future_write},
            remediation={
                "summary": "Review the future write grant to PUBLIC.",
                "steps": [
                    "Grant future write access to explicit account or database roles when account-wide availability is not intended.",
                ],
            },
            record_id=record_id,
        ))
    if isinstance(future_read, int) and future_read > 0:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_PUBLIC_FUTURE_DATA_ACCESS,
            finding_key=make_finding_key(_RULE_PUBLIC_FUTURE_DATA_ACCESS, record_id),
            severity="high",
            title="Future data-read access granted to PUBLIC",
            description="A future SELECT/read grant exists for Snowflake's PUBLIC role — newly created matching objects will be readable by every Snowflake user through the PUBLIC role.",
            evidence={**evidence, "future_public_read_count": future_read},
            remediation={
                "summary": "Review the future grant to PUBLIC.",
                "steps": [
                    "Grant access to explicit account or database roles when account-wide availability is not intended.",
                ],
            },
            record_id=record_id,
        ))
    # These three counts are always real ints by construction (message 5's
    # `_derive_public_exposure` never leaves them ``None``) — explicit
    # `isinstance` checks are used anyway rather than `x or 0`, so a future
    # change that ever left one of them ``None`` would make this residual
    # comparison fail closed (never fire) instead of silently coercing an
    # unknown count to a safe-looking zero.
    accounted = (
        (future_ownership if isinstance(future_ownership, int) else 0)
        + (future_write if isinstance(future_write, int) else 0)
        + (future_read if isinstance(future_read, int) else 0)
    )
    if isinstance(future_total, int) and future_total > accounted:
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_PUBLIC_FUTURE_BROAD_PRIVILEGE,
            finding_key=make_finding_key(_RULE_PUBLIC_FUTURE_BROAD_PRIVILEGE, record_id),
            severity="medium",
            title="Future privilege granted to PUBLIC",
            description="A future grant (not categorized as read, write, or ownership — e.g. USAGE) exists for Snowflake's PUBLIC role, broadening what is available to every Snowflake user through the PUBLIC role for newly created matching objects.",
            evidence={**evidence, "future_public_exposure_count": future_total},
            remediation={
                "summary": "Review the future grant to PUBLIC.",
                "steps": [
                    "Grant access to explicit account or database roles when account-wide availability is not intended.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── Network policy ───────────────────────────────────────────────────────────


def _eval_network_policy(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    policy_name = get_str(record, "policy_name")

    if record.get("allows_anywhere_ipv4") == "true" or record.get("allows_anywhere_ipv6") == "true":
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_NETWORK_POLICY_ALLOWS_ANYWHERE,
            finding_key=make_finding_key(_RULE_NETWORK_POLICY_ALLOWS_ANYWHERE, record_id),
            severity="high",
            title="Network policy allows access from anywhere",
            description="A Snowflake network policy explicitly allows connections from anywhere (0.0.0.0/0 or ::/0).",
            evidence={
                **evidence, "policy_name": policy_name,
                "allows_anywhere_ipv4": record.get("allows_anywhere_ipv4"),
                "allows_anywhere_ipv6": record.get("allows_anywhere_ipv6"),
            },
            remediation={
                "summary": "Restrict the network policy to the expected client networks instead of an anywhere CIDR.",
                "steps": [
                    "Replace the anywhere CIDR range with the specific networks that should be permitted.",
                    "Confirm the restricted policy still permits legitimate client access before applying.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── Authentication policy ─────────────────────────────────────────────────────


def _eval_authentication_policy(record: dict[str, Any]) -> list[FindingCandidate]:
    """MFA_ENROLLMENT semantics confirmed via current official Snowflake
    docs (CREATE AUTHENTICATION POLICY reference): REQUIRED covers
    password AND SSO authentication; REQUIRED_PASSWORD_ONLY covers only
    password authentication (SSO users are exempt — narrower coverage);
    OPTIONAL is retained for backward compatibility only (the weak,
    legacy state). Only ``set_on == "ACCOUNT"`` policies are evaluated
    here — an account-wide policy unambiguously affects person users too;
    a policy scoped to a specific named user's type is unknown to this
    evaluator and is never guessed at (service-user policies are never
    mistaken for a human-MFA weakness)."""
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    policy_name = get_str(record, "policy_name")
    set_on = record.get("set_on")
    mfa = record.get("mfa_enrollment")
    methods = record.get("authentication_methods") or []

    if set_on != "ACCOUNT":
        return out

    base_evidence = {**evidence, "policy_name": policy_name, "mfa_enrollment": mfa, "set_on": set_on}

    if mfa == "optional":
        if isinstance(methods, list) and ("password" in methods or "all" in methods):
            out.append(FindingCandidate(
                provider="snowflake",
                rule_key=_RULE_MFA_OPTIONAL_WITH_PASSWORD,
                finding_key=make_finding_key(_RULE_MFA_OPTIONAL_WITH_PASSWORD, record_id),
                severity="medium",
                title="Account-wide MFA is optional with password authentication allowed",
                description="The Snowflake account's authentication policy allows password authentication and does not require MFA enrollment.",
                evidence={**base_evidence, "authentication_methods": methods},
                remediation={
                    "summary": "Require MFA enrollment for password-authenticating users.",
                    "steps": [
                        "Set MFA_ENROLLMENT to REQUIRED (or REQUIRED_PASSWORD_ONLY at minimum) on the account-wide authentication policy.",
                    ],
                },
                record_id=record_id,
            ))
        else:
            out.append(FindingCandidate(
                provider="snowflake",
                rule_key=_RULE_MFA_OPTIONAL_FOR_PERSON_AUTH,
                finding_key=make_finding_key(_RULE_MFA_OPTIONAL_FOR_PERSON_AUTH, record_id),
                severity="medium",
                title="Account-wide MFA enrollment is optional",
                description="The Snowflake account's authentication policy does not require MFA enrollment for human users.",
                evidence=base_evidence,
                remediation={
                    "summary": "Require MFA enrollment on the account-wide authentication policy.",
                    "steps": [
                        "Set MFA_ENROLLMENT to REQUIRED (or REQUIRED_PASSWORD_ONLY at minimum).",
                    ],
                },
                record_id=record_id,
            ))
    elif mfa == "required_password_only":
        out.append(FindingCandidate(
            provider="snowflake",
            rule_key=_RULE_MFA_PASSWORD_ONLY_SCOPE,
            finding_key=make_finding_key(_RULE_MFA_PASSWORD_ONLY_SCOPE, record_id),
            severity="medium",
            title="MFA enrollment is required only for password authentication",
            description="The Snowflake account's authentication policy requires MFA enrollment only for password-authenticating users — single-sign-on users are exempt from this requirement, a narrower coverage than REQUIRED.",
            evidence=base_evidence,
            remediation={
                "summary": "Consider requiring MFA enrollment for SSO users as well.",
                "steps": [
                    "Set MFA_ENROLLMENT to REQUIRED to cover both password and SSO authentication, if SSO coverage is desired.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── Security integration ─────────────────────────────────────────────────────


def _eval_security_integration(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    integration_name = get_str(record, "integration_name")
    integration_type = record.get("integration_type")
    enabled = record.get("enabled")

    if integration_type == "scim":
        run_as_role = get_str(record, "scim_run_as_role")
        run_as_tier = record.get("scim_run_as_role_tier")
        run_as_manage_grants = record.get("scim_run_as_role_has_manage_grants")
        scim_evidence = {
            **evidence, "integration_name": integration_name, "scim_run_as_role": run_as_role,
            "scim_run_as_role_tier": run_as_tier, "scim_run_as_role_has_manage_grants": run_as_manage_grants,
        }
        if run_as_tier == "critical":
            out.append(FindingCandidate(
                provider="snowflake",
                rule_key=_RULE_SCIM_CRITICAL_PRIVILEGE_RUN_AS,
                finding_key=make_finding_key(_RULE_SCIM_CRITICAL_PRIVILEGE_RUN_AS, record_id),
                severity="critical",
                title="SCIM integration provisions using a critical-privilege role",
                description="A Snowflake SCIM integration's run-as role resolves to critical effective privilege (ACCOUNTADMIN-equivalent) — every user/role SCIM provisions is owned by this critical-privilege role.",
                evidence=scim_evidence,
                remediation={
                    "summary": "Use the narrowest Snowflake role required for SCIM provisioning rather than a critical-privilege administrative role.",
                    "steps": [
                        "Create a dedicated provisioner role scoped to CREATE USER/CREATE ROLE only.",
                        "Update the SCIM security integration's RUN_AS_ROLE to the narrower role.",
                    ],
                },
                record_id=record_id,
            ))
        elif run_as_tier == "high":
            out.append(FindingCandidate(
                provider="snowflake",
                rule_key=_RULE_SCIM_HIGH_PRIVILEGE_RUN_AS,
                finding_key=make_finding_key(_RULE_SCIM_HIGH_PRIVILEGE_RUN_AS, record_id),
                severity="high",
                title="SCIM integration provisions using a high-privilege role",
                description="A Snowflake SCIM integration's run-as role resolves to high effective privilege — every user/role SCIM provisions is owned by this high-privilege role.",
                evidence=scim_evidence,
                remediation={
                    "summary": "Use the narrowest Snowflake role required for SCIM provisioning rather than a broadly privileged role.",
                    "steps": [
                        "Create a dedicated provisioner role scoped to CREATE USER/CREATE ROLE only.",
                        "Update the SCIM security integration's RUN_AS_ROLE to the narrower role.",
                    ],
                },
                record_id=record_id,
            ))

    if integration_type == "saml2" and enabled == "true":
        issuer = record.get("saml2_issuer_configured")
        sso = record.get("saml2_sso_url_configured")
        cert = record.get("saml2_certificate_configured")
        if issuer == "false" or sso == "false" or cert == "false":
            out.append(FindingCandidate(
                provider="snowflake",
                rule_key=_RULE_SAML_INTEGRATION_INCOMPLETE_CONFIG,
                finding_key=make_finding_key(_RULE_SAML_INTEGRATION_INCOMPLETE_CONFIG, record_id),
                severity="medium",
                title="Enabled SAML integration is missing required configuration",
                description="An enabled Snowflake SAML security integration is missing its issuer, SSO URL, or certificate configuration.",
                evidence={
                    **evidence, "integration_name": integration_name,
                    "saml2_issuer_configured": issuer, "saml2_sso_url_configured": sso,
                    "saml2_certificate_configured": cert,
                },
                remediation={
                    "summary": "Complete the SAML integration's configuration or disable it until it is ready.",
                    "steps": [
                        "Configure the missing SAML2_ISSUER/SAML2_SSO_URL/SAML2_X509_CERT parameter(s).",
                        "Disable the integration if it is not yet ready for use.",
                    ],
                },
                record_id=record_id,
            ))

    return out
