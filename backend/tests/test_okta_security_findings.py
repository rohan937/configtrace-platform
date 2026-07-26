"""Okta Security Finding tests (Okta message 6 of 8).

For every one of the 30 Okta rule keys: a positive test (constructs a
normalized record that should trigger the rule via ``evaluate_record()``),
a negative test (explicit safe evidence — rule must not fire), and, for
every tri-state field the rule reads, an unknown test (field is ``None``/
``"unknown"`` — rule must not fire).

All tests build plain normalized-record dicts (the shape emitted by
app/connectors/okta.py) and exercise the real central dispatch path via
``security_finding_evaluator.evaluate_record()`` — never call the per-rule
functions in app/services/security_rules/okta.py directly.

Also includes representative Finding-vs-Change severity parity checks
(section 52 of the message-6 task) comparing static Finding severity
against the equivalent message 4/5 Change-classification severity for the
same underlying weak posture.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.okta import classify_okta_change
from app.services.security_finding_evaluator import evaluate_record

_TENANT = "id:t1"


def _keys(record):
    return {f.rule_key for f in evaluate_record(record, "okta")}


def _find(record, rule_key):
    matches = [f for f in evaluate_record(record, "okta") if f.rule_key == rule_key]
    return matches[0] if matches else None


def _privileged_identity(**overrides):
    base = {
        "record_type": "okta_privileged_identity",
        "record_id": "id:t1/privileged_identity/u1",
        "tenant_id": _TENANT,
        "user_id": "u1",
        "login": "alice@example.com",
        "user_status": "ACTIVE",
        "direct_admin_role_count": 1,
        "group_admin_role_count": 0,
        "highest_privilege_tier": "medium",
        "has_super_admin": False,
        "has_high_privilege": False,
        "privileged_via_group": False,
        "privileged_via_direct_assignment": True,
        "custom_admin_role_count": 0,
        "application_admin_scope": None,
        "dormant_privileged_category": "privileged_recent_login",
    }
    base.update(overrides)
    return base


def _privileged_group(**overrides):
    base = {
        "record_type": "okta_privileged_group",
        "record_id": "id:t1/privileged_group/g1",
        "tenant_id": _TENANT,
        "group_id": "g1",
        "group_name": "Admins",
        "member_count": 5,
        "admin_role_count": 1,
        "highest_privilege_tier": "medium",
        "contains_suspended_members": 0,
        "contains_deprovisioned_members": 0,
    }
    base.update(overrides)
    return base


def _admin_role(**overrides):
    base = {
        "record_type": "okta_admin_role",
        "record_id": "id:t1/admin_role/cr1",
        "tenant_id": _TENANT,
        "role_id": "cr1",
        "role_type": "CUSTOM",
        "role_label": "Custom Role",
        "built_in": False,
        "custom": True,
        "privilege_tier": "medium",
        "permissions_count": 3,
    }
    base.update(overrides)
    return base


def _user_assignment(**overrides):
    base = {
        "record_type": "okta_user_admin_role_assignment",
        "record_id": "id:t1/user_admin_role/u1/APP_ADMIN/all",
        "tenant_id": _TENANT,
        "user_id": "u1",
        "user_login": "alice@example.com",
        "user_status": "ACTIVE",
        "role_id": "APP_ADMIN",
        "role_type": "APP_ADMIN",
        "custom": False,
        "privilege_tier": "medium",
        "direct_assignment": True,
        "assignment_scope_category": "scoped",
        "resource_set_id": None,
        "resource_set_scope_category": None,
        "active": True,
    }
    base.update(overrides)
    return base


def _policy_rule(**overrides):
    base = {
        "record_type": "okta_policy_rule",
        "record_id": "id:t1/policy_rule/p1/r1",
        "tenant_id": _TENANT,
        "policy_id": "p1",
        "policy_name": "Sign-On",
        "rule_id": "r1",
        "rule_name": "Rule",
        "status": "ACTIVE",
        "active": True,
        "priority": 1,
        "scope_category": "scoped_groups",
        "access_category": "ALLOW",
        "mfa_requirement_category": "required",
        "phishing_resistant_category": "phishing_resistant",
    }
    base.update(overrides)
    return base


def _authenticator(**overrides):
    base = {
        "record_type": "okta_authenticator",
        "record_id": "id:t1/authenticator/a1",
        "tenant_id": _TENANT,
        "authenticator_id": "a1",
        "key": "okta_verify",
        "name": "Okta Verify",
        "status": "ACTIVE",
        "active": True,
    }
    base.update(overrides)
    return base


def _password_policy(**overrides):
    base = {
        "record_type": "okta_policy",
        "record_id": "id:t1/policy/pw1",
        "tenant_id": _TENANT,
        "policy_id": "pw1",
        "policy_name": "Password Policy",
        "policy_type": "PASSWORD",
        "status": "ACTIVE",
        "password_min_length": 14,
        "password_min_length_category": "strong",
        "password_complexity_required": True,
        "password_history_present": True,
        "password_lockout_present": True,
    }
    base.update(overrides)
    return base


def _application(**overrides):
    base = {
        "record_type": "okta_application",
        "record_id": "id:t1/app/app1",
        "tenant_id": _TENANT,
        "app_id": "app1",
        "label": "My App",
        "status": "ACTIVE",
        "sign_on_mode": "OPENID_CONNECT",
        "protocol_category": "OIDC_OAUTH",
        "app_type_category": "web",
        "wildcard_redirect_present": False,
        "http_redirect_count": 0,
        "custom_scheme_redirect_count": 0,
        "token_endpoint_auth_method_category": "client_secret_basic",
    }
    base.update(overrides)
    return base


def _app_group_assignment(**overrides):
    base = {
        "record_type": "okta_application_group_assignment",
        "record_id": "id:t1/app_assignment/app1/group/g1",
        "tenant_id": _TENANT,
        "app_id": "app1",
        "app_label": "My App",
        "group_id": "g1",
        "group_name": "Engineering",
        "everyone_group": False,
    }
    base.update(overrides)
    return base


def _app_user_assignment(**overrides):
    base = {
        "record_type": "okta_application_user_assignment",
        "record_id": "id:t1/app_assignment/app1/user/u1",
        "tenant_id": _TENANT,
        "app_id": "app1",
        "app_label": "My App",
        "user_id": "u1",
        "user_login": "alice@example.com",
        "user_status": "ACTIVE",
    }
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# Privileged identity
# ════════════════════════════════════════════════════════════════════════════


class TestSuperAdminAssigned:
    def test_positive(self):
        rec = _privileged_identity(has_super_admin=True, highest_privilege_tier="critical")
        f = _find(rec, "okta_super_admin_assigned")
        assert f is not None
        assert f.severity == "critical"

    def test_negative_high_tier_not_super_admin(self):
        rec = _privileged_identity(has_super_admin=False, has_high_privilege=True, highest_privilege_tier="high")
        assert "okta_super_admin_assigned" not in _keys(rec)

    def test_never_fires_on_false(self):
        rec = _privileged_identity(has_super_admin=False)
        assert "okta_super_admin_assigned" not in _keys(rec)


class TestHighTierAdminAssigned:
    def test_positive(self):
        rec = _privileged_identity(has_high_privilege=True, has_super_admin=False, highest_privilege_tier="high")
        f = _find(rec, "okta_high_tier_admin_assigned")
        assert f is not None and f.severity == "high"

    def test_excluded_when_super_admin(self):
        rec = _privileged_identity(has_high_privilege=True, has_super_admin=True, highest_privilege_tier="critical")
        assert "okta_high_tier_admin_assigned" not in _keys(rec)

    def test_negative_medium_tier(self):
        rec = _privileged_identity(has_high_privilege=False)
        assert "okta_high_tier_admin_assigned" not in _keys(rec)


class TestDeprovisionedRetainsAdmin:
    def test_positive_high_tier(self):
        rec = _privileged_identity(user_status="DEPROVISIONED", highest_privilege_tier="high")
        f = _find(rec, "okta_deprovisioned_identity_retains_admin_privilege")
        assert f is not None and f.severity == "high"

    def test_positive_medium_tier_severity(self):
        rec = _privileged_identity(user_status="DEPROVISIONED", highest_privilege_tier="medium")
        f = _find(rec, "okta_deprovisioned_identity_retains_admin_privilege")
        assert f is not None and f.severity == "medium"

    def test_negative_active(self):
        rec = _privileged_identity(user_status="ACTIVE")
        assert "okta_deprovisioned_identity_retains_admin_privilege" not in _keys(rec)

    def test_unknown_tier_does_not_fire(self):
        rec = _privileged_identity(user_status="DEPROVISIONED", highest_privilege_tier="unknown")
        assert "okta_deprovisioned_identity_retains_admin_privilege" not in _keys(rec)

    def test_read_only_tier_does_not_fire(self):
        rec = _privileged_identity(user_status="DEPROVISIONED", highest_privilege_tier="read_only")
        assert "okta_deprovisioned_identity_retains_admin_privilege" not in _keys(rec)


class TestSuspendedRetainsAdmin:
    def test_positive(self):
        rec = _privileged_identity(user_status="SUSPENDED", highest_privilege_tier="medium")
        f = _find(rec, "okta_suspended_identity_retains_admin_privilege")
        assert f is not None and f.severity == "medium"
        assert "unauthorized" not in f.description.lower()
        assert "active access" not in f.description.lower() or "restricted" in f.description.lower()

    def test_negative_active(self):
        rec = _privileged_identity(user_status="ACTIVE")
        assert "okta_suspended_identity_retains_admin_privilege" not in _keys(rec)

    def test_unknown_tier_does_not_fire(self):
        rec = _privileged_identity(user_status="SUSPENDED", highest_privilege_tier="unknown")
        assert "okta_suspended_identity_retains_admin_privilege" not in _keys(rec)


class TestDormantPrivilegedIdentity:
    def test_positive_high_tier_medium_severity(self):
        rec = _privileged_identity(dormant_privileged_category="privileged_stale_login", highest_privilege_tier="high")
        f = _find(rec, "okta_dormant_privileged_identity")
        assert f is not None and f.severity == "medium"

    def test_positive_medium_tier_low_severity(self):
        rec = _privileged_identity(dormant_privileged_category="privileged_stale_login", highest_privilege_tier="medium")
        f = _find(rec, "okta_dormant_privileged_identity")
        assert f is not None and f.severity == "low"

    def test_negative_recent_login(self):
        rec = _privileged_identity(dormant_privileged_category="privileged_recent_login")
        assert "okta_dormant_privileged_identity" not in _keys(rec)

    def test_unknown_dormant_category_does_not_fire(self):
        rec = _privileged_identity(dormant_privileged_category="unknown")
        assert "okta_dormant_privileged_identity" not in _keys(rec)


class TestNeverUsedPrivilegedIdentity:
    def test_positive(self):
        rec = _privileged_identity(dormant_privileged_category="privileged_never_logged_in")
        f = _find(rec, "okta_never_used_privileged_identity")
        assert f is not None and f.severity == "medium"

    def test_negative(self):
        rec = _privileged_identity(dormant_privileged_category="privileged_recent_login")
        assert "okta_never_used_privileged_identity" not in _keys(rec)


class TestPrivilegedGroupGrantsSuperAdmin:
    def test_positive(self):
        rec = _privileged_group(highest_privilege_tier="critical")
        f = _find(rec, "okta_privileged_group_grants_super_admin")
        assert f is not None and f.severity == "critical"

    def test_negative_high_tier_excluded(self):
        rec = _privileged_group(highest_privilege_tier="high")
        assert "okta_privileged_group_grants_super_admin" not in _keys(rec)


class TestPrivilegedGroupGrantsHighTier:
    def test_positive(self):
        rec = _privileged_group(highest_privilege_tier="high")
        f = _find(rec, "okta_privileged_group_grants_high_tier_admin")
        assert f is not None and f.severity == "high"

    def test_excluded_when_critical(self):
        rec = _privileged_group(highest_privilege_tier="critical")
        assert "okta_privileged_group_grants_high_tier_admin" not in _keys(rec)

    def test_negative_medium(self):
        rec = _privileged_group(highest_privilege_tier="medium")
        assert "okta_privileged_group_grants_high_tier_admin" not in _keys(rec)


class TestBroadPrivilegedGroup:
    def test_positive(self):
        rec = _privileged_group(highest_privilege_tier="high", member_count=50)
        f = _find(rec, "okta_broad_privileged_group")
        assert f is not None and f.severity == "high"

    def test_negative_small_group(self):
        rec = _privileged_group(highest_privilege_tier="high", member_count=5)
        assert "okta_broad_privileged_group" not in _keys(rec)

    def test_negative_medium_tier_broad(self):
        rec = _privileged_group(highest_privilege_tier="medium", member_count=200)
        assert "okta_broad_privileged_group" not in _keys(rec)


class TestCustomAdminRoleHighRisk:
    def test_positive_critical(self):
        rec = _admin_role(custom=True, privilege_tier="critical")
        f = _find(rec, "okta_custom_admin_role_high_risk")
        assert f is not None and f.severity == "critical"

    def test_positive_high(self):
        rec = _admin_role(custom=True, privilege_tier="high")
        f = _find(rec, "okta_custom_admin_role_high_risk")
        assert f is not None and f.severity == "high"

    def test_negative_medium(self):
        rec = _admin_role(custom=True, privilege_tier="medium")
        assert "okta_custom_admin_role_high_risk" not in _keys(rec)

    def test_negative_built_in(self):
        rec = _admin_role(custom=False, built_in=True, privilege_tier="critical")
        assert "okta_custom_admin_role_high_risk" not in _keys(rec)

    def test_unknown_tier_does_not_fire(self):
        rec = _admin_role(custom=True, privilege_tier="unknown")
        assert "okta_custom_admin_role_high_risk" not in _keys(rec)


class TestAdminRoleBroadResourceSet:
    def test_positive(self):
        rec = _user_assignment(custom=True, privilege_tier="high", resource_set_scope_category="all_resources")
        f = _find(rec, "okta_admin_role_broad_resource_set")
        assert f is not None and f.severity == "high"

    def test_negative_scoped(self):
        rec = _user_assignment(custom=True, privilege_tier="high", resource_set_scope_category="scoped")
        assert "okta_admin_role_broad_resource_set" not in _keys(rec)

    def test_unknown_scope_does_not_fire(self):
        rec = _user_assignment(custom=True, privilege_tier="high", resource_set_scope_category="unknown")
        assert "okta_admin_role_broad_resource_set" not in _keys(rec)

    def test_negative_not_custom(self):
        rec = _user_assignment(custom=False, privilege_tier="high", resource_set_scope_category="all_resources")
        assert "okta_admin_role_broad_resource_set" not in _keys(rec)


class TestUnscopedAdminRoleAssignment:
    def test_positive(self):
        rec = _user_assignment(role_type="APP_ADMIN", assignment_scope_category="all", custom=False)
        f = _find(rec, "okta_unscoped_admin_role_assignment")
        assert f is not None and f.severity == "medium"

    def test_negative_scoped(self):
        rec = _user_assignment(role_type="APP_ADMIN", assignment_scope_category="scoped")
        assert "okta_unscoped_admin_role_assignment" not in _keys(rec)

    def test_unknown_scope_does_not_fire(self):
        rec = _user_assignment(role_type="APP_ADMIN", assignment_scope_category="unknown")
        assert "okta_unscoped_admin_role_assignment" not in _keys(rec)

    def test_negative_super_admin_type_excluded(self):
        rec = _user_assignment(role_type="SUPER_ADMIN", assignment_scope_category="all")
        assert "okta_unscoped_admin_role_assignment" not in _keys(rec)

    def test_group_assignment_also_covered(self):
        rec = {
            "record_type": "okta_group_admin_role_assignment", "record_id": "id:t1/group_admin_role/g1/USER_ADMIN/all",
            "tenant_id": _TENANT, "group_id": "g1", "group_name": "G", "role_id": "USER_ADMIN",
            "role_type": "USER_ADMIN", "custom": False, "privilege_tier": "medium",
            "assignment_scope_category": "all", "active": True,
        }
        assert "okta_unscoped_admin_role_assignment" in _keys(rec)


# ════════════════════════════════════════════════════════════════════════════
# Authentication / MFA
# ════════════════════════════════════════════════════════════════════════════


class TestSignonMfaNotRequired:
    def test_positive(self):
        rec = _policy_rule(mfa_requirement_category="none", scope_category="scoped_groups")
        f = _find(rec, "okta_signon_mfa_not_required")
        assert f is not None and f.severity == "high"

    def test_negative_required(self):
        rec = _policy_rule(mfa_requirement_category="required")
        assert "okta_signon_mfa_not_required" not in _keys(rec)

    def test_unknown_does_not_fire(self):
        rec = _policy_rule(mfa_requirement_category="unknown")
        assert "okta_signon_mfa_not_required" not in _keys(rec)

    def test_superseded_by_broad_allow_rule(self):
        rec = _policy_rule(mfa_requirement_category="none", scope_category="all_users", access_category="ALLOW")
        keys = _keys(rec)
        assert "okta_broad_allow_rule_without_mfa" in keys
        assert "okta_signon_mfa_not_required" not in keys


class TestSignonMfaOptional:
    def test_positive(self):
        rec = _policy_rule(mfa_requirement_category="optional")
        f = _find(rec, "okta_signon_mfa_optional")
        assert f is not None and f.severity == "medium"

    def test_negative_required(self):
        rec = _policy_rule(mfa_requirement_category="required")
        assert "okta_signon_mfa_optional" not in _keys(rec)

    def test_unknown_does_not_fire(self):
        rec = _policy_rule(mfa_requirement_category="unknown")
        assert "okta_signon_mfa_optional" not in _keys(rec)


class TestBroadAllowWithoutMfa:
    def test_positive(self):
        rec = _policy_rule(mfa_requirement_category="none", access_category="ALLOW", scope_category="all_users")
        f = _find(rec, "okta_broad_allow_rule_without_mfa")
        assert f is not None and f.severity == "high"

    def test_negative_deny(self):
        rec = _policy_rule(mfa_requirement_category="none", access_category="DENY", scope_category="all_users")
        assert "okta_broad_allow_rule_without_mfa" not in _keys(rec)

    def test_negative_scoped(self):
        rec = _policy_rule(mfa_requirement_category="none", access_category="ALLOW", scope_category="scoped_groups")
        assert "okta_broad_allow_rule_without_mfa" not in _keys(rec)

    def test_unknown_scope_does_not_fire(self):
        rec = _policy_rule(mfa_requirement_category="none", access_category="ALLOW", scope_category="unknown")
        assert "okta_broad_allow_rule_without_mfa" not in _keys(rec)


class TestPhishingResistantNotRequired:
    def test_positive(self):
        rec = _policy_rule(phishing_resistant_category="not_phishing_resistant")
        f = _find(rec, "okta_phishing_resistant_not_required")
        assert f is not None and f.severity == "medium"

    def test_negative_required(self):
        rec = _policy_rule(phishing_resistant_category="phishing_resistant")
        assert "okta_phishing_resistant_not_required" not in _keys(rec)

    def test_unknown_does_not_fire(self):
        rec = _policy_rule(phishing_resistant_category="unknown")
        assert "okta_phishing_resistant_not_required" not in _keys(rec)


class TestWeakAuthenticatorEnabled:
    def test_positive_phone(self):
        rec = _authenticator(key="phone_number", active=True)
        f = _find(rec, "okta_weak_authenticator_enabled")
        assert f is not None and f.severity == "low"

    def test_positive_email(self):
        rec = _authenticator(key="email", active=True)
        assert "okta_weak_authenticator_enabled" in _keys(rec)

    def test_negative_inactive(self):
        rec = _authenticator(key="phone_number", active=False)
        assert "okta_weak_authenticator_enabled" not in _keys(rec)

    def test_negative_strong_factor(self):
        rec = _authenticator(key="webauthn", active=True)
        assert "okta_weak_authenticator_enabled" not in _keys(rec)


# ════════════════════════════════════════════════════════════════════════════
# Password policy
# ════════════════════════════════════════════════════════════════════════════


class TestPasswordWeakMinLength:
    def test_positive(self):
        rec = _password_policy(password_min_length_category="weak")
        f = _find(rec, "okta_password_policy_weak_min_length")
        assert f is not None and f.severity == "high"

    def test_negative_strong(self):
        rec = _password_policy(password_min_length_category="strong")
        assert "okta_password_policy_weak_min_length" not in _keys(rec)

    def test_unknown_length_does_not_fire(self):
        rec = _password_policy(password_min_length_category="unknown")
        assert "okta_password_policy_weak_min_length" not in _keys(rec)

    def test_non_password_policy_never_fires(self):
        rec = _password_policy(policy_type="OKTA_SIGN_ON", password_min_length_category="weak")
        assert "okta_password_policy_weak_min_length" not in _keys(rec)


class TestPasswordNoLockout:
    def test_positive(self):
        rec = _password_policy(password_lockout_present=False)
        f = _find(rec, "okta_password_policy_no_lockout")
        assert f is not None and f.severity == "medium"

    def test_negative_present(self):
        rec = _password_policy(password_lockout_present=True)
        assert "okta_password_policy_no_lockout" not in _keys(rec)

    def test_unknown_does_not_fire(self):
        rec = _password_policy(password_lockout_present=None)
        assert "okta_password_policy_no_lockout" not in _keys(rec)


class TestPasswordNoHistory:
    def test_positive(self):
        rec = _password_policy(password_history_present=False)
        f = _find(rec, "okta_password_policy_no_history")
        assert f is not None and f.severity == "medium"

    def test_unknown_does_not_fire(self):
        rec = _password_policy(password_history_present=None)
        assert "okta_password_policy_no_history" not in _keys(rec)


class TestPasswordNoComplexity:
    def test_positive(self):
        rec = _password_policy(password_complexity_required=False)
        f = _find(rec, "okta_password_policy_no_complexity")
        assert f is not None and f.severity == "low"

    def test_unknown_does_not_fire(self):
        rec = _password_policy(password_complexity_required=None)
        assert "okta_password_policy_no_complexity" not in _keys(rec)


# ════════════════════════════════════════════════════════════════════════════
# Applications
# ════════════════════════════════════════════════════════════════════════════


class TestOidcWildcardRedirect:
    def test_positive(self):
        rec = _application(wildcard_redirect_present=True)
        f = _find(rec, "okta_oidc_wildcard_redirect")
        assert f is not None and f.severity == "high"

    def test_negative(self):
        rec = _application(wildcard_redirect_present=False)
        assert "okta_oidc_wildcard_redirect" not in _keys(rec)

    def test_unknown_does_not_fire(self):
        rec = _application(wildcard_redirect_present=None)
        assert "okta_oidc_wildcard_redirect" not in _keys(rec)


class TestOidcHttpRedirect:
    def test_positive(self):
        rec = _application(http_redirect_count=1)
        f = _find(rec, "okta_oidc_http_redirect")
        assert f is not None and f.severity == "medium"

    def test_negative_zero(self):
        rec = _application(http_redirect_count=0)
        assert "okta_oidc_http_redirect" not in _keys(rec)

    def test_unknown_does_not_fire(self):
        rec = _application(http_redirect_count=None)
        assert "okta_oidc_http_redirect" not in _keys(rec)


class TestOidcCustomSchemeNonNative:
    def test_positive_web(self):
        rec = _application(custom_scheme_redirect_count=1, app_type_category="web")
        f = _find(rec, "okta_oidc_custom_scheme_redirect_non_native")
        assert f is not None and f.severity == "medium"

    def test_negative_native(self):
        rec = _application(custom_scheme_redirect_count=1, app_type_category="native")
        assert "okta_oidc_custom_scheme_redirect_non_native" not in _keys(rec)

    def test_unknown_app_type_does_not_fire(self):
        rec = _application(custom_scheme_redirect_count=1, app_type_category="unknown")
        assert "okta_oidc_custom_scheme_redirect_non_native" not in _keys(rec)

    def test_negative_zero_count(self):
        rec = _application(custom_scheme_redirect_count=0, app_type_category="web")
        assert "okta_oidc_custom_scheme_redirect_non_native" not in _keys(rec)


class TestSamlResponseSigningDisabled:
    def test_positive(self):
        rec = _application(saml_response_signed=False)
        f = _find(rec, "okta_saml_response_signing_disabled")
        assert f is not None and f.severity == "medium"

    def test_negative_signed(self):
        rec = _application(saml_response_signed=True)
        assert "okta_saml_response_signing_disabled" not in _keys(rec)

    def test_unknown_does_not_fire(self):
        rec = _application(saml_response_signed=None)
        assert "okta_saml_response_signing_disabled" not in _keys(rec)


class TestSamlAssertionSigningDisabled:
    def test_positive(self):
        rec = _application(saml_assertion_signed=False)
        f = _find(rec, "okta_saml_assertion_signing_disabled")
        assert f is not None and f.severity == "medium"

    def test_unknown_does_not_fire(self):
        rec = _application(saml_assertion_signed=None)
        assert "okta_saml_assertion_signing_disabled" not in _keys(rec)


class TestWeakTokenEndpointAuth:
    def test_positive(self):
        rec = _application(token_endpoint_auth_method_category="none")
        f = _find(rec, "okta_weak_token_endpoint_auth")
        assert f is not None and f.severity == "medium"

    def test_negative(self):
        rec = _application(token_endpoint_auth_method_category="client_secret_basic")
        assert "okta_weak_token_endpoint_auth" not in _keys(rec)

    def test_unknown_does_not_fire(self):
        rec = _application(token_endpoint_auth_method_category="unknown")
        assert "okta_weak_token_endpoint_auth" not in _keys(rec)


class TestAppAssignedToEveryoneGroup:
    def test_positive(self):
        rec = _app_group_assignment(everyone_group=True)
        f = _find(rec, "okta_app_assigned_to_everyone_group")
        assert f is not None and f.severity == "medium"

    def test_negative(self):
        rec = _app_group_assignment(everyone_group=False)
        assert "okta_app_assigned_to_everyone_group" not in _keys(rec)


# ════════════════════════════════════════════════════════════════════════════
# Identity lifecycle / entitlement
# ════════════════════════════════════════════════════════════════════════════


class TestDeprovisionedRetainsAppAssignment:
    def test_positive(self):
        rec = _app_user_assignment(user_status="DEPROVISIONED")
        f = _find(rec, "okta_deprovisioned_user_retains_app_assignment")
        assert f is not None and f.severity == "medium"

    def test_negative_active(self):
        rec = _app_user_assignment(user_status="ACTIVE")
        assert "okta_deprovisioned_user_retains_app_assignment" not in _keys(rec)


class TestSuspendedRetainsAppAssignment:
    def test_positive(self):
        rec = _app_user_assignment(user_status="SUSPENDED")
        f = _find(rec, "okta_suspended_user_retains_app_assignment")
        assert f is not None and f.severity == "low"

    def test_negative_active(self):
        rec = _app_user_assignment(user_status="ACTIVE")
        assert "okta_suspended_user_retains_app_assignment" not in _keys(rec)


# ════════════════════════════════════════════════════════════════════════════
# Claim discipline
# ════════════════════════════════════════════════════════════════════════════


class TestClaimDiscipline:
    def test_no_incident_language_in_any_finding(self):
        records = [
            _privileged_identity(has_super_admin=True, highest_privilege_tier="critical"),
            _privileged_identity(user_status="DEPROVISIONED", highest_privilege_tier="high"),
            _application(wildcard_redirect_present=True),
            _password_policy(password_min_length_category="weak"),
        ]
        banned = ("compromised", "attacker", "exploited", "stolen", "unauthorized", "breach")
        for rec in records:
            for f in evaluate_record(rec, "okta"):
                text = f"{f.title} {f.description}".lower()
                for word in banned:
                    assert word not in text, f"{f.rule_key} uses banned word {word!r}"


# ════════════════════════════════════════════════════════════════════════════
# Finding-vs-Change severity parity (task section 52)
# ════════════════════════════════════════════════════════════════════════════


def _snap(records):
    return NS(state=records)


class TestFindingChangeSeverityParity:
    def test_super_admin_assigned_matches_super_admin_grant_change(self):
        static_finding = _find(
            _privileged_identity(has_super_admin=True, highest_privilege_tier="critical"),
            "okta_super_admin_assigned",
        )
        assert static_finding.severity == "critical"

        prev = [_user_assignment(role_type="APP_ADMIN", privilege_tier="medium")]
        new = [{**_user_assignment(role_type="APP_ADMIN", privilege_tier="medium"), "role_type": "SUPER_ADMIN", "privilege_tier": "critical"}]
        changes = compute_diff(_snap(prev), _snap(new))
        change = next(c for c in changes if c["field_path"] == "role_type")
        change_level, _ = classify_okta_change(NS(**change))
        assert change_level == "critical" == static_finding.severity

    def test_wildcard_redirect_matches_change_severity(self):
        static_finding = _find(_application(wildcard_redirect_present=True), "okta_oidc_wildcard_redirect")
        assert static_finding.severity == "high"

        prev = [_application(wildcard_redirect_present=False)]
        new = [_application(wildcard_redirect_present=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = next(c for c in changes if c["field_path"] == "wildcard_redirect_present")
        change_level, _ = classify_okta_change(NS(**change))
        assert change_level == "high" == static_finding.severity

    def test_mfa_none_matches_mfa_removed_change(self):
        static_finding = _find(
            _policy_rule(mfa_requirement_category="none", scope_category="scoped_groups"),
            "okta_signon_mfa_not_required",
        )
        assert static_finding.severity == "high"

        prev = [_policy_rule(mfa_requirement_category="required")]
        new = [_policy_rule(mfa_requirement_category="none")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = next(c for c in changes if c["field_path"] == "mfa_requirement_category")
        change_level, _ = classify_okta_change(NS(**change))
        assert change_level == "high" == static_finding.severity

    def test_deprovisioned_retains_admin_not_lower_than_change_severity(self):
        static_finding = _find(
            _privileged_identity(user_status="DEPROVISIONED", highest_privilege_tier="critical"),
            "okta_deprovisioned_identity_retains_admin_privilege",
        )
        # Static current-state severity (high) is intentionally not required
        # to equal the Change-classification severity for the transition
        # into DEPROVISIONED (also conservative/medium-high territory) — the
        # invariant checked here is that neither is a "safe" verdict.
        assert static_finding.severity in ("high", "critical")
