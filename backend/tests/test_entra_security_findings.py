"""Microsoft Entra ID Security Finding predicate tests (Entra message 6 of 8).

For every implemented rule: a positive-trigger case and at least one
adjacent non-trigger case (unknown/missing/report-only/etc. that must
never fire). Uses ``evaluate()`` directly against hand-built normalized
records — connector-shape reachability is covered separately in
``test_entra_security_findings_reachability.py``.
"""

from __future__ import annotations

from app.services.security_rules.entra import evaluate

_TENANT = "id:t1"


def _keys(record: dict) -> set[str]:
    return {f.rule_key for f in evaluate(record)}


def _role_assignment(**overrides) -> dict:
    base = {
        "record_type": "entra_directory_role_assignment",
        "record_id": f"{_TENANT}/directory_role_assignment/a1",
        "tenant_id": _TENANT,
        "role_name": "Some Role",
        "role_template_id": None,
        "privilege_tier": "medium",
        "principal_id": "u1",
        "principal_type": "User",
        "directory_scope_category": "tenant_wide",
    }
    base.update(overrides)
    return base


def _privileged_identity(**overrides) -> dict:
    base = {
        "record_type": "entra_privileged_identity",
        "record_id": f"{_TENANT}/privileged_identity/u1",
        "tenant_id": _TENANT,
        "user_principal_name": "u1@example.com",
        "account_enabled_category": "enabled",
        "guest": False,
        "highest_privilege_tier": "high",
        "has_global_admin": False,
        "has_privileged_role_admin": False,
        "has_high_privilege": True,
    }
    base.update(overrides)
    return base


def _privileged_group(**overrides) -> dict:
    base = {
        "record_type": "entra_privileged_group",
        "record_id": f"{_TENANT}/privileged_group/g1",
        "tenant_id": _TENANT,
        "display_name": "Admins",
        "highest_privilege_tier": "high",
        "member_count": 5,
        "guest_member_count": 0,
    }
    base.update(overrides)
    return base


def _privileged_sp(**overrides) -> dict:
    base = {
        "record_type": "entra_privileged_service_principal",
        "record_id": f"{_TENANT}/privileged_service_principal/sp1",
        "tenant_id": _TENANT,
        "display_name": "Automation",
        "highest_privilege_tier": "high",
        "account_enabled": True,
    }
    base.update(overrides)
    return base


def _sp_app_role_assignment(**overrides) -> dict:
    base = {
        "record_type": "entra_service_principal_app_role_assignment",
        "record_id": f"{_TENANT}/app_role_assignment/x1",
        "tenant_id": _TENANT,
        "principal_name": "Client",
        "resource_name": "Microsoft Graph",
        "resource_is_microsoft_graph": True,
        "app_role_category": "User.Read",
    }
    base.update(overrides)
    return base


def _oauth2_grant(**overrides) -> dict:
    base = {
        "record_type": "entra_oauth2_permission_grant",
        "record_id": f"{_TENANT}/oauth2_permission_grant/g1",
        "tenant_id": _TENANT,
        "client_name": "Client",
        "resource_name": "Microsoft Graph",
        "consent_type_category": "AllPrincipals",
        "highest_scope_privilege_tier": "high",
        "client_verified_publisher_category": "verified",
    }
    base.update(overrides)
    return base


def _ca_policy(**overrides) -> dict:
    base = {
        "record_type": "entra_conditional_access_policy",
        "record_id": f"{_TENANT}/conditional_access_policy/p1",
        "tenant_id": _TENANT,
        "display_name": "Policy",
        "state_category": "enabled",
        "mfa_requirement_category": "required",
        "coverage_category": "selected_principals_selected_apps",
        "block_access": False,
        "legacy_auth_targeted": False,
        "user_target_category": "selected_groups",
    }
    base.update(overrides)
    return base


def _auth_method(**overrides) -> dict:
    base = {
        "record_type": "entra_authentication_method",
        "record_id": f"{_TENANT}/authentication_method/Fido2",
        "tenant_id": _TENANT,
        "state_category": "enabled",
        "method_type_category": "fido2",
    }
    base.update(overrides)
    return base


def _auth_strength(**overrides) -> dict:
    base = {
        "record_type": "entra_authentication_strength",
        "record_id": f"{_TENANT}/authentication_strength/s1",
        "tenant_id": _TENANT,
        "display_name": "Custom Strength",
        "kind_category": "custom",
        "phishing_resistance_category": "not_phishing_resistant",
    }
    base.update(overrides)
    return base


def _application(**overrides) -> dict:
    base = {
        "record_type": "entra_application",
        "record_id": f"{_TENANT}/application/app1",
        "tenant_id": _TENANT,
        "display_name": "App",
        "has_wildcard_redirect": False,
        "web_has_http_redirect": False,
        "has_custom_scheme_redirect": False,
        "public_client_redirect_count": 0,
        "nearest_credential_expiry_category": "healthy",
    }
    base.update(overrides)
    return base


def _service_principal(**overrides) -> dict:
    base = {
        "record_type": "entra_service_principal",
        "record_id": f"{_TENANT}/service_principal/sp1",
        "tenant_id": _TENANT,
        "display_name": "SP",
        "nearest_credential_expiry_category": "healthy",
        "assignment_required": True,
    }
    base.update(overrides)
    return base


def _app_user_assignment(**overrides) -> dict:
    base = {
        "record_type": "entra_application_user_assignment",
        "record_id": f"{_TENANT}/app_role_assignment/u1",
        "tenant_id": _TENANT,
        "application_name": "App",
        "account_enabled_category": "enabled",
    }
    base.update(overrides)
    return base


def _app_group_assignment(**overrides) -> dict:
    base = {
        "record_type": "entra_application_group_assignment",
        "record_id": f"{_TENANT}/app_role_assignment/g1",
        "tenant_id": _TENANT,
        "application_name": "App",
        "group_name": "Group",
        "role_assignable_group": False,
        "dynamic_group": False,
    }
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# Directory role assignment
# ════════════════════════════════════════════════════════════════════════════


class TestDirectoryRoleAssignment:
    def test_global_admin_fires_critical(self):
        rec = _role_assignment(role_template_id="62e90394-69f5-4237-9190-012177145e10", privilege_tier="critical")
        findings = evaluate(rec)
        assert len(findings) == 1
        assert findings[0].rule_key == "entra_global_admin_assigned"
        assert findings[0].severity == "critical"

    def test_privileged_role_administrator_fires_critical(self):
        rec = _role_assignment(role_template_id="e8611ab8-c189-46e8-94e1-60213ab1f814", privilege_tier="critical")
        assert "entra_privileged_role_administrator_assigned" in _keys(rec)

    def test_privileged_authentication_administrator_fires_critical(self):
        rec = _role_assignment(role_template_id="7be44c8a-adaf-4e2a-84d6-ab2649e08a13", privilege_tier="critical")
        assert "entra_privileged_authentication_administrator_assigned" in _keys(rec)

    def test_high_tier_role_fires_high(self):
        rec = _role_assignment(role_template_id="9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", privilege_tier="high")
        findings = evaluate(rec)
        assert findings[0].rule_key == "entra_high_tier_admin_assigned"
        assert findings[0].severity == "high"

    def test_medium_tier_role_does_not_fire(self):
        rec = _role_assignment(privilege_tier="medium")
        assert _keys(rec) == set()

    def test_unknown_tier_does_not_fire_high_tier_rule(self):
        rec = _role_assignment(privilege_tier="unknown")
        assert _keys(rec) == set()

    def test_high_tier_excluded_when_global_admin_already_matched(self):
        """A critical-tier role assignment (Global Admin) must not ALSO
        trigger the generic high-tier rule."""
        rec = _role_assignment(role_template_id="62e90394-69f5-4237-9190-012177145e10", privilege_tier="critical")
        keys = _keys(rec)
        assert "entra_high_tier_admin_assigned" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Privileged identity
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedIdentity:
    def test_guest_global_admin_fires_critical(self):
        rec = _privileged_identity(guest=True, has_global_admin=True, highest_privilege_tier="critical")
        assert "entra_guest_global_admin" in _keys(rec)

    def test_guest_high_privilege_fires_high(self):
        rec = _privileged_identity(guest=True, has_global_admin=False, has_high_privilege=True)
        findings = evaluate(rec)
        assert findings[0].rule_key == "entra_guest_has_high_privilege"
        assert findings[0].severity == "high"

    def test_non_guest_high_privilege_does_not_fire_guest_rule(self):
        rec = _privileged_identity(guest=False, has_high_privilege=True)
        assert "entra_guest_has_high_privilege" not in _keys(rec)
        assert "entra_guest_global_admin" not in _keys(rec)

    def test_disabled_identity_retains_privilege_fires(self):
        rec = _privileged_identity(account_enabled_category="disabled", highest_privilege_tier="high")
        findings = evaluate(rec)
        assert any(f.rule_key == "entra_disabled_identity_retains_admin_privilege" for f in findings)

    def test_enabled_identity_does_not_fire_disabled_rule(self):
        rec = _privileged_identity(account_enabled_category="enabled")
        assert "entra_disabled_identity_retains_admin_privilege" not in _keys(rec)

    def test_disabled_with_unknown_tier_does_not_fire(self):
        rec = _privileged_identity(account_enabled_category="disabled", highest_privilege_tier="unknown", guest=False)
        assert _keys(rec) == set()

    def test_disabled_guest_retains_high_privilege_fires_and_excludes_generic(self):
        rec = _privileged_identity(account_enabled_category="disabled", guest=True, highest_privilege_tier="high")
        keys = _keys(rec)
        assert "entra_disabled_guest_retains_high_privilege" in keys
        assert "entra_disabled_identity_retains_admin_privilege" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Privileged group
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedGroup:
    def test_group_critical_tier_fires(self):
        rec = _privileged_group(highest_privilege_tier="critical")
        findings = evaluate(rec)
        assert findings[0].rule_key == "entra_group_has_global_admin"
        assert findings[0].severity == "critical"

    def test_group_high_tier_fires_and_excludes_critical(self):
        rec = _privileged_group(highest_privilege_tier="high")
        keys = _keys(rec)
        assert "entra_group_has_high_privilege" in keys
        assert "entra_group_has_global_admin" not in keys

    def test_group_medium_tier_does_not_fire_tier_rules(self):
        rec = _privileged_group(highest_privilege_tier="medium")
        keys = _keys(rec)
        assert "entra_group_has_global_admin" not in keys
        assert "entra_group_has_high_privilege" not in keys

    def test_guest_member_in_privileged_group_fires(self):
        rec = _privileged_group(highest_privilege_tier="critical", guest_member_count=2)
        assert "entra_guest_member_in_privileged_group" in _keys(rec)

    def test_zero_guest_members_does_not_fire(self):
        rec = _privileged_group(highest_privilege_tier="critical", guest_member_count=0)
        assert "entra_guest_member_in_privileged_group" not in _keys(rec)

    def test_broad_membership_fires(self):
        rec = _privileged_group(highest_privilege_tier="high", member_count=25)
        assert "entra_privileged_group_broad_membership" in _keys(rec)

    def test_narrow_membership_does_not_fire_broad_rule(self):
        rec = _privileged_group(highest_privilege_tier="high", member_count=5)
        assert "entra_privileged_group_broad_membership" not in _keys(rec)


# ════════════════════════════════════════════════════════════════════════════
# Privileged service principal
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedServicePrincipal:
    def test_critical_tier_fires(self):
        rec = _privileged_sp(highest_privilege_tier="critical")
        findings = evaluate(rec)
        assert findings[0].rule_key == "entra_service_principal_has_critical_privilege"

    def test_high_tier_fires_and_excludes_critical(self):
        rec = _privileged_sp(highest_privilege_tier="high")
        keys = _keys(rec)
        assert "entra_service_principal_has_high_privilege" in keys
        assert "entra_service_principal_has_critical_privilege" not in keys

    def test_disabled_sp_retains_privilege_fires(self):
        rec = _privileged_sp(account_enabled=False, highest_privilege_tier="high")
        assert "entra_disabled_service_principal_retains_privilege" in _keys(rec)

    def test_enabled_sp_does_not_fire_disabled_rule(self):
        rec = _privileged_sp(account_enabled=True)
        assert "entra_disabled_service_principal_retains_privilege" not in _keys(rec)

    def test_unknown_tier_never_fires(self):
        rec = _privileged_sp(highest_privilege_tier="unknown", account_enabled=True)
        assert _keys(rec) == set()


# ════════════════════════════════════════════════════════════════════════════
# Service-principal application-permission grants
# ════════════════════════════════════════════════════════════════════════════


class TestServicePrincipalPermissions:
    def test_role_management_permission_fires_critical(self):
        rec = _sp_app_role_assignment(app_role_category="RoleManagement.ReadWrite.Directory")
        findings = evaluate(rec)
        assert findings[0].rule_key == "entra_service_principal_can_manage_directory_roles"
        assert findings[0].severity == "critical"

    def test_app_role_assignment_management_permission_fires_critical(self):
        rec = _sp_app_role_assignment(app_role_category="AppRoleAssignment.ReadWrite.All")
        assert "entra_service_principal_can_manage_app_role_assignments" in _keys(rec)

    def test_permission_grant_permission_fires_critical(self):
        rec = _sp_app_role_assignment(app_role_category="Policy.ReadWrite.PermissionGrant")
        assert "entra_service_principal_can_grant_arbitrary_permissions" in _keys(rec)

    def test_application_management_permission_fires_high(self):
        rec = _sp_app_role_assignment(app_role_category="Application.ReadWrite.All")
        findings = evaluate(rec)
        assert findings[0].severity == "high"

    def test_conditional_access_permission_fires_high(self):
        rec = _sp_app_role_assignment(app_role_category="Policy.ReadWrite.ConditionalAccess")
        assert "entra_service_principal_can_modify_conditional_access" in _keys(rec)

    def test_authentication_method_permission_fires_high(self):
        rec = _sp_app_role_assignment(app_role_category="UserAuthenticationMethod.ReadWrite.All")
        assert "entra_service_principal_can_modify_authentication_methods" in _keys(rec)

    def test_directory_write_permission_fires_high(self):
        rec = _sp_app_role_assignment(app_role_category="Directory.ReadWrite.All")
        assert "entra_service_principal_has_directory_write_permission" in _keys(rec)

    def test_user_write_permission_fires_medium(self):
        rec = _sp_app_role_assignment(app_role_category="User.ReadWrite.All")
        findings = evaluate(rec)
        assert findings[0].severity == "medium"

    def test_group_write_permission_fires_medium(self):
        rec = _sp_app_role_assignment(app_role_category="Group.ReadWrite.All")
        assert "entra_service_principal_has_group_write_permission" in _keys(rec)

    def test_ordinary_permission_does_not_fire(self):
        rec = _sp_app_role_assignment(app_role_category="User.Read")
        assert _keys(rec) == set()

    def test_unknown_permission_does_not_fire_known_critical_rule(self):
        rec = _sp_app_role_assignment(app_role_category=None)
        assert _keys(rec) == set()

    def test_non_graph_resource_never_fires(self):
        """Even an exact permission-VALUE match must never fire when the
        resource is not confirmed as Microsoft Graph."""
        rec = _sp_app_role_assignment(app_role_category="RoleManagement.ReadWrite.Directory", resource_is_microsoft_graph=False)
        assert _keys(rec) == set()


# ════════════════════════════════════════════════════════════════════════════
# OAuth2 delegated consent
# ════════════════════════════════════════════════════════════════════════════


class TestOAuth2Consent:
    def test_tenant_wide_critical_consent_fires(self):
        rec = _oauth2_grant(consent_type_category="AllPrincipals", highest_scope_privilege_tier="critical")
        findings = evaluate(rec)
        assert findings[0].rule_key == "entra_tenant_wide_critical_delegated_consent"

    def test_tenant_wide_high_risk_consent_fires(self):
        rec = _oauth2_grant(consent_type_category="AllPrincipals", highest_scope_privilege_tier="high")
        assert "entra_tenant_wide_high_risk_delegated_consent" in _keys(rec)

    def test_user_scoped_critical_consent_fires(self):
        rec = _oauth2_grant(consent_type_category="Principal", highest_scope_privilege_tier="critical")
        findings = evaluate(rec)
        assert findings[0].severity == "high"

    def test_user_scoped_high_risk_consent_fires_medium(self):
        rec = _oauth2_grant(consent_type_category="Principal", highest_scope_privilege_tier="high")
        findings = evaluate(rec)
        assert findings[0].severity == "medium"

    def test_ordinary_consent_does_not_fire(self):
        rec = _oauth2_grant(consent_type_category="AllPrincipals", highest_scope_privilege_tier="read_only")
        assert _keys(rec) == set()

    def test_offline_access_only_never_fires(self):
        rec = _oauth2_grant(consent_type_category="AllPrincipals", highest_scope_privilege_tier="low")
        assert _keys(rec) == set()

    def test_unknown_scope_tier_never_fires(self):
        rec = _oauth2_grant(consent_type_category="AllPrincipals", highest_scope_privilege_tier="unknown")
        assert _keys(rec) == set()

    def test_external_unverified_app_composite_fires_and_suppresses_generic(self):
        rec = _oauth2_grant(
            consent_type_category="AllPrincipals", highest_scope_privilege_tier="critical",
            client_verified_publisher_category="unverified",
        )
        keys = _keys(rec)
        assert "entra_external_unverified_app_tenant_wide_consent" in keys
        assert "entra_tenant_wide_critical_delegated_consent" not in keys

    def test_verified_publisher_does_not_fire_composite(self):
        rec = _oauth2_grant(
            consent_type_category="AllPrincipals", highest_scope_privilege_tier="critical",
            client_verified_publisher_category="verified",
        )
        keys = _keys(rec)
        assert "entra_external_unverified_app_tenant_wide_consent" not in keys
        assert "entra_tenant_wide_critical_delegated_consent" in keys


# ════════════════════════════════════════════════════════════════════════════
# Conditional Access / MFA
# ════════════════════════════════════════════════════════════════════════════


class TestConditionalAccess:
    def test_broad_no_mfa_fires_high(self):
        rec = _ca_policy(mfa_requirement_category="not_required", coverage_category="all_users_all_apps")
        findings = evaluate(rec)
        assert findings[0].rule_key == "entra_ca_broad_access_without_mfa"
        assert findings[0].severity == "high"

    def test_narrow_no_mfa_fires_medium(self):
        rec = _ca_policy(mfa_requirement_category="not_required", coverage_category="selected_principals_selected_apps")
        findings = evaluate(rec)
        assert findings[0].rule_key == "entra_ca_access_without_mfa"
        assert findings[0].severity == "medium"

    def test_mfa_required_does_not_fire(self):
        rec = _ca_policy(mfa_requirement_category="required")
        assert _keys(rec) == set()

    def test_unknown_mfa_requirement_never_fires(self):
        rec = _ca_policy(mfa_requirement_category="unknown")
        assert "entra_ca_broad_access_without_mfa" not in _keys(rec)
        assert "entra_ca_access_without_mfa" not in _keys(rec)

    def test_report_only_no_mfa_never_fires_enforced_rule(self):
        rec = _ca_policy(state_category="report_only", mfa_requirement_category="not_required", coverage_category="all_users_all_apps")
        assert "entra_ca_broad_access_without_mfa" not in _keys(rec)
        assert "entra_ca_access_without_mfa" not in _keys(rec)

    def test_disabled_policy_never_fires(self):
        rec = _ca_policy(state_category="disabled", mfa_requirement_category="not_required")
        assert _keys(rec) == set()

    def test_mfa_optional_via_or_operator_fires(self):
        rec = _ca_policy(mfa_requirement_category="one_of_multiple_controls", user_target_category="all_users")
        assert "entra_ca_mfa_optional_within_grant_controls" in _keys(rec)

    def test_mfa_optional_narrow_scope_does_not_fire(self):
        rec = _ca_policy(mfa_requirement_category="one_of_multiple_controls", user_target_category="selected_groups")
        assert "entra_ca_mfa_optional_within_grant_controls" not in _keys(rec)

    def test_legacy_auth_not_blocked_fires(self):
        rec = _ca_policy(legacy_auth_targeted=True, block_access=False)
        assert "entra_ca_legacy_auth_not_blocked" in _keys(rec)

    def test_legacy_auth_blocked_does_not_fire(self):
        rec = _ca_policy(legacy_auth_targeted=True, block_access=True)
        assert "entra_ca_legacy_auth_not_blocked" not in _keys(rec)

    def test_legacy_auth_not_targeted_does_not_fire(self):
        rec = _ca_policy(legacy_auth_targeted=False, block_access=False)
        assert "entra_ca_legacy_auth_not_blocked" not in _keys(rec)

    def test_report_only_broad_mfa_fires(self):
        rec = _ca_policy(state_category="report_only", mfa_requirement_category="required", coverage_category="all_users_all_apps")
        assert "entra_ca_report_only_broad_protection" in _keys(rec)

    def test_enabled_broad_mfa_does_not_fire_report_only_rule(self):
        rec = _ca_policy(state_category="enabled", mfa_requirement_category="required", coverage_category="all_users_all_apps")
        assert "entra_ca_report_only_broad_protection" not in _keys(rec)


# ════════════════════════════════════════════════════════════════════════════
# Authentication methods / strengths
# ════════════════════════════════════════════════════════════════════════════


class TestAuthenticationMethodsAndStrengths:
    def test_sms_enabled_fires_low(self):
        rec = _auth_method(state_category="enabled", method_type_category="sms")
        findings = evaluate(rec)
        assert findings[0].rule_key == "entra_weak_authentication_method_enabled"
        assert findings[0].severity == "low"

    def test_voice_enabled_fires(self):
        rec = _auth_method(state_category="enabled", method_type_category="voice")
        assert "entra_weak_authentication_method_enabled" in _keys(rec)

    def test_fido2_enabled_does_not_fire_weak_rule(self):
        rec = _auth_method(state_category="enabled", method_type_category="fido2")
        assert _keys(rec) == set()

    def test_sms_disabled_does_not_fire(self):
        rec = _auth_method(state_category="disabled", method_type_category="sms")
        assert _keys(rec) == set()

    def test_custom_strength_not_phishing_resistant_fires(self):
        rec = _auth_strength(kind_category="custom", phishing_resistance_category="not_phishing_resistant")
        assert "entra_authentication_strength_not_phishing_resistant" in _keys(rec)

    def test_built_in_strength_never_fires(self):
        rec = _auth_strength(kind_category="built_in", phishing_resistance_category="not_phishing_resistant")
        assert _keys(rec) == set()

    def test_phishing_resistant_custom_strength_does_not_fire(self):
        rec = _auth_strength(kind_category="custom", phishing_resistance_category="phishing_resistant")
        assert _keys(rec) == set()

    def test_unknown_phishing_resistance_never_fires(self):
        rec = _auth_strength(kind_category="custom", phishing_resistance_category="unknown")
        assert _keys(rec) == set()


# ════════════════════════════════════════════════════════════════════════════
# Applications / credentials
# ════════════════════════════════════════════════════════════════════════════


class TestApplications:
    def test_wildcard_redirect_fires_high(self):
        rec = _application(has_wildcard_redirect=True)
        findings = evaluate(rec)
        assert any(f.rule_key == "entra_application_wildcard_redirect" and f.severity == "high" for f in findings)

    def test_https_only_does_not_fire_redirect_rules(self):
        rec = _application()
        assert "entra_application_wildcard_redirect" not in _keys(rec)
        assert "entra_application_http_redirect" not in _keys(rec)

    def test_http_web_redirect_fires_medium(self):
        rec = _application(web_has_http_redirect=True)
        assert "entra_application_http_redirect" in _keys(rec)

    def test_custom_scheme_without_public_client_fires(self):
        rec = _application(has_custom_scheme_redirect=True, public_client_redirect_count=0)
        assert "entra_application_custom_scheme_redirect_unexpected" in _keys(rec)

    def test_custom_scheme_with_public_client_does_not_fire(self):
        """Native/mobile clients legitimately use custom-scheme redirects —
        must not falsely fire."""
        rec = _application(has_custom_scheme_redirect=True, public_client_redirect_count=1)
        assert "entra_application_custom_scheme_redirect_unexpected" not in _keys(rec)

    def test_expired_credential_fires(self):
        rec = _application(nearest_credential_expiry_category="expired")
        assert "entra_application_expired_credential" in _keys(rec)

    def test_unknown_credential_expiry_never_fires(self):
        rec = _application(nearest_credential_expiry_category="unknown")
        assert "entra_application_expired_credential" not in _keys(rec)

    def test_expiring_soon_does_not_fire_expired_rule(self):
        rec = _application(nearest_credential_expiry_category="expiring_soon")
        assert "entra_application_expired_credential" not in _keys(rec)


class TestServicePrincipals:
    def test_expired_credential_fires(self):
        rec = _service_principal(nearest_credential_expiry_category="expired")
        assert "entra_service_principal_expired_credential" in _keys(rec)

    def test_healthy_credential_does_not_fire(self):
        rec = _service_principal(nearest_credential_expiry_category="healthy")
        assert _keys(rec) == set()

    def test_assignment_not_required_fires_low(self):
        rec = _service_principal(assignment_required=False)
        findings = evaluate(rec)
        assert any(f.rule_key == "entra_service_principal_assignment_not_required" and f.severity == "low" for f in findings)

    def test_assignment_required_true_does_not_fire(self):
        rec = _service_principal(assignment_required=True)
        assert "entra_service_principal_assignment_not_required" not in _keys(rec)


# ════════════════════════════════════════════════════════════════════════════
# Identity lifecycle / group posture
# ════════════════════════════════════════════════════════════════════════════


class TestAppAssignmentPosture:
    def test_disabled_user_retains_app_assignment_fires(self):
        rec = _app_user_assignment(account_enabled_category="disabled")
        assert "entra_disabled_user_retains_application_assignment" in _keys(rec)

    def test_enabled_user_does_not_fire(self):
        rec = _app_user_assignment(account_enabled_category="enabled")
        assert _keys(rec) == set()

    def test_role_assignable_group_assignment_fires_medium(self):
        rec = _app_group_assignment(role_assignable_group=True)
        findings = evaluate(rec)
        assert findings[0].rule_key == "entra_role_assignable_group_assigned_to_application"
        assert findings[0].severity == "medium"

    def test_dynamic_group_assignment_fires_medium(self):
        rec = _app_group_assignment(dynamic_group=True)
        assert "entra_dynamic_group_assigned_to_application" in _keys(rec)

    def test_ordinary_group_assignment_does_not_fire(self):
        rec = _app_group_assignment(role_assignable_group=False, dynamic_group=False)
        assert _keys(rec) == set()

    def test_role_assignable_takes_precedence_over_dynamic(self):
        rec = _app_group_assignment(role_assignable_group=True, dynamic_group=True)
        keys = _keys(rec)
        assert "entra_role_assignable_group_assigned_to_application" in keys
        assert "entra_dynamic_group_assigned_to_application" not in keys
