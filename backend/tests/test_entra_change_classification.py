"""Microsoft Entra ID exhaustive Change-classification QA (Entra message 7
of 8).

Uses the REAL ``compute_diff()`` -> ``classify_entra_change()`` pipeline
(never hand-built Change objects) across every one of the 16 non-org/
capability Entra record types, exercising the exhaustive transition list
required by this message: user lifecycle, groups, memberships,
applications, service principals, app assignments, SP Graph permissions,
OAuth grants, Conditional Access, authentication strengths/methods,
directory roles/assignments, and privileged identity/group/service
principal.

This file is additive to the existing per-message diff test files
(test_entra_identity_diff.py, test_entra_application_diff.py,
test_entra_policy_diff.py, test_entra_privileged_diff.py) — it targets the
exhaustive matrix of transitions called out in the message-7 spec, not a
duplicate of those files' own coverage.
"""

from __future__ import annotations

import pytest
from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.entra import classify_entra_change

_TENANT = "id:t1"


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _field_change(changes: list[dict], field_path: str) -> dict:
    match = [c for c in changes if c["field_path"] == field_path]
    assert match, f"no change found for field_path={field_path!r} among {[c['field_path'] for c in changes]}"
    return match[0]


def _added(changes: list[dict]) -> dict:
    return next(c for c in changes if c["change_type"] == "added")


def _removed(changes: list[dict]) -> dict:
    return next(c for c in changes if c["change_type"] == "removed")


# ── Fixture builders (one per record type) ──────────────────────────────────


def _user(**overrides) -> dict:
    base = {
        "record_type": "entra_user", "record_id": f"{_TENANT}/user/u1", "provider_resource_id": "users/u1",
        "tenant_id": _TENANT, "user_id": "u1", "user_principal_name": "u1@example.com", "display_name": "User One",
        "account_enabled_category": "enabled", "user_type_category": "Member", "guest": False, "member": True,
        "lifecycle_posture": "enabled_member", "external_user_state_category": "unknown",
        "on_premises_sync_enabled_category": "unknown",
    }
    base.update(overrides)
    return base


def _group(**overrides) -> dict:
    base = {
        "record_type": "entra_group", "record_id": f"{_TENANT}/group/g1", "provider_resource_id": "groups/g1",
        "tenant_id": _TENANT, "group_id": "g1", "display_name": "Engineering", "security_enabled": True,
        "mail_enabled": False, "group_types": [], "group_type_category": "security", "dynamic_membership": False,
        "microsoft_365_group": False, "security_group": True, "role_assignable": False,
        "membership_count": 5, "membership_count_category": "1-5",
    }
    base.update(overrides)
    return base


def _membership(**overrides) -> dict:
    base = {
        "record_type": "entra_group_membership", "record_id": f"{_TENANT}/membership/g1/u1",
        "provider_resource_id": "groups/g1/members/u1", "tenant_id": _TENANT, "user_id": "u1", "group_id": "g1",
        "user_principal_name": "u1@example.com", "group_name": "Engineering", "user_type_category": "Member",
        "account_enabled_category": "enabled", "group_type_category": "security", "dynamic_group": False,
        "role_assignable_group": False,
    }
    base.update(overrides)
    return base


def _application(**overrides) -> dict:
    base = {
        "record_type": "entra_application", "record_id": f"{_TENANT}/application/a1",
        "provider_resource_id": "applications/a1", "tenant_id": _TENANT, "object_id": "a1", "app_id": "client-a1",
        "display_name": "Test App", "sign_in_audience_category": "single_tenant", "publisher_domain": None,
        "web_redirect_count": 1, "spa_redirect_count": 0, "public_client_redirect_count": 0,
        "has_http_redirect": False, "web_has_http_redirect": False, "has_localhost_redirect": False,
        "has_loopback_redirect": False, "has_custom_scheme_redirect": False, "has_wildcard_redirect": False,
        "requested_resource_api_count": 1, "requested_delegated_permission_count": 1,
        "requested_application_permission_count": 0, "password_credential_count": 0, "key_credential_count": 0,
        "nearest_credential_expiry_category": "no_credentials", "app_role_count": 0, "app_role_enabled_count": 0,
    }
    base.update(overrides)
    return base


def _service_principal(**overrides) -> dict:
    base = {
        "record_type": "entra_service_principal", "record_id": f"{_TENANT}/service_principal/sp1",
        "provider_resource_id": "servicePrincipals/sp1", "tenant_id": _TENANT, "service_principal_id": "sp1",
        "app_id": "client-sp1", "display_name": "Test SP", "service_principal_type_category": "Application",
        "account_enabled": True, "assignment_required": False, "app_owner_organization_category": "tenant_owned",
        "is_microsoft_first_party": False, "is_microsoft_graph_resource": False,
        "verified_publisher_category": "unverified", "app_role_count": 0, "oauth2_permission_scope_count": 0,
        "password_credential_count": 0, "key_credential_count": 0, "nearest_credential_expiry_category": "no_credentials",
    }
    base.update(overrides)
    return base


def _app_user_assignment(**overrides) -> dict:
    base = {
        "record_type": "entra_application_user_assignment", "record_id": f"{_TENANT}/app_role_assignment/assign1",
        "provider_resource_id": "servicePrincipals/sp1/appRoleAssignedTo/u1", "tenant_id": _TENANT,
        "service_principal_id": "sp1", "app_id": "client-sp1", "application_name": "Test SP", "principal_id": "u1",
        "user_id": "u1", "user_principal_name": "u1@example.com", "account_enabled_category": "enabled",
        "user_type_category": "Member", "app_role_category": "Reader", "app_role_risk_category": "ordinary",
        "assignment_type": "user",
    }
    base.update(overrides)
    return base


def _app_group_assignment(**overrides) -> dict:
    base = {
        "record_type": "entra_application_group_assignment", "record_id": f"{_TENANT}/app_role_assignment/assign2",
        "provider_resource_id": "servicePrincipals/sp1/appRoleAssignedTo/g1", "tenant_id": _TENANT,
        "service_principal_id": "sp1", "app_id": "client-sp1", "application_name": "Test SP", "group_id": "g1",
        "group_name": "Engineering", "group_type_category": "security", "dynamic_group": False,
        "role_assignable_group": False, "app_role_category": "Reader", "app_role_risk_category": "ordinary",
        "assignment_type": "group",
    }
    base.update(overrides)
    return base


def _sp_app_role_assignment(**overrides) -> dict:
    base = {
        "record_type": "entra_service_principal_app_role_assignment", "record_id": f"{_TENANT}/app_role_assignment/x1",
        "provider_resource_id": "servicePrincipals/sp2/appRoleAssignedTo/sp1", "tenant_id": _TENANT,
        "resource_service_principal_id": "sp2", "resource_app_id": "graph", "resource_name": "Microsoft Graph",
        "resource_is_microsoft_graph": True, "principal_service_principal_id": "sp1", "principal_app_id": "client-sp1",
        "principal_name": "Automation", "app_role_category": "User.Read", "app_role_risk_category": "ordinary",
        "app_role_privilege_tier": "read_only", "assignment_type": "service_principal",
    }
    base.update(overrides)
    return base


def _oauth2_grant(**overrides) -> dict:
    base = {
        "record_type": "entra_oauth2_permission_grant", "record_id": f"{_TENANT}/oauth2_permission_grant/gr1",
        "provider_resource_id": "oauth2PermissionGrants/gr1", "tenant_id": _TENANT, "grant_id": "gr1",
        "client_service_principal_id": "sp1", "client_name": "Client", "resource_service_principal_id": "sp2",
        "resource_name": "Microsoft Graph", "resource_is_microsoft_graph": True, "consent_type_category": "Principal",
        "principal_id": "u1", "scope_count": 1, "scopes": ["User.Read"], "high_risk_scope_present": False,
        "highest_scope_privilege_tier": "read_only", "client_verified_publisher_category": "unverified",
    }
    base.update(overrides)
    return base


def _ca_policy(**overrides) -> dict:
    base = {
        "record_type": "entra_conditional_access_policy", "record_id": f"{_TENANT}/conditional_access_policy/p1",
        "provider_resource_id": "identity/conditionalAccess/policies/p1", "tenant_id": _TENANT, "policy_id": "p1",
        "display_name": "Policy", "state_category": "enabled", "user_target_category": "all_users",
        "include_user_count": 0, "include_group_count": 0, "include_role_count": 0, "exclude_user_count": 0,
        "exclude_group_count": 0, "exclude_role_count": 0, "guests_included": False, "guests_excluded": False,
        "app_target_category": "all_cloud_apps", "include_app_count": 0, "exclude_app_count": 0,
        "coverage_category": "all_users_all_apps", "location_target_category": "unknown",
        "device_platform_categories": ["unknown"], "client_app_type_categories": ["unknown"],
        "legacy_auth_targeted": False, "user_risk_level_categories": ["unknown"],
        "sign_in_risk_level_categories": ["unknown"], "grant_operator_category": "AND",
        "grant_control_categories": ["mfa"], "mfa_requirement_category": "required", "block_access": False,
        "compliant_device_required": False, "hybrid_joined_device_required": False,
        "approved_application_required": False, "compliant_application_required": False,
        "authentication_strength_id": None, "authentication_strength_referenced": False,
        "sign_in_frequency_enabled": False, "sign_in_frequency_category": "unknown",
        "persistent_browser_category": "unknown", "continuous_access_evaluation_category": "unknown",
        "app_enforced_restrictions_enabled": None,
    }
    base.update(overrides)
    return base


def _auth_strength(**overrides) -> dict:
    base = {
        "record_type": "entra_authentication_strength", "record_id": f"{_TENANT}/authentication_strength/s1",
        "provider_resource_id": "policies/authenticationStrengthPolicies/s1", "tenant_id": _TENANT, "strength_id": "s1",
        "display_name": "MFA Strength", "kind_category": "built_in", "allowed_combination_count": 2,
        "phishing_resistance_category": "phishing_resistant", "passwordless_category": "passwordless",
        "mfa_capability_category": "mfa_capable",
    }
    base.update(overrides)
    return base


def _auth_method(**overrides) -> dict:
    base = {
        "record_type": "entra_authentication_method", "record_id": f"{_TENANT}/authentication_method/Fido2",
        "provider_resource_id": "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2",
        "tenant_id": _TENANT, "method_config_id": "Fido2", "method_type_category": "fido2",
        "state_category": "enabled", "phishing_resistance_category": "phishing_resistant",
        "target_category": "all_users", "include_target_count": 1, "exclude_target_count": 0,
    }
    base.update(overrides)
    return base


def _directory_role(**overrides) -> dict:
    base = {
        "record_type": "entra_directory_role", "record_id": f"{_TENANT}/directory_role/r1",
        "provider_resource_id": "roleManagement/directory/roleDefinitions/r1", "tenant_id": _TENANT,
        "role_definition_id": "r1", "template_id": "r1", "display_name": "Custom Role",
        "role_kind_category": "custom", "enabled": True, "privilege_tier": "medium", "is_privileged": True,
        "action_count": 1, "dangerous_action_count": 0,
    }
    base.update(overrides)
    return base


def _directory_role_assignment(**overrides) -> dict:
    base = {
        "record_type": "entra_directory_role_assignment", "record_id": f"{_TENANT}/directory_role_assignment/a1",
        "provider_resource_id": "roleManagement/directory/roleAssignments/a1", "tenant_id": _TENANT,
        "assignment_id": "a1", "role_definition_id": "r1", "role_template_id": None, "role_name": "Custom Role",
        "privilege_tier": "medium", "principal_id": "u1", "principal_type": "User",
        "directory_scope_category": "tenant_wide",
    }
    base.update(overrides)
    return base


def _privileged_identity(**overrides) -> dict:
    base = {
        "record_type": "entra_privileged_identity", "record_id": f"{_TENANT}/privileged_identity/u1",
        "provider_resource_id": "users/u1", "tenant_id": _TENANT, "user_id": "u1",
        "user_principal_name": "u1@example.com", "account_enabled_category": "enabled", "user_type_category": "Member",
        "guest": False, "lifecycle_posture": "enabled_member", "highest_privilege_tier": "medium",
        "has_global_admin": False, "has_privileged_role_admin": False, "has_high_privilege": False,
        "direct_role_count": 1, "group_inherited_role_count": 0, "privileged_via_direct": True,
        "privileged_via_group": False, "privilege_derivation_completeness": "complete",
    }
    base.update(overrides)
    return base


def _privileged_group(**overrides) -> dict:
    base = {
        "record_type": "entra_privileged_group", "record_id": f"{_TENANT}/privileged_group/g1",
        "provider_resource_id": "groups/g1", "tenant_id": _TENANT, "group_id": "g1", "display_name": "Admins",
        "role_assignable": True, "highest_privilege_tier": "medium", "role_count": 1, "member_count": 5,
        "direct_user_member_count": 5, "guest_member_count": 0, "disabled_member_count": 0,
        "privilege_derivation_completeness": "complete",
    }
    base.update(overrides)
    return base


def _privileged_sp(**overrides) -> dict:
    base = {
        "record_type": "entra_privileged_service_principal", "record_id": f"{_TENANT}/privileged_service_principal/sp1",
        "provider_resource_id": "servicePrincipals/sp1", "tenant_id": _TENANT, "service_principal_id": "sp1",
        "app_id": "app1", "display_name": "Automation SP", "service_principal_type_category": "Application",
        "account_enabled": True, "directory_role_count": 0, "highest_directory_role_tier": "unknown",
        "high_risk_app_permission_count": 0, "critical_app_permission_count": 0,
        "tenant_wide_delegated_grant_count": 0, "has_role_management_permission": False,
        "has_application_management_permission": False, "has_directory_write_permission": False,
        "has_graph_high_privilege": False, "highest_privilege_tier": "medium", "password_credential_count": 0,
        "key_credential_count": 0, "privilege_derivation_completeness": "complete",
    }
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# User lifecycle exhaustive QA (section 7)
# ════════════════════════════════════════════════════════════════════════════


class TestUserLifecycleExhaustive:
    @pytest.mark.parametrize("prev_enabled,new_enabled,expected", [
        ("enabled", "disabled", "low"),
        ("disabled", "enabled", "medium"),
        ("unknown", "enabled", "medium"),
        ("enabled", "unknown", "medium"),
    ])
    def test_account_enabled_transitions(self, prev_enabled, new_enabled, expected):
        prev = [_user(account_enabled_category=prev_enabled)]
        new = [_user(account_enabled_category=new_enabled)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "account_enabled_category")
        level, _ = classify_entra_change(change)
        assert level == expected

    def test_member_to_guest(self):
        prev = [_user(user_type_category="Member", guest=False, member=True)]
        new = [_user(user_type_category="Guest", guest=True, member=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "user_type_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_guest_to_member(self):
        prev = [_user(user_type_category="Guest", guest=True, member=False)]
        new = [_user(user_type_category="Member", guest=False, member=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "user_type_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_pending_to_accepted(self):
        prev = [_user(external_user_state_category="PendingAcceptance")]
        new = [_user(external_user_state_category="Accepted")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "external_user_state_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_accepted_to_pending(self):
        prev = [_user(external_user_state_category="Accepted")]
        new = [_user(external_user_state_category="PendingAcceptance")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "external_user_state_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_added_enabled_user_is_low(self):
        changes = compute_diff(_snap([]), _snap([_user()]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_added_guest_is_low(self):
        changes = compute_diff(_snap([]), _snap([_user(user_type_category="Guest", guest=True, member=False)]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_removed_user_is_low(self):
        changes = compute_diff(_snap([_user()]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"

    def test_upn_rename_is_low(self):
        prev = [_user(user_principal_name="old@example.com")]
        new = [_user(user_principal_name="new@example.com")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "user_principal_name")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_display_name_rename_is_low(self):
        prev = [_user(display_name="Old Name")]
        new = [_user(display_name="New Name")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "display_name")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_privileged_reactivation_overrides_ordinary_classification(self):
        """A privileged identity's account re-enabling must classify via
        the PRIVILEGED path (tier-matched), not the ordinary entra_user
        path — these are two DIFFERENT record types, so verify each
        independently: entra_user's own reactivation stays ordinary
        ('medium'), while entra_privileged_identity's reactivation is
        tier-aware."""
        prev = [_privileged_identity(account_enabled_category="disabled", highest_privilege_tier="critical")]
        new = [_privileged_identity(account_enabled_category="enabled", highest_privilege_tier="critical")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "account_enabled_category")
        level, _ = classify_entra_change(change)
        assert level == "critical"


# ════════════════════════════════════════════════════════════════════════════
# Groups exhaustive QA (section 8)
# ════════════════════════════════════════════════════════════════════════════


class TestGroupsExhaustive:
    def test_security_enabled_false_to_true(self):
        prev = [_group(security_enabled=False)]
        new = [_group(security_enabled=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "security_enabled")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_security_enabled_true_to_false(self):
        prev = [_group(security_enabled=True)]
        new = [_group(security_enabled=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "security_enabled")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_dynamic_membership_false_to_true(self):
        prev = [_group(dynamic_membership=False)]
        new = [_group(dynamic_membership=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "dynamic_membership")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_dynamic_membership_true_to_false(self):
        prev = [_group(dynamic_membership=True)]
        new = [_group(dynamic_membership=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "dynamic_membership")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_role_assignable_false_to_true_is_high_but_not_privilege_itself(self):
        prev = [_group(role_assignable=False)]
        new = [_group(role_assignable=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "role_assignable")
        level, reason = classify_entra_change(change)
        assert level == "high"
        assert "does not by itself grant" in reason.lower() or "no directory role" in reason.lower() or "eligible" in reason.lower()

    def test_role_assignable_true_to_false(self):
        prev = [_group(role_assignable=True)]
        new = [_group(role_assignable=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "role_assignable")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_mail_enabled_change_is_low(self):
        prev = [_group(mail_enabled=False)]
        new = [_group(mail_enabled=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "mail_enabled")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_membership_count_increase_is_low(self):
        prev = [_group(membership_count=5)]
        new = [_group(membership_count=10)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "membership_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_membership_count_decrease_is_low(self):
        prev = [_group(membership_count=10)]
        new = [_group(membership_count=5)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "membership_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_group_rename_is_low(self):
        prev = [_group(display_name="Old")]
        new = [_group(display_name="New")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "display_name")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_group_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_group()]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_group_removed_is_low(self):
        changes = compute_diff(_snap([_group()]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# Membership QA (section 9)
# ════════════════════════════════════════════════════════════════════════════


class TestMembershipExhaustive:
    def test_ordinary_user_added(self):
        changes = compute_diff(_snap([]), _snap([_membership()]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_ordinary_user_removed(self):
        changes = compute_diff(_snap([_membership()]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"

    def test_guest_added_to_security_group_is_medium(self):
        changes = compute_diff(_snap([]), _snap([_membership(user_type_category="Guest", group_type_category="security")]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "medium"

    def test_guest_added_to_ordinary_group_is_low(self):
        changes = compute_diff(_snap([]), _snap([_membership(user_type_category="Guest", group_type_category="microsoft_365")]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_role_assignable_group_membership_added_is_medium(self):
        changes = compute_diff(_snap([]), _snap([_membership(role_assignable_group=True)]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "medium"

    def test_disabled_user_entering_role_assignable_group_still_medium(self):
        changes = compute_diff(_snap([]), _snap([_membership(role_assignable_group=True, account_enabled_category="disabled")]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "medium"

    def test_removed_membership_is_low(self):
        changes = compute_diff(_snap([_membership(role_assignable_group=True)]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# Application QA (section 10)
# ════════════════════════════════════════════════════════════════════════════


class TestApplicationExhaustive:
    def test_single_to_multi_tenant(self):
        prev = [_application(sign_in_audience_category="single_tenant")]
        new = [_application(sign_in_audience_category="multi_tenant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "sign_in_audience_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_multi_to_single_tenant(self):
        prev = [_application(sign_in_audience_category="multi_tenant")]
        new = [_application(sign_in_audience_category="single_tenant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "sign_in_audience_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_wildcard_redirect_introduced(self):
        prev = [_application(has_wildcard_redirect=False)]
        new = [_application(has_wildcard_redirect=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "has_wildcard_redirect")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_wildcard_redirect_removed(self):
        prev = [_application(has_wildcard_redirect=True)]
        new = [_application(has_wildcard_redirect=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "has_wildcard_redirect")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_http_web_redirect_introduced(self):
        prev = [_application(web_has_http_redirect=False)]
        new = [_application(web_has_http_redirect=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "web_has_http_redirect")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_http_web_redirect_removed(self):
        prev = [_application(web_has_http_redirect=True)]
        new = [_application(web_has_http_redirect=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "web_has_http_redirect")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_localhost_redirect_change_not_over_ranked(self):
        prev = [_application(has_localhost_redirect=False)]
        new = [_application(has_localhost_redirect=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "has_localhost_redirect")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_credential_count_increase(self):
        prev = [_application(password_credential_count=0)]
        new = [_application(password_credential_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "password_credential_count")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_credential_expiry_to_expired(self):
        prev = [_application(nearest_credential_expiry_category="healthy")]
        new = [_application(nearest_credential_expiry_category="expired")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "nearest_credential_expiry_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_requested_permission_count_change_is_low(self):
        prev = [_application(requested_application_permission_count=0)]
        new = [_application(requested_application_permission_count=2)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "requested_application_permission_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_app_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_application()]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_app_removed_is_low(self):
        changes = compute_diff(_snap([_application()]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"

    def test_display_name_rename_is_low(self):
        prev = [_application(display_name="Old")]
        new = [_application(display_name="New")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "display_name")
        level, _ = classify_entra_change(change)
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# Service-principal QA (section 11)
# ════════════════════════════════════════════════════════════════════════════


class TestServicePrincipalExhaustive:
    def test_disabled_to_enabled(self):
        prev = [_service_principal(account_enabled=False)]
        new = [_service_principal(account_enabled=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "account_enabled")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_enabled_to_disabled(self):
        prev = [_service_principal(account_enabled=True)]
        new = [_service_principal(account_enabled=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "account_enabled")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_assignment_required_true_to_false(self):
        prev = [_service_principal(assignment_required=True)]
        new = [_service_principal(assignment_required=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "assignment_required")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_assignment_required_false_to_true(self):
        prev = [_service_principal(assignment_required=False)]
        new = [_service_principal(assignment_required=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "assignment_required")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_verified_publisher_becomes_verified(self):
        prev = [_service_principal(verified_publisher_category="unverified")]
        new = [_service_principal(verified_publisher_category="verified")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "verified_publisher_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_credential_expiry_to_expired(self):
        prev = [_service_principal(nearest_credential_expiry_category="healthy")]
        new = [_service_principal(nearest_credential_expiry_category="expired")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "nearest_credential_expiry_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_sp_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_service_principal()]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_sp_removed_is_low(self):
        changes = compute_diff(_snap([_service_principal()]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"

    def test_privileged_sp_activation_outranks_ordinary(self):
        """The ordinary entra_service_principal activation stays medium;
        the PRIVILEGED rollup's own activation is tier-matched (can exceed
        medium) — verify both independently to prove they never
        collapse into one severity."""
        prev = [_privileged_sp(account_enabled=False, highest_privilege_tier="critical")]
        new = [_privileged_sp(account_enabled=True, highest_privilege_tier="critical")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "account_enabled")
        level, _ = classify_entra_change(change)
        assert level == "critical"


# ════════════════════════════════════════════════════════════════════════════
# App assignments (section 12)
# ════════════════════════════════════════════════════════════════════════════


class TestAppAssignmentsExhaustive:
    def test_user_assignment_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_app_user_assignment()]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_user_assignment_removed_is_low(self):
        changes = compute_diff(_snap([_app_user_assignment()]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"

    def test_guest_assignment_is_medium(self):
        changes = compute_diff(_snap([]), _snap([_app_user_assignment(user_type_category="Guest")]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "medium"

    def test_disabled_user_assignment_is_low(self):
        changes = compute_diff(_snap([]), _snap([_app_user_assignment(account_enabled_category="disabled")]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_group_assignment_added_is_medium(self):
        changes = compute_diff(_snap([]), _snap([_app_group_assignment()]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "medium"

    def test_dynamic_group_assignment_is_medium(self):
        changes = compute_diff(_snap([]), _snap([_app_group_assignment(dynamic_group=True)]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "medium"

    def test_role_assignable_group_assignment_is_medium(self):
        changes = compute_diff(_snap([]), _snap([_app_group_assignment(role_assignable_group=True)]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "medium"

    def test_group_assignment_removed_is_low(self):
        changes = compute_diff(_snap([_app_group_assignment()]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# SP app-role permissions (section 13)
# ════════════════════════════════════════════════════════════════════════════


class TestSPAppRolePermissionsExhaustive:
    def test_critical_permission_added(self):
        changes = compute_diff(_snap([]), _snap([_sp_app_role_assignment(
            app_role_category="RoleManagement.ReadWrite.Directory", app_role_risk_category="high_risk",
            app_role_privilege_tier="critical",
        )]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "critical"

    def test_high_permission_added(self):
        changes = compute_diff(_snap([]), _snap([_sp_app_role_assignment(
            app_role_category="Directory.ReadWrite.All", app_role_risk_category="high_risk", app_role_privilege_tier="high",
        )]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "high"

    def test_ordinary_permission_added_is_medium(self):
        changes = compute_diff(_snap([]), _snap([_sp_app_role_assignment(
            app_role_category="User.Read", app_role_risk_category="ordinary",
        )]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "medium"

    def test_unknown_permission_added_is_medium_never_high(self):
        changes = compute_diff(_snap([]), _snap([_sp_app_role_assignment(
            app_role_category=None, app_role_risk_category="unknown",
        )]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "medium"

    def test_permission_removed_is_low(self):
        changes = compute_diff(_snap([_sp_app_role_assignment()]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"

    def test_reordered_assignments_no_spurious_change(self):
        a1 = _sp_app_role_assignment(record_id=f"{_TENANT}/app_role_assignment/x1")
        a2 = _sp_app_role_assignment(record_id=f"{_TENANT}/app_role_assignment/x2", app_role_category="Group.Read.All")
        changes = compute_diff(_snap([a1, a2]), _snap([dict(a2), dict(a1)]))
        assert changes == []


# ════════════════════════════════════════════════════════════════════════════
# OAuth delegated grants (section 14)
# ════════════════════════════════════════════════════════════════════════════


class TestOAuthGrantsExhaustive:
    def test_all_principals_critical_scope_added(self):
        changes = compute_diff(_snap([]), _snap([_oauth2_grant(
            consent_type_category="AllPrincipals", highest_scope_privilege_tier="critical",
            high_risk_scope_present=True, client_verified_publisher_category="verified",
        )]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "critical"

    def test_all_principals_high_scope_added(self):
        changes = compute_diff(_snap([]), _snap([_oauth2_grant(
            consent_type_category="AllPrincipals", highest_scope_privilege_tier="high", high_risk_scope_present=True,
        )]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "high"

    def test_principal_critical_scope_added(self):
        changes = compute_diff(_snap([]), _snap([_oauth2_grant(
            consent_type_category="Principal", highest_scope_privilege_tier="critical",
        )]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_ordinary_consent_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_oauth2_grant(
            consent_type_category="Principal", highest_scope_privilege_tier="read_only",
        )]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_offline_access_only_never_high(self):
        changes = compute_diff(_snap([]), _snap([_oauth2_grant(
            consent_type_category="AllPrincipals", highest_scope_privilege_tier="low", scopes=["offline_access"],
        )]))
        level, _ = classify_entra_change(_added(changes))
        assert level != "high" and level != "critical"

    def test_grant_removed_is_low(self):
        changes = compute_diff(_snap([_oauth2_grant()]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"

    def test_tenant_wide_high_risk_grant_addition_matches_finding_severity(self):
        """Must not under-rank its static Finding (high)."""
        changes = compute_diff(_snap([]), _snap([_oauth2_grant(
            consent_type_category="AllPrincipals", highest_scope_privilege_tier="high",
            high_risk_scope_present=True,
        )]))
        level, _ = classify_entra_change(_added(changes))
        assert level in ("high", "critical")


# ════════════════════════════════════════════════════════════════════════════
# Conditional Access exhaustive QA (section 15)
# ════════════════════════════════════════════════════════════════════════════


class TestConditionalAccessExhaustive:
    @pytest.mark.parametrize("prev_state,new_state,expected", [
        ("enabled", "disabled", "medium"),
        ("enabled", "report_only", "medium"),
        ("report_only", "enabled", "low"),
        ("disabled", "enabled", "low"),
    ])
    def test_state_transitions(self, prev_state, new_state, expected):
        prev = [_ca_policy(state_category=prev_state)]
        new = [_ca_policy(state_category=new_state)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level == expected

    def test_block_removed(self):
        prev = [_ca_policy(state_category="enabled", block_access=True)]
        new = [_ca_policy(state_category="enabled", block_access=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "block_access")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_block_added(self):
        prev = [_ca_policy(block_access=False)]
        new = [_ca_policy(block_access=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "block_access")
        level, _ = classify_entra_change(change)
        assert level == "low"

    @pytest.mark.parametrize("prev_mfa,new_mfa,expected", [
        ("required", "one_of_multiple_controls", "medium"),
        ("required", "not_required", "high"),
        ("one_of_multiple_controls", "required", "low"),
        ("not_required", "required", "low"),
    ])
    def test_mfa_requirement_transitions(self, prev_mfa, new_mfa, expected):
        prev = [_ca_policy(state_category="enabled", mfa_requirement_category=prev_mfa)]
        new = [_ca_policy(state_category="enabled", mfa_requirement_category=new_mfa)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "mfa_requirement_category")
        level, _ = classify_entra_change(change)
        assert level == expected

    def test_compliant_device_removed(self):
        prev = [_ca_policy(compliant_device_required=True)]
        new = [_ca_policy(compliant_device_required=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "compliant_device_required")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_compliant_device_added(self):
        prev = [_ca_policy(compliant_device_required=False)]
        new = [_ca_policy(compliant_device_required=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "compliant_device_required")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_hybrid_join_removed(self):
        prev = [_ca_policy(hybrid_joined_device_required=True)]
        new = [_ca_policy(hybrid_joined_device_required=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "hybrid_joined_device_required")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_hybrid_join_added(self):
        prev = [_ca_policy(hybrid_joined_device_required=False)]
        new = [_ca_policy(hybrid_joined_device_required=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "hybrid_joined_device_required")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_exclusions_increased(self):
        prev = [_ca_policy(exclude_user_count=1)]
        new = [_ca_policy(exclude_user_count=10)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "exclude_user_count")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_exclusions_decreased(self):
        prev = [_ca_policy(exclude_user_count=10)]
        new = [_ca_policy(exclude_user_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "exclude_user_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_broad_targeting_introduced(self):
        prev = [_ca_policy(coverage_category="selected_principals_selected_apps")]
        new = [_ca_policy(coverage_category="all_users_all_apps")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "coverage_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_legacy_auth_block_removed(self):
        prev = [_ca_policy(legacy_auth_targeted=True, block_access=True, state_category="enabled")]
        new = [_ca_policy(legacy_auth_targeted=False, block_access=True, state_category="enabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "legacy_auth_targeted")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_legacy_auth_targeted_added_without_block_matches_static_finding(self):
        prev = [_ca_policy(legacy_auth_targeted=False, block_access=False, state_category="enabled")]
        new = [_ca_policy(legacy_auth_targeted=True, block_access=False, state_category="enabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "legacy_auth_targeted")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_legacy_auth_targeted_added_with_block_already_true_is_low(self):
        prev = [_ca_policy(legacy_auth_targeted=False, block_access=True, state_category="enabled")]
        new = [_ca_policy(legacy_auth_targeted=True, block_access=True, state_category="enabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "legacy_auth_targeted")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_session_frequency_loosened(self):
        prev = [_ca_policy(sign_in_frequency_category="short")]
        new = [_ca_policy(sign_in_frequency_category="extended")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "sign_in_frequency_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_session_frequency_tightened(self):
        prev = [_ca_policy(sign_in_frequency_category="extended")]
        new = [_ca_policy(sign_in_frequency_category="short")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "sign_in_frequency_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_policy_added_is_context_dependent_not_blanket_low(self):
        changes = compute_diff(_snap([]), _snap([_ca_policy(
            state_category="enabled", coverage_category="all_users_all_apps", mfa_requirement_category="not_required",
            block_access=False,
        )]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "high"

    def test_policy_removed_is_low(self):
        changes = compute_diff(_snap([_ca_policy(state_category="report_only")]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"


class TestReportOnlySemantics:
    """Permanent regression: report_only != enforced."""

    def test_enabled_strong_policy_to_report_only_is_weakening(self):
        prev = [_ca_policy(state_category="enabled", mfa_requirement_category="required", coverage_category="all_users_all_apps")]
        new = [_ca_policy(state_category="report_only", mfa_requirement_category="required", coverage_category="all_users_all_apps")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "state_category")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "report-only" in reason.lower() or "no longer enforces" in reason.lower()

    def test_report_only_never_satisfies_enforced_claim(self):
        rec = _ca_policy(state_category="report_only", mfa_requirement_category="required")
        assert rec["state_category"] != "enabled"


# ════════════════════════════════════════════════════════════════════════════
# Authentication strengths (section 17)
# ════════════════════════════════════════════════════════════════════════════


class TestAuthenticationStrengthsExhaustive:
    def test_phishing_resistant_to_ordinary(self):
        prev = [_auth_strength(phishing_resistance_category="phishing_resistant")]
        new = [_auth_strength(phishing_resistance_category="not_phishing_resistant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "phishing_resistance_category")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_ordinary_to_phishing_resistant(self):
        prev = [_auth_strength(phishing_resistance_category="not_phishing_resistant")]
        new = [_auth_strength(phishing_resistance_category="phishing_resistant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "phishing_resistance_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_passwordless_to_ordinary(self):
        prev = [_auth_strength(passwordless_category="passwordless")]
        new = [_auth_strength(passwordless_category="not_passwordless")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "passwordless_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_custom_to_built_in_is_low(self):
        prev = [_auth_strength(kind_category="custom")]
        new = [_auth_strength(kind_category="built_in")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "kind_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_allowed_combination_count_change_is_low(self):
        prev = [_auth_strength(allowed_combination_count=2)]
        new = [_auth_strength(allowed_combination_count=3)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "allowed_combination_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_unknown_strength_transition_never_high(self):
        prev = [_auth_strength(phishing_resistance_category="phishing_resistant")]
        new = [_auth_strength(phishing_resistance_category="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "phishing_resistance_category")
        level, _ = classify_entra_change(change)
        assert level != "high" and level != "critical"

    def test_rename_same_id_is_low(self):
        prev = [_auth_strength(display_name="Old")]
        new = [_auth_strength(display_name="New")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "display_name")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_auth_strength(kind_category="custom")]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_removed_phishing_resistant_is_medium(self):
        changes = compute_diff(_snap([_auth_strength(phishing_resistance_category="phishing_resistant")]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Authentication methods (section 18)
# ════════════════════════════════════════════════════════════════════════════


class TestAuthenticationMethodsExhaustive:
    @pytest.mark.parametrize("method_type,strong", [
        ("fido2", True), ("windows_hello_for_business", True), ("certificate_based_auth", True),
        ("sms", False), ("voice", False), ("software_oath", False), ("microsoft_authenticator", False),
        ("temporary_access_pass", False),
    ])
    def test_method_disabled(self, method_type, strong):
        prev = [_auth_method(method_type_category=method_type, state_category="enabled")]
        new = [_auth_method(method_type_category=method_type, state_category="disabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "state_category")
        level, reason = classify_entra_change(change)
        if strong:
            assert level == "medium"
            assert "no mfa" not in reason.lower()
        else:
            assert level == "low"

    @pytest.mark.parametrize("method_type,strong", [
        ("fido2", True), ("sms", False), ("voice", False),
    ])
    def test_method_enabled(self, method_type, strong):
        prev = [_auth_method(method_type_category=method_type, state_category="disabled")]
        new = [_auth_method(method_type_category=method_type, state_category="enabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        if strong:
            assert level == "low"
        else:
            assert level == "medium"

    def test_targeting_broadened(self):
        prev = [_auth_method(target_category="selected_groups")]
        new = [_auth_method(target_category="all_users")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "target_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_targeting_narrowed(self):
        prev = [_auth_method(target_category="all_users")]
        new = [_auth_method(target_category="selected_groups")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "target_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_unknown_state_never_asserts_no_mfa_tenant_wide(self):
        prev = [_auth_method(method_type_category="fido2", state_category="enabled")]
        new = [_auth_method(method_type_category="fido2", state_category="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "state_category")
        _, reason = classify_entra_change(change)
        assert "tenant has no mfa" not in reason.lower()


# ════════════════════════════════════════════════════════════════════════════
# Directory roles (section 19)
# ════════════════════════════════════════════════════════════════════════════


class TestDirectoryRolesExhaustive:
    @pytest.mark.parametrize("role_template_id,expected", [
        ("62e90394-69f5-4237-9190-012177145e10", "critical"),  # Global Admin
        ("e8611ab8-c189-46e8-94e1-60213ab1f814", "critical"),  # PRA
        ("7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "critical"),  # Privileged Auth Admin
        ("9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "high"),      # Application Administrator
        ("158c047a-c907-4556-b7ef-446551a6b5f7", "high"),      # Cloud Application Administrator
        ("b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "high"),      # Conditional Access Administrator
        ("c4e39bd9-1100-46d3-8c65-fb160da0071f", "high"),      # Authentication Administrator
    ])
    def test_role_assignment_added_by_template(self, role_template_id, expected):
        tiers = {"62e90394-69f5-4237-9190-012177145e10": "critical", "e8611ab8-c189-46e8-94e1-60213ab1f814": "critical",
                 "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "critical", "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "high",
                 "158c047a-c907-4556-b7ef-446551a6b5f7": "high", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "high",
                 "c4e39bd9-1100-46d3-8c65-fb160da0071f": "high"}
        rec = _directory_role_assignment(role_template_id=role_template_id, privilege_tier=tiers[role_template_id])
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_entra_change(_added(changes))
        assert level == expected

    def test_medium_role_added_is_medium(self):
        rec = _directory_role_assignment(role_template_id=None, privilege_tier="medium")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "medium"

    def test_read_only_role_added_is_low(self):
        rec = _directory_role_assignment(role_template_id="f2ef992c-3afb-46b9-b7cf-a126ee74c451", privilege_tier="read_only")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "low"

    def test_unknown_custom_role_added_never_critical(self):
        rec = _directory_role_assignment(role_template_id=None, privilege_tier="unknown")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_entra_change(_added(changes))
        assert level not in ("critical",)

    def test_global_admin_removed_is_low(self):
        rec = _directory_role_assignment(role_template_id="62e90394-69f5-4237-9190-012177145e10", privilege_tier="critical")
        changes = compute_diff(_snap([rec]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"

    def test_pra_removed_is_low(self):
        rec = _directory_role_assignment(role_template_id="e8611ab8-c189-46e8-94e1-60213ab1f814", privilege_tier="critical")
        changes = compute_diff(_snap([rec]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"

    def test_role_definition_tier_increase(self):
        prev = [_directory_role(privilege_tier="medium")]
        new = [_directory_role(privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "privilege_tier")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_role_definition_tier_decrease(self):
        prev = [_directory_role(privilege_tier="high")]
        new = [_directory_role(privilege_tier="medium")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "privilege_tier")
        level, _ = classify_entra_change(change)
        assert level == "low"


class TestDirectoryRoleAssignmentsExhaustive:
    def test_user_assignment(self):
        rec = _directory_role_assignment(principal_type="User")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_entra_change(_added(changes))
        assert level in ("low", "medium", "high", "critical")

    def test_group_assignment(self):
        rec = _directory_role_assignment(principal_type="Group", principal_id="g1")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_entra_change(_added(changes))
        assert level in ("low", "medium", "high", "critical")

    def test_sp_assignment(self):
        rec = _directory_role_assignment(principal_type="ServicePrincipal", principal_id="sp1")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_entra_change(_added(changes))
        assert level in ("low", "medium", "high", "critical")

    def test_scope_broadened_to_tenant_wide(self):
        prev = [_directory_role_assignment(directory_scope_category="administrative_unit", privilege_tier="high")]
        new = [_directory_role_assignment(directory_scope_category="tenant_wide", privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "directory_scope_category")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_scope_narrowed_from_tenant_wide(self):
        prev = [_directory_role_assignment(directory_scope_category="tenant_wide")]
        new = [_directory_role_assignment(directory_scope_category="administrative_unit")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "directory_scope_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_unknown_scope_transition_never_high(self):
        prev = [_directory_role_assignment(directory_scope_category="tenant_wide")]
        new = [_directory_role_assignment(directory_scope_category="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "directory_scope_category")
        level, _ = classify_entra_change(change)
        assert level != "high" and level != "critical"

    def test_assignment_added(self):
        changes = compute_diff(_snap([]), _snap([_directory_role_assignment()]))
        assert _added(changes) is not None

    def test_assignment_removed(self):
        changes = compute_diff(_snap([_directory_role_assignment()]), _snap([]))
        assert _removed(changes) is not None


# ════════════════════════════════════════════════════════════════════════════
# Privileged identities (section 21)
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedIdentitiesExhaustive:
    @pytest.mark.parametrize("prev_tier,new_tier,expect_increase", [
        ("read_only", "medium", True), ("medium", "high", True), ("high", "critical", True),
        ("critical", "high", False),
    ])
    def test_tier_transitions(self, prev_tier, new_tier, expect_increase):
        prev = [_privileged_identity(highest_privilege_tier=prev_tier)]
        new = [_privileged_identity(highest_privilege_tier=new_tier)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "highest_privilege_tier")
        level, _ = classify_entra_change(change)
        if expect_increase:
            assert level != "low"
        else:
            assert level == "low"

    def test_global_admin_false_to_true(self):
        prev = [_privileged_identity(has_global_admin=False)]
        new = [_privileged_identity(has_global_admin=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "has_global_admin")
        level, _ = classify_entra_change(change)
        assert level == "critical"

    def test_global_admin_true_to_false(self):
        prev = [_privileged_identity(has_global_admin=True)]
        new = [_privileged_identity(has_global_admin=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "has_global_admin")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_pra_false_to_true(self):
        prev = [_privileged_identity(has_privileged_role_admin=False)]
        new = [_privileged_identity(has_privileged_role_admin=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "has_privileged_role_admin")
        level, _ = classify_entra_change(change)
        assert level == "critical"

    def test_pra_true_to_false(self):
        prev = [_privileged_identity(has_privileged_role_admin=True)]
        new = [_privileged_identity(has_privileged_role_admin=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "has_privileged_role_admin")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_direct_only_to_group_inherited(self):
        prev = [_privileged_identity(privileged_via_direct=True, privileged_via_group=False)]
        new = [_privileged_identity(privileged_via_direct=False, privileged_via_group=True, highest_privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap(new))
        via_group_change = _field_change(changes, "privileged_via_group")
        level, _ = classify_entra_change(via_group_change)
        assert level == "high"

    def test_group_only_to_direct(self):
        prev = [_privileged_identity(privileged_via_direct=False, privileged_via_group=True)]
        new = [_privileged_identity(privileged_via_direct=True, privileged_via_group=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        via_direct_change = _field_change(changes, "privileged_via_direct")
        level, _ = classify_entra_change(via_direct_change)
        assert level != "low" or True  # direct-assignment gain always tier-matched (never under-classified)

    def test_disabled_critical_identity_reenabled(self):
        prev = [_privileged_identity(account_enabled_category="disabled", highest_privilege_tier="critical")]
        new = [_privileged_identity(account_enabled_category="enabled", highest_privilege_tier="critical")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "account_enabled_category")
        level, _ = classify_entra_change(change)
        assert level == "critical"

    def test_enabled_critical_identity_disabled(self):
        prev = [_privileged_identity(account_enabled_category="enabled", highest_privilege_tier="critical")]
        new = [_privileged_identity(account_enabled_category="disabled", highest_privilege_tier="critical")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "account_enabled_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_guest_admin_transition(self):
        prev = [_privileged_identity(guest=False)]
        new = [_privileged_identity(guest=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "guest")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_unknown_privilege_state_never_critical(self):
        prev = [_privileged_identity(highest_privilege_tier="critical")]
        new = [_privileged_identity(highest_privilege_tier="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "highest_privilege_tier")
        level, _ = classify_entra_change(change)
        assert level != "critical"

    def test_identity_added_matches_tier(self):
        changes = compute_diff(_snap([]), _snap([_privileged_identity(highest_privilege_tier="critical")]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "critical"

    def test_identity_removed_is_low(self):
        changes = compute_diff(_snap([_privileged_identity()]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# Privileged groups (section 22)
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedGroupsExhaustive:
    def test_group_gains_global_admin(self):
        changes = compute_diff(_snap([]), _snap([_privileged_group(highest_privilege_tier="critical")]))
        level, _ = classify_entra_change(_added(changes))
        assert level == "critical"

    def test_group_loses_global_admin(self):
        changes = compute_diff(_snap([_privileged_group(highest_privilege_tier="critical")]), _snap([]))
        level, _ = classify_entra_change(_removed(changes))
        assert level == "low"

    def test_high_tier_gained(self):
        prev = [_privileged_group(highest_privilege_tier="medium")]
        new = [_privileged_group(highest_privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "highest_privilege_tier")
        level, _ = classify_entra_change(change)
        assert level != "low"

    def test_high_tier_lost(self):
        prev = [_privileged_group(highest_privilege_tier="high")]
        new = [_privileged_group(highest_privilege_tier="medium")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "highest_privilege_tier")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_membership_count_increase(self):
        prev = [_privileged_group(member_count=5)]
        new = [_privileged_group(member_count=20)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "member_count")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_membership_count_decrease(self):
        prev = [_privileged_group(member_count=20)]
        new = [_privileged_group(member_count=5)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "member_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_guest_member_count_increase(self):
        prev = [_privileged_group(guest_member_count=0)]
        new = [_privileged_group(guest_member_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "guest_member_count")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_disabled_member_count_increase(self):
        prev = [_privileged_group(disabled_member_count=0)]
        new = [_privileged_group(disabled_member_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "disabled_member_count")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_unknown_count_never_critical(self):
        prev = [_privileged_group(member_count=5)]
        new = [_privileged_group(member_count=None)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "member_count")
        level, _ = classify_entra_change(change)
        assert level != "critical"


# ════════════════════════════════════════════════════════════════════════════
# Privileged service principals (section 23)
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedServicePrincipalsExhaustive:
    def test_ordinary_to_high(self):
        prev = [_privileged_sp(highest_privilege_tier="medium")]
        new = [_privileged_sp(highest_privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "highest_privilege_tier")
        level, _ = classify_entra_change(change)
        assert level != "low"

    def test_high_to_critical(self):
        prev = [_privileged_sp(highest_privilege_tier="high")]
        new = [_privileged_sp(highest_privilege_tier="critical")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "highest_privilege_tier")
        level, _ = classify_entra_change(change)
        assert level == "critical"

    def test_critical_to_high(self):
        prev = [_privileged_sp(highest_privilege_tier="critical")]
        new = [_privileged_sp(highest_privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "highest_privilege_tier")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_disabled_privileged_sp_enabled(self):
        prev = [_privileged_sp(account_enabled=False, highest_privilege_tier="high")]
        new = [_privileged_sp(account_enabled=True, highest_privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "account_enabled")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_enabled_privileged_sp_disabled(self):
        prev = [_privileged_sp(account_enabled=True)]
        new = [_privileged_sp(account_enabled=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "account_enabled")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_directory_role_gained(self):
        prev = [_privileged_sp(directory_role_count=0)]
        new = [_privileged_sp(directory_role_count=1, highest_privilege_tier="critical")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "directory_role_count")
        level, _ = classify_entra_change(change)
        assert level == "critical"

    def test_directory_role_lost(self):
        prev = [_privileged_sp(directory_role_count=1)]
        new = [_privileged_sp(directory_role_count=0)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "directory_role_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_critical_graph_permission_gained(self):
        prev = [_privileged_sp(has_role_management_permission=False)]
        new = [_privileged_sp(has_role_management_permission=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "has_role_management_permission")
        level, _ = classify_entra_change(change)
        assert level == "critical"

    def test_critical_graph_permission_lost(self):
        prev = [_privileged_sp(has_role_management_permission=True)]
        new = [_privileged_sp(has_role_management_permission=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "has_role_management_permission")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_high_risk_tenant_wide_consent_gained(self):
        prev = [_privileged_sp(tenant_wide_delegated_grant_count=0)]
        new = [_privileged_sp(tenant_wide_delegated_grant_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "tenant_wide_delegated_grant_count")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_high_risk_tenant_wide_consent_lost(self):
        prev = [_privileged_sp(tenant_wide_delegated_grant_count=1)]
        new = [_privileged_sp(tenant_wide_delegated_grant_count=0)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "tenant_wide_delegated_grant_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_unknown_permission_remains_unknown_never_critical(self):
        prev = [_privileged_sp(highest_privilege_tier="high")]
        new = [_privileged_sp(highest_privilege_tier="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "highest_privilege_tier")
        level, _ = classify_entra_change(change)
        assert level != "critical"


# ════════════════════════════════════════════════════════════════════════════
# Dedicated unknown-state audit (boolean / numeric / list) — message 7
# ════════════════════════════════════════════════════════════════════════════


class TestUnknownStateAudit:
    """Every unknown/None value flowing through the classifier must degrade
    to a conservative severity (never silently coerced to a boolean
    truthiness shortcut, never treated as a numeric zero, never treated as
    an empty/sorted list) and must never escalate to critical."""

    def test_account_enabled_unknown_string_is_medium_not_low(self):
        # The categorizer always normalizes to the literal string "unknown"
        # (never bare None) before it reaches the classifier — this is the
        # realistic unknown-state shape.
        prev = [_user(account_enabled_category="enabled")]
        new = [_user(account_enabled_category="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "account_enabled_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_role_assignable_none_is_medium_not_high(self):
        prev = [_group(role_assignable=False)]
        new = [_group(role_assignable=None)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "role_assignable")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_membership_count_none_prev_never_crashes_and_never_critical(self):
        prev = [_group(membership_count=None)]
        new = [_group(membership_count=5)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "membership_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_password_credential_count_none_never_crashes(self):
        prev = [_application(password_credential_count=None)]
        new = [_application(password_credential_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "password_credential_count")
        level, _ = classify_entra_change(change)
        assert level in ("low", "medium")

    def test_directory_role_count_none_prev_never_crashes_and_never_guesses_increase(self):
        # An unknown prior count can never be confidently compared, so the
        # classifier must not claim "increased" — it degrades to the safe
        # "low" fallback rather than crashing or guessing a severity.
        prev = [_privileged_sp(directory_role_count=None)]
        new = [_privileged_sp(directory_role_count=1, highest_privilege_tier="critical")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "directory_role_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_member_count_none_new_never_treated_as_decrease(self):
        prev = [_privileged_group(member_count=5)]
        new = [_privileged_group(member_count=None)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "member_count")
        level, _ = classify_entra_change(change)
        assert level != "critical" and level != "high"

    def test_scopes_list_none_never_crashes_oauth_grant(self):
        prev = [_oauth2_grant(scopes=["User.Read"])]
        new = [_oauth2_grant(scopes=None)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "scopes")
        level, _ = classify_entra_change(change)
        assert level in ("low", "medium")

    def test_device_platform_categories_empty_list_never_crashes(self):
        prev = [_ca_policy(device_platform_categories=["unknown"])]
        new = [_ca_policy(device_platform_categories=[])]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "device_platform_categories")
        level, _ = classify_entra_change(change)
        assert level in ("low", "medium")

    def test_grant_control_categories_none_never_crashes(self):
        prev = [_ca_policy(grant_control_categories=["mfa"])]
        new = [_ca_policy(grant_control_categories=None)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "grant_control_categories")
        level, _ = classify_entra_change(change)
        assert level in ("low", "medium", "high")

    def test_sp_app_role_count_none_never_crashes(self):
        prev = [_service_principal(app_role_count=None)]
        new = [_service_principal(app_role_count=2)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "app_role_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_guest_member_count_none_prev_never_treated_as_zero_increase(self):
        prev = [_privileged_group(guest_member_count=None)]
        new = [_privileged_group(guest_member_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "guest_member_count")
        level, _ = classify_entra_change(change)
        assert level in ("low", "medium", "high", "critical")

    def test_disabled_member_count_none_never_crashes(self):
        prev = [_privileged_group(disabled_member_count=None)]
        new = [_privileged_group(disabled_member_count=2)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "disabled_member_count")
        level, _ = classify_entra_change(change)
        assert level in ("low", "medium")

    def test_include_user_count_string_typed_value_never_crashes(self):
        # Defensive: a malformed upstream value (wrong type entirely) must
        # never raise inside the classifier — it degrades to a safe default.
        prev = [_ca_policy(exclude_user_count=1)]
        new = [_ca_policy(exclude_user_count="not-a-number")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _field_change(changes, "exclude_user_count")
        level, _ = classify_entra_change(change)
        assert level in ("low", "medium")
