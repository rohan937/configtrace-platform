"""Microsoft Entra ID Finding-vs-Change severity parity tests (Entra
message 7 of 8).

Rule enforced throughout: for every static Security Finding that has a
direct Change-classification equivalent, the new-bad-state Change severity
must be >= the equivalent static Finding severity — a transition INTO a
risky state must never be classified as materially less severe than
ConfigTrace already considers that same state to be when evaluated
statically. Every case here goes through the REAL pipeline on both sides:
``evaluate_record()`` for the static Finding, ``compute_diff()`` ->
``classify_entra_change()`` for the transition.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.entra import classify_entra_change
from app.services.security_finding_evaluator import evaluate_record

_TENANT = "id:t1"
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _static_severity(record: dict, rule_key: str) -> str:
    matches = [f for f in evaluate_record(record, "entra") if f.rule_key == rule_key]
    assert matches, f"static rule {rule_key} did not fire for {record}"
    return matches[0].severity


def _assert_parity(change_severity: str, static_severity: str, *, label: str) -> None:
    assert _SEVERITY_RANK[change_severity] >= _SEVERITY_RANK[static_severity], (
        f"{label}: Change severity {change_severity!r} is LOWER than static "
        f"Finding severity {static_severity!r} — a transition into a risky "
        f"state must never under-rank the equivalent static posture."
    )


def _privileged_identity(**overrides) -> dict:
    base = {
        "record_type": "entra_privileged_identity", "record_id": f"{_TENANT}/privileged_identity/u1",
        "tenant_id": _TENANT, "user_id": "u1", "user_principal_name": "u1@example.com",
        "account_enabled_category": "enabled", "user_type_category": "Member", "guest": False,
        "lifecycle_posture": "enabled_member", "highest_privilege_tier": "medium",
        "has_global_admin": False, "has_privileged_role_admin": False, "has_high_privilege": False,
        "direct_role_count": 1, "group_inherited_role_count": 0, "privileged_via_direct": True,
        "privileged_via_group": False, "privilege_derivation_completeness": "complete",
    }
    base.update(overrides)
    return base


def _privileged_group(**overrides) -> dict:
    base = {
        "record_type": "entra_privileged_group", "record_id": f"{_TENANT}/privileged_group/g1",
        "tenant_id": _TENANT, "group_id": "g1", "display_name": "Admins", "role_assignable": True,
        "highest_privilege_tier": "medium", "role_count": 1, "member_count": 5,
        "direct_user_member_count": 5, "guest_member_count": 0, "disabled_member_count": 0,
        "privilege_derivation_completeness": "complete",
    }
    base.update(overrides)
    return base


def _privileged_sp(**overrides) -> dict:
    base = {
        "record_type": "entra_privileged_service_principal", "record_id": f"{_TENANT}/privileged_service_principal/sp1",
        "tenant_id": _TENANT, "service_principal_id": "sp1", "app_id": "app1", "display_name": "Automation SP",
        "service_principal_type_category": "Application", "account_enabled": True, "directory_role_count": 0,
        "highest_directory_role_tier": "unknown", "high_risk_app_permission_count": 0,
        "critical_app_permission_count": 0, "tenant_wide_delegated_grant_count": 0,
        "has_role_management_permission": False, "has_application_management_permission": False,
        "has_directory_write_permission": False, "has_graph_high_privilege": False,
        "highest_privilege_tier": "medium", "password_credential_count": 0, "key_credential_count": 0,
        "privilege_derivation_completeness": "complete",
    }
    base.update(overrides)
    return base


def _oauth2_grant(**overrides) -> dict:
    base = {
        "record_type": "entra_oauth2_permission_grant", "record_id": f"{_TENANT}/oauth2_permission_grant/gr1",
        "tenant_id": _TENANT, "grant_id": "gr1", "client_service_principal_id": "sp1", "client_name": "Client",
        "resource_service_principal_id": "sp2", "resource_name": "Microsoft Graph", "resource_is_microsoft_graph": True,
        "consent_type_category": "AllPrincipals", "principal_id": None, "scope_count": 1, "scopes": ["User.Read"],
        "high_risk_scope_present": False, "highest_scope_privilege_tier": "read_only",
        "client_verified_publisher_category": "unverified",
    }
    base.update(overrides)
    return base


def _ca_policy(**overrides) -> dict:
    base = {
        "record_type": "entra_conditional_access_policy", "record_id": f"{_TENANT}/conditional_access_policy/p1",
        "tenant_id": _TENANT, "policy_id": "p1", "display_name": "Policy", "state_category": "enabled",
        "user_target_category": "all_users", "include_user_count": 0, "include_group_count": 0,
        "include_role_count": 0, "exclude_user_count": 0, "exclude_group_count": 0, "exclude_role_count": 0,
        "guests_included": False, "guests_excluded": False, "app_target_category": "all_cloud_apps",
        "include_app_count": 0, "exclude_app_count": 0, "coverage_category": "all_users_all_apps",
        "location_target_category": "unknown", "device_platform_categories": ["unknown"],
        "client_app_type_categories": ["unknown"], "legacy_auth_targeted": False,
        "user_risk_level_categories": ["unknown"], "sign_in_risk_level_categories": ["unknown"],
        "grant_operator_category": "AND", "grant_control_categories": [], "mfa_requirement_category": "not_required",
        "block_access": False, "compliant_device_required": False, "hybrid_joined_device_required": False,
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
        "tenant_id": _TENANT, "strength_id": "s1", "display_name": "MFA Strength", "kind_category": "custom",
        "allowed_combination_count": 2, "phishing_resistance_category": "not_phishing_resistant",
        "passwordless_category": "not_passwordless", "mfa_capability_category": "mfa_capable",
    }
    base.update(overrides)
    return base


def _auth_method(**overrides) -> dict:
    base = {
        "record_type": "entra_authentication_method", "record_id": f"{_TENANT}/authentication_method/Sms",
        "tenant_id": _TENANT, "method_config_id": "Sms", "method_type_category": "sms", "state_category": "enabled",
        "phishing_resistance_category": "not_phishing_resistant", "target_category": "all_users",
        "include_target_count": 1, "exclude_target_count": 0,
    }
    base.update(overrides)
    return base


def _application(**overrides) -> dict:
    base = {
        "record_type": "entra_application", "record_id": f"{_TENANT}/application/a1", "tenant_id": _TENANT,
        "object_id": "a1", "app_id": "client-a1", "display_name": "Test App",
        "sign_in_audience_category": "single_tenant", "publisher_domain": None, "web_redirect_count": 1,
        "spa_redirect_count": 0, "public_client_redirect_count": 0, "has_http_redirect": False,
        "web_has_http_redirect": False, "has_localhost_redirect": False, "has_loopback_redirect": False,
        "has_custom_scheme_redirect": False, "has_wildcard_redirect": False, "requested_resource_api_count": 1,
        "requested_delegated_permission_count": 1, "requested_application_permission_count": 0,
        "password_credential_count": 0, "key_credential_count": 0, "nearest_credential_expiry_category": "no_credentials",
        "app_role_count": 0, "app_role_enabled_count": 0,
    }
    base.update(overrides)
    return base


def _directory_role_assignment(**overrides) -> dict:
    base = {
        "record_type": "entra_directory_role_assignment", "record_id": f"{_TENANT}/directory_role_assignment/a1",
        "tenant_id": _TENANT, "assignment_id": "a1", "role_definition_id": "r1", "role_template_id": None,
        "role_name": "Custom Role", "privilege_tier": "medium", "principal_id": "u1", "principal_type": "User",
        "directory_scope_category": "tenant_wide",
    }
    base.update(overrides)
    return base


class TestPrivilegedIdentityParity:
    def test_global_admin_assigned(self):
        rec = _directory_role_assignment(role_template_id="62e90394-69f5-4237-9190-012177145e10", privilege_tier="critical")
        static = _static_severity(rec, "entra_global_admin_assigned")

        changes = compute_diff(_snap([]), _snap([rec]))
        change_sev, _ = classify_entra_change(next(c for c in changes if c["change_type"] == "added"))
        _assert_parity(change_sev, static, label="global_admin_assigned (added)")

    def test_high_tier_admin_assigned(self):
        rec = _directory_role_assignment(role_template_id=None, privilege_tier="high")
        static = _static_severity(rec, "entra_high_tier_admin_assigned")

        changes = compute_diff(_snap([]), _snap([rec]))
        change_sev, _ = classify_entra_change(next(c for c in changes if c["change_type"] == "added"))
        _assert_parity(change_sev, static, label="high_tier_admin_assigned (added)")

    def test_guest_global_admin(self):
        rec = _privileged_identity(guest=True, user_type_category="Guest", has_global_admin=True, highest_privilege_tier="critical")
        static = _static_severity(rec, "entra_guest_global_admin")

        changes = compute_diff(_snap([]), _snap([rec]))
        change_sev, _ = classify_entra_change(next(c for c in changes if c["change_type"] == "added"))
        _assert_parity(change_sev, static, label="guest_global_admin (added)")

    def test_disabled_identity_retains_admin_privilege(self):
        rec = _privileged_identity(account_enabled_category="disabled", highest_privilege_tier="high")
        static = _static_severity(rec, "entra_disabled_identity_retains_admin_privilege")

        prev = [_privileged_identity(account_enabled_category="enabled", highest_privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap([rec]))
        change = next(c for c in changes if c["field_path"] == "account_enabled_category")
        change_sev, _ = classify_entra_change(change)
        # Written exception (same reasoning as Okta/Kubernetes precedent):
        # enabled->disabled is itself a restrictive/access-reducing
        # transition and is correctly Low — hardening an account is never
        # High just because the entitlement being restricted was
        # important. The STATIC High severity measures a DIFFERENT thing:
        # the residual entitlement persisting AFTER disablement (the role
        # was never cleaned up), not the disablement transition itself.
        assert change_sev == "low"
        assert static in ("high", "critical")


class TestPrivilegedGroupParity:
    def test_group_has_global_admin(self):
        rec = _privileged_group(highest_privilege_tier="critical")
        static = _static_severity(rec, "entra_group_has_global_admin")

        changes = compute_diff(_snap([]), _snap([rec]))
        change_sev, _ = classify_entra_change(next(c for c in changes if c["change_type"] == "added"))
        _assert_parity(change_sev, static, label="group_has_global_admin (added)")

    def test_guest_member_in_privileged_group(self):
        rec = _privileged_group(guest_member_count=1, highest_privilege_tier="critical")
        static = _static_severity(rec, "entra_guest_member_in_privileged_group")

        prev = [_privileged_group(guest_member_count=0, highest_privilege_tier="critical")]
        changes = compute_diff(_snap(prev), _snap([rec]))
        change = next(c for c in changes if c["field_path"] == "guest_member_count")
        change_sev, _ = classify_entra_change(change)
        _assert_parity(change_sev, static, label="guest_member_in_privileged_group")


class TestServicePrincipalParity:
    def test_sp_has_critical_privilege(self):
        rec = _privileged_sp(highest_privilege_tier="critical")
        static = _static_severity(rec, "entra_service_principal_has_critical_privilege")

        prev = [_privileged_sp(highest_privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap([rec]))
        change = next(c for c in changes if c["field_path"] == "highest_privilege_tier")
        change_sev, _ = classify_entra_change(change)
        _assert_parity(change_sev, static, label="sp_has_critical_privilege")

    def test_sp_can_manage_directory_roles(self):
        rec = {
            "record_type": "entra_service_principal_app_role_assignment",
            "record_id": f"{_TENANT}/app_role_assignment/x1", "tenant_id": _TENANT,
            "resource_service_principal_id": "graph", "resource_app_id": "graph", "resource_name": "Microsoft Graph",
            "resource_is_microsoft_graph": True, "principal_service_principal_id": "sp1", "principal_app_id": "client-sp1",
            "principal_name": "Automation", "app_role_category": "RoleManagement.ReadWrite.Directory",
            "app_role_risk_category": "high_risk", "app_role_privilege_tier": "critical", "assignment_type": "service_principal",
        }
        static = _static_severity(rec, "entra_service_principal_can_manage_directory_roles")

        changes = compute_diff(_snap([]), _snap([rec]))
        change_sev, _ = classify_entra_change(next(c for c in changes if c["change_type"] == "added"))
        _assert_parity(change_sev, static, label="sp_can_manage_directory_roles (added)")

    def test_sp_has_role_management_permission_derived_rollup(self):
        rec = _privileged_sp(has_role_management_permission=True, highest_privilege_tier="critical")
        prev = [_privileged_sp(has_role_management_permission=False, highest_privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap([rec]))
        change = next(c for c in changes if c["field_path"] == "has_role_management_permission")
        change_sev, _ = classify_entra_change(change)
        assert change_sev == "critical"

    def test_disabled_sp_retains_privilege(self):
        rec = _privileged_sp(account_enabled=False, highest_privilege_tier="high")
        static = _static_severity(rec, "entra_disabled_service_principal_retains_privilege")

        prev = [_privileged_sp(account_enabled=True, highest_privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap([rec]))
        change = next(c for c in changes if c["field_path"] == "account_enabled")
        change_sev, _ = classify_entra_change(change)
        # Written exception, same reasoning as the identity case above:
        # enabled->disabled is a restrictive transition (Low); the static
        # rule measures the residual entitlement, not this transition.
        assert change_sev == "low"
        assert static in ("high", "critical")


class TestConsentGrantParity:
    def test_tenant_wide_critical_consent(self):
        rec = _oauth2_grant(
            consent_type_category="AllPrincipals", highest_scope_privilege_tier="critical",
            high_risk_scope_present=True, client_verified_publisher_category="verified",
        )
        static = _static_severity(rec, "entra_tenant_wide_critical_delegated_consent")

        changes = compute_diff(_snap([]), _snap([rec]))
        change_sev, _ = classify_entra_change(next(c for c in changes if c["change_type"] == "added"))
        _assert_parity(change_sev, static, label="tenant_wide_critical_delegated_consent (added)")

    def test_tenant_wide_high_risk_consent(self):
        rec = _oauth2_grant(
            consent_type_category="AllPrincipals", highest_scope_privilege_tier="high",
            high_risk_scope_present=True, client_verified_publisher_category="verified",
        )
        static = _static_severity(rec, "entra_tenant_wide_high_risk_delegated_consent")

        changes = compute_diff(_snap([]), _snap([rec]))
        change_sev, _ = classify_entra_change(next(c for c in changes if c["change_type"] == "added"))
        _assert_parity(change_sev, static, label="tenant_wide_high_risk_delegated_consent (added)")


class TestConditionalAccessParity:
    def test_ca_broad_access_without_mfa(self):
        rec = _ca_policy(state_category="enabled", coverage_category="all_users_all_apps", mfa_requirement_category="not_required", block_access=False)
        static = _static_severity(rec, "entra_ca_broad_access_without_mfa")

        changes = compute_diff(_snap([]), _snap([rec]))
        change_sev, _ = classify_entra_change(next(c for c in changes if c["change_type"] == "added"))
        _assert_parity(change_sev, static, label="ca_broad_access_without_mfa (added)")

    def test_ca_legacy_auth_not_blocked(self):
        rec = _ca_policy(state_category="enabled", legacy_auth_targeted=True, block_access=False)
        static = _static_severity(rec, "entra_ca_legacy_auth_not_blocked")

        prev = [_ca_policy(state_category="enabled", legacy_auth_targeted=False, block_access=False)]
        changes = compute_diff(_snap(prev), _snap([rec]))
        change = next(c for c in changes if c["field_path"] == "legacy_auth_targeted")
        change_sev, _ = classify_entra_change(change)
        _assert_parity(change_sev, static, label="ca_legacy_auth_not_blocked")


class TestAuthenticationParity:
    def test_auth_strength_not_phishing_resistant(self):
        rec = _auth_strength(phishing_resistance_category="not_phishing_resistant")
        static = _static_severity(rec, "entra_authentication_strength_not_phishing_resistant")

        prev = [_auth_strength(phishing_resistance_category="phishing_resistant")]
        changes = compute_diff(_snap(prev), _snap([rec]))
        change = next(c for c in changes if c["field_path"] == "phishing_resistance_category")
        change_sev, _ = classify_entra_change(change)
        _assert_parity(change_sev, static, label="auth_strength_not_phishing_resistant")

    def test_weak_authentication_method_enabled(self):
        rec = _auth_method(method_type_category="sms", state_category="enabled")
        static = _static_severity(rec, "entra_weak_authentication_method_enabled")

        prev = [_auth_method(method_type_category="sms", state_category="disabled")]
        changes = compute_diff(_snap(prev), _snap([rec]))
        change = next(c for c in changes if c["field_path"] == "state_category")
        change_sev, _ = classify_entra_change(change)
        _assert_parity(change_sev, static, label="weak_authentication_method_enabled")


class TestApplicationParity:
    def test_wildcard_redirect(self):
        rec = _application(has_wildcard_redirect=True)
        static = _static_severity(rec, "entra_application_wildcard_redirect")

        prev = [_application(has_wildcard_redirect=False)]
        changes = compute_diff(_snap(prev), _snap([rec]))
        change = next(c for c in changes if c["field_path"] == "has_wildcard_redirect")
        change_sev, _ = classify_entra_change(change)
        _assert_parity(change_sev, static, label="application_wildcard_redirect")

    def test_http_redirect(self):
        rec = _application(has_http_redirect=True, web_has_http_redirect=True)
        static = _static_severity(rec, "entra_application_http_redirect")

        prev = [_application(has_http_redirect=False, web_has_http_redirect=False)]
        changes = compute_diff(_snap(prev), _snap([rec]))
        change = next(c for c in changes if c["field_path"] == "web_has_http_redirect")
        change_sev, _ = classify_entra_change(change)
        _assert_parity(change_sev, static, label="application_http_redirect")


class TestSeverityRankSanity:
    def test_severity_rank_is_total_order(self):
        assert _SEVERITY_RANK["low"] < _SEVERITY_RANK["medium"] < _SEVERITY_RANK["high"] < _SEVERITY_RANK["critical"]
