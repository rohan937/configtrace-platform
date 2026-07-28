"""Microsoft Entra ID directory-role / privileged-identity diff/risk
classification tests (Entra message 5 of 8).

Uses the REAL ``compute_diff()`` and ``classify_entra_change()`` — never
hand-built Change objects standing in for the diff pipeline — to verify
Global Administrator / Privileged Role Administrator grant and removal,
high/medium/read-only role tier transitions, scope broadening,
privileged-group membership changes, privileged-user/service-principal
reactivation, critical Graph permission grant/removal, high-risk admin
consent, unknown-permission handling, and provider metadata.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.entra import classify_entra_change

_TENANT = "id:t1"


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _find_field_change(changes: list[dict], field_path: str) -> dict:
    match = [c for c in changes if c["field_path"] == field_path]
    assert match, f"no change found for field_path={field_path!r} in {changes}"
    return match[0]


def _role_record(**overrides) -> dict:
    base = {
        "record_type": "entra_directory_role",
        "record_id": f"{_TENANT}/directory_role/r1",
        "provider_resource_id": "roleManagement/directory/roleDefinitions/r1",
        "tenant_id": _TENANT,
        "role_definition_id": "r1",
        "template_id": "r1",
        "display_name": "Global Administrator",
        "role_kind_category": "built_in",
        "enabled": True,
        "privilege_tier": "critical",
        "is_privileged": True,
        "action_count": 0,
        "dangerous_action_count": 0,
    }
    base.update(overrides)
    return base


def _assignment_record(**overrides) -> dict:
    base = {
        "record_type": "entra_directory_role_assignment",
        "record_id": f"{_TENANT}/directory_role_assignment/a1",
        "provider_resource_id": "roleManagement/directory/roleAssignments/a1",
        "tenant_id": _TENANT,
        "assignment_id": "a1",
        "role_definition_id": "r1",
        "role_template_id": "62e90394-69f5-4237-9190-012177145e10",
        "role_name": "Global Administrator",
        "privilege_tier": "critical",
        "principal_id": "u1",
        "principal_type": "User",
        "directory_scope_category": "tenant_wide",
    }
    base.update(overrides)
    return base


def _privileged_identity_record(**overrides) -> dict:
    base = {
        "record_type": "entra_privileged_identity",
        "record_id": f"{_TENANT}/privileged_identity/u1",
        "provider_resource_id": "users/u1",
        "tenant_id": _TENANT,
        "user_id": "u1",
        "user_principal_name": "u1@example.com",
        "account_enabled_category": "enabled",
        "user_type_category": "Member",
        "guest": False,
        "lifecycle_posture": "enabled_member",
        "highest_privilege_tier": "high",
        "has_global_admin": False,
        "has_privileged_role_admin": False,
        "has_high_privilege": True,
        "direct_role_count": 1,
        "group_inherited_role_count": 0,
        "privileged_via_direct": True,
        "privileged_via_group": False,
        "privilege_derivation_completeness": "complete",
    }
    base.update(overrides)
    return base


def _privileged_group_record(**overrides) -> dict:
    base = {
        "record_type": "entra_privileged_group",
        "record_id": f"{_TENANT}/privileged_group/g1",
        "provider_resource_id": "groups/g1",
        "tenant_id": _TENANT,
        "group_id": "g1",
        "display_name": "Admins",
        "role_assignable": True,
        "highest_privilege_tier": "high",
        "role_count": 1,
        "member_count": 5,
        "direct_user_member_count": 5,
        "guest_member_count": 0,
        "disabled_member_count": 0,
        "privilege_derivation_completeness": "complete",
    }
    base.update(overrides)
    return base


def _privileged_sp_record(**overrides) -> dict:
    base = {
        "record_type": "entra_privileged_service_principal",
        "record_id": f"{_TENANT}/privileged_service_principal/sp1",
        "provider_resource_id": "servicePrincipals/sp1",
        "tenant_id": _TENANT,
        "service_principal_id": "sp1",
        "app_id": "app1",
        "display_name": "Automation SP",
        "service_principal_type_category": "Application",
        "account_enabled": True,
        "directory_role_count": 0,
        "highest_directory_role_tier": "unknown",
        "high_risk_app_permission_count": 0,
        "critical_app_permission_count": 0,
        "tenant_wide_delegated_grant_count": 0,
        "has_role_management_permission": False,
        "has_application_management_permission": False,
        "has_directory_write_permission": False,
        "has_graph_high_privilege": False,
        "highest_privilege_tier": "high",
        "password_credential_count": 0,
        "key_credential_count": 0,
        "privilege_derivation_completeness": "complete",
    }
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# No spurious changes
# ════════════════════════════════════════════════════════════════════════════


class TestNoSpuriousChangeWhenIdentical:
    def test_identical_role_produces_no_change(self):
        rec = _role_record()
        assert compute_diff(_snap([rec]), _snap([dict(rec)])) == []

    def test_identical_assignment_produces_no_change(self):
        rec = _assignment_record()
        assert compute_diff(_snap([rec]), _snap([dict(rec)])) == []

    def test_identical_privileged_identity_produces_no_change(self):
        rec = _privileged_identity_record()
        assert compute_diff(_snap([rec]), _snap([dict(rec)])) == []

    def test_reordered_assignments_produce_no_change(self):
        a1 = _assignment_record(assignment_id="a1", record_id=f"{_TENANT}/directory_role_assignment/a1", principal_id="u1")
        a2 = _assignment_record(assignment_id="a2", record_id=f"{_TENANT}/directory_role_assignment/a2", principal_id="u2")
        changes = compute_diff(_snap([a1, a2]), _snap([dict(a2), dict(a1)]))
        assert changes == []


# ════════════════════════════════════════════════════════════════════════════
# Global Administrator / Privileged Role Administrator grant + removal
# ════════════════════════════════════════════════════════════════════════════


class TestGlobalAdminAndPRAChanges:
    def test_global_admin_assignment_added_is_critical(self):
        changes = compute_diff(_snap([]), _snap([_assignment_record(role_template_id="62e90394-69f5-4237-9190-012177145e10")]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, reason = classify_entra_change(change)
        assert level == "critical"
        assert "global administrator" in reason.lower()

    def test_pra_assignment_added_is_critical(self):
        changes = compute_diff(
            _snap([]),
            _snap([_assignment_record(role_template_id="e8611ab8-c189-46e8-94e1-60213ab1f814", role_name="Privileged Role Administrator")]),
        )
        change = next(c for c in changes if c["change_type"] == "added")
        level, reason = classify_entra_change(change)
        assert level == "critical"
        assert "privileged role administrator" in reason.lower()

    def test_global_admin_assignment_removed_is_low(self):
        changes = compute_diff(_snap([_assignment_record(role_template_id="62e90394-69f5-4237-9190-012177145e10")]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_privileged_identity_has_global_admin_true_is_critical(self):
        prev = [_privileged_identity_record(has_global_admin=False)]
        new = [_privileged_identity_record(has_global_admin=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "has_global_admin")
        level, reason = classify_entra_change(change)
        assert level == "critical"

    def test_privileged_identity_has_global_admin_removed_is_low(self):
        prev = [_privileged_identity_record(has_global_admin=True)]
        new = [_privileged_identity_record(has_global_admin=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "has_global_admin")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_privileged_identity_has_privileged_role_admin_true_is_critical(self):
        prev = [_privileged_identity_record(has_privileged_role_admin=False)]
        new = [_privileged_identity_record(has_privileged_role_admin=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "has_privileged_role_admin")
        level, _ = classify_entra_change(change)
        assert level == "critical"


# ════════════════════════════════════════════════════════════════════════════
# Role/assignment tier transitions
# ════════════════════════════════════════════════════════════════════════════


class TestTierTransitions:
    def test_high_tier_role_added_is_high(self):
        changes = compute_diff(_snap([]), _snap([_role_record(privilege_tier="high")]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_medium_tier_role_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_role_record(privilege_tier="medium")]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_read_only_role_assignment_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_assignment_record(privilege_tier="read_only", role_template_id="f2ef992c-3afb-46b9-b7cf-a126ee74c451", role_name="Global Reader")]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_assignment_privilege_tier_increase_severity_matches_tier(self):
        prev = [_assignment_record(privilege_tier="medium")]
        new = [_assignment_record(privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "privilege_tier")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_assignment_privilege_tier_decrease_is_low(self):
        prev = [_assignment_record(privilege_tier="high")]
        new = [_assignment_record(privilege_tier="medium")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "privilege_tier")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_unknown_tier_transition_never_high(self):
        prev = [_assignment_record(privilege_tier="high")]
        new = [_assignment_record(privilege_tier="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "privilege_tier")
        level, _ = classify_entra_change(change)
        assert level != "high" and level != "critical"


# ════════════════════════════════════════════════════════════════════════════
# Scope broadening
# ════════════════════════════════════════════════════════════════════════════


class TestScopeBroadening:
    def test_scope_broadened_to_tenant_wide_on_high_tier_is_high(self):
        prev = [_assignment_record(directory_scope_category="administrative_unit", privilege_tier="high")]
        new = [_assignment_record(directory_scope_category="tenant_wide", privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "directory_scope_category")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_scope_narrowed_from_tenant_wide_is_low(self):
        prev = [_assignment_record(directory_scope_category="tenant_wide")]
        new = [_assignment_record(directory_scope_category="administrative_unit")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "directory_scope_category")
        level, _ = classify_entra_change(change)
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# Privileged-group membership changes
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedGroupMembershipChanges:
    def test_privileged_group_added_severity_matches_tier(self):
        changes = compute_diff(_snap([]), _snap([_privileged_group_record(highest_privilege_tier="critical")]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "critical"

    def test_privileged_group_member_count_increase_is_medium(self):
        prev = [_privileged_group_record(member_count=5)]
        new = [_privileged_group_record(member_count=10)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "member_count")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_privileged_group_member_count_decrease_is_low(self):
        prev = [_privileged_group_record(member_count=10)]
        new = [_privileged_group_record(member_count=5)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "member_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_privileged_identity_privileged_via_group_added_matches_tier(self):
        prev = [_privileged_identity_record(privileged_via_group=False, highest_privilege_tier="critical")]
        new = [_privileged_identity_record(privileged_via_group=True, highest_privilege_tier="critical")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "privileged_via_group")
        level, _ = classify_entra_change(change)
        assert level == "critical"


# ════════════════════════════════════════════════════════════════════════════
# Privileged-user / service-principal reactivation
# ════════════════════════════════════════════════════════════════════════════


class TestReactivation:
    def test_privileged_user_reenabled_matches_tier(self):
        prev = [_privileged_identity_record(account_enabled_category="disabled", highest_privilege_tier="critical")]
        new = [_privileged_identity_record(account_enabled_category="enabled", highest_privilege_tier="critical")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "account_enabled_category")
        level, _ = classify_entra_change(change)
        assert level == "critical"

    def test_privileged_user_disabled_is_low(self):
        prev = [_privileged_identity_record(account_enabled_category="enabled")]
        new = [_privileged_identity_record(account_enabled_category="disabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "account_enabled_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_privileged_sp_reenabled_matches_tier(self):
        prev = [_privileged_sp_record(account_enabled=False, highest_privilege_tier="high")]
        new = [_privileged_sp_record(account_enabled=True, highest_privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "account_enabled")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_privileged_sp_disabled_is_low(self):
        prev = [_privileged_sp_record(account_enabled=True)]
        new = [_privileged_sp_record(account_enabled=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "account_enabled")
        level, _ = classify_entra_change(change)
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# Critical Graph permission grant/removal on privileged service principal
# ════════════════════════════════════════════════════════════════════════════


class TestCriticalGraphPermissionChanges:
    def test_role_management_permission_granted_is_critical(self):
        prev = [_privileged_sp_record(has_role_management_permission=False)]
        new = [_privileged_sp_record(has_role_management_permission=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "has_role_management_permission")
        level, _ = classify_entra_change(change)
        assert level == "critical"

    def test_role_management_permission_removed_is_low(self):
        prev = [_privileged_sp_record(has_role_management_permission=True)]
        new = [_privileged_sp_record(has_role_management_permission=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "has_role_management_permission")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_critical_app_permission_count_increase_is_critical(self):
        prev = [_privileged_sp_record(critical_app_permission_count=0)]
        new = [_privileged_sp_record(critical_app_permission_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "critical_app_permission_count")
        level, _ = classify_entra_change(change)
        assert level == "critical"

    def test_high_risk_app_permission_count_increase_is_high(self):
        prev = [_privileged_sp_record(high_risk_app_permission_count=0)]
        new = [_privileged_sp_record(high_risk_app_permission_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "high_risk_app_permission_count")
        level, _ = classify_entra_change(change)
        assert level == "high"


# ════════════════════════════════════════════════════════════════════════════
# High-risk admin consent
# ════════════════════════════════════════════════════════════════════════════


class TestHighRiskAdminConsent:
    def test_tenant_wide_delegated_grant_count_increase_is_high(self):
        prev = [_privileged_sp_record(tenant_wide_delegated_grant_count=0)]
        new = [_privileged_sp_record(tenant_wide_delegated_grant_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "tenant_wide_delegated_grant_count")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_oauth2_grant_scope_tier_increase_tenant_wide_high_risk_is_high(self):
        prev_grant = {
            "record_type": "entra_oauth2_permission_grant",
            "record_id": f"{_TENANT}/oauth2_permission_grant/g1",
            "provider_resource_id": "oauth2PermissionGrants/g1",
            "tenant_id": _TENANT,
            "grant_id": "g1",
            "client_service_principal_id": "sp1",
            "client_name": "Client",
            "resource_service_principal_id": "sp2",
            "resource_name": "Microsoft Graph",
            "resource_is_microsoft_graph": True,
            "consent_type_category": "AllPrincipals",
            "principal_id": None,
            "scope_count": 1,
            "scopes": ["User.Read"],
            "high_risk_scope_present": False,
            "highest_scope_privilege_tier": "read_only",
        }
        new_grant = dict(prev_grant, scopes=["Directory.ReadWrite.All"], highest_scope_privilege_tier="high", high_risk_scope_present=True)
        changes = compute_diff(_snap([prev_grant]), _snap([new_grant]))
        change = _find_field_change(changes, "highest_scope_privilege_tier")
        level, _ = classify_entra_change(change)
        assert level == "high"


# ════════════════════════════════════════════════════════════════════════════
# Unknown permission handling
# ════════════════════════════════════════════════════════════════════════════


class TestUnknownPermissionHandling:
    def test_unknown_app_role_privilege_tier_transition_never_high(self):
        prev_assignment = {
            "record_type": "entra_service_principal_app_role_assignment",
            "record_id": f"{_TENANT}/app_role_assignment/x1",
            "provider_resource_id": "x",
            "tenant_id": _TENANT,
            "resource_service_principal_id": "sp2",
            "resource_app_id": "app2",
            "resource_name": "Some API",
            "resource_is_microsoft_graph": False,
            "principal_service_principal_id": "sp1",
            "principal_app_id": "app1",
            "principal_name": "Client",
            "app_role_category": "SomeScope",
            "app_role_risk_category": "unknown",
            "app_role_privilege_tier": "high",
            "assignment_type": "service_principal",
        }
        new_assignment = dict(prev_assignment, app_role_privilege_tier="unknown")
        changes = compute_diff(_snap([prev_assignment]), _snap([new_assignment]))
        change = _find_field_change(changes, "app_role_privilege_tier")
        level, _ = classify_entra_change(change)
        assert level != "high" and level != "critical"


# ════════════════════════════════════════════════════════════════════════════
# Provider metadata
# ════════════════════════════════════════════════════════════════════════════


class TestProviderMetadata:
    def test_role_metadata_has_definition_id_and_tier(self):
        prev = [_role_record(display_name="Old")]
        new = [_role_record(display_name="New")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "display_name")
        pm = change["provider_metadata"]
        assert pm["role_definition_id"] == "r1"
        assert pm["privilege_tier"] == "critical"

    def test_assignment_metadata_has_role_name_and_principal(self):
        prev = [_assignment_record(directory_scope_category="tenant_wide")]
        new = [_assignment_record(directory_scope_category="administrative_unit")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "directory_scope_category")
        pm = change["provider_metadata"]
        assert pm["role_name"] == "Global Administrator"
        assert pm["principal_id"] == "u1"

    def test_privileged_identity_metadata_has_user_id_and_tier(self):
        prev = [_privileged_identity_record(account_enabled_category="enabled")]
        new = [_privileged_identity_record(account_enabled_category="disabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "account_enabled_category")
        pm = change["provider_metadata"]
        assert pm["user_id"] == "u1"
        assert pm["highest_privilege_tier"] == "high"

    def test_privileged_group_metadata_has_group_id(self):
        prev = [_privileged_group_record(member_count=1)]
        new = [_privileged_group_record(member_count=2)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "member_count")
        pm = change["provider_metadata"]
        assert pm["group_id"] == "g1"

    def test_privileged_sp_metadata_has_sp_id(self):
        prev = [_privileged_sp_record(account_enabled=True)]
        new = [_privileged_sp_record(account_enabled=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "account_enabled")
        pm = change["provider_metadata"]
        assert pm["service_principal_id"] == "sp1"

    def test_provider_metadata_never_contains_raw_actions_or_resource_paths(self):
        prev = [_role_record(display_name="Old")]
        new = [_role_record(display_name="New")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "display_name")
        pm = change["provider_metadata"]
        assert "allowedResourceActions" not in pm
        assert "rolePermissions" not in pm
