"""Okta privileged identity diff/risk-classification tests (Okta message 5 of 8).

Uses the REAL ``compute_diff()`` and ``classify_okta_change()`` — never
hand-built Change objects standing in for the diff pipeline — to verify
Super Admin addition/removal, high/medium/read-only role changes,
privileged group assignment and membership changes, lifecycle
reactivation, tier changes, provider metadata, and added/removed full
records.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import _tracked_fields_for, compute_diff
from app.services.risk_rules.okta import classify_okta_change


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _admin_role_record(**overrides) -> dict:
    base = {
        "record_type": "okta_admin_role",
        "record_id": "id:t1/admin_role/SUPER_ADMIN",
        "tenant_id": "id:t1",
        "role_id": "SUPER_ADMIN",
        "role_type": "SUPER_ADMIN",
        "role_label": "Super Administrator",
        "built_in": True,
        "custom": False,
        "privilege_tier": "critical",
        "permissions_count": None,
    }
    base.update(overrides)
    return base


def _custom_role_record(**overrides) -> dict:
    base = {
        "record_type": "okta_admin_role",
        "record_id": "id:t1/admin_role/cr1",
        "tenant_id": "id:t1",
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


def _user_assignment_record(**overrides) -> dict:
    base = {
        "record_type": "okta_user_admin_role_assignment",
        "record_id": "id:t1/user_admin_role/u1/SUPER_ADMIN/all",
        "tenant_id": "id:t1",
        "user_id": "u1",
        "user_login": "alice@example.com",
        "user_status": "ACTIVE",
        "role_id": "SUPER_ADMIN",
        "role_type": "SUPER_ADMIN",
        "custom": False,
        "privilege_tier": "critical",
        "direct_assignment": True,
        "assignment_scope_category": "all",
        "active": True,
    }
    base.update(overrides)
    return base


def _group_assignment_record(**overrides) -> dict:
    base = {
        "record_type": "okta_group_admin_role_assignment",
        "record_id": "id:t1/group_admin_role/g1/APP_ADMIN/all",
        "tenant_id": "id:t1",
        "group_id": "g1",
        "group_name": "Admins",
        "group_type": "OKTA_GROUP",
        "role_id": "APP_ADMIN",
        "role_type": "APP_ADMIN",
        "custom": False,
        "privilege_tier": "medium",
        "assignment_scope_category": "all",
        "active": True,
    }
    base.update(overrides)
    return base


def _privileged_identity_record(**overrides) -> dict:
    base = {
        "record_type": "okta_privileged_identity",
        "record_id": "id:t1/privileged_identity/u1",
        "tenant_id": "id:t1",
        "user_id": "u1",
        "login": "alice@example.com",
        "user_status": "ACTIVE",
        "direct_admin_role_count": 1,
        "group_admin_role_count": 0,
        "highest_privilege_tier": "critical",
        "has_super_admin": True,
        "has_high_privilege": True,
        "privileged_via_group": False,
        "privileged_via_direct_assignment": True,
        "custom_admin_role_count": 0,
        "application_admin_scope": None,
        "dormant_privileged_category": "privileged_recent_login",
    }
    base.update(overrides)
    return base


def _privileged_group_record(**overrides) -> dict:
    base = {
        "record_type": "okta_privileged_group",
        "record_id": "id:t1/privileged_group/g1",
        "tenant_id": "id:t1",
        "group_id": "g1",
        "group_name": "Admins",
        "member_count": 10,
        "admin_role_count": 1,
        "highest_privilege_tier": "medium",
        "contains_suspended_members": 0,
        "contains_deprovisioned_members": 0,
    }
    base.update(overrides)
    return base


def _find_field_change(changes: list[dict], field_path: str) -> dict:
    match = [c for c in changes if c["field_path"] == field_path]
    assert match, f"no change found for field_path={field_path!r} in {changes}"
    return match[0]


# ════════════════════════════════════════════════════════════════════════════
# okta_admin_role
# ════════════════════════════════════════════════════════════════════════════


class TestAdminRoleChanges:
    def test_new_high_tier_custom_role_observed_is_medium(self):
        changes = compute_diff(_snap([]), _snap([_custom_role_record(privilege_tier="high")]))
        assert changes[0]["change_type"] == "added"
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "medium"

    def test_new_low_tier_role_observed_is_low(self):
        changes = compute_diff(_snap([]), _snap([_custom_role_record(privilege_tier="read_only")]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_role_removed_is_low(self):
        changes = compute_diff(_snap([_admin_role_record()]), _snap([]))
        assert changes[0]["change_type"] == "removed"
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_custom_role_permission_tier_increased(self):
        prev = [_custom_role_record(privilege_tier="medium")]
        new = [_custom_role_record(privilege_tier="critical")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "privilege_tier")
        level, _ = classify_okta_change(NS(**change))
        assert level == "critical"

    def test_custom_role_permission_tier_decreased(self):
        prev = [_custom_role_record(privilege_tier="critical")]
        new = [_custom_role_record(privilege_tier="medium")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "privilege_tier")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_permissions_count_increase(self):
        prev = [_custom_role_record(permissions_count=2)]
        new = [_custom_role_record(permissions_count=5)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "permissions_count")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"


# ════════════════════════════════════════════════════════════════════════════
# okta_user_admin_role_assignment — Super Admin / tier transitions
# ════════════════════════════════════════════════════════════════════════════


class TestSuperAdminAssignment:
    def test_super_admin_addition_is_critical(self):
        changes = compute_diff(_snap([]), _snap([_user_assignment_record()]))
        assert changes[0]["change_type"] == "added"
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "critical"
        assert "super administrator" in reason.lower()

    def test_super_admin_removal_is_low(self):
        changes = compute_diff(_snap([_user_assignment_record()]), _snap([]))
        assert changes[0]["change_type"] == "removed"
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_high_tier_addition_is_high(self):
        rec = _user_assignment_record(role_id="ORG_ADMIN", role_type="ORG_ADMIN", privilege_tier="high",
                                       record_id="id:t1/user_admin_role/u1/ORG_ADMIN/all")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "high"

    def test_medium_tier_addition_is_medium(self):
        rec = _user_assignment_record(role_id="APP_ADMIN", role_type="APP_ADMIN", privilege_tier="medium",
                                       record_id="id:t1/user_admin_role/u1/APP_ADMIN/all")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "medium"

    def test_read_only_addition_is_low(self):
        rec = _user_assignment_record(role_id="READ_ONLY_ADMIN", role_type="READ_ONLY_ADMIN", privilege_tier="read_only",
                                       record_id="id:t1/user_admin_role/u1/READ_ONLY_ADMIN/all")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_unknown_tier_addition_is_medium_not_safe(self):
        rec = _user_assignment_record(role_id="FUTURE_ROLE", role_type="FUTURE_ROLE", privilege_tier="unknown",
                                       record_id="id:t1/user_admin_role/u1/FUTURE_ROLE/all")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "medium"

    def test_tier_medium_to_high_increase(self):
        prev = [_user_assignment_record(privilege_tier="medium")]
        new = [_user_assignment_record(privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "privilege_tier")
        level, _ = classify_okta_change(NS(**change))
        assert level == "high"

    def test_tier_high_to_medium_decrease(self):
        prev = [_user_assignment_record(privilege_tier="high")]
        new = [_user_assignment_record(privilege_tier="medium")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "privilege_tier")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_role_type_changed_to_super_admin_is_critical(self):
        prev = [_user_assignment_record(role_type="APP_ADMIN")]
        new = [_user_assignment_record(role_type="SUPER_ADMIN")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "role_type")
        level, _ = classify_okta_change(NS(**change))
        assert level == "critical"

    def test_scope_broadened_to_all_for_high_tier_is_high(self):
        prev = [_user_assignment_record(privilege_tier="high", assignment_scope_category="scoped")]
        new = [_user_assignment_record(privilege_tier="high", assignment_scope_category="all")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "assignment_scope_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "high"

    def test_scope_broadened_to_all_for_medium_tier_is_medium(self):
        prev = [_user_assignment_record(privilege_tier="medium", assignment_scope_category="scoped")]
        new = [_user_assignment_record(privilege_tier="medium", assignment_scope_category="all")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "assignment_scope_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_scope_narrowed_is_low(self):
        prev = [_user_assignment_record(assignment_scope_category="all")]
        new = [_user_assignment_record(assignment_scope_category="scoped")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "assignment_scope_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"


class TestPrivilegedLifecycleReactivation:
    def test_suspended_to_active_super_admin_is_critical(self):
        prev = [_user_assignment_record(user_status="SUSPENDED")]
        new = [_user_assignment_record(user_status="ACTIVE")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "user_status")
        level, reason = classify_okta_change(NS(**change))
        assert level == "critical"
        assert "reactivat" in reason.lower()

    def test_deprovisioned_to_active_super_admin_is_critical(self):
        prev = [_user_assignment_record(user_status="DEPROVISIONED")]
        new = [_user_assignment_record(user_status="ACTIVE")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "user_status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "critical"

    def test_locked_to_active_medium_tier_is_medium(self):
        prev = [_user_assignment_record(privilege_tier="medium", user_status="LOCKED_OUT")]
        new = [_user_assignment_record(privilege_tier="medium", user_status="ACTIVE")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "user_status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_active_to_suspended_privileged_is_low(self):
        prev = [_user_assignment_record(user_status="ACTIVE")]
        new = [_user_assignment_record(user_status="SUSPENDED")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "user_status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_active_to_deprovisioned_privileged_is_low(self):
        prev = [_user_assignment_record(user_status="ACTIVE")]
        new = [_user_assignment_record(user_status="DEPROVISIONED")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "user_status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# okta_group_admin_role_assignment
# ════════════════════════════════════════════════════════════════════════════


class TestGroupAdminRoleAssignment:
    def test_group_gains_super_admin_is_critical(self):
        rec = _group_assignment_record(role_id="SUPER_ADMIN", role_type="SUPER_ADMIN", privilege_tier="critical",
                                        record_id="id:t1/group_admin_role/g1/SUPER_ADMIN/all")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "critical"
        assert "super administrator" in reason.lower()

    def test_group_loses_super_admin_is_low(self):
        rec = _group_assignment_record(role_id="SUPER_ADMIN", role_type="SUPER_ADMIN", privilege_tier="critical",
                                        record_id="id:t1/group_admin_role/g1/SUPER_ADMIN/all")
        changes = compute_diff(_snap([rec]), _snap([]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_group_scoped_app_admin_addition_is_medium(self):
        changes = compute_diff(_snap([]), _snap([_group_assignment_record()]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "medium"

    def test_group_role_removed_is_low(self):
        changes = compute_diff(_snap([_group_assignment_record()]), _snap([]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_ordinary_group_role_change_unaffected_by_super_admin_wording(self):
        changes = compute_diff(_snap([]), _snap([_group_assignment_record()]))
        _, reason = classify_okta_change(NS(**changes[0]))
        assert "super administrator" not in reason.lower()


# ════════════════════════════════════════════════════════════════════════════
# okta_privileged_identity
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedIdentityDiff:
    def test_identity_added_super_admin_is_critical(self):
        changes = compute_diff(_snap([]), _snap([_privileged_identity_record()]))
        assert changes[0]["change_type"] == "added"
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "critical"

    def test_identity_removed_is_low(self):
        changes = compute_diff(_snap([_privileged_identity_record()]), _snap([]))
        assert changes[0]["change_type"] == "removed"
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_has_super_admin_gained_is_critical(self):
        prev = [_privileged_identity_record(has_super_admin=False, highest_privilege_tier="medium")]
        new = [_privileged_identity_record(has_super_admin=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "has_super_admin")
        level, reason = classify_okta_change(NS(**change))
        assert level == "critical"
        assert "super administrator" in reason.lower()

    def test_has_super_admin_lost_is_low(self):
        prev = [_privileged_identity_record(has_super_admin=True)]
        new = [_privileged_identity_record(has_super_admin=False, highest_privilege_tier="medium")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "has_super_admin")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_has_high_privilege_gained_is_high(self):
        prev = [_privileged_identity_record(has_high_privilege=False)]
        new = [_privileged_identity_record(has_high_privilege=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "has_high_privilege")
        level, _ = classify_okta_change(NS(**change))
        assert level == "high"

    def test_tier_increase_medium_to_high(self):
        prev = [_privileged_identity_record(highest_privilege_tier="medium")]
        new = [_privileged_identity_record(highest_privilege_tier="high")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "highest_privilege_tier")
        level, _ = classify_okta_change(NS(**change))
        assert level == "high"

    def test_tier_decrease_high_to_medium(self):
        prev = [_privileged_identity_record(highest_privilege_tier="high")]
        new = [_privileged_identity_record(highest_privilege_tier="medium")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "highest_privilege_tier")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_gained_privilege_via_group(self):
        prev = [_privileged_identity_record(privileged_via_group=False)]
        new = [_privileged_identity_record(privileged_via_group=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "privileged_via_group")
        level, _ = classify_okta_change(NS(**change))
        assert level == "critical"  # highest_privilege_tier in fixture is critical

    def test_user_joins_privileged_group_via_added_group_admin_role_count(self):
        prev = [_privileged_identity_record(group_admin_role_count=0)]
        new = [_privileged_identity_record(group_admin_role_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "group_admin_role_count")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_user_leaves_privileged_group(self):
        prev = [_privileged_identity_record(group_admin_role_count=1)]
        new = [_privileged_identity_record(group_admin_role_count=0)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "group_admin_role_count")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_reactivation_of_suspended_privileged_identity(self):
        prev = [_privileged_identity_record(user_status="SUSPENDED")]
        new = [_privileged_identity_record(user_status="ACTIVE")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "user_status")
        level, reason = classify_okta_change(NS(**change))
        assert level == "critical"
        assert "reactivat" in reason.lower()

    def test_privileged_identity_suspended_is_low(self):
        prev = [_privileged_identity_record(user_status="ACTIVE")]
        new = [_privileged_identity_record(user_status="SUSPENDED")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "user_status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_application_admin_scope_broadened(self):
        prev = [_privileged_identity_record(application_admin_scope="scoped")]
        new = [_privileged_identity_record(application_admin_scope="all")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "application_admin_scope")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"


# ════════════════════════════════════════════════════════════════════════════
# okta_privileged_group
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedGroupDiff:
    def test_group_becomes_privileged_is_severity_by_tier(self):
        changes = compute_diff(_snap([]), _snap([_privileged_group_record(highest_privilege_tier="critical")]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "critical"

    def test_group_loses_privilege_is_low(self):
        changes = compute_diff(_snap([_privileged_group_record()]), _snap([]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_group_tier_increased(self):
        prev = [_privileged_group_record(highest_privilege_tier="medium")]
        new = [_privileged_group_record(highest_privilege_tier="critical")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "highest_privilege_tier")
        level, _ = classify_okta_change(NS(**change))
        assert level == "critical"

    def test_membership_grew(self):
        prev = [_privileged_group_record(member_count=5)]
        new = [_privileged_group_record(member_count=50)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "member_count")
        level, reason = classify_okta_change(NS(**change))
        assert level == "medium"
        assert "grew" in reason.lower()

    def test_membership_shrank(self):
        prev = [_privileged_group_record(member_count=50)]
        new = [_privileged_group_record(member_count=5)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "member_count")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_suspended_members_increased(self):
        prev = [_privileged_group_record(contains_suspended_members=0)]
        new = [_privileged_group_record(contains_suspended_members=2)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "contains_suspended_members")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Provider metadata
# ════════════════════════════════════════════════════════════════════════════


class TestProviderMetadata:
    def test_admin_role_provider_metadata(self):
        changes = compute_diff(_snap([]), _snap([_admin_role_record()]))
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "okta_admin_role"
        assert pm["role_id"] == "SUPER_ADMIN"
        assert pm["privilege_tier"] == "critical"

    def test_user_assignment_provider_metadata(self):
        changes = compute_diff(_snap([]), _snap([_user_assignment_record()]))
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "okta_user_admin_role_assignment"
        assert pm["user_id"] == "u1"
        assert pm["role_type"] == "SUPER_ADMIN"

    def test_group_assignment_provider_metadata(self):
        changes = compute_diff(_snap([]), _snap([_group_assignment_record()]))
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "okta_group_admin_role_assignment"
        assert pm["group_name"] == "Admins"

    def test_privileged_identity_provider_metadata(self):
        changes = compute_diff(_snap([]), _snap([_privileged_identity_record()]))
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "okta_privileged_identity"
        assert pm["highest_privilege_tier"] == "critical"

    def test_no_raw_permissions_or_secrets_in_metadata(self):
        changes = compute_diff(_snap([]), _snap([_custom_role_record()]))
        pm = changes[0]["provider_metadata"]
        assert "permissions" not in pm
        assert "api_token" not in pm


# ════════════════════════════════════════════════════════════════════════════
# Ignored fields / untracked
# ════════════════════════════════════════════════════════════════════════════


class TestIgnoredFields:
    def test_user_login_rename_not_tracked_on_assignment(self):
        fields = _tracked_fields_for({"record_type": "okta_user_admin_role_assignment"})
        assert "user_login" not in fields

    def test_collection_completeness_not_tracked(self):
        fields = _tracked_fields_for({"record_type": "okta_admin_role"})
        assert "collection_completeness" not in fields

    def test_last_login_category_not_double_tracked(self):
        fields = _tracked_fields_for({"record_type": "okta_privileged_identity"})
        assert "last_login_category" not in fields
        assert "dormant_privileged_category" in fields

    def test_unmapped_subtype_returns_empty(self):
        fields = _tracked_fields_for({"record_type": "okta_admin_role_totally_unknown_future_subtype"})
        assert fields == ()
