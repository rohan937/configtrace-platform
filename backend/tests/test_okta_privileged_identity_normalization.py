"""Okta privileged identity normalization tests (Okta message 5 of 8).

Covers ``OktaConnector._normalize_builtin_admin_role`` /
``_normalize_custom_admin_role`` / ``_parse_role_assignment`` /
``_normalize_user_admin_role_assignment`` /
``_normalize_group_admin_role_assignment`` /
``_derive_privileged_identities`` / ``_derive_privileged_groups`` in
isolation: every built-in role type, privilege tier mapping, custom-role
permission-derived tiering, assignment scope, lifecycle combinations, and
the sensitive-data exclusion boundary.
"""

from __future__ import annotations

import pytest

from app.connectors.okta import OktaConnector
from app.connectors.okta_schema import (
    ASSIGNMENT_SCOPE_ALL,
    ASSIGNMENT_SCOPE_SCOPED,
    ASSIGNMENT_SCOPE_UNKNOWN,
    PRIVILEGE_TIER_CRITICAL,
    PRIVILEGE_TIER_HIGH,
    PRIVILEGE_TIER_MEDIUM,
    PRIVILEGE_TIER_READ_ONLY,
    PRIVILEGE_TIER_UNKNOWN,
    ROLE_TYPE_API_ACCESS_MANAGEMENT_ADMIN,
    ROLE_TYPE_APP_ADMIN,
    ROLE_TYPE_GROUP_ADMIN,
    ROLE_TYPE_HELP_DESK_ADMIN,
    ROLE_TYPE_MOBILE_ADMIN,
    ROLE_TYPE_ORG_ADMIN,
    ROLE_TYPE_READ_ONLY_ADMIN,
    ROLE_TYPE_REPORT_ADMIN,
    ROLE_TYPE_SUPER_ADMIN,
    ROLE_TYPE_UNKNOWN,
    ROLE_TYPE_USER_ADMIN,
    categorize_dormant_privileged,
    categorize_permission,
    categorize_role_type,
    highest_privilege_tier,
    privilege_tier_for_permissions,
    privilege_tier_for_role_type,
)

_TENANT = "id:t1"


def _user_record(**overrides) -> dict:
    base = {
        "user_id": "u1", "login": "alice@example.com", "status": "ACTIVE",
        "last_login_category": "recent",
    }
    base.update(overrides)
    return base


def _group_record(**overrides) -> dict:
    base = {"group_id": "g1", "group_name": "Admins", "group_type": "OKTA_GROUP", "membership_count": 3}
    base.update(overrides)
    return base


def _admin_role(**overrides) -> dict:
    base = {
        "record_type": "okta_admin_role", "role_id": "SUPER_ADMIN", "role_type": "SUPER_ADMIN",
        "role_label": "Super Administrator", "built_in": True, "custom": False,
        "privilege_tier": "critical", "permissions_count": None,
    }
    base.update(overrides)
    return base


def _parsed_assignment(**overrides) -> dict:
    base = {
        "assignment_id": "ra1", "label": "Super Administrator", "role_type": "SUPER_ADMIN",
        "status": "ACTIVE", "active": True, "custom_role_id": None, "resource_set_id": None,
        "scope_category": "unknown",
    }
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# Built-in role type taxonomy
# ════════════════════════════════════════════════════════════════════════════


class TestRoleTypeTaxonomy:
    @pytest.mark.parametrize("raw_type,expected", [
        ("SUPER_ADMIN", ROLE_TYPE_SUPER_ADMIN),
        ("ORG_ADMIN", ROLE_TYPE_ORG_ADMIN),
        ("APP_ADMIN", ROLE_TYPE_APP_ADMIN),
        ("USER_ADMIN", ROLE_TYPE_USER_ADMIN),
        ("GROUP_ADMIN", ROLE_TYPE_GROUP_ADMIN),
        ("HELP_DESK_ADMIN", ROLE_TYPE_HELP_DESK_ADMIN),
        ("READ_ONLY_ADMIN", ROLE_TYPE_READ_ONLY_ADMIN),
        ("MOBILE_ADMIN", ROLE_TYPE_MOBILE_ADMIN),
        ("API_ACCESS_MANAGEMENT_ADMIN", ROLE_TYPE_API_ACCESS_MANAGEMENT_ADMIN),
        ("REPORT_ADMIN", ROLE_TYPE_REPORT_ADMIN),
        ("CUSTOM", "CUSTOM"),
    ])
    def test_every_known_type(self, raw_type, expected):
        assert categorize_role_type(raw_type) == expected

    def test_unknown_role_type(self):
        assert categorize_role_type("SOME_FUTURE_ROLE") == ROLE_TYPE_UNKNOWN

    def test_none_role_type(self):
        assert categorize_role_type(None) == ROLE_TYPE_UNKNOWN

    def test_unknown_never_inferred_from_label(self):
        # A role's display label must never influence its type category.
        assert categorize_role_type("Super Administrator") == ROLE_TYPE_UNKNOWN


# ════════════════════════════════════════════════════════════════════════════
# Privilege tier mapping (built-in)
# ════════════════════════════════════════════════════════════════════════════


class TestBuiltInPrivilegeTier:
    def test_super_admin_is_critical(self):
        assert privilege_tier_for_role_type(ROLE_TYPE_SUPER_ADMIN) == PRIVILEGE_TIER_CRITICAL

    def test_org_admin_is_high(self):
        assert privilege_tier_for_role_type(ROLE_TYPE_ORG_ADMIN) == PRIVILEGE_TIER_HIGH

    def test_api_access_management_admin_is_high(self):
        assert privilege_tier_for_role_type(ROLE_TYPE_API_ACCESS_MANAGEMENT_ADMIN) == PRIVILEGE_TIER_HIGH

    def test_app_admin_is_medium(self):
        assert privilege_tier_for_role_type(ROLE_TYPE_APP_ADMIN) == PRIVILEGE_TIER_MEDIUM

    def test_user_admin_is_medium(self):
        assert privilege_tier_for_role_type(ROLE_TYPE_USER_ADMIN) == PRIVILEGE_TIER_MEDIUM

    def test_group_admin_is_medium(self):
        assert privilege_tier_for_role_type(ROLE_TYPE_GROUP_ADMIN) == PRIVILEGE_TIER_MEDIUM

    def test_mobile_admin_is_medium(self):
        assert privilege_tier_for_role_type(ROLE_TYPE_MOBILE_ADMIN) == PRIVILEGE_TIER_MEDIUM

    def test_help_desk_admin_is_medium_not_read_only(self):
        # Help Desk can reset passwords/unlock accounts — real
        # credential-reset capability, materially more than read-only.
        assert privilege_tier_for_role_type(ROLE_TYPE_HELP_DESK_ADMIN) == PRIVILEGE_TIER_MEDIUM

    def test_read_only_admin_is_read_only(self):
        assert privilege_tier_for_role_type(ROLE_TYPE_READ_ONLY_ADMIN) == PRIVILEGE_TIER_READ_ONLY

    def test_report_admin_is_read_only(self):
        assert privilege_tier_for_role_type(ROLE_TYPE_REPORT_ADMIN) == PRIVILEGE_TIER_READ_ONLY

    def test_read_only_admin_never_write_capable(self):
        assert privilege_tier_for_role_type(ROLE_TYPE_READ_ONLY_ADMIN) != PRIVILEGE_TIER_MEDIUM
        assert privilege_tier_for_role_type(ROLE_TYPE_READ_ONLY_ADMIN) != PRIVILEGE_TIER_CRITICAL

    def test_unknown_role_type_is_unknown_tier(self):
        assert privilege_tier_for_role_type(ROLE_TYPE_UNKNOWN) == PRIVILEGE_TIER_UNKNOWN

    def test_custom_role_type_via_this_function_is_unknown(self):
        # A custom role's tier comes from privilege_tier_for_permissions(),
        # never from this built-in-only mapping.
        assert privilege_tier_for_role_type("CUSTOM") == PRIVILEGE_TIER_UNKNOWN


class TestHighestPrivilegeTier:
    def test_known_tier_outranks_unknown(self):
        assert highest_privilege_tier([PRIVILEGE_TIER_HIGH, PRIVILEGE_TIER_UNKNOWN]) == PRIVILEGE_TIER_HIGH

    def test_critical_outranks_everything(self):
        assert highest_privilege_tier([PRIVILEGE_TIER_CRITICAL, PRIVILEGE_TIER_HIGH]) == PRIVILEGE_TIER_CRITICAL

    def test_empty_list_is_unknown(self):
        assert highest_privilege_tier([]) == PRIVILEGE_TIER_UNKNOWN

    def test_all_unknown_stays_unknown(self):
        assert highest_privilege_tier([PRIVILEGE_TIER_UNKNOWN, PRIVILEGE_TIER_UNKNOWN]) == PRIVILEGE_TIER_UNKNOWN


# ════════════════════════════════════════════════════════════════════════════
# Custom-role permission-derived tier
# ════════════════════════════════════════════════════════════════════════════


class TestPermissionCategorization:
    def test_admin_management_permission(self):
        assert categorize_permission("okta.roles.manage") == "administrator_management"

    def test_credential_reset_permission(self):
        assert categorize_permission("okta.users.credentials.manage") == "credential_reset"

    def test_read_only_permission(self):
        assert categorize_permission("okta.users.read") == "read_only"

    def test_unknown_permission_never_guessed(self):
        assert categorize_permission("okta.some.future.permission") == "unknown"

    def test_none_permission(self):
        assert categorize_permission(None) == "unknown"


class TestCustomRolePrivilegeTier:
    def test_admin_management_is_critical(self):
        assert privilege_tier_for_permissions(["okta.roles.manage"]) == PRIVILEGE_TIER_CRITICAL

    def test_policy_management_is_high(self):
        assert privilege_tier_for_permissions(["okta.policies.manage"]) == PRIVILEGE_TIER_HIGH

    def test_api_access_management_is_high(self):
        assert privilege_tier_for_permissions(["okta.authzServers.manage"]) == PRIVILEGE_TIER_HIGH

    def test_user_management_is_medium(self):
        assert privilege_tier_for_permissions(["okta.users.manage"]) == PRIVILEGE_TIER_MEDIUM

    def test_group_management_is_medium(self):
        assert privilege_tier_for_permissions(["okta.groups.manage"]) == PRIVILEGE_TIER_MEDIUM

    def test_read_only_permissions_is_read_only(self):
        assert privilege_tier_for_permissions(["okta.users.read", "okta.groups.read"]) == PRIVILEGE_TIER_READ_ONLY

    def test_highest_of_multiple_permissions_wins(self):
        assert privilege_tier_for_permissions(["okta.users.read", "okta.roles.manage"]) == PRIVILEGE_TIER_CRITICAL

    def test_empty_permissions_is_unknown_not_safe(self):
        assert privilege_tier_for_permissions([]) == PRIVILEGE_TIER_UNKNOWN

    def test_none_permissions_is_unknown(self):
        assert privilege_tier_for_permissions(None) == PRIVILEGE_TIER_UNKNOWN

    def test_all_unrecognized_permissions_is_unknown_not_low(self):
        assert privilege_tier_for_permissions(["okta.future.thing", "okta.other.thing"]) == PRIVILEGE_TIER_UNKNOWN

    def test_mixed_known_and_unknown_uses_known(self):
        assert privilege_tier_for_permissions(["okta.future.thing", "okta.roles.manage"]) == PRIVILEGE_TIER_CRITICAL


# ════════════════════════════════════════════════════════════════════════════
# okta_admin_role normalization
# ════════════════════════════════════════════════════════════════════════════


class TestAdminRoleNormalization:
    def test_builtin_role_record(self):
        rec = OktaConnector._normalize_builtin_admin_role(_TENANT, "SUPER_ADMIN", "Super Administrator")
        assert rec["role_id"] == "SUPER_ADMIN"
        assert rec["built_in"] is True
        assert rec["custom"] is False
        assert rec["privilege_tier"] == "critical"
        assert rec["permissions_count"] is None

    def test_custom_role_record_with_permissions(self):
        raw = {"id": "cr1", "label": "My Role"}
        rec = OktaConnector._normalize_custom_admin_role(_TENANT, raw, ["okta.users.manage", "okta.groups.read"])
        assert rec["role_id"] == "cr1"
        assert rec["built_in"] is False
        assert rec["custom"] is True
        assert rec["permissions_count"] == 2
        assert rec["privilege_tier"] == "medium"

    def test_custom_role_record_no_permissions_data(self):
        raw = {"id": "cr1", "label": "My Role"}
        rec = OktaConnector._normalize_custom_admin_role(_TENANT, raw, None)
        assert rec["permissions_count"] is None
        assert rec["privilege_tier"] == PRIVILEGE_TIER_UNKNOWN

    def test_custom_role_missing_id_returns_none(self):
        assert OktaConnector._normalize_custom_admin_role(_TENANT, {"label": "x"}, []) is None

    def test_role_renamed_same_id(self):
        rec1 = OktaConnector._normalize_custom_admin_role(_TENANT, {"id": "cr1", "label": "Old"}, [])
        rec2 = OktaConnector._normalize_custom_admin_role(_TENANT, {"id": "cr1", "label": "New"}, [])
        assert rec1["record_id"] == rec2["record_id"]
        assert rec1["role_label"] != rec2["role_label"]


# ════════════════════════════════════════════════════════════════════════════
# Role-assignment parsing / scope
# ════════════════════════════════════════════════════════════════════════════


class TestAssignmentScope:
    def test_scoped_when_targets_link_present(self):
        raw = {"id": "ra1", "type": "APP_ADMIN", "status": "ACTIVE", "_links": {"targets": {"href": "x"}}}
        parsed = OktaConnector._parse_role_assignment(raw)
        assert parsed["scope_category"] == ASSIGNMENT_SCOPE_SCOPED

    def test_all_when_links_present_without_targets(self):
        raw = {"id": "ra1", "type": "APP_ADMIN", "status": "ACTIVE", "_links": {"self": {"href": "x"}}}
        parsed = OktaConnector._parse_role_assignment(raw)
        assert parsed["scope_category"] == ASSIGNMENT_SCOPE_ALL

    def test_unknown_when_links_missing_entirely(self):
        raw = {"id": "ra1", "type": "APP_ADMIN", "status": "ACTIVE"}
        parsed = OktaConnector._parse_role_assignment(raw)
        assert parsed["scope_category"] == ASSIGNMENT_SCOPE_UNKNOWN

    def test_missing_scope_never_reported_as_tenant_wide(self):
        raw = {"id": "ra1", "type": "APP_ADMIN", "status": "ACTIVE"}
        parsed = OktaConnector._parse_role_assignment(raw)
        assert parsed["scope_category"] != ASSIGNMENT_SCOPE_ALL

    def test_custom_role_id_extracted(self):
        raw = {"id": "ra1", "type": "CUSTOM", "status": "ACTIVE", "role": "cr1"}
        parsed = OktaConnector._parse_role_assignment(raw)
        assert parsed["custom_role_id"] == "cr1"

    def test_resource_set_extracted_for_custom(self):
        raw = {"id": "ra1", "type": "CUSTOM", "status": "ACTIVE", "role": "cr1", "resource-set": "rs1"}
        parsed = OktaConnector._parse_role_assignment(raw)
        assert parsed["resource_set_id"] == "rs1"

    def test_missing_assignment_id_returns_none(self):
        raw = {"type": "SUPER_ADMIN", "status": "ACTIVE"}
        assert OktaConnector._parse_role_assignment(raw) is None


# ════════════════════════════════════════════════════════════════════════════
# okta_user_admin_role_assignment / okta_group_admin_role_assignment
# ════════════════════════════════════════════════════════════════════════════


class TestUserAdminRoleAssignmentNormalization:
    def test_stable_record_id(self):
        rec = OktaConnector._normalize_user_admin_role_assignment(
            _TENANT, _user_record(), _parsed_assignment(scope_category="all"), _admin_role(),
        )
        assert rec["record_id"] == f"{_TENANT}/user_admin_role/u1/SUPER_ADMIN/all"

    def test_identity_derived_from_user_id_not_login(self):
        rec1 = OktaConnector._normalize_user_admin_role_assignment(
            _TENANT, _user_record(login="alice@example.com"), _parsed_assignment(), _admin_role(),
        )
        rec2 = OktaConnector._normalize_user_admin_role_assignment(
            _TENANT, _user_record(login="alice.new@example.com"), _parsed_assignment(), _admin_role(),
        )
        assert rec1["record_id"] == rec2["record_id"]

    def test_direct_assignment_always_true(self):
        rec = OktaConnector._normalize_user_admin_role_assignment(
            _TENANT, _user_record(), _parsed_assignment(), _admin_role(),
        )
        assert rec["direct_assignment"] is True

    def test_privilege_tier_denormalized_from_role(self):
        rec = OktaConnector._normalize_user_admin_role_assignment(
            _TENANT, _user_record(), _parsed_assignment(), _admin_role(privilege_tier="high"),
        )
        assert rec["privilege_tier"] == "high"


class TestGroupAdminRoleAssignmentNormalization:
    def test_stable_record_id(self):
        rec = OktaConnector._normalize_group_admin_role_assignment(
            _TENANT, _group_record(), _parsed_assignment(role_type="APP_ADMIN", scope_category="scoped"),
            _admin_role(role_id="APP_ADMIN", role_type="APP_ADMIN", privilege_tier="medium"),
        )
        assert rec["record_id"] == f"{_TENANT}/group_admin_role/g1/APP_ADMIN/scoped"

    def test_group_renamed_same_id(self):
        rec1 = OktaConnector._normalize_group_admin_role_assignment(
            _TENANT, _group_record(group_name="Old"), _parsed_assignment(), _admin_role(),
        )
        rec2 = OktaConnector._normalize_group_admin_role_assignment(
            _TENANT, _group_record(group_name="New"), _parsed_assignment(), _admin_role(),
        )
        assert rec1["record_id"] == rec2["record_id"]
        assert rec1["group_name"] != rec2["group_name"]


# ════════════════════════════════════════════════════════════════════════════
# Effective privileged identity derivation
# ════════════════════════════════════════════════════════════════════════════


def _u_assignment(**overrides) -> dict:
    base = {
        "record_type": "okta_user_admin_role_assignment", "user_id": "u1", "role_type": "SUPER_ADMIN",
        "privilege_tier": "critical", "custom": False, "assignment_scope_category": "all",
    }
    base.update(overrides)
    return base


def _g_assignment(**overrides) -> dict:
    base = {
        "record_type": "okta_group_admin_role_assignment", "group_id": "g1", "role_type": "APP_ADMIN",
        "privilege_tier": "medium", "custom": False, "assignment_scope_category": "all",
    }
    base.update(overrides)
    return base


def _membership(**overrides) -> dict:
    base = {"user_id": "u1", "group_id": "g1"}
    base.update(overrides)
    return base


class TestPrivilegedIdentityDerivation:
    def test_direct_privilege_only(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()}, [_u_assignment()], [], [],
        )
        assert len(recs) == 1
        assert recs[0]["privileged_via_direct_assignment"] is True
        assert recs[0]["privileged_via_group"] is False

    def test_group_privilege_only(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()}, [], [_g_assignment()], [_membership()],
        )
        assert len(recs) == 1
        assert recs[0]["privileged_via_group"] is True
        assert recs[0]["privileged_via_direct_assignment"] is False

    def test_direct_and_group_privilege(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()}, [_u_assignment()], [_g_assignment()], [_membership()],
        )
        assert len(recs) == 1
        assert recs[0]["privileged_via_direct_assignment"] is True
        assert recs[0]["privileged_via_group"] is True
        assert recs[0]["direct_admin_role_count"] == 1
        assert recs[0]["group_admin_role_count"] == 1

    def test_highest_tier_selected(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()},
            [_u_assignment(privilege_tier="medium", role_type="APP_ADMIN")],
            [_g_assignment(privilege_tier="critical", role_type="SUPER_ADMIN")],
            [_membership()],
        )
        assert recs[0]["highest_privilege_tier"] == "critical"

    def test_multiple_roles_dedup_by_user(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()},
            [_u_assignment(), _u_assignment(role_type="ORG_ADMIN", privilege_tier="high")],
            [], [],
        )
        assert len(recs) == 1
        assert recs[0]["direct_admin_role_count"] == 2

    def test_no_admin_role_produces_no_privileged_identity(self):
        recs = OktaConnector._derive_privileged_identities(_TENANT, {"u1": _user_record()}, [], [], [])
        assert recs == []

    def test_unknown_role_still_produces_visible_identity(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()},
            [_u_assignment(role_type="SOME_FUTURE_ROLE", privilege_tier=PRIVILEGE_TIER_UNKNOWN)], [], [],
        )
        assert len(recs) == 1
        assert recs[0]["highest_privilege_tier"] == PRIVILEGE_TIER_UNKNOWN

    def test_super_admin_boolean(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()}, [_u_assignment(role_type="SUPER_ADMIN")], [], [],
        )
        assert recs[0]["has_super_admin"] is True

    def test_non_super_admin_boolean_false(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()}, [_u_assignment(role_type="APP_ADMIN", privilege_tier="medium")], [], [],
        )
        assert recs[0]["has_super_admin"] is False

    def test_has_high_privilege_boolean(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()}, [_u_assignment(role_type="ORG_ADMIN", privilege_tier="high")], [], [],
        )
        assert recs[0]["has_high_privilege"] is True

    def test_medium_tier_not_high_privilege(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()}, [_u_assignment(role_type="APP_ADMIN", privilege_tier="medium")], [], [],
        )
        assert recs[0]["has_high_privilege"] is False

    def test_application_admin_scope_all(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()},
            [_u_assignment(role_type="APP_ADMIN", privilege_tier="medium", assignment_scope_category="all")], [], [],
        )
        assert recs[0]["application_admin_scope"] == "all"

    def test_application_admin_scope_scoped(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()},
            [_u_assignment(role_type="APP_ADMIN", privilege_tier="medium", assignment_scope_category="scoped")], [], [],
        )
        assert recs[0]["application_admin_scope"] == "scoped"

    def test_no_app_admin_role_scope_is_none(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()}, [_u_assignment(role_type="SUPER_ADMIN")], [], [],
        )
        assert recs[0]["application_admin_scope"] is None


class TestPrivilegedLifecycleCombinations:
    def test_active_super_admin(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record(status="ACTIVE")}, [_u_assignment()], [], [],
        )
        assert recs[0]["user_status"] == "ACTIVE"
        assert recs[0]["has_super_admin"] is True

    def test_suspended_super_admin_still_visible(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record(status="SUSPENDED")}, [_u_assignment()], [], [],
        )
        assert recs[0]["user_status"] == "SUSPENDED"
        assert recs[0]["has_super_admin"] is True  # suspension doesn't erase the assignment

    def test_deprovisioned_super_admin_still_visible(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record(status="DEPROVISIONED")}, [_u_assignment()], [], [],
        )
        assert recs[0]["user_status"] == "DEPROVISIONED"
        assert recs[0]["has_super_admin"] is True

    def test_stale_login_privileged_identity(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record(last_login_category="stale")}, [_u_assignment()], [], [],
        )
        assert recs[0]["dormant_privileged_category"] == categorize_dormant_privileged("stale")

    def test_never_login_privileged_identity(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record(last_login_category="never")}, [_u_assignment()], [], [],
        )
        assert recs[0]["dormant_privileged_category"] == "privileged_never_logged_in"

    def test_recent_login_privileged_identity(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record(last_login_category="recent")}, [_u_assignment()], [], [],
        )
        assert recs[0]["dormant_privileged_category"] == "privileged_recent_login"


# ════════════════════════════════════════════════════════════════════════════
# Group membership privilege joins
# ════════════════════════════════════════════════════════════════════════════


class TestGroupMembershipPrivilegeJoin:
    def test_user_in_privileged_group(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()}, [], [_g_assignment()], [_membership()],
        )
        assert len(recs) == 1

    def test_user_in_ordinary_group_not_privileged(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()}, [], [], [_membership(group_id="ordinary_group")],
        )
        assert recs == []

    def test_suspended_user_in_privileged_group_still_visible(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record(status="SUSPENDED")}, [], [_g_assignment()], [_membership()],
        )
        assert len(recs) == 1
        assert recs[0]["user_status"] == "SUSPENDED"

    def test_duplicate_membership_does_not_duplicate_privilege(self):
        recs = OktaConnector._derive_privileged_identities(
            _TENANT, {"u1": _user_record()}, [], [_g_assignment()],
            [_membership(), dict(_membership())],
        )
        assert len(recs) == 1


# ════════════════════════════════════════════════════════════════════════════
# Effective privileged group derivation
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedGroupDerivation:
    def test_group_with_admin_role_becomes_privileged(self):
        recs = OktaConnector._derive_privileged_groups(
            _TENANT, {"g1": _group_record()}, [_g_assignment()], [], {},
        )
        assert len(recs) == 1
        assert recs[0]["group_id"] == "g1"
        assert recs[0]["admin_role_count"] == 1

    def test_group_without_admin_role_not_privileged(self):
        recs = OktaConnector._derive_privileged_groups(_TENANT, {"g1": _group_record()}, [], [], {})
        assert recs == []

    def test_member_count_denormalized(self):
        recs = OktaConnector._derive_privileged_groups(
            _TENANT, {"g1": _group_record(membership_count=42)}, [_g_assignment()], [], {},
        )
        assert recs[0]["member_count"] == 42

    def test_broad_membership_super_admin_group(self):
        recs = OktaConnector._derive_privileged_groups(
            _TENANT, {"g1": _group_record(membership_count=500)},
            [_g_assignment(role_type="SUPER_ADMIN", privilege_tier="critical")], [], {},
        )
        assert recs[0]["highest_privilege_tier"] == "critical"
        assert recs[0]["member_count"] == 500

    def test_contains_suspended_members_count(self):
        members = [_membership(user_id="u1"), _membership(user_id="u2")]
        users = {"u1": _user_record(status="SUSPENDED"), "u2": _user_record(status="ACTIVE")}
        recs = OktaConnector._derive_privileged_groups(_TENANT, {"g1": _group_record()}, [_g_assignment()], members, users)
        assert recs[0]["contains_suspended_members"] == 1

    def test_contains_deprovisioned_members_count(self):
        members = [_membership(user_id="u1")]
        users = {"u1": _user_record(status="DEPROVISIONED")}
        recs = OktaConnector._derive_privileged_groups(_TENANT, {"g1": _group_record()}, [_g_assignment()], members, users)
        assert recs[0]["contains_deprovisioned_members"] == 1

    def test_no_suspended_or_deprovisioned_members(self):
        members = [_membership(user_id="u1")]
        users = {"u1": _user_record(status="ACTIVE")}
        recs = OktaConnector._derive_privileged_groups(_TENANT, {"g1": _group_record()}, [_g_assignment()], members, users)
        assert recs[0]["contains_suspended_members"] == 0
        assert recs[0]["contains_deprovisioned_members"] == 0


# ════════════════════════════════════════════════════════════════════════════
# Sensitive-data exclusion
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveDataExclusion:
    def test_raw_permission_response_body_never_stored(self):
        raw = {"id": "cr1", "label": "My Role"}
        rec = OktaConnector._normalize_custom_admin_role(_TENANT, raw, ["okta.users.manage"])
        assert "permissions" not in rec
        assert "okta.users.manage" not in str(rec)

    def test_resource_set_urls_never_stored(self):
        raw = {"id": "ra1", "type": "CUSTOM", "status": "ACTIVE", "role": "cr1", "resource-set": "rs1"}
        parsed = OktaConnector._parse_role_assignment(raw)
        assert parsed["resource_set_id"] == "rs1"
        assert "href" not in str(parsed)

    def test_factor_secrets_never_present_on_assignment(self):
        raw = {"id": "ra1", "type": "SUPER_ADMIN", "status": "ACTIVE", "otpSeed": "SHOULD_NEVER_APPEAR"}
        parsed = OktaConnector._parse_role_assignment(raw)
        assert "SHOULD_NEVER_APPEAR" not in str(parsed)

    def test_api_token_never_present_anywhere(self):
        rec = OktaConnector._normalize_builtin_admin_role(_TENANT, "SUPER_ADMIN", "Super Administrator")
        assert "api_token" not in str(rec).lower().replace("privilege", "")

    def test_user_profile_extras_never_leak_into_privileged_identity(self):
        user = _user_record()
        user["phoneNumber"] = "SHOULD_NEVER_APPEAR_PHONE"
        recs = OktaConnector._derive_privileged_identities(_TENANT, {"u1": user}, [_u_assignment()], [], [])
        assert "SHOULD_NEVER_APPEAR_PHONE" not in str(recs)
