"""Microsoft Entra ID directory-role / privileged-identity normalization
tests (Entra message 5 of 8).

Covers ``EntraConnector._normalize_directory_role``,
``_normalize_directory_role_assignment``, ``_derive_privileged_identities``,
``_derive_privileged_groups``, and ``_derive_privileged_service_principals``
directly: built-in role recognition, custom-role action tiering, principal
type resolution, directory scope categorization, effective-privilege
rollup, unknown-state discipline, completeness semantics, and
sensitive-data exclusion.
"""

from __future__ import annotations

from app.connectors.entra import EntraConnector
from app.connectors.entra_schema import (
    ENTRA_PRIVILEGE_TIER_CRITICAL,
    ENTRA_PRIVILEGE_TIER_HIGH,
    ENTRA_PRIVILEGE_TIER_MEDIUM,
    ENTRA_PRIVILEGE_TIER_READ_ONLY,
    ENTRA_PRIVILEGE_TIER_UNKNOWN,
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    FAMILY_PARTIAL,
    ROLE_TEMPLATE_APPLICATION_ADMINISTRATOR,
    ROLE_TEMPLATE_AUTHENTICATION_ADMINISTRATOR,
    ROLE_TEMPLATE_CLOUD_APPLICATION_ADMINISTRATOR,
    ROLE_TEMPLATE_CONDITIONAL_ACCESS_ADMINISTRATOR,
    ROLE_TEMPLATE_DIRECTORY_READERS,
    ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR,
    ROLE_TEMPLATE_GLOBAL_READER,
    ROLE_TEMPLATE_GROUPS_ADMINISTRATOR,
    ROLE_TEMPLATE_PRIVILEGED_AUTHENTICATION_ADMINISTRATOR,
    ROLE_TEMPLATE_PRIVILEGED_ROLE_ADMINISTRATOR,
    ROLE_TEMPLATE_SECURITY_ADMINISTRATOR,
    ROLE_TEMPLATE_USER_ADMINISTRATOR,
    graph_permission_privilege_tier,
)

_TENANT = "id:t1"


# ════════════════════════════════════════════════════════════════════════════
# Built-in role recognition
# ════════════════════════════════════════════════════════════════════════════


class TestBuiltInRoleTiers:
    def test_global_administrator_is_critical(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_CRITICAL

    def test_privileged_role_administrator_is_critical(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": ROLE_TEMPLATE_PRIVILEGED_ROLE_ADMINISTRATOR, "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_CRITICAL

    def test_privileged_authentication_administrator_is_critical(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": ROLE_TEMPLATE_PRIVILEGED_AUTHENTICATION_ADMINISTRATOR, "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_CRITICAL

    def test_application_administrator_is_high(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": ROLE_TEMPLATE_APPLICATION_ADMINISTRATOR, "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_HIGH

    def test_cloud_application_administrator_is_high(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": ROLE_TEMPLATE_CLOUD_APPLICATION_ADMINISTRATOR, "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_HIGH

    def test_authentication_administrator_is_high(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": ROLE_TEMPLATE_AUTHENTICATION_ADMINISTRATOR, "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_HIGH

    def test_conditional_access_administrator_is_high(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": ROLE_TEMPLATE_CONDITIONAL_ACCESS_ADMINISTRATOR, "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_HIGH

    def test_user_administrator_is_medium(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": ROLE_TEMPLATE_USER_ADMINISTRATOR, "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_MEDIUM

    def test_groups_administrator_is_medium(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": ROLE_TEMPLATE_GROUPS_ADMINISTRATOR, "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_MEDIUM

    def test_security_administrator_is_medium(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": ROLE_TEMPLATE_SECURITY_ADMINISTRATOR, "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_MEDIUM

    def test_global_reader_is_read_only(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": ROLE_TEMPLATE_GLOBAL_READER, "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_READ_ONLY

    def test_directory_readers_is_read_only(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": ROLE_TEMPLATE_DIRECTORY_READERS, "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_READ_ONLY

    def test_unknown_built_in_role_type_is_unknown_not_low(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": "some-future-role-guid", "isBuiltIn": True})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_UNKNOWN
        assert rec["is_privileged"] is None

    def test_role_never_identified_from_display_name_alone(self):
        """A role named 'Global Administrator' with an unrecognized ID must
        NOT be classified critical — only the stable template ID counts."""
        rec = EntraConnector._normalize_directory_role(
            _TENANT, {"id": "not-the-real-guid", "displayName": "Global Administrator", "isBuiltIn": True},
        )
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_UNKNOWN


# ════════════════════════════════════════════════════════════════════════════
# Custom role action taxonomy
# ════════════════════════════════════════════════════════════════════════════


class TestCustomRoleActionTaxonomy:
    def test_role_management_action_is_critical(self):
        rec = EntraConnector._normalize_directory_role(
            _TENANT,
            {"id": "custom1", "isBuiltIn": False, "rolePermissions": [
                {"allowedResourceActions": ["microsoft.directory/roleAssignments/allProperties/allTasks"]},
            ]},
        )
        assert rec["role_kind_category"] == "custom"
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_CRITICAL

    def test_application_credential_management_action_is_high(self):
        rec = EntraConnector._normalize_directory_role(
            _TENANT,
            {"id": "custom2", "isBuiltIn": False, "rolePermissions": [
                {"allowedResourceActions": ["microsoft.directory/applications/credentials/update"]},
            ]},
        )
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_HIGH

    def test_conditional_access_management_action_is_high(self):
        rec = EntraConnector._normalize_directory_role(
            _TENANT,
            {"id": "custom3", "isBuiltIn": False, "rolePermissions": [
                {"allowedResourceActions": ["microsoft.directory/conditionalAccessPolicies/basic/update"]},
            ]},
        )
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_HIGH

    def test_user_management_action_is_medium(self):
        rec = EntraConnector._normalize_directory_role(
            _TENANT,
            {"id": "custom4", "isBuiltIn": False, "rolePermissions": [
                {"allowedResourceActions": ["microsoft.directory/users/basic/update"]},
            ]},
        )
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_MEDIUM

    def test_read_only_action_is_read_only(self):
        rec = EntraConnector._normalize_directory_role(
            _TENANT,
            {"id": "custom5", "isBuiltIn": False, "rolePermissions": [
                {"allowedResourceActions": ["microsoft.directory/users/standard/read"]},
            ]},
        )
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_READ_ONLY

    def test_unknown_action_is_unknown_not_safe(self):
        rec = EntraConnector._normalize_directory_role(
            _TENANT,
            {"id": "custom6", "isBuiltIn": False, "rolePermissions": [
                {"allowedResourceActions": ["microsoft.somethingBrandNew/frobnicate"]},
            ]},
        )
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_UNKNOWN

    def test_empty_actions_is_unknown(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": "custom7", "isBuiltIn": False, "rolePermissions": []})
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_UNKNOWN

    def test_custom_role_not_assumed_risky_by_default(self):
        """A custom role is never tiered risky just for being custom — only
        its actual actions determine the tier."""
        rec = EntraConnector._normalize_directory_role(
            _TENANT,
            {"id": "custom8", "isBuiltIn": False, "rolePermissions": [
                {"allowedResourceActions": ["microsoft.directory/groups/standard/read"]},
            ]},
        )
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_READ_ONLY

    def test_highest_tier_among_multiple_actions_wins(self):
        rec = EntraConnector._normalize_directory_role(
            _TENANT,
            {"id": "custom9", "isBuiltIn": False, "rolePermissions": [
                {"allowedResourceActions": [
                    "microsoft.directory/users/standard/read",
                    "microsoft.directory/roleAssignments/allProperties/allTasks",
                ]},
            ]},
        )
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_CRITICAL

    def test_raw_action_list_never_persisted(self):
        rec = EntraConnector._normalize_directory_role(
            _TENANT,
            {"id": "custom10", "isBuiltIn": False, "rolePermissions": [
                {"allowedResourceActions": ["microsoft.directory/roleAssignments/allProperties/allTasks"]},
            ]},
        )
        assert "allowedResourceActions" not in str(rec)
        assert rec["action_count"] == 1
        assert rec["dangerous_action_count"] == 1

    def test_missing_id_returns_none(self):
        assert EntraConnector._normalize_directory_role(_TENANT, {"displayName": "X"}) is None

    def test_stable_record_id(self):
        rec = EntraConnector._normalize_directory_role(_TENANT, {"id": "r1"})
        assert rec["record_id"] == f"{_TENANT}/directory_role/r1"


# ════════════════════════════════════════════════════════════════════════════
# Directory role assignment normalization
# ════════════════════════════════════════════════════════════════════════════


class TestDirectoryRoleAssignmentNormalization:
    def _role_by_id(self):
        return {
            ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR: {
                "display_name": "Global Administrator", "template_id": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR,
                "privilege_tier": ENTRA_PRIVILEGE_TIER_CRITICAL,
            },
        }

    def test_user_principal_resolved(self):
        rec = EntraConnector._normalize_directory_role_assignment(
            _TENANT, {"id": "a1", "roleDefinitionId": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "principalId": "u1", "directoryScopeId": "/"},
            self._role_by_id(), {"u1": {}}, {}, {},
        )
        assert rec["principal_type"] == "User"
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_CRITICAL
        assert rec["role_name"] == "Global Administrator"

    def test_group_principal_resolved(self):
        rec = EntraConnector._normalize_directory_role_assignment(
            _TENANT, {"id": "a1", "roleDefinitionId": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "principalId": "g1", "directoryScopeId": "/"},
            self._role_by_id(), {}, {"g1": {}}, {},
        )
        assert rec["principal_type"] == "Group"

    def test_service_principal_resolved(self):
        rec = EntraConnector._normalize_directory_role_assignment(
            _TENANT, {"id": "a1", "roleDefinitionId": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "principalId": "sp1", "directoryScopeId": "/"},
            self._role_by_id(), {}, {}, {"sp1": {}},
        )
        assert rec["principal_type"] == "ServicePrincipal"

    def test_unresolvable_principal_is_unknown_not_user(self):
        rec = EntraConnector._normalize_directory_role_assignment(
            _TENANT, {"id": "a1", "roleDefinitionId": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "principalId": "ghost1", "directoryScopeId": "/"},
            self._role_by_id(), {}, {}, {},
        )
        assert rec["principal_type"] == "unknown"

    def test_missing_role_record_is_unknown_tier(self):
        rec = EntraConnector._normalize_directory_role_assignment(
            _TENANT, {"id": "a1", "roleDefinitionId": "unresolved-role", "principalId": "u1", "directoryScopeId": "/"},
            {}, {"u1": {}}, {}, {},
        )
        assert rec["privilege_tier"] == ENTRA_PRIVILEGE_TIER_UNKNOWN

    def test_tenant_wide_scope(self):
        rec = EntraConnector._normalize_directory_role_assignment(
            _TENANT, {"id": "a1", "roleDefinitionId": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "principalId": "u1", "directoryScopeId": "/"},
            self._role_by_id(), {"u1": {}}, {}, {},
        )
        assert rec["directory_scope_category"] == "tenant_wide"

    def test_administrative_unit_scope(self):
        rec = EntraConnector._normalize_directory_role_assignment(
            _TENANT,
            {"id": "a1", "roleDefinitionId": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "principalId": "u1", "directoryScopeId": "/administrativeUnits/au-guid-1"},
            self._role_by_id(), {"u1": {}}, {}, {},
        )
        assert rec["directory_scope_category"] == "administrative_unit"

    def test_unknown_scope_when_missing(self):
        rec = EntraConnector._normalize_directory_role_assignment(
            _TENANT, {"id": "a1", "roleDefinitionId": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "principalId": "u1"},
            self._role_by_id(), {"u1": {}}, {}, {},
        )
        assert rec["directory_scope_category"] == "unknown"

    def test_application_scope(self):
        rec = EntraConnector._normalize_directory_role_assignment(
            _TENANT,
            {"id": "a1", "roleDefinitionId": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "principalId": "u1", "appScopeId": "/app-guid-1"},
            self._role_by_id(), {"u1": {}}, {}, {},
        )
        assert rec["directory_scope_category"] == "application"

    def test_missing_principal_id_returns_none(self):
        assert EntraConnector._normalize_directory_role_assignment(
            _TENANT, {"id": "a1", "roleDefinitionId": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR}, {}, {}, {}, {},
        ) is None

    def test_stable_record_id_from_assignment_id(self):
        rec = EntraConnector._normalize_directory_role_assignment(
            _TENANT, {"id": "a1", "roleDefinitionId": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "principalId": "u1"},
            self._role_by_id(), {"u1": {}}, {}, {},
        )
        assert rec["record_id"] == f"{_TENANT}/directory_role_assignment/a1"

    def test_raw_resource_paths_never_persisted_beyond_category(self):
        rec = EntraConnector._normalize_directory_role_assignment(
            _TENANT,
            {"id": "a1", "roleDefinitionId": ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "principalId": "u1", "directoryScopeId": "/administrativeUnits/secret-au-guid"},
            self._role_by_id(), {"u1": {}}, {}, {},
        )
        assert "secret-au-guid" not in str(rec)


# ════════════════════════════════════════════════════════════════════════════
# Privileged identity derivation
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedIdentityDerivation:
    def _assignment(self, principal_id, principal_type, tier, *, role_template_id=None):
        return {
            "role_definition_id": "r1", "role_template_id": role_template_id, "role_name": "Role",
            "privilege_tier": tier, "principal_id": principal_id, "principal_type": principal_type,
            "directory_scope_category": "tenant_wide",
        }

    def test_direct_only_privilege(self):
        assignments = [self._assignment("u1", "User", ENTRA_PRIVILEGE_TIER_HIGH)]
        recs = EntraConnector._derive_privileged_identities(
            _TENANT, {"u1": {"user_id": "u1", "guest": False}}, assignments, [],
            memberships_completeness=FAMILY_COMPLETE,
        )
        assert len(recs) == 1
        assert recs[0]["privileged_via_direct"] is True
        assert recs[0]["privileged_via_group"] is False

    def test_group_only_privilege(self):
        assignments = [self._assignment("g1", "Group", ENTRA_PRIVILEGE_TIER_HIGH)]
        memberships = [{"user_id": "u1", "group_id": "g1"}]
        recs = EntraConnector._derive_privileged_identities(
            _TENANT, {"u1": {"user_id": "u1", "guest": False}}, assignments, memberships,
            memberships_completeness=FAMILY_COMPLETE,
        )
        assert len(recs) == 1
        assert recs[0]["privileged_via_direct"] is False
        assert recs[0]["privileged_via_group"] is True

    def test_direct_and_group_both(self):
        assignments = [
            self._assignment("u1", "User", ENTRA_PRIVILEGE_TIER_MEDIUM),
            self._assignment("g1", "Group", ENTRA_PRIVILEGE_TIER_HIGH),
        ]
        memberships = [{"user_id": "u1", "group_id": "g1"}]
        recs = EntraConnector._derive_privileged_identities(
            _TENANT, {"u1": {"user_id": "u1", "guest": False}}, assignments, memberships,
            memberships_completeness=FAMILY_COMPLETE,
        )
        assert recs[0]["privileged_via_direct"] is True
        assert recs[0]["privileged_via_group"] is True
        assert recs[0]["highest_privilege_tier"] == ENTRA_PRIVILEGE_TIER_HIGH

    def test_highest_tier_selected(self):
        assignments = [
            self._assignment("u1", "User", ENTRA_PRIVILEGE_TIER_MEDIUM),
            self._assignment("u1", "User", ENTRA_PRIVILEGE_TIER_CRITICAL),
        ]
        recs = EntraConnector._derive_privileged_identities(
            _TENANT, {"u1": {"user_id": "u1", "guest": False}}, assignments, [],
            memberships_completeness=FAMILY_COMPLETE,
        )
        assert recs[0]["highest_privilege_tier"] == ENTRA_PRIVILEGE_TIER_CRITICAL

    def test_has_global_admin_boolean(self):
        assignments = [self._assignment("u1", "User", ENTRA_PRIVILEGE_TIER_CRITICAL, role_template_id=ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR)]
        recs = EntraConnector._derive_privileged_identities(
            _TENANT, {"u1": {"user_id": "u1", "guest": False}}, assignments, [],
            memberships_completeness=FAMILY_COMPLETE,
        )
        assert recs[0]["has_global_admin"] is True
        assert recs[0]["has_privileged_role_admin"] is False

    def test_has_privileged_role_admin_boolean(self):
        assignments = [self._assignment("u1", "User", ENTRA_PRIVILEGE_TIER_CRITICAL, role_template_id=ROLE_TEMPLATE_PRIVILEGED_ROLE_ADMINISTRATOR)]
        recs = EntraConnector._derive_privileged_identities(
            _TENANT, {"u1": {"user_id": "u1", "guest": False}}, assignments, [],
            memberships_completeness=FAMILY_COMPLETE,
        )
        assert recs[0]["has_privileged_role_admin"] is True

    def test_disabled_privileged_user_stays_visible(self):
        assignments = [self._assignment("u1", "User", ENTRA_PRIVILEGE_TIER_HIGH)]
        recs = EntraConnector._derive_privileged_identities(
            _TENANT, {"u1": {"user_id": "u1", "account_enabled_category": "disabled", "guest": False}}, assignments, [],
            memberships_completeness=FAMILY_COMPLETE,
        )
        assert len(recs) == 1
        assert recs[0]["account_enabled_category"] == "disabled"

    def test_guest_global_admin_distinguishable(self):
        assignments = [self._assignment("u1", "User", ENTRA_PRIVILEGE_TIER_CRITICAL, role_template_id=ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR)]
        recs = EntraConnector._derive_privileged_identities(
            _TENANT, {"u1": {"user_id": "u1", "guest": True}}, assignments, [],
            memberships_completeness=FAMILY_COMPLETE,
        )
        assert recs[0]["guest"] is True
        assert recs[0]["has_global_admin"] is True

    def test_ordinary_guest_not_privileged(self):
        recs = EntraConnector._derive_privileged_identities(
            _TENANT, {"u1": {"user_id": "u1", "guest": True}}, [], [],
            memberships_completeness=FAMILY_COMPLETE,
        )
        assert recs == []

    def test_denied_memberships_never_claim_no_group_privilege(self):
        """If group memberships are denied/partial, a user with ONLY a
        direct assignment must show privileged_via_group=None (unknown),
        never False."""
        assignments = [self._assignment("u1", "User", ENTRA_PRIVILEGE_TIER_HIGH)]
        recs = EntraConnector._derive_privileged_identities(
            _TENANT, {"u1": {"user_id": "u1", "guest": False}}, assignments, [],
            memberships_completeness=FAMILY_DENIED,
        )
        assert recs[0]["privileged_via_group"] is None
        assert recs[0]["privilege_derivation_completeness"] == FAMILY_PARTIAL

    def test_no_privilege_no_record(self):
        recs = EntraConnector._derive_privileged_identities(_TENANT, {}, [], [], memberships_completeness=FAMILY_COMPLETE)
        assert recs == []

    def test_deterministic_ordering(self):
        assignments = [
            self._assignment("u2", "User", ENTRA_PRIVILEGE_TIER_HIGH),
            self._assignment("u1", "User", ENTRA_PRIVILEGE_TIER_HIGH),
        ]
        recs = EntraConnector._derive_privileged_identities(
            _TENANT, {"u1": {}, "u2": {}}, assignments, [], memberships_completeness=FAMILY_COMPLETE,
        )
        assert [r["user_id"] for r in recs] == ["u1", "u2"]


# ════════════════════════════════════════════════════════════════════════════
# Privileged group derivation
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedGroupDerivation:
    def test_role_assignable_without_role_is_not_privileged(self):
        recs = EntraConnector._derive_privileged_groups(
            _TENANT, {"g1": {"role_assignable": True, "display_name": "Eligible"}}, {}, [], [],
            memberships_completeness=FAMILY_COMPLETE,
        )
        assert recs == []

    def test_group_with_role_is_privileged(self):
        assignments = [{
            "principal_id": "g1", "principal_type": "Group", "privilege_tier": ENTRA_PRIVILEGE_TIER_CRITICAL,
        }]
        recs = EntraConnector._derive_privileged_groups(
            _TENANT, {"g1": {"role_assignable": True, "display_name": "Admins", "membership_count": 3}},
            {}, assignments, [], memberships_completeness=FAMILY_COMPLETE,
        )
        assert len(recs) == 1
        assert recs[0]["highest_privilege_tier"] == ENTRA_PRIVILEGE_TIER_CRITICAL

    def test_member_counts(self):
        assignments = [{"principal_id": "g1", "principal_type": "Group", "privilege_tier": ENTRA_PRIVILEGE_TIER_HIGH}]
        memberships = [{"group_id": "g1", "user_id": "u1"}, {"group_id": "g1", "user_id": "u2"}]
        user_index = {
            "u1": {"guest": True, "account_enabled_category": "enabled"},
            "u2": {"guest": False, "account_enabled_category": "disabled"},
        }
        recs = EntraConnector._derive_privileged_groups(
            _TENANT, {"g1": {"role_assignable": True}}, user_index, assignments, memberships,
            memberships_completeness=FAMILY_COMPLETE,
        )
        assert recs[0]["direct_user_member_count"] == 2
        assert recs[0]["guest_member_count"] == 1
        assert recs[0]["disabled_member_count"] == 1

    def test_nested_group_not_flattened(self):
        """member counts only ever come from direct message-2 memberships —
        no sub-group expansion is performed here either."""
        assignments = [{"principal_id": "g1", "principal_type": "Group", "privilege_tier": ENTRA_PRIVILEGE_TIER_HIGH}]
        recs = EntraConnector._derive_privileged_groups(
            _TENANT, {"g1": {"role_assignable": True}}, {}, assignments, [],
            memberships_completeness=FAMILY_COMPLETE,
        )
        assert recs[0]["direct_user_member_count"] == 0


# ════════════════════════════════════════════════════════════════════════════
# Privileged service principal derivation
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedServicePrincipalDerivation:
    def test_sp_privileged_via_directory_role(self):
        role_assignments = [{"principal_id": "sp1", "principal_type": "ServicePrincipal", "privilege_tier": ENTRA_PRIVILEGE_TIER_CRITICAL}]
        recs = EntraConnector._derive_privileged_service_principals(
            _TENANT, {"sp1": {"app_id": "app1", "display_name": "Automation"}}, role_assignments, [], [],
            directory_role_assignments_completeness=FAMILY_COMPLETE,
            app_role_assignments_completeness=FAMILY_COMPLETE,
            oauth2_grants_completeness=FAMILY_COMPLETE,
        )
        assert len(recs) == 1
        assert recs[0]["highest_privilege_tier"] == ENTRA_PRIVILEGE_TIER_CRITICAL

    def test_sp_privileged_via_critical_app_permission(self):
        app_role_assignments = [{
            "principal_service_principal_id": "sp1", "app_role_category": "RoleManagement.ReadWrite.Directory",
            "app_role_privilege_tier": ENTRA_PRIVILEGE_TIER_CRITICAL,
        }]
        recs = EntraConnector._derive_privileged_service_principals(
            _TENANT, {"sp1": {"app_id": "app1", "display_name": "Automation"}}, [], app_role_assignments, [],
            directory_role_assignments_completeness=FAMILY_COMPLETE,
            app_role_assignments_completeness=FAMILY_COMPLETE,
            oauth2_grants_completeness=FAMILY_COMPLETE,
        )
        assert recs[0]["has_role_management_permission"] is True
        assert recs[0]["critical_app_permission_count"] == 1

    def test_sp_privileged_via_tenant_wide_high_risk_consent(self):
        grants = [{"client_service_principal_id": "sp1", "consent_type_category": "AllPrincipals", "highest_scope_privilege_tier": ENTRA_PRIVILEGE_TIER_HIGH}]
        recs = EntraConnector._derive_privileged_service_principals(
            _TENANT, {"sp1": {"app_id": "app1", "display_name": "Automation"}}, [], [], grants,
            directory_role_assignments_completeness=FAMILY_COMPLETE,
            app_role_assignments_completeness=FAMILY_COMPLETE,
            oauth2_grants_completeness=FAMILY_COMPLETE,
        )
        assert len(recs) == 1
        assert recs[0]["tenant_wide_delegated_grant_count"] == 1

    def test_ordinary_app_permission_not_emitted(self):
        app_role_assignments = [{
            "principal_service_principal_id": "sp1", "app_role_category": "User.Read",
            "app_role_privilege_tier": ENTRA_PRIVILEGE_TIER_READ_ONLY,
        }]
        recs = EntraConnector._derive_privileged_service_principals(
            _TENANT, {"sp1": {"app_id": "app1", "display_name": "Ordinary"}}, [], app_role_assignments, [],
            directory_role_assignments_completeness=FAMILY_COMPLETE,
            app_role_assignments_completeness=FAMILY_COMPLETE,
            oauth2_grants_completeness=FAMILY_COMPLETE,
        )
        assert recs == []

    def test_unknown_app_permission_surfaced_not_hidden(self):
        """An unresolved/unknown-tier granted permission must be
        surfaced for review — never silently dropped as if it were
        ordinary."""
        app_role_assignments = [{
            "principal_service_principal_id": "sp1", "app_role_category": None,
            "app_role_privilege_tier": ENTRA_PRIVILEGE_TIER_UNKNOWN,
        }]
        recs = EntraConnector._derive_privileged_service_principals(
            _TENANT, {"sp1": {"app_id": "app1", "display_name": "Mystery"}}, [], app_role_assignments, [],
            directory_role_assignments_completeness=FAMILY_COMPLETE,
            app_role_assignments_completeness=FAMILY_COMPLETE,
            oauth2_grants_completeness=FAMILY_COMPLETE,
        )
        assert len(recs) == 1
        assert recs[0]["highest_privilege_tier"] == ENTRA_PRIVILEGE_TIER_UNKNOWN

    def test_managed_identity_included_in_privilege_derivation(self):
        role_assignments = [{"principal_id": "sp1", "principal_type": "ServicePrincipal", "privilege_tier": ENTRA_PRIVILEGE_TIER_HIGH}]
        recs = EntraConnector._derive_privileged_service_principals(
            _TENANT, {"sp1": {"app_id": None, "display_name": "MI", "service_principal_type_category": "ManagedIdentity"}},
            role_assignments, [], [],
            directory_role_assignments_completeness=FAMILY_COMPLETE,
            app_role_assignments_completeness=FAMILY_COMPLETE,
            oauth2_grants_completeness=FAMILY_COMPLETE,
        )
        assert len(recs) == 1
        assert recs[0]["service_principal_type_category"] == "ManagedIdentity"

    def test_completeness_partial_when_family_incomplete(self):
        role_assignments = [{"principal_id": "sp1", "principal_type": "ServicePrincipal", "privilege_tier": ENTRA_PRIVILEGE_TIER_HIGH}]
        recs = EntraConnector._derive_privileged_service_principals(
            _TENANT, {"sp1": {"app_id": "app1", "display_name": "X"}}, role_assignments, [], [],
            directory_role_assignments_completeness=FAMILY_DENIED,
            app_role_assignments_completeness=FAMILY_COMPLETE,
            oauth2_grants_completeness=FAMILY_COMPLETE,
        )
        assert recs[0]["privilege_derivation_completeness"] == FAMILY_PARTIAL

    def test_deduplicates_multiple_evidence_sources_for_same_sp(self):
        role_assignments = [{"principal_id": "sp1", "principal_type": "ServicePrincipal", "privilege_tier": ENTRA_PRIVILEGE_TIER_HIGH}]
        app_role_assignments = [{
            "principal_service_principal_id": "sp1", "app_role_category": "Directory.ReadWrite.All",
            "app_role_privilege_tier": ENTRA_PRIVILEGE_TIER_HIGH,
        }]
        recs = EntraConnector._derive_privileged_service_principals(
            _TENANT, {"sp1": {"app_id": "app1", "display_name": "X"}}, role_assignments, app_role_assignments, [],
            directory_role_assignments_completeness=FAMILY_COMPLETE,
            app_role_assignments_completeness=FAMILY_COMPLETE,
            oauth2_grants_completeness=FAMILY_COMPLETE,
        )
        assert len(recs) == 1


# ════════════════════════════════════════════════════════════════════════════
# Graph app-permission privilege tier
# ════════════════════════════════════════════════════════════════════════════


class TestGraphPermissionPrivilegeTier:
    def test_role_management_readwrite_directory_is_critical(self):
        assert graph_permission_privilege_tier("RoleManagement.ReadWrite.Directory") == ENTRA_PRIVILEGE_TIER_CRITICAL

    def test_approle_assignment_readwrite_all_is_critical(self):
        assert graph_permission_privilege_tier("AppRoleAssignment.ReadWrite.All") == ENTRA_PRIVILEGE_TIER_CRITICAL

    def test_directory_readwrite_all_is_high(self):
        assert graph_permission_privilege_tier("Directory.ReadWrite.All") == ENTRA_PRIVILEGE_TIER_HIGH

    def test_user_read_is_read_only(self):
        assert graph_permission_privilege_tier("User.Read") == ENTRA_PRIVILEGE_TIER_READ_ONLY

    def test_unknown_permission_is_unknown_not_ordinary(self):
        assert graph_permission_privilege_tier("SomeBrandNew.Scope") == ENTRA_PRIVILEGE_TIER_UNKNOWN

    def test_non_graph_third_party_permission_is_always_unknown(self):
        """Never assume a third-party API's permission is safe just
        because ConfigTrace doesn't recognize the API — even a value
        string this taxonomy WOULD otherwise recognize for Graph must
        still resolve unknown when the resource isn't Microsoft Graph."""
        assert graph_permission_privilege_tier(
            "RoleManagement.ReadWrite.Directory", is_microsoft_graph_resource=False,
        ) == ENTRA_PRIVILEGE_TIER_UNKNOWN

    def test_openid_is_low_not_high(self):
        assert graph_permission_privilege_tier("openid") == "low"

    def test_missing_value_is_unknown(self):
        assert graph_permission_privilege_tier(None) == ENTRA_PRIVILEGE_TIER_UNKNOWN


# ════════════════════════════════════════════════════════════════════════════
# Sensitive-data exclusion
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveDataExclusion:
    def test_directory_role_never_persists_raw_actions(self):
        rec = EntraConnector._normalize_directory_role(
            _TENANT,
            {"id": "custom1", "isBuiltIn": False, "rolePermissions": [
                {"allowedResourceActions": ["microsoft.directory/applications/credentials/update"]},
            ]},
        )
        blob = str(rec).lower()
        for forbidden in ("secret", "certificate", "private_key", "credentials/update"):
            assert forbidden not in blob

    def test_privileged_sp_never_persists_credential_secrets(self):
        role_assignments = [{"principal_id": "sp1", "principal_type": "ServicePrincipal", "privilege_tier": ENTRA_PRIVILEGE_TIER_HIGH}]
        recs = EntraConnector._derive_privileged_service_principals(
            _TENANT, {"sp1": {"app_id": "app1", "display_name": "X", "password_credential_count": 1}},
            role_assignments, [], [],
            directory_role_assignments_completeness=FAMILY_COMPLETE,
            app_role_assignments_completeness=FAMILY_COMPLETE,
            oauth2_grants_completeness=FAMILY_COMPLETE,
        )
        blob = str(recs).lower()
        for forbidden in ("secrettext", "client_secret", "private_key"):
            assert forbidden not in blob
