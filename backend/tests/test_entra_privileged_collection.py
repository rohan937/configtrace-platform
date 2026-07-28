"""Microsoft Entra ID directory-role / privileged-identity collection tests
(Entra message 5 of 8).

Covers directory-role-definition / directory-role-assignment collection
end-to-end via ``EntraConnector.fetch()``: tenant-wide (no N+1) collection,
principal resolution, group inheritance, family independence (fail-soft),
pagination, call-count assertions, and scale behavior. Normalization
correctness is covered separately in ``test_entra_privileged_normalization.py``;
diff/risk behavior in ``test_entra_privileged_diff.py``.
"""

from __future__ import annotations

import httpx
import respx

from app.connectors.entra import EntraConnector
from app.connectors.entra_schema import (
    ENTRA_DIRECTORY_ROLE,
    ENTRA_DIRECTORY_ROLE_ASSIGNMENT,
    ENTRA_ORGANIZATION,
    ENTRA_PRIVILEGED_GROUP,
    ENTRA_PRIVILEGED_IDENTITY,
    ENTRA_PRIVILEGED_SERVICE_PRINCIPAL,
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR,
    ROLE_TEMPLATE_USER_ADMINISTRATOR,
)

_TENANT_ID = "11111111-1111-1111-1111-111111111111"
_CLIENT_ID = "22222222-2222-2222-2222-222222222222"
_SECRET = "fake-entra-client-secret-value"
_CREDS = {"tenant_id": _TENANT_ID, "client_id": _CLIENT_ID, "client_secret": _SECRET}
_TOKEN_URL = f"https://login.microsoftonline.com/{_TENANT_ID}/oauth2/v2.0/token"
_GRAPH = "https://graph.microsoft.com/v1.0"

_IDENTITY_APP_FAMILY_PATHS = (
    "applications", "servicePrincipals", "oauth2PermissionGrants",
    "identity/conditionalAccess/policies", "policies/authenticationStrengthPolicies",
    "policies/authenticationMethodsPolicy/authenticationMethodConfigurations",
)


def _mock_token():
    respx.post(_TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600}))


def _mock_org():
    respx.get(f"{_GRAPH}/organization").mock(
        return_value=httpx.Response(200, json={"value": [{"id": _TENANT_ID, "displayName": "Example Corp"}]})
    )


def _mock_identity_and_app_families_empty():
    respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
    for path in _IDENTITY_APP_FAMILY_PATHS:
        respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))


def _mock_role_families_empty():
    respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(return_value=httpx.Response(200, json={"value": []}))


def _user(user_id: str, **overrides) -> dict:
    base = {
        "id": user_id, "userPrincipalName": f"{user_id}@example.com", "displayName": f"User {user_id}",
        "accountEnabled": True, "userType": "Member", "createdDateTime": "2020-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def _group(group_id: str, **overrides) -> dict:
    base = {
        "id": group_id, "displayName": f"Group {group_id}", "securityEnabled": True,
        "mailEnabled": False, "groupTypes": [], "isAssignableToRole": True,
    }
    base.update(overrides)
    return base


def _member_ref(user_id: str) -> dict:
    return {"id": user_id, "@odata.type": "#microsoft.graph.user"}


def _role_def(role_id: str, **overrides) -> dict:
    base = {"id": role_id, "displayName": f"Role {role_id}", "isBuiltIn": True, "isEnabled": True}
    base.update(overrides)
    return base


def _role_assignment(assignment_id: str, role_definition_id: str, principal_id: str, **overrides) -> dict:
    base = {
        "id": assignment_id, "roleDefinitionId": role_definition_id, "principalId": principal_id,
        "directoryScopeId": "/",
    }
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# Directory role definition collection
# ════════════════════════════════════════════════════════════════════════════


class TestDirectoryRoleDefinitionCollection:
    @respx.mock
    def test_collects_all_role_definitions_single_page(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(
            return_value=httpx.Response(200, json={"value": [
                _role_def(ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, displayName="Global Administrator"),
                _role_def(ROLE_TEMPLATE_USER_ADMINISTRATOR, displayName="User Administrator"),
            ]})
        )
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        roles = [r for r in records if r["record_type"] == ENTRA_DIRECTORY_ROLE]
        assert len(roles) == 2
        assert {r["role_definition_id"] for r in roles} == {ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, ROLE_TEMPLATE_USER_ADMINISTRATOR}

    @respx.mock
    def test_collects_role_definitions_across_multiple_pages(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        page1 = httpx.Response(
            200, json={"value": [_role_def("r1")], "@odata.nextLink": f"{_GRAPH}/roleManagement/directory/roleDefinitions?skip=1"},
        )
        page2 = httpx.Response(200, json={"value": [_role_def("r2")]})
        respx.get(url__regex=r".*/roleManagement/directory/roleDefinitions.*").mock(side_effect=[page1, page2])
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        roles = [r for r in records if r["record_type"] == ENTRA_DIRECTORY_ROLE]
        assert {r["role_definition_id"] for r in roles} == {"r1", "r2"}

    @respx.mock
    def test_denied_role_definitions_family_reports_denied_and_does_not_abort(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(return_value=httpx.Response(403, json={"error": {"code": "Forbidden"}}))
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["directory_role_definitions"] == FAMILY_DENIED
        assert [r for r in records if r["record_type"] == ENTRA_DIRECTORY_ROLE] == []
        # Other families are unaffected by this one family's denial.
        assert org["family_completeness"]["directory_role_assignments"] == FAMILY_COMPLETE


# ════════════════════════════════════════════════════════════════════════════
# Directory role assignment collection (tenant-wide, no N+1)
# ════════════════════════════════════════════════════════════════════════════


class TestDirectoryRoleAssignmentCollection:
    @respx.mock
    def test_collects_all_assignments_single_page(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(
            return_value=httpx.Response(200, json={"value": [_role_def(ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR)]})
        )
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(
            return_value=httpx.Response(200, json={"value": [
                _role_assignment("a1", ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "u1"),
                _role_assignment("a2", ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "u2"),
            ]})
        )

        records = EntraConnector().fetch(_CREDS)
        assignments = [r for r in records if r["record_type"] == ENTRA_DIRECTORY_ROLE_ASSIGNMENT]
        assert len(assignments) == 2
        assert {a["principal_id"] for a in assignments} == {"u1", "u2"}

    @respx.mock
    def test_call_count_is_flat_regardless_of_user_group_count(self):
        """The whole point of preferring the modern role-management API:
        collection must be TWO flat calls (definitions + assignments),
        never one call per user/group — contrast with Okta's forced N+1
        design."""
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(
            return_value=httpx.Response(200, json={"value": [_user(f"u{i}") for i in range(50)]})
        )
        respx.get(f"{_GRAPH}/groups").mock(
            return_value=httpx.Response(200, json={"value": [_group(f"g{i}") for i in range(50)]})
        )
        for i in range(50):
            respx.get(f"{_GRAPH}/groups/g{i}/members").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        role_def_route = respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(
            return_value=httpx.Response(200, json={"value": [_role_def(ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR)]})
        )
        role_assignment_route = respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(
            return_value=httpx.Response(200, json={"value": [_role_assignment("a1", ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "u1")]})
        )

        EntraConnector().fetch(_CREDS)
        assert role_def_route.call_count == 1
        assert role_assignment_route.call_count == 1

    @respx.mock
    def test_principal_resolved_locally_no_expand_call(self):
        """Principal type/identity resolution must never require
        ``$expand=principal`` or any other per-assignment Graph call — it
        is resolved locally against the already-built user/group/SP
        indexes."""
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [_user("u1")]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(
            return_value=httpx.Response(200, json={"value": [_role_def(ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR)]})
        )
        route = respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(
            return_value=httpx.Response(200, json={"value": [_role_assignment("a1", ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "u1")]})
        )

        records = EntraConnector().fetch(_CREDS)
        assignment = next(r for r in records if r["record_type"] == ENTRA_DIRECTORY_ROLE_ASSIGNMENT)
        assert assignment["principal_type"] == "User"
        params = route.calls[0].request.url.params
        assert "expand" not in "".join(params.keys()).lower()

    @respx.mock
    def test_denied_assignments_family_reports_denied_and_does_not_abort(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(return_value=httpx.Response(403, json={"error": {"code": "Forbidden"}}))

        records = EntraConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["directory_role_assignments"] == FAMILY_DENIED
        assert org["family_completeness"]["directory_role_definitions"] == FAMILY_COMPLETE


# ════════════════════════════════════════════════════════════════════════════
# Group inheritance (privileged group -> member privilege)
# ════════════════════════════════════════════════════════════════════════════


class TestGroupInheritance:
    @respx.mock
    def test_user_inherits_privilege_via_role_assignable_group_membership(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [_user("u1")]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [_group("g1")]}))
        respx.get(f"{_GRAPH}/groups/g1/members").mock(return_value=httpx.Response(200, json={"value": [_member_ref("u1")]}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(
            return_value=httpx.Response(200, json={"value": [_role_def(ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR)]})
        )
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(
            return_value=httpx.Response(200, json={"value": [_role_assignment("a1", ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "g1")]})
        )

        records = EntraConnector().fetch(_CREDS)
        priv_identity = next(r for r in records if r["record_type"] == ENTRA_PRIVILEGED_IDENTITY)
        assert priv_identity["user_id"] == "u1"
        assert priv_identity["privileged_via_group"] is True
        assert priv_identity["privileged_via_direct"] is False
        priv_group = next(r for r in records if r["record_type"] == ENTRA_PRIVILEGED_GROUP)
        assert priv_group["group_id"] == "g1"

    @respx.mock
    def test_nested_group_not_flattened(self):
        """Only DIRECT group membership is modeled — a user in a
        sub-group of a privileged group is never inferred as privileged
        (message 2's documented nested-group limitation)."""
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [_user("u1")]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [_group("g1"), _group("g2")]}))
        # u1 is a direct member of g2 only; g2 is a member of g1 (nested) —
        # but nested group membership is never expanded/flattened.
        respx.get(f"{_GRAPH}/groups/g1/members").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups/g2/members").mock(return_value=httpx.Response(200, json={"value": [_member_ref("u1")]}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(
            return_value=httpx.Response(200, json={"value": [_role_def(ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR)]})
        )
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(
            return_value=httpx.Response(200, json={"value": [_role_assignment("a1", ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "g1")]})
        )

        records = EntraConnector().fetch(_CREDS)
        privileged_identities = [r for r in records if r["record_type"] == ENTRA_PRIVILEGED_IDENTITY]
        assert privileged_identities == []


# ════════════════════════════════════════════════════════════════════════════
# Service principal privilege collection
# ════════════════════════════════════════════════════════════════════════════


class TestServicePrincipalPrivilegeCollection:
    @respx.mock
    def test_service_principal_privileged_via_directory_role(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": [
            {"id": "sp1", "appId": "app1", "displayName": "Automation SP", "accountEnabled": True},
        ]}))
        respx.get(f"{_GRAPH}/servicePrincipals/sp1/appRoleAssignedTo").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in ("identity/conditionalAccess/policies", "policies/authenticationStrengthPolicies",
                     "policies/authenticationMethodsPolicy/authenticationMethodConfigurations"):
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(
            return_value=httpx.Response(200, json={"value": [_role_def(ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR)]})
        )
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(
            return_value=httpx.Response(200, json={"value": [_role_assignment("a1", ROLE_TEMPLATE_GLOBAL_ADMINISTRATOR, "sp1")]})
        )

        records = EntraConnector().fetch(_CREDS)
        priv_sp = next(r for r in records if r["record_type"] == ENTRA_PRIVILEGED_SERVICE_PRINCIPAL)
        assert priv_sp["service_principal_id"] == "sp1"
        assert priv_sp["directory_role_count"] == 1
        assert priv_sp["highest_privilege_tier"] == "critical"

    @respx.mock
    def test_ordinary_service_principal_not_emitted(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": [
            {"id": "sp1", "appId": "app1", "displayName": "Ordinary SP", "accountEnabled": True},
        ]}))
        respx.get(f"{_GRAPH}/servicePrincipals/sp1/appRoleAssignedTo").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in ("identity/conditionalAccess/policies", "policies/authenticationStrengthPolicies",
                     "policies/authenticationMethodsPolicy/authenticationMethodConfigurations"):
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()

        records = EntraConnector().fetch(_CREDS)
        assert [r for r in records if r["record_type"] == ENTRA_PRIVILEGED_SERVICE_PRINCIPAL] == []


# ════════════════════════════════════════════════════════════════════════════
# Deterministic ordering + scale
# ════════════════════════════════════════════════════════════════════════════


class TestDeterministicOrderingAndScale:
    @respx.mock
    def test_deterministic_ordering(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(
            return_value=httpx.Response(200, json={"value": [_role_def("r2"), _role_def("r1")]})
        )
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        role_ids = [r["role_definition_id"] for r in records if r["record_type"] == ENTRA_DIRECTORY_ROLE]
        assert role_ids == sorted(role_ids)

    @respx.mock
    def test_scale_many_role_assignments(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(
            return_value=httpx.Response(200, json={"value": [_user(f"u{i}") for i in range(500)]})
        )
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(
            return_value=httpx.Response(200, json={"value": [_role_def(ROLE_TEMPLATE_USER_ADMINISTRATOR)]})
        )
        many_assignments = [
            _role_assignment(f"a{i}", ROLE_TEMPLATE_USER_ADMINISTRATOR, f"u{i}") for i in range(500)
        ]
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(return_value=httpx.Response(200, json={"value": many_assignments}))

        records = EntraConnector().fetch(_CREDS)
        assignments = [r for r in records if r["record_type"] == ENTRA_DIRECTORY_ROLE_ASSIGNMENT]
        privileged = [r for r in records if r["record_type"] == ENTRA_PRIVILEGED_IDENTITY]
        assert len(assignments) == 500
        assert len(privileged) == 500
