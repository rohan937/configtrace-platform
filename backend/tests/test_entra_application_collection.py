"""Microsoft Entra ID application security collection tests (Entra message
3 of 8).

Covers application/service-principal/assignment/OAuth-grant collection
end-to-end via ``EntraConnector.fetch()``: pagination, family independence
(fail-soft), per-SP assignment enumeration (bounded, branched by principal
type), local app-role/permission resolution, deduplication, stable IDs,
and scale behavior. Normalization correctness is covered separately in
``test_entra_application_normalization.py``; diff/risk behavior in
``test_entra_application_diff.py``.
"""

from __future__ import annotations

import time

import httpx
import respx

from app.connectors.entra import EntraConnector
from app.connectors.entra_schema import (
    ENTRA_APPLICATION,
    ENTRA_APPLICATION_GROUP_ASSIGNMENT,
    ENTRA_APPLICATION_USER_ASSIGNMENT,
    ENTRA_OAUTH2_PERMISSION_GRANT,
    ENTRA_ORGANIZATION,
    ENTRA_SERVICE_PRINCIPAL,
    ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT,
    FAMILY_COMPLETE,
    FAMILY_DENIED,
)

_TENANT_ID = "11111111-1111-1111-1111-111111111111"
_CLIENT_ID = "22222222-2222-2222-2222-222222222222"
_SECRET = "fake-entra-client-secret-value"
_CREDS = {"tenant_id": _TENANT_ID, "client_id": _CLIENT_ID, "client_secret": _SECRET}
_TOKEN_URL = f"https://login.microsoftonline.com/{_TENANT_ID}/oauth2/v2.0/token"
_GRAPH = "https://graph.microsoft.com/v1.0"

_OPTIONAL_FAMILY_PATHS = (
    "identity/conditionalAccess/policies", "policies/authenticationMethodsPolicy", "directoryRoles",
)


def _mock_token():
    respx.post(_TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600}))


def _mock_org():
    respx.get(f"{_GRAPH}/organization").mock(
        return_value=httpx.Response(200, json={"value": [{"id": _TENANT_ID, "displayName": "Example Corp"}]})
    )


def _mock_empty_identity():
    respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))


def _mock_optional_families_empty():
    for path in _OPTIONAL_FAMILY_PATHS:
        respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))


def _application(app_id: str, *, client_id: str = None, name: str = None) -> dict:
    return {
        "id": app_id,
        "appId": client_id or f"client-{app_id}",
        "displayName": name or f"App {app_id}",
        "signInAudience": "AzureADMyOrg",
        "web": {"redirectUris": ["https://example.com/cb"]},
        "requiredResourceAccess": [],
        "passwordCredentials": [],
        "keyCredentials": [],
        "appRoles": [],
    }


def _service_principal(sp_id: str, *, app_id: str = None, name: str = None, roles: list = None) -> dict:
    return {
        "id": sp_id,
        "appId": app_id or f"client-{sp_id}",
        "displayName": name or f"SP {sp_id}",
        "servicePrincipalType": "Application",
        "accountEnabled": True,
        "appRoleAssignmentRequired": False,
        "appOwnerOrganizationId": _TENANT_ID,
        "passwordCredentials": [],
        "keyCredentials": [],
        "appRoles": roles or [],
        "oauth2PermissionScopes": [],
    }


def _assignment(principal_id: str, principal_type: str, *, assignment_id: str = None, app_role_id: str = None) -> dict:
    return {
        "id": assignment_id or f"assign-{principal_id}",
        "principalId": principal_id,
        "principalType": principal_type,
        "appRoleId": app_role_id or "00000000-0000-0000-0000-000000000000",
    }


def _grant(grant_id: str, *, client_id: str, resource_id: str, consent_type: str = "AllPrincipals", scope: str = "User.Read") -> dict:
    return {
        "id": grant_id,
        "clientId": client_id,
        "resourceId": resource_id,
        "consentType": consent_type,
        "scope": scope,
    }


def _mock_full_fetch_scaffold():
    _mock_token()
    _mock_org()
    _mock_empty_identity()
    _mock_optional_families_empty()


# ════════════════════════════════════════════════════════════════════════════
# Application collection
# ════════════════════════════════════════════════════════════════════════════


class TestApplicationCollection:
    @respx.mock
    def test_collects_all_applications_single_page(self):
        _mock_full_fetch_scaffold()
        respx.get(f"{_GRAPH}/applications").mock(
            return_value=httpx.Response(200, json={"value": [_application("a1"), _application("a2")]})
        )
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        apps = [r for r in records if r["record_type"] == ENTRA_APPLICATION]
        assert len(apps) == 2
        assert {a["object_id"] for a in apps} == {"a1", "a2"}

    @respx.mock
    def test_collects_applications_across_multiple_pages(self):
        _mock_full_fetch_scaffold()
        page1 = httpx.Response(
            200, json={"value": [_application("a1")], "@odata.nextLink": f"{_GRAPH}/applications?skip=1"},
        )
        page2 = httpx.Response(200, json={"value": [_application("a2")]})
        respx.get(url__regex=r".*/applications.*").mock(side_effect=[page1, page2])
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        apps = [r for r in records if r["record_type"] == ENTRA_APPLICATION]
        assert {a["object_id"] for a in apps} == {"a1", "a2"}

    @respx.mock
    def test_applications_select_uses_explicit_allowlist(self):
        _mock_full_fetch_scaffold()
        route = respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        EntraConnector().fetch(_CREDS)
        select_param = route.calls[0].request.url.params.get("$select")
        assert select_param == EntraConnector._APPLICATION_SELECT
        assert "secretText" not in select_param


# ════════════════════════════════════════════════════════════════════════════
# Service principal collection
# ════════════════════════════════════════════════════════════════════════════


class TestServicePrincipalCollection:
    @respx.mock
    def test_collects_all_service_principals(self):
        _mock_full_fetch_scaffold()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(
            return_value=httpx.Response(200, json={"value": [_service_principal("sp1"), _service_principal("sp2")]})
        )
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        sps = [r for r in records if r["record_type"] == ENTRA_SERVICE_PRINCIPAL]
        assert len(sps) == 2
        assert {s["service_principal_id"] for s in sps} == {"sp1", "sp2"}

    @respx.mock
    def test_service_principals_select_uses_explicit_allowlist(self):
        _mock_full_fetch_scaffold()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        route = respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        EntraConnector().fetch(_CREDS)
        select_param = route.calls[0].request.url.params.get("$select")
        assert select_param == EntraConnector._SERVICE_PRINCIPAL_SELECT


# ════════════════════════════════════════════════════════════════════════════
# App-role assignment collection (per-SP enumeration, principal branching)
# ════════════════════════════════════════════════════════════════════════════


class TestAssignmentCollection:
    @respx.mock
    def test_user_assignment_collected_per_sp(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [
            {"id": "u1", "userPrincipalName": "u1@example.com", "displayName": "U1", "accountEnabled": True, "userType": "Member"},
        ]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_optional_families_empty()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": [_service_principal("sp1")]}))
        respx.get(f"{_GRAPH}/servicePrincipals/sp1/appRoleAssignedTo").mock(
            return_value=httpx.Response(200, json={"value": [_assignment("u1", "User")]})
        )
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        assignments = [r for r in records if r["record_type"] == ENTRA_APPLICATION_USER_ASSIGNMENT]
        assert len(assignments) == 1
        assert assignments[0]["user_id"] == "u1"

    @respx.mock
    def test_group_assignment_branched_correctly(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [
            {"id": "g1", "displayName": "G1", "securityEnabled": True, "mailEnabled": False, "groupTypes": [], "isAssignableToRole": False},
        ]}))
        _mock_optional_families_empty()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": [_service_principal("sp1")]}))
        respx.get(f"{_GRAPH}/servicePrincipals/sp1/appRoleAssignedTo").mock(
            return_value=httpx.Response(200, json={"value": [_assignment("g1", "Group")]})
        )
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        assignments = [r for r in records if r["record_type"] == ENTRA_APPLICATION_GROUP_ASSIGNMENT]
        assert len(assignments) == 1
        assert assignments[0]["group_id"] == "g1"
        assert not any(r["record_type"] == ENTRA_APPLICATION_USER_ASSIGNMENT for r in records)

    @respx.mock
    def test_service_principal_permission_branched_correctly(self):
        _mock_full_fetch_scaffold()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": [
            _service_principal("sp1"), _service_principal("sp2"),
        ]}))
        respx.get(f"{_GRAPH}/servicePrincipals/sp1/appRoleAssignedTo").mock(
            return_value=httpx.Response(200, json={"value": [_assignment("sp2", "ServicePrincipal")]})
        )
        respx.get(f"{_GRAPH}/servicePrincipals/sp2/appRoleAssignedTo").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        sp_assignments = [r for r in records if r["record_type"] == ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT]
        assert len(sp_assignments) == 1
        assert sp_assignments[0]["principal_service_principal_id"] == "sp2"
        assert sp_assignments[0]["resource_service_principal_id"] == "sp1"

    @respx.mock
    def test_unknown_principal_type_skipped_not_raised(self):
        _mock_full_fetch_scaffold()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": [_service_principal("sp1")]}))
        respx.get(f"{_GRAPH}/servicePrincipals/sp1/appRoleAssignedTo").mock(
            return_value=httpx.Response(200, json={"value": [_assignment("device1", "Device")]})
        )
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)  # must not raise
        assert not any(
            r["record_type"] in (
                ENTRA_APPLICATION_USER_ASSIGNMENT, ENTRA_APPLICATION_GROUP_ASSIGNMENT,
                ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT,
            )
            for r in records
        )

    @respx.mock
    def test_does_not_call_per_user_app_role_assignments_endpoint(self):
        """Confirms the chosen strategy is SP->assignedTo, not per-user
        app-role-assignment enumeration."""
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [
            {"id": "u1", "userPrincipalName": "u1@example.com", "displayName": "U1", "accountEnabled": True, "userType": "Member"},
        ]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_optional_families_empty()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": [_service_principal("sp1")]}))
        respx.get(f"{_GRAPH}/servicePrincipals/sp1/appRoleAssignedTo").mock(return_value=httpx.Response(200, json={"value": []}))
        per_user_route = respx.get(f"{_GRAPH}/users/u1/appRoleAssignments").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        EntraConnector().fetch(_CREDS)
        assert per_user_route.call_count == 0

    @respx.mock
    def test_local_app_role_resolution_no_extra_call(self):
        """appRoleId is resolved from the resource SP's own already-fetched
        appRoles array — never a separate Graph lookup."""
        _mock_full_fetch_scaffold()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": [
            _service_principal("sp1", roles=[{"id": "role1", "value": "Reader.All", "isEnabled": True}]),
        ]}))
        respx.get(f"{_GRAPH}/servicePrincipals/sp1/appRoleAssignedTo").mock(
            return_value=httpx.Response(200, json={"value": [_assignment("sp-other", "ServicePrincipal", app_role_id="role1")]})
        )
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        sp_assignment = next(r for r in records if r["record_type"] == ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT)
        assert sp_assignment["app_role_category"] == "Reader.All"


# ════════════════════════════════════════════════════════════════════════════
# OAuth2 permission grant collection (tenant-wide)
# ════════════════════════════════════════════════════════════════════════════


class TestOAuth2GrantCollection:
    @respx.mock
    def test_collects_grants_tenant_wide_no_per_app_walk(self):
        _mock_full_fetch_scaffold()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": [
            _service_principal("sp1"), _service_principal("sp2"),
        ]}))
        respx.get(f"{_GRAPH}/servicePrincipals/sp1/appRoleAssignedTo").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals/sp2/appRoleAssignedTo").mock(return_value=httpx.Response(200, json={"value": []}))
        grants_route = respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(
            return_value=httpx.Response(200, json={"value": [_grant("g1", client_id="sp1", resource_id="sp2")]})
        )

        records = EntraConnector().fetch(_CREDS)
        grants = [r for r in records if r["record_type"] == ENTRA_OAUTH2_PERMISSION_GRANT]
        assert len(grants) == 1
        # One call from the family collection + one from the message-1
        # capability probe sweep — never one call per app/SP.
        assert grants_route.call_count == 2


# ════════════════════════════════════════════════════════════════════════════
# Family independence / fail-soft
# ════════════════════════════════════════════════════════════════════════════


class TestFamilyIndependence:
    @respx.mock
    def test_applications_and_sps_available_assignments_denied(self):
        _mock_full_fetch_scaffold()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": [_application("a1")]}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": [_service_principal("sp1")]}))
        respx.get(f"{_GRAPH}/servicePrincipals/sp1/appRoleAssignedTo").mock(return_value=httpx.Response(403))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        assert any(r["record_type"] == ENTRA_APPLICATION for r in records)
        assert any(r["record_type"] == ENTRA_SERVICE_PRINCIPAL for r in records)
        assert not any(r["record_type"] == ENTRA_APPLICATION_USER_ASSIGNMENT for r in records)

        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["applications"] == FAMILY_COMPLETE
        assert org["family_completeness"]["service_principals"] == FAMILY_COMPLETE
        assert org["family_completeness"]["app_role_assignments"] == FAMILY_DENIED

    @respx.mock
    def test_applications_denied_sps_still_attempted(self):
        _mock_full_fetch_scaffold()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(403))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": [_service_principal("sp1")]}))
        respx.get(f"{_GRAPH}/servicePrincipals/sp1/appRoleAssignedTo").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)  # must not raise
        assert not any(r["record_type"] == ENTRA_APPLICATION for r in records)
        assert any(r["record_type"] == ENTRA_SERVICE_PRINCIPAL for r in records)
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["applications"] == FAMILY_DENIED

    @respx.mock
    def test_oauth_grants_denied_does_not_fail_entire_fetch(self):
        _mock_full_fetch_scaffold()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(403))

        records = EntraConnector().fetch(_CREDS)  # must not raise
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["oauth2_permission_grants"] == FAMILY_DENIED

    @respx.mock
    def test_no_sps_at_all_assignments_complete_not_denied(self):
        _mock_full_fetch_scaffold()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["app_role_assignments"] == FAMILY_COMPLETE


# ════════════════════════════════════════════════════════════════════════════
# Dedup / stable IDs
# ════════════════════════════════════════════════════════════════════════════


class TestDedupAndStableIds:
    @respx.mock
    def test_assignment_dedup_within_an_sp(self):
        _mock_full_fetch_scaffold()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": [_service_principal("sp1")]}))
        page1 = httpx.Response(
            200, json={"value": [_assignment("u1", "User")], "@odata.nextLink": f"{_GRAPH}/servicePrincipals/sp1/appRoleAssignedTo?skip=1"},
        )
        page2 = httpx.Response(200, json={"value": [_assignment("u1", "User")]})
        respx.get(url__regex=r".*/servicePrincipals/sp1/appRoleAssignedTo.*").mock(side_effect=[page1, page2])
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        records = EntraConnector().fetch(_CREDS)
        assignments = [r for r in records if r["record_type"] == ENTRA_APPLICATION_USER_ASSIGNMENT]
        assert len(assignments) == 1

    def test_application_stable_record_id(self):
        tenant_id = "id:t1"
        rec = EntraConnector._normalize_application(tenant_id, _application("a1"))
        assert rec["record_id"] == f"{tenant_id}/application/a1"

    def test_service_principal_stable_record_id(self):
        tenant_id = "id:t1"
        rec = EntraConnector._normalize_service_principal(tenant_id, _service_principal("sp1"), "t1")
        assert rec["record_id"] == f"{tenant_id}/service_principal/sp1"

    def test_assignment_uses_graph_own_id_when_available(self):
        tenant_id = "id:t1"
        sp_record = EntraConnector._normalize_service_principal(tenant_id, _service_principal("sp1"), "t1")
        rec = EntraConnector._normalize_app_user_assignment(
            tenant_id, sp_record, None, _assignment("u1", "User", assignment_id="assign-xyz"),
        )
        assert rec["record_id"] == f"{tenant_id}/app_role_assignment/assign-xyz"

    def test_missing_object_id_rejected(self):
        assert EntraConnector._normalize_application("id:t1", {"appId": "x"}) is None

    def test_missing_sp_id_rejected(self):
        assert EntraConnector._normalize_service_principal("id:t1", {"appId": "x"}, "t1") is None


# ════════════════════════════════════════════════════════════════════════════
# N+1 / call-count audit
# ════════════════════════════════════════════════════════════════════════════


class TestCallCount:
    @respx.mock
    def test_assignment_walk_is_sp_directed_bounded_call_count(self):
        _mock_full_fetch_scaffold()
        n_sps = 5
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(
            return_value=httpx.Response(200, json={"value": [_service_principal(f"sp{i}") for i in range(n_sps)]})
        )
        assignment_route = respx.get(url__regex=r".*/servicePrincipals/sp\d+/appRoleAssignedTo.*").mock(
            return_value=httpx.Response(200, json={"value": []})
        )
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))

        EntraConnector().fetch(_CREDS)
        assert assignment_route.call_count == n_sps


# ════════════════════════════════════════════════════════════════════════════
# Scale
# ════════════════════════════════════════════════════════════════════════════


class TestScale:
    @respx.mock
    def test_2000_applications_3000_sps_with_assignments_and_grants(self):
        _mock_full_fetch_scaffold()

        n_apps = 2000
        n_sps = 3000
        respx.get(f"{_GRAPH}/applications").mock(
            return_value=httpx.Response(200, json={"value": [_application(f"a{i}") for i in range(n_apps)]})
        )
        sps_json = [_service_principal(f"sp{i}") for i in range(n_sps)]
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": sps_json}))

        # ~7 assignments per SP across 3000 SPs => ~21,000 assignments.
        assignments_per_sp = 7
        for si in range(n_sps):
            slice_ = [_assignment(f"principal{si}-{k}", "ServicePrincipal", assignment_id=f"assign-{si}-{k}") for k in range(assignments_per_sp)]
            respx.get(f"{_GRAPH}/servicePrincipals/sp{si}/appRoleAssignedTo").mock(
                return_value=httpx.Response(200, json={"value": slice_})
            )

        grants_json = [_grant(f"grant{i}", client_id="sp0", resource_id="sp1") for i in range(10_000)]
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": grants_json}))

        start = time.monotonic()
        records = EntraConnector().fetch(_CREDS)
        elapsed = time.monotonic() - start

        apps = [r for r in records if r["record_type"] == ENTRA_APPLICATION]
        sps = [r for r in records if r["record_type"] == ENTRA_SERVICE_PRINCIPAL]
        sp_assignments = [r for r in records if r["record_type"] == ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT]
        grants = [r for r in records if r["record_type"] == ENTRA_OAUTH2_PERMISSION_GRANT]

        assert len(apps) == n_apps
        assert len(sps) == n_sps
        assert len(sp_assignments) == n_sps * assignments_per_sp
        assert len(grants) == 10_000
        assert len({a["record_id"] for a in apps}) == n_apps
        assert len({s["record_id"] for s in sps}) == n_sps
        assert len({g["record_id"] for g in grants}) == len(grants)
        assert elapsed < 120.0
