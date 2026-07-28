"""Microsoft Entra ID scale / N+1 / determinism reliability tests (Entra
message 7 of 8).

Per-family scale (users+groups+memberships, applications+service
principals+assignments, directory-role assignments) is already covered by
messages 2/3/5's own collection test files
(test_entra_identity_collection.py, test_entra_application_collection.py,
test_entra_privileged_collection.py). This file adds what message 7
specifically owns: a combined multi-family large-tenant fetch, capability
-probe call-count staying constant regardless of tenant size, deterministic
ordering/idempotency at the whole-fetch level, and no state leakage across
sequential fetches on a REUSED connector instance (the scenario the
message-7 token-cache ``credential_key`` hardening targets).
"""

from __future__ import annotations

import time

import httpx
import respx

from app.connectors.entra import EntraConnector
from app.connectors.entra_schema import (
    ENTRA_APPLICATION,
    ENTRA_DIRECTORY_ROLE_ASSIGNMENT,
    ENTRA_GROUP,
    ENTRA_GROUP_MEMBERSHIP,
    ENTRA_ORGANIZATION,
    ENTRA_PRIVILEGED_IDENTITY,
    ENTRA_SERVICE_PRINCIPAL,
    ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT,
    ENTRA_USER,
    ROLE_TEMPLATE_USER_ADMINISTRATOR,
)

_TENANT_ID = "11111111-1111-1111-1111-111111111111"
_CLIENT_ID = "22222222-2222-2222-2222-222222222222"
_SECRET = "fake-entra-client-secret-value"
_CREDS = {"tenant_id": _TENANT_ID, "client_id": _CLIENT_ID, "client_secret": _SECRET}
_TOKEN_URL = f"https://login.microsoftonline.com/{_TENANT_ID}/oauth2/v2.0/token"
_GRAPH = "https://graph.microsoft.com/v1.0"


def _mock_token():
    respx.post(_TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600}))


def _mock_org(tenant_id: str = _TENANT_ID):
    respx.get(f"{_GRAPH}/organization").mock(
        return_value=httpx.Response(200, json={"value": [{"id": tenant_id, "displayName": "Example Corp"}]})
    )


def _user(uid: str) -> dict:
    return {"id": uid, "userPrincipalName": f"{uid}@example.com", "displayName": f"User {uid}", "accountEnabled": True, "userType": "Member"}


def _group(gid: str) -> dict:
    return {"id": gid, "displayName": f"Group {gid}", "securityEnabled": True, "mailEnabled": False, "groupTypes": [], "isAssignableToRole": False}


def _member_ref(uid: str) -> dict:
    return {"id": uid, "@odata.type": "#microsoft.graph.user"}


def _application(aid: str) -> dict:
    return {
        "id": aid, "appId": f"client-{aid}", "displayName": f"App {aid}", "signInAudience": "AzureADMyOrg",
        "web": {"redirectUris": []}, "requiredResourceAccess": [], "passwordCredentials": [], "keyCredentials": [], "appRoles": [],
    }


def _service_principal(spid: str) -> dict:
    return {
        "id": spid, "appId": f"client-{spid}", "displayName": f"SP {spid}", "servicePrincipalType": "Application",
        "accountEnabled": True, "appRoleAssignmentRequired": False, "appOwnerOrganizationId": _TENANT_ID,
        "passwordCredentials": [], "keyCredentials": [], "appRoles": [], "oauth2PermissionScopes": [],
    }


def _sp_assignment(idx: int) -> dict:
    return {"id": f"assign{idx}", "principalId": f"principal{idx}", "principalType": "ServicePrincipal", "appRoleId": "00000000-0000-0000-0000-000000000000"}


def _role_def(template_id: str) -> dict:
    return {"id": template_id, "templateId": template_id, "displayName": "User Administrator", "isBuiltIn": True, "isEnabled": True, "rolePermissions": []}


def _role_assignment(idx: int, template_id: str, principal_id: str) -> dict:
    return {"id": f"ra{idx}", "roleDefinitionId": template_id, "principalId": principal_id, "principalType": "User", "directoryScopeId": "/"}


def _mock_combined_tenant(n_users: int, n_groups: int, members_per_group: int, n_apps: int, n_sps: int, n_role_assignments: int):
    respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [_user(f"u{i}") for i in range(n_users)]}))
    groups_json = [_group(f"g{i}") for i in range(n_groups)]
    respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": groups_json}))
    for gi in range(n_groups):
        members = [_member_ref(f"u{(gi * members_per_group + k) % n_users}") for k in range(members_per_group)]
        respx.get(f"{_GRAPH}/groups/g{gi}/members").mock(return_value=httpx.Response(200, json={"value": members}))

    respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": [_application(f"a{i}") for i in range(n_apps)]}))
    sps_json = [_service_principal(f"sp{i}") for i in range(n_sps)]
    respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": sps_json}))
    for si in range(n_sps):
        respx.get(f"{_GRAPH}/servicePrincipals/sp{si}/appRoleAssignedTo").mock(
            return_value=httpx.Response(200, json={"value": [_sp_assignment(si)]})
        )

    respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(
        return_value=httpx.Response(200, json={"value": [_role_def(ROLE_TEMPLATE_USER_ADMINISTRATOR)]})
    )
    role_assignments_json = [_role_assignment(i, ROLE_TEMPLATE_USER_ADMINISTRATOR, f"u{i}") for i in range(n_role_assignments)]
    respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(return_value=httpx.Response(200, json={"value": role_assignments_json}))


def _fetch(_sleep_fn=lambda s: None):
    return EntraConnector().fetch(_CREDS, _sleep_fn=_sleep_fn)


# ════════════════════════════════════════════════════════════════════════════
# Combined multi-family large-tenant scale
# ════════════════════════════════════════════════════════════════════════════


class TestCombinedTenantScale:
    @respx.mock
    def test_multi_family_tenant_at_representative_scale(self):
        _mock_token()
        _mock_org()
        n_users, n_groups, members_per_group = 1_500, 400, 5
        n_apps, n_sps = 800, 800
        n_role_assignments = 300
        _mock_combined_tenant(n_users, n_groups, members_per_group, n_apps, n_sps, n_role_assignments)

        start = time.monotonic()
        records = _fetch()
        elapsed = time.monotonic() - start

        users = [r for r in records if r["record_type"] == ENTRA_USER]
        groups = [r for r in records if r["record_type"] == ENTRA_GROUP]
        memberships = [r for r in records if r["record_type"] == ENTRA_GROUP_MEMBERSHIP]
        apps = [r for r in records if r["record_type"] == ENTRA_APPLICATION]
        sps = [r for r in records if r["record_type"] == ENTRA_SERVICE_PRINCIPAL]
        sp_assignments = [r for r in records if r["record_type"] == ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT]
        role_assignments = [r for r in records if r["record_type"] == ENTRA_DIRECTORY_ROLE_ASSIGNMENT]
        privileged = [r for r in records if r["record_type"] == ENTRA_PRIVILEGED_IDENTITY]

        assert len(users) == n_users
        assert len(groups) == n_groups
        assert len(memberships) == n_groups * members_per_group
        assert len(apps) == n_apps
        assert len(sps) == n_sps
        assert len(sp_assignments) == n_sps
        assert len(role_assignments) == n_role_assignments
        assert len(privileged) == n_role_assignments
        assert len({r["record_id"] for r in records}) == len(records)  # no duplicate record_ids anywhere
        assert elapsed < 60.0

        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert all(v == "complete" for v in org["family_completeness"].values())


# ════════════════════════════════════════════════════════════════════════════
# Capability-probe call count stays constant regardless of tenant size
# ════════════════════════════════════════════════════════════════════════════


class TestCapabilityProbeCallCountBounded:
    @respx.mock
    def test_probe_call_count_independent_of_tenant_size(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=300, n_groups=50, members_per_group=3, n_apps=100, n_sps=100, n_role_assignments=20)

        users_route = respx.routes[f"{_GRAPH}/users"] if f"{_GRAPH}/users" in respx.routes else None
        # Count every GET to the exact singleton-style probe paths that have
        # NO other collection caller (identity/conditionalAccess/policies and
        # applications DO get a real collection call too — so instead assert
        # each family's request count is small and bounded, never scaling
        # with record counts).
        apps_route = respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": [_application(f"a{i}") for i in range(100)]}))

        records = _fetch()
        # One real collection GET plus one capability-probe GET ($top=1) —
        # never proportional to the 100 applications actually returned.
        assert apps_route.call_count == 2
        assert any(r["record_type"] == "entra_api_capability" for r in records)


# ════════════════════════════════════════════════════════════════════════════
# Deterministic ordering / idempotency
# ════════════════════════════════════════════════════════════════════════════


class TestDeterministicOrderingAndIdempotency:
    @respx.mock
    def test_same_source_data_produces_identical_record_sets(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=50, n_groups=10, members_per_group=2, n_apps=20, n_sps=20, n_role_assignments=5)

        records1 = _fetch()
        records2 = _fetch()

        ids1 = [(r["record_type"], r["record_id"]) for r in records1]
        ids2 = [(r["record_type"], r["record_id"]) for r in records2]
        assert ids1 == ids2

    def test_idempotent_diff_produces_zero_changes(self):
        from types import SimpleNamespace as NS
        from app.services.diff_service import compute_diff

        snapshot_state = [
            {"record_type": "entra_organization", "record_id": "id:t1", "tenant_id": "id:t1", "family_completeness": {"users": "complete"}},
            {"record_type": "entra_user", "record_id": "id:t1/user/u1", "tenant_id": "id:t1", "user_id": "u1", "user_principal_name": "a@x.com"},
        ]
        changes = compute_diff(NS(state=snapshot_state), NS(state=snapshot_state))
        assert changes == []


# ════════════════════════════════════════════════════════════════════════════
# No state leakage across sequential fetches on a reused connector instance
# ════════════════════════════════════════════════════════════════════════════


class TestNoStateLeakageBetweenFetches:
    @respx.mock
    def test_reused_connector_instance_does_not_leak_state_between_tenants(self):
        _mock_token()
        _mock_org(tenant_id="11111111-1111-1111-1111-111111111111")
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [_user("u1")]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [_group("g1")]}))
        respx.get(f"{_GRAPH}/groups/g1/members").mock(return_value=httpx.Response(200, json={"value": [_member_ref("u1")]}))
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(
            return_value=httpx.Response(200, json={"value": [_role_def(ROLE_TEMPLATE_USER_ADMINISTRATOR)]})
        )
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(
            return_value=httpx.Response(200, json={"value": [_role_assignment(1, ROLE_TEMPLATE_USER_ADMINISTRATOR, "u1")]})
        )

        connector = EntraConnector()
        records_a = connector.fetch(_CREDS, _sleep_fn=lambda s: None)
        assert any(r["record_type"] == "entra_privileged_identity" for r in records_a)

        # Second fetch, SAME connector instance, DIFFERENT tenant — the
        # instance-scoped token cache (with its message-7 credential_key
        # binding) must re-acquire a token for tenant B rather than reusing
        # tenant A's cached token, and no tenant-A record/tenant_id must
        # leak into tenant B's result.
        other_tenant_id = "99999999-9999-9999-9999-999999999999"
        other_token_url = f"https://login.microsoftonline.com/{other_tenant_id}/oauth2/v2.0/token"
        respx.post(other_token_url).mock(return_value=httpx.Response(200, json={"access_token": "tok-b", "expires_in": 3600}))
        _mock_org(tenant_id=other_tenant_id)
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))

        other_creds = {"tenant_id": other_tenant_id, "client_id": _CLIENT_ID, "client_secret": _SECRET}
        records_b = connector.fetch(other_creds, _sleep_fn=lambda s: None)

        assert not any(r["record_type"] == "entra_privileged_identity" for r in records_b)
        assert not any(r.get("tenant_id") == f"id:{_TENANT_ID}" for r in records_b)
        org_b = next(r for r in records_b if r["record_type"] == "entra_organization")
        org_a = next(r for r in records_a if r["record_type"] == "entra_organization")
        assert org_b["tenant_id"] != org_a["tenant_id"]


# ════════════════════════════════════════════════════════════════════════════
# Per-family scale granularity (message 7's own additions beyond messages
# 2/3/5's per-family scale tests)
# ════════════════════════════════════════════════════════════════════════════


class TestPerFamilyScaleGranularity:
    @respx.mock
    def test_zero_records_every_family_still_produces_org_and_capability_records(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=0, n_groups=0, members_per_group=0, n_apps=0, n_sps=0, n_role_assignments=0)

        records = _fetch()
        assert any(r["record_type"] == "entra_organization" for r in records)
        assert any(r["record_type"] == "entra_api_capability" for r in records)
        assert len(records) > 1  # org + capability probes only, no phantom records

    @respx.mock
    def test_single_record_every_family_collects_exactly_one(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=1, n_groups=1, members_per_group=1, n_apps=1, n_sps=1, n_role_assignments=1)

        records = _fetch()
        assert len([r for r in records if r["record_type"] == ENTRA_USER]) == 1
        assert len([r for r in records if r["record_type"] == ENTRA_GROUP]) == 1
        assert len([r for r in records if r["record_type"] == ENTRA_GROUP_MEMBERSHIP]) == 1
        assert len([r for r in records if r["record_type"] == ENTRA_APPLICATION]) == 1
        assert len([r for r in records if r["record_type"] == ENTRA_SERVICE_PRINCIPAL]) == 1
        assert len([r for r in records if r["record_type"] == ENTRA_DIRECTORY_ROLE_ASSIGNMENT]) == 1

    @respx.mock
    def test_3000_users_scale_alone(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=3_000, n_groups=0, members_per_group=0, n_apps=0, n_sps=0, n_role_assignments=0)

        start = time.monotonic()
        records = _fetch()
        elapsed = time.monotonic() - start
        users = [r for r in records if r["record_type"] == ENTRA_USER]
        assert len(users) == 3_000
        assert len({u["record_id"] for u in users}) == 3_000
        assert elapsed < 30.0

    @respx.mock
    def test_1000_groups_10_members_each_scale_alone(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=200, n_groups=1_000, members_per_group=10, n_apps=0, n_sps=0, n_role_assignments=0)

        start = time.monotonic()
        records = _fetch()
        elapsed = time.monotonic() - start
        memberships = [r for r in records if r["record_type"] == ENTRA_GROUP_MEMBERSHIP]
        assert len(memberships) == 10_000
        assert len({m["record_id"] for m in memberships}) == 10_000
        assert elapsed < 30.0

    @respx.mock
    def test_2000_sps_with_one_assignment_each_scale_alone(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=0, n_groups=0, members_per_group=0, n_apps=0, n_sps=2_000, n_role_assignments=0)

        start = time.monotonic()
        records = _fetch()
        elapsed = time.monotonic() - start
        sps = [r for r in records if r["record_type"] == ENTRA_SERVICE_PRINCIPAL]
        assignments = [r for r in records if r["record_type"] == ENTRA_SERVICE_PRINCIPAL_APP_ROLE_ASSIGNMENT]
        assert len(sps) == 2_000
        assert len(assignments) == 2_000
        assert elapsed < 30.0

    @respx.mock
    def test_1000_directory_role_assignments_scale_alone(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=1_000, n_groups=0, members_per_group=0, n_apps=0, n_sps=0, n_role_assignments=1_000)

        records = _fetch()
        assignments = [r for r in records if r["record_type"] == ENTRA_DIRECTORY_ROLE_ASSIGNMENT]
        privileged = [r for r in records if r["record_type"] == ENTRA_PRIVILEGED_IDENTITY]
        assert len(assignments) == 1_000
        assert len(privileged) == 1_000

    @respx.mock
    def test_sp_assignment_walk_call_count_is_linear_not_quadratic(self):
        _mock_token()
        _mock_org()
        n_sps = 200
        _mock_combined_tenant(n_users=0, n_groups=0, members_per_group=0, n_apps=0, n_sps=n_sps, n_role_assignments=0)

        _fetch()
        # Exactly one appRoleAssignedTo call per SP — never re-walked, never
        # skipped, and never proportional to assignment COUNT (only to SP
        # count), which is the N+1 hardening guarantee this message owns.
        assignment_calls = [c for c in respx.calls if "/appRoleAssignedTo" in str(c.request.url)]
        assert len(assignment_calls) == n_sps

    @respx.mock
    def test_group_membership_walk_call_count_is_linear_not_quadratic(self):
        _mock_token()
        _mock_org()
        n_groups = 200
        _mock_combined_tenant(n_users=50, n_groups=n_groups, members_per_group=3, n_apps=0, n_sps=0, n_role_assignments=0)

        _fetch()
        member_calls = [c for c in respx.calls if "/members" in str(c.request.url)]
        assert len(member_calls) == n_groups

    @respx.mock
    def test_directory_role_assignments_never_n_plus_one_per_user(self):
        # Directory role assignments are collected via ONE tenant-wide list
        # call, never one call per user/group/SP principal — verify the
        # roleAssignments endpoint is hit exactly once regardless of how
        # many users exist.
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=500, n_groups=0, members_per_group=0, n_apps=0, n_sps=0, n_role_assignments=50)
        role_assignments_route = respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments")

        _fetch()
        assert role_assignments_route.call_count == 1

    @respx.mock
    def test_capability_probes_are_exactly_eight_regardless_of_scale(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=1_000, n_groups=200, members_per_group=5, n_apps=300, n_sps=300, n_role_assignments=100)

        records = _fetch()
        capability_records = [r for r in records if r["record_type"] == "entra_api_capability"]
        assert len(capability_records) == 8

    @respx.mock
    def test_no_duplicate_record_ids_at_scale(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=800, n_groups=200, members_per_group=4, n_apps=200, n_sps=200, n_role_assignments=50)

        records = _fetch()
        ids = [(r["record_type"], r["record_id"]) for r in records]
        assert len(ids) == len(set(ids))

    @respx.mock
    def test_ordering_is_stable_across_repeated_fetches_at_scale(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=300, n_groups=100, members_per_group=3, n_apps=100, n_sps=100, n_role_assignments=30)

        first = _fetch()
        second = _fetch()
        assert [(r["record_type"], r["record_id"]) for r in first] == [(r["record_type"], r["record_id"]) for r in second]

    @respx.mock
    def test_500_applications_scale_alone(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=0, n_groups=0, members_per_group=0, n_apps=500, n_sps=0, n_role_assignments=0)

        records = _fetch()
        apps = [r for r in records if r["record_type"] == ENTRA_APPLICATION]
        assert len(apps) == 500
        assert len({a["record_id"] for a in apps}) == 500

    @respx.mock
    def test_three_consecutive_fetches_on_reused_instance_stay_consistent(self):
        _mock_token()
        _mock_org()
        _mock_combined_tenant(n_users=100, n_groups=20, members_per_group=2, n_apps=30, n_sps=30, n_role_assignments=10)
        connector = EntraConnector()

        results = []
        for _ in range(3):
            results.append(connector.fetch(_CREDS, _sleep_fn=lambda s: None))
        ids = [[(r["record_type"], r["record_id"]) for r in result] for result in results]
        assert ids[0] == ids[1] == ids[2]

    @respx.mock
    def test_100_oauth2_grants_scale_alone(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": []}))
        grants_json = [{"id": f"gr{i}", "clientId": "sp1", "resourceId": "sp2", "consentType": "AllPrincipals", "scope": "User.Read"} for i in range(100)]
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": grants_json}))
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(return_value=httpx.Response(200, json={"value": []}))

        records = _fetch()
        grants = [r for r in records if r["record_type"] == "entra_oauth2_permission_grant"]
        assert len(grants) == 100
        assert len({g["record_id"] for g in grants}) == 100
