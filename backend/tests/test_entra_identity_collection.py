"""Microsoft Entra ID identity inventory collection tests (Entra message 2
of 8).

Covers user/group/membership collection end-to-end via
``EntraConnector.fetch()``: pagination, family independence (fail-soft),
deduplication, stable IDs, membership-collection strategy (per-group
enumeration, group->members direction), non-user member exclusion, and
scale behavior. Normalization correctness is covered separately in
``test_entra_identity_normalization.py``; diff/risk behavior in
``test_entra_identity_diff.py``.
"""

from __future__ import annotations

import time

import httpx
import respx

from app.connectors.entra import EntraConnector
from app.connectors.entra_schema import (
    ENTRA_GROUP,
    ENTRA_GROUP_MEMBERSHIP,
    ENTRA_ORGANIZATION,
    ENTRA_USER,
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
    "applications", "servicePrincipals", "identity/conditionalAccess/policies",
    "policies/authenticationMethodsPolicy", "directoryRoles", "oauth2PermissionGrants",
)


def _mock_token():
    respx.post(_TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600}))


def _mock_org():
    respx.get(f"{_GRAPH}/organization").mock(
        return_value=httpx.Response(200, json={"value": [{"id": _TENANT_ID, "displayName": "Example Corp"}]})
    )


def _mock_optional_families_empty():
    for path in _OPTIONAL_FAMILY_PATHS:
        respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))


def _user(user_id: str, *, upn: str = None, enabled: bool = True, user_type: str = "Member") -> dict:
    return {
        "id": user_id,
        "userPrincipalName": upn or f"{user_id}@example.com",
        "displayName": f"User {user_id}",
        "accountEnabled": enabled,
        "userType": user_type,
        "createdDateTime": "2020-01-01T00:00:00Z",
    }


def _group(group_id: str, *, name: str = None) -> dict:
    return {
        "id": group_id,
        "displayName": name or f"Group {group_id}",
        "securityEnabled": True,
        "mailEnabled": False,
        "groupTypes": [],
        "isAssignableToRole": False,
    }


def _member_ref(user_id: str) -> dict:
    return {"id": user_id, "@odata.type": "#microsoft.graph.user"}


# ════════════════════════════════════════════════════════════════════════════
# Users collection
# ════════════════════════════════════════════════════════════════════════════


class TestUserCollection:
    @respx.mock
    def test_collects_all_users_single_page(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [_user("u1"), _user("u2")]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)
        users = [r for r in records if r["record_type"] == ENTRA_USER]
        assert len(users) == 2
        assert {u["user_id"] for u in users} == {"u1", "u2"}

    @respx.mock
    def test_collects_users_across_multiple_pages(self):
        _mock_token()
        _mock_org()
        page1 = httpx.Response(
            200, json={"value": [_user("u1")], "@odata.nextLink": f"{_GRAPH}/users?skip=1"},
        )
        page2 = httpx.Response(200, json={"value": [_user("u2")]})
        respx.get(url__regex=r".*/users.*").mock(side_effect=[page1, page2])
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)
        users = [r for r in records if r["record_type"] == ENTRA_USER]
        assert {u["user_id"] for u in users} == {"u1", "u2"}

    @respx.mock
    def test_users_select_uses_explicit_allowlist(self):
        _mock_token()
        _mock_org()
        route = respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_optional_families_empty()

        EntraConnector().fetch(_CREDS)
        select_param = route.calls[0].request.url.params.get("$select")
        assert select_param == EntraConnector._USER_SELECT
        assert "mobilePhone" not in select_param
        assert "passwordProfile" not in select_param


# ════════════════════════════════════════════════════════════════════════════
# Groups collection
# ════════════════════════════════════════════════════════════════════════════


class TestGroupCollection:
    @respx.mock
    def test_collects_all_groups(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [_group("g1"), _group("g2")]}))
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)
        groups = [r for r in records if r["record_type"] == ENTRA_GROUP]
        assert len(groups) == 2
        assert {g["group_id"] for g in groups} == {"g1", "g2"}

    @respx.mock
    def test_groups_select_uses_explicit_allowlist(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        route = respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_optional_families_empty()

        EntraConnector().fetch(_CREDS)
        select_param = route.calls[0].request.url.params.get("$select")
        assert select_param == EntraConnector._GROUP_SELECT
        assert "membershipRule" not in select_param
        assert "owners" not in select_param


# ════════════════════════════════════════════════════════════════════════════
# Membership collection (per-group enumeration strategy)
# ════════════════════════════════════════════════════════════════════════════


class TestMembershipCollection:
    @respx.mock
    def test_membership_collected_per_group(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [_user("u1"), _user("u2")]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [_group("g1")]}))
        respx.get(f"{_GRAPH}/groups/g1/members").mock(
            return_value=httpx.Response(200, json={"value": [_member_ref("u1"), _member_ref("u2")]})
        )
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)
        memberships = [r for r in records if r["record_type"] == ENTRA_GROUP_MEMBERSHIP]
        assert len(memberships) == 2
        assert {m["user_id"] for m in memberships} == {"u1", "u2"}
        assert all(m["group_id"] == "g1" for m in memberships)

    @respx.mock
    def test_does_not_call_per_user_memberof_endpoint(self):
        """Confirms the chosen strategy is group->members, not user->memberOf
        — the per-user endpoint must never be called."""
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [_user("u1")]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [_group("g1")]}))
        respx.get(f"{_GRAPH}/groups/g1/members").mock(
            return_value=httpx.Response(200, json={"value": [_member_ref("u1")]})
        )
        per_user_route = respx.get(f"{_GRAPH}/users/u1/memberOf").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_optional_families_empty()

        EntraConnector().fetch(_CREDS)
        assert per_user_route.call_count == 0

    @respx.mock
    def test_group_with_zero_members(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [_group("g1")]}))
        respx.get(f"{_GRAPH}/groups/g1/members").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)
        memberships = [r for r in records if r["record_type"] == ENTRA_GROUP_MEMBERSHIP]
        assert memberships == []
        group = next(r for r in records if r["record_type"] == ENTRA_GROUP)
        assert group["membership_count"] == 0

    @respx.mock
    def test_no_groups_at_all_is_complete_not_denied(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["memberships"] == FAMILY_COMPLETE

    @respx.mock
    def test_non_user_directory_member_excluded(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [_user("u1")]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [_group("g1")]}))
        respx.get(f"{_GRAPH}/groups/g1/members").mock(
            return_value=httpx.Response(200, json={"value": [
                _member_ref("u1"),
                {"id": "sp1", "@odata.type": "#microsoft.graph.servicePrincipal"},
                {"id": "dev1", "@odata.type": "#microsoft.graph.device"},
                {"id": "g2", "@odata.type": "#microsoft.graph.group"},
            ]})
        )
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)
        memberships = [r for r in records if r["record_type"] == ENTRA_GROUP_MEMBERSHIP]
        assert len(memberships) == 1
        assert memberships[0]["user_id"] == "u1"
        group = next(r for r in records if r["record_type"] == ENTRA_GROUP)
        assert group["membership_count"] == 1

    @respx.mock
    def test_nested_group_not_flattened_into_membership(self):
        """A nested group member must never appear as a user membership
        record, and must not be silently counted."""
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [_group("g1"), _group("g2")]}))
        respx.get(f"{_GRAPH}/groups/g1/members").mock(
            return_value=httpx.Response(200, json={"value": [{"id": "g2", "@odata.type": "#microsoft.graph.group"}]})
        )
        respx.get(f"{_GRAPH}/groups/g2/members").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)
        memberships = [r for r in records if r["record_type"] == ENTRA_GROUP_MEMBERSHIP]
        assert memberships == []


# ════════════════════════════════════════════════════════════════════════════
# Family independence / fail-soft
# ════════════════════════════════════════════════════════════════════════════


class TestFamilyIndependence:
    @respx.mock
    def test_users_available_groups_available_memberships_denied(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [_user("u1")]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [_group("g1")]}))
        respx.get(f"{_GRAPH}/groups/g1/members").mock(return_value=httpx.Response(403))
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)
        assert any(r["record_type"] == ENTRA_USER for r in records)
        assert any(r["record_type"] == ENTRA_GROUP for r in records)
        assert not any(r["record_type"] == ENTRA_GROUP_MEMBERSHIP for r in records)

        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["users"] == FAMILY_COMPLETE
        assert org["family_completeness"]["groups"] == FAMILY_COMPLETE
        assert org["family_completeness"]["memberships"] == FAMILY_DENIED

        group = next(r for r in records if r["record_type"] == ENTRA_GROUP)
        assert group["membership_count"] is None

    @respx.mock
    def test_users_denied_groups_and_memberships_still_attempted(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(403))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [_group("g1")]}))
        respx.get(f"{_GRAPH}/groups/g1/members").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)  # must not raise
        assert not any(r["record_type"] == ENTRA_USER for r in records)
        assert any(r["record_type"] == ENTRA_GROUP for r in records)
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["users"] == FAMILY_DENIED

    @respx.mock
    def test_fetch_does_not_fail_entirely_on_partial_denial(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(403))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(403))
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)  # must not raise
        assert any(r["record_type"] == ENTRA_ORGANIZATION for r in records)


# ════════════════════════════════════════════════════════════════════════════
# Deduplication / stable IDs / call counts
# ════════════════════════════════════════════════════════════════════════════


class TestDedupAndStableIds:
    @respx.mock
    def test_membership_dedup_within_a_group(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [_user("u1")]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": [_group("g1")]}))
        page1 = httpx.Response(
            200, json={"value": [_member_ref("u1")], "@odata.nextLink": f"{_GRAPH}/groups/g1/members?skip=1"},
        )
        page2 = httpx.Response(200, json={"value": [_member_ref("u1")]})
        respx.get(url__regex=r".*/groups/g1/members.*").mock(side_effect=[page1, page2])
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)
        memberships = [r for r in records if r["record_type"] == ENTRA_GROUP_MEMBERSHIP]
        assert len(memberships) == 1

    def test_stable_record_ids_prefer_tenant_plus_object_id(self):
        tenant_id = "id:t1"
        user_rec = EntraConnector._normalize_user(tenant_id, _user("u1"))
        assert user_rec["record_id"] == f"{tenant_id}/user/u1"
        group_rec = EntraConnector._normalize_group(tenant_id, _group("g1"), membership_count=0)
        assert group_rec["record_id"] == f"{tenant_id}/group/g1"

    def test_upn_rename_same_object_id_is_same_record_id(self):
        tenant_id = "id:t1"
        rec1 = EntraConnector._normalize_user(tenant_id, _user("u1", upn="old@example.com"))
        rec2 = EntraConnector._normalize_user(tenant_id, _user("u1", upn="new@example.com"))
        assert rec1["record_id"] == rec2["record_id"]
        assert rec1["user_principal_name"] != rec2["user_principal_name"]

    def test_missing_user_id_rejected(self):
        assert EntraConnector._normalize_user("id:t1", {"userPrincipalName": "no-id@example.com"}) is None

    def test_missing_group_id_rejected(self):
        assert EntraConnector._normalize_group("id:t1", {"displayName": "no id"}, membership_count=0) is None

    @respx.mock
    def test_deterministic_ordering_independent_of_api_response_order(self):
        _mock_token()
        _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": [_user("u2"), _user("u1")]}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_optional_families_empty()

        records = EntraConnector().fetch(_CREDS)
        user_ids = [r["user_id"] for r in records if r["record_type"] == ENTRA_USER]
        assert user_ids == sorted(user_ids)


# ════════════════════════════════════════════════════════════════════════════
# N+1 / call-count audit
# ════════════════════════════════════════════════════════════════════════════


class TestCallCount:
    @respx.mock
    def test_membership_walk_is_group_directed_bounded_call_count(self):
        """One /members call per group, never one /memberOf call per user —
        confirms the chosen direction bounds total request count to
        O(groups), not O(users)."""
        _mock_token()
        _mock_org()
        n_users = 50
        n_groups = 5
        respx.get(f"{_GRAPH}/users").mock(
            return_value=httpx.Response(200, json={"value": [_user(f"u{i}") for i in range(n_users)]})
        )
        respx.get(f"{_GRAPH}/groups").mock(
            return_value=httpx.Response(200, json={"value": [_group(f"g{i}") for i in range(n_groups)]})
        )
        members_route = respx.get(url__regex=r".*/groups/g\d+/members.*").mock(
            return_value=httpx.Response(200, json={"value": []})
        )
        _mock_optional_families_empty()

        EntraConnector().fetch(_CREDS)
        assert members_route.call_count == n_groups


# ════════════════════════════════════════════════════════════════════════════
# Scale
# ════════════════════════════════════════════════════════════════════════════


class TestScale:
    @respx.mock
    def test_5000_users_2000_groups_with_memberships(self):
        _mock_token()
        _mock_org()

        n_users = 5000
        n_groups = 2000
        users_json = [_user(f"u{i}") for i in range(n_users)]
        groups_json = [_group(f"g{i}") for i in range(n_groups)]

        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": users_json}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": groups_json}))

        # 10 members per group * 2000 groups = 20,000 memberships.
        members_per_group = 10
        for gi in range(n_groups):
            member_slice = [
                _member_ref(f"u{(gi * members_per_group + k) % n_users}") for k in range(members_per_group)
            ]
            respx.get(f"{_GRAPH}/groups/g{gi}/members").mock(
                return_value=httpx.Response(200, json={"value": member_slice})
            )

        _mock_optional_families_empty()

        start = time.monotonic()
        records = EntraConnector().fetch(_CREDS)
        elapsed = time.monotonic() - start

        users = [r for r in records if r["record_type"] == ENTRA_USER]
        groups = [r for r in records if r["record_type"] == ENTRA_GROUP]
        memberships = [r for r in records if r["record_type"] == ENTRA_GROUP_MEMBERSHIP]

        assert len(users) == n_users
        assert len(groups) == n_groups
        assert len(memberships) == n_groups * members_per_group
        assert len({u["record_id"] for u in users}) == n_users
        assert len({g["record_id"] for g in groups}) == n_groups
        assert len({m["record_id"] for m in memberships}) == len(memberships)
        # No pathological wall-clock blowup (generous, non-flaky bound).
        assert elapsed < 60.0
