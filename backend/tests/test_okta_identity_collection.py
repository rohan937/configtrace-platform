"""Okta identity inventory collection tests (Okta message 2 of 8).

Covers user/group/membership collection end-to-end via
``OktaConnector.fetch()``: pagination, family independence (fail-soft),
deduplication, stable IDs, membership-collection strategy (per-group
enumeration), and scale behavior. Normalization correctness is covered
separately in ``test_okta_identity_normalization.py``; diff/risk behavior
in ``test_okta_identity_diff.py``.
"""

from __future__ import annotations

import time

import httpx
import respx

from app.connectors.okta import OktaConnector
from app.connectors.okta_schema import (
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    OKTA_GROUP,
    OKTA_GROUP_MEMBERSHIP,
    OKTA_ORGANIZATION,
    OKTA_USER,
)

_ORG_URL = "https://example.okta.com"
_TOKEN = "fake-okta-api-token-value"
_CREDS = {"org_url": _ORG_URL, "api_token": _TOKEN}


def _org_response() -> httpx.Response:
    return httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})


def _user(user_id: str, *, status: str = "ACTIVE", login: str = None) -> dict:
    return {
        "id": user_id,
        "status": status,
        "created": "2020-01-01T00:00:00.000Z",
        "activated": "2020-01-02T00:00:00.000Z",
        "profile": {
            "login": login or f"{user_id}@example.com",
            "firstName": "First",
            "lastName": "Last",
        },
        "credentials": {"provider": {"type": "OKTA"}},
        "type": {"id": "typ1"},
    }


def _group(group_id: str, *, name: str = None, gtype: str = "OKTA_GROUP") -> dict:
    return {
        "id": group_id,
        "type": gtype,
        "profile": {"name": name or f"Group {group_id}", "description": "A group"},
    }


# ════════════════════════════════════════════════════════════════════════════
# Users collection
# ════════════════════════════════════════════════════════════════════════════


class TestUserCollection:
    @respx.mock
    def test_collects_all_users_single_page(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(
            return_value=httpx.Response(200, json=[_user("u1"), _user("u2")])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        for path in (
            "/api/v1/apps", "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)
        users = [r for r in records if r["record_type"] == OKTA_USER]
        assert len(users) == 2
        assert {u["user_id"] for u in users} == {"u1", "u2"}

    @respx.mock
    def test_collects_users_across_multiple_pages(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        page1 = httpx.Response(
            200, json=[_user("u1")],
            headers={"Link": f'<{_ORG_URL}/api/v1/users?after=u1>; rel="next"'},
        )
        page2 = httpx.Response(200, json=[_user("u2")])
        respx.get(url__regex=r".*/api/v1/users.*").mock(side_effect=[page1, page2])
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        for path in (
            "/api/v1/apps", "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)
        users = [r for r in records if r["record_type"] == OKTA_USER]
        assert {u["user_id"] for u in users} == {"u1", "u2"}


# ════════════════════════════════════════════════════════════════════════════
# Groups collection
# ════════════════════════════════════════════════════════════════════════════


class TestGroupCollection:
    @respx.mock
    def test_collects_all_groups(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(
            return_value=httpx.Response(200, json=[_group("g1"), _group("g2")])
        )
        for path in (
            "/api/v1/apps", "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)
        groups = [r for r in records if r["record_type"] == OKTA_GROUP]
        assert len(groups) == 2
        assert {g["group_id"] for g in groups} == {"g1", "g2"}


# ════════════════════════════════════════════════════════════════════════════
# Membership collection (per-group enumeration strategy)
# ════════════════════════════════════════════════════════════════════════════


class TestMembershipCollection:
    @respx.mock
    def test_membership_collected_per_group(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(
            return_value=httpx.Response(200, json=[_user("u1"), _user("u2")])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(
            return_value=httpx.Response(200, json=[_group("g1")])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/users").mock(
            return_value=httpx.Response(200, json=[_user("u1"), _user("u2")])
        )
        for path in (
            "/api/v1/apps", "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)
        memberships = [r for r in records if r["record_type"] == OKTA_GROUP_MEMBERSHIP]
        assert len(memberships) == 2
        assert {m["user_id"] for m in memberships} == {"u1", "u2"}
        assert all(m["group_id"] == "g1" for m in memberships)

    @respx.mock
    def test_does_not_call_per_user_groups_endpoint(self):
        """Confirms the chosen strategy is group->users, not user->groups —
        the per-user endpoint must never be called."""
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(
            return_value=httpx.Response(200, json=[_user("u1")])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(
            return_value=httpx.Response(200, json=[_group("g1")])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/users").mock(
            return_value=httpx.Response(200, json=[_user("u1")])
        )
        per_user_groups_route = respx.get(f"{_ORG_URL}/api/v1/users/u1/groups").mock(
            return_value=httpx.Response(200, json=[])
        )
        for path in (
            "/api/v1/apps", "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))

        OktaConnector().fetch(_CREDS)
        assert per_user_groups_route.call_count == 0

    @respx.mock
    def test_group_with_zero_users(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(
            return_value=httpx.Response(200, json=[_group("g1")])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/users").mock(
            return_value=httpx.Response(200, json=[])
        )
        for path in (
            "/api/v1/apps", "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)
        memberships = [r for r in records if r["record_type"] == OKTA_GROUP_MEMBERSHIP]
        assert memberships == []
        group = next(r for r in records if r["record_type"] == OKTA_GROUP)
        assert group["membership_count"] == 0

    @respx.mock
    def test_no_groups_at_all_is_complete_not_denied(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        for path in (
            "/api/v1/apps", "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == OKTA_ORGANIZATION)
        assert org["family_completeness"]["memberships"] == FAMILY_COMPLETE


# ════════════════════════════════════════════════════════════════════════════
# Family independence / fail-soft
# ════════════════════════════════════════════════════════════════════════════


class TestFamilyIndependence:
    @respx.mock
    def test_users_available_groups_available_memberships_denied(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(
            return_value=httpx.Response(200, json=[_user("u1")])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(
            return_value=httpx.Response(200, json=[_group("g1")])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/users").mock(return_value=httpx.Response(403))
        for path in (
            "/api/v1/apps", "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)
        # users/groups retained despite membership denial
        assert any(r["record_type"] == OKTA_USER for r in records)
        assert any(r["record_type"] == OKTA_GROUP for r in records)
        assert not any(r["record_type"] == OKTA_GROUP_MEMBERSHIP for r in records)

        org = next(r for r in records if r["record_type"] == OKTA_ORGANIZATION)
        assert org["family_completeness"]["users"] == FAMILY_COMPLETE
        assert org["family_completeness"]["groups"] == FAMILY_COMPLETE
        assert org["family_completeness"]["memberships"] == FAMILY_DENIED

        # membership denial must never be reported as "zero memberships"
        group = next(r for r in records if r["record_type"] == OKTA_GROUP)
        assert group["membership_count"] is None

    @respx.mock
    def test_users_denied_groups_and_memberships_still_attempted(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(403))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(
            return_value=httpx.Response(200, json=[_group("g1")])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/users").mock(
            return_value=httpx.Response(200, json=[])
        )
        for path in (
            "/api/v1/apps", "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)  # must not raise
        assert not any(r["record_type"] == OKTA_USER for r in records)
        assert any(r["record_type"] == OKTA_GROUP for r in records)
        org = next(r for r in records if r["record_type"] == OKTA_ORGANIZATION)
        assert org["family_completeness"]["users"] == FAMILY_DENIED

    @respx.mock
    def test_sync_does_not_fail_entirely_on_partial_denial(self):
        """The whole fetch() call must not raise when only a non-org family
        is denied."""
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(403))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(403))
        for path in (
            "/api/v1/apps", "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)  # must not raise
        assert any(r["record_type"] == OKTA_ORGANIZATION for r in records)


# ════════════════════════════════════════════════════════════════════════════
# Deduplication / stable IDs
# ════════════════════════════════════════════════════════════════════════════


class TestDedupAndStableIds:
    @respx.mock
    def test_membership_dedup_within_a_group(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(
            return_value=httpx.Response(200, json=[_user("u1")])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(
            return_value=httpx.Response(200, json=[_group("g1")])
        )
        # Overlapping pages re-serve u1 — paginate()'s own id-dedup handles this.
        page1 = httpx.Response(
            200, json=[_user("u1")],
            headers={"Link": f'<{_ORG_URL}/api/v1/groups/g1/users?after=1>; rel="next"'},
        )
        page2 = httpx.Response(200, json=[_user("u1")])
        respx.get(url__regex=r".*/api/v1/groups/g1/users.*").mock(side_effect=[page1, page2])
        for path in (
            "/api/v1/apps", "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)
        memberships = [r for r in records if r["record_type"] == OKTA_GROUP_MEMBERSHIP]
        assert len(memberships) == 1

    def test_stable_record_ids_prefer_tenant_plus_okta_id(self):
        tenant_id = "id:t1"
        user_rec = OktaConnector._normalize_user(tenant_id, _user("u1"))
        assert user_rec["record_id"] == f"{tenant_id}/user/u1"
        group_rec = OktaConnector._normalize_group(tenant_id, _group("g1"), membership_count=0)
        assert group_rec["record_id"] == f"{tenant_id}/group/g1"

    def test_login_change_same_user_id_is_same_record_id(self):
        tenant_id = "id:t1"
        rec1 = OktaConnector._normalize_user(tenant_id, _user("u1", login="old@example.com"))
        rec2 = OktaConnector._normalize_user(tenant_id, _user("u1", login="new@example.com"))
        assert rec1["record_id"] == rec2["record_id"]
        assert rec1["login"] != rec2["login"]


# ════════════════════════════════════════════════════════════════════════════
# Scale
# ════════════════════════════════════════════════════════════════════════════


class TestScale:
    @respx.mock
    def test_2000_users_500_groups_10000_memberships(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())

        n_users = 2000
        n_groups = 500
        users_json = [_user(f"u{i}") for i in range(n_users)]
        groups_json = [_group(f"g{i}") for i in range(n_groups)]

        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=users_json))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=groups_json))

        # 20 members per group * 500 groups = 10,000 memberships.
        members_per_group = 20
        for gi in range(n_groups):
            member_slice = [_user(f"u{(gi * members_per_group + k) % n_users}") for k in range(members_per_group)]
            respx.get(f"{_ORG_URL}/api/v1/groups/g{gi}/users").mock(
                return_value=httpx.Response(200, json=member_slice)
            )

        for path in (
            "/api/v1/apps", "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))

        start = time.monotonic()
        records = OktaConnector().fetch(_CREDS)
        elapsed = time.monotonic() - start

        users = [r for r in records if r["record_type"] == OKTA_USER]
        groups = [r for r in records if r["record_type"] == OKTA_GROUP]
        memberships = [r for r in records if r["record_type"] == OKTA_GROUP_MEMBERSHIP]

        assert len(users) == n_users
        assert len(groups) == n_groups
        assert len(memberships) == n_groups * members_per_group
        # Stable IDs: every user/group record_id is unique.
        assert len({u["record_id"] for u in users}) == n_users
        assert len({g["record_id"] for g in groups}) == n_groups
        # No pathological wall-clock blowup (generous, non-flaky bound —
        # this is pure in-memory normalization against mocked HTTP, so
        # even a slow CI box should finish well under this).
        assert elapsed < 30.0
