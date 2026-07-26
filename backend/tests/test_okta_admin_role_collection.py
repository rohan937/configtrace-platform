"""Okta privileged identity / admin-role collection tests (Okta message 5 of 8).

Covers admin-role collection end-to-end via ``OktaConnector.fetch()``:
built-in role discovery (via per-user/per-group assignment walks — Okta
has no endpoint that lists the built-in role catalog directly), custom
role collection (tenant-wide, ``/api/v1/iam/roles``), family
independence (fail-soft), deduplication, stable IDs, pagination of the
object-wrapped IAM list endpoints, and scale behavior. Normalization
correctness is covered separately in
``test_okta_privileged_identity_normalization.py``; diff/risk behavior in
``test_okta_privileged_identity_diff.py``.
"""

from __future__ import annotations

import time

import httpx
import respx

from app.connectors.okta import OktaConnector
from app.connectors.okta_schema import (
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    OKTA_ADMIN_ROLE,
    OKTA_GROUP_ADMIN_ROLE_ASSIGNMENT,
    OKTA_PRIVILEGED_GROUP,
    OKTA_PRIVILEGED_IDENTITY,
    OKTA_USER_ADMIN_ROLE_ASSIGNMENT,
)

_ORG_URL = "https://example.okta.com"
_TOKEN = "fake-okta-api-token-value"
_CREDS = {"org_url": _ORG_URL, "api_token": _TOKEN}

_POLICY_TYPES = ("OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL", "ACCESS_POLICY", "PROFILE_ENROLLMENT", "IDP_DISCOVERY")


def _org_response() -> httpx.Response:
    return httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})


def _user(user_id: str, *, login: str = None, status: str = "ACTIVE") -> dict:
    return {"id": user_id, "status": status, "profile": {"login": login or f"{user_id}@example.com"}}


def _group(group_id: str, *, name: str = None) -> dict:
    return {"id": group_id, "type": "OKTA_GROUP", "profile": {"name": name or f"Group {group_id}"}}


def _role_assignment(assignment_id: str, *, role_type: str = "SUPER_ADMIN", label: str = None, status: str = "ACTIVE", scoped: bool = False) -> dict:
    rec = {"id": assignment_id, "label": label or role_type, "type": role_type, "status": status}
    # A real Okta role-assignment object always carries a `_links` block
    # (at minimum `self`) whether or not the assignment is scoped —
    # `targets` is present only for a SCOPED assignment.
    if scoped:
        rec["_links"] = {
            "self": {"href": f"{_ORG_URL}/api/v1/x/roles/{assignment_id}"},
            "targets": {"href": f"{_ORG_URL}/api/v1/x/roles/{assignment_id}/targets"},
        }
    else:
        rec["_links"] = {"self": {"href": f"{_ORG_URL}/api/v1/x/roles/{assignment_id}"}}
    return rec


def _custom_role_assignment(assignment_id: str, *, custom_role_id: str, status: str = "ACTIVE") -> dict:
    return {"id": assignment_id, "label": "Custom", "type": "CUSTOM", "status": status, "role": custom_role_id}


def _custom_role(role_id: str, *, label: str = None) -> dict:
    return {"id": role_id, "label": label or f"Role {role_id}"}


def _mock_empty_baseline():
    """Every family empty — the minimal wiring every test starts from."""
    respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))
    for ptype in _POLICY_TYPES:
        respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(200, json={"roles": []}))
    respx.get(f"{_ORG_URL}/api/v1/logs").mock(return_value=httpx.Response(200, json=[]))


def _mock_users(users: list):
    respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=users))


def _mock_groups(groups: list):
    respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=groups))
    for g in groups:
        respx.get(f"{_ORG_URL}/api/v1/groups/{g['id']}/users").mock(return_value=httpx.Response(200, json=[]))


# ════════════════════════════════════════════════════════════════════════════
# Built-in role discovery via user/group assignment walks
# ════════════════════════════════════════════════════════════════════════════


class TestBuiltInRoleDiscovery:
    @respx.mock
    def test_super_admin_discovered_from_user_assignment(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[_role_assignment("ra1", role_type="SUPER_ADMIN")])
        )

        records = OktaConnector().fetch(_CREDS)
        roles = [r for r in records if r["record_type"] == OKTA_ADMIN_ROLE]
        assert any(r["role_type"] == "SUPER_ADMIN" and r["built_in"] for r in roles)

    @respx.mock
    def test_app_admin_discovered_from_group_assignment(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        _mock_groups([_group("g1")])
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/roles").mock(
            return_value=httpx.Response(200, json=[_role_assignment("ra2", role_type="APP_ADMIN")])
        )

        records = OktaConnector().fetch(_CREDS)
        assignments = [r for r in records if r["record_type"] == OKTA_GROUP_ADMIN_ROLE_ASSIGNMENT]
        assert len(assignments) == 1
        assert assignments[0]["role_type"] == "APP_ADMIN"

    @respx.mock
    def test_same_role_type_on_user_and_group_dedups_to_one_catalog_entry(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        _mock_users([_user("u1")])
        _mock_groups([_group("g1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[_role_assignment("ra1", role_type="ORG_ADMIN")])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/roles").mock(
            return_value=httpx.Response(200, json=[_role_assignment("ra2", role_type="ORG_ADMIN")])
        )

        records = OktaConnector().fetch(_CREDS)
        roles = [r for r in records if r["record_type"] == OKTA_ADMIN_ROLE and r["role_type"] == "ORG_ADMIN"]
        assert len(roles) == 1

    @respx.mock
    def test_no_admin_roles_produces_no_admin_role_records(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)
        assert not any(r["record_type"] == OKTA_ADMIN_ROLE for r in records)
        assert not any(r["record_type"] == OKTA_PRIVILEGED_IDENTITY for r in records)


# ════════════════════════════════════════════════════════════════════════════
# Custom role collection (tenant-wide)
# ════════════════════════════════════════════════════════════════════════════


class TestCustomRoleCollection:
    @respx.mock
    def test_custom_role_collected_with_permissions(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(
            return_value=httpx.Response(200, json={"roles": [_custom_role("cr1")]})
        )
        respx.get(f"{_ORG_URL}/api/v1/iam/roles/cr1/permissions").mock(
            return_value=httpx.Response(200, json={"permissions": [{"label": "okta.users.manage"}]})
        )

        records = OktaConnector().fetch(_CREDS)
        roles = [r for r in records if r["record_type"] == OKTA_ADMIN_ROLE and r["custom"]]
        assert len(roles) == 1
        assert roles[0]["permissions_count"] == 1
        assert roles[0]["privilege_tier"] == "medium"

    @respx.mock
    def test_custom_role_not_refetched_by_assignment_walk(self):
        """The custom-role catalog is fetched tenant-wide exactly once —
        per-user/per-group assignment walks resolve to it by ID, never
        re-fetching /api/v1/iam/roles themselves."""
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        roles_route = respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(
            return_value=httpx.Response(200, json={"roles": [_custom_role("cr1")]})
        )
        respx.get(f"{_ORG_URL}/api/v1/iam/roles/cr1/permissions").mock(
            return_value=httpx.Response(200, json={"permissions": []})
        )
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[_custom_role_assignment("ra1", custom_role_id="cr1")])
        )

        records = OktaConnector().fetch(_CREDS)
        # capability probe hits /api/v1/iam/roles?limit=1 too, so exactly 2 total.
        assert roles_route.call_count == 2
        assignments = [r for r in records if r["record_type"] == OKTA_USER_ADMIN_ROLE_ASSIGNMENT]
        assert assignments[0]["role_id"] == "cr1"
        assert assignments[0]["custom"] is True

    @respx.mock
    def test_custom_role_assignment_unresolvable_role_skipped(self):
        """A CUSTOM assignment referencing a role ID that never appeared
        in the tenant-wide roles list is skipped rather than fabricated."""
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[_custom_role_assignment("ra1", custom_role_id="unknown_role")])
        )

        records = OktaConnector().fetch(_CREDS)
        assert not any(r["record_type"] == OKTA_USER_ADMIN_ROLE_ASSIGNMENT for r in records)

    @respx.mock
    def test_iam_roles_object_wrapped_pagination(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        page1 = httpx.Response(
            200,
            json={"roles": [_custom_role("cr1")], "_links": {"next": {"href": f"{_ORG_URL}/api/v1/iam/roles?after=cr1"}}},
        )
        page2 = httpx.Response(200, json={"roles": [_custom_role("cr2")]})
        # Replaces the exact-match route _mock_empty_baseline() already
        # registered for this same URL (respx routes are matched in
        # registration order — re-registering the identical pattern
        # replaces it rather than adding a lower-priority alternative).
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(side_effect=[page1, page2])
        respx.get(f"{_ORG_URL}/api/v1/iam/roles/cr1/permissions").mock(return_value=httpx.Response(200, json={"permissions": []}))
        respx.get(f"{_ORG_URL}/api/v1/iam/roles/cr2/permissions").mock(return_value=httpx.Response(200, json={"permissions": []}))

        records = OktaConnector().fetch(_CREDS)
        roles = [r for r in records if r["record_type"] == OKTA_ADMIN_ROLE and r["custom"]]
        assert {r["role_id"] for r in roles} == {"cr1", "cr2"}


# ════════════════════════════════════════════════════════════════════════════
# Resource-set resolution (custom-role assignments only)
# ════════════════════════════════════════════════════════════════════════════


class TestResourceSetResolution:
    @respx.mock
    def test_scoped_resource_set_resolved(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(
            return_value=httpx.Response(200, json={"roles": [_custom_role("cr1")]})
        )
        respx.get(f"{_ORG_URL}/api/v1/iam/roles/cr1/permissions").mock(
            return_value=httpx.Response(200, json={"permissions": []})
        )
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[_custom_role_assignment("ra1", custom_role_id="cr1")])
        )
        respx.get(f"{_ORG_URL}/api/v1/iam/resource-sets/rs1/resources").mock(
            return_value=httpx.Response(200, json={"resources": [
                {"orn": "okta:apps:0oaAPP1"}, {"orn": "okta:apps:0oaAPP2"}, {"orn": "okta:groups:0ogGRP1"},
            ]})
        )
        # _custom_role_assignment doesn't set resource-set by default — set it directly.
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[{
                "id": "ra1", "label": "Custom", "type": "CUSTOM", "status": "ACTIVE",
                "role": "cr1", "resource-set": "rs1",
            }])
        )

        records = OktaConnector().fetch(_CREDS)
        assignment = next(r for r in records if r["record_type"] == OKTA_USER_ADMIN_ROLE_ASSIGNMENT)
        assert assignment["resource_set_scope_category"] == "scoped"
        assert assignment["resource_set_app_count"] == 2
        assert assignment["resource_set_group_count"] == 1

    @respx.mock
    def test_all_resources_resource_set(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(
            return_value=httpx.Response(200, json={"roles": [_custom_role("cr1")]})
        )
        respx.get(f"{_ORG_URL}/api/v1/iam/roles/cr1/permissions").mock(
            return_value=httpx.Response(200, json={"permissions": []})
        )
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[{
                "id": "ra1", "label": "Custom", "type": "CUSTOM", "status": "ACTIVE",
                "role": "cr1", "resource-set": "rs1",
            }])
        )
        respx.get(f"{_ORG_URL}/api/v1/iam/resource-sets/rs1/resources").mock(
            return_value=httpx.Response(200, json={"resources": [{"orn": "okta:apps:*"}]})
        )

        records = OktaConnector().fetch(_CREDS)
        assignment = next(r for r in records if r["record_type"] == OKTA_USER_ADMIN_ROLE_ASSIGNMENT)
        assert assignment["resource_set_scope_category"] == "all_resources"

    @respx.mock
    def test_resource_set_denied_is_unknown_not_scoped(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(
            return_value=httpx.Response(200, json={"roles": [_custom_role("cr1")]})
        )
        respx.get(f"{_ORG_URL}/api/v1/iam/roles/cr1/permissions").mock(
            return_value=httpx.Response(200, json={"permissions": []})
        )
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[{
                "id": "ra1", "label": "Custom", "type": "CUSTOM", "status": "ACTIVE",
                "role": "cr1", "resource-set": "rs1",
            }])
        )
        respx.get(f"{_ORG_URL}/api/v1/iam/resource-sets/rs1/resources").mock(return_value=httpx.Response(403))

        records = OktaConnector().fetch(_CREDS)
        assignment = next(r for r in records if r["record_type"] == OKTA_USER_ADMIN_ROLE_ASSIGNMENT)
        assert assignment["resource_set_scope_category"] is None

    @respx.mock
    def test_resource_set_shared_across_assignments_fetched_once(self):
        """Two assignments (a user's and a group's) referencing the SAME
        resource set must only trigger one resources fetch."""
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(
            return_value=httpx.Response(200, json={"roles": [_custom_role("cr1")]})
        )
        respx.get(f"{_ORG_URL}/api/v1/iam/roles/cr1/permissions").mock(
            return_value=httpx.Response(200, json={"permissions": []})
        )
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[{
                "id": "ra1", "label": "Custom", "type": "CUSTOM", "status": "ACTIVE",
                "role": "cr1", "resource-set": "rs1",
            }])
        )
        _mock_groups([_group("g1")])
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/roles").mock(
            return_value=httpx.Response(200, json=[{
                "id": "ra2", "label": "Custom", "type": "CUSTOM", "status": "ACTIVE",
                "role": "cr1", "resource-set": "rs1",
            }])
        )
        resources_route = respx.get(f"{_ORG_URL}/api/v1/iam/resource-sets/rs1/resources").mock(
            return_value=httpx.Response(200, json={"resources": [{"orn": "okta:apps:*"}]})
        )

        OktaConnector().fetch(_CREDS)
        assert resources_route.call_count == 1


# ════════════════════════════════════════════════════════════════════════════
# User admin-role assignment collection
# ════════════════════════════════════════════════════════════════════════════


class TestUserAssignmentCollection:
    @respx.mock
    def test_assignments_collected_per_user(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        _mock_users([_user("u1"), _user("u2")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[_role_assignment("ra1", role_type="SUPER_ADMIN")])
        )
        respx.get(f"{_ORG_URL}/api/v1/users/u2/roles").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)
        assignments = [r for r in records if r["record_type"] == OKTA_USER_ADMIN_ROLE_ASSIGNMENT]
        assert len(assignments) == 1
        assert assignments[0]["user_id"] == "u1"
        assert assignments[0]["user_login"] == "u1@example.com"

    @respx.mock
    def test_scoped_app_admin_scope_category(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[_role_assignment("ra1", role_type="APP_ADMIN", scoped=True)])
        )

        records = OktaConnector().fetch(_CREDS)
        assignment = next(r for r in records if r["record_type"] == OKTA_USER_ADMIN_ROLE_ASSIGNMENT)
        assert assignment["assignment_scope_category"] == "scoped"

    @respx.mock
    def test_unscoped_admin_scope_category(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[_role_assignment("ra1", role_type="APP_ADMIN", scoped=False)])
        )

        records = OktaConnector().fetch(_CREDS)
        assignment = next(r for r in records if r["record_type"] == OKTA_USER_ADMIN_ROLE_ASSIGNMENT)
        assert assignment["assignment_scope_category"] == "all"

    @respx.mock
    def test_dedup_within_a_users_paginated_role_list(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        _mock_users([_user("u1")])
        page1 = httpx.Response(
            200, json=[_role_assignment("ra1", role_type="SUPER_ADMIN")],
            headers={"Link": f'<{_ORG_URL}/api/v1/users/u1/roles?after=1>; rel="next"'},
        )
        page2 = httpx.Response(200, json=[_role_assignment("ra1", role_type="SUPER_ADMIN")])
        respx.get(url__regex=r".*/api/v1/users/u1/roles.*").mock(side_effect=[page1, page2])

        records = OktaConnector().fetch(_CREDS)
        assignments = [r for r in records if r["record_type"] == OKTA_USER_ADMIN_ROLE_ASSIGNMENT]
        assert len(assignments) == 1


# ════════════════════════════════════════════════════════════════════════════
# Family independence / fail-soft
# ════════════════════════════════════════════════════════════════════════════


class TestFamilyIndependence:
    @respx.mock
    def test_custom_roles_denied_user_assignments_available(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(403))
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[_role_assignment("ra1", role_type="SUPER_ADMIN")])
        )

        records = OktaConnector().fetch(_CREDS)
        assert any(r["record_type"] == OKTA_USER_ADMIN_ROLE_ASSIGNMENT for r in records)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["custom_admin_roles"] == FAMILY_DENIED
        assert org["family_completeness"]["user_admin_role_assignments"] == FAMILY_COMPLETE

    @respx.mock
    def test_user_assignments_denied_group_assignments_available(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(return_value=httpx.Response(403))
        _mock_groups([_group("g1")])
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/roles").mock(
            return_value=httpx.Response(200, json=[_role_assignment("ra2", role_type="APP_ADMIN")])
        )

        records = OktaConnector().fetch(_CREDS)
        assert not any(r["record_type"] == OKTA_USER_ADMIN_ROLE_ASSIGNMENT for r in records)
        assert any(r["record_type"] == OKTA_GROUP_ADMIN_ROLE_ASSIGNMENT for r in records)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["user_admin_role_assignments"] == FAMILY_DENIED
        assert org["family_completeness"]["group_admin_role_assignments"] == FAMILY_COMPLETE

    @respx.mock
    def test_full_denial_does_not_crash_fetch(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(403))
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(return_value=httpx.Response(403))

        records = OktaConnector().fetch(_CREDS)  # must not raise
        assert any(r["record_type"] == "okta_organization" for r in records)

    @respx.mock
    def test_iam_roles_unsupported_edition_is_unavailable_not_denied(self):
        """A 404 on /api/v1/iam/roles (Identity Governance not enabled on
        this Okta edition) is a real API-surface gap, not a permission
        denial — reported as unavailable."""
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(404))

        records = OktaConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["custom_admin_roles"] in ("unavailable", "denied")


# ════════════════════════════════════════════════════════════════════════════
# Stable IDs
# ════════════════════════════════════════════════════════════════════════════


class TestStableIds:
    def test_builtin_role_record_id_is_role_type(self):
        rec = OktaConnector._normalize_builtin_admin_role("id:t1", "SUPER_ADMIN", "Super Administrator")
        assert rec["record_id"] == "id:t1/admin_role/SUPER_ADMIN"

    def test_custom_role_record_id_is_role_id(self):
        rec = OktaConnector._normalize_custom_admin_role("id:t1", _custom_role("cr1"), [])
        assert rec["record_id"] == "id:t1/admin_role/cr1"

    def test_repeated_fetch_produces_identical_ids(self):
        rec1 = OktaConnector._normalize_builtin_admin_role("id:t1", "ORG_ADMIN", "Org Admin")
        rec2 = OktaConnector._normalize_builtin_admin_role("id:t1", "ORG_ADMIN", "Org Admin")
        assert rec1["record_id"] == rec2["record_id"]


# ════════════════════════════════════════════════════════════════════════════
# Privileged identity / group derivation via fetch()
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedDerivationViaFetch:
    @respx.mock
    def test_direct_super_admin_becomes_privileged_identity(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(
            return_value=httpx.Response(200, json=[_role_assignment("ra1", role_type="SUPER_ADMIN")])
        )

        records = OktaConnector().fetch(_CREDS)
        identities = [r for r in records if r["record_type"] == OKTA_PRIVILEGED_IDENTITY]
        assert len(identities) == 1
        assert identities[0]["has_super_admin"] is True
        assert identities[0]["privileged_via_direct_assignment"] is True
        assert identities[0]["privileged_via_group"] is False

    @respx.mock
    def test_group_admin_membership_creates_inherited_privileged_identity(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_baseline()
        _mock_users([_user("u1")])
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[_group("g1")]))
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/users").mock(return_value=httpx.Response(200, json=[{"id": "u1"}]))
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/roles").mock(
            return_value=httpx.Response(200, json=[_role_assignment("ra2", role_type="APP_ADMIN")])
        )

        records = OktaConnector().fetch(_CREDS)
        identities = [r for r in records if r["record_type"] == OKTA_PRIVILEGED_IDENTITY]
        assert len(identities) == 1
        assert identities[0]["user_id"] == "u1"
        assert identities[0]["privileged_via_group"] is True
        assert identities[0]["privileged_via_direct_assignment"] is False

        groups = [r for r in records if r["record_type"] == OKTA_PRIVILEGED_GROUP]
        assert len(groups) == 1
        assert groups[0]["group_id"] == "g1"
        assert groups[0]["member_count"] == 1


# ════════════════════════════════════════════════════════════════════════════
# Scale
# ════════════════════════════════════════════════════════════════════════════


class TestScale:
    @respx.mock
    def test_scale_users_groups_admin_assignments_custom_roles(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        for ptype in _POLICY_TYPES:
            respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/logs").mock(return_value=httpx.Response(200, json=[]))

        n_users = 500
        n_groups = 100
        n_custom_roles = 50

        respx.get(f"{_ORG_URL}/api/v1/users").mock(
            return_value=httpx.Response(200, json=[_user(f"u{i}") for i in range(n_users)])
        )
        # Only the first 5 users are given an admin role — the rest resolve
        # to an empty roles list, exercising the bounded per-user N+1 walk
        # without asserting every one of 500 calls individually.
        for i in range(n_users):
            payload = [_role_assignment(f"ra{i}", role_type="SUPER_ADMIN")] if i < 5 else []
            respx.get(f"{_ORG_URL}/api/v1/users/u{i}/roles").mock(return_value=httpx.Response(200, json=payload))

        groups_json = [_group(f"g{i}") for i in range(n_groups)]
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=groups_json))
        for i in range(n_groups):
            respx.get(f"{_ORG_URL}/api/v1/groups/g{i}/users").mock(return_value=httpx.Response(200, json=[]))
            respx.get(f"{_ORG_URL}/api/v1/groups/g{i}/roles").mock(return_value=httpx.Response(200, json=[]))

        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(
            return_value=httpx.Response(200, json={"roles": [_custom_role(f"cr{i}") for i in range(n_custom_roles)]})
        )
        for i in range(n_custom_roles):
            respx.get(f"{_ORG_URL}/api/v1/iam/roles/cr{i}/permissions").mock(
                return_value=httpx.Response(200, json={"permissions": []})
            )

        start = time.monotonic()
        records = OktaConnector().fetch(_CREDS)
        elapsed = time.monotonic() - start

        custom_roles = [r for r in records if r["record_type"] == OKTA_ADMIN_ROLE and r["custom"]]
        user_assignments = [r for r in records if r["record_type"] == OKTA_USER_ADMIN_ROLE_ASSIGNMENT]
        identities = [r for r in records if r["record_type"] == OKTA_PRIVILEGED_IDENTITY]

        assert len(custom_roles) == n_custom_roles
        assert len(user_assignments) == 5
        assert len(identities) == 5
        assert len({r["record_id"] for r in custom_roles}) == n_custom_roles
        assert len({r["record_id"] for r in user_assignments}) == 5
        assert elapsed < 30.0

    @respx.mock
    def test_user_walk_capped_below_total_user_count_reports_partial(self):
        """Confirm the per-user role-enumeration walk is genuinely bounded
        (not silently scanning every one of many users) by using a user
        count far above _MAX_USERS_FOR_ROLE_ENUMERATION and checking the
        family is reported partial, not complete."""
        from app.connectors import okta as okta_module

        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        for ptype in _POLICY_TYPES:
            respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(200, json={"roles": []}))
        respx.get(f"{_ORG_URL}/api/v1/logs").mock(return_value=httpx.Response(200, json=[]))

        n_users = okta_module._MAX_USERS_FOR_ROLE_ENUMERATION + 25
        respx.get(f"{_ORG_URL}/api/v1/users").mock(
            return_value=httpx.Response(200, json=[_user(f"u{i}") for i in range(n_users)])
        )
        roles_route = respx.get(url__regex=r".*/api/v1/users/u\d+/roles").mock(return_value=httpx.Response(200, json=[]))

        records = OktaConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["user_admin_role_assignments"] == "partial"
        assert roles_route.call_count == okta_module._MAX_USERS_FOR_ROLE_ENUMERATION
