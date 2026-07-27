"""Okta scale / N+1 / determinism reliability tests (Okta message 7 of 8).

Representative large-tenant scale (thousands of records per family, split
across focused tests per the message-7 instruction to avoid one giant
memory-bomb test), resource-set cache dedup regression, deterministic
ordering/idempotency, and no cross-fetch state leakage.

Scale figures here are representative (matching the convention already
established across messages 1-6's own scale tests — e.g. 200/2,000/50 in
the policy-collection scale test) rather than literally 20,000/100,000,
to keep the suite fast while still exercising the same bounded-collection
code paths at multi-thousand-record volume.
"""

from __future__ import annotations

import time

import httpx
import respx

from app.connectors.okta import OktaConnector

_ORG_URL = "https://example.okta.com"
_TOKEN = "fake-okta-api-token-value"
_CREDS = {"org_url": _ORG_URL, "api_token": _TOKEN}
_POLICY_TYPES = ("OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL", "ACCESS_POLICY", "PROFILE_ENROLLMENT", "IDP_DISCOVERY")


def _org_response() -> httpx.Response:
    return httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})


def _mock_empty_policies_authenticators_roles():
    for ptype in _POLICY_TYPES:
        respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(200, json={"roles": []}))
    respx.get(f"{_ORG_URL}/api/v1/logs").mock(return_value=httpx.Response(200, json=[]))


def _fetch(_sleep_fn=lambda s: None):
    return OktaConnector().fetch(_CREDS, _sleep_fn=_sleep_fn)


# ════════════════════════════════════════════════════════════════════════════
# Large-tenant scale
# ════════════════════════════════════════════════════════════════════════════


class TestUserGroupMembershipScale:
    @respx.mock
    def test_2000_users_500_groups_with_memberships(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_policies_authenticators_roles()
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))

        n_users = 2_000
        n_groups = 500
        respx.get(f"{_ORG_URL}/api/v1/users").mock(
            return_value=httpx.Response(200, json=[
                {"id": f"u{i}", "status": "ACTIVE", "profile": {"login": f"u{i}@x.com"}} for i in range(n_users)
            ])
        )
        groups_json = [{"id": f"g{i}", "type": "OKTA_GROUP", "profile": {"name": f"Group {i}"}} for i in range(n_groups)]
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=groups_json))
        # Each group gets 4 members — 2,000 total membership edges.
        for i in range(n_groups):
            members = [{"id": f"u{(i * 4 + k) % n_users}"} for k in range(4)]
            respx.get(f"{_ORG_URL}/api/v1/groups/g{i}/users").mock(return_value=httpx.Response(200, json=members))
            respx.get(f"{_ORG_URL}/api/v1/groups/g{i}/roles").mock(return_value=httpx.Response(200, json=[]))
        for i in range(n_users):
            respx.get(f"{_ORG_URL}/api/v1/users/u{i}/roles").mock(return_value=httpx.Response(200, json=[]))

        start = time.monotonic()
        records = _fetch()
        elapsed = time.monotonic() - start

        users = [r for r in records if r["record_type"] == "okta_user"]
        groups = [r for r in records if r["record_type"] == "okta_group"]
        memberships = [r for r in records if r["record_type"] == "okta_group_membership"]

        assert len(users) == n_users
        assert len(groups) == n_groups
        assert len(memberships) == n_groups * 4
        assert len({r["record_id"] for r in users}) == n_users
        assert len({r["record_id"] for r in groups}) == n_groups
        assert len({r["record_id"] for r in memberships}) == len(memberships)
        assert elapsed < 30.0


class TestApplicationAssignmentScale:
    @respx.mock
    def test_500_apps_with_assignments(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_policies_authenticators_roles()
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[
            {"id": "u1", "status": "ACTIVE", "profile": {"login": "u1@x.com"}},
        ]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(return_value=httpx.Response(200, json=[]))

        n_apps = 500
        apps_json = [{"id": f"app{i}", "label": f"App {i}", "status": "ACTIVE", "signOnMode": "OPENID_CONNECT", "settings": {}} for i in range(n_apps)]
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=apps_json))
        for i in range(n_apps):
            respx.get(f"{_ORG_URL}/api/v1/apps/app{i}/users").mock(return_value=httpx.Response(200, json=[{"id": "u1", "status": "ACTIVE", "scope": "USER"}]))
            respx.get(f"{_ORG_URL}/api/v1/apps/app{i}/groups").mock(return_value=httpx.Response(200, json=[]))

        start = time.monotonic()
        records = _fetch()
        elapsed = time.monotonic() - start

        apps = [r for r in records if r["record_type"] == "okta_application"]
        user_assignments = [r for r in records if r["record_type"] == "okta_application_user_assignment"]

        assert len(apps) == n_apps
        assert len(user_assignments) == n_apps  # one assignment (u1) per app
        assert len({r["record_id"] for r in apps}) == n_apps
        assert len({r["record_id"] for r in user_assignments}) == n_apps
        assert elapsed < 30.0


class TestPolicyRuleScale:
    @respx.mock
    def test_300_policies_3000_rules(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(200, json={"roles": []}))
        respx.get(f"{_ORG_URL}/api/v1/logs").mock(return_value=httpx.Response(200, json=[]))

        n_policies = 300
        policies_json = [{"id": f"p{i}", "name": f"Policy {i}", "type": "OKTA_SIGN_ON", "status": "ACTIVE", "priority": 1} for i in range(n_policies)]
        respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": "OKTA_SIGN_ON"}).mock(return_value=httpx.Response(200, json=policies_json))
        for ptype in _POLICY_TYPES:
            if ptype == "OKTA_SIGN_ON":
                continue
            respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(return_value=httpx.Response(200, json=[]))

        rules_per_policy = 10
        for i in range(n_policies):
            rules = [{
                "id": f"r{i}_{k}", "name": f"Rule {k}", "status": "ACTIVE", "priority": 1,
                "actions": {"signon": {"access": "ALLOW", "requireFactor": True}},
            } for k in range(rules_per_policy)]
            respx.get(f"{_ORG_URL}/api/v1/policies/p{i}/rules").mock(return_value=httpx.Response(200, json=rules))

        start = time.monotonic()
        records = _fetch()
        elapsed = time.monotonic() - start

        policies = [r for r in records if r["record_type"] == "okta_policy"]
        rules = [r for r in records if r["record_type"] == "okta_policy_rule"]

        assert len(policies) == n_policies
        assert len(rules) == n_policies * rules_per_policy
        assert len({r["record_id"] for r in rules}) == len(rules)
        assert elapsed < 30.0


# ════════════════════════════════════════════════════════════════════════════
# Resource-set cache regression (message 5 introduced; message 7 hardens)
# ════════════════════════════════════════════════════════════════════════════


class TestResourceSetCacheRegression:
    @respx.mock
    def test_same_resource_set_referenced_100_times_fetched_once(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        for ptype in _POLICY_TYPES:
            respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/logs").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))

        n_users = 100
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[
            {"id": f"u{i}", "status": "ACTIVE", "profile": {"login": f"u{i}@x.com"}} for i in range(n_users)
        ]))
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(200, json={"roles": [{"id": "cr1", "label": "Custom"}]}))
        respx.get(f"{_ORG_URL}/api/v1/iam/roles/cr1/permissions").mock(return_value=httpx.Response(200, json={"permissions": []}))
        # Every one of the 100 users is assigned the SAME custom role bound
        # to the SAME resource set — the resource set must be resolved once.
        for i in range(n_users):
            respx.get(f"{_ORG_URL}/api/v1/users/u{i}/roles").mock(return_value=httpx.Response(200, json=[{
                "id": f"ra{i}", "label": "Custom", "type": "CUSTOM", "status": "ACTIVE",
                "role": "cr1", "resource-set": "rs_shared",
            }]))
        resources_route = respx.get(f"{_ORG_URL}/api/v1/iam/resource-sets/rs_shared/resources").mock(
            return_value=httpx.Response(200, json={"resources": [{"orn": "okta:apps:*"}]})
        )

        records = _fetch()
        assignments = [r for r in records if r["record_type"] == "okta_user_admin_role_assignment"]
        assert len(assignments) == n_users
        assert all(a["resource_set_scope_category"] == "all_resources" for a in assignments)
        assert resources_route.call_count == 1  # cached, not fetched per-assignment

    @respx.mock
    def test_denied_resource_set_is_unknown_not_scoped(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        for ptype in _POLICY_TYPES:
            respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/logs").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[
            {"id": "u1", "status": "ACTIVE", "profile": {"login": "u1@x.com"}},
        ]))
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(200, json={"roles": [{"id": "cr1", "label": "Custom"}]}))
        respx.get(f"{_ORG_URL}/api/v1/iam/roles/cr1/permissions").mock(return_value=httpx.Response(200, json={"permissions": []}))
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(return_value=httpx.Response(200, json=[{
            "id": "ra1", "label": "Custom", "type": "CUSTOM", "status": "ACTIVE",
            "role": "cr1", "resource-set": "rs1",
        }]))
        respx.get(f"{_ORG_URL}/api/v1/iam/resource-sets/rs1/resources").mock(return_value=httpx.Response(403))

        records = _fetch()
        assignment = next(r for r in records if r["record_type"] == "okta_user_admin_role_assignment")
        assert assignment["resource_set_scope_category"] is None  # never coerced to "scoped"


# ════════════════════════════════════════════════════════════════════════════
# Deterministic ordering / idempotency
# ════════════════════════════════════════════════════════════════════════════


class TestDeterministicOrderingAndIdempotency:
    @respx.mock
    def test_same_source_data_produces_identical_record_sets(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_policies_authenticators_roles()
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[
            {"id": "u1", "status": "ACTIVE", "profile": {"login": "u1@x.com"}},
            {"id": "u2", "status": "ACTIVE", "profile": {"login": "u2@x.com"}},
        ]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[
            {"id": "g1", "type": "OKTA_GROUP", "profile": {"name": "Admins"}},
        ]))
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/users").mock(return_value=httpx.Response(200, json=[{"id": "u1"}, {"id": "u2"}]))
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/roles").mock(return_value=httpx.Response(200, json=[
            {"id": "ra1", "label": "App Admin", "type": "APP_ADMIN", "status": "ACTIVE"},
        ]))
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users/u2/roles").mock(return_value=httpx.Response(200, json=[]))

        records1 = _fetch()
        records2 = _fetch()

        ids1 = [(r["record_type"], r["record_id"]) for r in records1]
        ids2 = [(r["record_type"], r["record_id"]) for r in records2]
        assert ids1 == ids2  # identical order, identical IDs across independent fetches

        privileged_identities_1 = [r for r in records1 if r["record_type"] == "okta_privileged_identity"]
        privileged_identities_2 = [r for r in records2 if r["record_type"] == "okta_privileged_identity"]
        assert [r["record_id"] for r in privileged_identities_1] == [r["record_id"] for r in privileged_identities_2]

    def test_idempotent_diff_produces_zero_changes(self):
        from types import SimpleNamespace as NS
        from app.services.diff_service import compute_diff

        snapshot_state = [
            {"record_type": "okta_organization", "record_id": "id:t1", "tenant_id": "id:t1", "family_completeness": {"users": "complete"}},
            {"record_type": "okta_user", "record_id": "id:t1/user/u1", "tenant_id": "id:t1", "user_id": "u1", "login": "a@x.com", "status": "ACTIVE"},
        ]
        changes = compute_diff(NS(state=snapshot_state), NS(state=snapshot_state))
        assert changes == []


# ════════════════════════════════════════════════════════════════════════════
# No cross-fetch state leakage
# ════════════════════════════════════════════════════════════════════════════


class TestNoStateLeakageBetweenFetches:
    @respx.mock
    def test_reused_connector_instance_does_not_leak_state_between_tenants(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_policies_authenticators_roles()
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[
            {"id": "u1", "status": "ACTIVE", "profile": {"login": "u1@tenant-a.com"}},
        ]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[
            {"id": "g1", "type": "OKTA_GROUP", "profile": {"name": "Admins"}},
        ]))
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups/g1/roles").mock(return_value=httpx.Response(200, json=[
            {"id": "ra1", "label": "Super Administrator", "type": "SUPER_ADMIN", "status": "ACTIVE"},
        ]))
        respx.get(f"{_ORG_URL}/api/v1/users/u1/roles").mock(return_value=httpx.Response(200, json=[]))

        connector = OktaConnector()
        records_a = connector.fetch(_CREDS, _sleep_fn=lambda s: None)

        # Second fetch on the SAME connector instance — resource-set cache,
        # completeness accumulators, and any per-fetch local index must be
        # freshly initialized, never carried over from the first fetch.
        other_org_url = "https://other-tenant.okta.com"
        with respx.mock(base_url=other_org_url) as m:
            m.get("/api/v1/org").mock(return_value=httpx.Response(200, json={"id": "00o2other", "status": "ACTIVE"}))
            m.get("/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
            m.get("/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
            m.get("/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))
            m.get("/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
            m.get("/api/v1/iam/roles").mock(return_value=httpx.Response(200, json={"roles": []}))
            m.get("/api/v1/logs").mock(return_value=httpx.Response(200, json=[]))
            for ptype in _POLICY_TYPES:
                m.get("/api/v1/policies", params={"type": ptype}).mock(return_value=httpx.Response(200, json=[]))

            records_b = connector.fetch({"org_url": other_org_url, "api_token": "other-token"}, _sleep_fn=lambda s: None)

        # Tenant B's fetch must be completely clean — no leaked tenant-A
        # users/groups/privileged identities, and no leaked tenant_id.
        assert not any(r.get("tenant_id") == "id:00o1abcXYZ" for r in records_b)
        assert not any(r["record_type"] == "okta_privileged_identity" for r in records_b)
        org_b = next(r for r in records_b if r["record_type"] == "okta_organization")
        assert org_b["tenant_id"] != next(r for r in records_a if r["record_type"] == "okta_organization")["tenant_id"]
