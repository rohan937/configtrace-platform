"""Okta authentication policy collection tests (Okta message 4 of 8).

Covers policy/rule/authenticator collection end-to-end via
``OktaConnector.fetch()``: per-policy-type collection (Okta requires an
explicit `type` per policy list call), per-policy rule enumeration,
authenticator collection, family independence (fail-soft), deduplication,
stable IDs, and scale behavior. Normalization correctness is covered
separately in ``test_okta_policy_normalization.py``; diff/risk behavior in
``test_okta_policy_diff.py``.
"""

from __future__ import annotations

import time

import httpx
import respx

from app.connectors.okta import OktaConnector
from app.connectors.okta_schema import (
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    OKTA_AUTHENTICATOR,
    OKTA_POLICY,
    OKTA_POLICY_RULE,
)

_ORG_URL = "https://example.okta.com"
_TOKEN = "fake-okta-api-token-value"
_CREDS = {"org_url": _ORG_URL, "api_token": _TOKEN}

_POLICY_TYPES = ("OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL", "ACCESS_POLICY", "PROFILE_ENROLLMENT", "IDP_DISCOVERY")


def _org_response() -> httpx.Response:
    return httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})


def _policy(policy_id: str, *, name: str = None, ptype: str = "OKTA_SIGN_ON") -> dict:
    return {"id": policy_id, "name": name or f"Policy {policy_id}", "type": ptype, "status": "ACTIVE", "priority": 1}


def _rule(rule_id: str, *, name: str = None) -> dict:
    return {
        "id": rule_id, "name": name or f"Rule {rule_id}", "status": "ACTIVE", "priority": 1,
        "actions": {"signon": {"access": "ALLOW", "requireFactor": True}},
    }


def _authenticator(auth_id: str, *, key: str = "okta_verify") -> dict:
    return {"id": auth_id, "key": key, "type": "app", "name": key, "status": "ACTIVE"}


def _mock_empty_users_groups_apps():
    respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))


def _mock_all_policy_types_empty(exclude: tuple = ()):
    for ptype in _POLICY_TYPES:
        if ptype in exclude:
            continue
        respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(
            return_value=httpx.Response(200, json=[])
        )


def _mock_remaining_probes():
    for path in ("/api/v1/logs",):
        respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))


# ════════════════════════════════════════════════════════════════════════════
# Policy collection (per policy-type)
# ════════════════════════════════════════════════════════════════════════════


class TestPolicyCollection:
    @respx.mock
    def test_collects_policies_across_all_types(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        for ptype in _POLICY_TYPES:
            respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(
                return_value=httpx.Response(200, json=[_policy(f"p_{ptype}", ptype=ptype)])
            )
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        _mock_remaining_probes()

        records = OktaConnector().fetch(_CREDS)
        policies = [r for r in records if r["record_type"] == OKTA_POLICY]
        assert len(policies) == len(_POLICY_TYPES)
        assert {p["policy_type"] for p in policies} == set(_POLICY_TYPES)

    @respx.mock
    def test_each_policy_type_queried_with_explicit_type_param(self):
        """Okta's Policies API requires an explicit `type` param per call —
        confirm every one of the 6 known types is actually requested."""
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        routes = {}
        for ptype in _POLICY_TYPES:
            routes[ptype] = respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(
                return_value=httpx.Response(200, json=[])
            )
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        _mock_remaining_probes()

        OktaConnector().fetch(_CREDS)
        for ptype, route in routes.items():
            assert route.call_count >= 1, f"{ptype} was never queried"

    @respx.mock
    def test_collects_policies_across_multiple_pages(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        page1 = httpx.Response(
            200, json=[_policy("p1")],
            headers={"Link": f'<{_ORG_URL}/api/v1/policies?type=OKTA_SIGN_ON&after=p1>; rel="next"'},
        )
        page2 = httpx.Response(200, json=[_policy("p2")])
        respx.get(url__regex=r".*/api/v1/policies\?type=OKTA_SIGN_ON.*").mock(side_effect=[page1, page2])
        for ptype in _POLICY_TYPES:
            if ptype == "OKTA_SIGN_ON":
                continue
            respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(
                return_value=httpx.Response(200, json=[])
            )
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        _mock_remaining_probes()

        records = OktaConnector().fetch(_CREDS)
        policies = [r for r in records if r["record_type"] == OKTA_POLICY]
        assert {p["policy_id"] for p in policies} == {"p1", "p2"}


# ════════════════════════════════════════════════════════════════════════════
# Per-policy rule collection
# ════════════════════════════════════════════════════════════════════════════


class TestRuleCollection:
    @respx.mock
    def test_rules_collected_per_policy(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": "OKTA_SIGN_ON"}).mock(
            return_value=httpx.Response(200, json=[_policy("p1")])
        )
        _mock_all_policy_types_empty(exclude=("OKTA_SIGN_ON",))
        respx.get(f"{_ORG_URL}/api/v1/policies/p1/rules").mock(
            return_value=httpx.Response(200, json=[_rule("r1"), _rule("r2")])
        )
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        _mock_remaining_probes()

        records = OktaConnector().fetch(_CREDS)
        rules = [r for r in records if r["record_type"] == OKTA_POLICY_RULE]
        assert len(rules) == 2
        assert {r["rule_id"] for r in rules} == {"r1", "r2"}
        assert all(r["policy_id"] == "p1" for r in rules)

    @respx.mock
    def test_policies_collected_once_not_refetched_for_rules(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        sign_on_route = respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": "OKTA_SIGN_ON"}).mock(
            return_value=httpx.Response(200, json=[_policy("p1")])
        )
        _mock_all_policy_types_empty(exclude=("OKTA_SIGN_ON",))
        respx.get(f"{_ORG_URL}/api/v1/policies/p1/rules").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        _mock_remaining_probes()

        OktaConnector().fetch(_CREDS)
        # capability probe also calls /api/v1/policies?type=OKTA_SIGN_ON&limit=1
        # once — total calls should be exactly 2 (collection + probe).
        assert sign_on_route.call_count == 2

    @respx.mock
    def test_policy_with_zero_rules(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": "OKTA_SIGN_ON"}).mock(
            return_value=httpx.Response(200, json=[_policy("p1")])
        )
        _mock_all_policy_types_empty(exclude=("OKTA_SIGN_ON",))
        respx.get(f"{_ORG_URL}/api/v1/policies/p1/rules").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        _mock_remaining_probes()

        records = OktaConnector().fetch(_CREDS)
        policy = next(r for r in records if r["record_type"] == OKTA_POLICY)
        assert policy["rule_count"] == 0

    @respx.mock
    def test_no_policies_at_all_is_complete_not_denied(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        _mock_all_policy_types_empty()
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        _mock_remaining_probes()

        records = OktaConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["policy_rules"] == FAMILY_COMPLETE


# ════════════════════════════════════════════════════════════════════════════
# Authenticator collection
# ════════════════════════════════════════════════════════════════════════════


class TestAuthenticatorCollection:
    @respx.mock
    def test_collects_all_authenticators(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        _mock_all_policy_types_empty()
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(
            return_value=httpx.Response(200, json=[_authenticator("a1"), _authenticator("a2", key="webauthn")])
        )
        _mock_remaining_probes()

        records = OktaConnector().fetch(_CREDS)
        authenticators = [r for r in records if r["record_type"] == OKTA_AUTHENTICATOR]
        assert len(authenticators) == 2
        assert {a["authenticator_id"] for a in authenticators} == {"a1", "a2"}


# ════════════════════════════════════════════════════════════════════════════
# Family independence / fail-soft
# ════════════════════════════════════════════════════════════════════════════


class TestFamilyIndependence:
    @respx.mock
    def test_policies_available_rules_denied_authenticators_available(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": "OKTA_SIGN_ON"}).mock(
            return_value=httpx.Response(200, json=[_policy("p1")])
        )
        _mock_all_policy_types_empty(exclude=("OKTA_SIGN_ON",))
        respx.get(f"{_ORG_URL}/api/v1/policies/p1/rules").mock(return_value=httpx.Response(403))
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(
            return_value=httpx.Response(200, json=[_authenticator("a1")])
        )
        _mock_remaining_probes()

        records = OktaConnector().fetch(_CREDS)
        assert any(r["record_type"] == OKTA_POLICY for r in records)
        assert not any(r["record_type"] == OKTA_POLICY_RULE for r in records)
        assert any(r["record_type"] == OKTA_AUTHENTICATOR for r in records)

        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["policies"] == FAMILY_COMPLETE
        assert org["family_completeness"]["policy_rules"] == FAMILY_DENIED
        assert org["family_completeness"]["authenticators"] == FAMILY_COMPLETE

        policy = next(r for r in records if r["record_type"] == OKTA_POLICY)
        assert policy["rule_count"] is None  # never inferred as zero

    @respx.mock
    def test_sync_does_not_fail_entirely_on_full_denial(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        for ptype in _POLICY_TYPES:
            respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(return_value=httpx.Response(403))
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(403))
        _mock_remaining_probes()

        records = OktaConnector().fetch(_CREDS)  # must not raise
        assert any(r["record_type"] == "okta_organization" for r in records)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["policies"] == FAMILY_DENIED
        assert org["family_completeness"]["authenticators"] == FAMILY_DENIED


# ════════════════════════════════════════════════════════════════════════════
# Deduplication / stable IDs
# ════════════════════════════════════════════════════════════════════════════


class TestDedupAndStableIds:
    @respx.mock
    def test_rule_dedup_within_a_policy(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": "OKTA_SIGN_ON"}).mock(
            return_value=httpx.Response(200, json=[_policy("p1")])
        )
        _mock_all_policy_types_empty(exclude=("OKTA_SIGN_ON",))
        page1 = httpx.Response(
            200, json=[_rule("r1")],
            headers={"Link": f'<{_ORG_URL}/api/v1/policies/p1/rules?after=1>; rel="next"'},
        )
        page2 = httpx.Response(200, json=[_rule("r1")])
        respx.get(url__regex=r".*/api/v1/policies/p1/rules.*").mock(side_effect=[page1, page2])
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        _mock_remaining_probes()

        records = OktaConnector().fetch(_CREDS)
        rules = [r for r in records if r["record_type"] == OKTA_POLICY_RULE]
        assert len(rules) == 1

    def test_stable_record_ids_prefer_tenant_plus_okta_id(self):
        tenant_id = "id:t1"
        policy_rec = OktaConnector._normalize_policy(tenant_id, _policy("p1"), rule_count=0)
        assert policy_rec["record_id"] == f"{tenant_id}/policy/p1"
        rule_rec = OktaConnector._normalize_policy_rule(tenant_id, policy_rec, _rule("r1"))
        assert rule_rec["record_id"] == f"{tenant_id}/policy_rule/p1/r1"
        auth_rec = OktaConnector._normalize_authenticator(tenant_id, _authenticator("a1"))
        assert auth_rec["record_id"] == f"{tenant_id}/authenticator/a1"


# ════════════════════════════════════════════════════════════════════════════
# Pagination edge cases
# ════════════════════════════════════════════════════════════════════════════


class TestPaginationEdgeCases:
    @respx.mock
    def test_repeated_link_stops_pagination(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        loop_resp = httpx.Response(
            200, json=[_policy("p1")],
            headers={"Link": f'<{_ORG_URL}/api/v1/policies?type=OKTA_SIGN_ON&p=2>; rel="next"'},
        )
        respx.get(url__regex=r".*/api/v1/policies\?type=OKTA_SIGN_ON.*").mock(return_value=loop_resp)
        for ptype in _POLICY_TYPES:
            if ptype == "OKTA_SIGN_ON":
                continue
            respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(
                return_value=httpx.Response(200, json=[])
            )
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        _mock_remaining_probes()

        records = OktaConnector().fetch(_CREDS)  # must not hang / loop forever
        assert any(r["record_type"] == OKTA_POLICY for r in records)

    @respx.mock
    def test_cross_origin_link_rejected(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": "OKTA_SIGN_ON"}).mock(
            return_value=httpx.Response(
                200, json=[_policy("p1")],
                headers={"Link": '<https://evil.example.com/steal>; rel="next"'},
            )
        )
        _mock_all_policy_types_empty(exclude=("OKTA_SIGN_ON",))
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        _mock_remaining_probes()

        records = OktaConnector().fetch(_CREDS)
        policies = [r for r in records if r["record_type"] == OKTA_POLICY]
        assert len(policies) == 1

    @respx.mock
    def test_partial_second_page_still_returns_first_page_results(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()
        page1 = httpx.Response(
            200, json=[_policy("p1")],
            headers={"Link": f'<{_ORG_URL}/api/v1/policies?type=OKTA_SIGN_ON&after=p1>; rel="next"'},
        )
        respx.get(url__regex=r".*/api/v1/policies\?type=OKTA_SIGN_ON.*").mock(
            side_effect=[page1, httpx.Response(500)],
        )
        for ptype in _POLICY_TYPES:
            if ptype == "OKTA_SIGN_ON":
                continue
            respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(
                return_value=httpx.Response(200, json=[])
            )
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
        _mock_remaining_probes()

        records = OktaConnector().fetch(_CREDS)  # must not raise
        policies = [r for r in records if r["record_type"] == OKTA_POLICY]
        assert len(policies) == 1


# ════════════════════════════════════════════════════════════════════════════
# Scale
# ════════════════════════════════════════════════════════════════════════════


class TestScale:
    @respx.mock
    def test_200_policies_2000_rules_50_authenticators(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_empty_users_groups_apps()

        n_policies = 200
        policies_json = [_policy(f"p{i}") for i in range(n_policies)]
        respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": "OKTA_SIGN_ON"}).mock(
            return_value=httpx.Response(200, json=policies_json)
        )
        _mock_all_policy_types_empty(exclude=("OKTA_SIGN_ON",))

        # 10 rules per policy * 200 policies = 2,000 rules.
        rules_per_policy = 10
        for pi in range(n_policies):
            rule_slice = [_rule(f"r{pi}_{k}") for k in range(rules_per_policy)]
            respx.get(f"{_ORG_URL}/api/v1/policies/p{pi}/rules").mock(
                return_value=httpx.Response(200, json=rule_slice)
            )

        n_auth = 50
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(
            return_value=httpx.Response(200, json=[_authenticator(f"a{i}") for i in range(n_auth)])
        )
        _mock_remaining_probes()

        start = time.monotonic()
        records = OktaConnector().fetch(_CREDS)
        elapsed = time.monotonic() - start

        policies = [r for r in records if r["record_type"] == OKTA_POLICY]
        rules = [r for r in records if r["record_type"] == OKTA_POLICY_RULE]
        authenticators = [r for r in records if r["record_type"] == OKTA_AUTHENTICATOR]

        assert len(policies) == n_policies
        assert len(rules) == n_policies * rules_per_policy
        assert len(authenticators) == n_auth
        assert len({p["record_id"] for p in policies}) == n_policies
        assert len({r["record_id"] for r in rules}) == len(rules)
        assert elapsed < 30.0
