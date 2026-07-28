"""Microsoft Entra ID authentication policy collection tests (Entra message
4 of 8).

Covers Conditional Access policy / authentication strength / authentication
method configuration collection end-to-end via ``EntraConnector.fetch()``:
pagination, family independence (fail-soft), denied permissions, dedup, and
scale behavior. Normalization correctness is covered separately in
``test_entra_policy_normalization.py``; diff/risk behavior in
``test_entra_policy_diff.py``.
"""

from __future__ import annotations

import httpx
import respx

from app.connectors.entra import EntraConnector
from app.connectors.entra_schema import (
    ENTRA_AUTHENTICATION_METHOD,
    ENTRA_AUTHENTICATION_STRENGTH,
    ENTRA_CONDITIONAL_ACCESS_POLICY,
    ENTRA_ORGANIZATION,
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    FAMILY_PARTIAL,
)

_TENANT_ID = "11111111-1111-1111-1111-111111111111"
_CLIENT_ID = "22222222-2222-2222-2222-222222222222"
_SECRET = "fake-entra-client-secret-value"
_CREDS = {"tenant_id": _TENANT_ID, "client_id": _CLIENT_ID, "client_secret": _SECRET}
_TOKEN_URL = f"https://login.microsoftonline.com/{_TENANT_ID}/oauth2/v2.0/token"
_GRAPH = "https://graph.microsoft.com/v1.0"

_OPTIONAL_FAMILY_PATHS = (
    "users", "groups", "applications", "servicePrincipals",
    "directoryRoles", "oauth2PermissionGrants",
)


def _mock_token():
    respx.post(_TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600}))


def _mock_org():
    respx.get(f"{_GRAPH}/organization").mock(
        return_value=httpx.Response(200, json={"value": [{"id": _TENANT_ID, "displayName": "Example Corp"}]})
    )


def _mock_identity_and_app_families_empty():
    for path in _OPTIONAL_FAMILY_PATHS:
        respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))


def _mock_policy_families_empty():
    respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
        return_value=httpx.Response(200, json={"value": []})
    )


def _ca_policy(policy_id: str, **overrides) -> dict:
    base = {
        "id": policy_id,
        "displayName": f"Policy {policy_id}",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
        },
        "grantControls": {"operator": "AND", "builtInControls": ["mfa"]},
    }
    base.update(overrides)
    return base


def _strength(strength_id: str, **overrides) -> dict:
    base = {
        "id": strength_id,
        "displayName": f"Strength {strength_id}",
        "policyType": "custom",
        "allowedCombinations": ["fido2"],
    }
    base.update(overrides)
    return base


def _method_config(config_id: str, **overrides) -> dict:
    base = {"id": config_id, "state": "enabled", "includeTargets": [{"id": "all_users"}]}
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# Conditional Access policy collection
# ════════════════════════════════════════════════════════════════════════════


class TestConditionalAccessPolicyCollection:
    @respx.mock
    def test_collects_all_policies_single_page(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(
            return_value=httpx.Response(200, json={"value": [_ca_policy("p1"), _ca_policy("p2")]})
        )
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(200, json={"value": []})
        )

        records = EntraConnector().fetch(_CREDS)
        policies = [r for r in records if r["record_type"] == ENTRA_CONDITIONAL_ACCESS_POLICY]
        assert len(policies) == 2
        assert {p["policy_id"] for p in policies} == {"p1", "p2"}

    @respx.mock
    def test_collects_policies_across_multiple_pages(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        page1 = httpx.Response(
            200, json={"value": [_ca_policy("p1")], "@odata.nextLink": f"{_GRAPH}/identity/conditionalAccess/policies?skip=1"},
        )
        page2 = httpx.Response(200, json={"value": [_ca_policy("p2")]})
        respx.get(url__regex=r".*/identity/conditionalAccess/policies.*").mock(side_effect=[page1, page2])
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(200, json={"value": []})
        )

        records = EntraConnector().fetch(_CREDS)
        policies = [r for r in records if r["record_type"] == ENTRA_CONDITIONAL_ACCESS_POLICY]
        assert {p["policy_id"] for p in policies} == {"p1", "p2"}

    @respx.mock
    def test_dedups_repeated_policy_id_within_a_page(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(
            return_value=httpx.Response(200, json={"value": [_ca_policy("p1"), _ca_policy("p1")]})
        )
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(200, json={"value": []})
        )

        records = EntraConnector().fetch(_CREDS)
        policies = [r for r in records if r["record_type"] == ENTRA_CONDITIONAL_ACCESS_POLICY]
        assert len(policies) == 1

    @respx.mock
    def test_denied_ca_family_reports_denied_completeness_and_does_not_abort(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(403, json={"error": {"code": "Forbidden"}}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(200, json={"value": []})
        )

        records = EntraConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["conditional_access_policies"] == FAMILY_DENIED
        policies = [r for r in records if r["record_type"] == ENTRA_CONDITIONAL_ACCESS_POLICY]
        assert policies == []
        # Other families are unaffected by this one family's denial.
        assert org["family_completeness"]["authentication_strengths"] == FAMILY_COMPLETE

    @respx.mock
    def test_ca_policy_truncated_pagination_is_partial(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        page1 = httpx.Response(
            200, json={"value": [_ca_policy("p1")], "@odata.nextLink": f"{_GRAPH}/identity/conditionalAccess/policies?skip=1"},
        )
        page2 = httpx.Response(500, json={"error": {"code": "InternalServerError"}})
        page2b = httpx.Response(500, json={"error": {"code": "InternalServerError"}})
        page2c = httpx.Response(500, json={"error": {"code": "InternalServerError"}})
        respx.get(url__regex=r".*/identity/conditionalAccess/policies.*").mock(side_effect=[page1, page2, page2b, page2c])
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(200, json={"value": []})
        )

        records = EntraConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["conditional_access_policies"] == FAMILY_PARTIAL


# ════════════════════════════════════════════════════════════════════════════
# Authentication strength collection
# ════════════════════════════════════════════════════════════════════════════


class TestAuthenticationStrengthCollection:
    @respx.mock
    def test_collects_all_strengths(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(
            return_value=httpx.Response(200, json={"value": [_strength("s1"), _strength("s2")]})
        )
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(200, json={"value": []})
        )

        records = EntraConnector().fetch(_CREDS)
        strengths = [r for r in records if r["record_type"] == ENTRA_AUTHENTICATION_STRENGTH]
        assert len(strengths) == 2
        assert {s["strength_id"] for s in strengths} == {"s1", "s2"}

    @respx.mock
    def test_denied_strength_family_reports_denied_and_does_not_abort(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(403, json={"error": {"code": "Forbidden"}}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(200, json={"value": []})
        )

        records = EntraConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["authentication_strengths"] == FAMILY_DENIED
        assert org["family_completeness"]["conditional_access_policies"] == FAMILY_COMPLETE
        assert org["family_completeness"]["authentication_methods"] == FAMILY_COMPLETE


# ════════════════════════════════════════════════════════════════════════════
# Authentication method configuration collection
# ════════════════════════════════════════════════════════════════════════════


class TestAuthenticationMethodCollection:
    @respx.mock
    def test_collects_all_method_configurations(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(200, json={"value": [_method_config("Fido2"), _method_config("Sms")]})
        )

        records = EntraConnector().fetch(_CREDS)
        methods = [r for r in records if r["record_type"] == ENTRA_AUTHENTICATION_METHOD]
        assert len(methods) == 2
        assert {m["method_config_id"] for m in methods} == {"Fido2", "Sms"}

    @respx.mock
    def test_uses_nested_collection_endpoint_not_singleton(self):
        """Confirms collection hits the true list endpoint
        (authenticationMethodConfigurations), never parsing the
        authenticationMethodsPolicy singleton's embedded array."""
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        singleton_route = respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy").mock(
            return_value=httpx.Response(200, json={"id": "authenticationMethodsPolicy"})
        )
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(200, json={"value": [_method_config("Fido2")]})
        )

        records = EntraConnector().fetch(_CREDS)
        methods = [r for r in records if r["record_type"] == ENTRA_AUTHENTICATION_METHOD]
        assert len(methods) == 1
        # The singleton is only ever hit by the message-1 capability probe
        # (a single GET), never by collection re-parsing its body.
        assert singleton_route.call_count == 1

    @respx.mock
    def test_denied_method_family_reports_denied_and_does_not_abort(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(403, json={"error": {"code": "Forbidden"}})
        )

        records = EntraConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["authentication_methods"] == FAMILY_DENIED
        assert org["family_completeness"]["conditional_access_policies"] == FAMILY_COMPLETE
        assert org["family_completeness"]["authentication_strengths"] == FAMILY_COMPLETE


# ════════════════════════════════════════════════════════════════════════════
# Family independence + completeness rollup
# ════════════════════════════════════════════════════════════════════════════


class TestFamilyIndependence:
    @respx.mock
    def test_all_three_new_families_independent_of_each_other_and_prior_families(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": [_ca_policy("p1")]}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(403, json={"error": {"code": "Forbidden"}}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(200, json={"value": [_method_config("Fido2")]})
        )

        records = EntraConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["conditional_access_policies"] == FAMILY_COMPLETE
        assert org["family_completeness"]["authentication_strengths"] == FAMILY_DENIED
        assert org["family_completeness"]["authentication_methods"] == FAMILY_COMPLETE
        assert org["family_completeness"]["users"] == FAMILY_COMPLETE
        assert len([r for r in records if r["record_type"] == ENTRA_CONDITIONAL_ACCESS_POLICY]) == 1
        assert len([r for r in records if r["record_type"] == ENTRA_AUTHENTICATION_METHOD]) == 1

    @respx.mock
    def test_deterministic_ordering_includes_new_record_types(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(
            return_value=httpx.Response(200, json={"value": [_ca_policy("p2"), _ca_policy("p1")]})
        )
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(200, json={"value": []})
        )

        records = EntraConnector().fetch(_CREDS)
        policy_ids = [r["policy_id"] for r in records if r["record_type"] == ENTRA_CONDITIONAL_ACCESS_POLICY]
        assert policy_ids == sorted(policy_ids)


# ════════════════════════════════════════════════════════════════════════════
# Scale
# ════════════════════════════════════════════════════════════════════════════


class TestScale:
    @respx.mock
    def test_many_conditional_access_policies_collected(self):
        _mock_token()
        _mock_org()
        _mock_identity_and_app_families_empty()
        many_policies = [_ca_policy(f"p{i}") for i in range(500)]
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": many_policies}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(
            return_value=httpx.Response(200, json={"value": []})
        )

        records = EntraConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org["family_completeness"]["conditional_access_policies"] == FAMILY_COMPLETE
        assert len([r for r in records if r["record_type"] == ENTRA_CONDITIONAL_ACCESS_POLICY]) == 500
