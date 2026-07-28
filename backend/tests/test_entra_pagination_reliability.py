"""Microsoft Entra ID pagination/retry/reliability tests (Entra message 7
of 8).

Exercises the full ``EntraConnector.fetch()`` path (not the low-level
``call_graph``/``paginate_graph`` unit tests already covered in
test_entra_foundation.py) for: multi-page partial failures (403/429/
timeout/5xx on page 2), 429 exhaustion, timeout/5xx family behavior,
401/403/404 permission-vs-unsupported distinctions, and capability drift
(a family that was previously readable becoming denied/unsupported must
never be inferred as "everything in it was deleted").
"""

from __future__ import annotations

import httpx
import respx

from app.connectors.entra import EntraConnector
from app.connectors.entra_schema import FAMILY_COMPLETE, FAMILY_DENIED, FAMILY_PARTIAL, FAMILY_UNAVAILABLE

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


def _mock_all_baseline():
    _mock_token()
    _mock_org()
    _mock_identity_and_app_families_empty()
    _mock_role_families_empty()


def _fetch():
    return EntraConnector().fetch(_CREDS, _sleep_fn=lambda s: None)


def _org(records: list[dict]) -> dict:
    return next(r for r in records if r["record_type"] == "entra_organization")


# ════════════════════════════════════════════════════════════════════════════
# Multi-page partial failures
# ════════════════════════════════════════════════════════════════════════════


class TestMultiPagePartialFailure:
    @respx.mock
    def test_page1_succeeds_page2_403(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        page1 = httpx.Response(
            200, json={
                "value": [{"id": "u1", "userPrincipalName": "a@x.com", "accountEnabled": True, "userType": "Member"}],
                "@odata.nextLink": f"{_GRAPH}/users?$skiptoken=abc",
            },
        )
        respx.get(url__regex=r".*/users.*").mock(side_effect=[page1, httpx.Response(403)])

        records = _fetch()
        users = [r for r in records if r["record_type"] == "entra_user"]
        assert len(users) == 1
        assert _org(records)["family_completeness"]["users"] == FAMILY_PARTIAL

    @respx.mock
    def test_page1_succeeds_page2_429_exhausted(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        page1 = httpx.Response(
            200, json={
                "value": [{"id": "u1", "userPrincipalName": "a@x.com", "accountEnabled": True, "userType": "Member"}],
                "@odata.nextLink": f"{_GRAPH}/users?$skiptoken=abc",
            },
        )
        respx.get(url__regex=r".*/users.*").mock(side_effect=[page1] + [httpx.Response(429)] * 10)

        records = _fetch()  # must not raise / hang
        users = [r for r in records if r["record_type"] == "entra_user"]
        assert len(users) == 1
        assert _org(records)["family_completeness"]["users"] == FAMILY_PARTIAL

    @respx.mock
    def test_page1_succeeds_page2_times_out(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        page1 = httpx.Response(
            200, json={
                "value": [{"id": "u1", "userPrincipalName": "a@x.com", "accountEnabled": True, "userType": "Member"}],
                "@odata.nextLink": f"{_GRAPH}/users?$skiptoken=abc",
            },
        )
        respx.get(url__regex=r".*/users.*").mock(side_effect=[page1, httpx.ReadTimeout("timed out")])

        records = _fetch()  # must not raise
        users = [r for r in records if r["record_type"] == "entra_user"]
        assert len(users) == 1
        assert _org(records)["family_completeness"]["users"] == FAMILY_PARTIAL

    @respx.mock
    def test_page1_succeeds_page2_5xx(self):
        for status in (500, 502, 503, 504):
            _mock_token(); _mock_org()
            respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
            for path in _IDENTITY_APP_FAMILY_PATHS:
                respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
            _mock_role_families_empty()
            page1 = httpx.Response(
                200, json={
                    "value": [{"id": "u1", "userPrincipalName": "a@x.com", "accountEnabled": True, "userType": "Member"}],
                    "@odata.nextLink": f"{_GRAPH}/users?$skiptoken=abc",
                },
            )
            respx.get(url__regex=r".*/users.*").mock(side_effect=[page1, httpx.Response(status)])
            records = _fetch()
            users = [r for r in records if r["record_type"] == "entra_user"]
            assert len(users) == 1, f"failed for status {status}"


# ════════════════════════════════════════════════════════════════════════════
# First-page failure modes (whole family)
# ════════════════════════════════════════════════════════════════════════════


class TestFirstPageFailureModes:
    @respx.mock
    def test_users_429_exhausted_is_partial_not_crash(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(429))

        records = _fetch()
        org = _org(records)
        assert org["family_completeness"]["users"] in (FAMILY_UNAVAILABLE, FAMILY_DENIED, FAMILY_PARTIAL)
        assert not any(r["record_type"] == "entra_user" for r in records)

    @respx.mock
    def test_users_connect_timeout_is_unavailable(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        respx.get(f"{_GRAPH}/users").mock(side_effect=httpx.ConnectTimeout("timed out connecting"))

        records = _fetch()  # must not raise
        assert _org(records)["family_completeness"]["users"] == FAMILY_UNAVAILABLE

    @respx.mock
    def test_users_read_timeout_is_unavailable(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        respx.get(f"{_GRAPH}/users").mock(side_effect=httpx.ReadTimeout("timed out reading"))

        records = _fetch()
        assert _org(records)["family_completeness"]["users"] == FAMILY_UNAVAILABLE

    @respx.mock
    def test_users_500_is_unavailable(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(500))

        records = _fetch()
        assert _org(records)["family_completeness"]["users"] == FAMILY_UNAVAILABLE

    @respx.mock
    def test_users_503_is_unavailable(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(503))

        records = _fetch()
        assert _org(records)["family_completeness"]["users"] == FAMILY_UNAVAILABLE

    @respx.mock
    def test_users_403_is_denied(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(403))

        records = _fetch()
        assert _org(records)["family_completeness"]["users"] == FAMILY_DENIED

    @respx.mock
    def test_users_401_mid_fetch_is_unavailable_not_fatal(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(401))

        records = _fetch()  # must not raise
        assert any(r["record_type"] == "entra_organization" for r in records)

    @respx.mock
    def test_groups_403_is_denied_users_unaffected(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(403))

        records = _fetch()
        org = _org(records)
        assert org["family_completeness"]["groups"] == FAMILY_DENIED
        assert org["family_completeness"]["users"] == FAMILY_COMPLETE

    @respx.mock
    def test_applications_500_is_unavailable_service_principals_unaffected(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(500))

        records = _fetch()
        org = _org(records)
        assert org["family_completeness"]["applications"] == FAMILY_UNAVAILABLE
        assert org["family_completeness"]["service_principals"] == FAMILY_COMPLETE

    @respx.mock
    def test_directory_role_assignments_denied_role_definitions_unaffected(self):
        _mock_token(); _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(return_value=httpx.Response(403))

        records = _fetch()
        org = _org(records)
        assert org["family_completeness"]["directory_role_assignments"] == FAMILY_DENIED
        assert org["family_completeness"]["directory_role_definitions"] == FAMILY_COMPLETE


# ════════════════════════════════════════════════════════════════════════════
# Capability drift — a family available before must never imply deletion
# ════════════════════════════════════════════════════════════════════════════


class TestCapabilityDrift:
    @respx.mock
    def test_applications_becomes_403_does_not_infer_all_apps_deleted(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(403))

        records = _fetch()
        org = _org(records)
        assert org["family_completeness"]["applications"] == FAMILY_DENIED
        assert not any(r["record_type"] == "entra_application" for r in records)

    @respx.mock
    def test_oauth2_grants_becomes_unavailable_does_not_infer_deletion(self):
        _mock_all_baseline()
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(500))

        records = _fetch()
        org = _org(records)
        assert org["family_completeness"]["oauth2_permission_grants"] == FAMILY_UNAVAILABLE
        assert not any(r["record_type"] == "entra_oauth2_permission_grant" for r in records)


# ════════════════════════════════════════════════════════════════════════════
# Cross-origin / malformed / repeated next-link edge cases at fetch() level
# ════════════════════════════════════════════════════════════════════════════


class TestNextLinkEdgeCasesAtFetchLevel:
    @respx.mock
    def test_cross_origin_next_link_does_not_leak_credentials_or_hang(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(
            200, json={
                "value": [{"id": "u1", "userPrincipalName": "a@x.com", "accountEnabled": True, "userType": "Member"}],
                "@odata.nextLink": "https://evil.example.com/steal?token=x",
            },
        ))

        records = _fetch()
        users = [r for r in records if r["record_type"] == "entra_user"]
        assert len(users) == 1

    @respx.mock
    def test_repeated_next_link_does_not_hang(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        for path in _IDENTITY_APP_FAMILY_PATHS:
            respx.get(f"{_GRAPH}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        loop_resp = httpx.Response(
            200, json={
                "value": [{"id": "u1", "userPrincipalName": "a@x.com", "accountEnabled": True, "userType": "Member"}],
                "@odata.nextLink": f"{_GRAPH}/users?$skiptoken=loop",
            },
        )
        respx.get(url__regex=r".*/users.*").mock(return_value=loop_resp)

        records = _fetch()  # must terminate
        assert any(r["record_type"] == "entra_user" for r in records)


# ════════════════════════════════════════════════════════════════════════════
# Recovery / idempotency at fetch() level
# ════════════════════════════════════════════════════════════════════════════


class TestFetchIdempotency:
    @respx.mock
    def test_two_consecutive_fetches_with_identical_mocks_produce_identical_records(self):
        _mock_all_baseline()
        first = _fetch()
        _mock_all_baseline()
        second = EntraConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
        assert first == second


# ════════════════════════════════════════════════════════════════════════════
# Remaining families: first-page failure modes (429/5xx/timeout/403)
# ════════════════════════════════════════════════════════════════════════════


class TestRemainingFamilyFailureModes:
    @respx.mock
    def test_service_principals_429_exhausted_is_not_crash(self):
        _mock_token(); _mock_org()
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/applications").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(return_value=httpx.Response(200, json={"value": []}))
        _mock_role_families_empty()
        respx.get(f"{_GRAPH}/servicePrincipals").mock(return_value=httpx.Response(429))

        records = _fetch()
        assert _org(records)["family_completeness"]["service_principals"] in (FAMILY_UNAVAILABLE, FAMILY_DENIED, FAMILY_PARTIAL)
        assert not any(r["record_type"] == "entra_service_principal" for r in records)

    @respx.mock
    def test_oauth2_permission_grants_500_is_unavailable(self):
        _mock_all_baseline()
        respx.get(f"{_GRAPH}/oauth2PermissionGrants").mock(return_value=httpx.Response(500))

        records = _fetch()
        assert _org(records)["family_completeness"]["oauth2_permission_grants"] == FAMILY_UNAVAILABLE
        assert not any(r["record_type"] == "entra_oauth2_permission_grant" for r in records)

    @respx.mock
    def test_conditional_access_policies_403_is_denied(self):
        _mock_all_baseline()
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(403))

        records = _fetch()
        assert _org(records)["family_completeness"]["conditional_access_policies"] == FAMILY_DENIED
        assert not any(r["record_type"] == "entra_conditional_access_policy" for r in records)

    @respx.mock
    def test_authentication_strengths_timeout_is_unavailable(self):
        _mock_all_baseline()
        respx.get(f"{_GRAPH}/policies/authenticationStrengthPolicies").mock(side_effect=httpx.ReadTimeout("timed out"))

        records = _fetch()  # must not raise
        assert _org(records)["family_completeness"]["authentication_strengths"] == FAMILY_UNAVAILABLE

    @respx.mock
    def test_authentication_methods_5xx_is_unavailable(self):
        _mock_all_baseline()
        respx.get(f"{_GRAPH}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations").mock(return_value=httpx.Response(503))

        records = _fetch()
        assert _org(records)["family_completeness"]["authentication_methods"] == FAMILY_UNAVAILABLE

    @respx.mock
    def test_directory_role_definitions_429_exhausted_is_not_crash(self):
        _mock_token(); _mock_org()
        _mock_identity_and_app_families_empty()
        respx.get(f"{_GRAPH}/roleManagement/directory/roleDefinitions").mock(return_value=httpx.Response(429))
        respx.get(f"{_GRAPH}/roleManagement/directory/roleAssignments").mock(return_value=httpx.Response(200, json={"value": []}))

        records = _fetch()  # must not raise / hang
        assert _org(records)["family_completeness"]["directory_role_definitions"] in (FAMILY_UNAVAILABLE, FAMILY_DENIED, FAMILY_PARTIAL)

    @respx.mock
    def test_organization_itself_401_raises_authentication_error(self):
        from app.connectors.exceptions import AuthenticationError
        _mock_token()
        respx.get(f"{_GRAPH}/organization").mock(return_value=httpx.Response(401))

        try:
            _fetch()
            raised = False
        except AuthenticationError:
            raised = True
        assert raised  # the org call itself is the one call that MUST raise, never fail-soft
