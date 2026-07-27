"""Microsoft Entra ID provider foundation tests (Entra message 1 of 8).

Covers the connector architecture built in this message: GUID tenant_id/
client_id validation (rejecting 'common'/'organizations'/'consumers'),
OAuth2 client_credentials token acquisition against the tenant-specific
Microsoft identity platform token endpoint, the in-memory connector-scoped
token cache, stable tenant identity, @odata.nextLink pagination (same-
origin enforcement, cycle detection, page cap), the fail-soft API-call
wrapper with bounded 429/5xx retry, and read-only capability probes for
the eight future record families. No users, groups, applications, service
principals, Conditional Access policies, authentication methods, directory
roles, or consent-grant collection exists yet — that begins in later
messages.

All tests are pure-mock (respx) or unit-level; no real Microsoft Graph
tenant is contacted.
"""

from __future__ import annotations

import re

import httpx
import pytest
import respx

from app.connectors.entra import (
    CATEGORY_AUTH_FAILED,
    CATEGORY_SUCCESS,
    CATEGORY_THROTTLED,
    EntraConnector,
    EntraTokenError,
    _extract_next_link,
    _validate_next_link_origin,
    call_graph,
    paginate_graph,
)
from app.connectors.entra_schema import (
    CAPABILITY_AVAILABLE,
    CAPABILITY_DENIED,
    CAPABILITY_THROTTLED,
    CAPABILITY_UNAVAILABLE,
    CAPABILITY_UNSUPPORTED,
    ENTRA_API_CAPABILITY,
    ENTRA_ORGANIZATION,
    EntraCredentialError,
    validate_client_id,
    validate_tenant_id,
)
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)

_TENANT_ID = "11111111-1111-1111-1111-111111111111"
_CLIENT_ID = "22222222-2222-2222-2222-222222222222"
_SECRET = "fake-entra-client-secret-value"
_CREDS = {"tenant_id": _TENANT_ID, "client_id": _CLIENT_ID, "client_secret": _SECRET}
_TOKEN_URL = f"https://login.microsoftonline.com/{_TENANT_ID}/oauth2/v2.0/token"
_GRAPH = "https://graph.microsoft.com/v1.0"


def _noop_sleep(_seconds: float) -> None:
    """Injected in place of time.sleep so retry tests never really sleep."""


def _token_response(token: str = "fake-access-token", expires_in: int = 3600) -> httpx.Response:
    return httpx.Response(200, json={"access_token": token, "expires_in": expires_in, "token_type": "Bearer"})


def _org_response(tenant_id: str = _TENANT_ID, display_name: str = "Example Corp") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "value": [{
                "id": tenant_id,
                "displayName": display_name,
                "verifiedDomains": [
                    {"name": "example.onmicrosoft.com", "isDefault": True},
                ],
                "onPremisesSyncEnabled": None,
            }],
        },
    )


def _mock_probe_families_empty():
    for path in (
        "/users", "/groups", "/applications", "/servicePrincipals",
        "/identity/conditionalAccess/policies", "/policies/authenticationMethodsPolicy",
        "/directoryRoles", "/oauth2PermissionGrants",
    ):
        respx.get(url__regex=re.escape(path) + r".*").mock(
            return_value=httpx.Response(200, json={"value": []})
        )


# ── Tenant / client ID validation ────────────────────────────────────────────


class TestValidateTenantId:
    def test_valid_guid_accepted(self):
        assert validate_tenant_id(_TENANT_ID) == _TENANT_ID

    def test_uppercase_guid_lowercased(self):
        assert validate_tenant_id(_TENANT_ID.upper()) == _TENANT_ID

    def test_common_rejected(self):
        with pytest.raises(EntraCredentialError):
            validate_tenant_id("common")

    def test_organizations_rejected(self):
        with pytest.raises(EntraCredentialError):
            validate_tenant_id("organizations")

    def test_consumers_rejected(self):
        with pytest.raises(EntraCredentialError):
            validate_tenant_id("consumers")

    def test_embedded_url_rejected(self):
        with pytest.raises(EntraCredentialError):
            validate_tenant_id("https://evil.example/" + _TENANT_ID)

    def test_non_guid_string_rejected(self):
        with pytest.raises(EntraCredentialError):
            validate_tenant_id("not-a-guid")

    def test_empty_string_rejected(self):
        with pytest.raises(EntraCredentialError):
            validate_tenant_id("")

    def test_non_string_rejected(self):
        with pytest.raises(EntraCredentialError):
            validate_tenant_id(None)

    def test_query_fragment_rejected(self):
        with pytest.raises(EntraCredentialError):
            validate_tenant_id(_TENANT_ID + "?x=1")


class TestValidateClientId:
    def test_valid_guid_accepted(self):
        assert validate_client_id(_CLIENT_ID) == _CLIENT_ID

    def test_non_guid_rejected(self):
        with pytest.raises(EntraCredentialError):
            validate_client_id("not-a-guid")

    def test_empty_rejected(self):
        with pytest.raises(EntraCredentialError):
            validate_client_id("")

    def test_embedded_url_rejected(self):
        with pytest.raises(EntraCredentialError):
            validate_client_id("https://evil.example/" + _CLIENT_ID)


# ── Authentication ───────────────────────────────────────────────────────────


class TestAuthentication:
    @respx.mock
    def test_valid_client_credentials_succeeds(self):
        respx.post(_TOKEN_URL).mock(return_value=_token_response())
        respx.get(f"{_GRAPH}/organization").mock(return_value=_org_response())
        conn = EntraConnector()
        assert conn.validate_credentials(_CREDS) is True

    @respx.mock
    def test_invalid_client_secret_raises_authentication_error(self):
        respx.post(_TOKEN_URL).mock(
            return_value=httpx.Response(401, json={"error": "invalid_client"})
        )
        conn = EntraConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials(_CREDS)

    @respx.mock
    def test_invalid_tenant_raises_authentication_error(self):
        # Microsoft returns 400 for an unrecognized tenant on the token
        # endpoint (AADSTS90002-style errors), not a 404.
        respx.post(_TOKEN_URL).mock(
            return_value=httpx.Response(400, json={"error": "invalid_request", "error_description": "unknown tenant"})
        )
        conn = EntraConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials(_CREDS)

    @respx.mock
    def test_permission_denied_on_organization_probe_raises_connector_error(self):
        """403 means the token is accepted but lacks the Organization.Read.All
        (or Directory.Read.All) application permission — distinct from 401
        (rejected token)."""
        respx.post(_TOKEN_URL).mock(return_value=_token_response())
        respx.get(f"{_GRAPH}/organization").mock(return_value=httpx.Response(403))
        conn = EntraConnector()
        with pytest.raises(ConnectorError):
            conn.validate_credentials(_CREDS)

    @respx.mock
    def test_token_response_missing_access_token_raises(self):
        respx.post(_TOKEN_URL).mock(return_value=httpx.Response(200, json={"token_type": "Bearer"}))
        conn = EntraConnector()
        with pytest.raises(EntraTokenError):
            conn.validate_credentials(_CREDS)

    @respx.mock
    def test_token_endpoint_timeout_raises_network_error(self):
        respx.post(_TOKEN_URL).mock(side_effect=httpx.ConnectTimeout("timed out"))
        conn = EntraConnector()
        with pytest.raises(NetworkError):
            conn.validate_credentials(_CREDS)

    @respx.mock
    def test_graph_timeout_raises_network_error(self):
        respx.post(_TOKEN_URL).mock(return_value=_token_response())
        respx.get(f"{_GRAPH}/organization").mock(side_effect=httpx.ReadTimeout("timed out"))
        conn = EntraConnector()
        with pytest.raises(NetworkError):
            conn.validate_credentials(_CREDS)

    def test_missing_client_secret_raises_authentication_error(self):
        conn = EntraConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials({"tenant_id": _TENANT_ID, "client_id": _CLIENT_ID})

    def test_malformed_tenant_id_raises_before_any_request(self):
        conn = EntraConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials({"tenant_id": "not-a-guid", "client_id": _CLIENT_ID, "client_secret": _SECRET})

    def test_common_tenant_id_rejected(self):
        conn = EntraConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials({"tenant_id": "common", "client_id": _CLIENT_ID, "client_secret": _SECRET})

    @respx.mock
    def test_authorization_header_uses_bearer_scheme(self):
        respx.post(_TOKEN_URL).mock(return_value=_token_response(token="my-token"))
        route = respx.get(f"{_GRAPH}/organization").mock(return_value=_org_response())
        conn = EntraConnector()
        conn.validate_credentials(_CREDS)
        assert route.calls.last.request.headers["Authorization"] == "Bearer my-token"

    @respx.mock
    def test_secret_never_appears_in_exception_text(self):
        respx.post(_TOKEN_URL).mock(
            return_value=httpx.Response(401, json={"error": "invalid_client"})
        )
        conn = EntraConnector()
        try:
            conn.validate_credentials(_CREDS)
        except AuthenticationError as exc:
            assert _SECRET not in str(exc)
        else:
            pytest.fail("expected AuthenticationError")

    @respx.mock
    def test_secret_never_logged(self, caplog):
        import logging

        respx.post(_TOKEN_URL).mock(return_value=_token_response())
        respx.get(f"{_GRAPH}/organization").mock(return_value=_org_response())
        conn = EntraConnector()
        with caplog.at_level(logging.DEBUG):
            conn.validate_credentials(_CREDS)
        assert _SECRET not in caplog.text


# ── Token caching ────────────────────────────────────────────────────────────


class TestTokenCaching:
    @respx.mock
    def test_first_call_acquires_token(self):
        route = respx.post(_TOKEN_URL).mock(return_value=_token_response())
        conn = EntraConnector()
        conn._get_token(_CREDS)
        assert route.call_count == 1

    @respx.mock
    def test_multiple_graph_calls_reuse_cached_token(self):
        token_route = respx.post(_TOKEN_URL).mock(return_value=_token_response())
        respx.get(f"{_GRAPH}/organization").mock(return_value=_org_response())
        _mock_probe_families_empty()
        conn = EntraConnector()
        conn.fetch(_CREDS)
        # One organization call + 8 capability probes = 9 Graph calls, but
        # only ONE token acquisition.
        assert token_route.call_count == 1

    def test_expired_token_refreshes(self):
        conn = EntraConnector()
        times = iter([0.0, 10_000.0])  # first call, then far in the future

        calls = {"n": 0}

        def fake_acquire(tenant_id, client_id, client_secret, *, _sleep_fn=None):
            calls["n"] += 1
            return f"token-{calls['n']}", 60.0  # 60s TTL

        conn._acquire_token = fake_acquire  # type: ignore[method-assign]
        token1 = conn._get_token(_CREDS, _time_fn=lambda: next(times))
        token2 = conn._get_token(_CREDS, _time_fn=lambda: next(times))
        assert token1 == "token-1"
        assert token2 == "token-2"
        assert calls["n"] == 2

    def test_unexpired_token_not_refreshed(self):
        conn = EntraConnector()
        calls = {"n": 0}

        def fake_acquire(tenant_id, client_id, client_secret, *, _sleep_fn=None):
            calls["n"] += 1
            return "token-1", 3600.0

        conn._acquire_token = fake_acquire  # type: ignore[method-assign]
        t1 = conn._get_token(_CREDS, _time_fn=lambda: 0.0)
        t2 = conn._get_token(_CREDS, _time_fn=lambda: 5.0)
        assert t1 == t2 == "token-1"
        assert calls["n"] == 1

    def test_token_never_stored_as_plain_instance_dict_key(self):
        """The token cache is a dedicated dataclass, not an arbitrary dict
        attribute that could accidentally be serialized elsewhere."""
        conn = EntraConnector()
        assert hasattr(conn, "_token_cache")
        assert conn._token_cache.access_token is None
        assert conn._token_cache.expires_at is None

    def test_fresh_instance_starts_with_empty_cache(self):
        conn1 = EntraConnector()
        conn1._token_cache.access_token = "leftover-token"
        conn2 = EntraConnector()
        assert conn2._token_cache.access_token is None


# ── Tenant identity ──────────────────────────────────────────────────────────


class TestTenantIdentity:
    def test_stable_tenant_identity(self):
        id1 = EntraConnector.compute_tenant_id(_TENANT_ID, {"id": _TENANT_ID})
        id2 = EntraConnector.compute_tenant_id(_TENANT_ID, {"id": _TENANT_ID})
        assert id1 == id2

    def test_token_rotation_does_not_change_identity(self):
        # compute_tenant_id depends only on the credential's own validated
        # tenant_id, never on the token — so rotating the token cannot
        # change it.
        id_before = EntraConnector.compute_tenant_id(_TENANT_ID, {"id": _TENANT_ID})
        id_after = EntraConnector.compute_tenant_id(_TENANT_ID, {"id": _TENANT_ID})
        assert id_before == id_after

    def test_different_tenants_are_distinct(self):
        other_tenant = "33333333-3333-3333-3333-333333333333"
        id_a = EntraConnector.compute_tenant_id(_TENANT_ID, {"id": _TENANT_ID})
        id_b = EntraConnector.compute_tenant_id(other_tenant, {"id": other_tenant})
        assert id_a != id_b

    def test_display_name_change_does_not_alter_id(self):
        id_before = EntraConnector.compute_tenant_id(
            _TENANT_ID, {"id": _TENANT_ID, "displayName": "Old Name Inc"}
        )
        id_after = EntraConnector.compute_tenant_id(
            _TENANT_ID, {"id": _TENANT_ID, "displayName": "New Name LLC"}
        )
        assert id_before == id_after

    def test_identity_derived_from_credential_tenant_id(self):
        tenant_id = EntraConnector.compute_tenant_id(_TENANT_ID, {})
        assert tenant_id == f"id:{_TENANT_ID}"

    @respx.mock
    def test_fetch_uses_tenant_id_as_identity(self):
        respx.post(_TOKEN_URL).mock(return_value=_token_response())
        respx.get(f"{_GRAPH}/organization").mock(return_value=_org_response())
        _mock_probe_families_empty()
        conn = EntraConnector()
        records = conn.fetch(_CREDS)
        org_record = next(r for r in records if r["record_type"] == ENTRA_ORGANIZATION)
        assert org_record["tenant_id"] == f"id:{_TENANT_ID}"


# ── Pagination ───────────────────────────────────────────────────────────────


class TestPagination:
    @respx.mock
    def test_one_page(self):
        respx.get(f"{_GRAPH}/things").mock(
            return_value=httpx.Response(200, json={"value": [{"id": "1"}, {"id": "2"}]})
        )
        with httpx.Client(base_url=_GRAPH) as client:
            items, truncated = paginate_graph(client, "/things")
        assert [i["id"] for i in items] == ["1", "2"]
        assert truncated is False

    @respx.mock
    def test_multiple_pages_follows_next_link(self):
        page1 = httpx.Response(
            200,
            json={"value": [{"id": "1"}], "@odata.nextLink": f"{_GRAPH}/things?skip=1"},
        )
        page2 = httpx.Response(200, json={"value": [{"id": "2"}]})
        respx.get(url__regex=r".*/things.*").mock(side_effect=[page1, page2])
        with httpx.Client(base_url=_GRAPH) as client:
            items, truncated = paginate_graph(client, "/things")
        assert [i["id"] for i in items] == ["1", "2"]
        assert truncated is False

    @respx.mock
    def test_repeated_next_link_stops_and_marks_truncated(self):
        loop_resp = httpx.Response(
            200,
            json={"value": [{"id": "1"}], "@odata.nextLink": f"{_GRAPH}/things?loop=1"},
        )
        respx.get(url__regex=r".*/things.*").mock(return_value=loop_resp)
        with httpx.Client(base_url=_GRAPH) as client:
            items, truncated = paginate_graph(client, "/things", max_pages=5)
        assert len(items) < 5
        assert truncated is True

    @respx.mock
    def test_cross_origin_next_link_rejected(self):
        page1 = httpx.Response(
            200,
            json={"value": [{"id": "1"}], "@odata.nextLink": "https://evil.example/things?skip=1"},
        )
        respx.get(f"{_GRAPH}/things").mock(return_value=page1)
        with httpx.Client(base_url=_GRAPH) as client:
            items, truncated = paginate_graph(client, "/things")
        assert [i["id"] for i in items] == ["1"]
        assert truncated is True  # a nextLink was claimed but not followed

    def test_malformed_next_link_ignored(self):
        assert _extract_next_link({"value": [], "@odata.nextLink": 12345}) is None
        assert _extract_next_link({"value": []}) is None
        assert _extract_next_link("not a dict") is None

    def test_non_https_next_link_rejected(self):
        result = _validate_next_link_origin(f"http://graph.microsoft.com/v1.0/things", trusted_origin=_GRAPH.rsplit("/v1.0", 1)[0])
        assert result is None

    @respx.mock
    def test_page_cap_marks_truncated(self):
        pages = [
            httpx.Response(
                200,
                json={"value": [{"id": str(i)}], "@odata.nextLink": f"{_GRAPH}/things?p={i + 1}"},
            )
            for i in range(5)
        ]
        respx.get(url__regex=r".*/things.*").mock(side_effect=pages)
        with httpx.Client(base_url=_GRAPH) as client:
            items, truncated = paginate_graph(client, "/things", max_pages=3)
        assert len(items) == 3
        assert truncated is True

    @respx.mock
    def test_partial_later_page_failure_marks_truncated_not_raised(self):
        page1 = httpx.Response(
            200,
            json={"value": [{"id": "1"}], "@odata.nextLink": f"{_GRAPH}/things?skip=1"},
        )
        respx.get(url__regex=r".*/things.*").mock(side_effect=[page1, httpx.Response(500)])
        with httpx.Client(base_url=_GRAPH) as client:
            items, truncated = paginate_graph(client, "/things", _sleep_fn=_noop_sleep)
        assert [i["id"] for i in items] == ["1"]
        assert truncated is True

    @respx.mock
    def test_first_page_failure_raises(self):
        respx.get(f"{_GRAPH}/things").mock(return_value=httpx.Response(403))
        with httpx.Client(base_url=_GRAPH) as client:
            with pytest.raises(ConnectorError):
                paginate_graph(client, "/things")

    @respx.mock
    def test_dedupes_records_by_id(self):
        page1 = httpx.Response(
            200,
            json={"value": [{"id": "1"}, {"id": "2"}], "@odata.nextLink": f"{_GRAPH}/things?skip=2"},
        )
        page2 = httpx.Response(200, json={"value": [{"id": "2"}, {"id": "3"}]})
        respx.get(url__regex=r".*/things.*").mock(side_effect=[page1, page2])
        with httpx.Client(base_url=_GRAPH) as client:
            items, truncated = paginate_graph(client, "/things")
        ids = [i["id"] for i in items]
        assert ids.count("2") == 1
        assert set(ids) == {"1", "2", "3"}
        assert truncated is False


# ── Rate limiting / retry ────────────────────────────────────────────────────


class TestRateLimit:
    @respx.mock
    def test_429_then_success(self):
        respx.get(f"{_GRAPH}/organization").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0"}),
                _org_response(),
            ]
        )
        with httpx.Client(base_url=_GRAPH) as client:
            outcome = call_graph(client, "GET", "/organization", _sleep_fn=_noop_sleep)
        assert outcome.ok is True
        assert outcome.category == CATEGORY_SUCCESS

    @respx.mock
    def test_429_exhausted_retries(self):
        respx.get(f"{_GRAPH}/organization").mock(return_value=httpx.Response(429))
        with httpx.Client(base_url=_GRAPH) as client:
            outcome = call_graph(client, "GET", "/organization", _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_THROTTLED

    @respx.mock
    def test_503_then_success(self):
        respx.get(f"{_GRAPH}/organization").mock(
            side_effect=[httpx.Response(503), _org_response()]
        )
        with httpx.Client(base_url=_GRAPH) as client:
            outcome = call_graph(client, "GET", "/organization", _sleep_fn=_noop_sleep)
        assert outcome.ok is True

    @respx.mock
    def test_5xx_retry_budget_exhausted(self):
        respx.get(f"{_GRAPH}/organization").mock(return_value=httpx.Response(503))
        with httpx.Client(base_url=_GRAPH) as client:
            outcome = call_graph(client, "GET", "/organization", _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == "server_error"

    @respx.mock
    def test_sleep_is_mocked_never_real(self):
        sleep_calls: list[float] = []
        respx.get(f"{_GRAPH}/organization").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0.001"}),
                _org_response(),
            ]
        )
        with httpx.Client(base_url=_GRAPH) as client:
            call_graph(client, "GET", "/organization", _sleep_fn=sleep_calls.append)
        assert len(sleep_calls) == 1

    @respx.mock
    def test_401_never_retried(self):
        route = respx.get(f"{_GRAPH}/organization").mock(return_value=httpx.Response(401))
        with httpx.Client(base_url=_GRAPH) as client:
            call_graph(client, "GET", "/organization", _sleep_fn=_noop_sleep)
        assert route.call_count == 1

    @respx.mock
    def test_403_never_retried(self):
        route = respx.get(f"{_GRAPH}/organization").mock(return_value=httpx.Response(403))
        with httpx.Client(base_url=_GRAPH) as client:
            call_graph(client, "GET", "/organization", _sleep_fn=_noop_sleep)
        assert route.call_count == 1

    @respx.mock
    def test_token_endpoint_429_retried_with_backoff(self):
        respx.post(_TOKEN_URL).mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0"}),
                _token_response(),
            ]
        )
        conn = EntraConnector()
        token, expires_in = conn._acquire_token(_TENANT_ID, _CLIENT_ID, _SECRET, _sleep_fn=_noop_sleep)
        assert token == "fake-access-token"

    @respx.mock
    def test_token_endpoint_429_exhausted_raises_rate_limit_error(self):
        respx.post(_TOKEN_URL).mock(return_value=httpx.Response(429))
        conn = EntraConnector()
        with pytest.raises(RateLimitError):
            conn._acquire_token(_TENANT_ID, _CLIENT_ID, _SECRET, _sleep_fn=_noop_sleep)


# ── Capability probes ────────────────────────────────────────────────────────


class TestCapabilityProbes:
    @respx.mock
    def test_mixed_available_and_denied(self):
        respx.post(_TOKEN_URL).mock(return_value=_token_response())
        respx.get(f"{_GRAPH}/organization").mock(return_value=_org_response())
        respx.get(f"{_GRAPH}/users").mock(return_value=httpx.Response(200, json={"value": []}))
        respx.get(f"{_GRAPH}/groups").mock(return_value=httpx.Response(403))
        for path in (
            "/applications", "/servicePrincipals", "/identity/conditionalAccess/policies",
            "/policies/authenticationMethodsPolicy", "/directoryRoles", "/oauth2PermissionGrants",
        ):
            respx.get(url__regex=re.escape(path) + r".*").mock(
                return_value=httpx.Response(200, json={"value": []})
            )
        conn = EntraConnector()
        records = conn.fetch(_CREDS)
        capabilities = {r["family"]: r["status"] for r in records if r["record_type"] == ENTRA_API_CAPABILITY}
        assert capabilities["users"] == CAPABILITY_AVAILABLE
        assert capabilities["groups"] == CAPABILITY_DENIED

    @respx.mock
    def test_unsupported_optional_family_reports_unsupported(self):
        respx.post(_TOKEN_URL).mock(return_value=_token_response())
        respx.get(f"{_GRAPH}/organization").mock(return_value=_org_response())
        respx.get(f"{_GRAPH}/identity/conditionalAccess/policies").mock(return_value=httpx.Response(404))
        for path in (
            "/users", "/groups", "/applications", "/servicePrincipals",
            "/policies/authenticationMethodsPolicy", "/directoryRoles", "/oauth2PermissionGrants",
        ):
            respx.get(url__regex=re.escape(path) + r".*").mock(
                return_value=httpx.Response(200, json={"value": []})
            )
        conn = EntraConnector()
        records = conn.fetch(_CREDS)
        capabilities = {r["family"]: r["status"] for r in records if r["record_type"] == ENTRA_API_CAPABILITY}
        assert capabilities["conditional_access"] == CAPABILITY_UNSUPPORTED

    @respx.mock
    def test_throttled_family_reports_throttled(self):
        respx.post(_TOKEN_URL).mock(return_value=_token_response())
        respx.get(f"{_GRAPH}/organization").mock(return_value=_org_response())
        respx.get(f"{_GRAPH}/directoryRoles").mock(return_value=httpx.Response(429))
        for path in (
            "/users", "/groups", "/applications", "/servicePrincipals",
            "/identity/conditionalAccess/policies", "/policies/authenticationMethodsPolicy",
            "/oauth2PermissionGrants",
        ):
            respx.get(url__regex=re.escape(path) + r".*").mock(
                return_value=httpx.Response(200, json={"value": []})
            )
        conn = EntraConnector()
        records = conn.fetch(_CREDS)
        capabilities = {r["family"]: r["status"] for r in records if r["record_type"] == ENTRA_API_CAPABILITY}
        assert capabilities["directory_roles"] == CAPABILITY_THROTTLED

    def test_probes_use_minimal_top_1(self):
        for family, path, params in EntraConnector._CAPABILITY_PROBES:
            if "$top" in params:
                assert params["$top"] == "1"

    def test_eight_families_probed(self):
        assert len(EntraConnector._CAPABILITY_PROBES) == 8


# ── Sensitive-data safety ────────────────────────────────────────────────────


class TestSensitiveDataSafety:
    @respx.mock
    def test_client_secret_absent_from_records(self):
        respx.post(_TOKEN_URL).mock(return_value=_token_response())
        respx.get(f"{_GRAPH}/organization").mock(return_value=_org_response())
        _mock_probe_families_empty()
        conn = EntraConnector()
        records = conn.fetch(_CREDS)
        blob = str(records)
        assert _SECRET not in blob

    @respx.mock
    def test_access_token_absent_from_records(self):
        respx.post(_TOKEN_URL).mock(return_value=_token_response(token="super-secret-access-token"))
        respx.get(f"{_GRAPH}/organization").mock(return_value=_org_response())
        _mock_probe_families_empty()
        conn = EntraConnector()
        records = conn.fetch(_CREDS)
        blob = str(records)
        assert "super-secret-access-token" not in blob

    @respx.mock
    def test_authorization_header_absent_from_records(self):
        respx.post(_TOKEN_URL).mock(return_value=_token_response())
        respx.get(f"{_GRAPH}/organization").mock(return_value=_org_response())
        _mock_probe_families_empty()
        conn = EntraConnector()
        records = conn.fetch(_CREDS)
        blob = str(records)
        assert "Authorization" not in blob
        assert "Bearer" not in blob

    @respx.mock
    def test_raw_token_response_body_absent_from_records(self):
        respx.post(_TOKEN_URL).mock(return_value=_token_response())
        respx.get(f"{_GRAPH}/organization").mock(return_value=_org_response())
        _mock_probe_families_empty()
        conn = EntraConnector()
        records = conn.fetch(_CREDS)
        blob = str(records)
        assert "token_type" not in blob
        assert "expires_in" not in blob
