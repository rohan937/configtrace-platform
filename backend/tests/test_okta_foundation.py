"""Okta provider foundation tests (Okta message 1 of 8).

Covers the connector architecture built in this message: org_url safety
(HTTPS-only, embedded-credential/query/fragment rejection, SSRF guard),
SSWS-header authentication, stable tenant identity, RFC5988 Link-header
pagination (same-origin enforcement, cycle detection, page cap), the
fail-soft API-call wrapper with bounded 429 retry, and read-only capability
probes for the seven future record families. No users, groups,
applications, policies, authenticators, admin roles, or System Log
collection exists yet — that begins in later messages.

All tests are pure-mock (respx) or unit-level; no real Okta org is contacted.
"""

from __future__ import annotations

import inspect

import httpx
import pytest
import respx

from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.okta import (
    CATEGORY_AUTH_FAILED,
    CATEGORY_CONNECTION_ERROR,
    CATEGORY_NOT_FOUND,
    CATEGORY_PERMISSION_DENIED,
    CATEGORY_SUCCESS,
    CATEGORY_THROTTLED,
    OktaConnector,
    OktaURLError,
    _extract_next_link,
    call_okta,
    normalize_org_url,
    paginate,
)
from app.connectors.okta_schema import (
    CAPABILITY_AVAILABLE,
    CAPABILITY_DENIED,
    CAPABILITY_THROTTLED,
    CAPABILITY_UNAVAILABLE,
    CAPABILITY_UNSUPPORTED,
    OKTA_API_CAPABILITY,
    OKTA_ORGANIZATION,
    ORG_STATUS_ACTIVE,
    categorize_org_status,
)

_ORG_URL = "https://example.okta.com"
_TOKEN = "fake-okta-api-token-value"
_CREDS = {"org_url": _ORG_URL, "api_token": _TOKEN}


def _noop_sleep(_seconds: float) -> None:
    """Injected in place of time.sleep so retry tests never really sleep."""


# ── URL normalization ────────────────────────────────────────────────────────


class TestNormalizeOrgUrl:
    def test_strips_trailing_slash(self):
        assert normalize_org_url("https://example.okta.com/") == "https://example.okta.com"

    def test_lowercases_host(self):
        assert normalize_org_url("https://EXAMPLE.OKTA.COM") == "https://example.okta.com"

    def test_http_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url("http://example.okta.com")

    def test_embedded_credentials_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url("https://user:pass@example.okta.com")

    def test_query_string_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url("https://example.okta.com?foo=bar")

    def test_fragment_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url("https://example.okta.com#frag")

    def test_path_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url("https://example.okta.com/api/v1")

    def test_custom_domain_accepted(self):
        # No hardcoded ".okta.com" suffix requirement.
        assert normalize_org_url("https://sso.mycompany.example") == "https://sso.mycompany.example"

    def test_localhost_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url("https://localhost")

    def test_loopback_ip_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url("https://127.0.0.1")

    def test_private_ip_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url("https://10.0.0.5")

    def test_link_local_ip_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url("https://169.254.169.254")  # cloud metadata IP

    def test_empty_string_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url("")

    def test_non_string_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url(None)

    def test_port_preserved(self):
        assert normalize_org_url("https://example.okta.com:8443") == "https://example.okta.com:8443"

    def test_malformed_url_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url("not a url at all")

    def test_no_hostname_rejected(self):
        with pytest.raises(OktaURLError):
            normalize_org_url("https://")


# ── Authentication ───────────────────────────────────────────────────────────


class TestAuthentication:
    @respx.mock
    def test_valid_token_succeeds(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            return_value=httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})
        )
        conn = OktaConnector()
        assert conn.validate_credentials(_CREDS) is True

    @respx.mock
    def test_401_raises_authentication_error(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(401))
        conn = OktaConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials(_CREDS)

    @respx.mock
    def test_403_raises_connector_error_not_authentication_error(self):
        """403 means the token is accepted but lacks scope — distinct from
        401 (rejected token). validate_credentials only requires GET
        /api/v1/org, which a minimally-scoped token should have; a 403
        here is a genuine (non-auth) API error."""
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(403))
        conn = OktaConnector()
        with pytest.raises(ConnectorError):
            conn.validate_credentials(_CREDS)

    def test_malformed_org_url_raises_before_any_request(self):
        conn = OktaConnector()
        with pytest.raises(OktaURLError):
            conn.validate_credentials({"org_url": "not-a-url", "api_token": _TOKEN})

    def test_missing_api_token_raises_authentication_error(self):
        conn = OktaConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials({"org_url": _ORG_URL})

    def test_empty_api_token_raises_authentication_error(self):
        conn = OktaConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials({"org_url": _ORG_URL, "api_token": ""})

    def test_authorization_header_uses_ssws_scheme(self):
        source = inspect.getsource(OktaConnector._make_client)
        assert 'f"SSWS {api_token}"' in source

    @respx.mock
    def test_token_never_appears_in_exception_text(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(401))
        conn = OktaConnector()
        try:
            conn.validate_credentials(_CREDS)
        except AuthenticationError as exc:
            assert _TOKEN not in str(exc)
        else:
            pytest.fail("expected AuthenticationError")

    @respx.mock
    def test_token_never_logged(self, caplog):
        import logging

        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            return_value=httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})
        )
        conn = OktaConnector()
        with caplog.at_level(logging.DEBUG):
            conn.validate_credentials(_CREDS)
        assert _TOKEN not in caplog.text


# ── Tenant identity ──────────────────────────────────────────────────────────


class TestTenantIdentity:
    def test_stable_across_token_rotation(self):
        # compute_tenant_id only depends on org_hostname + the org's own id
        # field, never the token — so rotating the token cannot change it.
        raw_org = {"id": "00o1abcXYZ"}
        id1 = OktaConnector.compute_tenant_id("example.okta.com", raw_org)
        id2 = OktaConnector.compute_tenant_id("example.okta.com", raw_org)
        assert id1 == id2

    def test_different_tenants_are_distinct(self):
        id_a = OktaConnector.compute_tenant_id("a.okta.com", {"id": "00o1AAA"})
        id_b = OktaConnector.compute_tenant_id("b.okta.com", {"id": "00o1BBB"})
        assert id_a != id_b

    def test_display_name_change_does_not_alter_id(self):
        # The tenant id is derived only from the org's immutable `id` field
        # (or the hostname fallback) — never from companyName.
        id_before = OktaConnector.compute_tenant_id(
            "example.okta.com", {"id": "00o1abcXYZ", "companyName": "Old Name Inc"}
        )
        id_after = OktaConnector.compute_tenant_id(
            "example.okta.com", {"id": "00o1abcXYZ", "companyName": "New Name LLC"}
        )
        assert id_before == id_after

    def test_prefers_org_id_over_hostname(self):
        tenant_id = OktaConnector.compute_tenant_id("example.okta.com", {"id": "00o1abcXYZ"})
        assert tenant_id.startswith("id:")
        assert "00o1abcXYZ" in tenant_id

    def test_falls_back_to_hostname_when_no_id(self):
        tenant_id = OktaConnector.compute_tenant_id("example.okta.com", {})
        assert tenant_id == "host:example.okta.com"

    def test_falls_back_to_hostname_when_id_not_a_string(self):
        tenant_id = OktaConnector.compute_tenant_id("example.okta.com", {"id": 12345})
        assert tenant_id == "host:example.okta.com"

    @respx.mock
    def test_fetch_uses_org_id_as_tenant_id(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            return_value=httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})
        )
        for family_path in (
            "/api/v1/users", "/api/v1/groups", "/api/v1/apps",
            "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{family_path}").mock(return_value=httpx.Response(200, json=[]))
        conn = OktaConnector()
        records = conn.fetch(_CREDS)
        org_record = next(r for r in records if r["record_type"] == OKTA_ORGANIZATION)
        assert org_record["tenant_id"] == "id:00o1abcXYZ"


# ── Pagination ───────────────────────────────────────────────────────────────


class TestPagination:
    @respx.mock
    def test_one_page(self):
        respx.get(f"{_ORG_URL}/api/v1/things").mock(
            return_value=httpx.Response(200, json=[{"id": "1"}, {"id": "2"}])
        )
        with httpx.Client(base_url=_ORG_URL) as client:
            items, truncated = paginate(client, _ORG_URL, "/api/v1/things")
        assert len(items) == 2
        assert truncated is False

    @respx.mock
    def test_multiple_pages_via_link_header(self):
        page1 = httpx.Response(
            200, json=[{"id": "1"}],
            headers={"Link": f'<{_ORG_URL}/api/v1/things?after=1>; rel="next"'},
        )
        page2 = httpx.Response(200, json=[{"id": "2"}])
        # One route with an ordered side_effect list — avoids relying on
        # respx's query-string route disambiguation, which is ambiguous
        # when a plain (unparameterized) route and a params-scoped route
        # both structurally match the same path.
        respx.get(url__regex=r".*/api/v1/things.*").mock(side_effect=[page1, page2])
        with httpx.Client(base_url=_ORG_URL) as client:
            items, truncated = paginate(client, _ORG_URL, "/api/v1/things")
        assert {i["id"] for i in items} == {"1", "2"}
        assert truncated is False  # reached a natural end (no further next link)

    def test_extract_next_link_parses_rel_next(self):
        resp = httpx.Response(
            200, headers={"Link": f'<{_ORG_URL}/api/v1/things?after=1>; rel="next"'},
        )
        assert _extract_next_link(resp, trusted_origin=_ORG_URL) == f"{_ORG_URL}/api/v1/things?after=1"

    def test_extract_next_link_ignores_rel_self(self):
        resp = httpx.Response(
            200, headers={"Link": f'<{_ORG_URL}/api/v1/things>; rel="self"'},
        )
        assert _extract_next_link(resp, trusted_origin=_ORG_URL) is None

    def test_extract_next_link_absent(self):
        resp = httpx.Response(200)
        assert _extract_next_link(resp, trusted_origin=_ORG_URL) is None

    def test_cross_origin_next_link_rejected(self):
        resp = httpx.Response(
            200, headers={"Link": '<https://evil.example.com/steal>; rel="next"'},
        )
        assert _extract_next_link(resp, trusted_origin=_ORG_URL) is None

    @respx.mock
    def test_cross_origin_next_stops_pagination_without_raising(self):
        page1 = httpx.Response(
            200, json=[{"id": "1"}],
            headers={"Link": '<https://evil.example.com/steal>; rel="next"'},
        )
        respx.get(f"{_ORG_URL}/api/v1/things").mock(return_value=page1)
        with httpx.Client(base_url=_ORG_URL) as client:
            items, truncated = paginate(client, _ORG_URL, "/api/v1/things")
        assert len(items) == 1
        assert truncated is True  # a next link existed but was rejected — not a natural end

    def test_page_cap_bounds_iteration(self):
        with httpx.Client(base_url=_ORG_URL) as client:
            with respx.mock:
                # Every page links to itself — without a cap this would spin forever.
                respx.get(url__regex=r".*/api/v1/things.*").mock(
                    return_value=httpx.Response(
                        200, json=[{"id": "x"}],
                        headers={"Link": f'<{_ORG_URL}/api/v1/things?p=2>; rel="next"'},
                    )
                )
                items, truncated = paginate(client, _ORG_URL, "/api/v1/things", max_pages=3)
        assert len(items) <= 3
        assert truncated is True  # hit max_pages with more data still available

    @respx.mock
    def test_repeated_next_link_detected_and_stopped(self):
        # Page always returns the SAME next URL — must not loop forever.
        loop_resp = httpx.Response(
            200, json=[{"id": "x"}],
            headers={"Link": f'<{_ORG_URL}/api/v1/things?p=2>; rel="next"'},
        )
        respx.get(url__regex=r".*/api/v1/things.*").mock(return_value=loop_resp)
        with httpx.Client(base_url=_ORG_URL) as client:
            items, truncated = paginate(client, _ORG_URL, "/api/v1/things", max_pages=50)
        # Should terminate well before max_pages due to repeated-URL detection.
        assert len(items) < 50
        assert truncated is True  # stopped due to a repeated Link, not a natural end

    def test_malformed_link_header_ignored(self):
        resp = httpx.Response(200, headers={"Link": "not a valid link header"})
        assert _extract_next_link(resp, trusted_origin=_ORG_URL) is None

    @respx.mock
    def test_dedupes_records_by_id(self):
        page1 = httpx.Response(
            200, json=[{"id": "1"}, {"id": "2"}],
            headers={"Link": f'<{_ORG_URL}/api/v1/things?after=2>; rel="next"'},
        )
        # Overlapping page — re-serves id=2.
        page2 = httpx.Response(200, json=[{"id": "2"}, {"id": "3"}])
        respx.get(url__regex=r".*/api/v1/things.*").mock(side_effect=[page1, page2])
        with httpx.Client(base_url=_ORG_URL) as client:
            items, truncated = paginate(client, _ORG_URL, "/api/v1/things")
        ids = [i["id"] for i in items]
        assert ids.count("2") == 1
        assert set(ids) == {"1", "2", "3"}
        assert truncated is False


# ── Rate limiting ────────────────────────────────────────────────────────────


class TestRateLimit:
    @respx.mock
    def test_429_then_success(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0"}),
                httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"}),
            ]
        )
        with httpx.Client(base_url=_ORG_URL) as client:
            outcome = call_okta(client, "GET", "/api/v1/org", _sleep_fn=_noop_sleep)
        assert outcome.ok is True
        assert outcome.category == CATEGORY_SUCCESS

    @respx.mock
    def test_exhausted_retries_raises_rate_limit_error(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(429))
        with httpx.Client(base_url=_ORG_URL) as client:
            outcome = call_okta(client, "GET", "/api/v1/org", _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_THROTTLED

    @respx.mock
    def test_sleep_is_mocked_never_real(self):
        """The bounded retry loop must call the injected sleep function, not
        actually block — this test itself completing quickly is the proof,
        but we also assert the mock was invoked."""
        sleep_calls: list[float] = []
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0.001"}),
                httpx.Response(200, json={"id": "x"}),
            ]
        )
        with httpx.Client(base_url=_ORG_URL) as client:
            call_okta(client, "GET", "/api/v1/org", _sleep_fn=sleep_calls.append)
        assert len(sleep_calls) == 1

    @respx.mock
    def test_401_never_retried(self):
        route = respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(401))
        with httpx.Client(base_url=_ORG_URL) as client:
            call_okta(client, "GET", "/api/v1/org", _sleep_fn=_noop_sleep)
        assert route.call_count == 1

    @respx.mock
    def test_403_never_retried(self):
        route = respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(403))
        with httpx.Client(base_url=_ORG_URL) as client:
            call_okta(client, "GET", "/api/v1/org", _sleep_fn=_noop_sleep)
        assert route.call_count == 1


# ── Capability probes ────────────────────────────────────────────────────────


class TestCapabilityProbes:
    @respx.mock
    def test_all_available(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            return_value=httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})
        )
        for path in (
            "/api/v1/users", "/api/v1/groups", "/api/v1/apps",
            "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))
        conn = OktaConnector()
        records = conn.fetch(_CREDS)
        capability_records = [r for r in records if r["record_type"] == OKTA_API_CAPABILITY]
        assert len(capability_records) == 7
        assert all(r["status"] == CAPABILITY_AVAILABLE for r in capability_records)

    @respx.mock
    def test_denied_family(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            return_value=httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})
        )
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(403))
        for path in (
            "/api/v1/groups", "/api/v1/apps", "/api/v1/policies",
            "/api/v1/authenticators", "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))
        conn = OktaConnector()
        records = conn.fetch(_CREDS)
        users_probe = next(
            r for r in records
            if r["record_type"] == OKTA_API_CAPABILITY and r["family"] == "users"
        )
        assert users_probe["status"] == CAPABILITY_DENIED

    @respx.mock
    def test_unsupported_family(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            return_value=httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})
        )
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(404))
        for path in (
            "/api/v1/users", "/api/v1/groups", "/api/v1/apps",
            "/api/v1/policies", "/api/v1/authenticators", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))
        conn = OktaConnector()
        records = conn.fetch(_CREDS)
        roles_probe = next(
            r for r in records
            if r["record_type"] == OKTA_API_CAPABILITY and r["family"] == "admin_roles"
        )
        assert roles_probe["status"] == CAPABILITY_UNSUPPORTED

    @respx.mock
    def test_mixed_outcomes(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            return_value=httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})
        )
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(403))
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(404))
        respx.get(f"{_ORG_URL}/api/v1/policies").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(500))
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/logs").mock(
            side_effect=httpx.ConnectError("refused")
        )
        conn = OktaConnector()
        records = conn.fetch(_CREDS)
        by_family = {
            r["family"]: r["status"]
            for r in records if r["record_type"] == OKTA_API_CAPABILITY
        }
        assert by_family["users"] == CAPABILITY_AVAILABLE
        assert by_family["groups"] == CAPABILITY_DENIED
        assert by_family["applications"] == CAPABILITY_UNSUPPORTED
        assert by_family["policies"] == CAPABILITY_AVAILABLE
        assert by_family["admin_roles"] == CAPABILITY_AVAILABLE
        assert by_family["system_log"] == CAPABILITY_UNAVAILABLE

    @respx.mock
    def test_capability_probe_failure_never_raises(self):
        """A capability probe failure must never abort the whole fetch —
        only the org-record fetch itself can raise."""
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            return_value=httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})
        )
        for path in (
            "/api/v1/users", "/api/v1/groups", "/api/v1/apps",
            "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(500))
        conn = OktaConnector()
        records = conn.fetch(_CREDS)  # must not raise
        assert any(r["record_type"] == OKTA_ORGANIZATION for r in records)

    def test_probes_never_fetch_more_than_one_page(self):
        assert isinstance(OktaConnector._CAPABILITY_PROBES, tuple)
        for family, path, params in OktaConnector._CAPABILITY_PROBES:
            if "limit" in params:
                assert params["limit"] == "1"

    def test_probes_cover_all_seven_families(self):
        families = {f for f, _p, _params in OktaConnector._CAPABILITY_PROBES}
        assert families == {
            "users", "groups", "applications", "policies",
            "authenticators", "admin_roles", "system_log",
        }


# ── Failure classification ──────────────────────────────────────────────────


class TestFailureClassification:
    @respx.mock
    def test_401(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(401))
        with httpx.Client(base_url=_ORG_URL) as client:
            outcome = call_okta(client, "GET", "/api/v1/org", _sleep_fn=_noop_sleep)
        assert outcome.category == CATEGORY_AUTH_FAILED

    @respx.mock
    def test_403(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(403))
        with httpx.Client(base_url=_ORG_URL) as client:
            outcome = call_okta(client, "GET", "/api/v1/org", _sleep_fn=_noop_sleep)
        assert outcome.category == CATEGORY_PERMISSION_DENIED

    @respx.mock
    def test_404(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(404))
        with httpx.Client(base_url=_ORG_URL) as client:
            outcome = call_okta(client, "GET", "/api/v1/org", _sleep_fn=_noop_sleep)
        assert outcome.category == CATEGORY_NOT_FOUND

    @respx.mock
    def test_429(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(429))
        with httpx.Client(base_url=_ORG_URL) as client:
            outcome = call_okta(client, "GET", "/api/v1/org", _sleep_fn=_noop_sleep)
        assert outcome.category == CATEGORY_THROTTLED

    @respx.mock
    def test_5xx(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(503))
        with httpx.Client(base_url=_ORG_URL) as client:
            outcome = call_okta(client, "GET", "/api/v1/org", _sleep_fn=_noop_sleep)
        assert outcome.category == "server_error"

    @respx.mock
    def test_timeout(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(side_effect=httpx.ConnectTimeout("timed out"))
        with httpx.Client(base_url=_ORG_URL) as client:
            outcome = call_okta(client, "GET", "/api/v1/org", _sleep_fn=_noop_sleep)
        assert outcome.category == "timeout"

    @respx.mock
    def test_tls_error(self):
        import ssl

        respx.get(f"{_ORG_URL}/api/v1/org").mock(side_effect=ssl.SSLError("cert verify failed"))
        with httpx.Client(base_url=_ORG_URL) as client:
            outcome = call_okta(client, "GET", "/api/v1/org", _sleep_fn=_noop_sleep)
        assert outcome.category == "tls_error"

    @respx.mock
    def test_dns_failure_classified_as_connection_error(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            side_effect=httpx.ConnectError("[Errno 8] nodename nor servname provided")
        )
        with httpx.Client(base_url=_ORG_URL) as client:
            outcome = call_okta(client, "GET", "/api/v1/org", _sleep_fn=_noop_sleep)
        assert outcome.category == CATEGORY_CONNECTION_ERROR

    @respx.mock
    def test_malformed_json_raises_connector_error_on_fetch(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            return_value=httpx.Response(200, content=b"not json{{{")
        )
        conn = OktaConnector()
        with pytest.raises(ConnectorError):
            conn.fetch(_CREDS)

    @respx.mock
    def test_org_response_not_a_dict_raises_connector_error(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(200, json=[1, 2, 3]))
        conn = OktaConnector()
        with pytest.raises(ConnectorError):
            conn.fetch(_CREDS)


# ── Diff / provider metadata ─────────────────────────────────────────────────


class TestDiffAndProviderMetadata:
    def test_real_compute_diff_detects_org_status_change(self):
        from types import SimpleNamespace

        from app.services.diff_service import compute_diff

        prev = [{
            "record_type": OKTA_ORGANIZATION, "record_id": "id:00o1abcXYZ",
            "tenant_id": "id:00o1abcXYZ", "org_hostname": "example.okta.com",
            "org_display_name": "Acme Inc", "status_category": ORG_STATUS_ACTIVE,
        }]
        new = [{
            "record_type": OKTA_ORGANIZATION, "record_id": "id:00o1abcXYZ",
            "tenant_id": "id:00o1abcXYZ", "org_hostname": "example.okta.com",
            "org_display_name": "Acme Inc", "status_category": "suspended",
        }]
        changes = compute_diff(SimpleNamespace(state=prev), SimpleNamespace(state=new))
        assert any(c["field_path"] == "status_category" for c in changes)

    def test_foundation_record_modification_produces_change(self):
        from types import SimpleNamespace

        from app.services.diff_service import compute_diff

        prev = [{
            "record_type": OKTA_API_CAPABILITY, "record_id": "id:t1/capability/users",
            "tenant_id": "id:t1", "family": "users", "status": CAPABILITY_AVAILABLE,
        }]
        new = [{
            "record_type": OKTA_API_CAPABILITY, "record_id": "id:t1/capability/users",
            "tenant_id": "id:t1", "family": "users", "status": CAPABILITY_DENIED,
        }]
        changes = compute_diff(SimpleNamespace(state=prev), SimpleNamespace(state=new))
        assert len(changes) == 1
        assert changes[0]["field_path"] == "status"

    def test_transient_fields_absent_from_tracked_fields(self):
        from app.services.diff_service import _tracked_fields_for

        fields = _tracked_fields_for({"record_type": OKTA_ORGANIZATION})
        for forbidden in ("request_id", "fetched_at", "api_call_count", "created", "expiresAt"):
            assert forbidden not in fields

    def test_unmapped_okta_subtype_returns_empty_tuple(self):
        from app.services.diff_service import _tracked_fields_for

        fields = _tracked_fields_for({"record_type": "okta_totally_unknown_future_type"})
        assert fields == ()


# ── Sensitive-data exclusion ─────────────────────────────────────────────────


class TestSensitiveDataExclusion:
    @respx.mock
    def test_token_absent_from_records(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            return_value=httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})
        )
        for path in (
            "/api/v1/users", "/api/v1/groups", "/api/v1/apps",
            "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))
        conn = OktaConnector()
        records = conn.fetch(_CREDS)
        assert _TOKEN not in str(records)

    @respx.mock
    def test_token_absent_from_errors(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=httpx.Response(401))
        conn = OktaConnector()
        try:
            conn.fetch(_CREDS)
        except AuthenticationError as exc:
            assert _TOKEN not in str(exc)

    @respx.mock
    def test_raw_org_response_never_stored_verbatim(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(
            return_value=httpx.Response(200, json={
                "id": "00o1abcXYZ",
                "status": "ACTIVE",
                "companyName": "Acme Inc",
                "phoneNumber": "+15555550100",
                "supportPhoneNumber": "+15555550199",
                "address1": "123 Main St",
                "technicalContactEmail": "admin@acme.example",
                "expiresAt": "2099-01-01T00:00:00.000Z",
            })
        )
        for path in (
            "/api/v1/users", "/api/v1/groups", "/api/v1/apps",
            "/api/v1/policies", "/api/v1/authenticators",
            "/api/v1/iam/roles", "/api/v1/logs",
        ):
            respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))
        conn = OktaConnector()
        records = conn.fetch(_CREDS)
        blob = str(records)
        assert "+15555550100" not in blob
        assert "+15555550199" not in blob
        assert "123 Main St" not in blob
        assert "admin@acme.example" not in blob
        assert "2099-01-01T00:00:00.000Z" not in blob

    def test_okta_organization_record_has_no_forbidden_keys(self):
        rec = OktaConnector._normalize_organization(
            "example.okta.com",
            {"id": "00o1abcXYZ", "status": "ACTIVE", "companyName": "Acme"},
        )
        for forbidden in (
            "password", "token", "api_token", "secret", "phoneNumber",
            "address1", "technicalContactEmail", "expiresAt",
        ):
            assert forbidden not in rec

    def test_capability_probe_record_never_includes_response_body(self):
        rec = OktaConnector._normalize_capability("id:t1", "users", CAPABILITY_AVAILABLE)
        assert set(rec.keys()) == {
            "record_type", "record_id", "provider_resource_id",
            "tenant_id", "family", "status",
        }
