"""Sentry provider foundation tests (Sentry message 1 of 8).

Covers the connector architecture built in this message: organization
slug/auth-token validation, bearer-token authentication over the Sentry
SaaS REST API, stable organization identity derived from the organization
detail response's immutable ``id`` field, the fail-soft API-call wrapper
with bounded 429/5xx retry, trusted-origin-constrained pagination, and
read-only capability probes for the 10 future record families. No
projects, teams, members, alert rules, integrations, webhooks,
repositories, ownership rules, or releases are collected yet — that
begins in later messages.

All tests are pure-mock (respx) or unit-level; no real Sentry organization
is contacted.
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
from app.connectors.sentry import (
    CATEGORY_AUTH_FAILED,
    CATEGORY_SUCCESS,
    CATEGORY_THROTTLED,
    CallOutcome,
    SentryConnector,
    _parse_link_header,
    call_sentry,
    paginate_sentry,
)
from app.connectors.sentry_schema import (
    CAPABILITY_AVAILABLE,
    CAPABILITY_DENIED,
    CAPABILITY_FAMILIES,
    CAPABILITY_FAMILY_ISSUE_ALERTS,
    CAPABILITY_FAMILY_OWNERSHIP_RULES,
    CAPABILITY_FAMILY_WEBHOOKS,
    CAPABILITY_MALFORMED,
    CAPABILITY_THROTTLED,
    CAPABILITY_TIMED_OUT,
    CAPABILITY_UNAVAILABLE,
    CAPABILITY_UNSUPPORTED,
    SENTRY_API_CAPABILITY,
    SENTRY_ORGANIZATION,
    STRUCTURALLY_UNSUPPORTED_FAMILIES,
    SentryCredentialError,
    validate_auth_token,
    validate_organization_slug,
)

_SLUG = "my-organization"
_TOKEN = "fake-sentry-auth-token-value"
_CREDS = {"organization_slug": _SLUG, "auth_token": _TOKEN}
_BASE = "https://sentry.io/api/0"


def _noop_sleep(_seconds: float) -> None:
    """Injected in place of time.sleep so retry tests never really sleep."""


def _org_response(
    *, org_id="123456", slug=_SLUG, name="My Organization", status_id="active",
    date_created="2020-01-01T00:00:00.000Z",
) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": org_id,
            "slug": slug,
            "name": name,
            "status": {"id": status_id, "name": status_id.capitalize()},
            "dateCreated": date_created,
        },
    )


def _ok_probe_response() -> httpx.Response:
    return httpx.Response(200, json=[])


# ── Organization slug / auth token validation ───────────────────────────────


class TestValidateOrganizationSlug:
    def test_valid_slug_accepted(self):
        assert validate_organization_slug("my-organization") == "my-organization"

    def test_uppercase_lowercased(self):
        assert validate_organization_slug("My-Organization") == "my-organization"

    def test_url_scheme_rejected(self):
        with pytest.raises(SentryCredentialError):
            validate_organization_slug("https://evil.example")

    def test_path_rejected(self):
        with pytest.raises(SentryCredentialError):
            validate_organization_slug("my-organization/evil")

    def test_query_fragment_rejected(self):
        with pytest.raises(SentryCredentialError):
            validate_organization_slug("my-organization?x=1")

    def test_dot_rejected(self):
        with pytest.raises(SentryCredentialError):
            validate_organization_slug("my.organization")

    def test_whitespace_rejected(self):
        with pytest.raises(SentryCredentialError):
            validate_organization_slug("my organization")

    def test_empty_string_rejected(self):
        with pytest.raises(SentryCredentialError):
            validate_organization_slug("")

    def test_non_string_rejected(self):
        with pytest.raises(SentryCredentialError):
            validate_organization_slug(None)


class TestValidateAuthToken:
    def test_valid_token_accepted(self):
        assert validate_auth_token(_TOKEN) == _TOKEN

    def test_empty_rejected(self):
        with pytest.raises(SentryCredentialError):
            validate_auth_token("")

    def test_non_string_rejected(self):
        with pytest.raises(SentryCredentialError):
            validate_auth_token(None)

    def test_whitespace_only_rejected(self):
        with pytest.raises(SentryCredentialError):
            validate_auth_token("   ")

    def test_no_prefix_format_enforced(self):
        """Current official docs do not confirm a stable token-prefix
        contract — any non-empty string is accepted; Sentry's own API is
        the source of truth for acceptance."""
        assert validate_auth_token("arbitrary-token-shape") == "arbitrary-token-shape"


# ── Authentication ────────────────────────────────────────────────────────────


class TestAuthentication:
    @respx.mock
    def test_valid_credentials_succeed(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=_org_response())
        conn = SentryConnector()
        assert conn.validate_credentials(_CREDS) is True

    @respx.mock
    def test_invalid_token_raises_authentication_error(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=httpx.Response(401))
        conn = SentryConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials(_CREDS)

    @respx.mock
    def test_permission_denied_raises_authentication_error(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=httpx.Response(403))
        conn = SentryConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials(_CREDS)

    @respx.mock
    def test_organization_not_found_raises_connector_error(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=httpx.Response(404))
        conn = SentryConnector()
        with pytest.raises(ConnectorError):
            conn.validate_credentials(_CREDS)

    def test_missing_token_raises_before_any_request(self):
        conn = SentryConnector()
        with pytest.raises(SentryCredentialError):
            conn.validate_credentials({"organization_slug": _SLUG})

    def test_malformed_organization_slug_raises_before_any_request(self):
        conn = SentryConnector()
        with pytest.raises(SentryCredentialError):
            conn.validate_credentials({"organization_slug": "https://evil.example", "auth_token": _TOKEN})

    @respx.mock
    def test_timeout_raises_network_error(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(side_effect=httpx.ConnectTimeout("timed out"))
        conn = SentryConnector()
        with pytest.raises(NetworkError):
            conn.validate_credentials(_CREDS)

    @respx.mock
    def test_429_raises_rate_limit_error_after_exhausted_retries(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=httpx.Response(429))
        conn = SentryConnector()
        with pytest.raises(RateLimitError):
            with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
                outcome = call_sentry(client, f"/organizations/{_SLUG}/", _sleep_fn=_noop_sleep)
                from app.connectors.sentry import _raise_for_outcome
                _raise_for_outcome(outcome)

    @respx.mock
    def test_503_retried_then_succeeds(self):
        route = respx.get(f"{_BASE}/organizations/{_SLUG}/")
        route.side_effect = [httpx.Response(503), _org_response()]
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            outcome = call_sentry(client, f"/organizations/{_SLUG}/", _sleep_fn=_noop_sleep)
        assert outcome.ok is True
        assert outcome.category == CATEGORY_SUCCESS

    @respx.mock
    def test_401_never_retried(self):
        route = respx.get(f"{_BASE}/organizations/{_SLUG}/")
        route.mock(return_value=httpx.Response(401))
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            outcome = call_sentry(client, f"/organizations/{_SLUG}/", _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_AUTH_FAILED
        assert route.call_count == 1

    @respx.mock
    def test_403_never_retried(self):
        route = respx.get(f"{_BASE}/organizations/{_SLUG}/")
        route.mock(return_value=httpx.Response(403))
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            outcome = call_sentry(client, f"/organizations/{_SLUG}/", _sleep_fn=_noop_sleep)
        assert route.call_count == 1

    @respx.mock
    def test_429_bounded_retry_exhausted(self):
        route = respx.get(f"{_BASE}/organizations/{_SLUG}/")
        route.mock(return_value=httpx.Response(429))
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            outcome = call_sentry(client, f"/organizations/{_SLUG}/", _sleep_fn=_noop_sleep)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_THROTTLED
        # 1 initial + 4 retries = 5 total calls.
        assert route.call_count == 5


# ── Organization identity ────────────────────────────────────────────────────


class TestOrganizationIdentity:
    def test_compute_organization_id_from_string(self):
        assert SentryConnector.compute_organization_id("123456") == "id:123456"

    def test_compute_organization_id_from_int(self):
        assert SentryConnector.compute_organization_id(123456) == "id:123456"

    def test_compute_organization_id_none_for_missing(self):
        assert SentryConnector.compute_organization_id(None) is None

    def test_compute_organization_id_none_for_empty_string(self):
        assert SentryConnector.compute_organization_id("") is None

    @respx.mock
    def test_fetch_establishes_stable_identity(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=_org_response(org_id="999"))
        for family, path in [
            ("projects", "projects"), ("teams", "teams"), ("members", "members"),
            ("alert-rules", "alert-rules"), ("integrations", "integrations"),
            ("repos", "repos"), ("releases", "releases"),
        ]:
            respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=_ok_probe_response())
        conn = SentryConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        org_record = next(r for r in records if r["record_type"] == SENTRY_ORGANIZATION)
        assert org_record["organization_id"] == "id:999"
        assert org_record["record_id"] == "id:999"

    @respx.mock
    def test_slug_rename_preserves_identity(self):
        """The stable organization_id is derived from the immutable `id`
        field, never the slug — a slug rename must not change identity."""
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(
            return_value=_org_response(org_id="999", slug="renamed-org")
        )
        for path in ["projects", "teams", "members", "alert-rules", "integrations", "repos", "releases"]:
            respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=_ok_probe_response())
        conn = SentryConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        org_record = next(r for r in records if r["record_type"] == SENTRY_ORGANIZATION)
        assert org_record["organization_id"] == "id:999"
        assert org_record["slug"] == "renamed-org"

    @respx.mock
    def test_missing_id_field_raises_connector_error(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(
            return_value=httpx.Response(200, json={"slug": _SLUG, "name": "X"})
        )
        conn = SentryConnector()
        with pytest.raises(ConnectorError):
            conn.fetch(_CREDS, _sleep_fn=_noop_sleep)

    @respx.mock
    def test_non_dict_response_raises_connector_error(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=httpx.Response(200, json=[1, 2, 3]))
        conn = SentryConnector()
        with pytest.raises(ConnectorError):
            conn.fetch(_CREDS, _sleep_fn=_noop_sleep)

    @respx.mock
    def test_malformed_json_raises_connector_error(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(
            return_value=httpx.Response(200, content=b"not json")
        )
        conn = SentryConnector()
        with pytest.raises(ConnectorError):
            conn.fetch(_CREDS, _sleep_fn=_noop_sleep)


# ── Capability probes ────────────────────────────────────────────────────────


class TestCapabilityProbes:
    @respx.mock
    def test_all_families_available(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=_org_response())
        for path in ["projects", "teams", "members", "alert-rules", "integrations", "repos", "releases"]:
            respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=_ok_probe_response())
        conn = SentryConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        capability_records = [r for r in records if r["record_type"] == SENTRY_API_CAPABILITY]
        assert {r["family"] for r in capability_records} == set(CAPABILITY_FAMILIES)
        for r in capability_records:
            if r["family"] in STRUCTURALLY_UNSUPPORTED_FAMILIES:
                assert r["status"] == CAPABILITY_UNSUPPORTED
            else:
                assert r["status"] == CAPABILITY_AVAILABLE

    @respx.mock
    def test_mixed_available_denied(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=_org_response())
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=_ok_probe_response())
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=httpx.Response(403))
        for path in ["members", "alert-rules", "integrations", "repos", "releases"]:
            respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=_ok_probe_response())
        conn = SentryConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        by_family = {r["family"]: r["status"] for r in records if r["record_type"] == SENTRY_API_CAPABILITY}
        assert by_family["projects"] == CAPABILITY_AVAILABLE
        assert by_family["teams"] == CAPABILITY_DENIED
        # Organization is still emitted even with one family denied.
        assert any(r["record_type"] == SENTRY_ORGANIZATION for r in records)

    @respx.mock
    def test_unsupported_family_via_404(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=_org_response())
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(404))
        for path in ["projects", "teams", "members", "alert-rules", "integrations", "releases"]:
            respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=_ok_probe_response())
        conn = SentryConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        by_family = {r["family"]: r["status"] for r in records if r["record_type"] == SENTRY_API_CAPABILITY}
        assert by_family["repositories"] == CAPABILITY_UNSUPPORTED

    @respx.mock
    def test_rate_limited_family(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=_org_response())
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=httpx.Response(429))
        for path in ["projects", "teams", "alert-rules", "integrations", "repos", "releases"]:
            respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=_ok_probe_response())
        conn = SentryConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        by_family = {r["family"]: r["status"] for r in records if r["record_type"] == SENTRY_API_CAPABILITY}
        assert by_family["members"] == CAPABILITY_THROTTLED

    @respx.mock
    def test_timed_out_family(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=_org_response())
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(side_effect=httpx.ConnectTimeout("x"))
        for path in ["projects", "teams", "members", "alert-rules", "repos", "releases"]:
            respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=_ok_probe_response())
        conn = SentryConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        by_family = {r["family"]: r["status"] for r in records if r["record_type"] == SENTRY_API_CAPABILITY}
        assert by_family["integrations"] == CAPABILITY_TIMED_OUT

    @respx.mock
    def test_malformed_family(self):
        """Capability probes are status-only (never parse the response
        body — see the module docstring) so a 200-with-invalid-JSON body
        still counts as available; CAPABILITY_MALFORMED is reachable via
        a genuinely unclassifiable transport-level failure instead."""
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=_org_response())
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(
            side_effect=RuntimeError("completely unclassified failure")
        )
        for path in ["projects", "teams", "members", "alert-rules", "integrations", "repos"]:
            respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=_ok_probe_response())
        conn = SentryConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        by_family = {r["family"]: r["status"] for r in records if r["record_type"] == SENTRY_API_CAPABILITY}
        assert by_family["releases"] == CAPABILITY_MALFORMED

    @respx.mock
    def test_200_with_invalid_json_body_still_available(self):
        """Probes never parse the response body — only the HTTP status
        matters for a capability probe, so a malformed JSON body on a 2xx
        response does not downgrade the family's status."""
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=_org_response())
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(
            return_value=httpx.Response(200, content=b"not json")
        )
        for path in ["projects", "teams", "members", "alert-rules", "integrations", "repos"]:
            respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=_ok_probe_response())
        conn = SentryConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        by_family = {r["family"]: r["status"] for r in records if r["record_type"] == SENTRY_API_CAPABILITY}
        assert by_family["releases"] == CAPABILITY_AVAILABLE

    @respx.mock
    def test_structurally_unsupported_families_never_call_http(self):
        """issue_alerts, webhooks, ownership_rules always report
        unsupported WITHOUT an HTTP call — verified by asserting no route
        was ever registered/matched for any guessed project-scoped path."""
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=_org_response())
        for path in ["projects", "teams", "members", "alert-rules", "integrations", "repos", "releases"]:
            respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=_ok_probe_response())
        conn = SentryConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        by_family = {r["family"]: r["status"] for r in records if r["record_type"] == SENTRY_API_CAPABILITY}
        assert by_family[CAPABILITY_FAMILY_ISSUE_ALERTS] == CAPABILITY_UNSUPPORTED
        assert by_family[CAPABILITY_FAMILY_WEBHOOKS] == CAPABILITY_UNSUPPORTED
        assert by_family[CAPABILITY_FAMILY_OWNERSHIP_RULES] == CAPABILITY_UNSUPPORTED

    @respx.mock
    def test_independent_statuses_organization_still_emitted(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=_org_response())
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(403))
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=httpx.Response(429))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(side_effect=httpx.ConnectTimeout("x"))
        for path in ["alert-rules", "integrations", "repos", "releases"]:
            respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=_ok_probe_response())
        conn = SentryConnector()
        records = conn.fetch(_CREDS, _sleep_fn=_noop_sleep)
        assert any(r["record_type"] == SENTRY_ORGANIZATION for r in records)
        by_family = {r["family"]: r["status"] for r in records if r["record_type"] == SENTRY_API_CAPABILITY}
        assert by_family["projects"] == CAPABILITY_DENIED
        assert by_family["teams"] == CAPABILITY_THROTTLED
        assert by_family["members"] == CAPABILITY_TIMED_OUT
        assert by_family["metric_alerts"] == CAPABILITY_AVAILABLE


# ── Pagination ───────────────────────────────────────────────────────────────


class TestLinkHeaderParsing:
    def test_next_and_previous_parsed(self):
        header = (
            f'<{_BASE}/organizations/{_SLUG}/projects/?&cursor=0:0:1>; rel="previous"; results="false"; cursor="0:0:1", '
            f'<{_BASE}/organizations/{_SLUG}/projects/?&cursor=0:100:0>; rel="next"; results="true"; cursor="0:100:0"'
        )
        links = _parse_link_header(header, trusted_origin="https://sentry.io")
        assert links["next"]["results"] is True
        assert links["next"]["url"] is not None
        assert links["previous"]["results"] is False

    def test_results_false_means_natural_end(self):
        header = f'<{_BASE}/x?cursor=0:100:0>; rel="next"; results="false"; cursor="0:100:0"'
        links = _parse_link_header(header, trusted_origin="https://sentry.io")
        assert links["next"]["results"] is False

    def test_cross_origin_next_rejected(self):
        header = '<https://evil.example/organizations/x/projects/?cursor=0:100:0>; rel="next"; results="true"; cursor="0:100:0"'
        links = _parse_link_header(header, trusted_origin="https://sentry.io")
        assert links["next"]["url"] is None

    def test_malformed_header_returns_empty(self):
        links = _parse_link_header("garbage-not-a-link-header", trusted_origin="https://sentry.io")
        assert links == {}

    def test_http_scheme_next_rejected(self):
        header = f'<http://sentry.io/organizations/x/projects/?cursor=0:100:0>; rel="next"; results="true"'
        links = _parse_link_header(header, trusted_origin="https://sentry.io")
        assert links["next"]["url"] is None


class TestPagination:
    @respx.mock
    def test_single_page_no_next(self):
        respx.get(f"{_BASE}/x").mock(
            return_value=httpx.Response(
                200, json=[{"id": "1"}],
                headers={"Link": f'<{_BASE}/x?cursor=0:0:1>; rel="previous"; results="false"; cursor="0:0:1", <{_BASE}/x?cursor=0:100:0>; rel="next"; results="false"; cursor="0:100:0"'},
            )
        )
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            items, truncated = paginate_sentry(client, "/x", _sleep_fn=_noop_sleep)
        assert len(items) == 1
        assert truncated is False

    @respx.mock
    def test_multiple_pages_followed(self):
        page1 = httpx.Response(
            200, json=[{"id": "1"}],
            headers={"Link": f'<{_BASE}/x?cursor=0:0:1>; rel="previous"; results="false"; cursor="0:0:1", <{_BASE}/x?cursor=0:100:0>; rel="next"; results="true"; cursor="0:100:0"'},
        )
        page2 = httpx.Response(
            200, json=[{"id": "2"}],
            headers={"Link": f'<{_BASE}/x?cursor=0:100:1>; rel="previous"; results="true"; cursor="0:100:1", <{_BASE}/x?cursor=0:200:0>; rel="next"; results="false"; cursor="0:200:0"'},
        )
        respx.get(url__regex=r".*/x.*").mock(side_effect=[page1, page2])
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            items, truncated = paginate_sentry(client, "/x", _sleep_fn=_noop_sleep)
        assert len(items) == 2
        assert truncated is False

    @respx.mock
    def test_repeated_cursor_stops_and_marks_truncated(self):
        page = httpx.Response(
            200, json=[{"id": "1"}],
            headers={"Link": f'<{_BASE}/x?cursor=0:0:1>; rel="previous"; results="false", <{_BASE}/x?cursor=0:100:0>; rel="next"; results="true"; cursor="0:100:0"'},
        )
        respx.get(url__regex=r".*/x.*").mock(side_effect=[page, page])
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            items, truncated = paginate_sentry(client, "/x", _sleep_fn=_noop_sleep)
        assert truncated is True

    @respx.mock
    def test_malformed_link_header_on_later_page_is_truncated(self):
        page1 = httpx.Response(
            200, json=[{"id": "1"}],
            headers={"Link": f'<{_BASE}/x?cursor=0:100:0>; rel="next"; results="true"; cursor="0:100:0"'},
        )
        page2 = httpx.Response(200, json=[{"id": "2"}])  # no Link header at all
        respx.get(url__regex=r".*/x.*").mock(side_effect=[page1, page2])
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            items, truncated = paginate_sentry(client, "/x", _sleep_fn=_noop_sleep)
        assert truncated is True
        assert len(items) == 2

    @respx.mock
    def test_untrusted_next_url_rejected_and_truncated(self):
        page1 = httpx.Response(
            200, json=[{"id": "1"}],
            headers={"Link": '<https://evil.example/x?cursor=0:100:0>; rel="next"; results="true"; cursor="0:100:0"'},
        )
        respx.get(url__regex=r".*/x.*").mock(return_value=page1)
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            items, truncated = paginate_sentry(client, "/x", _sleep_fn=_noop_sleep)
        assert truncated is True
        assert len(items) == 1

    @respx.mock
    def test_later_page_403_stops_but_returns_partial(self):
        page1 = httpx.Response(
            200, json=[{"id": "1"}],
            headers={"Link": f'<{_BASE}/x?cursor=0:100:0>; rel="next"; results="true"; cursor="0:100:0"'},
        )
        respx.get(url__regex=r".*/x.*").mock(side_effect=[page1, httpx.Response(403)])
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            items, truncated = paginate_sentry(client, "/x", _sleep_fn=_noop_sleep)
        assert truncated is True
        assert len(items) == 1

    @respx.mock
    def test_later_page_429_retried_then_succeeds_not_truncated(self):
        page1 = httpx.Response(
            200, json=[{"id": "1"}],
            headers={"Link": f'<{_BASE}/x?cursor=0:100:0>; rel="next"; results="true"; cursor="0:100:0"'},
        )
        page2 = httpx.Response(
            200, json=[{"id": "2"}],
            headers={"Link": f'<{_BASE}/x?cursor=0:200:0>; rel="next"; results="false"; cursor="0:200:0"'},
        )
        respx.get(url__regex=r".*/x.*").mock(side_effect=[page1, httpx.Response(429), page2])
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            items, truncated = paginate_sentry(client, "/x", _sleep_fn=_noop_sleep)
        assert truncated is False
        assert len(items) == 2

    @respx.mock
    def test_first_page_failure_raises(self):
        respx.get(url__regex=r".*/x.*").mock(return_value=httpx.Response(401))
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            with pytest.raises(AuthenticationError):
                paginate_sentry(client, "/x", _sleep_fn=_noop_sleep)

    @respx.mock
    def test_deterministic_ordering_and_no_duplicate_ids(self):
        page1 = httpx.Response(
            200, json=[{"id": "1"}, {"id": "2"}],
            headers={"Link": f'<{_BASE}/x?cursor=0:100:0>; rel="next"; results="true"; cursor="0:100:0"'},
        )
        page2 = httpx.Response(
            200, json=[{"id": "2"}, {"id": "3"}],  # id "2" repeated — server overlap
            headers={"Link": f'<{_BASE}/x?cursor=0:200:0>; rel="next"; results="false"; cursor="0:200:0"'},
        )
        respx.get(url__regex=r".*/x.*").mock(side_effect=[page1, page2])
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            items, truncated = paginate_sentry(client, "/x", _sleep_fn=_noop_sleep)
        ids = [i["id"] for i in items]
        assert ids == ["1", "2", "3"]
        assert truncated is False

    @respx.mock
    def test_max_pages_bound_marks_truncated(self):
        """An endlessly-paginating server (every page advertises another
        `results="true"` next cursor) must never cause an infinite loop —
        `max_pages` bounds it and the result is reported truncated."""
        call_count = 0

        def _endless_next_page(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(
                200, json=[{"id": str(call_count)}],
                headers={"Link": f'<{_BASE}/x?cursor=0:{call_count * 100}:0>; rel="next"; results="true"; cursor="0:{call_count * 100}:0"'},
            )

        respx.get(url__regex=r".*/x.*").mock(side_effect=_endless_next_page)
        with httpx.Client(base_url=_BASE, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
            items, truncated = paginate_sentry(client, "/x", max_pages=3, _sleep_fn=_noop_sleep)
        assert truncated is True
        assert len(items) == 3
