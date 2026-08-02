"""Sentry HTTP reliability, trusted-origin, and isolation tests (Sentry
message 7 of 8).

Complements ``test_sentry_foundation.py``'s message-1 pagination/retry
coverage (single/multi-page, repeated cursor, malformed Link, untrusted
next URL, later-page 403/429, max-page exhaustion, dedup) with scenarios
not yet covered: explicit 404-never-retried, additional trusted-origin
attack variants, error-message redaction, credential isolation across two
connector instances, token-rotation identity stability, and organization-
slug-rename identity stability — all via real ``SentryConnector.fetch()``
calls, not isolated helper calls only.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.connectors.sentry import SentryConnector, _parse_link_header, _TRUSTED_ORIGIN

_SLUG = "my-organization"
_TOKEN = "fake-sentry-auth-token-value"
_CREDS = {"organization_slug": _SLUG, "auth_token": _TOKEN}
_BASE = "https://sentry.io/api/0"


def _noop_sleep(_seconds: float) -> None:
    pass


def _link_header(*, has_next: bool, path: str, cursor: str) -> str:
    prev = f'<https://sentry.io{path}?cursor=0:0:1>; rel="previous"; results="false"; cursor="0:0:1"'
    next_results = "true" if has_next else "false"
    nxt = f'<https://sentry.io{path}?cursor={cursor}>; rel="next"; results="{next_results}"; cursor="{cursor}"'
    return f"{prev}, {nxt}"


def _paginated(items: list, *, path: str) -> httpx.Response:
    return httpx.Response(200, json=items, headers={"Link": _link_header(has_next=False, path=path, cursor="0:100:0")})


def _mock_org(slug: str = _SLUG, org_id: str = "999", name: str = "My Org"):
    respx.get(f"{_BASE}/organizations/{slug}/").mock(
        return_value=httpx.Response(200, json={"id": org_id, "slug": slug, "name": name, "status": {"id": "active"}})
    )


def _mock_empty_collection(slug: str = _SLUG):
    for path in (
        f"/organizations/{slug}/projects/",
        f"/organizations/{slug}/teams/",
        f"/organizations/{slug}/members/",
        f"/organizations/{slug}/alert-rules/",
    ):
        respx.get(f"{_BASE}{path}").mock(return_value=_paginated([], path=f"/api/0{path}"))
    respx.get(f"{_BASE}/organizations/{slug}/releases/").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_BASE}/organizations/{slug}/integrations/").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_BASE}/organizations/{slug}/repos/").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_BASE}/organizations/{slug}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))


class Test404NeverRetried:
    @respx.mock
    def test_404_on_organization_raises_without_retry(self):
        route = respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=httpx.Response(404, json={}))
        with pytest.raises(ConnectorError):
            SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        assert route.call_count == 1

    @respx.mock
    def test_400_on_organization_raises_without_retry(self):
        route = respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=httpx.Response(400, json={}))
        with pytest.raises(ConnectorError):
            SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        assert route.call_count == 1


class TestTrustedOriginVariants:
    def test_sentry_io_accepted(self):
        links = _parse_link_header(
            '<https://sentry.io/api/0/x?cursor=1>; rel="next"; results="true"; cursor="1"',
            trusted_origin=_TRUSTED_ORIGIN,
        )
        assert links["next"]["url"] is not None

    def test_lookalike_subdomain_rejected(self):
        links = _parse_link_header(
            '<https://sentry.io.evil.example/x?cursor=1>; rel="next"; results="true"; cursor="1"',
            trusted_origin=_TRUSTED_ORIGIN,
        )
        assert links["next"]["url"] is None

    def test_lookalike_prefix_rejected(self):
        links = _parse_link_header(
            '<https://evil-sentry.io/x?cursor=1>; rel="next"; results="true"; cursor="1"',
            trusted_origin=_TRUSTED_ORIGIN,
        )
        assert links["next"]["url"] is None

    def test_http_scheme_rejected(self):
        links = _parse_link_header(
            '<http://sentry.io/x?cursor=1>; rel="next"; results="true"; cursor="1"',
            trusted_origin=_TRUSTED_ORIGIN,
        )
        assert links["next"]["url"] is None

    def test_userinfo_host_confusion_rejected(self):
        links = _parse_link_header(
            '<https://sentry.io@evil.example/x?cursor=1>; rel="next"; results="true"; cursor="1"',
            trusted_origin=_TRUSTED_ORIGIN,
        )
        assert links["next"]["url"] is None

    def test_unrelated_host_rejected(self):
        links = _parse_link_header(
            '<https://attacker.example/steal?cursor=1>; rel="next"; results="true"; cursor="1"',
            trusted_origin=_TRUSTED_ORIGIN,
        )
        assert links["next"]["url"] is None

    def test_path_and_query_never_override_origin_when_trusted(self):
        links = _parse_link_header(
            '<https://sentry.io/api/0/organizations/x/projects/?cursor=999&evil=1>; rel="next"; results="true"; cursor="999"',
            trusted_origin=_TRUSTED_ORIGIN,
        )
        assert links["next"]["url"] == "https://sentry.io/api/0/organizations/x/projects/?cursor=999&evil=1"


class TestErrorSanitization:
    @respx.mock
    def test_401_error_message_never_includes_token(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=httpx.Response(401, json={}))
        with pytest.raises(AuthenticationError) as exc_info:
            SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        assert _TOKEN not in str(exc_info.value)
        assert "bearer" not in str(exc_info.value).lower()
        assert "authorization" not in str(exc_info.value).lower()

    @respx.mock
    def test_403_error_message_never_includes_token(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(return_value=httpx.Response(403, json={}))
        with pytest.raises(AuthenticationError) as exc_info:
            SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        assert _TOKEN not in str(exc_info.value)

    @respx.mock
    def test_500_error_message_never_includes_raw_response_body(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(
            return_value=httpx.Response(500, text='{"secret_field": "leaked-internal-detail-xyz"}')
        )
        with pytest.raises(ConnectorError) as exc_info:
            SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        assert "leaked-internal-detail-xyz" not in str(exc_info.value)


class TestCredentialAndOrganizationIsolation:
    @respx.mock
    def test_two_organizations_never_leak_records(self):
        _mock_org(slug="org-a", org_id="111", name="Org A")
        _mock_empty_collection(slug="org-a")
        records_a = SentryConnector().fetch({"organization_slug": "org-a", "auth_token": "token-a"}, _sleep_fn=_noop_sleep)

        respx.calls.clear()
        _mock_org(slug="org-b", org_id="222", name="Org B")
        _mock_empty_collection(slug="org-b")
        records_b = SentryConnector().fetch({"organization_slug": "org-b", "auth_token": "token-b"}, _sleep_fn=_noop_sleep)

        org_a_ids = {r["organization_id"] for r in records_a}
        org_b_ids = {r["organization_id"] for r in records_b}
        assert org_a_ids == {"id:111"}
        assert org_b_ids == {"id:222"}
        assert org_a_ids.isdisjoint(org_b_ids)

    @respx.mock
    def test_no_token_leakage_in_any_record(self):
        _mock_org()
        _mock_empty_collection()
        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        blob = str(records)
        assert _TOKEN not in blob


class TestTokenRotationIdentity:
    @respx.mock
    def test_same_organization_new_token_stable_identity(self):
        _mock_org(org_id="999")
        _mock_empty_collection()
        records_old = SentryConnector().fetch({"organization_slug": _SLUG, "auth_token": "old-token"}, _sleep_fn=_noop_sleep)

        respx.calls.clear()
        _mock_org(org_id="999")
        _mock_empty_collection()
        records_new = SentryConnector().fetch({"organization_slug": _SLUG, "auth_token": "new-rotated-token"}, _sleep_fn=_noop_sleep)

        org_old = next(r for r in records_old if r["record_type"] == "sentry_organization")
        org_new = next(r for r in records_new if r["record_type"] == "sentry_organization")
        assert org_old["organization_id"] == org_new["organization_id"] == "id:999"


class TestSlugRenameIdentity:
    @respx.mock
    def test_slug_rename_preserves_stable_organization_id(self):
        _mock_org(slug=_SLUG, org_id="999")
        _mock_empty_collection(slug=_SLUG)
        records_before = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)

        respx.calls.clear()
        new_slug = "acme-renamed"
        respx.get(f"{_BASE}/organizations/{new_slug}/").mock(
            return_value=httpx.Response(200, json={"id": "999", "slug": new_slug, "name": "My Org", "status": {"id": "active"}})
        )
        _mock_empty_collection(slug=new_slug)
        records_after = SentryConnector().fetch({"organization_slug": new_slug, "auth_token": _TOKEN}, _sleep_fn=_noop_sleep)

        org_before = next(r for r in records_before if r["record_type"] == "sentry_organization")
        org_after = next(r for r in records_after if r["record_type"] == "sentry_organization")
        assert org_before["organization_id"] == org_after["organization_id"] == "id:999"
        assert org_after["slug"] == new_slug
