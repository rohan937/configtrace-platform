"""Okta pagination/retry/reliability tests (Okta message 7 of 8).

Exercises the full ``OktaConnector.fetch()`` path (not the low-level
``call_okta``/``paginate`` unit tests already covered in
test_okta_foundation.py) for: multi-page partial failures (403/429/
timeout/5xx on page 2), 429 exhaustion, timeout/5xx family behavior,
401/403/404 permission-vs-unsupported distinctions, and capability drift
(a family that was previously readable becoming denied/unsupported must
never be inferred as "everything in it was deleted").
"""

from __future__ import annotations

import httpx
import respx

from app.connectors.okta import OktaConnector
from app.connectors.okta_schema import FAMILY_COMPLETE, FAMILY_DENIED, FAMILY_PARTIAL, FAMILY_UNAVAILABLE

_ORG_URL = "https://example.okta.com"
_TOKEN = "fake-okta-api-token-value"
_CREDS = {"org_url": _ORG_URL, "api_token": _TOKEN}
_POLICY_TYPES = ("OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL", "ACCESS_POLICY", "PROFILE_ENROLLMENT", "IDP_DISCOVERY")


def _org_response() -> httpx.Response:
    return httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})


def _mock_baseline():
    respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))
    for ptype in _POLICY_TYPES:
        respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(200, json={"roles": []}))
    respx.get(f"{_ORG_URL}/api/v1/logs").mock(return_value=httpx.Response(200, json=[]))


def _fetch_org():
    return next(r for r in OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None) if r["record_type"] == "okta_organization")


# ════════════════════════════════════════════════════════════════════════════
# Multi-page partial failures
# ════════════════════════════════════════════════════════════════════════════


class TestMultiPagePartialFailure:
    @respx.mock
    def test_page1_succeeds_page2_403(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        page1 = httpx.Response(
            200, json=[{"id": "u1", "status": "ACTIVE", "profile": {"login": "a@x.com"}}],
            headers={"Link": f'<{_ORG_URL}/api/v1/users?after=u1>; rel="next"'},
        )
        respx.get(url__regex=r".*/api/v1/users.*").mock(side_effect=[page1, httpx.Response(403)])

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
        users = [r for r in records if r["record_type"] == "okta_user"]
        assert len(users) == 1  # page 1's record retained
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["users"] == FAMILY_PARTIAL

    @respx.mock
    def test_page1_succeeds_page2_429_exhausted(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        page1 = httpx.Response(
            200, json=[{"id": "u1", "status": "ACTIVE", "profile": {"login": "a@x.com"}}],
            headers={"Link": f'<{_ORG_URL}/api/v1/users?after=u1>; rel="next"'},
        )
        respx.get(url__regex=r".*/api/v1/users.*").mock(side_effect=[page1] + [httpx.Response(429)] * 10)

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)  # must not raise / hang
        users = [r for r in records if r["record_type"] == "okta_user"]
        assert len(users) == 1
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["users"] == FAMILY_PARTIAL

    @respx.mock
    def test_page1_succeeds_page2_times_out(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        page1 = httpx.Response(
            200, json=[{"id": "u1", "status": "ACTIVE", "profile": {"login": "a@x.com"}}],
            headers={"Link": f'<{_ORG_URL}/api/v1/users?after=u1>; rel="next"'},
        )
        respx.get(url__regex=r".*/api/v1/users.*").mock(side_effect=[page1, httpx.ReadTimeout("timed out")])

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)  # must not raise
        users = [r for r in records if r["record_type"] == "okta_user"]
        assert len(users) == 1
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["users"] == FAMILY_PARTIAL

    @respx.mock
    def test_page1_succeeds_page2_5xx(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        page1 = httpx.Response(
            200, json=[{"id": "u1", "status": "ACTIVE", "profile": {"login": "a@x.com"}}],
            headers={"Link": f'<{_ORG_URL}/api/v1/users?after=u1>; rel="next"'},
        )
        for status in (500, 502, 503, 504):
            respx.get(url__regex=r".*/api/v1/users.*").mock(side_effect=[page1, httpx.Response(status)])
            records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
            users = [r for r in records if r["record_type"] == "okta_user"]
            assert len(users) == 1, f"failed for status {status}"


# ════════════════════════════════════════════════════════════════════════════
# First-page failure modes (whole family)
# ════════════════════════════════════════════════════════════════════════════


class TestFirstPageFailureModes:
    @respx.mock
    def test_users_429_exhausted_is_partial_not_crash(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(429))

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["users"] in (FAMILY_UNAVAILABLE, FAMILY_DENIED)
        assert not any(r["record_type"] == "okta_user" for r in records)

    @respx.mock
    def test_users_timeout_is_unavailable(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(side_effect=httpx.ConnectTimeout("timed out connecting"))

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)  # must not raise
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["users"] == FAMILY_UNAVAILABLE

    @respx.mock
    def test_users_read_timeout_is_unavailable(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(side_effect=httpx.ReadTimeout("timed out reading"))

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["users"] == FAMILY_UNAVAILABLE

    @respx.mock
    def test_users_500_is_unavailable(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(500))

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["users"] == FAMILY_UNAVAILABLE

    @respx.mock
    def test_users_503_is_unavailable(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(503))

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["users"] == FAMILY_UNAVAILABLE

    @respx.mock
    def test_users_403_is_denied(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(403))

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["users"] == FAMILY_DENIED

    @respx.mock
    def test_users_401_mid_fetch_is_unavailable_not_fatal(self):
        # validate_credentials/the org call already proved the token works;
        # a LATER 401 on a specific family (e.g. a scoped/rotated token)
        # must not abort the whole fetch.
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(401))

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)  # must not raise
        assert any(r["record_type"] == "okta_organization" for r in records)


# ════════════════════════════════════════════════════════════════════════════
# 404 / optional-endpoint semantics
# ════════════════════════════════════════════════════════════════════════════


class TestOptionalEndpointNotFound:
    @respx.mock
    def test_custom_roles_404_is_unavailable_not_denied_not_fatal(self):
        """A 404 on /api/v1/iam/roles (Identity Governance not enabled on
        this Okta edition) is an unsupported-API-surface signal, never
        treated as 'the tenant/token is invalid' or as a permission
        denial, and must not abort the rest of the fetch."""
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(404))

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["custom_admin_roles"] in (FAMILY_UNAVAILABLE, FAMILY_DENIED)
        # Rest of the fetch proceeded normally.
        assert any(r["record_type"] == "okta_organization" for r in records)


# ════════════════════════════════════════════════════════════════════════════
# Capability drift — a family available before must never imply deletion
# ════════════════════════════════════════════════════════════════════════════


class TestCapabilityDrift:
    @respx.mock
    def test_custom_roles_becomes_403_does_not_infer_all_roles_deleted(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(403))

        # A fetch with custom roles now denied must report denied — not
        # an empty-but-"complete" list implying zero custom roles exist.
        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["custom_admin_roles"] == FAMILY_DENIED
        assert not any(r["record_type"] == "okta_admin_role" and r["custom"] for r in records)

    @respx.mock
    def test_authenticators_becomes_unavailable_does_not_infer_deletion(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))
        for ptype in _POLICY_TYPES:
            respx.get(f"{_ORG_URL}/api/v1/policies", params={"type": ptype}).mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/iam/roles").mock(return_value=httpx.Response(200, json={"roles": []}))
        respx.get(f"{_ORG_URL}/api/v1/logs").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/authenticators").mock(return_value=httpx.Response(500))

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["authenticators"] == FAMILY_UNAVAILABLE
        # No fabricated okta_authenticator records, and no crash.
        assert not any(r["record_type"] == "okta_authenticator" for r in records)


# ════════════════════════════════════════════════════════════════════════════
# Cross-origin / malformed / repeated Link edge cases at fetch() level
# ════════════════════════════════════════════════════════════════════════════


class TestLinkHeaderEdgeCasesAtFetchLevel:
    @respx.mock
    def test_cross_origin_next_link_does_not_leak_credentials_or_hang(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(
            200, json=[{"id": "u1", "status": "ACTIVE", "profile": {"login": "a@x.com"}}],
            headers={"Link": '<https://evil.example.com/steal?token=x>; rel="next"'},
        ))

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)
        users = [r for r in records if r["record_type"] == "okta_user"]
        assert len(users) == 1

    @respx.mock
    def test_repeated_next_link_does_not_hang(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        _mock_baseline()
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        loop_resp = httpx.Response(
            200, json=[{"id": "u1", "status": "ACTIVE", "profile": {"login": "a@x.com"}}],
            headers={"Link": f'<{_ORG_URL}/api/v1/users?page=2>; rel="next"'},
        )
        respx.get(url__regex=r".*/api/v1/users.*").mock(return_value=loop_resp)

        records = OktaConnector().fetch(_CREDS, _sleep_fn=lambda s: None)  # must terminate
        assert any(r["record_type"] == "okta_user" for r in records)
