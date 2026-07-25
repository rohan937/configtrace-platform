"""Okta application inventory collection tests (Okta message 3 of 8).

Covers application/assignment collection end-to-end via
``OktaConnector.fetch()``: pagination, family independence (fail-soft),
deduplication, stable IDs, assignment-collection strategy (per-app
enumeration collecting apps once), and scale behavior. Normalization
correctness is covered separately in
``test_okta_application_normalization.py``; diff/risk behavior in
``test_okta_application_diff.py``.
"""

from __future__ import annotations

import time

import httpx
import respx

from app.connectors.okta import OktaConnector
from app.connectors.okta_schema import (
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    OKTA_APPLICATION,
    OKTA_APPLICATION_GROUP_ASSIGNMENT,
    OKTA_APPLICATION_USER_ASSIGNMENT,
)

_ORG_URL = "https://example.okta.com"
_TOKEN = "fake-okta-api-token-value"
_CREDS = {"org_url": _ORG_URL, "api_token": _TOKEN}


def _org_response() -> httpx.Response:
    return httpx.Response(200, json={"id": "00o1abcXYZ", "status": "ACTIVE"})


def _user(user_id: str, *, status: str = "ACTIVE") -> dict:
    return {
        "id": user_id,
        "status": status,
        "profile": {"login": f"{user_id}@example.com", "firstName": "First", "lastName": "Last"},
        "credentials": {"provider": {"type": "OKTA"}},
        "type": {"id": "typ1"},
    }


def _group(group_id: str, *, name: str = None) -> dict:
    return {"id": group_id, "type": "OKTA_GROUP", "profile": {"name": name or f"Group {group_id}"}}


def _app(app_id: str, *, label: str = None, status: str = "ACTIVE", sign_on_mode: str = "OPENID_CONNECT") -> dict:
    return {
        "id": app_id,
        "label": label or f"App {app_id}",
        "status": status,
        "signOnMode": sign_on_mode,
        "settings": {"oauthClient": {
            "redirect_uris": ["https://app.example.com/cb"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
        }},
    }


def _app_assignment(user_id: str, *, status: str = "ACTIVE", scope: str = "USER") -> dict:
    return {"id": user_id, "status": status, "scope": scope}


def _app_group_assignment(group_id: str) -> dict:
    return {"id": group_id, "priority": 0}


def _mock_empty_users_groups():
    respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))


def _mock_empty_probes():
    for path in ("/api/v1/policies", "/api/v1/authenticators", "/api/v1/iam/roles", "/api/v1/logs"):
        respx.get(f"{_ORG_URL}{path}").mock(return_value=httpx.Response(200, json=[]))
    # /api/v1/apps and /api/v1/users and /api/v1/groups are also probe
    # targets (limit=1) but the family-collection mocks below already
    # answer them, since capability probes reuse the same paths.


# ════════════════════════════════════════════════════════════════════════════
# Application collection
# ════════════════════════════════════════════════════════════════════════════


class TestApplicationCollection:
    @respx.mock
    def test_collects_all_applications_single_page(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(
            return_value=httpx.Response(200, json=[_app("app1"), _app("app2")])
        )
        _mock_empty_users_groups()
        _mock_empty_probes()

        records = OktaConnector().fetch(_CREDS)
        apps = [r for r in records if r["record_type"] == OKTA_APPLICATION]
        assert len(apps) == 2
        assert {a["app_id"] for a in apps} == {"app1", "app2"}

    @respx.mock
    def test_collects_applications_across_multiple_pages(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        page1 = httpx.Response(
            200, json=[_app("app1")],
            headers={"Link": f'<{_ORG_URL}/api/v1/apps?after=app1>; rel="next"'},
        )
        page2 = httpx.Response(200, json=[_app("app2")])
        respx.get(url__regex=r".*/api/v1/apps($|\?).*").mock(side_effect=[page1, page2])
        _mock_empty_users_groups()
        _mock_empty_probes()

        records = OktaConnector().fetch(_CREDS)
        apps = [r for r in records if r["record_type"] == OKTA_APPLICATION]
        assert {a["app_id"] for a in apps} == {"app1", "app2"}


# ════════════════════════════════════════════════════════════════════════════
# Per-app user/group assignment collection
# ════════════════════════════════════════════════════════════════════════════


class TestAssignmentCollection:
    @respx.mock
    def test_user_assignments_collected_per_app(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[_app("app1")]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(
            return_value=httpx.Response(200, json=[_user("u1"), _user("u2")])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/users").mock(
            return_value=httpx.Response(200, json=[_app_assignment("u1"), _app_assignment("u2")])
        )
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/groups").mock(return_value=httpx.Response(200, json=[]))
        _mock_empty_probes()

        records = OktaConnector().fetch(_CREDS)
        assignments = [r for r in records if r["record_type"] == OKTA_APPLICATION_USER_ASSIGNMENT]
        assert len(assignments) == 2
        assert {a["user_id"] for a in assignments} == {"u1", "u2"}
        assert all(a["app_id"] == "app1" for a in assignments)

    @respx.mock
    def test_group_assignments_collected_per_app(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[_app("app1")]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(
            return_value=httpx.Response(200, json=[_group("g1"), _group("g2")])
        )
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/groups").mock(
            return_value=httpx.Response(200, json=[_app_group_assignment("g1"), _app_group_assignment("g2")])
        )
        _mock_empty_probes()

        records = OktaConnector().fetch(_CREDS)
        assignments = [r for r in records if r["record_type"] == OKTA_APPLICATION_GROUP_ASSIGNMENT]
        assert len(assignments) == 2
        assert {a["group_id"] for a in assignments} == {"g1", "g2"}

    @respx.mock
    def test_apps_collected_once_not_refetched_for_assignments(self):
        """The app list itself must be fetched exactly once — assignment
        collection reuses it, never re-queries /api/v1/apps."""
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        apps_route = respx.get(f"{_ORG_URL}/api/v1/apps").mock(
            return_value=httpx.Response(200, json=[_app("app1")])
        )
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[_user("u1")]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[_group("g1")]))
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/groups").mock(return_value=httpx.Response(200, json=[]))
        _mock_empty_probes()

        OktaConnector().fetch(_CREDS)
        # capability probe also calls /api/v1/apps?limit=1 once — so total
        # calls to that path should be exactly 2 (collection + probe), not
        # more (i.e. never re-fetched per-assignment-walk).
        assert apps_route.call_count == 2

    @respx.mock
    def test_app_with_zero_assignments(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[_app("app1")]))
        _mock_empty_users_groups()
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/users").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/groups").mock(return_value=httpx.Response(200, json=[]))
        _mock_empty_probes()

        records = OktaConnector().fetch(_CREDS)
        app = next(r for r in records if r["record_type"] == OKTA_APPLICATION)
        assert app["user_assignment_count"] == 0
        assert app["group_assignment_count"] == 0

    @respx.mock
    def test_no_apps_at_all_is_complete_not_denied(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[]))
        _mock_empty_users_groups()
        _mock_empty_probes()

        records = OktaConnector().fetch(_CREDS)
        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["app_user_assignments"] == FAMILY_COMPLETE
        assert org["family_completeness"]["app_group_assignments"] == FAMILY_COMPLETE


# ════════════════════════════════════════════════════════════════════════════
# Family independence / fail-soft
# ════════════════════════════════════════════════════════════════════════════


class TestFamilyIndependence:
    @respx.mock
    def test_apps_complete_user_assignments_denied(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[_app("app1")]))
        _mock_empty_users_groups()
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/users").mock(return_value=httpx.Response(403))
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/groups").mock(return_value=httpx.Response(200, json=[]))
        _mock_empty_probes()

        records = OktaConnector().fetch(_CREDS)
        assert any(r["record_type"] == OKTA_APPLICATION for r in records)
        assert not any(r["record_type"] == OKTA_APPLICATION_USER_ASSIGNMENT for r in records)

        org = next(r for r in records if r["record_type"] == "okta_organization")
        assert org["family_completeness"]["applications"] == FAMILY_COMPLETE
        assert org["family_completeness"]["app_user_assignments"] == FAMILY_DENIED
        assert org["family_completeness"]["app_group_assignments"] == FAMILY_COMPLETE

        app = next(r for r in records if r["record_type"] == OKTA_APPLICATION)
        assert app["user_assignment_count"] is None  # never inferred as zero
        assert app["group_assignment_count"] == 0

    @respx.mock
    def test_user_assignments_complete_group_assignments_denied(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[_app("app1")]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[_user("u1")]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/users").mock(
            return_value=httpx.Response(200, json=[_app_assignment("u1")])
        )
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/groups").mock(return_value=httpx.Response(403))
        _mock_empty_probes()

        records = OktaConnector().fetch(_CREDS)
        assert any(r["record_type"] == OKTA_APPLICATION_USER_ASSIGNMENT for r in records)
        assert not any(r["record_type"] == OKTA_APPLICATION_GROUP_ASSIGNMENT for r in records)

        app = next(r for r in records if r["record_type"] == OKTA_APPLICATION)
        assert app["user_assignment_count"] == 1
        assert app["group_assignment_count"] is None

    @respx.mock
    def test_sync_does_not_fail_entirely_on_assignment_denial(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[_app("app1")]))
        _mock_empty_users_groups()
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/users").mock(return_value=httpx.Response(403))
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/groups").mock(return_value=httpx.Response(403))
        _mock_empty_probes()

        records = OktaConnector().fetch(_CREDS)  # must not raise
        assert any(r["record_type"] == "okta_organization" for r in records)


# ════════════════════════════════════════════════════════════════════════════
# Deduplication / stable IDs
# ════════════════════════════════════════════════════════════════════════════


class TestDedupAndStableIds:
    @respx.mock
    def test_user_assignment_dedup_within_an_app(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())
        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=[_app("app1")]))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(return_value=httpx.Response(200, json=[_user("u1")]))
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(return_value=httpx.Response(200, json=[]))
        page1 = httpx.Response(
            200, json=[_app_assignment("u1")],
            headers={"Link": f'<{_ORG_URL}/api/v1/apps/app1/users?after=1>; rel="next"'},
        )
        page2 = httpx.Response(200, json=[_app_assignment("u1")])
        respx.get(url__regex=r".*/api/v1/apps/app1/users.*").mock(side_effect=[page1, page2])
        respx.get(f"{_ORG_URL}/api/v1/apps/app1/groups").mock(return_value=httpx.Response(200, json=[]))
        _mock_empty_probes()

        records = OktaConnector().fetch(_CREDS)
        assignments = [r for r in records if r["record_type"] == OKTA_APPLICATION_USER_ASSIGNMENT]
        assert len(assignments) == 1

    def test_stable_record_id_prefers_tenant_plus_okta_id(self):
        tenant_id = "id:t1"
        rec = OktaConnector._normalize_application(
            tenant_id, _app("app1"), user_assignment_count=0, group_assignment_count=0,
        )
        assert rec["record_id"] == f"{tenant_id}/app/app1"

    def test_label_change_same_app_id_is_same_record_id(self):
        tenant_id = "id:t1"
        rec1 = OktaConnector._normalize_application(
            tenant_id, _app("app1", label="Old Label"), user_assignment_count=0, group_assignment_count=0,
        )
        rec2 = OktaConnector._normalize_application(
            tenant_id, _app("app1", label="New Label"), user_assignment_count=0, group_assignment_count=0,
        )
        assert rec1["record_id"] == rec2["record_id"]
        assert rec1["label"] != rec2["label"]


# ════════════════════════════════════════════════════════════════════════════
# Scale
# ════════════════════════════════════════════════════════════════════════════


class TestScale:
    @respx.mock
    def test_500_apps_5000_user_assignments_2000_group_assignments(self):
        respx.get(f"{_ORG_URL}/api/v1/org").mock(return_value=_org_response())

        n_apps = 500
        n_users = 100
        n_groups = 50
        apps_json = [_app(f"app{i}") for i in range(n_apps)]

        respx.get(f"{_ORG_URL}/api/v1/apps").mock(return_value=httpx.Response(200, json=apps_json))
        respx.get(f"{_ORG_URL}/api/v1/users").mock(
            return_value=httpx.Response(200, json=[_user(f"u{i}") for i in range(n_users)])
        )
        respx.get(f"{_ORG_URL}/api/v1/groups").mock(
            return_value=httpx.Response(200, json=[_group(f"g{i}") for i in range(n_groups)])
        )

        # 10 user assignments per app * 500 apps = 5,000 user assignments.
        users_per_app = 10
        # 4 group assignments per app * 500 apps = 2,000 group assignments.
        groups_per_app = 4
        for ai in range(n_apps):
            user_slice = [_app_assignment(f"u{(ai * users_per_app + k) % n_users}") for k in range(users_per_app)]
            group_slice = [_app_group_assignment(f"g{(ai * groups_per_app + k) % n_groups}") for k in range(groups_per_app)]
            respx.get(f"{_ORG_URL}/api/v1/apps/app{ai}/users").mock(
                return_value=httpx.Response(200, json=user_slice)
            )
            respx.get(f"{_ORG_URL}/api/v1/apps/app{ai}/groups").mock(
                return_value=httpx.Response(200, json=group_slice)
            )

        _mock_empty_probes()

        start = time.monotonic()
        records = OktaConnector().fetch(_CREDS)
        elapsed = time.monotonic() - start

        apps = [r for r in records if r["record_type"] == OKTA_APPLICATION]
        user_assignments = [r for r in records if r["record_type"] == OKTA_APPLICATION_USER_ASSIGNMENT]
        group_assignments = [r for r in records if r["record_type"] == OKTA_APPLICATION_GROUP_ASSIGNMENT]

        assert len(apps) == n_apps
        assert len(user_assignments) == n_apps * users_per_app
        assert len(group_assignments) == n_apps * groups_per_app
        # No duplicate app IDs.
        assert len({a["record_id"] for a in apps}) == n_apps
        # No duplicate assignments (app_id, user_id)/(app_id, group_id) pairs.
        assert len({(a["app_id"], a["user_id"]) for a in user_assignments}) == len(user_assignments)
        assert len({(a["app_id"], a["group_id"]) for a in group_assignments}) == len(group_assignments)
        assert elapsed < 30.0
