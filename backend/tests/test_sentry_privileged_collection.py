"""Sentry effective-access derivation collection tests (Sentry message 5
of 8).

Covers ``sentry_privileged_member``/``sentry_privileged_team``/
``sentry_routing_context`` derivation end-to-end via
``SentryConnector.fetch()``: organization-wide access via owner/manager
roles, team-mediated project access, deduplication across multiple
teams reaching the same project, unknown-role handling, incomplete
source-family propagation, and — critically — that this message adds
ZERO additional HTTP requests beyond what messages 1-4 already make.
Normalization-level unit behavior is covered in
``test_sentry_privileged_normalization.py``; diff/risk behavior in
``test_sentry_privileged_diff.py``.
"""

from __future__ import annotations

import httpx
import respx

from app.connectors.sentry import SentryConnector
from app.connectors.sentry_schema import (
    FAMILY_COMPLETE,
    FAMILY_PARTIAL,
    SENTRY_PRIVILEGED_MEMBER,
    SENTRY_PRIVILEGED_TEAM,
    SENTRY_ROUTING_CONTEXT,
)

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


def _mock_org():
    respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(
        return_value=httpx.Response(200, json={"id": "999", "slug": _SLUG, "name": "My Org", "status": {"id": "active"}})
    )


def _mock_base_empty(*, projects=None, teams=None, members=None):
    respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
        return_value=_paginated(projects or [], path=f"/api/0/organizations/{_SLUG}/projects/")
    )
    respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(
        return_value=_paginated(teams or [], path=f"/api/0/organizations/{_SLUG}/teams/")
    )
    respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(
        return_value=_paginated(members or [], path=f"/api/0/organizations/{_SLUG}/members/")
    )
    respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))
    for p in (projects or []):
        respx.get(f"{_BASE}/projects/{_SLUG}/{p['slug']}/rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/{p['slug']}/ownership/").mock(return_value=httpx.Response(404, json={}))


def _project(pid, slug=None):
    return {"id": pid, "slug": slug or f"proj-{pid}", "name": f"P{pid}", "platform": "python", "status": "active"}


def _team(tid, slug=None, projects=None):
    return {"id": tid, "slug": slug or f"team-{tid}", "name": f"T{tid}", "memberCount": 1, "projects": projects or []}


def _member(mid, org_role="member"):
    return {"id": mid, "orgRole": org_role, "pending": False, "expired": False}


def _record_types(records, rt):
    return [r for r in records if r["record_type"] == rt]


def _organization_record(records):
    return next(r for r in records if r["record_type"] == "sentry_organization")


def _fetch():
    return SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)


class TestZeroExtraHttpCalls:
    @respx.mock
    def test_derivation_adds_no_new_requests(self):
        _mock_org()
        p1, p2 = _project("p1"), _project("p2")
        t1 = _team("t1", projects=[{"id": "p1"}])
        _mock_base_empty(projects=[p1, p2], teams=[t1], members=[_member("m1", "owner"), _member("m2")])
        respx.get(f"{_BASE}/teams/{_SLUG}/team-t1/members/").mock(return_value=httpx.Response(200, json=[{"id": "m2"}]))

        # Every endpoint touched by fetch() is registered above and
        # nothing else — if message-5 derivation issued a single extra
        # HTTP request, respx's assert_all_mocked default would fail
        # this test with an unmocked-request error.
        records = _fetch()
        assert len(_record_types(records, SENTRY_PRIVILEGED_MEMBER)) >= 1


class TestOrganizationWideAccess:
    @respx.mock
    def test_owner_gets_org_wide_access_to_all_projects(self):
        _mock_org()
        p1, p2 = _project("p1"), _project("p2")
        _mock_base_empty(projects=[p1, p2], teams=[], members=[_member("m1", "owner")])
        records = _fetch()
        pm = _record_types(records, SENTRY_PRIVILEGED_MEMBER)[0]
        assert pm["organization_wide_project_access"] is True
        assert pm["effective_project_count"] == 2
        assert pm["privilege_tier"] == "critical"

    @respx.mock
    def test_manager_gets_org_wide_access(self):
        _mock_org()
        _mock_base_empty(projects=[_project("p1")], teams=[], members=[_member("m1", "manager")])
        records = _fetch()
        pm = _record_types(records, SENTRY_PRIVILEGED_MEMBER)[0]
        assert pm["organization_wide_project_access"] is True
        assert pm["privilege_tier"] == "high"

    @respx.mock
    def test_admin_does_not_get_org_wide_access(self):
        _mock_org()
        _mock_base_empty(projects=[_project("p1")], teams=[], members=[_member("m1", "admin")])
        records = _fetch()
        pm = _record_types(records, SENTRY_PRIVILEGED_MEMBER)[0]
        assert pm["organization_wide_project_access"] is False
        assert pm["privilege_tier"] == "medium"


class TestTeamMediatedAccess:
    @respx.mock
    def test_member_access_via_single_team(self):
        _mock_org()
        p1 = _project("p1")
        t1 = _team("t1", projects=[{"id": "p1"}])
        _mock_base_empty(projects=[p1], teams=[t1], members=[_member("m1")])
        respx.get(f"{_BASE}/teams/{_SLUG}/team-t1/members/").mock(return_value=httpx.Response(200, json=[{"id": "m1"}]))
        records = _fetch()
        # ordinary member with only ordinary team membership is excluded
        assert _record_types(records, SENTRY_PRIVILEGED_MEMBER) == []

    @respx.mock
    def test_dedup_across_multiple_teams_reaching_same_project(self):
        _mock_org()
        p1 = _project("p1")
        t1 = _team("t1", projects=[{"id": "p1"}])
        t2 = _team("t2", projects=[{"id": "p1"}])
        _mock_base_empty(projects=[p1], teams=[t1, t2], members=[_member("m1", "admin")])
        respx.get(f"{_BASE}/teams/{_SLUG}/team-t1/members/").mock(return_value=httpx.Response(200, json=[{"id": "m1"}]))
        respx.get(f"{_BASE}/teams/{_SLUG}/team-t2/members/").mock(return_value=httpx.Response(200, json=[{"id": "m1"}]))
        records = _fetch()
        pm = _record_types(records, SENTRY_PRIVILEGED_MEMBER)[0]
        assert pm["effective_project_count"] == 1
        assert pm["direct_team_count"] == 2

    @respx.mock
    def test_one_team_multiple_projects(self):
        _mock_org()
        p1, p2 = _project("p1"), _project("p2")
        t1 = _team("t1", projects=[{"id": "p1"}, {"id": "p2"}])
        _mock_base_empty(projects=[p1, p2], teams=[t1], members=[_member("m1", "admin")])
        respx.get(f"{_BASE}/teams/{_SLUG}/team-t1/members/").mock(return_value=httpx.Response(200, json=[{"id": "m1"}]))
        records = _fetch()
        pm = _record_types(records, SENTRY_PRIVILEGED_MEMBER)[0]
        assert pm["effective_project_count"] == 2

    @respx.mock
    def test_team_admin_grants_meaningful_authority_without_org_role(self):
        _mock_org()
        t1 = _team("t1")
        _mock_base_empty(projects=[], teams=[t1], members=[_member("m1")])
        respx.get(f"{_BASE}/teams/{_SLUG}/team-t1/members/").mock(
            return_value=httpx.Response(200, json=[{"id": "m1", "teamRole": "admin"}])
        )
        records = _fetch()
        pm = _record_types(records, SENTRY_PRIVILEGED_MEMBER)
        assert len(pm) == 1
        assert pm[0]["team_admin_team_count"] == 1
        assert pm[0]["privilege_tier"] == "medium"


class TestUnknownRole:
    @respx.mock
    def test_unknown_role_never_becomes_low_or_ordinary(self):
        _mock_org()
        _mock_base_empty(projects=[_project("p1")], teams=[], members=[_member("m1", "some-new-role")])
        records = _fetch()
        pm = _record_types(records, SENTRY_PRIVILEGED_MEMBER)[0]
        assert pm["privilege_tier"] == "unknown"
        assert pm["organization_wide_project_access"] is None
        assert pm["effective_project_count"] is None


class TestPrivilegedTeams:
    @respx.mock
    def test_ordinary_team_excluded(self):
        _mock_org()
        t1 = _team("t1")
        _mock_base_empty(projects=[], teams=[t1], members=[])
        respx.get(f"{_BASE}/teams/{_SLUG}/team-t1/members/").mock(return_value=httpx.Response(200, json=[]))
        records = _fetch()
        assert _record_types(records, SENTRY_PRIVILEGED_TEAM) == []

    @respx.mock
    def test_team_with_project_assignment_is_privileged(self):
        _mock_org()
        p1 = _project("p1")
        t1 = _team("t1", projects=[{"id": "p1"}])
        _mock_base_empty(projects=[p1], teams=[t1], members=[])
        respx.get(f"{_BASE}/teams/{_SLUG}/team-t1/members/").mock(return_value=httpx.Response(200, json=[]))
        records = _fetch()
        pt = _record_types(records, SENTRY_PRIVILEGED_TEAM)
        assert len(pt) == 1
        assert pt[0]["project_count"] == 1


class TestRoutingContext:
    @respx.mock
    def test_ownership_target_and_alert_target_each_get_routing_context(self):
        _mock_org()
        p1 = _project("p1")
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated([p1], path=f"/api/0/organizations/{_SLUG}/projects/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/teams/"))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(
            return_value=_paginated([_member("m1", "owner")], path=f"/api/0/organizations/{_SLUG}/members/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=httpx.Response(200, json=[
            {"id": "ar1", "name": "R", "status": 0, "projects": ["proj-p1"], "triggers": [
                {"id": "tr1", "label": "critical", "alertThreshold": 1, "actions": [
                    {"id": "a1", "type": "email", "targetType": "user", "targetIdentifier": "m1"},
                ]},
            ]},
        ]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(return_value=httpx.Response(200, json={
            "isActive": True, "fallthrough": True, "autoAssignment": "Turn off Auto-Assignment",
            "schema": {"$version": 1, "rules": [{"matcher": {"type": "path", "pattern": "*.py"}, "owners": [{"type": "user", "id": "m1"}]}]},
        }))
        records = _fetch()
        routing = _record_types(records, SENTRY_ROUTING_CONTEXT)
        assert len(routing) == 2
        types = {r["context_type"] for r in routing}
        assert types == {"ownership_rule", "alert_action"}
        for r in routing:
            assert r["target_resolved"] is True
            assert r["target_active"] is True


class TestEffectiveAccessFamilyKeys:
    @respx.mock
    def test_effective_access_family_completeness_keys_present(self):
        _mock_org()
        p1 = _project("p1")
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated([p1], path=f"/api/0/organizations/{_SLUG}/projects/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/teams/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(
            return_value=_paginated([_member("m1", "owner")], path=f"/api/0/organizations/{_SLUG}/members/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/alert-rules/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(
            return_value=_paginated([], path=f"/api/0/projects/{_SLUG}/proj-p1/rules/")
        )
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(return_value=httpx.Response(404, json={}))
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))
        records = _fetch()
        fc = _organization_record(records)["family_completeness"]
        assert fc["privileged_members"] == FAMILY_COMPLETE
        assert fc["privileged_teams"] == FAMILY_COMPLETE
        assert fc["routing_context"] == FAMILY_COMPLETE


class TestCompletenessPropagation:
    @respx.mock
    def test_incomplete_member_family_marks_privileged_members_partial(self):
        _mock_org()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[_project("p1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=httpx.Response(200, json=[]))
        # No Link header -> paginate_sentry treats as truncated/partial
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=httpx.Response(200, json=[_member("m1", "owner")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(return_value=httpx.Response(404, json={}))
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))
        records = _fetch()
        fc = _organization_record(records)["family_completeness"]
        assert fc["privileged_members"] == FAMILY_PARTIAL
