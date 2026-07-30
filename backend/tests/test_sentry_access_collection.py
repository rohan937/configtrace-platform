"""Sentry project/team/member/access collection tests (Sentry message 2 of
8).

Covers project/team/member/team-membership/project-team-assignment
collection end-to-end via ``SentryConnector.fetch()``: family
independence (fail-soft), per-parent (per-team) completeness tracking,
pagination reuse/truncation, deduplication, deterministic ordering, the
zero-extra-call project-team-assignment derivation from the nested
teams-list response, and scale/cap behavior. Normalization correctness is
covered separately in ``test_sentry_access_normalization.py``; diff/risk
behavior in ``test_sentry_access_diff.py``.
"""

from __future__ import annotations

import httpx
import respx

from app.connectors.sentry import SentryConnector
from app.connectors.sentry_schema import (
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    FAMILY_PARTIAL,
    FAMILY_UNAVAILABLE,
    SENTRY_MEMBER,
    SENTRY_PROJECT,
    SENTRY_PROJECT_TEAM_ASSIGNMENT,
    SENTRY_TEAM,
    SENTRY_TEAM_MEMBERSHIP,
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


def _paginated_response(
    items: list, *, has_next: bool = False, path: str = f"/api/0/organizations/{_SLUG}/projects/", cursor: str = "0:100:0",
) -> httpx.Response:
    return httpx.Response(200, json=items, headers={"Link": _link_header(has_next=has_next, path=path, cursor=cursor)})


def _mock_org():
    respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(
        return_value=httpx.Response(200, json={"id": "999", "slug": _SLUG, "name": "My Org", "status": {"id": "active"}})
    )


def _mock_probes_empty():
    for path in ("alert-rules", "integrations", "repos", "releases"):
        respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=httpx.Response(200, json=[]))


def _project(pid: str, *, slug=None, name=None, platform="python", status="active") -> dict:
    return {
        "id": pid, "slug": slug or f"proj-{pid}", "name": name or f"Project {pid}",
        "platform": platform, "status": status, "dateCreated": "2020-01-01T00:00:00Z",
    }


def _team(tid: str, *, slug=None, name=None, projects=None, member_count=0) -> dict:
    return {
        "id": tid, "slug": slug or f"team-{tid}", "name": name or f"Team {tid}",
        "memberCount": member_count, "dateCreated": "2020-01-01T00:00:00Z",
        "projects": projects if projects is not None else [],
    }


def _member(mid: str, *, org_role="member", pending=False, expired=False) -> dict:
    return {
        "id": mid, "orgRole": org_role, "pending": pending, "expired": expired,
        "dateCreated": "2020-01-01T00:00:00Z",
    }


def _record_types(records: list[dict], record_type: str) -> list[dict]:
    return [r for r in records if r["record_type"] == record_type]


def _organization_record(records: list[dict]) -> dict:
    return next(r for r in records if r["record_type"] == "sentry_organization")


# ════════════════════════════════════════════════════════════════════════════
# Family independence
# ════════════════════════════════════════════════════════════════════════════


class TestFamilyIndependence:
    @respx.mock
    def test_projects_denied_does_not_block_teams_or_members(self):
        _mock_org()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(403, json={}))
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated_response([_team("t1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([_member("m1")]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        assert _record_types(records, SENTRY_PROJECT) == []
        assert len(_record_types(records, SENTRY_TEAM)) == 1
        assert len(_record_types(records, SENTRY_MEMBER)) == 1
        fc = _organization_record(records)["family_completeness"]
        assert fc["projects"] == FAMILY_DENIED
        assert fc["teams"] == FAMILY_COMPLETE
        assert fc["members"] == FAMILY_COMPLETE

    @respx.mock
    def test_members_unavailable_does_not_block_projects_or_teams(self):
        _mock_org()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=_paginated_response([_project("p1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated_response([_team("t1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=httpx.Response(500, json={}))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        assert len(_record_types(records, SENTRY_PROJECT)) == 1
        assert len(_record_types(records, SENTRY_TEAM)) == 1
        assert _record_types(records, SENTRY_MEMBER) == []
        fc = _organization_record(records)["family_completeness"]
        assert fc["members"] == FAMILY_UNAVAILABLE

    @respx.mock
    def test_no_fake_empty_list_treated_as_complete_when_denied(self):
        _mock_org()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(403, json={}))
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        fc = _organization_record(records)["family_completeness"]
        assert fc["projects"] == FAMILY_DENIED
        assert fc["teams"] == FAMILY_COMPLETE  # a genuinely empty org has zero teams — never denied


# ════════════════════════════════════════════════════════════════════════════
# Project-team assignment: derived from nested teams response, zero extra calls
# ════════════════════════════════════════════════════════════════════════════


class TestProjectTeamAssignmentDerivation:
    @respx.mock
    def test_assignments_derived_from_nested_teams_projects_with_no_extra_calls(self):
        _mock_org()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated_response([_project("p1"), _project("p2")])
        )
        team_route = respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(
            return_value=_paginated_response([_team("t1", projects=[{"id": "p1"}, {"id": "p2"}])])
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([]))
        # No route registered for /teams/{slug}/{team_slug}/members/ or any
        # per-project endpoint — if the connector tried an extra call for
        # assignments, respx's assert_all_mocked default would fail the test.

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        assignments = _record_types(records, SENTRY_PROJECT_TEAM_ASSIGNMENT)
        assert {(a["project_id"], a["team_id"]) for a in assignments} == {("p1", "t1"), ("p2", "t1")}
        # Called exactly twice: once for the message-1 capability probe
        # (page 1 only, never paginated), once for message-2's real
        # collection — never a THIRD call for a separate assignment-
        # discovery request (there is no such endpoint to call).
        assert team_route.call_count == 2

    @respx.mock
    def test_zero_teams_produces_zero_assignments_not_unknown(self):
        _mock_org()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=_paginated_response([_project("p1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        assert _record_types(records, SENTRY_PROJECT_TEAM_ASSIGNMENT) == []
        fc = _organization_record(records)["family_completeness"]
        assert fc["project_team_assignments"] == FAMILY_COMPLETE


# ════════════════════════════════════════════════════════════════════════════
# Per-team membership walk (per-parent completeness)
# ════════════════════════════════════════════════════════════════════════════


class TestTeamMembershipWalk:
    @respx.mock
    def test_one_team_denied_one_succeeds_is_partial(self):
        _mock_org()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(
            return_value=_paginated_response([_team("t1"), _team("t2")])
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/teams/{_SLUG}/team-t1/members/").mock(
            return_value=_paginated_response([{"id": "m1", "teamRole": "contributor"}])
        )
        respx.get(f"{_BASE}/teams/{_SLUG}/team-t2/members/").mock(return_value=httpx.Response(403, json={}))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        memberships = _record_types(records, SENTRY_TEAM_MEMBERSHIP)
        assert len(memberships) == 1
        assert memberships[0]["team_id"] == "t1"
        fc = _organization_record(records)["family_completeness"]
        assert fc["team_memberships"] == FAMILY_PARTIAL

    @respx.mock
    def test_all_teams_denied_is_denied(self):
        _mock_org()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated_response([_team("t1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/teams/{_SLUG}/team-t1/members/").mock(return_value=httpx.Response(403, json={}))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        fc = _organization_record(records)["family_completeness"]
        assert fc["team_memberships"] == FAMILY_DENIED

    @respx.mock
    def test_zero_teams_is_trivially_complete_not_unknown(self):
        _mock_org()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        fc = _organization_record(records)["family_completeness"]
        assert fc["team_memberships"] == FAMILY_COMPLETE

    @respx.mock
    def test_team_missing_slug_is_unavailable_not_skipped_silently(self):
        _mock_org()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=_paginated_response([]))
        broken_team = {"id": "t1", "name": "No Slug", "dateCreated": "2020-01-01T00:00:00Z", "projects": []}
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated_response([broken_team]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        fc = _organization_record(records)["family_completeness"]
        assert fc["team_memberships"] == FAMILY_UNAVAILABLE


# ════════════════════════════════════════════════════════════════════════════
# Pagination reuse / truncation / dedup / ordering
# ════════════════════════════════════════════════════════════════════════════


class TestPaginationAndOrdering:
    @respx.mock
    def test_multi_page_projects_collected_across_pages(self):
        _mock_org()
        _mock_probes_empty()
        # The FIRST response answers the message-1 capability probe (page 1
        # only, never paginated by the probe) — the real, paginated
        # collection sequence starts from the second response.
        probe_response = httpx.Response(200, json=[])
        page1 = _paginated_response([_project("p1")], has_next=True)
        page2 = _paginated_response([_project("p2")], has_next=False)
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(side_effect=[probe_response, page1, page2])
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        projects = _record_types(records, SENTRY_PROJECT)
        assert {p["project_id"] for p in projects} == {"p1", "p2"}
        fc = _organization_record(records)["family_completeness"]
        assert fc["projects"] == FAMILY_COMPLETE

    @respx.mock
    def test_missing_link_header_is_truncated_partial(self):
        _mock_org()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[_project("p1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        fc = _organization_record(records)["family_completeness"]
        assert fc["projects"] == FAMILY_PARTIAL

    @respx.mock
    def test_dedup_by_id_across_overlapping_pages(self):
        _mock_org()
        _mock_probes_empty()
        probe_response = httpx.Response(200, json=[])
        page1 = _paginated_response([_project("p1"), _project("p2")], has_next=True)
        page2 = _paginated_response([_project("p2"), _project("p3")], has_next=False)
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(side_effect=[probe_response, page1, page2])
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        projects = _record_types(records, SENTRY_PROJECT)
        assert sorted(p["project_id"] for p in projects) == ["p1", "p2", "p3"]

    @respx.mock
    def test_deterministic_sort_by_stable_id(self):
        _mock_org()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated_response([_project("p3"), _project("p1"), _project("p2")])
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        projects = _record_types(records, SENTRY_PROJECT)
        assert [p["project_id"] for p in projects] == ["p1", "p2", "p3"]


# ════════════════════════════════════════════════════════════════════════════
# Scale / caps
# ════════════════════════════════════════════════════════════════════════════


class TestScale:
    @respx.mock
    def test_hitting_project_cap_is_partial(self, monkeypatch):
        import app.connectors.sentry as sentry_module

        monkeypatch.setattr(sentry_module, "_MAX_PROJECTS", 2)
        _mock_org()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated_response([_project("p1"), _project("p2"), _project("p3")])
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=_paginated_response([]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        projects = _record_types(records, SENTRY_PROJECT)
        assert len(projects) == 2
        fc = _organization_record(records)["family_completeness"]
        assert fc["projects"] == FAMILY_PARTIAL
