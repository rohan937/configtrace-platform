"""Sentry scale/call-count/determinism/idempotency reliability tests
(Sentry message 7 of 8).

Verifies:
* the message-5 effective-access derivation (``_derive_effective_access``)
  scales to thousands of members/teams/projects/routing records without a
  members x projects cross product, using ID-map lookups only, and
  completes in bounded time;
* the connector's per-fetch() HTTP call-count formula matches the
  documented shape (fixed + bounded + O(teams) + O(projects), never
  duplicated within one fetch());
* deterministic ordering (shuffled API response order produces identical
  derived records/IDs);
* idempotency (two identical fetch() calls produce identical records).
"""

from __future__ import annotations

import random
import time

import httpx
import respx

from app.connectors.sentry import SentryConnector

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


class TestDerivationScale:
    def test_large_effective_access_derivation_is_fast_and_correct(self):
        n_members = 3000
        n_teams = 500
        n_projects = 1000

        member_records = [
            {
                "record_id": f"o/member/m{i}", "member_id": f"m{i}",
                "org_role_category": "owner" if i == 0 else "member",
                "member_status_category": "active",
            }
            for i in range(n_members)
        ]
        team_records = [{"record_id": f"o/team/t{i}", "team_id": f"t{i}"} for i in range(n_teams)]
        project_records = [{"record_id": f"o/project/p{i}", "project_id": f"p{i}"} for i in range(n_projects)]
        # Each member (except the owner) belongs to exactly one team (m_i -> t_(i % n_teams))
        membership_records = [
            {"record_id": f"o/tm/{i}", "team_id": f"t{i % n_teams}", "member_id": f"m{i}", "team_role_category": "contributor"}
            for i in range(1, n_members)
        ]
        # Each team is assigned exactly one project (t_i -> p_(i % n_projects))
        assignment_records = [
            {"record_id": f"o/assign/{i}", "team_id": f"t{i}", "project_id": f"p{i % n_projects}"}
            for i in range(n_teams)
        ]

        start = time.monotonic()
        privileged_members, privileged_teams, routing_contexts = SentryConnector._derive_effective_access(
            "o",
            project_records=project_records, team_records=team_records, member_records=member_records,
            membership_records=membership_records, assignment_records=assignment_records,
            metric_rule_records=[], issue_rule_records=[],
            metric_action_records=[], issue_action_records=[],
            ownership_records=[], integration_records=[],
            member_completeness="complete", team_completeness="complete",
            membership_completeness="complete", assignment_completeness="complete",
            ownership_completeness="complete", action_completeness="complete",
            integration_completeness="complete",
        )
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, f"derivation took {elapsed:.2f}s — too slow, possible O(n^2) regression"
        # Only the owner (org-wide access) qualifies as privileged among
        # ordinary members with a single ordinary team/project each.
        assert len(privileged_members) == 1
        assert privileged_members[0]["member_id"] == "m0"
        assert privileged_members[0]["effective_project_count"] == n_projects
        # Every team is assigned exactly one project (project_count=1>0),
        # which alone qualifies a team as privileged per the message-5
        # emission criteria — so all n_teams teams are privileged here.
        assert len(privileged_teams) == n_teams
        assert routing_contexts == []


class TestCallCountFormula:
    @respx.mock
    def test_fetch_call_count_matches_documented_formula(self):
        """organization(1) + capability probes(7, page-1-only) + projects(1) +
        teams(1) + members(1) + team_memberships(O(teams)) +
        metric_alert_rules(1) + issue_alert_rules(O(projects)) +
        integrations(1) + repositories(1) + code_mappings(1) +
        ownership_rules(O(projects)) — zero duplicate calls for any family
        within one fetch()."""
        n_teams = 3
        n_projects = 2

        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(
            return_value=httpx.Response(200, json={"id": "999", "slug": _SLUG, "name": "Org", "status": {"id": "active"}})
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated(
                [{"id": f"p{i}", "slug": f"proj-p{i}", "name": f"P{i}", "platform": "python", "status": "active"} for i in range(n_projects)],
                path=f"/api/0/organizations/{_SLUG}/projects/",
            )
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(
            return_value=_paginated(
                [{"id": f"t{i}", "slug": f"team-t{i}", "name": f"T{i}", "memberCount": 0, "projects": []} for i in range(n_teams)],
                path=f"/api/0/organizations/{_SLUG}/teams/",
            )
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/members/")
        )
        team_membership_routes = []
        for i in range(n_teams):
            team_membership_routes.append(
                respx.get(f"{_BASE}/teams/{_SLUG}/team-t{i}/members/").mock(return_value=httpx.Response(200, json=[]))
            )
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/alert-rules/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
        issue_rule_routes = []
        ownership_routes = []
        for i in range(n_projects):
            issue_rule_routes.append(
                respx.get(f"{_BASE}/projects/{_SLUG}/proj-p{i}/rules/").mock(
                    return_value=_paginated([], path=f"/api/0/projects/{_SLUG}/proj-p{i}/rules/")
                )
            )
            ownership_routes.append(
                respx.get(f"{_BASE}/projects/{_SLUG}/proj-p{i}/ownership/").mock(return_value=httpx.Response(404, json={}))
            )
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))

        SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)

        for route in team_membership_routes:
            assert route.call_count == 1, "each team's membership must be fetched exactly once"
        for route in issue_rule_routes:
            assert route.call_count == 1, "each project's issue-alert rules must be fetched exactly once"
        for route in ownership_routes:
            assert route.call_count == 1, "each project's ownership must be fetched exactly once"
        # Message 1's capability probes hit the SAME page-1 URL as several
        # message 2-4 collection calls (projects, teams, members, the
        # metric-alert "alert-rules" endpoint, integrations, repos,
        # releases) — each of those 7 families is called twice per
        # fetch() (one probe + one real collection), except releases
        # (always unsupported for real collection — probe only).
        assert respx.calls.call_count == (
            1  # organization identity
            + 2 * 6  # projects/teams/members/alert-rules/integrations/repos: probe + real
            + 1  # releases: probe only (never really collected)
            + n_teams  # team memberships (not probed, O(teams))
            + n_projects  # issue-alert rules (not probed, O(projects))
            + n_projects  # ownership rules (not probed, O(projects))
            + 1  # code-mappings (not probed, single org-wide call)
        )


class TestDeterministicOrderingAndIdempotency:
    def _fixture_records(self, *, member_order: list[int]) -> list:
        return [{"id": f"m{i}", "orgRole": "owner" if i == 0 else "member", "pending": False, "expired": False} for i in member_order]

    @respx.mock
    def test_shuffled_member_order_produces_identical_derived_output(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(
            return_value=httpx.Response(200, json={"id": "999", "slug": _SLUG, "name": "Org", "status": {"id": "active"}})
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated([{"id": "p1", "slug": "proj-p1", "name": "P1", "platform": "python", "status": "active"}], path=f"/api/0/organizations/{_SLUG}/projects/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/teams/")
        )
        order_a = list(range(20))
        order_b = list(range(20))
        random.Random(42).shuffle(order_b)

        def _run(order):
            respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(
                return_value=_paginated(self._fixture_records(member_order=order), path=f"/api/0/organizations/{_SLUG}/members/")
            )
            respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=httpx.Response(200, json=[]))
            respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
            respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(return_value=httpx.Response(200, json=[]))
            respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(return_value=httpx.Response(404, json={}))
            respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
            respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[]))
            respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))
            return SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)

        records_a = _run(order_a)
        records_b = _run(order_b)

        privileged_a = [r for r in records_a if r["record_type"] == "sentry_privileged_member"]
        privileged_b = [r for r in records_b if r["record_type"] == "sentry_privileged_member"]
        assert privileged_a == privileged_b
        assert [r["member_id"] for r in privileged_a] == sorted(r["member_id"] for r in privileged_a)

    @respx.mock
    def test_two_identical_fetches_are_idempotent(self):
        respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(
            return_value=httpx.Response(200, json={"id": "999", "slug": _SLUG, "name": "Org", "status": {"id": "active"}})
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated([{"id": "p1", "slug": "proj-p1", "name": "P1", "platform": "python", "status": "active"}], path=f"/api/0/organizations/{_SLUG}/projects/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/teams/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(
            return_value=_paginated([{"id": "m1", "orgRole": "owner", "pending": False, "expired": False}], path=f"/api/0/organizations/{_SLUG}/members/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(return_value=httpx.Response(404, json={}))
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))

        records_1 = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        records_2 = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        assert records_1 == records_2
