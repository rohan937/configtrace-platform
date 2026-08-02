"""Sentry Security Finding connector-shape reachability tests (Sentry
message 6 of 8).

For a representative rule from every category, proves the full path: a
real ``SentryConnector.fetch()`` call (respx-mocked HTTP, exercising the
same message 1-5 collection/derivation code the live connector uses) ->
real normalized/derived records -> ``evaluate_record()`` -> a Finding with
the expected rule key. Not testing hand-fabricated Finding dictionaries.
"""

from __future__ import annotations

import httpx
import respx

from app.connectors.sentry import SentryConnector
from app.services.security_finding_evaluator import evaluate_record

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


def _project(pid, slug=None):
    return {"id": pid, "slug": slug or f"proj-{pid}", "name": f"P{pid}", "platform": "python", "status": "active"}


def _member(mid, org_role="member", pending=False):
    return {"id": mid, "orgRole": org_role, "pending": pending, "expired": False}


def _record_types(records, rt):
    return [r for r in records if r["record_type"] == rt]


def _rule_keys_for_all(records, provider="sentry"):
    keys: set[str] = set()
    for r in records:
        keys |= {f.rule_key for f in evaluate_record(r, provider)}
    return keys


class TestPrivilegedMemberReachability:
    """Real member + org-role -> derived sentry_privileged_member -> Finding."""

    @respx.mock
    def test_active_owner_reachable(self):
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
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(return_value=httpx.Response(404, json={}))
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        privileged = _record_types(records, "sentry_privileged_member")
        assert len(privileged) == 1
        keys = _rule_keys_for_all(privileged)
        assert "sentry_active_organization_owner" in keys

    @respx.mock
    def test_pending_manager_reachable(self):
        _mock_org()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/projects/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/teams/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(
            return_value=_paginated([_member("m2", "manager", pending=True)], path=f"/api/0/organizations/{_SLUG}/members/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        privileged = _record_types(records, "sentry_privileged_member")
        assert len(privileged) == 1
        keys = _rule_keys_for_all(privileged)
        assert "sentry_pending_privileged_invitation" in keys
        assert "sentry_active_organization_manager" not in keys


class TestAlertCoverageReachability:
    """Real enabled metric alert rule with zero actions -> Finding."""

    @respx.mock
    def test_metric_alert_unrouted_reachable(self):
        _mock_org()
        p1 = _project("p1")
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated([p1], path=f"/api/0/organizations/{_SLUG}/projects/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/teams/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/members/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=httpx.Response(200, json=[
            {"id": "ar1", "name": "Prod errors", "status": 0, "projects": ["proj-p1"], "triggers": []},
        ]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(return_value=httpx.Response(404, json={}))
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        rules = _record_types(records, "sentry_metric_alert_rule")
        assert len(rules) == 1
        assert rules[0]["action_count"] == 0
        keys = _rule_keys_for_all(rules)
        assert "sentry_metric_alert_unrouted" in keys


class TestAlertRoutingReachability:
    """Real alert action targeting a missing member -> routing_context ->
    Finding."""

    @respx.mock
    def test_alert_targets_missing_member_reachable(self):
        _mock_org()
        p1 = _project("p1")
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated([p1], path=f"/api/0/organizations/{_SLUG}/projects/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/teams/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/members/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=_paginated([
            {"id": "ar1", "name": "R", "status": 0, "projects": ["proj-p1"], "triggers": [
                {"id": "tr1", "label": "critical", "alertThreshold": 1, "actions": [
                    {"id": "a1", "type": "email", "targetType": "user", "targetIdentifier": "ghost-user"},
                ]},
            ]},
        ], path=f"/api/0/organizations/{_SLUG}/alert-rules/"))
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(
            return_value=_paginated([], path=f"/api/0/projects/{_SLUG}/proj-p1/rules/")
        )
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(return_value=httpx.Response(404, json={}))
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        routing = _record_types(records, "sentry_routing_context")
        assert len(routing) == 1
        assert routing[0]["target_resolved"] is False
        keys = _rule_keys_for_all(routing)
        assert "sentry_alert_targets_missing_member" in keys


class TestOwnershipRoutingReachability:
    """Real ownership rule targeting a missing team -> routing_context ->
    Finding."""

    @respx.mock
    def test_ownership_targets_missing_team_reachable(self):
        _mock_org()
        p1 = _project("p1")
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated([p1], path=f"/api/0/organizations/{_SLUG}/projects/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/teams/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/members/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(return_value=httpx.Response(200, json={
            "isActive": True, "fallthrough": True, "autoAssignment": "Turn off Auto-Assignment",
            "schema": {"$version": 1, "rules": [{"matcher": {"type": "path", "pattern": "*.py"}, "owners": [{"type": "team", "id": "ghost-team"}]}]},
        }))
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        routing = _record_types(records, "sentry_routing_context")
        assert len(routing) == 1
        assert routing[0]["context_type"] == "ownership_rule"
        assert routing[0]["target_resolved"] is False
        keys = _rule_keys_for_all(routing)
        assert "sentry_ownership_targets_missing_team" in keys


class TestRepositoryReachability:
    """Real repository with pending_deletion status -> Finding."""

    @respx.mock
    def test_repository_pending_deletion_reachable(self):
        _mock_org()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/projects/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/teams/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(
            return_value=_paginated([], path=f"/api/0/organizations/{_SLUG}/members/")
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(200, json=[
            {"id": "repo1", "name": "acme/webapp", "provider": {"id": "github"}, "status": "pending_deletion", "integrationId": "int1", "externalId": "1"},
        ]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(return_value=httpx.Response(200, json=[]))

        records = SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)
        repos = _record_types(records, "sentry_repository")
        assert len(repos) == 1
        assert repos[0]["status_category"] == "pending_deletion"
        keys = _rule_keys_for_all(repos)
        assert "sentry_repository_pending_deletion" in keys
