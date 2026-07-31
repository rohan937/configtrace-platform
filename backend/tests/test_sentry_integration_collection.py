"""Sentry organization integration / repository / code-mapping /
ownership-rule collection tests (Sentry message 4 of 8).

Covers organization-integration/repository/code-mapping (org-scoped,
single paginated call each) and ownership-rule (bounded per-project
single-object walk) collection end-to-end via ``SentryConnector.fetch()``:
family independence, per-project completeness, pagination, dedup,
deterministic ordering, the always-unsupported webhooks/release-config/
deployment-config families, and scale/cap behavior. Normalization
correctness is covered separately in
``test_sentry_integration_normalization.py``; diff/risk behavior in
``test_sentry_integration_diff.py``.
"""

from __future__ import annotations

import httpx
import respx

from app.connectors.sentry import SentryConnector
from app.connectors.sentry_schema import (
    CAPABILITY_UNSUPPORTED,
    FAMILY_COMPLETE,
    FAMILY_DENIED,
    FAMILY_PARTIAL,
    FAMILY_UNAVAILABLE,
    SENTRY_CODE_MAPPING,
    SENTRY_ORGANIZATION_INTEGRATION,
    SENTRY_OWNERSHIP_RULE,
    SENTRY_REPOSITORY,
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


def _paginated_response(items: list, *, has_next: bool = False, path: str = None, cursor: str = "0:100:0") -> httpx.Response:
    resolved_path = path or f"/api/0/organizations/{_SLUG}/integrations/"
    return httpx.Response(200, json=items, headers={"Link": _link_header(has_next=has_next, path=resolved_path, cursor=cursor)})


def _mock_org():
    respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(
        return_value=httpx.Response(200, json={"id": "999", "slug": _SLUG, "name": "My Org", "status": {"id": "active"}})
    )


def _mock_msg2_3_empty():
    respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_BASE}/organizations/{_SLUG}/releases/").mock(return_value=httpx.Response(200, json=[]))


def _mock_projects(projects):
    respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=projects))


def _mock_all_empty(*, projects=None):
    _mock_org()
    _mock_msg2_3_empty()
    _mock_projects(projects if projects is not None else [])
    respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=_paginated_response([]))
    respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(
        return_value=_paginated_response([], path=f"/api/0/organizations/{_SLUG}/repos/")
    )
    respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(
        return_value=_paginated_response([], path=f"/api/0/organizations/{_SLUG}/code-mappings/")
    )


def _project(pid: str, slug: str = None) -> dict:
    return {"id": pid, "slug": slug or f"proj-{pid}", "name": f"Project {pid}", "platform": "python", "status": "active"}


def _integration(iid: str, **overrides) -> dict:
    base = {
        "id": iid, "name": "my-org", "provider": {"key": "github", "features": ["commits"]},
        "organizationIntegrationStatus": "active", "externalId": "1", "outOfDate": False,
    }
    base.update(overrides)
    return base


def _repo(rid: str, **overrides) -> dict:
    base = {
        "id": rid, "name": "my-org/my-repo", "provider": {"id": "integrations:github", "name": "GitHub"},
        "status": "active", "integrationId": "i1", "externalId": "42", "dateCreated": "2020-01-01T00:00:00Z",
        "url": "https://github.com/my-org/my-repo",
    }
    base.update(overrides)
    return base


def _code_mapping(cid: str, **overrides) -> dict:
    base = {
        "id": cid, "projectId": "p1", "repoId": "r1", "integrationId": "i1",
        "stackRoot": "src/", "sourceRoot": "", "defaultBranch": "main", "automaticallyGenerated": False,
    }
    base.update(overrides)
    return base


def _ownership_response(**overrides) -> dict:
    base = {
        "raw": "path:*.js #frontend",
        "fallthrough": True, "isActive": True, "autoAssignment": "Turn off Auto-Assignment",
        "codeownersAutoSync": False,
        "schema": {"$version": 1, "rules": [
            {"matcher": {"type": "path", "pattern": "*.js"}, "owners": [{"type": "team", "name": "frontend", "id": "55"}]},
        ]},
    }
    base.update(overrides)
    return base


def _record_types(records: list[dict], record_type: str) -> list[dict]:
    return [r for r in records if r["record_type"] == record_type]


def _organization_record(records: list[dict]) -> dict:
    return next(r for r in records if r["record_type"] == "sentry_organization")


def _fetch():
    return SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)


# ════════════════════════════════════════════════════════════════════════════
# Organization integrations
# ════════════════════════════════════════════════════════════════════════════


class TestOrganizationIntegrationCollection:
    @respx.mock
    def test_collects_integrations(self):
        _mock_all_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(
            return_value=_paginated_response([_integration("i1"), _integration("i2")])
        )
        records = _fetch()
        assert len(_record_types(records, SENTRY_ORGANIZATION_INTEGRATION)) == 2

    @respx.mock
    def test_integrations_denied_does_not_block_repositories(self):
        _mock_all_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(return_value=httpx.Response(403, json={}))
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(
            return_value=_paginated_response([_repo("r1")], path=f"/api/0/organizations/{_SLUG}/repos/")
        )
        records = _fetch()
        assert _record_types(records, SENTRY_ORGANIZATION_INTEGRATION) == []
        assert len(_record_types(records, SENTRY_REPOSITORY)) == 1
        fc = _organization_record(records)["family_completeness"]
        assert fc["organization_integrations"] == FAMILY_DENIED
        assert fc["repositories"] == FAMILY_COMPLETE

    @respx.mock
    def test_dedup_by_integration_id(self):
        _mock_all_empty()
        probe = httpx.Response(200, json=[])
        page1 = _paginated_response([_integration("i1")], has_next=True)
        page2 = _paginated_response([_integration("i1")], has_next=False)
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(side_effect=[probe, page1, page2])
        records = _fetch()
        assert len(_record_types(records, SENTRY_ORGANIZATION_INTEGRATION)) == 1

    @respx.mock
    def test_deterministic_ordering(self):
        _mock_all_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(
            return_value=_paginated_response([_integration("i3"), _integration("i1"), _integration("i2")])
        )
        records = _fetch()
        ids = [r["integration_id"] for r in _record_types(records, SENTRY_ORGANIZATION_INTEGRATION)]
        assert ids == ["i1", "i2", "i3"]

    @respx.mock
    def test_hitting_cap_is_partial(self, monkeypatch):
        import app.connectors.sentry as sentry_module
        monkeypatch.setattr(sentry_module, "_MAX_ORGANIZATION_INTEGRATIONS", 2)
        _mock_all_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/integrations/").mock(
            return_value=_paginated_response([_integration("i1"), _integration("i2"), _integration("i3")])
        )
        records = _fetch()
        assert len(_record_types(records, SENTRY_ORGANIZATION_INTEGRATION)) == 2
        fc = _organization_record(records)["family_completeness"]
        assert fc["organization_integrations"] == FAMILY_PARTIAL


# ════════════════════════════════════════════════════════════════════════════
# Repositories
# ════════════════════════════════════════════════════════════════════════════


class TestRepositoryCollection:
    @respx.mock
    def test_collects_repositories(self):
        _mock_all_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(
            return_value=_paginated_response([_repo("r1"), _repo("r2")], path=f"/api/0/organizations/{_SLUG}/repos/")
        )
        records = _fetch()
        assert len(_record_types(records, SENTRY_REPOSITORY)) == 2

    @respx.mock
    def test_multi_page_repositories(self):
        _mock_all_empty()
        probe = httpx.Response(200, json=[])
        page1 = _paginated_response([_repo("r1")], has_next=True, path=f"/api/0/organizations/{_SLUG}/repos/")
        page2 = _paginated_response([_repo("r2")], has_next=False, path=f"/api/0/organizations/{_SLUG}/repos/")
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(side_effect=[probe, page1, page2])
        records = _fetch()
        assert {r["repository_id"] for r in _record_types(records, SENTRY_REPOSITORY)} == {"r1", "r2"}
        fc = _organization_record(records)["family_completeness"]
        assert fc["repositories"] == FAMILY_COMPLETE


# ════════════════════════════════════════════════════════════════════════════
# Code mappings
# ════════════════════════════════════════════════════════════════════════════


class TestCodeMappingCollection:
    @respx.mock
    def test_collects_code_mappings(self):
        _mock_all_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(
            return_value=_paginated_response([_code_mapping("cm1")], path=f"/api/0/organizations/{_SLUG}/code-mappings/")
        )
        records = _fetch()
        assert len(_record_types(records, SENTRY_CODE_MAPPING)) == 1

    @respx.mock
    def test_repositories_denied_does_not_block_code_mappings(self):
        _mock_all_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/repos/").mock(return_value=httpx.Response(403, json={}))
        respx.get(f"{_BASE}/organizations/{_SLUG}/code-mappings/").mock(
            return_value=_paginated_response([_code_mapping("cm1")], path=f"/api/0/organizations/{_SLUG}/code-mappings/")
        )
        records = _fetch()
        assert _record_types(records, SENTRY_REPOSITORY) == []
        assert len(_record_types(records, SENTRY_CODE_MAPPING)) == 1
        fc = _organization_record(records)["family_completeness"]
        assert fc["repositories"] == FAMILY_DENIED
        assert fc["code_mappings"] == FAMILY_COMPLETE


# ════════════════════════════════════════════════════════════════════════════
# Ownership rules (per-project single-object walk)
# ════════════════════════════════════════════════════════════════════════════


class TestOwnershipRuleCollection:
    @respx.mock
    def test_collects_rules_from_single_project(self):
        _mock_all_empty(projects=[_project("p1")])
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(return_value=httpx.Response(200, json=_ownership_response()))
        records = _fetch()
        rules = _record_types(records, SENTRY_OWNERSHIP_RULE)
        assert len(rules) == 1
        assert rules[0]["project_id"] == "p1"
        assert rules[0]["owner_id"] == "55"

    @respx.mock
    def test_project_with_no_ownership_config_is_complete_zero_rules(self):
        _mock_all_empty(projects=[_project("p1")])
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(return_value=httpx.Response(404, json={}))
        records = _fetch()
        assert _record_types(records, SENTRY_OWNERSHIP_RULE) == []
        fc = _organization_record(records)["family_completeness"]
        assert fc["ownership_rules"] == FAMILY_COMPLETE

    @respx.mock
    def test_one_project_denied_one_succeeds_is_partial(self):
        _mock_all_empty(projects=[_project("p1", "proj-a"), _project("p2", "proj-b")])
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-a/ownership/").mock(return_value=httpx.Response(200, json=_ownership_response()))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-b/ownership/").mock(return_value=httpx.Response(403, json={}))
        records = _fetch()
        rules = _record_types(records, SENTRY_OWNERSHIP_RULE)
        assert len(rules) == 1
        assert rules[0]["project_id"] == "p1"
        fc = _organization_record(records)["family_completeness"]
        assert fc["ownership_rules"] == FAMILY_PARTIAL

    @respx.mock
    def test_raw_text_without_schema_is_partial_not_zero(self):
        _mock_all_empty(projects=[_project("p1")])
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(
            return_value=httpx.Response(200, json={"raw": "path:*.js #frontend", "isActive": True, "fallthrough": True})
        )
        records = _fetch()
        assert _record_types(records, SENTRY_OWNERSHIP_RULE) == []
        fc = _organization_record(records)["family_completeness"]
        assert fc["ownership_rules"] == FAMILY_PARTIAL

    @respx.mock
    def test_zero_projects_is_trivially_complete(self):
        _mock_all_empty(projects=[])
        records = _fetch()
        fc = _organization_record(records)["family_completeness"]
        assert fc["ownership_rules"] == FAMILY_COMPLETE

    @respx.mock
    def test_rule_order_preserved(self):
        _mock_all_empty(projects=[_project("p1")])
        multi_rule = _ownership_response(schema={"$version": 1, "rules": [
            {"matcher": {"type": "path", "pattern": "*.py"}, "owners": [{"type": "team", "id": "1"}]},
            {"matcher": {"type": "url", "pattern": "/checkout"}, "owners": [{"type": "team", "id": "2"}]},
        ]})
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/ownership/").mock(return_value=httpx.Response(200, json=multi_rule))
        records = _fetch()
        rules = _record_types(records, SENTRY_OWNERSHIP_RULE)
        assert [r["rule_index"] for r in rules] == [0, 1]


# ════════════════════════════════════════════════════════════════════════════
# Always-unsupported families (webhooks / release / deployment config)
# ════════════════════════════════════════════════════════════════════════════


class TestAlwaysUnsupportedFamilies:
    @respx.mock
    def test_webhooks_and_release_deployment_config_never_call_http(self):
        _mock_all_empty()
        # No routes registered for any webhook/release-config/deployment-
        # config-shaped endpoint — if the connector tried one, respx's
        # assert_all_mocked default would fail this test.
        records = _fetch()
        fc = _organization_record(records)["family_completeness"]
        assert fc["webhooks"] == CAPABILITY_UNSUPPORTED
        assert fc["release_configuration"] == CAPABILITY_UNSUPPORTED
        assert fc["deployment_configuration"] == CAPABILITY_UNSUPPORTED
