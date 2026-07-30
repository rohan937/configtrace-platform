"""Sentry metric/issue alert rule + notification action collection tests
(Sentry message 3 of 8).

Covers metric-alert-rule (organization-scoped, single paginated call with
embedded triggers/actions) and issue-alert-rule (bounded per-project walk)
collection end-to-end via ``SentryConnector.fetch()``: family
independence, per-project completeness, pagination reuse, dedup,
deterministic ordering, the zero-extra-call trigger/action extraction
from the metric-alert-rules response, and scale/cap behavior.
Normalization correctness is covered separately in
``test_sentry_alert_normalization.py``; diff/risk behavior in
``test_sentry_alert_diff.py``.
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
    SENTRY_ALERT_ACTION,
    SENTRY_ISSUE_ALERT_RULE,
    SENTRY_METRIC_ALERT_RULE,
    SENTRY_METRIC_ALERT_TRIGGER,
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
    resolved_path = path or f"/api/0/organizations/{_SLUG}/alert-rules/"
    return httpx.Response(200, json=items, headers={"Link": _link_header(has_next=has_next, path=resolved_path, cursor=cursor)})


def _mock_org():
    respx.get(f"{_BASE}/organizations/{_SLUG}/").mock(
        return_value=httpx.Response(200, json={"id": "999", "slug": _SLUG, "name": "My Org", "status": {"id": "active"}})
    )


def _mock_msg2_empty():
    respx.get(f"{_BASE}/organizations/{_SLUG}/teams/").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{_BASE}/organizations/{_SLUG}/members/").mock(return_value=httpx.Response(200, json=[]))


def _mock_probes_empty():
    for path in ("integrations", "repos", "releases"):
        respx.get(f"{_BASE}/organizations/{_SLUG}/{path}/").mock(return_value=httpx.Response(200, json=[]))


def _project(pid: str, slug: str = None) -> dict:
    return {"id": pid, "slug": slug or f"proj-{pid}", "name": f"Project {pid}", "platform": "python", "status": "active"}


def _metric_rule(rid: str, *, triggers=None, projects=None, **overrides) -> dict:
    base = {
        "id": rid, "name": f"Rule {rid}", "status": 0, "dataset": "transactions", "aggregate": "count()",
        "query": "", "timeWindow": 10, "environment": None, "thresholdType": 0, "resolveThreshold": None,
        "detectionType": "static", "comparisonDelta": None, "owner": None,
        "projects": projects if projects is not None else ["proj-p1"],
        "dateCreated": "2020-01-01T00:00:00Z",
        "triggers": triggers if triggers is not None else [],
    }
    base.update(overrides)
    return base


def _trigger(tid: str, *, actions=None, **overrides) -> dict:
    base = {"id": tid, "label": "critical", "alertThreshold": 100, "actions": actions if actions is not None else []}
    base.update(overrides)
    return base


def _metric_action(aid: str, **overrides) -> dict:
    base = {"id": aid, "type": "email", "targetType": "user", "targetIdentifier": "42"}
    base.update(overrides)
    return base


def _issue_rule(rid: str, *, actions=None, **overrides) -> dict:
    base = {
        "id": rid, "name": f"Issue Rule {rid}", "status": "active", "environment": None,
        "actionMatch": "any", "filterMatch": "all", "frequency": 30,
        "conditions": [{"id": "c1"}], "filters": [], "actions": actions if actions is not None else [],
        "owner": None, "dateCreated": "2020-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def _record_types(records: list[dict], record_type: str) -> list[dict]:
    return [r for r in records if r["record_type"] == record_type]


def _organization_record(records: list[dict]) -> dict:
    return next(r for r in records if r["record_type"] == "sentry_organization")


def _fetch(**mocks):
    return SentryConnector().fetch(_CREDS, _sleep_fn=_noop_sleep)


# ════════════════════════════════════════════════════════════════════════════
# Metric alert rules: embedded triggers/actions, zero extra calls
# ════════════════════════════════════════════════════════════════════════════


class TestMetricAlertCollection:
    @respx.mock
    def test_collects_rule_trigger_and_action_with_no_extra_calls(self):
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[_project("p1")]))
        rules_route = respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(
            return_value=_paginated_response([
                _metric_rule("r1", projects=["proj-p1"], triggers=[_trigger("t1", actions=[_metric_action("a1")])])
            ])
        )
        # No route registered for any per-rule/per-trigger detail endpoint —
        # if the connector tried an extra call, respx's assert_all_mocked
        # default would fail this test.

        records = _fetch()
        assert len(_record_types(records, SENTRY_METRIC_ALERT_RULE)) == 1
        assert len(_record_types(records, SENTRY_METRIC_ALERT_TRIGGER)) == 1
        actions = _record_types(records, SENTRY_ALERT_ACTION)
        assert len(actions) == 1
        assert actions[0]["rule_type"] == "metric"
        rule = _record_types(records, SENTRY_METRIC_ALERT_RULE)[0]
        assert rule["project_id"] == "p1"
        assert rule["trigger_count"] == 1
        assert rule["action_count"] == 1
        # Called exactly twice: once for the message-1 capability probe
        # (page 1 only, never paginated), once for message-3's real
        # collection — never a separate per-rule/per-trigger detail call.
        assert rules_route.call_count == 2

    @respx.mock
    def test_project_resolved_by_slug_without_extra_call(self):
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=httpx.Response(200, json=[_project("p1", slug="checkout-service")])
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(
            return_value=_paginated_response([_metric_rule("r1", projects=["checkout-service"])])
        )
        records = _fetch()
        rule = _record_types(records, SENTRY_METRIC_ALERT_RULE)[0]
        assert rule["project_id"] == "p1"

    @respx.mock
    def test_unresolvable_project_slug_is_none_not_guessed(self):
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(
            return_value=_paginated_response([_metric_rule("r1", projects=["unknown-project"])])
        )
        records = _fetch()
        rule = _record_types(records, SENTRY_METRIC_ALERT_RULE)[0]
        assert rule["project_id"] is None

    @respx.mock
    def test_metric_alerts_denied_does_not_block_issue_alerts(self):
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[_project("p1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=httpx.Response(403, json={}))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(return_value=_paginated_response([_issue_rule("ir1")], path=f"/api/0/projects/{_SLUG}/proj-p1/rules/"))

        records = _fetch()
        assert _record_types(records, SENTRY_METRIC_ALERT_RULE) == []
        assert len(_record_types(records, SENTRY_ISSUE_ALERT_RULE)) == 1
        fc = _organization_record(records)["family_completeness"]
        assert fc["metric_alert_rules"] == FAMILY_DENIED
        assert fc["issue_alert_rules"] == FAMILY_COMPLETE

    @respx.mock
    def test_multi_page_metric_rules(self):
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[_project("p1")]))
        probe_response = httpx.Response(200, json=[])
        page1 = _paginated_response([_metric_rule("r1")], has_next=True)
        page2 = _paginated_response([_metric_rule("r2")], has_next=False)
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(side_effect=[probe_response, page1, page2])

        records = _fetch()
        rules = _record_types(records, SENTRY_METRIC_ALERT_RULE)
        assert {r["rule_id"] for r in rules} == {"r1", "r2"}
        fc = _organization_record(records)["family_completeness"]
        assert fc["metric_alert_rules"] == FAMILY_COMPLETE

    @respx.mock
    def test_dedup_by_rule_id(self):
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[_project("p1")]))
        probe_response = httpx.Response(200, json=[])
        page1 = _paginated_response([_metric_rule("r1")], has_next=True)
        page2 = _paginated_response([_metric_rule("r1")], has_next=False)
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(side_effect=[probe_response, page1, page2])
        records = _fetch()
        assert len(_record_types(records, SENTRY_METRIC_ALERT_RULE)) == 1

    @respx.mock
    def test_deterministic_ordering(self):
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[_project("p1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(
            return_value=_paginated_response([_metric_rule("r3"), _metric_rule("r1"), _metric_rule("r2")])
        )
        records = _fetch()
        rules = _record_types(records, SENTRY_METRIC_ALERT_RULE)
        assert [r["rule_id"] for r in rules] == ["r1", "r2", "r3"]

    @respx.mock
    def test_hitting_cap_is_partial(self, monkeypatch):
        import app.connectors.sentry as sentry_module
        monkeypatch.setattr(sentry_module, "_MAX_METRIC_ALERT_RULES", 2)
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[_project("p1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(
            return_value=_paginated_response([_metric_rule("r1"), _metric_rule("r2"), _metric_rule("r3")])
        )
        records = _fetch()
        assert len(_record_types(records, SENTRY_METRIC_ALERT_RULE)) == 2
        fc = _organization_record(records)["family_completeness"]
        assert fc["metric_alert_rules"] == FAMILY_PARTIAL


# ════════════════════════════════════════════════════════════════════════════
# Issue alert rules: bounded per-project walk
# ════════════════════════════════════════════════════════════════════════════


class TestIssueAlertCollection:
    @respx.mock
    def test_one_project_denied_one_succeeds_is_partial(self):
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(
            return_value=httpx.Response(200, json=[_project("p1", "proj-a"), _project("p2", "proj-b")])
        )
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-a/rules/").mock(
            return_value=_paginated_response([_issue_rule("ir1")], path=f"/api/0/projects/{_SLUG}/proj-a/rules/")
        )
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-b/rules/").mock(return_value=httpx.Response(403, json={}))

        records = _fetch()
        rules = _record_types(records, SENTRY_ISSUE_ALERT_RULE)
        assert len(rules) == 1
        assert rules[0]["project_id"] == "p1"
        fc = _organization_record(records)["family_completeness"]
        assert fc["issue_alert_rules"] == FAMILY_PARTIAL

    @respx.mock
    def test_all_projects_denied_is_denied(self):
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[_project("p1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(return_value=httpx.Response(403, json={}))
        records = _fetch()
        fc = _organization_record(records)["family_completeness"]
        assert fc["issue_alert_rules"] == FAMILY_DENIED

    @respx.mock
    def test_zero_projects_is_trivially_complete(self):
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=_paginated_response([]))
        records = _fetch()
        fc = _organization_record(records)["family_completeness"]
        assert fc["issue_alert_rules"] == FAMILY_COMPLETE

    @respx.mock
    def test_project_missing_slug_is_unavailable(self):
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        broken_project = {"id": "p1", "name": "No Slug", "platform": "python", "status": "active"}
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[broken_project]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=_paginated_response([]))
        records = _fetch()
        fc = _organization_record(records)["family_completeness"]
        assert fc["issue_alert_rules"] == FAMILY_UNAVAILABLE

    @respx.mock
    def test_issue_alert_actions_use_position_based_identity(self):
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[_project("p1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(
            return_value=_paginated_response(
                [_issue_rule("ir1", actions=[{"id": "sentry.mail.actions.NotifyEmailAction"}, {"id": "sentry.integrations.slack.notify"}])],
                path=f"/api/0/projects/{_SLUG}/proj-p1/rules/",
            )
        )
        records = _fetch()
        actions = _record_types(records, SENTRY_ALERT_ACTION)
        assert len(actions) == 2
        assert {a["record_id"] for a in actions} == {"id:999/alert_action/issue/ir1/0", "id:999/alert_action/issue/ir1/1"}


# ════════════════════════════════════════════════════════════════════════════
# Scale
# ════════════════════════════════════════════════════════════════════════════


class TestAlertScale:
    @respx.mock
    def test_issue_alert_rule_cap_is_partial(self, monkeypatch):
        import app.connectors.sentry as sentry_module
        monkeypatch.setattr(sentry_module, "_MAX_ISSUE_ALERT_RULES_PER_PROJECT", 2)
        _mock_org()
        _mock_msg2_empty()
        _mock_probes_empty()
        respx.get(f"{_BASE}/organizations/{_SLUG}/projects/").mock(return_value=httpx.Response(200, json=[_project("p1")]))
        respx.get(f"{_BASE}/organizations/{_SLUG}/alert-rules/").mock(return_value=_paginated_response([]))
        respx.get(f"{_BASE}/projects/{_SLUG}/proj-p1/rules/").mock(
            return_value=_paginated_response(
                [_issue_rule("ir1"), _issue_rule("ir2"), _issue_rule("ir3")],
                path=f"/api/0/projects/{_SLUG}/proj-p1/rules/",
            )
        )
        records = _fetch()
        assert len(_record_types(records, SENTRY_ISSUE_ALERT_RULE)) == 2
        fc = _organization_record(records)["family_completeness"]
        assert fc["issue_alert_rules"] == FAMILY_PARTIAL
