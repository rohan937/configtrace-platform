"""Sentry metric/issue alert rule + notification action diff/risk-
classification tests (Sentry message 3 of 8).

Uses the REAL ``compute_diff()`` and ``classify_sentry_change()`` — never
hand-built Change objects standing in for the diff pipeline — to verify
rule enabled/disabled, removal, threshold weakening/strengthening
(direction-aware), action-count-drops-to-zero routing severity, action
add/remove/target changes, and provider_metadata context.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.sentry import classify_sentry_change

_ORG_ID = "id:999"


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _metric_rule(rid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_metric_alert_rule",
        "record_id": f"{_ORG_ID}/metric_alert_rule/{rid}",
        "provider_resource_id": f"alert-rules/{rid}",
        "organization_id": _ORG_ID,
        "project_id": "p1",
        "rule_id": rid,
        "name": f"Rule {rid}",
        "status_category": "enabled",
        "dataset_category": "transactions",
        "aggregate_category": "percentile",
        "has_query": True,
        "time_window_minutes": 10,
        "environment_category": "all",
        "threshold_type_category": "above",
        "resolve_threshold": None,
        "detection_type_category": "static",
        "comparison_delta_minutes": None,
        "owner_type_category": "unknown",
        "owner_id": None,
        "trigger_count": 1,
        "action_count": 1,
        "date_created": "2020-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def _metric_trigger(rid: str, tid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_metric_alert_trigger",
        "record_id": f"{_ORG_ID}/metric_alert_trigger/{rid}/{tid}",
        "provider_resource_id": f"alert-rule-triggers/{tid}",
        "organization_id": _ORG_ID,
        "rule_id": rid,
        "trigger_id": tid,
        "label_category": "critical",
        "alert_threshold": 500.0,
        "action_count": 1,
        "threshold_type_category": "above",
    }
    base.update(overrides)
    return base


def _issue_rule(rid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_issue_alert_rule",
        "record_id": f"{_ORG_ID}/issue_alert_rule/{rid}",
        "provider_resource_id": f"rules/{rid}",
        "organization_id": _ORG_ID,
        "project_id": "p1",
        "rule_id": rid,
        "name": f"Issue Rule {rid}",
        "status_category": "enabled",
        "environment_category": "all",
        "action_match_category": "any",
        "filter_match_category": "all",
        "frequency_minutes": 30,
        "condition_count": 1,
        "filter_count": 0,
        "action_count": 1,
        "owner_type_category": "unknown",
        "owner_id": None,
        "date_created": "2020-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def _action(rid: str, aid: str, *, rule_type="metric", trigger_id="t1", **overrides) -> dict:
    scope = trigger_id if rule_type == "metric" else rid
    base = {
        "record_type": "sentry_alert_action",
        "record_id": f"{_ORG_ID}/alert_action/{rule_type}/{scope}/{aid}",
        "provider_resource_id": f"alert-actions/{rule_type}/{scope}/{aid}",
        "organization_id": _ORG_ID,
        "rule_type": rule_type,
        "rule_id": rid,
        "trigger_id": trigger_id if rule_type == "metric" else None,
        "action_category": "slack",
        "target_type_category": "team",
        "target_id": "55",
        "integration_id": "99",
    }
    base.update(overrides)
    return base


def _diff(prev: list[dict], new: list[dict]):
    return compute_diff(_snap(prev), _snap(new))


def _find(changes, *, field_path=None, change_type=None):
    for c in changes:
        if change_type is not None and c["change_type"] != change_type:
            continue
        if field_path is not None and c.get("field_path") != field_path:
            continue
        return c
    raise AssertionError(f"no change matched field_path={field_path!r} change_type={change_type!r} in {changes}")


# ════════════════════════════════════════════════════════════════════════════
# Metric alert rule
# ════════════════════════════════════════════════════════════════════════════


class TestMetricAlertRuleDiff:
    def test_added_enabled_with_actions_is_low(self):
        changes = _diff([], [_metric_rule("r1", action_count=1)])
        c = _find(changes, change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_added_enabled_zero_actions_is_medium(self):
        changes = _diff([], [_metric_rule("r1", action_count=0)])
        c = _find(changes, change_type="added")
        assert classify_sentry_change(c)[0] == "medium"

    def test_removed_is_medium(self):
        changes = _diff([_metric_rule("r1")], [])
        c = _find(changes, change_type="removed")
        assert classify_sentry_change(c)[0] == "medium"

    def test_disabled_is_medium(self):
        changes = _diff(
            [_metric_rule("r1", status_category="enabled")],
            [_metric_rule("r1", status_category="disabled")],
        )
        c = _find(changes, field_path="status_category")
        assert classify_sentry_change(c)[0] == "medium"

    def test_reenabled_is_low(self):
        changes = _diff(
            [_metric_rule("r1", status_category="disabled")],
            [_metric_rule("r1", status_category="enabled")],
        )
        c = _find(changes, field_path="status_category")
        assert classify_sentry_change(c)[0] == "low"

    def test_action_count_drops_to_zero_on_enabled_rule_is_high(self):
        changes = _diff(
            [_metric_rule("r1", status_category="enabled", action_count=1)],
            [_metric_rule("r1", status_category="enabled", action_count=0)],
        )
        c = _find(changes, field_path="action_count")
        severity, msg = classify_sentry_change(c)
        assert severity == "high"
        assert "last notification action" in msg

    def test_action_count_drops_to_zero_on_disabled_rule_is_medium(self):
        changes = _diff(
            [_metric_rule("r1", status_category="disabled", action_count=1)],
            [_metric_rule("r1", status_category="disabled", action_count=0)],
        )
        c = _find(changes, field_path="action_count")
        assert classify_sentry_change(c)[0] == "medium"

    def test_action_count_increases_is_low(self):
        changes = _diff(
            [_metric_rule("r1", action_count=1)],
            [_metric_rule("r1", action_count=2)],
        )
        c = _find(changes, field_path="action_count")
        assert classify_sentry_change(c)[0] == "low"

    def test_owner_change_is_medium(self):
        changes = _diff(
            [_metric_rule("r1", owner_type_category="team", owner_id="1")],
            [_metric_rule("r1", owner_type_category="team", owner_id="2")],
        )
        c = _find(changes, field_path="owner_id")
        assert classify_sentry_change(c)[0] == "medium"

    def test_dataset_change_is_low(self):
        changes = _diff(
            [_metric_rule("r1", dataset_category="transactions")],
            [_metric_rule("r1", dataset_category="sessions")],
        )
        c = _find(changes, field_path="dataset_category")
        assert classify_sentry_change(c)[0] == "low"

    def test_has_query_not_tracked(self):
        changes = _diff(
            [_metric_rule("r1", has_query=True)],
            [_metric_rule("r1", has_query=False)],
        )
        assert changes == []

    def test_provider_metadata_carries_context(self):
        changes = _diff([], [_metric_rule("r1", action_count=3)])
        c = _find(changes, change_type="added")
        assert c["provider_metadata"]["rule_id"] == "r1"
        assert c["provider_metadata"]["action_count"] == 3


# ════════════════════════════════════════════════════════════════════════════
# Metric alert trigger — threshold weakening/strengthening
# ════════════════════════════════════════════════════════════════════════════


class TestMetricAlertTriggerDiff:
    def test_added_is_low(self):
        changes = _diff([], [_metric_trigger("r1", "t1")])
        c = _find(changes, change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_removed_is_medium(self):
        changes = _diff([_metric_trigger("r1", "t1")], [])
        c = _find(changes, change_type="removed")
        assert classify_sentry_change(c)[0] == "medium"

    def test_above_threshold_raised_is_weakened_medium(self):
        changes = _diff(
            [_metric_trigger("r1", "t1", alert_threshold=500.0, threshold_type_category="above")],
            [_metric_trigger("r1", "t1", alert_threshold=900.0, threshold_type_category="above")],
        )
        c = _find(changes, field_path="alert_threshold")
        severity, msg = classify_sentry_change(c)
        assert severity == "medium"
        assert "weakened" in msg

    def test_above_threshold_lowered_is_strengthened_low(self):
        changes = _diff(
            [_metric_trigger("r1", "t1", alert_threshold=500.0, threshold_type_category="above")],
            [_metric_trigger("r1", "t1", alert_threshold=200.0, threshold_type_category="above")],
        )
        c = _find(changes, field_path="alert_threshold")
        severity, msg = classify_sentry_change(c)
        assert severity == "low"
        assert "strengthened" in msg

    def test_below_threshold_lowered_is_weakened_medium(self):
        changes = _diff(
            [_metric_trigger("r1", "t1", alert_threshold=500.0, threshold_type_category="below")],
            [_metric_trigger("r1", "t1", alert_threshold=200.0, threshold_type_category="below")],
        )
        c = _find(changes, field_path="alert_threshold")
        severity, msg = classify_sentry_change(c)
        assert severity == "medium"
        assert "weakened" in msg

    def test_below_threshold_raised_is_strengthened_low(self):
        changes = _diff(
            [_metric_trigger("r1", "t1", alert_threshold=200.0, threshold_type_category="below")],
            [_metric_trigger("r1", "t1", alert_threshold=500.0, threshold_type_category="below")],
        )
        c = _find(changes, field_path="alert_threshold")
        severity, msg = classify_sentry_change(c)
        assert severity == "low"
        assert "strengthened" in msg

    def test_unknown_direction_is_low_diagnostic_not_guessed(self):
        changes = _diff(
            [_metric_trigger("r1", "t1", alert_threshold=500.0, threshold_type_category="unknown")],
            [_metric_trigger("r1", "t1", alert_threshold=900.0, threshold_type_category="unknown")],
        )
        c = _find(changes, field_path="alert_threshold")
        severity, msg = classify_sentry_change(c)
        assert severity == "low"
        assert "unknown" in msg.lower()

    def test_action_count_drops_to_zero_on_trigger_is_medium(self):
        changes = _diff(
            [_metric_trigger("r1", "t1", action_count=1)],
            [_metric_trigger("r1", "t1", action_count=0)],
        )
        c = _find(changes, field_path="action_count")
        assert classify_sentry_change(c)[0] == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Issue alert rule
# ════════════════════════════════════════════════════════════════════════════


class TestIssueAlertRuleDiff:
    def test_added_enabled_zero_actions_is_medium(self):
        changes = _diff([], [_issue_rule("ir1", action_count=0)])
        c = _find(changes, change_type="added")
        assert classify_sentry_change(c)[0] == "medium"

    def test_added_with_actions_is_low(self):
        changes = _diff([], [_issue_rule("ir1", action_count=1)])
        c = _find(changes, change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_removed_is_medium(self):
        changes = _diff([_issue_rule("ir1")], [])
        c = _find(changes, change_type="removed")
        assert classify_sentry_change(c)[0] == "medium"

    def test_disabled_is_medium(self):
        changes = _diff(
            [_issue_rule("ir1", status_category="enabled")],
            [_issue_rule("ir1", status_category="disabled")],
        )
        c = _find(changes, field_path="status_category")
        assert classify_sentry_change(c)[0] == "medium"

    def test_action_count_drops_to_zero_enabled_is_high(self):
        changes = _diff(
            [_issue_rule("ir1", status_category="enabled", action_count=1)],
            [_issue_rule("ir1", status_category="enabled", action_count=0)],
        )
        c = _find(changes, field_path="action_count")
        assert classify_sentry_change(c)[0] == "high"

    def test_condition_count_change_is_low(self):
        changes = _diff(
            [_issue_rule("ir1", condition_count=1)],
            [_issue_rule("ir1", condition_count=2)],
        )
        c = _find(changes, field_path="condition_count")
        assert classify_sentry_change(c)[0] == "low"

    def test_owner_change_is_medium(self):
        changes = _diff(
            [_issue_rule("ir1", owner_type_category="user", owner_id="1")],
            [_issue_rule("ir1", owner_type_category="user", owner_id="2")],
        )
        c = _find(changes, field_path="owner_id")
        assert classify_sentry_change(c)[0] == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Alert action
# ════════════════════════════════════════════════════════════════════════════


class TestAlertActionDiff:
    def test_added_is_low(self):
        changes = _diff([], [_action("r1", "a1")])
        c = _find(changes, change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_removed_is_medium(self):
        changes = _diff([_action("r1", "a1")], [])
        c = _find(changes, change_type="removed")
        assert classify_sentry_change(c)[0] == "medium"

    def test_target_changed_is_medium(self):
        changes = _diff(
            [_action("r1", "a1", target_id="55")],
            [_action("r1", "a1", target_id="66")],
        )
        c = _find(changes, field_path="target_id")
        assert classify_sentry_change(c)[0] == "medium"

    def test_integration_changed_is_medium(self):
        changes = _diff(
            [_action("r1", "a1", integration_id="99")],
            [_action("r1", "a1", integration_id="100")],
        )
        c = _find(changes, field_path="integration_id")
        assert classify_sentry_change(c)[0] == "medium"

    def test_provider_metadata_never_includes_target_id_pii(self):
        changes = _diff([], [_action("r1", "a1", target_type_category="specific", target_id=None)])
        c = _find(changes, change_type="added")
        assert "target_id" not in c["provider_metadata"] or c["provider_metadata"].get("target_id") is None

    def test_reordered_actions_produce_no_diff(self):
        prev = [_action("r1", "a1"), _action("r1", "a2")]
        new = [_action("r1", "a2"), _action("r1", "a1")]
        assert _diff(prev, new) == []


# ════════════════════════════════════════════════════════════════════════════
# Notification routing severity (action-count-drops-to-zero across both
# metric and issue alert rules)
# ════════════════════════════════════════════════════════════════════════════


class TestNotificationRoutingSeverity:
    def test_metric_rule_routing_lost_while_enabled_is_high(self):
        changes = _diff(
            [_metric_rule("r1", status_category="enabled", action_count=1)],
            [_metric_rule("r1", status_category="enabled", action_count=0)],
        )
        c = _find(changes, field_path="action_count")
        assert classify_sentry_change(c)[0] == "high"

    def test_issue_rule_routing_lost_while_enabled_is_high(self):
        changes = _diff(
            [_issue_rule("ir1", status_category="enabled", action_count=1)],
            [_issue_rule("ir1", status_category="enabled", action_count=0)],
        )
        c = _find(changes, field_path="action_count")
        assert classify_sentry_change(c)[0] == "high"

    def test_routing_restored_from_zero_is_low(self):
        changes = _diff(
            [_metric_rule("r1", action_count=0)],
            [_metric_rule("r1", action_count=1)],
        )
        c = _find(changes, field_path="action_count")
        assert classify_sentry_change(c)[0] == "low"
