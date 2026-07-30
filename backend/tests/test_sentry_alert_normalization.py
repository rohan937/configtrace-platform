"""Sentry metric/issue alert rule + notification action normalization
tests (Sentry message 3 of 8).

Covers the pure ``SentryConnector._normalize_*`` methods and the
``sentry_schema`` categorizers they use: stable identity, status/dataset/
aggregate/environment/threshold-type/detection-type/match-type/action/
target-type taxonomies, unknown-state discipline, and the sensitive-data
boundary (never raw query strings, emails, webhook URLs, or integration
secrets on any message-3 record). Collection-level behavior is covered
in ``test_sentry_alert_collection.py``; diff/risk behavior in
``test_sentry_alert_diff.py``.
"""

from __future__ import annotations

from app.connectors.sentry import SentryConnector
from app.connectors.sentry_schema import (
    ACTION_CATEGORY_EMAIL,
    ACTION_CATEGORY_PAGERDUTY,
    ACTION_CATEGORY_SLACK,
    ACTION_CATEGORY_UNKNOWN,
    AGGREGATE_CATEGORY_COUNT,
    AGGREGATE_CATEGORY_OTHER,
    AGGREGATE_CATEGORY_PERCENTILE,
    AGGREGATE_CATEGORY_UNKNOWN,
    DATASET_CATEGORY_OTHER,
    DATASET_CATEGORY_TRANSACTIONS,
    DATASET_CATEGORY_UNKNOWN,
    DETECTION_TYPE_STATIC,
    DETECTION_TYPE_UNKNOWN,
    ENVIRONMENT_CATEGORY_ALL,
    ENVIRONMENT_CATEGORY_OTHER,
    ENVIRONMENT_CATEGORY_PRODUCTION,
    ISSUE_ALERT_STATUS_DISABLED,
    ISSUE_ALERT_STATUS_ENABLED,
    ISSUE_ALERT_STATUS_UNKNOWN,
    MATCH_TYPE_ALL,
    MATCH_TYPE_ANY,
    MATCH_TYPE_UNKNOWN,
    METRIC_ALERT_STATUS_DISABLED,
    METRIC_ALERT_STATUS_ENABLED,
    METRIC_ALERT_STATUS_UNKNOWN,
    OWNER_TYPE_TEAM,
    OWNER_TYPE_UNKNOWN,
    OWNER_TYPE_USER,
    TARGET_TYPE_SPECIFIC,
    TARGET_TYPE_TEAM,
    TARGET_TYPE_UNKNOWN,
    THRESHOLD_TYPE_ABOVE,
    THRESHOLD_TYPE_BELOW,
    THRESHOLD_TYPE_UNKNOWN,
    TRIGGER_LABEL_CRITICAL,
    TRIGGER_LABEL_OTHER,
    TRIGGER_LABEL_UNKNOWN,
    categorize_aggregate,
    categorize_dataset,
    categorize_detection_type,
    categorize_environment,
    categorize_issue_action_id,
    categorize_issue_alert_status,
    categorize_match_type,
    categorize_metric_action_type,
    categorize_metric_alert_status,
    categorize_owner,
    categorize_target_type,
    categorize_threshold_type,
    categorize_trigger_label,
)

_ORG_ID = "id:999"


class TestMetricAlertRuleNormalization:
    def test_normalizes_basic_fields(self):
        rec = SentryConnector._normalize_metric_alert_rule(_ORG_ID, {
            "id": "r1", "name": "High errors", "status": 0, "dataset": "transactions",
            "aggregate": "p95(transaction.duration)", "query": "event.type:transaction",
            "timeWindow": 10, "environment": "production", "thresholdType": 0,
            "resolveThreshold": 50.0, "detectionType": "static", "comparisonDelta": 60,
            "owner": "team:5", "triggers": [{}, {}], "dateCreated": "2020-01-01T00:00:00Z",
        }, project_id="p1")
        assert rec["record_type"] == "sentry_metric_alert_rule"
        assert rec["record_id"] == f"{_ORG_ID}/metric_alert_rule/r1"
        assert rec["project_id"] == "p1"
        assert rec["status_category"] == METRIC_ALERT_STATUS_ENABLED
        assert rec["dataset_category"] == DATASET_CATEGORY_TRANSACTIONS
        assert rec["has_query"] is True
        assert rec["time_window_minutes"] == 10
        assert rec["environment_category"] == ENVIRONMENT_CATEGORY_PRODUCTION
        assert rec["threshold_type_category"] == THRESHOLD_TYPE_ABOVE
        assert rec["resolve_threshold"] == 50.0
        assert rec["owner_type_category"] == OWNER_TYPE_TEAM
        assert rec["owner_id"] == "5"
        assert rec["trigger_count"] == 2

    def test_missing_id_returns_none(self):
        assert SentryConnector._normalize_metric_alert_rule(_ORG_ID, {}, project_id=None) is None

    def test_never_stores_raw_query_string(self):
        rec = SentryConnector._normalize_metric_alert_rule(
            _ORG_ID, {"id": "r1", "query": "user.email:someone@customer.example.com"}, project_id=None,
        )
        assert "someone@customer.example.com" not in str(rec)
        assert rec["has_query"] is True

    def test_missing_time_window_is_none(self):
        rec = SentryConnector._normalize_metric_alert_rule(_ORG_ID, {"id": "r1"}, project_id=None)
        assert rec["time_window_minutes"] is None

    def test_missing_resolve_threshold_is_none_not_zero(self):
        rec = SentryConnector._normalize_metric_alert_rule(_ORG_ID, {"id": "r1"}, project_id=None)
        assert rec["resolve_threshold"] is None

    def test_missing_trigger_count_is_none_not_zero(self):
        rec = SentryConnector._normalize_metric_alert_rule(_ORG_ID, {"id": "r1"}, project_id=None)
        assert rec["trigger_count"] is None

    def test_action_count_starts_as_none_filled_by_collector(self):
        rec = SentryConnector._normalize_metric_alert_rule(_ORG_ID, {"id": "r1"}, project_id=None)
        assert rec["action_count"] is None


class TestMetricAlertStatusTaxonomy:
    def test_disabled_value(self):
        assert categorize_metric_alert_status(5) == METRIC_ALERT_STATUS_DISABLED

    def test_other_known_values_are_enabled(self):
        assert categorize_metric_alert_status(0) == METRIC_ALERT_STATUS_ENABLED
        assert categorize_metric_alert_status(4) == METRIC_ALERT_STATUS_ENABLED
        assert categorize_metric_alert_status(6) == METRIC_ALERT_STATUS_ENABLED

    def test_missing_or_unrecognized_is_unknown(self):
        assert categorize_metric_alert_status(None) == METRIC_ALERT_STATUS_UNKNOWN
        assert categorize_metric_alert_status(99) == METRIC_ALERT_STATUS_UNKNOWN
        assert categorize_metric_alert_status(True) == METRIC_ALERT_STATUS_UNKNOWN


class TestIssueAlertStatusTaxonomy:
    def test_recognized_values(self):
        assert categorize_issue_alert_status("active") == ISSUE_ALERT_STATUS_ENABLED
        assert categorize_issue_alert_status("disabled") == ISSUE_ALERT_STATUS_DISABLED

    def test_missing_or_unrecognized_is_unknown(self):
        assert categorize_issue_alert_status(None) == ISSUE_ALERT_STATUS_UNKNOWN
        assert categorize_issue_alert_status("weird") == ISSUE_ALERT_STATUS_UNKNOWN


class TestDatasetTaxonomy:
    def test_recognized_values(self):
        assert categorize_dataset("transactions") == DATASET_CATEGORY_TRANSACTIONS
        assert categorize_dataset("sessions") == "sessions"

    def test_unrecognized_is_other_missing_is_unknown(self):
        assert categorize_dataset("some-new-dataset") == DATASET_CATEGORY_OTHER
        assert categorize_dataset(None) == DATASET_CATEGORY_UNKNOWN


class TestAggregateTaxonomy:
    def test_recognized_prefixes(self):
        assert categorize_aggregate("count()") == AGGREGATE_CATEGORY_COUNT
        assert categorize_aggregate("p95(transaction.duration)") == AGGREGATE_CATEGORY_PERCENTILE

    def test_unrecognized_is_other_missing_is_unknown(self):
        assert categorize_aggregate("weird_fn()") == AGGREGATE_CATEGORY_OTHER
        assert categorize_aggregate(None) == AGGREGATE_CATEGORY_UNKNOWN

    def test_never_retains_raw_expression_with_field_names(self):
        category = categorize_aggregate("avg(user.sensitive_field)")
        assert "sensitive_field" not in category


class TestEnvironmentTaxonomy:
    def test_none_means_all_not_unknown(self):
        assert categorize_environment(None) == ENVIRONMENT_CATEGORY_ALL

    def test_recognized_names(self):
        assert categorize_environment("production") == ENVIRONMENT_CATEGORY_PRODUCTION
        assert categorize_environment("prod-us-east") == ENVIRONMENT_CATEGORY_PRODUCTION

    def test_unrecognized_is_other(self):
        assert categorize_environment("my-custom-env") == ENVIRONMENT_CATEGORY_OTHER


class TestThresholdTypeTaxonomy:
    def test_recognized_values(self):
        assert categorize_threshold_type(0) == THRESHOLD_TYPE_ABOVE
        assert categorize_threshold_type(1) == THRESHOLD_TYPE_BELOW

    def test_missing_or_unrecognized_is_unknown(self):
        assert categorize_threshold_type(None) == THRESHOLD_TYPE_UNKNOWN
        assert categorize_threshold_type(99) == THRESHOLD_TYPE_UNKNOWN
        assert categorize_threshold_type(True) == THRESHOLD_TYPE_UNKNOWN


class TestDetectionTypeTaxonomy:
    def test_recognized_value(self):
        assert categorize_detection_type("static") == DETECTION_TYPE_STATIC

    def test_missing_is_unknown(self):
        assert categorize_detection_type(None) == DETECTION_TYPE_UNKNOWN


class TestMatchTypeTaxonomy:
    def test_recognized_values(self):
        assert categorize_match_type("all") == MATCH_TYPE_ALL
        assert categorize_match_type("any") == MATCH_TYPE_ANY

    def test_missing_is_unknown(self):
        assert categorize_match_type(None) == MATCH_TYPE_UNKNOWN


class TestTriggerLabelTaxonomy:
    def test_recognized_value(self):
        assert categorize_trigger_label("critical") == TRIGGER_LABEL_CRITICAL

    def test_unrecognized_is_other_missing_is_unknown(self):
        assert categorize_trigger_label("custom-label") == TRIGGER_LABEL_OTHER
        assert categorize_trigger_label(None) == TRIGGER_LABEL_UNKNOWN


class TestMetricAlertTriggerNormalization:
    def test_normalizes_basic_fields(self):
        rec = SentryConnector._normalize_metric_alert_trigger(
            _ORG_ID, "r1", {"id": "t1", "label": "critical", "alertThreshold": 500, "actions": [{}]},
            threshold_type_category=THRESHOLD_TYPE_ABOVE,
        )
        assert rec["record_type"] == "sentry_metric_alert_trigger"
        assert rec["record_id"] == f"{_ORG_ID}/metric_alert_trigger/r1/t1"
        assert rec["label_category"] == TRIGGER_LABEL_CRITICAL
        assert rec["alert_threshold"] == 500.0
        assert rec["action_count"] == 1
        assert rec["threshold_type_category"] == THRESHOLD_TYPE_ABOVE

    def test_missing_id_returns_none(self):
        assert SentryConnector._normalize_metric_alert_trigger(
            _ORG_ID, "r1", {}, threshold_type_category=THRESHOLD_TYPE_ABOVE,
        ) is None

    def test_missing_threshold_is_none(self):
        rec = SentryConnector._normalize_metric_alert_trigger(
            _ORG_ID, "r1", {"id": "t1"}, threshold_type_category=THRESHOLD_TYPE_ABOVE,
        )
        assert rec["alert_threshold"] is None


class TestIssueAlertRuleNormalization:
    def test_normalizes_basic_fields(self):
        rec = SentryConnector._normalize_issue_alert_rule(_ORG_ID, "p1", {
            "id": "ir1", "name": "New issue", "status": "active", "environment": None,
            "actionMatch": "any", "filterMatch": "all", "frequency": 30,
            "conditions": [{}], "filters": [], "actions": [{}, {}], "owner": "user:9",
            "dateCreated": "2020-01-01T00:00:00Z",
        })
        assert rec["record_type"] == "sentry_issue_alert_rule"
        assert rec["record_id"] == f"{_ORG_ID}/issue_alert_rule/ir1"
        assert rec["project_id"] == "p1"
        assert rec["status_category"] == ISSUE_ALERT_STATUS_ENABLED
        assert rec["action_match_category"] == MATCH_TYPE_ANY
        assert rec["filter_match_category"] == MATCH_TYPE_ALL
        assert rec["frequency_minutes"] == 30
        assert rec["condition_count"] == 1
        assert rec["filter_count"] == 0
        assert rec["action_count"] == 2
        assert rec["owner_type_category"] == OWNER_TYPE_USER
        assert rec["owner_id"] == "9"

    def test_missing_id_returns_none(self):
        assert SentryConnector._normalize_issue_alert_rule(_ORG_ID, "p1", {}) is None

    def test_missing_condition_filter_counts_are_none_not_zero(self):
        rec = SentryConnector._normalize_issue_alert_rule(_ORG_ID, "p1", {"id": "ir1"})
        assert rec["condition_count"] is None
        assert rec["filter_count"] is None
        assert rec["action_count"] is None


class TestActionCategoryTaxonomy:
    def test_metric_action_type_slugs(self):
        assert categorize_metric_action_type("slack") == ACTION_CATEGORY_SLACK
        assert categorize_metric_action_type("pagerduty") == ACTION_CATEGORY_PAGERDUTY
        assert categorize_metric_action_type("email") == ACTION_CATEGORY_EMAIL

    def test_metric_action_type_unrecognized_is_unknown(self):
        assert categorize_metric_action_type("something-new") == ACTION_CATEGORY_UNKNOWN
        assert categorize_metric_action_type(None) == ACTION_CATEGORY_UNKNOWN

    def test_issue_action_id_class_path_substring_match(self):
        assert categorize_issue_action_id("sentry.mail.actions.NotifyEmailAction") == ACTION_CATEGORY_EMAIL
        assert categorize_issue_action_id("sentry.integrations.slack.notify_action.SlackAction") == ACTION_CATEGORY_SLACK

    def test_issue_action_id_missing_is_unknown(self):
        assert categorize_issue_action_id(None) == ACTION_CATEGORY_UNKNOWN
        assert categorize_issue_action_id("") == ACTION_CATEGORY_UNKNOWN


class TestTargetTypeTaxonomy:
    def test_recognized_values(self):
        assert categorize_target_type("team") == TARGET_TYPE_TEAM
        assert categorize_target_type("specific") == TARGET_TYPE_SPECIFIC

    def test_missing_is_unknown(self):
        assert categorize_target_type(None) == TARGET_TYPE_UNKNOWN


class TestOwnerCategorization:
    def test_team_and_user_actors(self):
        assert categorize_owner("team:123") == (OWNER_TYPE_TEAM, "123")
        assert categorize_owner("user:456") == (OWNER_TYPE_USER, "456")

    def test_missing_or_malformed_is_unknown(self):
        assert categorize_owner(None) == (OWNER_TYPE_UNKNOWN, None)
        assert categorize_owner("bare-numeric-id") == (OWNER_TYPE_UNKNOWN, None)


class TestAlertActionNormalization:
    def test_metric_action_resolves_team_target(self):
        rec = SentryConnector._normalize_metric_alert_action(_ORG_ID, "r1", "t1", {
            "id": "a1", "type": "slack", "targetType": "team", "targetIdentifier": "55", "integrationId": "99",
        })
        assert rec["record_type"] == "sentry_alert_action"
        assert rec["record_id"] == f"{_ORG_ID}/alert_action/metric/t1/a1"
        assert rec["rule_type"] == "metric"
        assert rec["action_category"] == ACTION_CATEGORY_SLACK
        assert rec["target_type_category"] == TARGET_TYPE_TEAM
        assert rec["target_id"] == "55"
        assert rec["integration_id"] == "99"

    def test_metric_action_missing_id_returns_none(self):
        assert SentryConnector._normalize_metric_alert_action(_ORG_ID, "r1", "t1", {}) is None

    def test_specific_target_identifier_never_stored(self):
        rec = SentryConnector._normalize_metric_alert_action(_ORG_ID, "r1", "t1", {
            "id": "a1", "type": "email", "targetType": "specific", "targetIdentifier": "someone@example.com",
        })
        assert rec["target_id"] is None
        assert "someone@example.com" not in str(rec)

    def test_issue_action_uses_position_based_identity(self):
        rec = SentryConnector._normalize_issue_alert_action(_ORG_ID, "ir1", 2, {"id": "sentry.mail.actions.NotifyEmailAction"})
        assert rec["record_id"] == f"{_ORG_ID}/alert_action/issue/ir1/2"
        assert rec["rule_type"] == "issue"
        assert rec["trigger_id"] is None
        assert rec["action_category"] == ACTION_CATEGORY_EMAIL

    def test_issue_action_team_target_resolved(self):
        rec = SentryConnector._normalize_issue_alert_action(_ORG_ID, "ir1", 0, {
            "id": "sentry.mail.actions.NotifyEmailAction", "targetType": "Team", "targetIdentifier": "55",
        })
        assert rec["target_type_category"] == TARGET_TYPE_TEAM
        assert rec["target_id"] == "55"
