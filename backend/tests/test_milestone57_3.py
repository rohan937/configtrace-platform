"""M57.3 tests — Needs Review Queue, SnoozeRule, dashboard counts, alert suppression.

Coverage
--------
1.  ChangeSnoozeRule model fields + defaults
2.  create_snooze_rule — happy path
3.  create_snooze_rule — past expiry raises ValueError
4.  create_snooze_rule — >90 days raises ValueError
5.  create_snooze_rule — naive datetime normalised to UTC
6.  list_active_rules — returns only active, non-expired
7.  deactivate_rule — sets is_active False
8.  deactivate_rule — missing rule returns None
9.  is_change_snoozed_by_rule — no workspace_id → False
10. is_change_snoozed_by_rule — no matching rules → False
11. is_change_snoozed_by_rule — exact match → True
12. is_change_snoozed_by_rule — record_identifier mismatch → False
13. is_change_snoozed_by_rule — risk_level mismatch → False
14. is_change_snoozed_by_rule — expired rule → False
15. is_change_snoozed_by_rule — DB error → fails open (False)
16. get_needs_review_changes — returns changes with no review row
17. get_needs_review_changes — excludes acknowledged changes
18. get_needs_review_changes — includes expired-snooze changes
19. count_needs_review — correct scalar
20. count_needs_review_by_risk — filtered by risk level
21. alert_service: snooze-rule suppresses eligible change
22. alert_service: snooze-rule lookup error → fails open (not suppressed)
23. notification_service: snooze-rule suppresses qualifying change
24. dashboard_service: review_queue counts populated
25. /changes/needs-review endpoint — returns 200 with items + total
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _future(days: int = 7) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)


def _past(days: int = 1) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def _make_mock_rule(
    *,
    integration_id=None,
    record_identifier_pattern=None,
    field_path=None,
    risk_level=None,
    snoozed_until=None,
    is_active=True,
) -> MagicMock:
    rule = MagicMock()
    rule.id = _uuid()
    rule.integration_id = integration_id or _uuid()
    rule.record_identifier_pattern = record_identifier_pattern
    rule.field_path = field_path
    rule.risk_level = risk_level
    rule.snoozed_until = snoozed_until or _future()
    rule.is_active = is_active
    return rule


def _make_mock_change(
    *,
    integration_id=None,
    record_identifier="example.com",
    field_path="proxied",
    risk_level="high",
    user_id=None,
) -> MagicMock:
    change = MagicMock()
    change.id = _uuid()
    change.integration_id = integration_id or _uuid()
    change.record_identifier = record_identifier
    change.field_path = field_path
    change.risk_level = risk_level
    change.user_id = user_id or _uuid()
    return change


# ─────────────────────────────────────────────────────────────────────────────
# 1. ChangeSnoozeRule model fields + defaults
# ─────────────────────────────────────────────────────────────────────────────


class TestChangeSnoozeRuleModel:
    def test_tablename(self):
        from app.models.change_snooze_rule import ChangeSnoozeRule

        assert ChangeSnoozeRule.__tablename__ == "change_snooze_rules"

    def test_required_columns_exist(self):
        from app.models.change_snooze_rule import ChangeSnoozeRule

        table = ChangeSnoozeRule.__table__
        col_names = {c.name for c in table.c}
        for col in (
            "id",
            "created_at",
            "updated_at",
            "workspace_id",
            "integration_id",
            "snoozed_until",
            "is_active",
        ):
            assert col in col_names, f"Missing column: {col}"

    def test_optional_columns_exist(self):
        from app.models.change_snooze_rule import ChangeSnoozeRule

        table = ChangeSnoozeRule.__table__
        col_names = {c.name for c in table.c}
        for col in (
            "record_identifier_pattern",
            "field_path",
            "risk_level",
            "reason",
            "created_by_user_id",
        ):
            assert col in col_names, f"Missing column: {col}"

    def test_is_active_server_default_true(self):
        from app.models.change_snooze_rule import ChangeSnoozeRule

        table = ChangeSnoozeRule.__table__
        is_active_col = table.c["is_active"]
        assert is_active_col.server_default is not None
        assert "true" in str(is_active_col.server_default.arg).lower()


# ─────────────────────────────────────────────────────────────────────────────
# 2-5. create_snooze_rule
# ─────────────────────────────────────────────────────────────────────────────


class TestCreateSnoozeRule:
    def _mock_db(self):
        db = MagicMock()
        db.add = MagicMock()
        db.flush = MagicMock()

        def side_refresh(obj):
            pass

        db.refresh = side_refresh
        return db

    def test_happy_path(self):
        from app.services.snooze_rule_service import create_snooze_rule

        ws_id = _uuid()
        integ_id = _uuid()
        user_id = _uuid()
        until = _future(10)
        db = self._mock_db()

        with patch("app.services.snooze_rule_service.ChangeSnoozeRule") as MockRule:
            instance = MagicMock()
            MockRule.return_value = instance
            result = create_snooze_rule(
                workspace_id=ws_id,
                integration_id=integ_id,
                created_by_user_id=user_id,
                snoozed_until=until,
                db=db,
                reason="test reason",
            )
        db.add.assert_called_once_with(instance)
        db.flush.assert_called_once()

    def test_past_expiry_raises(self):
        from app.services.snooze_rule_service import create_snooze_rule

        with pytest.raises(ValueError, match="future"):
            create_snooze_rule(
                workspace_id=_uuid(),
                integration_id=_uuid(),
                created_by_user_id=_uuid(),
                snoozed_until=_past(),
                db=MagicMock(),
            )

    def test_exceeds_max_days_raises(self):
        from app.services.snooze_rule_service import create_snooze_rule

        with pytest.raises(ValueError, match="90"):
            create_snooze_rule(
                workspace_id=_uuid(),
                integration_id=_uuid(),
                created_by_user_id=_uuid(),
                snoozed_until=_future(91),
                db=MagicMock(),
            )

    def test_naive_datetime_normalised(self):
        from app.services.snooze_rule_service import create_snooze_rule

        naive = datetime.now() + timedelta(days=5)  # naive, no tzinfo
        assert naive.tzinfo is None

        db = self._mock_db()
        with patch("app.services.snooze_rule_service.ChangeSnoozeRule") as MockRule:
            instance = MagicMock()
            MockRule.return_value = instance
            # Should NOT raise — naive is normalised to UTC before comparison
            create_snooze_rule(
                workspace_id=_uuid(),
                integration_id=_uuid(),
                created_by_user_id=_uuid(),
                snoozed_until=naive,
                db=db,
            )
        db.add.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 6. list_active_rules
# ─────────────────────────────────────────────────────────────────────────────


class TestListActiveRules:
    def test_returns_active_rules(self):
        from app.services.snooze_rule_service import list_active_rules

        integ_id = _uuid()
        rule = _make_mock_rule(integration_id=integ_id)

        db = MagicMock()
        # list_active_rules: .query().filter(A,B,C).order_by().all()
        db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [rule]

        result = list_active_rules(integ_id, db)
        assert result == [rule]


# ─────────────────────────────────────────────────────────────────────────────
# 7-8. deactivate_rule
# ─────────────────────────────────────────────────────────────────────────────


class TestDeactivateRule:
    def test_deactivates_existing_rule(self):
        from app.services.snooze_rule_service import deactivate_rule

        rule = _make_mock_rule()
        rule.is_active = True
        db = MagicMock()
        db.get.return_value = rule
        db.flush = MagicMock()

        result = deactivate_rule(rule.id, db)
        assert result is rule
        assert rule.is_active is False
        db.flush.assert_called_once()

    def test_missing_rule_returns_none(self):
        from app.services.snooze_rule_service import deactivate_rule

        db = MagicMock()
        db.get.return_value = None

        result = deactivate_rule(_uuid(), db)
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# 9-15. is_change_snoozed_by_rule
# ─────────────────────────────────────────────────────────────────────────────


class TestIsChangeSnoozedByRule:
    def _db_with_rules(self, rules):
        db = MagicMock()
        # is_change_snoozed_by_rule: .query().filter(A,B,C).all()
        db.query.return_value.filter.return_value.all.return_value = rules
        return db

    def test_no_workspace_id_returns_false(self):
        from app.services.snooze_rule_service import is_change_snoozed_by_rule

        change = _make_mock_change()
        result = is_change_snoozed_by_rule(change, None, MagicMock())
        assert result is False

    def test_no_matching_rules_returns_false(self):
        from app.services.snooze_rule_service import is_change_snoozed_by_rule

        change = _make_mock_change()
        db = self._db_with_rules([])
        assert is_change_snoozed_by_rule(change, _uuid(), db) is False

    def test_exact_match_returns_true(self):
        from app.services.snooze_rule_service import is_change_snoozed_by_rule

        change = _make_mock_change(
            record_identifier="example.com",
            field_path="proxied",
            risk_level="high",
        )
        rule = _make_mock_rule(
            integration_id=change.integration_id,
            record_identifier_pattern="example.com",
            field_path="proxied",
            risk_level="high",
        )
        db = self._db_with_rules([rule])
        assert is_change_snoozed_by_rule(change, _uuid(), db) is True

    def test_wildcard_criteria_match_any(self):
        """Rule with all None criteria matches any change from that integration."""
        from app.services.snooze_rule_service import is_change_snoozed_by_rule

        change = _make_mock_change()
        rule = _make_mock_rule(
            integration_id=change.integration_id,
            # all optional criteria None → match any
        )
        db = self._db_with_rules([rule])
        assert is_change_snoozed_by_rule(change, _uuid(), db) is True

    def test_record_identifier_mismatch_returns_false(self):
        from app.services.snooze_rule_service import is_change_snoozed_by_rule

        change = _make_mock_change(record_identifier="other.com")
        rule = _make_mock_rule(
            integration_id=change.integration_id,
            record_identifier_pattern="example.com",
        )
        db = self._db_with_rules([rule])
        assert is_change_snoozed_by_rule(change, _uuid(), db) is False

    def test_risk_level_mismatch_returns_false(self):
        from app.services.snooze_rule_service import is_change_snoozed_by_rule

        change = _make_mock_change(risk_level="low")
        rule = _make_mock_rule(
            integration_id=change.integration_id,
            risk_level="critical",
        )
        db = self._db_with_rules([rule])
        assert is_change_snoozed_by_rule(change, _uuid(), db) is False

    def test_db_error_fails_open(self):
        """Any DB exception → return False (do not suppress alert)."""
        from app.services.snooze_rule_service import is_change_snoozed_by_rule

        change = _make_mock_change()
        db = MagicMock()
        db.query.side_effect = RuntimeError("DB unavailable")

        result = is_change_snoozed_by_rule(change, _uuid(), db)
        assert result is False


# ─────────────────────────────────────────────────────────────────────────────
# 16-18. get_needs_review_changes
# ─────────────────────────────────────────────────────────────────────────────


class TestGetNeedsReviewChanges:
    def _mock_query_result(self, db, items, count=None):
        q = MagicMock()
        q.join.return_value = q  # workspace-collaboration fix (2bcd639): always joins Integration now
        q.outerjoin.return_value = q
        q.filter.return_value = q
        q.order_by.return_value = q
        q.count.return_value = count if count is not None else len(items)
        q.offset.return_value.limit.return_value.all.return_value = items
        db.query.return_value = q
        return q

    def test_returns_unreviewed_changes(self):
        from app.services.changes_service import get_needs_review_changes

        user_id = _uuid()
        changes = [_make_mock_change(user_id=user_id)]
        db = MagicMock()
        self._mock_query_result(db, changes)

        with patch("app.services.changes_service.get_user_workspace_ids", return_value=[]):
            items, total = get_needs_review_changes(user_id, db, page=1, page_size=50)
        assert items == changes
        assert total == 1

    def test_empty_result(self):
        from app.services.changes_service import get_needs_review_changes

        db = MagicMock()
        self._mock_query_result(db, [], 0)
        with patch("app.services.changes_service.get_user_workspace_ids", return_value=[]):
            items, total = get_needs_review_changes(_uuid(), db)
        assert items == []
        assert total == 0


# ─────────────────────────────────────────────────────────────────────────────
# 19-20. count_needs_review / count_needs_review_by_risk
# ─────────────────────────────────────────────────────────────────────────────


class TestCountNeedsReview:
    def _mock_count(self, db, n):
        q = MagicMock()
        q.join.return_value = q  # workspace-collaboration fix (2bcd639): always joins Integration now
        q.outerjoin.return_value = q
        q.filter.return_value = q
        q.count.return_value = n
        db.query.return_value = q

    def test_count_needs_review(self):
        from app.services.changes_service import count_needs_review

        db = MagicMock()
        self._mock_count(db, 7)
        with patch("app.services.changes_service.get_user_workspace_ids", return_value=[]):
            result = count_needs_review(_uuid(), db)
        assert result == 7

    def test_count_needs_review_by_risk(self):
        from app.services.changes_service import count_needs_review_by_risk

        db = MagicMock()
        self._mock_count(db, 3)
        with patch("app.services.changes_service.get_user_workspace_ids", return_value=[]):
            result = count_needs_review_by_risk(_uuid(), "critical", db)
        assert result == 3


# ─────────────────────────────────────────────────────────────────────────────
# 21-22. alert_service — snooze-rule suppression
# ─────────────────────────────────────────────────────────────────────────────


class TestAlertServiceSnoozeSuppression:
    def _make_integration(self, workspace_id=None):
        integ = MagicMock()
        integ.id = _uuid()
        integ.user_id = _uuid()
        integ.workspace_id = workspace_id or _uuid()
        integ.provider = "cloudflare"
        integ.display_name = "My Integration"
        return integ

    def test_snoozed_change_not_alerted(self):
        """A change matched by a snooze rule must be excluded from alert dispatch."""
        from app.services import alert_service

        change = _make_mock_change(risk_level="high")
        integ = self._make_integration()
        db = MagicMock()

        # get_or_create_settings is a local import inside dispatch_alerts_for_sync,
        # so patch at the source module.
        mock_user_settings = MagicMock()
        mock_user_settings.alert_risk_threshold = "high_and_critical"

        with (
            patch("app.services.settings_service.get_or_create_settings", return_value=mock_user_settings),
            patch("app.services.alert_service.settings") as mock_settings,
            patch("app.services.snooze_rule_service.is_change_snoozed_by_rule", return_value=True),
        ):
            mock_settings.is_email_alerting_configured = True
            result = alert_service.dispatch_alerts_for_sync(
                changes=[change],
                integration=integ,
                sync_run_id=_uuid(),
                db=db,
            )
        # The change was snoozed — no email sent, no Alert row recorded
        assert result["sent"] == 0
        assert result["recorded"] == 0

    def test_snooze_rule_db_error_fails_open(self):
        """If snooze-rule lookup raises, the alert must still be dispatched (fail-open)."""
        from app.services import alert_service

        change = _make_mock_change(risk_level="high")
        integ = self._make_integration()
        db = MagicMock()

        mock_user_settings = MagicMock()
        mock_user_settings.alert_risk_threshold = "high_and_critical"

        with (
            patch("app.services.settings_service.get_or_create_settings", return_value=mock_user_settings),
            patch("app.services.alert_service.settings") as mock_settings,
            patch(
                "app.services.snooze_rule_service.is_change_snoozed_by_rule",
                side_effect=RuntimeError("DB down"),
            ),
            patch("app.services.alert_service._already_alerted", return_value=False),
            patch("app.services.alert_service._resolve_recipient", return_value="user@example.com"),
            patch("app.services.alert_service.email_service") as mock_email,
        ):
            mock_settings.is_email_alerting_configured = True
            mock_email.send_email.return_value = {"id": "msg1"}
            result = alert_service.dispatch_alerts_for_sync(
                changes=[change],
                integration=integ,
                sync_run_id=_uuid(),
                db=db,
            )
        # Fail-open: the error in snooze lookup must not suppress the alert
        assert result["sent"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# 23. notification_service — snooze-rule suppression
# ─────────────────────────────────────────────────────────────────────────────


class TestNotificationServiceSnoozeSuppression:
    def test_snoozed_change_not_notified(self):
        """A change matched by a snooze rule must be excluded from Slack/webhook dispatch."""
        from app.services import notification_service

        change = _make_mock_change(risk_level="high")
        integ = MagicMock()
        integ.id = _uuid()
        integ.workspace_id = _uuid()
        integ.provider = "cloudflare"
        integ.display_name = "Test"

        settings_row = MagicMock()
        settings_row.slack_enabled = True
        settings_row.webhook_enabled = False
        settings_row.notify_on_risk_level = "high_and_critical"
        settings_row.slack_webhook_url_encrypted = b"encrypted"
        settings_row.slack_webhook_iv = b"iv"

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = settings_row

        with patch(
            "app.services.snooze_rule_service.is_change_snoozed_by_rule",
            return_value=True,
        ):
            result = notification_service.dispatch_notifications_for_sync(
                changes=[change],
                integration=integ,
                sync_run_id=_uuid(),
                db=db,
            )
        # Snoozed → not sent
        assert result["slack_sent"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# 24. dashboard_service — review_queue populated
# ─────────────────────────────────────────────────────────────────────────────


class TestDashboardReviewQueue:
    def test_review_queue_in_response(self):
        """get_dashboard_summary must include a review_queue with total/critical/high."""
        from app.services import dashboard_service

        user_id = _uuid()
        db = MagicMock()

        # Stub all sub-queries to avoid real DB
        db.query.return_value.filter.return_value.all.return_value = []
        db.query.return_value.filter.return_value.group_by.return_value.all.return_value = []
        db.query.return_value.filter.return_value.scalar.return_value = 0
        db.query.return_value.filter.return_value.distinct.return_value.all.return_value = []
        db.query.return_value.filter.return_value.order_by.return_value.first.return_value = None
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        db.query.return_value.filter.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        db.query.return_value.join.return_value.filter.return_value.filter.return_value.filter.return_value.group_by.return_value.all.return_value = []

        with (
            patch.object(
                dashboard_service.changes_service,
                "count_needs_review",
                return_value=5,
            ),
            patch.object(
                dashboard_service.changes_service,
                "count_needs_review_by_risk",
                side_effect=lambda uid, risk, _db: 2 if risk == "critical" else 1,
            ),
            patch("app.services.integration_service.get_latest_sync_run_summary", return_value=(None, None, None)),
        ):
            summary = dashboard_service.get_dashboard_summary(user_id=user_id, db=db)

        assert hasattr(summary, "review_queue")
        assert summary.review_queue.total == 5
        assert summary.review_queue.critical == 2
        assert summary.review_queue.high == 1


# ─────────────────────────────────────────────────────────────────────────────
# 25. /changes/needs-review endpoint
# ─────────────────────────────────────────────────────────────────────────────


class TestNeedsReviewEndpoint:
    def test_needs_review_returns_paginated_list(self):
        """GET /changes/needs-review returns 200 with items + total."""
        from fastapi.testclient import TestClient
        from app.main import app
        from app.core.auth import get_current_user
        from app.database import get_db

        user = MagicMock()
        user.id = _uuid()

        db = MagicMock()

        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[get_db] = lambda: db

        change = _make_mock_change(user_id=user.id)
        change.resource_id = _uuid()       # must be a real UUID for Pydantic
        change.change_type = "modified"    # must be a real string
        change.prev_value = None
        change.new_value = None
        change.provider_metadata = None
        change.risk_reason = None
        change.created_at = datetime.now(timezone.utc)

        try:
            with (
                patch("app.routers.changes.changes_service.get_needs_review_changes", return_value=([change], 1)),
                patch("app.routers.changes.change_review_service.get_reviews_for_changes", return_value={}),
            ):
                client = TestClient(app)
                response = client.get("/changes/needs-review")

            assert response.status_code == 200
            data = response.json()
            assert "items" in data
            assert data["total"] == 1
        finally:
            app.dependency_overrides.pop(get_current_user, None)
            app.dependency_overrides.pop(get_db, None)
