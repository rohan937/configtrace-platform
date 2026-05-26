"""Tests for M58.15 — Weekly Executive / Security Digest.

Strategy
--------
Pure unit tests using MagicMock for DB sessions and email_service.
No real DB or network connection required.

Test categories
---------------
Digest computation:
  1.  compute_digest returns correct total_changes for period
  2.  risk_counts are correct (critical/high/medium/low)
  3.  review_counts are correct (needs_review/acknowledged/expected/snoozed)
  4.  provider_activity groups by integration.provider
  5.  top_risks prioritize critical > high > unreviewed > newest

Policy violations:
  6.  policy violations included and counted from policy engine

Stale integrations:
  7.  stale_integrations included when last_synced_at > 48h ago
  8.  healthy integrations NOT included in stale list

Recommended actions:
  9.  recommended_actions generated for unreviewed + policy violations + stale

Authorization:
  10. preview endpoint enforces workspace membership (404 for non-member)
  11. settings GET accessible to any member
  12. settings PUT requires admin (403 for plain member)

Settings CRUD:
  13. update_digest_settings saves fields and returns updated settings
  14. update_digest_settings rejects invalid day (ValueError)
  15. update_digest_settings rejects invalid hour (ValueError)

Email / test send:
  16. test_send_digest sends email when configured; masked recipient returned
  17. test_send_digest returns email body even when email is not configured

Scheduler:
  18. send_due_weekly_digests sends when due (correct day/hour, not recently sent)
  19. send_due_weekly_digests skips when not due (wrong day or gap too short)
  20. weekly_digest_last_sent_at updated after successful send

Email safety:
  21. render_digest_email_body never contains secret/token/command/customer data
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_change(
    *,
    risk_level: str = "high",
    change_type: str = "modified",
    record_type: str = "aws_security_group",
    record_identifier: str = "sg-001",
    integration_id: uuid.UUID | None = None,
    created_at: datetime | None = None,
) -> MagicMock:
    c = MagicMock()
    c.id = uuid.uuid4()
    c.integration_id = integration_id or uuid.uuid4()
    c.risk_level = risk_level
    c.change_type = change_type
    c.record_identifier = record_identifier
    c.field_path = None
    c.new_value = None
    c.prev_value = None
    c.risk_reason = ""
    c.provider_metadata = {"record_type": record_type}
    c.created_at = created_at or datetime.now(timezone.utc)
    return c


def _make_integration(
    *,
    workspace_id: uuid.UUID,
    provider: str = "aws",
    display_name: str = "My AWS",
    last_synced_at: datetime | None = None,
    consecutive_failure_count: int = 0,
    status: str = "active",
) -> MagicMock:
    i = MagicMock()
    i.id = uuid.uuid4()
    i.workspace_id = workspace_id
    i.provider = provider
    i.display_name = display_name
    i.last_synced_at = last_synced_at
    i.consecutive_failure_count = consecutive_failure_count
    i.status = status
    return i


def _make_review(change_id: uuid.UUID, status: str) -> MagicMock:
    r = MagicMock()
    r.change_id = change_id
    r.review_status = status
    return r


def _make_workspace(name: str = "Test Workspace") -> MagicMock:
    w = MagicMock()
    w.id = uuid.uuid4()
    w.name = name
    return w


def _make_settings_row(
    *,
    workspace_id: uuid.UUID | None = None,
    weekly_digest_enabled: bool = False,
    weekly_digest_day: int = 0,
    weekly_digest_hour: int = 9,
    weekly_digest_timezone: str | None = None,
    weekly_digest_last_sent_at: datetime | None = None,
) -> MagicMock:
    row = MagicMock()
    row.workspace_id = workspace_id or uuid.uuid4()
    row.weekly_digest_enabled = weekly_digest_enabled
    row.weekly_digest_day = weekly_digest_day
    row.weekly_digest_hour = weekly_digest_hour
    row.weekly_digest_timezone = weekly_digest_timezone
    row.weekly_digest_last_sent_at = weekly_digest_last_sent_at
    return row


def _build_digest_db(
    workspace_id: uuid.UUID,
    *,
    changes: list | None = None,
    integrations: list | None = None,
    reviews: list | None = None,
    workspace_name: str = "Test Workspace",
) -> MagicMock:
    """Build a DB mock for compute_digest."""
    db = MagicMock()
    changes = changes or []
    integrations = integrations or []
    reviews = reviews or []

    # db.get(Workspace, workspace_id)
    ws = _make_workspace(workspace_name)
    ws.id = workspace_id

    # db.get returns workspace for first call
    def _db_get(model, pk):
        from app.models.workspace import Workspace
        if model is Workspace:
            return ws
        return None

    db.get.side_effect = _db_get

    # Query results: (Change, Integration) rows
    change_integ_rows = []
    for c in changes:
        integ = next(
            (i for i in integrations if i.id == c.integration_id),
            integrations[0] if integrations else _make_integration(workspace_id=workspace_id),
        )
        change_integ_rows.append((c, integ))

    # Query routing: first call is for (Change, Integration) join,
    # second is for ChangeReview in_, third is for Integration (stale check)
    call_count = [0]

    def _query(*args):
        q = MagicMock()
        idx = call_count[0]
        call_count[0] += 1

        if idx == 0:
            # (Change, Integration) join
            q.join.return_value.filter.return_value.all.return_value = change_integ_rows
        elif idx == 1:
            # ChangeReview.in_
            q.filter.return_value.all.return_value = reviews
        elif idx == 2:
            # Integration stale check
            q.filter.return_value.all.return_value = integrations
        elif idx == 3:
            # WorkspaceNotificationSettings overrides (policy engine)
            q.filter.return_value.all.return_value = []
        else:
            q.filter.return_value.all.return_value = []
            q.join.return_value.filter.return_value.all.return_value = []

        return q

    db.query.side_effect = _query
    return db


# ── 1–5: Digest computation ───────────────────────────────────────────────────


class TestComputeDigest:

    def _run(self, workspace_id, changes, integrations=None, reviews=None):
        from app.services.weekly_digest_service import compute_digest

        if integrations is None:
            integ = _make_integration(workspace_id=workspace_id)
            for c in changes:
                c.integration_id = integ.id
            integrations = [integ]

        db = _build_digest_db(
            workspace_id, changes=changes, integrations=integrations, reviews=reviews or []
        )
        return compute_digest(workspace_id, db)

    def test_total_changes_matches_period(self):
        """compute_digest.total_changes == number of changes in window."""
        ws_id = uuid.uuid4()
        changes = [_make_change() for _ in range(7)]
        result = self._run(ws_id, changes)
        assert result.total_changes == 7

    def test_risk_counts_correct(self):
        """risk_counts buckets match actual change risk levels."""
        ws_id = uuid.uuid4()
        changes = [
            _make_change(risk_level="critical"),
            _make_change(risk_level="high"),
            _make_change(risk_level="high"),
            _make_change(risk_level="medium"),
            _make_change(risk_level="low"),
        ]
        result = self._run(ws_id, changes)
        assert result.risk_counts.critical == 1
        assert result.risk_counts.high == 2
        assert result.risk_counts.medium == 1
        assert result.risk_counts.low == 1

    def test_review_counts_correct(self):
        """review_counts uses ChangeReview rows; missing row = needs_review."""
        ws_id = uuid.uuid4()
        c_needs = _make_change()
        c_ack = _make_change()
        c_exp = _make_change()
        changes = [c_needs, c_ack, c_exp]

        reviews = [
            _make_review(c_ack.id, "acknowledged"),
            _make_review(c_exp.id, "expected"),
        ]
        result = self._run(ws_id, changes, reviews=reviews)
        assert result.review_counts.needs_review == 1
        assert result.review_counts.acknowledged == 1
        assert result.review_counts.expected == 1

    def test_provider_activity_groups_by_provider(self):
        """provider_activity groups changes by integration provider."""
        ws_id = uuid.uuid4()
        aws_integ = _make_integration(workspace_id=ws_id, provider="aws")
        gh_integ = _make_integration(workspace_id=ws_id, provider="github")

        changes = [
            _make_change(integration_id=aws_integ.id),
            _make_change(integration_id=aws_integ.id),
            _make_change(integration_id=gh_integ.id, risk_level="critical"),
        ]
        result = self._run(ws_id, changes, integrations=[aws_integ, gh_integ])
        providers = {p.provider: p for p in result.provider_activity}

        assert "aws" in providers
        assert "github" in providers
        assert providers["aws"].change_count == 2
        assert providers["github"].change_count == 1
        assert providers["github"].high_or_critical_count == 1

    def test_top_risks_prioritize_critical_unreviewed(self):
        """top_risks: critical+needs_review appears before high+acknowledged."""
        ws_id = uuid.uuid4()
        c_crit = _make_change(risk_level="critical")
        c_high_ack = _make_change(risk_level="high")
        changes = [c_crit, c_high_ack]

        reviews = [_make_review(c_high_ack.id, "acknowledged")]
        result = self._run(ws_id, changes, reviews=reviews)

        assert len(result.top_risks) >= 1
        assert result.top_risks[0].risk_level == "critical"
        assert result.top_risks[0].status == "needs_review"


# ── 6: Policy violations ──────────────────────────────────────────────────────


class TestDigestPolicyViolations:

    def test_policy_violations_included_from_engine(self):
        """policy_violations.total > 0 when a policy-triggering change is in window."""
        ws_id = uuid.uuid4()

        # AWS SG + public SSH risk_reason triggers aws_no_public_ssh
        c = _make_change(
            record_type="aws_security_group",
            risk_level="critical",
        )
        c.risk_reason = "Public inbound rule: SSH (port 22) open to 0.0.0.0/0"
        c.new_value = None
        c.prev_value = None

        integ = _make_integration(workspace_id=ws_id, provider="aws")
        c.integration_id = integ.id

        db = _build_digest_db(ws_id, changes=[c], integrations=[integ])

        from app.services.weekly_digest_service import compute_digest
        result = compute_digest(ws_id, db)

        assert result.policy_violations.total >= 1
        top_keys = [e.policy_key for e in result.policy_violations.top_policies]
        assert "aws_no_public_ssh" in top_keys


# ── 7–8: Stale integrations ───────────────────────────────────────────────────


class TestStaleIntegrations:

    def test_stale_integration_included_when_old_sync(self):
        """Integration with last_synced_at > 48h ago appears in stale_integrations."""
        ws_id = uuid.uuid4()
        old_sync = datetime.now(timezone.utc) - timedelta(hours=72)
        stale_integ = _make_integration(
            workspace_id=ws_id, provider="stripe",
            display_name="Stripe prod", last_synced_at=old_sync,
        )

        db = _build_digest_db(ws_id, changes=[], integrations=[stale_integ])
        from app.services.weekly_digest_service import compute_digest
        result = compute_digest(ws_id, db)

        assert len(result.stale_integrations) >= 1
        ids = [s.integration_id for s in result.stale_integrations]
        assert str(stale_integ.id) in ids

    def test_healthy_integration_not_in_stale(self):
        """Integration synced recently with no failures is NOT stale."""
        ws_id = uuid.uuid4()
        fresh_sync = datetime.now(timezone.utc) - timedelta(hours=1)
        healthy_integ = _make_integration(
            workspace_id=ws_id, provider="github",
            display_name="GitHub", last_synced_at=fresh_sync,
            consecutive_failure_count=0,
        )

        db = _build_digest_db(ws_id, changes=[], integrations=[healthy_integ])
        from app.services.weekly_digest_service import compute_digest
        result = compute_digest(ws_id, db)

        ids = [s.integration_id for s in result.stale_integrations]
        assert str(healthy_integ.id) not in ids


# ── 9: Recommended actions ────────────────────────────────────────────────────


class TestRecommendedActions:

    def test_recommended_actions_generated(self):
        """recommended_actions is non-empty and actionable."""
        from app.services.weekly_digest_service import _build_recommended_actions
        from app.schemas.weekly_digest import (
            WeeklyDigestReviewCounts,
            WeeklyDigestPolicyViolations,
            WeeklyDigestPolicyViolationEntry,
            WeeklyDigestStaleIntegration,
        )

        review_counts = WeeklyDigestReviewCounts(
            needs_review=3, acknowledged=2, expected=0, snoozed=1
        )
        policy_violations = WeeklyDigestPolicyViolations(
            total=1,
            top_policies=[
                WeeklyDigestPolicyViolationEntry(
                    policy_key="aws_no_public_ssh",
                    name="No public SSH",
                    count=1,
                    severity="critical",
                )
            ],
        )
        stale = [
            WeeklyDigestStaleIntegration(
                integration_id=str(uuid.uuid4()),
                provider="stripe",
                name="Stripe prod",
                last_synced_at=None,
                consecutive_failure_count=0,
            )
        ]

        actions = _build_recommended_actions(
            review_counts=review_counts,
            policy_violations=policy_violations,
            stale_integrations=stale,
        )
        assert len(actions) >= 3

        combined = " ".join(actions).lower()
        assert "unacknowledged" in combined or "review" in combined
        assert "policy" in combined or "no public ssh" in combined.lower()
        assert "stale" in combined or "stripe" in combined.lower()


# ── 10–12: Authorization ──────────────────────────────────────────────────────


class TestDigestAuthorization:

    def _make_db_with_workspace(self):
        """Return a db mock that simulates no workspace membership."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        return db

    def test_preview_endpoint_rejects_non_member(self):
        """GET /weekly-digest/preview returns 404 for non-member."""
        from fastapi import HTTPException
        from app.services import workspace_service

        ws_id = uuid.uuid4()

        with patch.object(
            workspace_service, "require_role",
            side_effect=LookupError("Workspace not found.")
        ):
            db = MagicMock()
            user = MagicMock()
            user.id = uuid.uuid4()

            from app.routers.workspaces import preview_weekly_digest
            with pytest.raises(HTTPException) as exc_info:
                preview_weekly_digest(
                    workspace_id=ws_id,
                    db=db,
                    current_user=user,
                )
            assert exc_info.value.status_code == 404

    def test_settings_get_accessible_to_member(self):
        """GET /weekly-digest/settings passes for any workspace member."""
        from app.services import workspace_service
        from app.models.notification_settings import WorkspaceNotificationSettings

        ws_id = uuid.uuid4()
        row = _make_settings_row(workspace_id=ws_id)

        with patch.object(workspace_service, "require_role", return_value=MagicMock()):
            db = MagicMock()
            # Simulate get_or_create_notification_settings
            db.query.return_value.filter.return_value.first.return_value = row
            user = MagicMock()
            user.id = uuid.uuid4()

            with patch(
                "app.services.notification_service.get_or_create_notification_settings",
                return_value=row,
            ):
                from app.routers.workspaces import get_weekly_digest_settings
                result = get_weekly_digest_settings(
                    workspace_id=ws_id,
                    db=db,
                    current_user=user,
                )
            assert result.workspace_id == str(ws_id)

    def test_settings_put_rejects_plain_member(self):
        """PUT /weekly-digest/settings returns 403 for non-admin member."""
        from fastapi import HTTPException
        from app.services import workspace_service

        ws_id = uuid.uuid4()

        with patch.object(
            workspace_service, "require_role",
            side_effect=PermissionError("Requires at least admin role.")
        ):
            db = MagicMock()
            user = MagicMock()
            user.id = uuid.uuid4()

            from app.schemas.weekly_digest import WeeklyDigestSettingsUpdateRequest
            from app.routers.workspaces import update_weekly_digest_settings
            with pytest.raises(HTTPException) as exc_info:
                update_weekly_digest_settings(
                    workspace_id=ws_id,
                    body=WeeklyDigestSettingsUpdateRequest(weekly_digest_enabled=True),
                    db=db,
                    current_user=user,
                )
            assert exc_info.value.status_code == 403


# ── 13–15: Settings CRUD ──────────────────────────────────────────────────────


class TestDigestSettingsCRUD:

    def test_update_digest_settings_persists_fields(self):
        """update_digest_settings saves enabled, day, hour to the row."""
        from app.services.weekly_digest_service import update_digest_settings
        from app.schemas.weekly_digest import WeeklyDigestSettingsUpdateRequest

        ws_id = uuid.uuid4()
        row = _make_settings_row(workspace_id=ws_id)

        with patch(
            "app.services.notification_service.get_or_create_notification_settings",
            return_value=row,
        ):
            db = MagicMock()
            result = update_digest_settings(
                ws_id,
                WeeklyDigestSettingsUpdateRequest(
                    weekly_digest_enabled=True,
                    weekly_digest_day=1,    # Tuesday
                    weekly_digest_hour=10,
                ),
                db,
            )

        assert result.weekly_digest_enabled is True
        assert result.weekly_digest_day == 1
        assert result.weekly_digest_hour == 10

    def test_update_digest_settings_rejects_invalid_day(self):
        """update_digest_settings raises ValueError for day > 6."""
        from app.services.weekly_digest_service import update_digest_settings
        from app.schemas.weekly_digest import WeeklyDigestSettingsUpdateRequest

        ws_id = uuid.uuid4()
        row = _make_settings_row(workspace_id=ws_id)

        with patch(
            "app.services.notification_service.get_or_create_notification_settings",
            return_value=row,
        ):
            db = MagicMock()
            with pytest.raises(ValueError, match="weekly_digest_day"):
                update_digest_settings(
                    ws_id,
                    WeeklyDigestSettingsUpdateRequest(weekly_digest_day=7),
                    db,
                )

    def test_update_digest_settings_rejects_invalid_hour(self):
        """update_digest_settings raises ValueError for hour > 23."""
        from app.services.weekly_digest_service import update_digest_settings
        from app.schemas.weekly_digest import WeeklyDigestSettingsUpdateRequest

        ws_id = uuid.uuid4()
        row = _make_settings_row(workspace_id=ws_id)

        with patch(
            "app.services.notification_service.get_or_create_notification_settings",
            return_value=row,
        ):
            db = MagicMock()
            with pytest.raises(ValueError, match="weekly_digest_hour"):
                update_digest_settings(
                    ws_id,
                    WeeklyDigestSettingsUpdateRequest(weekly_digest_hour=24),
                    db,
                )


# ── 16–17: Email / test send ──────────────────────────────────────────────────


class TestDigestEmail:

    def _make_minimal_digest(self, ws_id: uuid.UUID) -> "WeeklyDigest":
        from app.schemas.weekly_digest import (
            WeeklyDigest,
            WeeklyDigestRiskCounts,
            WeeklyDigestReviewCounts,
            WeeklyDigestPolicyViolations,
        )
        now = datetime.now(timezone.utc)
        return WeeklyDigest(
            workspace_id=str(ws_id),
            workspace_name="Test WS",
            period_start=now - timedelta(days=7),
            period_end=now,
            generated_at=now,
            total_changes=5,
            risk_counts=WeeklyDigestRiskCounts(critical=1, high=2, medium=1, low=1),
            review_counts=WeeklyDigestReviewCounts(needs_review=2, acknowledged=2, expected=1, snoozed=0),
            review_completion_rate=0.6,
            policy_violations=WeeklyDigestPolicyViolations(total=0, top_policies=[]),
            provider_activity=[],
            top_risks=[],
            stale_integrations=[],
            recommended_actions=["Review 2 unacknowledged changes."],
        )

    def test_test_send_digest_sends_email_when_configured(self):
        """test_send_digest returns sent=True when email service is configured."""
        from app.services import weekly_digest_service

        ws_id = uuid.uuid4()
        user_id = uuid.uuid4()
        digest = self._make_minimal_digest(ws_id)

        user = MagicMock()
        # Use a non-placeholder email (example.com is a placeholder pattern)
        user.email = "admin@acme-corp.io"

        db = MagicMock()
        db.get.return_value = user

        with (
            patch.object(weekly_digest_service, "compute_digest", return_value=digest),
            patch("app.services.email_service.settings") as mock_settings,
            patch("app.services.email_service.send_email") as mock_send,
        ):
            mock_settings.is_email_alerting_configured = True
            mock_send.return_value = {"id": "msg_123"}

            result = weekly_digest_service.test_send_digest(ws_id, user_id, db)

        assert result.sent is True
        assert result.email_configured is True
        assert result.recipient is not None
        # Recipient must be masked — not the full raw email
        assert "admin@acme-corp.io" not in (result.recipient or "")
        assert result.preview_body is not None
        assert len(result.preview_body) > 100

    def test_test_send_digest_returns_body_when_unconfigured(self):
        """test_send_digest returns preview_body even when email is not configured."""
        from app.services import weekly_digest_service
        from app.services.email_service import EmailNotConfigured

        ws_id = uuid.uuid4()
        user_id = uuid.uuid4()
        digest = self._make_minimal_digest(ws_id)

        user = MagicMock()
        user.email = "admin@example.com"

        db = MagicMock()
        db.get.return_value = user

        with (
            patch.object(weekly_digest_service, "compute_digest", return_value=digest),
            patch("app.services.email_service.settings") as mock_settings,
        ):
            mock_settings.is_email_alerting_configured = False

            result = weekly_digest_service.test_send_digest(ws_id, user_id, db)

        assert result.sent is False
        assert result.email_configured is False
        assert result.preview_body is not None
        assert len(result.preview_body) > 100


# ── 18–20: Scheduler ─────────────────────────────────────────────────────────


class TestScheduler:

    def _make_scheduler_db(self, rows: list) -> MagicMock:
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = rows
        return db

    def test_send_due_digests_sends_when_due(self):
        """send_due_weekly_digests calls send_and_record_digest when due."""
        from app.services import weekly_digest_service

        ws_id = uuid.uuid4()
        # Monday, 09:00 UTC
        now = datetime(2026, 5, 25, 9, 0, 0, tzinfo=timezone.utc)  # Monday
        assert now.weekday() == 0  # sanity

        row = _make_settings_row(
            workspace_id=ws_id,
            weekly_digest_enabled=True,
            weekly_digest_day=0,   # Monday
            weekly_digest_hour=9,
            weekly_digest_last_sent_at=None,
        )
        db = self._make_scheduler_db([row])

        with patch.object(
            weekly_digest_service, "send_and_record_digest",
            return_value={"sent": 1, "failed": 0, "skipped": 0, "body": "..."},
        ) as mock_send:
            result = weekly_digest_service.send_due_weekly_digests(now, db)

        mock_send.assert_called_once()
        assert result["sent"] == 1

    def test_send_due_digests_skips_when_wrong_day(self):
        """send_due_weekly_digests skips workspace when day doesn't match."""
        from app.services import weekly_digest_service

        ws_id = uuid.uuid4()
        # Tuesday, 09:00
        now = datetime(2026, 5, 26, 9, 0, 0, tzinfo=timezone.utc)
        assert now.weekday() == 1  # Tuesday

        row = _make_settings_row(
            workspace_id=ws_id,
            weekly_digest_enabled=True,
            weekly_digest_day=0,   # Monday — mismatch
            weekly_digest_hour=9,
        )
        db = self._make_scheduler_db([row])

        with patch.object(
            weekly_digest_service, "send_and_record_digest"
        ) as mock_send:
            result = weekly_digest_service.send_due_weekly_digests(now, db)

        mock_send.assert_not_called()
        assert result["skipped"] == 1

    def test_last_sent_at_updated_after_send(self):
        """weekly_digest_last_sent_at is set on the row after successful send."""
        from app.services import weekly_digest_service

        ws_id = uuid.uuid4()
        now = datetime(2026, 5, 25, 9, 0, 0, tzinfo=timezone.utc)

        row = _make_settings_row(
            workspace_id=ws_id,
            weekly_digest_enabled=True,
            weekly_digest_day=0,
            weekly_digest_hour=9,
            weekly_digest_last_sent_at=None,
        )

        digest = MagicMock()
        digest.workspace_name = "Test"

        with (
            patch.object(weekly_digest_service, "compute_digest", return_value=digest),
            patch.object(weekly_digest_service, "send_digest_email",
                         return_value={"sent": 1, "failed": 0, "skipped": 0, "body": ""}),
        ):
            db = MagicMock()
            weekly_digest_service.send_and_record_digest(ws_id, db, settings_row=row)

        # weekly_digest_last_sent_at should have been set
        assert row.weekly_digest_last_sent_at is not None


# ── 21: Email safety ──────────────────────────────────────────────────────────


class TestEmailSafety:

    FORBIDDEN_PATTERNS = [
        # Specific secret/credential key patterns (not the word "credential" itself,
        # which can appear legitimately in safety disclaimers)
        "api_key=",
        "bot_token=",
        "private_key=",
        "webhook_url=",
        "RESEND_API_KEY",
        "ENCRYPTION_KEY",
        # Customer data patterns
        "customer_id",
        "order_id",
        "payment_method",
        "card_number",
        # Command patterns (lines that could be executed)
        "ALTER TABLE",
        "DROP TABLE",
        "aws configure",
        "kubectl delete",
        # Raw diff markers
        "prev_value",
        "new_value",
    ]

    def test_email_body_does_not_contain_forbidden_content(self):
        """render_digest_email_body output must not contain secrets or commands."""
        from app.services.weekly_digest_service import render_digest_email_body
        from app.schemas.weekly_digest import (
            WeeklyDigest,
            WeeklyDigestRiskCounts,
            WeeklyDigestReviewCounts,
            WeeklyDigestPolicyViolations,
            WeeklyDigestPolicyViolationEntry,
            WeeklyDigestProviderActivity,
            WeeklyDigestTopRisk,
            WeeklyDigestStaleIntegration,
        )
        now = datetime.now(timezone.utc)
        ws_id = uuid.uuid4()
        change_id = uuid.uuid4()

        digest = WeeklyDigest(
            workspace_id=str(ws_id),
            workspace_name="Acme Corp",
            period_start=now - timedelta(days=7),
            period_end=now,
            generated_at=now,
            total_changes=18,
            risk_counts=WeeklyDigestRiskCounts(critical=1, high=3, medium=7, low=7),
            review_counts=WeeklyDigestReviewCounts(
                needs_review=2, acknowledged=5, expected=3, snoozed=1
            ),
            review_completion_rate=0.87,
            policy_violations=WeeklyDigestPolicyViolations(
                total=2,
                top_policies=[
                    WeeklyDigestPolicyViolationEntry(
                        policy_key="aws_no_public_ssh",
                        name="No public SSH",
                        count=1,
                        severity="critical",
                    )
                ],
            ),
            provider_activity=[
                WeeklyDigestProviderActivity(
                    provider="github", change_count=6, high_or_critical_count=1
                )
            ],
            top_risks=[
                WeeklyDigestTopRisk(
                    change_id=str(change_id),
                    title="Aws Security Group modified — sg-public-001",
                    provider="aws",
                    risk_level="critical",
                    status="needs_review",
                    url=f"https://app.configtrace.org/changes/{change_id}",
                )
            ],
            stale_integrations=[
                WeeklyDigestStaleIntegration(
                    integration_id=str(uuid.uuid4()),
                    provider="stripe",
                    name="Stripe production",
                    last_synced_at=now - timedelta(hours=72),
                    consecutive_failure_count=0,
                )
            ],
            recommended_actions=["Review 2 unacknowledged changes."],
        )

        body = render_digest_email_body(digest)

        # Body must be non-empty and contain key sections
        assert len(body) > 200
        assert "Acme Corp" in body
        assert "ConfigTrace Weekly Drift Report" in body

        # Safety check — forbidden patterns must NOT appear
        body_lower = body.lower()
        found = [p for p in self.FORBIDDEN_PATTERNS if p.lower() in body_lower]
        assert found == [], (
            f"Email body contains forbidden content: {found}\n"
            f"First 2000 chars:\n{body[:2000]}"
        )
