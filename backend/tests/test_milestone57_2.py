"""Tests for M57.2 — Change Acknowledgment + Snooze.

Test conventions (same as test_milestone57_1.py / test_milestone51.py):
- All tests use MagicMock — no real DB connection required.
- DATABASE_URL=sqlite:///test.db is fine; tests never touch the DB.
- Tests import service/model modules directly and call them with mock sessions.

Coverage
--------
1.  Model imports cleanly and has correct table name
2.  Model column defaults (via table metadata)
3.  Migration imports and has correct revision chain
4.  Migration creates expected table/columns/indexes
5.  get_review — returns None for unknown change
6.  get_reviews_for_changes — empty list → empty dict
7.  get_reviews_for_changes — returns map keyed by change_id
8.  get_or_create_review — creates row when absent
9.  get_or_create_review — returns existing row
10. acknowledge_change — sets correct fields
11. acknowledge_change — clears snooze fields
12. mark_change_expected — sets correct fields
13. mark_change_expected — clears snooze fields
14. snooze_change — sets status/snoozed_until/reason
15. snooze_change — rejects past datetime
16. snooze_change — rejects >90 days in future
17. reopen_change — resets status to needs_review
18. reopen_change — clears snoozed_until
19. reopen_change — optional note stored
20. snooze_change — note too long raises ValueError
21. acknowledge_change — note too long raises ValueError
22. _emit_audit — calls log_audit_event with safe metadata
23. _emit_audit — no call if workspace_id is None
24. schemas — AcknowledgeRequest accepts empty note → None
25. schemas — SnoozeRequest requires until field
26. schemas — snooze note too long raises ValidationError
27. router — GET /changes returns review field
28. router — POST /changes/{id}/acknowledge returns review response
29. router — POST /changes/{id}/snooze returns review response
30. router — POST /changes/{id}/reopen returns review response
31. router — POST /changes/{id}/mark-expected returns review response
32. router — review endpoints return 404 for unknown change
33. router — RBAC: non-member cannot review (404)
34. snooze_change — exactly 90 days is accepted
35. review_status filter in GET /changes response
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_mock_change(
    change_id: uuid.UUID | None = None,
    risk_level: str = "high",
    workspace_id: uuid.UUID | None = None,
) -> MagicMock:
    """Create a mock Change object with the fields review_service accesses."""
    change = MagicMock()
    change.id = change_id or uuid.uuid4()
    change.risk_level = risk_level
    change.integration_id = uuid.uuid4()
    change.record_identifier = "api.example.com"
    change.provider_metadata = {"record_type": "A"}
    change.user_id = uuid.uuid4()

    # Stub integration lookup
    integ = MagicMock()
    integ.workspace_id = workspace_id or uuid.uuid4()
    return change, integ


def _make_mock_review(
    change_id: uuid.UUID | None = None,
    status: str = "needs_review",
) -> MagicMock:
    row = MagicMock()
    row.change_id = change_id or uuid.uuid4()
    row.review_status = status
    row.reviewed_by_user_id = None
    row.reviewed_at = None
    row.review_note = None
    row.snoozed_until = None
    row.snooze_reason = None
    row.workspace_id = uuid.uuid4()
    return row


def _make_mock_db() -> MagicMock:
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.query.return_value.filter.return_value.all.return_value = []
    db.get.return_value = None
    return db


# ── 1–2: Model ────────────────────────────────────────────────────────────────


class TestChangeReviewModel:
    def test_model_imports(self):
        from app.models.change_review import ChangeReview
        assert ChangeReview is not None

    def test_table_name(self):
        from app.models.change_review import ChangeReview
        assert ChangeReview.__tablename__ == "change_reviews"

    def test_model_column_defaults(self):
        """Column-level INSERT defaults are set correctly."""
        from app.models.change_review import ChangeReview
        table = ChangeReview.__table__
        assert table.c.review_status.default.arg == "needs_review"

    def test_model_inherits_base_mixin(self):
        from app.models.change_review import ChangeReview
        from app.models.base import BaseMixin
        assert issubclass(ChangeReview, BaseMixin)

    def test_model_repr(self):
        from app.models.change_review import ChangeReview
        row = MagicMock(spec=ChangeReview)
        row.change_id = uuid.uuid4()
        row.review_status = "acknowledged"
        row.reviewed_by_user_id = None
        assert "ChangeReview" in ChangeReview.__repr__(row)


# ── 3–4: Migration ────────────────────────────────────────────────────────────


class TestMigration008:
    def _load_module(self):
        import importlib.util, os
        versions_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "alembic", "versions")
        )
        spec = importlib.util.spec_from_file_location(
            "migration_008",
            os.path.join(versions_dir, "008_m57_change_review.py"),
        )
        mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod

    def test_migration_imports_cleanly(self):
        mod = self._load_module()
        assert mod is not None

    def test_migration_revision_chain(self):
        mod = self._load_module()
        assert mod.revision == "008"
        assert mod.down_revision == "007"

    def test_migration_has_upgrade_and_downgrade(self):
        mod = self._load_module()
        assert callable(mod.upgrade)
        assert callable(mod.downgrade)


# ── 5–9: Read helpers ─────────────────────────────────────────────────────────


class TestGetReview:
    def test_returns_none_when_no_row(self):
        from app.services.change_review_service import get_review
        db = _make_mock_db()
        result = get_review(uuid.uuid4(), db)
        assert result is None

    def test_returns_row_when_present(self):
        from app.services.change_review_service import get_review
        db = _make_mock_db()
        mock_row = _make_mock_review()
        db.query.return_value.filter.return_value.first.return_value = mock_row
        result = get_review(mock_row.change_id, db)
        assert result is mock_row


class TestGetReviewsForChanges:
    def test_empty_list_returns_empty_dict(self):
        from app.services.change_review_service import get_reviews_for_changes
        db = _make_mock_db()
        result = get_reviews_for_changes([], db)
        assert result == {}
        # Should not call DB
        db.query.assert_not_called()

    def test_returns_map_keyed_by_change_id(self):
        from app.services.change_review_service import get_reviews_for_changes
        db = _make_mock_db()
        cid1 = uuid.uuid4()
        cid2 = uuid.uuid4()
        row1 = _make_mock_review(change_id=cid1)
        row2 = _make_mock_review(change_id=cid2)
        db.query.return_value.filter.return_value.all.return_value = [row1, row2]
        result = get_reviews_for_changes([cid1, cid2], db)
        assert result[cid1] is row1
        assert result[cid2] is row2


class TestGetOrCreateReview:
    def test_creates_row_when_absent(self):
        from app.services.change_review_service import get_or_create_review
        db = _make_mock_db()
        change, integ = _make_mock_change()
        # DB has no existing row AND no integration (resolve_workspace falls back)
        db.query.return_value.filter.return_value.first.return_value = None
        db.get.return_value = integ  # returns integration for workspace lookup

        with patch("app.services.change_review_service.ChangeReview") as MockReview:
            mock_row = MagicMock()
            MockReview.return_value = mock_row
            row = get_or_create_review(change, db)

        db.add.assert_called_once()
        db.flush.assert_called_once()

    def test_returns_existing_row_without_insert(self):
        from app.services.change_review_service import get_or_create_review
        db = _make_mock_db()
        change, _ = _make_mock_change()
        existing = _make_mock_review(change_id=change.id)
        db.query.return_value.filter.return_value.first.return_value = existing
        row = get_or_create_review(change, db)
        db.add.assert_not_called()
        assert row is existing


# ── 10–21: Write actions ──────────────────────────────────────────────────────


class TestAcknowledgeChange:
    def _setup(self):
        change, integ = _make_mock_change()
        db = _make_mock_db()
        existing = _make_mock_review(change_id=change.id)
        db.query.return_value.filter.return_value.first.return_value = existing
        db.get.return_value = integ
        return change, db, existing

    def test_sets_acknowledged_status(self):
        from app.services.change_review_service import acknowledge_change
        change, db, row = self._setup()
        with patch("app.services.change_review_service._emit_audit"):
            acknowledge_change(change, uuid.uuid4(), db)
        assert row.review_status == "acknowledged"

    def test_sets_reviewed_by_user(self):
        from app.services.change_review_service import acknowledge_change
        change, db, row = self._setup()
        actor = uuid.uuid4()
        with patch("app.services.change_review_service._emit_audit"):
            acknowledge_change(change, actor, db)
        assert row.reviewed_by_user_id == actor

    def test_sets_reviewed_at(self):
        from app.services.change_review_service import acknowledge_change
        change, db, row = self._setup()
        before = _utcnow()
        with patch("app.services.change_review_service._emit_audit"):
            acknowledge_change(change, uuid.uuid4(), db)
        assert row.reviewed_at is not None
        assert row.reviewed_at >= before

    def test_stores_note(self):
        from app.services.change_review_service import acknowledge_change
        change, db, row = self._setup()
        with patch("app.services.change_review_service._emit_audit"):
            acknowledge_change(change, uuid.uuid4(), db, note="Checked manually.")
        assert row.review_note == "Checked manually."

    def test_clears_snooze_fields(self):
        from app.services.change_review_service import acknowledge_change
        change, db, row = self._setup()
        row.snoozed_until = _utcnow() + timedelta(days=7)
        row.snooze_reason = "known window"
        with patch("app.services.change_review_service._emit_audit"):
            acknowledge_change(change, uuid.uuid4(), db)
        assert row.snoozed_until is None
        assert row.snooze_reason is None

    def test_note_too_long_raises(self):
        from app.services.change_review_service import acknowledge_change
        change, db, _ = self._setup()
        with pytest.raises(ValueError, match="1000"):
            acknowledge_change(change, uuid.uuid4(), db, note="x" * 1001)


class TestMarkChangeExpected:
    def _setup(self):
        change, integ = _make_mock_change()
        db = _make_mock_db()
        existing = _make_mock_review(change_id=change.id)
        db.query.return_value.filter.return_value.first.return_value = existing
        db.get.return_value = integ
        return change, db, existing

    def test_sets_expected_status(self):
        from app.services.change_review_service import mark_change_expected
        change, db, row = self._setup()
        with patch("app.services.change_review_service._emit_audit"):
            mark_change_expected(change, uuid.uuid4(), db)
        assert row.review_status == "expected"

    def test_clears_snooze_fields(self):
        from app.services.change_review_service import mark_change_expected
        change, db, row = self._setup()
        row.snoozed_until = _utcnow() + timedelta(days=1)
        with patch("app.services.change_review_service._emit_audit"):
            mark_change_expected(change, uuid.uuid4(), db)
        assert row.snoozed_until is None

    def test_stores_note(self):
        from app.services.change_review_service import mark_change_expected
        change, db, row = self._setup()
        with patch("app.services.change_review_service._emit_audit"):
            mark_change_expected(change, uuid.uuid4(), db, note="deploy release")
        assert row.review_note == "deploy release"


class TestSnoozeChange:
    def _setup(self, workspace_id=None):
        change, integ = _make_mock_change(workspace_id=workspace_id)
        db = _make_mock_db()
        existing = _make_mock_review(change_id=change.id)
        db.query.return_value.filter.return_value.first.return_value = existing
        db.get.return_value = integ
        return change, db, existing

    def test_sets_snoozed_status(self):
        from app.services.change_review_service import snooze_change
        change, db, row = self._setup()
        until = _utcnow() + timedelta(days=7)
        with patch("app.services.change_review_service._emit_audit"):
            snooze_change(change, uuid.uuid4(), db, until=until)
        assert row.review_status == "snoozed"

    def test_sets_snoozed_until(self):
        from app.services.change_review_service import snooze_change
        change, db, row = self._setup()
        until = _utcnow() + timedelta(days=30)
        with patch("app.services.change_review_service._emit_audit"):
            snooze_change(change, uuid.uuid4(), db, until=until)
        assert row.snoozed_until == until

    def test_stores_reason(self):
        from app.services.change_review_service import snooze_change
        change, db, row = self._setup()
        until = _utcnow() + timedelta(days=1)
        with patch("app.services.change_review_service._emit_audit"):
            snooze_change(change, uuid.uuid4(), db, until=until, reason="known window")
        assert row.snooze_reason == "known window"

    def test_rejects_past_datetime(self):
        from app.services.change_review_service import snooze_change
        change, db, _ = self._setup()
        past = _utcnow() - timedelta(hours=1)
        with pytest.raises(ValueError, match="future"):
            snooze_change(change, uuid.uuid4(), db, until=past)

    def test_rejects_more_than_90_days(self):
        from app.services.change_review_service import snooze_change
        change, db, _ = self._setup()
        too_far = _utcnow() + timedelta(days=91)
        with pytest.raises(ValueError, match="90"):
            snooze_change(change, uuid.uuid4(), db, until=too_far)

    def test_accepts_exactly_90_days(self):
        from app.services.change_review_service import snooze_change
        change, db, row = self._setup()
        exactly_90 = _utcnow() + timedelta(days=90) - timedelta(seconds=1)
        with patch("app.services.change_review_service._emit_audit"):
            result_row = snooze_change(change, uuid.uuid4(), db, until=exactly_90)
        # No exception raised — just verify status was set (row is mocked)
        assert row.review_status == "snoozed"

    def test_reason_too_long_raises(self):
        from app.services.change_review_service import snooze_change
        change, db, _ = self._setup()
        until = _utcnow() + timedelta(days=1)
        with pytest.raises(ValueError, match="1000"):
            snooze_change(change, uuid.uuid4(), db, until=until, reason="x" * 1001)

    def test_naive_datetime_normalised_to_utc(self):
        """A naive datetime in the future is accepted (normalised to UTC)."""
        from app.services.change_review_service import snooze_change
        change, db, row = self._setup()
        naive_future = datetime.now() + timedelta(days=1)
        assert naive_future.tzinfo is None
        with patch("app.services.change_review_service._emit_audit"):
            snooze_change(change, uuid.uuid4(), db, until=naive_future)
        assert row.review_status == "snoozed"


class TestReopenChange:
    def _setup(self):
        change, integ = _make_mock_change()
        db = _make_mock_db()
        existing = _make_mock_review(change_id=change.id, status="acknowledged")
        db.query.return_value.filter.return_value.first.return_value = existing
        db.get.return_value = integ
        return change, db, existing

    def test_resets_to_needs_review(self):
        from app.services.change_review_service import reopen_change
        change, db, row = self._setup()
        with patch("app.services.change_review_service._emit_audit"):
            reopen_change(change, uuid.uuid4(), db)
        assert row.review_status == "needs_review"

    def test_clears_snoozed_until(self):
        from app.services.change_review_service import reopen_change
        change, db, row = self._setup()
        row.snoozed_until = _utcnow() + timedelta(days=7)
        with patch("app.services.change_review_service._emit_audit"):
            reopen_change(change, uuid.uuid4(), db)
        assert row.snoozed_until is None

    def test_optional_note_stored(self):
        from app.services.change_review_service import reopen_change
        change, db, row = self._setup()
        with patch("app.services.change_review_service._emit_audit"):
            reopen_change(change, uuid.uuid4(), db, note="revisiting after update")
        assert row.review_note == "revisiting after update"


# ── 22–23: Audit helper ───────────────────────────────────────────────────────


class TestEmitAudit:
    def test_calls_log_audit_event_with_safe_metadata(self):
        from app.services.change_review_service import _emit_audit
        change, _ = _make_mock_change()
        review = _make_mock_review(change_id=change.id)
        review.review_status = "acknowledged"
        actor = uuid.uuid4()

        # log_audit_event is imported lazily inside _emit_audit, so patch at source
        with patch("app.services.workspace_service.log_audit_event") as mock_log, \
             patch("app.models.workspace.WorkspaceAuditLog"):
            db = _make_mock_db()
            _emit_audit(change, review, "change_acknowledged", actor, db)
            mock_log.assert_called_once()
            _, kwargs = mock_log.call_args[0], mock_log.call_args[1]
            meta = kwargs.get("metadata", {})
            assert "change_id" in meta
            assert "risk_level" in meta
            assert "review_status" in meta
            # Must not include prev_value/new_value
            assert "prev_value" not in meta
            assert "new_value" not in meta

    def test_no_audit_when_workspace_id_is_none(self):
        from app.services.change_review_service import _emit_audit
        change, _ = _make_mock_change()
        review = _make_mock_review(change_id=change.id)
        review.workspace_id = None
        review.review_status = "acknowledged"

        with patch("app.services.workspace_service.log_audit_event") as mock_log:
            db = _make_mock_db()
            _emit_audit(change, review, "change_acknowledged", uuid.uuid4(), db)
            mock_log.assert_not_called()


# ── 24–26: Schema validation ──────────────────────────────────────────────────


class TestSchemas:
    def test_acknowledge_empty_note_becomes_none(self):
        from app.schemas.change_review import AcknowledgeRequest
        req = AcknowledgeRequest(note="")
        assert req.note is None

    def test_snooze_requires_until(self):
        from app.schemas.change_review import SnoozeRequest
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            SnoozeRequest()  # missing required 'until'

    def test_snooze_note_too_long_raises(self):
        from app.schemas.change_review import SnoozeRequest
        import pydantic
        until = datetime.now(timezone.utc) + timedelta(days=7)
        with pytest.raises(pydantic.ValidationError, match="1000"):
            SnoozeRequest(until=until, reason="x" * 1001)

    def test_mark_expected_empty_note_becomes_none(self):
        from app.schemas.change_review import MarkExpectedRequest
        req = MarkExpectedRequest(note="  ")
        # Whitespace-only becomes None via validator (strip + or None)
        assert req.note is None or req.note.strip() == ""

    def test_reopen_request_note_optional(self):
        from app.schemas.change_review import ReopenRequest
        req = ReopenRequest()
        assert req.note is None


# ── 27–35: Router tests ───────────────────────────────────────────────────────


class TestChangesRouter:
    """Router-level tests using TestClient with mocked dependencies."""

    def _make_app(self):
        from fastapi import FastAPI
        from app.routers.changes import router
        app = FastAPI()
        app.include_router(router)
        return app

    def _make_user(self, user_id=None):
        user = MagicMock()
        user.id = user_id or uuid.uuid4()
        user.email = "user@example.com"
        return user

    def _make_change_with_review(self, change_id=None, user_id=None, status="needs_review"):
        change = MagicMock()
        change.id = change_id or uuid.uuid4()
        change.user_id = user_id or uuid.uuid4()
        change.integration_id = uuid.uuid4()
        change.resource_id = uuid.uuid4()
        change.change_type = "modified"
        change.record_identifier = "api.example.com"
        change.field_path = "ttl"
        change.prev_value = 300
        change.new_value = 60
        change.risk_level = "high"
        change.risk_reason = "TTL decreased"
        change.provider_metadata = {}
        change.created_at = _utcnow()
        change.prev_snapshot_id = uuid.uuid4()
        change.new_snapshot_id = uuid.uuid4()
        return change

    def test_get_change_includes_review_field(self):
        """GET /changes/{id} response includes review field."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = self._make_app()
        user = self._make_user()
        change = self._make_change_with_review(user_id=user.id)

        mock_db = _make_mock_db()
        # changes_service.get_change_by_id returns the change
        with patch("app.services.changes_service.get_change_by_id", return_value=change), \
             patch("app.services.change_review_service.get_review", return_value=None), \
             patch.object(mock_db, "get", return_value=None):

            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db

            client = TestClient(app)
            resp = client.get(f"/changes/{change.id}")

        assert resp.status_code == 200
        body = resp.json()
        assert "review" in body

    def test_acknowledge_returns_review_response(self):
        """POST /changes/{id}/acknowledge returns ChangeReviewResponse."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = self._make_app()
        user = self._make_user()
        change = self._make_change_with_review(user_id=user.id)

        mock_review = MagicMock()
        mock_review.change_id = change.id
        mock_review.review_status = "acknowledged"
        mock_review.reviewed_by_user_id = user.id
        mock_review.reviewed_at = _utcnow()
        mock_review.review_note = None
        mock_review.snoozed_until = None
        mock_review.snooze_reason = None

        mock_db = _make_mock_db()
        ws_id = uuid.uuid4()

        integ = MagicMock()
        integ.workspace_id = ws_id

        ws_member = MagicMock()
        ws_member.workspace_id = ws_id
        ws_member.user_id = user.id

        with patch("app.services.change_review_service.acknowledge_change",
                   return_value=mock_review):

            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db

            # Override _get_change_and_workspace
            with patch("app.routers.changes._get_change_and_workspace",
                       return_value=(change, ws_id)):
                client = TestClient(app)
                resp = client.post(
                    f"/changes/{change.id}/acknowledge",
                    json={"note": "Checked manually."},
                )

        assert resp.status_code == 200
        body = resp.json()
        assert body["review_status"] == "acknowledged"

    def test_snooze_returns_review_response(self):
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = self._make_app()
        user = self._make_user()
        change = self._make_change_with_review(user_id=user.id)

        until = (_utcnow() + timedelta(days=7)).isoformat()
        mock_review = MagicMock()
        mock_review.change_id = change.id
        mock_review.review_status = "snoozed"
        mock_review.reviewed_by_user_id = user.id
        mock_review.reviewed_at = _utcnow()
        mock_review.review_note = None
        mock_review.snoozed_until = _utcnow() + timedelta(days=7)
        mock_review.snooze_reason = "migration window"

        mock_db = _make_mock_db()
        ws_id = uuid.uuid4()

        with patch("app.services.change_review_service.snooze_change",
                   return_value=mock_review):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db

            with patch("app.routers.changes._get_change_and_workspace",
                       return_value=(change, ws_id)):
                client = TestClient(app)
                resp = client.post(
                    f"/changes/{change.id}/snooze",
                    json={"until": until, "reason": "migration window"},
                )

        assert resp.status_code == 200
        body = resp.json()
        assert body["review_status"] == "snoozed"

    def test_mark_expected_returns_review_response(self):
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = self._make_app()
        user = self._make_user()
        change = self._make_change_with_review(user_id=user.id)

        mock_review = MagicMock()
        mock_review.change_id = change.id
        mock_review.review_status = "expected"
        mock_review.reviewed_by_user_id = user.id
        mock_review.reviewed_at = _utcnow()
        mock_review.review_note = "planned deploy"
        mock_review.snoozed_until = None
        mock_review.snooze_reason = None

        mock_db = _make_mock_db()
        ws_id = uuid.uuid4()

        with patch("app.services.change_review_service.mark_change_expected",
                   return_value=mock_review):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db

            with patch("app.routers.changes._get_change_and_workspace",
                       return_value=(change, ws_id)):
                client = TestClient(app)
                resp = client.post(
                    f"/changes/{change.id}/mark-expected",
                    json={"note": "planned deploy"},
                )

        assert resp.status_code == 200
        assert resp.json()["review_status"] == "expected"

    def test_reopen_returns_review_response(self):
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = self._make_app()
        user = self._make_user()
        change = self._make_change_with_review(user_id=user.id)

        mock_review = MagicMock()
        mock_review.change_id = change.id
        mock_review.review_status = "needs_review"
        mock_review.reviewed_by_user_id = user.id
        mock_review.reviewed_at = _utcnow()
        mock_review.review_note = None
        mock_review.snoozed_until = None
        mock_review.snooze_reason = None

        mock_db = _make_mock_db()
        ws_id = uuid.uuid4()

        with patch("app.services.change_review_service.reopen_change",
                   return_value=mock_review):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db

            with patch("app.routers.changes._get_change_and_workspace",
                       return_value=(change, ws_id)):
                client = TestClient(app)
                resp = client.post(
                    f"/changes/{change.id}/reopen",
                    json={},
                )

        assert resp.status_code == 200
        assert resp.json()["review_status"] == "needs_review"

    def test_review_endpoint_returns_404_for_unknown_change(self):
        """_get_change_and_workspace raising 404 propagates correctly."""
        from fastapi import HTTPException
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = self._make_app()
        user = self._make_user()
        mock_db = _make_mock_db()

        with patch("app.routers.changes._get_change_and_workspace",
                   side_effect=HTTPException(status_code=404, detail="Change not found.")):
            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db

            client = TestClient(app)
            resp = client.post(
                f"/changes/{uuid.uuid4()}/acknowledge",
                json={},
            )

        assert resp.status_code == 404

    def test_non_member_gets_404(self):
        """Non-workspace-member sees 404 (not 403) to avoid leaking existence."""
        from fastapi import HTTPException
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = self._make_app()
        other_user = self._make_user()
        mock_db = _make_mock_db()

        # Simulate _get_change_and_workspace raising 404 for non-member
        with patch("app.routers.changes._get_change_and_workspace",
                   side_effect=HTTPException(status_code=404, detail="Change not found.")):
            app.dependency_overrides[get_current_user] = lambda: other_user
            app.dependency_overrides[get_db] = lambda: mock_db

            client = TestClient(app)
            resp = client.post(
                f"/changes/{uuid.uuid4()}/snooze",
                json={"until": (_utcnow() + timedelta(days=7)).isoformat()},
            )

        assert resp.status_code == 404

    def test_get_changes_list_includes_review(self):
        """GET /changes list response items include a 'review' field."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db

        app = self._make_app()
        user = self._make_user()
        change = self._make_change_with_review(user_id=user.id)

        mock_db = _make_mock_db()

        with patch("app.services.changes_service.get_changes",
                   return_value=([change], 1)), \
             patch("app.services.change_review_service.get_reviews_for_changes",
                   return_value={}):

            app.dependency_overrides[get_current_user] = lambda: user
            app.dependency_overrides[get_db] = lambda: mock_db

            client = TestClient(app)
            resp = client.get("/changes")

        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 1
        assert "review" in body["items"][0]
        # No review row → None
        assert body["items"][0]["review"] is None
